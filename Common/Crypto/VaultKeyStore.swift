/// Domain roots of trust: each domain owns a `domainKey` that is **always wrapped at rest**,
/// sealed to the install's active gating public key.
///
/// ```
///  CEREMONY (one method active)      GATING KEYPAIR              DOMAIN ROOT / LEAF SECRETS
///  ────────────────────────────      ──────────────              ──────────────────────────
///  none      32B, no ACL       ┐
///  pin       PBKDF2(PIN)       ├──▶ vault.gating.<m>.params
///  biometric 32B, ACL          │      (the only slot that
///  secure    eph pub + Enclave ┘       differs by method)
///                                            │ AEAD-opens
///                                            ▼
///                                  vault.gating.<m>.wrapped ──▶ vault.gating.<m>.pub
///                                       (P-256 private)              (not secret)
///                                                                          │ ECIES
///                                                                          ▼
///                                                              domainKey.wrapped[d]
///                                                                          │
///                              ┌───────────────────────────────────────────┤
///                              ▼                    ▼                      ▼
///                    userIdentityKey       fileKeysKEK            refreshTokenKey
///                      (RSA DER)            (AES-256)              (P-256 priv)
/// ```
///
/// `.none`, `.pin` and `.biometric` share one triple per install (account
/// ``CryptoKeychain/gatingSharedAccount``); `.secure` mints one per domain (account = domain
/// identifier). Sealing needs only `<m>.pub`, which is readable at any time — so a domain can be
/// added while the vault is locked, under **all four** methods.
///
/// The invariants this type enforces in one place:
///
/// > **I1.** No key is at rest unwrapped, except the three Provider-readable `unwrapped` slots,
/// > which exist only between an unlock and the next lock.
/// >
/// > **I2.** No key that opens a wrapper is persisted in the plain. The ceremony key comes from
/// > the gating ceremony and from nothing else; the gating private key is persisted only sealed
/// > under it.
/// >
/// > **I3.** `domainKey` is never persisted unwrapped, and is evicted from memory when the
/// > unlock operation completes. It is a local, never a stored property.
/// >
/// > **I4.** The `refreshTokenKey` private half is never persisted unwrapped, and is evicted
/// > once the refresh token has been opened. The gating private half follows the same discipline.
/// >
/// > **I5′.** Isolation is per gating method, and the method's UI copy says which the user gets.
/// > `.secure` is per-domain: its gating keypair is minted per domain, so a captured gating key
/// > opens exactly one vault. `.none`, `.pin` and `.biometric` share one install-wide gating
/// > keypair. In every case each domain still owns its own `domainKey`, and no leaf secret is
/// > ever shared.
///
/// I5′ is what the gating choice buys, and it is stated rather than defended: the shared three
/// already shared one keychain slot (`.none`, `.biometric`) or one enrolled PIN record, since
/// per-domain PBKDF2 would mean per-domain PINs. Below the gating layer nothing is shared, so a
/// captured `domainKey` still opens exactly one vault. Because the wrapper *is* the gating, no
/// value opens a domain without it: switching methods re-seals every wrapper and deletes the
/// superseded triple, so no silently readable path survives. One unlock path, one ``setGating``
/// path, no enrolled/unenrolled regime to branch on.
///
/// Two caveats are deliberate and documented rather than designed away:
///
/// * `vault.gating.biometric.params` — the ceremony key — is **exportable after device-owner
///   auth**: `SecItemCopyMatching` returns its bytes once the prompt is satisfied, and with them
///   the gating private key it seals. It is bypassable with the device password.
///   ``SharedConfig/VaultGating/secure`` is the resolution, offered as the user's choice: its
///   private half never leaves the Secure Enclave. The trade is that a Touch ID enrollment change
///   destroys the key and every wrapper gated by it, which is why it is opt-in.
/// * `.none` gating is a **UX affordance, not a security boundary**: `vault.gating.none.params`
///   is readable silently by any App Group process. The `domainKey` is still never at rest
///   unwrapped, but anything able to run code in the group can unlock.
///
/// ### Rotation discipline
///
/// **Rotating any leaf secret must rotate the `domainKey`** — see ``rotateDomainKey(for:)``. A
/// `domainKey` captured during a past unlock window keeps reach over anything later sealed under
/// it, so re-keying a leaf under the same `domainKey` yields a key the attacker reads on first
/// use. Two fresh-ephemeral disciplines apply at different layers and must not be conflated:
/// every mint of a `.secure` gating keypair enrolls a **fresh Layer-1 ephemeral** against the
/// enclave (reusing the stored one reproduces the identical ceremony key), and every ECIES seal
/// in ``seal(_:to:)`` mints its own fresh **Layer-2 ephemeral**. Same discipline as never reusing
/// a nonce, in both places.
///
/// The AES-GCM envelope is a pure function (``wrap(_:with:)`` / ``unwrap(_:with:)``), as are
/// ``seal(_:to:)`` / ``openSealed(_:with:)``, so they are unit-testable without any keychain or
/// `LAContext`. Everything the four methods do differently sits behind ``GatingCeremony``, over
/// ``BiometricGate``, ``PINGate`` and ``SecureEnclaveGate``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import CryptoKit
import Foundation
import Security
import os.log

/// Abstracts the user-presence check so tests can bypass the real Touch ID / passcode prompt.
public protocol BiometricGate: Sendable {
    /// Prompt for device-owner authentication with `reason`. Throws on cancel/failure.
    func authenticate(reason: String) async throws
    /// Whether biometric (or passcode fallback) auth is available on this device.
    var isAvailable: Bool { get }
    /// Prompt for device-owner auth and return the evaluated `LAContext` (as `AnyObject` to keep
    /// `Common` free of a `LocalAuthentication` import here). Bind it into keychain queries via
    /// `kSecUseAuthenticationContext` so an ACL item can be written/read under this presence.
    /// Returns `nil` on a gate that cannot supply one (tests) — callers then fall back to no context.
    func authenticatedContext(reason: String) async throws -> AnyObject?

    /// Tear down a context returned by ``authenticatedContext(reason:)``.
    ///
    /// An evaluated context is a live presence capability: while it exists it satisfies ACL'd
    /// keychain reads and enclave agreements with no prompt. Dropping the reference is not
    /// enough to say *when* that capability ends, so every unlock invalidates its own context
    /// as the operation closes — the gating key must not outlive the operation that needed it.
    func invalidateContext(_ context: AnyObject?)
}

public extension BiometricGate {
    func authenticatedContext(reason: String) async throws -> AnyObject? { nil }
    /// No-op for gates that supply no context (tests).
    func invalidateContext(_ context: AnyObject?) {}
}

public enum VaultKeyStoreError: Error, Equatable {
    /// AES-GCM open failed — wrong gating key or corrupt/truncated blob.
    case unwrapFailed
    /// The domain's `domainKey` is not obtainable without a gating ceremony (the vault is
    /// locked); an unlock is required first.
    case locked
    /// Keychain read/write failure.
    case keychain(OSStatus)
    /// The device cannot perform biometric/passcode auth.
    case biometricsUnavailable
    /// The gating key for the active gating is missing — the vault cannot be opened.
    case gatingKeyMissing
    /// PIN gating is active but no PIN was supplied to the unlock.
    case pinRequired
    /// This domain's `domainKey` wrapper is gone while its leaf material remains, so nothing it
    /// sealed can ever be opened. Scoped to the one domain — no sibling is affected. Recover by
    /// removing that vault and adding it again.
    case orphanedDomainKeys
    /// The device has no Secure Enclave, or no enrolled biometric, so `.secure` gating cannot be
    /// used.
    case secureEnclaveUnavailable
    /// One or more unwrapped slots survived an eviction, and their **plaintext key material is
    /// still readable**. Names every slot that survived, not just the first: eviction attempts all
    /// of them, so a partial failure must report the whole set.
    ///
    /// An absent slot is never a failure — deleting one is idempotent — so a non-empty payload
    /// always means live key material outlived a lock.
    case evictionFailed([UnwrappedSlot])
}

/// A Provider-readable slot holding plaintext key material while its domain is unlocked. Evicting
/// all of these *is* what locking a vault means, so a failure names the slot that survived.
public enum UnwrappedSlot: String, Equatable, Sendable, CaseIterable {
    /// The RSA user identity private key — the BC01 decrypt path.
    case userIdentityKey
    /// The per-domain file-keys KEK — the BC01 header cache.
    case fileKeysKEK
    /// The OneDrive refresh token — mints access tokens while present.
    case refreshToken
}

/// Whether **one domain's** vault can be used, computed in one place from the two facts that
/// decide it: the presence of that domain's `domainKey` wrapper, and whether the domain is
/// configured at all.
///
/// ```
/// wrapper present? ─ yes ─▶ unwrapped slots present? ─ yes ─▶ .ready
///                                                    └─ no ─▶ .locked
///                  └─ no ──▶ domain configured? ─ no ─▶ .ready (nothing to open)
///                                               └─ yes ▶ .orphaned
/// ```
///
/// Per-domain, per I5′ — every `domainKey` is its own — so an orphaned domain names itself
/// rather than blocking the whole app.
/// Startup, add-domain and unlock all ask this rather than each re-deriving readiness from a
/// thrown error or the gating marker — inferences that drift.
public enum VaultReadiness: Hashable {
    /// Usable now: a wrapper exists and the domain is open, or the domain holds nothing sealed
    /// so there is nothing to unlock.
    case ready
    /// A wrapper exists but the domain is not open. Recoverable by unlocking.
    case locked
    /// The wrapper is absent while the domain is still configured. Its material is sealed under
    /// a `domainKey` that is gone. Only removing and re-adding this domain clears it.
    case orphaned
}

/// AES-GCM envelope + per-domain `domainKey` / gating lifecycle.
///
/// Holds **no** resident key material: `domainKey` is a local in every operation that needs one
/// (I3), and lock state is the presence of a domain's unwrapped slots, not a flag in memory.
public final class VaultKeyStore: @unchecked Sendable {
    private let gate: BiometricGate
    private let pinGate: PINGate
    private let secureGate: SecureEnclaveGate
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "vault-keys")

    /// Authoritative, promptless record of the install's active gating (persisted on
    /// ``SharedConfig/vaultGating``). The keychain cannot be probed for a `.biometryCurrentSet`
    /// item without prompting, so the method is read/written here.
    /// Injected for testability; defaults to the shared store.
    private let readGating: () -> SharedConfig.VaultGating
    private let writeGating: (SharedConfig.VaultGating) -> Void

    /// Reads and writes `vault.gating.none.params` — the unguarded 32-byte unwrapping key.
    ///
    /// Injected because that slot is the one place this type needs
    /// `kSecUseDataProtectionKeychain` with no `SecAccessControl`, which requires an
    /// app-identifier entitlement. A test bundle with no host application does not carry one, so
    /// every write there fails with `errSecMissingEntitlement` (-34018). Tests substitute an
    /// in-memory pair; production reads and writes the real slot. The `.biometric`, `.pin` and
    /// `.secure` ceremonies are unaffected — they are already behind ``BiometricGate``,
    /// ``PINGate`` and ``SecureEnclaveGate``.
    private let readDeviceGatingKey: @Sendable () throws -> Data?
    private let writeDeviceGatingKey: @Sendable (Data) throws -> Void
    private let deleteDeviceGatingKey: @Sendable () -> Void

    /// Reads and writes `vault.gating.biometric.params` — injected for the same reason as the
    /// `.none` accessors above, and so an unattended suite raises no Touch ID prompt.
    private let readBiometricGatingKey: @Sendable (AnyObject?) throws -> Data?
    private let writeBiometricGatingKey: @Sendable (Data, AnyObject?) throws -> Void
    private let deleteBiometricGatingKey: @Sendable () -> Void

    /// Whether a domain is configured — the per-domain orphan check used by ``readiness(for:)``.
    ///
    /// Reads the **configuration**, not the keychain. A configured domain is the only thing the
    /// UI can list for removal, so a report keyed on it is always clearable by the user. Key
    /// material with no config row is invisible to them.
    private let isConfiguredDomain: (String) -> Bool

    /// Every configured domain's identifier.
    ///
    /// Injected alongside ``readGating`` for the same reason: an install-wide re-gate must re-seal
    /// the same domain set the rest of this type sees. Reading the shared store directly here
    /// would ignore an injected view and leave a domain sealed to a superseded keypair.
    private let allDomainIdentifiers: () -> [String]

    /// The production device-gating accessors, named so they can serve as default arguments —
    /// an internal member cannot appear inline in a public one's default value.
    static func keychainDeviceGatingRead() throws -> Data? {
        try CryptoKeychain.loadGatingParams(.none, domain: CryptoKeychain.gatingSharedAccount)
    }

    static func keychainDeviceGatingWrite(_ raw: Data) throws {
        try CryptoKeychain.storeGatingParams(raw, method: .none,
                                             domain: CryptoKeychain.gatingSharedAccount)
    }

    static func keychainDeviceGatingDelete() {
        CryptoKeychain.deleteGatingKey(service: CryptoKeychain.gatingParamsService(.none),
                                       account: CryptoKeychain.gatingSharedAccount)
    }

    public init(gate: BiometricGate,
                pinGate: PINGate = PINGate(
                    load: { CryptoKeychain.vaultPINRecord() },
                    save: { try CryptoKeychain.storeVaultPINRecord($0) }),
                secureGate: SecureEnclaveGate = SecureEnclaveKeyGate(),
                readGating: @escaping () -> SharedConfig.VaultGating = {
                    SharedConfigStore.shared.read(\.vaultGating)
                },
                writeGating: @escaping (SharedConfig.VaultGating) -> Void = { gating in
                    SharedConfigStore.shared.write(\.vaultGating, gating)
                },
                isConfiguredDomain: @escaping (String) -> Bool = { domain in
                    SharedConfigStore.shared.allAccounts()[domain] != nil
                },
                allDomainIdentifiers: @escaping () -> [String] = {
                    Array(SharedConfigStore.shared.allAccounts().keys)
                },
                readDeviceGatingKey: (@Sendable () throws -> Data?)? = nil,
                writeDeviceGatingKey: (@Sendable (Data) throws -> Void)? = nil,
                deleteDeviceGatingKey: (@Sendable () -> Void)? = nil,
                readBiometricGatingKey: (@Sendable (AnyObject?) throws -> Data?)? = nil,
                writeBiometricGatingKey: (@Sendable (Data, AnyObject?) throws -> Void)? = nil,
                deleteBiometricGatingKey: (@Sendable () -> Void)? = nil) {
        self.gate = gate
        self.pinGate = pinGate
        self.secureGate = secureGate
        self.readGating = readGating
        self.writeGating = writeGating
        self.isConfiguredDomain = isConfiguredDomain
        self.allDomainIdentifiers = allDomainIdentifiers
        // `nil` means "use the real slot". The production accessors are internal, so they cannot
        // appear as default argument values on a public initializer; resolving them here keeps
        // them out of the public surface.
        self.readDeviceGatingKey = readDeviceGatingKey ?? Self.keychainDeviceGatingRead
        self.writeDeviceGatingKey = writeDeviceGatingKey ?? Self.keychainDeviceGatingWrite
        self.deleteDeviceGatingKey = deleteDeviceGatingKey ?? Self.keychainDeviceGatingDelete
        self.readBiometricGatingKey = readBiometricGatingKey ?? BiometricCeremony.keychainRead
        self.writeBiometricGatingKey = writeBiometricGatingKey ?? BiometricCeremony.keychainWrite
        self.deleteBiometricGatingKey = deleteBiometricGatingKey ?? BiometricCeremony.keychainDelete
    }

    /// The process-wide store.
    ///
    /// Stateless with respect to key material, so a second instance would be harmless — but the
    /// PIN throttle is per-instance state that must not be reset by minting a new store.
    public static let shared = VaultKeyStore(gate: LABiometricGate())

    // MARK: - Pure AES-GCM envelope

    /// Wrap `plaintext` under `key`. Returns the combined GCM box (nonce‖ciphertext‖tag).
    public static func wrap(_ plaintext: Data, with key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw VaultKeyStoreError.unwrapFailed }
        return combined
    }

    /// Unwrap a combined GCM box back to plaintext under `key`.
    public static func unwrap(_ wrapped: Data, with key: SymmetricKey) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(combined: wrapped)
            return try AES.GCM.open(box, using: key)
        } catch {
            throw VaultKeyStoreError.unwrapFailed
        }
    }

    /// Wrap `plaintext` under `key`, binding `aad` into the GCM tag.
    ///
    /// The additional authenticated data is not stored in the box: the opener must supply the
    /// identical bytes, so a box cannot be transplanted onto a different context (for the BC01
    /// header cache, a different item or content revision) even if the surrounding columns are
    /// rewritten to agree.
    ///
    /// - Parameters:
    ///   - plaintext: The secret bytes to seal.
    ///   - key: The wrapping key.
    ///   - aad: Context bytes bound into the authentication tag.
    /// - Returns: The combined GCM box (nonce‖ciphertext‖tag).
    public static func wrap(_ plaintext: Data, with key: SymmetricKey,
                            authenticating aad: Data) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        guard let combined = sealed.combined else { throw VaultKeyStoreError.unwrapFailed }
        return combined
    }

    /// Unwrap a combined GCM box sealed by ``wrap(_:with:authenticating:)``.
    ///
    /// Throws ``VaultKeyStoreError/unwrapFailed`` when the key, the box, **or `aad`** does not
    /// match what was sealed.
    ///
    /// - Parameters:
    ///   - wrapped: The combined GCM box.
    ///   - key: The wrapping key.
    ///   - aad: The same context bytes supplied at seal time.
    /// - Returns: The recovered plaintext.
    public static func unwrap(_ wrapped: Data, with key: SymmetricKey,
                              authenticating aad: Data) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(combined: wrapped)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw VaultKeyStoreError.unwrapFailed
        }
    }

    /// Generate a fresh 256-bit key.
    public static func generateKey() -> SymmetricKey { SymmetricKey(size: .bits256) }

    // MARK: - Lock state

    /// Whether a domain is open — i.e. **any** of its Provider-readable slots is populated.
    ///
    /// Derived from the keychain, not from a flag: there is no resident key whose presence could
    /// answer this (I3), and the slots are the actual thing the Provider reads, so anything else
    /// would be a second source of truth that drifts.
    ///
    /// It must be *any*, never one nominated slot, because no single slot is common to every
    /// domain: `userIdentityKey` exists only under `.bc01`, and `refreshToken` only for a backend
    /// that authenticates (OneDrive). Naming one would report a domain that legitimately lacks it
    /// as permanently locked. Lock evicts all three together, so "any present" is exactly "not
    /// locked".
    ///
    /// A domain holding no leaf material at all reads as locked; ``readiness(for:)`` is the caller
    /// that distinguishes that from a domain that is merely closed, via the wrapper.
    public func isUnlocked(domain domainIdentifier: String) -> Bool {
        ((try? CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainIdentifier)) ?? nil) != nil
            || ((try? CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainIdentifier)) ?? nil) != nil
            || ((try? CryptoKeychain.loadUnwrappedRefreshToken(for: domainIdentifier)) ?? nil) != nil
    }

    /// Seconds to wait before another PIN attempt is accepted (escalating backoff, no lockout).
    public var pinRetryDelay: TimeInterval { pinGate.throttle.currentDelay }

    /// Evaluate the install's gating ceremony for its presence prompt alone, and hand the
    /// evaluated context to the caller.
    ///
    /// The `.biometric` / `.secure` half of the gate in front of the Security screen: it proves
    /// the user can produce the gating key and populates **no** domain's `.unwrapped` slots.
    ///
    /// **The returned context is a live presence capability**, and ownership transfers to the
    /// caller: while it exists it satisfies ACL'd keychain reads and enclave agreements with no
    /// prompt. The caller must invalidate it — via ``invalidatePresence(_:)`` — as soon as the
    /// intent it was obtained for is finished. It is returned rather than discarded so that one
    /// continuous intent (admit the user, then re-key on Save) costs one prompt; the re-key spends
    /// it by passing it to ``setGating(_:newPIN:currentPIN:presenceContext:)``.
    ///
    /// - Returns: The evaluated context, or `nil` for a method that needs no user presence.
    /// - Throws: Whatever the ceremony failed with — a cancelled prompt, or
    ///   ``VaultKeyStoreError/gatingKeyMissing`` when a `.secure` key was destroyed by an
    ///   enrollment change.
    public func evaluatePresence(reason: String) async throws -> AnyObject? {
        let method = readGating()
        // `.pin` is proven by `verifyPIN`, and `.none` has nothing to prove.
        guard method == .biometric || method == .secure else { return nil }
        // Deliberately not `withPresenceContext`: that invalidates on return, which is right for
        // a self-contained operation and wrong here — the capability is the thing being handed on.
        return try await presenceContext(for: method, reason: reason)
    }

    /// End a presence capability obtained from ``evaluatePresence(reason:)``.
    ///
    /// Idempotent, and safe with `nil`. Every holder calls this the moment its intent completes
    /// or is abandoned, so "forgotten at the end of the operation" stays true of a borrowed
    /// context as much as of an internally-scoped one.
    public func invalidatePresence(_ context: AnyObject?) {
        guard let context else { return }
        gate.invalidateContext(context)
    }

    /// Whether `pin` opens this install, without unlocking anything.
    ///
    /// For the UI gate in front of the Security screen: that screen needs to know the PIN is
    /// correct *before* letting the user in, but must not populate any domain's `.unwrapped`
    /// slots as a side effect — entering a settings screen is not an unlock, and the gating key
    /// it proves is forgotten here as everywhere else.
    ///
    /// Runs the throttled derivation rather than ``PINGate/verify(_:)`` so a wrong entry here
    /// costs the same escalating backoff as one at the unlock screen; a cheap unthrottled oracle
    /// in front of the settings screen would simply be the easier place to guess.
    ///
    /// - Parameter pin: The entered PIN.
    /// - Returns: `true` when the PIN matches the enrolled record.
    public func verifyPIN(_ pin: String) -> Bool {
        do {
            // The derived key is deliberately discarded: proving the PIN is the whole job, and
            // holding a gating key past the operation that obtained it is what this design
            // forbids.
            _ = try pinGate.deriveGatingKey(with: pin)
            return true
        } catch {
            return false
        }
    }

    /// The unlock method in force for this install. Silent — reads the persisted marker, never
    /// the keychain (a `.biometryCurrentSet` item cannot be probed without prompting).
    public func gating() -> SharedConfig.VaultGating {
        readGating()
    }

    /// Whether `method` requires a user-presence ceremony to open. Pure — no keychain, no gates.
    ///
    /// Drives the single presence evaluation that serves N domains in
    /// ``populateUnwrappedSlots(for:pin:)``.
    public static func requiresPresence(_ method: SharedConfig.VaultGating) -> Bool {
        switch method {
        case .none, .pin: return false
        case .biometric, .secure: return true
        }
    }

    /// Whether a domain has been provisioned (a `domainKey` wrapper exists).
    public func isProvisioned(domain domainIdentifier: String) -> Bool {
        ((try? CryptoKeychain.loadWrappedDomainKey(for: domainIdentifier)) ?? nil) != nil
    }

    /// Lock a domain: evict its Provider-readable slots. There is no in-memory key to drop.
    public func lock(domain domainIdentifier: String) {
        try? evictUnwrappedSlots(for: domainIdentifier)
        log.info("🔒 domain locked \(domainIdentifier, privacy: .public)")
    }

    // MARK: - Domain key

    /// Obtain a domain's `domainKey` by running its gating ceremony and opening the wrapper.
    ///
    /// The returned key is a **local** — never stored on the instance (I3). Callers use it
    /// within one operation and let it go.
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain whose key is wanted.
    ///   - pin: The entered PIN, for `.pin` gating.
    ///   - reason: Prompt text for the `.biometric` / `.secure` ceremonies.
    ///   - context: A pre-evaluated `LAContext` to reuse, so unlocking N domains costs one prompt.
    /// - Returns: The domain's `domainKey`.
    /// - Throws: ``VaultKeyStoreError/orphanedDomainKeys`` when the wrapper is absent.
    private func domainKey(for domainIdentifier: String,
                           pin: String?,
                           reason: String,
                           context: AnyObject? = nil) async throws -> SymmetricKey {
        guard let box = try CryptoKeychain.loadWrappedDomainKey(for: domainIdentifier) else {
            throw VaultKeyStoreError.orphanedDomainKeys
        }
        let method = readGating()
        // Layer 1 — the ceremony, the only method-specific step.
        let ceremonyKey = try await ceremony(for: method).open(
            domain: domainIdentifier, pin: pin, reason: reason, context: context)
        // Layer 2 — open the gating private half, then the domainKey sealed to its public half.
        // Both are locals, evicted when this returns (I4).
        let priv = try gatingPrivateKey(method: method, domain: domainIdentifier,
                                        ceremonyKey: ceremonyKey)
        return SymmetricKey(data: try Self.openSealed(box, with: priv))
    }

    /// The ``GatingCeremony`` for `method`. One resolution point — no call site branches on the
    /// method beyond this.
    private func ceremony(for method: SharedConfig.VaultGating) -> GatingCeremony {
        switch method {
        case .none:
            return NoneCeremony(readParams: readDeviceGatingKey, writeParams: writeDeviceGatingKey)
        case .pin:
            return PINCeremony(gate: pinGate)
        case .biometric:
            return BiometricCeremony(gate: gate,
                                     readParams: readBiometricGatingKey,
                                     writeParams: writeBiometricGatingKey)
        case .secure:
            return SecureEnclaveCeremony(gate: secureGate)
        }
    }

    /// Open `vault.gating.<m>.wrapped` with the key the ceremony produced.
    ///
    /// The returned private key is a **local** at every call site (I4) — never stored on the
    /// instance, never persisted unwrapped.
    private func gatingPrivateKey(method: SharedConfig.VaultGating,
                                  domain: String,
                                  ceremonyKey: SymmetricKey) throws -> P256.KeyAgreement.PrivateKey {
        guard let wrapped = try CryptoKeychain.loadGatingWrappedKey(method, domain: domain) else {
            throw VaultKeyStoreError.gatingKeyMissing
        }
        return try P256.KeyAgreement.PrivateKey(
            rawRepresentation: try Self.unwrap(wrapped, with: ceremonyKey))
    }

    /// Mint `method`'s gating keypair for `domain` and seal the private half under a fresh
    /// ceremony. Promptless for every method.
    ///
    /// - Returns: The public half, which seals every `domainKey` gated by this method.
    @discardableResult
    private func mintGatingKeypair(method: SharedConfig.VaultGating,
                                   domain: String,
                                   pin: String?) async throws -> P256.KeyAgreement.PublicKey {
        let ceremonyKey = try await ceremony(for: method).enroll(domain: domain, pin: pin)
        let priv = P256.KeyAgreement.PrivateKey()
        try CryptoKeychain.storeGatingWrappedKey(try Self.wrap(priv.rawRepresentation, with: ceremonyKey),
                                                 method: method, domain: domain)
        try CryptoKeychain.storeGatingPublicKey(priv.publicKey.x963Representation,
                                                method: method, domain: domain)
        return priv.publicKey
    }

    /// Seal a domain's `domainKey` to the active method's gating public key.
    ///
    /// No ceremony, no prompt: this is what lets a domain be added while the vault is locked.
    /// Mints the keypair on first use so the very first domain under a method enrolls it.
    private func sealDomainKey(_ key: SymmetricKey, for domainIdentifier: String,
                               method: SharedConfig.VaultGating,
                               pin: String? = nil) async throws {
        // Both halves must be present to reuse the keypair. `.pub` alone is not enough: a `.pub`
        // whose `.wrapped` is gone can still seal, but nothing could ever open it.
        let existing = try CryptoKeychain.loadGatingPublicKey(method, domain: domainIdentifier)
        let openable = try CryptoKeychain.loadGatingWrappedKey(method, domain: domainIdentifier) != nil
        let pub: P256.KeyAgreement.PublicKey
        if let existing, openable {
            pub = try P256.KeyAgreement.PublicKey(x963Representation: existing)
        } else {
            pub = try await mintGatingKeypair(method: method, domain: domainIdentifier, pin: pin)
        }
        try CryptoKeychain.storeWrappedDomainKey(try Self.seal(key.raw, to: pub),
                                                 for: domainIdentifier)
    }

    /// HKDF-SHA256 over the ECDH shared secret, salted with the ephemeral public key and bound to
    /// the domain.
    ///
    /// `domainIdentifier` in `info` is belt-and-braces: even a wrongly reused ephemeral would
    /// still derive a different key per domain.
    static func deriveSecureGatingKey(sharedSecret: Data,
                                      ephemeralPublicKey: Data,
                                      domainIdentifier: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: sharedSecret),
                               salt: ephemeralPublicKey,
                               info: Data(domainIdentifier.utf8),
                               outputByteCount: 32)
    }

    /// Delete every gating triple superseded by `keep`.
    ///
    /// Gating is install-wide, so a method the install has moved off is dead for **every** domain
    /// at once — there is no sibling still gated onto it to survey for. `.secure`'s triple is
    /// per-domain, so retiring it means deleting one per domain.
    ///
    /// Idempotent, and only ever removes the *non*-active method, which is why this can never
    /// brick a vault.
    ///
    /// - Parameter keep: The method that stays active.
    private func deleteGatingKeys(except keep: SharedConfig.VaultGating) {
        for method in SharedConfig.VaultGating.allCases where method != keep {
            if method == .secure {
                for domain in allDomainIdentifiers() {
                    CryptoKeychain.deleteGatingTriple(.secure, domain: domain)
                }
            } else {
                CryptoKeychain.deleteGatingTriple(method,
                                                  domain: CryptoKeychain.gatingSharedAccount)
            }
            // `.none`'s params slot is behind the injected accessors, and `.pin`'s throttle state
            // lives on the gate — both need their own teardown beyond the raw item delete.
            if method == .none { deleteDeviceGatingKey() }
            if method == .biometric { deleteBiometricGatingKey() }
            if method == .pin { try? pinGate.clearPIN() }
        }
    }

    // MARK: - Unlock / gating changes

    /// Unlock one domain: run its gating ceremony, open its `domainKey`, and populate the three
    /// Provider-readable slots.
    ///
    /// One path for all four gatings — the ceremony differs only in how the gating key is
    /// obtained. The `domainKey` is discarded when this returns (I3), as is the refresh-token
    /// private key once the token is opened (I4).
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain to unlock.
    ///   - pin: The entered PIN, for `.pin` gating.
    ///   - reason: Prompt text shown for `.biometric` and `.secure` gating.
    ///   - context: A pre-evaluated `LAContext` to reuse, so unlocking N domains costs one prompt.
    public func unlock(domain domainIdentifier: String,
                       pin: String? = nil,
                       reason: String = "Unlock your vaults",
                       context: AnyObject? = nil) async throws {
        let key = try await domainKey(for: domainIdentifier, pin: pin,
                                      reason: reason, context: context)
        try populateUnwrappedSlots(for: domainIdentifier, domainKey: key)
        log.info("🔓 domain unlocked \(domainIdentifier, privacy: .public) (gating \(self.readGating().rawValue, privacy: .public))")
        // `key` goes out of scope here — I3.
    }

    /// Switch the **install** to `target`: enroll the new method, mint its keypair(s), and
    /// re-seal every domain's `domainKey` to the new `.pub`.
    ///
    /// No `domainKey` changes, so every leaf blob stays valid; only the wrappers and the gating
    /// keypair change. Every domain is opened under the *current* method first — one ceremony,
    /// its context reused — which is what makes changing a PIN on a locked vault work.
    ///
    /// **Ordering under crash.** Every new wrapper is written *before* any superseded gating
    /// material is deleted. A crash in that window leaves two gating keypairs but one wrapper per
    /// domain, so every vault still opens (no lockout) and ``reconcile(domain:)`` cleans up on
    /// next launch. The reverse order could brick the vault.
    ///
    /// **Atomicity.** The re-seal either completes for every domain or throws having deleted
    /// nothing — a domain that fails to open under the current method aborts the whole switch,
    /// leaving the install on its existing method rather than half-migrated.
    ///
    /// - Parameters:
    ///   - target: The method to switch the install to.
    ///   - newPIN: The PIN to enroll, when `target` is `.pin`.
    ///   - currentPIN: The PIN opening the *current* method, when it is `.pin`.
    public func setGating(_ target: SharedConfig.VaultGating,
                          newPIN: String? = nil,
                          currentPIN: String? = nil,
                          presenceContext: AnyObject? = nil) async throws {
        let current = readGating()
        let domains = allDomainIdentifiers()

        // One presence evaluation for the whole re-gate, reused across every domain and
        // invalidated as soon as Phase A closes — it is not held across the re-seal.
        let reason = "Confirm to change your vault lock settings"

        // Phase A — open every domain under the current method. Any failure aborts here, before
        // a single wrapper or gating slot has been touched.
        //
        // A caller-supplied context is *borrowed*, not owned: the UI gate in front of the
        // Security screen already evaluated presence to admit the user, and re-evaluating here
        // would prompt a second time for one continuous intent. Its owner invalidates it; this
        // method must not, which is why the borrowed path does not go through
        // ``withPresenceContext(for:reason:_:)`` (that helper invalidates what it is given).
        var opened: [String: SymmetricKey] = [:]
        let openAll: (AnyObject?) async throws -> Void = { context in
            for domain in domains where self.isProvisioned(domain: domain) {
                opened[domain] = try await self.domainKey(
                    for: domain, pin: currentPIN, reason: reason, context: context)
            }
        }
        if let presenceContext {
            try await openAll(presenceContext)
        } else {
            try await withPresenceContext(for: current, reason: reason, openAll)
        }

        // Phase B — mint the target keypair(s). One for the shared three; one per domain for
        // `.secure`, which is what its per-domain isolation means.
        if target != .secure {
            try await mintGatingKeypair(method: target,
                                        domain: CryptoKeychain.gatingSharedAccount, pin: newPIN)
        }

        // Phase C — re-seal every domain to the new `.pub`. New wrapper before old key deleted.
        for (domain, key) in opened {
            try await sealDomainKey(key, for: domain, method: target, pin: newPIN)
        }

        writeGating(target)
        deleteGatingKeys(except: target)
        log.info("🔑 install gating → \(target.rawValue, privacy: .public) across \(opened.count) domain(s)")
    }

    /// A single evaluated `LAContext` for `method`, or `nil` when it needs no user presence.
    ///
    /// An evaluated context is a **presence token, not a per-item unlock**: bound via
    /// `kSecUseAuthenticationContext` it satisfies N ACL'd keychain reads, and passed to
    /// ``SecureEnclaveGate/agree(withEphemeralPublicKey:reason:context:)`` it satisfies N enclave
    /// agreements. That is what keeps Unlock All at one prompt while `.secure` keeps per-domain
    /// keypairs.
    private func presenceContext(for method: SharedConfig.VaultGating,
                                 reason: String) async throws -> AnyObject? {
        guard Self.requiresPresence(method) else { return nil }
        return try await gate.authenticatedContext(reason: reason)
    }

    /// Run `body` under a single presence evaluation for `method`, invalidating it on every exit
    /// path — success, throw, or cancellation.
    ///
    /// The only way this store obtains a presence token. Returning a bare context let the
    /// capability outlive the unlock; a scoped helper makes "forgotten at the end of the
    /// operation" a property of the code rather than of each call site remembering.
    private func withPresenceContext<T>(for method: SharedConfig.VaultGating,
                                        reason: String,
                                        _ body: (AnyObject?) async throws -> T) async throws -> T {
        let context = try await presenceContext(for: method, reason: reason)
        defer { gate.invalidateContext(context) }
        return try await body(context)
    }

    /// Rotate a domain's `domainKey`, re-wrapping all three leaf blobs under the new value.
    ///
    /// **The only way any leaf secret is re-keyed.** A `domainKey` captured during a past unlock
    /// window keeps reach over anything later sealed under it, so re-keying a leaf under the same
    /// `domainKey` yields a key the attacker reads on first use. Every rotation path calls this.
    ///
    /// Mints a fresh ephemeral under `.secure`, per the same discipline as never reusing a nonce.
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain to re-key.
    ///   - pin: The entered PIN, for `.pin` gating.
    public func rotateDomainKey(for domainIdentifier: String, pin: String? = nil) async throws {
        let old = try await domainKey(for: domainIdentifier, pin: pin,
                                      reason: "Confirm to re-key your vault")
        let fresh = Self.generateKey()

        // Re-wrap every leaf that exists. Absent leaves are simply not yet provisioned.
        if let box = try CryptoKeychain.loadWrappedUserIdentityKey(for: domainIdentifier) {
            let der = try Self.unwrap(box, with: old)
            try CryptoKeychain.storeWrappedUserIdentityKey(try Self.wrap(der, with: fresh),
                                                           for: domainIdentifier)
        }
        if let box = try CryptoKeychain.loadWrappedFileKeysKEK(for: domainIdentifier) {
            let raw = try Self.unwrap(box, with: old)
            try CryptoKeychain.storeWrappedFileKeysKEK(try Self.wrap(raw, with: fresh),
                                                       for: domainIdentifier)
        }
        if let box = try CryptoKeychain.loadWrappedRefreshTokenKey(for: domainIdentifier) {
            let priv = try Self.unwrap(box, with: old)
            try CryptoKeychain.storeWrappedRefreshTokenKey(try Self.wrap(priv, with: fresh),
                                                           for: domainIdentifier)
        }

        // Wrapper last: a crash before this leaves the leaves re-wrapped under a key no wrapper
        // names, which `reconcile` reports as orphaned — recoverable — rather than silently
        // half-rotated. The gating keypair is unchanged: rotation re-keys the domain, not the
        // ceremony that opens it.
        try await sealDomainKey(fresh, for: domainIdentifier, method: readGating(), pin: pin)
        log.info("🔑 domainKey rotated for \(domainIdentifier, privacy: .public)")
    }

    /// Reconcile the crash window described by ``setGating(_:for:newPIN:currentPIN:)``.
    ///
    /// If the marker names gating X, any gating key for Y≠X is stale — the wrapper it opened has
    /// already been replaced — so it is deleted. Only ever removes the *non*-active gating, which
    /// is why this can never brick a vault. Call at launch, per domain.
    ///
    /// - Parameter domainIdentifier: The domain to reconcile.
    public func reconcile(domain domainIdentifier: String) {
        let active = readGating()
        deleteGatingKeys(except: active)
        log.info("🔑 gating reconciled (active \(active.rawValue, privacy: .public))")
    }

    // MARK: - Readiness

    /// Whether a domain's vault is usable, and if not, why.
    ///
    /// The wrapper is authoritative for *existence*; the gating marker only records which
    /// ceremony opens it, so it is deliberately not consulted here.
    ///
    /// - Parameter domainIdentifier: The domain to report on.
    /// - Returns: ``VaultReadiness/ready``, ``VaultReadiness/locked`` or
    ///   ``VaultReadiness/orphaned``.
    public func readiness(for domainIdentifier: String) throws -> VaultReadiness {
        guard try CryptoKeychain.loadWrappedDomainKey(for: domainIdentifier) != nil else {
            // No wrapper: either nothing was ever sealed for this domain (safe), or its root is
            // lost — which, per I5′, orphans this domain and no other.
            return isConfiguredDomain(domainIdentifier) ? .orphaned : .ready
        }
        return isUnlocked(domain: domainIdentifier) ? .ready : .locked
    }

    /// Every configured domain whose `domainKey` wrapper is missing — the unrecoverable ones.
    ///
    /// Per I5′ an orphan is scoped to itself, so the UI names these domains rather than blocking
    /// the whole app. Removing and re-adding each one clears it.
    public static func orphanedDomainIDs() -> [String] {
        SharedConfigStore.shared.allAccounts().keys.filter { domain in
            ((try? CryptoKeychain.loadWrappedDomainKey(for: domain)) ?? nil) == nil
        }
    }

    // MARK: - Domain key material

    /// Provision a domain: mint its `domainKey` and `refreshTokenKey`, seal every leaf under the
    /// `domainKey`, and write the wrapper under the domain's gating key.
    ///
    /// Runs for **every** algorithm, `.plain` included — a `.plain` OneDrive domain still needs a
    /// `domainKey` for its refresh token. The raw DER is never persisted unwrapped beyond the
    /// Provider-readable slot.
    ///
    /// The domain's `fileKeysKEK` (which seals the BC01 header cache) is minted and released here
    /// too. It cannot be deferred to the first unlock: the common case is a domain added while
    /// already unlocked, which will not run an unlock ceremony again for hours — leaving the
    /// Provider-readable slot absent, which the header cache reads as `locked`.
    ///
    /// - Parameters:
    ///   - der: The RSA private key in PKCS#1 DER, or `nil` for a `.plain` domain.
    ///   - domainIdentifier: The domain being provisioned.
    ///   - pin: The PIN to enroll, needed only when `.pin` is the active method and its keypair
    ///     has not been minted yet.
    public func provisionDomain(userIdentityKeyDER der: Data?,
                                for domainIdentifier: String,
                                pin: String? = nil) async throws {
        let key = Self.generateKey()

        if let der {
            try CryptoKeychain.storeWrappedUserIdentityKey(try Self.wrap(der, with: key),
                                                           for: domainIdentifier)
            try CryptoKeychain.storeUnwrappedUserIdentityKey(der, for: domainIdentifier)
        }

        // fileKeysKEK — minted and released in the same pass.
        let kek = Self.generateKey().raw
        try CryptoKeychain.storeWrappedFileKeysKEK(try Self.wrap(kek, with: key),
                                                   for: domainIdentifier)
        try CryptoKeychain.storeUnwrappedFileKeysKEK(kek, for: domainIdentifier)

        // refreshTokenKey — the public half stays in the clear so a rotated token can be sealed
        // while locked, by the Provider or by a locked app.
        let tokenKey = P256.KeyAgreement.PrivateKey()
        try CryptoKeychain.storeWrappedRefreshTokenKey(
            try Self.wrap(tokenKey.rawRepresentation, with: key), for: domainIdentifier)
        try CryptoKeychain.storeRefreshTokenKeyPublic(
            tokenKey.publicKey.x963Representation, for: domainIdentifier)

        // Wrapper last, so a crash leaves an orphan this domain can report rather than a wrapper
        // naming leaves that were never written.
        //
        // Sealing needs only the active method's `.pub`, which is readable at any time — so this
        // runs with no ceremony and no prompt, from a locked vault, for all four methods.
        let method = readGating()
        try await sealDomainKey(key, for: domainIdentifier, method: method, pin: pin)
        log.info("🔑 domain provisioned \(domainIdentifier, privacy: .public) (gating \(method.rawValue, privacy: .public))")
    }

    /// Open a domain's wrapped material into the three Provider-readable slots.
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain being opened.
    ///   - key: That domain's `domainKey`, held only for this call (I3).
    private func populateUnwrappedSlots(for domainIdentifier: String,
                                        domainKey key: SymmetricKey) throws {
        // 1. User identity.
        if let box = try CryptoKeychain.loadWrappedUserIdentityKey(for: domainIdentifier) {
            do {
                try CryptoKeychain.storeUnwrappedUserIdentityKey(try Self.unwrap(box, with: key),
                                                                 for: domainIdentifier)
            } catch VaultKeyStoreError.unwrapFailed {
                // Sealed under a domainKey that no longer exists — unrecoverable, so drop it
                // rather than leave a blob that fails every unlock. The domain must re-provision.
                log.error("❌ unopenable user identity blob for \(domainIdentifier, privacy: .public) — dropping (domain must re-provision)")
                try? CryptoKeychain.deleteWrappedUserIdentityKey(for: domainIdentifier)
            }
        }

        // 2. File-keys KEK. Regenerable, so a failure mints afresh — the rows it sealed are
        //    already unreadable ballast.
        try populateUnwrappedFileKeysKEK(for: domainIdentifier, domainKey: key)

        // 3. Refresh token. **Not** regenerable, unlike the KEK: drop and log, never mint.
        try populateUnwrappedRefreshToken(for: domainIdentifier, domainKey: key)
    }

    /// Open every listed domain that is currently reachable, skipping those still locked.
    ///
    /// Used by the launch-time slot reconcile, where a domain whose ceremony would prompt must
    /// not be forced open. A domain with no wrapper is skipped, not treated as an error.
    ///
    /// - Parameters:
    ///   - domainIdentifiers: The domains to consider.
    ///   - pin: The entered PIN, for `.pin`-gated domains.
    public func populateUnwrappedSlots(for domainIdentifiers: [String],
                                       pin: String? = nil) async throws {
        // One presence evaluation, N domains. `.secure` derives an independent per-domain key
        // from it; the shared three resolve to the same install keypair. One prompt either way.
        let reason = "Unlock your vaults"
        let pending = domainIdentifiers.filter { isProvisioned(domain: $0) }
        // Nothing to open means nothing to prove — never evaluate presence for an empty set.
        guard !pending.isEmpty else { return }
        try await withPresenceContext(for: readGating(), reason: reason) { context in
            for domain in pending {
                do {
                    let key = try await domainKey(for: domain, pin: pin,
                                                  reason: reason, context: context)
                    try populateUnwrappedSlots(for: domain, domainKey: key)
                    // `key` goes out of scope each iteration — I3. No domainKey is carried
                    // across domains, so one vault's material never reaches another's.
                } catch VaultKeyStoreError.locked, VaultKeyStoreError.pinRequired {
                    // Not a failure: this method's contract is to skip domains that would need a
                    // ceremony. Logging these at `.error` made the expected outcome look like a fault.
                    log.debug("slot populate skipped for \(domain, privacy: .public): still locked")
                } catch {
                    log.error("⚠️ slot populate failed for \(domain, privacy: .public): \(String(describing: error), privacy: .public)")
                }
            }
        }
        // The presence token is invalidated here — it cannot be reused to open a vault the user
        // did not ask for.
    }

    /// Unwrap (or, on first unlock, mint) a domain's `fileKeysKEK` into the Provider-readable slot.
    ///
    /// The KEK is an independent random AES-256 value rather than a derivation of the `domainKey`,
    /// so the header cache can be rotated — drop the rows, delete this item, regenerate — without
    /// touching the wrapped user identity DER.
    private func populateUnwrappedFileKeysKEK(for domainIdentifier: String,
                                              domainKey key: SymmetricKey) throws {
        let raw: Data
        if let box = try CryptoKeychain.loadWrappedFileKeysKEK(for: domainIdentifier) {
            do {
                raw = try Self.unwrap(box, with: key)
            } catch {
                log.error("❌ unopenable fileKeysKEK for \(domainIdentifier, privacy: .public) — regenerating")
                raw = Self.generateKey().raw
                try CryptoKeychain.storeWrappedFileKeysKEK(try Self.wrap(raw, with: key),
                                                           for: domainIdentifier)
            }
        } else {
            raw = Self.generateKey().raw
            try CryptoKeychain.storeWrappedFileKeysKEK(try Self.wrap(raw, with: key),
                                                       for: domainIdentifier)
        }
        try CryptoKeychain.storeUnwrappedFileKeysKEK(raw, for: domainIdentifier)
    }

    /// Open the sealed refresh token into the Provider-readable slot, then discard the private key.
    ///
    /// On failure the blob is **dropped and logged, never re-minted** — a refresh token is not
    /// regenerable, so minting a replacement would be minting nonsense. The domain re-authenticates.
    private func populateUnwrappedRefreshToken(for domainIdentifier: String,
                                               domainKey key: SymmetricKey) throws {
        guard let sealed = try CryptoKeychain.loadWrappedRefreshToken(for: domainIdentifier),
              let wrappedKey = try CryptoKeychain.loadWrappedRefreshTokenKey(for: domainIdentifier)
        else { return }
        do {
            let priv = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: try Self.unwrap(wrappedKey, with: key))
            let token = try Self.openSealedToken(sealed, with: priv)
            try CryptoKeychain.storeUnwrappedRefreshToken(token, for: domainIdentifier)
            // `priv` goes out of scope here — I4.
        } catch {
            log.error("❌ unopenable refresh token for \(domainIdentifier, privacy: .public) — dropping (domain must re-authenticate)")
            try? CryptoKeychain.deleteWrappedRefreshToken(for: domainIdentifier)
        }
    }

    // MARK: - Refresh token sealing

    /// Seal a refresh token to a domain's `refreshTokenKey.pub` and write the token slots.
    ///
    /// The **sealed** slot is always written: sealing needs no unlocked state and no `domainKey`,
    /// only the public half. That is what lets the Provider rotate a token while the domain is
    /// locked, and what makes divergence impossible — the same writer updates both slots in one
    /// operation, so the next unlock opens the newest token rather than a long-dead one.
    ///
    /// The **plaintext** slot is *overwritten but never created*. A locked domain has had that slot
    /// deleted deliberately, so re-creating it would leave a readable credential behind a lock the
    /// user asked for — the belt-and-braces guard against a Provider still rotating when lock
    /// sweeps the slots. A rotation that loses that race persists in the sealed slot and surfaces
    /// at the next unlock, so nothing is lost by skipping the write.
    ///
    /// The gate is the **token's own** slot, deliberately not ``isUnlocked(domain:)``: that reads
    /// `fileKeysKEK.unwrapped`, which belongs to the encryption subsystem, and a `.plain` domain
    /// has no file keys to speak of. Only `refreshToken.unwrapped` is guaranteed to exist for every
    /// algorithm, and gating the slot on itself is the one predicate that cannot drift away from
    /// what it guards.
    ///
    /// The one exception is the **first** commit for a domain, where the slot cannot exist yet:
    /// sign-in precedes the domain, so the buffered token is committed just after
    /// provisioning, into a domain that is open but has never held a token. `establishing: true`
    /// says so explicitly rather than inferring it from an absent slot — which is precisely the
    /// state a lock produces, and would defeat the guard.
    ///
    /// - Parameters:
    ///   - token: The refresh token as returned by MSAL.
    ///   - domainIdentifier: The domain the token belongs to.
    ///   - establishing: `true` only for the initial commit that follows provisioning, where the
    ///     plaintext slot is created rather than refreshed. Rotations leave this `false`.
    public func commitRefreshToken(_ token: String,
                                   for domainIdentifier: String,
                                   establishing: Bool = false) throws {
        guard let pubRaw = try CryptoKeychain.loadRefreshTokenKeyPublic(for: domainIdentifier) else {
            throw VaultKeyStoreError.orphanedDomainKeys
        }
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: pubRaw)
        let hasPlaintextSlot = try CryptoKeychain.loadUnwrappedRefreshToken(for: domainIdentifier) != nil
        try CryptoKeychain.storeWrappedRefreshToken(try Self.sealToken(token, to: pub),
                                                    for: domainIdentifier)
        guard establishing || hasPlaintextSlot else {
            log.info("🔒 sealed a rotated token for locked \(domainIdentifier, privacy: .public) — plaintext slot left absent")
            return
        }
        try CryptoKeychain.storeUnwrappedRefreshToken(token, for: domainIdentifier)
    }

    /// ECIES-style seal: a fresh ephemeral P-256 key agreed against `pub`, HKDF to an AES-256 key,
    /// AES-GCM over the token. The ephemeral public key is prefixed to the box so the opener can
    /// reproduce the agreement.
    ///
    /// Hand-rolled rather than `SecKeyCreateEncryptedData` so the same code path works against the
    /// CryptoKit keys used throughout this type, and so it is testable with no keychain at all.
    /// CryptoKit's `HPKE` would be the natural tool but is macOS 14+; the deployment target is 13.
    static func seal(_ plaintext: Data, to pub: P256.KeyAgreement.PublicKey) throws -> Data {
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: pub)
        let ephPub = eph.publicKey.x963Representation
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                 salt: ephPub,
                                                 sharedInfo: Data(),
                                                 outputByteCount: 32)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw VaultKeyStoreError.unwrapFailed }
        return ephPub + combined
    }

    /// Seal a UTF-8 string. The refresh-token spelling of ``seal(_:to:)``.
    static func sealToken(_ token: String, to pub: P256.KeyAgreement.PublicKey) throws -> Data {
        try seal(Data(token.utf8), to: pub)
    }

    /// Open a box produced by ``seal(_:to:)``.
    static func openSealed(_ box: Data, with priv: P256.KeyAgreement.PrivateKey) throws -> Data {
        // An x9.63 P-256 public key is 65 bytes: 0x04 ‖ X(32) ‖ Y(32).
        let ephPubLength = 65
        guard box.count > ephPubLength else { throw VaultKeyStoreError.unwrapFailed }
        let ephPub = box.prefix(ephPubLength)
        let payload = box.suffix(from: box.startIndex + ephPubLength)
        let shared = try priv.sharedSecretFromKeyAgreement(
            with: try P256.KeyAgreement.PublicKey(x963Representation: ephPub))
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                 salt: ephPub,
                                                 sharedInfo: Data(),
                                                 outputByteCount: 32)
        return try AES.GCM.open(try AES.GCM.SealedBox(combined: payload), using: key)
    }

    /// Open a box produced by ``sealToken(_:to:)`` back into a UTF-8 string.
    static func openSealedToken(_ box: Data, with priv: P256.KeyAgreement.PrivateKey) throws -> String {
        guard let token = String(data: try openSealed(box, with: priv), encoding: .utf8) else {
            throw VaultKeyStoreError.unwrapFailed
        }
        return token
    }

    // MARK: - Eviction

    /// Evict the Provider-readable unwrapped slots for **one** domain (per-vault lock primitive).
    ///
    /// The wrapped material is untouched, so the domain reopens on the next unlock without
    /// re-provisioning. Locking one vault must not reach another's slots, which is why this
    /// exists alongside ``evictUnwrappedSlots()``.
    ///
    /// - Parameter domainIdentifier: The domain whose unwrapped slots are being evicted.
    public func evictUnwrappedSlots(for domainIdentifier: String) throws {
        try Self.evictingAll([
            (.userIdentityKey, { try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: domainIdentifier) }),
            (.fileKeysKEK,     { try CryptoKeychain.deleteUnwrappedFileKeysKEK(for: domainIdentifier) }),
            (.refreshToken,    { try CryptoKeychain.deleteUnwrappedRefreshToken(for: domainIdentifier) }),
        ])
    }

    /// Run every eviction, then raise the ones that failed.
    ///
    /// A `try` chain stops at the first throw, which would leave the remaining slots populated —
    /// a locked vault still holding a readable KEK or refresh token, reported as a single failure.
    /// Each deletion is independent and idempotent (an absent slot succeeds), so there is no
    /// reason to let one failure mask the others.
    /// - Parameter evictions: Each deletion, paired with the slot it clears — or `nil` for one
    ///   that exposes no plaintext key material and so is attempted but not reported.
    private static func evictingAll(
        _ evictions: [(UnwrappedSlot?, () throws -> Void)]
    ) throws {
        var survived: [UnwrappedSlot] = []
        for (slot, evict) in evictions {
            do { try evict() } catch { if let slot { survived.append(slot) } }
        }
        guard survived.isEmpty else { throw VaultKeyStoreError.evictionFailed(survived) }
    }

    /// Evict every Provider-readable unwrapped slot (lock primitive). Safe from any App-Group
    /// process — plain `SecItemDelete` on non-ACL items.
    public func evictUnwrappedSlots() throws {
        try Self.evictingAll([
            (.userIdentityKey, { try CryptoKeychain.deleteAllUnwrappedUserIdentityKeys() }),
            // The header cache reads only this slot, so its removal is what stops cache hits once
            // each extension's short key-residency window expires.
            (.fileKeysKEK,     { try CryptoKeychain.deleteAllUnwrappedFileKeysKEKs() }),
            // The token is a credential, not content: locking a `.plain` OneDrive vault stops its
            // Provider, which is intended.
            (.refreshToken,    { try CryptoKeychain.deleteAllUnwrappedRefreshTokens() }),
        ])
    }

    /// Remove a domain's key material entirely (deprovisioning).
    ///
    /// Deletes every slot **scoped to this domain**, unconditionally: its `domainKey` wrapper,
    /// its leaves, and — because `.secure` is the one per-domain method — its `.secure` gating
    /// triple. Per I5′ each of those names this domain alone, so no sibling survey is needed.
    ///
    /// The install-wide triples (`.none`, `.pin`, `.biometric`) are deliberately **not** touched:
    /// they are shared by every remaining domain and are retired only by ``setGating(_:newPIN:currentPIN:)``.
    public func forgetDomain(_ domainIdentifier: String) throws {
        CryptoKeychain.deleteGatingTriple(.secure, domain: domainIdentifier)
        // Best-effort across the whole set, for the reason ``evictingAll(_:)`` documents: a `try`
        // chain that threw on the `domainKey` wrapper used to strand all three *unwrapped* slots,
        // leaving plaintext key material behind for a domain the user had torn down. Only those
        // three carry that exposure, so only they are named in the failure; the sealed slots and
        // the two non-secret ones are unreachable residue once the wrapper is gone.
        try Self.evictingAll([
            (.userIdentityKey, { try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: domainIdentifier) }),
            (.fileKeysKEK,     { try CryptoKeychain.deleteUnwrappedFileKeysKEK(for: domainIdentifier) }),
            (.refreshToken,    { try CryptoKeychain.deleteUnwrappedRefreshToken(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteWrappedDomainKey(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteWrappedUserIdentityKey(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteWrappedFileKeysKEK(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteWrappedRefreshTokenKey(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteRefreshTokenKeyPublic(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteWrappedRefreshToken(for: domainIdentifier) }),
            // The public key and user ID are written alongside the sealed material by
            // `CryptoConfigViewModel.store(_:for:keyStore:)`. Forgetting a domain must be the
            // exact inverse of provisioning it, or every teardown leaks two items per domain.
            (nil, { try CryptoKeychain.deleteUserIdentityPublicKey(for: domainIdentifier) }),
            (nil, { try CryptoKeychain.deleteUserId(for: domainIdentifier) }),
        ])
    }
}

#if DEBUG
public extension VaultKeyStore {
    /// A key store whose gating is `.none`, backed by an in-process gating marker.
    ///
    /// Test fixtures provision domains against the real keychain but must neither read nor
    /// disturb the user's actual per-domain gating settings — and `.pin`/`.biometric` gating
    /// cannot be minted without a PIN or a Touch ID prompt, so a suite using ``shared`` would
    /// fail or prompt depending on whoever ran it last.
    ///
    /// Per I5′ the `.none` gating keypair is install-wide, so it is minted here on this run's own
    /// namespace behind an in-memory `.params` stand-in; each domain's `domainKey` is still minted
    /// at provisioning and sealed to that keypair's public half.
    ///
    /// - Important: The domain slots this store writes are real keychain items on whatever names
    ///   ``CryptoKeychain/serviceNamespace`` is currently set to — the production ones unless a
    ///   test moved them aside. Suites that provision a domain must subclass
    ///   `KeychainIsolatedTestCase` (or otherwise install a test namespace), or they write the
    ///   developer's live keychain.
    ///
    /// - Returns: A store with in-process gating state.
    static func isolatedForTesting() -> VaultKeyStore {
        isolatedForTesting(gatings: GatingBox())
    }

    /// As ``isolatedForTesting()``, over a caller-supplied box so a test can set the install's
    /// method and register domains.
    static func isolatedForTesting(gatings: GatingBox) -> VaultKeyStore {
        // The device gating key is held in memory rather than in the keychain: its slot needs
        // `kSecUseDataProtectionKeychain`, whose app-identifier entitlement a test bundle with
        // no host application does not carry (`errSecMissingEntitlement`, -34018). Everything
        // *below* the gating key — every wrapper and leaf this store writes — is a real keychain
        // item on the current namespace, so the wrapping under test is genuinely exercised.
        let deviceKey = DeviceKeyBox()
        // `.biometric` params are held in memory behind a stub gate: the real slot needs an
        // app-identifier entitlement a test bundle lacks, and evaluating a real `LAContext` would
        // raise a Touch ID prompt no unattended suite can satisfy.
        let biometricKey = DeviceKeyBox()
        return VaultKeyStore(gate: StubBiometricGate(),
                             secureGate: StubSecureEnclaveGate(),
                             readGating: { gatings.value },
                             writeGating: { gatings.set($0) },
                             isConfiguredDomain: { gatings.contains($0) },
                             allDomainIdentifiers: { gatings.all },
                             readDeviceGatingKey: { deviceKey.value },
                             writeDeviceGatingKey: { deviceKey.value = $0 },
                             deleteDeviceGatingKey: { deviceKey.value = nil },
                             readBiometricGatingKey: { _ in biometricKey.value },
                             writeBiometricGatingKey: { raw, _ in biometricKey.value = raw },
                             deleteBiometricGatingKey: { biometricKey.value = nil })
    }

    /// The in-memory stand-in for the `vault.gating.none.params` slot.
    final class DeviceKeyBox: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: Data?
        var value: Data? {
            get { lock.lock(); defer { lock.unlock() }; return storage }
            set { lock.lock(); defer { lock.unlock() }; storage = newValue }
        }
    }

    /// In-process per-domain gating markers, standing in for `SharedConfig`.
    /// The in-process stand-in for `SharedConfig.vaultGating` plus the configured domain set.
    ///
    /// Install-wide, matching production: one method, many domains.
    final class GatingBox: @unchecked Sendable {
        private let lock = NSLock()
        private var method: SharedConfig.VaultGating = .none
        private var domains: Set<String> = []
        var value: SharedConfig.VaultGating {
            lock.lock(); defer { lock.unlock() }
            return method
        }
        func set(_ gating: SharedConfig.VaultGating) {
            lock.lock(); defer { lock.unlock() }
            method = gating
        }
        /// Register a domain as configured, so the re-seal and orphan surveys can see it.
        func register(_ domain: String) {
            lock.lock(); defer { lock.unlock() }
            domains.insert(domain)
        }
        func contains(_ domain: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return domains.contains(domain)
        }
        var all: [String] {
            lock.lock(); defer { lock.unlock() }
            return Array(domains)
        }
    }

    /// A ``BiometricGate`` that reports available and hands back no context, so `.biometric` is
    /// exercisable with no hardware and — critically — no prompt in an unattended suite.
    struct StubBiometricGate: BiometricGate {
        public var isAvailable: Bool { true }
        public func authenticate(reason: String) async throws {}
        public func authenticatedContext(reason: String) async throws -> AnyObject? { nil }
    }

    /// A ``SecureEnclaveGate`` backed by an in-process P-256 key, so `.secure` is exercisable on
    /// machines with no enclave and with no Touch ID prompt.
    final class StubSecureEnclaveGate: SecureEnclaveGate, @unchecked Sendable {
        private let priv = P256.KeyAgreement.PrivateKey()
        public var isAvailable: Bool { true }
        public func enrollEphemeral() throws -> SecureEnclaveEnrollment {
            let eph = P256.KeyAgreement.PrivateKey()
            let shared = try eph.sharedSecretFromKeyAgreement(with: priv.publicKey)
            return SecureEnclaveEnrollment(
                ephemeralPublicKey: eph.publicKey.x963Representation,
                sharedSecret: shared.withUnsafeBytes { Data($0) })
        }
        public func agree(withEphemeralPublicKey ephemeralPublicKey: Data,
                          reason: String, context: AnyObject?) throws -> Data {
            let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
            return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
        }
    }
}
#endif

extension SymmetricKey {
    /// The key's raw bytes. Shared with the ``GatingCeremony`` conformances.
    var raw: Data { withUnsafeBytes { Data($0) } }
}
