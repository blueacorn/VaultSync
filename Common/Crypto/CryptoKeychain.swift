/// App Group keychain storage for the vault's key material.
///
/// Two families of slot live here, and the service names keep them apart:
///
/// * `vault.*` — the gating keys. One per install for `.none`, `.biometric` and `.pin`; the
///   `.secure` ephemeral public key is `vault.`-prefixed but keyed **per domain**, because the
///   Secure Enclave key is install-wide while the ephemeral agreed against it is not.
/// * `domain.*` — keyed by File Provider domain identifier. Each domain's own `domainKey`
///   (sealed under its gating key) and the three leaf secrets sealed under that: the user
///   identity RSA key, the file-keys KEK and the OneDrive refresh-token key. The public DER,
///   user ID and refresh-token public key are not secret and stay in the clear so the encrypt
///   and token-seal paths keep working while locked.
///
/// ```
/// gating key[d] ─AES-GCM─▶ domain.domainKey.wrapped[d] ─domainKey[d]─▶ userIdentityKey.wrapped
///                                                                 ├──▶ fileKeysKEK.wrapped
///                                                                 └──▶ refreshTokenKey.wrapped
/// unlock: domainKey opens all three into the `*.unwrapped` slots the sandboxed Provider reads.
/// lock:   delete the `*.unwrapped` slots — absent means locked, unconditionally.
/// ```
///
/// There is **no install-wide key** — every wrapping key is scoped to exactly one domain, so a
/// captured key reaches exactly one vault. There is no slot holding a secret in the clear at
/// rest: the `*.unwrapped` slots exist only between an unlock and the next lock, and are the
/// entire app→Provider channel.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Security

public struct CryptoKeychain {
    // MARK: - Test isolation

    /// Prefix applied to every `kSecAttrService` this type addresses.
    ///
    /// Empty in production, so the slot names are exactly the constants below. Tests that must
    /// exercise the real App Group keychain (the vault slots cannot be written from a bundle with
    /// no host application) set this to a unique value, which moves every read, write and delete
    /// onto slots of their own. Without it a suite's setup/teardown deletes the developer's live
    /// gating keys — the `vault.*` slots are one-per-install and otherwise shared.
    ///
    /// Not thread-safe by design: set it once, before the items under test are touched.
    public enum ServiceNamespace: Equatable {
        /// The real slots, named exactly as the constants below. Prefixing these would rename
        /// every item and orphan the material already stored under the current names.
        case production
        /// Slots private to one test run.
        case isolated(String)

        /// The prefix to apply, or `nil` for the unprefixed production names.
        var prefix: String? {
            switch self {
            case .production: nil
            case .isolated(let token): token
            }
        }
    }

    nonisolated(unsafe) public static var serviceNamespace: ServiceNamespace = .production

    /// Applies ``serviceNamespace`` to a service name. Every `kSecAttrService` passes through here.
    static func namespaced(_ service: String) -> String {
        guard let prefix = serviceNamespace.prefix else { return service }
        return "\(prefix).\(service)"
    }

    #if DEBUG
    /// Moves every slot this type addresses onto names private to one test run, and returns the
    /// namespace that was in force so a suite's teardown can restore it.
    ///
    /// Prefer ``XCTestCase`` teardown over calling this directly: the namespace is process-wide
    /// static state, so a suite that installs one and does not restore it silently redirects
    /// every later suite in the same process.
    @discardableResult
    public static func installTestNamespace(_ token: String = UUID().uuidString) -> ServiceNamespace {
        let previous = serviceNamespace
        let isolated = ServiceNamespace.isolated("test.\(token)")
        serviceNamespace = isolated
        return previous
    }

    /// Restores both namespaces this type's test hook moves.
    public static func restoreNamespace(_ namespace: ServiceNamespace) {
        // Purge before restoring, while the queries below still resolve to the isolated names.
        // A test namespace is per-run and never revisited, so anything left under it is
        // unreachable residue that accumulates one item per suite, per run.
        purgeCurrentTestNamespace()
        serviceNamespace = namespace
    }

    /// Deletes every item written under the active isolated namespace. A no-op in production —
    /// this must never be able to touch the real slots.
    static func purgeCurrentTestNamespace() {
        guard serviceNamespace.prefix != nil else { return }
        let services = [
            domainKeyWrappedService,
            wrappedService, unwrappedService, pubService, uidService,
            wrappedFileKeysKEKService, unwrappedFileKeysKEKService,
            refreshTokenKeyWrappedService, refreshTokenKeyPubService,
            wrappedRefreshTokenService, unwrappedRefreshTokenService,
        ]
        for service in services {
            // Account-less: removes every account under the service, across all test domains.
            try? delete(service: service, account: nil)
        }
        // The gating triple exists once per method; `.secure`'s is keyed per domain, which the
        // account-less delete above also covers.
        for method in SharedConfig.VaultGating.allCases {
            for service in [gatingPubService(method),
                            gatingWrappedService(method),
                            gatingParamsService(method)] {
                try? delete(service: service, account: nil)
            }
        }
    }
    #endif

    // MARK: - Service names

    /// The gating keypair for method `<m>` — exactly one method is active at a time.
    ///
    /// `.pub` seals every domain's `domainKey` and is **not** secret: sealing needs no ceremony, so
    /// a domain can be added while the vault is locked. `.wrapped` is the private half, sealed under
    /// whatever `.params` describes.
    ///
    /// - Important: `.none`, `.pin` and `.biometric` use account ``gatingSharedAccount`` (one
    ///   keypair per install). `.secure` uses account = domain identifier (one keypair per domain)
    ///   — that per-domain isolation is what `.secure` means. Resolve it with
    ///   ``gatingAccount(_:domain:)``; never assume.
    static func gatingPubService(_ m: SharedConfig.VaultGating) -> String {
        "org.vaultsync.VaultSync.vault.gating.\(m.rawValue).pub"
    }

    static func gatingWrappedService(_ m: SharedConfig.VaultGating) -> String {
        "org.vaultsync.VaultSync.vault.gating.\(m.rawValue).wrapped"
    }

    /// How to open `<m>.wrapped` — the only slot that differs between methods. For `.pin` and
    /// `.secure` these are non-secret inputs (PBKDF2 parameters; an ephemeral public key). For
    /// `.none` and `.biometric` this slot holds the unwrapping key **itself**, protected only by
    /// the item's own access policy. Never log it.
    static func gatingParamsService(_ m: SharedConfig.VaultGating) -> String {
        "org.vaultsync.VaultSync.vault.gating.\(m.rawValue).params"
    }

    /// Fixed account for the install-wide gating slots (`.none`, `.pin`, `.biometric`).
    static let gatingSharedAccount = "vault"

    /// The account for method `<m>`: ``gatingSharedAccount`` for the shared three,
    /// `domainIdentifier` for `.secure`.
    ///
    /// One rule, one exception, stated in code rather than implied at each call site — a caller
    /// reading a `.secure` slot under the shared account would silently miss every per-domain
    /// keypair.
    static func gatingAccount(_ m: SharedConfig.VaultGating, domain: String) -> String {
        m == .secure ? domain : gatingSharedAccount
    }

    /// A domain's `domainKey`, sealed under that domain's gating key (AES-256-GCM combined box).
    /// The root of one domain's key graph — there is no key above it and none shared with any
    /// other domain.
    static let domainKeyWrappedService = "org.vaultsync.VaultSync.domain.domainKey.wrapped"

    /// `domainKey`-wrapped user identity DER (AES-GCM box). Persists across lock; unusable
    /// without that domain's `domainKey`.
    static let wrappedService     = "org.vaultsync.VaultSync.domain.userIdentityKey.wrapped"
    /// Unwrapped user identity DER made readable to the sandboxed Provider while unlocked. Deleting
    /// this slot is the cross-process lock primitive (see ``VaultLockController``).
    static let unwrappedService   = "org.vaultsync.VaultSync.domain.userIdentityKey.unwrapped"
    /// RSA public DER — not secret, readable while locked so encryption keeps working.
    private static let pubService = "org.vaultsync.VaultSync.domain.userIdentityKey.pub"
    /// The user owning the RSA key pair — a non-secret identifier.
    private static let uidService = "org.vaultsync.VaultSync.domain.userIdentityKey.userId"
    /// Per-domain file-keys KEK, wrapped under the domain's `domainKey`. Ciphertext, so no ACL is needed;
    /// persists across lock like ``wrappedService``. Seals the BC01 header cache's key material.
    static let wrappedFileKeysKEKService   = "org.vaultsync.VaultSync.domain.fileKeysKEK.wrapped"
    /// Per-domain file-keys KEK in the clear, readable by the sandboxed Provider while unlocked.
    /// Deleting this slot is what makes vault lock reach the extension's BC01 header cache.
    static let unwrappedFileKeysKEKService = "org.vaultsync.VaultSync.domain.fileKeysKEK.unwrapped"
    /// The domain's OneDrive refresh-token P-256 **private** key, sealed under its `domainKey`.
    static let refreshTokenKeyWrappedService = "org.vaultsync.VaultSync.domain.refreshTokenKey.wrapped"
    /// The matching P-256 **public** key, in the clear. Not secret, and deliberately readable
    /// while locked: sealing a rotated token needs only the public half, so the Provider (and a
    /// locked app) can re-seal holding nothing readable.
    static let refreshTokenKeyPubService = "org.vaultsync.VaultSync.domain.refreshTokenKey.pub"
    /// The refresh token, ECIES-sealed to ``refreshTokenKeyPubService``. Written by whichever
    /// process rotates the token — app or Provider, locked or not.
    static let wrappedRefreshTokenService = "org.vaultsync.VaultSync.domain.refreshToken.wrapped"
    /// The refresh token in the clear, readable by the sandboxed Provider while unlocked.
    static let unwrappedRefreshTokenService = "org.vaultsync.VaultSync.domain.refreshToken.unwrapped"
    private static let appGroup   = AppIdentifiers.appGroupID

    /// The access group to pin queries to, or `nil` to leave the item in the caller's own group.
    ///
    /// Under an isolated namespace this is `nil`: a test bundle with no host application does not
    /// carry the App Group entitlement, so pinning it makes every data-protection write fail with
    /// `errSecMissingEntitlement` and every legacy write land in the login keychain unowned —
    /// which is how the `com.test.*` residue accumulated. Dropping the pin keeps isolated items
    /// in the test process's own group, where they are writable and disposable.
    private static var accessGroup: String? {
        serviceNamespace.prefix == nil ? appGroup : nil
    }

    /// Applies ``accessGroup`` to a query, omitting the key entirely when there is none, and
    /// pins the query to the **data-protection keychain**.
    ///
    /// On macOS `SecItem*` defaults to the legacy file-based keychain, where items carry a
    /// `SecACL` naming the code-signing identity that wrote them. A slot written under one
    /// signature then rejects this process's `SecItemDelete` with `errSecInvalidOwnerEdit`
    /// (-25244) — which is how an unwrapped slot survived vault lock while every *write* went on
    /// succeeding (``upsert(service:account:data:)`` falls back to `SecItemUpdate`). Only the
    /// data-protection keychain honours ``accessGroup`` and `kSecAttrAccessible`, so it is also
    /// the only one that genuinely shares these slots with `Provider.appex`.
    ///
    /// The flag rides with ``accessGroup``: under an isolated namespace there is no App Group
    /// entitlement, and pinning the data-protection keychain without one fails every write with
    /// `errSecMissingEntitlement`.
    private static func scoped(_ query: [String: Any]) -> [String: Any] {
        guard let accessGroup else { return query }
        var q = query
        q[kSecAttrAccessGroup as String] = accessGroup
        q[kSecUseDataProtectionKeychain as String] = true
        return q
    }

    public enum KeychainError: Error {
        case storeFailed(OSStatus)
        case loadFailed(OSStatus)
        case invalidKey
    }

    // MARK: - Domain key wrapper (one per domain)

    /// Read a domain's sealed `domainKey`, or `nil` when the domain has never been provisioned.
    public static func loadWrappedDomainKey(for domainIdentifier: String) throws -> Data? {
        try loadData(service: domainKeyWrappedService, account: domainIdentifier)
    }

    /// Persist a domain's sealed `domainKey`, replacing any existing wrapper.
    public static func storeWrappedDomainKey(_ box: Data, for domainIdentifier: String) throws {
        try upsert(service: domainKeyWrappedService, account: domainIdentifier, data: box)
    }

    /// Remove a domain's `domainKey` wrapper. Destroys access to **that domain's** leaf secrets
    /// and no others — see ``VaultKeyStore``.
    public static func deleteWrappedDomainKey(for domainIdentifier: String) throws {
        try delete(service: domainKeyWrappedService, account: domainIdentifier)
    }

    // MARK: - Gating keypair (`.pub` / `.wrapped`)

    /// Read the gating **public** key for `method`, or `nil` when the method is not enrolled.
    ///
    /// Never guarded: this is the half that seals a new domain's `domainKey`, so it must be
    /// readable while the vault is locked.
    public static func loadGatingPublicKey(_ method: SharedConfig.VaultGating,
                                           domain: String) throws -> Data? {
        try loadData(service: gatingPubService(method),
                     account: gatingAccount(method, domain: domain))
    }

    /// Persist the gating public key for `method`.
    public static func storeGatingPublicKey(_ pub: Data, method: SharedConfig.VaultGating,
                                            domain: String) throws {
        try upsert(service: gatingPubService(method),
                   account: gatingAccount(method, domain: domain), data: pub)
    }

    /// Read the sealed gating **private** key for `method`, or `nil` when absent.
    public static func loadGatingWrappedKey(_ method: SharedConfig.VaultGating,
                                            domain: String) throws -> Data? {
        try loadData(service: gatingWrappedService(method),
                     account: gatingAccount(method, domain: domain))
    }

    /// Persist the sealed gating private key for `method`. Ciphertext, so no ACL is needed —
    /// what guards it is whatever `.params` describes.
    public static func storeGatingWrappedKey(_ box: Data, method: SharedConfig.VaultGating,
                                             domain: String) throws {
        try upsert(service: gatingWrappedService(method),
                   account: gatingAccount(method, domain: domain), data: box)
    }

    /// Remove one method's whole triple for `domain` — `.pub`, `.wrapped` and `.params`.
    ///
    /// Idempotent: absence is not an error. For the shared three the caller must first establish
    /// that no other domain is still gated onto the method (see `VaultKeyStore`).
    public static func deleteGatingTriple(_ method: SharedConfig.VaultGating,
                                          domain: String) {
        let account = gatingAccount(method, domain: domain)
        // `.pub` and `.wrapped` are plain items written by `upsert`, so they must be deleted by
        // the matching plain query — `deleteGatingKey` pins `kSecUseDataProtectionKeychain` and
        // would not match them. Only `.biometric`'s params live behind that flag.
        try? delete(service: gatingPubService(method), account: account)
        try? delete(service: gatingWrappedService(method), account: account)
        if method == .biometric {
            deleteGatingKey(service: gatingParamsService(method), account: account)
        } else {
            try? delete(service: gatingParamsService(method), account: account)
        }
    }

    // MARK: - Gating params (`.params`)

    /// Read `<m>.params`, or `nil` when absent or not readable without a prompt.
    ///
    /// Only `.biometric` stores its params behind a `SecAccessControl`, so only it needs the
    /// data-protection query with its `LAContext` binding. The others are plain items — routing
    /// them through the guarded path would demand an app-identifier entitlement a test bundle
    /// with no host application does not carry (`errSecMissingEntitlement`).
    ///
    /// - Parameter context: An evaluated `LAContext` for `.biometric`, or `nil` for a silent read.
    public static func loadGatingParams(_ method: SharedConfig.VaultGating,
                                        domain: String,
                                        context: AnyObject? = nil) throws -> Data? {
        let account = gatingAccount(method, domain: domain)
        guard method == .biometric else {
            return try loadData(service: gatingParamsService(method), account: account)
        }
        return try loadGatingKey(service: gatingParamsService(method),
                                 account: account, context: context)
    }

    /// Write `<m>.params`, replacing any existing item.
    ///
    /// - Parameters:
    ///   - access: The `SecAccessControl` for `.biometric`; `nil` writes an unguarded item at
    ///     `AfterFirstUnlockThisDeviceOnly`.
    ///   - context: The evaluated `LAContext` an ACL'd write is bound to.
    public static func storeGatingParams(_ raw: Data, method: SharedConfig.VaultGating,
                                         domain: String,
                                         access: SecAccessControl? = nil,
                                         context: AnyObject? = nil) throws {
        let account = gatingAccount(method, domain: domain)
        // Unguarded params are plain items — see ``loadGatingParams(_:domain:context:)``.
        guard access != nil else {
            try upsert(service: gatingParamsService(method), account: account, data: raw)
            return
        }
        try storeGatingKey(raw, service: gatingParamsService(method), account: account,
                           access: access, context: context)
    }

    /// The stored ``PINRecord`` — `.pin`'s `.params` — or `nil` when PIN gating is not enrolled.
    public static func vaultPINRecord() -> PINRecord? {
        guard let data = ((try? loadGatingParams(.pin, domain: gatingSharedAccount)) ?? nil) else {
            return nil
        }
        return try? JSONDecoder().decode(PINRecord.self, from: data)
    }

    /// Persist the PIN derivation parameters, or remove them when `record` is `nil`.
    public static func storeVaultPINRecord(_ record: PINRecord?) throws {
        guard let record else {
            try? delete(service: gatingParamsService(.pin), account: gatingSharedAccount)
            return
        }
        try storeGatingParams(try JSONEncoder().encode(record),
                              method: .pin, domain: gatingSharedAccount)
    }

    // MARK: - Gating key slots

    /// Read a raw gating key. `context` binds an evaluated `LAContext` for the biometric item;
    /// without one, a gated item is read with `kSecUseAuthenticationUISkip` so no caller can
    /// accidentally surface a prompt — it reports not-found instead.
    ///
    /// - Parameters:
    ///   - service: A ``gatingParamsService(_:)`` slot.
    ///   - account: The matching account — see ``gatingAccount(_:domain:)``.
    ///   - context: An evaluated `LAContext`, or `nil` for a silent read.
    /// - Returns: The 32 raw bytes, or `nil` when absent or not readable without a prompt.
    static func loadGatingKey(service: String, account: String,
                              context: AnyObject?) throws -> Data? {
        var query: [String: Any] = scoped([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespaced(service),
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
        ])
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        } else {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound || status == errSecInteractionNotAllowed { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.loadFailed(status)
        }
        return data
    }

    /// Write a gating key, replacing any existing item at that slot.
    ///
    /// `access` carries the `SecAccessControl` for the biometric item (with `context` the
    /// evaluated `LAContext` the write is bound to); passing `nil` writes the unguarded device
    /// item at `AfterFirstUnlockThisDeviceOnly`.
    static func storeGatingKey(_ raw: Data, service: String, account: String,
                               access: SecAccessControl?, context: AnyObject?) throws {
        let base: [String: Any] = scoped([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespaced(service),
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ])
        SecItemDelete(base as CFDictionary)

        var add = base
        add[kSecValueData as String] = raw
        if let access {
            add[kSecAttrAccessControl as String] = access
            if let context { add[kSecUseAuthenticationContext as String] = context }
        } else {
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.storeFailed(status) }
    }

    /// Delete a gating key slot. Never throws on absence — deletion is idempotent.
    @discardableResult
    static func deleteGatingKey(service: String, account: String) -> OSStatus {
        let query: [String: Any] = scoped([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespaced(service),
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ])
        return SecItemDelete(query as CFDictionary)
    }

    // MARK: - Wrapped / unwrapped user identity slots

    /// Store the `domainKey`-wrapped user identity DER (AES-GCM combined box). Survives lock.
    public static func storeWrappedUserIdentityKey(_ box: Data, for domainIdentifier: String) throws {
        try upsert(service: wrappedService, account: domainIdentifier, data: box)
    }

    /// Load the KEK-wrapped user identity DER, or nil if not enrolled.
    public static func loadWrappedUserIdentityKey(for domainIdentifier: String) throws -> Data? {
        try loadData(service: wrappedService, account: domainIdentifier)
    }

    public static func deleteWrappedUserIdentityKey(for domainIdentifier: String) throws {
        try delete(service: wrappedService, account: domainIdentifier)
    }

    /// Store the unwrapped user identity DER in the Provider-readable slot (unlock).
    public static func storeUnwrappedUserIdentityKey(_ der: Data, for domainIdentifier: String) throws {
        try upsert(service: unwrappedService, account: domainIdentifier, data: der)
    }

    /// Load the user identity private key as a `SecKey` for the decrypt path.
    ///
    /// Reads the `unwrapped` slot **only**. There is no steady-state slot holding the DER in the
    /// clear: the key lives wrapped under the domain's `domainKey`, and unlock is what places it
    /// here. **Absent ⇒ locked**, unconditionally, and `nil` is the correct answer — the encrypt
    /// path is unaffected because it uses the public key from its own slot.
    public static func loadUserIdentityPrivateKey(for domainIdentifier: String) throws -> SecKey? {
        guard let der = try loadData(service: unwrappedService, account: domainIdentifier)
        else { return nil }
        return try importRSAPrivateKey(der)
    }

    /// The unwrapped user identity DER as raw bytes, or `nil` while locked.
    ///
    /// The `SecKey` form is what the decrypt path wants; this is for callers that need the DER
    /// itself (re-wrapping, and the crypto test fixtures).
    public static func loadUnwrappedUserIdentityKeyDER(for domainIdentifier: String) throws -> Data? {
        try loadData(service: unwrappedService, account: domainIdentifier)
    }

    /// Evict a domain's unwrapped user identity slot (per-domain lock primitive; Provider-safe).
    public static func deleteUnwrappedUserIdentityKey(for domainIdentifier: String) throws {
        try delete(service: unwrappedService, account: domainIdentifier)
    }

    // MARK: - File-keys KEK slots (BC01 header cache)

    /// Store the `domainKey`-wrapped `fileKeysKEK` for a domain. Survives lock.
    public static func storeWrappedFileKeysKEK(_ box: Data, for domainIdentifier: String) throws {
        try upsert(service: wrappedFileKeysKEKService, account: domainIdentifier, data: box)
    }

    /// Load the wrapped `fileKeysKEK`, or `nil` when the domain has none yet.
    public static func loadWrappedFileKeysKEK(for domainIdentifier: String) throws -> Data? {
        try loadData(service: wrappedFileKeysKEKService, account: domainIdentifier)
    }

    public static func deleteWrappedFileKeysKEK(for domainIdentifier: String) throws {
        try delete(service: wrappedFileKeysKEKService, account: domainIdentifier)
    }

    /// Store the unwrapped `fileKeysKEK` in the Provider-readable slot (unlock).
    public static func storeUnwrappedFileKeysKEK(_ raw: Data, for domainIdentifier: String) throws {
        try upsert(service: unwrappedFileKeysKEKService, account: domainIdentifier, data: raw)
    }

    /// Load the unwrapped `fileKeysKEK` for a domain, or `nil` when the slot is absent.
    ///
    /// An absent slot is the lock signal: the app evicts it on lock, and the extension learns of
    /// the lock by this read returning `nil`. Mirrors ``loadUserIdentityPrivateKey(for:)`` — the unwrapped
    /// slot is the only slot the Provider ever reads.
    public static func loadUnwrappedFileKeysKEK(for domainIdentifier: String) throws -> Data? {
        try loadData(service: unwrappedFileKeysKEKService, account: domainIdentifier)
    }

    public static func deleteUnwrappedFileKeysKEK(for domainIdentifier: String) throws {
        try delete(service: unwrappedFileKeysKEKService, account: domainIdentifier)
    }

    /// Delete every unwrapped `fileKeysKEK` slot across all domains — the global lock primitive
    /// for the header cache, alongside ``deleteAllUnwrappedUserIdentityKeys()``.
    public static func deleteAllUnwrappedFileKeysKEKs() throws {
        try delete(service: unwrappedFileKeysKEKService, account: nil)
    }

    // MARK: - Refresh-token slots

    /// Store the `domainKey`-wrapped refresh-token P-256 private key. Survives lock.
    public static func storeWrappedRefreshTokenKey(_ box: Data, for domainIdentifier: String) throws {
        try upsert(service: refreshTokenKeyWrappedService, account: domainIdentifier, data: box)
    }

    /// Load the wrapped refresh-token private key, or `nil` when the domain has none.
    public static func loadWrappedRefreshTokenKey(for domainIdentifier: String) throws -> Data? {
        try loadData(service: refreshTokenKeyWrappedService, account: domainIdentifier)
    }

    public static func deleteWrappedRefreshTokenKey(for domainIdentifier: String) throws {
        try delete(service: refreshTokenKeyWrappedService, account: domainIdentifier)
    }

    /// Store the refresh-token P-256 public key (x9.63 representation). Not secret.
    public static func storeRefreshTokenKeyPublic(_ raw: Data, for domainIdentifier: String) throws {
        try upsert(service: refreshTokenKeyPubService, account: domainIdentifier, data: raw)
    }

    /// Load the refresh-token public key, or `nil` when the domain has none.
    ///
    /// Readable while locked by design — sealing a rotated token needs only this half, which is
    /// what lets the Provider re-seal without ever holding an unlocked wrapping key.
    public static func loadRefreshTokenKeyPublic(for domainIdentifier: String) throws -> Data? {
        try loadData(service: refreshTokenKeyPubService, account: domainIdentifier)
    }

    public static func deleteRefreshTokenKeyPublic(for domainIdentifier: String) throws {
        try delete(service: refreshTokenKeyPubService, account: domainIdentifier)
    }

    /// Store the ECIES-sealed refresh token. Written on every rotation, by any process.
    public static func storeWrappedRefreshToken(_ box: Data, for domainIdentifier: String) throws {
        try upsert(service: wrappedRefreshTokenService, account: domainIdentifier, data: box)
    }

    /// Load the sealed refresh token, or `nil` when the domain has never authenticated.
    public static func loadWrappedRefreshToken(for domainIdentifier: String) throws -> Data? {
        try loadData(service: wrappedRefreshTokenService, account: domainIdentifier)
    }

    public static func deleteWrappedRefreshToken(for domainIdentifier: String) throws {
        try delete(service: wrappedRefreshTokenService, account: domainIdentifier)
    }

    /// Store the refresh token in the Provider-readable slot (unlock, and every rotation).
    public static func storeUnwrappedRefreshToken(_ token: String, for domainIdentifier: String) throws {
        try upsert(service: unwrappedRefreshTokenService, account: domainIdentifier,
                   data: Data(token.utf8))
    }

    /// Load the refresh token from the Provider-readable slot, or `nil` when the slot is absent.
    ///
    /// **Absent ⇒ locked** (or never authenticated), exactly as with
    /// ``loadUnwrappedFileKeysKEK(for:)``. The Provider reads this slot and no other.
    public static func loadUnwrappedRefreshToken(for domainIdentifier: String) throws -> String? {
        guard let data = try loadData(service: unwrappedRefreshTokenService, account: domainIdentifier)
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func deleteUnwrappedRefreshToken(for domainIdentifier: String) throws {
        try delete(service: unwrappedRefreshTokenService, account: domainIdentifier)
    }

    /// Delete every unwrapped refresh-token slot across all domains — the global lock primitive
    /// for OAuth credentials, alongside ``deleteAllUnwrappedUserIdentityKeys()`` and
    /// ``deleteAllUnwrappedFileKeysKEKs()``.
    public static func deleteAllUnwrappedRefreshTokens() throws {
        try delete(service: unwrappedRefreshTokenService, account: nil)
    }

    // MARK: - Public key

    /// Stores raw DER bytes of the RSA public key in the App Group keychain.
    public static func storeUserIdentityPublicKey(_ rsaPublicKeyDER: Data, for domainIdentifier: String) throws {
        try upsert(service: pubService, account: domainIdentifier, data: rsaPublicKeyDER)
    }

    /// Returns the RSA public key, or nil if not yet stored.
    public static func loadUserIdentityPublicKey(for domainIdentifier: String) throws -> SecKey? {
        let query: [String: Any] = scoped([
            kSecClass as String:         kSecClassGenericPassword,
            kSecAttrService as String:   namespaced(pubService),
            kSecAttrAccount as String:   domainIdentifier,
            kSecReturnData as String:    true,
        ])
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let der = result as? Data else {
            throw KeychainError.loadFailed(status)
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:  kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? KeychainError.invalidKey
        }
        return key
    }

    public static func deleteUserIdentityPublicKey(for domainIdentifier: String) throws {
        let query: [String: Any] = scoped([
            kSecClass as String:         kSecClassGenericPassword,
            kSecAttrService as String:   namespaced(pubService),
            kSecAttrAccount as String:   domainIdentifier,
        ])
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.storeFailed(status)
        }
    }

    // MARK: - User ID

    /// Stores the first user ID from the `.bckey` in the App Group keychain.
    public static func storeUserId(_ userID: String, for domainIdentifier: String) throws {
        try upsert(service: uidService, account: domainIdentifier, data: Data(userID.utf8))
    }

    /// Removes the stored user ID. Part of the domain-forget set, so provisioning leaves
    /// nothing behind once a domain is torn down.
    public static func deleteUserId(for domainIdentifier: String) throws {
        try delete(service: uidService, account: domainIdentifier)
    }

    /// Returns the stored user ID string, or nil if not yet stored.
    public static func loadUserId(for domainIdentifier: String) throws -> String? {
        let query: [String: Any] = scoped([
            kSecClass as String:         kSecClassGenericPassword,
            kSecAttrService as String:   namespaced(uidService),
            kSecAttrAccount as String:   domainIdentifier,
            kSecReturnData as String:    true,
        ])
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let uid = String(data: data, encoding: .utf8)
        else { throw KeychainError.loadFailed(status) }
        return uid
    }

    /// Delete every unwrapped user identity slot across all domains. The cross-process global lock
    /// primitive — a plain `SecItemDelete` on non-ACL items, callable from `Provider.appex`.
    public static func deleteAllUnwrappedUserIdentityKeys() throws {
        try delete(service: unwrappedService, account: nil)
    }

    // MARK: - Private

    /// Read a single generic-password item's data, or nil if not found.
    private static func loadData(service: String, account: String) throws -> Data? {
        let query: [String: Any] = scoped([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespaced(service),
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ])
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.loadFailed(status)
        }
        return data
    }

    /// Delete item(s) for a service, optionally scoped to one account (nil == all accounts).
    ///
    /// The account-less form loops. A single `SecItemDelete` against a query matching several
    /// generic-password items removes **one** of them and reports success, so one call left every
    /// domain but the first still holding its slot — which, on the `*.unwrapped` services, meant
    /// a global lock silently failed to lock any domain after the first. Repeating until
    /// `errSecItemNotFound` is what actually clears the service.
    private static func delete(service: String, account: String?) throws {
        var query: [String: Any] = scoped([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespaced(service),
        ])
        if let account {
            query[kSecAttrAccount as String] = account
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError.storeFailed(status)
            }
            return
        }
        // Bounded so a keychain that kept reporting success could never spin forever.
        for _ in 0..<1024 {
            let status = SecItemDelete(query as CFDictionary)
            if status == errSecItemNotFound { return }
            guard status == errSecSuccess else { throw KeychainError.storeFailed(status) }
        }
        throw KeychainError.storeFailed(errSecInternalError)
    }

    /// Insert-or-replace a generic-password item in the App Group keychain.
    ///
    /// Deletes any existing item for `{service, account, appGroup}` then adds the new value.
    /// If the add reports `errSecDuplicateItem` — which happens when the existing item cannot
    /// be removed by the current process (e.g. it was written under a different code-signing
    /// identity, so its ACL rejects our `SecItemDelete`) — fall back to `SecItemUpdate` on the
    /// stored data. This keeps the store idempotent across re-signings instead of failing.
    private static func upsert(service: String, account: String, data: Data) throws {
        let query: [String: Any] = scoped([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespaced(service),
            kSecAttrAccount as String: account,
        ])
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        addQuery[kSecValueData as String] = data

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            let attributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            guard updateStatus == errSecSuccess else { throw KeychainError.storeFailed(updateStatus) }
        default:
            throw KeychainError.storeFailed(status)
        }
    }

    static func importRSAPrivateKey(_ der: Data) throws -> SecKey {
        try BC01CryptoCommon.importRSAPrivateKey(der)
    }
}
