/// Per-method ceremony producing the key that unwraps `vault.gating.<m>.wrapped`.
//  GatingCeremony.swift
//  Common
//
//  The one place the four unlock methods differ.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import CryptoKit
import Foundation
import LocalAuthentication
import os

/// Produces the key that opens `vault.gating.<m>.wrapped`. The four methods differ **only**
/// here; everything above this line — sealing a `domainKey` to `<m>.pub`, opening it with the
/// private half — is shared.
///
/// Every conformance stores whatever it needs in `vault.gating.<m>.params`, the single slot whose
/// contents vary by method. `enroll` is promptless for all four, which is what lets a domain be
/// added while the vault is locked.
public protocol GatingCeremony: Sendable {
    /// Establish this method's params and return the key `.wrapped` is sealed under.
    ///
    /// Promptless for every method — this is what lets a domain be added while locked.
    ///
    /// - Parameters:
    ///   - domain: The domain being enrolled. Ignored by the install-wide three; `.secure` mints
    ///     a per-domain ephemeral against it.
    ///   - pin: The PIN to enroll, for `.pin`.
    func enroll(domain: String, pin: String?) async throws -> SymmetricKey

    /// Re-derive that key from the stored params, running whatever ceremony the method requires.
    ///
    /// - Parameters:
    ///   - domain: The domain being opened.
    ///   - pin: The entered PIN, for `.pin`.
    ///   - reason: Prompt text for the methods that show one.
    ///   - context: A pre-evaluated `LAContext`, so N domains cost one prompt.
    func open(domain: String, pin: String?, reason: String,
              context: AnyObject?) async throws -> SymmetricKey

    /// Whether this method can be used on this machine.
    var isAvailable: Bool { get }

    /// Whether opening this method requires a user-presence ceremony.
    ///
    /// Drives the single presence evaluation that serves N domains — see
    /// ``VaultKeyStore/requiresPresence(_:)``.
    var requiresPresence: Bool { get }
}

// MARK: - `.none`

/// Silent gating: `.params` holds the 32-byte unwrapping key behind nothing but the item's own
/// access policy.
///
/// A UX affordance, not a security boundary — anything that can read the keychain item opens the
/// vault. The accessors are injected because this is the one slot needing
/// `kSecUseDataProtectionKeychain` with no `SecAccessControl`, which a test bundle with no host
/// application cannot write (`errSecMissingEntitlement`).
struct NoneCeremony: GatingCeremony {
    let readParams: @Sendable () throws -> Data?
    let writeParams: @Sendable (Data) throws -> Void
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "vault-keys")

    var isAvailable: Bool { true }
    var requiresPresence: Bool { false }

    func enroll(domain: String, pin: String?) async throws -> SymmetricKey {
        // Reuse the existing key when there is one: it is install-wide, so re-minting it here
        // would strand every domain already sealed to the matching keypair.
        if let raw = ((try? readParams()) ?? nil) { return SymmetricKey(data: raw) }
        let key = VaultKeyStore.generateKey()
        do {
            try writeParams(key.raw)
        } catch CryptoKeychain.KeychainError.storeFailed(let status) {
            log.error("🔑 device gating params store failed: OSStatus \(status)")
            throw VaultKeyStoreError.keychain(status)
        }
        return key
    }

    func open(domain: String, pin: String?, reason: String,
              context: AnyObject?) async throws -> SymmetricKey {
        guard let raw = try readParams() else { throw VaultKeyStoreError.gatingKeyMissing }
        return SymmetricKey(data: raw)
    }
}

// MARK: - `.pin`

/// PBKDF2 gating: `.params` holds `{salt, iterations, verifier}` and no key material at all.
///
/// The only method whose opening key exists nowhere at rest — it is re-derived from the entered
/// PIN every time. ``PINGate`` already implements exactly this, including constant-time
/// verification and escalating backoff, so this is a thin adapter over it.
struct PINCeremony: GatingCeremony {
    let gate: PINGate

    var isAvailable: Bool { true }
    var requiresPresence: Bool { false }

    func enroll(domain: String, pin: String?) async throws -> SymmetricKey {
        guard let pin else { throw VaultKeyStoreError.pinRequired }
        return try gate.setPIN(pin)
    }

    func open(domain: String, pin: String?, reason: String,
              context: AnyObject?) async throws -> SymmetricKey {
        guard let pin else { throw VaultKeyStoreError.pinRequired }
        return try gate.deriveGatingKey(with: pin)
    }
}

// MARK: - `.biometric`

/// Touch ID gating: `.params` holds the 32-byte unwrapping key behind a `SecAccessControl`
/// carrying `.biometryCurrentSet` with the device passcode as the OS's own fallback.
///
/// The key is exportable once device-owner auth succeeds — an honest caveat, not a flaw: the
/// guarantee is presence at read time, not non-exportability. `.secure` is the option that offers
/// the latter.
struct BiometricCeremony: GatingCeremony {
    let gate: BiometricGate
    /// Reads and writes `vault.gating.biometric.params`.
    ///
    /// Injected for the same reason as ``NoneCeremony``'s: the ACL'd write needs an
    /// app-identifier entitlement a test bundle with no host application does not carry
    /// (`errSecMissingEntitlement`). Substituting it also keeps automated runs free of a Touch ID
    /// prompt, which no unattended suite can satisfy.
    let readParams: @Sendable (AnyObject?) throws -> Data?
    let writeParams: @Sendable (Data, AnyObject?) throws -> Void
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "vault-keys")

    var isAvailable: Bool { gate.isAvailable }
    var requiresPresence: Bool { true }

    /// The production accessors, bound to the real ACL'd keychain item.
    static func keychainRead(_ context: AnyObject?) throws -> Data? {
        try CryptoKeychain.loadGatingParams(.biometric,
                                            domain: CryptoKeychain.gatingSharedAccount,
                                            context: context)
    }

    static func keychainDelete() {
        CryptoKeychain.deleteGatingKey(service: CryptoKeychain.gatingParamsService(.biometric),
                                       account: CryptoKeychain.gatingSharedAccount)
    }

    static func keychainWrite(_ raw: Data, _ context: AnyObject?) throws {
        try CryptoKeychain.storeGatingParams(raw, method: .biometric,
                                             domain: CryptoKeychain.gatingSharedAccount,
                                             access: try accessControl(), context: context)
    }

    /// Promptless, unlike the ceremony it enrolls.
    ///
    /// Writing an ACL'd item needs no evaluated context — only *reading* one does. That asymmetry
    /// is what lets a domain be added to a `.biometric` install while the vault is locked.
    func enroll(domain: String, pin: String?) async throws -> SymmetricKey {
        guard gate.isAvailable else { throw VaultKeyStoreError.biometricsUnavailable }
        let key = VaultKeyStore.generateKey()
        do {
            try writeParams(key.raw, nil)
        } catch CryptoKeychain.KeychainError.storeFailed(let status) {
            log.error("🔑 biometric gating params store failed: OSStatus \(status)")
            throw VaultKeyStoreError.keychain(status)
        }
        return key
    }

    func open(domain: String, pin: String?, reason: String,
              context: AnyObject?) async throws -> SymmetricKey {
        guard gate.isAvailable else { throw VaultKeyStoreError.biometricsUnavailable }
        let ctx: AnyObject?
        if let context { ctx = context } else { ctx = try await gate.authenticatedContext(reason: reason) }
        guard let raw = try readParams(ctx) else { throw VaultKeyStoreError.gatingKeyMissing }
        return SymmetricKey(data: raw)
    }

    /// The ACL for the biometric params item: current biometric enrollment, or the device
    /// passcode as the fallback the OS itself offers.
    static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode], &error) else {
            throw VaultKeyStoreError.biometricsUnavailable
        }
        return access
    }
}

// MARK: - `.secure`

/// Secure Enclave gating: `.params` holds a per-domain ephemeral P-256 **public** key, agreed
/// against the install's non-exportable enclave private key.
///
/// The only method whose opening key cannot be exported, and the only one scoped per domain — a
/// gating key captured during one vault's unlock opens that vault alone.
public struct SecureEnclaveCeremony: GatingCeremony {
    let gate: SecureEnclaveGate

    /// - Parameter gate: The enclave gate to enroll and agree against.
    public init(gate: SecureEnclaveGate) { self.gate = gate }

    public var isAvailable: Bool { gate.isAvailable }
    public var requiresPresence: Bool { true }

    /// Promptless: touches only the enclave's *public* half.
    ///
    /// A fresh ephemeral every time — reusing one reproduces the identical gating key, so an
    /// attacker holding the old ephemeral would open the new wrapper.
    ///
    /// - Note: Any App Group process can therefore seal new material to the enclave without user
    ///   presence. That is inherent to ECDH-with-public-half and is **not** a threat: an attacker
    ///   gains nothing by creating a vault they cannot open.
    public func enroll(domain: String, pin: String?) async throws -> SymmetricKey {
        guard gate.isAvailable else { throw VaultKeyStoreError.secureEnclaveUnavailable }
        let enrolled = try gate.enrollEphemeral()
        try CryptoKeychain.storeGatingParams(enrolled.ephemeralPublicKey,
                                             method: .secure, domain: domain)
        return VaultKeyStore.deriveSecureGatingKey(sharedSecret: enrolled.sharedSecret,
                                                   ephemeralPublicKey: enrolled.ephemeralPublicKey,
                                                   domainIdentifier: domain)
    }

    public func open(domain: String, pin: String?, reason: String,
                     context: AnyObject?) async throws -> SymmetricKey {
        guard let ephemeralPub = try CryptoKeychain.loadGatingParams(.secure, domain: domain)
        else { throw VaultKeyStoreError.gatingKeyMissing }
        // Touch ID, no password fallback — the enclave enforces it, not this call.
        let shared = try gate.agree(withEphemeralPublicKey: ephemeralPub,
                                    reason: reason, context: context)
        return VaultKeyStore.deriveSecureGatingKey(sharedSecret: shared,
                                                   ephemeralPublicKey: ephemeralPub,
                                                   domainIdentifier: domain)
    }
}
