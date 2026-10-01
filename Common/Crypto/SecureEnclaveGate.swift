/// Secure Enclave abstraction for `.secure` vault gating (promptless enroll, prompted key agreement).
//
//  SecureEnclaveGate.swift
//  Common
//
//  Secure Enclave gating for ``SharedConfig/VaultGating/secure``.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import CryptoKit
import Foundation
import LocalAuthentication
import Security
import os.log

/// The result of a promptless `.secure` enrollment: a fresh per-domain ephemeral public key and
/// the secret it agreed with the enclave's public half.
public struct SecureEnclaveEnrollment: Sendable {
    /// The ephemeral P-256 public key, in x9.63 form. Stored in the clear — it is not secret.
    public let ephemeralPublicKey: Data
    /// The ECDH shared secret. Never persisted; HKDF'd into the gating key and discarded.
    public let sharedSecret: Data

    public init(ephemeralPublicKey: Data, sharedSecret: Data) {
        self.ephemeralPublicKey = ephemeralPublicKey
        self.sharedSecret = sharedSecret
    }
}

/// Abstracts the Secure Enclave so `.secure` gating is testable without an enclave (and without a
/// Touch ID prompt), mirroring how ``BiometricGate`` isolates the presence check.
///
/// The asymmetry between the two members is the whole point of the design:
///
/// * ``enrollEphemeral()`` uses only the enclave's **public** key, so it needs no enclave access
///   and raises **no prompt**.
/// * ``agree(withEphemeralPublicKey:reason:context:)`` needs the enclave's private key, so it
///   **prompts** — Touch ID only, with no password fallback.
///
/// This is the same write-silent/read-gated property `SecItemAdd` gives an ACL'd item, obtained a
/// stronger way: a public-key operation needs no private key at all.
public protocol SecureEnclaveGate: Sendable {
    /// Whether this machine has a Secure Enclave and an enrolled biometric.
    var isAvailable: Bool { get }

    /// Mint a fresh ephemeral keypair and agree it against the install's Secure Enclave public
    /// key. Promptless.
    ///
    /// - Returns: The ephemeral public key to store, and the shared secret to derive from.
    func enrollEphemeral() throws -> SecureEnclaveEnrollment

    /// Reproduce the shared secret by agreeing `ephemeralPublicKey` against the enclave's
    /// **private** key. Prompts for Touch ID; there is no password fallback.
    ///
    /// - Parameters:
    ///   - ephemeralPublicKey: The stored per-domain ephemeral public key, x9.63 form.
    ///   - reason: Prompt text.
    ///   - context: A pre-evaluated `LAContext` to reuse, so N domains cost one prompt.
    /// - Returns: The ECDH shared secret.
    func agree(withEphemeralPublicKey ephemeralPublicKey: Data,
               reason: String, context: AnyObject?) throws -> Data
}

/// The production ``SecureEnclaveGate``: one P-256 key per install, held in the data-protection
/// keychain with `kSecAttrTokenIDSecureEnclave`.
///
/// One key per install, not per domain. Isolation comes from the per-domain ephemeral, not from N
/// enclave keys — the same finger opens all of them, so N keys buy nothing and would multiply the
/// enrollment-change blast radius.
///
/// - Important: The key carries `.biometryCurrentSet`, so **a Touch ID enrollment change destroys
///   it** and with it every `domainKey.wrapped` gated `.secure`. That is the intended meaning of
///   the strict option and the reason it is opt-in; the UI states it plainly. A recovery wrapper
///   under a second gating is deliberately rejected — two wrappers on one `domainKey` would mean
///   the vault opens without the strict gate.
public struct SecureEnclaveKeyGate: SecureEnclaveGate {
    private static let tag = Data("org.vaultsync.VaultSync.vault.gating.secure.sekey".utf8)
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "vault-keys")

    public init() {}

    public var isAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                             error: &error)
    }

    public func enrollEphemeral() throws -> SecureEnclaveEnrollment {
        // Only the enclave's public half is touched here, so this raises no prompt.
        let pub = try enclavePublicKey()
        let eph = P256.KeyAgreement.PrivateKey()

        var error: Unmanaged<CFError>?
        guard let shared = SecKeyCopyKeyExchangeResult(
            eph.secKeyRepresentation(),
            .ecdhKeyExchangeStandard,
            pub,
            [:] as CFDictionary,
            &error) as Data? else {
            throw error?.takeRetainedValue() ?? VaultKeyStoreError.secureEnclaveUnavailable as NSError
        }
        return SecureEnclaveEnrollment(ephemeralPublicKey: eph.publicKey.x963Representation,
                                       sharedSecret: shared)
    }

    public func agree(withEphemeralPublicKey ephemeralPublicKey: Data,
                      reason: String, context: AnyObject?) throws -> Data {
        let priv = try enclavePrivateKey(reason: reason, context: context)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let ephPub = SecKeyCreateWithData(ephemeralPublicKey as CFData,
                                                attrs as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? VaultKeyStoreError.unwrapFailed as NSError
        }
        guard let shared = SecKeyCopyKeyExchangeResult(
            priv, .ecdhKeyExchangeStandard, ephPub, [:] as CFDictionary, &error) as Data? else {
            throw error?.takeRetainedValue() ?? VaultKeyStoreError.gatingKeyMissing as NSError
        }
        return shared
    }

    // MARK: - Private

    /// The install's Secure Enclave private key, creating it on first use.
    ///
    /// Reading it is what prompts. `context` lets one evaluated `LAContext` serve N domains, so
    /// unlock-all costs a single prompt while still deriving N independent `domainKey`s — the
    /// isolation lives in the key graph, not in the prompt count.
    /// The install's enclave private key, for an **unlock**. Never creates one.
    ///
    /// Creation belongs to enrollment alone. Minting here would hand `agree` a private half that
    /// no existing `.params` ephemeral was agreed against: every derived gating key would be
    /// wrong, and the failure would surface as a generic `unwrapFailed` rather than the
    /// destroyed-enclave cause ``UnlockView`` exists to name. Worse, it would silently replace
    /// the key that every `.secure` vault is gated on, so a transient `errSecItemNotFound`
    /// would permanently strand them.
    private func enclavePrivateKey(reason: String, context: AnyObject?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        query[kSecUseOperationPrompt as String] = reason

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let key = result {
            return key as! SecKey
        }
        // Both the destroyed key (Touch ID re-enrollment) and the absent one are reported as
        // `gatingKeyMissing`: neither is recoverable by retrying, and the caller names the cause.
        // `errSecItemNotFound` used to mint a replacement here — see the note above.
        log.error("🔑 Secure Enclave key unavailable: OSStatus \(status)")
        throw VaultKeyStoreError.gatingKeyMissing
    }

    /// The enclave key's public half, creating the key on first use.
    ///
    /// Copying the public key does **not** prompt, which is what makes enrollment silent.
    private func enclavePublicKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let priv: SecKey
        if status == errSecSuccess, let key = result {
            priv = key as! SecKey
        } else if status == errSecItemNotFound || status == errSecInteractionNotAllowed {
            // `errSecInteractionNotAllowed` means the key exists but its ACL blocks a silent ref
            // read; the reference is still usable for a public-key copy on macOS, so re-query
            // without the skip and take the ref without evaluating it.
            priv = status == errSecItemNotFound ? try createEnclaveKey() : try existingKeyRef()
        } else {
            throw VaultKeyStoreError.gatingKeyMissing
        }
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw VaultKeyStoreError.secureEnclaveUnavailable
        }
        return pub
    }

    /// A reference to the existing enclave key without evaluating its ACL.
    private func existingKeyRef() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let key = result else {
            throw VaultKeyStoreError.gatingKeyMissing
        }
        return key as! SecKey
    }

    /// Create the install's Secure Enclave key.
    ///
    /// `.biometryCurrentSet` **without** `.devicePasscode` is the whole point: unlike the ACL'd
    /// `.biometric` gating key, this one cannot be reached with the device password.
    private func createEnclaveKey() throws -> SecKey {
        guard isAvailable else {
            throw VaultKeyStoreError.secureEnclaveUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error) else {
            throw error?.takeRetainedValue() ?? VaultKeyStoreError.secureEnclaveUnavailable as NSError
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? VaultKeyStoreError.secureEnclaveUnavailable as NSError
        }
        log.info("🔑 Secure Enclave gating key created")
        return key
    }
}

private extension P256.KeyAgreement.PrivateKey {
    /// The key as a `SecKey`, so it can be passed to `SecKeyCopyKeyExchangeResult` alongside the
    /// enclave's `SecKey`-only public half.
    func secKeyRepresentation() -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        // x963Representation ‖ the scalar is the DER-free form SecKey accepts for EC private keys.
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            (publicKey.x963Representation + rawRepresentation) as CFData,
            attrs as CFDictionary, &error) else {
            fatalError("P-256 private key is always representable as a SecKey")
        }
        return key
    }
}
