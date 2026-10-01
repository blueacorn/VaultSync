/// Phase 1 BC01 key derivation: PBKDF2-SHA512 + HMAC-SHA256 verification + AES-256-CBC decrypt → RSA DER.
///
/// Derivation is split from persistence so a `.bckey` + password pair can be *validated*
/// without writing to the keychain: ``CryptoConfigViewModel/deriveKey(bckeyURL:password:)``
/// is pure, and ``CryptoConfigViewModel/store(_:for:keyStore:)`` commits the result. The domain
/// add/edit flow validates during preflight and commits only after the domain is
/// registered, so a wrong password never leaves key material behind.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import CryptoKit
import CommonCrypto
import FileProvider

// MARK: - BCKey file model

public struct BCKeyFile: Codable {
    public struct User: Codable {
        public let id: String
        /// Base64 DER SubjectPublicKeyInfo; cross-checks the unwrapped private key.
        public let publicKey: String
        public let privateKey: String
        public let salt: String
        public let kdfIterations: Int
    }
    public let users: [User]
}

// MARK: - Errors

public enum CryptoConfigError: Error, Equatable {
    case noBckeyUsers
    case invalidBase64
    case pbkdf2Failed
    case hmacVerificationFailed
    case aesFailed
    /// The unwrapped private key does not match `users[0].publicKey`.
    case keyPairMismatch
}

// MARK: - Derived key material

/// The RSA key pair unlocked from a `.bckey` file, before any persistence.
///
/// Produced by ``CryptoConfigViewModel/deriveKey(bckeyURL:password:)``. Holding this value
/// proves the supplied password was correct; committing it to the keychain is a separate
/// step (``CryptoConfigViewModel/store(_:for:keyStore:)``).
public struct DerivedKeyMaterial: Sendable {
    /// `users[0].id` from the `.bckey` file, for writing to `DomainCryptoConfig`.
    public let userId: String
    /// Raw RSA private key in DER form.
    public let privateKeyDER: Data
    /// Raw RSA public key in DER form, derived from the private key and verified against
    /// `users[0].publicKey`.
    public let publicKeyDER: Data
}

// MARK: - ViewModel

public final class CryptoConfigViewModel {

    public init() {}

    /// Derives the RSA private key from `.bckey` + password **and** stores it in the App
    /// Group keychain.
    ///
    /// Convenience composition of ``deriveKey(bckeyURL:password:)`` and
    /// ``store(_:for:keyStore:)``, retained for callers that validate and commit in one step
    /// (notably the crypto test suites). The domain add/edit flow calls the two halves separately
    /// so validation can run before any persistence.
    ///
    /// - Parameter keyStore: The vault key store to seal the private key under. Defaults to
    ///   the process-wide ``VaultKeyStore/shared``.
    /// - Returns: The `userId` from `users[0].id`, for writing to `DomainCryptoConfig`.
    @discardableResult
    public func deriveAndStoreKey(bckeyURL: URL, password: String,
                                  for domainIdentifier: NSFileProviderDomainIdentifier,
                                  keyStore: VaultKeyStore = .shared) async throws -> String {
        let material = try deriveKey(bckeyURL: bckeyURL, password: password)
        try await store(material, for: domainIdentifier, keyStore: keyStore)
        return material.userId
    }

    /// Unlocks the RSA key pair from `.bckey` + password. **Pure** — touches no keychain and
    /// no domain state, so it is safe to call purely to validate a password.
    ///
    /// The wrapped blob's HMAC does not cover its IV, so the first plaintext block can be altered
    /// undetected. Strict base64 decoding and the key-pair check against `users[0].publicKey`
    /// close that gap.
    ///
    /// - Throws: ``CryptoConfigError/hmacVerificationFailed`` for a wrong password;
    ///   ``CryptoConfigError/keyPairMismatch`` for a tampered private key; the other
    ///   ``CryptoConfigError`` cases for a malformed or corrupt key file.
    public func deriveKey(bckeyURL: URL, password: String) throws -> DerivedKeyMaterial {
        let bckeyData = try Data(contentsOf: bckeyURL)
        let bckey = try JSONDecoder().decode(BCKeyFile.self, from: bckeyData)

        guard let user = bckey.users.first else { throw CryptoConfigError.noBckeyUsers }

        guard let encryptedPrivKeyBytes = Data(base64Encoded: user.privateKey),
              let saltBytes = Data(base64Encoded: user.salt)
        else { throw CryptoConfigError.invalidBase64 }

        // PBKDF2-SHA512 → 64 bytes (first 32: AES key, next 32: HMAC key)
        var derived = [UInt8](repeating: 0, count: 64)
        let pwUTF8 = Array(password.utf8)
        let saltArr = Array(saltBytes)
        let status: Int32 = pwUTF8.withUnsafeBufferPointer { pwBuf in
            saltArr.withUnsafeBufferPointer { saltBuf in
                derived.withUnsafeMutableBufferPointer { derivedBuf in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pwBuf.baseAddress.map { UnsafePointer<Int8>(OpaquePointer($0)) },
                        pwUTF8.count,
                        saltBuf.baseAddress,
                        saltBuf.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(user.kdfIterations),
                        derivedBuf.baseAddress,
                        derivedBuf.count
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw CryptoConfigError.pbkdf2Failed }

        let aesKey  = Data(derived[0..<32])
        let hmacKey = SymmetricKey(data: Data(derived[32..<64]))

        // Layout: [16 bytes IV][32 bytes HMAC][N bytes AES-CBC ciphertext]
        let iv              = Data(encryptedPrivKeyBytes[0..<16])
        let givenHmac       = Data(encryptedPrivKeyBytes[16..<48])
        let ciphertext      = Data(encryptedPrivKeyBytes[48...])

        // Verify HMAC-SHA256 over ciphertext (constant-time)
        let computedHmac = Data(HMAC<SHA256>.authenticationCode(for: ciphertext, using: hmacKey))
        guard timingSafeEqual(computedHmac, givenHmac) else {
            throw CryptoConfigError.hmacVerificationFailed
        }

        // AES-256-CBC decrypt → base64 string containing raw RSA DER
        let decryptedBytes = try aes256CBCDecrypt(ciphertext, key: aesKey, iv: iv)
        guard let b64String = String(data: decryptedBytes, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              let rsaPrivateKeyDER = Data(base64Encoded: b64String)
        else { throw CryptoConfigError.invalidBase64 }

        let privKey = try BC01CryptoCommon.importRSAPrivateKey(rsaPrivateKeyDER)
        guard let pubKey = SecKeyCopyPublicKey(privKey) else {
            throw CryptoConfigError.invalidBase64
        }
        var cfErr: Unmanaged<CFError>?
        guard let pubKeyDER = SecKeyCopyExternalRepresentation(pubKey, &cfErr) as Data? else {
            throw cfErr?.takeRetainedValue() ?? CryptoConfigError.invalidBase64
        }
        guard try Self.publicKeyDER(fromSPKIBase64: user.publicKey) == pubKeyDER else {
            throw CryptoConfigError.keyPairMismatch
        }

        return DerivedKeyMaterial(userId: user.id,
                                  privateKeyDER: rsaPrivateKeyDER,
                                  publicKeyDER: pubKeyDER)
    }

    /// Imports a base64 SubjectPublicKeyInfo RSA public key and returns its PKCS#1 DER, the
    /// form `SecKeyCopyExternalRepresentation` produces.
    private static func publicKeyDER(fromSPKIBase64 base64: String) throws -> Data {
        guard let spki = Data(base64Encoded: base64) else { throw CryptoConfigError.invalidBase64 }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(spki as CFData, attrs as CFDictionary, &error),
              let der = SecKeyCopyExternalRepresentation(key, &error) as Data?
        else { throw CryptoConfigError.keyPairMismatch }
        return der
    }

    /// Commits previously derived key material to the App Group keychain for `domainIdentifier`.
    ///
    /// The private DER is handed to ``VaultKeyStore`` and sealed under the domain's own
    /// `domainKey` — it is never persisted in the clear. The public DER and user ID are not
    /// secret and are stored plainly so the encrypt path keeps working while the vault is locked.
    ///
    /// All-or-nothing: if sealing the private key fails, the public key and user ID written first
    /// are rolled back, so a domain is never left half-provisioned with no usable private key.
    ///
    /// - Parameters:
    ///   - material: The derived user identity key material.
    ///   - domainIdentifier: The domain to provision.
    ///   - keyStore: The vault key store that mints the `domainKey` and does the sealing.
    ///   - pin: The PIN to enroll, needed only when `.pin` is the install's method and its
    ///     gating keypair has not been minted yet.
    public func store(_ material: DerivedKeyMaterial,
                      for domainIdentifier: NSFileProviderDomainIdentifier,
                      keyStore: VaultKeyStore,
                      pin: String? = nil) async throws {
        let domain = domainIdentifier.rawValue
        // No ceremony to run: `provisionDomain` mints this domain's own `domainKey` and seals it
        // to the active method's public half, which is readable while locked. So this succeeds
        // from a locked vault, for every method.
        try CryptoKeychain.storeUserIdentityPublicKey(material.publicKeyDER, for: domain)
        try CryptoKeychain.storeUserId(material.userId, for: domain)
        do {
            try await keyStore.provisionDomain(userIdentityKeyDER: material.privateKeyDER,
                                               for: domain, pin: pin)
        } catch {
            // `forgetDomain` is the full inverse of this method, public key and user ID included.
            try? keyStore.forgetDomain(domain)
            throw error
        }
    }

    // MARK: - Private

    private func timingSafeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for (x, y) in zip(a, b) { result |= x ^ y }
        return result == 0
    }

    private func aes256CBCDecrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        var out = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
        var outLen = 0
        let status: CCCryptorStatus = ciphertext.withUnsafeBytes { ctBuf in
            key.withUnsafeBytes { keyBuf in
                iv.withUnsafeBytes { ivBuf in
                    CCCrypt(
                        CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBuf.baseAddress, key.count,
                        ivBuf.baseAddress,
                        ctBuf.baseAddress, ciphertext.count,
                        &out, out.count, &outLen
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw CryptoConfigError.aesFailed }
        return Data(out[..<outLen])
    }
}
