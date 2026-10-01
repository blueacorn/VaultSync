/// Unit tests for `CryptoConfigViewModel`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
import FileProvider
@testable import Common

/// Covers the derive/store split: ``CryptoConfigViewModel/deriveKey(bckeyURL:password:)``
/// must validate a `.bckey` + password pair *without* persisting anything, so the domain
/// add/edit flow can reject a wrong password before provisioning.
final class CryptoConfigViewModelTests: KeychainIsolatedTestCase {

    private let correctPassword = "password"
    private var bckeyURL: URL!
    private var scratchDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        let testDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()
        bckeyURL = projectRoot.appendingPathComponent("data/corpus/example.bckey")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: bckeyURL.path),
                          "example.bckey fixture missing")

        scratchDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("CryptoConfigViewModelTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratchDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let scratchDir { try? FileManager.default.removeItem(at: scratchDir) }
        try super.tearDownWithError()
    }

    // MARK: - Success

    func testDeriveKeyWithCorrectPasswordReturnsKeyMaterial() throws {
        let material = try CryptoConfigViewModel().deriveKey(bckeyURL: bckeyURL,
                                                             password: correctPassword)

        XCTAssertFalse(material.userId.isEmpty, "userId should come from users[0].id")
        XCTAssertFalse(material.privateKeyDER.isEmpty)
        XCTAssertFalse(material.publicKeyDER.isEmpty)
        // The private key must be importable — proves we decrypted real DER, not garbage
        // that happened to survive PKCS7 unpadding.
        XCTAssertNoThrow(try BC01CryptoCommon.importRSAPrivateKey(material.privateKeyDER))
    }

    func testDeriveKeyIsDeterministic() throws {
        let vm = CryptoConfigViewModel()
        let first = try vm.deriveKey(bckeyURL: bckeyURL, password: correctPassword)
        let second = try vm.deriveKey(bckeyURL: bckeyURL, password: correctPassword)

        XCTAssertEqual(first.userId, second.userId)
        XCTAssertEqual(first.privateKeyDER, second.privateKeyDER)
    }

    /// The property the split exists to guarantee: validating a password must not write key
    /// material for the domain. Otherwise preflight would leave residue on every attempt.
    func testDeriveKeyWritesNothingToKeychain() throws {
        let domainID = "com.test.derivekey.\(UUID().uuidString)"
        addTeardownBlock {
            try? CryptoKeychain.deleteUnwrappedUserIdentityKey(for: domainID)
            try? CryptoKeychain.deleteUserIdentityPublicKey(for: domainID)
        }

        _ = try CryptoConfigViewModel().deriveKey(bckeyURL: bckeyURL, password: correctPassword)

        XCTAssertNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainID),
                     "deriveKey must not persist key material")
        XCTAssertNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: domainID),
                     "deriveKey must not persist key material")
    }

    /// Provisioning seals the private DER under the VMK and releases it to the Provider slot —
    /// and never writes it anywhere in the clear that survives a lock.
    func testStoreSealsKeyMaterialUnderTheVMK() async throws {
        let domainID = "com.test.storekey.\(UUID().uuidString)"
        let keyStore = VaultKeyStore.isolatedForTesting()
        addTeardownBlock {
            try? keyStore.forgetDomain(domainID)
            try? CryptoKeychain.deleteUserIdentityPublicKey(for: domainID)
        }

        let material = try CryptoConfigViewModel().deriveKey(bckeyURL: bckeyURL,
                                                             password: correctPassword)
        try await CryptoConfigViewModel().store(material,
                                                for: NSFileProviderDomainIdentifier(domainID),
                                                keyStore: keyStore)

        XCTAssertNotNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainID),
                        "the private key must be sealed under the VMK")
        XCTAssertNotNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: domainID),
                        "and released to the Provider slot while unlocked")

        // Locking evicts the only readable copy: nothing in the clear survives it.
        try keyStore.evictUnwrappedSlots()
        XCTAssertNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: domainID),
                     "no plaintext copy of the private key may survive a lock")
    }

    // MARK: - Tamper detection

    /// The wrapped blob's HMAC excludes the IV, so an IV edit flips first-block plaintext bits
    /// undetected. Turning the leading base64 character into a non-base64 one must fail decode.
    func testDeriveKeyRejectsIVTamperProducingNonBase64() throws {
        let url = try writeTamperedBckey { user in
            var blob = try XCTUnwrap(Data(base64Encoded: user["privateKey"] as? String ?? ""))
            blob[0] ^= UInt8(ascii: "M") ^ UInt8(ascii: "!")
            user["privateKey"] = blob.base64EncodedString()
        }

        XCTAssertThrowsError(try CryptoConfigViewModel().deriveKey(bckeyURL: url,
                                                                   password: correctPassword)) {
            XCTAssertEqual($0 as? CryptoConfigError, .invalidBase64)
        }
    }

    /// A private key that no longer matches `users[0].publicKey` must be rejected.
    func testDeriveKeyRejectsPublicKeyMismatch() throws {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        let otherPrivate = try XCTUnwrap(SecKeyCreateRandomKey(attrs as CFDictionary, &error))
        let otherPublic = try XCTUnwrap(SecKeyCopyPublicKey(otherPrivate))
        let otherPublicDER = try XCTUnwrap(SecKeyCopyExternalRepresentation(otherPublic, &error) as Data?)
        let url = try writeTamperedBckey { user in
            user["publicKey"] = otherPublicDER.base64EncodedString()
        }

        XCTAssertThrowsError(try CryptoConfigViewModel().deriveKey(bckeyURL: url,
                                                                   password: correctPassword)) {
            XCTAssertEqual($0 as? CryptoConfigError, .keyPairMismatch)
        }
    }

    /// Writes a copy of the fixture with `users[0]` modified by `mutate`.
    private func writeTamperedBckey(_ mutate: (inout [String: Any]) throws -> Void) throws -> URL {
        var root = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: Data(contentsOf: bckeyURL)) as? [String: Any])
        var users = try XCTUnwrap(root["users"] as? [[String: Any]])
        try mutate(&users[0])
        root["users"] = users
        let url = scratchDir.appendingPathComponent("tampered.bckey")
        try JSONSerialization.data(withJSONObject: root).write(to: url)
        return url
    }
}
