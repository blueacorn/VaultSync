/// Unit tests for `BC01Integration`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
import FileProvider

import Common

final class BC01IntegrationTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()
    private var decryptor: BC01Decryptor?
    private let testDomainID = "com.test.bc01integration-\(UUID().uuidString)"

    override func setUpWithError() throws {
        try super.setUpWithError()
        let testFileURL = URL(fileURLWithPath: #filePath)
        let testDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()
        let bckeyURL = projectRoot.appendingPathComponent("data/corpus/example.bckey")

        let semaphore = DispatchSemaphore(value: 0)
        var setupError: Error?
        Task {
            do {
                _ = try await CryptoConfigViewModel().deriveAndStoreKey(
                    bckeyURL: bckeyURL,
                    password: "password",
                    for: NSFileProviderDomainIdentifier(testDomainID),
                    keyStore: Self.testKeyStore
                )
                semaphore.signal()
            } catch {
                setupError = error
                semaphore.signal()
            }
        }
        semaphore.wait()

        if let error = setupError { throw error }

        let der = try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID)
        XCTAssertNotNil(der, "RSA private key not loaded from keychain")

        decryptor = BC01Decryptor(rsaPrivateKey: try BC01CryptoCommon.importRSAPrivateKey(der!))
    }

    override func tearDownWithError() throws {
        try Self.testKeyStore.forgetDomain(testDomainID)
        try super.tearDownWithError()
    }

    func testDecryptTxtCorpus() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let testFileURL = URL(fileURLWithPath: #filePath)
        let testDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()
        let encryptedDir = projectRoot.appendingPathComponent("data/corpus/bc01/txt")
        let plaintextDir = projectRoot.appendingPathComponent("data/corpus/plain/txt")

        let fm = FileManager.default
        let encryptedFiles = try fm.contentsOfDirectory(
            at: encryptedDir,
            includingPropertiesForKeys: nil
        ).filter { $0.lastPathComponent.hasSuffix(".bc") }.sorted { $0.path < $1.path }

        for encryptedURL in encryptedFiles {
            let stem = encryptedURL.lastPathComponent.dropLast(3) // remove ".bc"
            let plaintextURL = plaintextDir.appendingPathComponent(String(stem))

            guard fm.fileExists(atPath: plaintextURL.path) else {
                XCTFail("Missing plaintext reference: \(plaintextURL.lastPathComponent)")
                continue
            }

            let encrypted = try Data(contentsOf: encryptedURL)
            let decrypted = try decryptor.decrypt(encrypted)
            let expected = try Data(contentsOf: plaintextURL)

            XCTAssertEqual(decrypted, expected, "Mismatch for \(plaintextURL.lastPathComponent)")
        }
    }

    func testDecryptBinCorpus() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let testFileURL = URL(fileURLWithPath: #filePath)
        let testDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()
        let encryptedDir = projectRoot.appendingPathComponent("data/corpus/bc01/bin")
        let plaintextDir = projectRoot.appendingPathComponent("data/corpus/plain/bin")

        let fm = FileManager.default
        let encryptedFiles = try fm.contentsOfDirectory(
            at: encryptedDir,
            includingPropertiesForKeys: nil
        ).filter { $0.lastPathComponent.hasSuffix(".bc") }.sorted { $0.path < $1.path }

        for encryptedURL in encryptedFiles {
            let stem = encryptedURL.lastPathComponent.dropLast(3) // remove ".bc"
            let plaintextURL = plaintextDir.appendingPathComponent(String(stem))

            guard fm.fileExists(atPath: plaintextURL.path) else {
                XCTFail("Missing plaintext reference: \(plaintextURL.lastPathComponent)")
                continue
            }

            let encrypted = try Data(contentsOf: encryptedURL)
            let decrypted = try decryptor.decrypt(encrypted)
            let expected = try Data(contentsOf: plaintextURL)

            XCTAssertEqual(decrypted, expected, "Mismatch for \(plaintextURL.lastPathComponent)")
        }
    }
}
