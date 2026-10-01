/// Unit tests for `BC01Decryptor`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
import FileProvider
import Common

final class BC01DecryptorTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()
    private var decryptor: BC01Decryptor?
    private let testDomainID = "com.test.bc01decryptor-\(UUID().uuidString)"

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

        // Provisioning writes the raw session DER; loadUserIdentityPrivateKey reads the
        // Provider-only unwrapped slot, so read the raw slot directly here.
        let der = try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID)
        XCTAssertNotNil(der, "RSA private key not loaded from keychain")
        let privKey = try BC01CryptoCommon.importRSAPrivateKey(der!)

        decryptor = BC01Decryptor(rsaPrivateKey: privKey)
    }

    override func tearDownWithError() throws {
        try Self.testKeyStore.forgetDomain(testDomainID)
        try super.tearDownWithError()
    }

    func testDecryptValidFile() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let testFileURL = URL(fileURLWithPath: #filePath)
        let testDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()
        let encryptedPath = projectRoot.appendingPathComponent("data/corpus/bc01/txt/apple.txt.bc")
        let plaintextPath = projectRoot.appendingPathComponent("data/corpus/plain/txt/apple.txt")

        let encrypted = try Data(contentsOf: encryptedPath)
        let decrypted = try decryptor.decrypt(encrypted)
        let expected = try Data(contentsOf: plaintextPath)

        XCTAssertEqual(decrypted, expected, "Decrypted data should match plaintext")
    }

    func testDecryptEmptyFile() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let testFileURL = URL(fileURLWithPath: #filePath)
        let testDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()

        let encryptedPath = projectRoot.appendingPathComponent("data/corpus/bc01/txt/apple.txt.bc")
        let encrypted = try Data(contentsOf: encryptedPath)
        let decrypted = try decryptor.decrypt(encrypted)

        XCTAssert(!decrypted.isEmpty, "apple.txt should decrypt to non-empty data")
    }

    func testDecryptTruncatedFile() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let truncated = Data([0x62, 0x63, 0x30, 0x31])
        do {
            _ = try decryptor.decrypt(truncated)
            XCTFail("Should throw truncatedFile error")
        } catch BC01Error.truncatedFile {
            // Expected
        }
    }

    func testDecryptInvalidMagic() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        var data = Data(count: 16)
        data[0] = 0xFF
        data[1] = 0xFF
        data[2] = 0xFF
        data[3] = 0xFF

        do {
            _ = try decryptor.decrypt(data)
            XCTFail("Should throw invalidHeader error")
        } catch BC01Error.invalidHeader {
            // Expected
        }
    }

    func testDecryptMultipleBlocks() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let testFileURL = URL(fileURLWithPath: #filePath)
        let testDir = testFileURL.deletingLastPathComponent()
        let projectRoot = testDir.deletingLastPathComponent()

        let encryptedPath = projectRoot.appendingPathComponent("data/corpus/bc01/bin/elephant.bin.bc")
        let plaintextPath = projectRoot.appendingPathComponent("data/corpus/plain/bin/elephant.bin")

        let encrypted = try Data(contentsOf: encryptedPath)
        let decrypted = try decryptor.decrypt(encrypted)
        let expected = try Data(contentsOf: plaintextPath)

        XCTAssertEqual(decrypted, expected, "Multi-block file should decrypt correctly")
    }

    func testDecryptManySmallFiles() throws {
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
            let stem = encryptedURL.lastPathComponent.dropLast(3)
            let plaintextURL = plaintextDir.appendingPathComponent(String(stem))

            let encrypted = try Data(contentsOf: encryptedURL)
            let decrypted = try decryptor.decrypt(encrypted)
            let expected = try Data(contentsOf: plaintextURL)

            XCTAssertEqual(decrypted, expected, "File \(stem) should decrypt correctly")
        }
    }

    func testDecryptBinaryFiles() throws {
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
            let stem = encryptedURL.lastPathComponent.dropLast(3)
            let plaintextURL = plaintextDir.appendingPathComponent(String(stem))

            let encrypted = try Data(contentsOf: encryptedURL)
            let decrypted = try decryptor.decrypt(encrypted)
            let expected = try Data(contentsOf: plaintextURL)

            XCTAssertEqual(decrypted, expected, "Binary file \(stem) should decrypt correctly")
        }
    }

    /// Decrypting block-by-block via the resolved header context must reproduce exactly the
    /// whole-blob `decrypt(_:)` output. This is the unit the parallel range path relies on:
    /// each fetched ciphertext block is decrypted independently by its index, then reassembled.
    func testBlockwiseDecryptMatchesWholeBlob() throws {
        guard let decryptor = decryptor else {
            XCTFail("Decryptor not initialized")
            return
        }

        let projectRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let encryptedPath = projectRoot.appendingPathComponent("data/corpus/bc01/bin/elephant.bin.bc")
        let encrypted = try Data(contentsOf: encryptedPath)

        let header = try decryptor.makeBlockContext(from: encrypted)
        XCTAssertGreaterThan(encrypted.count, header.headerEnd, "fixture must have ciphertext")

        let ciphertext = encrypted[(encrypted.startIndex + header.headerEnd)...]
        var reassembled = Data()
        var offset = ciphertext.startIndex
        var blockIndex = 0
        while offset < ciphertext.endIndex {
            let remaining = ciphertext.endIndex - offset
            let isLast = remaining <= header.blockSize
            let end = isLast ? ciphertext.endIndex : offset + header.blockSize
            let block = Data(ciphertext[offset..<end])
            reassembled.append(try BC01CryptoCommon.decryptBlock(
                block, blockIndex: blockIndex, isLast: isLast, header: header))
            offset = end
            blockIndex += 1
        }

        XCTAssertEqual(reassembled, try decryptor.decrypt(encrypted),
                       "block-by-block decrypt must equal whole-blob decrypt")
        XCTAssertGreaterThan(blockIndex, 1, "fixture must span multiple blocks to exercise IV indexing")
    }
}
