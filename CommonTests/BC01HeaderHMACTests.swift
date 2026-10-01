/// Unit tests for `BC01HeaderHMAC`.
//
//  BC01HeaderHMACTests.swift
//  CommonTests
//
//  BC01 96-byte file key + JSON core header HMAC (raw-header bytes 16–47).
//
//  Pins ``BC01FileKey`` layout, the encryptor's HMAC over the exact on-disk JSON, and the
//  decrypt-side ``BC01HeaderHMACStatus`` / ``BC01HeaderHMACPolicy`` against Boxcryptor ground
//  truth (`probe-pkcs7`).
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
import FileProvider
@testable import Common

final class BC01HeaderHMACTests: KeychainIsolatedTestCase {

    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    private let userID = "test-user"
    private var rsaPrivateKey: SecKey!
    private var rsaPublicKey: SecKey!
    private var corpus: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        corpus = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("data/corpus")
        let bckeyURL = corpus.appendingPathComponent("example.bckey")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: bckeyURL.path),
                          "BC01 corpus keypair not present")

        let domain = "com.test.bc01hmac-\(UUID().uuidString)"
        let semaphore = DispatchSemaphore(value: 0)
        var setupError: Error?
        Task {
            do {
                _ = try await CryptoConfigViewModel().deriveAndStoreKey(
                    bckeyURL: bckeyURL, password: "password",
                    for: NSFileProviderDomainIdentifier(domain), keyStore: Self.testKeyStore)
            } catch { setupError = error }
            semaphore.signal()
        }
        semaphore.wait()
        addTeardownBlock { try? Self.testKeyStore.forgetDomain(domain) }
        if let setupError { throw setupError }
        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domain))
        rsaPrivateKey = try BC01CryptoCommon.importRSAPrivateKey(der)
        rsaPublicKey = try XCTUnwrap(SecKeyCopyPublicKey(rsaPrivateKey))
    }

    // MARK: - Helpers

    private func decryptor(_ policy: BC01HeaderHMACPolicy) -> BC01Decryptor {
        BC01Decryptor(rsaPrivateKey: rsaPrivateKey, hmacPolicy: policy)
    }

    private func rsaUnwrap(_ wrapped: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(rsaPrivateKey, .rsaEncryptionOAEPSHA1,
                                                    wrapped as CFData, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        return plain
    }

    private func probe(_ name: String) throws -> (plain: Data, encrypted: Data) {
        (try Data(contentsOf: corpus.appendingPathComponent("plain/bin/probe-pkcs7/\(name).bin")),
         try Data(contentsOf: corpus.appendingPathComponent("bc01/bin/probe-pkcs7/\(name).bin.bc")))
    }

    private func ours(_ plain: Data) throws -> Data {
        try BC01Encryptor(rsaPublicKey: rsaPublicKey, userID: userID)
            .encrypt(plain, originalFilename: "vector.bin")
    }

    private func assertThrowsHMACMismatch(_ expr: @autoclosure () throws -> some Any,
                                          _ message: String, line: UInt = #line) {
        XCTAssertThrowsError(try expr(), message, line: line) { error in
            guard case BC01Error.headerHMACMismatch = error else {
                return XCTFail("expected headerHMACMismatch, got \(error)", line: line)
            }
        }
    }

    // MARK: - BC01FileKey

    func testGeneratedKeyRoundTripsWithValidChecksum() throws {
        let key = try BC01FileKey.generate()
        let wrapped = key.wrappedPlaintext
        XCTAssertEqual(wrapped.count, 96)
        XCTAssertEqual(Data(wrapped[0..<32]), Data(SHA256.hash(data: wrapped[32..<96])))
        let parsed = try BC01FileKey(unwrapped: wrapped)
        XCTAssertEqual(parsed.contentKey, key.contentKey)
        XCTAssertEqual(parsed.macKey, key.macKey)
    }

    func testInvalidLengthAndChecksumThrow() throws {
        for count in [0, 32, 63, 64, 65, 95, 97, 128] {
            XCTAssertThrowsError(try BC01FileKey(unwrapped: Data(count: count)), "length \(count)")
        }
        var bad = try BC01FileKey.generate().wrappedPlaintext
        bad[0] ^= 0x01
        XCTAssertThrowsError(try BC01FileKey(unwrapped: bad)) { error in
            guard case BC01Error.invalidFileKey = error else { return XCTFail("\(error)") }
        }
    }

    func testHeaderHMACIsHMACSHA256UnderMacKey() throws {
        let key = try BC01FileKey.generate()
        let json = Data(#"{"a":1}"#.utf8)
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: json, using: SymmetricKey(data: key.macKey)))
        XCTAssertEqual(key.headerHMAC(json), expected)
    }

    // MARK: - Our encrypt → parse

    func testOurFilesCarry96ByteKeyAndVerify() throws {
        for size in [0, 1, 4096, 4097, 40_000] {
            let plain = Data((0..<size).map { UInt8(truncatingIfNeeded: $0) })
            let ct = try ours(plain)
            var unwrappedCount = 0
            let header = try BC01CryptoCommon.parseHeader(ct, hmacPolicy: .strict) { wrapped in
                let plain = try self.rsaUnwrap(wrapped)
                unwrappedCount = plain.count
                return plain
            }
            XCTAssertEqual(unwrappedCount, 96, "size \(size)")
            XCTAssertEqual(header.headerHMACStatus, .verified, "size \(size)")
            XCTAssertNotEqual(Data(ct[16..<48]), Data(count: 32), "size \(size)")
            XCTAssertEqual(try decryptor(.strict).decrypt(ct), plain, "size \(size)")
        }
    }

    func testTamperedJSONOnOurFileMismatches() throws {
        let plain = Data(repeating: 7, count: 100)
        var ct = try ours(plain)
        let range = try XCTUnwrap(ct.range(of: Data("vector.bin".utf8)))
        ct.replaceSubrange(range, with: Data("vectos.bin".utf8))

        XCTAssertEqual(try decryptor(.warnOnly).makeBlockContext(from: ct).headerHMACStatus, .mismatch)
        XCTAssertEqual(try decryptor(.warnOnly).decrypt(ct), plain)
        assertThrowsHMACMismatch(try decryptor(.strict).decrypt(ct), "strict must reject tampered JSON")
    }

    func testCorruptedChecksumThrowsInBothModes() throws {
        let ct = try ours(Data(repeating: 1, count: 10))
        for policy in [BC01HeaderHMACPolicy.warnOnly, .strict] {
            XCTAssertThrowsError(try BC01CryptoCommon.parseHeader(ct, hmacPolicy: policy) { wrapped in
                var key = try self.rsaUnwrap(wrapped)
                key[key.startIndex] ^= 0xFF
                return key
            }) { error in
                guard case BC01Error.invalidFileKey = error else { return XCTFail("\(policy): \(error)") }
            }
        }
    }

    // MARK: - Boxcryptor ground truth

    func testBoxcryptorProbesMatchingOnDiskJSONVerify() throws {
        for name in ["p15", "p4096", "p4097"] {
            let (plain, encrypted) = try probe(name)
            XCTAssertEqual(try decryptor(.strict).makeBlockContext(from: encrypted).headerHMACStatus,
                           .verified, name)
            XCTAssertEqual(try decryptor(.strict).decrypt(encrypted), plain, name)
        }
    }

    func testBoxcryptorProbesWithReorderedJSONMismatch() throws {
        for name in ["p0", "p1", "p16"] {
            let (plain, encrypted) = try probe(name)
            XCTAssertEqual(try decryptor(.warnOnly).makeBlockContext(from: encrypted).headerHMACStatus,
                           .mismatch, name)
            XCTAssertEqual(try decryptor(.warnOnly).decrypt(encrypted), plain, name)
            assertThrowsHMACMismatch(try decryptor(.strict).decrypt(encrypted), name)
        }
    }

    // MARK: - Flag

    func testFlagDefaultsToWarnOnly() {
        XCTAssertTrue(FeatureFlags.bc01HeaderHMACWarnOnly.defaultIfNotPresent)
        let unset = NSFileProviderDomainIdentifier("com.test.bc01hmac-unset-\(UUID().uuidString)")
        XCTAssertEqual(BC01DecryptorFactory.hmacPolicy(for: unset), .warnOnly)
    }
}
