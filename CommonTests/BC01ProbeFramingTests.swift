/// Unit tests for `BC01ProbeFraming`.
//
//  BC01ProbeFramingTests.swift
//  CommonTests
//
//  Boxcryptor ground truth for BC01 framing at every geometry boundary.
//
//  The `probe-pkcs7` corpus was written through a real Boxcryptor mount: `plain/bin/probe-pkcs7/pN.bin`
//  is N random bytes, `bc01/bin/probe-pkcs7/pN.bin.bc` is what Boxcryptor stored for it. Sizes
//  straddle the AES unit (16), the BC01 block (4096), the 1% header-reserve step
//  (819,100/819,101) and the 10 MiB flat-reserve threshold.
//
//  Both directions are pinned against it:
//  - decrypt: every Boxcryptor file decrypts to its plaintext, and its header matches
//    ``BC01Framing`` (reserved header size, PKCS7 pad count — 0 for a full final block).
//  - encrypt: our encryptor frames each plaintext exactly as Boxcryptor did (same total size,
//    header size and pad count), and the result round-trips.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
@testable import Common

final class BC01ProbeFramingTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    /// Plaintext sizes present in the probe corpus.
    private static let probeSizes = [0, 1, 15, 16, 4080, 4081, 4095, 4096, 4097, 8192, 409_600,
                                     819_100, 819_101, 1_048_576, 10_485_759, 10_485_760]

    private let userID = "test-user"
    private var rsaPrivateKey: SecKey!
    private var rsaPublicKey: SecKey!
    private var plainDir: URL!
    private var encryptedDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let corpus = projectRoot.appendingPathComponent("data/corpus")
        let bckeyURL = corpus.appendingPathComponent("example.bckey")
        plainDir = corpus.appendingPathComponent("plain/bin/probe-pkcs7")
        encryptedDir = corpus.appendingPathComponent("bc01/bin/probe-pkcs7")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: bckeyURL.path),
                          "BC01 corpus keypair not present")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: encryptedDir.path),
                          "BC01 probe-pkcs7 corpus not present")

        let domain = "com.test.bc01probe-\(UUID().uuidString)"
        let semaphore = DispatchSemaphore(value: 0)
        var setupError: Error?
        Task {
            do {
                _ = try await CryptoConfigViewModel().deriveAndStoreKey(
                    bckeyURL: bckeyURL, password: "password",
                    for: NSFileProviderDomainIdentifier(domain),
                    keyStore: Self.testKeyStore)
                semaphore.signal()
            } catch { setupError = error; semaphore.signal() }
        }
        semaphore.wait()
        addTeardownBlock { try? Self.testKeyStore.forgetDomain(domain) }
        if let setupError { throw setupError }

        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domain))
        rsaPrivateKey = try BC01CryptoCommon.importRSAPrivateKey(der)
        rsaPublicKey = try XCTUnwrap(SecKeyCopyPublicKey(rsaPrivateKey))
    }

    // MARK: - Helpers

    /// Boxcryptor's output for plaintext size `size`, with its plaintext.
    private func probe(_ size: Int) throws -> (plain: Data, encrypted: Data) {
        let plain = try Data(contentsOf: plainDir.appendingPathComponent("p\(size).bin"))
        let encrypted = try Data(contentsOf: encryptedDir.appendingPathComponent("p\(size).bin.bc"))
        XCTAssertEqual(plain.count, size, "probe plaintext p\(size).bin has wrong length")
        return (plain, encrypted)
    }

    /// Raw-header `cipherPadding` field (LE uint32 at offset 12).
    private func storedCipherPadding(_ ciphertext: Data) -> Int {
        Int(ciphertext.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 12, as: UInt32.self)) })
    }

    // MARK: - Decrypt path

    /// Boxcryptor-written files decrypt to their plaintext at every boundary — including a full
    /// final block, which Boxcryptor stores without PKCS7 padding.
    func testBoxcryptorProbesDecrypt() throws {
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey)
        for size in Self.probeSizes {
            let (plain, encrypted) = try probe(size)
            XCTAssertEqual(try decryptor.decrypt(encrypted), plain,
                           "Boxcryptor probe p\(size) did not decrypt to its plaintext")
        }
    }

    /// Boxcryptor's header matches ``BC01Framing``: reserved header size, PKCS7 pad count, and
    /// total ciphertext length. The header-derived exact size recovers the plaintext length.
    func testBoxcryptorProbesMatchFraming() throws {
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey)
        for size in Self.probeSizes {
            let (_, encrypted) = try probe(size)
            let header = try decryptor.makeBlockContext(from: encrypted)
            let p = Int64(size)

            XCTAssertEqual(Int64(header.headerEnd), BC01Framing.headerSize(plaintextSize: p),
                           "header size mismatch at \(size)")
            XCTAssertEqual(Int64(header.cipherPadding), BC01Framing.cipherPadding(plaintextSize: p),
                           "cipherPadding mismatch at \(size)")
            XCTAssertEqual(header.cipherPadding, BC01CryptoCommon.cipherPadding(plaintextSize: size),
                           "encryptor padding rule diverges from Boxcryptor at \(size)")
            XCTAssertEqual(Int64(encrypted.count), BC01Framing.ciphertextSize(plaintextSize: p),
                           "ciphertext size mismatch at \(size)")
            XCTAssertEqual(BC01CryptoCommon.exactPlaintextSize(header: header,
                                                               remoteSize: encrypted.count),
                           size, "header-derived size mismatch at \(size)")
        }
    }

    // MARK: - Encrypt path

    /// Our encryptor frames each probe plaintext exactly as Boxcryptor did — same total length,
    /// reserved header size and pad count — and the output round-trips.
    func testEncryptorMatchesBoxcryptorFraming() throws {
        let encryptor = BC01Encryptor(rsaPublicKey: rsaPublicKey, userID: userID)
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        for size in Self.probeSizes {
            let (plain, reference) = try probe(size)
            let ours = try encryptor.encrypt(plain, originalFilename: "p\(size).bin")
            let referenceHeader = try BC01Decryptor(rsaPrivateKey: rsaPrivateKey)
                .makeBlockContext(from: reference)
            let oursHeader = try decryptor.makeBlockContext(from: ours)

            XCTAssertEqual(ours.count, reference.count, "ciphertext size differs at \(size)")
            XCTAssertEqual(oursHeader.headerEnd, referenceHeader.headerEnd,
                           "header size differs at \(size)")
            XCTAssertEqual(storedCipherPadding(ours), storedCipherPadding(reference),
                           "cipherPadding differs at \(size)")
            XCTAssertEqual(try decryptor.decrypt(ours), plain, "round-trip failed at \(size)")
        }
    }

    /// Streaming session geometry (what ``BC01UploadPlan`` sizes `Content-Range` from) matches
    /// Boxcryptor's on-disk length at every probe size.
    func testSessionGeometryMatchesBoxcryptor() throws {
        let encryptor = BC01Encryptor(rsaPublicKey: rsaPublicKey, userID: userID)
        for size in Self.probeSizes {
            let reference = try Data(contentsOf: encryptedDir.appendingPathComponent("p\(size).bin.bc"))
            let session = try encryptor.beginSession(plaintextSize: size,
                                                     originalFilename: "p\(size).bin")
            XCTAssertEqual(session.headerBytes.count
                               + BC01CryptoCommon.ciphertextBodySize(plaintextSize: size),
                           reference.count, "session geometry differs at \(size)")
            XCTAssertEqual(session.cipherPadding, storedCipherPadding(reference),
                           "session cipherPadding differs at \(size)")
        }
    }
}
