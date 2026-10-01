/// Unit tests for `BC01Encryptor`.
//
//  BC01EncryptorTests.swift
//  CommonTests
//
//  Deterministic ciphertext gate for BC01 encryption.
//
//  These vectors pin `BC01Encryptor`'s byte-exact output for fixed key material across the
//  block-boundary cases. They exist to guard the refactor of the block loop onto
//  ``FileEncryptionSession``: the streaming uploader encrypts block ranges independently, so
//  any drift in header layout, per-block IV derivation, or PKCS7 placement must fail here
//  rather than silently produce files the decryptor cannot read.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
import FileProvider
@testable import Common

final class BC01EncryptorTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    /// Fixed, non-secret key material so ciphertext is reproducible run to run.
    private let fileKey: BC01FileKey = {
        let body = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) })
        return try! BC01FileKey(unwrapped: Data(SHA256.hash(data: body)) + body)
    }()
    private let baseIV = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 11 &+ 5) })

    private var rsaPrivateKey: SecKey!
    private var rsaPublicKey: SecKey!
    private let userID = "test-user"

    override func setUpWithError() throws {
        try super.setUpWithError()
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let bckeyURL = projectRoot.appendingPathComponent("data/corpus/example.bckey")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: bckeyURL.path),
                          "BC01 corpus keypair not present")

        let domain = "com.test.bc01encryptor-\(UUID().uuidString)"
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
        // A teardown block, not a `defer`: a `defer` here fires at the end of *setup*, which is
        // not a teardown and leaves nothing registered if the provisioning above throws.
        addTeardownBlock { try? Self.testKeyStore.forgetDomain(domain) }
        if let setupError { throw setupError }

        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domain))
        rsaPrivateKey = try BC01CryptoCommon.importRSAPrivateKey(der)
        rsaPublicKey = try XCTUnwrap(SecKeyCopyPublicKey(rsaPrivateKey))
    }

    private func makeEncryptor() -> BC01Encryptor {
        BC01Encryptor(rsaPublicKey: rsaPublicKey, userID: userID)
    }

    private func plaintext(_ n: Int) -> Data {
        Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 17) })
    }

    /// Sizes that straddle every geometry boundary: empty, sub-AES-unit, exact AES unit,
    /// sub-block, exact block, block+1, multi-block, and the 320 KiB fragment boundary.
    private let sizes = [0, 1, 15, 16, 17, 4095, 4096, 4097, 8192, 8193, 10_000,
                         320 * 1024 - 1, 320 * 1024, 320 * 1024 + 1]

    // MARK: - Structural invariants

    /// Ciphertext size is exactly headerEnd + the padded body length. This is the geometry
    /// `BC01UploadPlan` computes ahead of encrypting anything, so it must be derivable from
    /// plaintext size alone.
    func testCiphertextGeometryIsPredictable() throws {
        let encryptor = makeEncryptor()
        for size in sizes {
            let ct = try encryptor.encryptDeterministic(
                plaintext: plaintext(size), fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")

            let header = try BC01CryptoCommon.parseHeader(ct, userID: userID) { wrapped in
                var error: Unmanaged<CFError>?
                guard let k = SecKeyCreateDecryptedData(self.rsaPrivateKey,
                                                        .rsaEncryptionOAEPSHA1,
                                                        wrapped as CFData, &error) as Data? else {
                    throw error!.takeRetainedValue()
                }
                return k
            }

            // A partial final block does NOT round up to a whole 4096-byte block: AES-CBC
            // works in 16-byte units, so the body is the plaintext plus its PKCS7 pad
            // (1...16 bytes, or 0 when the final 4096-byte block is full) — never a whole-block
            // round-up. Getting this wrong misstates the `Content-Range` total size.
            let expected = header.headerEnd + BC01CryptoCommon.ciphertextBodySize(plaintextSize: size)
            XCTAssertEqual(ct.count, expected,
                           "ciphertext size mismatch for plaintext size \(size)")
        }
    }

    /// Encryption is deterministic for fixed key material — the property the vectors rest on.
    func testDeterministicForFixedKeyMaterial() throws {
        let encryptor = makeEncryptor()
        for size in [0, 4096, 8193] {
            let a = try encryptor.encryptDeterministic(
                plaintext: plaintext(size), fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")
            let b = try encryptor.encryptDeterministic(
                plaintext: plaintext(size), fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")
            // The RSA-OAEP key wrap is randomised, so the header differs; the ciphertext
            // body (from headerEnd on) must be identical.
            XCTAssertEqual(a.suffix(size == 0 ? 0 : 4096), b.suffix(size == 0 ? 0 : 4096),
                           "block body not deterministic at size \(size)")
        }
    }

    // MARK: - Round-trip gate

    /// Every size round-trips through the real decryptor. This is the load-bearing assertion:
    /// it pins per-block IV derivation and PKCS7 placement without hardcoding bytes that the
    /// randomised RSA wrap would make unstable.
    func testRoundTripThroughDecryptor() throws {
        let encryptor = makeEncryptor()
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        for size in sizes {
            let source = plaintext(size)
            let ct = try encryptor.encryptDeterministic(
                plaintext: source, fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")
            let recovered = try decryptor.decrypt(ct)
            XCTAssertEqual(recovered, source, "round-trip failed at size \(size)")
        }
    }

    /// The random-key `encrypt(_:)` entry point round-trips too — it shares the block loop.
    func testRandomKeyEncryptRoundTrips() throws {
        let encryptor = makeEncryptor()
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        for size in [0, 1, 4096, 40_000] {
            let source = plaintext(size)
            let ct = try encryptor.encrypt(source, originalFilename: "vector.bin")
            XCTAssertEqual(try decryptor.decrypt(ct), source, "round-trip failed at size \(size)")
        }
    }

    // MARK: - Session equivalence (the streaming premise)

    /// Encrypting in arbitrary block-range splits must produce byte-identical output to one
    /// sequential pass. This is the property the parallel uploader depends on: lanes encrypt
    /// disjoint ranges independently and concatenate.
    func testSplitSpansMatchSinglePass() throws {
        let encryptor = makeEncryptor()
        for size in [1, 4096, 4097, 8192, 8193, 40_000, 320 * 1024 + 7] {
            let source = plaintext(size)
            let session = try encryptor.makeSession(
                plaintextSize: size, fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")

            let whole = try session.encryptBlocks(source, firstBlock: 0, isFinal: true)
            let blockCount = (size + 4095) / 4096

            // Split at every plausible lane boundary, including uneven ones.
            for splitBlock in stride(from: 1, to: max(2, blockCount), by: 1) {
                guard splitBlock < blockCount else { continue }
                let cut = splitBlock * 4096
                let head = try session.encryptBlocks(
                    Data(source[0..<cut]), firstBlock: 0, isFinal: false)
                let tail = try session.encryptBlocks(
                    Data(source[cut...]), firstBlock: splitBlock, isFinal: true)
                XCTAssertEqual(head + tail, whole,
                               "split at block \(splitBlock) diverged for size \(size)")
            }
        }
    }

    /// A split-encrypted file still decrypts correctly end to end.
    func testSplitSpanOutputDecrypts() throws {
        let encryptor = makeEncryptor()
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        let size = 40_000
        let source = plaintext(size)
        let session = try encryptor.makeSession(
            plaintextSize: size, fileKey: fileKey,
            baseIV: baseIV, originalFilename: "vector.bin")

        var ct = session.headerBytes
        ct += try session.encryptBlocks(Data(source[0..<8192]), firstBlock: 0, isFinal: false)
        ct += try session.encryptBlocks(Data(source[8192...]), firstBlock: 2, isFinal: true)
        XCTAssertEqual(try decryptor.decrypt(ct), source)
    }

    /// Session-reported ciphertext size matches what the session actually produces.
    func testSessionGeometryMatchesOutput() throws {
        let encryptor = makeEncryptor()
        for size in sizes {
            let session = try encryptor.makeSession(
                plaintextSize: size, fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")
            let body = size == 0 ? Data()
                : try session.encryptBlocks(plaintext(size), firstBlock: 0, isFinal: true)
            XCTAssertEqual(body.count,
                           BC01CryptoCommon.ciphertextBodySize(plaintextSize: size),
                           "body size mismatch at \(size)")
            XCTAssertEqual(session.headerBytes.count + body.count,
                           session.headerBytes.count
                               + BC01CryptoCommon.ciphertextBodySize(plaintextSize: size))
        }
    }

    // MARK: - cipherPadding header field

    /// `cipherPadding` at raw-header offset 12 is the PKCS7 pad byte count in [0...16], derived
    /// from the AES block size (16) — not a boolean flag, and not a function of the BC01 block
    /// size (4096) — except that a full final 4096-byte block is unpadded (count 0), as
    /// Boxcryptor writes it. A short final block that is an exact multiple of 16 takes a full
    /// 16-byte pad unit.
    func testCipherPaddingHeaderFieldIsPKCS7ByteCount() throws {
        let encryptor = makeEncryptor()
        let expectations: [(size: Int, padding: Int, body: Int)] = [
            (0, 0, 0), (1, 15, 16), (15, 1, 16), (16, 16, 32), (17, 15, 32),
            (4080, 16, 4096), (4095, 1, 4096), (4096, 0, 4096), (4097, 15, 4112),
            (8192, 0, 8192), (10_000, 16, 10_016),
        ]
        for (size, expectedPadding, expectedBody) in expectations {
            XCTAssertEqual(BC01CryptoCommon.cipherPadding(plaintextSize: size), expectedPadding,
                           "cipherPadding wrong at size \(size)")
            XCTAssertEqual(BC01CryptoCommon.ciphertextBodySize(plaintextSize: size), expectedBody,
                           "body size wrong at size \(size)")

            let ct = try encryptor.encryptDeterministic(
                plaintext: plaintext(size), fileKey: fileKey,
                baseIV: baseIV, originalFilename: "vector.bin")
            let stored = Int(ct.withUnsafeBytes {
                UInt32(littleEndian: $0.load(fromByteOffset: 12, as: UInt32.self)) })
            XCTAssertEqual(stored, expectedPadding,
                           "header cipherPadding wrong at size \(size)")
        }
    }

    /// Decrypt treats `cipherPadding` as "> 0 means unpad", so legacy headers that stored the
    /// flag value 1 over a genuinely PKCS7-padded body still decrypt. This is the
    /// backwards-compatibility contract that lets the encoder start writing true counts.
    func testLegacyFlagStyleCipherPaddingStillDecrypts() throws {
        let size = 4097   // non-multiple of 4096: the old encoder wrote 1 here
        let source = plaintext(size)
        let ct = try makeEncryptor().encryptDeterministic(
            plaintext: source, fileKey: fileKey,
            baseIV: baseIV, originalFilename: "vector.bin")

        // Rewrite offset 12 from the true count (15) back to the legacy flag value.
        var legacy = ct
        var flag = UInt32(1).littleEndian
        legacy.replaceSubrange(12..<16, with: Data(bytes: &flag, count: 4))

        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        XCTAssertEqual(try decryptor.decrypt(legacy), source,
                       "legacy flag-style cipherPadding must still decrypt")
    }

    /// The original filename survives into the header metadata.
    func testHeaderCarriesOriginalFilename() throws {
        let ct = try makeEncryptor().encryptDeterministic(
            plaintext: plaintext(100), fileKey: fileKey,
            baseIV: baseIV, originalFilename: "report.pdf")
        let jsonLen = Int(ct.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 4, as: UInt32.self)) })
        let json = ct[48..<(48 + jsonLen)]
        let decoded = try JSONDecoder().decode(BCFileHeader.self, from: json)
        XCTAssertEqual(decoded.metadata.name.value, "report.pdf")
        XCTAssertEqual(decoded.cipher.blockSize, 4096)
    }

    /// A header that outgrows the reserved region (here via an oversized filename in the JSON
    /// core) throws rather than writing a file whose length breaks ``BC01Framing``.
    func testHeaderExceedingReserveThrows() throws {
        let oversizedFilename = String(repeating: "a", count: 5000)
        let reservedSize = Int(BC01Framing.headerSize(plaintextSize: 100))
        XCTAssertThrowsError(try makeEncryptor().encryptDeterministic(
            plaintext: plaintext(100), fileKey: fileKey,
            baseIV: baseIV, originalFilename: oversizedFilename)) { error in
            guard case let BC01Error.headerExceedsReserve(headerSize, reserved) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(reserved, reservedSize)
            XCTAssertGreaterThan(headerSize, reserved)
        }
    }

    // MARK: - exactPlaintextSize

    /// The header alone determines the exact plaintext length: body length minus the stored
    /// PKCS7 pad count. This is what lets a *ranged* fetch publish the true whole-file size
    /// without decrypting the body, so it must agree with the real plaintext at every boundary
    /// size — especially exact multiples of the AES unit and of the BC01 block.
    func testExactPlaintextSizeMatchesRealPlaintext() throws {
        let encryptor = makeEncryptor()
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        for size in [0, 1, 15, 16, 17, 4095, 4096, 4097, 65_536] {
            let source = plaintext(size)
            let ct = try encryptor.encrypt(source, originalFilename: "vector.bin")
            let header = try decryptor.makeBlockContext(from: ct)

            XCTAssertEqual(
                BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: ct.count),
                size, "header-derived size mismatch at \(size)")
        }
    }

    /// The header-derived size and the post-decrypt on-disk length are the two authorities for
    /// an item's size, and `fetchContentsInline` now trusts the former on both the whole-file and
    /// the ranged path. They must never disagree.
    func testExactPlaintextSizeAgreesWithDecryptedLength() throws {
        let encryptor = makeEncryptor()
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        for size in [0, 1, 15, 16, 17, 4095, 4096, 4097, 65_536] {
            let ct = try encryptor.encrypt(plaintext(size), originalFilename: "vector.bin")
            let header = try decryptor.makeBlockContext(from: ct)
            XCTAssertEqual(
                BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: ct.count),
                try decryptor.decrypt(ct).count,
                "header-derived size diverged from decrypted length at \(size)")
        }
    }

    /// A header-only file (no body) is zero bytes of plaintext, not a negative size.
    func testExactPlaintextSizeHeaderOnlyIsZero() throws {
        let encryptor = makeEncryptor()
        let decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: userID)
        let ct = try encryptor.encrypt(Data(), originalFilename: "empty.bin")
        let header = try decryptor.makeBlockContext(from: ct)
        XCTAssertEqual(BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: header.headerEnd), 0)
        // A remote size that undercuts the header must clamp to 0 rather than go negative.
        XCTAssertEqual(BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: 0), 0)
    }

    // MARK: - hasBC01Magic

    /// The shared "are these bytes really BC01?" test. A `.bc` *name* is a declaration; the magic
    /// is the proof. Must reject short prefixes rather than reading past the end.
    func testHasBC01Magic() throws {
        let ct = try makeEncryptor().encrypt(plaintext(1024), originalFilename: "vector.bin")
        XCTAssertTrue(BC01CryptoCommon.hasBC01Magic(ct))
        XCTAssertTrue(BC01CryptoCommon.hasBC01Magic(Data(ct.prefix(4))))

        XCTAssertFalse(BC01CryptoCommon.hasBC01Magic(Data()))
        XCTAssertFalse(BC01CryptoCommon.hasBC01Magic(Data([0x62, 0x63, 0x30])), "3 bytes cannot match")
        XCTAssertFalse(BC01CryptoCommon.hasBC01Magic(Data("%PDF-1.7".utf8)))
        XCTAssertFalse(BC01CryptoCommon.hasBC01Magic(Data(repeating: 0, count: 4096)))
    }
}
