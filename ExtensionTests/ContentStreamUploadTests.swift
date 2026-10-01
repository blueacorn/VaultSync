/// Unit tests for `ContentStreamUpload`.
//
//  ContentStreamUploadTests.swift
//  ExtensionTests
//
//  Exercises the streaming encrypt + upload pipeline (`ContentStreamUploader`) over an in-memory
//  putter, with no live OneDrive. Fragments are reassembled into a sparse buffer and asserted
//  against the whole-blob encryptor and the real decryptor.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
import CryptoKit
@testable import Extension

/// In-memory ``ContentPutting`` that reassembles fragments into a single buffer and records
/// arrival order, concurrency, and coverage so tests can assert lane behaviour.
private final class FakePutter: ContentPutting, @unchecked Sendable {
    let fragmentAlignment: Int
    let supportsParallelFragments: Bool
    let singleRequestLimit: Int
    /// Artificial per-fragment delay to force out-of-order completion.
    let delay: (Int) -> UInt64
    /// Fragment index that should fail once before succeeding, to exercise retry.
    private let failOnceAt: Int?

    private let lock = NSLock()
    private var buffer = Data()
    private var covered: [Range<Int>] = []
    private(set) var arrivals: [(start: Int, length: Int)] = []
    private(set) var failedStarts: Set<Int> = []
    private var inFlight = 0
    private(set) var peakInFlight = 0
    private(set) var peakBytesInFlight = 0
    private var bytesInFlight = 0
    /// Every body handed to ``putWhole(_:)``, in call order.
    private(set) var wholeBodies: [Data] = []

    init(fragmentAlignment: Int = 320 * 1024,
         supportsParallelFragments: Bool = true,
         singleRequestLimit: Int = 0,
         failOnceAtStart: Int? = nil,
         delay: @escaping (Int) -> UInt64 = { _ in 0 }) {
        self.fragmentAlignment = fragmentAlignment
        self.supportsParallelFragments = supportsParallelFragments
        self.singleRequestLimit = singleRequestLimit
        self.failOnceAt = failOnceAtStart
        self.delay = delay
    }

    func putWhole(_ bytes: Data) async throws -> Data {
        lock.lock(); defer { lock.unlock() }
        wholeBodies.append(bytes)
        buffer = bytes
        covered = bytes.isEmpty ? [] : [0..<bytes.count]
        return Data(#"{"id":"whole"}"#.utf8)
    }

    func putRange(_ bytes: Data, start: Int, totalSize: Int) async throws -> Data? {
        lock.lock()
        inFlight += 1
        bytesInFlight += bytes.count
        peakInFlight = max(peakInFlight, inFlight)
        peakBytesInFlight = max(peakBytesInFlight, bytesInFlight)
        let shouldFail = (failOnceAt == start) && !failedStarts.contains(start)
        if shouldFail { failedStarts.insert(start) }
        lock.unlock()

        defer {
            lock.lock(); inFlight -= 1; bytesInFlight -= bytes.count; lock.unlock()
        }

        let ns = delay(start)
        if ns > 0 { try await Task.sleep(nanoseconds: ns) }

        if shouldFail { throw URLError(.badServerResponse) }

        lock.lock()
        arrivals.append((start, bytes.count))
        covered.append(start..<(start + bytes.count))
        if buffer.count < totalSize { buffer.append(Data(count: totalSize - buffer.count)) }
        buffer.replaceSubrange(start..<(start + bytes.count), with: bytes)
        let done = coveredByteCount() >= totalSize
        lock.unlock()

        return done ? Data(#"{"id":"final"}"#.utf8) : nil
    }

    /// Total distinct bytes covered (unlocked; caller holds the lock).
    private func coveredByteCount() -> Int {
        let sorted = covered.sorted { $0.lowerBound < $1.lowerBound }
        var total = 0, cursor = 0
        for r in sorted {
            let lo = max(r.lowerBound, cursor)
            if r.upperBound > lo { total += r.upperBound - lo; cursor = r.upperBound }
        }
        return total
    }

    var assembled: Data { lock.lock(); defer { lock.unlock() }; return buffer }

    /// True when fragments tile `[0, totalSize)` exactly once — no gaps, no overlap.
    func tilesExactly(_ totalSize: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let sorted = covered.sorted { $0.lowerBound < $1.lowerBound }
        var cursor = 0
        for r in sorted {
            guard r.lowerBound == cursor else { return false }
            cursor = r.upperBound
        }
        return cursor == totalSize
    }
}

final class ContentStreamUploadTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    private let testDomainID = "com.test.streamupload-\(UUID().uuidString)"
    private var rsaPrivateKey: SecKey!
    private var rsaPublicKey: SecKey!
    private var encryptor: BC01Encryptor!
    private var decryptor: BC01Decryptor!
    private var tempDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
        let bckeyURL = projectRoot.appendingPathComponent("data/corpus/example.bckey")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: bckeyURL.path),
                          "BC01 corpus keypair not present")

        let semaphore = DispatchSemaphore(value: 0)
        var setupError: Error?
        Task {
            do {
                _ = try await CryptoConfigViewModel().deriveAndStoreKey(
                    bckeyURL: bckeyURL, password: "password",
                    for: NSFileProviderDomainIdentifier(testDomainID),
                    keyStore: Self.testKeyStore)
                semaphore.signal()
            } catch { setupError = error; semaphore.signal() }
        }
        semaphore.wait()
        if let setupError { throw setupError }

        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID))
        rsaPrivateKey = try BC01CryptoCommon.importRSAPrivateKey(der)
        rsaPublicKey = try XCTUnwrap(SecKeyCopyPublicKey(rsaPrivateKey))
        encryptor = BC01Encryptor(rsaPublicKey: rsaPublicKey, userID: testDomainID)
        decryptor = BC01Decryptor(rsaPrivateKey: rsaPrivateKey, userID: testDomainID)

        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("streamupload-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? Self.testKeyStore.forgetDomain(testDomainID)
        try? CryptoKeychain.deleteUnwrappedUserIdentityKey(for: testDomainID)
        if let tempDir { try? FileManager.default.removeItem(at: tempDir) }
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    private func makeSource(_ size: Int) throws -> URL {
        let url = tempDir.appendingPathComponent("src-\(size)-\(UUID().uuidString).bin")
        let bytes = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 17) })
        try bytes.write(to: url)
        return url
    }

    private func sourceBytes(_ url: URL) throws -> Data { try Data(contentsOf: url) }

    // MARK: - Round-trip

    /// The assembled upload decrypts back to the original plaintext at every geometry boundary.
    /// This is the load-bearing assertion: it validates header placement, per-block IVs, PKCS7
    /// on the true final block, and fragment offsets in one shot.
    func testRoundTripAcrossSizes() async throws {
        let sizes = [0, 1, 4095, 4096, 4097, 8192,
                     320 * 1024 - 1, 320 * 1024, 320 * 1024 + 1,
                     5 * 1024 * 1024 + 12_345]
        for size in sizes {
            let src = try makeSource(size)
            let putter = FakePutter()
            let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4)
            let result = try await uploader.run(from: src, originalFilename: "vector.bin",
                                                progress: Progress())

            XCTAssertEqual(putter.assembled.count, result.ciphertextSize,
                           "assembled size mismatch at \(size)")
            XCTAssertTrue(putter.tilesExactly(result.ciphertextSize),
                          "fragments did not tile exactly at size \(size)")
            let recovered = try decryptor.decrypt(putter.assembled)
            XCTAssertEqual(recovered, try sourceBytes(src), "round-trip failed at size \(size)")
        }
    }

    /// A large multi-lane file round-trips — the case the whole feature exists for.
    func testLargeFileRoundTrips() async throws {
        let size = 40 * 1024 * 1024 + 777
        let src = try makeSource(size)
        let putter = FakePutter()
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 6)
        let result = try await uploader.run(from: src, originalFilename: "big.bin",
                                            progress: Progress())
        XCTAssertTrue(putter.tilesExactly(result.ciphertextSize))
        XCTAssertEqual(try decryptor.decrypt(putter.assembled), try sourceBytes(src))
    }

    /// Streamed output is byte-identical to a one-shot encrypt of the same session — the
    /// streaming path is not a second encryption format.
    ///
    /// Compared from `headerEnd` onward: the RSA-OAEP key wrap is randomised, so two headers
    /// built from the same file key still differ byte for byte. The encrypted body is the part
    /// that must match exactly.
    func testMatchesWholeBlobEncryptorBytes() async throws {
        let size = 40_000
        let src = try makeSource(size)
        let fileKey = try BC01FileKey.generate()
        let baseIV = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 11 &+ 5) })

        let session = try encryptor.makeSession(plaintextSize: size, fileKey: fileKey,
                                                baseIV: baseIV, originalFilename: "vector.bin")
        let fixed = FixedSessionEncryptor(session: session)
        let putter = FakePutter()
        let uploader = ContentStreamUploader(putter: putter, encryptor: fixed, lanes: 4,
                                             maxSpanBytes: 320 * 1024)
        _ = try await uploader.run(from: src, originalFilename: "vector.bin", progress: Progress())

        let oneShot = try fixed.encrypt(try sourceBytes(src), originalFilename: "vector.bin")
        XCTAssertEqual(putter.assembled, oneShot)

        // And it decrypts, which is the property that actually matters.
        XCTAssertEqual(try decryptor.decrypt(putter.assembled), try sourceBytes(src))
    }

    // MARK: - Fragment discipline

    /// Every non-final fragment starts at a multiple of the transport's alignment.
    func testFragmentAlignment() async throws {
        let src = try makeSource(12 * 1024 * 1024 + 5)
        let putter = FakePutter(fragmentAlignment: 320 * 1024)
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4)
        let result = try await uploader.run(from: src, originalFilename: "a.bin",
                                            progress: Progress())
        for arrival in putter.arrivals where arrival.start + arrival.length < result.ciphertextSize {
            XCTAssertEqual(arrival.start % (320 * 1024), 0,
                           "non-final fragment at \(arrival.start) is not 320 KiB aligned")
        }
    }

    /// Alignment holds across sizes and span caps. The header rides with fragment 0 and is not
    /// itself 320 KiB-aligned, so fragment 0 must be shortened to land the next boundary
    /// correctly — this is the regression guard for that.
    func testFragmentAlignmentAcrossSizesAndSpans() async throws {
        for maxSpan in [320 * 1024, 5 * 1024 * 1024] {
            for size in [2 * 1024 * 1024, 7 * 1024 * 1024 + 33, 12 * 1024 * 1024 + 5] {
                let src = try makeSource(size)
                let putter = FakePutter(fragmentAlignment: 320 * 1024)
                let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor,
                                                     lanes: 4, maxSpanBytes: maxSpan)
                let result = try await uploader.run(from: src, originalFilename: "a.bin",
                                                    progress: Progress())
                for a in putter.arrivals where a.start + a.length < result.ciphertextSize {
                    XCTAssertEqual(a.start % (320 * 1024), 0,
                                   "unaligned fragment at \(a.start), size \(size), span \(maxSpan)")
                }
                XCTAssertTrue(putter.tilesExactly(result.ciphertextSize))
                XCTAssertEqual(try decryptor.decrypt(putter.assembled), try sourceBytes(src))
            }
        }
    }

    /// Concurrency never exceeds `lanes`, and peak resident fragment bytes stay within
    /// `lanes × maxSpanBytes` — the bound that makes large files safe.
    func testLaneWindowBoundsConcurrencyAndMemory() async throws {
        let lanes = 3
        let maxSpan = 320 * 1024
        let src = try makeSource(20 * 1024 * 1024)
        let putter = FakePutter(delay: { _ in 2_000_000 })
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor,
                                             lanes: lanes, maxSpanBytes: maxSpan)
        let result = try await uploader.run(from: src, originalFilename: "a.bin",
                                            progress: Progress())

        XCTAssertGreaterThan(putter.arrivals.count, lanes,
                             "test needs more fragments than lanes to be meaningful")
        XCTAssertLessThanOrEqual(putter.peakInFlight, lanes,
                                 "in-flight fragments exceeded the lane window")
        // Header rides with fragment 0, so allow one header's slack.
        XCTAssertLessThanOrEqual(putter.peakBytesInFlight, lanes * maxSpan + 8192,
                                 "peak resident bytes exceeded lanes × maxSpanBytes")
        XCTAssertTrue(putter.tilesExactly(result.ciphertextSize))
    }

    /// Memory bound is independent of file size: doubling the file must not raise peak bytes.
    func testMemoryBoundIndependentOfFileSize() async throws {
        let lanes = 2, maxSpan = 320 * 1024
        var peaks: [Int] = []
        for size in [8 * 1024 * 1024, 32 * 1024 * 1024] {
            let src = try makeSource(size)
            let putter = FakePutter(delay: { _ in 500_000 })
            let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor,
                                                 lanes: lanes, maxSpanBytes: maxSpan)
            _ = try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())
            peaks.append(putter.peakBytesInFlight)
        }
        XCTAssertLessThanOrEqual(peaks[1], lanes * maxSpan + 8192,
                                 "4× file size raised the memory ceiling")
    }

    /// A transport that rejects concurrency receives fragments serially, in ascending order.
    func testSerialFallbackPreservesOrder() async throws {
        let src = try makeSource(6 * 1024 * 1024)
        let putter = FakePutter(supportsParallelFragments: false)
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 6,
                                             maxSpanBytes: 320 * 1024)
        _ = try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())

        XCTAssertEqual(putter.peakInFlight, 1, "serial transport saw concurrent fragments")
        let starts = putter.arrivals.map(\.start)
        XCTAssertEqual(starts, starts.sorted(), "fragments were not ascending")
    }

    /// Fragment size is chosen from plaintext size, 320 KiB-aligned, under Graph's 60 MiB cap.
    func testFragmentSizeTiers() {
        let MiB = 1024 * 1024
        XCTAssertEqual(ContentStreamUploader.fragmentBytes(forPlaintextSize: 1), 5 * MiB)
        XCTAssertEqual(ContentStreamUploader.fragmentBytes(forPlaintextSize: 31 * MiB), 5 * MiB)
        XCTAssertEqual(ContentStreamUploader.fragmentBytes(forPlaintextSize: 55 * MiB), 10 * MiB)
        XCTAssertEqual(ContentStreamUploader.fragmentBytes(forPlaintextSize: 2000 * MiB), 20 * MiB)

        for size in [0, 1, 55 * MiB, 4000 * MiB] {
            let fragment = ContentStreamUploader.fragmentBytes(forPlaintextSize: size)
            XCTAssertEqual(fragment % (320 * 1024), 0, "not 320 KiB-aligned at \(size)")
            XCTAssertLessThanOrEqual(fragment, ContentStreamUploader.transportFragmentCeiling,
                                     "exceeds Graph's per-fragment ceiling at \(size)")
        }
    }

    /// A 55 MiB upload uses 10 MiB fragments and still tiles the ciphertext exactly.
    func testDefaultSizingUsedWhenSpanNotPinned() async throws {
        let size = 55 * 1024 * 1024
        let src = try makeSource(size)
        let putter = FakePutter(supportsParallelFragments: false)
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4)
        let result = try await uploader.run(from: src, originalFilename: "big.bin",
                                            progress: Progress())

        XCTAssertTrue(putter.tilesExactly(result.ciphertextSize), "fragments did not tile")
        // 55 MiB at 10 MiB per fragment — far fewer round trips than the old 5 MiB default.
        XCTAssertEqual(putter.arrivals.count, 6, "unexpected fragment count")
        for arrival in putter.arrivals.dropLast() {
            XCTAssertEqual(arrival.start % (320 * 1024), 0, "unaligned fragment start")
        }
    }

    /// The OneDrive adapter must declare fragments serial and 320 KiB-aligned.
    ///
    /// Pins the two Graph upload-session constraints at their source. Graph documents that
    /// "the fragments of the file must be uploaded sequentially in order" and answers an
    /// out-of-order or already-received fragment with `416 Requested Range Not Satisfiable`;
    /// it separately requires every non-final fragment to be a multiple of 320 KiB. Declaring
    /// parallel fragments here fails every multi-fragment upload against the live service, and
    /// no pipeline-level test can catch it because the fault is in the transport's contract.
    func testGraphPutterDeclaresSerialAlignedFragments() {
        XCTAssertFalse(GraphContentPutter.graphSupportsParallelFragments,
                       "Graph rejects out-of-order fragments with 416; must upload serially")
        XCTAssertEqual(GraphContentPutter.graphFragmentAlignment, 327_680,
                       "Graph requires 320 KiB fragment alignment")
    }

    /// A serial transport must see strictly non-overlapping PUTs even when many lanes are
    /// configured, and the fragments must still tile the ciphertext exactly.
    ///
    /// Regression guard for the OneDrive failure: Graph's upload session keeps a single
    /// expected-range cursor and documents that "fragments must be uploaded sequentially in
    /// order", answering anything else with 416. Configuring lanes > 1 must not leak
    /// concurrency past a putter that declares `supportsParallelFragments == false`.
    func testSerialTransportIgnoresLaneCount() async throws {
        let size = 12 * 1024 * 1024
        let src = try makeSource(size)
        let putter = FakePutter(supportsParallelFragments: false,
                                delay: { _ in 200_000 })
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 8,
                                             maxSpanBytes: 640 * 1024)
        let result = try await uploader.run(from: src, originalFilename: "a.bin",
                                            progress: Progress())

        XCTAssertEqual(putter.peakInFlight, 1,
                       "lanes:8 leaked concurrency past a serial transport")

        // Ascending, gapless, non-overlapping, and covering exactly [0, ciphertextSize).
        var cursor = 0
        for arrival in putter.arrivals {
            XCTAssertEqual(arrival.start, cursor, "fragment did not resume at the cursor")
            cursor += arrival.length
        }
        XCTAssertEqual(cursor, result.ciphertextSize, "fragments did not tile the ciphertext")
    }

    /// Out-of-order lane completion still assembles correctly — offsets, not arrival order,
    /// determine placement.
    func testOutOfOrderCompletionStillAssembles() async throws {
        let src = try makeSource(8 * 1024 * 1024)
        // Later fragments finish first.
        let putter = FakePutter(delay: { start in start == 0 ? 8_000_000 : 500_000 })
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4,
                                             maxSpanBytes: 320 * 1024)
        let result = try await uploader.run(from: src, originalFilename: "a.bin",
                                            progress: Progress())
        XCTAssertTrue(putter.tilesExactly(result.ciphertextSize))
        XCTAssertEqual(try decryptor.decrypt(putter.assembled), try sourceBytes(src))
    }

    // MARK: - Plain passthrough

    /// A plain domain uploads the file untouched: no header, ciphertext == plaintext.
    func testPlainEncryptorPassesThrough() async throws {
        let size = 3 * 1024 * 1024
        let src = try makeSource(size)
        let putter = FakePutter()
        let uploader = ContentStreamUploader(putter: putter, encryptor: PlainFileEncryptor(),
                                             lanes: 4, maxSpanBytes: 320 * 1024)
        let result = try await uploader.run(from: src, originalFilename: "a.txt",
                                            progress: Progress())
        XCTAssertEqual(result.ciphertextSize, size)
        XCTAssertEqual(putter.assembled, try sourceBytes(src))
    }

    // MARK: - Single-request path

    /// A ciphertext within the transport's one-shot limit goes out as exactly one `putWhole`.
    func testWithinLimitUsesSinglePutWhole() async throws {
        let src = try makeSource(100_000)
        let putter = FakePutter(singleRequestLimit: 4 * 1024 * 1024)
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4)
        let result = try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())
        XCTAssertEqual(putter.wholeBodies.count, 1)
        XCTAssertTrue(putter.arrivals.isEmpty, "no fragment may be sent on the single-request path")
        XCTAssertEqual(result.completionPayload, Data(#"{"id":"whole"}"#.utf8))
        XCTAssertEqual(putter.wholeBodies[0].count, result.ciphertextSize)
        XCTAssertEqual(try decryptor.decrypt(putter.wholeBodies[0]), try sourceBytes(src))
        XCTAssertNotNil(result.blockContext)
    }

    /// Over the limit, the object is fragmented and `putWhole` is never called.
    func testOverLimitNeverUsesPutWhole() async throws {
        let src = try makeSource(2 * 1024 * 1024)
        let putter = FakePutter(singleRequestLimit: 1024 * 1024)
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4)
        let result = try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())
        XCTAssertTrue(putter.wholeBodies.isEmpty)
        XCTAssertTrue(putter.tilesExactly(result.ciphertextSize))
    }

    /// An empty file always takes `putWhole`: header only (BC01) or zero bytes (plain), even
    /// with the single-request path disabled.
    func testEmptyFileUsesPutWhole() async throws {
        let src = try makeSource(0)
        let bcPutter = FakePutter(singleRequestLimit: 0)
        let bc = try await ContentStreamUploader(putter: bcPutter, encryptor: encryptor, lanes: 1)
            .run(from: src, originalFilename: "a.bin", progress: Progress())
        XCTAssertEqual(bcPutter.wholeBodies.count, 1)
        XCTAssertEqual(bcPutter.wholeBodies[0].count, bc.ciphertextSize)
        XCTAssertGreaterThan(bc.ciphertextSize, 0, "BC01 empty file still carries its header")
        XCTAssertTrue(bcPutter.arrivals.isEmpty)

        let plainPutter = FakePutter(singleRequestLimit: 0)
        _ = try await ContentStreamUploader(putter: plainPutter, encryptor: PlainFileEncryptor(), lanes: 1)
            .run(from: src, originalFilename: "a.bin", progress: Progress())
        XCTAssertEqual(plainPutter.wholeBodies, [Data()])
        XCTAssertTrue(plainPutter.arrivals.isEmpty)
    }

    /// `singleRequestLimit == 0` disables the single-request path for non-empty files.
    func testZeroLimitDisablesSingleRequest() async throws {
        let src = try makeSource(10)
        let putter = FakePutter(singleRequestLimit: 0)
        let result = try await ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 1)
            .run(from: src, originalFilename: "a.bin", progress: Progress())
        XCTAssertTrue(putter.wholeBodies.isEmpty)
        XCTAssertTrue(putter.tilesExactly(result.ciphertextSize))
    }

    /// `ciphertextSize == limit` fits; `limit - 1` fragments. A plaintext of exactly the limit
    /// is pushed over it by the BC01 header reserve.
    func testSingleRequestBoundary() async throws {
        let limit = 4 * 1024 * 1024
        // A short (padded) final block just under the limit; its framed size is the boundary.
        let fitting = limit - Int(BC01Framing.headerSize(plaintextSize: Int64(limit))) - 16
        let exactLimit = Int(BC01Framing.ciphertextSize(plaintextSize: Int64(fitting)))
        XCTAssertLessThanOrEqual(exactLimit, limit)

        let exact = try makeSource(fitting)
        let exactPutter = FakePutter(singleRequestLimit: exactLimit)
        let exactResult = try await ContentStreamUploader(putter: exactPutter, encryptor: encryptor, lanes: 1)
            .run(from: exact, originalFilename: "a.bin", progress: Progress())
        XCTAssertEqual(exactResult.ciphertextSize, exactLimit)
        XCTAssertEqual(exactPutter.wholeBodies.count, 1)

        let overPutter = FakePutter(singleRequestLimit: exactLimit - 1)
        _ = try await ContentStreamUploader(putter: overPutter, encryptor: encryptor, lanes: 1)
            .run(from: exact, originalFilename: "a.bin", progress: Progress())
        XCTAssertTrue(overPutter.wholeBodies.isEmpty, "exactLimit - 1 must fragment")

        let fourMiB = try makeSource(limit)
        let fourPutter = FakePutter(singleRequestLimit: limit)
        let fourResult = try await ContentStreamUploader(putter: fourPutter, encryptor: encryptor, lanes: 1)
            .run(from: fourMiB, originalFilename: "a.bin", progress: Progress())
        XCTAssertGreaterThan(fourResult.ciphertextSize, limit)
        XCTAssertTrue(fourPutter.wholeBodies.isEmpty)
        XCTAssertEqual(try decryptor.decrypt(fourPutter.assembled), try sourceBytes(fourMiB))
    }

    // MARK: - Completion, progress, failure

    /// Exactly one fragment carries the completion payload.
    func testSingleCompletionPayload() async throws {
        let src = try makeSource(4 * 1024 * 1024)
        let putter = FakePutter()
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4,
                                             maxSpanBytes: 320 * 1024)
        let result = try await uploader.run(from: src, originalFilename: "a.bin",
                                            progress: Progress())
        XCTAssertEqual(result.completionPayload, Data(#"{"id":"final"}"#.utf8))
    }

    /// A transport that never acknowledges completion is an error, not a silent success.
    func testMissingCompletionPayloadThrows() async throws {
        final class SilentPutter: ContentPutting, @unchecked Sendable {
            var fragmentAlignment: Int { 320 * 1024 }
            var supportsParallelFragments: Bool { true }
            var singleRequestLimit: Int { 0 }
            func putWhole(_ bytes: Data) async throws -> Data { Data() }
            func putRange(_ bytes: Data, start: Int, totalSize: Int) async throws -> Data? { nil }
        }
        let src = try makeSource(1024)
        let uploader = ContentStreamUploader(putter: SilentPutter(), encryptor: encryptor, lanes: 2)
        do {
            _ = try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())
            XCTFail("expected an error when no fragment completes the upload")
        } catch {
            XCTAssertTrue(error is CommonError, "unexpected error: \(error)")
        }
    }

    /// Progress reaches its total on success.
    func testProgressCompletes() async throws {
        let src = try makeSource(6 * 1024 * 1024)
        let progress = Progress()
        let putter = FakePutter()
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4,
                                             maxSpanBytes: 320 * 1024)
        _ = try await uploader.run(from: src, originalFilename: "a.bin", progress: progress)
        XCTAssertEqual(progress.completedUnitCount, progress.totalUnitCount)
        XCTAssertGreaterThan(progress.totalUnitCount, 0)
    }

    /// A fragment failure propagates rather than completing a partial upload.
    func testFragmentFailurePropagates() async throws {
        let src = try makeSource(6 * 1024 * 1024)
        let putter = FakePutter(failOnceAtStart: 0)
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4,
                                             maxSpanBytes: 320 * 1024)
        do {
            _ = try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())
            XCTFail("expected the fragment failure to propagate")
        } catch {
            XCTAssertTrue(error is URLError, "unexpected error: \(error)")
        }
    }

    /// Cancellation mid-transfer surfaces as an error and does not complete.
    func testCancellationPropagates() async throws {
        let src = try makeSource(32 * 1024 * 1024)
        let putter = FakePutter(delay: { _ in 50_000_000 })
        let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 2,
                                             maxSpanBytes: 320 * 1024)
        let task = Task {
            try await uploader.run(from: src, originalFilename: "a.bin", progress: Progress())
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            // CancellationError, or a transport error raised as the lane unwound.
            XCTAssertTrue(error is CancellationError || error is URLError || error is CommonError,
                          "unexpected error: \(error)")
        }
    }

    // MARK: - Cross-pipeline integration

    /// Upload through `ContentStreamUploader`, then materialise the result through
    /// `ContentStreamDownloader`. This closes the loop across both pipelines and is the
    /// strongest single guard on the shared BC01 geometry: any disagreement about header end,
    /// block indices, or padding shows up as corrupt plaintext here.
    func testUploadThenDownloadRoundTrips() async throws {
        for size in [4097, 320 * 1024 + 11, 9 * 1024 * 1024 + 1234] {
            let src = try makeSource(size)
            let putter = FakePutter()
            let uploader = ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4,
                                                 maxSpanBytes: 320 * 1024)
            let uploaded = try await uploader.run(from: src, originalFilename: "vector.bin",
                                                  progress: Progress())

            // Feed the assembled ciphertext back through the download pipeline.
            let fetcher = ReplayFetcher(blob: putter.assembled)
            let downloader = ContentStreamDownloader(
                fetcher: fetcher, decryptor: decryptor,
                isEncrypted: true, lanes: 4, threshold: 1)
            let dest = tempDir.appendingPathComponent("rt-\(size).bin")
            let result = try await downloader.run(to: dest, progress: Progress())

            XCTAssertEqual(Int(result.plaintextWindow.length), size, "plaintext size mismatch at \(size)")
            XCTAssertEqual(try Data(contentsOf: dest), try sourceBytes(src),
                           "cross-pipeline round-trip failed at size \(size)")
            XCTAssertEqual(uploaded.ciphertextSize, putter.assembled.count)
        }
    }

    /// Emulator: every size goes out as one whole-body RPC through the shared uploader, and the
    /// body round-trips through the download pipeline for both BC01 and plain.
    func testEmulatorPutterRoundTripsBC01AndPlain() async throws {
        final class Captured: @unchecked Sendable { var bodies: [Data] = [] }
        for size in [0, 1, 4096, 9 * 1024 * 1024 + 5] {
            let src = try makeSource(size)
            for (encryptor, fileDecryptor, isEncrypted) in [
                (encryptor as any FileEncryptor, decryptor as any FileDecryptor, true),
                (PlainFileEncryptor(), PlainFileDecryptor(), false)
            ] {
                let captured = Captured()
                let putter = EmulatorContentPutter { body in
                    captured.bodies.append(body)
                    return Data()
                }
                let result = try await ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 4)
                    .run(from: src, originalFilename: "vector.bin", progress: Progress())
                XCTAssertEqual(captured.bodies.count, 1, "one RPC at size \(size)")
                XCTAssertEqual(isEncrypted, result.blockContext != nil)

                let dest = tempDir.appendingPathComponent("emu-\(size)-\(isEncrypted).bin")
                _ = try await ContentStreamDownloader(
                    fetcher: ReplayFetcher(blob: captured.bodies[0]), decryptor: fileDecryptor,
                    isEncrypted: isEncrypted, lanes: 4, threshold: 1)
                    .run(to: dest, progress: Progress())
                XCTAssertEqual(try Data(contentsOf: dest), try sourceBytes(src),
                               "emulator round-trip failed at \(size) encrypted=\(isEncrypted)")
            }
        }
    }

    // MARK: - Geometry unit tests

    /// `BC01UploadPlan` agrees with the encryptor about total ciphertext size.
    func testPlanCiphertextSizeMatchesEncryptor() throws {
        for size in [0, 1, 4095, 4096, 4097, 40_000, 5 * 1024 * 1024 + 3] {
            let session = try encryptor.beginSession(plaintextSize: size, originalFilename: "a.bin")
            let plan = BC01UploadPlan(headerSize: session.headerBytes.count,
                                      plaintextSize: size, blockSize: session.blockSize,
                                      cipherPadding: session.cipherPadding)
            let actual = try encryptor.encrypt(
                Data((0..<size).map { UInt8(truncatingIfNeeded: $0) }), originalFilename: "a.bin")
            // Header length varies only with the RSA wrap, which is fixed-width for a given key.
            XCTAssertEqual(plan.ciphertextSize, actual.count, "plan size mismatch at \(size)")
        }
    }

    /// Lane spans tile the block range exactly and stay within the span cap.
    func testLaneSpansTileBlockRange() {
        let plan = BC01UploadPlan(headerSize: 4096, plaintextSize: 50 * 1024 * 1024,
                                  blockSize: 4096,
                                  cipherPadding: BC01CryptoCommon.cipherPadding(
                                      plaintextSize: 50 * 1024 * 1024))
        let spans = plan.laneSpans(maxSpanBytes: 5 * 1024 * 1024, alignment: 320 * 1024)
        var cursor = 0
        for span in spans {
            XCTAssertEqual(span.lowerBound, cursor)
            cursor = span.upperBound
            XCTAssertLessThanOrEqual(span.count * 4096, 5 * 1024 * 1024)
        }
        XCTAssertEqual(cursor, plan.blockCount)
    }
}

/// Serves ranges out of an in-memory ciphertext blob, for feeding upload output back into the
/// download pipeline.
private struct ReplayFetcher: ContentFetching {
    let blob: Data
    var totalSize: Int { blob.count }
    func fetchRange(start: Int, length: Int) async throws -> Data {
        let end = min(start + length, blob.count)
        guard start < end else { return Data() }
        return blob.subdata(in: start..<end)
    }
}

/// Encryptor that hands out one pre-built session, so a streamed run and a one-shot encrypt
/// share key material and can be compared byte for byte.
private struct FixedSessionEncryptor: FileEncryptor {
    let session: BC01EncryptionSession

    func encrypt(_ plaintext: Data, originalFilename: String) throws -> Data {
        var out = session.headerBytes
        out.append(try session.encryptBlocks(plaintext, firstBlock: 0, isFinal: true))
        return out
    }

    func beginSession(plaintextSize: Int, originalFilename: String) throws -> any FileEncryptionSession {
        session
    }
}

// MARK: - Header cache seeding

extension ContentStreamUploadTests {

    private func assertSameHeader(_ a: BC01Header?, _ b: BC01Header?,
                                  file: StaticString = #filePath, line: UInt = #line) {
        guard let a, let b else { return XCTFail("missing header", file: file, line: line) }
        XCTAssertEqual(a.baseIV, b.baseIV, file: file, line: line)
        XCTAssertEqual(a.fileKey, b.fileKey, file: file, line: line)
        XCTAssertEqual(a.blockSize, b.blockSize, file: file, line: line)
        XCTAssertEqual(a.headerEnd, b.headerEnd, file: file, line: line)
        XCTAssertEqual(a.cipherPadding, b.cipherPadding, file: file, line: line)
    }

    private func makeCache(keyProvider: @escaping () throws -> SymmetricKey) throws -> (BC01HeaderCache, String) {
        let domain = "seed-\(UUID().uuidString)"
        return (try BC01HeaderCache(domainID: domain, keyProvider: keyProvider, keyResidencySeconds: 0), domain)
    }

    /// The session's block context must be exactly what the download probe parses from its header.
    func testSessionBlockContextMatchesParsedHeader() throws {
        let session = try encryptor.beginSession(plaintextSize: 10_000, originalFilename: "a.txt")
        assertSameHeader(session.blockContext, try decryptor.makeBlockContext(from: session.headerBytes))
        XCTAssertNil(PlainEncryptionSession(plaintextSize: 10).blockContext)
    }

    /// Seeding writes a row keyed on the content identity (stamp stripped) that the read side hits.
    func testSeedStoresRowReadableByDownloadKey() throws {
        let kek = SymmetricKey(size: .bits256)
        let (cache, domain) = try makeCache { kek }
        defer { try? BC01HeaderCache.destroy(domainID: domain) }
        let session = try encryptor.beginSession(plaintextSize: 10_000, originalFilename: "a.txt")
        let revision = DomainService.Version(content: "cTag2\(DomainService.Version.Separator)10000",
                                             metadata: "eTag2")

        HeaderCacheSeeding.seed(cache, header: session.blockContext, itemID: "item", contentIdentity: revision.contentIdentity)

        assertSameHeader(cache.header(itemID: "item", contentRevision: revision.contentIdentity),
                         session.blockContext)
        XCTAssertEqual(try cache.rawRow(itemID: "item")?.contentRevision, "cTag2")
    }

    /// No header, or a store that cannot seal (vault locked), must drop any existing row.
    func testSeedInvalidatesWhenHeaderUnavailableOrStoreFails() throws {
        let kek = SymmetricKey(size: .bits256)
        var locked = false
        let (cache, domain) = try makeCache {
            if locked { throw VaultKeyStoreError.locked }
            return kek
        }
        defer { try? BC01HeaderCache.destroy(domainID: domain) }
        let old = try XCTUnwrap(try encryptor.beginSession(plaintextSize: 1, originalFilename: "a").blockContext)
        let rev1 = DomainService.Version(content: "c1", metadata: "e1")
        let rev2 = DomainService.Version(content: "c2", metadata: "e2")

        try cache.store(old, itemID: "item", contentRevision: "c1")
        HeaderCacheSeeding.seed(cache, header: nil, itemID: "item", contentIdentity: rev2.contentIdentity)
        XCTAssertNil(try cache.rawRow(itemID: "item"), "nil header must invalidate")

        try cache.store(old, itemID: "item", contentRevision: "c1")
        locked = true
        HeaderCacheSeeding.seed(cache, header: old, itemID: "item", contentIdentity: rev1.contentIdentity)
        XCTAssertNil(try cache.rawRow(itemID: "item"), "failed store must invalidate")
    }
}
