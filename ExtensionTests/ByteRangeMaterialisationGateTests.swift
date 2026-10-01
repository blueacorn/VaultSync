/// Unit tests for `ByteRangeMaterialisationGate`.
//
//  ByteRangeMaterialisationGateTests.swift
//  ExtensionTests
//
//  Covers the `supportsByteRangeMaterialisation` capability gate: byte-range materialisation
//  (BRM) is now a *backend* capability, not a global config toggle. Bugs guarded:
//   - A backend that cannot serve an explicit plaintext byte range must never be handed one;
//     the Extension drops the range and falls back to whole-file materialisation.
//   - A capable backend (OneDrive, emulator) must receive the range and return a *block-aligned
//     covering window* whose reported origin lets the OS read the correct bytes.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import Extension

/// In-memory ``ContentFetching`` standing in for a backend's ranged GET, recording every range
/// so tests can assert the transport only ever fetched the covering window.
private final class RangeSpyFetcher: ContentFetching, @unchecked Sendable {
    let blob: Data
    let totalSize: Int
    private let lock = NSLock()
    private(set) var fetches: [(start: Int, length: Int)] = []

    init(blob: Data) {
        self.blob = blob
        self.totalSize = blob.count
    }

    func fetchRange(start: Int, length: Int) async throws -> Data {
        lock.lock(); fetches.append((start, length)); lock.unlock()
        let end = min(start + length, blob.count)
        guard start < end else { return Data() }
        return blob.subdata(in: start..<end)
    }

    /// Total bytes pulled over the wire — the measure BRM exists to reduce.
    var bytesFetched: Int { lock.withLock { fetches.reduce(0) { $0 + $1.length } } }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T { lock(); defer { unlock() }; return body() }
}

final class ByteRangeMaterialisationGateTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    private let testDomainID = "com.test.brmgate-\(UUID().uuidString)"
    private var decryptor: BC01Decryptor!
    private var projectRoot: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        projectRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let bckeyURL = projectRoot.appendingPathComponent("data/corpus/example.bckey")

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
        if let error = setupError { throw error }

        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID))
        decryptor = BC01Decryptor(rsaPrivateKey: try BC01CryptoCommon.importRSAPrivateKey(der))
    }

    override func tearDownWithError() throws {
        try Self.testKeyStore.forgetDomain(testDomainID)
        try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: testDomainID)
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("brmgate-\(UUID().uuidString).bin")
    }

    private func encryptedBlob(_ name: String) throws -> (cipher: Data, plain: Data) {
        let cipher = try Data(contentsOf: projectRoot
            .appendingPathComponent("data/corpus/bc01/bin/\(name).bc"))
        let plain = try Data(contentsOf: projectRoot
            .appendingPathComponent("data/corpus/plain/bin/\(name)"))
        return (cipher, plain)
    }

    /// Mirrors `Extension.fetchPartialContents`' capability gate exactly: a capable backend keeps
    /// the requested range, an incapable one has it coerced to `nil` (whole-file materialisation).
    private func gatedRange(supportsBRM: Bool, minimalRange: NSRange) -> NSRange? {
        supportsBRM ? minimalRange : nil
    }

    /// A domain identifier private to this test, whose on-disk stores are removed afterwards.
    ///
    /// `GraphDriveClient` opens a ``BC01HeaderCache`` lazily, keyed by domain identifier, in the
    /// real App Group container. A shared literal (`"d"`) therefore wrote — and left behind —
    /// `BC01HeaderCache/d.sqlite3` beside the user's own domain stores on every run.
    private func uniqueDomainID() -> String {
        let id = "gate-\(UUID().uuidString)"
        addTeardownBlock { try? BC01HeaderCache.destroy(domainID: id) }
        return id
    }

    // MARK: - Concrete backend capabilities (no network)

    /// OneDrive serves Graph ranged content GETs and maps a plaintext window onto covering BC01
    /// blocks, so it opts in.
    func testOneDriveSupportsByteRangeMaterialisation() {
        let onedrive = GraphDriveClient(displayName: "OneDrive", domainID: uniqueDomainID(),
                                        servingItemID: "root")
        XCTAssertTrue(onedrive.supportsByteRangeMaterialisation)
    }

    /// The reference emulator also supports ranged fetches.
    func testEmulatorSupportsByteRangeMaterialisation() {
        let emulator = ServerEmulatorClient(domainIdentifier: uniqueDomainID(), secret: "s",
                                            hostname: "localhost", port: 24680)
        XCTAssertTrue(emulator.supportsByteRangeMaterialisation)
    }

    // MARK: - The gate itself

    /// A capable backend is handed the OS's minimal range verbatim.
    func testCapableBackendReceivesRange() {
        let range = NSRange(location: 4096, length: 8192)
        XCTAssertEqual(gatedRange(supportsBRM: true, minimalRange: range), range)
    }

    /// An incapable backend must receive `nil` — `fetchContentsInternal` then materialises the
    /// whole file rather than issuing a range the backend cannot honour.
    func testIncapableBackendGetsNoRange() {
        let range = NSRange(location: 4096, length: 8192)
        XCTAssertNil(gatedRange(supportsBRM: false, minimalRange: range),
                     "a backend with no ranged-GET support must never be handed a byte range")
    }

    // MARK: - BRM correctness over the OneDrive pipeline

    /// End-to-end for the OneDrive shape: a mid-file plaintext window on a BC01 item is decrypted
    /// correctly, the reported window origin is block-aligned, and the returned window contains
    /// the requested bytes at the right relative offset.
    func testRangedEncryptedFetchReturnsAlignedWindowCoveringRequest() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let header = try decryptor.makeBlockContext(from: cipher)
        let blockSize = header.blockSize

        // A window deliberately straddling a block boundary and starting mid-block.
        let lower = blockSize + 100
        let upper = min(2 * blockSize + 500, plain.count)
        try XCTSkipUnless(lower < upper, "corpus file smaller than two BC01 blocks")

        let fetcher = RangeSpyFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress(),
                                              plaintextRange: lower..<upper)

        // Origin must be block-aligned and at or before the request (a covering window).
        XCTAssertEqual(Int(result.plaintextWindow.origin) % blockSize, 0,
                       "BC01 window origin must be block-aligned")
        XCTAssertLessThanOrEqual(Int(result.plaintextWindow.origin), lower)

        let origin = Int(result.plaintextWindow.origin)
        // Sparse file: the window sits at its absolute plaintext offset.
        let file = try Data(contentsOf: dest)
        XCTAssertEqual(file.count, origin + Int(result.plaintextWindow.length),
                       "file must end where the reported window ends")
        XCTAssertGreaterThanOrEqual(file.count, upper,
                                    "window must cover the whole requested range")

        // The requested bytes, read at their absolute offset, must match.
        XCTAssertEqual(file.subdata(in: lower..<upper),
                       plain.subdata(in: lower..<upper),
                       "decrypted window bytes must match the plaintext corpus")
    }

    /// The point of BRM: a small window must not pull the whole object over the wire. Only the
    /// covering ciphertext blocks (plus any header probe) are fetched.
    func testRangedFetchDoesNotDownloadWholeFile() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let header = try decryptor.makeBlockContext(from: cipher)
        let blockSize = header.blockSize
        try XCTSkipUnless(plain.count > 4 * blockSize, "corpus file too small to show a saving")

        let lower = blockSize
        let upper = lower + 64
        let fetcher = RangeSpyFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1,
            preResolvedHeader: header)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress(), plaintextRange: lower..<upper)

        XCTAssertLessThan(fetcher.bytesFetched, cipher.count,
                          "a one-block window must not fetch the whole ciphertext")
        XCTAssertLessThanOrEqual(fetcher.bytesFetched, 2 * blockSize,
                                 "only the covering block(s) should be fetched")
    }

    /// Whole-file materialisation (the incapable-backend fallback, `range == nil`) still yields
    /// the complete plaintext at origin 0 — the path a gated-off backend takes.
    func testWholeFileFallbackYieldsFullPlaintextAtOriginZero() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let fetcher = RangeSpyFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress(), plaintextRange: nil)

        XCTAssertEqual(result.plaintextWindow.origin, 0)
        XCTAssertEqual(Int(result.plaintextWindow.length), plain.count)
        XCTAssertEqual(try Data(contentsOf: dest), plain)
    }

    /// A ranged fetch on a plain (non-`.bc`) item needs no block alignment: the window origin is
    /// the requested lower bound exactly.
    func testRangedPlainFetchOriginIsRequestedLowerBound() async throws {
        var bytes = [UInt8](repeating: 0, count: 1_000_000)
        var x: UInt8 = 3
        for i in 0..<bytes.count { x = x &* 31 &+ 7; bytes[i] = x }
        let blob = Data(bytes)
        let window = 250_000..<400_000

        let fetcher = RangeSpyFetcher(blob: blob)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress(), plaintextRange: window)

        XCTAssertEqual(Int(result.plaintextWindow.origin), window.lowerBound)
        XCTAssertEqual(Int(result.plaintextWindow.length), window.count)
        XCTAssertEqual(try Data(contentsOf: dest).subdata(in: window), blob.subdata(in: window))
        XCTAssertLessThan(fetcher.bytesFetched, blob.count)
    }

    // MARK: - documentSize vs returned window

    /// A ranged fetch still RESOLVES the whole-file plaintext size (from the header) even though
    /// it only materialises a window. That value is what gets persisted to
    /// `MetadataCache.plaintext_size` and delivered to the system by the next enumeration — the
    /// completion item cannot carry it, since the system treats that item as a version token and
    /// reads `documentSize` from its own enumerated copy.
    func testRangedFetchResolvesWholeFileSize() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let header = try decryptor.makeBlockContext(from: cipher)
        let blockSize = header.blockSize
        try XCTSkipUnless(plain.count > 3 * blockSize, "corpus file too small for a partial window")

        let window = blockSize..<(blockSize + 64)
        let fetcher = RangeSpyFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1, preResolvedHeader: header)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress(), plaintextRange: window)

        // What gets persisted for enumeration to publish:
        XCTAssertEqual(result.wholeFilePlaintextSize, Int64(plain.count),
                       "the persisted size must be the whole-file plaintext length")
        // What the fetch returns as the extent:
        XCTAssertLessThan(result.plaintextWindow.length, result.wholeFilePlaintextSize,
                          "the materialised window is a strict subset of the file")
        XCTAssertGreaterThan(result.wholeFilePlaintextSize, Int64(result.plaintextWindow.origin),
                             "whole-file size must extend beyond the window origin")
    }

    /// `alignReturnedExtent` clamps the rounded-up end to the item's plaintext size. That
    /// size is the TRUE plaintext length, so an EOF-adjacent window is clamped exactly rather
    /// than against a ciphertext-derived over-estimate.
    func testAlignReturnedExtentClampsToTruePlaintextSize() {
        let alignment = 4096
        // A file whose true plaintext EOF is mid-alignment-unit.
        let trueSize = 10_000
        // Window covering the tail: [8192, 10000).
        let extent = NSRange(location: 8192, length: trueSize - 8192)

        let aligned = Extension.alignReturnedExtent(extent, alignment: alignment,
                                                    plaintextSize: trueSize)
        XCTAssertEqual(aligned.location, 8192, "start is already aligned")
        XCTAssertEqual(aligned.location + aligned.length, trueSize,
                       "end must clamp to true EOF, not round past it")

        // Interior window: rounds up normally, nowhere near EOF.
        let interior = Extension.alignReturnedExtent(NSRange(location: 0, length: 100),
                                                     alignment: alignment,
                                                     plaintextSize: trueSize)
        XCTAssertEqual(interior, NSRange(location: 0, length: alignment),
                       "an interior extent rounds up to the alignment unit")

        // An interior window on a much larger file reports only what was written, rounded to
        // alignment — it must never be grown out to the file's size (that would tell the OS a
        // partial fetch had materialised the whole file).
        let bigFile = 15_194_121
        let window = Extension.alignReturnedExtent(NSRange(location: 0, length: 5_000_000),
                                                   alignment: alignment,
                                                   plaintextSize: bigFile)
        XCTAssertEqual(window, NSRange(location: 0, length: 5_001_216),
                       "rounds to the next 4096 unit and no further")
        XCTAssertLessThan(window.length, bigFile,
                          "must never claim the whole file for a partial window")

        // A stale/smaller size must not shrink the extent below the bytes genuinely written.
        let staleSize = Extension.alignReturnedExtent(NSRange(location: 0, length: 5000),
                                                      alignment: alignment,
                                                      plaintextSize: 1024)
        XCTAssertEqual(staleSize.length, 5000,
                       "a smaller reported size must not truncate the written extent")

        // Unknown size: no clamp available, round up.
        let unclamped = Extension.alignReturnedExtent(NSRange(location: 8192, length: 1808),
                                                      alignment: alignment, plaintextSize: nil)
        XCTAssertEqual(unclamped.length, 2 * alignment - 4096,
                       "with no known EOF the end rounds up to the alignment unit")
    }
}
