/// Unit tests for `ContentStreamDownload`.
//
//  ContentStreamDownloadTests.swift
//  ExtensionTests
//
//  Exercises the streaming download + decrypt + offset-write pipeline
//  (`ContentStreamDownloader`) over an in-memory transport, with no live OneDrive. Correctness
//  is asserted against the BC01 corpus and the whole-blob decryptor.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
import FileProvider
import Common
@testable import Extension

/// In-memory ``ContentFetching`` over a fixed blob, with optional per-range delay and an
/// observable fetch log so tests can assert lane fan-out and order-independence.
private final class FakeFetcher: ContentFetching, @unchecked Sendable {
    let blob: Data
    let totalSize: Int
    /// Artificial per-fetch delay (nanoseconds) to force out-of-order lane completion.
    let delay: (Int) -> UInt64
    private let lock = NSLock()
    private(set) var fetches: [(start: Int, length: Int)] = []
    /// Concurrent `fetchRange` calls, and the high-water mark across the run, so tests can
    /// assert the downloader bounds in-flight requests to its lane count.
    private var inFlight = 0
    private(set) var peakInFlight = 0

    init(blob: Data, delay: @escaping (Int) -> UInt64 = { _ in 0 }) {
        self.blob = blob
        self.totalSize = blob.count
        self.delay = delay
    }

    func fetchRange(start: Int, length: Int) async throws -> Data {
        lock.lock()
        fetches.append((start, length))
        inFlight += 1
        peakInFlight = max(peakInFlight, inFlight)
        lock.unlock()
        defer { lock.lock(); inFlight -= 1; lock.unlock() }
        let ns = delay(start)
        if ns > 0 { try await Task.sleep(nanoseconds: ns) }
        let end = min(start + length, blob.count)
        return blob.subdata(in: start..<end)
    }
}

final class ContentStreamDownloadTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    private let testDomainID = "com.test.graphstream-\(UUID().uuidString)"
    private var decryptor: BC01Decryptor!
    private var projectRoot: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        // ExtensionTests/ → repo root is one level up.
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

        // Provisioning seals the DER under the VMK and releases it to the Provider-readable
        // unwrapped slot; that slot is where the plaintext DER now lives.
        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID))
        decryptor = BC01Decryptor(rsaPrivateKey: try BC01CryptoCommon.importRSAPrivateKey(der))
    }

    override func tearDownWithError() throws {
        try Self.testKeyStore.forgetDomain(testDomainID)
        try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: testDomainID)
        try super.tearDownWithError()
    }

    // MARK: - Vault-locked gate

    /// With a KEK enrolled the raw slot is removed and the key lives wrapped, so an empty
    /// unwrapped slot means the vault is locked and ``CryptoKeychain/loadUserIdentityPrivateKey(for:)``
    /// must return nil. Callers surface this as a typed "vault locked" error.
    func testLoadUserIdentityPrivateKeyNilWhenUnwrappedSlotEmpty() throws {
        // Lock: the unwrapped slot is the only readable copy, so evicting it is the whole lock.
        try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: testDomainID)
        XCTAssertNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: testDomainID),
                     "locked vault must present no usable session key to the Provider")
    }

    /// There is no raw-slot fallback in any gating: with the unwrapped slot evicted the
    /// key is unavailable even though the wrapped blob is still on disk. This is the guard —
    /// no gating may leave a promptless path to key material.
    func testLoadUserIdentityPrivateKeyHasNoRawSlotFallback() throws {
        XCTAssertNotNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: testDomainID),
                        "precondition: the wrapped blob is present")
        try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: testDomainID)

        XCTAssertNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: testDomainID),
                     "a locked vault must expose no session key, wrapped blob notwithstanding")
    }

    /// Populating the unwrapped slot (unlock) makes the key available again.
    func testLoadUserIdentityPrivateKeyPresentAfterUnwrappedSlotPopulated() throws {
        let der = try XCTUnwrap(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID))
        try CryptoKeychain.storeUnwrappedUserIdentityKey(der, for: testDomainID)
        XCTAssertNotNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: testDomainID))
    }

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("graphstream-\(UUID().uuidString).bin")
    }

    // MARK: - Plain (plaintext == ciphertext)

    /// Deterministic pseudo-random blob of `count` bytes (cheap to construct).
    private func makeBlob(_ count: Int, seed: UInt8 = 1) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var x: UInt8 = seed
        for i in 0..<count { x = x &* 31 &+ 7; bytes[i] = x }
        return Data(bytes)
    }

    func testSingleLanePlain() async throws {
        let blob = makeBlob(200 * 1024)
        let fetcher = FakeFetcher(blob: blob)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 1, threshold: 8 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let progress = Progress(totalUnitCount: 0)
        let result = try await downloader.run(to: dest, progress: progress)

        XCTAssertEqual(try Data(contentsOf: dest), blob)
        XCTAssertEqual(result.plaintextWindow.length, Int64(blob.count))
        XCTAssertEqual(progress.completedUnitCount, progress.totalUnitCount)
    }

    func testMultiLanePlainReassembles() async throws {
        let blob = makeBlob(10 * 1024 * 1024 + 777, seed: 9)
        // Reverse-bias delays so later spans finish first.
        let fetcher = FakeFetcher(blob: blob, delay: { start in UInt64(max(0, 2_000_000 - start)) })
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 8, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), blob)
        XCTAssertEqual(result.plaintextWindow.length, Int64(blob.count))
        XCTAssertGreaterThan(fetcher.fetches.count, 1, "expected multi-lane fan-out")
    }

    // MARK: - Zero-length remotes

    /// An empty plain file is a legitimate object, not a failure: the pipeline must create a
    /// 0-byte destination and report zero sizes without issuing any ranged GET (there is no
    /// byte to ask for, and a `[0,0)` request is not a valid range).
    func testZeroLengthPlainMaterialisesEmptyFile() async throws {
        let fetcher = FakeFetcher(blob: Data())
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 8, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.path))
        XCTAssertEqual(try Data(contentsOf: dest).count, 0)
        XCTAssertEqual(result.plaintextWindow.length, 0)
        XCTAssertEqual(result.plaintextWindow.origin, 0)
        XCTAssertEqual(result.wholeFilePlaintextSize, 0)
        XCTAssertTrue(fetcher.fetches.isEmpty, "a zero-byte object needs no ranged GET")
    }

    /// A zero-byte object named `.bc` carries no BC01 magic, so the header probe must fall through
    /// to the plain path rather than throwing `invalidHeader`.
    func testZeroLengthEncryptedNameFallsThroughToPlain() async throws {
        let fetcher = FakeFetcher(blob: Data())
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 8, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.path))
        XCTAssertEqual(try Data(contentsOf: dest).count, 0)
        XCTAssertEqual(result.plaintextWindow.length, 0)
        XCTAssertEqual(result.wholeFilePlaintextSize, 0)
    }

    // MARK: - Truncation detection

    /// Regression: a backend that returns a short body for a whole-file plain fetch
    /// used to have that truncation written to disk and reported as the complete plaintext size,
    /// so the OS stamped the item materialised over a partial file. It must fail instead.
    func testPlainShortReadThrowsRatherThanTruncating() async throws {
        let blob = makeBlob(12 * 1024 * 1024, seed: 21)
        let fetcher = TruncatingFetcher(blob: blob, cutoff: 5 * 1024 * 1024)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 1, threshold: 64 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        do {
            let result = try await downloader.run(to: dest, progress: Progress())
            XCTFail("expected truncation to throw; got plaintextSize \(result.plaintextWindow.length)")
        } catch let error as ContentStreamError {
            guard case .shortRead = error else {
                return XCTFail("expected .shortRead, got \(error)")
            }
        }
    }

    /// A gap in the middle of a multi-lane plain transfer must not be reported as success:
    /// `maxOffsetEnd` alone would show the furthest span and hide the hole beneath it.
    func testPlainMissingMiddleSpanIsDetected() async throws {
        let blob = makeBlob(8 * 1024 * 1024, seed: 22)
        let fetcher = TruncatingFetcher(blob: blob, cutoff: blob.count, emptyAfter: 1)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1, maxSpanBytes: 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        do {
            _ = try await downloader.run(to: dest, progress: Progress())
            XCTFail("expected an incomplete transfer to throw")
        } catch is ContentStreamError {
            // expected
        }
    }

    /// A complete transfer must still succeed once the guards are in place — the exactness check
    /// is bounded by the object's real end, so a final short tail read is legitimate.
    func testCompletePlainTransferStillSucceeds() async throws {
        let blob = makeBlob(6 * 1024 * 1024 + 13, seed: 23)
        let fetcher = FakeFetcher(blob: blob)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1, maxSpanBytes: 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())
        XCTAssertEqual(try Data(contentsOf: dest), blob)
        XCTAssertEqual(result.plaintextWindow.length, Int64(blob.count))
        XCTAssertEqual(result.wholeFilePlaintextSize, Int64(blob.count))
    }

    // MARK: - Span cap

    /// Without a cap a lane's span is `size / lanes`, so a large file yields a few huge requests:
    /// one failure discards the whole span and lane skew strands a single stream in the tail.
    /// With the cap set, no request may exceed it.
    func testPlainSpanCapBoundsRequestSize() async throws {
        let blob = makeBlob(8 * 1024 * 1024, seed: 3)
        let fetcher = FakeFetcher(blob: blob)
        let cap = 512 * 1024
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1, maxSpanBytes: cap)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), blob, "capped spans must still reassemble exactly")
        XCTAssertEqual(fetcher.fetches.count, 16, "8 MiB at a 512 KiB cap is 16 requests, not 4 lanes")
        for fetch in fetcher.fetches {
            XCTAssertLessThanOrEqual(fetch.length, cap, "no request may exceed the span cap")
        }
    }

    /// The cap produces more spans than lanes; those extra spans are queued work, not extra
    /// concurrency. In-flight requests must stay bounded by the lane count, or the cap would
    /// simply move the burst into URLSession's queue and inflate peak memory.
    func testSpanCapDoesNotRaiseConcurrency() async throws {
        let blob = makeBlob(4 * 1024 * 1024, seed: 5)
        let fetcher = FakeFetcher(blob: blob, delay: { _ in 2_000_000 })
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 3, threshold: 1, maxSpanBytes: 256 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), blob)
        XCTAssertGreaterThan(fetcher.fetches.count, 3, "cap must split into more spans than lanes")
        XCTAssertLessThanOrEqual(fetcher.peakInFlight, 3, "in-flight requests must stay within the lane count")
    }

    /// A zero cap is the opt-out: partitioning reverts to an even split across the lanes.
    func testZeroSpanCapKeepsEvenLaneSplit() async throws {
        let blob = makeBlob(4 * 1024 * 1024, seed: 7)
        let fetcher = FakeFetcher(blob: blob)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1, maxSpanBytes: 0)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), blob)
        XCTAssertEqual(fetcher.fetches.count, 4, "no cap means exactly one span per lane")
    }

    /// The encrypted path must stay block-aligned under the cap: every capped span decrypts
    /// independently, including the final block carrying PKCS7 padding.
    func testEncryptedSpanCapMatchesWholeBlobPlaintext() async throws {
        let (cipher, plain) = try encryptedBlob("jellyfish.bin") // ~9.5 MB
        let cap = 512 * 1024
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1, maxSpanBytes: cap)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain, "capped block-aligned spans must decrypt exactly")
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        // Body spans honour the cap; the header probe is a separate, smaller fetch.
        let bodyFetches = fetcher.fetches.filter { $0.length > cap }
        XCTAssertTrue(bodyFetches.isEmpty, "no body request may exceed the span cap")
        XCTAssertGreaterThan(fetcher.fetches.count, 4, "cap must split the body beyond the lane count")
    }

    // MARK: - Encrypted

    private func encryptedBlob(_ name: String) throws -> (cipher: Data, plain: Data) {
        let cipher = try Data(contentsOf: projectRoot
            .appendingPathComponent("data/corpus/bc01/bin/\(name).bc"))
        let plain = try Data(contentsOf: projectRoot
            .appendingPathComponent("data/corpus/plain/bin/\(name)"))
        return (cipher, plain)
    }

    func testSingleLaneEncrypted() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 8 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
    }

    func testMultiLaneEncryptedOutOfOrder() async throws {
        let (cipher, plain) = try encryptedBlob("jellyfish.bin") // ~9.5 MB
        let fetcher = FakeFetcher(blob: cipher, delay: { start in UInt64(max(0, 3_000_000 - start / 4)) })
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 8, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain, "8-lane encrypted decrypt must match whole-blob plaintext")
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        XCTAssertGreaterThan(fetcher.fetches.count, 2, "expected header probe + multiple lanes")
    }

    func testHeaderLargerThanProbeRefetches() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let fetcher = FakeFetcher(blob: cipher)
        // Force a tiny probe so the header (a few KB) exceeds it and the refetch path runs.
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 8 * 1024 * 1024, headerProbeLen: 64)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        // First fetch is the 64-byte probe; a later fetch must cover more (the refetch).
        XCTAssertEqual(fetcher.fetches.first?.length, 64)
        XCTAssertGreaterThan(fetcher.fetches.count, 1)
    }

    // MARK: - Progress quantisation

    func testProgressIsQuantisedAndMonotonic() async throws {
        let (cipher, _) = try encryptedBlob("jellyfish.bin")
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 8, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let progress = Progress()

        // Observe every completedUnitCount mutation.
        final class Box: @unchecked Sendable { var samples: [Int64] = []; let lock = NSLock() }
        let box = Box()
        let obs = progress.observe(\.completedUnitCount, options: [.new]) { p, _ in
            box.lock.lock(); box.samples.append(p.completedUnitCount); box.lock.unlock()
        }
        defer { obs.invalidate() }

        _ = try await downloader.run(to: dest, progress: progress)

        let samples = box.samples
        XCTAssertFalse(samples.isEmpty)
        // Monotonic non-decreasing.
        XCTAssertEqual(samples, samples.sorted())
        XCTAssertEqual(samples.last, progress.totalUnitCount)
        // ~10 quantised steps + final; allow generous slack but reject per-block thrash.
        XCTAssertLessThanOrEqual(samples.count, 14, "progress should be quantised (~10 updates)")
    }

    /// A ranged fetch reports progress against the whole file: it starts at the window origin's
    /// fraction (never resetting to 0%) and ends at the window end's fraction (never 100%).
    func testRangedProgressIsRelativeToWholeFile() async throws {
        let blob = makeBlob(1_000_000, seed: 7)
        let window = 500_000..<750_000
        let downloader = ContentStreamDownloader(
            fetcher: FakeFetcher(blob: blob), decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let progress = Progress()
        final class Box: @unchecked Sendable { var samples: [Int64] = []; let lock = NSLock() }
        let box = Box()
        let obs = progress.observe(\.completedUnitCount, options: [.new]) { p, _ in
            box.lock.lock(); box.samples.append(p.completedUnitCount); box.lock.unlock()
        }
        defer { obs.invalidate() }

        _ = try await downloader.run(to: dest, progress: progress, plaintextRange: window)

        XCTAssertEqual(progress.totalUnitCount, Int64(blob.count), "total is the whole file")
        XCTAssertEqual(box.samples.first, Int64(window.lowerBound), "starts at the window origin")
        XCTAssertEqual(box.samples, box.samples.sorted(), "monotonic")
        XCTAssertEqual(progress.completedUnitCount, Int64(window.upperBound), "ends at the window end")
        XCTAssertEqual(progress.fractionCompleted, 0.75, accuracy: 0.0001)
    }

    // MARK: - Cancellation

    func testCancellationRemovesPartialFile() async throws {
        let (cipher, _) = try encryptedBlob("jellyfish.bin")
        // Slow every fetch so we can cancel mid-flight.
        let fetcher = FakeFetcher(blob: cipher, delay: { _ in 200_000_000 })
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 8, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }

        let task = Task { try await downloader.run(to: dest, progress: Progress()) }
        try await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("cancelled download should throw")
        } catch is CancellationError {
            // Expected.
        }
        // The driver (downloadToFile) removes the partial file on cancel; the downloader itself
        // leaves the handle closed — assert the run threw so the driver's cleanup path engages.
    }

    // MARK: - Ranged plaintext fetch (BRM/partial)

    func testRangedEncryptedMatchesWholeBlobSlice() async throws {
        let (cipher, plain) = try encryptedBlob("jellyfish.bin")
        let blockSize = BC01CryptoCommon.blockSize

        // Exercise block-boundary, mid-block, head, and tail windows across lane counts.
        let windows: [Range<Int>] = [
            0..<blockSize,                                   // first block exactly
            blockSize..<(3 * blockSize),                     // aligned interior
            (blockSize + 100)..<(2 * blockSize + 500),       // mid-block start + end
            (plain.count - blockSize)..<plain.count,         // tail (final, possibly short block)
            (5 * blockSize)..<(5 * blockSize + 10)           // tiny window inside a block
        ]

        for window in windows {
            let lo = min(window.lowerBound, plain.count)
            let hi = min(window.upperBound, plain.count)
            guard lo < hi else { continue }
            let expected = plain.subdata(in: lo..<hi)

            for lanes in [1, 4] {
                let fetcher = FakeFetcher(blob: cipher)
                let downloader = ContentStreamDownloader(
                    fetcher: fetcher, decryptor: decryptor,
                    isEncrypted: true, lanes: lanes, threshold: 1)

                let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
                let result = try await downloader.run(to: dest, progress: Progress(), plaintextRange: lo..<hi)

                // The file is sparse: the covering block window sits at its absolute plaintext
                // offset, so the requested plaintext is the slice at [lo, hi) of the file.
                let written = try Data(contentsOf: dest)
                let firstBlock = lo / blockSize
                let slice = written.subdata(in: lo..<hi)
                XCTAssertEqual(slice, expected,
                               "window \(lo)..<\(hi) lanes=\(lanes) ranged decrypt mismatch")

                // The reported window origin must be the first covered block's plaintext offset,
                // so the Extension reports a correct (location, length) return range. Fix 1/2.
                XCTAssertEqual(result.plaintextWindow.origin, Int64(firstBlock * blockSize),
                               "window \(lo)..<\(hi) lanes=\(lanes) origin must be block-aligned")
                // The materialised window must CONTAIN the requested [lo, hi) plaintext range.
                let origin = Int(result.plaintextWindow.origin)
                XCTAssertLessThanOrEqual(origin, lo, "origin must not exceed requested start")
                XCTAssertGreaterThanOrEqual(origin + Int(result.plaintextWindow.length), hi,
                                            "window must cover the requested end")
            }
        }
    }

    func testRangedPlainMatchesSlice() async throws {
        let blob = makeBlob(2 * 1024 * 1024, seed: 5)
        let window = 500_000..<1_200_000

        let fetcher = FakeFetcher(blob: blob)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress(), plaintextRange: window)

        XCTAssertEqual(try Data(contentsOf: dest).subdata(in: window), blob.subdata(in: window))
        XCTAssertEqual(result.plaintextWindow.length, Int64(window.count))
        // Plain files map 1:1, so the window origin is exactly the requested lower bound. Fix 1.
        XCTAssertEqual(result.plaintextWindow.origin, Int64(window.lowerBound))
    }

    // MARK: - Window origin (Fix 1) — whole-file fetches report origin 0

    func testWholeFileWindowOriginIsZeroPlain() async throws {
        let blob = makeBlob(300 * 1024)
        let fetcher = FakeFetcher(blob: blob)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: PlainFileDecryptor(),
            isEncrypted: false, lanes: 4, threshold: 1)
        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())
        XCTAssertEqual(result.plaintextWindow.origin, 0)
        XCTAssertEqual(result.plaintextWindow.length, Int64(blob.count))
    }

    func testWholeFileWindowOriginIsZeroEncrypted() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 8 * 1024 * 1024)
        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())
        XCTAssertEqual(result.plaintextWindow.origin, 0)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
    }

    // MARK: - Header cache injection

    func testPreResolvedHeaderSkipsProbe() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let header = try decryptor.makeBlockContext(from: cipher)

        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 8 * 1024 * 1024,
            preResolvedHeader: header)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        // With the header injected, the only fetches are body lane(s); the first starts at headerEnd
        // rather than the offset-0 header probe.
        XCTAssertEqual(fetcher.fetches.first?.start, header.headerEnd,
                       "pre-resolved header must skip the header probe (first fetch is the body)")
    }

    func testOnHeaderResolvedPublishesHeaderOnProbe() async throws {
        let (cipher, _) = try encryptedBlob("beaver.bin")
        let expected = try decryptor.makeBlockContext(from: cipher)

        final class Box: @unchecked Sendable { var header: BC01Header?; let lock = NSLock() }
        let box = Box()

        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 8 * 1024 * 1024,
            onHeaderResolved: { h in box.lock.lock(); box.header = h; box.lock.unlock() })

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(box.header?.headerEnd, expected.headerEnd,
                       "probe must publish the resolved header for caching")
    }

    // MARK: - BC01Plan geometry (pure, no I/O)

    /// The block geometry both decrypt paths share is computed once in `BC01Plan`; pin the cases
    /// the streaming and single-GET paths used to derive inline.
    func testBC01PlanGeometry() throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let header = try decryptor.makeBlockContext(from: cipher)
        let bs = header.blockSize
        let clamp: (Range<Int>?, Int) -> Range<Int> = { range, total in
            guard let r = range else { return 0..<max(total, 0) }
            let lo = max(0, min(r.lowerBound, total)); let hi = max(lo, min(r.upperBound, total))
            return lo..<hi
        }

        // Whole-file: covers block 0 through the last; window origin 0.
        let whole = BC01Plan(header: header, remoteSize: cipher.count, plaintextRange: nil, clamp: clamp)
        XCTAssertFalse(whole.isEmpty)
        XCTAssertEqual(whole.firstBlock, 0)
        XCTAssertEqual(whole.writeBase, 0)
        XCTAssertEqual(whole.startOffset, header.headerEnd)
        XCTAssertEqual(whole.endOffset, cipher.count)
        XCTAssertEqual(whole.totalBlocks, (cipher.count - header.headerEnd + bs - 1) / bs)

        // Mid-block window → block-aligned base, covering only the touched blocks.
        let mid = BC01Plan(header: header, remoteSize: cipher.count,
                           plaintextRange: (bs + 100)..<(2 * bs + 500), clamp: clamp)
        XCTAssertEqual(mid.firstBlock, 1)
        XCTAssertEqual(mid.lastBlock, 2)
        XCTAssertEqual(mid.writeBase, bs)
        XCTAssertEqual(mid.startOffset, header.headerEnd + bs)
        XCTAssertEqual(mid.writeBudget, 2 * bs)

        // Tail window (last block) → endOffset clamps to remoteSize.
        let tail = BC01Plan(header: header, remoteSize: cipher.count,
                            plaintextRange: (plain.count - bs)..<plain.count, clamp: clamp)
        XCTAssertEqual(tail.lastBlock, tail.totalBlocks - 1)
        XCTAssertEqual(tail.endOffset, cipher.count)

        // Empty ciphertext body (remoteSize <= headerEnd) → isEmpty, origin 0.
        let empty = BC01Plan(header: header, remoteSize: header.headerEnd, plaintextRange: nil, clamp: clamp)
        XCTAssertTrue(empty.isEmpty)
        XCTAssertEqual(empty.writeBase, 0)
    }

    // MARK: - Single-GET fast path (small encrypted whole-file / near-front range)

    /// A small encrypted whole-file fetch with no cached header fetches the whole object in ONE
    /// GET (header + body together) instead of a separate header probe + body — saving a round-trip.
    func testSmallEncryptedWholeFileUsesSingleGet() async throws {
        let (cipher, plain) = try encryptedBlob("aardvark.bin") // ~16 KB
        let fetcher = FakeFetcher(blob: cipher)
        // threshold above the file → fast path; single lane regardless.
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 8, threshold: 1 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        XCTAssertEqual(result.plaintextWindow.origin, 0)
        XCTAssertEqual(fetcher.fetches.count, 1, "small whole-file fetch must use a single GET")
        XCTAssertEqual(fetcher.fetches.first?.start, 0)
        XCTAssertEqual(fetcher.fetches.first?.length, cipher.count, "the one GET covers the whole object")
    }

    /// The fast path still publishes the resolved header so subsequent ranged fetches hit the cache.
    func testSingleGetPublishesHeader() async throws {
        let (cipher, _) = try encryptedBlob("aardvark.bin")
        let expected = try decryptor.makeBlockContext(from: cipher)

        final class Box: @unchecked Sendable { var header: BC01Header?; let lock = NSLock() }
        let box = Box()
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 1 * 1024 * 1024,
            onHeaderResolved: { h in box.lock.lock(); box.header = h; box.lock.unlock() })

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        _ = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(box.header?.headerEnd, expected.headerEnd,
                       "single-GET fast path must still publish the header for caching")
    }

    /// A small near-front ranged fetch also collapses to one GET.
    func testSmallEncryptedNearFrontRangeUsesSingleGet() async throws {
        let (cipher, plain) = try encryptedBlob("aardvark.bin")
        let blockSize = BC01CryptoCommon.blockSize
        let window = 0..<min(blockSize, plain.count)

        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress(), plaintextRange: window)

        let written = try Data(contentsOf: dest)
        let inWindow = written.subdata(in: window)
        XCTAssertEqual(inWindow, plain.subdata(in: window))
        XCTAssertEqual(fetcher.fetches.count, 1, "near-front small range must use a single GET")
    }

    /// A cached header means there is nothing to probe, so the fast path is never engaged: the
    /// pre-resolved path is taken and the only fetches are the body lane(s).
    func testCachedHeaderBypassesFastPath() async throws {
        let (cipher, plain) = try encryptedBlob("aardvark.bin")
        let header = try decryptor.makeBlockContext(from: cipher)
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 1 * 1024 * 1024,
            preResolvedHeader: header)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        XCTAssertEqual(fetcher.fetches.first?.start, header.headerEnd,
                       "cached header → body fetch starts past the header, no offset-0 GET")
    }

    /// `threshold == 0` (multi-lane disabled) must never take the fast path — behaviour stays
    /// identical to the streaming probe + body path.
    func testThresholdZeroNeverFastPaths() async throws {
        let (cipher, plain) = try encryptedBlob("aardvark.bin")
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 0)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        // Probe + body → first fetch is the small offset-0 header probe, not the whole object.
        XCTAssertGreaterThan(fetcher.fetches.count, 1, "threshold 0 keeps the separate probe")
        XCTAssertEqual(fetcher.fetches.first?.start, 0)
        XCTAssertLessThan(fetcher.fetches.first!.length, cipher.count)
    }

    /// A large file (above threshold) keeps the probe + multi-lane path — the fast path declines.
    func testLargeEncryptedKeepsProbeAndLanes() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin") // ~10.6 MB > threshold
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 8, threshold: 8 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(try Data(contentsOf: dest), plain)
        XCTAssertEqual(result.plaintextWindow.length, Int64(plain.count))
        XCTAssertGreaterThan(fetcher.fetches.count, 1, "large file keeps probe + lane fan-out")
    }

    // MARK: - Shared backend seam (StreamingDownload) — same pipeline for every backend

    /// Both OneDrive and the emulator drive `downloadToFile` through `StreamingDownload.run` over
    /// their own ``ContentFetching`` adapter. Exercising it with a fake adapter proves the shared
    /// seam decrypts correctly and warms the header cache so a second (ranged) fetch skips the probe.
    func testStreamingDownloadHelperDecryptsAndWarmsCache() async throws {
        let (cipher, plain) = try encryptedBlob("jellyfish.bin")
        let cacheDomain = "stream-dl-\(UUID().uuidString)"
        let kek = SymmetricKey(size: .bits256)
        let cache = try BC01HeaderCache(domainID: cacheDomain, keyProvider: { kek })
        defer { try? BC01HeaderCache.destroy(domainID: cacheDomain) }
        let itemID = DomainService.ItemIdentifier("emu-1")
        let rev = DomainService.Version(content: "1", metadata: "1")

        // First (whole-file) fetch: cold cache → header probe occurs.
        let f1 = FakeFetcher(blob: cipher)
        let dest1 = tempURL(); defer { try? FileManager.default.removeItem(at: dest1) }
        let (window1, wholeSize1) = try await StreamingDownload.run(
            fetcher: f1, decryptor: decryptor, isEncrypted: true,
            itemIdentifier: itemID, revision: rev, plaintextRange: nil,
            destinationURL: dest1, progress: Progress(), headerCache: cache,
            lanes: 4, threshold: 1)
        XCTAssertEqual(try Data(contentsOf: dest1), plain)
        XCTAssertEqual(window1.length, Int64(plain.count))
        XCTAssertEqual(window1.origin, 0, "whole-file fetch reports window origin 0")
        XCTAssertEqual(wholeSize1, Int64(plain.count), "helper surfaces the whole-file plaintext size")
        XCTAssertEqual(f1.fetches.first?.start, 0, "cold fetch begins with the header probe at 0")

        // Second (ranged) fetch on the same item: warm cache → no offset-0 header probe.
        let blockSize = BC01CryptoCommon.blockSize
        let window = (2 * blockSize)..<(4 * blockSize)
        let f2 = FakeFetcher(blob: cipher)
        let dest2 = tempURL(); defer { try? FileManager.default.removeItem(at: dest2) }
        _ = try await StreamingDownload.run(
            fetcher: f2, decryptor: decryptor, isEncrypted: true,
            itemIdentifier: itemID, revision: rev, plaintextRange: window,
            destinationURL: dest2, progress: Progress(), headerCache: cache,
            lanes: 4, threshold: 1)

        let header = try decryptor.makeBlockContext(from: cipher)
        XCTAssertFalse(f2.fetches.contains { $0.start == 0 && $0.length <= header.headerEnd },
                       "warm cache must skip the header probe on the ranged fetch")
        XCTAssertEqual(try Data(contentsOf: dest2).subdata(in: window), plain.subdata(in: window),
                       "ranged fetch via shared seam must decrypt the requested window")
    }

    /// A content write re-encrypts under a fresh file key/IV. Fetching the new content under
    /// its new revision must bypass the old row rather than decrypt with a stale header.
    func testStreamingDownloadAfterContentWriteUsesNewHeader() async throws {
        let (cipherA, plainA) = try encryptedBlob("jellyfish.bin")
        let (cipherB, plainB) = try encryptedBlob("beaver.bin")
        let cacheDomain = "stream-dl-\(UUID().uuidString)"
        let kek = SymmetricKey(size: .bits256)
        let cache = try BC01HeaderCache(domainID: cacheDomain, keyProvider: { kek })
        defer { try? BC01HeaderCache.destroy(domainID: cacheDomain) }
        let itemID = DomainService.ItemIdentifier("item-1")

        let destA = tempURL(); defer { try? FileManager.default.removeItem(at: destA) }
        _ = try await StreamingDownload.run(
            fetcher: FakeFetcher(blob: cipherA), decryptor: decryptor, isEncrypted: true,
            itemIdentifier: itemID, revision: DomainService.Version(content: "cA", metadata: "eA"),
            plaintextRange: nil, destinationURL: destA, progress: Progress(), headerCache: cache,
            lanes: 4, threshold: 1)
        XCTAssertEqual(try Data(contentsOf: destA), plainA)

        let destB = tempURL(); defer { try? FileManager.default.removeItem(at: destB) }
        _ = try await StreamingDownload.run(
            fetcher: FakeFetcher(blob: cipherB), decryptor: decryptor, isEncrypted: true,
            itemIdentifier: itemID, revision: DomainService.Version(content: "cB", metadata: "eB"),
            plaintextRange: nil, destinationURL: destB, progress: Progress(), headerCache: cache,
            lanes: 4, threshold: 1)
        XCTAssertEqual(try Data(contentsOf: destB), plainB, "new revision must not reuse the stale header")
        XCTAssertEqual(try cache.rawRow(itemID: itemID.id)?.contentRevision, "cB")
    }

    // MARK: - Whole-file plaintext size

    /// The whole-file plaintext size must be reported for a RANGED fetch too — that is the case
    /// the Extension cannot otherwise know, since `plaintextSize` there is only the materialised
    /// window. Derived from the header, so it is independent of which window was fetched.
    func testWholeFileSizeReportedForRangedFetch() async throws {
        let (cipher, plain) = try encryptedBlob("jellyfish.bin")
        let blockSize = BC01CryptoCommon.blockSize
        let windows: [Range<Int>] = [
            0..<blockSize,
            blockSize..<(3 * blockSize),
            (blockSize + 17)..<(2 * blockSize - 3),
            max(0, plain.count - 100)..<plain.count,
        ]
        for window in windows {
            for lanes in [1, 4] {
                let fetcher = FakeFetcher(blob: cipher)
                let downloader = ContentStreamDownloader(
                    fetcher: fetcher, decryptor: decryptor,
                    isEncrypted: true, lanes: lanes, threshold: 1)
                let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
                let result = try await downloader.run(to: dest, progress: Progress(),
                                                      plaintextRange: window)

                XCTAssertEqual(result.wholeFilePlaintextSize, Int64(plain.count),
                               "window \(window) lanes \(lanes): whole-file size must be the FILE size")
                // The window itself stays a window — the two values are distinct concepts.
                XCTAssertLessThan(result.plaintextWindow.length, result.wholeFilePlaintextSize)
            }
        }
    }

    /// Whole-file fetch: the header-derived size and the on-disk length agree.
    func testWholeFileSizeMatchesOnDiskForWholeFetch() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        let fetcher = FakeFetcher(blob: cipher)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor,
            isEncrypted: true, lanes: 1, threshold: 8 * 1024 * 1024)

        let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
        let result = try await downloader.run(to: dest, progress: Progress())

        XCTAssertEqual(result.wholeFilePlaintextSize, Int64(plain.count))
        XCTAssertEqual(result.wholeFilePlaintextSize, result.plaintextWindow.length)
    }

    /// Plain files: plaintext == ciphertext, so the whole-file size is the remote size, on both
    /// the whole-file and the ranged path.
    func testWholeFileSizePlain() async throws {
        let blob = makeBlob(200 * 1024)
        for range in [nil, 1000..<2000] as [Range<Int>?] {
            let fetcher = FakeFetcher(blob: blob)
            let downloader = ContentStreamDownloader(
                fetcher: fetcher, decryptor: PlainFileDecryptor(),
                isEncrypted: false, lanes: 1, threshold: 8 * 1024 * 1024)
            let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
            let result = try await downloader.run(to: dest, progress: Progress(),
                                                  plaintextRange: range)
            XCTAssertEqual(result.wholeFilePlaintextSize, Int64(blob.count))
        }
    }

    // MARK: - `.bc` name, plain bytes

    /// A file DECLARED encrypted by its `.bc` name but whose bytes carry no BC01 magic is plain
    /// content wearing the suffix. It must be served as passthrough rather than failing the fetch
    /// with `invalidHeader`, and its exact size is simply the remote size.
    ///
    /// Covers both `acquireHeader` branches: the single-GET fast path (small file / large
    /// threshold) and the probe path (`threshold == 0` disables the fast path).
    func testPlainBytesUnderBCNameAreServedAsPlain() async throws {
        let blob = makeBlob(300 * 1024, seed: 5)
        XCTAssertFalse(BC01CryptoCommon.hasBC01Magic(blob), "fixture must not look like BC01")

        // threshold 8MB → fast path (one GET from zero); threshold 0 → probe path.
        for threshold in [8 * 1024 * 1024, 0] {
            for range in [nil, 4096..<20_000] as [Range<Int>?] {
                let fetcher = FakeFetcher(blob: blob)
                let downloader = ContentStreamDownloader(
                    fetcher: fetcher, decryptor: decryptor,
                    isEncrypted: true,          // declared encrypted by name
                    lanes: 1, threshold: threshold)

                let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
                let result = try await downloader.run(to: dest, progress: Progress(),
                                                      plaintextRange: range)

                let written = try Data(contentsOf: dest)
                XCTAssertEqual(range.map { written.subdata(in: $0) } ?? written,
                               range.map { blob.subdata(in: $0) } ?? blob,
                               "threshold \(threshold) range \(String(describing: range)): bytes must pass through unmodified")
                XCTAssertEqual(result.wholeFilePlaintextSize, Int64(blob.count),
                               "demoted item's size is exactly the remote size")
            }
        }
    }

    /// The inverse guard: a genuinely-encrypted file must NEVER be demoted. A wrongly-demoted
    /// item would write ciphertext to disk as if it were plaintext — silent corruption.
    func testEncryptedFixtureIsNotDemoted() async throws {
        let (cipher, plain) = try encryptedBlob("beaver.bin")
        for threshold in [8 * 1024 * 1024, 0] {
            let fetcher = FakeFetcher(blob: cipher)
            let downloader = ContentStreamDownloader(
                fetcher: fetcher, decryptor: decryptor,
                isEncrypted: true, lanes: 1, threshold: threshold)
            let dest = tempURL(); defer { try? FileManager.default.removeItem(at: dest) }
            let result = try await downloader.run(to: dest, progress: Progress())

            XCTAssertEqual(try Data(contentsOf: dest), plain,
                           "threshold \(threshold): encrypted file must still decrypt")
            XCTAssertNotEqual(result.wholeFilePlaintextSize, Int64(cipher.count),
                              "a decrypted file's size must not equal its ciphertext size")
        }
    }
}

/// Fetcher that emulates an early-terminated HTTP body: serves bytes normally up to `cutoff`,
/// then returns whatever prefix of the requested range falls below it. Optionally returns empty
/// for spans after the first `emptyAfter`, emulating a lane whose response never arrives.
private final class TruncatingFetcher: ContentFetching, @unchecked Sendable {
    let blob: Data
    let totalSize: Int
    let cutoff: Int
    let emptyAfter: Int?
    private let lock = NSLock()
    private var served = 0

    init(blob: Data, cutoff: Int, emptyAfter: Int? = nil) {
        self.blob = blob
        self.totalSize = blob.count
        self.cutoff = cutoff
        self.emptyAfter = emptyAfter
    }

    func fetchRange(start: Int, length: Int) async throws -> Data {
        lock.lock()
        served += 1
        let index = served
        lock.unlock()
        if let emptyAfter, index > emptyAfter { return Data() }
        let end = min(min(start + length, blob.count), cutoff)
        guard start < end else { return Data() }
        return blob.subdata(in: start..<end)
    }
}
