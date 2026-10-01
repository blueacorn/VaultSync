/// Unit tests for `BC01HeaderSize`.
//
//  BC01HeaderSizeTests.swift
//  ExtensionTests
//
//  Exercises the BC01 header fetch ladder (`BC01HeaderProbe`) and the size arithmetic derived
//  from it (`BC01CryptoCommon.exactPlaintextSize`), over an in-memory transport with no live
//  OneDrive. That pair is how a content fetch learns an item's true plaintext length, and the
//  length it yields is what `recordPlaintextSize` persists and enumeration then publishes as
//  `documentSize` — an over-report there makes partial content fetching loop forever, so the
//  round-trip assertions against real encryptor output are the point of this file.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
import FileProvider
import Common
@testable import Extension

/// In-memory ``ContentFetching`` with a fetch log, so tests can assert how many round trips
/// reading a header actually cost — at most one, save for the widening case.
private final class CountingFetcher: ContentFetching, @unchecked Sendable {
    let blob: Data
    let totalSize: Int
    private let lock = NSLock()
    private(set) var fetches: [(start: Int, length: Int)] = []

    init(blob: Data) {
        self.blob = blob
        self.totalSize = blob.count
    }

    var fetchCount: Int {
        lock.lock(); defer { lock.unlock() }
        return fetches.count
    }

    func fetchRange(start: Int, length: Int) async throws -> Data {
        lock.lock(); fetches.append((start, length)); lock.unlock()
        let end = min(start + length, blob.count)
        guard start < end else { return Data() }
        return blob.subdata(in: start..<end)
    }
}

final class BC01HeaderSizeTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    /// Domains whose header-cache database files this test created; removed in tearDown.
    private var cacheDomains: [String] = []


    private let testDomainID = "com.test.sizeprobe-\(UUID().uuidString)"
    private var encryptor: BC01Encryptor!
    private var decryptor: BC01Decryptor!

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
        let privateKey = try BC01CryptoCommon.importRSAPrivateKey(der)
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        encryptor = BC01Encryptor(rsaPublicKey: publicKey, userID: testDomainID)
        decryptor = BC01Decryptor(rsaPrivateKey: privateKey, userID: testDomainID)
    }

    override func tearDownWithError() throws {
        try? Self.testKeyStore.forgetDomain(testDomainID)
        for domain in cacheDomains { try? BC01HeaderCache.destroy(domainID: domain) }
        cacheDomains = []
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    private func makeBlob(_ count: Int, seed: UInt8 = 3) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var x: UInt8 = seed
        for i in 0..<count { x = x &* 31 &+ 11; bytes[i] = x }
        return Data(bytes)
    }

    /// Identity of a cached header: the item plus its content revision.
    private struct CacheKey { var itemID = "item"; var revision = "rev1" }

    /// A header cache over a real (unique, torn-down) SQLite file with an injected KEK, so the
    /// size ladder can be exercised without a keychain.
    private func makeCache() throws -> BC01HeaderCache {
        let domain = "header-size-\(UUID().uuidString)"
        cacheDomains.append(domain)
        let kek = SymmetricKey(size: .bits256)
        return try BC01HeaderCache(domainID: domain, keyProvider: { kek })
    }

    /// Read `fetcher`'s BC01 header through the ladder and derive the exact plaintext length,
    /// consulting and priming `cache` the way the download path does.
    ///
    /// Mirrors what `ContentStreamDownloader` performs before it decrypts a byte: a cached
    /// header short-circuits the fetch, a freshly parsed one is stored back, and a non-BC01
    /// body is plaintext already.
    private func headerDerivedSize(_ fetcher: ContentFetching,
                                   cache: BC01HeaderCache? = nil,
                                   key: CacheKey? = nil) async throws -> Int64 {
        let cache = try cache ?? makeCache()
        let remoteSize = fetcher.totalSize
        guard remoteSize > BC01CryptoCommon.blockSize else { return 0 }
        let cacheKey = key ?? CacheKey()

        if let cached = cache.header(itemID: cacheKey.itemID, contentRevision: cacheKey.revision) {
            return Int64(BC01CryptoCommon.exactPlaintextSize(header: cached, remoteSize: remoteSize))
        }

        let outcome = try await BC01HeaderProbe.fetchHeader(fetcher: fetcher,
                                                           decryptor: decryptor,
                                                           remoteSize: remoteSize)
        switch outcome {
        case .notBC01:
            return Int64(remoteSize)
        case .encrypted(let header, _):
            try cache.store(header, itemID: cacheKey.itemID, contentRevision: cacheKey.revision)
            return Int64(BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: remoteSize))
        }
    }

    // MARK: - Exactness

    /// The header-derived size must equal the real plaintext length at every block/padding
    /// boundary. This is the guard: enumeration trusts this number unconditionally, and a
    /// too-large value is what makes `fetchPartialContents` loop forever.
    func testResolvesExactSizeAcrossBoundaries() async throws {
        for size in [0, 1, 15, 16, 17, 4095, 4096, 4097, 65536] {
            let plaintext = makeBlob(size)
            let ciphertext = try encryptor.encrypt(plaintext, originalFilename: "f.txt")
            let fetcher = CountingFetcher(blob: ciphertext)

            let resolved = try await headerDerivedSize(fetcher)
            XCTAssertEqual(resolved, Int64(size),
                           "header-derived size must equal plaintext length for \(size)-byte file")
        }
    }

    /// The header-derived size and a full decrypt must never disagree: both are authorities for
    /// the same number, and enumeration publishes the recorded one while materialisation writes
    /// the decrypt's.
    func testAgreesWithFullDecryptLength() async throws {
        for size in [1, 17, 4097, 65536] {
            let plaintext = makeBlob(size)
            let ciphertext = try encryptor.encrypt(plaintext, originalFilename: "f.txt")
            let fetcher = CountingFetcher(blob: ciphertext)

            let probed = try await headerDerivedSize(fetcher)
            let decrypted = try decryptor.decrypt(ciphertext)
            XCTAssertEqual(probed, Int64(decrypted.count),
                           "header-derived size and full decrypt must agree for \(size)-byte file")
        }
    }

    /// A plaintext that exactly fills its last block gets a FULL 16-byte PKCS7 pad block, so the
    /// final block's ciphertext is `blockSize + 16` — longer than a block, not shorter. The
    /// streaming path must fetch and decrypt all of it: bounding the last span by a block
    /// multiple silently truncated the unpad and lost 3 bytes off the end of every such file
    /// (4096, 8192, 16384, 65536 …), while non-multiples were unaffected.
    func testExactBlockMultipleRoundTripsThroughStreamingDecrypt() async throws {
        for size in [4096, 8192, 16384, 65536] {
            let plaintext = makeBlob(size)
            let ciphertext = try encryptor.encrypt(plaintext, originalFilename: "f.txt")
            let downloader = ContentStreamDownloader(
                fetcher: CountingFetcher(blob: ciphertext), decryptor: decryptor,
                isEncrypted: true, lanes: 1, threshold: 0)
            let dest = FileManager.default.temporaryDirectory
                .appendingPathComponent("exact-\(UUID().uuidString).bin")
            defer { try? FileManager.default.removeItem(at: dest) }

            let result = try await downloader.run(to: dest, progress: Progress(totalUnitCount: 0))

            XCTAssertEqual(try Data(contentsOf: dest), plaintext,
                           "\(size)-byte plaintext must survive the streaming decrypt intact")
            XCTAssertEqual(result.plaintextWindow.length, Int64(size))
            XCTAssertEqual(result.wholeFilePlaintextSize, Int64(size))
        }
    }

    /// The same full-pad-block case across multiple lanes: the final lane, not just a
    /// single-span download, must carry the padding.
    func testExactBlockMultipleRoundTripsAcrossLanes() async throws {
        let size = 65536
        let plaintext = makeBlob(size)
        let ciphertext = try encryptor.encrypt(plaintext, originalFilename: "f.txt")
        let downloader = ContentStreamDownloader(
            fetcher: CountingFetcher(blob: ciphertext), decryptor: decryptor,
            isEncrypted: true, lanes: 4, threshold: 1)
        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("lanes-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: dest) }

        let result = try await downloader.run(to: dest, progress: Progress(totalUnitCount: 0))

        XCTAssertEqual(try Data(contentsOf: dest), plaintext)
        XCTAssertEqual(result.wholeFilePlaintextSize, Int64(size))
    }

    // MARK: - Round-trip cost

    /// A cached header means the size is already derivable: no transport call at all. This is
    /// what makes a re-fetch of an item the session has already touched free.
    func testHeaderCacheHitCostsNoFetch() async throws {
        let ciphertext = try encryptor.encrypt(makeBlob(4096), originalFilename: "f.txt")
        let cache = try makeCache()
        let cacheKey = CacheKey()

        let warm = CountingFetcher(blob: ciphertext)
        _ = try await headerDerivedSize(warm, cache: cache, key: cacheKey)
        XCTAssertGreaterThan(warm.fetchCount, 0, "the first read must fetch the header")

        let cold = CountingFetcher(blob: ciphertext)
        let second = try await headerDerivedSize(cold, cache: cache, key: cacheKey)
        XCTAssertEqual(cold.fetchCount, 0, "a cached header must resolve with zero fetches")
        XCTAssertEqual(second, 4096)
    }

    /// A header inside the first probe costs exactly one ranged GET — never a body transfer,
    /// which is what keeps the header read a rounding error against the download it precedes.
    func testHeaderWithinProbeCostsOneFetch() async throws {
        let ciphertext = try encryptor.encrypt(makeBlob(1024 * 1024), originalFilename: "big.bin")
        let fetcher = CountingFetcher(blob: ciphertext)

        _ = try await headerDerivedSize(fetcher)

        XCTAssertEqual(fetcher.fetchCount, 1)
        XCTAssertLessThanOrEqual(fetcher.fetches[0].length, BC01HeaderProbe.defaultMinHeaderLen,
                                 "probe must not pull the body")
    }

    /// A header larger than the initial probe widens exactly once, sized from the header's own
    /// declared end rather than escalating to the maximum.
    func testOversizedHeaderWidensOnce() async throws {
        let ciphertext = try encryptor.encrypt(makeBlob(8192), originalFilename: "f.txt")
        let fetcher = CountingFetcher(blob: ciphertext)
        // Force the widening branch by starting below the real header size.
        let outcome = try await BC01HeaderProbe.fetchHeader(fetcher: fetcher,
                                                           decryptor: decryptor,
                                                           remoteSize: ciphertext.count,
                                                           minHeaderLen: 8)
        guard case .encrypted(let header, _) = outcome else {
            return XCTFail("real BC01 content must not be demoted")
        }
        XCTAssertEqual(fetcher.fetchCount, 2, "one probe + exactly one widening refetch")
        XCTAssertGreaterThan(fetcher.fetches[1].length, fetcher.fetches[0].length)
        XCTAssertEqual(BC01CryptoCommon.exactPlaintextSize(header: header,
                                                           remoteSize: ciphertext.count), 8192)
    }

    /// Parsing a header primes the cache, so a subsequent content fetch of the same item pays
    /// no header round trip of its own.
    func testResolutionPrimesCacheForSubsequentDownload() async throws {
        let plaintext = makeBlob(64 * 1024)
        let ciphertext = try encryptor.encrypt(plaintext, originalFilename: "f.txt")
        let cache = try makeCache()
        let cacheKey = CacheKey()

        _ = try await headerDerivedSize(CountingFetcher(blob: ciphertext), cache: cache, key: cacheKey)

        let cached = cache.header(itemID: cacheKey.itemID, contentRevision: cacheKey.revision)
        XCTAssertNotNil(cached, "a parsed header must be published to the cache")

        // The downloader with a pre-resolved header issues no header GET.
        let fetcher = CountingFetcher(blob: ciphertext)
        let downloader = ContentStreamDownloader(
            fetcher: fetcher, decryptor: decryptor, isEncrypted: true,
            lanes: 1, threshold: 0, preResolvedHeader: cached)
        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("probe-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: dest) }

        let result = try await downloader.run(to: dest, progress: Progress(totalUnitCount: 0))
        XCTAssertEqual(result.wholeFilePlaintextSize, Int64(plaintext.count))
        XCTAssertEqual(try Data(contentsOf: dest), plaintext)
        XCTAssertFalse(fetcher.fetches.contains { $0.start == 0 && $0.length <= BC01HeaderProbe.defaultMinHeaderLen },
                       "a pre-resolved header must eliminate the header probe")
    }

    // MARK: - Demotion

    /// A `.bc`-named file whose bytes are not BC01 is plain content wearing the suffix:
    /// plaintext == ciphertext. It must size to the remote size, not throw.
    func testPlainBytesWithBCNameResolveToRemoteSize() async throws {
        let plain = makeBlob(5000)
        let fetcher = CountingFetcher(blob: plain)

        let resolved = try await headerDerivedSize(fetcher)

        XCTAssertEqual(resolved, Int64(plain.count))
    }

    /// The magic test must not be over-eager: real ciphertext is never demoted. A wrongly
    /// demoted file would report its ciphertext length as the plaintext length.
    func testGenuineCiphertextIsNotDemoted() async throws {
        let ciphertext = try encryptor.encrypt(makeBlob(4096), originalFilename: "f.txt")
        let fetcher = CountingFetcher(blob: ciphertext)

        let resolved = try await headerDerivedSize(fetcher)

        XCTAssertEqual(resolved, 4096)
        XCTAssertNotEqual(resolved, Int64(ciphertext.count),
                          "ciphertext length must never be published as the plaintext size")
    }

    /// A zero-byte remote has no header to read and no body to size.
    func testEmptyRemoteResolvesWithoutFetching() async throws {
        let fetcher = CountingFetcher(blob: Data())

        let resolved = try await headerDerivedSize(fetcher)

        XCTAssertEqual(resolved, 0)
        XCTAssertEqual(fetcher.fetchCount, 0)
    }
}
