/// Unit tests for `BC01HeaderCache`.
//
//  BC01HeaderCacheTests.swift
//  ExtensionTests
//
//  Unit tests for the persistent BC01 header cache. Covers the design properties the store is
//  built around rather than incidental behaviour:
//
//  * round trip, AAD binding, and locked-vault-is-a-miss (never an error)
//  * `item_id` alone as the primary key — N revisions of one item leave exactly ONE row, and a
//    stale cTag misses *and* drops the row (the regression a composite key would introduce)
//  * a read performs no write (there is no `last_used_at` to maintain)
//  * cached statements survive a schema rebuild
//  * key residency: the memoised KEK is bounded, and a THROWING refresh leaves nothing resident
//
//  The SQLite file is real, keyed by a unique per-test domain and destroyed in tearDown; only
//  the KEK provider and the clock are injected.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
import SQLite3
import Common
@testable import Extension

final class BC01HeaderCacheTests: XCTestCase {

    private var domainID: String!
    private let kek = SymmetricKey(size: .bits256)

    /// Injected clock, advanced by tests to drive TTL and key-residency behaviour.
    private var clock = Date(timeIntervalSince1970: 1_700_000_000)
    /// Number of times the injected key provider was invoked — the amortisation assertions.
    private var loaderCalls = 0
    /// When true the provider throws `.locked`, standing in for the app evicting the slot.
    private var vaultLocked = false

    override func setUpWithError() throws {
        domainID = "bc01-header-\(UUID().uuidString)"
    }

    override func tearDownWithError() throws {
        if let domainID { try? BC01HeaderCache.destroy(domainID: domainID) }
        domainID = nil
    }

    // MARK: - Helpers

    /// A cache over the test domain with the injected clock and lock-aware key provider.
    private func makeCache(keyResidencySeconds: TimeInterval = 5,
                           maxAgeSeconds: TimeInterval = 180 * 86_400,
                           maxRows: Int = 500_000) throws -> BC01HeaderCache {
        try BC01HeaderCache(domainID: domainID,
                            keyProvider: { [self] in
                                loaderCalls += 1
                                if vaultLocked { throw VaultKeyStoreError.locked }
                                return kek
                            },
                            now: { [self] in clock },
                            maxAgeSeconds: maxAgeSeconds,
                            maxRows: maxRows,
                            keyResidencySeconds: keyResidencySeconds)
    }

    private func header(iv: UInt8 = 0xAA, key: UInt8 = 0xBB) -> BC01Header {
        BC01Header(baseIV: Data(repeating: iv, count: 16),
                   fileKey: Data(repeating: key, count: 32),
                   blockSize: 4096,
                   headerEnd: 512,
                   cipherPadding: 7)
    }

    // MARK: - 1. Round trip, AAD, locked vault, eviction

    func testStoreThenReadRoundTrips() throws {
        let cache = try makeCache()
        let original = header()
        try cache.store(original, itemID: "item-1", contentRevision: "cTag-1")

        let read = try XCTUnwrap(cache.header(itemID: "item-1", contentRevision: "cTag-1"))
        XCTAssertEqual(read.baseIV, original.baseIV)
        XCTAssertEqual(read.fileKey, original.fileKey)
        XCTAssertEqual(read.blockSize, original.blockSize)
        XCTAssertEqual(read.headerEnd, original.headerEnd)
        XCTAssertEqual(read.cipherPadding, original.cipherPadding)
    }

    /// The AAD is the cryptographic gate behind the cheap cTag comparison. Rewriting the
    /// revision column to agree must not make a transplanted blob open.
    func testTamperedRevisionColumnFailsToOpen() throws {
        let cache = try makeCache()
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        let row = try XCTUnwrap(cache.rawRow(itemID: "item-1"))

        // Same sealed blob, presented under a different revision: the AAD no longer matches.
        let opened = try? VaultKeyStore.unwrap(
            row.sealedSecrets, with: kek,
            authenticating: Data("item-1\u{0}cTag-2".utf8))
        XCTAssertNil(opened, "a blob must not open under a different content revision")

        // And under a different item id.
        let transplanted = try? VaultKeyStore.unwrap(
            row.sealedSecrets, with: kek,
            authenticating: Data("item-2\u{0}cTag-1".utf8))
        XCTAssertNil(transplanted, "a blob must not open under a different item")
    }

    /// A locked vault is a cache MISS, never an error — the caller falls through to the probe.
    func testLockedVaultIsAMissNotAnError() throws {
        let cache = try makeCache(keyResidencySeconds: 0)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")

        vaultLocked = true
        XCTAssertNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))
        XCTAssertEqual(try cache.rowCount(), 1, "a locked read must not delete the row")
    }

    func testSweepEvictsRowsPastTheTTL() throws {
        let cache = try makeCache(maxAgeSeconds: 10)
        try cache.store(header(), itemID: "old", contentRevision: "r")
        clock = clock.addingTimeInterval(60)
        try cache.store(header(), itemID: "new", contentRevision: "r")

        try cache.sweep()

        XCTAssertEqual(try cache.rowCount(), 1)
        XCTAssertNil(try cache.rawRow(itemID: "old"))
        XCTAssertNotNil(try cache.rawRow(itemID: "new"))
    }

    /// The row cap keeps the newest rows, measured by `created_at` — not by recency of use.
    func testSweepEnforcesTheRowCap() throws {
        let cache = try makeCache(maxRows: 3)
        for i in 0..<6 {
            clock = clock.addingTimeInterval(1)
            try cache.store(header(), itemID: "item-\(i)", contentRevision: "r")
        }

        try cache.sweep()

        XCTAssertEqual(try cache.rowCount(), 3)
        XCTAssertNil(try cache.rawRow(itemID: "item-0"))
        XCTAssertNotNil(try cache.rawRow(itemID: "item-5"))
    }

    // MARK: - 2. Keying: item_id alone

    /// The regression a composite `(item_id, content_revision)` key would introduce: a file saved
    /// N times would hold N rows, N-1 of them permanently unreachable.
    func testStoringManyRevisionsOfOneItemLeavesExactlyOneRow() throws {
        let cache = try makeCache()
        for i in 0..<50 {
            try cache.store(header(iv: UInt8(i)), itemID: "item-1", contentRevision: "cTag-\(i)")
        }

        XCTAssertEqual(try cache.rowCount(), 1)
        let row = try XCTUnwrap(cache.rawRow(itemID: "item-1"))
        XCTAssertEqual(row.contentRevision, "cTag-49", "the surviving row holds the newest cTag")
        let read = try XCTUnwrap(cache.header(itemID: "item-1", contentRevision: "cTag-49"))
        XCTAssertEqual(read.baseIV, Data(repeating: 49, count: 16))
    }

    func testStaleRevisionMissesAndRemovesTheRow() throws {
        let cache = try makeCache()
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-2")

        XCTAssertNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"),
                     "a stale cTag must miss before any crypto runs")
        XCTAssertEqual(try cache.rowCount(), 0, "the unreachable row must be dropped")
    }

    // MARK: - 3. A read performs no write

    func testReadPerformsNoWrite() throws {
        let cache = try makeCache()
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")

        let before = cache.totalChanges
        for _ in 0..<25 {
            XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))
        }
        XCTAssertEqual(cache.totalChanges, before,
                       "a hit must not dirty a page — there is no last_used_at to maintain")
    }

    /// A run of pure reads must not grow the WAL either.
    func testPureReadsDoNotGrowTheWAL() throws {
        let cache = try makeCache()
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        _ = cache.header(itemID: "item-1", contentRevision: "cTag-1")

        let walURL = try walURL()
        let sizeBefore = try walSize(walURL)
        for _ in 0..<100 { _ = cache.header(itemID: "item-1", contentRevision: "cTag-1") }
        XCTAssertEqual(try walSize(walURL), sizeBefore)
    }

    private func walURL() throws -> URL {
        let db = try BC01HeaderCache.databaseURL(domainID: domainID, createDirectory: false)
        return db.deletingLastPathComponent()
            .appendingPathComponent(db.lastPathComponent + "-wal")
    }

    private func walSize(_ url: URL) throws -> Int {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.size] as? Int) ?? 0
    }

    // MARK: - 4. AAD wrap/unwrap overloads

    func testWrapUnwrapRoundTripsWithMatchingAAD() throws {
        let aad = Data("item‖rev".utf8)
        let box = try VaultKeyStore.wrap(Data("secret".utf8), with: kek, authenticating: aad)
        XCTAssertEqual(try VaultKeyStore.unwrap(box, with: kek, authenticating: aad),
                       Data("secret".utf8))
    }

    func testUnwrapRejectsMismatchedAAD() throws {
        let box = try VaultKeyStore.wrap(Data("secret".utf8), with: kek,
                                             authenticating: Data("aad-a".utf8))
        XCTAssertThrowsError(try VaultKeyStore.unwrap(box, with: kek,
                                                          authenticating: Data("aad-b".utf8))) {
            XCTAssertEqual($0 as? VaultKeyStoreError, .unwrapFailed)
        }
        XCTAssertThrowsError(try VaultKeyStore.unwrap(box, with: kek, authenticating: Data())) {
            XCTAssertEqual($0 as? VaultKeyStoreError, .unwrapFailed)
        }
    }

    // MARK: - 5. Cached statements survive a rebuild

    /// A cached statement over a dropped table is invalid, so `rebuildSchema` must finalize
    /// before the DROP and re-prepare after. Reopening at a mismatched schema version is the
    /// only way to drive that path — the store must be fully usable afterwards.
    func testCachedStatementsSurviveASchemaRebuild() throws {
        let cache = try makeCache()
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))

        // Force a version mismatch on the shared file, then reopen: `open()` rebuilds.
        try forceSchemaVersion(0)
        let reopened = try makeCache()

        XCTAssertEqual(try reopened.rowCount(), 0, "a rebuild drops the table")
        // Every cached statement must work post-rebuild: upsert, select, delete, sweep.
        try reopened.store(header(), itemID: "item-2", contentRevision: "cTag-2")
        XCTAssertNotNil(reopened.header(itemID: "item-2", contentRevision: "cTag-2"))
        try reopened.invalidate(itemID: "item-2")
        XCTAssertEqual(try reopened.rowCount(), 0)
        XCTAssertNoThrow(try reopened.sweep())
    }

    /// Write a bogus `schema_version` straight into the store's `meta` table, so the next
    /// `open()` takes the rebuild branch.
    private func forceSchemaVersion(_ version: Int) throws {
        let url = try BC01HeaderCache.databaseURL(domainID: domainID, createDirectory: false)
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &db), SQLITE_OK)
        defer { sqlite3_close(db) }
        XCTAssertEqual(sqlite3_exec(db,
            "INSERT INTO meta(key,value) VALUES('schema_version','\(version)') " +
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value;", nil, nil, nil), SQLITE_OK)
    }

    // MARK: - 9a–9e. Key residency

    /// 9a — hits before lock, misses after, on the same live instance. The cache may serve for
    /// at most `keyResidencySeconds` past the slot eviction, then every call misses.
    func testHitsBeforeLockAndMissesAfterTheResidencyWindow() throws {
        let cache = try makeCache(keyResidencySeconds: 5)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))

        vaultLocked = true   // the app evicts the Provider-readable slot

        // Inside the window the memoised key still serves.
        clock = clock.addingTimeInterval(1)
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"),
                        "within the residency window the memo still serves")

        // Past it, the re-resolve fails and every subsequent call misses.
        clock = clock.addingTimeInterval(10)
        for _ in 0..<3 {
            XCTAssertNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"),
                         "past the window a locked vault must miss")
        }
    }

    /// 9b — `keyResidencySeconds = 0` forces a keychain read on every operation.
    func testZeroResidencyResolvesTheKeyEveryCall() throws {
        let cache = try makeCache(keyResidencySeconds: 0)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")

        let before = loaderCalls
        for _ in 0..<5 { _ = cache.header(itemID: "item-1", contentRevision: "cTag-1") }
        XCTAssertEqual(loaderCalls - before, 5, "zero residency must re-read per call")
    }

    /// 9c — within one window the loader runs once across N operations. This amortisation is
    /// the reason the memo exists at all.
    func testLoaderInvokedOncePerResidencyWindow() throws {
        let cache = try makeCache(keyResidencySeconds: 5)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")

        let before = loaderCalls
        for _ in 0..<20 {
            clock = clock.addingTimeInterval(0.1)   // 2 s total: inside one 5 s window
            XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))
        }
        XCTAssertEqual(loaderCalls - before, 0,
                       "the key resolved by the store must serve the whole window")
    }

    /// 9d — a throwing refresh leaves NO resident key. Guards the specific bug where `memo` is
    /// only reassigned on the success path: expiry alone would then never clear it, and the
    /// stale key would keep serving hits for the life of the process.
    func testThrowingRefreshLeavesNoResidentKey() throws {
        let cache = try makeCache(keyResidencySeconds: 5)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"), "memo warm")

        clock = clock.addingTimeInterval(10)   // past expiry
        vaultLocked = true

        var previous = loaderCalls
        for _ in 0..<3 {
            XCTAssertNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"),
                         "no key may survive a failed refresh")
            XCTAssertGreaterThan(loaderCalls, previous,
                                 "each call must re-invoke the loader — proving nothing is retained")
            previous = loaderCalls
        }

        // And the cache recovers the moment the vault unlocks again.
        vaultLocked = false
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))
    }

    /// 9e — `empty()` drops the memo, so a Lock-and-Remove cannot leave a key resident beside
    /// an emptied table.
    func testEmptyDropsTheMemoisedKey() throws {
        let cache = try makeCache(keyResidencySeconds: 5)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"), "memo warm")

        try cache.empty()
        XCTAssertEqual(try cache.rowCount(), 0)

        // Still inside the residency window: without the drop the memo would serve this store
        // without touching the loader.
        let before = loaderCalls
        try cache.store(header(), itemID: "item-2", contentRevision: "cTag-2")
        XCTAssertGreaterThan(loaderCalls, before,
                             "empty() must force the next operation to re-resolve the key")
    }

    /// 9e (destroy half) — after `destroy` unlinks the store, a fresh instance starts with no
    /// resident key and no rows.
    func testDestroyLeavesNoRowsAndNoResidentKey() throws {
        let cache = try makeCache(keyResidencySeconds: 5)
        try cache.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: "cTag-1"))

        try BC01HeaderCache.destroy(domainID: domainID)
        let dbURL = try BC01HeaderCache.databaseURL(domainID: domainID, createDirectory: false)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dbURL.path))

        let before = loaderCalls
        let fresh = try makeCache(keyResidencySeconds: 5)
        XCTAssertEqual(try fresh.rowCount(), 0)
        XCTAssertNil(fresh.header(itemID: "item-1", contentRevision: "cTag-1"))
        try fresh.store(header(), itemID: "item-1", contentRevision: "cTag-1")
        XCTAssertGreaterThan(loaderCalls, before, "a new instance holds no key from the old one")
    }

    // MARK: - Content identity as the cache key

    /// The `|p<size>` plaintext-size stamp must not participate in the cache key.
    ///
    /// Regression: the stamp is folded into the content version so `documentSize` re-reads once
    /// a BC01 header reveals the true plaintext length — but that length is resolved BY the
    /// fetch whose header the cache stores. Keying on the stamped token stored the row under the
    /// pre-resolution version and looked it up under the post-resolution one, so every item's
    /// first read missed and paid a second full header GET.
    func testStampedRevisionsShareOneCacheRow() throws {
        let cache = try makeCache()
        let unresolved = DomainService.Version(content: "cTag-1", metadata: "eTag-1")
        let resolved = DomainService.Version(content: "cTag-1|p13839441", metadata: "eTag-1")

        try cache.store(header(), itemID: "item-1", contentRevision: unresolved.contentIdentity)

        XCTAssertNotNil(cache.header(itemID: "item-1", contentRevision: resolved.contentIdentity),
                        "resolving the plaintext size must not invalidate the header row")
        XCTAssertEqual(try cache.rowCount(), 1, "one item at one cTag is one row")
    }

    /// A genuine content change (new cTag) still invalidates, stamp or no stamp.
    func testNewContentTagStillMissesDespiteStamp() throws {
        let cache = try makeCache()
        let old = DomainService.Version(content: "cTag-1|p100", metadata: "eTag-1")
        let new = DomainService.Version(content: "cTag-2|p100", metadata: "eTag-1")

        try cache.store(header(), itemID: "item-1", contentRevision: old.contentIdentity)

        XCTAssertNil(cache.header(itemID: "item-1", contentRevision: new.contentIdentity),
                     "a new cTag is a real content change and must drop the row")
    }

    /// `contentIdentity` strips the stamp and leaves an unstamped token untouched.
    func testContentIdentityStripsPlaintextSizeStamp() {
        XCTAssertEqual(DomainService.Version(content: "cTag-1|p42", metadata: "e").contentIdentity,
                       "cTag-1")
        XCTAssertEqual(DomainService.Version(content: "cTag-1", metadata: "e").contentIdentity,
                       "cTag-1")
        XCTAssertEqual(DomainService.Version.zero.contentIdentity, "0")
    }

}
