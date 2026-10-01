/// Tests for in-place emptying of the OneDrive metadata cache.
///
/// "Lock and Remove Vault" clears a domain's cached metadata while the Provider may still hold
/// the database open, so it empties rather than deletes — unlinking under a live handle risks the
/// WAL sidecars being recreated and a stale handle writing to an unlinked inode.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
@testable import Extension

final class MetadataCacheEmptyTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "empty-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private func item(_ i: Int) -> CachedItem {
        CachedItem(graphID: "item-\(i)", parentGraphID: "ROOT", name: "file-\(i).txt",
                   isFolder: false, remoteFileSize: Int64(i), eTag: "etag-\(i)", cTag: nil,
                   createdDate: nil, modifiedDate: nil, deleted: false, rank: 0)
    }

    private func seed(_ count: Int = 50) throws {
        _ = try cache.upsertBatch((0..<count).map(item))
    }

    func testEmptyRemovesAllRows() throws {
        try seed()
        XCTAssertGreaterThan(try cache.indexedCount(), 0)

        try cache.empty()

        XCTAssertEqual(try cache.indexedCount(), 0)
        XCTAssertNil(try cache.item(graphID: "item-0"))
    }

    /// The delta cursor must go with the rows: it points at remote state whose local rows have
    /// been deleted, so resuming from it would skip re-seeding them.
    func testEmptyClearsTheDeltaCursor() throws {
        try cache.setDeltaLink("https://graph.example/delta?token=abc")
        XCTAssertNotNil(cache.deltaLink)

        try cache.empty()

        XCTAssertTrue(cache.deltaLink?.isEmpty ?? true)
    }

    func testEmptyClearsTheRootGraphID() throws {
        try cache.setRootGraphID("ROOT-ID")
        try cache.empty()
        XCTAssertNil(cache.rootGraphID())
    }

    /// The file must survive, so a Provider holding this database open keeps a valid handle.
    func testEmptyKeepsTheDatabaseFileAndHandleUsable() throws {
        try seed()
        try cache.empty()

        // Same instance still works — no reopen, no error.
        _ = try cache.upsertBatch([item(999)])
        XCTAssertNotNil(try cache.item(graphID: "item-999"))
        XCTAssertEqual(try cache.indexedCount(), 1)
    }

    /// `schema_version` is re-seeded, so reopening does not trigger a schema rebuild.
    func testReopenAfterEmptyPreservesSeededRows() throws {
        try cache.empty()
        _ = try cache.upsertBatch([item(1)])
        cache = nil

        let reopened = try MetadataCache(domainID: domainID)
        // A rebuild would have dropped the items table and lost this row.
        XCTAssertNotNil(try reopened.item(graphID: "item-1"))
    }

    func testEmptyIsIdempotent() throws {
        try seed(5)
        try cache.empty()
        XCTAssertNoThrow(try cache.empty())
        XCTAssertEqual(try cache.indexedCount(), 0)
    }
}
