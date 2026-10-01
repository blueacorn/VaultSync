/// Unit tests for `MetadataCacheTombstonedIDs`.
//
//  MetadataCacheTombstonedIDsTests.swift
//  ExtensionTests
//
//  Coverage for `tombstonedIDs(among:)`, the batched replacement for probing
//  `itemIncludingDeleted` once per row. Both cold-folder seeding
//  (`fetchAndCacheChildren`) and delta reconciliation (`GraphDeltaSync`) ask the same
//  question — "which of these ids are tombstoned?" — and the per-row form paid a serial
//  cache-queue hop plus a fresh prepared statement for every candidate, which dominated
//  first-open latency on a large cold folder. These tests pin that the batched query
//  answers exactly what the per-row form did.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCacheTombstonedIDsTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "tombstoned-ids-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private func row(_ id: String, parent: String = "parent") -> CachedItem {
        CachedItem(graphID: id, parentGraphID: parent, name: "\(id).txt",
                   isFolder: false, remoteFileSize: 1, eTag: "etag-\(id)", cTag: nil,
                   createdDate: nil, modifiedDate: nil, deleted: false, rank: 0)
    }

    /// Only tombstoned ids come back: live rows and unknown ids are both excluded.
    func testReturnsOnlyTombstonedIDs() throws {
        try cache.upsertBatch([row("live-1"), row("live-2"), row("dead-1"), row("dead-2")])
        try cache.markDeleted(graphID: "dead-1")
        try cache.markDeleted(graphID: "dead-2")

        let found = try cache.tombstonedIDs(among: ["live-1", "live-2", "dead-1", "dead-2", "never-seen"])

        XCTAssertEqual(found, ["dead-1", "dead-2"])
    }

    /// A trashed row (`deleted_at` set) is tombstoned too — the per-row form tested
    /// `cached.deleted`, which is true for both trashed and purged states.
    func testTrashedRowCountsAsTombstoned() throws {
        try cache.upsertBatch([row("trashed")])
        try cache.markTrashed(graphID: "trashed", deletedAt: Date())

        XCTAssertEqual(try cache.tombstonedIDs(among: ["trashed"]), ["trashed"])
    }

    /// The common case: nothing is tombstoned, so the caller's resurrect loop does no work.
    func testAllLiveReturnsEmpty() throws {
        try cache.upsertBatch((0..<50).map { row("id-\($0)") })

        XCTAssertTrue(try cache.tombstonedIDs(among: (0..<50).map { "id-\($0)" }).isEmpty)
    }

    /// Empty input short-circuits without touching SQLite.
    func testEmptyInputReturnsEmpty() throws {
        XCTAssertTrue(try cache.tombstonedIDs(among: []).isEmpty)
    }

    /// More ids than SQLITE_MAX_VARIABLE_NUMBER (999): the query chunks, and every
    /// tombstone across the chunk boundary is still found.
    func testChunksBeyondSQLiteVariableLimit() throws {
        let ids = (0..<2500).map { "bulk-\($0)" }
        try cache.upsertBatch(ids.map { row($0) })
        // Straddle the 900-row chunk boundaries.
        let dead = ["bulk-0", "bulk-899", "bulk-900", "bulk-1799", "bulk-1800", "bulk-2499"]
        for id in dead { try cache.markDeleted(graphID: id) }

        XCTAssertEqual(try cache.tombstonedIDs(among: ids), Set(dead))
    }

    /// Duplicate ids are harmless and de-duped by the returned Set.
    func testDuplicateIDsAreHarmless() throws {
        try cache.upsertBatch([row("dup")])
        try cache.markDeleted(graphID: "dup")

        XCTAssertEqual(try cache.tombstonedIDs(among: ["dup", "dup", "dup"]), ["dup"])
    }
}
