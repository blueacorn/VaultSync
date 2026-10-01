/// Unit tests for `MetadataCacheBatchSeed`.
//
//  MetadataCacheBatchSeedTests.swift
//  ExtensionTests
//
//  Regression coverage for the cold-folder seeding path. `fetchAndCacheChildren` now seeds
//  a page of `/children` via a single `upsertBatch` transaction instead of one `upsert`
//  (one BEGIN/COMMIT + WAL fsync) per row — the dominant cause of 10–20 s folder-population
//  latency on large cold folders. These tests pin that a batched seed produces the same
//  cached result as row-by-row, advances ranks once per genuinely-new row, and is
//  idempotent (a re-seed neither duplicates rows nor bumps ranks).
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCacheBatchSeedTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "batch-seed-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private func child(_ i: Int, parent: String) -> CachedItem {
        CachedItem(graphID: "child-\(i)", parentGraphID: parent, name: "file-\(i).txt",
                   isFolder: false, remoteFileSize: Int64(i), eTag: "etag-\(i)", cTag: nil,
                   createdDate: nil, modifiedDate: nil, deleted: false, rank: 0)
    }

    /// Batch-seeding a folder's children caches every row under the correct parent.
    func testBatchSeedCachesAllChildren() throws {
        let parent = "PARENT"
        let rows = (0..<500).map { child($0, parent: parent) }

        let written = try cache.upsertBatch(rows)

        XCTAssertEqual(written, 500)
        let cached = try cache.children(ofParentGraphID: parent)
        XCTAssertEqual(Set(cached.map(\.graphID)), Set(rows.map(\.graphID)))
    }

    /// A batched seed assigns a distinct, advancing rank per new row (so `enumerateChanges`
    /// can page them) — matching the per-row `upsert` contract.
    func testBatchSeedAdvancesRankPerNewRow() throws {
        let before = cache.currentRank()
        _ = try cache.upsertBatch((0..<100).map { child($0, parent: "P") })
        let after = cache.currentRank()

        XCTAssertEqual(after - before, 100, "rank high-water mark advances once per new row")
        let ranks = try cache.children(ofParentGraphID: "P").map(\.rank)
        XCTAssertEqual(Set(ranks).count, ranks.count, "ranks are distinct")
    }

    /// Re-seeding identical rows (a cold folder re-opened, or a delta re-crawl) is a no-op:
    /// no duplicate rows, no rank churn.
    func testReSeedIsIdempotent() throws {
        let rows = (0..<200).map { child($0, parent: "P") }
        _ = try cache.upsertBatch(rows)
        let rankAfterFirst = cache.currentRank()

        let writtenSecond = try cache.upsertBatch(rows)

        XCTAssertEqual(writtenSecond, 0, "identical re-seed writes nothing")
        XCTAssertEqual(cache.currentRank(), rankAfterFirst, "no rank churn on re-seed")
        XCTAssertEqual(try cache.children(ofParentGraphID: "P").count, 200, "no duplicate rows")
    }
}
