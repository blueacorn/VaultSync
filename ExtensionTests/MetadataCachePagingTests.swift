/// Unit tests for `MetadataCachePaging`.
//
//  MetadataCachePagingTests.swift
//  ExtensionTests
//
//  Verifies the paged cache queries that back File Provider enumeration: `childrenPage`
//  (a folder's direct children), `liveItemsPage` (the working-set walk from the serving
//  root) and `descendants` (a recursive subtree below it), all keyset-paged on `graph_id`. These guarantee the enumerator can never be handed an
//  unbounded result set that overflows the 20000-items-per-batch framework ceiling.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCachePagingTests: XCTestCase {

    /// Each test uses a unique domain id so its SQLite file is isolated in the App Group
    /// container; tear-down removes it.
    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "paging-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        // Close the handle before removing the file so WAL sidecars aren't recreated.
        cache = nil
        if let domainID {
            try? MetadataCache.destroy(domainID: domainID)
        }
        domainID = nil
    }

    private func makeItem(_ graphID: String, parent: String?, name: String, isFolder: Bool = false) -> CachedItem {
        CachedItem(graphID: graphID, parentGraphID: parent, name: name, isFolder: isFolder,
                   remoteFileSize: 0, eTag: nil, cTag: nil, createdDate: nil, modifiedDate: nil,
                   deleted: false, rank: 0)
    }

    /// `childrenPage` returns disjoint, complete pages over a folder's direct children and
    /// stops cleanly at the boundary, even when the count is an exact multiple of the page.
    func testChildrenPageCoversAllRowsWithoutGapsOrDuplicates() throws {
        let parent = "root"
        let total = 2000
        let pageSize: Int64 = 500   // 2000 is an exact multiple of 500
        let rows = (0..<total).map {
            makeItem("c\($0)", parent: parent, name: String(format: "child-%04d", $0))
        }
        try cache.upsertBatch(rows)

        var seen: [String] = []
        var after: String?
        while true {
            let page = try cache.childrenPage(ofParentGraphID: parent, after: after, limit: pageSize)
            if page.isEmpty { break }
            XCTAssertLessThanOrEqual(page.count, Int(pageSize), "page must not exceed limit")
            seen.append(contentsOf: page.map(\.graphID))
            after = page.last?.graphID
        }

        XCTAssertEqual(seen.count, total, "every child enumerated exactly once")
        XCTAssertEqual(Set(seen).count, total, "no duplicates across pages")
    }

    /// Deleted rows are excluded from paging.
    func testChildrenPageExcludesDeleted() throws {
        let parent = "root"
        try cache.upsert(makeItem("live", parent: parent, name: "a-live"))
        try cache.upsert(makeItem("dead", parent: parent, name: "b-dead"))
        try cache.markDeleted(graphID: "dead")

        let page = try cache.childrenPage(ofParentGraphID: parent, after: nil, limit: 100)
        XCTAssertEqual(page.map(\.graphID), ["live"])
    }

    /// `descendants` walks the full subtree, not just direct children, and pages it.
    func testDescendantsCoversFullSubtree() throws {
        let root = "root"
        // root has folderA (with 3 files) and folderB (with 2 files) plus 1 loose file.
        try cache.upsert(makeItem("fA", parent: root, name: "folderA", isFolder: true))
        try cache.upsert(makeItem("fB", parent: root, name: "folderB", isFolder: true))
        try cache.upsert(makeItem("loose", parent: root, name: "loose.txt"))
        for i in 0..<3 { try cache.upsert(makeItem("a\(i)", parent: "fA", name: "a\(i).txt")) }
        for i in 0..<2 { try cache.upsert(makeItem("b\(i)", parent: "fB", name: "b\(i).txt")) }

        // Direct children: fA, fB, loose (3).
        XCTAssertEqual(try cache.childrenPage(ofParentGraphID: root, after: nil, limit: 100).count, 3)

        // Full subtree: 2 folders + 1 loose + 3 + 2 = 8.
        let seen = try walk(limit: 3) { try cache.descendants(ofRootGraphID: root, after: $0, limit: $1) }
        XCTAssertEqual(Set(seen), ["fA", "fB", "loose", "a0", "a1", "a2", "b0", "b1"])
        XCTAssertEqual(seen.count, 8, "no duplicates while paging the subtree")
    }

    /// Empty folder / subtree pages to nothing.
    func testEmptyFolderPagesEmpty() throws {
        XCTAssertTrue(try cache.childrenPage(ofParentGraphID: "nope", after: nil, limit: 100).isEmpty)
        XCTAssertTrue(try cache.descendants(ofRootGraphID: "nope", after: nil, limit: 100).isEmpty)
    }

    // MARK: - Keyset stability

    /// Walk every page with `fetch(after, limit)` until a short page, returning ids in order.
    private func walk(limit: Int64, _ fetch: (String?, Int64) throws -> [CachedItem],
                      betweenPages: (Int) throws -> Void = { _ in }) throws -> [String] {
        var seen: [String] = []
        var after: String?
        var pageIndex = 0
        while true {
            let page = try fetch(after, limit)
            seen.append(contentsOf: page.map(\.graphID))
            guard Int64(page.count) == limit, let last = page.last else { break }
            after = last.graphID
            try betweenPages(pageIndex)
            pageIndex += 1
        }
        return seen
    }

    /// The working-set walk from the serving root covers every live descendant, excludes the
    /// root row itself (delta scoped to a folder returns that folder) and tombstones.
    func testLiveItemsPageCoversSubtreeExcludingRoot() throws {
        try cache.upsert(makeItem("ROOT", parent: "outside", name: "Root", isFolder: true))
        try cache.upsert(makeItem("f", parent: "ROOT", name: "folder", isFolder: true))
        try cache.upsert(makeItem("a", parent: "f", name: "a.txt"))
        try cache.upsert(makeItem("b", parent: "ROOT", name: "b.txt"))
        try cache.upsert(makeItem("dead", parent: "ROOT", name: "dead.txt"))
        try cache.markDeleted(graphID: "dead")

        let seen = try walk(limit: 2) { try cache.liveItemsPage(excludingGraphID: "ROOT", after: $0, limit: $1) }
        XCTAssertEqual(seen, ["a", "b", "f"])
    }

    /// A row whose parent has not been cached yet (delta delivered the child first) is still
    /// enumerated by the root walk; a parent-linked CTE would silently drop it.
    func testLiveItemsPageIncludesOrphans() throws {
        try cache.upsert(makeItem("child", parent: "notYetCached", name: "c.txt"))
        let seen = try walk(limit: 10) { try cache.liveItemsPage(excludingGraphID: "ROOT", after: $0, limit: $1) }
        XCTAssertEqual(seen, ["child"])
        XCTAssertTrue(try cache.descendants(ofRootGraphID: "ROOT", after: nil, limit: 10).isEmpty)
    }

    /// Tombstoning and renaming rows before the cursor mid-walk must not skip any unchanged
    /// row. Offset paging lost one row per tombstone and could lose rows on rename; the change
    /// feed cannot recover those because their rank never moved.
    func testMutationsBehindCursorDoNotSkipUnchangedRows() throws {
        let ids = (0..<30).map { String(format: "id%02d", $0) }
        try cache.upsertBatch(ids.map { makeItem($0, parent: "ROOT", name: "n-\($0)") })

        var mutated: Set<String> = []
        let seen = try walk(limit: 5, { try cache.childrenPage(ofParentGraphID: "ROOT", after: $0, limit: $1) },
                            betweenPages: { pageIndex in
            // Tombstone the first row of the page just delivered, rename its second so it
            // sorts first by name — both behind the cursor.
            let dead = ids[pageIndex * 5], renamed = ids[pageIndex * 5 + 1]
            try cache.markDeleted(graphID: dead)
            try cache.upsert(makeItem(renamed, parent: "ROOT", name: "0000"))
            mutated.formUnion([dead, renamed])
        })

        XCTAssertEqual(seen, ids, "every row delivered once, in key order")
        XCTAssertFalse(mutated.isEmpty)
    }

    /// Trash pages are keyset on `graph_id`: complete and duplicate-free across page boundaries.
    func testTrashedItemsPageKeyset() throws {
        let ids = (0..<7).map { "t\($0)" }
        for id in ids {
            try cache.upsert(makeItem(id, parent: "ROOT", name: id))
            try cache.markTrashed(graphID: id, deletedAt: Date(timeIntervalSince1970: 1000))
        }
        try cache.upsert(makeItem("live", parent: "ROOT", name: "live"))

        let seen = try walk(limit: 3) { try cache.trashedItemsPage(after: $0, limit: $1) }
        XCTAssertEqual(seen, ids)
    }

    // MARK: - itemsChanged paging (enumerateChanges page bound)

    /// `itemsChanged(sinceRank:limit:)` caps the result and returns it in ascending-rank
    /// order so `listChanges` can drive the change observer one bounded *page* at a time.
    /// The File Provider framework sums every `didUpdate` item between two
    /// `finishEnumeratingChanges` calls into a single page and aborts past 20000; capping
    /// here, then resuming from the last row's rank, is what keeps each page legal.
    func testItemsChangedRespectsLimitAndOrdersByRank() throws {
        try cache.upsertBatch((0..<1000).map { makeItem("c\($0)", parent: "P", name: "f\($0)") })

        let page = try cache.itemsChanged(sinceRank: 0, limit: 250)
        XCTAssertEqual(page.count, 250, "result is capped at the limit")
        let ranks = page.map(\.rank)
        XCTAssertEqual(ranks, ranks.sorted(), "rows are ascending by rank")
        XCTAssertEqual(Set(ranks).count, ranks.count, "ranks are distinct → usable resume anchor")
    }

    /// Paging the full changeset by resuming from the last row's rank covers every changed
    /// row exactly once — the contract `GraphDriveClient.listChanges` relies on when it
    /// reports `hasMore` + a resume rank to the framework.
    func testItemsChangedResumesByRankWithoutGapsOrDuplicates() throws {
        let total = 1000
        try cache.upsertBatch((0..<total).map { makeItem("c\($0)", parent: "P", name: "f\($0)") })

        var seen: [String] = []
        var sinceRank: Int64 = 0
        let pageLimit = 137  // deliberately not a divisor of total
        while true {
            let page = try cache.itemsChanged(sinceRank: sinceRank, limit: pageLimit)
            if page.isEmpty { break }
            XCTAssertLessThanOrEqual(page.count, pageLimit, "page never exceeds the limit")
            seen.append(contentsOf: page.map(\.graphID))
            sinceRank = page.last!.rank   // resume strictly after the last emitted rank
        }

        XCTAssertEqual(seen.count, total, "every changed row enumerated exactly once")
        XCTAssertEqual(Set(seen).count, total, "no row repeated across resume pages")
    }

    /// No limit returns the entire changeset (back-compat with the original signature).
    func testItemsChangedWithoutLimitReturnsAll() throws {
        try cache.upsertBatch((0..<300).map { makeItem("c\($0)", parent: "P", name: "f\($0)") })
        XCTAssertEqual(try cache.itemsChanged(sinceRank: 0).count, 300)
    }
}
