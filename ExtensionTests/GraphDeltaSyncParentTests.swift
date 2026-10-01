/// Unit tests for `GraphDeltaSyncParent`.
//
//  GraphDeltaSyncParentTests.swift
//  ExtensionTests
//
//  Regression coverage that a delta pass surfaces the *parent containers* whose children
//  changed. This is the data the poller needs to signal the right folders; without it the
//  fix upstream (parent-container signalling) has nothing to act on.
//
//  Scenario mirrors the original bug report: a folder + file created on OneDrive Web under
//  an existing sub-folder. The delta page carries the new items (upserts); the pass must
//  report their `parentReference.id` as a changed container. A tombstoned item's parent is
//  resolved from the cache (the `deleted` facet carries no parent).
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class GraphDeltaSyncParentTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "delta-parent-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    /// Build a `GraphDeltaSync` whose network fetch returns `json` once, then a final empty
    /// delta page (so the loop terminates after one content page).
    private func makeSync(returning json: String) -> GraphDeltaSync {
        let pages = [Data(json.utf8),
                     Data(#"{"value":[],"@odata.deltaLink":"https://x/delta?token=final"}"#.utf8)]
        var index = 0
        return GraphDeltaSync(
            cache: cache,
            rootGraphID: "ROOT",
            fetch: { _, _ in
                defer { index = min(index + 1, pages.count - 1) }
                return pages[index]
            })
    }

    /// A delta page adding a new folder and a new file under an existing parent reports
    /// that parent as a changed container.
    func testUpsertedChildrenReportTheirParent() async throws {
        let json = """
        {
          "value": [
            {"id":"folderNew","name":"folder-test-3","folder":{"childCount":1},
             "parentReference":{"id":"PARENT_TEST"}},
            {"id":"fileNew","name":"test-3.txt","file":{"mimeType":"text/plain"},"size":5,
             "parentReference":{"id":"folderNew"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        let sync = makeSync(returning: json)

        let result = try await sync.runPass()

        XCTAssertTrue(result.changed)
        XCTAssertFalse(result.cursorExpired)
        // The existing sub-folder (file's grandparent) *and* the new folder are both
        // containers whose direct children changed.
        XCTAssertEqual(result.changedParentGraphIDs, ["PARENT_TEST", "folderNew"])
    }

    /// A tombstoned item resolves its parent from the cache, since the `deleted` facet
    /// carries only an id.
    func testDeletedItemResolvesParentFromCache() async throws {
        // Seed the cache with the item that the delta will tombstone.
        try cache.upsert(CachedItem(graphID: "doomed", parentGraphID: "PARENT_DEL", name: "old.txt",
                                    isFolder: false, remoteFileSize: 1, eTag: nil, cTag: nil,
                                    createdDate: nil, modifiedDate: nil, deleted: false, rank: 0))

        let json = """
        {
          "value": [
            {"id":"doomed","deleted":{"state":"deleted"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        let sync = makeSync(returning: json)

        let result = try await sync.runPass()

        XCTAssertTrue(result.changed)
        XCTAssertEqual(result.changedParentGraphIDs, ["PARENT_DEL"])
        XCTAssertNil(try cache.item(graphID: "doomed"), "tombstoned item should be filtered out")
    }

    /// A no-op pass (empty page) reports no changed parents and no change.
    func testEmptyPassReportsNoParents() async throws {
        let sync = makeSync(returning: #"{"value":[],"@odata.deltaLink":"https://x/delta?token=t"}"#)

        let result = try await sync.runPass()

        XCTAssertFalse(result.changed)
        XCTAssertTrue(result.changedParentGraphIDs.isEmpty)
    }
}
