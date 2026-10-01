/// Unit tests for `GraphDeltaSyncCrawlComplete`.
//
//  GraphDeltaSyncCrawlCompleteTests.swift
//  ExtensionTests
//
//  A delta pass records completeness exactly once: when Graph hands back a `deltaLink`
//  rather than a `nextLink`. That link is the only proof the crawl reached the end of the
//  enumeration, and it is what lets folder navigation stop walking `/children`.
//
//  The negative cases matter as much as the positive one — a pass that stopped on a
//  `nextLink` (cancellation) or died on a `410` saw only part of the drive, and marking
//  either would serve truncated folder listings from the cache forever.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class GraphDeltaSyncCrawlCompleteTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "delta-crawl-complete-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    /// Build a sync whose fetch serves `pages` in order, then repeats the last one.
    private func makeSync(pages: [String]) -> GraphDeltaSync {
        let data = pages.map { Data($0.utf8) }
        var index = 0
        return GraphDeltaSync(cache: cache, rootGraphID: "ROOT", fetch: { _, _ in
            defer { index = min(index + 1, data.count - 1) }
            return data[index]
        })
    }

    private static let onePage = """
    {"value":[{"id":"f1","name":"doc.txt","file":{"mimeType":"text/plain"},"size":3,
               "parentReference":{"id":"ROOT"}}],
     "@odata.deltaLink":"https://x/delta?token=final"}
    """

    /// A pass that pages through to a `deltaLink` has enumerated the whole serving root.
    func testPassEndingOnDeltaLinkMarksCrawlComplete() async throws {
        XCTAssertFalse(cache.isInitialCrawlComplete)

        _ = try await makeSync(pages: [Self.onePage]).runPass()

        XCTAssertTrue(cache.isInitialCrawlComplete)
        XCTAssertEqual(cache.deltaLink, "https://x/delta?token=final")
    }

    /// Cancellation lands on a page boundary holding a `nextLink`: the crawl is resumable,
    /// but incomplete, so the flag must stay clear.
    func testCancelledPassOnNextLinkDoesNotMarkComplete() async throws {
        let paging = """
        {"value":[{"id":"f1","name":"a.txt","file":{"mimeType":"text/plain"},"size":1,
                   "parentReference":{"id":"ROOT"}}],
         "@odata.nextLink":"https://x/delta?token=more"}
        """
        let sync = makeSync(pages: [paging])

        // Cancel before the pass runs; the check sits at the page boundary, after the first
        // page's nextLink is persisted.
        let task = Task {
            try await sync.runPass()
        }
        task.cancel()
        let result = try await task.value

        XCTAssertTrue(result.cancelled)
        XCTAssertFalse(cache.isInitialCrawlComplete,
                       "a pass stopped on a nextLink has not seen the whole drive")
        XCTAssertEqual(cache.deltaLink, "https://x/delta?token=more",
                       "the resumable cursor is still saved")
    }

    /// A `410 Gone` means the cursor is unusable: the pass neither marks completeness nor
    /// keeps a cursor.
    func testExpiredCursorDoesNotMarkCompleteAndClearsDeltaLink() async throws {
        try cache.setDeltaLink("https://x/delta?token=stale")

        let sync = GraphDeltaSync(cache: cache, rootGraphID: "ROOT", fetch: { _, _ in
            throw DeltaHTTPError(statusCode: 410)
        })
        let result = try await sync.runPass()

        XCTAssertTrue(result.cursorExpired)
        XCTAssertFalse(cache.isInitialCrawlComplete)
        XCTAssertTrue(cache.deltaLink?.isEmpty ?? true, "the stale cursor is cleared")
    }

    /// The load-bearing case: a 410 on a cache that HAS completed a crawl must withdraw the
    /// claim. Graph never replayed the skipped cursor range, so deletions and moves inside it
    /// are absent — serving folders from cache would show ghosts. Nothing else rotates the
    /// cache on this path (`destroy`/`empty` are host-driven deprovisioning), so the pass
    /// itself has to clear the flag.
    func testExpiredCursorClearsAnAlreadyCompleteCrawl() async throws {
        _ = try await makeSync(pages: [Self.onePage]).runPass()
        XCTAssertTrue(cache.isInitialCrawlComplete, "precondition: crawl marked complete")

        let sync = GraphDeltaSync(cache: cache, rootGraphID: "ROOT", fetch: { _, _ in
            throw DeltaHTTPError(statusCode: 410)
        })
        _ = try await sync.runPass()

        XCTAssertFalse(cache.isInitialCrawlComplete,
                       "a 410 invalidates completeness; navigation must walk /children again")
    }

    /// Recovery: after a 410 clears the flag, a fresh crawl that reaches a deltaLink sets it
    /// again. The clear is a withdrawal, not a permanent downgrade.
    func testCrawlAfterExpiryRestoresCompleteness() async throws {
        _ = try await makeSync(pages: [Self.onePage]).runPass()
        _ = try await GraphDeltaSync(cache: cache, rootGraphID: "ROOT",
                                     fetch: { _, _ in throw DeltaHTTPError(statusCode: 410) }).runPass()
        XCTAssertFalse(cache.isInitialCrawlComplete)

        _ = try await makeSync(pages: [Self.onePage]).runPass()

        XCTAssertTrue(cache.isInitialCrawlComplete)
    }

    /// Steady state re-marks an already-marked cache; the flag is monotonic, never cleared
    /// by a later pass that happens to page.
    func testRepeatedPassesKeepFlagSet() async throws {
        let sync = makeSync(pages: [Self.onePage])
        _ = try await sync.runPass()
        XCTAssertTrue(cache.isInitialCrawlComplete)

        _ = try await makeSync(pages: [Self.onePage]).runPass()
        XCTAssertTrue(cache.isInitialCrawlComplete)
    }
}
