/// Unit tests for `MetadataCachePlaintextSize`.
//
//  MetadataCachePlaintextSizeTests.swift
//  ExtensionTests
//
//  Verifies the `plaintext_size` column: the persisted exact plaintext length of a BC01 item,
//  learned from its header during a download. This is the delivery channel for a size learned
//  during a PARTIAL fetch — the completion item of `fetchPartialContents` is a version token the
//  system does not read metadata from, so the corrected size must survive to the next enumeration.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCachePlaintextSizeTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "plaintextsize-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    /// `size` is the BACKEND (ciphertext) length, bound to `remoteFileSize`; `cTag`
    /// identifies the content version.
    private func makeItem(_ graphID: String, parent: String? = "root", name: String = "doc.bc",
                          size: Int64 = 8192, cTag: String? = "c1") -> CachedItem {
        CachedItem(graphID: graphID, parentGraphID: parent, name: name, isFolder: false,
                   remoteFileSize: size, eTag: "e1", cTag: cTag, createdDate: nil, modifiedDate: nil,
                   deleted: false, rank: 0)
    }

    /// A fresh row has no plaintext size — callers must fall back to the ciphertext estimate.
    func testPlaintextSizeStartsNil() throws {
        try cache.upsert(makeItem("a"))
        XCTAssertNil(try cache.item(graphID: "a")?.plaintextSize)
    }

    /// Round-trip, and the value surfaces through the other read paths (children enumeration).
    func testSetPlaintextSizePersists() throws {
        try cache.upsert(makeItem("a"))
        XCTAssertTrue(try cache.setPlaintextSize(8000, graphID: "a"))

        XCTAssertEqual(try cache.item(graphID: "a")?.plaintextSize, 8000)
        XCTAssertEqual(try cache.children(ofParentGraphID: "root").first?.plaintextSize, 8000)
        // The backend size is untouched — the two are different quantities.
        XCTAssertEqual(try cache.item(graphID: "a")?.remoteFileSize, 8192)
    }

    /// The return value gates the enumerator signal: only a real change may provoke one, or a
    /// steady-state re-fetch would signal on every download.
    func testSetPlaintextSizeReportsChangeOnlyOnce() throws {
        try cache.upsert(makeItem("a"))
        XCTAssertTrue(try cache.setPlaintextSize(8000, graphID: "a"), "first write is a change")
        XCTAssertFalse(try cache.setPlaintextSize(8000, graphID: "a"), "same value is not a change")
        XCTAssertTrue(try cache.setPlaintextSize(7999, graphID: "a"), "different value is a change")
    }

    /// A real change bumps `rank`, so the rank-derived domain version advances and the
    /// working-set feed delivers the corrected size. No change → no bump.
    func testSetPlaintextSizeBumpsRankOnChange() throws {
        try cache.upsert(makeItem("a"))
        let before = try XCTUnwrap(try cache.item(graphID: "a")?.rank)

        XCTAssertTrue(try cache.setPlaintextSize(8000, graphID: "a"))
        let afterChange = try XCTUnwrap(try cache.item(graphID: "a")?.rank)
        XCTAssertGreaterThan(afterChange, before, "a changed size must reach enumerateChanges")

        XCTAssertFalse(try cache.setPlaintextSize(8000, graphID: "a"))
        XCTAssertEqual(try cache.item(graphID: "a")?.rank, afterChange,
                       "an unchanged size must not churn the working-set feed")
    }

    /// The delta/children upsert path carries no plaintext knowledge (it only sees the backend
    /// size). It must PRESERVE a resolved value rather than null it out on every sync.
    func testDeltaUpsertPreservesPlaintextSize() throws {
        try cache.upsert(makeItem("a"))
        try cache.setPlaintextSize(8000, graphID: "a")

        // Same cTag (no content change), e.g. a re-crawl or an unrelated metadata echo.
        try cache.upsert(makeItem("a", name: "renamed.bc", cTag: "c1"))

        XCTAssertEqual(try cache.item(graphID: "a")?.plaintextSize, 8000,
                       "a re-crawl must not discard a resolved plaintext size")
        XCTAssertEqual(try cache.item(graphID: "a")?.name, "renamed.bc", "other fields still update")
    }

    /// A content change invalidates the size: it describes bytes that no longer exist. A
    /// confidently-wrong size is worse than the estimate, so it must be cleared and
    /// re-resolved by the next fetch. Here both signals move together, as Graph normally
    /// reports them.
    func testContentChangeClearsPlaintextSize() throws {
        try cache.upsert(makeItem("a", cTag: "c1"))
        try cache.setPlaintextSize(8000, graphID: "a")

        try cache.upsert(makeItem("a", size: 16384, cTag: "c2"))

        XCTAssertNil(try cache.item(graphID: "a")?.plaintextSize,
                     "a content change must invalidate the recorded plaintext size")
    }

    /// `remoteFileSize` is an independent invalidation signal. A different ciphertext length
    /// IS a content change, even when the cTag is unchanged or absent — so the stale plaintext
    /// size must be cleared on that alone, not only when the cTag moves.
    func testRemoteFileSizeChangeAloneClearsPlaintextSize() throws {
        try cache.upsert(makeItem("a", cTag: "c1"))
        try cache.setPlaintextSize(8000, graphID: "a")

        try cache.upsert(makeItem("a", size: 16384, cTag: "c1"))

        XCTAssertNil(try cache.item(graphID: "a")?.plaintextSize,
                     "a changed remote size must invalidate even with an unchanged cTag")
    }

    /// The same, with no cTag at all: `IS NOT` treats NULL-to-NULL as unchanged, so the size
    /// term is the only thing that can catch a rewrite from a provider that omits cTag.
    func testRemoteFileSizeChangeClearsPlaintextSizeWithNilCTag() throws {
        try cache.upsert(makeItem("a", cTag: nil))
        try cache.setPlaintextSize(8000, graphID: "a")

        try cache.upsert(makeItem("a", size: 16384, cTag: nil))

        XCTAssertNil(try cache.item(graphID: "a")?.plaintextSize,
                     "a changed remote size must invalidate when cTag is absent entirely")
    }

    /// The guard must not overfire: an unchanged row keeps its resolved size.
    func testUnchangedRemoteFileSizeAndCTagPreservesPlaintextSize() throws {
        try cache.upsert(makeItem("a", size: 8192, cTag: "c1"))
        try cache.setPlaintextSize(8000, graphID: "a")

        try cache.upsert(makeItem("a", size: 8192, cTag: "c1"))

        XCTAssertEqual(try cache.item(graphID: "a")?.plaintextSize, 8000)
    }

    /// The batch seed path (cold /children enumeration) shares the upsert SQL, so preservation
    /// must hold there too.
    func testBatchUpsertPreservesPlaintextSize() throws {
        try cache.upsert(makeItem("a"))
        try cache.setPlaintextSize(8000, graphID: "a")

        _ = try cache.upsertBatch([makeItem("a", cTag: "c1"), makeItem("b")])

        XCTAssertEqual(try cache.item(graphID: "a")?.plaintextSize, 8000)
        XCTAssertNil(try cache.item(graphID: "b")?.plaintextSize)
    }

    /// Completeness is a property of the crawl, not of any folder: the flag starts false,
    /// is set only by an explicit mark, and re-marking is a no-op.
    func testInitialCrawlCompleteFlag() throws {
        XCTAssertFalse(cache.isInitialCrawlComplete)

        cache.markInitialCrawlComplete()
        XCTAssertTrue(cache.isInitialCrawlComplete)

        cache.markInitialCrawlComplete()
        XCTAssertTrue(cache.isInitialCrawlComplete, "re-marking must stay true")

        try cache.beginFullCrawl()
        XCTAssertFalse(cache.isInitialCrawlComplete)
        try cache.beginFullCrawl()
        XCTAssertFalse(cache.isInitialCrawlComplete, "clearing an absent flag is a no-op")
    }

    /// Holding rows is not evidence of having crawled to completion — delta seeds
    /// breadth-first, so a populated cache may still be mid-crawl.
    func testCrawlCompleteIsNotImpliedByChildren() throws {
        try cache.upsert(makeItem("a", parent: "f"))
        _ = try cache.upsertBatch([makeItem("b", parent: "f"), makeItem("c", parent: "f")])

        XCTAssertFalse(cache.isInitialCrawlComplete,
                       "having children must not imply the crawl finished")
    }
}
