/// Unit tests for `MetadataCacheLocalMetadata`.
//
//  MetadataCacheLocalMetadataTests.swift
//  ExtensionTests
//
//  Verifies local-only metadata (Finder tagData + extended attributes, the latter carrying
//  the heart / pinned / isShared marks) persisted in the OneDrive `MetadataCache`: round-trip
//  through reads, rank bump so the working-set feed delivers the change, and isolation from
//  the delta upsert path (a re-crawl must not clobber them).
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCacheLocalMetadataTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "localmeta-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private func makeItem(_ graphID: String, parent: String?, name: String) -> CachedItem {
        CachedItem(graphID: graphID, parentGraphID: parent, name: name, isFolder: false,
                   remoteFileSize: 0, eTag: nil, cTag: nil, createdDate: nil, modifiedDate: nil,
                   deleted: false, rank: 0)
    }

    private func heartBlob(_ on: Bool) -> Data { try! JSONEncoder().encode(on) }

    /// `setLocalMetadata` persists xattrs + tagData and surfaces them via `item` and `children`.
    func testLocalMetadataRoundTrip() throws {
        try cache.upsert(makeItem("a", parent: "root", name: "file"))
        let meta = LocalMetadata(extendedAttributes: [DomainService.MarkParameter.heartXattr: heartBlob(true)],
                                 tagData: Data([0x01, 0x02, 0x03]))
        try cache.setLocalMetadata(graphID: "a", meta)

        XCTAssertEqual(try cache.item(graphID: "a")?.localMetadata, meta)
        let children = try cache.children(ofParentGraphID: "root")
        XCTAssertEqual(children.first?.localMetadata, meta)
    }

    /// An empty blob clears the stored metadata (unheart / unpin / remove tags).
    func testLocalMetadataClear() throws {
        try cache.upsert(makeItem("a", parent: "root", name: "file"))
        try cache.setLocalMetadata(graphID: "a", LocalMetadata(extendedAttributes: [:], tagData: Data([0x01])))
        try cache.setLocalMetadata(graphID: "a", .empty)

        XCTAssertEqual(try cache.item(graphID: "a")?.localMetadata, .empty)
    }

    /// Setting metadata bumps the row's rank so the change is delivered by the working-set
    /// feed (`itemsChanged(sinceRank:)`).
    func testLocalMetadataBumpsRankAndIsDeliveredByChangeFeed() throws {
        try cache.upsert(makeItem("a", parent: "root", name: "file"))
        let beforeRank = try XCTUnwrap(cache.item(graphID: "a")).rank

        let newRank = try cache.setLocalMetadata(
            graphID: "a",
            LocalMetadata(extendedAttributes: [DomainService.MarkParameter.pinnedXattr: heartBlob(true)], tagData: nil))
        XCTAssertGreaterThan(newRank, beforeRank)

        let changed = try cache.itemsChanged(sinceRank: beforeRank)
        XCTAssertEqual(changed.map(\.graphID), ["a"])
        XCTAssertFalse(changed[0].localMetadata.isEmpty)
    }

    /// A delta re-crawl (`upsert`/`upsertBatch` of the same remote row) must NOT erase the
    /// local-only metadata: it is written independently of the upsert column set.
    func testDeltaUpsertDoesNotClobberLocalMetadata() throws {
        try cache.upsert(makeItem("a", parent: "root", name: "file"))
        let meta = LocalMetadata(extendedAttributes: [DomainService.MarkParameter.heartXattr: heartBlob(true)],
                                 tagData: Data([0xAA]))
        try cache.setLocalMetadata(graphID: "a", meta)

        // Re-crawl delivers the same row again (e.g. a later delta page) with no local meta.
        _ = try cache.upsertBatch([makeItem("a", parent: "root", name: "file")])

        XCTAssertEqual(try cache.item(graphID: "a")?.localMetadata, meta,
                       "tags + marks must survive a delta re-crawl")
    }

    /// `LocalMetadata.merging` (used by `modifyMetadata`) applies only the fields a change
    /// marks present, leaving the rest of the sidecar intact.
    func testMergingAppliesOnlyValidEntries() {
        let existing = LocalMetadata(extendedAttributes: [DomainService.MarkParameter.heartXattr: heartBlob(true)],
                                     tagData: Data([0x01]))

        // A tags-only change must replace tagData and preserve the heart xattr.
        let tagsOnly = DomainService.EntryMetadata(
            fileSystemFlags: nil, lastUsedDate: nil, tagData: Data([0x09]), favoriteRank: nil,
            creationDate: nil, contentModificationDate: nil, extendedAttributes: nil,
            typeAndCreator: nil, validEntries: [.tagData])
        let merged = existing.merging(tagsOnly)
        XCTAssertEqual(merged.tagData, Data([0x09]))
        XCTAssertEqual(merged.extendedAttributes, existing.extendedAttributes)

        // A change touching neither field is a no-op.
        let unrelated = DomainService.EntryMetadata(
            fileSystemFlags: nil, lastUsedDate: nil, tagData: nil, favoriteRank: nil,
            creationDate: nil, contentModificationDate: nil, extendedAttributes: nil,
            typeAndCreator: nil, validEntries: [.lastUsedDate])
        XCTAssertEqual(existing.merging(unrelated), existing)
    }
}
