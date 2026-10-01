/// Unit tests for `MetadataCacheTrashName`.
//
//  MetadataCacheTrashNameTests.swift
//  ExtensionTests
//
//  Regression coverage for the "trashed item shows its graph-id instead of its name" bug.
//  Two independent mechanisms are pinned here:
//
//  1. `markTrashed` refreshes the row's display name/parent when the caller passes
//     authoritative values (as `trashItem` now does from its `/items/{id}` fetch), so the
//     tombstoned row surfaces the real name in trash enumeration.
//  2. `upsert` (the delta / `/children` reconciliation path) never overwrites a real cached
//     name with a placeholder name equal to the graph id — the shape a `deleted`-facet or
//     name-less delta echo takes.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCacheTrashNameTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "trash-name-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private func liveItem(graphID: String, name: String, parent: String?) -> CachedItem {
        CachedItem(graphID: graphID, parentGraphID: parent, name: name, isFolder: false,
                   remoteFileSize: 1, eTag: "etag", cTag: nil, createdDate: nil, modifiedDate: nil,
                   deleted: false, rank: 0)
    }

    /// `markTrashed` with an explicit name/parent refreshes those columns, so a trashed row
    /// whose cached name was stale (or a placeholder) surfaces the authoritative name.
    func testMarkTrashedRefreshesName() throws {
        _ = try cache.upsert(liveItem(graphID: "G1", name: "G1", parent: "OLD")) // placeholder name

        try cache.markTrashed(graphID: "G1", deletedAt: Date(), name: "Report.txt",
                              parentGraphID: "PARENT")

        let page = try cache.trashedItemsPage(after: nil, limit: 10)
        let row = try XCTUnwrap(page.first { $0.graphID == "G1" })
        XCTAssertEqual(row.name, "Report.txt")
        XCTAssertEqual(row.parentGraphID, "PARENT")
        XCTAssertNotNil(row.deletedAt)
    }

    /// `markTrashed` without a name (delta-driven caller) preserves the existing cached name.
    func testMarkTrashedWithoutNamePreservesName() throws {
        _ = try cache.upsert(liveItem(graphID: "G2", name: "Keep.txt", parent: "P"))

        try cache.markTrashed(graphID: "G2", deletedAt: Date())

        let page = try cache.trashedItemsPage(after: nil, limit: 10)
        let row = try XCTUnwrap(page.first { $0.graphID == "G2" })
        XCTAssertEqual(row.name, "Keep.txt", "nil name must not clobber the cached name")
        XCTAssertEqual(row.parentGraphID, "P")
    }

    /// An upsert whose name equals the graph id (a name-less delta echo) must not overwrite a
    /// real cached name.
    func testUpsertPlaceholderNameDoesNotClobber() throws {
        _ = try cache.upsert(liveItem(graphID: "G3", name: "Photo.jpg", parent: "P"))

        // Placeholder shape: name == graphID (mirrors `item.name ?? item.id`).
        _ = try cache.upsert(liveItem(graphID: "G3", name: "G3", parent: "P"))

        let row = try XCTUnwrap(try cache.item(graphID: "G3"))
        XCTAssertEqual(row.name, "Photo.jpg", "placeholder name must not overwrite real name")
    }

    /// A genuine rename (real name, not equal to the id) still overwrites.
    func testUpsertRealNameStillOverwrites() throws {
        _ = try cache.upsert(liveItem(graphID: "G4", name: "Old.txt", parent: "P"))

        _ = try cache.upsert(liveItem(graphID: "G4", name: "New.txt", parent: "P"))

        let row = try XCTUnwrap(try cache.item(graphID: "G4"))
        XCTAssertEqual(row.name, "New.txt")
    }

    /// B: once a row is tombstoned, a later `/children` reconciliation
    /// carrying a *real but different* name (e.g. the recycle bin reports the name with the
    /// `.bc` extension stripped) must not overwrite the authoritative name/parent captured at
    /// trash time. Without the tombstone guard the placeholder-name check (name == graphID)
    /// would let this through and the trashed item would lose its `.bc` badge.
    func testTombstonedRowFreezesNameAgainstRealUpsert() throws {
        _ = try cache.upsert(liveItem(graphID: "G6", name: "Secret.bc", parent: "P"))
        try cache.markTrashed(graphID: "G6", deletedAt: Date(), name: "Secret.bc", parentGraphID: "P")

        // Recycle-bin reconciliation: a genuine (non-placeholder) name that differs, plus a
        // different live parent. Neither may touch the tombstoned row.
        _ = try cache.upsert(liveItem(graphID: "G6", name: "Secret", parent: "RECYCLE"))

        let page = try cache.trashedItemsPage(after: nil, limit: 10)
        let row = try XCTUnwrap(page.first { $0.graphID == "G6" })
        XCTAssertEqual(row.name, "Secret.bc", "tombstoned name must not be overwritten by a live upsert")
        XCTAssertEqual(row.parentGraphID, "P", "tombstoned parent must not be overwritten by a live upsert")
    }

    /// A tombstoned row must freeze its display facets (size, created, modified) the same way
    /// it freezes name/parent: OneDrive delta echoes a recycle-bin item with stripped facets
    /// (size absent → 0, no dates). Without the guard the upsert flips the trashed item to
    /// size 0 and a 1970 modified date while the name stays — exactly the reported symptom.
    func testTombstonedRowFreezesSizeAndDatesAgainstStrippedUpsert() throws {
        let created = Date(timeIntervalSince1970: 1_600_000_000)
        let modified = Date(timeIntervalSince1970: 1_600_000_500)
        _ = try cache.upsert(CachedItem(graphID: "G8", parentGraphID: "P", name: "big.bc",
                                        isFolder: false, remoteFileSize: 4096, eTag: "e", cTag: "c",
                                        createdDate: created, modifiedDate: modified,
                                        deleted: false, rank: 0))
        try cache.markTrashed(graphID: "G8", deletedAt: Date(), name: "big.bc", parentGraphID: "P")

        // Stripped delta echo of the recycle-bin item: size 0, no dates.
        _ = try cache.upsert(CachedItem(graphID: "G8", parentGraphID: "RECYCLE", name: "G8",
                                        isFolder: false, remoteFileSize: 0, eTag: "e", cTag: "c",
                                        createdDate: nil, modifiedDate: nil,
                                        deleted: false, rank: 0))

        let row = try XCTUnwrap(try cache.itemIncludingDeleted(graphID: "G8"))
        XCTAssertEqual(row.remoteFileSize, 4096, "tombstoned size must survive a stripped delta echo")
        XCTAssertEqual(row.createdDate, created, "tombstoned created date must survive")
        XCTAssertEqual(row.modifiedDate, modified, "tombstoned modified date must survive")
    }

    /// C: the `modifyItem` idempotency guard keys off the tombstone shape
    /// (`deleted=1 AND deleted_at NOT NULL`) via `isItemTrashed`. A row the action already
    /// trashed must report as trashed so ANY of Finder's echoed modifies on it (observed:
    /// `.filename`, not `.parentItemIdentifier`) is a no-op instead of a doomed PATCH/DELETE on
    /// a recycle-bin item (404). A live row must report not-trashed so a genuine trash still runs.
    func testTombstonedRowIsDetectableForIdempotentTrash() throws {
        _ = try cache.upsert(liveItem(graphID: "G7", name: "note.txt", parent: "P"))
        // Live row: not yet trashed.
        XCTAssertNil(try cache.item(graphID: "G7")?.deletedAt)

        try cache.markTrashed(graphID: "G7", deletedAt: Date(), name: "note.txt", parentGraphID: "P")

        let row = try XCTUnwrap(try cache.itemIncludingDeleted(graphID: "G7"))
        XCTAssertTrue(row.deleted && row.deletedAt != nil,
                      "tombstoned row must be detectable (drives the modifyItem no-op guard)")
    }

    /// Restore action gate: `markTrashed(outOfBand:)` persists the
    /// `restorableOutOfBand` flag on the row's local metadata so `entry(from:)` can vend
    /// `userInfo.restorable` — the predicate that shows the custom "Put Back" only for items
    /// trashed by the encrypt/decrypt action. A framework move-to-trash (`outOfBand:false`) must
    /// NOT set it, so the native "Put Back" is never duplicated. The flag must also survive a
    /// later `/children` reconciliation (upsert never touches `local_meta`).
    func testOutOfBandTrashSetsRestorableFlagAndPlainTrashDoesNot() throws {
        _ = try cache.upsert(liveItem(graphID: "OOB", name: "orig.bc", parent: "P"))
        try cache.markTrashed(graphID: "OOB", deletedAt: Date(), name: "orig.bc", parentGraphID: "P", outOfBand: true)
        XCTAssertEqual(try cache.itemIncludingDeleted(graphID: "OOB")?.localMetadata.restorableOutOfBand, true,
                       "out-of-band trash must flag the row restorable")

        // A later /children reconciliation carrying live values must not drop the flag.
        _ = try cache.upsert(liveItem(graphID: "OOB", name: "orig", parent: "RECYCLE"))
        XCTAssertEqual(try cache.itemIncludingDeleted(graphID: "OOB")?.localMetadata.restorableOutOfBand, true,
                       "restorable flag must survive a live upsert (local_meta is never clobbered)")

        _ = try cache.upsert(liveItem(graphID: "FW", name: "doc.bc", parent: "P"))
        try cache.markTrashed(graphID: "FW", deletedAt: Date(), name: "doc.bc", parentGraphID: "P")
        XCTAssertNil(try cache.itemIncludingDeleted(graphID: "FW")?.localMetadata.restorableOutOfBand,
                     "framework move-to-trash must NOT flag restorable (no duplicate Put Back)")
    }

    /// The `LifecycleState` view maps the `deleted`/`deletedAt` column pair onto the three
    /// named states every reader switches on. Pins the derivation so a future column tweak
    /// can't silently reclassify a row (e.g. a purged tombstone read as trashed → restorable).
    func testLifecycleStateDerivation() throws {
        _ = try cache.upsert(liveItem(graphID: "L1", name: "live.txt", parent: "P"))
        let live = try XCTUnwrap(try cache.item(graphID: "L1"))
        XCTAssertEqual(live.lifecycle, .live)
        XCTAssertFalse(live.isTrashed); XCTAssertFalse(live.isPurged)

        try cache.markTrashed(graphID: "L1", deletedAt: Date(), name: "live.txt", parentGraphID: "P")
        let trashed = try XCTUnwrap(try cache.itemIncludingDeleted(graphID: "L1"))
        XCTAssertEqual(trashed.lifecycle, .trashed)
        XCTAssertTrue(trashed.isTrashed); XCTAssertFalse(trashed.isPurged)

        try cache.purgeItem(graphID: "L1")
        let purged = try XCTUnwrap(try cache.itemIncludingDeleted(graphID: "L1"))
        XCTAssertEqual(purged.lifecycle, .purged)
        XCTAssertFalse(purged.isTrashed); XCTAssertTrue(purged.isPurged)
    }

    /// The `is_trashed` generated column must agree with the Swift `isTrashed` derivation:
    /// `trashedItemsPage` (which filters on `is_trashed`) returns exactly the trashed row and
    /// excludes both live and purged rows.
    func testGeneratedIsTrashedColumnMatchesSwiftDerivation() throws {
        _ = try cache.upsert(liveItem(graphID: "T-live", name: "a", parent: "P"))
        _ = try cache.upsert(liveItem(graphID: "T-trash", name: "b", parent: "P"))
        _ = try cache.upsert(liveItem(graphID: "T-purge", name: "c", parent: "P"))
        try cache.markTrashed(graphID: "T-trash", deletedAt: Date(), name: "b", parentGraphID: "P")
        try cache.markTrashed(graphID: "T-purge", deletedAt: Date(), name: "c", parentGraphID: "P")
        try cache.purgeItem(graphID: "T-purge")

        let page = try cache.trashedItemsPage(after: nil, limit: 10)
        let ids = Set(page.map(\.graphID))
        XCTAssertEqual(ids, ["T-trash"], "only the trashed row satisfies is_trashed")
    }

    /// End-to-end: trash a real-named item, then a name-less delta echo arrives; the trash page
    /// name stays stable (does not revert to the graph id).
    func testTrashNameStableAcrossDeltaEcho() throws {
        _ = try cache.upsert(liveItem(graphID: "G5", name: "Doc.pdf", parent: "P"))
        try cache.markTrashed(graphID: "G5", deletedAt: Date(), name: "Doc.pdf", parentGraphID: "P")

        // Delta echoes the item back with no usable name (placeholder == graphID).
        _ = try cache.upsert(liveItem(graphID: "G5", name: "G5", parent: "P"))

        let page = try cache.trashedItemsPage(after: nil, limit: 10)
        let row = try XCTUnwrap(page.first { $0.graphID == "G5" })
        XCTAssertEqual(row.name, "Doc.pdf", "trashed name must survive a name-less delta echo")
    }
}
