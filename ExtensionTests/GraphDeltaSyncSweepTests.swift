/// Unit tests for the generation-tagged full crawl (mark-and-sweep) in `GraphDeltaSync`.
//
//  GraphDeltaSyncSweepTests.swift
//  ExtensionTests
//
//  A 410 restarts a full crawl under a new generation; reaching the deltaLink purges every
//  live row the crawl did not return. Rows are never wiped, so local-only state survives.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class GraphDeltaSyncSweepTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "delta-sweep-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    // MARK: - Fixtures

    private static func file(_ id: String) -> String {
        #"{"id":"\#(id)","name":"\#(id).txt","file":{"mimeType":"text/plain"},"size":3,"eTag":"e\#(id)","cTag":"c\#(id)","parentReference":{"id":"ROOT"}}"#
    }

    private static func page(_ ids: [String], next: String? = nil) -> Result<Data, Error> {
        let link = next.map { #""@odata.nextLink":"https://x/delta?token=\#($0)""# }
            ?? #""@odata.deltaLink":"https://x/delta?token=final""#
        return .success(Data(#"{"value":[\#(ids.map(file).joined(separator: ","))],\#(link)}"#.utf8))
    }

    private static let gone: Result<Data, Error> = .failure(DeltaHTTPError(statusCode: 410))

    /// A sync whose fetch serves `responses` in order, then repeats the last one.
    private func makeSync(_ responses: [Result<Data, Error>]) -> GraphDeltaSync {
        var index = 0
        return GraphDeltaSync(cache: cache, rootGraphID: "ROOT", fetch: { _, _ in
            defer { index = min(index + 1, responses.count - 1) }
            return try responses[index].get()
        })
    }

    /// Seed A, B, C through a completed first crawl.
    private func seedABC() async throws {
        _ = try await makeSync([Self.page(["A", "B", "C"])]).runPass()
        XCTAssertNil(cache.pendingFullCrawlGeneration, "precondition: first crawl finished")
        XCTAssertTrue(cache.isInitialCrawlComplete)
    }

    private func isLive(_ id: String) throws -> Bool { try cache.item(graphID: id) != nil }

    // MARK: - Tests

    /// 410 → full crawl returns A, C → B purged and delivered by the working-set feed.
    func testExpiryCrawlPurgesItemsMissingFromCrawl() async throws {
        try await seedABC()
        let hwm = cache.withMetaTransaction { $0.currentRank() }

        let result = try await makeSync([Self.gone, Self.page(["A", "C"])]).runPass()

        XCTAssertFalse(result.cursorExpired)
        XCTAssertTrue(result.changed)
        XCTAssertTrue(result.changedParentGraphIDs.contains("ROOT"))
        XCTAssertTrue(try isLive("A"))
        XCTAssertTrue(try isLive("C"))
        let b = try XCTUnwrap(cache.itemIncludingDeleted(graphID: "B"))
        XCTAssertTrue(b.deleted)
        XCTAssertNil(b.deletedAt, "purged, not trashed")
        let changed = try cache.itemsChanged(sinceRank: hwm)
        XCTAssertEqual(changed.map(\.graphID), ["B"], "only the purge moves rank")
        XCTAssertNil(cache.pendingFullCrawlGeneration)
        XCTAssertTrue(cache.isInitialCrawlComplete)
        XCTAssertEqual(cache.deltaLink, "https://x/delta?token=final")
    }

    /// Cancelled mid-crawl after a 410: nothing swept; the resumed crawl completes and sweeps.
    func testCancelledCrawlDefersSweepUntilResumedCrawlCompletes() async throws {
        try await seedABC()

        let sync = makeSync([Self.gone, Self.page(["A"], next: "p2")])
        let task = Task { try await sync.runPass() }
        task.cancel()
        let partial = try await task.value

        XCTAssertTrue(partial.cancelled)
        XCTAssertTrue(try isLive("B"), "no sweep before the crawl completes")
        XCTAssertNotNil(cache.pendingFullCrawlGeneration, "pending generation persists")
        XCTAssertEqual(cache.deltaLink, "https://x/delta?token=p2")

        _ = try await makeSync([Self.page(["C"])]).runPass()

        XCTAssertFalse(try isLive("B"))
        XCTAssertTrue(try isLive("A"), "seen on the page before cancellation")
        XCTAssertTrue(try isLive("C"))
        XCTAssertNil(cache.pendingFullCrawlGeneration)
    }

    /// A trashed row the crawl does not return stays trashed rather than being purged.
    func testTrashedRowAbsentFromCrawlStaysTrashed() async throws {
        try await seedABC()
        let trashedAt = Date(timeIntervalSince1970: 1_700_000_000)
        try cache.markTrashed(graphID: "B", deletedAt: trashedAt)

        _ = try await makeSync([Self.gone, Self.page(["A", "C"])]).runPass()

        let b = try XCTUnwrap(cache.itemIncludingDeleted(graphID: "B"))
        XCTAssertTrue(b.deleted)
        XCTAssertNotNil(b.deletedAt, "still in the recycle bin")
    }

    /// An unchanged row re-seen by the crawl keeps local metadata, plaintext size and rank.
    func testUnchangedRowKeepsLocalStateAndRank() async throws {
        try await seedABC()
        let tags = LocalMetadata(extendedAttributes: ["k": Data([1])], tagData: Data([2]))
        try cache.setLocalMetadata(graphID: "A", tags)
        let before = try XCTUnwrap(cache.item(graphID: "A"))

        _ = try await makeSync([Self.gone, Self.page(["A"])]).runPass()

        let after = try XCTUnwrap(cache.item(graphID: "A"))
        XCTAssertEqual(after.localMetadata, tags)
        XCTAssertEqual(after.plaintextSize, before.plaintextSize)
        XCTAssertNotNil(after.plaintextSize)
        XCTAssertEqual(after.rank, before.rank, "seen-stamp only, no rank bump")
    }

    /// A row inserted by a non-crawl writer during a pending crawl is not swept.
    func testRowInsertedDuringPendingCrawlIsNotSwept() async throws {
        try await seedABC()
        try cache.beginFullCrawl()
        try cache.upsertBatch([CachedItem(graphID: "D", parentGraphID: "ROOT", name: "D.txt",
                                          isFolder: false, remoteFileSize: 1, eTag: "eD", cTag: "cD",
                                          createdDate: nil, modifiedDate: nil, deleted: false, rank: 0)])

        _ = try await makeSync([Self.page(["A", "B", "C"])]).runPass()

        XCTAssertTrue(try isLive("D"), "/children data is current remote state")
    }

    /// A 410 on the fresh crawl too: report expiry, keep the pending generation.
    func testDoubleExpiryReportsCursorExpiredAndKeepsPendingGeneration() async throws {
        try await seedABC()

        let result = try await makeSync([Self.gone]).runPass()

        XCTAssertTrue(result.cursorExpired)
        XCTAssertNotNil(cache.pendingFullCrawlGeneration)
        XCTAssertTrue(try isLive("B"), "no sweep without a completed crawl")
        XCTAssertFalse(cache.isInitialCrawlComplete)
    }

    /// Rebuild Index opened from the host mid-crawl: the stale pass must not restore its old
    /// cursor, and the new generation's crawl restarts from scratch.
    func testCursorWriteRejectedAfterNewerGeneration() throws {
        let old = try cache.beginFullCrawl()
        try cache.beginFullCrawl()

        XCTAssertFalse(try cache.saveCursor("https://x/delta?token=stale", generation: old))
        XCTAssertEqual(cache.deltaLink, "", "cursor stays cleared for the newer crawl")
    }

    /// Rebuild Index on an idle domain: next pass crawls from scratch and sweeps.
    func testRebuildIndexTriggersCrawlAndSweep() async throws {
        try await seedABC()
        var signalled: [String] = []
        let service = OneDriveProvisioningService(
            beginFullCrawl: { [cache] _ in try cache!.beginFullCrawl() },
            signalWorkingSet: { signalled.append($0) })

        try await service.rebuildIndex(domainIdentifier: domainID)

        XCTAssertEqual(signalled, [domainID])
        XCTAssertFalse(cache.isInitialCrawlComplete)
        _ = try await makeSync([Self.page(["A"])]).runPass()
        XCTAssertFalse(try isLive("B"))
        XCTAssertFalse(try isLive("C"))
        XCTAssertTrue(try isLive("A"))
    }
}

/// `DeltaPageUpdate.isFullCrawlInProgress` drives the detail panel's crawl-progress figure.
final class GraphDeltaSyncFullCrawlProgressTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "delta-crawl-progress-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private final class Recorder: @unchecked Sendable {
        var flags: [Bool] = []
    }

    private func run(_ pages: [String]) async throws -> [Bool] {
        let data = pages.map { Data($0.utf8) }
        var index = 0
        let recorder = Recorder()
        let sync = GraphDeltaSync(cache: cache, rootGraphID: "ROOT", fetch: { _, _ in
            defer { index = min(index + 1, data.count - 1) }
            return data[index]
        }, onDeltaUpdates: { recorder.flags.append($0.isFullCrawlInProgress) })
        _ = try await sync.runPass()
        return recorder.flags
    }

    private static let more = #"{"value":[],"@odata.nextLink":"https://x/delta?token=more"}"#
    private static let final = #"{"value":[],"@odata.deltaLink":"https://x/delta?token=final"}"#

    /// Full crawl: in progress on every page but the last; incremental pass: never.
    func testFlagTracksFullCrawlPages() async throws {
        let full = try await run([Self.more, Self.final])
        let incremental = try await run([Self.more, Self.final])
        XCTAssertEqual(full, [true, false])
        XCTAssertEqual(incremental, [false, false], "incremental pass")
    }
}
