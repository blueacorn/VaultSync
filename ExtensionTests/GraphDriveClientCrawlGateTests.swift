/// Unit tests for `GraphDriveClientCrawlGate`.
//
//  GraphDriveClientCrawlGateTests.swift
//  ExtensionTests
//
//  `listFolder` walks `/children` only while the initial delta crawl is unfinished. Once the
//  crawl has reached a `deltaLink` the cache holds every child of every folder, so navigation
//  is served purely from SQLite.
//
//  The gate is asserted through the *network*, not a spy: these tests run with no Graph
//  credentials, so any attempt to walk `/children` fails on token acquisition. A page that
//  returns cached rows therefore proves no request was issued, and a throw proves one was.
//  `servingItemID` is supplied so resolving the serving root needs no round-trip either.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class GraphDriveClientCrawlGateTests: XCTestCase {

    private static let rootID = "ROOT"

    private var domainID: String!
    private var cache: MetadataCache!
    private var client: GraphDriveClient!

    override func setUpWithError() throws {
        domainID = "crawl-gate-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
        client = GraphDriveClient(displayName: "OneDrive", domainID: domainID,
                                  servingItemID: Self.rootID)
    }

    override func tearDownWithError() throws {
        client = nil
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    /// Seed one live child directly into the cache, bypassing any Graph path.
    private func seedChild(_ graphID: String, name: String) throws {
        try cache.upsert(CachedItem(graphID: graphID, parentGraphID: Self.rootID, name: name,
                                    isFolder: false, remoteFileSize: 4, eTag: nil, cTag: nil,
                                    createdDate: nil, modifiedDate: nil, deleted: false,
                                    deletedAt: nil, rank: 0))
    }

    private let rootFolder: DomainService.ItemIdentifier = .root

    /// `listFolder` is a completion-handler API; bridge it so the tests read linearly.
    private func listFolder(recursive: Bool) async throws -> DomainService.ListFolderReturn {
        try await withCheckedThrowingContinuation { continuation in
            _ = client.listFolder(rootFolder, recursive: recursive, startingCursor: nil) { result in
                continuation.resume(with: result)
            }
        }
    }

    /// Crawl complete + populated cache: the page comes back from SQLite with no `/children`
    /// request. Without the gate this call would throw acquiring a Graph token.
    func testCrawlCompleteServesFromCacheWithoutChildrenRequest() async throws {
        try seedChild("c1", name: "a.txt")
        cache.markInitialCrawlComplete()

        let page = try await listFolder(recursive: false)

        XCTAssertEqual(page.entries.count, 1)
        XCTAssertNil(page.cursor, "a short page exhausts the result set")
    }

    /// Crawl unfinished: the cache is only partially seeded, so the folder must still be
    /// walked. With no credentials that walk fails — which is the observable proof it ran.
    func testIncompleteCrawlIssuesChildrenRequest() async throws {
        try seedChild("c1", name: "a.txt")
        XCTAssertFalse(cache.isInitialCrawlComplete)

        do {
            _ = try await listFolder(recursive: false)
            XCTFail("expected the /children walk to be attempted and fail without credentials")
        } catch {
            // Expected: the gate let the request through.
        }
    }

    /// End-to-end consequence of a cursor expiry: clearing the flag puts the gate back into
    /// its cold state, so navigation walks `/children` again (and here, fails without
    /// credentials) rather than serving a cache that may hold ghosts.
    func testClearingCrawlCompleteRestoresChildrenWalk() async throws {
        try seedChild("c1", name: "a.txt")
        cache.markInitialCrawlComplete()
        _ = try await listFolder(recursive: false)   // served from cache, no walk

        try cache.beginFullCrawl()                   // what a 410 does

        do {
            _ = try await listFolder(recursive: false)
            XCTFail("expected the /children walk to resume once completeness is withdrawn")
        } catch {
            // Expected.
        }
    }

    /// The gate gates only the cold, first page of a non-recursive listing. A recursive
    /// (working-set) enumeration is cache-only regardless of crawl state.
    func testRecursiveEnumerationNeverWalksChildren() async throws {
        try seedChild("c1", name: "a.txt")
        XCTAssertFalse(cache.isInitialCrawlComplete)

        let page = try await listFolder(recursive: true)

        XCTAssertEqual(page.entries.count, 1)
    }
}
