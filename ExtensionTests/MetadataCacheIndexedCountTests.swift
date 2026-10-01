/// Unit tests for `MetadataCacheIndexedCount`.
//
//  MetadataCacheIndexedCountTests.swift
//  ExtensionTests
//
//  Coverage for `MetadataCache.indexedCount()` — the live (non-tombstoned)
//  row count surfaced to the app's menu-bar detail view via the progress relay.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class MetadataCacheIndexedCountTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "indexed-count-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    private func item(_ i: Int) -> CachedItem {
        CachedItem(graphID: "item-\(i)", parentGraphID: "P", name: "file-\(i).txt",
                   isFolder: false, remoteFileSize: Int64(i), eTag: "etag-\(i)", cTag: nil,
                   createdDate: nil, modifiedDate: nil, deleted: false, rank: 0)
    }

    func testEmptyCacheCountsZero() throws {
        XCTAssertEqual(try cache.indexedCount(), 0)
    }

    func testCountsLiveRows() throws {
        _ = try cache.upsertBatch((0..<10).map(item))
        XCTAssertEqual(try cache.indexedCount(), 10)
    }

    func testExcludesTombstonedRows() throws {
        _ = try cache.upsertBatch((0..<10).map(item))
        try cache.markDeleted(graphID: "item-0")
        try cache.markDeleted(graphID: "item-1")
        XCTAssertEqual(try cache.indexedCount(), 8)
    }
}
