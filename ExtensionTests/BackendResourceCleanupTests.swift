/// Unit tests for `BackendResourceCleanup`.
//
//  BackendResourceCleanupTests.swift
//  ExtensionTests
//
//  Verifies the shared on-disk teardown entry point: `destroy` removes the domain's stores and
//  is idempotent (including for a domain that never had them), the shared steps run for a
//  backend absent from the routing registry (and for a nil backend), and `empty` clears rows in
//  place while leaving the database file and a still-open handle usable.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import Extension

final class BackendResourceCleanupTests: XCTestCase {

    private let appGroupID = AppIdentifiers.appGroupID
    private var domainID: String!

    override func setUpWithError() throws {
        domainID = "backend-cleanup-\(UUID().uuidString)"
    }

    override func tearDownWithError() throws {
        // Every store the shared teardown owns, not just the metadata cache: `empty` constructs a
        // `BC01HeaderCache`, which creates its database in the real App Group container. Removing
        // only one of the two left a `backend-cleanup-<uuid>.sqlite3` behind on every run.
        if let domainID { try? BackendResourceCleanup.destroy(domainID: domainID, backend: nil) }
        domainID = nil
    }

    // MARK: - Helpers

    /// The metadata cache database URL for the test domain, without creating it.
    private func metadataCacheURL() throws -> URL {
        let container = try XCTUnwrap(FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID))
        let safe = domainID.replacingOccurrences(of: "/", with: "_")
        return container
            .appendingPathComponent("OneDriveCache", isDirectory: true)
            .appendingPathComponent("\(safe).sqlite3")
    }

    /// Every store the shared teardown owns, as on-disk paths.
    private func sharedStoreURLs() throws -> [URL] {
        [try metadataCacheURL()]
    }

    private func seedStores() throws {
        let cache = try MetadataCache(domainID: domainID)
        try cache.upsert(sampleItem(graphID: "root"))
    }

    private func sampleItem(graphID: String) -> CachedItem {
        CachedItem(graphID: graphID, parentGraphID: nil, name: graphID,
                   isFolder: true, remoteFileSize: 0, eTag: nil, cTag: nil,
                   createdDate: nil, modifiedDate: nil, deleted: false, rank: 0)
    }

    // MARK: - destroy

    /// `destroy` unlinks every shared store, and is idempotent on a second call.
    func testDestroyRemovesSharedStoresAndIsIdempotent() throws {
        try seedStores()
        for url in try sharedStoreURLs() {
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path),
                          "precondition: \(url.lastPathComponent) exists")
        }

        try BackendResourceCleanup.destroy(domainID: domainID, backend: .oneDrive)

        for url in try sharedStoreURLs() {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                           "store removed: \(url.lastPathComponent)")
        }

        XCTAssertNoThrow(try BackendResourceCleanup.destroy(domainID: domainID, backend: .oneDrive),
                         "second destroy is a no-op")
    }

    /// A domain that never had stores is not an error.
    func testDestroyOnDomainWithoutStoresIsNoOp() throws {
        XCTAssertNoThrow(try BackendResourceCleanup.destroy(domainID: "never-existed-\(UUID().uuidString)",
                                                            backend: .oneDrive))
    }

    /// The shared steps are not gated on the routing registry: a backend with no registered
    /// ``BackendResourceCleaning`` — and an unresolved (`nil`) backend — still get full teardown.
    func testBackendAbsentFromRegistryStillGetsSharedSteps() throws {
        try seedStores()
        try BackendResourceCleanup.destroy(domainID: domainID, backend: .emulator)
        for url in try sharedStoreURLs() {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                           "emulator domain's shared store removed: \(url.lastPathComponent)")
        }

        try seedStores()
        try BackendResourceCleanup.destroy(domainID: domainID, backend: nil)
        for url in try sharedStoreURLs() {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                           "nil backend's shared store removed: \(url.lastPathComponent)")
        }
    }

    // MARK: - empty

    /// `empty` leaves the database file present with zero rows, and a handle opened *before*
    /// the call still usable afterwards — the invariant "Lock and Remove Vault" depends on.
    func testEmptyLeavesFilesPresentAndOpenHandleUsable() throws {
        let cache = try MetadataCache(domainID: domainID)
        try cache.upsert(sampleItem(graphID: "root"))
        XCTAssertNotNil(try cache.item(graphID: "root"), "precondition: row present")

        try BackendResourceCleanup.empty(domainID: domainID, backend: .oneDrive)

        for url in try sharedStoreURLs() {
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path),
                          "file survives empty: \(url.lastPathComponent)")
        }
        XCTAssertNil(try cache.item(graphID: "root"), "rows cleared through the pre-existing handle")

        // The handle is still writable: emptying must not have unlinked the inode underneath it.
        try cache.upsert(sampleItem(graphID: "after"))
        XCTAssertNotNil(try cache.item(graphID: "after"), "open handle remains usable after empty")
    }

    /// `empty` is repeatable, including against stores that were never created.
    ///
    /// Lock-and-remove now clears local data whether or not the domain removal succeeded, and
    /// `reconcileRemovedDomainsAtLaunch` re-runs the same teardown at the next launch to finish an
    /// interrupted one. That second pass normally lands on already-empty stores, so a repeat call
    /// must be a clean no-op rather than an error the caller has to special-case.
    func testEmptyIsIdempotentAndSafeOnAbsentStores() throws {
        XCTAssertNoThrow(try BackendResourceCleanup.empty(domainID: "never-existed-\(UUID().uuidString)",
                                                          backend: .oneDrive),
                         "emptying stores that were never created must not throw")

        let cache = try MetadataCache(domainID: domainID)
        try cache.upsert(sampleItem(graphID: "root"))

        try BackendResourceCleanup.empty(domainID: domainID, backend: .oneDrive)
        XCTAssertNoThrow(try BackendResourceCleanup.empty(domainID: domainID, backend: .oneDrive),
                         "a second pass over already-empty stores must be a no-op")
        XCTAssertNil(try cache.item(graphID: "root"), "rows stay cleared across repeated empties")
    }
}
