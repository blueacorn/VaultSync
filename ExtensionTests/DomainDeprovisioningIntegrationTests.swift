/// Unit tests for `DomainDeprovisioningIntegration`.
//
//  DomainDeprovisioningIntegrationTests.swift
//  ExtensionTests
//
//  End-to-end teardown: provisions a OneDrive-style domain (config entry + a populated
//  ``MetadataCache`` SQLite file in the App Group container), runs the `.standard`
//  ``DomainDeprovisioningService`` pipeline, and asserts the config entry is gone and the
//  cache file (plus WAL/SHM sidecars) has been removed from disk.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import Extension

final class DomainDeprovisioningIntegrationTests: ConfigIsolatedTestCase {

    private let appGroupID = AppIdentifiers.appGroupID
    private var domainID: NSFileProviderDomainIdentifier!

    override func setUpWithError() throws {
        domainID = NSFileProviderDomainIdentifier(rawValue: "deprovision-int-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        // Defensive: ensure nothing leaks even if an assertion failed mid-test.
        if let domainID {
            SharedConfigStore.shared.removeAllConfiguration(for: domainID)
            try? MetadataCache.destroy(domainID: domainID.rawValue)
        }
        domainID = nil
    }

    private func cacheFileURL() throws -> URL {
        let container = try XCTUnwrap(FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID))
        let safe = domainID.rawValue.replacingOccurrences(of: "/", with: "_")
        return container
            .appendingPathComponent("OneDriveCache", isDirectory: true)
            .appendingPathComponent("\(safe).sqlite3")
    }

    func testTearDownRemovesConfigAndMetadataCache() async throws {
        let store = SharedConfigStore.shared

        // Provision: config binding + a populated cache (forces the db + WAL onto disk).
        store.setAccount(DomainAccount(displayName: "OneDrive", backendKind: .oneDrive),
                         for: domainID)
        do {
            let cache = try MetadataCache(domainID: domainID.rawValue)
            try cache.upsert(CachedItem(graphID: "root", parentGraphID: nil, name: "root",
                                        isFolder: true, remoteFileSize: 0, eTag: nil, cTag: nil,
                                        createdDate: nil, modifiedDate: nil, deleted: false, rank: 0))
        } // close the handle before destroy

        let dbURL = try cacheFileURL()
        XCTAssertTrue(FileManager.default.fileExists(atPath: dbURL.path),
                      "precondition: cache db exists after provisioning")

        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { _ in },
            backendResourceDestroy: { try BackendResourceCleanup.destroy(domainID: $0, backend: $1) },
            backendResourceEmpty: { try BackendResourceCleanup.empty(domainID: $0, backend: $1) }
        )
        try await service.tearDown(domain: domainID, displayName: "OneDrive")

        XCTAssertNil(store.account(for: domainID), "config binding removed")
        let base = dbURL.deletingLastPathComponent()
        let name = dbURL.lastPathComponent
        for url in [dbURL,
                    base.appendingPathComponent(name + "-wal"),
                    base.appendingPathComponent(name + "-shm")] {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                           "cache artifact removed: \(url.lastPathComponent)")
        }
    }

    /// `destroy` is idempotent — destroying a domain with no cache is not an error.
    func testDestroyMissingCacheIsNoOp() throws {
        XCTAssertNoThrow(try MetadataCache.destroy(domainID: domainID.rawValue))
    }
}
