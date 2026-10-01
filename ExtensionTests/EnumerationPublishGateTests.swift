/// Unit tests for `EnumerationPublishGate`.
//
//  EnumerationPublishGateTests.swift
//  ExtensionTests
//
//  Exercises the enumeration publish gate.
//
//  Enumeration used to WITHHOLD an encrypted row until its exact plaintext size was known,
//  because the only size otherwise available is the over-reporting ciphertext estimate and an
//  over-reported `documentSize` breaks `NSFileProviderPartialContentFetching`. Withholding was
//  the bigger risk: a withheld row is a file the user simply cannot see, and no speculative
//  header probing remains to shorten the wait. So publication is unconditional and the estimate
//  stands until a content fetch parses the header and records the exact length.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import Extension

final class EnumerationPublishGateTests: ConfigIsolatedTestCase {

    private var domainID: String!
    private var client: GraphDriveClient!

    override func setUpWithError() throws {
        domainID = "publish-gate-\(UUID().uuidString)"
        UserDefaults.sharedContainerDefaults.setCryptoConfig(
            DomainCryptoConfig(algorithm: .bc01, userId: "u1"),
            for: NSFileProviderDomainIdentifier(rawValue: domainID))
        client = GraphDriveClient(displayName: "OneDrive", domainID: domainID,
                                  servingItemID: nil)
    }

    override func tearDownWithError() throws {
        client = nil
        if let domainID {
            // Writing an empty config would leave the dictionary entry in place, accumulating one
            // row per run in the shared App Group store. This removes the key outright.
            SharedConfigStore.shared.removeAllConfiguration(
                for: NSFileProviderDomainIdentifier(rawValue: domainID))
            try? MetadataCache.destroy(domainID: domainID)
        }
        domainID = nil
    }

    private func row(_ graphID: String, name: String, isFolder: Bool = false,
                     deleted: Bool = false, plaintextSize: Int64? = nil) -> CachedItem {
        CachedItem(graphID: graphID, parentGraphID: "root", name: name, isFolder: isFolder,
                   remoteFileSize: 8192, eTag: "e1", cTag: "c1",
                   createdDate: nil, modifiedDate: nil, deleted: deleted, rank: 0,
                   plaintextSize: plaintextSize)
    }

    // MARK: - Publication is unconditional

    /// The case the change exists for: an encrypted file whose true size is unknown is published
    /// with the estimate rather than withheld. Visible-but-approximate beats invisible.
    func testEncryptedRowWithoutSizeIsPublishable() {
        XCTAssertTrue(client.isPublishable(row("a", name: "secret.bc")),
                      "withholding would make the file invisible in Finder")
    }

    func testEncryptedRowWithSizeIsPublishable() {
        XCTAssertTrue(client.isPublishable(row("a", name: "secret.bc", plaintextSize: 4096)))
    }

    func testFolderIsPublishable() {
        XCTAssertTrue(client.isPublishable(row("d", name: "dir", isFolder: true)))
    }

    func testPlainFileIsPublishable() {
        XCTAssertTrue(client.isPublishable(row("p", name: "notes.txt")))
    }

    /// A tombstone must still enumerate or trash breaks: the framework needs the row to place
    /// the item in the recycle bin and to offer Put Back.
    func testTombstoneIsPublishable() {
        XCTAssertTrue(client.isPublishable(row("t", name: "gone.bc", deleted: true)))
    }
}
