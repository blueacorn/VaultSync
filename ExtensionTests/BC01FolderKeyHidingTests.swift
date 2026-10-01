/// Unit tests for `BC01FolderKeyHiding`.
//
//  BC01FolderKeyHidingTests.swift
//  ExtensionTests
//
//  `FolderKey.bch` is Boxcryptor's folder-key sidecar: folder metadata, not user content. It
//  must never reach the Finder domain, and its presence marks its *parent* folder encrypted.
//
//  The filter lives at the two ingestion seams — `GraphDeltaSync.partition` and
//  `GraphDriveClient.fetchAndCacheChildren` — rather than at the four cache readers. These
//  tests therefore assert the row is never *inserted*: absence from `children`/`descendants`
//  follows by construction, and the two seeders MUST agree or a key hidden on one path
//  reappears via the other.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class BC01FolderKeyHidingTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "bc01-folderkey-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    /// Build a `GraphDeltaSync` returning `pages` in order, then repeating a terminal empty
    /// delta page so the crawl loop finishes.
    private func makeSync(pages: [String], algorithm: CryptoAlgorithm) -> GraphDeltaSync {
        let payloads = pages.map { Data($0.utf8) }
            + [Data(#"{"value":[],"@odata.deltaLink":"https://x/delta?token=final"}"#.utf8)]
        var index = 0
        return GraphDeltaSync(
            cache: cache,
            rootGraphID: "ROOT",
            fetch: { _, _ in
                defer { index = min(index + 1, payloads.count - 1) }
                return payloads[index]
            },
            translator: BoxcryptorMetadataTranslator(algorithm: algorithm),
            specialItem: BC01SpecialItem(algorithm: algorithm))
    }

    // MARK: MetadataCache

    func testFolderEncryptedMarkIsAbsentUntilSetAndIsIdempotent() {
        XCTAssertFalse(cache.isFolderEncrypted("PARENT"))
        cache.markFolderEncrypted("PARENT")
        XCTAssertTrue(cache.isFolderEncrypted("PARENT"))
        cache.markFolderEncrypted("PARENT")
        XCTAssertTrue(cache.isFolderEncrypted("PARENT"))
    }

    func testFolderEncryptedMarkDoesNotLeakBetweenFolders() {
        cache.markFolderEncrypted("A")
        XCTAssertTrue(cache.isFolderEncrypted("A"))
        XCTAssertFalse(cache.isFolderEncrypted("B"))
    }

    // MARK: Delta seeder

    /// A live folder key is dropped from the upserts and marks its parent encrypted.
    func testDeltaFolderKeyIsHiddenAndMarksParent() async throws {
        let json = """
        {
          "value": [
            {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
             "size":512,"parentReference":{"id":"PARENT"}},
            {"id":"doc1","name":"notes.txt","file":{"mimeType":"text/plain"},"size":5,
             "parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        _ = try await makeSync(pages: [json], algorithm: .bc01).runPass()

        let names = try cache.children(ofParentGraphID: "PARENT").map(\.name)
        XCTAssertEqual(names, ["notes.txt"])
        XCTAssertNil(try? cache.itemIncludingDeleted(graphID: "key1") ?? nil)
        XCTAssertTrue(cache.isFolderEncrypted("PARENT"))
    }

    /// A *deleted* folder key must be skipped before the tombstone branch: it was never
    /// inserted, so a tombstone for it would be a row the system never saw. It is also not
    /// evidence — deletion of the key does not, on its own, mark the parent.
    func testDeletedDeltaFolderKeyIsSkippedEntirelyAndDoesNotMark() async throws {
        let json = """
        {
          "value": [
            {"id":"key1","name":"FolderKey.bch","deleted":{"state":"deleted"},
             "parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        _ = try await makeSync(pages: [json], algorithm: .bc01).runPass()

        XCTAssertNil(try? cache.itemIncludingDeleted(graphID: "key1") ?? nil)
        XCTAssertFalse(cache.isFolderEncrypted("PARENT"))
    }

    /// Under `.plain` the name is an ordinary user file: upserted normally, no mark written.
    func testPlainDomainKeepsFolderKeyAsOrdinaryFile() async throws {
        let json = """
        {
          "value": [
            {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
             "size":512,"parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        _ = try await makeSync(pages: [json], algorithm: .plain).runPass()

        XCTAssertEqual(try cache.children(ofParentGraphID: "PARENT").map(\.name), ["FolderKey.bch"])
        XCTAssertFalse(cache.isFolderEncrypted("PARENT"))
    }

    /// A folder named `FolderKey.bch` is not a sidecar — `isFolder` decides, not the name.
    func testFolderNamedFolderKeyIsEnumeratedNormally() async throws {
        let json = """
        {
          "value": [
            {"id":"dir1","name":"FolderKey.bch","folder":{"childCount":0},
             "parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        _ = try await makeSync(pages: [json], algorithm: .bc01).runPass()

        XCTAssertEqual(try cache.children(ofParentGraphID: "PARENT").map(\.name), ["FolderKey.bch"])
        XCTAssertFalse(cache.isFolderEncrypted("PARENT"))
    }

    /// Case variance is matched: the comparison is case-insensitive on both seeders.
    func testDeltaFolderKeyCaseVarianceIsHidden() async throws {
        let json = """
        {
          "value": [
            {"id":"key1","name":"folderkey.BCH","file":{"mimeType":"application/octet-stream"},
             "size":512,"parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        _ = try await makeSync(pages: [json], algorithm: .bc01).runPass()

        XCTAssertTrue(try cache.children(ofParentGraphID: "PARENT").isEmpty)
        XCTAssertTrue(cache.isFolderEncrypted("PARENT"))
    }

    /// Two pages naming the same parent still leave a single mark — the mark is a keyed `meta`
    /// row, and the caller `Set`-de-dupes each page's parents before writing.
    func testSameParentAcrossPagesMarksOnce() async throws {
        let page = { (id: String) in """
        {
          "value": [
            {"id":"\(id)","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
             "size":512,"parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """ }
        _ = try await makeSync(pages: [page("key1"), page("key2")], algorithm: .bc01).runPass()

        XCTAssertTrue(try cache.children(ofParentGraphID: "PARENT").isEmpty)
        XCTAssertTrue(cache.isFolderEncrypted("PARENT"))
    }

    // MARK: Enumeration readers

    /// The row is never inserted, so every reader is closed by construction — asserted for the
    /// non-recursive folder page and the recursive working-set walk.
    func testHiddenFolderKeyIsAbsentFromBothEnumerationReaders() async throws {
        let json = """
        {
          "value": [
            {"id":"PARENT","name":"folder","folder":{"childCount":2},
             "parentReference":{"id":"ROOT"}},
            {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
             "size":512,"parentReference":{"id":"PARENT"}},
            {"id":"doc1","name":"notes.txt","file":{"mimeType":"text/plain"},"size":5,
             "parentReference":{"id":"PARENT"}}
          ],
          "@odata.nextLink": "https://x/delta?token=more"
        }
        """
        _ = try await makeSync(pages: [json], algorithm: .bc01).runPass()

        let page = try cache.childrenPage(ofParentGraphID: "PARENT", after: nil, limit: 100)
        XCTAssertEqual(page.map(\.name), ["notes.txt"])

        let all = try cache.descendants(ofRootGraphID: "ROOT", after: nil, limit: 100)
        XCTAssertFalse(all.contains { $0.name.caseInsensitiveCompare("FolderKey.bch") == .orderedSame })
        XCTAssertTrue(all.contains { $0.name == "notes.txt" })
    }
}
