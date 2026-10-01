/// Unit tests for `BC01FolderKeySeeder`.
//
//  BC01FolderKeySeederTests.swift
//  ExtensionTests
//
//  The `/children` seeder and the emulator listing filter, exercised through the pure seams
//  extracted from them — `GraphDriveClient.classifyChildrenPage` and
//  `ServerEmulatorClient.visibleEntries`. Neither needs Graph auth, a `URLSession`, or the
//  rate limiter: the paging/transport loops keep the I/O, these keep the decisions.
//
//  The delta seeder's half of the same contract lives in `BC01FolderKeyHidingTests`. The two
//  ingestion seeders MUST agree — a folder key hidden on one path but not the other simply
//  reappears — so the agreement itself is asserted here rather than left implicit.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class BC01FolderKeySeederTests: XCTestCase {

    private let bc01 = BC01SpecialItem(algorithm: .bc01)
    private let plain = BC01SpecialItem(algorithm: .plain)
    private let bc01Translator = BoxcryptorMetadataTranslator(algorithm: .bc01)
    private let plainTranslator = BoxcryptorMetadataTranslator(algorithm: .plain)

    /// Decode a `/children` page the same way the live seeder does, so the fixtures exercise
    /// the real wire shape rather than hand-built model values.
    private func page(_ json: String) throws -> [GraphDriveItem] {
        try GraphMapping.makeDecoder()
            .decode(GraphCollection<GraphDriveItem>.self, from: Data(json.utf8)).value
    }

    private func classify(_ items: [GraphDriveItem],
                          algorithm: CryptoAlgorithm,
                          parentGraphID: String = "PARENT")
        -> (rows: [CachedItem], encryptedParents: [String]) {
        GraphDriveClient.classifyChildrenPage(
            items,
            parentGraphID: parentGraphID,
            translator: algorithm == .bc01 ? bc01Translator : plainTranslator,
            specialItem: algorithm == .bc01 ? bc01 : plain)
    }

    // MARK: `/children` seeder

    func testChildrenPageDropsFolderKeyAndMarksParent() throws {
        let items = try page("""
        {"value":[
          {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
           "size":512,"parentReference":{"id":"PARENT"}},
          {"id":"doc1","name":"notes.txt","file":{"mimeType":"text/plain"},"size":5,
           "parentReference":{"id":"PARENT"}}
        ]}
        """)
        let result = classify(items, algorithm: .bc01)

        XCTAssertEqual(result.rows.map(\.name), ["notes.txt"])
        XCTAssertEqual(result.encryptedParents, ["PARENT"])
    }

    /// A row without a `parentReference` falls back to the folder being listed.
    func testFolderKeyWithoutParentReferenceMarksTheListedFolder() throws {
        let items = try page("""
        {"value":[
          {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},"size":512}
        ]}
        """)
        let result = classify(items, algorithm: .bc01, parentGraphID: "LISTED")

        XCTAssertTrue(result.rows.isEmpty)
        XCTAssertEqual(result.encryptedParents, ["LISTED"])
    }

    func testChildrenPageCaseVarianceIsDropped() throws {
        let items = try page("""
        {"value":[
          {"id":"key1","name":"FOLDERKEY.BCH","file":{"mimeType":"application/octet-stream"},
           "size":512,"parentReference":{"id":"PARENT"}}
        ]}
        """)
        let result = classify(items, algorithm: .bc01)

        XCTAssertTrue(result.rows.isEmpty)
        XCTAssertEqual(result.encryptedParents, ["PARENT"])
    }

    func testChildrenPageUnderPlainKeepsFolderKeyAndMarksNothing() throws {
        let items = try page("""
        {"value":[
          {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
           "size":512,"parentReference":{"id":"PARENT"}}
        ]}
        """)
        let result = classify(items, algorithm: .plain)

        XCTAssertEqual(result.rows.map(\.name), ["FolderKey.bch"])
        XCTAssertTrue(result.encryptedParents.isEmpty)
    }

    func testChildrenPageFolderNamedFolderKeyIsKept() throws {
        let items = try page("""
        {"value":[
          {"id":"dir1","name":"FolderKey.bch","folder":{"childCount":0},
           "parentReference":{"id":"PARENT"}}
        ]}
        """)
        let result = classify(items, algorithm: .bc01)

        XCTAssertEqual(result.rows.map(\.name), ["FolderKey.bch"])
        XCTAssertTrue(result.rows[0].isFolder)
        XCTAssertTrue(result.encryptedParents.isEmpty)
    }

    /// Dropping the sidecar must not disturb the surrounding rows — in particular the
    /// exact-plaintext-size rule the two seeders also share.
    func testDroppingFolderKeyLeavesSiblingRowsIntact() throws {
        let items = try page("""
        {"value":[
          {"id":"key1","name":"FolderKey.bch","file":{"mimeType":"application/octet-stream"},
           "size":512,"parentReference":{"id":"PARENT"}},
          {"id":"doc1","name":"notes.txt","file":{"mimeType":"text/plain"},"size":5,
           "parentReference":{"id":"PARENT"}},
          {"id":"enc1","name":"secret.txt.bc","file":{"mimeType":"application/octet-stream"},
           "size":600,"parentReference":{"id":"PARENT"}}
        ]}
        """)
        let result = classify(items, algorithm: .bc01)

        XCTAssertEqual(result.rows.map(\.name), ["notes.txt", "secret.txt.bc"])
        // Plain name → size exactly known; encrypted name → unresolved until a header probe.
        XCTAssertEqual(result.rows[0].plaintextSize, 5)
        XCTAssertNil(result.rows[1].plaintextSize)
    }

    // MARK: Seeder agreement

    /// The `/children` and delta seeders classify the same payload identically. Asserted on
    /// the *rule* both share, across the matrix that separates hiding from evidence.
    func testChildrenSeederAgreesWithDeltaSeederOnWhatIsHidden() {
        for algorithm in [CryptoAlgorithm.bc01, .plain] {
            let recogniser = BC01SpecialItem(algorithm: algorithm)
            for name in ["FolderKey.bch", "folderkey.bch", "FolderKey.bch.bc", "notes.txt"] {
                for isFolder in [true, false] {
                    // Both seeders gate the cache row on `isSpecial` and the mark on
                    // `isFolderKeyEvidence`; neither may diverge from the other.
                    let hidden = recogniser.isSpecial(name: name, isFolder: isFolder)
                    let marks = recogniser.isFolderKeyEvidence(name: name, isFolder: isFolder)
                    XCTAssertEqual(hidden, marks, "\(algorithm) \(name) isFolder=\(isFolder)")
                }
            }
        }
    }

    // MARK: Emulator

    private func entry(_ name: String, type: DomainService.EntryType) -> DomainService.Entry {
        DomainService.Entry(name: name, id: .init(name), parent: .init("PARENT"),
                            revision: .zero, deleted: false, size: 0, children: nil,
                            type: type, metadata: .empty,
                            userInfo: .init(conflictCount: nil, originatorName: nil,
                                            symlinkTargetPath: nil, implicitLockOwner: nil,
                                            quotaRemaining: nil, quotaTotal: nil))
    }

    func testEmulatorStripsFolderKeyUnderBC01() {
        let entries = [entry("FolderKey.bch", type: .file),
                       entry("notes.txt", type: .file)]

        XCTAssertEqual(ServerEmulatorClient.visibleEntries(entries, specialItem: bc01).map(\.name),
                       ["notes.txt"])
    }

    func testEmulatorKeepsFolderKeyUnderPlain() {
        let entries = [entry("FolderKey.bch", type: .file),
                       entry("notes.txt", type: .file)]

        XCTAssertEqual(ServerEmulatorClient.visibleEntries(entries, specialItem: plain).map(\.name),
                       ["FolderKey.bch", "notes.txt"])
    }

    func testEmulatorKeepsFolderNamedFolderKey() {
        let entries = [entry("FolderKey.bch", type: .folder)]

        XCTAssertEqual(ServerEmulatorClient.visibleEntries(entries, specialItem: bc01).map(\.name),
                       ["FolderKey.bch"])
    }

    func testEmulatorStripsCaseVariants() {
        let entries = [entry("folderkey.BCH", type: .file), entry("keep.txt", type: .file)]

        XCTAssertEqual(ServerEmulatorClient.visibleEntries(entries, specialItem: bc01).map(\.name),
                       ["keep.txt"])
    }
}
