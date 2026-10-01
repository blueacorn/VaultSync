/// Unit tests for `PlaintextSizeVersion`.
//
//  PlaintextSizeVersionTests.swift
//  ExtensionTests
//
//  Pins the rule that a resolved plaintext size is visible in the item's *content* version.
//
//  `documentSize` is not keyed on rank: the framework re-reads an item's fields only when its
//  `NSFileProviderItemVersion` changes. `cTag`/`eTag` describe the ciphertext and do not move
//  when `plaintext_size` is resolved locally — so a resolved size was re-emitted under an
//  unchanged version and the daemon kept its stale, ciphertext-derived size indefinitely.
//
//  The version is therefore stamped from the size actually published, unconditionally, so that
//  equal versions imply equal sizes by construction. These tests fail if that regresses.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class PlaintextSizeVersionTests: XCTestCase {

    private static let root = "ROOT"
    /// Ciphertext length of the fixture item; the estimate published when unresolved.
    static let ciphertextSize: Int64 = 384272

    private func item(cTag: String = "c:{ABC},2",
                      eTag: String = "{ABC},2",
                      size: Int64 = ciphertextSize) -> GraphDriveItem {
        GraphDriveItem(
            id: "34664DB4FE9E7CF0!258222", name: "photo.jpg.bc", eTag: eTag, cTag: cTag,
            size: size, createdDateTime: nil, lastModifiedDateTime: nil,
            parentReference: GraphDriveItem.ParentReference(
                driveId: nil, id: "34664DB4FE9E7CF0!258216", path: nil),
            file: GraphDriveItem.FileFacet(mimeType: nil), folder: nil, deleted: nil)
    }

    private func contentVersion(plaintextSize: Int64?,
                                cTag: String = "c:{ABC},2") -> String {
        GraphMapping.entry(from: item(cTag: cTag), rootGraphID: Self.root, translator: IdentityMetadataTranslator(),
                           plaintextSize: plaintextSize).revision.content
    }

    /// The regression itself: unresolved and resolved must not share a content version, or the
    /// framework never re-reads `documentSize` and Finder keeps the ciphertext size.
    func testResolvingSizeChangesContentVersion() {
        XCTAssertNotEqual(contentVersion(plaintextSize: nil),
                          contentVersion(plaintextSize: 380172),
                          "resolution must be a content-version change or Finder keeps the stale size")
    }

    /// The reverse direction: a re-upsert that clears the size must also change the version, so
    /// the published size and the displayed size never diverge.
    func testClearingSizeChangesContentVersion() {
        XCTAssertNotEqual(contentVersion(plaintextSize: 380172),
                          contentVersion(plaintextSize: nil))
    }

    /// Distinct sizes must be distinct versions — otherwise a corrected size never propagates.
    func testDifferentSizesDifferentVersions() {
        XCTAssertNotEqual(contentVersion(plaintextSize: 380172),
                          contentVersion(plaintextSize: 380173))
    }

    /// A new cTag must still change the version even at an identical plaintext size, so a
    /// remote content change is never masked.
    func testNewCTagStillChangesVersionAtSameSize() {
        XCTAssertNotEqual(contentVersion(plaintextSize: 380172, cTag: "c:{ABC},2"),
                          contentVersion(plaintextSize: 380172, cTag: "c:{ABC},3"))
    }

    /// Unresolved is stamped with the *estimate*, not left bare: the version is a function of
    /// the size actually published, whatever its provenance.
    func testUnresolvedIsStampedWithEstimate() {
        XCTAssertEqual(contentVersion(plaintextSize: nil), "c:{ABC},2|p\(Self.ciphertextSize)")
    }

    /// The invariant the whole design rests on: the content version is a function of the
    /// published `size`. Equal versions must imply equal sizes — otherwise the framework, which
    /// re-reads fields only when the version moves, keeps a stale `documentSize` forever. Checked
    /// across the states an item passes through: unresolved (estimate), resolved, and corrected.
    func testContentVersionDeterminesPublishedSize() {
        let states: [Int64?] = [nil, 380172, 380173, 0, Self.ciphertextSize]
        var sizeForVersion: [String: Int64] = [:]
        for state in states {
            let entry = GraphMapping.entry(from: item(), rootGraphID: Self.root, translator: IdentityMetadataTranslator(), plaintextSize: state)
            if let seen = sizeForVersion[entry.revision.content] {
                XCTAssertEqual(seen, entry.size,
                               "two different sizes published under one content version")
            }
            sizeForVersion[entry.revision.content] = entry.size
        }
        XCTAssertEqual(sizeForVersion.count, 4,
                       "an unresolved item and one resolved to the ciphertext length publish "
                       + "the same size, so they legitimately share a version")
    }

    /// Only the content version carries the size, and no other field moves. `documentSize`
    /// describes content; bumping the metadata version would invite re-requests of metadata we
    /// did not change.
    func testMetadataVersionAndFieldsUntouched() {
        let bare = GraphMapping.entry(from: item(), rootGraphID: Self.root, translator: IdentityMetadataTranslator())
        let sized = GraphMapping.entry(from: item(), rootGraphID: Self.root, translator: IdentityMetadataTranslator(), plaintextSize: 380172)
        XCTAssertEqual(sized.revision.metadata, bare.revision.metadata)
        XCTAssertEqual(sized.name, bare.name)
        XCTAssertEqual(sized.id, bare.id)
        XCTAssertEqual(sized.parent, bare.parent)
    }

    /// `size` and the content version must be derived from the SAME value.
    ///
    /// This previously asserted the opposite — that `size` stayed at the ciphertext length and
    /// `displayEntry` would substitute the real one later. It cannot: `displaySize` returns nil
    /// for a `.bc` file (plaintext length is not derivable from ciphertext length), so the
    /// estimate survived and the item was published with a resolved version (`…|p380172`) next
    /// to an unresolved size. The framework only re-reads fields when the version moves, so that
    /// record overwrote the exact size a prior hydration had delivered — Finder's size snapped
    /// back to the ciphertext length on the next enumeration.
    func testResolvedSizeIsPublishedAsDocumentSize() {
        let bare = GraphMapping.entry(from: item(), rootGraphID: Self.root, translator: IdentityMetadataTranslator())
        let sized = GraphMapping.entry(from: item(), rootGraphID: Self.root, translator: IdentityMetadataTranslator(), plaintextSize: 380172)
        XCTAssertEqual(sized.size, 380172, "a resolved plaintext length is authoritative for size")
        XCTAssertEqual(bare.size, Self.ciphertextSize,
                       "unresolved still reports the ciphertext estimate")
    }

    /// Omitting the parameter must behave exactly as an unresolved row, so the many call sites
    /// that map Graph responses without cache context keep publishing the estimate.
    func testDefaultParameterMatchesUnresolved() {
        XCTAssertEqual(GraphMapping.entry(from: item(), rootGraphID: Self.root, translator: IdentityMetadataTranslator()).revision.content,
                       contentVersion(plaintextSize: nil))
    }

    // MARK: Estimate (BC01 framing)

    /// Unresolved: the estimate is derived from the ciphertext length, published and stamped.
    /// Resolved: the exact size is published, and display translation must not estimate from it
    /// again (that subtracted the header twice and truncated the last partial-fetch window).
    func testEstimateAppliesOnlyToCiphertext() {
        let bc01 = BoxcryptorMetadataTranslator(algorithm: .bc01)
        let cipher: Int64 = 18_556_736, exact: Int64 = 18_425_648   // _MG_3810.jpg

        let unresolved = GraphMapping.entry(from: item(size: cipher), rootGraphID: Self.root, translator: bc01)
        XCTAssertEqual(unresolved.size, exact + 15, "largest plaintext consistent with the ciphertext")
        XCTAssertEqual(bc01.displayEntry(unresolved).size, unresolved.size)

        let resolved = GraphMapping.entry(from: item(size: cipher), rootGraphID: Self.root, translator: bc01,
                                          plaintextSize: exact)
        XCTAssertEqual(resolved.size, exact)
        XCTAssertEqual(bc01.displayEntry(resolved).size, exact, "must not re-estimate a plaintext size")
    }
}
