/// Unit tests for `BoxcryptorMetadataTranslatorSize`.
//
//  BoxcryptorMetadataTranslatorSizeTests.swift
//  CommonTests
//
//  Covers the display-size contract: a name-based translator cannot know an encrypted item's
//  plaintext length, so it reports `nil` rather than guessing. An over-reported `documentSize`
//  makes `NSFileProviderPartialContentFetching` unusable — the system requests tail bytes past
//  the real EOF that never arrive — which is why "unknown" must be representable at all.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

final class BoxcryptorMetadataTranslatorSizeTests: XCTestCase {

    private let bc01 = BoxcryptorMetadataTranslator(algorithm: .bc01)
    private let plain = BoxcryptorMetadataTranslator(algorithm: .plain)

    /// One BC01 header block. A ciphertext at or below this is all header.
    private let headerBlock: Int64 = 4096

    // MARK: displaySize

    /// The core change: an encrypted body's plaintext length is not derivable from the
    /// ciphertext length (header + PKCS7 padding are both invisible here), so it is `nil`.
    func testEncryptedBodySizeIsUnknown() {
        XCTAssertNil(bc01.displaySize(forBackendSize: headerBlock + 1, name: "f.bc"))
        XCTAssertNil(bc01.displaySize(forBackendSize: 8192, name: "f.bc"))
        XCTAssertNil(bc01.displaySize(forBackendSize: 1_000_000, name: "f.bc"))
    }

    /// A ciphertext no larger than one header block carries no plaintext. Knowable, so not `nil`.
    func testHeaderOnlyFileIsKnownZero() {
        XCTAssertEqual(bc01.displaySize(forBackendSize: 0, name: "f.bc"), 0)
        XCTAssertEqual(bc01.displaySize(forBackendSize: headerBlock, name: "f.bc"), 0)
    }

    /// With BC01 inactive there is no encryption, so ciphertext size *is* plaintext size exactly.
    func testInactiveTranslatorAlwaysKnowsSize() {
        XCTAssertEqual(plain.displaySize(forBackendSize: 8192, name: "f.bc"), 8192)
        XCTAssertEqual(plain.displaySize(forBackendSize: 0, name: "f.bc"), 0)
    }

    /// A non-`.bc` name is not content-encrypted even while BC01 is active, so its backend
    /// size is its plaintext size exactly.
    func testPlaintextNameUnderActiveBC01KnowsSize() {
        XCTAssertEqual(bc01.displaySize(forBackendSize: 8192, name: "notes.txt"), 8192)
    }

    // MARK: displayEntry / isDisplaySizeKnown

    /// `Entry.size` cannot express "unknown", so an unknown size passes the entry's size through
    /// unchanged — it may already be a resolved plaintext size, so it is never re-estimated here
    /// (the backend applies the estimate where the size is known to be ciphertext). The caller
    /// needs `isDisplaySizeKnown` to know to substitute the exact `plaintext_size`.
    func testUnknownSizePassesThroughAndIsFlagged() {
        let entry = makeEntry(name: "report.pdf.bc", size: 8192)
        let display = bc01.displayEntry(entry)

        XCTAssertEqual(display.name, "report.pdf", "the name is still decoded")
        XCTAssertEqual(display.size, 8192, "never re-estimated at this layer")
        XCTAssertFalse(bc01.isDisplaySizeKnown(entry),
                       "must be flagged, or the caller cannot know to substitute plaintext_size")
    }

    /// A header-only encrypted file resolves to 0 here, with no substitution owed.
    func testHeaderOnlyEntryIsKnown() {
        let entry = makeEntry(name: "empty.txt.bc", size: headerBlock)
        XCTAssertEqual(bc01.displayEntry(entry).size, 0)
        XCTAssertTrue(bc01.isDisplaySizeKnown(entry))
    }

    /// A non-`.bc` file is not encrypted, so its size is exact and never withheld or substituted.
    func testPlainFileSizeIsKnownAndUnchanged() {
        let entry = makeEntry(name: "notes.txt", size: 4242)
        XCTAssertEqual(bc01.displayEntry(entry).size, 4242)
        XCTAssertTrue(bc01.isDisplaySizeKnown(entry))
    }

    /// The identity translator never withholds a size — there is no encryption to hide it.
    func testIdentityTranslatorAlwaysKnowsSize() {
        let identity = IdentityMetadataTranslator()
        XCTAssertEqual(identity.displaySize(forBackendSize: 8192, name: "f.bc"), 8192)
        XCTAssertTrue(identity.isDisplaySizeKnown(makeEntry(name: "a.bc", size: 8192)))
    }

    // MARK: Helpers

    private func makeEntry(name: String, size: Int64) -> DomainService.Entry {
        DomainService.Entry(
            name: name,
            id: DomainService.ItemIdentifier("id-\(name)"),
            parent: DomainService.ItemIdentifier("parent"),
            revision: DomainService.Version(content: "c1", metadata: "e1"),
            deleted: false, size: size, children: nil, type: .file,
            metadata: DomainService.EntryMetadata(
                fileSystemFlags: nil, lastUsedDate: nil, tagData: nil, favoriteRank: nil,
                creationDate: nil, contentModificationDate: nil, extendedAttributes: nil,
                typeAndCreator: nil, validEntries: nil),
            userInfo: DomainService.Entry.UserInfo(
                conflictCount: nil, originatorName: nil, symlinkTargetPath: nil,
                implicitLockOwner: nil, quotaRemaining: nil, quotaTotal: nil))
    }
}
