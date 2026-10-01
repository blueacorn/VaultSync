/// Unit tests for `BC01SpecialItem`.
//
//  BC01SpecialItemTests.swift
//  CommonTests
//
//  The BC01 special-item recogniser is pure — a name plus a type flag in, a Bool out — so it
//  is exercised here with no fixtures and no store. Both methods are covered separately: they
//  coincide today (`isSpecial` forwards to `isFolderKeyEvidence`) but are separately callable,
//  and the subset invariant below is what must survive the first sidecar that breaks them apart.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

final class BC01SpecialItemTests: XCTestCase {

    private let bc01 = BC01SpecialItem(algorithm: .bc01)
    private let plain = BC01SpecialItem(algorithm: .plain)

    // MARK: Recognition

    func testFolderKeyFileIsSpecialAndEvidenceUnderBC01() {
        XCTAssertTrue(bc01.isSpecial(name: "FolderKey.bch", isFolder: false))
        XCTAssertTrue(bc01.isFolderKeyEvidence(name: "FolderKey.bch", isFolder: false))
    }

    func testComparisonIsCaseInsensitive() {
        for name in ["folderkey.bch", "FOLDERKEY.BCH", "FolderKey.BCH", "fOlDeRkEy.bCh"] {
            XCTAssertTrue(bc01.isSpecial(name: name, isFolder: false), name)
            XCTAssertTrue(bc01.isFolderKeyEvidence(name: name, isFolder: false), name)
        }
    }

    /// A *folder* so named is not bookkeeping — only a file is. Callers pass the backend's own
    /// type flag rather than guessing from the name.
    func testFolderNamedFolderKeyIsOrdinary() {
        XCTAssertFalse(bc01.isSpecial(name: "FolderKey.bch", isFolder: true))
        XCTAssertFalse(bc01.isFolderKeyEvidence(name: "FolderKey.bch", isFolder: true))
    }

    /// Under `.plain` the name is an ordinary user file and must pass through untouched.
    func testPlainAlgorithmRecognisesNothing() {
        for isFolder in [true, false] {
            for name in ["FolderKey.bch", "folderkey.bch", "FOLDERKEY.BCH"] {
                XCTAssertFalse(plain.isSpecial(name: name, isFolder: isFolder), name)
                XCTAssertFalse(plain.isFolderKeyEvidence(name: name, isFolder: isFolder), name)
            }
        }
    }

    /// Callers pass a *leaf* name, so an exact whole-name match is required — no prefix,
    /// suffix, or path-component matching.
    func testNearMissesAreOrdinary() {
        for name in ["FolderKey.bch.bc", "MyFolderKey.bch", "FolderKey.bc", "FolderKey",
                     "sub/FolderKey.bch", "FolderKey.bch ", ".bch", ""] {
            XCTAssertFalse(bc01.isSpecial(name: name, isFolder: false), name)
            XCTAssertFalse(bc01.isFolderKeyEvidence(name: name, isFolder: false), name)
        }
    }

    // MARK: Invariant

    /// Evidence is a strict subset of special: every folder key is hidden, but a future
    /// sidecar could be hidden while proving nothing about encryption. Asserted across the
    /// whole input matrix so the implication cannot silently invert.
    func testEvidenceImpliesSpecial() {
        let names = ["FolderKey.bch", "folderkey.bch", "FOLDERKEY.BCH", "FolderKey.bch.bc",
                     "MyFolderKey.bch", "FolderKey.bc", "notes.txt", ""]
        for recogniser in [bc01, plain] {
            for name in names {
                for isFolder in [true, false] {
                    if recogniser.isFolderKeyEvidence(name: name, isFolder: isFolder) {
                        XCTAssertTrue(recogniser.isSpecial(name: name, isFolder: isFolder), name)
                    }
                }
            }
        }
    }
}
