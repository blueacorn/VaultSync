/// Regression tests for rename preserving backend encryption state.
//
//  RenameBackendFilenameTests.swift
//  ExtensionTests
//
//  Regression coverage for: restoring (Finder "Put Back") a plaintext file that the
//  Encrypt Files action trashed renamed its backend file to a `.bc` name, so the Provider
//  then tried to decrypt plaintext as BC01 and materialisation failed.
//
//  The rename rule must preserve the item's CURRENT backend encryption state (the `.bc`
//  suffix on the backend name), not blindly apply the domain default. `encodeForBackend`
//  alone always appends `.bc` in a BC01 domain — that is the bug this rule guards.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class RenameBackendFilenameTests: XCTestCase {

    /// Plaintext passthrough item in a BC01 domain: backend name has no `.bc`, so a rename
    /// must keep the plaintext backend name (no `.bc` appended).
    func testPlaintextItemKeepsPlaintextBackendNameOnRename() {
        let result = Extension.backendFilename(forNewDisplayName: "notes.txt",
                                               currentBackendName: "notes.txt",
                                               algorithm: .bc01)
        XCTAssertEqual(result, "notes.txt", "plaintext item must not gain a .bc suffix on rename/restore")
    }

    /// Encrypted item in a BC01 domain: backend name ends in `.bc`, so the rename re-encodes
    /// the new display name to a `.bc` backend name.
    func testEncryptedItemGetsBcSuffixOnRename() {
        let result = Extension.backendFilename(forNewDisplayName: "secret.txt",
                                               currentBackendName: "secret.txt.bc",
                                               algorithm: .bc01)
        XCTAssertEqual(result, "secret.txt.bc", "encrypted item must keep its .bc backend name on rename")
    }

    /// Non-BC01 (plaintext) domain: identity regardless of current name.
    func testPlaintextDomainIsIdentity() {
        XCTAssertEqual(Extension.backendFilename(forNewDisplayName: "a.txt",
                                                 currentBackendName: "a.txt",
                                                 algorithm: .plain),
                       "a.txt")
    }
}
