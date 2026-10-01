/// Base XCTestCase isolating shared configuration per test.
//
//  ConfigIsolatedTestCase.swift
//  CommonTests
//
//  Base class for suites that write the App Group `config.json`.
//
//  `SharedConfigStore.shared` is one-per-install and shared with the running app and its
//  extension, so a suite mutating it edits the developer's live configuration. That is worse
//  than stray residue: `SharedConfig.vaultGating` is authoritative for
//  `VaultKeyStore.reconcile()`, which deletes every gating key except the one the file names —
//  so a test-written gating value costs the user their vault on the next launch.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

/// Points SharedConfigStore/shared at a document private to this suite.
///
/// Installation replaces the singleton outright, so it holds regardless of what resolved
/// `shared` first — a host app that builds its config store at launch, or an earlier suite.
class ConfigIsolatedTestCase: XCTestCase {

    private static var previousStore: SharedConfigStore?
    private static var isolatedStore: SharedConfigStore?

    override class func setUp() {
        super.setUp()
        previousStore = SharedConfigStore.shared
        let isolated = SharedConfigStore(namespace: "test.\(UUID().uuidString)")
        isolatedStore = isolated
        SharedConfigStore.shared = isolated
    }

    override class func tearDown() {
        if let isolated = isolatedStore {
            // Writes are queued asynchronously; deleting before they land would let a late
            // write recreate the document after teardown.
            isolated.drainPendingWrites()
            try? FileManager.default.removeItem(at: isolated.configFileURL)
        }
        if let previousStore { SharedConfigStore.shared = previousStore }
        isolatedStore = nil
        previousStore = nil
        super.tearDown()
    }
}
