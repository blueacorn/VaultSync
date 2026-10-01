/// Unit tests for `CryptoProgressReporter`.
//
//  CryptoProgressReporterTests.swift
//  ExtensionTests
//
//  Coverage for the crypto-progress observer seam: begin registers a CryptoOp,
//  update sets its fraction (throttle bypassed at completion), finish removes it.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class CryptoProgressReporterTests: XCTestCase {

    private var domainID: String!
    private var store: ProgressStore!
    private var reporter: ProgressStoreCryptoReporter!

    override func setUpWithError() throws {
        domainID = "crypto-progress-test-\(UUID().uuidString)"
        store = ProgressStore()
        // No throttle so updates land synchronously for assertions.
        reporter = ProgressStoreCryptoReporter(domainID: domainID, store: store, throttle: 0)
    }

    override func tearDownWithError() throws {
        // `ProgressStore` writes a real JSON document per domain into the App Group container;
        // without this every test left one behind beside the user's own domains' snapshots.
        if let domainID { store.remove(for: domainID) }
        domainID = nil
    }

    func testBeginRegistersIndeterminateOp() {
        reporter.begin(itemID: "42", name: "secret.txt", direction: .decrypt)
        let ops = store.snapshot(for: domainID).cryptoOps
        XCTAssertEqual(ops.count, 1)
        XCTAssertEqual(ops.first?.name, "secret.txt")
        XCTAssertEqual(ops.first?.direction, .decrypt)
        XCTAssertNil(ops.first?.fractionCompleted)
    }

    func testUpdateSetsFraction() {
        reporter.begin(itemID: "42", name: "secret.txt", direction: .decrypt)
        reporter.update(itemID: "42", fraction: 0.6)
        XCTAssertEqual(store.snapshot(for: domainID).cryptoOps.first?.fractionCompleted, 0.6)
    }

    func testFinishRemovesOp() {
        reporter.begin(itemID: "42", name: "secret.txt", direction: .decrypt)
        reporter.finish(itemID: "42")
        XCTAssertTrue(store.snapshot(for: domainID).cryptoOps.isEmpty)
    }

    func testUpdateClampsFraction() {
        reporter.begin(itemID: "42", name: "s.txt", direction: .encrypt)
        reporter.update(itemID: "42", fraction: 1.5)
        XCTAssertEqual(store.snapshot(for: domainID).cryptoOps.first?.fractionCompleted, 1)
    }
}
