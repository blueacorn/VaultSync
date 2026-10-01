/// Tests for the bulk encrypt/decrypt Finder progress reporter.
//
//  EncryptionProgressReporterTests.swift
//  ExtensionTests
//
//  Coverage for the bulk encrypt/decrypt Finder progress reporter: the
//  production reporter drives the action `Progress` with an accurate per-file total and
//  advances once per file, and `finish` always completes the indicator (success or error).
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Foundation
@testable import Extension

final class EncryptionProgressReporterTests: XCTestCase {

    /// `start` sets the real file count as the total and resets completion.
    func testStartSetsTotalAndResets() {
        let progress = Progress()
        let reporter = EncryptionProgressReporter(actionProgress: progress)

        reporter.start(totalFiles: 12, description: "Encrypting 12 files…")

        XCTAssertEqual(progress.totalUnitCount, 12)
        XCTAssertEqual(progress.completedUnitCount, 0)
        XCTAssertEqual(progress.localizedDescription, "Encrypting 12 files…")
    }

    /// `advance` per file reaches the total; `finish` pins completion to the total.
    func testAdvanceReachesTotalAndFinishCompletes() {
        let progress = Progress()
        let reporter = EncryptionProgressReporter(actionProgress: progress)
        reporter.start(totalFiles: 3, description: "…")

        reporter.advance()
        reporter.advance()
        reporter.advance()
        XCTAssertEqual(progress.completedUnitCount, 3)

        reporter.finish()
        XCTAssertEqual(progress.completedUnitCount, progress.totalUnitCount)
    }

    /// `finish` on an incomplete run (an error mid-way) still completes so Finder does not
    /// leave a stalled indicator.
    func testFinishCompletesEvenWhenNotAllAdvanced() {
        let progress = Progress()
        let reporter = EncryptionProgressReporter(actionProgress: progress)
        reporter.start(totalFiles: 5, description: "…")
        reporter.advance() // only one of five processed before a throw

        reporter.finish()

        XCTAssertEqual(progress.completedUnitCount, 5)
    }

    /// A negative/zero count is clamped to a non-negative total.
    func testEmptySelectionTotalsZero() {
        let progress = Progress()
        let reporter = EncryptionProgressReporter(actionProgress: progress)

        reporter.start(totalFiles: 0, description: "…")

        XCTAssertEqual(progress.totalUnitCount, 0)
    }
}
