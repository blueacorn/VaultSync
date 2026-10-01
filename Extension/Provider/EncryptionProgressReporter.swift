/// Drives a Finder-visible progress indicator for a bulk encrypt/decrypt action.
///
/// Wraps the `Progress` the action returns to the File Provider framework from
/// `performAction(identifier:onItemsWithIdentifiers:completionHandler:)`. Finder surfaces that
/// `Progress` as the operation's status/pie indicator, so accurate `totalUnitCount` and
/// per-file `completedUnitCount` updates are what make the bar meaningful. The action collects
/// its target files first, calls ``start`` with the real file count, then ``advance`` once per
/// processed file; ``finish`` completes the indicator so Finder removes it.
///
/// (`NSFileProviderManager` exposes no public domain-wide progress reporter, so the returned
/// action `Progress` is the supported surface for this.)
///
/// The seam is a plain protocol so the action can be unit-tested with an in-memory recorder
/// (see `EncryptionProgressReporterTests`) without a live `Progress` observer.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider

/// Progress sink for a bulk encryption action.
protocol EncryptionProgressReporting: AnyObject {
    /// Begin reporting for `totalFiles` files with a localized `description`.
    func start(totalFiles: Int, description: String)
    /// Mark one more file processed.
    func advance()
    /// Complete the indicator (drives `completed == total`).
    func finish()
}

/// Production reporter backed by the action's `Progress`.
final class EncryptionProgressReporter: EncryptionProgressReporting {

    /// The `Progress` returned to the framework from `performAction`.
    private let actionProgress: Progress

    /// - Parameter actionProgress: the `Progress` handed back to `performAction`.
    init(actionProgress: Progress) {
        self.actionProgress = actionProgress
    }

    func start(totalFiles: Int, description: String) {
        actionProgress.totalUnitCount = Int64(max(totalFiles, 0))
        actionProgress.completedUnitCount = 0
        actionProgress.localizedDescription = description
    }

    func advance() {
        actionProgress.completedUnitCount += 1
    }

    func finish() {
        actionProgress.completedUnitCount = actionProgress.totalUnitCount
    }
}
