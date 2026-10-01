/// Narrow observer seam for reporting encrypt/decrypt progress to the app.
///
/// Extracted so the streaming pipeline (`StreamingDownload` / `ContentStreamDownloader`)
/// stays decoupled from the App Group relay and remains unit-testable with a stub
/// (`[[extract-refactor-for-testability]]`). The concrete
/// ``ProgressStoreCryptoReporter`` translates events into ``CryptoOp`` entries in the
/// per-domain ``ProgressStore`` and posts the coalesced change notification.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// Reports the lifecycle of a single crypto operation. All methods are best-effort and
/// safe to call from background tasks.
protocol CryptoProgressReporter: Sendable {
    /// A crypto op started for `itemID` (`fraction` nil = total not yet known — BC01
    /// plaintext size is indeterminate until the header parses,
    /// `[[plaintext-size-from-decrypt-not-estimate]]`).
    func begin(itemID: String, name: String, direction: CryptoOp.Direction)
    /// Progress update (0…1). Throttled by the reporter.
    func update(itemID: String, fraction: Double)
    /// The op finished (success or error) — remove it from the snapshot.
    func finish(itemID: String)
}

/// No-op reporter for backends/paths that do not relay crypto progress.
struct NoOpCryptoProgressReporter: CryptoProgressReporter {
    func begin(itemID: String, name: String, direction: CryptoOp.Direction) {}
    func update(itemID: String, fraction: Double) {}
    func finish(itemID: String) {}
}

/// Writes crypto-op lifecycle into the per-domain ``ProgressStore``. Progress updates are
/// throttled to ~500 ms of wall-clock per item so byte-level progress does not spam the
/// cross-process notification (mirrors the `.itemsChanged` throttle).
final class ProgressStoreCryptoReporter: CryptoProgressReporter, @unchecked Sendable {
    private let domainID: String
    private let store: ProgressStore
    private let lock = NSLock()
    /// Last publish time per item, for throttling.
    private var lastPublish: [String: Date] = [:]
    private let throttle: TimeInterval

    init(domainID: String, store: ProgressStore = .shared, throttle: TimeInterval = 0.5) {
        self.domainID = domainID
        self.store = store
        self.throttle = throttle
    }

    func begin(itemID: String, name: String, direction: CryptoOp.Direction) {
        store.update(domainID: domainID) { snapshot in
            snapshot.cryptoOps.removeAll { $0.id == itemID }
            snapshot.cryptoOps.append(CryptoOp(id: itemID, name: name,
                                               direction: direction, fractionCompleted: nil))
        }
    }

    func update(itemID: String, fraction: Double) {
        lock.lock()
        let now = Date()
        if let last = lastPublish[itemID], now.timeIntervalSince(last) < throttle, fraction < 1 {
            lock.unlock(); return
        }
        lastPublish[itemID] = now
        lock.unlock()

        store.update(domainID: domainID) { snapshot in
            if let idx = snapshot.cryptoOps.firstIndex(where: { $0.id == itemID }) {
                snapshot.cryptoOps[idx].fractionCompleted = min(max(fraction, 0), 1)
            }
        }
    }

    func finish(itemID: String) {
        lock.lock(); lastPublish[itemID] = nil; lock.unlock()
        store.update(domainID: domainID) { snapshot in
            snapshot.cryptoOps.removeAll { $0.id == itemID }
        }
    }
}
