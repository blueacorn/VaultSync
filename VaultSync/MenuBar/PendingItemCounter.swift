/// Counts a domain's pending (unsynced) items.
///
/// "Lock and Remove Vault" discards local data, which is only *destructive* when some of that
/// data has not reached the server yet. Materialized-but-clean files re-download on unlock; items
/// in the pending set do not. Counting the pending set is therefore what decides whether the user
/// is asked to confirm.
///
/// Wraps the callback-based `NSFileProviderEnumerationObserver` in an `async` count. Unlike
/// ``FileListModel`` this enumerates to completion (no display limit) and keeps no rows.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import FileProvider
import Foundation

enum PendingItemCounter {

    /// Total items the enumerator yields, or `nil` if enumeration failed.
    ///
    /// A `nil` result means "unknown", not "none" — callers fail safe and confirm anyway.
    static func count(using enumerator: NSFileProviderEnumerator) async -> Int? {
        await withCheckedContinuation { continuation in
            let observer = CountingObserver(enumerator: enumerator) { result in
                continuation.resume(returning: result)
            }
            observer.start()
        }
    }
}

/// Accumulates counts across enumeration pages, resuming its completion exactly once.
private final class CountingObserver: NSObject, NSFileProviderEnumerationObserver {
    private let enumerator: NSFileProviderEnumerator
    private let completion: (Int?) -> Void
    private let lock = NSLock()
    private var total = 0
    private var finished = false
    /// Retains the observer for the duration of enumeration; the enumerator does not.
    private var selfRetain: CountingObserver?

    init(enumerator: NSFileProviderEnumerator, completion: @escaping (Int?) -> Void) {
        self.enumerator = enumerator
        self.completion = completion
        super.init()
        selfRetain = self
    }

    func start() {
        enumerator.enumerateItems(for: self, startingAt: NSFileProviderPage.initialPageSortedByDate as NSFileProviderPage)
    }

    /// Deliver the result once and drop the self-retain.
    private func finish(_ result: Int?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        lock.unlock()
        completion(result)
        selfRetain = nil
    }

    func didEnumerate(_ updatedItems: [NSFileProviderItemProtocol]) {
        lock.lock()
        total += updatedItems.count
        lock.unlock()
    }

    func finishEnumerating(upTo nextPage: NSFileProviderPage?) {
        guard let nextPage else {
            lock.lock(); let result = total; lock.unlock()
            finish(result)
            return
        }
        enumerator.enumerateItems(for: self, startingAt: nextPage)
    }

    func finishEnumeratingWithError(_ error: Error) {
        finish(nil)
    }
}
