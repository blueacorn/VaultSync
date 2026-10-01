/// Signal throttle that coalesces bursts of enumerator signals.
//
//  Coalesces a burst of "signal now" requests into at most one delivered signal per interval,
//  with leading + trailing edges. Used to tame the per-file `.workingSet` enumeration storm a
//  bulk encrypt/decrypt action would otherwise cause: each `signalEnumerator` drives a
//  full recursive `enumerateChanges($root)` sweep, so N files must not mean N sweeps.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation

/// Thread-safe leading+trailing throttle. `request(_:)` fires `action` immediately if at least
/// `minInterval` has elapsed since the last fire; otherwise it schedules a single trailing fire
/// at the interval boundary, collapsing any further requests in the window into that one fire.
///
/// - The leading edge keeps the first trash appearing in Trash promptly.
/// - The trailing edge guarantees the final trash in a burst is delivered.
final class SignalThrottle {

    private let minInterval: TimeInterval
    private let now: () -> Date
    private let schedule: (TimeInterval, @escaping () -> Void) -> Void
    private let lock = NSLock()

    private var lastFire: Date?
    private var trailingScheduled = false

    /// - Parameters:
    ///   - minInterval: Minimum seconds between delivered signals.
    ///   - now: Clock source (injectable for tests).
    ///   - schedule: Delayed-dispatch source (injectable for tests). Defaults to the main queue.
    init(minInterval: TimeInterval,
         now: @escaping () -> Date = Date.init,
         schedule: @escaping (TimeInterval, @escaping () -> Void) -> Void = { delay, work in
             DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
         }) {
        self.minInterval = minInterval
        self.now = now
        self.schedule = schedule
    }

    /// Request that `action` be delivered, subject to the throttle. `action` may run synchronously
    /// (leading edge) or later on the `schedule` queue (trailing edge). It is never dropped.
    func request(_ action: @escaping () -> Void) {
        lock.lock()
        let current = now()
        if let last = lastFire, current.timeIntervalSince(last) < minInterval {
            // Inside the window: ensure exactly one trailing fire is queued.
            if trailingScheduled {
                lock.unlock()
                return
            }
            trailingScheduled = true
            let remaining = minInterval - current.timeIntervalSince(last)
            lock.unlock()
            schedule(remaining) { [weak self] in
                guard let self else { return }
                self.lock.lock()
                self.trailingScheduled = false
                self.lastFire = self.now()
                self.lock.unlock()
                action()
            }
            return
        }
        // Leading edge: fire immediately.
        lastFire = current
        lock.unlock()
        action()
    }
}
