/// Production ``LockScheduler`` for the app process.
///
/// A `DispatchSourceTimer` drives the idle countdown. App-side because the idle policy is:
/// `Provider.appex` runs no countdown of its own and evicts slots directly instead. Its sibling
/// seam, ``SystemLockEvents``, is implemented next door by `WorkspaceLockEvents`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Common
import Foundation

/// GCD-backed one-shot idle timer.
final class SystemLockScheduler: LockScheduler {
    private let queue = DispatchQueue(label: "org.vaultsync.VaultSync.vault-lock.timer")
    private var timer: DispatchSourceTimer?

    func schedule(after seconds: TimeInterval, _ fire: @escaping () -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.timer?.cancel()
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + seconds)
            t.setEventHandler { fire() }
            self.timer = t
            t.resume()
        }
    }

    func cancel() {
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
        }
    }
}
