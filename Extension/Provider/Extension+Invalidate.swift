/// Teardown: winding down this domain's background work.
//
//  Abstract:
//  Extension teardown — `invalidate()` and the shared background-work stop path.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common

extension Extension {
    /// Cancel and await this domain's long-running background work.
    ///
    /// Shared by ``invalidate()`` (OS-driven teardown) and the cancellation coordinator
    /// (host-driven lock-and-remove) so both paths wind down identically. The poller's loop
    /// honours `Task.isCancelled`, and the transfer paths use `Task.checkCancellation()`, so
    /// stopping the owners is sufficient.
    ///
    /// Unlike ``invalidate()`` this awaits the stops rather than detaching them — the host's
    /// acknowledgement is only meaningful once the work has actually ceased.
    ///
    /// Also terminal for background work: the host stops the Provider because the vault is being
    /// locked, so a straggling request that resolves the backend afterwards must not restart the
    /// poller against a vault whose key material has just been evicted.
    func stopBackgroundWork() async {
        logger.infoPublic("➡️  stopBackgroundWork() domain(\(self.domain.identifier.rawValue))")
        backendLock.lock()
        isInvalidated = true
        let poller = deltaPoller
        deltaPoller = nil
        backendLock.unlock()

        await poller?.stopAndWait()
    }

    public func invalidate() {
        logger.infoPublic("➡️  invalidate() domain(\(self.domain.identifier.rawValue))")
        cancellationCoordinator?.stop()
        cancellationCoordinator = nil
        backendLock.lock()
        // Terminal: a late call must not be mistaken for a first call and restart the poller.
        isInvalidated = true
        let poller = deltaPoller
        deltaPoller = nil
        cachedBackend = nil
        backendLock.unlock()
        if let poller { Task { await poller.stop() } }
    }
}
