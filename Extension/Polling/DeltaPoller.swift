/// Periodic background change-detection for a single File Provider domain.
///
/// Owned by ``Extension`` for the domain's lifetime, the poller drives the backend's
/// ``ProviderBackend/pollDelta()`` hook on a jittered interval and, whenever a pass
/// reconciles changes (or reports cursor expiry), signals the working set so the File
/// Provider re-enumerates affected containers and the Finder Domain view updates.
///
/// Polling — not webhooks — is the v1 mechanism: the sandboxed extension has no public
/// callback endpoint Graph could reach, and delta remains the durable source of truth
/// regardless. Backends without a remote
/// inherit the no-op `pollDelta`, so `Extension` only starts a poller for backends that
/// actually poll.
///
/// The loop is resilient: transient failures (offline, throttling, token refresh) are
/// logged and retried with exponential backoff; the loop only ends on cancellation.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import FileProvider
import os.log

actor DeltaPoller {

    /// Default poll cadence (in seconds)
    static let defaultInterval: TimeInterval = 45

    private let backend: ProviderBackend
    private let domainID: NSFileProviderDomainIdentifier
    private let manager: NSFileProviderManager
    /// Coalesces working-set signals. Each `signalEnumerator(for: .workingSet)` drives a full
    /// recursive `enumerateChanges` sweep, so high-frequency sources must not mean one sweep
    /// each. Owned by ``Extension`` and shared with the per-page and bulk encrypt/decrypt
    /// paths, so all of them coalesce against one another.
    private let workingSetThrottle: SignalThrottle
    private let backgroundInterval: TimeInterval
    /// Invoked after a completed poll pass that reconciled something (see
    /// ``shouldReportPassCompletion(for:)``). Injected as a closure so the poller carries no
    /// dependency on what consumes the event. Not invoked when the pass throws.
    private let onPassCompleted: PassCompletionHandler?
    private let log: Logger

    /// Notification that one delta pass finished, carrying its outcome.
    typealias PassCompletionHandler = @Sendable (_ result: DeltaPollResult) async -> Void

    /// The running loop; `nil` when stopped. Guards against double-start.
    private var task: Task<Void, Never>?

    /// Backoff ceiling after repeated failures (offline machine, etc.).
    private static let maxBackoff: TimeInterval = 5 * 60

    init(backend: ProviderBackend,
         domainID: NSFileProviderDomainIdentifier,
         manager: NSFileProviderManager,
         workingSetThrottle: SignalThrottle,
         interval: TimeInterval = DeltaPoller.defaultInterval,
         onPassCompleted: PassCompletionHandler? = nil,
         log: Logger) {
        self.backend = backend
        self.domainID = domainID
        self.manager = manager
        self.workingSetThrottle = workingSetThrottle
        self.backgroundInterval = interval
        self.onPassCompleted = onPassCompleted
        self.log = log
    }

    /// Start the poll loop. Idempotent — a second call while running is a no-op.
    func start() {
        guard task == nil else { return }
        log.infoPublic("⏱️ delta poller starting (interval=\(Int(backgroundInterval))s)")
        task = Task { [weak self] in
            await self?.run()
        }
    }

    /// Stop the poll loop and release the task.
    func stop() {
        task?.cancel()
        task = nil
        log.infoPublic("🛑 delta poller stopped")
    }

    /// Stop the loop and wait for it to actually exit.
    ///
    /// ``stop()`` only requests cancellation; the loop may still be mid-iteration when it
    /// returns. Callers that must know the work has ceased — the host cancellation handshake
    /// before a vault teardown — await this instead.
    func stopAndWait() async {
        let running = task
        task = nil
        running?.cancel()
        await running?.value
    }

    // MARK: - Signalling

    /// Signal the working set — the replicated extension's remote-change feed, which drives
    /// `WorkingSetEnumerator.enumerateChanges(from:)` and delivers a changed child without
    /// depending on its parent folder's `itemVersion` changing (OneDrive does not bump a
    /// folder's eTag when a child is added).
    ///
    /// Goes through the throttle; `request` is synchronous and fires leading-edge + trailing,
    /// so the signal itself is dispatched into a detached Task rather than awaited.
    private func signalWorkingSet() {
        workingSetThrottle.request { [manager] in
            Task { try? await manager.signalEnumerator(for: .workingSet) }
        }
    }

    // MARK: - Loop

    private func run() async {
        var consecutiveFailures = 0
        while !Task.isCancelled {
            do {
                let result = try await backend.pollDelta()
                consecutiveFailures = 0
                // Only the post-crawl reconcile parents arrive here; the crawl's own changes
                // were already signalled per page via `onDeltaProgress`, and the indexed count
                // is published from there too. A cursor expiry the pass could not recover
                // in-pass (double 410) still gets a working-set signal.
                if result.changed || result.cursorExpired {
                    log.infoPublic("🔔 post-crawl changes (cursorExpired=\(result.cursorExpired)) → signal \(result.changedParentIdentifiers.count) container(s)")
                    signalWorkingSet()
                    //for container in result.changedParentIdentifiers.sorted(by: { $0.id < $1.id }) {
                    //    try? await manager.signalEnumerator(for: NSFileProviderItemIdentifier(container.id))
                    //}
                }
                if Self.shouldReportPassCompletion(for: result) {
                    await onPassCompleted?(result)
                }
            } catch {
                // A locked vault is terminal for background work, not a transient fault: the key
                // material is evicted and no amount of backoff brings it back. Retrying burns a
                // wakeup and a Graph round-trip every interval for as long as the vault stays
                // locked. Unlocking repopulates the slots and restarts the poller, so stopping
                // here costs nothing and is not a self-cancellation of the extension — the OS
                // owns that, and enumerations keep answering `notAuthenticated` meanwhile.
                if Self.isVaultLocked(error) {
                    log.infoPublic("🔒 vault locked — stopping delta poller until unlock")
                    break
                }
                consecutiveFailures += 1
                log.errorPublic("⚠️ delta poll failed (attempt \(consecutiveFailures)): \(String(describing: error))")
            }
            // Sleep before the next pass, with exponential backoff after failures
            do {
                try await Task.sleep(nanoseconds: nextDelay(failures: consecutiveFailures))
            } catch {
                break // cancelled
            }
        }
    }

    /// Whether `error` means the vault is locked, in either of the two shapes that can reach
    /// the poll loop: a sealed refresh token that cannot be opened (``AuthError/vaultLocked``)
    /// and an evicted Provider-readable slot (``VaultKeyStoreError/locked``).
    ///
    /// A pure function for the same reason as ``shouldReportPassCompletion(for:)`` — the policy
    /// is testable without standing up a backend or a live vault.
    static func isVaultLocked(_ error: Error) -> Bool {
        if let authError = error as? AuthError, authError == .vaultLocked { return true }
        return (error as? VaultKeyStoreError) == .locked
    }

    /// Whether a completed pass is worth reporting through ``onPassCompleted``.
    ///
    /// Expressed as a pure function so the policy is testable without stubbing the 39-member
    /// ``ProviderBackend`` or standing up a live `NSFileProviderManager`.
    ///
    /// Only a pass that reconciled something is worth relaying, so a steady-state no-op pass
    /// reports nothing: relaying every 45s tick would turn an event path into a second,
    /// redundant clock. Cursor expiry counts as a change — the rotated cache re-indexes
    /// everything.
    static func shouldReportPassCompletion(for result: DeltaPollResult) -> Bool {
        result.changed || result.cursorExpired
    }

    /// The sleep before the next pass: the base interval (with ±20% jitter to keep multiple
    /// domains from synchronising), or an exponential backoff after failures.
    private func nextDelay(failures: Int) -> UInt64 {
        let base: TimeInterval
        let jitter = Double.random(in: 0.8...1.2)
        if failures == 0 {
            base = backgroundInterval * jitter
        } else {
            let backoff = min(backgroundInterval * pow(2, Double(failures)), Self.maxBackoff)
            base = backoff
        }
        return UInt64(base * 1_000_000_000)
    }
}
