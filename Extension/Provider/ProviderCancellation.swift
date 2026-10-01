/// Graceful-teardown handshake, Provider side.
///
/// When the host locks-and-removes a vault it must stop the Provider's in-flight work *before*
/// emptying the domain's metadata cache — otherwise a running delta crawl or chunked transfer
/// keeps writing rows into a cache that is being cleared, and the teardown races work it cannot
/// see.
///
/// ```
///  App                                     Provider
///   │  bump SharedConfig.cancelGeneration → N
///   │────── Darwin notification ───────────▶│
///   │                                       │  state = .cancelling, ack = N
///   │                                       │  cancel pollers + in-flight tasks
///   │                                       │  state = .cancelled,  ack = N
///   │◀───── progressDidChange ──────────────│
///   │  state == .cancelled && ack >= N      │
///   │  → tear down                          │
/// ```
///
/// The app waits with a timeout and proceeds regardless on expiry: `MetadataCache.empty()` never
/// unlinks the database, so a late writer is harmless — the wait is about *promptness and
/// tidiness*, not correctness.
///
/// Cancellation is delivered by cancelling the `Task`s that own the long-running loops. Those
/// loops already honour `Task.isCancelled` / `Task.checkCancellation()`, so no new cooperative
/// checks are needed in the transfer and sync paths.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Combine
import Common
import FileProvider
import Foundation
import os.log

/// Watches `SharedConfig.cancelGeneration` for one domain and runs a supplied stop routine when
/// it advances, reporting completion through ``ProgressStore``.
///
/// The generation is a counter rather than a flag because it is a *command*: the coordinator must
/// tell a fresh request apart from one it has already served. The reply carries the generation
/// back for the mirror-image reason — ``ProviderState/cancelled`` says *a* cancellation finished,
/// not *which*, and the state is never reset to `.idle`. A bare state would therefore let the
/// `.cancelled` from one lock/unlock cycle acknowledge the next cycle's request instantly, and the
/// host would tear the domain down with the Provider still live.
///
/// Kept separate from ``Extension`` so the handshake is unit-testable without a File Provider
/// domain: the config read and the stop routine are both injected.
final class ProviderCancellationCoordinator: @unchecked Sendable {

    private let domainID: String
    private let readGeneration: () -> Int
    private let stopWork: () async -> Void
    private let report: (ProviderState, Int) -> Void
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "provider-cancel")

    private let lock = NSLock()
    /// Highest generation already handled, so a repeated notification is not re-processed.
    private var acknowledged: Int
    private var cancellable: AnyCancellable?

    /// - Parameters:
    ///   - domainID: Domain identifier `rawValue`, used as the progress-store key.
    ///   - readGeneration: Reads the current requested cancellation generation.
    ///   - report: Publishes provider state, and the generation it answers, back to the host.
    ///   - stopWork: Cancels and awaits this domain's in-flight work.
    init(domainID: String,
         readGeneration: @escaping () -> Int,
         report: @escaping (ProviderState, Int) -> Void,
         stopWork: @escaping () async -> Void) {
        self.domainID = domainID
        self.readGeneration = readGeneration
        self.report = report
        self.stopWork = stopWork
        // Adopt the generation present at launch: it was either already acknowledged, or belongs
        // to a teardown that completed while this process was not running. Either way it is not a
        // fresh request, and re-running teardown for it would cancel work that just started.
        self.acknowledged = readGeneration()
    }

    /// Begin observing config changes. The store reloads on the host's Darwin notification and
    /// then emits `objectWillChange`, which is the wakeup this subscribes to.
    func start(publisher: AnyPublisher<Void, Never>) {
        cancellable = publisher.sink { [weak self] in self?.checkForRequest() }
        checkForRequest()
    }

    func stop() {
        cancellable?.cancel()
        cancellable = nil
    }

    /// Handle a config change: run the stop routine if a newer generation has been requested.
    private func checkForRequest() {
        let requested = readGeneration()

        lock.lock()
        guard requested > acknowledged else { lock.unlock(); return }
        acknowledged = requested
        lock.unlock()

        log.info("🛑 cancellation requested domain=\(self.domainID, privacy: .public) generation=\(requested)")
        report(.cancelling, requested)

        Task { [stopWork, report, log, domainID] in
            await stopWork()
            report(.cancelled, requested)
            log.info("✅ cancellation acknowledged domain=\(domainID, privacy: .public) generation=\(requested)")
        }
    }
}
