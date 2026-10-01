/// Per-client throttling for Microsoft Graph requests.
///
/// Honors `Retry-After` on `429 Too Many Requests` / `503 Service Unavailable` and
/// applies exponential backoff with jitter between automatic retries. One limiter
/// instance is held per ``GraphDriveClient`` (KISS); a cross-process/global limiter is
/// deferred.
///
/// ## Priority lanes
/// Requests carry a ``Priority``. Interactive requests (Finder enumeration, downloads)
/// must stay responsive while the background delta crawl saturates Graph and trips
/// throttling. The limiter therefore:
/// - caps concurrent interactive requests (``maxInteractive``) so bursty client load queues
///   locally instead of fanning out into a 429,
/// - has the background crawl **soft-yield** between pages while any interactive
///   request is pending (see ``yieldToInteractiveIfNeeded()``), and
/// - gates every attempt on the server cool-off: all lanes wait it out (cancellably). Failing
///   interactive requests fast does not help — the system re-issues a failed fetch within tens
///   of milliseconds, so clients see a stream of errors instead of one slow read. When the
///   cool-off ends, ``onCoolOffEnded`` fires once so the owner can tell the system to resume
///   any work it did park on a `serverUnreachable` (e.g. retries exhausted).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Common
import FileProvider
import Foundation
import os

actor GraphRateLimiter {

    /// Request lane. Interactive work is shielded from the background crawl's cool-offs.
    enum Priority {
        /// Finder-origin enumeration, item fetch, downloads — latency-sensitive.
        case interactive
        /// Delta crawl / background polling — yields to interactive work.
        case background

        var label: String { self == .interactive ? "interactive" : "background" }
    }

    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "graph-client")

    /// Until this instant, new requests are gated (set from `Retry-After`).
    private var notBefore: Date = .distantPast

    /// Bumped on every cool-off extension; the end-of-cool-off watcher only fires for the
    /// latest one, so ``onCoolOffEnded`` runs once per throttling episode.
    private var coolOffGeneration = 0

    /// Count of interactive requests currently holding a slot.
    private var interactiveInFlight = 0

    /// Interactive requests queued for a slot, FIFO.
    private var interactiveWaiters: [CheckedContinuation<Void, Never>] = []

    /// Maximum automatic retries for a throttled/transient request.
    let maxRetries: Int

    /// Maximum concurrent interactive requests.
    let maxInteractive: Int

    /// Upper bound a background page-pause will wait per yield, so the crawl still makes
    /// forward progress under sustained browsing rather than starving outright.
    private let maxYield: TimeInterval = 1.0

    /// Called once when a throttling cool-off has fully elapsed.
    private let onCoolOffEnded: @Sendable () async -> Void

    init(maxRetries: Int = 5,
         maxInteractive: Int = 8,
         onCoolOffEnded: @escaping @Sendable () async -> Void = {}) {
        self.maxRetries = maxRetries
        self.maxInteractive = max(1, maxInteractive)
        self.onCoolOffEnded = onCoolOffEnded
    }

    /// Register a request in its lane; interactive requests wait for a free slot.
    /// Call ``endRequest(_:)`` when the request completes.
    /// - Returns: Seconds spent queued for a slot, for trace instrumentation.
    @discardableResult
    func beginRequest(_ priority: Priority) async -> TimeInterval {
        guard priority == .interactive else { return 0 }
        guard interactiveInFlight >= maxInteractive else {
            interactiveInFlight += 1
            return 0
        }
        let started = Date()
        // The releasing request hands its slot over directly (count unchanged).
        await withCheckedContinuation { interactiveWaiters.append($0) }
        return Date().timeIntervalSince(started)
    }

    /// Balance a ``beginRequest(_:)`` call.
    func endRequest(_ priority: Priority) {
        guard priority == .interactive else { return }
        if interactiveWaiters.isEmpty {
            interactiveInFlight = max(0, interactiveInFlight - 1)
        } else {
            interactiveWaiters.removeFirst().resume()
        }
    }

    /// Gate one attempt against the server-mandated `Retry-After` window.
    ///
    /// Called before **every** attempt, so a retry never re-issues inside a cool-off (sending
    /// during throttling extends it). Every lane waits out the full window; the wait is
    /// cancellable, so a fetch the system abandons ends promptly.
    /// - Returns: Seconds spent waiting, for trace instrumentation.
    func waitForCoolOff(priority: Priority) async throws -> TimeInterval {
        let remaining = notBefore.timeIntervalSinceNow
        guard remaining > 0 else { return 0 }
        logger.debugPublic("🚦 cool-off wait [\(priority.label)] \(String(format: "%.1f", remaining))s")
        try await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
        return remaining
    }

    /// Error surfaced when throttling retries are exhausted. A File Provider error, so outer
    /// retry loops treat it as terminal and the system retries after ``onCoolOffEnded``
    /// signals the domain reachable again.
    static var throttledError: NSError {
        NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.serverUnreachable.rawValue)
    }

    /// Soft-yield hook for the background crawl: if interactive requests are in flight,
    /// pause briefly (bounded by ``maxYield``) so Finder's network requests get the slot.
    /// No-op when nothing interactive is pending, so an idle drive crawls at full speed.
    func yieldToInteractiveIfNeeded() async {
        guard interactiveInFlight > 0 else { return }
        try? await Task.sleep(nanoseconds: UInt64(maxYield * 1_000_000_000))
    }

    /// Record a `Retry-After` directive (seconds) from a throttled response, and arm the
    /// end-of-cool-off signal.
    /// - Parameter source: The throttled request, for the log line.
    func noteRetryAfter(seconds: TimeInterval, source: String) {
        let candidate = Date().addingTimeInterval(seconds)
        guard candidate > notBefore else { return }
        let previous = notBefore.timeIntervalSinceNow
        notBefore = candidate
        coolOffGeneration += 1
        let generation = coolOffGeneration
        let action = previous > 0 ? "extended \(String(format: "%.1f", previous))s →" : "set"
        logger.warningPublic("🚦 cool-off \(action) \(String(format: "%.0f", seconds))s gen=\(generation) source=\(source)")
        Task { await self.fireCoolOffEnded(generation: generation, after: seconds) }
    }

    /// Fire ``onCoolOffEnded`` if no later `Retry-After` superseded `generation`.
    private func fireCoolOffEnded(generation: Int, after seconds: TimeInterval) async {
        try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
        guard generation == coolOffGeneration else { return }
        logger.infoPublic("🚦 cool-off ended gen=\(generation) interactiveInFlight=\(interactiveInFlight) queued=\(interactiveWaiters.count)")
        await onCoolOffEnded()
    }

    /// Backoff delay (seconds) for `attempt` (0-based), decorrelated jitter over a floor.
    ///
    /// The jitter window is `[base/2, base]` rather than `[0, base]`. Full jitter can return a
    /// near-zero delay, and when several parallel lanes fail together on the same torn
    /// connection that collapses their retries into one indistinguishable burst — the retry
    /// storm looks like runaway fan-out and hits the server harder than one lane would.
    func backoffDelay(attempt: Int) -> TimeInterval {
        let base = min(pow(2.0, Double(attempt)), 30.0)
        return Double.random(in: (base / 2)...base)
    }
}
