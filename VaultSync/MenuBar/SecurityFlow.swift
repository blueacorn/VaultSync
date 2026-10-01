/// Owns the presence capability shared by the Security gate and the Security settings form.
///
/// Changing the install's gating method is **one intent spanning two screens**: ``UnlockView``
/// proves the user can produce the current gating key, then ``SecurityView`` spends that proof to
/// re-wrap every domain's `.wrapped` entries. Evaluating presence twice for that one intent
/// prompted the user a second time on Save — for a screen whose only purpose is the change they
/// had just authenticated to reach.
///
/// The context is held here, in an object with a real `deinit`, rather than in a SwiftUI view's
/// `@State`. Views are values, recreated on every re-render, and `onDisappear` does not fire on
/// every path out of a popover — so a view could not say *when* the capability ends. An object
/// can: ARC ends it, and the explicit calls below end it sooner.
///
/// ```
///  ┌─────────────────────── SecurityFlow (owns the context) ───────────────────────┐
///  │                                                                               │
///  │   UnlockView ──proves presence──▶ [context]  ──borrowed by──▶ SecurityView    │
///  │        (gate)                         │                          (Save)       │
///  │                                       ▼                                       │
///  │                    invalidated on: re-key done · cancel · idle · deinit        │
///  └───────────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// The capability is never handed out as a value. ``withPresence(_:)`` lends it for the duration
/// of one call, so no caller can copy the reference somewhere that outlives this object — the
/// same discipline ``VaultKeyStore`` applies internally, one level up.
///
/// `.pin` holds no context: its gating key is *derived from the secret*, so the PIN itself is
/// carried instead (``currentPIN``) and re-derives the key at Save.
///
/// A `.none` install has neither, and still gets a flow: the idle countdown doubles as the
/// screen's auto-close, which is a UI behaviour rather than a security one. Every method's
/// Security screen therefore puts itself away the same way — see ``beginWithoutPresence()``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Combine
import Common
import Foundation

@MainActor
final class SecurityFlow: ObservableObject {

    /// Default idle window before the capability is dropped and the screen closes.
    ///
    /// Bounds the one case `deinit` cannot: a popover left open on the Security screen keeps this
    /// object — and its live presence capability — alive indefinitely. Any interaction with the
    /// form restarts the countdown (see ``noteActivity()``), so it expires only on a user who has
    /// actually walked away.
    ///
    /// It closes the screen as well as ending the capability, so it applies under `.none` too,
    /// where there is nothing to end and the auto-close is the whole of it.
    static let defaultIdleTimeout: TimeInterval = 60

    /// This flow's idle window. Injected so the expiry behaviour can be exercised without a
    /// minute-long test.
    private let idleTimeout: TimeInterval

    /// The live presence capability, or `nil` under `.pin` / `.none` and after invalidation.
    ///
    /// `private` with no accessor by design: see ``withPresence(_:)``.
    private var presenceContext: AnyObject?

    /// The verified PIN admitting the user, when the install is gated `.pin`. Empty otherwise.
    private(set) var currentPIN: String = ""

    /// Set when the idle timeout fires, so the hosting view can dismiss itself.
    ///
    /// The flow does not navigate: it reports that its capability is gone, and the view decides
    /// what to do about it. Keeps navigation in one place rather than split across an observable.
    @Published private(set) var didExpire = false

    /// Invalidates the context when it is no longer needed. Injected so tests can observe the
    /// lifetime without a real `LAContext`.
    private let invalidate: (AnyObject?) -> Void

    private var idleTask: Task<Void, Never>?

    /// - Parameters:
    ///   - idleTimeout: How long the flow may sit idle before its capability is dropped.
    ///   - invalidate: Ends a presence capability. Defaults to the production store.
    init(idleTimeout: TimeInterval = SecurityFlow.defaultIdleTimeout,
         invalidate: @escaping (AnyObject?) -> Void = { VaultKeyStore.shared.invalidatePresence($0) }) {
        self.idleTimeout = idleTimeout
        self.invalidate = invalidate
    }

    deinit {
        // The backstop, not the primary path: every completed or abandoned intent below ends the
        // capability explicitly. This catches the ways a popover can be torn down without any of
        // them running.
        //
        // `invalidate` is called directly rather than hopping to the main actor: a `Task` here
        // would outlive `self` and could not capture it, leaving the capability alive for exactly
        // as long as the hop takes.
        idleTask?.cancel()
        invalidate(presenceContext)
    }

    // MARK: - Admission

    /// Record a passed gate: the capability (or the PIN) that admitted the user.
    ///
    /// - Parameters:
    ///   - context: The evaluated presence capability, for `.biometric` / `.secure`.
    ///   - pin: The verified PIN, for `.pin`.
    func admit(context: AnyObject?, pin: String = "") {
        // Never silently replace a live capability: that would leak the previous one.
        if presenceContext != nil, presenceContext !== context { invalidate(presenceContext) }
        presenceContext = context
        currentPIN = pin
        didExpire = false
        startIdleCountdown()
    }

    /// Begin a flow that holds no capability at all — the `.none` install.
    ///
    /// There is no gating key to protect here, so this arms nothing but the idle countdown. It
    /// exists because the auto-close is a **UI** behaviour, not a security one: a settings screen
    /// left open in a popover should put itself away whichever method the install uses, and the
    /// user should not meet two different behaviours depending on how their vaults are gated.
    func beginWithoutPresence() {
        didExpire = false
        startIdleCountdown()
    }

    /// Whether a presence capability is currently held.
    var hasPresence: Bool { presenceContext != nil }

    /// Whether the idle countdown is running.
    var isCountingDown: Bool { idleTask != nil }

    // MARK: - Spending the capability

    /// Lend the presence capability to `body` for the duration of one call.
    ///
    /// Borrowed, never handed over: the context is not returned, stored, or otherwise made
    /// copyable by the caller, so its lifetime cannot escape this object.
    ///
    /// - Parameter body: Receives the capability, or `nil` when none is held.
    func withPresence<T>(_ body: (AnyObject?) async throws -> T) async rethrows -> T {
        try await body(presenceContext)
    }

    // MARK: - Ending the capability

    /// End the capability now — the intent it was obtained for is finished or abandoned.
    ///
    /// Idempotent. Called on a completed re-key, on Cancel, and on idle expiry; `deinit` repeats
    /// it only for the paths none of those cover.
    func end() {
        idleTask?.cancel()
        idleTask = nil
        invalidate(presenceContext)
        presenceContext = nil
        currentPIN = ""
    }

    // MARK: - Idle timeout

    /// Restart the idle countdown. Called from every control the user can touch on the form.
    ///
    /// Keyed on whether a countdown is *running*, not on whether a capability is held: under
    /// `.none` there is nothing to hold, and requiring one would leave that screen as the single
    /// case that never auto-closes. A spent flow stays spent — ``end()`` cancels the countdown,
    /// and nothing here restarts it.
    func noteActivity() {
        guard isCountingDown else { return }
        startIdleCountdown()
    }

    private func startIdleCountdown() {
        idleTask?.cancel()
        let timeout = idleTimeout
        idleTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard !Task.isCancelled else { return }
            guard let self else { return }
            // Drop the capability first, then report: the screen must never outlive it, and a
            // publish that triggered a re-render before the invalidation would invert that.
            self.end()
            self.didExpire = true
        }
    }
}
