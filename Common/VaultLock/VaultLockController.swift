/// Vault lock/unlock policy orchestration (tasks 29, 41, 47, 51).
///
/// Each domain owns a `domainKey`, always wrapped at rest under exactly one gating key of its own
/// (see ``VaultKeyStore``):
///
/// ```
/// gating key[d] ─AES-GCM─▶ domainKey.wrapped[d] ─domainKey[d]─▶ userIdentityKey / fileKeysKEK
///                                                            └▶ refreshTokenKey → refreshToken
/// unlock: obtain the gating key (silent / Touch ID / PIN / Enclave) → open that domain's
///         domainKey → populate its Provider-readable "unwrapped" slots → discard the domainKey
/// lock:   evict those slots. There is no in-memory key to drop.
/// ```
///
/// The controller owns *policy* — gating changes, unlock ceremonies, idle timeout, and
/// system-event relocks — but not domain plumbing (disconnect/reconnect NSFileProviderManager).
/// Those are injected via ``onLock`` / ``onUnlock`` so the controller stays testable without
/// FileProvider.
///
/// **Policy is install-wide; keys are per domain.** One timeout and one set of triggers, whose
/// expiry locks *every* domain. Per-domain timeouts would multiply UI for no security gain — the
/// keys are already separated, which is where the isolation matters.
///
/// There is no enrolled/unenrolled regime: `.none` is a gating like any other, differing only in
/// that its gating key is read silently. Lock under `.none` is therefore a UX affordance rather
/// than a security boundary — the `domainKey` is still never at rest unwrapped, but any App Group
/// process can obtain the gating key. Locking itself is available to the sandboxed
/// `Provider.appex` in every gating: evicting the unwrapped slots is a plain `SecItemDelete` on
/// non-ACL items; only *unlocking* needs the app-side ceremony.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import os.log

/// Abstracts the wall clock + one-shot timer so the idle-lock path is deterministic under test.
public protocol LockScheduler: AnyObject {
    /// Schedule `fire` to run after `seconds`. Replaces any prior pending fire.
    func schedule(after seconds: TimeInterval, _ fire: @escaping () -> Void)
    /// Cancel any pending fire.
    func cancel()
}

/// Abstracts subscription to system lock/logout/power events so they can be simulated in tests.
public protocol SystemLockEvents: AnyObject {
    /// Begin delivering the enabled events to `handler`. `trigger` names which policy fired.
    func start(_ handler: @escaping (_ trigger: VaultLockController.Trigger) -> Void)
    func stop()
}

/// The per-domain key-lifecycle surface the controller drives. ``VaultKeyStore`` is the
/// production implementation; tests inject a fake to exercise the gating/unlock decision logic
/// without the keychain, an `LAContext` prompt, or PBKDF2.
///
/// Key material is domain-parameterised — every `domainKey` and leaf is scoped to one domain.
/// The unlock **method** is not: it is install-wide (I5′), so ``gating()`` and
/// ``setGating(_:newPIN:currentPIN:)`` take no domain.
public protocol VaultKeyGuarding: AnyObject {
    /// Whether a domain is open — its Provider-readable slots are populated.
    func isUnlocked(domain domainIdentifier: String) -> Bool
    /// The unlock method in force for this install (silent — no prompt).
    func gating() -> SharedConfig.VaultGating
    /// Whether a domain's `domainKey` wrapper exists, i.e. it has been provisioned.
    func isProvisioned(domain domainIdentifier: String) -> Bool
    /// Lock one domain by evicting its unwrapped slots.
    func lock(domain domainIdentifier: String)
    func unlock(domain domainIdentifier: String, pin: String?, reason: String,
                context: AnyObject?) async throws
    /// Re-gate the install, optionally borrowing an already-evaluated presence context so a
    /// caller that has just proven presence does not prompt a second time.
    func setGating(_ target: SharedConfig.VaultGating,
                   newPIN: String?, currentPIN: String?,
                   presenceContext: AnyObject?) async throws
    func reconcile(domain domainIdentifier: String)
    func populateUnwrappedSlots(for domainIdentifiers: [String], pin: String?) async throws
    func evictUnwrappedSlots() throws
    /// Evict only the named domain's slots, leaving every other domain's intact.
    func evictUnwrappedSlots(for domainIdentifier: String) throws
}

extension VaultKeyStore: VaultKeyGuarding {}

/// Coordinates the vault key lifecycle and relock policy.
public final class VaultLockController: @unchecked Sendable {
    /// What caused a relock (for logging + policy gating).
    ///
    /// Named for the *delivery* event, not the user's intent: `powerOff` is the one
    /// `NSWorkspace` notification that logout, restart and shutdown all post, and
    /// `sessionResign` is fast user switching. The user-facing logout / restart flags stay
    /// separate and are reconciled in ``LockPolicy/allows(_:)``.
    public enum Trigger: String, Sendable {
        case manual, idleTimeout, screenLock, powerOff, sessionResign
    }

    private let guardKeys: VaultKeyGuarding
    private let scheduler: LockScheduler
    private let events: SystemLockEvents
    private let config: () -> LockPolicy
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "vault-lock")
    private let stateLock = NSLock()
    /// Whether ``armSystemEvents()`` has subscribed, so repeat calls are idempotent.
    private var systemEventsArmed = false

    /// Snapshot of the user's relock preferences (read from `SharedConfig` app-side).
    ///
    /// Carries no gating field: the unlock ceremony is derived from ``VaultKeyGuarding/gating``,
    /// which is the single authoritative record. A second copy here could drift out of sync with
    /// it — exactly the split that let a PIN gate the UI without gating the key.
    public struct LockPolicy: Sendable, Equatable {
        /// The master switch. When `false` no trigger fires, whatever the individual flags say —
        /// the one place `autoLockEnabled` is honoured for the idle and system-event triggers,
        /// matching what ``SharedConfig/locksOnQuit`` already does for quit.
        public var enabled: Bool
        public var timeoutSeconds: Int
        public var onScreenLock: Bool
        public var onLogout: Bool
        public var onRestart: Bool
        public init(enabled: Bool = true,
                    timeoutSeconds: Int,
                    onScreenLock: Bool, onLogout: Bool, onRestart: Bool) {
            self.enabled = enabled
            self.timeoutSeconds = timeoutSeconds
            self.onScreenLock = onScreenLock
            self.onLogout = onLogout
            self.onRestart = onRestart
        }

        /// Whether `trigger` should relock, under this policy.
        ///
        /// One rule for every system trigger, so the arming decision cannot drift between the
        /// subscription site and the delivery site.
        public func allows(_ trigger: Trigger) -> Bool {
            guard enabled else { return false }
            switch trigger {
            case .screenLock: return onScreenLock
            // Either flag arms it: the notification cannot tell logout from restart, so
            // honouring only one silently disables the other.
            case .powerOff:      return onLogout || onRestart
            // Session switch-out is a screen-lock-grade event: the desktop is no longer
            // visible to this user, but the process is not going away.
            case .sessionResign: return onScreenLock
            case .idleTimeout: return timeoutSeconds > 0
            case .manual:     return true
            }
        }
    }

    /// Invoked when a lock takes effect (disconnect domains, signal enumerators). Runs after
    /// key material is evicted.
    public var onLock: ((Trigger) -> Void)?
    /// Invoked when an unlock completes (reconnect domains). Runs after slots are repopulated.
    ///
    /// Carries the domains that were actually opened, so unlocking one vault reconnects that
    /// vault alone. An install-wide callback here is what let a single "Unlock Vault" reconnect
    /// every sibling, including ones whose gating ceremony was never run.
    public var onUnlock: (([String]) -> Void)?
    /// Supplies the current domain identifiers to wrap / unwrap / evict.
    public var domainIdentifiers: () -> [String] = { [] }

    public init(guardKeys: VaultKeyGuarding,
                scheduler: LockScheduler,
                events: SystemLockEvents,
                config: @escaping () -> LockPolicy) {
        self.guardKeys = guardKeys
        self.scheduler = scheduler
        self.events = events
        self.config = config
    }

    // MARK: - Gating

    /// The unlock method in force for this install (silent — no prompt).
    public func gating() -> SharedConfig.VaultGating {
        guardKeys.gating()
    }

    /// Reconcile a crashed gating change on every domain, then arm the relock policy. Call once
    /// at launch.
    ///
    /// A crash between writing a new `domainKey` wrapper and deleting the old gating key leaves a
    /// stale gating key behind; this removes it. Deliberately only ever touches the *non*-active
    /// gating, so it can never brick a vault.
    ///
    /// Also re-derives the Provider-readable slots for every unlocked domain. Populating them is
    /// otherwise reachable only through an unlock ceremony, so a domain that gained material
    /// while already unlocked — or one provisioned by a build that predates a slot — would have
    /// that slot absent until the next lock/unlock cycle, which the Provider cannot distinguish
    /// from a locked vault.
    public func reconcileAtLaunch() {
        for domain in domainIdentifiers() { guardKeys.reconcile(domain: domain) }
        // Deliberately does *not* reconcile slots, so the two stay separately callable and the
        // launch ordering is visible at the call site rather than buried in a detached `Task`.
    }

    /// Switch one domain to `target` gating.
    ///
    /// One path for every transition — there is no first-enable special case. The domain is
    /// opened under its *current* gating inside ``VaultKeyGuarding``, so changing a PIN on a
    /// locked vault works.
    ///
    /// - Parameters:
    ///   - target: The method to switch the install to.
    ///   - newPIN: The PIN to enroll, when `target` is `.pin`.
    ///   - currentPIN: The PIN opening the current method, when it is `.pin` and we are locked.
    ///   - presenceContext: An already-evaluated context to borrow, from a caller that has just
    ///     proven presence. Ownership stays with that caller.
    public func setGating(_ target: SharedConfig.VaultGating,
                          newPIN: String? = nil,
                          currentPIN: String? = nil,
                          presenceContext: AnyObject? = nil) async throws {
        try await guardKeys.setGating(target, newPIN: newPIN, currentPIN: currentPIN,
                                      presenceContext: presenceContext)
        // Every domain was re-sealed, so every domain's slots must be repopulated — repopulating
        // one would leave the rest locked behind a method they no longer answer to.
        try await guardKeys.populateUnwrappedSlots(for: domainIdentifiers(), pin: newPIN)
        beginActivityWindow()
        log.info("🔐 install gating set to \(target.rawValue, privacy: .public)")
    }

    // MARK: - Lock / unlock

    /// Relock **every** domain: evict the Provider-readable slots, then notify the host to
    /// disconnect.
    ///
    /// Install-wide by policy, not by key layout: the idle timer and system triggers are one set
    /// for the whole app, and their expiry locks everything.
    public func lock(trigger: Trigger = .manual) {
        evictKeyMaterial()
        log.info("🔒 vault locked (\(trigger.rawValue))")
        onLock?(trigger)
    }

    /// Evict every domain's Provider-readable slots, without notifying ``onLock``.
    ///
    /// For callers that already handle their own domain plumbing (e.g. a lock-and-remove flow
    /// that disconnects/unregisters the affected domains itself) and would otherwise trigger a
    /// redundant, racy ``onLock``-driven disconnect of every domain.
    public func evictKeyMaterial() {
        try? guardKeys.evictUnwrappedSlots()
        scheduler.cancel()
    }

    /// Evict key material for a *subset* of domains, without notifying ``onLock``.
    ///
    /// Only the named domains' Provider-readable slots are removed: vaults that stay unlocked
    /// keep theirs, so their Provider goes on materializing. A vault-wide evict here is what
    /// broke every other vault when one was locked.
    ///
    /// - Parameter lockedDomainIdentifiers: The domains being locked.
    public func evictKeyMaterial(for lockedDomainIdentifiers: [String]) {
        for domain in lockedDomainIdentifiers {
            do {
                try guardKeys.evictUnwrappedSlots(for: domain)
            } catch {
                log.error("⚠️ slot eviction failed for \(domain, privacy: .public): \(String(describing: error), privacy: .public)")
            }
        }
        // Nothing install-wide left to drop: each domain's key existed only for the duration of
        // its own unlock. Locking one vault cannot reach another's material.
        scheduler.cancel()
    }

    /// Unlock one domain: obtain its gating key — silently, via a Touch ID prompt, by deriving
    /// from `pin`, or through the Secure Enclave — open its `domainKey`, repopulate its
    /// Provider-readable slots, then notify the host to reconnect.
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain to unlock.
    ///   - pin: The entered PIN, required when that domain's gating is `.pin`.
    ///   - reason: Prompt text shown for `.biometric` and `.secure` gating.
    public func unlock(domain domainIdentifier: String,
                       pin: String? = nil,
                       reason: String = "Unlock your vaults") async throws {
        try await restoreKeyMaterial(domain: domainIdentifier, pin: pin, reason: reason)
        log.info("🔓 vault unlocked \(domainIdentifier, privacy: .public)")
        onUnlock?([domainIdentifier])
    }

    /// Unlock the named domains behind one gating ceremony, at the cost of a single prompt.
    ///
    /// The prompt is evaluated once and reused across `domainIdentifiers`; each still derives its
    /// **own** `domainKey`, so a captured key opens exactly one vault. This is a UX affordance
    /// and deliberately not a weakening of I5.
    ///
    /// Takes an explicit list rather than reaching for ``domainIdentifiers``: the caller decides
    /// how far its ceremony reaches. An implicit install-wide scope here is what let a single
    /// vault's PIN entry open every other vault.
    ///
    /// Domains whose ceremony fails are logged and skipped rather than failing the whole call —
    /// one PIN cannot open a `.secure` domain, and that is not an error for the others.
    ///
    /// - Parameters:
    ///   - domainIdentifiers: The domains this ceremony was run for.
    ///   - pin: The entered PIN, for `.pin`-gated domains.
    ///   - reason: Prompt text.
    public func unlock(domains domainIdentifiers: [String],
                       pin: String? = nil,
                       reason: String = "Unlock your vaults") async throws {
        guard !domainIdentifiers.isEmpty else { return }
        try await guardKeys.populateUnwrappedSlots(for: domainIdentifiers, pin: pin)
        beginActivityWindow()
        log.info("🔓 vaults unlocked \(domainIdentifiers.count, privacy: .public)")
        onUnlock?(domainIdentifiers)
    }

    /// Obtain the gating key, open one domain's `domainKey`, and repopulate its
    /// Provider-readable slots, without notifying ``onUnlock``.
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain to open.
    ///   - pin: The entered PIN, required when that domain's gating is `.pin`.
    ///   - reason: Prompt text shown for `.biometric` and `.secure` gating.
    public func restoreKeyMaterial(domain domainIdentifier: String,
                                   pin: String? = nil,
                                   reason: String = "Unlock your vaults") async throws {
        try await guardKeys.unlock(domain: domainIdentifier, pin: pin,
                                   reason: reason, context: nil)
        beginActivityWindow()
    }

    // MARK: - Idle + system-event relock

    /// (Re)arm the idle timer and subscribe to system lock/logout/power events. Call on unlock and
    /// on any user activity that should reset the idle countdown.
    public func beginActivityWindow() {
        armSystemEvents()
        armIdleTimer(config())
    }

    /// Subscribe to the system lock/logout/power events, if not already subscribed.
    ///
    /// Separate from ``beginActivityWindow()`` because subscription must not depend on an unlock
    /// having happened in *this* launch: the app is a menu-bar agent that outlives any one
    /// ceremony, and vaults are commonly already open at startup. Call once at launch.
    ///
    /// The handler re-reads ``config`` on each event rather than closing over a snapshot, so a
    /// policy edited in the Security screen takes effect immediately instead of at the next
    /// unlock.
    public func armSystemEvents() {
        stateLock.lock()
        let alreadyArmed = systemEventsArmed
        systemEventsArmed = true
        stateLock.unlock()
        guard !alreadyArmed else { return }
        events.start { [weak self] trigger in
            guard let self else { return }
            self.handleSystemEvent(trigger, policy: self.config())
        }
    }

    /// The relock policy currently in force.
    ///
    /// Exposed so callers that must make the same arming decision as the system-event handler
    /// ask ``LockPolicy/allows(_:)`` rather than re-deriving it from the individual flags — the
    /// drift this type's doc comment already warns against.
    public func currentPolicy() -> LockPolicy { config() }

    /// Re-read the policy and re-arm the idle timer to match it.
    ///
    /// For the Security screen, which writes the policy to `SharedConfig` directly: the system
    /// event handler re-reads config on each event, but a timer scheduled under the *old*
    /// interval is already pending and would otherwise keep the previous timeout until the next
    /// unlock. Cancels the timer outright when the new policy disarms the idle trigger.
    public func policyDidChange() {
        armIdleTimer(config())
    }

    /// Reset the idle countdown (user touched the vault). No-op while every domain is locked.
    public func noteActivity() {
        guard domainIdentifiers().contains(where: { guardKeys.isUnlocked(domain: $0) })
        else { return }
        armIdleTimer(config())
    }

    private func armIdleTimer(_ policy: LockPolicy) {
        guard policy.allows(.idleTimeout) else { scheduler.cancel(); return }
        scheduler.schedule(after: TimeInterval(policy.timeoutSeconds)) { [weak self] in
            self?.lock(trigger: .idleTimeout)
        }
    }

    private func handleSystemEvent(_ trigger: Trigger, policy: LockPolicy) {
        guard policy.allows(trigger) else {
            log.info("🚪 entry point: handleSystemEvent (\(trigger.rawValue, privacy: .public)) — not armed by policy, ignored")
            return
        }
        log.info("🚪 entry point: handleSystemEvent (\(trigger.rawValue, privacy: .public)) — armed, locking")
        lock(trigger: trigger)
    }
}
