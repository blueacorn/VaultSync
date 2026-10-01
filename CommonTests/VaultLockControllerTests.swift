/// Unit tests for `VaultLockController`.
//
//  VaultLockControllerTests.swift
//  CommonTests
//
//  Policy tests for VaultLockController (tasks 29, 47): idle timeout, system-event relock, and
//  the single-path gating transitions. Keychain effects are covered on-device; here we drive the
//  controller with a fake key guard, a manual scheduler, and a manual event source so the policy
//  is deterministic.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

private final class ManualScheduler: LockScheduler {
    private(set) var scheduledSeconds: TimeInterval?
    private var fire: (() -> Void)?
    private(set) var cancelCount = 0

    func schedule(after seconds: TimeInterval, _ fire: @escaping () -> Void) {
        scheduledSeconds = seconds
        self.fire = fire
    }
    func cancel() { cancelCount += 1; fire = nil; scheduledSeconds = nil }
    /// Simulate the idle timer firing.
    func fireNow() { fire?() }
}

private final class ManualEvents: SystemLockEvents {
    private var handler: ((VaultLockController.Trigger) -> Void)?
    private(set) var started = false
    func start(_ handler: @escaping (VaultLockController.Trigger) -> Void) {
        self.handler = handler; started = true
    }
    func stop() { handler = nil; started = false }
    func emit(_ trigger: VaultLockController.Trigger) { handler?(trigger) }
}

private struct StubGate: BiometricGate {
    var isAvailable: Bool { true }
    func authenticate(reason: String) async throws {}
}

/// Records the install-wide gating and per-domain unlock decision path without touching the
/// keychain, an LAContext or PBKDF2.
///
/// Models the invariants that matter here: the unlock **method** is install-wide (I5′), while each
/// domain keeps its own `domainKey` identity that must survive every method change — two domains
/// sharing one would be an I5′ violation.
private final class FakeGuard: VaultKeyGuarding {
    /// Stands in for each domain's `domainKey` value. Any change means that domain's leaves were
    /// orphaned; two domains sharing one would be an I5′ violation.
    var domainKeys: [String: UUID] = [:]
    /// The install's active method — one value, not one per domain.
    var installGating: SharedConfig.VaultGating = .none
    var provisioned: Set<String> = []
    var unlockedDomains: Set<String> = []
    /// The gating keypairs that currently exist, install-wide. At most one after a clean change.
    var gatingKeys: Set<SharedConfig.VaultGating> = [.none]
    /// Set to leave a stale gating keypair behind, simulating a crash mid-`setGating`.
    var crashBeforeDeletingOldKeys = false

    private(set) var calls: [String] = []

    /// Seed a domain as provisioned, with its own distinct `domainKey`.
    func seed(_ domain: String, gating: SharedConfig.VaultGating = .none, unlocked: Bool = false) {
        provisioned.insert(domain)
        installGating = gating
        gatingKeys.insert(gating)
        domainKeys[domain] = UUID()
        if unlocked { unlockedDomains.insert(domain) }
    }

    func isUnlocked(domain domainIdentifier: String) -> Bool {
        unlockedDomains.contains(domainIdentifier)
    }
    func gating() -> SharedConfig.VaultGating { installGating }
    func isProvisioned(domain domainIdentifier: String) -> Bool {
        provisioned.contains(domainIdentifier)
    }
    func lock(domain domainIdentifier: String) {
        calls.append("lock:\(domainIdentifier)")
        unlockedDomains.remove(domainIdentifier)
    }

    func unlock(domain domainIdentifier: String, pin: String?, reason: String,
                context: AnyObject?) async throws {
        let g = installGating
        calls.append("unlock:\(domainIdentifier)(\(g.rawValue)\(pin == nil ? "" : "+pin"))")
        if g == .pin, pin == nil { throw VaultKeyStoreError.pinRequired }
        guard gatingKeys.contains(g) else { throw VaultKeyStoreError.gatingKeyMissing }
        unlockedDomains.insert(domainIdentifier)
    }

    /// Contexts the re-key was lent, so a test can assert a borrowed capability is threaded
    /// through rather than a fresh ceremony being run.
    var borrowedContexts: [AnyObject?] = []
    func setGating(_ target: SharedConfig.VaultGating,
                   newPIN: String?, currentPIN: String?,
                   presenceContext: AnyObject?) async throws {
        calls.append("setGating(\(target.rawValue))")
        borrowedContexts.append(presenceContext)
        // Every provisioned domain is opened under the current method before the switch.
        for domain in provisioned where !isUnlocked(domain: domain) {
            try await unlock(domain: domain, pin: currentPIN, reason: "change",
                             context: presenceContext)
        }
        // New wrappers written first, superseded keypair deleted after — the crash-safe ordering.
        gatingKeys.insert(target)
        if !crashBeforeDeletingOldKeys { gatingKeys = [target] }
        installGating = target
    }

    func reconcile(domain domainIdentifier: String) {
        calls.append("reconcile:\(domainIdentifier)")
        gatingKeys = gatingKeys.intersection([installGating])
    }

    func populateUnwrappedSlots(for domainIdentifiers: [String], pin: String?) async throws {
        for domain in domainIdentifiers {
            if installGating == .pin, pin == nil { continue }
            guard gatingKeys.contains(installGating) else { continue }
            unlockedDomains.insert(domain)
        }
        calls.append("populate")
    }
    func evictUnwrappedSlots() throws {
        calls.append("evict")
        unlockedDomains.removeAll()
    }
    func evictUnwrappedSlots(for domainIdentifier: String) throws {
        calls.append("evict:\(domainIdentifier)")
        unlockedDomains.remove(domainIdentifier)
    }
}

/// Mutable policy holder, so a test can change what `config` returns after construction.
private final class PolicyBox: @unchecked Sendable {
    var value: VaultLockController.LockPolicy
    init(_ value: VaultLockController.LockPolicy) { self.value = value }
}

final class VaultLockControllerTests: XCTestCase {

    private func makeController(
        policy: VaultLockController.LockPolicy
    ) -> (VaultLockController, FakeGuard, ManualScheduler, ManualEvents) {
        let guardKeys = FakeGuard()
        let scheduler = ManualScheduler()
        let events = ManualEvents()
        let controller = VaultLockController(
            guardKeys: guardKeys, scheduler: scheduler, events: events, config: { policy })
        return (controller, guardKeys, scheduler, events)
    }

    private func policy(enabled: Bool = true, timeout: Int = 3600, screen: Bool = true,
                        logout: Bool = true, restart: Bool = true
    ) -> VaultLockController.LockPolicy {
        .init(enabled: enabled, timeoutSeconds: timeout,
              onScreenLock: screen, onLogout: logout, onRestart: restart)
    }

    /// A controller whose policy can be changed after construction, so the Security screen's
    /// "save then re-arm" sequence can be exercised.
    private func makeMutableController(
        _ initial: VaultLockController.LockPolicy
    ) -> (VaultLockController, FakeGuard, ManualScheduler, ManualEvents,
          (VaultLockController.LockPolicy) -> Void) {
        let guardKeys = FakeGuard()
        let scheduler = ManualScheduler()
        let events = ManualEvents()
        let box = PolicyBox(initial)
        let controller = VaultLockController(
            guardKeys: guardKeys, scheduler: scheduler, events: events,
            config: { box.value })
        return (controller, guardKeys, scheduler, events, { box.value = $0 })
    }

    // MARK: - Master switch

    func testMasterSwitchOffSuppressesEveryTrigger() {
        let (controller, guardKeys, scheduler, events) =
            makeController(policy: policy(enabled: false, timeout: 300))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }
        controller.beginActivityWindow()

        XCTAssertNil(scheduler.scheduledSeconds, "auto-lock off → no idle timer")
        for trigger: VaultLockController.Trigger in [.screenLock, .powerOff, .sessionResign] {
            events.emit(trigger)
        }
        XCTAssertEqual(lockCount, 0, "auto-lock off → no system-event relock")
    }

    func testManualLockIgnoresMasterSwitch() {
        let (controller, guardKeys, _, _) =
            makeController(policy: policy(enabled: false))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        controller.lock()
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"),
                       "an explicit lock is not an auto-lock trigger")
    }

    // MARK: - Arming

    func testArmSystemEventsSubscribesWithoutUnlock() {
        let (controller, guardKeys, _, events) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var trigger: VaultLockController.Trigger?
        controller.onLock = { trigger = $0 }

        // No `beginActivityWindow()`: this is the launch path, where the vaults are already open.
        controller.armSystemEvents()
        events.emit(.screenLock)
        XCTAssertEqual(trigger, .screenLock,
                       "triggers must be live at launch, not only after an unlock ceremony")
    }

    func testArmSystemEventsIsIdempotent() {
        let (controller, guardKeys, _, events) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }

        controller.armSystemEvents()
        controller.armSystemEvents()
        controller.beginActivityWindow()
        events.emit(.screenLock)
        XCTAssertEqual(lockCount, 1, "one relock per event, however often arming is requested")
    }

    func testPolicyDidChangeRearmsIdleTimerToNewTimeout() {
        let (controller, guardKeys, scheduler, _, setPolicy) =
            makeMutableController(policy(timeout: 3600))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        controller.beginActivityWindow()
        XCTAssertEqual(scheduler.scheduledSeconds, 3600)

        setPolicy(policy(timeout: 60))
        controller.policyDidChange()
        XCTAssertEqual(scheduler.scheduledSeconds, 60,
                       "a saved policy must not wait for the next unlock to take effect")
    }

    func testPolicyDidChangeCancelsTimerWhenAutoLockDisabled() {
        let (controller, guardKeys, scheduler, _, setPolicy) =
            makeMutableController(policy(timeout: 300))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        controller.beginActivityWindow()
        XCTAssertEqual(scheduler.scheduledSeconds, 300)

        setPolicy(policy(enabled: false, timeout: 300))
        controller.policyDidChange()
        XCTAssertNil(scheduler.scheduledSeconds, "disarming auto-lock must cancel a live timer")
    }

    /// `currentPolicy()` exists so callers outside the controller — launch reconciliation, which
    /// must decide whether an unlocked vault surviving a logout is a fault or the configured
    /// behaviour — ask ``LockPolicy/allows(_:)`` instead of re-deriving the rule from the flags.
    /// It must therefore read through to config, not a snapshot taken at construction.
    func testCurrentPolicyReadsThroughToLiveConfig() {
        let (controller, _, _, _, setPolicy) = makeMutableController(policy(timeout: 3600))
        XCTAssertEqual(controller.currentPolicy().timeoutSeconds, 3600)

        setPolicy(policy(enabled: false, timeout: 60))
        XCTAssertFalse(controller.currentPolicy().enabled,
                       "a policy edited after construction must be visible to external callers")
        XCTAssertEqual(controller.currentPolicy().timeoutSeconds, 60)
    }

    /// The decision launch reconciliation actually makes: with auto-lock disarmed, a vault left
    /// unlocked across a logout is configured behaviour and must not be relocked at launch.
    func testCurrentPolicyGatesPowerOffTheSameWayDeliveryDoes() {
        let (controller, _, _, _, setPolicy) = makeMutableController(policy(logout: true))
        XCTAssertTrue(controller.currentPolicy().allows(.powerOff))

        setPolicy(policy(enabled: false, logout: true))
        XCTAssertFalse(controller.currentPolicy().allows(.powerOff),
                       "the master switch must disarm the launch-side repair too")
    }

    func testSystemEventUsesPolicyAtDeliveryTime() {
        let (controller, guardKeys, _, events, setPolicy) =
            makeMutableController(policy(screen: false))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }
        controller.armSystemEvents()

        events.emit(.screenLock)
        XCTAssertEqual(lockCount, 0)

        setPolicy(policy(screen: true))
        events.emit(.screenLock)
        XCTAssertEqual(lockCount, 1,
                       "the handler must re-read config, not close over a stale snapshot")
    }

    func testIdleTimeoutLocks() {
        let (controller, guardKeys, scheduler, _) = makeController(policy: policy(timeout: 300))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)

        var locked: VaultLockController.Trigger?
        controller.onLock = { locked = $0 }
        controller.beginActivityWindow()

        XCTAssertEqual(scheduler.scheduledSeconds, 300)
        XCTAssertTrue(guardKeys.isUnlocked(domain: "A"))

        scheduler.fireNow()
        XCTAssertEqual(locked, .idleTimeout)
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"),
                       "every domain's slots must be evicted on idle lock")
    }

    func testZeroTimeoutDisablesIdleTimer() {
        let (controller, _, scheduler, _) = makeController(policy: policy(timeout: 0))
        controller.beginActivityWindow()
        XCTAssertNil(scheduler.scheduledSeconds, "timeout 0 → no idle timer")
    }

    func testNoteActivityRearmsWhenUnlocked() {
        let (controller, guardKeys, scheduler, _) = makeController(policy: policy(timeout: 120))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        controller.noteActivity()
        XCTAssertEqual(scheduler.scheduledSeconds, 120)
    }

    func testNoteActivityIgnoredWhenLocked() {
        let (controller, _, scheduler, _) = makeController(policy: policy(timeout: 120))
        controller.noteActivity()
        XCTAssertNil(scheduler.scheduledSeconds, "locked guard must not arm the idle timer")
    }

    func testScreenLockTriggerRespectsPolicy() {
        let (controller, guardKeys, _, events) = makeController(policy: policy(screen: false))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }
        controller.beginActivityWindow()

        events.emit(.screenLock)
        XCTAssertEqual(lockCount, 0, "screen-lock disabled → no relock")
    }

    /// `willPowerOff` is the only notification logout posts, and it is indistinguishable from
    /// restart and shutdown — so the logout flag alone must arm it. Gating `.powerOff` on
    /// `onRestart` alone made `lockOnLogout` unreachable from any real event.
    func testPowerOffLocksWhenOnlyLogoutIsArmed() {
        let (controller, guardKeys, _, events) =
            makeController(policy: policy(logout: true, restart: false))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var trigger: VaultLockController.Trigger?
        controller.onLock = { trigger = $0 }
        controller.beginActivityWindow()

        events.emit(.powerOff)
        XCTAssertEqual(trigger, .powerOff)
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"))
    }

    /// The mirror case: the restart flag alone must arm the same notification.
    func testPowerOffLocksWhenOnlyRestartIsArmed() {
        let (controller, guardKeys, _, events) =
            makeController(policy: policy(logout: false, restart: true))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var trigger: VaultLockController.Trigger?
        controller.onLock = { trigger = $0 }
        controller.beginActivityWindow()

        events.emit(.powerOff)
        XCTAssertEqual(trigger, .powerOff)
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"))
    }

    func testPowerOffDoesNotLockWhenNeitherFlagIsArmed() {
        let (controller, guardKeys, _, events) =
            makeController(policy: policy(logout: false, restart: false))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }
        controller.beginActivityWindow()

        events.emit(.powerOff)
        XCTAssertEqual(lockCount, 0, "neither logout nor restart armed → no relock")
        XCTAssertTrue(guardKeys.isUnlocked(domain: "A"))
    }

    /// Fast user switching is screen-lock-grade: the desktop is hidden, the process lives on.
    /// It must follow `onScreenLock`, never the logout flag — mapping it to logout let a
    /// switch-out tear down every domain for a session that was coming straight back.
    func testSessionResignFollowsScreenLockFlag() {
        let (controller, guardKeys, _, events) =
            makeController(policy: policy(screen: true, logout: false, restart: false))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var trigger: VaultLockController.Trigger?
        controller.onLock = { trigger = $0 }
        controller.beginActivityWindow()

        events.emit(.sessionResign)
        XCTAssertEqual(trigger, .sessionResign)
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"))
    }

    func testSessionResignSuppressedWhenScreenLockDisabled() {
        let (controller, guardKeys, _, events) =
            makeController(policy: policy(screen: false, logout: true, restart: true))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }
        controller.beginActivityWindow()

        events.emit(.sessionResign)
        XCTAssertEqual(lockCount, 0, "session resign follows the screen-lock flag alone")
    }

    /// The master switch outranks every individual flag, including the two that share
    /// `.powerOff`.
    func testMasterSwitchOffSuppressesPowerOffAndSessionResign() {
        let (controller, guardKeys, _, events) =
            makeController(policy: policy(enabled: false, screen: true,
                                          logout: true, restart: true))
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        var lockCount = 0
        controller.onLock = { _ in lockCount += 1 }
        controller.beginActivityWindow()

        events.emit(.powerOff)
        events.emit(.sessionResign)
        XCTAssertEqual(lockCount, 0, "auto-lock off → neither trigger relocks")
        XCTAssertTrue(guardKeys.isUnlocked(domain: "A"))
    }

    func testManualLockEvictsAndCancelsTimer() {
        let (controller, guardKeys, scheduler, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", unlocked: true)
        controller.beginActivityWindow()

        controller.lock(trigger: .manual)
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"))
        XCTAssertGreaterThan(scheduler.cancelCount, 0)
    }

    /// Locking one vault of several must leave the other vaults' Provider-readable slots alone.
    ///
    /// A vault-wide `evictUnwrappedSlots()` here stripped the still-unlocked vault's keys and made
    /// its Provider fail every materialization.
    func testPerDomainLockEvictsOnlyThatDomainsSlots() {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A", unlocked: true)
        guardKeys.seed("B", unlocked: true)

        controller.evictKeyMaterial(for: ["A"])

        XCTAssertTrue(guardKeys.calls.contains("evict:A"))
        XCTAssertFalse(guardKeys.calls.contains("evict:B"), "B is still unlocked")
        XCTAssertFalse(guardKeys.calls.contains("evict"), "must not evict vault-wide")
        XCTAssertTrue(guardKeys.isUnlocked(domain: "B"), "B keeps serving content")
    }

    /// I5: locking one vault reaches **nothing** belonging to another.
    ///
    /// Under the old install-wide VMK this test asserted the opposite — that the shared key was
    /// dropped on every lock, however few vaults it covered, because retaining it would have let
    /// the locked vault be reopened with no ceremony. Per-domain there is no such key: A's
    /// material is gone and B's is entirely untouched.
    func testPerDomainLockLeavesSiblingKeyMaterialIntact() {
        let (controller, guardKeys, scheduler, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A", unlocked: true)
        guardKeys.seed("B", unlocked: true)
        let bKey = guardKeys.domainKeys["B"]
        controller.beginActivityWindow()

        controller.evictKeyMaterial(for: ["A"])

        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"))
        XCTAssertTrue(guardKeys.isUnlocked(domain: "B"))
        XCTAssertEqual(guardKeys.domainKeys["B"], bKey, "B's domainKey is untouched")
        XCTAssertGreaterThan(scheduler.cancelCount, 0)
    }

    // MARK: - Gating transitions (tasks 47, 51)

    /// Each domain's `domainKey` is its root of trust: every gating change must re-seal the
    /// *same* key, or that domain's wrapped leaves are orphaned.
    func testGatingTransitionsPreserveDomainKeyIdentity() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A")
        let original = guardKeys.domainKeys["A"]

        for target in [SharedConfig.VaultGating.biometric, .pin, .none, .secure, .biometric] {
            try await controller.setGating(target, newPIN: target == .pin ? "1234" : nil,
                                           currentPIN: guardKeys.installGating == .pin ? "1234" : nil)
            XCTAssertEqual(guardKeys.domainKeys["A"], original,
                           "gating → \(target.rawValue) must not change the domainKey")
        }
    }

    /// Exactly one gating keypair exists after every transition.
    func testExactlyOneGatingKeyAfterEveryTransition() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A")

        for target in [SharedConfig.VaultGating.biometric, .pin, .none, .secure] {
            try await controller.setGating(target, newPIN: target == .pin ? "1234" : nil,
                                           currentPIN: guardKeys.installGating == .pin ? "1234" : nil)
            XCTAssertEqual(guardKeys.gatingKeys, [target],
                           "only \(target.rawValue)'s gating keypair may exist")
        }
    }

    /// **I5′ regression guard.** One method change re-seals every domain, and each keeps its
    /// **own** `domainKey` — no leaf secret is ever shared.
    func testReGatingCoversEveryDomainButKeepsKeysDistinct() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A", gating: .pin)
        guardKeys.seed("B", gating: .pin)
        let aKey = guardKeys.domainKeys["A"]
        let bKey = guardKeys.domainKeys["B"]

        try await controller.setGating(.secure, currentPIN: "1234")

        XCTAssertEqual(guardKeys.gating(), .secure, "the method is install-wide")
        XCTAssertEqual(guardKeys.domainKeys["A"], aKey, "A's domainKey is preserved")
        XCTAssertEqual(guardKeys.domainKeys["B"], bKey, "B's domainKey is preserved")
        XCTAssertNotEqual(guardKeys.domainKeys["A"], guardKeys.domainKeys["B"],
                          "no two domains may share a domainKey")
        XCTAssertTrue(guardKeys.isUnlocked(domain: "B"),
                      "every domain is repopulated, not just the first")
    }

    /// With a PIN enrolled there must be no silently-readable path to any `domainKey`.
    /// The `.none` params slot — the one any App Group process can read without a prompt — is
    /// gone, so an unlock with no PIN cannot succeed.
    func testPINGatingLeavesNoSilentPathToTheDomainKey() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A")
        try await controller.setGating(.pin, newPIN: "1234")
        controller.lock()

        XCTAssertFalse(guardKeys.gatingKeys.contains(.none),
                       "the `.none` gating keypair must be deleted when PIN gating is active")

        do {
            try await controller.unlock(domain: "A")
            XCTFail("unlock with no PIN must fail under PIN gating")
        } catch {
            XCTAssertEqual(error as? VaultKeyStoreError, .pinRequired)
        }
        XCTAssertFalse(guardKeys.isUnlocked(domain: "A"))

        try await controller.unlock(domain: "A", pin: "1234")
        XCTAssertTrue(guardKeys.isUnlocked(domain: "A"))
    }

    /// Changing a PIN on a locked vault works: `setGating` unlocks under the current method
    /// first, and the same `domainKey` is re-sealed so leaf access is unaffected.
    func testPINChangeFromLockedPreservesDomainAccess() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A")
        try await controller.setGating(.pin, newPIN: "1111")
        let key = guardKeys.domainKeys["A"]
        controller.lock()

        try await controller.setGating(.pin, newPIN: "2222", currentPIN: "1111")

        XCTAssertEqual(guardKeys.domainKeys["A"], key,
                       "a PIN change must not re-mint the domainKey")
        XCTAssertTrue(guardKeys.calls.contains("populate"),
                      "domain slots must be repopulated after the change")
    }

    /// A method change repopulates **every** domain, not just one — otherwise
    /// N−1 vaults stay locked behind a method they no longer answer to.
    func testGatingChangeRepopulatesEveryDomain() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B", "C"] }
        guardKeys.seed("A")
        guardKeys.seed("B")
        guardKeys.seed("C")
        controller.lock()

        try await controller.setGating(.biometric)

        XCTAssertTrue(guardKeys.isUnlocked(domain: "A"))
        XCTAssertTrue(guardKeys.isUnlocked(domain: "B"))
        XCTAssertTrue(guardKeys.isUnlocked(domain: "C"))
    }

    /// Launch must never run a gating ceremony. Reconciliation is limited to dropping a stale
    /// gating keypair — a promptless keychain operation. Re-deriving slots was tried here and
    /// removed: backfilling one needs the `domainKey`, which needs the ceremony, so under
    /// `.biometric`/`.secure` there is no silent path and launch prompted for Touch ID
    /// unsolicited. A domain missing a slot surfaces in the UI as not-ready instead, and the
    /// user's own Lock/Unlock repopulates it.
    func testLaunchReconcileNeverOpensADomain() async {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A", gating: .biometric, unlocked: true)

        controller.reconcileAtLaunch()

        XCTAssertFalse(guardKeys.calls.contains("populate"),
                       "launch must not populate slots — that path prompts under biometric gating")
        XCTAssertFalse(guardKeys.calls.contains { $0.hasPrefix("unlock:") },
                       "launch must run no unlock ceremony")
    }

    /// Crash-window recovery: the new wrappers are written before the superseded gating keypair
    /// is deleted, so a crash leaves a stale one. Launch reconciliation removes it — and only
    /// ever the non-active one, so a vault can never be bricked.
    func testReconcileDropsStaleGatingKeyAfterCrash() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A")
        guardKeys.crashBeforeDeletingOldKeys = true
        try await controller.setGating(.biometric)
        XCTAssertEqual(guardKeys.gatingKeys, [.none, .biometric],
                       "crash window leaves two keypairs")

        guardKeys.crashBeforeDeletingOldKeys = false
        controller.reconcileAtLaunch()

        XCTAssertEqual(guardKeys.gatingKeys, [.biometric],
                       "reconcile must drop the superseded keypair and keep the active one")
    }

    /// A gating change on a locked vault unlocks under the *current* gating first, rather than
    /// minting a new key — which would orphan every wrapped leaf.
    func testGatingChangeWhileLockedUnlocksUnderCurrentGating() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A"] }
        guardKeys.seed("A")
        try await controller.setGating(.biometric)
        let key = guardKeys.domainKeys["A"]
        controller.lock()

        try await controller.setGating(.none)

        XCTAssertEqual(guardKeys.domainKeys["A"], key,
                       "the domainKey must be re-sealed, never re-minted")
        XCTAssertTrue(guardKeys.calls.contains("unlock:A(biometric)"),
                      "must unlock under the *current* gating before re-wrapping")
    }

    /// Unlocking one vault must not touch its siblings.
    ///
    /// `onUnlock` drives the host's domain reconnect. When it fired install-wide, a single
    /// "Unlock Vault" reconnected every domain — including vaults whose gating ceremony was
    /// never run — so one ceremony effectively opened the whole install.
    func testUnlockOneDomainNotifiesAndOpensOnlyThatDomain() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A")
        guardKeys.seed("B")
        var notified: [[String]] = []
        controller.onUnlock = { notified.append($0) }

        try await controller.unlock(domain: "A")

        XCTAssertEqual(notified, [["A"]], "only the unlocked domain may be reconnected")
        XCTAssertEqual(guardKeys.unlockedDomains, ["A"], "B must stay locked")
        XCTAssertFalse(guardKeys.calls.contains("unlock:B(none)"),
                       "no ceremony may run for a sibling vault")
    }

    /// The batched unlock reports exactly the domains it was asked for.
    func testUnlockAllNotifiesEveryDomain() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A")
        guardKeys.seed("B")
        var notified: [[String]] = []
        controller.onUnlock = { notified.append($0) }

        try await controller.unlock(domains: ["A", "B"])

        XCTAssertEqual(notified, [["A", "B"]])
        XCTAssertEqual(guardKeys.unlockedDomains, ["A", "B"])
    }

    /// A PIN entered to open one vault must not open its siblings.
    ///
    /// The PIN screen is reached by a route that once dropped the requested domain, so
    /// `submitUnlockPIN` unlocked every configured vault. The scope now travels with the
    /// request: a correct PIN authorises the vaults it was entered for and no others.
    func testScopedPINUnlockLeavesSiblingsLocked() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A", gating: .pin)
        guardKeys.seed("B", gating: .pin)
        var notified: [[String]] = []
        controller.onUnlock = { notified.append($0) }

        try await controller.unlock(domains: ["A"], pin: "1234")

        XCTAssertEqual(guardKeys.unlockedDomains, ["A"], "B must stay locked under PIN gating")
        XCTAssertEqual(notified, [["A"]], "only the requested vault may be reconnected")
    }

    /// An empty scope is a no-op, not an install-wide unlock.
    func testEmptyScopeUnlocksNothing() async throws {
        let (controller, guardKeys, _, _) = makeController(policy: policy())
        controller.domainIdentifiers = { ["A", "B"] }
        guardKeys.seed("A")
        guardKeys.seed("B")
        var notified: [[String]] = []
        controller.onUnlock = { notified.append($0) }

        try await controller.unlock(domains: [])

        XCTAssertTrue(guardKeys.unlockedDomains.isEmpty)
        XCTAssertTrue(notified.isEmpty)
    }
}
