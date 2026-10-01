/// The lock-on-quit rule in ``SharedConfig``.
///
/// The rule is shared by the Security screen (which shows the checkbox forced on and read-only)
/// and `AppDelegate.applicationWillTerminate` (which actually evicts key material). Testing it
/// here is what keeps those two from drifting into disagreeing about when a quit relocks.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
@testable import Common

final class QuitLockPolicyTests: XCTestCase {

    /// A config with auto-lock armed and every trigger off — the baseline the cases below vary.
    private func armedConfigWithNoTriggers() -> SharedConfig {
        var c = SharedConfig()
        c.autoLockEnabled = true
        c.lockOnScreenLock = false
        c.lockOnLogout = false
        c.lockOnRestart = false
        c.lockTimeoutSeconds = 0
        c.lockOnQuit = false
        return c
    }

    func testNoTriggersDoesNotForceQuitLock() {
        let c = armedConfigWithNoTriggers()
        XCTAssertFalse(c.quitLockIsForced)
        XCTAssertFalse(c.locksOnQuit, "quit lock left off when nothing else is armed")
    }

    /// Each trigger independently forces the quit lock: quitting removes the process that would
    /// have performed the relock, so a vault set to lock on any event must also lock on quit.
    func testEachTriggerForcesQuitLock() {
        var screen = armedConfigWithNoTriggers()
        screen.lockOnScreenLock = true
        XCTAssertTrue(screen.quitLockIsForced)
        XCTAssertTrue(screen.locksOnQuit)

        var logout = armedConfigWithNoTriggers()
        logout.lockOnLogout = true
        XCTAssertTrue(logout.quitLockIsForced)
        XCTAssertTrue(logout.locksOnQuit)

        var restart = armedConfigWithNoTriggers()
        restart.lockOnRestart = true
        XCTAssertTrue(restart.quitLockIsForced)
        XCTAssertTrue(restart.locksOnQuit)

        var idle = armedConfigWithNoTriggers()
        idle.lockTimeoutSeconds = 300
        XCTAssertTrue(idle.quitLockIsForced, "an idle timeout is a trigger like any other")
        XCTAssertTrue(idle.locksOnQuit)
    }

    /// "Never" (0 seconds) is not a trigger, so it forces nothing.
    func testIdleNeverIsNotATrigger() {
        var c = armedConfigWithNoTriggers()
        c.lockTimeoutSeconds = 0
        XCTAssertFalse(c.quitLockIsForced)
    }

    /// The quit lock can be chosen on its own, without any other trigger.
    func testQuitLockAloneIsHonoured() {
        var c = armedConfigWithNoTriggers()
        c.lockOnQuit = true
        XCTAssertFalse(c.quitLockIsForced, "chosen, not forced")
        XCTAssertTrue(c.locksOnQuit)
    }

    /// Disarming auto-lock disables the quit relock too — quit is an automatic trigger, and the
    /// user has opted out of automatic relocking. A forced flag must not survive that opt-out.
    func testDisabledAutoLockSuppressesQuitLock() {
        var c = armedConfigWithNoTriggers()
        c.autoLockEnabled = false
        c.lockOnQuit = true
        c.lockOnScreenLock = true

        XCTAssertTrue(c.quitLockIsForced, "the forcing rule is about triggers, not the master switch")
        XCTAssertFalse(c.locksOnQuit, "auto-lock off means no automatic relock at all")
    }

    /// The shipped default relocks on quit: the safe end of the trade, and consistent with the
    /// other triggers, which also default on.
    func testDefaultLocksOnQuitWhenAutoLockIsArmed() {
        var c = SharedConfig()
        c.autoLockEnabled = true
        XCTAssertTrue(c.locksOnQuit)
    }

    /// Any armable system trigger implies ``SharedConfig/locksOnQuit`` — exhaustively, over every
    /// combination of the five flags that decide it.
    ///
    /// This is the invariant `AppDelegate.applicationShouldTerminate` leans on: its `armed`
    /// predicate ORs `locksOnQuit` with an in-flight system lock, and that second clause could
    /// only ever decide the outcome if some trigger could arm *without* forcing the quit lock.
    /// Setting `lockAllTask` requires ``VaultLockController/LockPolicy/allows(_:)`` to pass,
    /// which needs `autoLockEnabled` plus one of screen-lock / logout / restart / idle-timeout
    /// — precisely the disjunction ``SharedConfig/quitLockIsForced`` tests. Decoupling the two
    /// would leave a logout able to reply `.terminateNow` mid-unregister, so this fails loudly
    /// if the subsumption is ever broken.
    func testAnyArmedTriggerImpliesQuitLock() {
        for autoLock in [false, true] {
            for screen in [false, true] {
                for logout in [false, true] {
                    for restart in [false, true] {
                        for timeout in [0, 3600] {
                            var c = SharedConfig()
                            c.autoLockEnabled = autoLock
                            c.lockOnScreenLock = screen
                            c.lockOnLogout = logout
                            c.lockOnRestart = restart
                            c.lockTimeoutSeconds = timeout
                            // Held off deliberately: the subsumption must come from the
                            // triggers alone, not from the user also ticking quit.
                            c.lockOnQuit = false

                            // Mirrors `LockPolicy.allows(_:)` for the four system triggers.
                            let anyTriggerArmed =
                                autoLock && (screen || logout || restart || timeout > 0)
                            guard anyTriggerArmed else { continue }

                            let shape = "autoLock=\(autoLock) screen=\(screen) "
                                + "logout=\(logout) restart=\(restart) timeout=\(timeout)"
                            XCTAssertTrue(c.locksOnQuit,
                                          "trigger armed without forcing the quit lock — " + shape)
                        }
                    }
                }
            }
        }
    }
}
