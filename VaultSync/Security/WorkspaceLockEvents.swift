/// Production ``SystemLockEvents`` for the app process.
///
/// `NSWorkspace` and distributed-notification names deliver screen-lock, session-resign and
/// power-off events. App-side because `Provider.appex` has no `NSWorkspace`; it evicts slots
/// directly instead. Its sibling seam, ``LockScheduler``, is implemented next door by
/// `SystemLockScheduler`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit
import Common
import Foundation
import os

/// Subscribes to `NSWorkspace` lock / session / power notifications.
final class WorkspaceLockEvents: SystemLockEvents {
    private var tokens: [NSObjectProtocol] = []
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "vault-lock")

    func start(_ handler: @escaping (VaultLockController.Trigger) -> Void) {
        stop()
        log.info("🚪 entry point: WorkspaceLockEvents.start — subscribing to screen-lock / session / power-off notifications")
        let center = NSWorkspace.shared.notificationCenter
        let dnc = DistributedNotificationCenter.default()

        // Screen lock / screensaver (distributed notifications; not in NSWorkspace).
        for name in ["com.apple.screenIsLocked", "com.apple.screensaver.didstart"] {
            tokens.append(dnc.addObserver(forName: Notification.Name(name), object: nil,
                                          queue: .main) { [log] _ in
                log.info("🚪 entry point: WorkspaceLockEvents \(name, privacy: .public) → .screenLock")
                handler(.screenLock)
            })
        }
        // Fast user switching — the session switches out, the process lives on, and the user is
        // coming back. Delivered as its own trigger so the policy gates it on the screen-lock
        // flag rather than the logout one: a user who armed logout-only no longer relocks on a
        // switch-out, and a switch-out no longer stands in for the logout event it is not.
        //
        // Known limitation, deliberately unaddressed here: gating is all this remap changes.
        // `onLock` discards the `Trigger` (see `AppDelegate.onLock`) and `performLockAll`
        // branches on ``SharedConfig/vaultLockMethod`` alone, so with `lockOnScreenLock` armed
        // and `.lockAndRemove` configured a switch-out still unregisters every domain and the
        // vaults are gone from Finder when the user switches back. Degrading a switch-out to a
        // disconnect-only lock would need the trigger carried through to the removal decision.
        tokens.append(center.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification,
                                         object: nil, queue: .main) { [log] _ in
            log.info("🚪 entry point: WorkspaceLockEvents sessionDidResignActive (user switch) → .sessionResign")
            handler(.sessionResign)
        })
        // One notification, three meanings. `willPowerOff` fires for logout, restart and
        // shutdown alike and carries no `userInfo` to separate them, so it is delivered as a
        // single `.powerOff` trigger and the policy satisfies whichever flag the user armed —
        // gating it on one alone makes the other unreachable.
        tokens.append(center.addObserver(forName: NSWorkspace.willPowerOffNotification,
                                         object: nil, queue: .main) { [log] _ in
            log.info("🚪 entry point: WorkspaceLockEvents willPowerOff (logout/restart/shutdown) → .powerOff")
            handler(.powerOff)
        })
    }

    func stop() {
        let center = NSWorkspace.shared.notificationCenter
        let dnc = DistributedNotificationCenter.default()
        for token in tokens {
            center.removeObserver(token)
            dnc.removeObserver(token)
        }
        tokens.removeAll()
    }
}
