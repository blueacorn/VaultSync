/// Application lifecycle, server startup, and domain management orchestration
//
//  Abstract:
//  A delegate that manages the app's life cycle.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Cocoa
import FileProvider
import Common
import os.log
import Extension
import FinderSync
import Server
import SwiftUI

extension NSFileProviderDomain {
    var prettyDescription: String {
        return "\(displayName) (\(identifier.rawValue.suffix(12)))"
    }
}

private actor Notifier {
    let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "notifier")

    var itemsToNotify: Set<DomainService.ItemIdentifier> = []

    func notify(for itemIdentifier: DomainService.ItemIdentifier) {
        itemsToNotify.insert(itemIdentifier)
    }

    func serverChangeReceived(_ entries: [DomainEntry]) async {
        guard !self.itemsToNotify.isEmpty else { return }
        for entry in entries {
            guard let manager = NSFileProviderManager(for: entry.domain) else { continue }
            logger.debug("🔆 notifying \(entry.domain.prettyDescription) for changes on \(self.itemsToNotify)")
            do {
                try await manager.signalEnumerator(for: .workingSet)
            } catch let error as NSError {
                logger.debug("❌ failed to signal working set for \(entry.domain.prettyDescription): \(error)")
            }
        }
        self.itemsToNotify.removeAll()
    }

    func signalItems(_ entries: [DomainEntry]) async {
        for entry in entries {
            guard let manager = NSFileProviderManager(for: entry.domain) else { continue }
            logger.debug("🔆 notifying \(entry.domain.prettyDescription) for auth status change")
            if entry.authenticated || UserDefaults.sharedContainerDefaults.ignoreAuthentication {
                do {
                    try await manager.signalErrorResolved(NSFileProviderError(.notAuthenticated))
                } catch let error as NSError {
                    logger.error("❌ failed to signal authentication error resolved for \(entry.domain.prettyDescription): \(error)")
                }
            } else {
                // Notify the workingSet because FileProvider needs to save the new unauthenticated state.
                do {
                    try await manager.signalEnumerator(for: .workingSet)
                } catch let error as NSError {
                    logger.error("❌ failed to signal working set for \(entry.domain.prettyDescription): \(error)")
                }
            }
        }
    }

}

@MainActor	class AppDelegate: NSObject, NSApplicationDelegate, NSXPCListenerDelegate {

    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "app")

    /// Menu-bar status item + popover controller (the primary UI).
    private var statusItemController: StatusItemController!
    /// Observable state hub bridging orchestration to the SwiftUI popover.
    let appModel = AppModel()
    /// Lazily-created Tweaks settings window.
    private var tweaksWindowController: NSWindowController?
    /// Per-domain key store: each domain owns a `domainKey`, always wrapped under
    /// exactly one gating key of its own. Shared process-wide so provisioning and unlock see one
    /// lock state per domain.
    let vaultKeys = VaultKeyStore.shared

    /// Vault lock policy orchestrator: gating changes, unlock ceremony, idle +
    /// system-event relock. Wired to disconnect/reconnect the File Provider domains.
    lazy var vaultLock: VaultLockController = {
        let controller = VaultLockController(
            guardKeys: vaultKeys,
            scheduler: SystemLockScheduler(),
            events: WorkspaceLockEvents(),
            config: {
                let c = SharedConfigStore.shared.snapshot()
                return VaultLockController.LockPolicy(
                    enabled: c.autoLockEnabled,
                    timeoutSeconds: c.lockTimeoutSeconds,
                    onScreenLock: c.lockOnScreenLock,
                    onLogout: c.lockOnLogout,
                    onRestart: c.lockOnRestart)
            })
        // Sourced from config, not `domainEntries`: config.json is the authoritative list of
        // domains, and it is a synchronous read. `domainEntries` is the *UI* list — rebuilt from
        // the OS domain registry, which arrives only on a change notification, so at launch it is
        // still empty and a slot reconcile against it would silently do nothing.
        controller.domainIdentifiers = { Array(SharedConfigStore.shared.allAccounts().keys) }
        // Routed through `lockAll` — the same method-aware path as the menu and the quit lock —
        // so a system trigger cannot drift from a user-initiated lock. A bare
        // `disconnectAllDomains` here ignored `vaultLockMethod` entirely: under `.lockAndRemove`
        // a logout or screen lock left the domains registered, so `fileproviderd` kept
        // `Provider.appex` resident and the vault stayed in Finder.
        //
        // Unattended, like the quit path: there is no user to answer a confirmation on a logout
        // or a screen lock, so removal degrades to `.preserveDirtyUserData` rather than
        // discarding unsynced edits the user never opted into losing.
        // Every configured domain, deliberately: `lock(trigger:)` evicts key material *before*
        // calling this, so `isUnlocked` already reports false everywhere and filtering on it
        // would select nothing. The triggers are install-wide policy anyway — their expiry
        // locks the lot — so the configured account list is the right target.
        controller.onLock = { [weak self] _ in
            guard let self else { return }
            // Recorded, not fire-and-forget: a logout delivers this trigger *and* terminates the
            // app moments later, so `applicationShouldTerminate` must be able to join this work
            // rather than replying while the unregister is still in flight. An orphaned task here
            // is exactly how a logout came to evict key material and nothing else.
            MainActor.assumeIsolated {
                self.trackSystemLock(domainIDs: Array(SharedConfigStore.shared.allAccounts().keys),
                                     mode: .preserveDirtyUserData)
            }
        }
        controller.onUnlock = { [weak self] domainIDs in self?.reconnectDomains(ids: domainIDs) }
        return controller
    }()

    /// Publishing only. Slot population is **not** driven from here: `provisionDomain` writes a
    /// new domain's unwrapped slots itself, while it still holds the freshly minted `domainKey`,
    /// so reconciling on a list change re-derived what was already correct. It also reconciled on
    /// *removal* — a lock-and-remove changes this list — which pulled every sibling that still had
    /// slots into a batch populate under one presence ceremony, i.e. locking one vault could
    /// re-open another the user never asked about. Launch is the only honest reconcile point; see
    /// ``applicationDidFinishLaunching(_:)``.
    /// **UI only. Never the authority on which vaults exist.**
    ///
    /// `SharedConfigStore.shared.allAccounts()` is the authoritative enumeration: it is
    /// config.json, a synchronous read, correct from the first instruction of launch. This list
    /// is a view model — rebuilt from an OS domain-registry notification, carrying KVO
    /// properties, `Progress` objects and formatted status strings for the popover. It is
    /// **empty until the popover is first opened**, and its `locked` flag asks whether Finder is
    /// disconnected, which is not the same question as whether a vault still holds key material.
    ///
    /// So: enumerate from `SharedConfig`, ask ``vaultKeys`` about key state, and use these
    /// entries only to render UI or as a cache of already-resolved `NSFileProviderDomain`s (see
    /// ``lockTargets(for:)``, which prefers a live entry but rebuilds from config when there is
    /// none). Driving a lock, a quit, or any other security operation off this list means it
    /// silently does nothing whenever the popover has not been opened — which is exactly how
    /// lock-on-quit and lock-on-logout came to skip their work.
    @objc dynamic var domainEntries = [DomainEntry]() {
        didSet { appModel.setDomains(domainEntries) }
    }
    @objc dynamic var userDefaultsController = NSUserDefaultsController(defaults: UserDefaults.sharedContainerDefaults, initialValues: nil)
    private var configMirror: SharedConfigUserDefaultsMirror?
    /// Whether the quit lock is already running, so a second `terminate` does not start it twice.
    private var isApplyingQuitLock = false
    /// Whether the deferred termination has been released, so the teardown and its timeout
    /// cannot both reply.
    private var hasRepliedToTerminate = false
    /// The in-flight ``lockAll(domainIDs:mode:)``, so concurrent triggers coalesce onto one run
    /// rather than unregistering the same domains twice (a logout fires both a system trigger
    /// and a terminate).
    private var lockAllTask: Task<Void, Never>?
    /// Live signal sources for the catchable termination signals.
    ///
    /// Retained for the process lifetime: a `DispatchSourceSignal` stops delivering as soon as it
    /// is released, so dropping these would silently restore the default disposition — the
    /// process dying in the kernel with no lock applied, which is the bug this exists to close.
    private var terminationSignalSources: [DispatchSourceSignal] = []
    let queue = DispatchQueue(label: "notify queue")
    private let notifier = Notifier()

    /// Legacy MainMenu.xib debug actions operated on the table's selected row. With the
    /// table gone they fall back to the first domain (debug-only convenience).
    private var selectedEntry: DomainEntry? { domainEntries.first }

    func setupDomainPipe() async {
        await setupDomainPipeAsync(notification: NotificationCenter.default.notifications(named: .fileProviderDomainDidChange))
        await setupDomainPipeAsync(notification: DistributedNotificationCenter.default().notifications(named: .accountsDidChange, object: nil))
    }

    func setupDomainPipeAsync(notification: NotificationCenter.Notifications) async {
        let domainAccounts = notification.map { _ -> ([NSFileProviderDomain], [String: DomainAccount]) in
            let domains: [NSFileProviderDomain] = try await NSFileProviderManager.domains()
            // Source the domain↔backend binding from SharedConfig, not a ListAccount RPC.
            let accounts: [String: DomainAccount] = SharedConfigStore.shared.allAccounts()
            return (domains, accounts)
        }
        Task {
            do {
                for try await value in domainAccounts {
                    await self.updateDomains(value)
                }
            } catch {
                handleDomainPipeError(error)
            }
        }
    }

    /// Re-read the domain list and republish it, without waiting for the change notification.
    ///
    /// The domain pipe normally reacts to `.fileProviderDomainDidChange`, but lock/unlock adds
    /// and removes domains itself and needs the UI consistent immediately afterwards.
    @MainActor
    func refreshDomainsFromSystem() async {
        let domains = (try? await NSFileProviderManager.domains()) ?? []
        await updateDomains((domains, SharedConfigStore.shared.allAccounts()))
    }

    func handleDomainPipeError(_ error: Error) {
        let retry = {
            DispatchQueue.main.asyncAfter(deadline: DispatchTime.now().advanced(by: .seconds(3))) {
                Task {
                    await self.setupDomainPipe()
                }
            }
        }
        switch error {
        case NSFileProviderError.providerNotFound:
            logger.error("couldn't find embedded provider")
            retry()
        case URLError.cannotConnectToHost:
            logger.error("couldn't connect to host")
            retry()
        default:
            self.presentError(error)
        }
    }

    var versionString: String {
        let shortVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString").map { "\($0)" } ?? "unknown"
        let version = Bundle.main.object(forInfoDictionaryKey: kCFBundleVersionKey as String).map { "\($0)" } ?? "unknown"
        return "\(shortVersion) (\(version))"
    }

    let notifyThrottle: Throttle

    let databaseURL = try! FileManager().url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        .appendingPathComponent("files.db")
    let builtinServer: StandaloneServer
    /// Backend-agnostic provisioning service passed to domain UI controllers.
    private(set) var provisioningService: any DomainProvisioningService = NoOpProvisioningService()
    /// Backend-agnostic full-resource teardown run when a domain is deleted.
    private(set) var deprovisioningService: any DomainDeprovisioningService = NoOpDeprovisioningService()

    @MainActor
    override init() {
        notifyThrottle = Throttle(timeout: .milliseconds(500), "notify throttle")
        builtinServer = StandaloneServer(databaseURL)

        super.init()

        // Route by backend: only emulator-backed domains have a StandaloneServer account row.
        // A OneDrive vault must never reach the emulator service (its server starts lazily and
        // may have no database open).
        provisioningService = BackendRoutingProvisioningService(
            services: [.emulator: EmulatorProvisioningService(server: builtinServer),
                       .oneDrive: OneDriveProvisioningService()])
        deprovisioningService = DefaultDomainDeprovisioningService.standard(
            configStore: .shared,
            tokenSignOut: { try await MSALTokenStore.shared.signOut(domainIdentifier: $0) },
            backendResourceDestroy: { try BackendResourceCleanup.destroy(domainID: $0, backend: $1) },
            backendResourceEmpty: { try BackendResourceCleanup.empty(domainID: $0, backend: $1) }
        )

        builtinServer.onAccountsLoaded = { [weak self] in
            // Bookmarks are resolved from SharedConfig; re-run on server load.
            self?.updateSecurityScopedAccess(for: SharedConfigStore.shared.allAccounts())
        }

        // The StandaloneServer (port 24680) only backs emulator ("local Server") domains.
        // OneDrive (and other cloud) domains route through their own client, so when no
        // emulator domain is configured there is nothing to serve — starting it would just
        // hold the port and collide with a second instance / the test host ("Address already
        // in use"). Skip the bind in that case, but still resolve security-scoped bookmarks.
        if Self.hasEmulatorDomain() {
            do {
                try builtinServer.run()
            } catch let error {
                presentError(error)
            }
        } else {
            logger.info("no emulator domain configured — not starting StandaloneServer")
            builtinServer.onAccountsLoaded?()
        }

        notifyThrottle.handler = { [weak self] in
            guard let strongSelf = self else {
                return
            }
            Task {
                await strongSelf.serverChangeReceived()
            }
        }
        notifyThrottle.resume()

        DistributedNotificationCenter.default().addObserver(self, selector: #selector(AppDelegate.itemsChanged(_:)),
                                                            name: .itemsChanged, object: nil, suspensionBehavior: .deliverImmediately)

        DistributedNotificationCenter.default().addObserver(self, selector: #selector(AppDelegate.progressDidChange(_:)),
                                                            name: .progressDidChange, object: nil, suspensionBehavior: .deliverImmediately)

        Task {
            await setupDomainPipe()
            NotificationCenter.default.post(Notification(name: NSNotification.Name.fileProviderDomainDidChange))
            DistributedNotificationCenter.default().post(Notification(name: .accountsDidChange))
        }
    }

    @objc
    func itemsChanged(_ notification: Notification) {
        guard let object = notification.object as? String,
              let id = Int64(object) else { return }
        Task { await notifier.notify(for: DomainService.ItemIdentifier(id)) }
        notifyThrottle.signal()
    }

    /// Provider relayed a progress-snapshot change for a domain. Read the snapshot
    /// from the App Group store and publish it into the menu-bar model on the main actor.
    @objc
    func progressDidChange(_ notification: Notification) {
        guard let domainID = notification.object as? String else { return }
        let snapshot = ProgressStore.shared.snapshot(for: domainID)
        Task { @MainActor in
            self.appModel.setSnapshot(snapshot, for: domainID)
        }
    }

    nonisolated func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Sudden termination lets macOS kill the process with `exit()`, skipping
        // `applicationShouldTerminate` entirely — which silently skips the quit lock and every
        // log line on that path. `Info.plist` already opts out, but frameworks re-enable it at
        // runtime (a plain `enableSuddenTermination` from any dependency is enough), so the
        // opt-out is asserted here as well: the quit lock must not depend on a plist default
        // that something else can flip out from under it.
        ProcessInfo.processInfo.disableSuddenTermination()

        // Initialise the shared App Group UserDefaults (host-local keys) and seed the
        // cross-process JSON store from any pre-existing UserDefaults values. Keys with
        // no live XIB bindings are stripped from the suite plist so the Provider reads
        // exclusively through SharedConfigStore. XIB-bound keys
        // (syncChildrenBeforeParentMove) remain in UserDefaults and are kept in sync with
        // the store by ``SharedConfigUserDefaultsMirror``.
        let defaults = UserDefaults.sharedContainerDefaults
        SharedConfigStore.shared.seedFromUserDefaultsIfNeeded(defaults)
        for key in [
            "hostname", "secrets", "offline", "domainVersions", "configEpoch", "featureFlag",
            "userInteractionSuppressedIdentifiers", "blockedProcesses",
            "supportBRM",
            "minFileSizeForBRM", "unalignedBRMResponse", "BRMChunkSizeMB"
        ] {
            defaults.removeObject(forKey: key)
        }

        Task { @MainActor in
            self.configMirror = SharedConfigUserDefaultsMirror(defaults: defaults)
        }

        Task { @MainActor in
            // Catchable kill signals route to the same lock-and-quit path as a menu Quit.
            // Armed before the vault reconcile below so there is no launch window in which a
            // `killall` would take the default disposition and skip the lock entirely.
            self.installTerminationSignalHandlers()
        }

        Task { @MainActor in
            // A crash between writing a new `domainKey` wrapper and deleting the superseded
            // gating key leaves the stale key behind; drop it before anything can unlock
            // through it.
            vaultLock.reconcileAtLaunch()
            // Arm the screen-lock / logout / restart observers for the whole launch, not just
            // for sessions in which an unlock ceremony happened to run. A menu-bar agent that
            // starts with its vaults already open would otherwise have no triggers at all.
            vaultLock.armSystemEvents()
            // After the vault reconcile above, so the lock state this reads is settled.
            await self.reconcileRemovedDomainsAtLaunch()
        }

        Task { @MainActor in
            // Menu-bar agent: no persistent window. The status item hosts the popover UI.
            appModel.actions = self
            statusItemController = StatusItemController(model: appModel)
            appModel.setDomains(domainEntries)
            // Seeds `vaultOrphaned` before the first icon render, so a missing vault key shows as
            // the fault badge from launch rather than only once the popover is opened.
            appModel.refreshVaultReadiness()
            logger.info("🌅  VaultSync \(self.versionString) started")
        }
    }

    /// Finish any relock that the previous exit left incomplete.
    ///
    /// The teardown on the quit path is asynchronous and races a deadline the app does not
    /// control: a logout allows only seconds before `SIGTERM`, and `handleTerminationSignal`
    /// cannot extend that grace period. `fileproviderd` compounds it by invalidating
    /// `Provider.appex` milliseconds after `willPowerOff`, which makes `NSFileProviderManager`
    /// removal fail outright however much of the budget is left. Either way the vault comes back
    /// in whatever half-locked state the exit reached.
    ///
    /// So the invariant is restored at launch rather than relying on the exit path completing.
    /// What that invariant *is* depends on the configured method, so each is reconciled to its
    /// own steady state:
    ///
    /// - ``VaultLockMethod/lockAndRemove``: a locked vault must have no registered domain. A
    ///   domain left in Finder means `fileproviderd` relaunches `Provider.appex` against a
    ///   locked vault, where it answers `notAuthenticated` for every enumeration — the exact
    ///   state lock-and-remove exists to prevent. Removal *and* the local-data teardown the
    ///   interrupted quit skipped.
    /// - ``VaultLockMethod/lock``: a registered-but-locked domain is the correct steady state, so
    ///   the domain stays. What can be wrong is the key material: a vault still unlocked here was
    ///   never relocked on the way out, leaving its slots populated across the logout. Locking it
    ///   restores the guarantee the exit failed to deliver.
    ///
    /// Both are gated on the relock policy being armed at all. With auto-lock off, an unlocked
    /// vault surviving a logout is the configured behaviour, not a fault to repair.
    @MainActor
    private func reconcileRemovedDomainsAtLaunch() async {
        let domains = (try? await NSFileProviderManager.domains()) ?? []
        guard !domains.isEmpty else { return }
        let accounts = SharedConfigStore.shared.allAccounts()
        let config = SharedConfigStore.shared.snapshot()

        if config.vaultLockMethod != .lockAndRemove {
            // `.lock`: leave every domain registered and relock whatever the exit left open.
            //
            // Gated on the same policy the system triggers honour, read through the controller so
            // the arming rule cannot drift from the one in ``VaultLockController/LockPolicy``. The
            // trigger is `.powerOff` because that is the event whose handling was interrupted —
            // this is that lock completing late, not a new policy decision.
            let policy = vaultLock.currentPolicy()
            guard policy.allows(.powerOff) else { return }
            let stillUnlocked = domains.map(\.identifier.rawValue)
                .filter { accounts[$0] != nil && vaultKeys.isUnlocked(domain: $0) }
            guard !stillUnlocked.isEmpty else { return }
            logger.info("🧹 \(stillUnlocked.count) vault(s) left unlocked by an interrupted relock; locking")
            await confirmedLockAction(domainIDs: stillUnlocked)
        } else {
            for domain in domains {
                let id = domain.identifier.rawValue
                // Only vaults this app manages, and only those still locked. An unlocked domain was
                // restored by a legitimate unlock and must be left alone.
                guard let account = accounts[id], !vaultKeys.isUnlocked(domain: id) else { continue }
                logger.info("🧹 \(account.displayName) left registered by an interrupted lock-and-remove; removing")
                let entry = DomainEntry(domain: domain, account: account, uploadProgress: nil,
                                        downloadProgress: nil, isRemoved: false)
                // `.preserveDirtyUserData` to match the quit path: the removal this completes was
                // started with unsynced edits preserved, and finishing it must not discard them.
                //
                // Routed through `performLockAndRemove` rather than `removeDomain` so the local-data
                // teardown runs alongside the removal. The quit path clears the caches itself now,
                // so this is normally a cheap re-clear of already-empty stores — but it must stay:
                // the quit may have been cut short by `SIGTERM` before its teardown ran at all,
                // and `empty` is idempotent, so repeating it is the safe half of that trade.
                await performLockAndRemove(entry, mode: .preserveDirtyUserData)
            }
        }
        await refreshDomainsFromSystem()
    }

    /// Route the catchable termination signals through the normal quit path.
    ///
    /// AppKit answers the `kAEQuitApplication` Apple Event, not POSIX signals, so a `SIGTERM`
    /// took its default disposition and killed the process in the kernel: neither
    /// ``applicationShouldTerminate(_:)`` nor ``applicationWillTerminate(_:)`` ran, and the vault
    /// was left with its unwrapped slots intact and its domains registered — a worse outcome
    /// than a logout, because not even the synchronous eviction happened. That covers `killall`,
    /// a plain `kill`, and the `SIGTERM`-then-`SIGKILL` sequence `launchctl` uses to restart a
    /// managed job.
    ///
    /// `SIGKILL` is deliberately absent: it cannot be caught by any process, so Force Quit and
    /// `kill -9` remain uncoverable by design. `SIGSTOP` likewise. Those are the only two.
    ///
    /// A `DispatchSourceSignal` is used rather than `signal(2)`, because a C signal handler runs
    /// in signal context and may call only async-signal-safe functions — it could not touch the
    /// keychain, AppKit, or `os_log`. The source instead delivers to the main queue as an
    /// ordinary block, where all of that is legal.
    @MainActor
    private func installTerminationSignalHandlers() {
        guard terminationSignalSources.isEmpty else { return }
        logger.info("🚪 entry point: installTerminationSignalHandlers — SIGTERM, SIGINT, SIGHUP")
        for number in [SIGTERM, SIGINT, SIGHUP] {
            // The source supplements the default disposition rather than replacing it, so the
            // default must be disarmed explicitly or the process still dies in the kernel.
            // Ordering matters: ignore first, then resume, or a signal arriving in between is
            // still fatal.
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in
                MainActor.assumeIsolated { self?.handleTerminationSignal(number) }
            }
            source.resume()
            terminationSignalSources.append(source)
        }
    }

    /// Human-readable name for a caught termination signal, for the log line only.
    private static func signalName(_ number: Int32) -> String {
        switch number {
        case SIGTERM: return "SIGTERM"
        case SIGINT: return "SIGINT"
        case SIGHUP: return "SIGHUP"
        default: return "signal \(number)"
        }
    }

    /// Apply the lock and quit, on delivery of a catchable termination signal.
    ///
    /// Eviction runs **first and synchronously**. A signal sender is under no obligation to wait
    /// — `launchctl` follows its `SIGTERM` with a `SIGKILL` after a grace period, and a script
    /// may do the same — so the half that must never be skipped is done before anything is
    /// allowed to suspend. The domain teardown (dematerialize, disconnect, unregister) is async
    /// and inherently best-effort against a deadline the app does not control; it proceeds via
    /// the normal terminate path below and completes when there is time.
    ///
    /// Terminating through ``NSApplication/terminate(_:)`` rather than tearing down here keeps
    /// this on the one shared exit path: ``applicationShouldTerminate(_:)`` defers termination
    /// and applies the quit lock exactly as it does for a menu Quit or a logout. A second,
    /// signal-specific teardown would be a parallel path free to drift from it.
    @MainActor
    private func handleTerminationSignal(_ number: Int32) {
        logger.info("🚪 entry point: handleTerminationSignal — signal \(number, privacy: .public) (\(Self.signalName(number), privacy: .public)); locking and terminating")
        if SharedConfigStore.shared.snapshot().locksOnQuit {
            vaultLock.evictKeyMaterial()
        }
        // From a fresh run-loop turn, for the reason given in ``quit()``: `terminate` runs a
        // nested event loop awaiting the `.terminateLater` reply, and the reply needs the main
        // queue this handler is already executing on.
        RunLoop.main.perform { NSApp.terminate(nil) }
    }

    nonisolated func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        // Menu-bar agent: nothing to reopen; the status item is always present.
        return false
	}

    /// Hold termination open long enough to apply the quit lock.
    ///
    /// `applicationWillTerminate` is synchronous and the process dies when it returns, so it can
    /// only ever evict key material — a `.lockAndRemove` needs `NSFileProviderManager.remove`,
    /// which is async. Under `.lockAndRemove` the quit path used to drop the slots and leave the
    /// domains registered, so `fileproviderd` kept the Provider alive and the vault stayed in
    /// Finder: the one lock path that did not honour ``SharedConfig/vaultLockMethod``.
    ///
    /// Deferring is the documented way to run asynchronous teardown on quit: reply `.later` and
    /// call `NSApp.reply(toApplicationShouldTerminate:)` when the work is done.
    nonisolated func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        MainActor.assumeIsolated {
            let config = SharedConfigStore.shared.snapshot()
            // Defer for the trigger lock too, not just the quit lock: on a logout the
            // `powerOff` trigger has already started a `lockAndRemove`, and replying
            // `.terminateNow` here kills the process mid-unregister — the domain survives in
            // Finder and `fileproviderd` keeps `Provider.appex` resident, which is the exact
            // state a lock-and-remove exists to prevent.
            //
            // The second clause is defence-in-depth, not a distinct arming case: today
            // ``SharedConfig/locksOnQuit`` already subsumes it. Setting `lockAllTask` requires a
            // trigger to have passed ``VaultLockController/LockPolicy/allows(_:)``, which needs
            // `autoLockEnabled` plus one of screen-lock / logout / restart / idle-timeout — and
            // every one of those also satisfies ``SharedConfig/quitLockIsForced``, hence
            // `locksOnQuit`. So the first clause short-circuits in every representable config.
            // The clause is retained so that decoupling the quit switch from the trigger flags
            // cannot silently reintroduce a `.terminateNow` mid-teardown; a decoupling must also
            // revisit the bare `locksOnQuit` gate in `applicationWillTerminate`.
            let armed = config.locksOnQuit || (config.autoLockEnabled && lockAllTask != nil)
            logger.info("🚪 entry point: applicationShouldTerminate — armed=\(armed, privacy: .public)")
            guard armed else {
                logger.info("🌃  VaultSync terminating — no lock armed, nothing to do")
                return .terminateNow
            }
            guard !isApplyingQuitLock else { return .terminateLater }
            isApplyingQuitLock = true
            logger.info("🌃  VaultSync \(self.versionString) terminating — applying quit lock")

            // No watchdog deadline here on purpose. A timeout that force-replies would let a
            // quit lock that hangs — or that silently fails to lock — still look like a clean
            // exit, which is the opposite of what a lock-on-quit is for, and it hides the very
            // bug it fires on. The reply is instead guaranteed structurally: `applyQuitLock`
            // must not block, and `defer` sends the reply on every path out, including a throw.
            Task { @MainActor in
                defer { self.replyToTerminate() }
                await self.applyQuitLock()
            }
            return .terminateLater
        }
    }

    /// Release the deferred termination exactly once.
    @MainActor
    private func replyToTerminate() {
        guard !hasRepliedToTerminate else { return }
        hasRepliedToTerminate = true
        NSApp.reply(toApplicationShouldTerminate: true)
    }

    nonisolated func applicationWillTerminate(_ aNotification: Notification) {
        // Synchronous, on this thread: the process is going away, so anything hopped onto a
        // `Task` may simply never run. The quit lock has already been applied by
        // `applicationShouldTerminate`; the belt-and-braces evict below covers the paths that
        // never consult it (a `terminateNow` from elsewhere, or a forced quit).
        MainActor.assumeIsolated {
            logger.info("🚪 entry point: applicationWillTerminate")
            if SharedConfigStore.shared.snapshot().locksOnQuit {
                // Unconditional even when a lock is mid-flight: `lockAndRemove` is slow
                // (unregister + local teardown) and a logout allows only seconds before the
                // process is killed, so the removal can be cut short. Eviction is the fast,
                // synchronous half and the half that actually matters — without the unwrapped
                // slots the Provider cannot decrypt, whether or not the domain survived in
                // Finder. Cheap and idempotent, so re-running it after a completed lock is free.
                vaultLock.evictKeyMaterial()
            }
            builtinServer.close()
            logger.info("🌃  VaultSync \(self.versionString) terminated")
        }
    }

    /// Apply the configured lock method to every unlocked vault, on the way out.
    ///
    /// Routes through the same actions as a user-initiated lock so the quit path cannot drift
    /// from the rest of the app — under `.lockAndRemove` that unregisters the domains, which is
    /// what actually stops `fileproviderd` keeping `Provider.appex` resident.
    ///
    /// **Unattended by construction.** A menu quit resolves its own confirmation *before*
    /// calling `terminate` (see ``quit()``), so by the time this runs there is no consent left
    /// to obtain — this is the logout / restart / shutdown path, where the user has already
    /// answered a system prompt and macOS allows only seconds before killing the process.
    /// Blocking on a dialog nobody can see would be the worst of both outcomes.
    ///
    /// Locking still wins over pending work — a vault left decrypted is the thing this exists to
    /// prevent — but removal degrades to `.preserveDirtyUserData` so unsynced edits survive on
    /// disk rather than being discarded on a quit the user never opted into per-vault.
    @MainActor
    private func applyQuitLock() async {
        // config.json is the authoritative domain list — the same source ``vaultLock``'s own
        // `domainIdentifiers` uses. `domainEntries` is the UI list, and its `locked` flag asks
        // whether Finder is disconnected, which is not the question here: a vault that is
        // connected-but-open and one that is merely disconnected both still hold key material.
        // Filtering on it found "0 unlocked" and silently locked nothing.
        //
        // Deliberately *not* filtered on `vaultKeys.isUnlocked` either. A logout fires the
        // `.powerOff` system trigger first, and `VaultLockController.lock(trigger:)` evicts key
        // material *before* it calls `onLock` — so by the time this runs every domain already
        // reports locked, the filter selected nothing, and the quit path returned early having
        // dematerialized nothing and unregistered nothing. Key eviction is not the lock; it is
        // the fast half of it. The domain teardown still has to run, and `lockAll` coalesces
        // onto the trigger's in-flight run when there is one.
        let domainIDs = Array(SharedConfigStore.shared.allAccounts().keys)
        guard !domainIDs.isEmpty else {
            vaultLock.evictKeyMaterial()
            logger.info("🔒 no configured vaults; key material evicted on quit")
            return
        }
        await lockAll(domainIDs: domainIDs, mode: .preserveDirtyUserData)
        logger.info("🔒 vaults locked on quit (\(domainIDs.count, privacy: .public), dirty user data preserved)")
    }

    func serverChangeReceived() async {
        let entries = domainEntries
        Task { await notifier.serverChangeReceived(entries) }
    }

    @IBAction func toggleAuthenticationIgnoreStatus(_ sender: AnyObject) {
        let entries = domainEntries
        // Assign to force an update on the table.
        domainEntries = entries
        Task { await notifier.signalItems(entries) }
     }

    @IBAction func changeAccountQuota(_ sender: AnyObject) {
        // The quota is general for all domains so signaling the resolved error for all domains.
        for entry in domainEntries {
            guard let manager = NSFileProviderManager(for: entry.domain) else { return }
            self.logger.info(
"""
🔆 notifying \(entry.domain.prettyDescription) for account quota change, \
now: \(String(describing: UserDefaults.sharedContainerDefaults.accountQuota))
""")
            Task {
                do {
                    try await manager.signalErrorResolved(NSFileProviderError(.insufficientQuota))
                    self.logger.info("✅ succeeded to signal insufficientQuota error as resolved for \(entry.domain.prettyDescription)")
                } catch  let error as NSError {
                    self.logger.error("❌ failed to signal insufficientQuota error as resolved for \(entry.domain.prettyDescription): \(error)")
                }
            }
        }
    }

    var knownDomains = [NSFileProviderDomain]()
    var knownAccounts = [String: DomainAccount]()
    /// Security-scoped URLs currently being accessed, keyed by account identifier.
    var activeScopedURLs: [String: URL] = [:]

    @MainActor
    func updateDomains(_ domains: ([NSFileProviderDomain], [String: DomainAccount])) async {
        knownDomains = domains.0
        knownAccounts = domains.1

        updateSecurityScopedAccess(for: knownAccounts)
        // Lazily start the emulator server the first time a local Server domain appears (it is
        // skipped at launch when only cloud domains exist — see init).
        if !builtinServer.isRunning, Self.hasEmulatorDomain(in: knownAccounts) {
            logger.info("emulator domain added — starting StandaloneServer")
            do { try builtinServer.run() } catch { presentError(error) }
        }
        updateListeners()
    }

    /// Whether any configured account is emulator-backed (i.e. served by the StandaloneServer).
    static func hasEmulatorDomain(in accounts: [String: DomainAccount]? = nil) -> Bool {
        let accounts = accounts ?? SharedConfigStore.shared.allAccounts()
        return accounts.values.contains { $0.backendKind == .emulator }
    }

    /// Resolves persisted security-scoped bookmarks for accounts that have a custom storage path.
    /// Starts access for new accounts and stops access for accounts that have been removed.
    private func updateSecurityScopedAccess(for accounts: [String: DomainAccount]) {
        let store = SharedConfigStore.shared
        let liveIdentifiers = Set(accounts.compactMap { $0.value.remotePath != nil ? $0.key : nil })

        // Stop access for removed accounts.
        for identifier in activeScopedURLs.keys where !liveIdentifiers.contains(identifier) {
            activeScopedURLs[identifier]?.stopAccessingSecurityScopedResource()
            activeScopedURLs.removeValue(forKey: identifier)
        }

        // Start access for accounts not yet tracked.
        for (identifier, account) in accounts {
            guard account.remotePath != nil, activeScopedURLs[identifier] == nil else { continue }
            let domainID = NSFileProviderDomainIdentifier(rawValue: identifier)
            guard let bookmarkData = store.bookmark(for: domainID) else { continue }
            var isStale = false
            guard let url = try? URL(resolvingBookmarkData: bookmarkData,
                                     options: .withSecurityScope,
                                     relativeTo: nil,
                                     bookmarkDataIsStale: &isStale) else { continue }
            if isStale,
               let fresh = try? url.bookmarkData(options: .withSecurityScope,
                                                  includingResourceValuesForKeys: nil,
                                                  relativeTo: nil) {
                store.setBookmark(fresh, for: domainID)
            }
            if url.startAccessingSecurityScopedResource() {
                activeScopedURLs[identifier] = url
            }
        }
    }

    @IBAction func addDomain(_ sender: AnyObject?) {
        appModel.beginAddDomain()
    }

    @IBAction func removeDomain(_ sender: AnyObject?) {
        guard let entry = selectedEntry else { return }
        presentRemoveDomain(entry)
    }

    func removeDomain(_ entry: DomainEntry) { presentRemoveDomain(entry) }

    /// Host window retained while a remove-domain sheet is presented (menu-bar app has no
    /// persistent window to parent the sheet on).
    private var removeDomainHostWindow: NSWindow?
    private var removeDomainController: RemoveDomainWindowController?

    /// Presents the remove-domain confirmation. In the menu-bar app there is no shared
    /// list spinner, so a detached progress indicator is used (removal completion is
    /// reflected by the domain leaving the popover list). The sheet is parented on a
    /// short-lived host window so its `endSheet(_:)` close path works unchanged.
    private func presentRemoveDomain(_ entry: DomainEntry) {
        let spinner = NSProgressIndicator()
        spinner.style = .spinning
        let controller = RemoveDomainWindowController(entry.domain, spinner: spinner) { [weak self] mode in
            guard let self else { return }
            Task { @MainActor in await self.confirmedDelete(entry, mode: mode) }
        }
        guard let sheet = controller.window else { return }

        let host = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
                            styleMask: [.borderless], backing: .buffered, defer: false)
        host.center()
        host.isReleasedWhenClosed = false
        host.alphaValue = 0
        removeDomainHostWindow = host
        removeDomainController = controller

        NSApp.activate(ignoringOtherApps: true)
        host.orderFront(nil)
        host.beginSheet(sheet) { [weak self] _ in
            host.close()
            self?.removeDomainHostWindow = nil
            self?.removeDomainController = nil
        }
    }

    /// Permanently delete a vault: unregister it and tear down every store keyed by its domain.
    ///
    /// Unlike "Lock and Remove Vault" this *does* discard the account, credential and metadata
    /// cache — the vault is gone, not restorable. It shares ``removeDomain(_:mode:reason:)`` for
    /// the unregister, but unlike lock-and-remove it must additionally wait for the Provider to
    /// let go: `tearDown` calls `MetadataCache.destroy()`, which unlinks the database and its
    /// WAL/SHM sidecars and requires that no live cache remains open. Removing the domain while
    /// the Provider was still crawling was what made deletion throw.
    @MainActor
    private func confirmedDelete(_ entry: DomainEntry,
                                 mode: NSFileProviderManager.DomainRemovalMode) async {
        // Deliberately unconditional, unlike lock-and-remove: a domain that fails to unregister
        // must still be deletable, or a wedged vault could never be cleared.
        let preservedURL = await removeDomain(entry, mode: mode, reason: "Vault deleted").preservedURL
        // Only the destructive path waits. `destroy` unlinks the store, so a straggling writer is
        // a genuine hazard here — unlike `empty`, which is safe against an open handle. Ordered
        // *after* the removal so the wait is satisfiable: `fileproviderd` has already torn the
        // extension down, rather than the ack being awaited from a process still to be stopped.
        await requestProviderCancellation(for: entry)

        // `provisioningService` routes by backend, so this is a no-op for backends that keep
        // no provisioning state of their own. It must run BEFORE `tearDown`, whose last step
        // clears the config that the backend lookup reads.
        do {
            try provisioningService.deprovision(domainIdentifier: entry.domain.identifier.rawValue)
        } catch {
            logger.error("❌ deprovision failed for \(entry.displayName): \(error.localizedDescription)")
        }
        do {
            try await deprovisioningService.tearDown(domain: entry.domain.identifier,
                                                     displayName: entry.displayName)
        } catch {
            logger.error("❌ teardown failed for \(entry.displayName): \(error.localizedDescription)")
        }

        if let preservedURL {
            let stop = preservedURL.startAccessingSecurityScopedResource()
            defer { if stop { preservedURL.stopAccessingSecurityScopedResource() } }
            logger.info("✅ domain was preserved to \(preservedURL)")
            NSWorkspace().selectFile(nil, inFileViewerRootedAtPath: preservedURL.path)
        }

        await refreshDomainsFromSystem()
    }

    @IBAction func blockedProcessesClicked(_ sender: NSButton) {
        let popover = NSPopover()
        popover.contentViewController = NSHostingController(rootView: BlockedProcessesEditorView())
        popover.behavior = .transient
        popover.show(relativeTo: NSRect(), of: sender, preferredEdge: .maxX)
    }

    @IBAction func editDomain(_ sender: Any) {
        guard let entry = selectedEntry else { return }
        appModel.path.append(.editDomain(domainID: entry.id))
    }

    @IBAction func toggleDomainConnection(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        let manager = NSFileProviderManager(for: domain)!

        Task {
            if domain.isDisconnected {
                do {
                    try await manager.reconnect()
                } catch let error as NSError {
                    self.logger.error("❌ failed to reconnect \(entry.domain.prettyDescription): \(error)")
                }
            } else {
                do {
                    try await manager.disconnect(reason: "Disconnected in UI", options: .temporary)
                } catch let error as NSError {
                    self.logger.error("❌ failed to disconnect \(entry.domain.prettyDescription): \(error)")
                }
            }
        }
    }

    @IBAction func toggleDomainHidden(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        domain.isHidden.toggle()

        Task {
            do {
                try await NSFileProviderManager.add(domain)
            } catch {

            }
        }
    }

    @IBAction func toggleShouldWarnOnImportingToFolder(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else {
            return
        }

        let domain = entry.domain
        UserDefaults.sharedContainerDefaults.toggleFeatureFlag(for: domain.identifier, featureFlag: FeatureFlags.shouldWarnOnImportingToFolder)
        self.signalWorkingSet(domain: domain)
    }

    @IBAction func togglePinnedFeatureEnabled(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else {
            return
        }

        let domain = entry.domain
        UserDefaults.sharedContainerDefaults.toggleFeatureFlag(for: domain.identifier, featureFlag: FeatureFlags.pinnedFeatureFlag)
        self.signalWorkingSet(domain: domain)
    }

    private func signalWorkingSet(domain: NSFileProviderDomain) {
        let seconds = 1.0
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
            guard let manager = NSFileProviderManager(for: domain) else {
                return
            }

            Task {
                do {
                    try await manager.signalEnumerator(for: .workingSet)
                } catch let error as NSError {
                    self.logger.error("❌ failed to signal working set for \(domain.prettyDescription): \(error)")
                }
            }
        }
    }

    @IBAction func toggleDomainAuthenticated(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        Task {
            do {
                // Auth toggle: clear the SharedConfig secret to deauthenticate,
                // or mint one to authenticate. DomainBackend pulls the secret lazily.
                let defaults = UserDefaults.sharedContainerDefaults
                if defaults.secret(for: domain.identifier) != nil {
                    defaults.set(secret: nil, for: domain.identifier)
                } else {
                    let secret = String(UUID().uuidString.suffix(12))
                    defaults.set(secret: secret, for: domain.identifier)
                }

                guard let manager = NSFileProviderManager(for: entry.domain) else {
                    return
                }
                self.logger.info("🔆 notifying \(entry.domain.prettyDescription) for auth status change")
                if entry.authenticated {
                    do {
                        try await manager.signalErrorResolved(NSFileProviderError(.notAuthenticated))
                    } catch let error as NSError {
                        self.logger.error("❌ failed to signal authentication error resolved for \(entry.domain.prettyDescription): \(error)")
                    }
                } else {
                    // Notify the workingSet because FileProvider needs to save the new unauthenticated state.
                    do {
                        try await manager.signalEnumerator(for: .workingSet)
                    } catch let error as NSError {
                        self.logger.error("❌ failed to signal working set for \(entry.domain.prettyDescription): \(error)")
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.presentError(error)
                }
            }

        }
    }

    @IBAction func resetSyncAnchor(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        do {
            try provisioningService.resetSyncAnchor(domainIdentifier: domain.identifier.rawValue)
            self.logger.debug("Sync anchor has been reset")
        } catch let error as NSError {
            self.logger.error("Cannot reset sync anchor: \(error)")
        }
    }

    @IBAction func toggleDomainOffline(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        let newState = !entry.offline
        Task {
            UserDefaults.sharedContainerDefaults.offline(newState, for: domain.identifier)
            let status = newState ? "Offline" : "Online"
            self.logger.debug("Domain offline status changed to \(status)")

            DistributedNotificationCenter.default().post(Notification(name: .accountsDidChange))
        }
    }

    @IBAction func showPendingItems(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        EnumerationWindowController(domain, .pending).showWindow(nil)
    }

    @IBAction func showUserInteractionSuppressions(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        let editor = UserInteractionSuppressionEditor(domainIdentifier: domain.identifier, domainDisplayName: domain.displayName)
        UserInteractionSuppressionWindowController(editor).showWindow(nil)
    }

    @IBAction func showMaterializedItems(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        EnumerationWindowController(domain, .materialized).showWindow(nil)
    }

    @IBAction func bumpDomainVersion(_ sender: NSMenuItem) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain

        // The host can no longer set the domain version directly (it is extension-owned and
        // rank-derived). Bump the config epoch and
        // signal the working set; the extension folds the epoch into the version on re-read.
        UserDefaults.sharedContainerDefaults.bumpConfigEpoch(for: domain.identifier)

        self.signalWorkingSet(domain: domain)
    }

    @IBAction func reimportDomain(_ sender: NSMenuItem) {
        guard let entry = selectedEntry,
            let manager = NSFileProviderManager(for: entry.domain) else {
                return
            }

        Task {
            do {
                try await manager.reimportItems(below: .rootContainer)
            } catch let error as NSError {
                self.logger.error("❌ failed to issue reimport \(error)")
            }
        }
    }

    @IBAction func domainDoubleClick(_ sender: NSTableView) {
        guard let entry = selectedEntry else { return }
        let domain = entry.domain
        guard let manager = NSFileProviderManager(for: domain) else { return }
        Task {
            do {
                let url = try await manager.getUserVisibleURL(for: NSFileProviderItemIdentifier.rootContainer)
                let stop = url.startAccessingSecurityScopedResource()
                defer {
                    if stop {
                        url.stopAccessingSecurityScopedResource()
                    }
                }
                NSWorkspace().selectFile(nil, inFileViewerRootedAtPath: url.path)
            } catch let error as NSError {
                self.logger.error("❌ failed to get user-visible url \(error)")
            }
        }
    }

    @IBAction func askUserToEnable(_ sender: NSMenuItem) {
        FIFinderSyncController.showExtensionManagementInterface()
    }

    /// Rebuild the UI's domain list from the *union* of registered domains and configured
    /// accounts.
    ///
    /// A vault locked with "Lock and Remove Vault" is deliberately taken out of Finder while its
    /// configuration is preserved, so it has an account but no registered domain. Sourcing the
    /// list from `NSFileProviderManager.domains()` alone would make it disappear from the popover
    /// entirely, leaving no way to unlock it — it is instead reconstructed from config and marked
    /// ``DomainEntry/isRemoved``.
    func updateListeners() {
        var entries = knownDomains.compactMap { domain -> DomainEntry? in
            if let port = domain.identifier.port, port != builtinServer.port {
                logger.info("domain \(String(describing: domain.identifier)) isn't running on main app port, not adding backend")
                return DomainEntry(domain: domain, account: nil, uploadProgress: nil, downloadProgress: nil)
            }
            if let associated = knownAccounts[domain.identifier.rawValue] {
                let manager = NSFileProviderManager(for: domain)!
                manager.signalErrorResolved(NSFileProviderError(.serverUnreachable)) { _ in }

                return DomainEntry(domain: domain, account: associated, uploadProgress: manager.globalProgress(for: .uploading),
                                   downloadProgress: manager.globalProgress(for: .downloading))
            }
            logger.info("domain \(String(describing: domain.identifier)) doesn't have a corresponding account, removing domain")
            NSFileProviderManager.remove(domain) { _ in }
            return nil
        }

        // Configured but unregistered → locked-and-removed; rebuild the domain from config so
        // `restoreVault` can hand it straight back to `NSFileProviderManager.add`.
        let registered = Set(knownDomains.map(\.identifier.rawValue))
        for (identifier, account) in knownAccounts.sorted(by: { $0.key < $1.key })
        where !registered.contains(identifier) {
            let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: identifier),
                                              displayName: account.displayName)
            entries.append(DomainEntry(domain: domain, account: account, uploadProgress: nil,
                                       downloadProgress: nil, isRemoved: true))
        }

        domainEntries = entries
    }
}

// MARK: - AppModelActions (menu-bar popover action surface)

@MainActor
extension AppDelegate: AppModelActions {
    func makeNewDomain() -> NSFileProviderDomain {
        NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: NSUUID().uuidString),
                             displayName: "")
    }

    func openInFinder(_ entry: DomainEntry) {
        guard let manager = NSFileProviderManager(for: entry.domain) else { return }
        Task {
            do {
                let url = try await manager.getUserVisibleURL(for: .rootContainer)
                let stop = url.startAccessingSecurityScopedResource()
                defer { if stop { url.stopAccessingSecurityScopedResource() } }
                NSWorkspace().selectFile(nil, inFileViewerRootedAtPath: url.path)
            } catch let error as NSError {
                self.logger.error("❌ failed to get user-visible url \(error)")
            }
        }
    }

    func openTweaks() {
        if tweaksWindowController == nil {
            let vc = TweaksViewController()
            let window = NSWindow(contentViewController: vc)
            window.title = "Tweaks"
            window.styleMask = [.titled, .closable]
            tweaksWindowController = NSWindowController(window: window)
        }
        NSApp.activate(ignoringOtherApps: true)
        tweaksWindowController?.showWindow(nil)
        tweaksWindowController?.window?.makeKeyAndOrderFront(nil)
    }

    /// "Lock Vaults": evict the Provider-readable session slots (+ in-memory KEK when biometric),
    /// then disconnect every domain so the Provider can no longer serve content. When not enrolled
    /// this is a plain disconnect (no key material to evict).
    func lockVaults() {
        beginLock(domainIDs: unlockedDomainIDs)
    }

    /// The vaults a "lock everything" action applies to.
    ///
    /// One definition, shared by the menu item and the quit path, so the two cannot disagree
    /// about what "all vaults" means.
    ///
    /// Enumerated from `SharedConfig` and asked of ``vaultKeys``, not from ``domainEntries``:
    /// the question is "which vaults still hold key material", and `DomainEntry.locked` answers
    /// a different one — whether Finder is disconnected. A vault that is connected-but-open and
    /// one that is merely disconnected both still hold keys. See the note on ``domainEntries``.
    private var unlockedDomainIDs: [String] {
        SharedConfigStore.shared.allAccounts().keys
            .filter { vaultKeys.isUnlocked(domain: $0) }
            .sorted()
    }

    /// Apply the configured lock method to `domainIDs`, past any confirmation.
    ///
    /// The tail of ``beginLock(domainIDs:)`` — the part that does the work, with the
    /// confirmation routing left behind. Shared with the quit path so a lock on the way out is
    /// the same operation as a lock from the menu.
    /// Resolve `domainIDs` to the entries the teardown works from, using `SharedConfig` as the
    /// authority rather than the UI list.
    ///
    /// A lock is a security operation on configured accounts, so it must not depend on
    /// `domainEntries` — that is a view model, rebuilt from an OS domain-registry notification,
    /// and it is empty until the popover has been opened at least once. Locks fired from a
    /// system trigger or the quit path routinely run before that, which is why those callers
    /// previously had to prime the UI list with `refreshDomainsFromSystem()` first.
    ///
    /// Prefers the live entry when one exists (it carries the registered `NSFileProviderDomain`
    /// and its real `isRemoved` state); otherwise rebuilds the domain from config, exactly as
    /// ``refreshDomainsFromSystem()`` does for a locked-and-removed vault.
    private func lockTargets(for domainIDs: [String]) -> [DomainEntry] {
        let accounts = SharedConfigStore.shared.allAccounts()
        return domainIDs.compactMap { id in
            if let entry = appModel.domain(for: id) { return entry }
            guard let account = accounts[id] else { return nil }
            let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: id),
                                              displayName: account.displayName)
            return DomainEntry(domain: domain, account: account, uploadProgress: nil,
                               downloadProgress: nil, isRemoved: false)
        }
    }

    /// Start a lock from a system trigger (screen lock / logout / restart) and retain its task.
    ///
    /// The trigger handler is synchronous, so the work has to run detached — but it must remain
    /// *joinable*: on a logout the same event that fires this trigger also terminates the app,
    /// and `applicationShouldTerminate` has to wait for the unregister rather than letting the
    /// process die mid-teardown.
    @MainActor
    private func trackSystemLock(domainIDs: [String],
                                 mode: NSFileProviderManager.DomainRemovalMode) {
        // Coalesced, not queued: a logout can deliver `screenIsLocked` then `powerOff` within
        // the same second and the work is identical. Both system-trigger callers pass
        // `.preserveDirtyUserData`, so the dropped `mode` cannot differ; a future caller with a
        // stronger mode must not use this entry point.
        guard lockAllTask == nil else { return }
        lockAllTask = Task { @MainActor in
            await self.performLockAll(domainIDs: domainIDs, mode: mode)
            self.lockAllTask = nil
        }
    }

    private func lockAll(domainIDs: [String],
                         mode: NSFileProviderManager.DomainRemovalMode = .removeAll) async {
        // Serialised: a logout delivers `sessionDidResignActive` *and* terminates the app, so
        // the system-trigger lock and the quit lock can both be in flight over the same domains.
        // Unregistering a domain twice concurrently leaves the second call operating on a
        // half-removed domain, which is one way `Provider.appex` survives a lock-and-remove.
        // Later callers await the running lock instead of starting a competing one.
        if let inFlight = lockAllTask {
            await inFlight.value
            return
        }
        let task = Task { @MainActor in
            await self.performLockAll(domainIDs: domainIDs, mode: mode)
        }
        lockAllTask = task
        await task.value
        lockAllTask = nil
    }

    /// The body of a lock-all, with the coalescing left to the callers above.
    @MainActor
    private func performLockAll(domainIDs: [String],
                                mode: NSFileProviderManager.DomainRemovalMode) async {
        if SharedConfigStore.shared.snapshot().vaultLockMethod == .lockAndRemove {
            await lockAndRemove(domainIDs: domainIDs, mode: mode)
        } else {
            await confirmedLockAction(domainIDs: domainIDs)
        }
    }


    /// Entry point for every user-initiated lock (all vaults or one).
    ///
    /// Routes through the confirmation screen only when locking would actually destroy
    /// something — see ``pendingItemCount(for:)``. A plain `.lock` never destroys anything, so
    /// it proceeds directly.
    private func beginLock(domainIDs: [String]) {
        guard !domainIDs.isEmpty else { return }
        if SharedConfigStore.shared.snapshot().vaultLockMethod != .lockAndRemove {
            Task { @MainActor in await self.confirmedLockAction(domainIDs: domainIDs) }
        } else {
            Task { @MainActor in
                var pending = 0
                for id in domainIDs {
                    guard let entry = self.appModel.domain(for: id) else { continue }
                    // An indeterminate count fails safe: treat it as "something might be lost".
                    guard let count = await self.pendingItemCount(for: entry) else {
                        self.appModel.path.append(.confirmLock(domainIDs: domainIDs, pendingCount: -1))
                        return
                    }
                    pending += count
                }
                if pending > 0 {
                    self.appModel.path.append(.confirmLock(domainIDs: domainIDs, pendingCount: pending))
                } else {
                    self.confirmedLockAndRemoveAction(domainIDs: domainIDs)
                }
            }
        }
    }

    /// Perform a plain lock, past any confirmation. A plain lock never destroys anything, so it
    /// is never routed through ``ConfirmLockView``.
    ///
    /// Bound to a SwiftUI button action (menu-bar "Lock Vaults" / per-vault lock); callers wrap
    /// this in `Task { @MainActor in await ... }` to bridge from a synchronous closure.
    @MainActor
    func confirmedLockAction(domainIDs: [String]) async {
        let entries = lockTargets(for: domainIDs)
        for entry in entries {
            await performLock(entry)
        }
        // Domain plumbing is already handled per-entry above; evict key material without
        // re-triggering onLock's lock-and-remove. Slot eviction is scoped to the
        // locked domains so vaults that stay unlocked keep serving content — and under I5 there
        // is no shared key to drop, so locking one vault cannot reach another's material.
        vaultLock.evictKeyMaterial(for: domainIDs)
        await refreshDomainsFromSystem()
    }

    /// Discard the domain's downloaded plaintext, so nothing readable remains on disk while the
    /// vault is locked.
    ///
    /// Evicts each materialized *file* rather than the root container: the root and folders have
    /// no on-disk representation and are not evictable, so `evictItem(.rootContainer)` fails with
    /// `NSUserCancelledError` and de-materializes nothing. See ``MaterializedEviction``.
    private func deMaterialize(_ entry: DomainEntry, manager: NSFileProviderManager) async {
        do {
            let evicted = try await MaterializedEviction.evictFiles(under: .rootContainer,
                                                                    manager: manager) { id, error in
                self.logger.error("⚠️ evict \(id.rawValue) failed for \(entry.displayName): \(error.localizedDescription)")
            }
            logger.info("✅ de-materialized \(entry.displayName) (\(evicted) file(s))")
        } catch {
            logger.error("❌ failed to de-materialize \(entry.domain.prettyDescription): \(error)")
        }
    }

    /// Lock one vault: de-materialize its content so no plaintext remains on disk while locked,
    /// then stop serving it.
    ///
    /// Sequenced rather than fired-and-forgotten, and in this order: `evictItem` is serviced *by*
    /// the Provider, so it can only succeed while the domain is still connected and its extension
    /// still running. Disconnecting (or cancelling the extension's work) first makes the OS cancel
    /// the eviction with `NSUserCancelledError`, leaving cached plaintext on disk.
    private func performLock(_ entry: DomainEntry) async {
        guard let manager = NSFileProviderManager(for: entry.domain) else { return }
        await deMaterialize(entry, manager: manager)
        do {
            try await manager.disconnect(reason: "Vault locked", options: [])
        } catch let error as NSError {
            logger.error("❌ failed to lock (disconnect) \(entry.domain.prettyDescription): \(error)")
        }
    }

    /// Perform a lock-and-remove, past ``ConfirmLockView`` confirmation.
    ///
    /// Bound to ``ConfirmLockView``'s "Lock Anyway" button.
    @MainActor
    func confirmedLockAndRemoveAction(domainIDs: [String]) {
        // Fire-and-forget for button callers: the popover closes and the work continues.
        Task { @MainActor in await self.lockAndRemove(domainIDs: domainIDs) }
    }

    /// The awaitable form of ``confirmedLockAndRemoveAction(domainIDs:)``.
    ///
    /// Separate from the `AppModelActions` witness rather than a completion parameter on it: the
    /// views have nothing to wait for, and only the quit path — which must hold termination open
    /// until the domains are genuinely unregistered — needs to await the result. One body, two
    /// entry points, so the two can never drift.
    @MainActor
    private func lockAndRemove(domainIDs: [String],
                               mode: NSFileProviderManager.DomainRemovalMode = .removeAll) async {
        let entries = lockTargets(for: domainIDs)
        for entry in entries {
            await performLockAndRemove(entry, mode: mode)
        }
        // Domain plumbing is already handled per-entry above; evict key material without
        // re-triggering onLock's lock, which would race the just-completed
        // unregister. Scoped to the locked domains — see ``confirmedLockAction``.
        vaultLock.evictKeyMaterial(for: domainIDs)
        await refreshDomainsFromSystem()
    }

    /// Lock one vault and remove it from Finder, leaving no locally readable data or metadata.
    ///
    /// Per-domain *configuration* is deliberately preserved so ``unlockVault(_:)`` can restore
    /// the domain without re-authenticating; remote data is never touched.
    ///
    /// The local-data teardown runs whether or not the removal succeeded. It used to be gated on
    /// the domain being genuinely out of Finder, to avoid a vault that reads as "still there" but
    /// has been gutted — but that gate made the caches survive exactly the case they most need to
    /// be cleared in. At logout `fileproviderd` invalidates `Provider.appex` before the app is
    /// even asked to terminate, so removal always fails there, and the gate skipped the teardown
    /// every time; the rows then outlived the lock until some later removal happened to succeed.
    ///
    /// Ungating it is safe on both counts the gate was protecting:
    ///
    /// - ``BackendResourceCleanup/empty(domainID:backend:)`` clears rebuildable rows in place and
    ///   is documented safe against a live store handle, unlike `destroy`. Configuration and
    ///   wrapped key material survive, so unlock still restores the vault from the server.
    /// - The "gutted but visible" state is not actually reachable. Locking evicts the domain's
    ///   `fileKeysKEK` first, so every retained header row is already permanently unreadable —
    ///   emptying only reclaims ballast, and a domain left registered is unusable either way.
    ///
    /// A failed removal is therefore no longer a reason to leave data behind; it is reported and
    /// repaired at the next launch by ``reconcileRemovedDomainsAtLaunch()``.
    private func performLockAndRemove(_ entry: DomainEntry,
                                      mode: NSFileProviderManager.DomainRemovalMode = .removeAll) async {
        let outcome = await removeDomain(entry, mode: mode, reason: "Vault locked and removed")
        if !outcome.isAbsent {
            logger.error("❌ \(entry.displayName) still registered; clearing local data anyway")
        }
        do {
            try await deprovisioningService.tearDownLocalData(domain: entry.domain.identifier,
                                                              displayName: entry.displayName)
            if outcome.isAbsent {
                logger.info("✅ lock-and-remove complete for \(entry.displayName)")
            } else {
                logger.info("🧹 local data cleared for \(entry.displayName); domain removal deferred to next launch")
            }
        } catch {
            logger.error("❌ local-data teardown failed: \(error.localizedDescription)")
        }
    }

    /// What ``removeDomain(_:mode:reason:)`` achieved.
    ///
    /// Distinguishing "already gone" from "could not remove" is what lets callers avoid tearing
    /// down local data for a domain that is still registered and being served — a half-applied
    /// state that reads to the user as "lock did nothing" while its caches were emptied anyway.
    private enum UnregisterOutcome {
        /// The domain is no longer registered, carrying any URL the removal mode preserved.
        case unregistered(preservedURL: URL?)
        /// The domain was not registered to begin with, so there was nothing to remove.
        case alreadyAbsent
        /// The domain is still registered: removal failed.
        case failed

        /// Whether the domain is now absent from the system, however it got that way.
        var isAbsent: Bool {
            switch self {
            case .unregistered, .alreadyAbsent: return true
            case .failed:                       return false
            }
        }

        /// The URL a `.preserve`-mode removal left behind, if any.
        var preservedURL: URL? {
            guard case .unregistered(let url) = self else { return nil }
            return url
        }
    }

    /// Unregister a domain from the system, returning any URL the removal mode preserved.
    ///
    /// Shared by "Lock and Remove Vault" and "Delete Vault". The only step that must precede the
    /// removal is de-materialisation, and only under a mode that preserves local content:
    /// `evictItem` is serviced *by* the Provider, so it can only succeed while the domain is
    /// still registered.
    ///
    /// Deliberately does **not** disconnect first, nor wait for the Provider to acknowledge a
    /// cancellation. Both were redundant ahead of a removal that stops the extension anyway, and
    /// on the logout path the cancellation wait was actively harmful: `invalidate()` tears the
    /// extension down before it can write its ack, so the wait always ran to its full timeout and
    /// `SIGTERM` arrived before `remove` was ever called — leaving the domain in Finder, which is
    /// the exact state a lock-and-remove exists to prevent. The local-data teardown this once
    /// guarded is gated on the removal having succeeded, and `BackendResourceCleanup.empty` is
    /// safe against an open handle by construction.
    ///
    /// A vault already removed by "Lock and Remove Vault" has no registered domain; calling
    /// `NSFileProviderManager.remove` on it throws, so that step is skipped.
    @discardableResult
    private func removeDomain(_ entry: DomainEntry,
                              mode: NSFileProviderManager.DomainRemovalMode,
                              reason: String) async -> UnregisterOutcome {
        // De-materialize first, while the domain is still registered for the Provider to service
        // it: `.removeAll` discards local content itself, so eviction there would be redundant.
        //
        // Best-effort by design. Key material is evicted before any of this runs, so the Provider
        // may already be answering `notAuthenticated` and evict nothing — that ordering is
        // deliberate (the unreadable-key half of a lock must never wait on I/O), and the Provider
        // handles it gracefully rather than this path deferring to it.
        if mode != .removeAll, !entry.isRemoved, let manager = NSFileProviderManager(for: entry.domain) {
            await deMaterialize(entry, manager: manager)
        }

        guard !entry.isRemoved else {
            logger.info("↩️ \(entry.displayName) has no registered domain; skipping remove")
            return .alreadyAbsent
        }
        do {
            let preservedURL = try await NSFileProviderManager.remove(entry.domain, mode: mode)
            logger.info("✅ unregistered domain \(entry.displayName) (\(reason))")
            return .unregistered(preservedURL: preservedURL)
        } catch let error as NSError {
            logger.error("❌ failed to remove domain \(entry.domain.prettyDescription): \(error)")
            return .failed
        }
    }

    /// Ask the Provider to cancel in-flight work for a domain and wait for its acknowledgement.
    ///
    /// The request is a `SharedConfig` generation bump (Darwin-notified to the extension); the
    /// acknowledgement comes back as `providerState == .cancelled` carrying that same generation
    /// in `cancelAckGeneration`. On timeout we proceed anyway — a wedged vault must still be
    /// deletable.
    ///
    /// Used only by the destructive delete path, and only *after* the domain is unregistered.
    /// Lock-and-remove does not wait: `MetadataCache.empty()` never unlinks the file, so a
    /// straggling writer is harmless there, and waiting ahead of the removal cost the logout
    /// path its entire budget before `NSFileProviderManager.remove` was ever reached.
    private func requestProviderCancellation(for entry: DomainEntry,
                                             timeout: TimeInterval = 5) async {
        let generation = UserDefaults.sharedContainerDefaults.requestCancellation(for: entry.domain.identifier)
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline {
            // Match the ack to *this* request. `providerState` is never reset to `.idle`, so a
            // `.cancelled` left by an earlier lock/unlock cycle would otherwise satisfy the wait
            // instantly and let the teardown race a fully live Provider.
            let snapshot = ProgressStore.shared.snapshot(for: entry.id)
            if snapshot.providerState == .cancelled, snapshot.cancelAckGeneration >= generation {
                logger.info("✅ provider stopped for \(entry.displayName)")
                return
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        logger.error("⏱️ provider cancellation not acknowledged in time for \(entry.displayName); proceeding")
    }

    /// Unlock vaults: obtain each domain's gating key — silently, via a Touch ID prompt, from a
    /// PIN entered in the popover, or through the Secure Enclave — open its `domainKey`,
    /// repopulate its Provider slots, then reconnect the domains.
    ///
    /// Routes on whether **any** locked domain needs a PIN, since PIN entry is the only ceremony
    /// that must collect input before it can run. Domains gated otherwise are opened in the same
    /// pass and simply ignore the PIN.
    func unlockVaults() {
        // An orphaned domain cannot be unlocked by any gating — the wrapper the gating key would
        // open is gone. Route to the gate's reset instead of prompting for a credential that
        // cannot succeed.
        guard !appModel.routeToVaultGateIfOrphaned() else { return }
        let needsPIN = vaultLock.gating() == .pin
        if needsPIN {
            // PIN entry happens in the popover; `submitUnlockPIN` resumes this flow. Scoped to
            // the locked vaults, which for this entry point is all of them.
            appModel.path.append(.unlock(domainIDs: domainEntries.filter(\.locked).map(\.id)))
        } else {
            Task { @MainActor in await self.completeUnlock() }
        }
    }

    /// Release key material for `domainIDs` and restore those vaults.
    ///
    /// Shared by all four gatings so restoration behaves identically however the unlock was
    /// gated; `pin` is supplied only on the PIN path and is ignored by domains gated otherwise.
    /// Each domain still derives its own `domainKey` — one prompt, N independent keys.
    ///
    /// One presence evaluation for N domains — see ``VaultKeyStore/populateUnwrappedSlots(for:pin:)``.
    ///
    /// - Parameter domainIDs: The vaults the ceremony was run for. Only these are opened and
    ///   restored; siblings are left exactly as they were.
    @MainActor
    func unlockVaults(domainIDs: [String]) async throws {
        try await vaultLock.unlock(domains: domainIDs, pin: nil, reason: "Unlock your vaults")
        await restoreVaults(domainIDs: domainIDs)
    }

    /// Bring the named vaults back into Finder and refresh the UI. The tail shared by every
    /// unlock path, whatever ceremony preceded it.
    @MainActor
    private func restoreVaults(domainIDs: [String]) async {
        let wanted = Set(domainIDs)
        for entry in domainEntries where wanted.contains(entry.id) {
            await restoreVault(entry)
        }
        await refreshDomainsFromSystem()
        appModel.loadPersistedSnapshots()
    }

    /// - Parameter pin: The entered PIN, for `.pin`-gated domains.
    @MainActor
    private func completeUnlock(domainIDs: [String]? = nil, pin: String? = nil) async {
        // Default scope is every *locked* vault — the install-wide "Unlock Vaults" entry point.
        // A caller that names its vaults gets exactly those.
        let scope = domainIDs ?? domainEntries.filter(\.locked).map(\.id)
        do {
            try await vaultLock.unlock(domains: scope, pin: pin, reason: "Unlock your vaults")
        } catch {
            logger.error("❌ vault unlock failed: \(error.localizedDescription)")
            return
        }
        await restoreVaults(domainIDs: scope)
    }

    /// Restore one vault: reconnect it, or re-add it when a "lock and remove" took it out of
    /// Finder. Its configuration was preserved, so no re-authentication is needed.
    @MainActor
    private func restoreVault(_ entry: DomainEntry) async {
        let known = (try? await NSFileProviderManager.domains()) ?? []
        if known.contains(where: { $0.identifier == entry.domain.identifier }) {
            guard let manager = NSFileProviderManager(for: entry.domain) else { return }
            do {
                try await manager.reconnect()
            } catch let error as NSError {
                logger.error("❌ failed to unlock (reconnect) \(entry.domain.prettyDescription): \(error)")
            }
        } else {
            do {
                try await NSFileProviderManager.add(entry.domain)
                logger.info("🔓 re-added removed vault \(entry.displayName) from preserved config")
            } catch let error as NSError {
                logger.error("❌ failed to re-add \(entry.domain.prettyDescription): \(error)")
            }
        }
    }

    /// Reconnect the named domains (best-effort). Shared by manual + policy-driven unlock.
    ///
    /// Scoped to `ids` rather than every domain: only vaults whose gating ceremony actually ran
    /// may come back. Reconnecting the whole list made one vault's unlock restore its siblings.
    ///
    /// - Parameter ids: The domain identifiers to reconnect.
    private func reconnectDomains(ids: [String]) {
        let wanted = Set(ids)
        for entry in domainEntries where wanted.contains(entry.id) {
            guard let manager = NSFileProviderManager(for: entry.domain) else { continue }
            Task {
                do {
                    try await manager.reconnect()
                } catch let error as NSError {
                    self.logger.error("❌ failed to reconnect \(entry.domain.prettyDescription): \(error)")
                }
            }
        }
    }

    /// Lock a single vault, honouring the configured lock method and confirming first when
    /// doing so would discard unsynced local changes.
    func lockVault(_ entry: DomainEntry) {
        beginLock(domainIDs: [entry.id])
    }

    /// Unlock a single vault: release its key material, then reconnect or re-add it.
    ///
    /// Genuinely per-domain now — this opens `entry` alone, using its own gating, and leaves
    /// every sibling as it was.
    func unlockVault(_ entry: DomainEntry) {
        guard !appModel.routeToVaultGateIfOrphaned() else { return }
        if vaultLock.gating() == .pin {
            // Carry `entry` through the PIN screen: the ceremony is per-vault, and a route that
            // forgot which vault was asked for unlocked every one of them.
            appModel.path.append(.unlock(domainIDs: [entry.id]))
            return
        }
        Task { @MainActor in
            do {
                try await self.unlockVault(entry)
            } catch {
                self.logger.error("❌ vault unlock failed for \(entry.id): \(error.localizedDescription)")
            }
        }
    }

    /// Unlock one vault and reconnect it, surfacing the ceremony's error.
    ///
    /// The single implementation; the fire-and-forget form above wraps this and logs. Callers
    /// that can present a failure — ``UnlockView`` — use this one, because a vault left locked
    /// does not say *why*: a cancelled prompt and a destroyed enclave key look identical from
    /// the domain rows, and only the thrown error separates them.
    ///
    /// - Parameter entry: The vault to open.
    /// - Throws: Whatever the gating ceremony failed with.
    @MainActor
    func unlockVault(_ entry: DomainEntry) async throws {
        try await unlockVaults(domainIDs: [entry.id])
    }

    /// Items with unsynced local changes, via the OS pending-items enumerator.
    ///
    /// `nil` when the count could not be determined; callers treat that as "may be destructive"
    /// and confirm anyway. Used to decide whether a lock needs confirmation.
    func pendingItemCount(for entry: DomainEntry) async -> Int? {
        guard let manager = NSFileProviderManager(for: entry.domain) else { return nil }
        return await PendingItemCounter.count(using: manager.enumeratorForPendingItems())
    }

    /// Re-authenticate a domain interactively. Minimal viable: push the edit screen for
    /// that domain so the user can re-run sign-in / re-supply credentials.
    func reauthenticate(_ entry: DomainEntry) {
        appModel.path.append(.editDomain(domainID: entry.id))
    }

    /// The unlock method protecting every vault on this install (silent — no prompt).
    var vaultGating: SharedConfig.VaultGating {
        SharedConfigStore.shared.snapshot().vaultGating
    }

    /// Switch the install to `gating`, re-sealing every vault's `domainKey` under the new method.
    ///
    /// One ceremony for the whole install: every domain is opened under the current method and
    /// re-sealed to the new method's public half. The config write is **last**, so a cancelled
    /// ceremony never leaves the config claiming a protection the vault lacks.
    ///
    /// - Parameters:
    ///   - gating: The method to switch the install to.
    ///   - newPIN: The PIN to enroll, required when `gating` is `.pin`.
    ///   - currentPIN: The PIN opening the current method, when it is `.pin`.
    /// - Throws: Whatever the commit failed with. The caller (``SecurityView``) reverts its
    ///   selection on a throw, so the UI can never claim a gating that was never written.
    func setVaultGating(_ gating: SharedConfig.VaultGating,
                        newPIN: String? = nil,
                        currentPIN: String? = nil,
                        presenceContext: AnyObject? = nil) async throws {
        do {
            try await vaultLock.setGating(gating, newPIN: newPIN, currentPIN: currentPIN,
                                          presenceContext: presenceContext)
            // Last, and only on success.
            SharedConfigStore.shared.write(\.vaultGating, gating)
            logger.info("🔑 install gating set (\(gating.rawValue))")
        } catch {
            logger.error("❌ gating change failed: \(error.localizedDescription)")
            throw error
        }
    }

    /// Choose what locking does to a vault.
    /// Re-arm the idle timer against the freshly-written policy, and make sure the system-event
    /// observers are live — enabling auto-lock for the first time must take effect now, not at
    /// the next unlock.
    func autoLockPolicyDidChange() {
        vaultLock.armSystemEvents()
        vaultLock.policyDidChange()
    }

    func setLockMethod(_ method: SharedConfig.VaultLockMethod) {
        SharedConfigStore.shared.write(\.vaultLockMethod, method)
    }

    /// Whether `pin` opens this install. Verification only — no slots are populated.
    @MainActor
    func verifyUnlockPIN(_ pin: String) async -> Bool {
        guard vaultLock.gating() == .pin else { return false }
        return vaultKeys.verifyPIN(pin)
    }

    /// Run the install's presence ceremony for its prompt alone. No slots are populated.
    ///
    /// The returned capability is handed to ``SecurityFlow``, which owns it from here.
    @MainActor
    func evaluateGatingPresence() async throws -> AnyObject? {
        try await vaultKeys.evaluatePresence(reason: "Confirm to change your security settings")
    }

    /// Seconds to wait before another PIN attempt is accepted (escalating backoff, no lockout).
    var pinRetryDelay: TimeInterval { vaultKeys.pinRetryDelay }

    /// Unlock with `pin` and, on success, restore the vaults. `false` leaves the caller on the
    /// unlock screen; the throttle has already recorded the failed attempt.
    func submitUnlockPIN(_ pin: String, domainIDs: [String]) async -> Bool {
        guard vaultLock.gating() == .pin else { return false }
        guard !domainIDs.isEmpty else { return false }
        do {
            // Verify the PIN against one domain before committing to the pass, so a wrong entry
            // is rejected by the throttled path rather than silently skipping every domain.
            try await vaultLock.unlock(domain: domainIDs[0], pin: pin,
                                       reason: "Unlock your vaults")
        } catch {
            logger.error("❌ PIN unlock failed: \(error.localizedDescription)")
            return false
        }
        // Scoped to the vaults the PIN screen was shown for. A correct PIN authorises those and
        // no others — it is not a pass to the whole install.
        await completeUnlock(domainIDs: domainIDs, pin: pin)
        return true
    }

    /// Legacy menu entry — make biometric the default gating for new vaults. Fire-and-forget is
    /// acceptable here (no UI state to revert); the error is surfaced rather than swallowed.
    func enrollBiometricLock() {
        Task { @MainActor in
            do { try await setVaultGating(.biometric, newPIN: nil) } catch { presentError(error) }
        }
    }

    // MARK: - Vault readiness

    /// Whether the vault is usable, and if not why. One computation, three presenters.
    ///
    /// A keychain read failure is reported as ``VaultReadiness/locked``: it is the conservative
    /// answer — it offers a retry rather than a destructive reset, and never claims readiness the
    /// vault may not have.
    var vaultReadiness: VaultReadiness {
        // Worst state across the domains, per I5: one orphaned domain no longer condemns the
        // install, but it must still be surfaced so the user can remove that one vault.
        let states = domainEntries.map { entry -> VaultReadiness in
            do {
                return try vaultKeys.readiness(for: entry.id)
            } catch {
                logger.error("❌ vault readiness check failed for \(entry.id): \(error.localizedDescription)")
                return .locked
            }
        }
        if states.contains(.orphaned) { return .orphaned }
        if states.contains(.locked) { return .locked }
        return .ready
    }

    /// Display names of the vaults a reset would delete — the orphaned ones only.
    ///
    /// Under I5 an orphan is scoped to itself, so a reset names and removes exactly the domains
    /// whose `domainKey` wrapper is gone. Healthy siblings are untouched.
    var vaultBackedDomainNames: [String] {
        let doomed = Set(VaultKeyStore.orphanedDomainIDs())
        return domainEntries.filter { doomed.contains($0.id) }
            .map(\.displayName)
            .sorted()
    }

    /// Delete the **orphaned** vaults — the recovery from ``VaultReadiness/orphaned``.
    ///
    /// Scoped to the domains whose own `domainKey` wrapper is missing. Under I5 there is no
    /// install-wide root to clear afterwards and no sibling to spare: a lost wrapper orphans
    /// exactly its own domain, so removing that domain is the whole recovery.
    ///
    /// `.plain` vaults are included when orphaned. They seal no *content* under the `domainKey`,
    /// but their refresh token is sealed under it, so the domain is equally unrecoverable.
    ///
    /// Reuses ``confirmedDelete(_:mode:)`` so a reset deletes a vault exactly as "Delete Vault…"
    /// does, rather than via a second teardown path that could drift from it.
    func resetVault() async {
        let blocking = Set(VaultKeyStore.orphanedDomainIDs())
        let doomed = domainEntries.filter { blocking.contains($0.id) }
        logger.error("🗑️ resetting vault — deleting \(doomed.count) vault(s)")

        for entry in doomed {
            // `confirmedDelete` runs the full teardown, whose `forgetDomain` step deletes every
            // one of that domain's slots. Under I5 there is no install-wide root left to clear
            // afterwards — removing the domains *is* the reset.
            await confirmedDelete(entry, mode: .removeAll)
        }
        await refreshDomainsFromSystem()
    }

    /// Open the Security preferences screen inside the popover nav stack.
    func openSecurity() {
        // Routed through the model so the "does this need a ceremony first?" decision lives in
        // one place (see ``AppModel/openSecurity()``).
        appModel.openSecurity()
    }

    /// Quit from the popover menu.
    ///
    /// The confirmation is resolved *here*, before `terminate` is called, rather than from
    /// `applicationShouldTerminate`: we own this menu item, so the one quit that has a user in
    /// front of it can ask its question while there is still an app to ask it from. That leaves
    /// `applicationShouldTerminate` with a single, unattended job (see ``applyQuitLock()``).
    ///
    /// Hops to the next run-loop pass rather than terminating inline: the call arrives from a
    /// SwiftUI `Menu` item while the popover is still tracking, and tearing the app down from
    /// inside that event dispatch is what left the menu item looking dead.
    func quit() {
        logger.info("🚪 entry point: quit — menu-bar Quit")
        statusItemController?.closePopover()
        Task { @MainActor in
            guard await confirmQuitDiscardingPendingWork() else {
                logger.info("↩️ quit cancelled; unsynced work kept")
                return
            }
            // Terminate from a fresh run-loop turn, never from inside this `Task`.
            //
            // `NSApplication.terminate` runs a *nested event loop* on the main thread while it
            // waits for the `.terminateLater` reply. Called from a main-actor `Task`, that loop
            // blocks the main actor itself, so the teardown and timeout `Task`s
            // `applicationShouldTerminate` enqueues can never be scheduled — the reply needs
            // them, they need the main actor, and the app hangs with the menu item looking
            // dead. Hopping to the run loop drains this task first, leaving the nested loop
            // free to run the work that answers it.
            RunLoop.main.perform { NSApp.terminate(nil) }
        }
    }

    /// Ask before a menu quit throws away unsynced work, and report whether to go ahead.
    ///
    /// Only asks when there is something to lose: no lock on quit, no `.lockAndRemove`, or
    /// nothing pending, and the quit proceeds silently. An indeterminate count fails safe and
    /// asks, matching ``beginLock(domainIDs:)``.
    @MainActor
    private func confirmQuitDiscardingPendingWork() async -> Bool {
        let config = SharedConfigStore.shared.snapshot()
        guard config.locksOnQuit, config.vaultLockMethod == .lockAndRemove else { return true }
        // Authoritative list + key state, as in ``applyQuitLock()``; the UI list is populated
        // only so the pending-count lookup below has a `DomainEntry` to work from.
        let unlocked = SharedConfigStore.shared.allAccounts().keys
            .filter { vaultKeys.isUnlocked(domain: $0) }
        guard !unlocked.isEmpty else { return true }
        if domainEntries.isEmpty { await refreshDomainsFromSystem() }
        let entries = unlocked.compactMap { appModel.domain(for: $0) }
        guard !entries.isEmpty else { return true }

        var pending = 0
        var indeterminate = false
        for entry in entries {
            guard let count = await pendingItemCount(for: entry) else { indeterminate = true; break }
            pending += count
        }
        guard indeterminate || pending > 0 else { return true }

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = entries.count == 1
            ? "Lock and remove “\(entries[0].displayName)”?"
            : "Lock and remove \(entries.count) vaults?"
        alert.informativeText = indeterminate
            ? "Some items may not have finished uploading yet. Quitting now removes the vaults "
              + "from this Mac and anything still unsynced will be lost."
            : (pending == 1
               ? "1 item hasn't finished uploading and will be lost. "
               : "\(pending) items haven't finished uploading and will be lost. ")
              + "Files already on the server are never touched."
        alert.addButton(withTitle: "Lock Anyway")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

class MillisecondTransformer: ValueTransformer {
    open override func transformedValue(_ value: Any?) -> Any? {
        guard let val = value as? NSNumber else { return "0 ms" }
        return "\(val.intValue) ms"
    }
}

class PercentageTransformer: ValueTransformer {
    open override func transformedValue(_ value: Any?) -> Any? {
        guard let val = value as? NSNumber else { return "0 %" }
        return "\(val.intValue) %"
    }
}

