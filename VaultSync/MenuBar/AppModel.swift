/// Observable UI state hub for the menu-bar popover.
///
/// `AppModel` is the single bridge between the AppKit `AppDelegate` orchestration
/// (domain pipe, provisioning, security-scoped access) and the SwiftUI navigation
/// stack hosted in the status-item popover. `AppDelegate` publishes domain changes
/// into it on the main actor; the popover views observe `AppModel` only and route
/// user actions back through ``AppModelActions``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit
import AuthenticationServices
import Combine
import FileProvider
import Foundation
import Common

/// Aggregate background state rendered by the status-item icon.
enum StatusActivity: Equatable {
    /// No domain error and no in-flight transfer.
    case idle
    /// At least one domain has a non-finished upload/download in flight.
    case active
    /// At least one domain is locked. Distinct from ``error``: locking is a state the user chose
    /// and can undo by unlocking, so it must not render as a fault.
    case locked
    /// At least one domain is unauthenticated / disconnected / erroring.
    case error
    /// The vault itself is unusable — a `domainKey` wrapper is gone while its vault remains configured
    /// (``VaultReadiness/orphaned``). Ranks above ``locked``: locking is a state the user chose
    /// and can undo, whereas this is a fault only a reset clears.
    case vaultError
}

/// Action surface the popover invokes on the host. Implemented by `AppDelegate`.
///
/// Keeping this a narrow protocol (rather than reaching into `AppDelegate`) keeps the
/// SwiftUI layer testable with a stub and documents exactly what the UI may trigger.
@MainActor
protocol AppModelActions: AnyObject {
    /// Provisioning service passed to the add/edit form's view model.
    var provisioningService: any DomainProvisioningService { get }
    /// All known domains (for duplicate-name checks in the edit form).
    var knownDomains: [NSFileProviderDomain] { get }
    /// All known accounts, keyed by domain identifier.
    var knownAccounts: [String: DomainAccount] { get }
    /// A fresh domain identity for the add flow.
    func makeNewDomain() -> NSFileProviderDomain
    /// Reveal a domain's root in Finder.
    func openInFinder(_ entry: DomainEntry)
    /// Delete a domain (presents its own confirmation UI).
    func removeDomain(_ entry: DomainEntry)
    /// Open the Tweaks configuration surface.
    func openTweaks()
    /// Lock all vaults: evict in-memory keys and disconnect domains.
    func lockVaults()
    /// Unlock all vaults: biometric prompt (if enrolled) then reconnect domains.
    func unlockVaults()
    /// Lock a single vault: disconnect it and evict (de-materialize) its content.
    func lockVault(_ entry: DomainEntry)
    /// Unlock a single vault: reconnect it. Fire-and-forget; errors are logged by the host.
    ///
    /// For the button callers, which have no surface on which to report a failure. A screen that
    /// must show *why* an unlock failed uses ``unlockVault(_:)-throwing`` instead.
    func unlockVault(_ entry: DomainEntry)
    /// Unlock a single vault, surfacing the ceremony's error to the caller.
    ///
    /// The throwing form exists because a failed ceremony is not observable from the domain rows:
    /// a cancelled Touch ID prompt and a destroyed Secure Enclave key both leave the vault
    /// locked, and only the thrown error tells them apart. ``UnlockView`` needs that distinction
    /// to name an unrecoverable cause rather than invite a retry that cannot succeed.
    ///
    /// - Parameter entry: The vault to open.
    /// - Throws: Whatever the gating ceremony failed with.
    func unlockVault(_ entry: DomainEntry) async throws
    /// Unlock the named vaults behind **one** ceremony, surfacing its error.
    ///
    /// Not a loop over ``unlockVault(_:)``: the gating *method* is install-wide, so one presence
    /// evaluation serves the whole set and looping would re-prompt per vault.
    /// Each domain still derives its own `domainKey`.
    ///
    /// Scoped rather than install-wide: "Unlock Vault" on one row must open that row alone, so
    /// the caller states which vaults its ceremony was for.
    ///
    /// - Parameter domainIDs: The vaults to open.
    func unlockVaults(domainIDs: [String]) async throws
    /// Re-authenticate a single domain (interactive). Minimal: opens its edit screen.
    func reauthenticate(_ entry: DomainEntry)
    /// The gating currently protecting the vault (silent — no prompt).
    var vaultGating: SharedConfig.VaultGating { get }
    /// Switch to biometric gating (legacy menu entry).
    func enrollBiometricLock()
    /// Switch the vault `gating`, preserving its `domainKey`. `newPIN` is required when
    /// `gating` is ``SharedConfig/VaultGating/pin``.
    ///
    /// Awaitable and failable so the caller learns whether the commit actually landed: a
    /// cancelled Touch ID enrollment throws, and the UI must revert its selection rather than
    /// leave a checkbox claiming a gating that was never written.
    ///
    /// `presenceContext` lets a caller that has just proven presence — the Security gate — lend
    /// its capability so the re-key does not prompt a second time for one continuous intent.
    /// Ownership stays with that caller; this must never invalidate it.
    func setVaultGating(_ gating: SharedConfig.VaultGating,
                        newPIN: String?, currentPIN: String?,
                        presenceContext: AnyObject?) async throws
    /// Choose what locking does to a vault (lock, or lock and remove).
    func setLockMethod(_ method: SharedConfig.VaultLockMethod)
    /// Re-arm the auto-lock policy after the Security screen has written new settings.
    func autoLockPolicyDidChange()
    /// Complete a PIN unlock for the named vaults. Returns `false` when the PIN is wrong (the
    /// caller stays on the unlock screen and shows the throttle delay).
    ///
    /// - Parameters:
    ///   - pin: The entered PIN.
    ///   - domainIDs: The vaults the PIN screen was shown for — never widened to every vault.
    func submitUnlockPIN(_ pin: String, domainIDs: [String]) async -> Bool
    /// Seconds the caller must wait before another PIN attempt is accepted.
    var pinRetryDelay: TimeInterval { get }
    /// Whether `pin` opens this install, unlocking nothing.
    ///
    /// The gate in front of the Security screen: it must establish that the user can produce the
    /// gating key before admitting them, without populating any domain's `.unwrapped` slots —
    /// opening the settings screen is not an unlock. Throttled like any other PIN attempt.
    func verifyUnlockPIN(_ pin: String) async -> Bool
    /// Run the install's presence ceremony for its prompt alone, unlocking nothing, and return
    /// the evaluated capability.
    ///
    /// The `.biometric` / `.secure` half of the same gate. Throws what the ceremony failed with,
    /// so a destroyed `.secure` key can be named rather than presented as a retryable error.
    ///
    /// - Returns: The evaluated presence context — **owned by the caller**, which must end it via
    ///   ``SecurityFlow`` — or `nil` for a method needing no presence.
    func evaluateGatingPresence() async throws -> AnyObject?
    /// Count of items with unsynced local changes, used to decide whether locking is
    /// destructive enough to warrant confirmation. `nil` when it could not be determined —
    /// callers then confirm anyway (fail safe).
    func pendingItemCount(for entry: DomainEntry) async -> Int?
    /// Lock the given domains with a plain lock, having passed any required confirmation.
    func confirmedLockAction(domainIDs: [String]) async
    /// Lock and remove the given domains, having passed ``ConfirmLockView`` confirmation.
    func confirmedLockAndRemoveAction(domainIDs: [String])
    /// Open the Security preferences surface.
    func openSecurity()
    /// Delete every configured vault and then the vault root — the recovery from
    /// ``VaultReadiness/orphaned``.
    func resetVault() async
    /// Quit the app.
    func quit()
    /// Whether the vault is usable, and if not why. Computed in one place by ``VaultKeyStore``;
    /// the three presenters (startup, add-domain, unlock) differ only in how they react.
    var vaultReadiness: VaultReadiness { get }
    /// Display names of the BC01 vaults a reset would delete, for the confirmation text.
    var vaultBackedDomainNames: [String] { get }
}

extension AppModelActions {
    /// Re-key without lending a presence capability — the ceremony evaluates its own.
    ///
    /// For every caller that is not the Security gate; keeps `presenceContext` an opt-in for the
    /// one flow that actually has a capability to lend.
    func setVaultGating(_ gating: SharedConfig.VaultGating,
                        newPIN: String?, currentPIN: String?) async throws {
        try await setVaultGating(gating, newPIN: newPIN, currentPIN: currentPIN,
                                 presenceContext: nil)
    }
}

@MainActor
final class AppModel: ObservableObject {
    /// Live domain rows, mirrored from `AppDelegate.domainEntries`.
    @Published private(set) var domains: [DomainEntry] = []
    /// Aggregate icon state, recomputed on every domain update.
    @Published private(set) var activity: StatusActivity = .idle

    /// The live gating-change flow, owning the presence capability that spans the gate and the
    /// settings form. `nil` whenever no such flow is in progress.
    ///
    /// Held here rather than passed through the `Route` because a route is a `Hashable` value the
    /// navigation stack may copy and compare; a capability's owner must be one object with one
    /// lifetime. See ``SecurityFlow``.
    @Published var securityFlow: SecurityFlow?

    /// Whether any vault is orphaned — its `domainKey` wrapper is gone while it remains
    /// configured. Cached from ``AppModelActions/vaultReadiness`` (a keychain read) so the icon
    /// and the popover can consult it without probing the keychain on every render.
    @Published private(set) var vaultOrphaned = false
    /// Popover navigation path.
    @Published var path: [Route] = []
    /// Per-domain progress snapshots relayed from the Provider, keyed by
    /// domain identifier `rawValue`.
    @Published private(set) var snapshots: [String: ProgressSnapshot] = [:]

    /// Host action delegate. Weak: `AppDelegate` owns the model.
    weak var actions: AppModelActions?

    /// Closes the status-bar popover. Set by ``StatusItemController``; invoked by screens
    /// that complete a flow (successful Save / Cancel) so the `.applicationDefined` popover,
    /// which no longer auto-closes on focus loss, is dismissed explicitly.
    var dismissPopover: (() -> Void)?

    /// Re-pins the popover under the status-item button. Set by ``StatusItemController``;
    /// invoked after the OAuth flow returns so a popover that `NSPopover` re-anchored to the
    /// wrong screen (multi-monitor) is snapped back beneath the menu-bar icon.
    var reanchorPopover: (() -> Void)?

    /// Cached add/edit form view model, keyed by the form's identity (`""` = the add flow,
    /// otherwise the existing domain id). Owned here — not as a view `@StateObject` — so the
    /// in-progress draft survives the popover being torn down and rebuilt (re-anchor after
    /// OAuth, or any transient dismissal). Cleared by ``discardDomainForm`` on close.
    private var domainForms: [String: EditDomainViewModel] = [:]

    /// Returns the persistent form view model for an add (`existingDomainID == nil`) or edit
    /// flow, building it once and reusing it across view reconstructions.
    func domainForm(existingDomainID: String?) -> EditDomainViewModel {
        let key = existingDomainID ?? ""
        if let existing = domainForms[key] { return existing }

        let provisioning = actions?.provisioningService ?? NoOpProvisioningService()

        // Read through to the host on every access. The form outlives popover teardowns while
        // `updateDomains` keeps mutating the registry, so a snapshot taken here would be stale
        // by the time Save validates against it.
        let registry: () -> (domains: [NSFileProviderDomain], accounts: [String: DomainAccount]) = {
            [weak actions] in (actions?.knownDomains ?? [], actions?.knownAccounts ?? [:])
        }

        let domain: NSFileProviderDomain
        if let existingDomainID,
           let existing = registry().domains.first(where: { $0.identifier.rawValue == existingDomainID }) {
            domain = existing
        } else {
            domain = actions?.makeNewDomain()
                ?? NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString), displayName: "")
        }

        let form = EditDomainViewModel(domain: domain,
                                       provisioningService: provisioning,
                                       registry: registry)
        domainForms[key] = form
        return form
    }

    /// Drops the cached form for a flow so the next open starts fresh. Call on Save/Cancel.
    func discardDomainForm(existingDomainID: String?) {
        domainForms[existingDomainID ?? ""] = nil
    }

    /// `true` while an add/edit draft is in progress. Used to decide whether re-opening the
    /// popover should resume the page-under-edit rather than reset to Home.
    var hasActiveDomainForm: Bool { !domainForms.isEmpty }

    /// Owns the interactive OneDrive sign-in for the lifetime of the flow. Held on the
    /// model (not the transient form view) so a popover teardown mid-auth doesn't cancel
    /// the awaiting `Task` or deallocate the `ASWebAuthenticationSession`.
    private var oneDriveSignIn: OneDriveSignIn?

    /// Dedicated window used solely as the `ASWebAuthenticationSession` presentation anchor.
    ///
    /// Anchoring to the popover's own window makes the popover resign key when the system
    /// consent prompt appears — tearing the popover (and form) down. A separate off-screen,
    /// invisible window keeps the auth UI off the popover.
    private lazy var authAnchorWindow: NSWindow = {
        let window = NSWindow(contentRect: .zero,
                              styleMask: [.borderless],
                              backing: .buffered,
                              defer: true)
        window.isReleasedWhenClosed = false
        window.alphaValue = 0
        window.ignoresMouseEvents = true
        return window
    }()

    /// Runs the interactive OneDrive sign-in, anchored off the popover so the popover
    /// survives the system consent prompt.
    ///
    /// `domainID` is `nil` for a domain that does not exist yet; the refresh token is then held
    /// pending and the returned handle is the caller's claim on it (see ``OneDriveSignIn``).
    @discardableResult
    func signInToOneDrive(domainID: String?) async throws -> String? {
        authAnchorWindow.orderFront(nil)
        let signIn = OneDriveSignIn()
        oneDriveSignIn = signIn
        defer {
            authAnchorWindow.orderOut(nil)
            oneDriveSignIn = nil
            // The OAuth prompt makes NSPopover re-anchor to the wrong screen on multi-monitor
            // setups; snap it back beneath the status item.
            reanchorPopover?()
        }
        return try await signIn.signIn(presentingFrom: authAnchorWindow, domainID: domainID)
    }

    /// Where a completed ceremony should land.
    ///
    /// The ceremony is one screen with one job — prove the user can produce the gating key — and
    /// this says what it was proven *for*. Keeping it here rather than branching inside
    /// ``UnlockView`` is what lets the ceremony and the Security form stay separate views.
    enum UnlockDestination: Hashable {
        /// Populate the named domains' `.unwrapped` slots; the unlock was the whole point.
        case dismiss
        /// Admit the user to the Security screen.
        ///
        /// A **gate**, not an unlock: no domain's slots are touched. Changing the gating method
        /// re-wraps every domain's `.wrapped` entries, which needs the gating key — and no gating
        /// key survives the operation that obtained it, so the screen is entered only by someone
        /// who has just demonstrated they can produce one.
        case security
    }

    /// Navigation destinations for the popover stack.
    enum Route: Hashable {
        case addDomain
        case editDomain(domainID: String)
        case domainDetail(domainID: String)
        case fileList(domainID: String, kind: FileListKind)
        /// The security settings form. Reached only through the ``UnlockView`` gate; whatever
        /// the re-wrap at Save needs is held by ``AppModel/securityFlow``.
        case security
        /// PIN entry, pushed when unlocking under ``SharedConfig/VaultGating/pin``.
        ///
        /// `domainIDs` scopes the ceremony to the vaults the user actually asked for: one entry
        /// for a per-vault "Unlock Vault", every locked vault for "Unlock Vaults". Dropping the
        /// scope here is what made a single-vault PIN unlock open the whole install.
        ///
        /// `then` names what the unlock was *for*, so the ceremony stays one screen with one
        /// job and the caller decides where a success lands.
        case unlock(domainIDs: [String], then: UnlockDestination = .dismiss)
        /// Destructive-lock confirmation. `pendingCount` is the number of items with unsynced
        /// local changes that locking would discard.
        case confirmLock(domainIDs: [String], pendingCount: Int)
        /// Vault-readiness gate, pushed instead of a flow that needs a usable vault. Carries the
        /// state so the view presents `.locked` (unlock) or `.orphaned` (reset) without
        /// re-deriving it.
        case vaultGate(readiness: VaultReadiness)

        /// The single domain this route is scoped to, if any. Drives route pruning when a
        /// domain disappears. `confirmLock` is deliberately excluded: it is a transient
        /// confirmation over a set of domains, not a view of one.
        var domainID: String? {
            switch self {
            case let .editDomain(domainID),
                 let .domainDetail(domainID),
                 let .fileList(domainID, _):
                return domainID
            case .addDomain, .security, .unlock, .confirmLock, .vaultGate:
                return nil
            }
        }
    }

    enum FileListKind: Hashable {
        case materialized
        case pending
        case recent
    }

    /// Replace the mirrored domains and recompute aggregate activity.
    /// Called by `AppDelegate` on the main actor whenever `domainEntries` changes.
    func setDomains(_ entries: [DomainEntry]) {
        domains = entries
        // Readiness depends on the configured domains, so it is re-read here rather than only at
        // launch: deleting the last vault clears the orphaned state, and adding one can create it.
        refreshVaultReadiness()
        activity = Self.deriveActivity(entries, vaultOrphaned: vaultOrphaned)
        // Seed any domain we have no snapshot for yet from its persisted JSON, so counts are
        // correct on first show without waiting for a Provider change event.
        for entry in entries where snapshots[entry.id] == nil {
            snapshots[entry.id] = ProgressStore.shared.snapshot(for: entry.id)
        }
        pruneRoutesForMissingDomains()
    }

    /// Drop any pushed route whose domain no longer exists, so deleting a vault cannot leave the
    /// stack sitting on a detail/file-list screen for something that is gone.
    ///
    /// Truncates at the first dead route rather than filtering: the routes below it are that
    /// domain's ancestors in the stack, so keeping the tail would strand a file list with no
    /// detail screen behind it. Deleting the vault you are viewing therefore returns you to
    /// ``HomeView``.
    private func pruneRoutesForMissingDomains() {
        let live = Set(domains.map(\.id))
        guard let cut = path.firstIndex(where: { route in
            guard let id = route.domainID else { return false }
            return !live.contains(id)
        }) else { return }
        path.removeSubrange(cut...)
    }

    /// Recompute activity without replacing the array (progress objects mutate in place
    /// via KVO; the host calls this on a throttle to refresh the icon).
    func refreshActivity() {
        activity = Self.deriveActivity(domains, vaultOrphaned: vaultOrphaned)
    }

    func domain(for id: String) -> DomainEntry? {
        domains.first { $0.id == id }
    }

    // MARK: - Vault readiness

    /// Push the add-domain form, or the readiness gate when the vault cannot back a new vault.
    ///
    /// The check belongs here rather than in the Save preflight: a user should learn the vault is
    /// unusable before choosing a `.bckey`, typing a password and waiting through PBKDF2 and a
    /// token round-trip, not after. The preflight call remains as the invariant that nothing is
    /// persisted without a vault root.
    func beginAddDomain() {
        // Read once: the property performs a keychain lookup, and routing on one value while
        // presenting another would be a race with nothing to gain.
        let readiness = actions?.vaultReadiness ?? .ready
        switch readiness {
        case .ready, .locked:
            path.append(.addDomain)
        case .orphaned:
            path.append(.vaultGate(readiness: readiness))
        }
    }

    /// Re-read vault readiness from the host and republish anything derived from it.
    ///
    /// Called at launch and after any change that can create or clear the orphaned state
    /// (domain list changes, a reset, an unlock), so the icon and the popover agree with the
    /// keychain without either of them polling it.
    func refreshVaultReadiness() {
        let orphaned = (actions?.vaultReadiness ?? .ready) == .orphaned
        guard orphaned != vaultOrphaned else { return }
        vaultOrphaned = orphaned
        refreshActivity()
    }

    /// Route the popover to the readiness gate when the vault is orphaned.
    ///
    /// Returns `true` when the gate was pushed and the caller should abandon its own flow. The
    /// single place unlock entry points and the popover-open check share, so "orphaned wins over
    /// locked" is decided once.
    @discardableResult
    func routeToVaultGateIfOrphaned() -> Bool {
        refreshVaultReadiness()
        guard vaultOrphaned else { return false }
        let gate = Route.vaultGate(readiness: .orphaned)
        if path.last != gate { path.append(gate) }
        return true
    }

    /// Route to the Security screen, behind the ceremony gate.
    ///
    /// ``UnlockView`` is a **UI gate** here: the user does not reach the settings form until they
    /// have demonstrated they can produce the gating key. Changing the gating method re-wraps
    /// every domain's `.wrapped` entries, and the gating key needed to do that is forgotten at the
    /// end of every operation — so possession must be established on entry, and re-established at
    /// Save. Whether any domain currently holds `.unwrapped` slots is irrelevant to this: that is
    /// a property of the domains, not of the gating key.
    ///
    /// The gate is therefore driven by the gating *method* alone, with no domain scope — it
    /// unlocks nothing. `.none` is the only method with nothing to prove.
    ///
    /// One helper rather than the same decision at each call site — the menu and the edit-domain
    /// screen's "Change in Security…" link must not disagree about when the gate applies.
    func openSecurity() {
        // A fresh flow per visit: the previous one's capability, if any, ends with it.
        let flow = SecurityFlow()
        securityFlow = flow
        // `.none` has no gating key to produce, so there is nothing to gate on. The flow is still
        // armed: its countdown is also the screen's auto-close, and a settings screen left open in
        // a popover should put itself away whatever the install is gated with.
        guard (actions?.vaultGating ?? .none) != .none else {
            flow.beginWithoutPresence()
            path.append(.security)
            return
        }
        path.append(.unlock(domainIDs: [], then: .security))
    }

    /// End the gating-change flow, dropping its presence capability immediately.
    ///
    /// Called when the user leaves the Security screen by any route. Dropping the reference alone
    /// would leave the end of the capability to ARC; ending it explicitly makes "gone when the
    /// screen goes" a fact rather than a hope.
    func endSecurityFlow() {
        securityFlow?.end()
        securityFlow = nil
    }

    /// Popover-open entry point: show the gate instead of Home when the vault is orphaned, so
    /// the fault is what the user sees first rather than something they must go looking for.
    func prepareForPopoverPresentation() {
        // An in-progress add/edit form keeps its page (the existing resume behaviour); the
        // orphan gate still takes precedence, since no form can be saved without a vault root.
        if !hasActiveDomainForm { path.removeAll() }
        routeToVaultGateIfOrphaned()
    }

    // MARK: - Lock affordances

    /// Whether any vault is currently unlocked — gates the "Lock Vaults" menu item.
    var hasUnlockedVaults: Bool { domains.contains { !$0.locked } }

    /// Whether any vault is currently locked — gates the "Unlock Vaults" menu item.
    var hasLockedVaults: Bool { domains.contains { $0.locked } }

    /// Progress snapshot for a domain (empty if none relayed yet).
    func snapshot(for id: String) -> ProgressSnapshot {
        snapshots[id] ?? ProgressSnapshot()
    }

    /// Store a relayed snapshot (called by `AppDelegate` on the main actor).
    func setSnapshot(_ snapshot: ProgressSnapshot, for id: String) {
        snapshots[id] = snapshot
    }

    /// Load each domain's last-persisted snapshot from disk.
    ///
    /// Snapshots otherwise arrive only via `progressDidChange`, so a freshly-launched app — or
    /// one whose vaults were just unlocked — would show "—" for "Files indexed" until the
    /// Provider next happened to write. The stored JSON is the Provider's most recent report and
    /// is valid immediately.
    func loadPersistedSnapshots() {
        for entry in domains {
            snapshots[entry.id] = ProgressStore.shared.snapshot(for: entry.id)
        }
    }

    // MARK: - Derivation

    /// Icon-state precedence: locked ▸ error ▸ active ▸ idle .
    static func deriveActivity(_ entries: [DomainEntry], vaultOrphaned: Bool = false) -> StatusActivity {
        // Ahead of everything: an orphaned vault root makes every vault unopenable, and no
        // per-domain state the user could act on is more urgent than that.
        if vaultOrphaned { return .vaultError }
        let ignoreAuth = UserDefaults.sharedContainerDefaults.ignoreAuthentication
        for entry in entries where entry.account != nil {
            if entry.locked { return .locked }
        }
        for entry in entries where entry.account != nil {
            if !ignoreAuth, !entry.authenticated { return .error }
        }
        for entry in entries {
            if Self.isActive(entry.uploadProgress) || Self.isActive(entry.downloadProgress) {
                return .active
            }
        }
        return .idle
    }

    private static func isActive(_ progress: Progress?) -> Bool {
        guard let progress else { return false }
        return !progress.isFinished && !progress.isCancelled
    }

    // MARK: - Status summary (hover / title text)

    /// Highest-priority human-readable status line for a single domain, plus the icon
    /// state it maps to. Precedence: error ▸ syncing ▸ indexing ▸ synchronized.
    func statusSummary(for entry: DomainEntry) -> (text: String, activity: StatusActivity) {
        let ignoreAuth = UserDefaults.sharedContainerDefaults.ignoreAuthentication
        if entry.account != nil {
            if vaultOrphaned { return ("Vault key missing", .vaultError) }
            if entry.locked { return (entry.isRemoved ? "Locked / removed" : "Locked / disconnected", .locked) }
            if !ignoreAuth, !entry.authenticated { return ("Not authenticated", .error) }
            if entry.offline { return ("Offline", .error) }
        }

        if let syncing = Self.syncingText(entry.uploadProgress, verb: "Uploading")
            ?? Self.syncingText(entry.downloadProgress, verb: "Downloading") {
            return (syncing, .active)
        }

        let indexed = snapshot(for: entry.id).indexedCount
        if !snapshot(for: entry.id).cryptoOps.isEmpty {
            return ("Indexing… (\(indexed.formatted()) indexed)", .active)
        }

        return ("All files synchronized", .idle)
    }

    /// Aggregate status line for the menu-bar system icon tooltip.
    func aggregateStatusSummary() -> String {
        switch activity {
        case .vaultError:
            return "Vault Sync — vault key missing"
        case .locked:
            return domains.compactMap { entry -> String? in
                let s = statusSummary(for: entry)
                return s.activity == .locked ? "\(entry.displayName): \(s.text)" : nil
            }.first ?? "Vault Sync — locked"
        case .error:
            return domains.compactMap { entry -> String? in
                let s = statusSummary(for: entry)
                return s.activity == .error ? "\(entry.displayName): \(s.text)" : nil
            }.first ?? "Vault Sync — error"
        case .active:
            return domains.compactMap { entry -> String? in
                let s = statusSummary(for: entry)
                return s.activity == .active ? "\(entry.displayName): \(s.text)" : nil
            }.first ?? "Syncing…"
        case .idle:
            return "All files synchronized"
        }
    }

    private static func syncingText(_ progress: Progress?, verb: String) -> String? {
        guard let progress, isActive(progress) else { return nil }
        if let total = progress.fileTotalCount, let completed = progress.fileCompletedCount, total > 0 {
            return "\(verb) \(completed) of \(total)…"
        }
        return "\(verb)…"
    }

    /// "<Backend> (<folder>)" subtitle for a domain, e.g. "OneDrive (root)".
    func backendFolderSubtitle(for entry: DomainEntry) -> String {
        let backend: String
        switch entry.account?.backendKind {
        case .oneDrive: backend = "OneDrive"
        case .emulator: backend = "Emulator"
        case .localFS: backend = "Local"
        case .none: backend = "Unknown"
        }
        let path = entry.account?.remotePath ?? ""
        let folder = path.isEmpty ? "root" : (path as NSString).lastPathComponent
        return "\(backend) (\(folder))"
    }
}
