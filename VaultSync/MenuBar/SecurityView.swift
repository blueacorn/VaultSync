/// Security screen inside the popover nav stack (tasks 29, 41, 47, 51, 52): choose the unlock
/// method protecting **every** vault, the lock method (lock, or lock and remove), and the relock
/// policy (idle timeout + system-event triggers).
///
/// Gating is one enum, ``SharedConfig/VaultGating``, so the screen has a single source of truth
/// for what protects a vault — there is no separate "enabled" state that could disagree with it.
/// Auto-lock is orthogonal: it arms the *triggers*, not the protection.
///
/// Gating is **install-wide** (``SharedConfig/vaultGating``): this is the only
/// screen that chooses it, and committing re-seals every vault's `domainKey` to the new method in
/// one step, behind one ceremony. The edit-domain screen shows the method read-only and routes
/// here — one picker, one commit path.
///
/// **The screen is a form, not a live control panel.** Every field edits a draft; nothing reaches
/// the vault or ``SharedConfigStore`` until `Save`. This is what fixes the re-keying storm: the
/// PIN field used to re-mint the gating key and re-wrap every domain key on *each keystroke*, so
/// a user typing a six-digit PIN raced six overlapping re-key passes against each other. A draft
/// plus one commit means one re-key, after the entry is known to be complete.
///
/// Re-keying also needs the *current* gating key — every vault is opened under the old method
/// before being re-sealed to the new one. That ceremony is **not** part of this screen: it runs
/// first, in ``UnlockView``, and this screen is only reached once it has succeeded (see
/// ``AppModel/openSecurity()``). Two screens with one job each, rather than a settings form that
/// sometimes grows a PIN prompt.
///
/// The ceremony is required whenever gating is not `.none`, **including when the vaults are
/// already unlocked**. No gating key is retained past the operation that obtained it: the presence
/// context is invalidated as soon as the call that created it returns (see
/// ``VaultKeyStore/withPresenceContext(for:reason:_:)``), so "the vaults are open" says nothing
/// about whether the key needed to re-wrap them is available.
///
/// Follows the popover panel idiom (``HomeHeader`` + `Divider` + vertically-sized content, then a
/// Cancel/Save footer); width comes from ``HomeRootView``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Common
import SwiftUI


/// The gating selection state machine behind ``SecurityView``, as a value.
///
/// Extracted from the view so the rules — a draft is only committable when it differs from the
/// vault *and* is internally valid, and a failed commit reverts to what the vault holds — are
/// testable without SwiftUI. The view owns presentation; this owns what is true.
struct GatingSelection: Equatable {
    /// What the form shows.
    private(set) var selected: SharedConfig.VaultGating
    /// What the vault actually holds.
    private(set) var committed: SharedConfig.VaultGating
    /// True while a commit is in flight.
    private(set) var committing = false

    init(committed: SharedConfig.VaultGating) {
        self.selected = committed
        self.committed = committed
    }

    /// Select `target` in the draft. Nothing is written until a commit is run.
    mutating func select(_ target: SharedConfig.VaultGating) {
        selected = target
    }

    /// Mark a commit as started.
    mutating func beginCommit() { committing = true }

    /// The commit landed: the vault now holds `target`.
    mutating func commitSucceeded(_ target: SharedConfig.VaultGating) {
        committing = false
        committed = target
        selected = target
    }

    /// The commit threw. Revert the selection to what the vault actually holds — the 49.2 fix:
    /// a cancelled Touch ID enrollment never reaches `writeGating`, so leaving the choice on
    /// would claim a protection the vault does not have.
    mutating func commitFailed() {
        committing = false
        selected = committed
    }

    /// Whether the draft differs from what the vault holds, i.e. Save has gating work to do.
    var isDirty: Bool { selected != committed }

    /// Whether the draft is internally consistent and may be committed.
    ///
    /// Generalises the task-41 PIN rule: `.pin` is not committable until the entry satisfies
    /// ``PINPolicy``. A clean draft is trivially valid — there is nothing to apply.
    ///
    /// - Parameter pinIsValid: Whether the entered PIN satisfies ``PINPolicy``.
    func canCommit(pinIsValid: Bool) -> Bool {
        guard !committing else { return false }
        if selected == .pin, !pinIsValid { return false }
        return true
    }

    /// Whether the screen may be left without losing a change: nothing in flight, and the draft
    /// agrees with the vault.
    ///
    /// Leaving with a dirty draft is not blocked — `Cancel` discards it, which is the point of a
    /// form — but the caller uses this to decide whether discarding needs saying out loud.
    var isSettled: Bool { !committing && !isDirty }
}

struct SecurityView: View {
    @ObservedObject var model: AppModel
    private var actions: AppModelActions? { model.actions }

    private let store = SharedConfigStore.shared

    // MARK: Draft state
    //
    // Every one of these is a *draft*: edited freely, written only by `save()`. The previous
    // screen wrote each on `.onChange`, which is what let a PIN keystroke start a re-key.

    @State private var enabled: Bool
    @State private var gating: SharedConfig.VaultGating
    @State private var lockMethod: SharedConfig.VaultLockMethod
    @State private var pin: String = ""
    @State private var confirmPIN: String = ""
    /// Selection vs. what the vault actually holds.
    @State private var selection: GatingSelection
    /// Inline failure text for the selected method — enrollment or PIN commit.
    @State private var gatingError: String?
    /// Whether `.secure` can be offered on this Mac.
    ///
    /// Asked of the ceremony, not of a hard-wired gate type — `GatingCeremony.isAvailable` is the
    /// one place availability is defined, so this screen cannot drift from what commit enforces.
    private let secureEnclaveAvailable: Bool = SecureEnclaveCeremony(
        gate: SecureEnclaveKeyGate()).isAvailable
    @State private var timeoutSeconds: Int
    @State private var onScreenLock: Bool
    @State private var onLogout: Bool
    @State private var onRestart: Bool
    @State private var onQuit: Bool

    /// The gating-change flow: owns the presence capability (and, under `.pin`, the verified PIN)
    /// that the ``UnlockView`` gate established.
    ///
    /// This screen shows no ceremony UI of its own — it borrows what the gate proved. Under
    /// `.pin` the gating key is *derived from the secret*, so the PIN itself is what Save needs;
    /// under the presence methods it is the evaluated context, lent for the duration of the
    /// re-key so one continuous intent costs one prompt.
    @ObservedObject var flow: SecurityFlow

    /// Idle-timeout choices (label → seconds). 0 disables the idle timer.
    private static let timeouts: [(String, Int)] = [
        ("1 minute", 60), ("5 minutes", 300), ("15 minutes", 900), ("30 minutes", 1800),
        ("1 hour", 3600), ("2 hours", 7200), ("4 hours", 14400), ("8 hours", 28800),
        ("12 hours", 43200), ("Never", 0),
    ]

    init(model: AppModel, flow: SecurityFlow) {
        self.model = model
        self.flow = flow
        let c = SharedConfigStore.shared.snapshot()
        _enabled = State(initialValue: c.autoLockEnabled)
        let current = model.actions?.vaultGating ?? .none
        _gating = State(initialValue: current)
        _selection = State(initialValue: GatingSelection(committed: current))
        _lockMethod = State(initialValue: c.vaultLockMethod)
        _timeoutSeconds = State(initialValue: c.lockTimeoutSeconds)
        _onScreenLock = State(initialValue: c.lockOnScreenLock)
        _onLogout = State(initialValue: c.lockOnLogout)
        _onRestart = State(initialValue: c.lockOnRestart)
        _onQuit = State(initialValue: c.lockOnQuit)
    }

    // MARK: - Validation

    /// Whether the new-PIN entry satisfies ``PINPolicy``.
    private var pinIsValid: Bool { PINPolicy.isValid(pin) }

    /// Whether the confirmation matches the new PIN. A mis-typed PIN cannot be recovered from —
    /// it is never stored in reversible form — so it is confirmed before it is enrolled.
    private var pinsMatch: Bool { pin == confirmPIN }

    /// Whether the PIN half of the draft is complete: valid and confirmed.
    ///
    /// Only meaningful when `.pin` is newly selected or its PIN is being changed; a `.pin` draft
    /// that is already committed and left untouched needs no entry at all.
    private var pinEntryIsUsable: Bool { pinIsValid && pinsMatch }

    /// Whether a new PIN must be supplied to save: `.pin` is selected and either it is a change
    /// of method or the user has started typing a replacement PIN.
    private var requiresNewPIN: Bool {
        gating == .pin && (selection.isDirty || !pin.isEmpty || !confirmPIN.isEmpty)
    }

    /// Whether the gating half of the draft may be committed.
    private var gatingIsCommittable: Bool {
        guard selection.canCommit(pinIsValid: requiresNewPIN ? pinEntryIsUsable : true) else {
            return false
        }
        if requiresNewPIN, !pinEntryIsUsable { return false }
        return true
    }

    /// Whether the auto-lock / lock-method halves differ from what is stored.
    private var policyIsDirty: Bool {
        let c = store.snapshot()
        return enabled != c.autoLockEnabled
            || lockMethod != c.vaultLockMethod
            || timeoutSeconds != c.lockTimeoutSeconds
            || onScreenLock != c.lockOnScreenLock
            || onLogout != c.lockOnLogout
            || onRestart != c.lockOnRestart
            || effectiveOnQuit != c.lockOnQuit
    }

    /// Whether anything at all has been edited.
    private var isDirty: Bool { selection.isDirty || requiresNewPIN || policyIsDirty }

    /// Pre-flight: whether `Save` may run, and why not when it may not.
    ///
    /// One evaluation for the button's disabled state and its inline explanation, so the two can
    /// never disagree about whether the form is savable.
    private var saveBlockedReason: String? {
        if selection.committing { return "Applying…" }
        if requiresNewPIN {
            if let violation = PINPolicy.validate(pin) { return PINPolicy.message(for: violation) }
            if !pinsMatch { return "The PINs don't match." }
        }
        return nil
    }

    private var canSave: Bool {
        guard isDirty else { return false }
        guard saveBlockedReason == nil else { return false }
        return gatingIsCommittable
    }

    /// The value actually written for "on application quit": forced on whenever another trigger
    /// is armed, so the stored config matches the read-only checkbox the user was shown.
    private var effectiveOnQuit: Bool { quitLockIsForced ? true : onQuit }

    /// Whether the quit checkbox is forced on (and therefore read-only) by another trigger.
    ///
    /// Evaluated from the *draft*, through the same rule the config uses, so the checkbox reacts
    /// as the user toggles the other triggers rather than reflecting what was last saved.
    private var quitLockIsForced: Bool {
        var draft = SharedConfig()
        draft.lockOnScreenLock = onScreenLock
        draft.lockOnLogout = onLogout
        draft.lockOnRestart = onRestart
        draft.lockTimeoutSeconds = timeoutSeconds
        return draft.quitLockIsForced
    }

    private func leave() {
        if !model.path.isEmpty { model.path.removeLast() }
    }

    /// Abandon the change: the capability ends with the intent that justified it.
    private func cancel() {
        model.endSecurityFlow()
        leave()
    }

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(backAction: { leave() }) {
                Text("Security").font(.headline)
                Spacer()
                Image(systemName: gating == .none ? "lock.open" : "lock.fill")
                    .foregroundStyle(gating == .none ? AnyShapeStyle(.secondary) : AnyShapeStyle(.green))
            }
            Divider()

            Form {
                gatingSection
                lockMethodSection
                autoLockSection
            }
            .formStyle(.grouped)

            Divider()
            footer
        }
        // Any interaction with the form is user activity: it restarts the idle countdown, so the
        // capability expires only on someone who has actually walked away.
        .onChange(of: gating) { _ in flow.noteActivity() }
        .onChange(of: pin) { _ in flow.noteActivity() }
        .onChange(of: confirmPIN) { _ in flow.noteActivity() }
        .onChange(of: lockMethod) { _ in flow.noteActivity() }
        .onChange(of: enabled) { _ in flow.noteActivity() }
        .onChange(of: timeoutSeconds) { _ in flow.noteActivity() }
        .onChange(of: onScreenLock) { _ in flow.noteActivity() }
        .onChange(of: onLogout) { _ in flow.noteActivity() }
        .onChange(of: onRestart) { _ in flow.noteActivity() }
        .onChange(of: onQuit) { _ in flow.noteActivity() }
        // The capability is gone, so the screen that exists to spend it must go too — leaving it
        // up would offer a Save that could only fail, or silently re-prompt. Under `.none` there
        // is no capability and this is purely the auto-close.
        .onChange(of: flow.didExpire) { expired in
            if expired { model.endSecurityFlow(); leave() }
        }
        // Belt and braces for the countdown. `openSecurity()` arms every flow it creates, but
        // this view must not depend on having been reached that way: an unarmed flow would be the
        // one screen that never puts itself away, and the failure would be silent.
        .task {
            if !flow.isCountingDown { flow.beginWithoutPresence() }
        }
    }

    /// Cancel discards the draft outright; Save applies it. Matches ``EditDomainView``'s footer.
    private var footer: some View {
        HStack {
            if let saveBlockedReason {
                Text(saveBlockedReason)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Cancel") { cancel() }
                .disabled(selection.committing)
            Button(selection.committing ? "Saving…" : "Save") { save() }
                .disabled(!canSave)
                .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Sections

    /// A four-way drop-down; the only place the method is chosen, so screens cannot drift.
    ///
    /// The description beneath updates with the selection because the user is trading security
    /// against convenience and the trade must be visible at the point of choice — the `.secure`
    /// warning in particular, which names the one routine system action that destroys the key.
    /// Copy comes from ``SharedConfig/VaultGating/unlockDescription`` so the edit-domain screen
    /// shows the same words.
    private var gatingSection: some View {
        Section("Unlock method") {
            Picker("Protection", selection: gatingBinding) {
                ForEach(SharedConfig.VaultGating.displayOrder, id: \.self) { option in
                    Text(option.displayName)
                        .tag(option)
                        // `.secure` needs an enclave with an enrolled finger; offering it on a
                        // Mac without one would fail at commit rather than at the point of choice.
                        .disabled(option == .secure && !secureEnclaveAvailable)
                }
            }
            .disabled(selection.committing)

            if gating == .pin { pinFields }

            if let gatingError {
                Text(gatingError).font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            gatingDescription

            // Install-wide: one method, every vault, one ceremony to change it.
            Text("This is the unlock method for all your vaults. Changing it re-protects every "
                 + "vault in one step when you save, and applies to vaults you add from now on.")
                .font(.caption).foregroundStyle(.secondary)

            Text(VaultLockCopy.lockedDomainConsequence)
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    /// The live description for the current selection, plus the `.secure` warning when it
    /// applies. The warning is emphasised rather than run into the paragraph: it is the only
    /// case where an ordinary system action causes unrecoverable loss.
    @ViewBuilder
    private var gatingDescription: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(gating.unlockDescription)
                .font(.caption).foregroundStyle(.secondary)
            if let warning = gating.secureEnclaveWarning {
                Label(warning, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).bold()
                    .foregroundStyle(.orange)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    /// New PIN + confirmation. Typing here changes **nothing** but this draft — the enrollment
    /// happens once, in ``save()``.
    @ViewBuilder
    private var pinFields: some View {
        SecureField(selection.committed == .pin ? "New PIN" : "PIN", text: $pin)
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: .infinity)
            .onChange(of: pin) { entered in
                pin = Self.digits(entered)
                gatingError = nil
            }
        SecureField("Confirm PIN", text: $confirmPIN)
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: .infinity)
            .onChange(of: confirmPIN) { entered in
                confirmPIN = Self.digits(entered)
                gatingError = nil
            }

        if selection.committed == .pin, !requiresNewPIN {
            Text("Leave blank to keep your current PIN.")
                .font(.caption).foregroundStyle(.secondary)
        } else if requiresNewPIN, let violation = PINPolicy.validate(pin) {
            Text(PINPolicy.message(for: violation))
                .font(.caption).foregroundStyle(.secondary)
        } else if requiresNewPIN, !pinsMatch {
            Text("The PINs don't match.")
                .font(.caption).foregroundStyle(.red)
        } else {
            Text("\(PINPolicy.minLength)–\(PINPolicy.maxLength) digits.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var lockMethodSection: some View {
        Section("Lock method") {
            Picker("When locking", selection: $lockMethod) {
                Text("Lock Vault").tag(SharedConfig.VaultLockMethod.lock)
                Text("Lock and Remove Vault").tag(SharedConfig.VaultLockMethod.lockAndRemove)
            }

            Text(lockMethod == .lock
                 ? "Disconnects each vault and removes downloaded content from this Mac."
                 : "Also removes the vault from Finder and clears its cached metadata. Your "
                   + "settings are kept, so unlocking restores the vault; files on the server "
                   + "are never touched.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    /// The enable toggle lives here: only the idle/trigger controls are conditional, while the
    /// unlock- and lock-method groups stay visible at all times.
    private var autoLockSection: some View {
        Section("Auto-lock") {
            Toggle("Auto-lock vaults", isOn: $enabled)
            Text("Locks vaults automatically on the triggers below. Locking evicts usable "
                 + "key material until you unlock.")
                .font(.caption).foregroundStyle(.secondary)

            if enabled { autoLockTriggers }
        }
    }

    @ViewBuilder
    private var autoLockTriggers: some View {
        Picker("After idle", selection: $timeoutSeconds) {
            ForEach(Self.timeouts, id: \.1) { Text($0.0).tag($0.1) }
        }
        Toggle("When the screen locks", isOn: $onScreenLock)
        Toggle("On logout", isOn: $onLogout)
        Toggle("On restart / shutdown", isOn: $onRestart)

        // Forced on by any other trigger: quitting removes the process that would have performed
        // the relock, so a vault set to lock on idle but not on quit would survive the one event
        // that guarantees nothing else can evict it.
        Toggle("On application quit", isOn: Binding(
            get: { effectiveOnQuit },
            set: { onQuit = $0 }))
            .disabled(quitLockIsForced)
        if quitLockIsForced {
            Text("Always on while another auto-lock trigger is selected — quitting is the one "
                 + "event after which nothing is left running to lock your vaults.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - Method selection

    /// Binding behind the drop-down. Records the draft only; ``save()`` is the sole commit path.
    private var gatingBinding: Binding<SharedConfig.VaultGating> {
        Binding(
            get: { gating },
            set: { next in
                guard next != gating else { return }
                gating = next
                gatingError = nil
                if next != .pin { pin = ""; confirmPIN = "" }
                selection.select(next)
            }
        )
    }

    /// Keep a PIN field numeric-only as typed, and bounded by the policy.
    private static func digits(_ entered: String) -> String {
        String(entered.filter(\.isNumber).prefix(PINPolicy.maxLength))
    }

    // MARK: - Save

    /// Apply the whole draft: gating first (it can fail), then the policy settings.
    ///
    /// Ordered deliberately. The gating commit is the only step that can throw, and a policy
    /// write that had already landed would leave the screen reporting a partial success. Writing
    /// the policy only after gating has settled means Save either applies everything it was asked
    /// to or reports why it did not.
    private func save() {
        guard canSave else { return }

        let gatingChanged = selection.isDirty || requiresNewPIN
        guard gatingChanged else {
            savePolicy()
            leave()
            return
        }

        guard let actions else { return }
        let target = gating
        let newPIN = requiresNewPIN ? pin : nil
        // Switching *away* from `.pin` still needs it: every vault is opened under the current
        // method before being re-sealed to the new one.
        let suppliedCurrentPIN = selection.committed == .pin ? flow.currentPIN : nil

        selection.beginCommit()
        Task { @MainActor in
            do {
                // The capability is *borrowed* for the call and no longer: `withPresence` lends
                // it, and the flow — its owner — ends it as soon as the re-key lands.
                try await flow.withPresence { context in
                    try await actions.setVaultGating(target,
                                                     newPIN: newPIN,
                                                     currentPIN: suppliedCurrentPIN,
                                                     presenceContext: context)
                }
                selection.commitSucceeded(target)
                gating = selection.selected
                gatingError = nil
                savePolicy()
                // The intent is complete, so the presence capability dies here rather than
                // waiting for the screen to be torn down.
                model.endSecurityFlow()
                leave()
            } catch {
                selection.commitFailed()
                gating = selection.selected
                if selection.selected != .pin { pin = ""; confirmPIN = "" }
                gatingError = Self.message(for: error)
            }
        }
    }

    /// Write the auto-lock and lock-method halves of the draft.
    ///
    /// `effectiveOnQuit` rather than the raw toggle: what is stored must be what the (possibly
    /// forced, read-only) checkbox showed.
    private func savePolicy() {
        store.write(\.vaultLockMethod, lockMethod)
        store.write(\.autoLockEnabled, enabled)
        store.write(\.lockTimeoutSeconds, timeoutSeconds)
        store.write(\.lockOnScreenLock, onScreenLock)
        store.write(\.lockOnLogout, onLogout)
        store.write(\.lockOnRestart, onRestart)
        store.write(\.lockOnQuit, effectiveOnQuit)
        // The store is the record; the controller holds the live timer and observers, so it is
        // told to re-read rather than left running the policy this Save just replaced.
        actions?.autoLockPolicyDidChange()
    }

    /// User-facing text for a failed gating commit.
    private static func message(for error: Error) -> String {
        switch error {
        case VaultKeyStoreError.biometricsUnavailable:
            return "Touch ID isn't available on this Mac."
        case VaultKeyStoreError.secureEnclaveUnavailable:
            return "This Mac has no Secure Enclave, or no fingerprint is enrolled."
        case VaultKeyStoreError.keychain:
            return "The unlock method couldn't be saved to the keychain."
        case PINGateError.incorrectPIN:
            return "That current PIN is incorrect."
        default:
            return "Couldn't set this unlock method. \(error.localizedDescription)"
        }
    }
}
