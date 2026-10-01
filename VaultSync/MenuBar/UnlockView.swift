/// Unlock screen for locked vaults (tasks 41, 51).
///
/// Per-selection: gating is per domain, so this screen presents the ceremony the
/// locked vaults actually need rather than assuming a PIN. It asks for a PIN only when some
/// locked vault is gated ``SharedConfig/VaultGating/pin``; a vault gated
/// ``SharedConfig/VaultGating/secure`` gets no PIN field and no password-fallback affordance,
/// because the Secure Enclave offers neither and showing either would promise a way in that does
/// not exist.
///
/// Failed PIN attempts impose an escalating delay from ``PINAttemptThrottle`` — backoff only,
/// never a lockout — so the Unlock button is disabled while a delay is outstanding.
///
/// Follows the popover panel idiom (``HomeHeader`` + self-sizing content + footer); width comes
/// from ``HomeRootView``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Common
import SwiftUI

struct UnlockView: View {
    @ObservedObject var model: AppModel
    /// The vaults this screen's ceremony is for — one for a per-vault "Unlock Vault", every
    /// locked vault for "Unlock Vaults". Never widened: a credential entered to open one vault
    /// does not authorise the rest.
    ///
    /// Required, and required to be non-empty. The screen has no default and no fallback to
    /// "every vault": an unlock whose scope is unknown must open **nothing**, because the
    /// failure mode of guessing is opening vaults the user never asked for. ``hasValidScope``
    /// disables submission and states the fault rather than running a ceremony that could only
    /// be wrong.
    let domainIDs: [String]

    /// What this ceremony was run for — where a success lands. Defaults to simply dismissing,
    /// which is what every "Unlock Vault(s)" button wants.
    var then: AppModel.UnlockDestination = .dismiss

    /// Whether this screen knows which vaults it is for. Fail-safe: `false` blocks the ceremony.
    ///
    /// The gate in front of Security is exempt: it opens nothing, so it has no scope to get
    /// wrong. The rule guards *unlocks* — an unlock whose scope is unknown must open nothing.
    private var hasValidScope: Bool { isGate || !domainIDs.isEmpty }

    /// Whether this screen is admitting the user to a settings screen rather than unlocking.
    ///
    /// In gate mode no domain's `.unwrapped` slots are touched: the user proves they can produce
    /// the gating key, and that proof is the entire outcome.
    private var isGate: Bool { then == .security }
    private var actions: AppModelActions? { model.actions }

    @State private var pin: String = ""
    @State private var errorText: String?
    @State private var submitting = false
    @State private var retryRemaining: TimeInterval = 0

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    // MARK: - What the locked vaults need

    /// The unlock method every locked vault shares.
    ///
    /// A single value: gating is install-wide, so there is no union of differing
    /// requirements to compute — one method, one ceremony, one prompt for all of them.
    private var lockedGating: SharedConfig.VaultGating {
        actions?.vaultGating ?? .none
    }

    /// Whether a PIN must be collected before anything can be opened. PIN entry is the only
    /// ceremony that needs input up front; the others prompt themselves.
    private var needsPIN: Bool { lockedGating == .pin }

    /// Whether the vaults are gated by the enclave, which changes what the screen may promise:
    /// Touch ID only, and no way back if the key was destroyed.
    private var hasSecure: Bool { lockedGating == .secure }

    private var canSubmit: Bool {
        guard hasValidScope, !submitting, retryRemaining <= 0 else { return false }
        return needsPIN ? PINPolicy.isValid(pin) : true
    }

    /// What the user is being asked to do, in one line.
    ///
    /// The method is install-wide, so these cases are mutually exclusive.
    private var prompt: String {
        if !hasValidScope { return Self.noScopeMessage }
        if then == .security {
            // The Security screen re-wraps every domain key, which requires the *current* gating
            // key — and no gating key outlives the operation that obtained it, so it is obtained
            // here whether or not the vaults happen to be open.
            return needsPIN
                ? "Enter your PIN to change your security settings."
                : "Confirm it's you to change your security settings."
        }
        if needsPIN {
            return "Enter your PIN to unlock."
        } else if hasSecure {
            return "Confirm with Touch ID to unlock. Your Mac's password will not work for "
                 + "these vaults."
        }
        return "Unlock to reconnect your vaults."
    }

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(backAction: { dismiss() }) {
                Text(Self.title(for: then, vaultCount: domainIDs.count)).font(.headline)
                Spacer()
                Image(systemName: "lock.fill").foregroundStyle(.secondary)
            }
            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Text(prompt)
                    .font(.caption).foregroundStyle(.secondary)

                // No PIN field under `.secure` or `.biometric` — those ceremonies collect their
                // own credential, and an inert field would read as a fallback that is not there.
                if needsPIN { pinField }

                // Stated for every vault rather than only the encrypted ones: a plaintext
                // vault's refresh token is gated like any other domain secret, so it stops
                // serving too. No branch on the encryption algorithm.
                Text(VaultLockCopy.lockedDomainConsequence)
                    .font(.caption).foregroundStyle(.secondary)

                if retryRemaining > 0 {
                    Text("Too many attempts — try again in \(Int(retryRemaining.rounded()))s.")
                        .font(.caption).foregroundStyle(.secondary)
                } else if let errorText {
                    Text(errorText).font(.caption).foregroundStyle(.red)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer(minLength: 0)
            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .buttonStyle(.plain)
                Spacer()
                if submitting { ProgressView().controlSize(.small) }
                Button(isGate ? "Continue" : "Unlock") { submit() }
                    .disabled(!canSubmit)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
        .onReceive(ticker) { _ in
            if retryRemaining > 0 { retryRemaining = max(0, retryRemaining - 1) }
        }
    }

    private var pinField: some View {
        SecureField("PIN", text: $pin)
            .textFieldStyle(.roundedBorder)
            .frame(width: 120)
            .onChange(of: pin) { entered in
                let digits = String(entered.filter(\.isNumber).prefix(PINPolicy.maxLength))
                if digits != entered { pin = digits }
                errorText = nil
            }
            .onSubmit { submit() }
    }

    private func dismiss() {
        if !model.path.isEmpty { model.path.removeLast() }
    }

    /// Land a successful ceremony where the caller asked.
    ///
    /// The Security screen *replaces* this one rather than stacking on top of it: the ceremony is
    /// finished, and leaving it behind would put a spent PIN prompt in the user's way on Back.
    private func proceed() {
        switch then {
        case .dismiss:
            dismiss()
        case .security:
            // Replaces this screen rather than stacking on it: the gate is spent, and Back must
            // not lead the user through it a second time.
            if !model.path.isEmpty { model.path.removeLast() }
            // What Save needs is already held by the flow (see `passGate`), so the route itself
            // carries nothing.
            model.path.append(.security)
        }
    }

    /// Header title for what this ceremony is for.
    private static func title(for destination: AppModel.UnlockDestination,
                              vaultCount: Int) -> String {
        switch destination {
        case .security: return "Confirm It's You"
        case .dismiss:  return vaultCount == 1 ? "Unlock Vault" : "Unlock Vaults"
        }
    }

    private func submit() {
        // Re-checked here, not only in `canSubmit`: `.keyboardShortcut(.defaultAction)` and
        // `.onSubmit` can both fire this, and a scope-less unlock must be impossible by every
        // route, not merely discouraged by a disabled button.
        guard hasValidScope else { errorText = Self.noScopeMessage; return }
        guard canSubmit else { return }
        submitting = true
        Task { @MainActor in
            let ok: Bool
            if isGate {
                ok = await passGate()
            } else if needsPIN {
                ok = await actions?.submitUnlockPIN(pin, domainIDs: domainIDs) ?? false
            } else {
                ok = await unlockWithoutPIN()
            }
            submitting = false
            if ok {
                proceed()
            } else if needsPIN, !isGate {
                // The gate reports its own failure (and its own backoff) in `passGate`.
                pin = ""
                errorText = "Incorrect PIN."
                retryRemaining = actions?.pinRetryDelay ?? 0
            }
        }
    }

    /// Establish that the user can produce the gating key, **without unlocking anything**.
    ///
    /// The gate in front of the Security screen. Under `.pin` the secret is verified through the
    /// throttled path, so a wrong entry here costs the same backoff as one at the unlock screen.
    /// Under the presence methods the ceremony is evaluated for its prompt alone.
    ///
    /// No domain's `.unwrapped` slots are populated either way: entering a settings screen is not
    /// an unlock, and the gating key this proves is forgotten the moment the check returns — as it
    /// is after every operation. Save re-establishes it.
    ///
    /// - Returns: `true` when the user may be admitted.
    @MainActor
    private func passGate() async -> Bool {
        guard let actions else { return false }
        errorText = nil
        if needsPIN {
            let ok = await actions.verifyUnlockPIN(pin)
            if ok {
                // The PIN, not a context: a PIN-derived gating key is re-derived from the secret
                // at Save, so that is what the flow carries.
                model.securityFlow?.admit(context: nil, pin: pin)
            } else {
                pin = ""
                errorText = "Incorrect PIN."
                retryRemaining = actions.pinRetryDelay
            }
            return ok
        }
        do {
            // Evaluates the ceremony for its presence prompt and opens nothing. Deliberately not
            // `unlockVaults(domainIDs: [])`: that returns silently on an empty list, so the gate
            // would pass without ever prompting.
            //
            // The evaluated capability is handed straight to the flow, which owns it from here
            // and ends it when the change lands or is abandoned. Holding it is what keeps the
            // Save from prompting a second time for one continuous intent.
            let context = try await actions.evaluateGatingPresence()
            model.securityFlow?.admit(context: context)
            return true
        } catch {
            let destroyedEnclave = lockedGating == .secure
                && (error as? VaultKeyStoreError) == .gatingKeyMissing
            errorText = destroyedEnclave ? Self.secureFailureMessage : Self.genericFailureMessage
            return false
        }
    }

    /// Run the prompting ceremonies (`.biometric`, `.secure`) for the locked vaults.
    ///
    /// Each unlock is awaited and its error caught, so the failure is *diagnosed* rather than
    /// inferred: a vault left locked cannot say why it is locked — a cancelled Touch ID prompt
    /// and a destroyed Secure Enclave key look identical from the domain rows. Only the thrown
    /// error separates them, and under `.secure` that distinction decides whether the screen
    /// invites a retry or names a cause no retry can fix (see ``secureFailureMessage``).
    ///
    /// Vaults are opened in sequence. Each carries its own gating and its own `domainKey`, so one
    /// failure is reported without abandoning the rest.
    ///
    /// - Returns: `true` when every vault this screen was shown for is now open.
    @MainActor
    private func unlockWithoutPIN() async -> Bool {
        guard let actions, hasValidScope else { return false }
        errorText = nil
        do {
            // The batch path, not a loop: one presence evaluation opens every vault in scope, so
            // N vaults cost one prompt.
            try await actions.unlockVaults(domainIDs: domainIDs)
            return true
        } catch {
            // `gatingKeyMissing` under `.secure` is the destroyed-enclave case: the ACL carries
            // `.biometryCurrentSet`, so an enrollment change takes the key with it. Anything else
            // — a cancelled prompt above all — is retryable and must not claim otherwise.
            let destroyedEnclave = lockedGating == .secure
                && (error as? VaultKeyStoreError) == .gatingKeyMissing
            errorText = destroyedEnclave ? Self.secureFailureMessage : Self.genericFailureMessage
            return false
        }
    }

    /// The `.secure` failure, as its own case rather than a generic unlock error.
    ///
    /// A Touch ID enrollment change destroys the install's Secure Enclave key: the ACL carries
    /// `.biometryCurrentSet`, so `SecItemCopyMatching` for the key returns a status other than
    /// `errSecItemNotFound`, ``SecureEnclaveKeyGate`` logs it and throws
    /// ``VaultKeyStoreError/gatingKeyMissing``, and the unlock cannot succeed on any later
    /// attempt. Reporting that as "unlock failed" would send the user round a loop with no exit,
    /// so the enrollment change is named as the cause.
    ///
    /// It never says "sign in again": re-authentication cannot succeed while the
    /// credential is sealed, and under `.secure` the seal is permanent.
    static let secureFailureMessage =
        "Couldn't unlock with Touch ID. If you have added or removed a fingerprint since setting "
        + "these vaults up, the Secure Enclave key was destroyed and cannot be recovered — "
        + "remove these vaults and add them again."

    /// Shown when the screen was pushed without a scope. Names the fault instead of unlocking
    /// something arbitrary — there is no safe guess, so there is no ceremony to offer.
    static let noScopeMessage =
        "No vault was selected to unlock. Go back and choose a vault."

    /// The failure for every other gating. Says "unlock", never "sign in again".
    static let genericFailureMessage =
        "Couldn't unlock these vaults. \(VaultLockCopy.lockedCallToAction)"
}
