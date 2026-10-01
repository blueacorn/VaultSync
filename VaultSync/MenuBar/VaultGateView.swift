/// Vault-readiness gate inside the popover nav stack.
///
/// Pushed instead of a flow that needs a usable vault, so the user learns the vault is unusable
/// *before* investing in a `.bckey`, a password and a token round-trip — not after.
///
/// One screen for both unusable states, because they differ only in the remedy:
/// ``VaultReadiness/locked`` offers an unlock, ``VaultReadiness/orphaned`` offers the destructive
/// reset. ``VaultReadiness/ready`` never reaches here (callers do not push the route), and is
/// rendered defensively rather than with a fatal error.
///
/// Follows the popover panel idiom (``HomeHeader`` + self-sizing content + footer); width comes
/// from ``HomeRootView``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Common
import SwiftUI

struct VaultGateView: View {
    @ObservedObject var model: AppModel
    let readiness: VaultReadiness
    private var actions: AppModelActions? { model.actions }

    @State private var resetting = false

    /// The vaults a reset would delete, named in the confirmation so the destructive scope is
    /// stated rather than implied.
    private var affectedVaults: [String] { actions?.vaultBackedDomainNames ?? [] }

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(backAction: { dismiss() }) {
                Text(title).font(.headline)
                Spacer()
                Image(systemName: readiness == .orphaned ? "exclamationmark.triangle.fill" : "lock.fill")
                    .foregroundStyle(readiness == .orphaned ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
            }
            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Text(message).font(.callout)
                if readiness == .orphaned {
                    affectedVaultList
                    Text("Files on the server are never touched — this removes the vaults from "
                         + "this Mac and starts a new vault key.")
                        .font(.caption).foregroundStyle(.secondary)
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
                if resetting { ProgressView().controlSize(.small) }
                primaryButton
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }

    // MARK: - Content

    private var title: String {
        switch readiness {
        case .locked: return "Vault Locked"
        case .orphaned: return "Vault Key Missing"
        case .ready: return "Vault Ready"
        }
    }

    private var message: String {
        switch readiness {
        case .locked:
            return "Your vault is locked. Unlock it to continue."
        case .orphaned:
            return "The key that protects your vaults is no longer on this Mac. Encrypted "
                 + "contents can no longer be opened, and no vault can be unlocked. Resetting "
                 + "removes your vaults and starts a new vault key."
        case .ready:
            return "Your vault is ready."
        }
    }

    @ViewBuilder
    private var affectedVaultList: some View {
        if affectedVaults.isEmpty {
            Text("No vaults are configured.")
                .font(.caption).foregroundStyle(.secondary)
        } else {
            VStack(alignment: .leading, spacing: 2) {
                Text("These vaults will be deleted:")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(affectedVaults, id: \.self) { name in
                    Text("• \(name)").font(.caption)
                }
            }
        }
    }

    @ViewBuilder
    private var primaryButton: some View {
        switch readiness {
        case .locked:
            Button("Unlock") { actions?.unlockVaults(); dismiss() }
                .keyboardShortcut(.defaultAction)
        case .orphaned:
            Button("Reset Vault", role: .destructive) { reset() }
                .disabled(resetting)
        case .ready:
            Button("Continue") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
    }

    // MARK: - Actions

    private func dismiss() {
        if !model.path.isEmpty { model.path.removeLast() }
    }

    private func reset() {
        guard !resetting else { return }
        resetting = true
        Task { @MainActor in
            await actions?.resetVault()
            resetting = false
            dismiss()
        }
    }
}
