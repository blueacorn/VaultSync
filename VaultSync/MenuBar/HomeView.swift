/// Home screen: header, domain list, footer (+ add / Settings).
///
/// Root of the popover stack. Lists ``DomainEntry`` rows from ``AppModel``; the `+`
/// button pushes the add-domain form and `S` opens the Settings menu (Tweaks / Lock
/// Vaults / Quit). A faint shield watermark sits behind the list per the UI spec.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import SwiftUI
import Common

struct HomeView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(title: "VAULT SYNC", chipSystemImage: "house.fill")
            Divider()

            ZStack {
                ShieldWatermark()
                content
            }

            Divider()
            HomeFooter(
                model: model,
                leadingLabel: model.domains.isEmpty ? "Click to add Vault Sync" : nil,
                onAdd: { model.beginAddDomain() },
                actions: model.actions
            )
        }
    }

    @ViewBuilder
    private var content: some View {
        if model.domains.isEmpty {
            Button(action: model.beginAddDomain) {
                VStack(spacing: 8) {
                    Image(systemName: "plus.circle")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No vaults yet")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Add Vault")
        } else {
            VStack(spacing: 4) {
                ForEach(model.domains) { entry in
                    DomainRow(model: model, entry: entry) {
                        // A locked vault has nothing to show in detail, so the row opens the
                        // unlock ceremony instead — scoped to this vault alone.
                        model.path.append(entry.locked
                            ? .unlock(domainIDs: [entry.id])
                            : .domainDetail(domainID: entry.id))
                    }
                }
            }
            .padding(8)
        }
    }
}

// MARK: - Header

struct HomeHeader<TitleContent: View>: View {
    let title: String
    let chip: String?
    let chipSystemImage: String?
    var backAction: (() -> Void)?
    @ViewBuilder let titleContent: () -> TitleContent

    /// Standard header: chevron (optional) + accent chip + centered headline title.
    init(title: String,
         chip: String? = nil,
         chipSystemImage: String? = nil,
         backAction: (() -> Void)? = nil) where TitleContent == EmptyView {
        self.title = title
        self.chip = chip
        self.chipSystemImage = chipSystemImage
        self.backAction = backAction
        self.titleContent = { EmptyView() }
    }

    /// Rich header: caller injects the title block (e.g. two-line domain title + icon).
    init(backAction: (() -> Void)? = nil,
         @ViewBuilder titleContent: @escaping () -> TitleContent) {
        self.title = ""
        self.chip = nil
        self.chipSystemImage = nil
        self.backAction = backAction
        self.titleContent = titleContent
    }

    var body: some View {
        HStack(spacing: 8) {
            if let backAction {
                Button(action: backAction) {
                    Image(systemName: "chevron.left")
                }
                .buttonStyle(.plain)
                .help("Back")
            }
            if TitleContent.self != EmptyView.self {
                titleContent()
            } else {
                chipView
                Spacer()
                Text(title)
                    .font(.headline)
                Spacer()
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private var chipView: some View {
        if chip != nil || chipSystemImage != nil {
            Group {
                if let chipSystemImage {
                    Image(systemName: chipSystemImage)
                        .font(.caption.weight(.bold))
                } else if let chip {
                    Text(chip).font(.caption2.weight(.bold))
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.accentColor.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 4))
        }
    }
}

// MARK: - Footer

struct HomeFooter: View {
    @ObservedObject var model: AppModel
    let leadingLabel: String?
    let onAdd: () -> Void
    weak var actions: AppModelActions?

    var body: some View {
        HStack {
            Button(action: onAdd) {
                Image(systemName: "plus")
            }
            .buttonStyle(.plain)
            .help("Add Vault Sync")

            if let leadingLabel {
                Text(leadingLabel)
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }
            Spacer()
            SettingsMenu(model: model, actions: actions)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

// MARK: - Settings menu

struct SettingsMenu: View {
    /// Supplies the lock/unlock affordance state (which vaults exist, and whether they are
    /// locked). Needed because "Lock Vaults" / "Unlock Vaults" are shown only when they would
    /// actually do something.
    @ObservedObject var model: AppModel
    weak var actions: AppModelActions?
    /// When set, a domain-scoped section (Lock / Unlock / Re-authenticate) is prepended.
    var domainContext: DomainEntry?

    var body: some View {
        Menu {
            if let entry = domainContext {
                Section(entry.displayName) {
                    // A removed vault has no registered domain, so it has no folder to open.
                    if !entry.isRemoved {
                        Button("Open Folder") { actions?.openInFinder(entry) }
                    }
                    if entry.locked {
                        Button("Unlock Vault") { actions?.unlockVault(entry) }
                    } else {
                        Button("Lock Vault") { actions?.lockVault(entry) }
                    }
                    if !UserDefaults.sharedContainerDefaults.ignoreAuthentication,
                       !entry.authenticated {
                        Button("Re-authenticate…") { actions?.reauthenticate(entry) }
                    }
                    Divider()
                    Button("Delete Vault…", role: .destructive) { actions?.removeDomain(entry) }
                }
                Divider()
            }
            Button("Tweaks…") { actions?.openTweaks() }
            Button("Security…") { actions?.openSecurity() }
            // Only offer an action that has something to act on.
            if model.hasUnlockedVaults {
                Button("Lock Vaults") { actions?.lockVaults() }
            }
            if model.hasLockedVaults {
                Button("Unlock Vaults") { actions?.unlockVaults() }
            }
            // Recovery of last resort. Offered only when there is something to reset, and routed
            // through the same gate view as the add-domain block so the confirmation naming the
            // affected vaults is written once.
            if !(actions?.vaultBackedDomainNames.isEmpty ?? true) {
                Button("Delete All Vaults and Reset Vault Keys", role: .destructive) {
                    model.path.append(.vaultGate(readiness: .orphaned))
                }
            }
            Divider()
            Button("Quit Vault Sync") { actions?.quit() }
        } label: {
            Image(systemName: "gearshape")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help("Settings")
    }
}

// MARK: - Watermark

struct ShieldWatermark: View {
    var body: some View {
        Image(systemName: "shield")
            .resizable()
            .scaledToFit()
            .frame(width: 120, height: 120)
            .foregroundStyle(.quaternary)
            .opacity(0.4)
            .allowsHitTesting(false)
    }
}

// MARK: - Domain row

struct DomainRow: View {
    @ObservedObject var model: AppModel
    let entry: DomainEntry
    let onOpen: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            BackendLogo(kind: entry.account?.backendKind)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.displayName)
                    .lineLimit(1)
                if let subtitle = entry.account?.remotePath, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            DomainStateIcon(model: model, entry: entry)
            Button(action: onOpen) {
                Image(systemName: "chevron.right")
            }
            .buttonStyle(.plain)
        }
        .padding(8)
        .background(Color.primary.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onTapGesture(perform: onOpen)
        .contextMenu {
            if !entry.isRemoved {
                Button("Open Folder") { model.actions?.openInFinder(entry) }
            }
            if entry.locked {
                Button("Unlock Vault") { model.actions?.unlockVault(entry) }
            } else {
                Button("Lock Vault") { model.actions?.lockVault(entry) }
            }
        }
    }
}

struct BackendLogo: View {
    let kind: BackendKind?

    var body: some View {
        Image(systemName: symbolName)
            .foregroundStyle(.secondary)
            .frame(width: 20)
    }

    private var symbolName: String {
        switch kind {
        case .oneDrive: return "cloud"
        case .emulator: return "server.rack"
        case .localFS: return "folder"
        case .none: return "questionmark.circle"
        }
    }
}

/// Per-domain state glyph: spinner while active, error badge if unauthenticated /
/// disconnected, otherwise a static shield.
struct DomainStateIcon: View {
    @ObservedObject var model: AppModel
    let entry: DomainEntry

    var body: some View {
        let summary = model.statusSummary(for: entry)
        icon(for: summary.activity)
            .imageScale(.large)
            .font(.title3)
            .help(summary.text)
    }

    @ViewBuilder
    private func icon(for activity: StatusActivity) -> some View {
        switch activity {
        case .active:
            ProgressView().controlSize(.small)
        case .locked:
            // Ahead of `.error`: a locked vault is a state the user chose (or can simply undo by
            // unlocking), not a fault, and the red warning triangle reads as the latter.
            Image(systemName: "lock.fill")
                .foregroundStyle(.secondary)
        case .error, .vaultError:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        case .idle:
            Image(systemName: "shield.fill")
                .foregroundStyle(.secondary)
        }
    }
}
