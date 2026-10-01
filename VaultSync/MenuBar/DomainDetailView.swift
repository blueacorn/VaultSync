/// Existing-domain detail (view mode).
///
/// Shows the domain header and navigation into the materialized / pending file lists.
/// The materialized-count and pending-count figures are fed by the progress relay.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import SwiftUI
import Common

struct DomainDetailView: View {
    @ObservedObject var model: AppModel
    let domainID: String

    private var entry: DomainEntry? { model.domain(for: domainID) }
    private var snapshot: ProgressSnapshot { model.snapshot(for: domainID) }

    /// Full-crawl progress while one runs (the cached row count is then the pre-crawl total),
    /// otherwise the cached row count.
    private var indexedText: String {
        if let seen = snapshot.fullCrawlItemsSeen {
            return "Indexing… \(seen.formatted()) items scanned"
        }
        return snapshot.indexedCount > 0
            ? "\(snapshot.indexedCount.formatted()) files indexed"
            : "—"
    }

    private var pendingActive: Bool {
        guard let entry else { return false }
        return AppModel.deriveActivity([entry]) == .active
    }

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(backAction: { if !model.path.isEmpty { model.path.removeLast() } }) {
                if let entry {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.displayName)
                            .font(.headline)
                            .lineLimit(1)
                        Text(model.backendFolderSubtitle(for: entry))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    DomainStateIcon(model: model, entry: entry)
                } else {
                    Text("Vault").font(.headline)
                    Spacer()
                }
            }
            Divider()

            VStack(spacing: 8) {
                DetailPanel(title: "Files indexed",
                            value: indexedText,
                            onOpen: { model.path.append(.fileList(domainID: domainID, kind: .materialized)) })
                DetailPanel(title: "Sync status",
                            value: pendingActive ? "Syncing…" : "All files synchronized",
                            onOpen: { model.path.append(.fileList(domainID: domainID,
                                                                  kind: pendingActive ? .pending : .recent)) })
                if !snapshot.cryptoOps.isEmpty {
                    CryptoOpsPanel(ops: snapshot.cryptoOps)
                }
            }
            .padding(8)

            Divider()
            HStack {
                Button("Back") { if !model.path.isEmpty { model.path.removeLast() } }
                    .buttonStyle(.plain)
                if let entry {
                    Button {
                        model.path.append(.editDomain(domainID: entry.id))
                    } label: {
                        Label("Edit", systemImage: "pencil")
                    }
                        .buttonStyle(.plain)
                        .help("Edit")
                }
                Spacer()
                SettingsMenu(model: model, actions: model.actions, domainContext: entry)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }
}

/// Lists active encrypt/decrypt operations relayed from the Provider.
///
/// The op list is the one part of this panel with no upper bound — the Provider relays a row per
/// in-flight operation. The popover sizes itself to its content, so an unbounded list would grow
/// the panel past the screen; the rows therefore scroll within a ceiling while the panel itself
/// keeps self-sizing, as ``FileListView`` does.
///
/// The cap binds only once the rows exceed it — a couple of operations occupy a couple of rows,
/// so short content is never stretched. Note it is the *scrolling region* that is bounded, never
/// the panel: pinning a height on the panel stretches short content and pushes it off-screen.
struct CryptoOpsPanel: View {
    let ops: [CryptoOp]

    /// Height at which the op rows begin to scroll instead of growing the panel. Roughly six
    /// rows — enough that scrolling is rare, low enough to leave the footer room alongside the
    /// other panels on a short screen.
    private static let maxRowsHeight: CGFloat = 132

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Encryption")
                .font(.caption).foregroundStyle(.secondary)
            // `.fixedSize(vertical:)` keeps the scroll view asking for exactly the rows' height
            // until it reaches the cap, so one op renders as one row rather than an empty box.
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(ops) { op in
                        HStack(spacing: 8) {
                            Image(systemName: op.direction == .encrypt ? "lock.fill" : "lock.open.fill")
                                .foregroundStyle(.secondary)
                            Text(op.name).lineLimit(1)
                            Spacer()
                            if let fraction = op.fractionCompleted {
                                ProgressView(value: fraction).frame(width: 60)
                            } else {
                                ProgressView().controlSize(.small)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: Self.maxRowsHeight)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct DetailPanel: View {
    let title: String
    let value: String
    let onOpen: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.caption).foregroundStyle(.secondary)
                Text(value)
            }
            Spacer()
            Button(action: onOpen) { Image(systemName: "chevron.right") }
                .buttonStyle(.plain)
        }
        .padding(10)
        .background(Color.primary.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onTapGesture(perform: onOpen)
    }
}
