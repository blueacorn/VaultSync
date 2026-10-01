/// Materialized / pending / recent file list.
///
/// Backed by ``FileListModel`` (an OS Replicated enumerator projection). Renders each item
/// with a relative timestamp, tap-to-open, and a `(..)` more-menu (open folder, view online
/// for remote backends). A `[Clear]` footer clears the local list.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import SwiftUI
import FileProvider
import Common

struct FileListView: View {
    @ObservedObject var model: AppModel
    let domainID: String
    let kind: AppModel.FileListKind

    @StateObject private var list: FileListModel

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f
    }()

    init(model: AppModel, domainID: String, kind: AppModel.FileListKind) {
        self.model = model
        self.domainID = domainID
        self.kind = kind
        let domain = model.domain(for: domainID)?.domain
            ?? NSFileProviderDomain(identifier: .init(rawValue: domainID), displayName: "")
        _list = StateObject(wrappedValue: FileListModel(domain: domain, kind: kind))
    }

    private var isRemote: Bool {
        model.domain(for: domainID)?.account?.backendKind == .oneDrive
    }

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(title: title, chip: nil,
                       backAction: { if !model.path.isEmpty { model.path.removeLast() } })
            Divider()

            content

            Divider()
            HStack {
                Button("Back") { if !model.path.isEmpty { model.path.removeLast() } }
                    .buttonStyle(.plain)
                Button("Clear") { list.clear() }
                    .buttonStyle(.plain)
                Spacer()
                SettingsMenu(model: model, actions: model.actions, domainContext: model.domain(for: domainID))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private var content: some View {
        if let error = list.errorMessage {
            Text(error).foregroundStyle(.red).padding()
        } else if list.rows.isEmpty {
            Text(kind == .pending ? "All files synchronized" : "No items")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
        } else {
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(list.rows) { row in
                        FileRow(row: row,
                                relativeDate: relativeString(row.modificationDate),
                                isRemote: isRemote,
                                onOpen: { list.open(row) },
                                onOpenFolder: { list.revealInFinder(row, enclosingFolder: true) },
                                onViewOnline: { list.revealInFinder(row, enclosingFolder: false) })
                        Divider()
                    }
                }
            }
            .frame(minHeight: 200, maxHeight: 320)
        }
    }

    private func relativeString(_ date: Date?) -> String {
        guard let date else { return "" }
        return Self.relativeFormatter.localizedString(for: date, relativeTo: Date())
    }

    private var title: String {
        switch kind {
        case .materialized: return "Materialized"
        case .pending: return "Pending"
        case .recent: return "Recently synched"
        }
    }
}

struct FileRow: View {
    let row: FileListModel.Row
    let relativeDate: String
    let isRemote: Bool
    let onOpen: () -> Void
    let onOpenFolder: () -> Void
    let onViewOnline: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: row.isFolder ? "folder" : "doc")
                .foregroundStyle(.secondary)
            Text(row.filename)
                .lineLimit(1)
                .onTapGesture(perform: onOpen)
            Spacer()
            Text(relativeDate)
                .font(.caption)
                .foregroundStyle(.secondary)
            Menu {
                Button("Open Folder") { onOpenFolder() }
                if isRemote {
                    Button("View Online") { onViewOnline() }
                }
            } label: {
                Image(systemName: "ellipsis")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .frame(width: 28)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .contentShape(Rectangle())
    }
}
