/// Enumerator-backed model for the menu-bar materialized / pending file lists.
///
/// Runs the OS Replicated `NSFileProviderManager` enumerator (materialized or pending)
/// and projects each item into a lightweight ``Row`` carrying the filename and
/// modification date, so the list can render relative timestamps and a per-row menu.
/// This mirrors the enumeration bookkeeping in `Common`'s `EnumerationView` but exposes
/// a richer row for the redesigned UI.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit
import Foundation
import FileProvider
import Combine
import os.log

@MainActor
final class FileListModel: NSObject, ObservableObject, NSFileProviderEnumerationObserver, NSFileProviderChangeObserver {
    struct Row: Identifiable, Hashable {
        let id: String
        let filename: String
        let modificationDate: Date?
        let isFolder: Bool
        let itemIdentifier: NSFileProviderItemIdentifier
    }

    @Published private(set) var rows: [Row] = []
    @Published private(set) var errorMessage: String?

    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "filelist")
    private let domain: NSFileProviderDomain
    private let enumerator: NSFileProviderEnumerator
    private var anchor: NSFileProviderSyncAnchor?
    /// Max rows shown (spec: last N = 50).
    private let limit = 50

    init(domain: NSFileProviderDomain, kind: AppModel.FileListKind) {
        self.domain = domain
        let manager = NSFileProviderManager(for: domain)
        switch kind {
        case .pending:
            enumerator = manager?.enumeratorForPendingItems() ?? EmptyEnumerator()
        case .materialized, .recent:
            enumerator = manager?.enumeratorForMaterializedItems() ?? EmptyEnumerator()
        }
        super.init()
        enumerator.enumerateItems(for: self, startingAt: NSFileProviderPage.initialPageSortedByDate as NSFileProviderPage)
    }

    /// Clear the local list (spec `[Clear]`). Non-destructive: only clears the in-memory
    /// projection; the OS-side materialized/pending sets are untouched.
    func clear() { rows.removeAll() }

    // MARK: NSFileProviderEnumerationObserver

    nonisolated func didEnumerate(_ updatedItems: [NSFileProviderItemProtocol]) {
        let mapped = updatedItems.map(Self.makeRow)
        Task { @MainActor in self.append(mapped) }
    }

    nonisolated func finishEnumerating(upTo nextPage: NSFileProviderPage?) {
        guard let nextPage else { return }
        Task { @MainActor in
            guard self.rows.count < self.limit else { return }
            self.enumerator.enumerateItems(for: self, startingAt: nextPage)
        }
    }

    nonisolated func finishEnumeratingWithError(_ error: Error) {
        Task { @MainActor in self.errorMessage = error.localizedDescription }
    }

    // MARK: NSFileProviderChangeObserver

    nonisolated func didUpdate(_ updatedItems: [NSFileProviderItemProtocol]) {
        let mapped = updatedItems.map(Self.makeRow)
        Task { @MainActor in self.append(mapped) }
    }

    nonisolated func didDeleteItems(withIdentifiers deletedItemIdentifiers: [NSFileProviderItemIdentifier]) {
        Task { @MainActor in
            self.rows.removeAll { deletedItemIdentifiers.contains($0.itemIdentifier) }
        }
    }

    nonisolated func finishEnumeratingChanges(upTo anchor: NSFileProviderSyncAnchor, moreComing: Bool) {}

    // MARK: - Helpers

    private func append(_ newRows: [Row]) {
        for row in newRows {
            if let idx = rows.firstIndex(where: { $0.id == row.id }) {
                rows[idx] = row
            } else {
                rows.append(row)
            }
        }
        // Newest first, capped at the display limit.
        rows.sort { ($0.modificationDate ?? .distantPast) > ($1.modificationDate ?? .distantPast) }
        if rows.count > limit { rows = Array(rows.prefix(limit)) }
    }

    private nonisolated static func makeRow(_ item: NSFileProviderItemProtocol) -> Row {
        Row(id: item.itemIdentifier.rawValue,
            filename: item.filename,
            modificationDate: (item.contentModificationDate ?? nil),
            isFolder: item.contentType == .folder,
            itemIdentifier: item.itemIdentifier)
    }

    /// Reveal the item (or its enclosing folder) in Finder.
    func revealInFinder(_ row: Row, enclosingFolder: Bool) {
        guard let manager = NSFileProviderManager(for: domain) else { return }
        let target = enclosingFolder ? NSFileProviderItemIdentifier.rootContainer : row.itemIdentifier
        Task {
            do {
                let url = try await manager.getUserVisibleURL(for: target)
                let stop = url.startAccessingSecurityScopedResource()
                defer { if stop { url.stopAccessingSecurityScopedResource() } }
                NSWorkspace.shared.selectFile(url.path, inFileViewerRootedAtPath: "")
            } catch {
                self.logger.error("❌ reveal failed: \(error.localizedDescription)")
            }
        }
    }

    /// Open the item with its default app.
    func open(_ row: Row) {
        guard let manager = NSFileProviderManager(for: domain) else { return }
        Task {
            do {
                let url = try await manager.getUserVisibleURL(for: row.itemIdentifier)
                let stop = url.startAccessingSecurityScopedResource()
                defer { if stop { url.stopAccessingSecurityScopedResource() } }
                NSWorkspace.shared.open(url)
            } catch {
                self.logger.error("❌ open failed: \(error.localizedDescription)")
            }
        }
    }
}

/// No-op enumerator used when a manager cannot be created for the domain (keeps the model
/// non-optional and simply produces an empty list).
private final class EmptyEnumerator: NSObject, NSFileProviderEnumerator {
    func invalidate() {}
    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        observer.finishEnumerating(upTo: nil)
    }
}
