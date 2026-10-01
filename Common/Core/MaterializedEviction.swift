/// De-materializing evictable content under a File Provider item.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import FileProvider
import Foundation

/// Evicts materialized (downloaded) content, files only.
///
/// The root container and folders are **not** evictable: they have no on-disk representation, so
/// `NSFileProviderManager.evictItem` rejects such a call — with `NSUserCancelledError` (Cocoa
/// 3072) for the root. Passing `.rootContainer` therefore evicts nothing and merely logs a
/// failure, which is why every caller must go through this type instead.
///
/// Rather than walking the folder tree on the server — one round-trip per page — this enumerates
/// the *local* materialized set via `NSFileProviderManager.enumeratorForMaterializedItems()`.
/// Only downloaded items can be evicted, so that set is both the complete and the minimal
/// universe to consider, with no server traffic.
///
/// Shared by the host app's lock flows and the Provider's "evict folder" custom action so the two
/// cannot drift; the host has no other way to reach the same behaviour.
public enum MaterializedEviction {

    /// Evict every materialized file under `target`.
    ///
    /// Per-file failures are collected rather than thrown: one undeletable file (open elsewhere,
    /// say) must not leave the rest of the vault's plaintext on disk.
    ///
    /// - Parameters:
    ///   - target: The container to evict under; `.rootContainer` means the whole domain.
    ///   - manager: The domain's manager.
    ///   - onFileError: Called for each file that could not be evicted, for logging.
    /// - Returns: The number of files successfully evicted.
    /// - Throws: Only if the materialized-set enumeration itself fails.
    @discardableResult
    public static func evictFiles(under target: NSFileProviderItemIdentifier,
                                  manager: NSFileProviderManager,
                                  onFileError: ((NSFileProviderItemIdentifier, Error) -> Void)? = nil)
        async throws -> Int {
        let materialized = try await collectMaterializedItems(
            from: manager.enumeratorForMaterializedItems())
        var evicted = 0
        for fileIdentifier in evictableFiles(under: target, in: materialized) {
            if let error = await evictFile(fileIdentifier, manager: manager) {
                onFileError?(fileIdentifier, error)
            } else {
                evicted += 1
            }
        }
        return evicted
    }

    /// Drains the materialized-items enumerator into a flat list, following pagination.
    /// Reads the local materialized set only; does not contact the server.
    static func collectMaterializedItems(from enumerator: NSFileProviderEnumerator)
        async throws -> [NSFileProviderItemProtocol] {
        final class Collector: NSObject, NSFileProviderEnumerationObserver {
            typealias Page = (items: [NSFileProviderItemProtocol], next: NSFileProviderPage?)
            private var items = [NSFileProviderItemProtocol]()
            private let onFinish: (Result<Page, Error>) -> Void
            init(onFinish: @escaping (Result<Page, Error>) -> Void) { self.onFinish = onFinish }
            func didEnumerate(_ updatedItems: [NSFileProviderItemProtocol]) {
                items.append(contentsOf: updatedItems)
            }
            func finishEnumerating(upTo nextPage: NSFileProviderPage?) {
                onFinish(.success((items, nextPage)))
            }
            func finishEnumeratingWithError(_ error: Error) { onFinish(.failure(error)) }
        }

        var collected = [NSFileProviderItemProtocol]()
        var page: NSFileProviderPage? = NSFileProviderPage.initialPageSortedByName as NSFileProviderPage
        while let current = page {
            let result: Collector.Page = try await withCheckedThrowingContinuation { continuation in
                let observer = Collector(onFinish: { continuation.resume(with: $0) })
                enumerator.enumerateItems(for: observer, startingAt: current)
            }
            collected.append(contentsOf: result.items)
            page = result.next
        }
        return collected
    }

    /// Picks the materialized `.file` items whose ancestry reaches `target`. When `target` is the
    /// root container every materialized file qualifies. Ancestry is resolved from the
    /// materialized set itself, so this is purely local.
    static func evictableFiles(under target: NSFileProviderItemIdentifier,
                               in items: [NSFileProviderItemProtocol]) -> [NSFileProviderItemIdentifier] {
        let parentByID = Dictionary(items.map { ($0.itemIdentifier, $0.parentItemIdentifier) },
                                    uniquingKeysWith: { first, _ in first })

        func isUnder(_ identifier: NSFileProviderItemIdentifier) -> Bool {
            if target == .rootContainer { return true }
            var current: NSFileProviderItemIdentifier? = identifier
            while let id = current, id != .rootContainer {
                if id == target { return true }
                current = parentByID[id]
            }
            return false
        }

        // Items vended by the materialized-items enumerator are system `NSFileProviderItem`s, not
        // our `Item` class — inspect `contentType` rather than casting. Only non-folder content is
        // evictable.
        return items.compactMap { item in
            guard let contentType = item.contentType, contentType != .folder else { return nil }
            return isUnder(item.itemIdentifier) ? item.itemIdentifier : nil
        }
    }

    /// Evicts a single downloaded file, returning any error rather than throwing so the caller can
    /// carry on with the remaining files.
    private static func evictFile(_ identifier: NSFileProviderItemIdentifier,
                                  manager: NSFileProviderManager) async -> Error? {
        await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in
            manager.evictItem(identifier: identifier) { error in continuation.resume(returning: error) }
        }
    }
}
