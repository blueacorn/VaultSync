/// NSFileProviderEnumerator implementation for directory listing
//
//  Abstract:
//  An enumerator class that provides details about files and changes.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common
import os.log
import CoreServices
import UniformTypeIdentifiers

extension DomainService.RankToken {
    init(_ anchor: NSFileProviderSyncAnchor) throws {
        self = try JSONDecoder().decode(DomainService.RankToken.self, from: anchor.rawValue)
    }
}

extension NSFileProviderSyncAnchor {
    init(_ token: DomainService.RankToken) {
        self.init(rawValue: try! JSONEncoder().encode(token))
    }
}

extension NSFileProviderPage {
    init(_ cursor: DomainService.PageCursor) {
        self.init(Data(cursor.rawValue.utf8))
    }

    /// The backend cursor this page carries, or `nil` for the first page — either one of the
    /// framework's initial-page sentinels or bytes that are not a cursor we issued.
    var pageCursor: DomainService.PageCursor? {
        if self == NSFileProviderPage.initialPageSortedByDate as NSFileProviderPage ||
            self == NSFileProviderPage.initialPageSortedByName as NSFileProviderPage {
            return nil
        }
        guard let raw = String(data: rawValue, encoding: .utf8), !raw.isEmpty else { return nil }
        return DomainService.PageCursor(raw)
    }
}

class ItemEnumerator: NSObject, NSFileProviderEnumerator
{
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "enumeration")

    let enumeratedItemIdentifier: DomainService.ItemIdentifier
    let backend: ProviderBackend
    let recursive: Bool

    internal var presentationStatusTimerSource: DispatchSourceTimer? = nil
    internal let enumerationIndex = Int64.random(in: 0...Int64.max)

    /// Default number of items per `didEnumerate` batch when the observer offers no
    /// suggestion. Kept well under the File Provider 20000-items-per-batch ceiling that
    /// triggers `__FILEPROVIDER_OBSERVER_TOO_MANY_ITEMS__`.
    static let defaultEnumerationBatchSize = 1000

    /// Hard upper bound on items per `didEnumerate` batch, regardless of the observer's
    /// suggestion. Guarantees a single batch never approaches the 20000 framework ceiling.
    static let maxEnumerationBatchSize = 2000

    /// The per-batch item count to use for an observer: its `suggestedPageSize` when offered
    /// (positive), else ``defaultEnumerationBatchSize``, always clamped to
    /// ``maxEnumerationBatchSize``. Both `enumerateItems` and `enumerateChanges` must batch
    /// their `didEnumerate`/`didUpdate`/`didDeleteItems` calls through this — a single call
    /// exceeding 20000 items trips the framework's `__FILEPROVIDER_OBSERVER_TOO_MANY_ITEMS__`
    /// assertion and aborts the whole enumeration.
    static func batchSize(suggested: Int) -> Int {
        max(1, min(suggested > 0 ? suggested : defaultEnumerationBatchSize, maxEnumerationBatchSize))
    }

    override var description: String {
        var parts = [String]()
        parts.append("\(enumeratedItemIdentifier)")
        if recursive {
            parts.append("recursive")
        }
        if let timer = presentationStatusTimerSource {
            parts.append("ping via \(timer)s")
        }
        return "\(super.description) \(parts.joined(separator: ", "))"
    }

    init(enumeratedItemIdentifier: NSFileProviderItemIdentifier, backend: ProviderBackend, recursive: Bool = false) {
        self.enumeratedItemIdentifier = DomainService.ItemIdentifier(enumeratedItemIdentifier)
        self.backend = backend
        self.recursive = recursive
        super.init()
        setupForPresentationStatusTracking()
    }

    static let untrackedTypes: [UTType] = ["com.apple.iwork.pages.sffpages", "com.apple.iwork.pages.pages-tef"].compactMap(UTType.init)

    static func shouldTrackPresentationStatus(for type: UTType) -> Bool {
        for untrackedType in ItemEnumerator.untrackedTypes where type.conforms(to: untrackedType) {
            return false
        }
        return true
    }

    func setupForPresentationStatusTracking() {
        backend.fetchItem(self.enumeratedItemIdentifier) { response in
            switch response {
            case .failure:
                // Ignore failures.
                break
            case .success(let res):
                // When an app presents a file, the system opens an enumerator
                // on the file to track it. VaultSync then displays a lock icon
                // in Finder next to any items that are in use. VaultSync implements
                // the icon as an `NSFileProviderItemDecoration`, using the `inUseDecoration`
                // decoration identifier.
                let displayName = self.backend.displayEntry(res.item).name
                if res.item.type == .file,
                    let type = UTType(tag: (displayName as NSString).pathExtension, tagClass: .filenameExtension, conformingTo: .data),
                    ItemEnumerator.shouldTrackPresentationStatus(for: type) {
                    self.pingPresentationStatus()

                    let source = DispatchSource.makeTimerSource(flags: [], queue: nil)
                    source.setEventHandler { [weak self] in
                        self?.pingPresentationStatus()
                    }
                    source.schedule(deadline: DispatchTime.now(),
                                    repeating: .milliseconds(Int(DomainService.PingLockParameter.pingInterval * 1000.0)), leeway: .milliseconds(500))
                    source.resume()
                    self.presentationStatusTimerSource = source
                }
            }
        }
    }

    func pingPresentationStatus() {
        // Regularly ping the server to inform it that the user is still looking at the item.
        backend.pingLock(enumeratedItemIdentifier, owner: backend.displayName, enumerationIndex: enumerationIndex)
    }

    func invalidate() {
        //logger.infoPublic("➡️  enumerator.invalidate(\(enumeratedItemIdentifier.id))")
        if let source = presentationStatusTimerSource {
            source.cancel()
            // Inform the server when the enumerator is no longer needed.
            backend.removeLock(enumeratedItemIdentifier, enumerationIndex: enumerationIndex)
        }
    }

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        logger.infoPublic("➡️  enumerateItems(\(enumeratedItemIdentifier.id)) cursor(\(page.pageCursor?.rawValue ?? "<start>")) recursive=\(recursive)")
        // Wall-clock from the framework's call into us through to `finishEnumerating`, so a
        // slow folder open can be attributed to the backend fetch versus our own delivery of
        // the batches to the observer.
        let started = DispatchTime.now()
        func since() -> Double {
            Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000_000
        }
        _ = backend.listFolder(enumeratedItemIdentifier, recursive: recursive, startingCursor: page.pageCursor) { result in
            switch result {
            case .failure(let error):
                self.logger.errorPublic("❌ enumerateItems(\(self.enumeratedItemIdentifier.id)) failed: \(String(describing: error))")
                observer.finishEnumeratingWithError(error.toPresentableError())
            case .success(let response):
                let items: [Item] = response.entries.compactMap { (entry) -> Item? in
                    if entry.id == ServerEmulatorClient.trashItemIdentifier { return nil }
                    let enc = self.backend.isBackendEncrypted(entry)
                    return Item(self.backend.displayEntry(entry),
                                supportsMoveToTrash: self.backend.supportsMoveToTrash,
                                isEncrypted: enc)
                }

                // Deliver items in sub-batches bounded by the observer's suggested page
                // size (clamped to our hard ceiling) so a single didEnumerate call can
                // never exceed the 20000-items-per-batch framework limit. suggestedPageSize
                // is an optional protocol member and may be absent or non-positive.
                let backendElapsed = since()
                let chunk = Self.batchSize(suggested: observer.suggestedPageSize ?? 0)
                for start in stride(from: 0, to: items.count, by: chunk) {
                    let end = min(start + chunk, items.count)
                    observer.didEnumerate(Array(items[start..<end]))
                }
                self.logger.infoPublic("⏱️ enumerateItems(\(self.enumeratedItemIdentifier.id)) items=\(items.count) chunk=\(chunk) backend=\(String(format: "%.2f", backendElapsed))s deliver=\(String(format: "%.2f", since() - backendElapsed))s total=\(String(format: "%.2f", since()))s")

                if let cursor = response.cursor {
                    observer.finishEnumerating(upTo: NSFileProviderPage(cursor))
                } else {
                    observer.finishEnumerating(upTo: nil)
                }
            }
        }
    }

    func currentSyncAnchor() async -> NSFileProviderSyncAnchor? {
        logger.infoPublic("➡️  currentSyncAnchor(\(enumeratedItemIdentifier.id))")
        do {
            let response = try await self.backend.latestRank(self.enumeratedItemIdentifier)
            return NSFileProviderSyncAnchor(response.rank)
        } catch {
            // Returning nil disables incremental change enumeration for this enumerator —
            // File Provider then never calls `enumerateChanges(from:)`, so working-set
            // remote-change delivery silently stops. Return a zero anchor so the change
            // feed stays enabled. A zero anchor makes the *next* `enumerateChanges` return
            // the full tree as "changes", but that is now bounded: `enumerateChanges`
            // batches its `didUpdate` calls (see `Self.batchSize`), so a large set no
            // longer trips the framework's 20000-items ceiling.
            logger.errorPublic("⚓️ currentSyncAnchor(\(self.enumeratedItemIdentifier.id)) failed (\(String(describing: error))) → zero anchor")
            return NSFileProviderSyncAnchor(DomainService.RankToken(rank: 0, tokenCheckNumber: 0))
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
        logger.infoPublic("➡️  enumerateChanges(\(enumeratedItemIdentifier.id)) recursive=\(recursive)")
        let rankToken: DomainService.RankToken
        do {
            rankToken = try DomainService.RankToken(anchor)
        } catch {
            observer.finishEnumeratingWithError(NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.syncAnchorExpired.rawValue,
                                                        userInfo: nil))
            return
        }

        logger.debugPublic("🔁 enumerateChanges(\(enumeratedItemIdentifier.id)) from rank=\(rankToken.rank) recursive=\(recursive)")
        Task {
            do {
                let response = try await self.backend.listChanges(enumeratedItemIdentifier, recursive: recursive, startingRank: rankToken)
                self.logger.debugPublic("🔁 enumerateChanges(\(self.enumeratedItemIdentifier.id)) → \(response.entries.count) updated, \(response.deletedEntries?.count ?? 0) deleted, newRank=\(response.rank.rank)")

                // Batch both deletions and updates: a single didDeleteItems/didUpdate call
                // exceeding the 20000-items framework ceiling trips
                // __FILEPROVIDER_OBSERVER_TOO_MANY_ITEMS__ and aborts the enumeration. This
                // is exactly the working-set change feed, which can carry the whole changed
                // subtree after a cursor reset.
                let chunk = Self.batchSize(suggested: observer.suggestedBatchSize ?? 0)

                let deleted = (response.deletedEntries ?? []).map(NSFileProviderItemIdentifier.init)
                for start in stride(from: 0, to: deleted.count, by: chunk) {
                    let end = min(start + chunk, deleted.count)
                    observer.didDeleteItems(withIdentifiers: Array(deleted[start..<end]))
                }

                let updated: [Item] = response.entries.compactMap { (entry) -> Item? in
                    if entry.id == ServerEmulatorClient.trashItemIdentifier { return nil }
                    let enc = self.backend.isBackendEncrypted(entry)
                    return Item(self.backend.displayEntry(entry),
                                supportsMoveToTrash: self.backend.supportsMoveToTrash,
                                isEncrypted: enc)
                }
                for start in stride(from: 0, to: updated.count, by: chunk) {
                    let end = min(start + chunk, updated.count)
                    observer.didUpdate(Array(updated[start..<end]))
                }

                observer.finishEnumeratingChanges(upTo: NSFileProviderSyncAnchor(response.rank), moreComing: response.hasMore)
            } catch {
                self.logger.errorPublic("❌ enumerateChanges(\(self.enumeratedItemIdentifier.id)) failed: \(String(describing: error))")
                observer.finishEnumeratingWithError(error.toPresentableError())
            }
        }
    }

}

class WorkingSetEnumerator: ItemEnumerator {
    init(backend: ProviderBackend) {
        // Enumerate everything from the root, recursively.
        super.init(enumeratedItemIdentifier: .rootContainer, backend: backend, recursive: true)
    }
}

class TrashEnumerator: ItemEnumerator {
    init(backend: ProviderBackend) {
        // Enumerate everything from the trash. This isn't recursive;
        // the File Provider framework asks for subitems if relevant.
        super.init(enumeratedItemIdentifier: .trashContainer, backend: backend, recursive: false)
    }
}
