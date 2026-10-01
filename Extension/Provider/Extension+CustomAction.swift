/// Custom actions (Pin, Unpin, Heart, Share)
//
//  Abstract:
//  Adds custom actions to the extension.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import os.log
import Common
import FileProvider

extension NSFileProviderExtensionActionIdentifier {
    static let heart = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.Heart")
    static let unheart = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.Unheart")
    static let forceLock = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.ForceLock")
    static let pin = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.Pin")
    static let unpin = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.Unpin")
    static let evictFolder = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.EvictFolder")
    static let startSharing = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.StartSharing")
    static let stopSharing = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.StopSharing")
    static let encryptFiles = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.EncryptFiles")
    static let createEncryptedCopy = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.CreateEncryptedCopy")
    static let createDecryptedCopy = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.CreateDecryptedCopy")
    static let decryptFiles = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.DecryptFiles")
    static let restore = NSFileProviderExtensionActionIdentifier("\(AppIdentifiers.bundleID).Action.Restore")
}

extension Extension: NSFileProviderCustomAction {
    public func performAction(identifier actionIdentifier: NSFileProviderExtensionActionIdentifier,
                              onItemsWithIdentifiers itemIdentifiers: [NSFileProviderItemIdentifier],
                              completionHandler: @escaping (Error?) -> Void) -> Progress
    {
        logger.debugPublic("➡️  performAction(with \(actionIdentifier.rawValue), onItemsWithIdentifiers: \(itemIdentifiers.map({ $0.rawValue })))")

        let progress: Progress
        let identifiers = itemIdentifiers.compactMap(DomainService.ItemIdentifier.init)
        switch actionIdentifier {
        case .heart, .unheart:
            let mark = DomainService.MarkParameter(identifiers: identifiers, heart: actionIdentifier == .heart)
            progress = performMarkAction(mark, completionHandler: completionHandler)
        case .startSharing, .stopSharing:
            let mark = DomainService.MarkParameter(identifiers: identifiers, isShared: actionIdentifier == .startSharing)
            progress = performMarkAction(mark, completionHandler: completionHandler)
        case .forceLock:
            progress = performForceLockAction(onItemsWithIdentifiers: itemIdentifiers, completionHandler: completionHandler)
        case .pin, .unpin:
            progress = performPinAction(withValue: actionIdentifier == .pin, onItemsWithIdentifiers: itemIdentifiers,
                                        completionHandler: completionHandler)
        case .evictFolder:
            progress = performEvictFolderAction(onItemsWithIdentifiers: itemIdentifiers, completionHandler: completionHandler)
        case .encryptFiles, .createEncryptedCopy, .createDecryptedCopy, .decryptFiles:
            progress = performEncryptionAction(actionIdentifier,
                                               onItemsWithIdentifiers: itemIdentifiers,
                                               completionHandler: completionHandler)
        case .restore:
            progress = performRestoreAction(onItemsWithIdentifiers: itemIdentifiers,
                                            completionHandler: completionHandler)
        default:
            completionHandler(CommonError.notImplemented.toPresentableError())
            progress = Progress()
        }

        progress.cancellationHandler = { completionHandler(NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }
        return progress
    }

    private func performMarkAction(_ mark: DomainService.MarkParameter, completionHandler: @escaping (Error?) -> Void) -> Progress {
        guard !mark.identifiers.isEmpty else {
            completionHandler(CommonError.notImplemented.toPresentableError())
            return Progress()
        }
        return backend.mark(mark) { [weak self] in
            switch $0 {
            case .failure(let error):
                completionHandler(error.toPresentableError())
            case .success:
                self?.signalWorkingSetAfterMark()
                completionHandler(nil)
            }
        }
    }

    /// After a `mark` persists, prompt the system to re-read the change feed so the
    /// updated decoration (heart / pin / share) renders. The mark bumped the affected
    /// rows' rank (advancing the rank-derived domain version); signalling the working set
    /// triggers `enumerateChanges`, which delivers the rows with their merged xattrs.
    /// See [[working-set-vs-parent-container-signal]].
    private func signalWorkingSetAfterMark() {
        manager.signalEnumerator(for: .workingSet) { [weak self] error in
            if let error {
                self?.logger.errorPublic("⚠️ signalEnumerator(.workingSet) after mark failed: \(error)")
            }
        }
    }

    /// Custom "Put Back" for items trashed out-of-band by the encrypt/decrypt action. Those
    /// tombstones have no framework-recorded original parent, so the native "Put Back" never
    /// appears; the action gate (`userInfo.restorable == YES`) restricts this to exactly those
    /// items. Each item is restored via the backend `/restore` (original parent, Graph default),
    /// then the working set is signalled so the resurrected rows leave the Trash in Finder.
    private func performRestoreAction(onItemsWithIdentifiers itemIdentifiers: [NSFileProviderItemIdentifier],
                                      completionHandler: @escaping (Error?) -> Void) -> Progress {
        let items = itemIdentifiers.compactMap(DomainService.ItemIdentifier.init)
        guard backend.supportsRestore, !items.isEmpty else {
            completionHandler(CommonError.notImplemented.toPresentableError())
            return Progress()
        }
        let progress = Progress(totalUnitCount: Int64(items.count))
        Task {
            do {
                for item in items {
                    // The Graph /restore POST carries no If-Match, but RestoreItemParameter
                    // requires a revision; fetch the tombstone entry to supply it.
                    let entry = try await fetchEntry(item)
                    let param = DomainService.RestoreItemParameter(
                        itemIdentifier: item, existingRevision: entry.revision,
                        targetParentIdentifier: nil)
                    _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                        _ = self.backend.restoreItem(param) { result in
                            switch result {
                            case .success: continuation.resume(returning: ())
                            case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                            }
                        }
                    }
                    progress.completedUnitCount += 1
                }
                self.manager.signalEnumerator(for: .workingSet) { [weak self] error in
                    if let error { self?.logger.errorPublic("⚠️ signalEnumerator(.workingSet) after restore failed: \(error)") }
                }
                completionHandler(nil)
            } catch {
                completionHandler(error.toPresentableError())
            }
        }
        return progress
    }

    private func performForceLockAction(onItemsWithIdentifiers itemIdentifiers: [NSFileProviderItemIdentifier],
                                        completionHandler: @escaping (Error?) -> Void) -> Progress {
        let items = itemIdentifiers.compactMap(DomainService.ItemIdentifier.init)
        // Because forcing the lock is such an aggressive measure, only allow it
        // to happen for one item at a time. This sample enforces this here and also in the
        // predicate in NSExtensionFileProviderActions.
        guard items.count == 1,
            let item = items.first else {
            completionHandler(CommonError.notImplemented.toPresentableError())
            return Progress()
        }
        return backend.forceLock(item) { result in
            switch result {
            case .failure(let error):
                completionHandler(error.toPresentableError())
            case .success:
                completionHandler(nil)
            }
        }
    }

    private func performPinAction(withValue value: Bool, onItemsWithIdentifiers itemIdentifiers: [NSFileProviderItemIdentifier],
                                  completionHandler: @escaping (Error?) -> Void) -> Progress {
        let items = itemIdentifiers.compactMap(DomainService.ItemIdentifier.init)
        guard !items.isEmpty else {
            completionHandler(CommonError.notImplemented.toPresentableError())
            return Progress()
        }

        let mark = {
            self.backend.mark(DomainService.MarkParameter(identifiers: items, pinned: value)) { [weak self] result in
                switch result {
                case .failure(let error):
                    completionHandler(error.toPresentableError())
                case .success:
                    self?.signalWorkingSetAfterMark()
                    completionHandler(nil)
                }
            }
        }

        if value {
            let group = DispatchGroup()
            // Grab a coordination intent for each file.
            var intents = [NSFileAccessIntent]()
            itemIdentifiers.forEach { ident in
                group.enter()
                manager.getUserVisibleURL(for: ident) { url, error in
                    defer {
                        group.leave()
                    }
                    if let error = error as NSError? {
                        self.logger.errorPublic("couldn't get url for item:\(error)")
                        return
                    }
                    guard let url = url else {
                        self.logger.errorPublic("couldn't get url for item, no error")
                        return
                    }
                    synchronized(group) {
                        intents.append(NSFileAccessIntent.readingIntent(with: url, options: []))
                    }
                }
            }
            group.wait()
            // Wait until the code gathers all intents.
            var coordinationError: Error? = nil

            let progress = Progress(totalUnitCount: Int64(intents.count + 1))
            group.enter()
            progress.performAsCurrent(withPendingUnitCount: Int64(intents.count)) { () -> Void in
                // Coordinate in the background and notify when the process finishes.
                NSFileCoordinator().coordinate(with: intents, queue: OperationQueue()) { innerError in
                    synchronized(group) {
                        coordinationError = innerError
                    }
                    group.leave()
                }
            }
            group.notify(queue: queue, execute: {
                if let error = coordinationError {
                    completionHandler(error.toPresentableError())
                    return
                }
                progress.performAsCurrent(withPendingUnitCount: 1) { () -> Void in
                    _ = mark()
                }
            })

            return progress
        } else {
            return mark()
        }
    }

    /// Evicts materialized (downloaded) files under the target, files only.
    ///
    /// Delegates to ``MaterializedEviction``, shared with the host app's lock flows — the root
    /// container and folders are not evictable, so neither side may simply evict the target.
    private func performEvictFolderAction(onItemsWithIdentifiers itemIdentifiers: [NSFileProviderItemIdentifier],
                                          completionHandler: @escaping (Error?) -> Void) -> Progress {
        guard let target = itemIdentifiers.first else {
            logger.errorPublic("⚠️ performEvictFolderAction: no item identifier provided")
            completionHandler(nil)
            return Progress()
        }

        Task {
            do {
                try await MaterializedEviction.evictFiles(under: target, manager: manager) { id, error in
                    self.logger.errorPublic("⚠️ performEvictFolderAction: evictItem(\(id.rawValue)) failed: \(error)")
                }
            } catch {
                logger.errorPublic("⚠️ performEvictFolderAction: materialized enumeration failed: \(error)")
            }
            completionHandler(nil)
        }
        return Progress()
    }
}
