/// Single-item meta-data lookup.
//
//  Abstract:
//  `NSFileProviderReplicatedExtension.item(for:request:)` — resolving one identifier to its item,
//  plus the shared `displayItem(_:)` entry-to-`Item` mapping used by every path that returns an item
//  to the OS (fetch, create, modify).
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common

extension Extension {
    public func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
                     completionHandler completionHander: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        logger.debugPublic("➡️  item(forIdentifier:\(identifier.rawValue)) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        return itemInternal(for: identifier, resolvingPlaintextSize: true, completionHandler: completionHander)
    }

    /// Resolves `identifier` to its display item without requiring an `NSFileProviderRequest`.
    ///
    /// Shared by the OS entry point and internal callers (fetch content, modify item) that need the
    /// same trash-support gating, error presentation and display mapping.
    ///
    /// - Parameters:
    ///   - identifier: Item to resolve.
    ///   - resolvingPlaintextSize: Passed to the backend's `fetchItem`, so the item carries the
    ///     exact `documentSize` and content version a partial fetch is validated against. Only the
    ///     OS `item(for:)` entry point opts in: a fetch path resolving here would invalidate the
    ///     version it was asked for.
    ///   - completionHandler: Receives the display item, or a presentable error.
    /// - Returns: Progress for the underlying backend call; cancelling completes with `NSUserCancelledError`.
    @discardableResult
    func itemInternal(for identifier: NSFileProviderItemIdentifier,
                      resolvingPlaintextSize: Bool = false,
                      completionHandler completionHander: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        if identifier == .trashContainer {
            if (try? requireBackend())?.supportsTrashEnumeration != true {
                logger.debugPublic("🌀 trash not supported: returning noSuchItem error")
                completionHander(nil, NSFileProviderError(.noSuchItem))
                return Progress()
            }
        }

        let progress = backend.fetchItem(DomainService.ItemIdentifier(identifier),
                                         resolvingPlaintextSize: resolvingPlaintextSize) { result in
            switch result {
            case .failure(let error):
                self.logger.errorPublic("❌ item(forIdentifier:\(identifier.rawValue)) failed: \(String(describing: error))")
                completionHander(nil, error.toPresentableError())
            case .success(let response):
                completionHander(self.displayItem(response.item), nil)
            }
        }
        progress.cancellationHandler = { completionHander(nil, NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }
        return progress
    }

    /// Returns an `Item` with backend name decoded and size approximated for display.
    ///
    /// Only entries the scheme recognises as encoded (for BC01, `.bc`-suffixed files) are
    /// rewritten; folders and plain files pass through unchanged. See
    /// ``MetadataTranslator/displayEntry(_:)``.
    func displayItem(_ entry: DomainService.Entry) -> Item {
        let translator = metadataTranslator
        return Item(translator.displayEntry(entry),
                    supportsMoveToTrash: backend.supportsMoveToTrash,
                    isEncrypted: translator.isBackendEncrypted(entry.name))
    }

    /// As ``displayItem(_:)`` but overrides the display size with an exact value — used by the
    /// fetch path, which knows the precise plaintext length from the decrypted bytes. Only
    /// applied to encoded entries (where the name changes under decode); others pass through.
    ///
    /// The exact size is folded into the *content* version with the same `|p<size>` stamp
    /// ``GraphMapping/entry(from:rootGraphID:plaintextSize:)`` applies, and for the same reason:
    /// `documentSize` is only re-read when the version changes. Overriding the size while reusing
    /// `entry.revision` published two different sizes under one version — hydration's exact
    /// length, then enumeration's ciphertext estimate — and whichever wrote last won. Finder
    /// showed the size snapping back to the ciphertext length on the next folder listing while
    /// `stat(2)` still reported the materialised length. Stamping here keeps the two publishers
    /// in agreement: same size, same version string.
    func displayItem(_ entry: DomainService.Entry, exactSize: Int64) -> Item {
        let translator = metadataTranslator
        let displayName = translator.decodeFromBackend(entry.name)
        guard displayName != entry.name else {
            return Item(entry, supportsMoveToTrash: backend.supportsMoveToTrash,
                        isEncrypted: translator.isBackendEncrypted(entry.name))
        }
        // Idempotent: entries from ``GraphMapping/entry(from:rootGraphID:plaintextSize:)`` always
        // arrive carrying a `|p<size>` stamp — the estimate before the size is resolved, the exact
        // length after. Appending unconditionally would yield `|p<estimate>|p<exact>` and disagree
        // with the single stamp enumeration publishes for the same state, which is the version
        // split this fix exists to close. Strip any existing stamp first.
        let stamped = entry.revision.stampingPlaintextSize(exactSize)
        let renamed = DomainService.Entry(
            name: displayName, id: entry.id, parent: entry.parent,
            revision: stamped, deleted: entry.deleted, size: exactSize,
            children: entry.children, type: entry.type, metadata: entry.metadata,
            userInfo: entry.userInfo)
        return Item(renamed, supportsMoveToTrash: backend.supportsMoveToTrash,
                    isEncrypted: true)
    }
}
