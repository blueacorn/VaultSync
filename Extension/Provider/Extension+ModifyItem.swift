/// Item modification.
//
//  Abstract:
//  `NSFileProviderReplicatedExtension.modifyItem(…)` — content writes (inline or streamed),
//  trash/restore, metadata modifies, and the BC01 auto-encrypt-on-edit rename.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common
import UniformTypeIdentifiers

extension Extension {
    public func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion, changedFields: NSFileProviderItemFields,
                           contents newContents: URL?, options: NSFileProviderModifyItemOptions = [], request: NSFileProviderRequest,
                           completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress
    {
        logger.infoPublic("➡️  modifyItem(\(item.itemIdentifier.rawValue)) changedFields(\(changedFields.rawValue)) contents(\(newContents != nil)) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        let progress = Progress(totalUnitCount: 100)
        Task {
            do {
                let (item, remainingFields, someBool) = try await self.modifyItemInternal(item,
                                                                                          baseVersion: version,
                                                                                          changedFields: changedFields,
                                                                                          contents: newContents,
                                                                                          options: options,
                                                                                          request: request,
                                                                                          progress: progress)
                completionHandler(item, remainingFields, someBool, nil)
            } catch {
                completionHandler(nil, [], false, error.asFileProviderError)
            }
        }
        return progress
    }

    /// Return a copy of `entry` whose `contentModificationDate` is taken from the incoming
    /// item `template` (the value Finder holds for the just-written bytes), overriding the
    /// backend's server-stamped modification date. Used only on the content-modify return
    /// path to avoid a spurious "changed by another application" conflict. No-op when the
    /// template carries no content-modification date.
    private func overridingContentModDate(_ entry: DomainService.Entry,
                                          from template: NSFileProviderItem) -> DomainService.Entry {
        guard let templateModDate = template.contentModificationDate.flatMap({ $0 }) else { return entry }
        let m = entry.metadata
        var valid = m.validEntries
        valid.insert(.contentModificationDate)
        let metadata = DomainService.EntryMetadata(
            fileSystemFlags: m.fileSystemFlags, lastUsedDate: m.lastUsedDate, tagData: m.tagData,
            favoriteRank: nil, creationDate: m.creationDate, contentModificationDate: templateModDate,
            extendedAttributes: m.extendedAttributes, typeAndCreator: m.typeAndCreator, validEntries: valid)
        return DomainService.Entry(name: entry.name, id: entry.id, parent: entry.parent,
                                   revision: entry.revision, deleted: entry.deleted, size: entry.size,
                                   children: entry.children, type: entry.type, metadata: metadata,
                                   userInfo: entry.userInfo)
    }

    private func modifyItemInternal(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion,
                                    changedFields: NSFileProviderItemFields, contents newContents: URL?,
                                    options: NSFileProviderModifyItemOptions = [],
                                    request: NSFileProviderRequest,
                                    progress: Progress) async throws -> (NSFileProviderItem?, NSFileProviderItemFields, Bool) {
        let backend = try requireBackend()
        logger.debugPublic("➡️  modifyItem(for:\(item.itemIdentifier.rawValue)) changedFields=\(changedFields.rawValue) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        // Idempotency for an already-trashed item. The encrypt/decrypt action trashes the
        // original (Graph DELETE → recycle bin) and signals the working set with the item
        // reparented to `$trash`. Finder reconciles by issuing its own `modifyItem` on the now
        // tombstoned item — and it is NOT always a move-to-trash: `changedFields` observed in
        // practice is `.filename` (Trash renames the entry), not `.parentItemIdentifier`. Any
        // such change forwarded to Graph is a PATCH/DELETE on a recycle-bin item → 404
        // (itemNotFound) → the framework errors the item and retries forever, and it can no
        // longer be restored. A recycle-bin item accepts no metadata mutation, so treat every
        // modify on a trashed item as a no-op success: hand back the existing trashed entry
        // (with `$trash` parent, via fetchItem) and clear all changed fields so Finder stops.
        // A genuine restore ("Put Back" / drag out of Trash) is also a modify on a trashed item,
        // but with `.parentItemIdentifier` set to a non-trash container — that must reach the
        // restore branch below, so it is excluded here.
        let isRestoreGesture = changedFields.contains(.parentItemIdentifier)
            && item.parentItemIdentifier != .trashContainer
        if !isRestoreGesture,
           (try? backend.isItemTrashed(DomainService.ItemIdentifier(item.itemIdentifier))) == true {
            logger.infoPublic("🗑️ modifyItem on already-trashed item id=\(item.itemIdentifier.rawValue) changedFields=\(changedFields.rawValue): no-op (recycle-bin item accepts no mutation)")
            return try await withCheckedThrowingContinuation { continuation in
                let callProgress = backend.fetchItem(DomainService.ItemIdentifier(item.itemIdentifier)) { res in
                    switch res {
                    case .failure(let error):
                        continuation.resume(throwing: error.toPresentableError())
                    case .success(let resp):
                        continuation.resume(returning: (self.displayItem(resp.item), [], false))
                    }
                }
                progress.addChild(callProgress, withPendingUnitCount: 100)
            }
        }
        // The server API breaks out the different types of changes into separate calls:
        // content changes, thumbnail changes, and metadata changes (such as renames).
        // A differently designed server API might want to back all of these changes
        // by the same endpoint.

        let cryptoConfig = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)

        if changedFields.contains(.contents) {
            // Per-item encryption plan for this content edit. In a BC01 domain the bytes are
            // encrypted only when the backend item is already `.bc`-named, OR when auto-encrypt
            // is on (in which case the item is also renamed to `.bc` below, in place). A
            // plaintext-named item in a BC01 domain with auto-encrypt OFF passes through as
            // plaintext — it must NOT be silently encrypted (that was the reported corruption).
            let editPlan = try await encryptionPlanForEdit(item: item, cryptoConfig: cryptoConfig)

            let fork: Data?
            /// Plaintext source of the new contents: `newContents`, or a temp file holding a
            /// symlink's target. Every content write uploads through `modifyContentsStreaming`.
            let sourceURL: URL
            /// Temp file this call created for a symlink target; removed on return.
            var tempSourceURL: URL?
            defer { if let tempSourceURL { try? FileManager.default.removeItem(at: tempSourceURL) } }
            let encryptor: any FileEncryptor
            /// Plaintext length of the bytes being written, when we read them from a file.
            /// Handed to the backend so an encrypted item's true size is known the instant the
            /// write lands, rather than after a background header probe — a just-saved file must
            /// not disappear from Finder.
            var uploadPlaintextSize: Int64?

            let contentType = item.contentType!
            switch contentType {
            case .symbolicLink:
                guard let accessor = item.symlinkTargetPath,
                    let targetPath = accessor else {
                        fatalError("couldn’t get symlinkTargetPath on \(item)")
                }
                let targetURL = makeTemporaryURL("symlinkTarget")
                try targetPath.utf8Data.write(to: targetURL)
                tempSourceURL = targetURL
                sourceURL = targetURL
                encryptor = PlainFileEncryptor()
                fork = nil
            case .folder:
                fatalError("folders should never get a modifyItem with .contents set")
            default:
                guard let contents = newContents else {
                    fatalError(".contents set in changedFields, but no contents URL passed")
                }

                do {
                    let rsrcUrl = contents.appendingPathComponent("..namedfork/rsrc")
                    fork = try Data(contentsOf: rsrcUrl, options: .alwaysMapped)
                } catch CocoaError.fileNoSuchFile, CocoaError.fileReadNoSuchFile {
                    fork = nil
                } catch let error {
                    fatalError("failed to read resource fork: \(error)")
                }

                sourceURL = contents
                // Honour the per-item plan: a plaintext-named item in a BC01 domain with
                // auto-encrypt off passes through untouched.
                encryptor = editPlan.encrypt ? try makeEncryptor() : PlainFileEncryptor()
                let plaintextSize = (try? FileManager.default
                    .attributesOfItem(atPath: contents.path)[.size] as? NSNumber)??.intValue ?? 0
                uploadPlaintextSize = Int64(plaintextSize)
            }

            let modifyContentsParameter = DomainService.ModifyContentsParameter(identifier: DomainService.ItemIdentifier(item.itemIdentifier),
                                                                                existingRevision: DomainService.Version(version),
                                                                                contentStorageType: .contents,
                                                                                updateResourceForkOnConflictedItem: false,
                                                                                plaintextSize: uploadPlaintextSize)
            let contentResult: (NSFileProviderItem?, NSFileProviderItemFields, Bool)

            let uploadProgress = Progress(totalUnitCount: 100)
            progress.addChild(uploadProgress, withPendingUnitCount: fork != nil ? 90 : 100)
            let resp: DomainService.ModifyContentsReturn
            do {
                resp = try await backend.modifyContentsStreaming(modifyContentsParameter,
                                                                 contentsAt: sourceURL,
                                                                 originalFilename: item.filename,
                                                                 encryptor: encryptor,
                                                                 progress: uploadProgress)
            } catch {
                throw error.toPresentableError()
            }
            // Echo the client's own content-modification date back for the bytes it just wrote —
            // NOT the server's `lastModifiedDateTime`. Backends stamp their own clock on write
            // (e.g. OneDrive), which is later than the local mtime the still-open document holds.
            // Returning the server mtime makes the OS see the open file's moddate move under it →
            // Finder "The document could not be saved. The file has been changed by another
            // application." Enumeration/delta still surface the server mtime for genuine remote edits.
            let respItem = overridingContentModDate(resp.item, from: item)
            if !resp.contentAccepted {
                // The server kept its own copy (conflict): only the fork follows, onto that item.
                guard let url = newContents else { return (displayItem(respItem), [], true) }
                return try await uploadResourceFork(item: respItem, fork: fork, changedFields: changedFields,
                                                    updateResourceForkOnConflictedItem: true,
                                                    contentType: contentType, url: url,
                                                    parentProgress: progress)
            }
            if let url = newContents {
                contentResult = try await uploadResourceFork(item: respItem, fork: fork,
                                                             changedFields: changedFields,
                                                             updateResourceForkOnConflictedItem: false,
                                                             contentType: contentType, url: url,
                                                             parentProgress: progress)
            } else {
                assert(item.contentType == .symbolicLink)
                contentResult = (displayItem(respItem), [], false)
            }

            // Auto-encrypt-on-edit: the bytes were just encrypted in place; now rename the
            // backend item to the `.bc` name so its encryption state matches the ciphertext
            // (the rename keeps the same identifier — the display name is unchanged, since the
            // translator strips `.bc` on decode, so File Provider sees no rename). Done after a
            // successful content write to minimise the inconsistency window.
            if editPlan.renameToBc, let resultItem = contentResult.0 {
                // Use the revision from the content-write response (carried on the returned
                // `Item`), NOT a re-fetch: the content PUT advanced the eTag, but a fetch is
                // cache-served and would return the stale pre-write eTag, making the rename
                // PATCH fail its `If-Match` precondition with 412 (wrongRevision) and loop.
                let freshRevision = (resultItem as? Item)?.entry.revision
                return try await renameBackendItemToEncrypted(displayItem: resultItem,
                                                              knownRevision: freshRevision,
                                                              fields: contentResult.1,
                                                              progress: progress)
            }
            return contentResult
        } else if changedFields.contains(.parentItemIdentifier) &&
            item.parentItemIdentifier == .trashContainer {
            if !backend.supportsMoveToTrash {
                logger.debugPublic("🌀 move-to-trash unsupported: moving back")
                return try await withCheckedThrowingContinuation { continuation in
                    let callProgress = backend.fetchItem(DomainService.ItemIdentifier(item.itemIdentifier)) { res in
                        Task {
                            switch res {
                            case .failure(let error):
                                continuation.resume(throwing: error.toPresentableError())
                            case .success(let resp):
                                continuation.resume(returning: (self.displayItem(resp.item), changedFields.removing(.parentItemIdentifier), false))
                            }
                        }
                    }
                    progress.addChild(callProgress, withPendingUnitCount: 100)
                    return
                }
            }
            // Idempotency: the encrypt/decrypt action already trashes the original (Graph
            // DELETE) and signals the working set with the item reparented to `$trash`.
            // Finder reconciles that by issuing its own move-to-trash `modifyItem` on the
            // now-tombstoned item. Re-running `trashItem` would PATCH/DELETE a recycle-bin
            // item → 404 (itemNotFound) → the framework marks it errored and retries forever,
            // and the item can no longer be restored. If it is already trashed, treat this as
            // a no-op success and hand back the existing trashed entry.
            if (try? backend.isItemTrashed(DomainService.ItemIdentifier(item.itemIdentifier))) == true {
                logger.debugPublic("🗑️ move-to-trash on already-trashed item \(item.itemIdentifier.rawValue): no-op")
                return try await withCheckedThrowingContinuation { continuation in
                    let callProgress = backend.fetchItem(DomainService.ItemIdentifier(item.itemIdentifier)) { res in
                        switch res {
                        case .failure(let error):
                            continuation.resume(throwing: error.toPresentableError())
                        case .success(let resp):
                            continuation.resume(returning: (self.displayItem(resp.item), changedFields.removing(.parentItemIdentifier), false))
                        }
                    }
                    progress.addChild(callProgress, withPendingUnitCount: 100)
                }
            }

            let param = DomainService.TrashItemParameter(itemIdentifier: DomainService.ItemIdentifier(item.itemIdentifier),
                                                         existingRevision: DomainService.Version(version))

            return try await withCheckedThrowingContinuation { continuation in
                let callProgress = backend.trashItem(param) { res in
                    switch res {
                    case .failure(let error):
                        continuation.resume(throwing: error.toPresentableError())
                    case .success(let resp):
                        continuation.resume(returning: (self.displayItem(resp.item), changedFields.removing(.parentItemIdentifier), false))
                    }
                }
                progress.addChild(callProgress, withPendingUnitCount: 100)
            }
        } else if changedFields.contains(.parentItemIdentifier),
                  item.parentItemIdentifier != .trashContainer,
                  backend.supportsRestore,
                  (try? backend.isItemTrashed(DomainService.ItemIdentifier(item.itemIdentifier))) == true {
            // Restore: item was trashed (tombstoned with deletedAt), new parent is not the trash
            // container. Issue POST /restore rather than a normal reparent PATCH.
            let targetParent: DomainService.ItemIdentifier? =
                item.parentItemIdentifier == .rootContainer ? nil
                : DomainService.ItemIdentifier(item.parentItemIdentifier)
            let param = DomainService.RestoreItemParameter(
                itemIdentifier: DomainService.ItemIdentifier(item.itemIdentifier),
                existingRevision: DomainService.Version(version),
                targetParentIdentifier: targetParent)
            return try await withCheckedThrowingContinuation { continuation in
                let callProgress = backend.restoreItem(param) { res in
                    switch res {
                    case .failure(let error):
                        continuation.resume(throwing: error.toPresentableError())
                    case .success(let resp):
                        continuation.resume(returning: (self.displayItem(resp.item), changedFields.removing(.parentItemIdentifier), false))
                    }
                }
                progress.addChild(callProgress, withPendingUnitCount: 100)
            }
        } else if changedFields.contains(.parentItemIdentifier) &&
            UserDefaults.sharedContainerDefaults.syncChildrenBeforeParentMove {

            logger.debugPublic("🚧 enforcing barrier before applying modifyItem(for:\(item.itemIdentifier.rawValue))")
            try await self.manager.waitForChanges(below: item.itemIdentifier)

            let parent = changedFields.contains(.parentItemIdentifier) ? DomainService.ItemIdentifier(item.parentItemIdentifier) : nil
            let backendFilename = changedFields.contains(.filename)
                ? try await backendFilename(forNewDisplayName: item.filename,
                                            identifier: item.itemIdentifier, cryptoConfig: cryptoConfig)
                : nil
            let param = DomainService.ModifyMetadataParameter(itemIdentifier: DomainService.ItemIdentifier(item.itemIdentifier),
                                                              existingRevision: DomainService.Version(version),
                                                              filename: backendFilename,
                                                              parent: parent,
                                                              metadata: DomainService.EntryMetadata(item, changedFields))
            return try await withCheckedThrowingContinuation { continuation in
                let subProgress = self.backend.modifyMetadata(param) { res in
                    switch res {
                    case .success(let resp):
                        continuation.resume(returning: (self.displayItem(resp.item), [], false))
                    case .failure(let error):
                        continuation.resume(throwing: error.toPresentableError())
                    }
                }
                progress.addChild(subProgress, withPendingUnitCount: 100)
                return
            }
        } else {
            // Plain metadata modify (rename / reparent / tags / favoriteRank / xattrs —
            // including the heart/pinned marks and Finder colour/label tags). The backend
            // persists every field however it can: remotely where it has a home, in a local
            // sidecar where it does not (OneDrive has no Graph field for tags/xattrs). It
            // returns the authoritative item with all persisted fields reflected, so the
            // tags/marks survive enumeration, materialisation, and relaunch. Persistence
            // location is the backend's concern — the Extension is a thin caller.
            return try await applyMetadataModify(item, changedFields: changedFields,
                                                 version: version, cryptoConfig: cryptoConfig,
                                                 progress: progress)
        }
    }

    /// Persist a plain metadata modify (rename / reparent / attributes / tags / xattrs)
    /// through the backend and return the authoritative item with no remaining fields.
    private func applyMetadataModify(_ item: NSFileProviderItem,
                                     changedFields: NSFileProviderItemFields,
                                     version: NSFileProviderItemVersion,
                                     cryptoConfig: DomainCryptoConfig,
                                     progress: Progress) async throws -> (NSFileProviderItem, NSFileProviderItemFields, Bool) {
        let parent = changedFields.contains(.parentItemIdentifier) ? DomainService.ItemIdentifier(item.parentItemIdentifier) : nil
        let backendFilename = changedFields.contains(.filename)
            ? try await backendFilename(forNewDisplayName: item.filename,
                                        identifier: item.itemIdentifier, cryptoConfig: cryptoConfig)
            : nil
        let param = DomainService.ModifyMetadataParameter(itemIdentifier: DomainService.ItemIdentifier(item.itemIdentifier),
                                                          existingRevision: DomainService.Version(version),
                                                          filename: backendFilename,
                                                          parent: parent,
                                                          metadata: DomainService.EntryMetadata(item, changedFields))
        return try await withCheckedThrowingContinuation { continuation in
            let callProgress = backend.modifyMetadata(param) { res in
                switch res {
                case .success(let resp):
                    continuation.resume(returning: (self.displayItem(resp.item), [], false))
                case .failure(let error):
                    continuation.resume(throwing: error.toPresentableError())
                }
            }
            progress.addChild(callProgress, withPendingUnitCount: 100)
            return
        }
    }

    // MARK: - Auto-encrypt on edit

    /// Per-item plan for encrypting (and possibly renaming) the bytes written by a content edit.
    struct EditEncryptionPlan {
        /// Whether to encrypt the bytes before upload.
        let encrypt: Bool
        /// Whether to rename the backend item to its `.bc` name after the content write
        /// (only when converting a plaintext-named item under auto-encrypt).
        let renameToBc: Bool
    }

    /// Decides whether a content edit should encrypt and/or convert the item.
    ///
    /// - `.plain` domain → never encrypt.
    /// - BC01 domain, backend item already `.bc`-named → encrypt, no rename (already encrypted).
    /// - BC01 domain, plaintext-named item, auto-encrypt ON → encrypt + rename to `.bc`.
    /// - BC01 domain, plaintext-named item, auto-encrypt OFF → pass through as plaintext.
    ///
    /// The backend name (not the display `item.filename`) is the source of truth for the item's
    /// current encryption state, so this fetches the live entry when BC01 is active.
    private func encryptionPlanForEdit(item: NSFileProviderItem,
                                       cryptoConfig: DomainCryptoConfig) async throws -> EditEncryptionPlan {
        guard cryptoConfig.algorithm == .bc01 else {
            return EditEncryptionPlan(encrypt: false, renameToBc: false)
        }
        // Symlinks are stored inline and never participate in BC01 file encryption.
        if item.contentType == .symbolicLink {
            return EditEncryptionPlan(encrypt: false, renameToBc: false)
        }

        let translator = BoxcryptorMetadataTranslator(algorithm: .bc01)
        let backendName = try await fetchBackendName(for: item.itemIdentifier)
        if translator.isBackendEncrypted(backendName) {
            logger.debugPublic("🔐 editPlan(\(item.itemIdentifier.rawValue)): backendName='\(backendName)' already .bc → encrypt, no rename")
            return EditEncryptionPlan(encrypt: true, renameToBc: false)
        }
        // Plaintext-named item: only encrypt+convert when the user opted in.
        let autoEncrypt = UserDefaults.sharedContainerDefaults.autoEncryptOnEdit(for: domain.identifier)
        logger.debugPublic("🔐 editPlan(\(item.itemIdentifier.rawValue)): backendName='\(backendName)' plaintext, autoEncryptOnEdit=\(autoEncrypt) → encrypt=\(autoEncrypt), renameToBc=\(autoEncrypt)")
        return EditEncryptionPlan(encrypt: autoEncrypt, renameToBc: autoEncrypt)
    }

    /// Compute the backend filename for a rename/reparent PATCH, preserving the item's
    /// **current** backend encryption state rather than assuming the domain default.
    ///
    /// `encodeForBackend` unconditionally appends `.bc` in a BC01 domain — correct for an
    /// encrypted item, but wrong for a plaintext passthrough item (a plaintext file the user
    /// keeps unencrypted, or one trashed by the Encrypt action and restored via "Put Back").
    /// Blindly appending `.bc` renames the plaintext backend file to a `.bc` name, so the
    /// Provider then tries to decrypt plaintext as BC01 and materialisation fails.
    ///
    /// The display name never carries the suffix (decode strips it); the backend name's
    /// existing `.bc` suffix is the source of truth for whether this item is encrypted. So:
    /// encrypted item → `newDisplayName + ".bc"`; plaintext item → `newDisplayName` unchanged.
    private func backendFilename(forNewDisplayName displayName: String,
                                 identifier: NSFileProviderItemIdentifier,
                                 cryptoConfig: DomainCryptoConfig) async throws -> String {
        let currentBackendName = try await fetchBackendName(for: identifier)
        return Self.backendFilename(forNewDisplayName: displayName,
                                    currentBackendName: currentBackendName,
                                    algorithm: cryptoConfig.algorithm)
    }

    /// Pure rename rule (testable): preserve the item's current backend encryption state.
    /// Encrypted backend name (`.bc` suffix) → `displayName + ".bc"`; plaintext → `displayName`.
    static func backendFilename(forNewDisplayName displayName: String,
                                currentBackendName: String,
                                algorithm: CryptoAlgorithm) -> String {
        let translator = BoxcryptorMetadataTranslator(algorithm: algorithm)
        guard translator.isBackendEncrypted(currentBackendName) else {
            // Plaintext passthrough item: keep the display name as-is on the backend.
            return displayName
        }
        return translator.encodeForBackend(displayName)
    }

    /// Fetches the item's current backend (raw, un-decoded) name.
    private func fetchBackendName(for identifier: NSFileProviderItemIdentifier) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            _ = backend.fetchItem(DomainService.ItemIdentifier(identifier)) { result in
                switch result {
                case .success(let resp): continuation.resume(returning: resp.item.name)
                case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                }
            }
        }
    }

    /// Renames the just-encrypted backend item to its `.bc` name in place (same identifier).
    /// The display name is unchanged (decode strips `.bc`), so File Provider sees no rename.
    /// Renames the just-encrypted backend item to its `.bc` name in place (same identifier).
    ///
    /// - Parameter knownRevision: the revision returned by the *content write* that just ran.
    ///   This MUST be threaded through (not re-fetched): `fetchItem` is cache-served and would
    ///   return the pre-write eTag, so the rename PATCH's `If-Match` precondition would fail
    ///   with 412 and macOS would retry the whole modify forever (leaving encrypted bytes under
    ///   a plaintext name). Falls back to a fresh fetch only when the caller has no revision.
    private func renameBackendItemToEncrypted(displayItem: NSFileProviderItem,
                                              knownRevision: DomainService.Version?,
                                              fields: NSFileProviderItemFields,
                                              progress: Progress) async throws
        -> (NSFileProviderItem?, NSFileProviderItemFields, Bool) {
        let backendName = try await fetchBackendName(for: displayItem.itemIdentifier)
        let translator = BoxcryptorMetadataTranslator(algorithm: .bc01)
        // Already encrypted-named (e.g. a racing converter won) → nothing to do.
        guard !translator.isBackendEncrypted(backendName) else {
            logger.debugPublic("🔐 renameToBc(\(displayItem.itemIdentifier.rawValue)): backendName='\(backendName)' already .bc → skip")
            return (displayItem, fields, false)
        }
        let target = translator.encodeForBackend(backendName)
        let revision: DomainService.Version
        if let knownRevision {
            revision = knownRevision
        } else {
            revision = try await fetchRevision(for: displayItem.itemIdentifier)
        }
        logger.debugPublic("🔐 renameToBc(\(displayItem.itemIdentifier.rawValue)): '\(backendName)' → '\(target)' eTag=\(revision.metadata)")
        let param = DomainService.ModifyMetadataParameter(
            itemIdentifier: DomainService.ItemIdentifier(displayItem.itemIdentifier),
            existingRevision: revision,
            filename: target,
            parent: nil,
            metadata: .empty)
        return try await withCheckedThrowingContinuation { continuation in
            let callProgress = backend.modifyMetadata(param) { res in
                switch res {
                case .success(let resp):
                    continuation.resume(returning: (self.displayItem(resp.item), fields, false))
                case .failure(let error):
                    continuation.resume(throwing: error.toPresentableError())
                }
            }
            progress.addChild(callProgress, withPendingUnitCount: 100)
        }
    }

    /// Fetches the item's current revision (for an in-place rename after a content write).
    private func fetchRevision(for identifier: NSFileProviderItemIdentifier) async throws -> DomainService.Version {
        try await withCheckedThrowingContinuation { continuation in
            _ = backend.fetchItem(DomainService.ItemIdentifier(identifier)) { result in
                switch result {
                case .success(let resp): continuation.resume(returning: resp.item.revision)
                case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                }
            }
        }
    }
}

/// Clearing a field from `changedFields` on the modify return path.
extension OptionSet {
    func removing(_ element: Element) -> Self {
        var mutable = self
        mutable.remove(element)
        return mutable
    }
}
