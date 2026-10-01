/// Finder context-menu encryption actions: "Encrypt File(s)", "Create Encrypted Copy", and
/// "Create Decrypted Copy". Declared in `Provider/Info.plist` (`NSExtensionFileProviderActions`)
/// and dispatched from ``Extension/performAction(identifier:onItemsWithIdentifiers:completionHandler:)``.
///
/// All four drive the safe ``ContentEncryptionConverter`` through ``convertFile(_:targetName:encryptor:removeOriginal:)``,
/// file to file through the streaming pipeline, so the original is never lost: every new item is
/// verified by streaming read-back before any removal, and the copy variants keep the original. `.bc` items are never re-encrypted
/// (idempotent), matching the create-path double-encrypt guard.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import os.log
import Common
import FileProvider

extension Extension {

    func performEncryptionAction(_ actionIdentifier: NSFileProviderExtensionActionIdentifier,
                                 onItemsWithIdentifiers itemIdentifiers: [NSFileProviderItemIdentifier],
                                 completionHandler: @escaping (Error?) -> Void) -> Progress {
        let ids = itemIdentifiers.map(DomainService.ItemIdentifier.init)
        guard !ids.isEmpty else {
            completionHandler(CommonError.notImplemented.toPresentableError())
            return Progress()
        }

        let progress = Progress(totalUnitCount: Int64(ids.count))
        let reporter = EncryptionProgressReporter(actionProgress: progress)
        Task {
            do {
                switch actionIdentifier {
                case .encryptFiles:
                    try await encryptSelection(ids, removeOriginal: removalPolicy(), progress: reporter)
                case .createEncryptedCopy:
                    try await createEncryptedCopies(ids, progress: reporter)
                case .createDecryptedCopy:
                    try await createDecryptedCopies(ids, progress: reporter)
                case .decryptFiles:
                    try await decryptSelection(ids, removeOriginal: removalPolicy(), progress: reporter)
                default:
                    throw CommonError.notImplemented
                }
                reporter.finish()
                self.signalWorkingSetAfterEncryptionAction()
                completionHandler(nil)
            } catch {
                // Finalize so Finder does not leave a stalled indicator on failure.
                reporter.finish()
                self.logger.errorPublic("⚠️ encryption action failed: \(error)")
                completionHandler(error.toPresentableError())
            }
        }
        return progress
    }

    // MARK: - Encrypt (in-place conversion, removes original)

    /// Encrypts every plaintext **file** in the selection, recursing into folders. `.bc` files
    /// are skipped (idempotent).
    private func encryptSelection(_ ids: [DomainService.ItemIdentifier],
                                  removeOriginal: RemoveOriginalPolicy,
                                  progress: EncryptionProgressReporting) async throws {
        let translator = metadataTranslator
        // Collect every target file across the selection first so the progress total reflects
        // the real file count (a folder of N files), then advance once per processed file.
        var files: [DomainService.Entry] = []
        for id in ids {
            let entry = try await fetchEntry(id)
            files += try await collectPlaintextFiles(under: entry, translator: translator)
        }
        progress.start(totalFiles: files.count, description: "Encrypting \(files.count) files…")
        for file in files {
            try await convertFile(file, targetName: translator.encodeForBackend(file.name),
                                  encryptor: try makeEncryptor(), removeOriginal: removeOriginal)
            progress.advance()
        }
    }

    // MARK: - Decrypt (in-place conversion, removes original)

    /// Decrypts every encrypted (`.bc`) **file** in the selection, recursing into folders.
    /// Plaintext files are skipped (idempotent). Mirrors ``encryptSelection`` in reverse:
    /// create a verified plaintext item, then remove the `.bc` original, so the ciphertext is
    /// never lost before its plaintext replacement is confirmed readable.
    private func decryptSelection(_ ids: [DomainService.ItemIdentifier],
                                  removeOriginal: RemoveOriginalPolicy,
                                  progress: EncryptionProgressReporting) async throws {
        let translator = metadataTranslator
        // Collect every target file first (see ``encryptSelection``) so progress totals the
        // real file count, then advance once per processed file.
        var files: [DomainService.Entry] = []
        for id in ids {
            let entry = try await fetchEntry(id)
            files += try await collectEncryptedFiles(under: entry, translator: translator)
        }
        progress.start(totalFiles: files.count, description: "Decrypting \(files.count) files…")
        for file in files {
            try await convertFile(file, targetName: translator.decodeFromBackend(file.name),
                                  encryptor: PlainFileEncryptor(), removeOriginal: removeOriginal)
            progress.advance()
        }
    }

    /// Convert one file into a new, verified item named `targetName` uploaded through
    /// `encryptor`, then remove the original per `removeOriginal` (`nil` keeps it). On any
    /// failure before removal the new item is rolled back and the original is left intact.
    private func convertFile(_ file: DomainService.Entry,
                             targetName: String,
                             encryptor: any FileEncryptor,
                             removeOriginal: RemoveOriginalPolicy?) async throws {
        _ = try await makeContentEncryptionConverter().convert(source: file,
                                                               targetName: targetName,
                                                               encryptor: encryptor,
                                                               removeOriginal: removeOriginal,
                                                               expectedRevision: file.revision)
        // A: surface the trashed original immediately (per file), rather than once after the
        // whole batch — otherwise originals only appear in the macOS Trash after every file
        // has been converted. The working-set delta re-emits the tombstoned row with a
        // `$trash` parent (move-to-trash), exactly like the "Move to Trash" gesture.
        if removeOriginal == .trash { signalWorkingSetNow(context: "after convert-trash of \(file.id.id)") }
    }

    /// Collects encrypted (`.bc`) files reachable from `entry`. A file yields itself when
    /// encrypted; a folder is listed recursively. Plaintext files are excluded so decryption
    /// stays idempotent.
    private func collectEncryptedFiles(under entry: DomainService.Entry,
                                       translator: BoxcryptorMetadataTranslator) async throws -> [DomainService.Entry] {
        if entry.type == .file {
            return translator.isBackendEncrypted(entry.name) ? [entry] : []
        }
        guard entry.type == .folder || entry.type == .root else { return [] }

        var results: [DomainService.Entry] = []
        var cursor: DomainService.PageCursor? = nil
        while true {
            let page: DomainService.ListFolderReturn = try await withCheckedThrowingContinuation { continuation in
                _ = backend.listFolder(entry.id, recursive: true, startingCursor: cursor) { result in
                    switch result {
                    case .success(let resp): continuation.resume(returning: resp)
                    case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                    }
                }
            }
            for child in page.entries where child.type == .file && translator.isBackendEncrypted(child.name) {
                results.append(child)
            }
            guard let next = page.cursor, next != cursor else { break }
            cursor = next
        }
        return results
    }

    // MARK: - Create Encrypted Copy (keeps original)

    private func createEncryptedCopies(_ ids: [DomainService.ItemIdentifier],
                                       progress: EncryptionProgressReporting) async throws {
        progress.start(totalFiles: ids.count, description: "Encrypting \(ids.count) files…")
        for id in ids {
            let entry = try await fetchEntry(id)
            guard entry.type == .file, !metadataTranslator.isBackendEncrypted(entry.name) else {
                progress.advance()
                continue
            }
            let displayName = copyName(metadataTranslator.decodeFromBackend(entry.name))
            try await convertFile(entry, targetName: metadataTranslator.encodeForBackend(displayName),
                                  encryptor: try makeEncryptor(), removeOriginal: nil)
            progress.advance()
        }
    }

    // MARK: - Create Decrypted Copy (keeps original)

    private func createDecryptedCopies(_ ids: [DomainService.ItemIdentifier],
                                       progress: EncryptionProgressReporting) async throws {
        progress.start(totalFiles: ids.count, description: "Decrypting \(ids.count) files…")
        for id in ids {
            let entry = try await fetchEntry(id)
            guard entry.type == .file, metadataTranslator.isBackendEncrypted(entry.name) else {
                progress.advance()
                continue
            }
            // Plaintext copy keeps a plaintext name (no `.bc`).
            let displayName = copyName(metadataTranslator.decodeFromBackend(entry.name))
            try await convertFile(entry, targetName: displayName,
                                  encryptor: PlainFileEncryptor(), removeOriginal: nil)
            progress.advance()
        }
    }

    // MARK: - Helpers

    /// Removal policy for the "Encrypt File(s)" action, honouring the per-domain
    /// "send plaintext to trash" preference and the backend's trash capability.
    private func removalPolicy() -> RemoveOriginalPolicy {
        let preferTrash = UserDefaults.sharedContainerDefaults.trashPlaintextOnAutoEncrypt(for: domain.identifier)
        return (preferTrash && backend.supportsMoveToTrash) ? .trash : .delete
    }

    /// Returns `"name copy.ext"` (or `"name copy"` when there is no extension).
    private func copyName(_ name: String) -> String {
        let ns = name as NSString
        let ext = ns.pathExtension
        let base = ns.deletingPathExtension
        return ext.isEmpty ? "\(base) copy" : "\(base) copy.\(ext)"
    }

    func fetchEntry(_ id: DomainService.ItemIdentifier) async throws -> DomainService.Entry {
        try await withCheckedThrowingContinuation { continuation in
            _ = backend.fetchItem(id) { result in
                switch result {
                case .success(let resp): continuation.resume(returning: resp.item)
                case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                }
            }
        }
    }

    /// Collects plaintext (non-`.bc`) files reachable from `entry`. A file yields itself; a
    /// folder is listed recursively. `.bc` files are excluded so encryption stays idempotent.
    private func collectPlaintextFiles(under entry: DomainService.Entry,
                                       translator: BoxcryptorMetadataTranslator) async throws -> [DomainService.Entry] {
        if entry.type == .file {
            return translator.isBackendEncrypted(entry.name) ? [] : [entry]
        }
        guard entry.type == .folder || entry.type == .root else { return [] }

        var results: [DomainService.Entry] = []
        var cursor: DomainService.PageCursor? = nil
        while true {
            let page: DomainService.ListFolderReturn = try await withCheckedThrowingContinuation { continuation in
                _ = backend.listFolder(entry.id, recursive: true, startingCursor: cursor) { result in
                    switch result {
                    case .success(let resp): continuation.resume(returning: resp)
                    case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                    }
                }
            }
            for child in page.entries where child.type == .file && !translator.isBackendEncrypted(child.name) {
                results.append(child)
            }
            // Pagination ends when the backend returns no continuation cursor.
            guard let next = page.cursor, next != cursor else { break }
            cursor = next
        }
        return results
    }

    /// Signal the working set immediately (per file) so a just-trashed original surfaces in
    /// the macOS Trash without waiting for the whole batch (symptom A).
    private func signalWorkingSetNow(context: String) {
        // Coalesced (leading + 1s trailing) so a bulk action's per-file signals don't each
        // trigger a full recursive enumerateChanges($root) sweep — the enumerate storm.
        workingSetThrottle.request { [weak self] in
            guard let self else { return }
            self.logger.infoPublic("🔄 signalEnumerator(.workingSet) \(context)")
            self.manager.signalEnumerator(for: .workingSet) { [weak self] error in
                if let error {
                    self?.logger.errorPublic("⚠️ signalEnumerator(.workingSet) \(context) failed: \(error)")
                }
            }
        }
    }

    /// Re-reads the working set so the new/renamed items and their badges surface in Finder.
    private func signalWorkingSetAfterEncryptionAction() {
        manager.signalEnumerator(for: .workingSet) { [weak self] error in
            if let error {
                self?.logger.errorPublic("⚠️ signalEnumerator(.workingSet) after encryption action failed: \(error)")
            }
        }
    }

    /// Stream an item's plaintext to a new temp file. Caller removes it.
    func downloadPlaintextFile(_ identifier: DomainService.ItemIdentifier) async throws -> URL {
        let dataURL = makeTemporaryURL("convertSource")
        let param = DomainService.DownloadItemParameter(itemIdentifier: identifier,
                                                        requestedRevision: nil, range: nil)
        let progress = Progress(totalUnitCount: 1)
        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                _ = backend.downloadToFile(param, destinationURL: dataURL, progress: progress) { result in
                    switch result {
                    case .success: continuation.resume()
                    case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                    }
                }
            }
        } catch {
            try? FileManager.default.removeItem(at: dataURL)
            throw error
        }
        return dataURL
    }

    /// Builds a backend-backed ``ContentEncryptionConverter`` for the Finder encryption actions.
    func makeContentEncryptionConverter() -> ContentEncryptionConverter {
        ContentEncryptionConverter(
            downloadPlaintext: { [self] id in
                try await downloadPlaintextFile(id)
            },
            createFile: { [self] parent, name, plaintextURL, encryptor in
                try await createFile(parent: parent, name: name, from: plaintextURL, encryptor: encryptor)
            },
            deleteItem: { [self] id, revision in
                try await deleteBackendItem(id, revision: revision)
            },
            trashItem: { [self] id, revision in
                try await trashBackendItem(id, revision: revision)
            })
    }

    /// Create a backend file named `name` under `parent`, streaming the plaintext at `sourceURL`
    /// through `encryptor`. Fails if an item of that name already exists.
    private func createFile(parent: DomainService.ItemIdentifier,
                            name: String,
                            from sourceURL: URL,
                            encryptor: any FileEncryptor) async throws -> DomainService.Entry {
        let size = (try? FileManager.default.attributesOfItem(atPath: sourceURL.path)[.size] as? NSNumber)??.int64Value
        let param = DomainService.CreateParameter(parent: parent, name: name, type: .file,
                                                  metadata: .empty, conflict: .failOnExisting,
                                                  contentStorageType: .contents,
                                                  plaintextSize: size)
        do {
            return try await backend.createStreaming(param,
                                                     contentsAt: sourceURL,
                                                     originalFilename: metadataTranslator.decodeFromBackend(name),
                                                     encryptor: encryptor,
                                                     progress: Progress()).item
        } catch {
            throw error.toPresentableError()
        }
    }

    private func deleteBackendItem(_ id: DomainService.ItemIdentifier,
                                   revision: DomainService.Version) async throws {
        let param = DomainService.DeleteItemParameter(itemIdentifier: id, existingRevision: revision,
                                                      recursiveDelete: false)
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            _ = backend.deleteItem(param) { result in
                switch result {
                case .success: continuation.resume(returning: ())
                case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                }
            }
        }
    }

    private func trashBackendItem(_ id: DomainService.ItemIdentifier,
                                  revision: DomainService.Version) async throws {
        // Out-of-band (converter) trashing: this backend DELETE bypasses the framework's
        // move-to-trash, so the framework records no original parent and shows no native
        // "Put Back". Flag it so the tombstone qualifies for the custom Restore action.
        let param = DomainService.TrashItemParameter(itemIdentifier: id, existingRevision: revision,
                                                     outOfBand: true)
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            _ = backend.trashItem(param) { result in
                switch result {
                case .success: continuation.resume(returning: ())
                case .failure(let error): continuation.resume(throwing: error.toPresentableError())
                }
            }
        }
    }
}
