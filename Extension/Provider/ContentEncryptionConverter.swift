/// Safe file-to-file conversion primitive: encrypt, decrypt, or copy an existing backend file
/// into a new item under a chosen encryptor.
///
/// Converting an existing backend item between plaintext and encrypted (`.bc`) form must never
/// risk data loss or leave ciphertext sitting under a plaintext name (content/name
/// mismatch corruption). Neither backend offers an atomic
/// content-replace-and-rename, so this performs a **copy-to-new, verify, then remove-original**
/// sequence, file to file, with memory bounded by the streaming pipeline:
///
/// ```
/// 1. download the source plaintext to a temp file
/// 2. create a NEW backend item from it  name = targetName, encryptor applied during upload
/// 3. verify: download the new item's plaintext to a temp file, stream-compare with step 1
/// 4. on verify success: remove the original (trash if allowed, else hard delete), or keep it
/// 5. on ANY failure before step 4: delete the just-created item  (no orphan, no data loss)
/// ```
///
/// The original is removed **only after** the new item is created *and* verified, so a failure
/// at any earlier point leaves it intact. Each temp file is removed before ``convert`` returns.
///
/// All backend / crypto effects are injected as closures so the converter is unit-testable
/// without a File Provider host or a live backend. See [[extract-refactor-for-testability]].
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// Errors specific to the conversion sequence. Backend / crypto errors propagate unchanged.
public enum ContentEncryptionConverterError: Error, Equatable {
    /// The new item failed read-back verification; it was deleted and the original left
    /// untouched.
    case verificationFailed
    /// The source item's revision moved between read and convert (a racing edit/rename); aborted
    /// with no deletion.
    case revisionMismatch
}

/// Whether the original is sent to the Trash or permanently deleted after a verified
/// conversion.
public enum RemoveOriginalPolicy: Equatable {
    case trash
    case delete
}

public struct ContentEncryptionConverter {

    // MARK: Injected effects

    /// Stream an item's plaintext to a new temp file and return its URL. The converter removes it.
    public var downloadPlaintext: (_ id: DomainService.ItemIdentifier) async throws -> URL
    /// Create a new backend file named `name` under `parent` from the plaintext at `plaintextURL`,
    /// uploaded through `encryptor`; returns the created entry. Must use a fail-on-existing
    /// strategy. For encryption, `encryptor` MUST be strict (no plaintext fallback).
    public var createFile: (_ parent: DomainService.ItemIdentifier,
                            _ name: String,
                            _ plaintextURL: URL,
                            _ encryptor: any FileEncryptor) async throws -> DomainService.Entry
    /// Permanently delete an item (used to roll back a failed conversion, and to hard-delete the
    /// original under `.delete`).
    public var deleteItem: (_ id: DomainService.ItemIdentifier,
                            _ revision: DomainService.Version) async throws -> Void
    /// Move the original item to trash (used under `.trash`).
    public var trashItem: (_ id: DomainService.ItemIdentifier,
                           _ revision: DomainService.Version) async throws -> Void

    public init(downloadPlaintext: @escaping (DomainService.ItemIdentifier) async throws -> URL,
                createFile: @escaping (DomainService.ItemIdentifier, String, URL, any FileEncryptor) async throws -> DomainService.Entry,
                deleteItem: @escaping (DomainService.ItemIdentifier, DomainService.Version) async throws -> Void,
                trashItem: @escaping (DomainService.ItemIdentifier, DomainService.Version) async throws -> Void) {
        self.downloadPlaintext = downloadPlaintext
        self.createFile = createFile
        self.deleteItem = deleteItem
        self.trashItem = trashItem
    }

    // MARK: Conversion

    /// Convert `source` into a new, verified item named `targetName`, uploaded through `encryptor`.
    ///
    /// - Parameters:
    ///   - source: the existing backend file.
    ///   - targetName: the new item's backend name (`name.bc` to encrypt, the plain name to
    ///     decrypt; `"name copy…"` for the copy actions).
    ///   - encryptor: the encryptor applied while uploading the new item.
    ///   - removeOriginal: removal policy, or `nil` to **keep** the original (copy actions).
    ///   - expectedRevision: if non-nil, the conversion aborts with ``ContentEncryptionConverterError/revisionMismatch``
    ///     when it does not match `source.revision` (guards against a racing edit/rename).
    /// - Returns: the created, verified entry.
    public func convert(source: DomainService.Entry,
                        targetName: String,
                        encryptor: any FileEncryptor,
                        removeOriginal: RemoveOriginalPolicy?,
                        expectedRevision: DomainService.Version? = nil) async throws -> DomainService.Entry {

        if let expectedRevision, expectedRevision != source.revision {
            throw ContentEncryptionConverterError.revisionMismatch
        }

        // 1. source plaintext → temp file
        let sourcePlaintext = try await downloadPlaintext(source.id)
        defer { try? FileManager.default.removeItem(at: sourcePlaintext) }

        // 2. create the new item (encryption, if any, happens during upload)
        let created = try await createFile(source.parent, targetName, sourcePlaintext, encryptor)

        // 3. verify by streaming read-back compare; on any failure, roll back the new item.
        do {
            let readBack = try await downloadPlaintext(created.id)
            defer { try? FileManager.default.removeItem(at: readBack) }
            guard try FileContentComparator.equal(readBack, sourcePlaintext) else {
                throw ContentEncryptionConverterError.verificationFailed
            }
        } catch {
            // Roll back: delete the just-created item so no orphan is left. The original is
            // still intact — propagate the original failure.
            try? await deleteItem(created.id, created.revision)
            throw error
        }

        // 4. remove the original (only when asked; copy actions keep it).
        if let removeOriginal {
            switch removeOriginal {
            case .trash:
                try await trashItem(source.id, source.revision)
            case .delete:
                try await deleteItem(source.id, source.revision)
            }
        }

        return created
    }
}
