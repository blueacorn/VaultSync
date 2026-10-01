/// Microsoft Graph `driveItem` model and its mapping to the VaultSync
/// ``DomainService`` currency types.
///
/// Graph identifiers and tags are opaque strings (see P3a): a ``DomainService/Entry``'s
/// `id` is the DriveItem id, and its `revision` carries the `cTag` (content) and `eTag`
/// (metadata). The user-chosen serving sub-path's DriveItem is presented as the domain
/// root (``GraphDriveClient/rootItemIdentifier``); the real Graph id is held by the
/// client and substituted when the root is addressed.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import FileProvider

// MARK: - Mapping

/// Maps shared Graph wire models (``GraphDriveItem`` et al., defined in Common) onto
/// VaultSync ``DomainService`` currency types.
enum GraphMapping {

    /// Build a JSON decoder configured for Graph timestamps. Shared with the app-side
    /// folder picker via ``GraphDecoding``.
    static func makeDecoder() -> JSONDecoder { GraphDecoding.makeDecoder() }

    /// Convert a Graph `driveItem` to a ``DomainService/Entry``.
    ///
    /// - Parameters:
    ///   - item: The Graph item.
    ///   - rootGraphID: The DriveItem id serving as the domain root; items with this id
    ///     (or whose parent is this id) are remapped to the reserved root identifier.
    ///   - translator: The domain's metadata translator; supplies the plaintext estimate for an
    ///     unresolved encrypted file from its ciphertext length (`item.size`).
    ///   - plaintextSize: The row's resolved BC01 plaintext length, when known. Becomes the
    ///     published `size` and is stamped into the *content* version; when nil the translator's
    ///     estimate (or the ciphertext length) stands in for both. See the `displaySize` /
    ///     `revision` construction below.
    static func entry(from item: GraphDriveItem, rootGraphID: String,
                      translator: MetadataTranslator,
                      plaintextSize: Int64? = nil) -> DomainService.Entry {
        let identifier = itemIdentifier(graphID: item.id, rootGraphID: rootGraphID)

        let parentGraphID = item.parentReference?.id
        let parentIdentifier: DomainService.ItemIdentifier
        if let parentGraphID, parentGraphID == rootGraphID {
            parentIdentifier = GraphDriveClient.rootItemIdentifier
        } else if let parentGraphID {
            parentIdentifier = DomainService.ItemIdentifier(parentGraphID)
        } else {
            parentIdentifier = GraphDriveClient.rootItemIdentifier
        }

        let type: DomainService.EntryType = item.isFolder ? .folder : .file
        // The size actually published as `documentSize`. A resolved plaintext length is
        // authoritative; `item.size` is the ciphertext length and is only exact when nothing is
        // encrypted. The translator's `displaySize` cannot substitute this downstream — it
        // returns nil for a `.bc` file (plaintext length is not derivable from ciphertext
        // length), so whatever is chosen here is what Finder shows.
        // `item.size` is always the Graph (ciphertext) length here, so this is the one place the
        // estimate can be applied safely: downstream, `Entry.size` may already be plaintext.
        let backendSize = item.size ?? 0
        let displaySize = plaintextSize
            ?? translator.estimatedDisplaySize(forBackendSize: backendSize, name: item.name ?? "")
            ?? backendSize

        // The content version is stamped from `displaySize` — the value published above — so the
        // two cannot disagree by construction. The framework re-reads an item's fields only when
        // its version changes, so any path that alters the published size without moving the
        // version leaves the stale size in place: that is exactly how a resolved `|p50362` came to
        // sit beside the ciphertext estimate 54464, the framework accepted the already-seen
        // version, and the correct size a prior hydration had delivered was overwritten.
        //
        // Deriving both from one expression makes that class of bug unrepresentable. `cTag`/`eTag`
        // describe the *ciphertext* and do not move when the plaintext size is resolved locally,
        // so the size has to enter the version explicitly. Stamping unconditionally (rather than
        // only when resolved) also means the estimate → exact transition is itself a version
        // change, and a row seeded with a placeholder `0` corrects itself once the real size
        // arrives. Content only — `documentSize` describes content, and bumping the metadata
        // version would invite re-requests of metadata we did not change.
        //
        // The suffix is an opaque token: nothing parses it to infer whether a size is exact.
        let contentTag = contentTag(for: item)
        let revision = DomainService.Version(content: contentTag, metadata: item.eTag ?? "0")
            .stampingPlaintextSize(displaySize)

        var valid: DomainService.EntryMetadata.ValidEntries = [.fileSystemFlags]
        var creation: Date? = nil
        var modification: Date? = nil
        if let created = item.createdDateTime { creation = created; valid.insert(.creationDate) }
        if let modified = item.lastModifiedDateTime { modification = modified; valid.insert(.contentModificationDate) }

        let flags: NSFileProviderFileSystemFlags = item.isFolder
            ? [.userExecutable, .userWritable, .userReadable]
            : [.userWritable, .userReadable]

        let metadata = DomainService.EntryMetadata(
            fileSystemFlags: flags,
            lastUsedDate: nil,
            tagData: nil,
            favoriteRank: nil,
            creationDate: creation,
            contentModificationDate: modification,
            extendedAttributes: nil,
            typeAndCreator: nil,
            validEntries: valid
        )

        let userInfo = DomainService.Entry.UserInfo(
            conflictCount: nil, originatorName: nil, symlinkTargetPath: nil,
            implicitLockOwner: nil, quotaRemaining: nil, quotaTotal: nil
        )

        return DomainService.Entry(
            name: item.name ?? identifier.id,
            id: identifier,
            parent: parentIdentifier,
            revision: revision,
            deleted: item.isDeleted,
            size: displaySize,
            children: item.folder?.childCount,
            type: type,
            metadata: metadata,
            userInfo: userInfo
        )
    }

    /// The content token a DriveItem's version is built from — the version's
    /// ``DomainService/Version/contentIdentity`` (before any `|p<size>` stamp). `cTag` tracks
    /// content; `eTag` stands in when Graph omits it.
    static func contentTag(for item: GraphDriveItem) -> String {
        item.cTag ?? item.eTag ?? "0"
    }

    /// Map a Graph DriveItem id to a ``DomainService/ItemIdentifier``, remapping the
    /// serving-root id to the reserved root identifier.
    static func itemIdentifier(graphID: String, rootGraphID: String) -> DomainService.ItemIdentifier {
        graphID == rootGraphID
            ? GraphDriveClient.rootItemIdentifier
            : DomainService.ItemIdentifier(graphID)
    }

    /// Resolve a ``DomainService/ItemIdentifier`` back to the Graph DriveItem id,
    /// substituting the serving folder's id for the universal root sentinel.
    static func graphID(for identifier: DomainService.ItemIdentifier, rootGraphID: String) -> String {
        identifier == .root ? rootGraphID : identifier.id
    }
}
