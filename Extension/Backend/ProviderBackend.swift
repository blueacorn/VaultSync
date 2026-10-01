/// The pluggable backend seam for the File Provider extension.
///
/// `ProviderBackend` abstracts the content + enumeration source behind a domain so the
/// extension can route operations to different backends (the reference `.emulator`
/// HTTP server, OneDrive over Microsoft Graph, a local filesystem) without the call
/// sites in `Extension`, `ItemEnumerator`, and the `Extension+*` files knowing which
/// one is live.
///
/// ## Currency
/// Operations exchange the existing `DomainService` value types
/// (``DomainService/Entry``, ``DomainService/ItemIdentifier``, the per-RPC
/// `*Return` structs) so the seam is a pure transport swap — no new item model.
///
/// ## Variants
/// Methods that the call sites drive through `Progress` (download, create,
/// modify-contents, thumbnail fetch) return a ``Progress`` and report via a result
/// block. Methods used through `try await` are exposed as `async throws`.
///
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import FileProvider

/// Outcome of a background change-detection pass (see ``ProviderBackend/pollDelta()``).
///
/// The protocol-level mirror of the OneDrive-internal `DeltaResult`, kept here so the
/// poller in `Extension` can react without knowing the concrete backend.
public struct DeltaPollResult: Sendable {
    /// Whether any change was reconciled into the backend's local cache.
    public let changed: Bool
    /// `true` if the remote sync cursor expired and a full re-enumeration is required.
    public let cursorExpired: Bool
    /// Identifiers of the containers whose direct children changed this pass. The poller
    /// signals each so the File Provider re-enumerates that folder and `enumerateChanges`
    /// delivers the new/updated/removed child. Empty when nothing changed.
    public let changedParentIdentifiers: Set<DomainService.ItemIdentifier>

    public init(changed: Bool,
                cursorExpired: Bool,
                changedParentIdentifiers: Set<DomainService.ItemIdentifier> = []) {
        self.changed = changed
        self.cursorExpired = cursorExpired
        self.changedParentIdentifiers = changedParentIdentifiers
    }
}

/// Progress from one reconciled page of a background change-detection crawl.
///
/// A delta pass crawls to completion, so its return value arrives once — too coarse to
/// signal from, or to show progress with, on a large initial crawl. This is the per-page channel
/// the extension acts on instead: signal the affected containers, publish the indexed count.
/// The protocol-level mirror of the OneDrive-internal `DeltaPageUpdate`.
public struct DeltaProgress: Sendable {
    /// Identifiers of the containers whose direct children changed on THIS page.
    public let changedParentIdentifiers: Set<DomainService.ItemIdentifier>
    /// Items reconciled so far this pass, across all pages.
    public let itemsSeen: Int
    /// 1-based index of the page just reconciled.
    public let page: Int
    /// `false` on the final page of the crawl.
    public let hasNextPage: Bool
    /// Whether this page reconciled anything. A no-op page still reports progress (the indexed
    /// count must keep advancing) but needs no enumerator signal.
    public let changed: Bool

    public init(changedParentIdentifiers: Set<DomainService.ItemIdentifier>,
                itemsSeen: Int,
                page: Int,
                hasNextPage: Bool,
                changed: Bool) {
        self.changedParentIdentifiers = changedParentIdentifiers
        self.itemsSeen = itemsSeen
        self.page = page
        self.hasNextPage = hasNextPage
        self.changed = changed
    }
}

public protocol ProviderBackend {

    // MARK: Reserved identifiers

    /// Identifier the extension uses for a domain's root item.
    static var rootItemIdentifier: DomainService.ItemIdentifier { get }
    /// Identifier the extension uses for a domain's trash container.
    static var trashItemIdentifier: DomainService.ItemIdentifier { get }

    /// Display name for the backing domain (used in lock-owner labels and logs).
    var displayName: String { get }

    // MARK: Capabilities


    /// Whether the backend accepts items into a recycle bin (move-to-trash), i.e. whether
    /// `.allowsTrashing` is offered and `trashItem(_:_:)` is honoured. Independent of
    /// ``supportsTrashEnumeration``: a backend may accept deletions into a bin yet have no
    /// API to list its contents. Default: `false`.
    var supportsMoveToTrash: Bool { get }

    /// Whether the backend can enumerate the contents of its trash container.
    ///
    /// Distinct from ``supportsMoveToTrash``. OneDrive Personal accepts move-to-trash
    /// (Graph `DELETE` → recycle bin) but has no recycle-bin children endpoint —
    /// `GET /me/drive/items/$trash/children` 400s — so it returns `false` here and the
    /// Extension answers the framework's trash-container probe with `noSuchItem` rather
    /// than issuing a guaranteed-failing round-trip. Default: `false`.
    var supportsTrashEnumeration: Bool { get }

    /// Whether the backend can store and round-trip an item's macOS resource fork / extended
    /// attributes (`..namedfork/rsrc`). Only the reference emulator does today; cloud backends
    /// (OneDrive, and others over their native object APIs) have no sidecar fork store, so they
    /// return `false` and the Extension neither reads nor writes the fork to them — macOS keeps
    /// the fork locally regardless, so nothing is lost. Default: `false`.
    var supportsResourceFork: Bool { get }

    /// Whether the backend can serve an explicit plaintext byte range cheaply enough for
    /// byte-range materialisation (BRM) — sparse, block-aligned partial downloads.
    ///
    /// `true` requires the backend's ``downloadToFile`` to honour
    /// ``DomainService/DownloadItemParameter/range`` and report an accurate
    /// ``DomainService/DownloadToFileReturn/plaintextWindow``. Backends returning `false`
    /// still answer `fetchPartialContents`, but the Extension drops the requested range and
    /// materialises the whole file. Default: `false`.
    var supportsByteRangeMaterialisation: Bool { get }

    // MARK: Display rewriting

    /// Returns `entry` with any backend-encoded filename decoded for display
    /// (e.g. BC01 `.bc` suffix stripping). Default: identity.
    func displayEntry(_ entry: DomainService.Entry) -> DomainService.Entry

    /// Whether the *raw* backend entry is encryption-encoded (e.g. BC01 `.bc` suffix
    /// under an active BC01 algorithm). Must be evaluated on the pre-`displayEntry` name,
    /// since decode strips the encoding signal. Drives the encrypted decoration. Default: `false`.
    func isBackendEncrypted(_ entry: DomainService.Entry) -> Bool

    // MARK: Enumeration

    /// Fetch a single item's metadata.
    ///
    /// - Parameters:
    ///   - identifier: Item to fetch.
    ///   - resolvingPlaintextSize: Resolve (and persist) an encrypted item's exact plaintext length
    ///     when still unknown, so the returned item carries the exact `documentSize` and content
    ///     version. Best-effort: a failure returns the estimate. Content-fetch paths pass `false`,
    ///     since resolving would change the version they validate against.
    ///   - block: Receives the item or an error.
    func fetchItem(_ identifier: DomainService.ItemIdentifier,
                   resolvingPlaintextSize: Bool,
                   _ block: @escaping (Result<DomainService.FetchItemReturn, Error>) -> Void) -> Progress

    /// List a folder's children (optionally recursive), paged by an opaque backend-owned
    /// cursor. Pass `nil` for the first page and the returned cursor for each next page.
    func listFolder(_ folder: DomainService.ItemIdentifier, recursive: Bool, startingCursor: DomainService.PageCursor?,
                    _ block: @escaping (Result<DomainService.ListFolderReturn, Error>) -> Void) -> Progress

    /// The latest sync rank for a folder (the current sync anchor).
    func latestRank(_ folder: DomainService.ItemIdentifier) async throws -> DomainService.LatestRankReturn

    /// Changes for a folder since `startingRank`.
    func listChanges(_ folder: DomainService.ItemIdentifier, recursive: Bool,
                     startingRank: DomainService.RankToken) async throws -> DomainService.ListChangesReturn

    // MARK: Background change detection

    /// Run one best-effort change-detection pass against the remote, reconciling any
    /// changes into the backend's local cache. Returns whether changes were applied and
    /// whether the sync cursor expired. Default: no-op (backend has no remote to poll).
    ///
    /// Driven by a periodic poller in `Extension`; a changed result bumps the domain
    /// version and signals each affected parent container so the File Provider
    /// re-enumerates it and surfaces the new/updated child.
    func pollDelta() async throws -> DeltaPollResult

    /// Count of live items currently indexed in the backend's local change store, or `nil`
    /// for backends without one. Surfaced to the app via the progress relay.
    /// Default: `nil`.
    func indexedItemCount() -> Int?

    // MARK: Domain version (extension-owned)

    /// The extension-owned ``NSFileProviderDomainVersion`` the system should see for this domain.
    ///
    /// Backends that maintain a local change-tracking store (OneDrive via ``MetadataCache`` +
    /// ``DomainVersionStore``) derive the version from their rank high-water mark and the supplied
    /// host `configEpoch`, advancing it when either moves; it is never persisted to the shared
    /// `config.json`. `configEpoch` is the host's monotonic config-change counter for the domain,
    /// read from `config.json` by the caller. Default: a fresh, stable version (no version store).
    func domainVersion(configEpoch: Int) -> NSFileProviderDomainVersion

    // MARK: Lock lifecycle (presentation status)

    /// Inform the backend the user is still presenting `identifier`.
    func pingLock(_ identifier: DomainService.ItemIdentifier, owner: String, enumerationIndex: Int64)
    /// Release a presentation lock.
    func removeLock(_ identifier: DomainService.ItemIdentifier, enumerationIndex: Int64)
    /// Force-break a lock on an item.
    func forceLock(_ identifier: DomainService.ItemIdentifier,
                   _ block: @escaping (Result<DomainService.ForceLockReturn, Error>) -> Void) -> Progress

    // MARK: Content

    /// Stream an item's content (whole-file or an explicit plaintext byte range) to
    /// `destinationURL`, reporting byte progress through the supplied ``Progress``.
    ///
    /// This is the single content-materialisation path for every backend — whole-file AND
    /// byte-range (BRM) fetches. The backend fetches, decrypts, and writes the plaintext bytes
    /// at their correct offsets — bounding memory to roughly one transfer
    /// span rather than the whole file. ``DomainService/DownloadToFileReturn/plaintextWindow`` is
    /// the span of plaintext written (origin 0 and the full length for a whole-file fetch; the
    /// materialised covering window for a ranged fetch).
    func downloadToFile(_ parameter: DomainService.DownloadItemParameter,
                        destinationURL: URL,
                        progress: Progress,
                        _ block: @escaping (Result<DomainService.DownloadToFileReturn, Error>) -> Void) -> Progress

    /// Fetch an item's macOS resource fork (`..namedfork/rsrc`) bytes, in memory.
    ///
    /// The fork is tiny sidecar metadata, a separate stored stream — not file content — so it
    /// stays an in-memory `Data` API and never routes through ``downloadToFile``. Backends with
    /// no fork store (``supportsResourceFork`` == `false`) return empty `Data()` with no network
    /// round-trip.
    func fetchResourceFork(_ identifier: DomainService.ItemIdentifier,
                           revision: DomainService.Version?) async throws -> Data

    /// Create a folder under `parent`. Files (including symlinks and aliases) are created through
    /// ``createStreaming(_:contentsAt:originalFilename:encryptor:progress:)``.
    func createFolder(_ parameter: DomainService.CreateParameter,
                      _ block: @escaping (Result<DomainService.CreateReturn, Error>) async -> Void) -> Progress

    /// Replace an item's resource fork (`contentStorageType == .resourceFork`). File contents are
    /// replaced through ``modifyContentsStreaming(_:contentsAt:originalFilename:encryptor:progress:)``.
    func modifyContents(_ parameter: DomainService.ModifyContentsParameter, data: Data?,
                        _ block: @escaping (Result<DomainService.ModifyContentsReturn, Error>) -> Void) -> Progress

    /// Create a file by streaming `sourceURL` through `encryptor`, encrypting and uploading in
    /// bounded spans rather than encrypting the whole file up front.
    ///
    /// The single upload path for file contents of every size: backends run the shared
    /// ``ContentStreamUploader``, which sends one request when the ciphertext fits the
    /// transport's limit and fragments otherwise.
    ///
    /// **Encryption boundary.** The Extension passes the *encryptor* across the seam so
    /// encryption can be interleaved with upload. The backend never gains access to key material: it only
    /// forwards the opaque ``FileEncryptor`` into `ContentStreamUploader`. The fail-closed
    /// guarantee is unchanged and still enforced Extension-side — `makeEncryptor()` throws
    /// `.notAuthenticated` before any backend call, so an unavailable key means nothing is
    /// uploaded, never plaintext to an encrypted domain.
    func createStreaming(_ parameter: DomainService.CreateParameter,
                         contentsAt sourceURL: URL,
                         originalFilename: String,
                         encryptor: any FileEncryptor,
                         progress: Progress) async throws -> DomainService.CreateReturn

    /// Replace an item's contents by streaming `sourceURL` through `encryptor`.
    /// See ``createStreaming(_:contentsAt:originalFilename:encryptor:progress:)``.
    func modifyContentsStreaming(_ parameter: DomainService.ModifyContentsParameter,
                                 contentsAt sourceURL: URL,
                                 originalFilename: String,
                                 encryptor: any FileEncryptor,
                                 progress: Progress) async throws -> DomainService.ModifyContentsReturn

    /// Persist a metadata change (rename / reparent / attributes / tags / xattrs).
    ///
    /// The backend persists **every** field in `parameter` using whatever stores it has —
    /// remote where it can, a local sidecar where the remote has no home for the field
    /// (e.g. OneDrive has no Graph field for Finder `tagData` / extended attributes) — and
    /// returns the authoritative item with all persisted fields reflected. Persistence
    /// location is the backend's concern and transparent to the caller.
    func modifyMetadata(_ parameter: DomainService.ModifyMetadataParameter,
                        _ block: @escaping (Result<DomainService.ModifyMetadataReturn, Error>) -> Void) -> Progress

    /// Permanently delete an item.
    func deleteItem(_ parameter: DomainService.DeleteItemParameter,
                    _ block: @escaping (Result<DomainService.DeleteItemReturn, Error>) -> Void) -> Progress

    /// Move an item to trash.
    func trashItem(_ parameter: DomainService.TrashItemParameter,
                   _ block: @escaping (Result<DomainService.TrashItemReturn, Error>) -> Void) -> Progress

    /// Whether the backend can restore a trashed item to its original location.
    var supportsRestore: Bool { get }

    /// Whether the item identified by `identifier` is currently in the local trash
    /// (tombstoned with a `deletedAt` timestamp). Used to detect "Put Back" vs normal reparent.
    func isItemTrashed(_ identifier: DomainService.ItemIdentifier) throws -> Bool

    /// Restore a trashed item (e.g. via Graph `/restore`).
    func restoreItem(_ parameter: DomainService.RestoreItemParameter,
                     _ block: @escaping (Result<DomainService.RestoreItemReturn, Error>) -> Void) -> Progress

    /// Set heart / pinned / shared marks on items.
    func mark(_ parameter: DomainService.MarkParameter,
              _ block: @escaping (Result<DomainService.MarkReturn, Error>) -> Void) -> Progress

    // MARK: Thumbnails

    /// Fetch a thumbnail's bytes.
    func fetchThumbnail(_ parameter: DomainService.FetchThumbnailParameter,
                        _ block: @escaping (Result<(response: DomainService.FetchThumbnailReturn, data: Data), Error>) -> Void) -> Progress

    /// Refresh/generate a thumbnail from supplied bytes.
    func updateThumbnail(_ parameter: DomainService.UpdateThumbnailParameter,
                         data: Data) async throws -> DomainService.UpdateThumbnailReturn

    // MARK: Conflict servicing

    /// List conflict versions for an item.
    func conflictVersions(_ parameter: DomainService.ConflictVersionsParameter,
                          _ block: @escaping (Result<DomainService.ConflictVersionsReturn, Error>) -> Void) -> Progress

    /// Resolve conflict versions for an item.
    func resolveConflictVersions(_ parameter: DomainService.ResolveConflictVersionsParameter,
                                 _ block: @escaping (Result<DomainService.ResolveConflictVersionsReturn, Error>) -> Void) -> Progress
}

// MARK: - Defaults

public extension ProviderBackend {

    func displayEntry(_ entry: DomainService.Entry) -> DomainService.Entry { entry }
    func isBackendEncrypted(_ entry: DomainService.Entry) -> Bool { false }

    /// Default: no fork store, so reading a fork is a no-op returning empty bytes. Backends that
    /// override ``supportsResourceFork`` to `true` must also override this to fetch real bytes.
    func fetchResourceFork(_ identifier: DomainService.ItemIdentifier,
                           revision: DomainService.Version?) async throws -> Data { Data() }

    /// Fetch without plaintext-size resolution.
    func fetchItem(_ identifier: DomainService.ItemIdentifier,
                   _ block: @escaping (Result<DomainService.FetchItemReturn, Error>) -> Void) -> Progress {
        fetchItem(identifier, resolvingPlaintextSize: false, block)
    }

    /// Default: the backend has no remote to poll (emulator, LocalFS).
    func pollDelta() async throws -> DeltaPollResult { .init(changed: false, cursorExpired: false) }

    /// Default: no local change store to count.
    func indexedItemCount() -> Int? { nil }

    /// Default: no local version store, so report a fresh, stable version.
    func domainVersion(configEpoch: Int) -> NSFileProviderDomainVersion { NSFileProviderDomainVersion() }

    var supportsByteRangeMaterialisation: Bool { false }
    var supportsResourceFork: Bool { false }

    /// Default: backends neither accept move-to-trash nor expose a browsable bin. Backends
    /// with a recycle bin opt in per capability.
    var supportsMoveToTrash: Bool { false }
    var supportsTrashEnumeration: Bool { false }

    var supportsRestore: Bool { false }
    func isItemTrashed(_ identifier: DomainService.ItemIdentifier) throws -> Bool { false }
    func restoreItem(_ parameter: DomainService.RestoreItemParameter,
                     _ block: @escaping (Result<DomainService.RestoreItemReturn, Error>) -> Void) -> Progress {
        block(.failure(CommonError.notImplemented)); return Progress()
    }
}
