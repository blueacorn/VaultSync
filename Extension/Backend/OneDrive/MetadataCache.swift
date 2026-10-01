/// Metadata-only mirror of the OneDrive sub-tree, persisted as SQLite in the App Group
/// container.
///
/// OneDrive (Graph) remains the source of truth; this cache exists to serve enumeration
/// and offline browsing quickly, to hold the delta cursor, and to assign the monotonic
/// local ranks that back File Provider sync anchors. It stores **metadata only** — no
/// file contents or content-addressed chunks.
///
/// Backed by the system `SQLite3` C library (no external package), so the sandboxed
/// extension stays lean. One database file per domain lives in the shared App Group
/// container, reachable by both the app and the extension.
///
/// Derived in spirit from `Server/ItemDatabase.swift` but reduced to: an `items` mirror
/// keyed by the stable Graph DriveItem id, and a `meta` key/value table holding the
/// persisted `deltaLink`, the serving-root Graph id, and the rank high-water mark.
/// On schema mismatch the store is rebuilt from a full delta (see ``GraphDeltaSync``).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import SQLite3
import os.log

/// A cached item row (metadata only).
struct CachedItem: Equatable {
    var graphID: String
    var parentGraphID: String?
    var name: String
    var isFolder: Bool
    /// Backend (ciphertext) byte length, as reported by Graph's `DriveItem.size`. For a `.bc`
    /// item this is NOT the length the user sees — that is ``plaintextSize``. Named for the
    /// remote so the two are never confused at a call site.
    var remoteFileSize: Int64
    var eTag: String?
    var cTag: String?
    var createdDate: Date?
    var modifiedDate: Date?
    var deleted: Bool
    /// Set when the item was moved to the recycle bin (`markTrashed`). Nil for
    /// permanently-deleted tombstones (`markDeleted`). Drives trash enumeration.
    var deletedAt: Date?
    /// Monotonic local rank assigned on upsert; backs the FP sync anchor.
    var rank: Int64
    /// Local-only metadata the remote cannot store: Finder colour/label `tagData`, and
    /// extended attributes (which include the heart / pinned / isShared marks). Never
    /// synced — OneDrive has no field for them. Persisted independently of the delta
    /// upsert path so a re-crawl never clobbers them. Empty when the item has none.
    var localMetadata: LocalMetadata = .empty
    /// Exact plaintext byte length, once known. ``remoteFileSize`` is the BACKEND (ciphertext)
    /// length; for a `.bc` item the two differ and the plaintext length is only knowable after
    /// the file's BC01 header has been read. `nil` = not yet resolved (never fetched, or a plain
    /// item where ``remoteFileSize`` is already exact), in which case callers fall back to the
    /// ciphertext-derived estimate.
    ///
    /// - Important: Only ever an EXACT value — from
    ///   ``BC01CryptoCommon/exactPlaintextSize(header:remoteSize:)`` for `.bc`, or the remote
    ///   size for a plain item. Never the display estimate from
    ///   `BoxcryptorMetadataTranslator.displaySize(forBackendSize:name:)`: a stored value outranks
    ///   that estimate on every read, so persisting it launders an approximation into an
    ///   authority. Persisted so a size learned during a PARTIAL fetch survives to the next
    /// enumeration — the only channel that can update the system's `documentSize` for an item
    /// that was never fully materialised.
    var plaintextSize: Int64?

    init(graphID: String, parentGraphID: String?, name: String, isFolder: Bool, remoteFileSize: Int64,
         eTag: String?, cTag: String?, createdDate: Date?, modifiedDate: Date?,
         deleted: Bool, deletedAt: Date? = nil, rank: Int64,
         localMetadata: LocalMetadata = .empty, plaintextSize: Int64? = nil) {
        self.graphID = graphID; self.parentGraphID = parentGraphID; self.name = name
        self.isFolder = isFolder; self.remoteFileSize = remoteFileSize
        self.eTag = eTag; self.cTag = cTag
        self.createdDate = createdDate; self.modifiedDate = modifiedDate
        self.deleted = deleted; self.deletedAt = deletedAt; self.rank = rank
        self.localMetadata = localMetadata
        self.plaintextSize = plaintextSize
    }
}

/// The local-only metadata blob stored alongside a cached row. Encoded as JSON in the
/// `local_meta` column. `extendedAttributes` carries the app marks (heart / pinned /
/// isShared) as well as any user xattrs; `tagData` carries Finder colour/label tags.
struct LocalMetadata: Codable, Equatable {
    var extendedAttributes: [String: Data]
    var tagData: Data?
    /// Set when a crypto/decode failure occurred on last download attempt; drives the
    /// `fileError` decoration. Never synced — local device state only.
    var contentError: Bool?
    /// Set when this item was moved to the recycle bin out-of-band — by the encrypt/decrypt
    /// bulk action's Graph DELETE — rather than by a framework-initiated move-to-trash. Only
    /// out-of-band trashing leaves the framework without a recorded original parent, so native
    /// "Put Back" never appears for these; this flag drives our custom Restore action and gates
    /// it to exactly those items (framework-trashed items keep their native "Put Back", no
    /// duplicate). Never synced — local device state only.
    var restorableOutOfBand: Bool?

    static let empty = LocalMetadata(extendedAttributes: [:], tagData: nil)

    var isEmpty: Bool {
        extendedAttributes.isEmpty && tagData == nil && contentError == nil
            && restorableOutOfBand == nil
    }

    /// Returns a copy with the local-only fields of `metadata` applied (only those marked
    /// present by its `validEntries`). Remote-only fields are ignored — they have no place
    /// in this sidecar. Used by `modifyMetadata` to fold a Finder change into the store.
    func merging(_ metadata: DomainService.EntryMetadata) -> LocalMetadata {
        var copy = self
        if metadata.validEntries.contains(.extendedAttributes) {
            copy.extendedAttributes = metadata.extendedAttributes?.values ?? [:]
        }
        if metadata.validEntries.contains(.tagData) {
            copy.tagData = metadata.tagData
        }
        return copy
    }

    /// Encode a heart / pinned / isShared mark into (or out of) `extendedAttributes` under
    /// `name`: stored when it should appear as an xattr, removed otherwise. `nil` is a no-op
    /// (the mark wasn't part of this action). Mirrors the emulator's xattr handling.
    mutating func applyMark<T: XAttrGettable>(_ value: T?, _ name: String) {
        guard let value else { return }
        if value.includeAsExtendedAttribute {
            extendedAttributes[name] = try? JSONEncoder().encode(value)
        } else {
            extendedAttributes.removeValue(forKey: name)
        }
    }
}

/// The lifecycle state a cached row is in, derived from the `deleted` / `deletedAt`
/// column pair. The two columns are the storage; this enum is the single named view
/// every reader should switch on instead of re-deriving the boolean algebra.
///
/// - `live`:    `deleted=0` — a normal, visible item.
/// - `trashed`: `deleted=1, deletedAt != nil` — in the recycle bin. Display facets are
///   frozen (see `upsertSQL`) and the item is restorable.
/// - `purged`:  `deleted=1, deletedAt == nil` — a permanent-deletion tombstone. The row
///   is kept only long enough to emit one `deletedEntries` event before being vacuumed.
enum LifecycleState { case live, trashed, purged }

extension CachedItem {
    /// The row's ``LifecycleState``, derived once from `deleted` / `deletedAt`.
    var lifecycle: LifecycleState {
        guard deleted else { return .live }
        return deletedAt != nil ? .trashed : .purged
    }

    /// In the recycle bin (`deleted=1 AND deleted_at NOT NULL`): restorable, facets frozen.
    var isTrashed: Bool { lifecycle == .trashed }

    /// A permanent-deletion tombstone (`deleted=1 AND deleted_at NULL`): pending vacuum.
    var isPurged: Bool { lifecycle == .purged }

    /// Whether `other` carries the same content as this row, ignoring `rank` (local
    /// bookkeeping). Used to skip rank-bumping no-op upserts during full delta re-crawls.
    func matchesContent(of other: CachedItem) -> Bool {
        parentGraphID == other.parentGraphID &&
        name == other.name &&
        isFolder == other.isFolder &&
        remoteFileSize == other.remoteFileSize &&
        eTag == other.eTag &&
        cTag == other.cTag &&
        createdDate == other.createdDate &&
        modifiedDate == other.modifiedDate &&
        deleted == other.deleted &&
        deletedAt == other.deletedAt &&
        // Part of the row's content, not local bookkeeping: an upsert that resolves (or clears)
        // the exact plaintext length must not be short-circuited as a no-op, or the rank never
        // advances and `enumerateChanges` never delivers the corrected `documentSize`.
        plaintextSize == other.plaintextSize
    }
}

/// Errors raised by the metadata cache.
enum MetadataCacheError: Error {
    case open(String)
    case prepare(String)
    case step(String)
    case containerUnavailable
}

final class MetadataCache {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "graph-cache")
    private static let appGroupID = AppIdentifiers.appGroupID
    /// Bump when the schema changes to force a rebuild from a full delta.
    private static let schemaVersion = 7

    private let domainID: String
    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "graph-metadata-cache")

    init(domainID: String) throws {
        self.domainID = domainID
        try open()
    }

    deinit { if let db { sqlite3_close(db) } }

    // MARK: - Lifecycle

    private func databaseURL() throws -> URL {
        try Self.databaseURL(domainID: domainID, createDirectory: true)
    }

    /// The backing SQLite file URL for `domainID` in the App Group container.
    ///
    /// - Parameter createDirectory: When `true`, ensures the `OneDriveCache` directory
    ///   exists (required before opening). `destroy` passes `false` — a missing directory
    ///   means nothing to delete.
    private static func databaseURL(domainID: String, createDirectory: Bool) throws -> URL {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            Self.log.error("❌ App Group container '\(appGroupID, privacy: .public)' unavailable for domain=\(domainID, privacy: .public) — metadata cache cannot be opened")
            throw MetadataCacheError.containerUnavailable
        }
        let dir = container.appendingPathComponent("OneDriveCache", isDirectory: true)
        if createDirectory {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        // One file per domain; sanitise the identifier for the filesystem.
        let safe = domainID.replacingOccurrences(of: "/", with: "_")
        return dir.appendingPathComponent("\(safe).sqlite3")
    }

    /// Delete every cached row while keeping the database file, schema and any open handle
    /// valid — the safe counterpart to ``destroy(domainID:)``.
    ///
    /// Used by "Lock and Remove Vault", where the Provider may still hold this cache open:
    /// unlinking the file under a live handle risks the WAL sidecars being recreated and a
    /// stale handle writing to an unlinked inode. Emptying in place has no such race.
    ///
    /// The delta cursor in `meta` is cleared deliberately. It refers to remote state whose
    /// local rows are being deleted, so resuming from it would skip re-seeding them and leave
    /// the cache permanently incomplete; dropping it forces the full re-seed that unlock needs.
    /// `schema_version` is re-seeded so the next open doesn't trigger a schema rebuild.
    func empty() throws {
        try queue.sync {
            try execUnsynced("DELETE FROM items;")
            try execUnsynced("DELETE FROM meta;")
            try setMetaUnsynced("schema_version", String(Self.schemaVersion))
            // Return the freed pages. Must not run inside an explicit transaction; none is
            // open here.
            try execUnsynced("VACUUM;")
        }
        Self.log.infoPublic("🧹 emptied OneDrive metadata cache")
    }

    /// Remove the on-disk metadata cache (db plus the `-wal`/`-shm` sidecars) for `domainID`.
    ///
    /// Idempotent: missing files are ignored. The caller must ensure no live
    /// ``MetadataCache`` for the domain remains open, otherwise the WAL sidecars may be
    /// recreated on the next write.
    static func destroy(domainID: String) throws {
        let dbURL = try databaseURL(domainID: domainID, createDirectory: false)
        let fm = FileManager.default
        // SQLite names the WAL/SHM sidecars `<db>-wal` / `<db>-shm` (suffix on the full
        // filename, not a replaced path extension).
        let base = dbURL.deletingLastPathComponent()
        let name = dbURL.lastPathComponent
        for url in [dbURL,
                    base.appendingPathComponent(name + "-wal"),
                    base.appendingPathComponent(name + "-shm")] {
            if fm.fileExists(atPath: url.path) {
                try fm.removeItem(at: url)
            }
        }
    }

    private func open() throws {
        let url = try databaseURL()
        Self.log.infoPublic("📂 opening cache db domain=\(domainID) path=\(url.path)")
        var handle: OpaquePointer?
        let rc = sqlite3_open(url.path, &handle)
        guard rc == SQLITE_OK, let handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open rc=\(rc)"
            Self.log.errorPublic("❌ sqlite3_open failed rc=\(rc) msg=\(msg) path=\(url.path)")
            throw MetadataCacheError.open(msg)
        }
        self.db = handle
        // Lock-and-Remove empties this cache from the **app** while `Provider.appex` may still
        // hold its own handle open and be mid-write: with no busy timeout the very first
        // `DELETE FROM items` returned SQLITE_BUSY ("database is locked") immediately, so the
        // teardown reported failure and left the whole file index on disk. Wait for the other
        // writer to finish rather than failing on contention that resolves in milliseconds.
        sqlite3_busy_timeout(handle, 5000)
        try exec("PRAGMA journal_mode=WAL;")
        // The cache is a rebuildable derived store (delta sync + `/children` reseed it), not
        // the source of truth. `synchronous=NORMAL` under WAL skips the per-commit fsync,
        // trading only a possible loss of the last commit(s) on power-loss/OS-crash (which a
        // subsequent delta pass simply re-applies) for a large reduction in write latency —
        // notably on cold-folder seeding, which commits a page of children at a time.
        try exec("PRAGMA synchronous=NORMAL;")
        // Cache is a rebuildable derived store and the product is local-dev-only (no
        // deployed domains to migrate): on any schema-version change, drop and recreate.
        try exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);")
        if currentSchemaVersion() != Self.schemaVersion {
            try rebuildSchema()
        } else {
            try createSchema()
        }
        Self.log.infoPublic("✅ cache db ready domain=\(domainID)")
    }

    private func createSchema() throws {
        try exec("""
        CREATE TABLE IF NOT EXISTS items (
            graph_id      TEXT PRIMARY KEY,
            parent_id     TEXT,
            name          TEXT NOT NULL,
            is_folder     INTEGER NOT NULL,
            remote_file_size INTEGER NOT NULL,
            etag          TEXT,
            ctag          TEXT,
            created       REAL,
            modified      REAL,
            deleted       INTEGER NOT NULL DEFAULT 0,
            deleted_at    REAL,
            rank          INTEGER NOT NULL,
            local_meta    BLOB,
            -- Exact plaintext length once known (NULL = unresolved; fall back to the
            -- ciphertext-derived estimate). See CachedItem.plaintextSize.
            plaintext_size INTEGER,
            -- Full-crawl generation that last saw this row live (see beginFullCrawl /
            -- sweepUnseen). 0 = never stamped by a generation-tagged crawl.
            seen_gen      INTEGER NOT NULL DEFAULT 0,
            -- Computed single source of truth for the "in the recycle bin" predicate.
            -- Every trash query and the tombstone-freeze CASEs read this name instead of
            -- respelling `deleted=1 AND deleted_at IS NOT NULL`. VIRTUAL: no stored bytes,
            -- evaluated on read off the row's own columns.
            is_trashed    INTEGER GENERATED ALWAYS AS (deleted = 1 AND deleted_at IS NOT NULL) VIRTUAL
        );
        """)
        try exec("CREATE INDEX IF NOT EXISTS idx_items_parent ON items(parent_id);")
        try exec("CREATE INDEX IF NOT EXISTS idx_items_rank ON items(rank);")
        try exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);")
        if currentSchemaVersion() == nil {
            try setMeta("schema_version", String(Self.schemaVersion))
        }
    }

    private func rebuildSchema() throws {
        Self.log.infoPublic("♻️ rebuilding OneDrive metadata cache (schema change)")
        try exec("DROP TABLE IF EXISTS items;")
        try exec("DELETE FROM meta;")
        try createSchema()
        try setMeta("schema_version", String(Self.schemaVersion))
    }

    private func currentSchemaVersion() -> Int? {
        (try? getMeta("schema_version")).flatMap { $0 }.flatMap(Int.init)
    }

    // MARK: - Meta key/value

    func setMeta(_ key: String, _ value: String) throws {
        try queue.sync {
            let stmt = try prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;")
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, key)
            bindText(stmt, 2, value)
            try stepDone(stmt)
        }
    }

    /// Remove a `meta` key. Deleting an absent key is not an error.
    func deleteMeta(_ key: String) throws {
        try queue.sync {
            let stmt = try prepare("DELETE FROM meta WHERE key = ?;")
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, key)
            try stepDone(stmt)
        }
    }

    func getMeta(_ key: String) throws -> String? {
        try queue.sync {
            let stmt = try prepare("SELECT value FROM meta WHERE key = ?;")
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, key)
            if sqlite3_step(stmt) == SQLITE_ROW {
                return column(stmt, 0)
            }
            return nil
        }
    }

    /// The persisted Graph `@odata.deltaLink`, if any.
    var deltaLink: String? {
        get { try? getMeta("delta_link") ?? nil }
    }
    func setDeltaLink(_ link: String?) throws {
        try setMeta("delta_link", link ?? "")
    }

    /// Whether a delta pass has ever crawled this cache to a `deltaLink` (as opposed to
    /// stopping on a `nextLink`). A completed crawl is a full enumeration of the serving
    /// root, so every folder's children are present and no `/children` walk is owed.
    ///
    /// Discarded with the rows it describes when the cache is torn down (`destroy` unlinks
    /// the file; `empty` drops all of `meta`), and cleared explicitly on a 410 cursor expiry
    /// and whenever a full crawl begins — see ``beginFullCrawl()``. A stale `true` must never
    /// outlive the rows.
    var isInitialCrawlComplete: Bool {
        ((try? getMeta(Self.crawlCompleteKey)) ?? nil) != nil
    }

    /// Record that a delta pass reached the end of the enumeration. Idempotent.
    func markInitialCrawlComplete() {
        try? setMeta(Self.crawlCompleteKey, ISO8601DateFormatter().string(from: Date()))
    }

    /// Withdrawn only by ``beginFullCrawl()`` (first crawl, `410 Gone`, Rebuild Index), never
    /// by a pass that merely paged or was cancelled: those saw part of the drive without
    /// invalidating what is already there.
    private static let crawlCompleteKey = "initial_crawl_complete"

    // MARK: - Full-crawl generations

    /// Monotonic full-crawl counter; reset only with the rows (`empty`, schema rebuild).
    private static let crawlGenerationKey = "crawl_gen"
    /// Generation of the full crawl in progress; absent when none is pending.
    private static let pendingCrawlGenerationKey = "pending_full_crawl_gen"

    /// Start a generation-tagged full crawl: bumps `crawl_gen`, records it as pending, and
    /// drops the delta cursor and the completeness claim — one transaction.
    ///
    /// Rows are not wiped: the crawl stamps every row it returns with the new generation, and
    /// ``sweepUnseen(generation:excludingGraphID:)`` purges the rest when the crawl reaches a
    /// deltaLink. Local-only state (`local_meta`, `plaintext_size`, `bcfolder:*` marks) and the
    /// `rank_hwm` therefore survive.
    ///
    /// Safe to call from the host app while the extension holds the cache open (busy timeout).
    ///
    /// - Returns: The new generation.
    @discardableResult
    func beginFullCrawl() throws -> Int64 {
        try queue.sync {
            try execUnsynced("BEGIN IMMEDIATE;")
            do {
                let current = (try getMetaUnsynced(Self.crawlGenerationKey)).flatMap(Int64.init) ?? 0
                let generation = current + 1
                try setMetaUnsynced(Self.crawlGenerationKey, String(generation))
                try setMetaUnsynced(Self.pendingCrawlGenerationKey, String(generation))
                try setMetaUnsynced("delta_link", "")
                try deleteMetaUnsynced(Self.crawlCompleteKey)
                try execUnsynced("COMMIT;")
                return generation
            } catch {
                try? execUnsynced("ROLLBACK;")
                throw error
            }
        }
    }

    /// The generation of the full crawl in progress, or `nil` when none is pending.
    var pendingFullCrawlGeneration: Int64? {
        ((try? getMeta(Self.pendingCrawlGenerationKey)) ?? nil).flatMap(Int64.init)
    }

    /// Purge every live row the full crawl `generation` did not see.
    ///
    /// Live (`deleted=0`) rows other than the serving root with `seen_gen < generation` become
    /// permanent-deletion tombstones (`deleted=1, deleted_at=NULL`) with a fresh rank, so the
    /// working-set feed emits them as deletions. Trashed rows are left as they are.
    ///
    /// - Returns: Parent Graph ids of the purged rows, for container signalling.
    @discardableResult
    func sweepUnseen(generation: Int64, excludingGraphID rootID: String) throws -> Set<String> {
        try queue.sync {
            try execUnsynced("BEGIN IMMEDIATE;")
            do {
                let select = try prepare("""
                    SELECT graph_id, parent_id FROM items
                    WHERE deleted = 0 AND seen_gen < ? AND graph_id <> ?;
                    """)
                defer { sqlite3_finalize(select) }
                sqlite3_bind_int64(select, 1, generation)
                bindText(select, 2, rootID)
                var unseen: [(graphID: String, parentID: String?)] = []
                while sqlite3_step(select) == SQLITE_ROW {
                    if let id = column(select, 0) { unseen.append((id, column(select, 1))) }
                }

                let purge = try prepare("UPDATE items SET deleted = 1, deleted_at = NULL, rank = ? WHERE graph_id = ?;")
                defer { sqlite3_finalize(purge) }
                var parents = Set<String>()
                for row in unseen {
                    let rank = try allocateRankUnsynced()
                    sqlite3_reset(purge)
                    sqlite3_clear_bindings(purge)
                    sqlite3_bind_int64(purge, 1, rank)
                    bindText(purge, 2, row.graphID)
                    try stepDone(purge)
                    if let parent = row.parentID { parents.insert(parent) }
                }
                try execUnsynced("COMMIT;")
                if !unseen.isEmpty {
                    Self.log.infoPublic("🧹 swept \(unseen.count) row(s) unseen by crawl gen \(generation)")
                }
                return parents
            } catch {
                try? execUnsynced("ROLLBACK;")
                throw error
            }
        }
    }

    /// Save a delta cursor on behalf of a pass running under `generation` (`nil` = incremental).
    ///
    /// Written only while the pending generation still equals `generation`, atomically with the
    /// check: a host-side ``beginFullCrawl()`` issued mid-pass clears the cursor, and a stale
    /// pass must not put its own link back — resuming it under the newer generation would make
    /// that generation's sweep purge every row the skipped pages carried.
    ///
    /// - Parameter finishCrawl: `true` for a full crawl's deltaLink: also clears the pending
    ///   generation (call after ``sweepUnseen(generation:excludingGraphID:)``).
    /// - Returns: `false` when a newer generation superseded the pass; nothing was written.
    func saveCursor(_ link: String, generation: Int64?, finishCrawl: Bool = false) throws -> Bool {
        try queue.sync {
            try execUnsynced("BEGIN IMMEDIATE;")
            do {
                guard try pendingCrawlGenerationUnsynced() == generation else {
                    try execUnsynced("ROLLBACK;")
                    return false
                }
                try setMetaUnsynced("delta_link", link)
                if finishCrawl { try deleteMetaUnsynced(Self.pendingCrawlGenerationKey) }
                try execUnsynced("COMMIT;")
                return true
            } catch {
                try? execUnsynced("ROLLBACK;")
                throw error
            }
        }
    }

    /// The serving-root Graph DriveItem id.
    func rootGraphID() -> String? { (try? getMeta("root_graph_id")) ?? nil }
    func setRootGraphID(_ id: String) throws { try setMeta("root_graph_id", id) }

    // MARK: - Rank allocation

    /// Allocate and persist the next monotonic rank.
    func allocateRank() throws -> Int64 {
        try queue.sync { try allocateRankUnsynced() }
    }

    /// Allocate the next rank; caller must already hold `queue`.
    private func allocateRankUnsynced() throws -> Int64 {
        let current = (try? getMetaUnsynced("rank_hwm")).flatMap { $0 }.flatMap(Int64.init) ?? 0
        let next = current + 1
        try setMetaUnsynced("rank_hwm", String(next))
        return next
    }

    /// Run a read-modify-write over `meta` rows under the cache lock, as one critical section.
    /// Lets a reader keep a multi-key `meta` update (e.g. a derived version token plus the rank
    /// it was stamped at) atomic with respect to concurrent cache writes, without exposing the
    /// lock or the SQLite handle. The cache treats every value as an opaque `String`;
    /// interpretation is the caller's concern.
    func withMetaTransaction<T>(_ body: (MetaTransaction) throws -> T) rethrows -> T {
        try queue.sync { try body(MetaTransaction(cache: self)) }
    }

    /// Scoped accessor for unsynchronised `meta` get/set, valid only inside ``withMetaTransaction``
    /// where the cache lock is already held.
    struct MetaTransaction {
        fileprivate let cache: MetadataCache
        func get(_ key: String) -> String? { (try? cache.getMetaUnsynced(key)).flatMap { $0 } }
        func set(_ key: String, _ value: String) throws { try cache.setMetaUnsynced(key, value) }
        /// The current rank high-water mark, read inside the same critical section.
        func currentRank() -> Int64 { (get("rank_hwm")).flatMap(Int64.init) ?? 0 }
    }

    // MARK: - Items

    /// Insert or update an item, assigning a fresh rank.
    ///
    /// A no-op when an identical row already exists: redundant upserts (e.g. a full delta
    /// re-crawl that re-sees every unchanged item) neither rewrite the row nor bump the
    /// rank, so the rank high-water mark only advances on genuine changes and
    /// `enumerateChanges` doesn't replay the entire tree.
    @discardableResult
    func upsert(_ item: CachedItem) throws -> Int64 {
        try queue.sync {
            if let existing = try? itemRowUnsynced(graphID: item.graphID),
               existing.matchesContent(of: item) {
                return existing.rank
            }
            let stmt = try prepare(Self.upsertSQL)
            defer { sqlite3_finalize(stmt) }
            let rank = try allocateRankUnsynced()
            bindUpsert(stmt, item, rank: rank, generation: nil,
                       insertGeneration: try pendingCrawlGenerationUnsynced())
            try stepDone(stmt)
            return rank
        }
    }

    /// Upsert a page of items in a single transaction, reusing one prepared statement.
    ///
    /// Far cheaper than per-row ``upsert`` for large delta pages: one `queue.sync`, one
    /// statement compile, and one fsync (the WAL commit) instead of N. Identical rows are
    /// skipped (no rank bump, no write); returns the number of rows actually written.
    ///
    /// - Parameter generation: The full-crawl generation that returned these rows. When set,
    ///   every row — including an identical one — is stamped `seen_gen = generation` (the
    ///   identical row gets that stamp only: no rank bump, not counted as written). `nil` for
    ///   non-crawl writers (`/children` seeding, mutations), which leave `seen_gen` untouched on
    ///   update and stamp a fresh insert with the pending generation: that data is current
    ///   remote state the crawl may already have paged past.
    @discardableResult
    func upsertBatch(_ items: [CachedItem], generation: Int64? = nil) throws -> Int {
        guard !items.isEmpty else { return 0 }
        return try queue.sync {
            try execUnsynced("BEGIN IMMEDIATE;")
            var written = 0
            do {
                let stmt = try prepare(Self.upsertSQL)
                defer { sqlite3_finalize(stmt) }
                let stamp = try prepare("UPDATE items SET seen_gen = ? WHERE graph_id = ?;")
                defer { sqlite3_finalize(stamp) }
                let insertGeneration = try generation ?? pendingCrawlGenerationUnsynced()
                for item in items {
                    if let existing = try? itemRowUnsynced(graphID: item.graphID),
                       existing.matchesContent(of: item) {
                        if let generation {
                            sqlite3_reset(stamp)
                            sqlite3_clear_bindings(stamp)
                            sqlite3_bind_int64(stamp, 1, generation)
                            bindText(stamp, 2, item.graphID)
                            try stepDone(stamp)
                        }
                        continue
                    }
                    let rank = try allocateRankUnsynced()
                    sqlite3_reset(stmt)
                    sqlite3_clear_bindings(stmt)
                    bindUpsert(stmt, item, rank: rank, generation: generation,
                               insertGeneration: insertGeneration)
                    try stepDone(stmt)
                    written += 1
                }
            } catch {
                try? execUnsynced("ROLLBACK;")
                throw error
            }
            try execUnsynced("COMMIT;")
            return written
        }
    }

    private static let upsertSQL = """
    INSERT INTO items(graph_id,parent_id,name,is_folder,remote_file_size,etag,ctag,created,modified,deleted,deleted_at,rank,plaintext_size,seen_gen)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(graph_id) DO UPDATE SET
        -- A trashed row (`is_trashed`, i.e. deleted=1 AND deleted_at NOT NULL) freezes its
        -- display identity and facets: a post-trash /children reconciliation or delta echo
        -- carrying the recycle-bin's stripped name (e.g. losing the `.bc` extension) or
        -- stripped facets (size absent → 0, no created/modified dates) must not overwrite
        -- the authoritative values captured at trash time — otherwise the trashed item
        -- flips to a placeholder name / size 0 / 1970 date. For live rows, keep the
        -- placeholder guard (never clobber a real name with the graph id). `is_trashed` is
        -- the generated column referencing this row's pre-update state.
        parent_id=CASE WHEN is_trashed THEN parent_id ELSE excluded.parent_id END,
        name=CASE WHEN is_trashed THEN name
                  WHEN excluded.name = excluded.graph_id THEN name
                  ELSE excluded.name END,
        is_folder=excluded.is_folder,
        remote_file_size=CASE WHEN is_trashed THEN remote_file_size
                              ELSE excluded.remote_file_size END,
        etag=excluded.etag, ctag=excluded.ctag,
        -- The delta/children upsert path never carries plaintext knowledge (it only sees the
        -- backend size), so it must PRESERVE a previously-resolved value rather than null it
        -- out on every sync. The exception is a content change, detected on EITHER signal:
        --   * a new cTag — Graph's content-change token; and
        --   * a changed remote_file_size — a different ciphertext length is a content change
        --     by itself, and catches the case where the cTag is absent/unchanged but the bytes
        --     are not (e.g. a provider that omits cTag, or a same-token re-write).
        -- After such a change the stored plaintext length describes bytes that no longer
        -- exist, and a confidently-wrong size is worse than the estimate — so drop it and let
        -- the next fetch re-resolve from the new header.
        --
        -- On a content change the incoming value still wins when the caller HAS resolved one
        -- (a download that learned the size from the new BC01 header upserts it alongside the
        -- new cTag/size); only a knowledge-free upsert falls through to NULL.
        plaintext_size=CASE WHEN ctag IS NOT excluded.ctag
                              OR remote_file_size IS NOT excluded.remote_file_size
                            THEN excluded.plaintext_size
                            ELSE COALESCE(excluded.plaintext_size, plaintext_size) END,
        created=CASE WHEN is_trashed THEN created ELSE excluded.created END,
        modified=CASE WHEN is_trashed THEN modified ELSE excluded.modified END,
        deleted=MAX(deleted, excluded.deleted),
        deleted_at=CASE WHEN deleted=1 THEN deleted_at ELSE excluded.deleted_at END,
        rank=excluded.rank,
        -- ?15: the crawl generation for a crawl write; NULL for other writers, which keep the
        -- row's existing stamp (`excluded.seen_gen` is the insert-only value).
        seen_gen=COALESCE(?15, seen_gen);
    """

    /// Bind a ``CachedItem`` (+ rank) onto the `upsertSQL` statement. Caller resets/clears.
    ///
    /// - Parameters:
    ///   - generation: Crawl generation stamped on insert and update; `nil` keeps an existing
    ///     row's `seen_gen`.
    ///   - insertGeneration: `seen_gen` for a fresh insert (0 when `nil`).
    private func bindUpsert(_ stmt: OpaquePointer?, _ item: CachedItem, rank: Int64,
                            generation: Int64?, insertGeneration: Int64?) {
        bindText(stmt, 1, item.graphID)
        bindTextOptional(stmt, 2, item.parentGraphID)
        bindText(stmt, 3, item.name)
        sqlite3_bind_int(stmt, 4, item.isFolder ? 1 : 0)
        sqlite3_bind_int64(stmt, 5, item.remoteFileSize)
        bindTextOptional(stmt, 6, item.eTag)
        bindTextOptional(stmt, 7, item.cTag)
        bindDateOptional(stmt, 8, item.createdDate)
        bindDateOptional(stmt, 9, item.modifiedDate)
        sqlite3_bind_int(stmt, 10, item.deleted ? 1 : 0)
        bindDateOptional(stmt, 11, item.deletedAt)
        sqlite3_bind_int64(stmt, 12, rank)
        // Bound explicitly so `excluded.plaintext_size` in the conflict clause carries the
        // caller's knowledge. Leaving it unbound made `excluded.plaintext_size` always NULL,
        // which turned the COALESCE preserve-branch into a no-op source and made the
        // cTag-change branch the only writer — silently discarding a resolved size.
        if let plaintextSize = item.plaintextSize {
            sqlite3_bind_int64(stmt, 13, plaintextSize)
        } else {
            sqlite3_bind_null(stmt, 13)
        }
        sqlite3_bind_int64(stmt, 14, insertGeneration ?? 0)
        if let generation {
            sqlite3_bind_int64(stmt, 15, generation)
        } else {
            sqlite3_bind_null(stmt, 15)
        }
    }

    /// Persist the local-only metadata (Finder `tagData` + extended attributes, which
    /// include the heart / pinned / isShared marks) for an item and bump its `rank`, so the
    /// rank-derived domain version advances and the working-set feed
    /// (``itemsChanged(sinceRank:)``) delivers the change to the system.
    ///
    /// `metadata` is the complete post-change blob; an empty blob stores `NULL` (none).
    /// Written independently of the delta upsert path so a re-crawl never clobbers it.
    /// Returns the new rank.
    @discardableResult
    func setLocalMetadata(graphID: String, _ metadata: LocalMetadata) throws -> Int64 {
        try queue.sync {
            let rank = try allocateRankUnsynced()
            let stmt = try prepare("UPDATE items SET local_meta = ?, rank = ? WHERE graph_id = ?;")
            defer { sqlite3_finalize(stmt) }
            if metadata.isEmpty {
                sqlite3_bind_null(stmt, 1)
            } else {
                let data = try JSONEncoder().encode(metadata)
                _ = data.withUnsafeBytes { sqlite3_bind_blob(stmt, 1, $0.baseAddress, Int32(data.count), Self.SQLITE_TRANSIENT) }
            }
            sqlite3_bind_int64(stmt, 2, rank)
            bindText(stmt, 3, graphID)
            try stepDone(stmt)
            return rank
        }
    }

    /// Record an item's exact plaintext length, learned from its BC01 header during a download.
    ///
    /// - Important: `size` MUST be exact — ``BC01CryptoCommon/exactPlaintextSize(header:remoteSize:)``
    ///   for a `.bc` item, or the remote size for a plain one. It MUST NOT be the display
    ///   estimate from `BoxcryptorMetadataTranslator.displaySize(forBackendSize:name:)`
    ///   (ciphertext − 4096), which ignores PKCS7 padding and assumes a single-block header.
    ///   What is stored here is treated as authoritative and outranks that estimate on every
    ///   subsequent read, so a persisted approximation is worse than none at all.
    ///
    /// Bumps `rank` on a real change so the rank-derived domain version advances and the
    /// working-set feed (``itemsChanged(sinceRank:)``) carries the corrected size to the system.
    /// This is the delivery channel for a size learned during a PARTIAL fetch: the completion
    /// item of `fetchPartialContents` is a version token the system does not read metadata from,
    /// so enumeration is the only way `documentSize` can be updated for an item that was never
    /// fully materialised.
    ///
    /// No-ops when the stored value already matches, so a steady-state re-fetch neither bumps the
    /// rank nor provokes a signal.
    ///
    /// - Returns: `true` when the stored value changed (the caller should signal the working set).
    @discardableResult
    func setPlaintextSize(_ size: Int64, graphID: String) throws -> Bool {
        try queue.sync {
            let existing = try prepare("SELECT plaintext_size FROM items WHERE graph_id = ?;")
            var unchanged = false
            bindText(existing, 1, graphID)
            if sqlite3_step(existing) == SQLITE_ROW {
                unchanged = sqlite3_column_type(existing, 0) != SQLITE_NULL
                    && sqlite3_column_int64(existing, 0) == size
            }
            sqlite3_finalize(existing)
            guard !unchanged else { return false }

            let rank = try allocateRankUnsynced()
            let stmt = try prepare("UPDATE items SET plaintext_size = ?, rank = ? WHERE graph_id = ?;")
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, size)
            sqlite3_bind_int64(stmt, 2, rank)
            bindText(stmt, 3, graphID)
            try stepDone(stmt)
            return sqlite3_changes(db) > 0
        }
    }

    /// Whether this folder is Boxcryptor-encrypted, evidenced by a `FolderKey.bch` sidecar
    /// seen among its children.
    ///
    /// Recorded in `meta` rather than as an `items` column: the fact is discovered from a
    /// *child* row, so it cannot be written by the parent's own upsert, and only encrypted
    /// folders carry a key at all — a sparse set that a keyed row models better than a
    /// column on every folder.
    func isFolderEncrypted(_ parentID: String) -> Bool {
        ((try? getMeta(Self.folderEncryptedKey(parentID))) ?? nil) != nil
    }

    /// Record that a `FolderKey.bch` was seen among this folder's children.
    ///
    /// - Note: Monotonic — there is deliberately no clear path. A folder that held a folder
    ///   key holds encrypted content; a delta that later deletes the key does not decrypt
    ///   what is already there. A full re-crawl (`410 Gone`, Rebuild Index) keeps the mark;
    ///   only ``empty()`` / ``destroy(domainID:)`` discard it.
    func markFolderEncrypted(_ parentID: String) {
        try? setMeta(Self.folderEncryptedKey(parentID), ISO8601DateFormatter().string(from: Date()))
    }

    private static func folderEncryptedKey(_ parentID: String) -> String { "bcfolder:\(parentID)" }

    /// Set or clear the `contentError` flag on a cached item's local metadata, leaving all
    /// other local-only fields (xattrs, tagData) intact. Bumps rank so enumerateChanges
    /// delivers the updated decoration to the system.
    @discardableResult
    func setContentError(_ value: Bool?, graphID: String) throws -> Int64 {
        try queue.sync {
            var local = (try? itemLocalMetadataUnsynced(graphID: graphID)) ?? .empty
            local.contentError = value
            let rank = try allocateRankUnsynced()
            let stmt = try prepare("UPDATE items SET local_meta = ?, rank = ? WHERE graph_id = ?;")
            defer { sqlite3_finalize(stmt) }
            if local.isEmpty {
                sqlite3_bind_null(stmt, 1)
            } else {
                let data = try JSONEncoder().encode(local)
                _ = data.withUnsafeBytes { sqlite3_bind_blob(stmt, 1, $0.baseAddress, Int32(data.count), Self.SQLITE_TRANSIENT) }
            }
            sqlite3_bind_int64(stmt, 2, rank)
            bindText(stmt, 3, graphID)
            try stepDone(stmt)
            return rank
        }
    }

    /// Mark an item deleted (tombstone) with a fresh rank.
    func markDeleted(graphID: String) throws {
        try queue.sync {
            let rank = try allocateRankUnsynced()
            let stmt = try prepare("UPDATE items SET deleted = 1, deleted_at = NULL, rank = ? WHERE graph_id = ?;")
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, rank)
            bindText(stmt, 2, graphID)
            try stepDone(stmt)
        }
    }

    /// Tombstone an item as trashed (moved to recycle bin). Preserves metadata and `parent_id`
    /// (restore target) for trash enumeration. Items with `deleted_at` appear in trash;
    /// items tombstoned via `markDeleted` (no `deleted_at`) are permanently gone.
    ///
    /// `name`/`parentGraphID` refresh the row's display name and restore target when the caller
    /// has authoritative values (e.g. a `getJSON` fetch during move-to-trash). Passing them
    /// prevents the trashed row from surfacing a stale or placeholder (graph-id) name after
    /// re-enumeration; both default to `nil` (preserve existing values) for delta-driven callers.
    /// - Parameter outOfBand: when `true`, this trashing originated from the encrypt/decrypt
    ///   bulk action's Graph DELETE (not a framework move-to-trash), so the framework has no
    ///   recorded original parent and will not show native "Put Back". The flag is persisted in
    ///   `local_meta` (`restorableOutOfBand`) and surfaced in `entry(from:)` userInfo to gate the
    ///   custom Restore action. Framework-initiated trashing passes `false` — no custom action,
    ///   so there is never a duplicate "Put Back".
    func markTrashed(graphID: String, deletedAt: Date, name: String? = nil,
                     parentGraphID: String? = nil, outOfBand: Bool = false) throws {
        try queue.sync {
            let rank = try allocateRankUnsynced()
            var local = (try? itemLocalMetadataUnsynced(graphID: graphID)) ?? .empty
            local.restorableOutOfBand = outOfBand ? true : nil
            let stmt = try prepare("""
                UPDATE items SET deleted = 1, deleted_at = ?, rank = ?,
                    name = COALESCE(?, name), parent_id = COALESCE(?, parent_id),
                    local_meta = ?
                WHERE graph_id = ?;
                """)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_double(stmt, 1, deletedAt.timeIntervalSince1970)
            sqlite3_bind_int64(stmt, 2, rank)
            bindTextOptional(stmt, 3, name)
            bindTextOptional(stmt, 4, parentGraphID)
            if local.isEmpty {
                sqlite3_bind_null(stmt, 5)
            } else {
                let data = try JSONEncoder().encode(local)
                _ = data.withUnsafeBytes { sqlite3_bind_blob(stmt, 5, $0.baseAddress, Int32(data.count), Self.SQLITE_TRANSIENT) }
            }
            bindText(stmt, 6, graphID)
            try stepDone(stmt)
        }
        // [trash] Confirm the tombstoned row's stored identity. `name`/`parentGraphID`
        // are nil when the caller (delta echo) has no fresh metadata — COALESCE then keeps the prior values
        if let stored = try? itemIncludingDeleted(graphID: graphID) {
            Self.log.infoPublic("🗑️ [trash] markTrashed graph_id=\(graphID) → stored name=\(stored.name) parent_id=\(stored.parentGraphID ?? "<nil>") (passed name=\(name ?? "<nil>") parent=\(parentGraphID ?? "<nil>"))")
        }
    }

    /// Restore a tombstoned row to live state (`deleted=0, deleted_at=NULL`). Used after a
    /// successful Graph `/restore` so the item reappears in its original parent. The upsert
    /// path cannot clear tombstones (it uses `MAX(deleted,…)` to prevent delta races from
    /// resurrecting deleted items), so this explicit mutation is the only restore path.
    func resurrectItem(graphID: String, parentGraphID: String?, name: String) throws {
        try queue.sync {
            let rank = try allocateRankUnsynced()
            let stmt = try prepare("""
                UPDATE items SET deleted = 0, deleted_at = NULL, rank = ?,
                    parent_id = COALESCE(?, parent_id), name = ?
                WHERE graph_id = ?;
                """)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, rank)
            bindTextOptional(stmt, 2, parentGraphID)
            bindText(stmt, 3, name)
            bindText(stmt, 4, graphID)
            try stepDone(stmt)
        }
    }

    /// Transition a trashed item to a permanent-deletion tombstone (`deleted=1, deleted_at=NULL`).
    /// The row stays in the table so `itemsChanged` can emit a `deletedEntries` signal to the
    /// framework before the row is vacuumed. Hard-deleting the row would lose the deletion event.
    func purgeItem(graphID: String) throws {
        try queue.sync {
            let rank = try allocateRankUnsynced()
            let stmt = try prepare("UPDATE items SET deleted = 1, deleted_at = NULL, rank = ? WHERE graph_id = ?;")
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, rank)
            bindText(stmt, 2, graphID)
            try stepDone(stmt)
        }
    }

    /// All trashed items (`is_trashed`) ordered by `deleted_at DESC`.
    func trashedItems() throws -> [CachedItem] {
        try queue.sync {
            let stmt = try prepare("""
                SELECT \(Self.itemColumns) FROM items
                WHERE is_trashed
                ORDER BY deleted_at DESC;
                """)
            defer { sqlite3_finalize(stmt) }
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// One page of trashed items, in `graph_id` order, strictly after `afterGraphID`
    /// (`nil` = first page). Keyset-paged so a restore or purge during the walk cannot shift
    /// an unchanged row out of the listing. Display order is the system's concern, not ours.
    func trashedItemsPage(after afterGraphID: String?, limit: Int64) throws -> [CachedItem] {
        try queue.sync {
            let stmt = try prepare("""
                SELECT \(Self.itemColumns) FROM items
                WHERE is_trashed AND (?1 IS NULL OR graph_id > ?1)
                ORDER BY graph_id LIMIT ?2;
                """)
            defer { sqlite3_finalize(stmt) }
            bindTextOptional(stmt, 1, afterGraphID)
            sqlite3_bind_int64(stmt, 2, limit)
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// The subset of `graphIDs` that currently exist as **tombstoned** rows.
    ///
    /// The batched form of probing ``itemIncludingDeleted(graphID:)`` per row. A cold
    /// `/children` seed of a large folder asked that question once per child, and each call
    /// paid its own `queue.sync` hop plus a `prepare`/`finalize` of a fresh statement — 1500
    /// children meant 1500 serialised round-trips before the batched upsert could even start,
    /// which dominated first-open latency for the folder. One `IN (...)` query over the
    /// `graph_id` primary key answers the same question in a single acquisition.
    ///
    /// Tombstones are rare, so the result is normally empty and the caller's resurrect loop
    /// does no work at all.
    ///
    /// - Parameter graphIDs: candidate ids; order is irrelevant and duplicates are harmless.
    /// - Returns: the ids among them whose row is tombstoned (`deleted = 1`).
    func tombstonedIDs(among graphIDs: [String]) throws -> Set<String> {
        guard !graphIDs.isEmpty else { return [] }
        return try queue.sync {
            var out = Set<String>()
            // Chunked to stay clear of SQLITE_MAX_VARIABLE_NUMBER (999 by default on the
            // system SQLite); a folder page can carry more ids than that.
            for chunk in stride(from: 0, to: graphIDs.count, by: 900).map({
                Array(graphIDs[$0..<min($0 + 900, graphIDs.count)])
            }) {
                let placeholders = Array(repeating: "?", count: chunk.count).joined(separator: ",")
                let stmt = try prepare("""
                    SELECT graph_id FROM items
                    WHERE graph_id IN (\(placeholders)) AND deleted = 1;
                    """)
                defer { sqlite3_finalize(stmt) }
                for (offset, id) in chunk.enumerated() { bindText(stmt, Int32(offset + 1), id) }
                while sqlite3_step(stmt) == SQLITE_ROW {
                    if let cText = sqlite3_column_text(stmt, 0) {
                        out.insert(String(cString: cText))
                    }
                }
            }
            return out
        }
    }

    /// Fetch one item by Graph id, including tombstoned rows. Used to distinguish a
    /// trashed item (`deleted=1`) from a live one when dispatching `deleteItem`.
    func itemIncludingDeleted(graphID: String) throws -> CachedItem? {
        try queue.sync {
            let stmt = try prepare("SELECT \(Self.itemColumns) FROM items WHERE graph_id = ?;")
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, graphID)
            return sqlite3_step(stmt) == SQLITE_ROW ? readItem(stmt) : nil
        }
    }

    /// Fetch one item by Graph id.
    func item(graphID: String) throws -> CachedItem? {
        try queue.sync {
            let stmt = try prepare("SELECT \(Self.itemColumns) FROM items WHERE graph_id = ? AND deleted = 0;")
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, graphID)
            return sqlite3_step(stmt) == SQLITE_ROW ? readItem(stmt) : nil
        }
    }

    /// Count of live (non-tombstoned) rows currently indexed for this domain.
    ///
    /// Grows as the delta sync indexes the remote. Excludes trashed/purged rows
    /// (`deleted = 0` — see ``LifecycleState`` / the `is_trashed` generated column,
    /// `[[tombstone-tristate-lifecycle]]`). Cheap: a single `COUNT(*)`. Surfaced to the
    /// app via the progress relay.
    func indexedCount() throws -> Int {
        try queue.sync {
            let stmt = try prepare("SELECT COUNT(*) FROM items WHERE deleted = 0;")
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
            return Int(sqlite3_column_int64(stmt, 0))
        }
    }

    /// Children of a folder (non-deleted).
    func children(ofParentGraphID parentID: String) throws -> [CachedItem] {
        try queue.sync {
            let stmt = try prepare("SELECT \(Self.itemColumns) FROM items WHERE parent_id = ? AND deleted = 0 ORDER BY name;")
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, parentID)
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// A single page of a folder's direct children (non-deleted), in `graph_id` order,
    /// strictly after `afterGraphID` (`nil` = first page).
    ///
    /// Keyset-paged on the immutable primary key: a row inserted, tombstoned or renamed
    /// during the walk never shifts an unchanged row out of the listing, and each page is an
    /// index range scan rather than a sort-and-skip over the whole folder.
    func childrenPage(ofParentGraphID parentID: String, after afterGraphID: String?,
                      limit: Int64) throws -> [CachedItem] {
        try queue.sync {
            let stmt = try prepare("""
                SELECT \(Self.itemColumns) FROM items
                WHERE parent_id = ?1 AND deleted = 0 AND (?2 IS NULL OR graph_id > ?2)
                ORDER BY graph_id LIMIT ?3;
                """)
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, parentID)
            bindTextOptional(stmt, 2, afterGraphID)
            sqlite3_bind_int64(stmt, 3, limit)
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// A single page of every live row except `rootID`, in `graph_id` order, strictly after
    /// `afterGraphID` (`nil` = first page).
    ///
    /// The cache is scoped to the serving root, so every live row other than the root itself
    /// is a descendant: this is the recursive walk from the root without the CTE. It also
    /// includes rows whose parent has not been cached yet, which a parent-linked walk would
    /// miss until something bumped the child's rank.
    func liveItemsPage(excludingGraphID rootID: String, after afterGraphID: String?,
                       limit: Int64) throws -> [CachedItem] {
        try queue.sync {
            let stmt = try prepare("""
                SELECT \(Self.itemColumns) FROM items
                WHERE deleted = 0 AND graph_id <> ?1 AND (?2 IS NULL OR graph_id > ?2)
                ORDER BY graph_id LIMIT ?3;
                """)
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, rootID)
            bindTextOptional(stmt, 2, afterGraphID)
            sqlite3_bind_int64(stmt, 3, limit)
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// A single page of the full (recursive) subtree rooted at `rootID` (non-deleted), in
    /// `graph_id` order, strictly after `afterGraphID` (`nil` = first page).
    ///
    /// Walks descendants via a recursive CTE seeded from the direct children of `rootID`.
    /// For the serving root use ``liveItemsPage(excludingGraphID:after:limit:)``, which needs
    /// no CTE; this form is for subtrees below it.
    func descendants(ofRootGraphID rootID: String, after afterGraphID: String?,
                     limit: Int64) throws -> [CachedItem] {
        try queue.sync {
            let stmt = try prepare("""
                WITH RECURSIVE subtree(graph_id) AS (
                    SELECT graph_id FROM items WHERE parent_id = ?1 AND deleted = 0
                    UNION ALL
                    SELECT i.graph_id FROM items i JOIN subtree s ON i.parent_id = s.graph_id
                    WHERE i.deleted = 0
                )
                SELECT \(Self.itemColumns) FROM items
                WHERE graph_id IN (SELECT graph_id FROM subtree) AND (?2 IS NULL OR graph_id > ?2)
                ORDER BY graph_id LIMIT ?3;
                """)
            defer { sqlite3_finalize(stmt) }
            bindText(stmt, 1, rootID)
            bindTextOptional(stmt, 2, afterGraphID)
            sqlite3_bind_int64(stmt, 3, limit)
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// Items changed since `rank` (for change enumeration), in rank order.
    /// Rows changed strictly after `rank`, ordered by ascending rank.
    ///
    /// `limit` caps the page so `listChanges` can drive the File Provider change
    /// observer one bounded page at a time: the framework sums every `didUpdate`
    /// item between two `finishEnumeratingChanges` calls into a single page and
    /// aborts the whole enumeration past 20000 (`__FILEPROVIDER_OBSERVER_TOO_MANY_ITEMS__`).
    /// Because rows are ordered by rank, the last row's rank is a resumable anchor.
    /// Pass `nil` for no limit.
    func itemsChanged(sinceRank rank: Int64, limit: Int? = nil) throws -> [CachedItem] {
        try queue.sync {
            let sql = "SELECT \(Self.itemColumns) FROM items WHERE rank > ? ORDER BY rank ASC"
                + (limit != nil ? " LIMIT ?;" : ";")
            let stmt = try prepare(sql)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, rank)
            if let limit { sqlite3_bind_int(stmt, 2, Int32(limit)) }
            var out: [CachedItem] = []
            while sqlite3_step(stmt) == SQLITE_ROW { out.append(readItem(stmt)) }
            return out
        }
    }

    /// The current rank high-water mark.
    func currentRank() -> Int64 {
        (try? getMeta("rank_hwm")).flatMap { $0 }.flatMap(Int64.init) ?? 0
    }

    // MARK: - Row mapping

    private static let itemColumns = "graph_id,parent_id,name,is_folder,remote_file_size,etag,ctag,created,modified,deleted,deleted_at,rank,local_meta,plaintext_size"

    private func readItem(_ stmt: OpaquePointer?) -> CachedItem {
        CachedItem(
            graphID: column(stmt, 0) ?? "",
            parentGraphID: column(stmt, 1),
            name: column(stmt, 2) ?? "",
            isFolder: sqlite3_column_int(stmt, 3) != 0,
            remoteFileSize: sqlite3_column_int64(stmt, 4),
            eTag: column(stmt, 5),
            cTag: column(stmt, 6),
            createdDate: date(stmt, 7),
            modifiedDate: date(stmt, 8),
            deleted: sqlite3_column_int(stmt, 9) != 0,
            deletedAt: date(stmt, 10),
            rank: sqlite3_column_int64(stmt, 11),
            localMetadata: Self.decodeLocalMetadata(blob(stmt, 12)),
            plaintextSize: sqlite3_column_type(stmt, 13) == SQLITE_NULL
                ? nil : sqlite3_column_int64(stmt, 13)
        )
    }

    /// Decode the `local_meta` BLOB column (JSON ``LocalMetadata``). A missing/invalid blob
    /// (rows from before schema 2, or never marked/tagged) decodes to empty.
    private static func decodeLocalMetadata(_ data: Data?) -> LocalMetadata {
        guard let data, !data.isEmpty,
              let decoded = try? JSONDecoder().decode(LocalMetadata.self, from: data) else { return .empty }
        return decoded
    }

    // MARK: - SQLite helpers

    private static let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private func exec(_ sql: String) throws {
        try queue.sync { try execUnsynced(sql) }
    }

    /// `sqlite3_exec` without acquiring `queue`; caller must already hold it.
    private func execUnsynced(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let message = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            throw MetadataCacheError.step(message)
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw MetadataCacheError.prepare(String(cString: sqlite3_errmsg(db)))
        }
        return stmt
    }

    private func stepDone(_ stmt: OpaquePointer?) throws {
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw MetadataCacheError.step(String(cString: sqlite3_errmsg(db)))
        }
    }

    private func bindText(_ stmt: OpaquePointer?, _ idx: Int32, _ value: String) {
        sqlite3_bind_text(stmt, idx, value, -1, Self.SQLITE_TRANSIENT)
    }
    private func bindTextOptional(_ stmt: OpaquePointer?, _ idx: Int32, _ value: String?) {
        if let value { bindText(stmt, idx, value) } else { sqlite3_bind_null(stmt, idx) }
    }
    private func bindDateOptional(_ stmt: OpaquePointer?, _ idx: Int32, _ date: Date?) {
        if let date { sqlite3_bind_double(stmt, idx, date.timeIntervalSince1970) } else { sqlite3_bind_null(stmt, idx) }
    }
    private func column(_ stmt: OpaquePointer?, _ idx: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, idx) else { return nil }
        return String(cString: c)
    }
    private func date(_ stmt: OpaquePointer?, _ idx: Int32) -> Date? {
        guard sqlite3_column_type(stmt, idx) != SQLITE_NULL else { return nil }
        return Date(timeIntervalSince1970: sqlite3_column_double(stmt, idx))
    }
    private func blob(_ stmt: OpaquePointer?, _ idx: Int32) -> Data? {
        guard sqlite3_column_type(stmt, idx) != SQLITE_NULL,
              let bytes = sqlite3_column_blob(stmt, idx) else { return nil }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(stmt, idx)))
    }

    /// Fetch one item (including tombstoned) by Graph id; caller must hold `queue`.
    private func itemRowUnsynced(graphID: String) throws -> CachedItem? {
        let stmt = try prepare("SELECT \(Self.itemColumns) FROM items WHERE graph_id = ?;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, graphID)
        return sqlite3_step(stmt) == SQLITE_ROW ? readItem(stmt) : nil
    }

    private func itemLocalMetadataUnsynced(graphID: String) throws -> LocalMetadata? {
        let stmt = try prepare("SELECT local_meta FROM items WHERE graph_id = ?;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, graphID)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return Self.decodeLocalMetadata(blob(stmt, 0))
    }

    // Unsynced variants for use inside an existing queue.sync block.
    private func getMetaUnsynced(_ key: String) throws -> String? {
        let stmt = try prepare("SELECT value FROM meta WHERE key = ?;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        return sqlite3_step(stmt) == SQLITE_ROW ? column(stmt, 0) : nil
    }
    private func deleteMetaUnsynced(_ key: String) throws {
        let stmt = try prepare("DELETE FROM meta WHERE key = ?;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        try stepDone(stmt)
    }
    private func pendingCrawlGenerationUnsynced() throws -> Int64? {
        try getMetaUnsynced(Self.pendingCrawlGenerationKey).flatMap(Int64.init)
    }
    private func setMetaUnsynced(_ key: String, _ value: String) throws {
        let stmt = try prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        bindText(stmt, 2, value)
        try stepDone(stmt)
    }
}
