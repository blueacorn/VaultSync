/// Persistent, per-domain cache of parsed BC01 file headers.
///
/// A ranged BC01 fetch cannot begin until the header is parsed: block IVs derive from
/// `baseIV` + `fileKey`, and span geometry from `blockSize` / `headerEnd` / `cipherPadding`.
/// For a file at or above the parallel-download threshold that costs a **separate** ranged GET,
/// serialised before any lane opens — and against Graph, a 302 to a CDN URL makes that two round
/// trips (~150–300 ms). Persisting the parsed header removes it.
///
/// The store is a single layer with no memory tier in front: one warm hit is a bound cached
/// statement plus an AES-GCM open of ~48 bytes (~15–35 µs) against a ~200 ms probe, and a header
/// is resolved once per fetch, so there is no repeated read for a memory tier to absorb.
///
/// Modelled structurally on ``MetadataCache`` — `final class`, a serial `DispatchQueue`, the
/// system `SQLite3` C library, one database file per domain in the App Group container, and the
/// same `open` / `createSchema` / `rebuildSchema` / `empty` / `destroy` lifecycle — but in its
/// own directory (`BC01HeaderCache/`) so its different lifetime, eviction policy and sensitivity
/// stay separate, `destroy` can remove the whole tree per domain, and the two stores' WAL
/// sidecars never contend on one write lock.
///
/// ### Key material
///
/// `baseIV` and `fileKey` are sealed under a per-domain `fileKeysKEK`, itself stored wrapped
/// under the vault KEK that already gates the session RSA key — so possession of the unlocked
/// vault yields nothing the RSA key did not already yield. Geometry stays plaintext (it is
/// derivable from the remote size anyway). Rows are AAD-bound to `itemID ‖ contentRevision`, so
/// a row cannot be transplanted onto another file or survive a re-upload.
///
/// ### Lock discipline
///
/// Locking is driven from the app; this cache lives in `Provider.appex`, which observes lock
/// only by reading the keychain slot the app evicts. The resolved KEK is therefore memoised for
/// a **bounded** window (``SharedConfig/headerCacheKeyResidencySeconds``) and then re-resolved —
/// never held indefinitely. A locked vault is a **cache miss, never an error**.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common
import CryptoKit
import SQLite3
import os.log

/// A cached BC01 header row, as stored.
///
/// `sealedSecrets` is the AES-GCM box over `baseIV ‖ fileKey`; the geometry columns are
/// plaintext. Surfaced for tests and diagnostics — the download path uses ``BC01Header`` values
/// returned by ``BC01HeaderCache/header(itemID:contentRevision:)``.
struct CachedHeader: Equatable {
    /// The backend's stable item identifier; the table's primary key.
    var itemID: String
    /// The content revision (cTag) the row describes. A column, never part of the key.
    var contentRevision: String
    /// Offset of the first ciphertext body byte.
    var headerEnd: Int64
    /// Plaintext span each independently-IV'd block covers.
    var blockSize: Int64
    /// PKCS7 padding bytes carried by the final AES unit.
    var cipherPadding: Int64
    /// AES-GCM(`fileKeysKEK`, `baseIV ‖ fileKey`, aad: `itemID ‖ contentRevision`).
    var sealedSecrets: Data
    /// When the row was written — the sole input to eviction (there is no `last_used_at`).
    var createdAt: Date
}

/// Errors raised by the BC01 header cache. A *miss* is never an error; these signal a store that
/// could not be opened or written.
enum BC01HeaderCacheError: Error {
    case open(String)
    case prepare(String)
    case step(String)
    case containerUnavailable
}

final class BC01HeaderCache {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "bc01-header-cache")
    private static let appGroupID = AppIdentifiers.appGroupID
    /// Bump to drop and recreate the table. The store is purely derived — a rebuild costs
    /// re-probes, nothing else.
    private static let schemaVersion = 1
    /// Directory under the App Group container. Deliberately not `OneDriveCache/`.
    private static let directoryName = "BC01HeaderCache"
    /// Sweep at most this often, tracked in `meta`.
    private static let sweepIntervalSeconds: TimeInterval = 24 * 60 * 60
    /// Stores between sweep attempts, in addition to the once-per-open attempt.
    private static let sweepEveryNStores = 128
    private static let lastSweepKey = "last_sweep_at"

    private let domainID: String
    private let keyProvider: () throws -> SymmetricKey
    private let now: () -> Date
    private let maxAgeSeconds: TimeInterval
    private let maxRows: Int
    private let keyResidencySeconds: TimeInterval

    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "bc01-header-cache")

    /// The resolved `fileKeysKEK`, held only until `expires`.
    ///
    /// The unwrapped keychain slot **is** the lock signal, so re-reading it on expiry is what
    /// makes vault lock take effect in this process. Never hold the key indefinitely.
    private var memo: (key: SymmetricKey, expires: Date)?
    /// Stores since the last sweep attempt.
    private var storesSinceSweep = 0

    /// Open (creating if needed) the per-domain header store.
    ///
    /// - Parameters:
    ///   - domainID: The domain whose store this is; names the database file and scopes the KEK.
    ///   - keyProvider: Resolves the domain's `fileKeysKEK`. Throws
    ///     ``VaultKeyStoreError/locked`` when the Provider-readable slot has been evicted.
    ///     Injected so tests need no keychain. Defaults to the App Group slot.
    ///   - now: Clock, injected for deterministic TTL and key-residency tests.
    ///   - maxAgeSeconds: Row TTL. Defaults to ``SharedConfig/headerCacheMaxAgeDays``.
    ///   - maxRows: Row cap. Defaults to ``SharedConfig/headerCacheMaxRows``.
    ///   - keyResidencySeconds: How long a resolved KEK may be memoised. `0` re-resolves per
    ///     call. Defaults to ``SharedConfig/headerCacheKeyResidencySeconds``.
    init(domainID: String,
         keyProvider: (() throws -> SymmetricKey)? = nil,
         now: @escaping () -> Date = Date.init,
         maxAgeSeconds: TimeInterval? = nil,
         maxRows: Int? = nil,
         keyResidencySeconds: TimeInterval? = nil) throws {
        self.domainID = domainID
        self.keyProvider = keyProvider ?? { try Self.loadFileKeysKEK(domainID: domainID) }
        self.now = now
        self.maxAgeSeconds = maxAgeSeconds
            ?? TimeInterval(UserDefaults.sharedContainerDefaults.headerCacheMaxAgeDays) * 86_400
        self.maxRows = maxRows ?? UserDefaults.sharedContainerDefaults.headerCacheMaxRows
        self.keyResidencySeconds = keyResidencySeconds
            ?? UserDefaults.sharedContainerDefaults.headerCacheKeyResidencySeconds
        try open()
        try? sweepIfDue()
    }

    deinit {
        finalizeCachedStatements()
        if let db { sqlite3_close(db) }
    }

    // MARK: - Cached statements

    // The entire hot path is one keyed SELECT, so `sqlite3_prepare_v2` would dominate the call.
    // These are prepared once at the end of `open()` and reused with reset/clear/bind; they are
    // finalized in `deinit` and — critically — before any `DROP TABLE`, since a cached statement
    // over a dropped table is invalid.
    private var selectStmt: OpaquePointer?
    private var upsertStmt: OpaquePointer?
    private var deleteStmt: OpaquePointer?
    private var sweepStmt: OpaquePointer?

    private func prepareCachedStatements() throws {
        selectStmt = try prepare("""
        SELECT content_revision, header_end, block_size, cipher_padding, sealed_secrets, created_at
        FROM bc01_header WHERE item_id = ?;
        """)
        upsertStmt = try prepare("""
        INSERT INTO bc01_header
            (item_id, content_revision, header_end, block_size, cipher_padding, sealed_secrets, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(item_id) DO UPDATE SET
            content_revision = excluded.content_revision,
            header_end       = excluded.header_end,
            block_size       = excluded.block_size,
            cipher_padding   = excluded.cipher_padding,
            sealed_secrets   = excluded.sealed_secrets,
            created_at       = excluded.created_at;
        """)
        deleteStmt = try prepare("DELETE FROM bc01_header WHERE item_id = ?;")
        sweepStmt = try prepare("DELETE FROM bc01_header WHERE created_at < ?;")
    }

    /// Finalize and clear every cached statement. Idempotent.
    private func finalizeCachedStatements() {
        for stmt in [selectStmt, upsertStmt, deleteStmt, sweepStmt] where stmt != nil {
            sqlite3_finalize(stmt)
        }
        selectStmt = nil; upsertStmt = nil; deleteStmt = nil; sweepStmt = nil
    }

    // MARK: - Key residency

    /// Resolve the `fileKeysKEK`, memoised for at most ``keyResidencySeconds``.
    ///
    /// - Returns: The domain's file-keys KEK.
    /// - Throws: Whatever `keyProvider` throws — ``VaultKeyStoreError/locked`` when the
    ///   vault is locked. Callers on the read path translate that to a miss.
    private func resolveKEK() throws -> SymmetricKey {
        if let memo, now() < memo.expires { return memo.key }

        // Drop the expired key BEFORE attempting the refresh. On the throwing path (vault
        // locked → slot evicted) there is no assignment, so leaving `memo` set would keep the
        // stale key resident for the life of the process — expiry alone never clears it, only a
        // SUCCESSFUL refresh overwrites it. That is precisely the residency bound this design
        // promises. Clearing the tuple releases its only strong reference to the `SymmetricKey`,
        // whose deinitialiser zeroes the backing buffer.
        memo = nil

        let key = try keyProvider()
        // A zero window means "re-read every call": don't retain it at all.
        if keyResidencySeconds > 0 {
            memo = (key, now().addingTimeInterval(keyResidencySeconds))
        }
        return key
    }

    /// End key residency immediately. Called wherever the cache's contents stop being valid, so
    /// a Lock-and-Remove cannot leave a key resident beside an emptied table.
    private func dropMemo() { memo = nil }

    /// Load the domain's `fileKeysKEK` from the Provider-readable App Group slot.
    ///
    /// An absent slot means the app has evicted it — the vault is locked.
    private static func loadFileKeysKEK(domainID: String) throws -> SymmetricKey {
        guard let raw = try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainID) else {
            throw VaultKeyStoreError.locked
        }
        return SymmetricKey(data: raw)
    }

    // MARK: - Read

    /// The cached header for `itemID` at `contentRevision`, or `nil` on **any** miss.
    ///
    /// A miss is an absent row, a stale revision (the row is dropped), a locked vault, or a
    /// failed unwrap. None of these is an error: the caller simply takes the probe path.
    ///
    /// Performs no write on a hit — there is no `last_used_at` to maintain, so the read path
    /// never dirties a page, appends to the WAL, or takes a write lock.
    ///
    /// - Parameters:
    ///   - itemID: The backend item identifier.
    ///   - contentRevision: The expected content revision (cTag).
    /// - Returns: The parsed header, or `nil` on a miss.
    func header(itemID: String, contentRevision: String) -> BC01Header? {
        do {
            guard let row = try queue.sync(execute: { try rowUnsynced(itemID: itemID) }) else {
                Self.log.debugPublic("⚠️ header cache MISS item=\(itemID) (absent)")
                return nil
            }
            // Cheap correctness gate before any crypto runs. The AAD below is the cryptographic
            // one; both are kept.
            guard row.contentRevision == contentRevision else {
                // Permanently unreachable — nothing queries an old cTag again.
                try? invalidate(itemID: itemID)
                Self.log.debugPublic("⚠️ header cache MISS item=\(itemID) (stale revision, row dropped)")
                return nil
            }
            let kek = try queue.sync(execute: { try resolveKEK() })
            let secrets = try VaultKeyStore.unwrap(row.sealedSecrets, with: kek,
                                                       authenticating: Self.aad(itemID: itemID,
                                                                                contentRevision: row.contentRevision))
            guard let header = Self.decodeSecrets(secrets, row: row) else {
                Self.log.errorPublic("❌ header cache row malformed item=\(itemID) — treating as miss")
                return nil
            }
            Self.log.debugPublic("✅ header cache HIT item=\(itemID) (skipping header GET)")
            return header
        } catch {
            // Locked vault, unwrap failure, or a store-level error — all are misses.
            Self.log.debugPublic("⚠️ header cache MISS item=\(itemID) (\(String(describing: error)))")
            return nil
        }
    }

    // MARK: - Write

    /// Persist `header` for `itemID` at `contentRevision`, replacing any existing row.
    ///
    /// One row per item: the upsert makes a content write **overwrite** the stale row rather
    /// than accumulate beside it, which a composite `(item_id, content_revision)` key would.
    ///
    /// - Parameters:
    ///   - header: The freshly parsed header.
    ///   - itemID: The backend item identifier.
    ///   - contentRevision: The revision the header describes.
    /// - Throws: ``BC01HeaderCacheError`` on a store failure, or the key provider's error when
    ///   the vault is locked. Callers on the download path log and swallow — a cache write must
    ///   never fail a download.
    func store(_ header: BC01Header, itemID: String, contentRevision: String) throws {
        let sealed = try queue.sync { () -> Data in
            let kek = try resolveKEK()
            return try VaultKeyStore.wrap(Self.encodeSecrets(header), with: kek,
                                              authenticating: Self.aad(itemID: itemID,
                                                                       contentRevision: contentRevision))
        }
        try queue.sync {
            let stmt = upsertStmt
            sqlite3_reset(stmt)
            sqlite3_clear_bindings(stmt)
            bindText(stmt, 1, itemID)
            bindText(stmt, 2, contentRevision)
            sqlite3_bind_int64(stmt, 3, Int64(header.headerEnd))
            sqlite3_bind_int64(stmt, 4, Int64(header.blockSize))
            sqlite3_bind_int64(stmt, 5, Int64(header.cipherPadding))
            bindBlob(stmt, 6, sealed)
            sqlite3_bind_int64(stmt, 7, Int64(now().timeIntervalSince1970))
            try stepDone(stmt)
            storesSinceSweep += 1
        }
        Self.log.debugPublic("🗂️ header cache STORE item=\(itemID) rev=\(contentRevision) headerEnd=\(header.headerEnd)")
        if storesSinceSweep >= Self.sweepEveryNStores { try? sweepIfDue() }
    }

    /// Drop the row for `itemID`. Removing an absent row is not an error.
    ///
    /// Required for **deletes**, where no subsequent ``store(_:itemID:contentRevision:)`` will
    /// ever arrive to overwrite the row. A content write needs no explicit call — the upsert
    /// replaces the row, and in the interim a stale row misses on the revision check.
    ///
    /// - Parameter itemID: The item whose cached header is no longer valid.
    func invalidate(itemID: String) throws {
        try queue.sync {
            sqlite3_reset(deleteStmt)
            sqlite3_clear_bindings(deleteStmt)
            bindText(deleteStmt, 1, itemID)
            try stepDone(deleteStmt)
        }
    }

    // MARK: - Eviction

    /// Apply both bounds: drop rows older than the TTL, then trim to the row cap.
    ///
    /// Age is measured from when the row was **written**. Recency buys nothing: a row describes
    /// one `(item_id, cTag)` pair whose validity does not decay with use, and a content write
    /// already replaces the row and its `created_at`. Maintaining a `last_used_at` would instead
    /// turn every cache *hit* into a write.
    ///
    /// Runs on domain start and after every N stores — **never** on the read path.
    func sweep() throws {
        try queue.sync {
            let cutoff = Int64(now().addingTimeInterval(-maxAgeSeconds).timeIntervalSince1970)
            sqlite3_reset(sweepStmt)
            sqlite3_clear_bindings(sweepStmt)
            sqlite3_bind_int64(sweepStmt, 1, cutoff)
            try stepDone(sweepStmt)

            // Row cap: keep the `maxRows` newest.
            let stmt = try prepare("""
            DELETE FROM bc01_header WHERE item_id IN (
                SELECT item_id FROM bc01_header ORDER BY created_at DESC LIMIT -1 OFFSET ?);
            """)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_int64(stmt, 1, Int64(maxRows))
            try stepDone(stmt)

            try setMetaUnsynced(Self.lastSweepKey, String(Int64(now().timeIntervalSince1970)))
            storesSinceSweep = 0
        }
    }

    /// Run ``sweep()`` only if the throttle interval has elapsed since the last one.
    private func sweepIfDue() throws {
        let last = (try? queue.sync { try getMetaUnsynced(Self.lastSweepKey) })
            .flatMap { $0 }.flatMap(Double.init) ?? 0
        guard now().timeIntervalSince1970 - last >= Self.sweepIntervalSeconds else {
            storesSinceSweep = 0
            return
        }
        try sweep()
    }

    // MARK: - Lifecycle

    /// Delete every cached row while keeping the database file, schema and any open handle
    /// valid — the safe counterpart to ``destroy(domainID:)``.
    ///
    /// Used by "Lock and Remove Vault", where the Provider may still hold this cache open.
    /// Correct on its own terms too: locking destroys the `fileKeysKEK`, so every retained row
    /// would be permanently unreadable ballast. Also drops the memoised KEK, so the action
    /// cannot leave a key resident beside an emptied table.
    func empty() throws {
        try queue.sync {
            dropMemo()
            try execUnsynced("DELETE FROM bc01_header;")
            try execUnsynced("DELETE FROM meta;")
            try setMetaUnsynced("schema_version", String(Self.schemaVersion))
            // Return the freed pages. Must not run inside an explicit transaction; none is open.
            try execUnsynced("VACUUM;")
        }
        Self.log.infoPublic("🧹 emptied BC01 header cache domain=\(domainID)")
    }

    /// Remove the on-disk store (database plus the `-wal`/`-shm` sidecars) for `domainID`.
    ///
    /// Idempotent: missing files are ignored. The caller must ensure no live cache for the
    /// domain remains open, otherwise the WAL sidecars may be recreated on the next write.
    ///
    /// - Parameter domainID: The domain whose store is being removed.
    static func destroy(domainID: String) throws {
        let dbURL = try databaseURL(domainID: domainID, createDirectory: false)
        let fm = FileManager.default
        let base = dbURL.deletingLastPathComponent()
        let name = dbURL.lastPathComponent
        for url in [dbURL,
                    base.appendingPathComponent(name + "-wal"),
                    base.appendingPathComponent(name + "-shm")] {
            if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
        }
    }

    /// The backing SQLite file URL for `domainID` in the App Group container.
    ///
    /// - Parameters:
    ///   - domainID: The domain the store belongs to.
    ///   - createDirectory: When `true`, ensures `BC01HeaderCache/` exists (required before
    ///     opening). ``destroy(domainID:)`` passes `false` — a missing directory means nothing
    ///     to delete.
    /// - Returns: The database file URL.
    static func databaseURL(domainID: String, createDirectory: Bool) throws -> URL {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            Self.log.error("❌ App Group container '\(appGroupID, privacy: .public)' unavailable for domain=\(domainID, privacy: .public) — header cache cannot be opened")
            throw BC01HeaderCacheError.containerUnavailable
        }
        let dir = container.appendingPathComponent(directoryName, isDirectory: true)
        if createDirectory {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        let safe = domainID.replacingOccurrences(of: "/", with: "_")
        return dir.appendingPathComponent("\(safe).sqlite3")
    }

    private func open() throws {
        let url = try Self.databaseURL(domainID: domainID, createDirectory: true)
        var handle: OpaquePointer?
        let rc = sqlite3_open(url.path, &handle)
        guard rc == SQLITE_OK, let handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open rc=\(rc)"
            Self.log.errorPublic("❌ sqlite3_open failed rc=\(rc) msg=\(msg)")
            throw BC01HeaderCacheError.open(msg)
        }
        self.db = handle
        // Wait out a concurrent writer rather than failing on it — see `MetadataCache.open()`:
        // Lock-and-Remove empties this cache from the app while the Provider may still hold a
        // handle, and without this the first DELETE fails with "database is locked".
        sqlite3_busy_timeout(handle, 5000)
        try exec("PRAGMA journal_mode=WAL;")
        // Rebuildable derived store: a lost commit costs one re-probe, so skip the per-commit
        // fsync (same rationale as `MetadataCache`).
        try exec("PRAGMA synchronous=NORMAL;")
        try exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);")
        if currentSchemaVersion() != Self.schemaVersion {
            try rebuildSchema()
        } else {
            try createSchema()
        }
        try queue.sync { try prepareCachedStatements() }
        Self.log.infoPublic("✅ BC01 header cache ready domain=\(domainID)")
    }

    private func createSchema() throws {
        try exec("""
        CREATE TABLE IF NOT EXISTS bc01_header (
            item_id          TEXT NOT NULL PRIMARY KEY,
            -- cTag: a column, NOT part of the key. One row per item, so a content write
            -- overwrites the stale row instead of orphaning it beside the new one.
            content_revision TEXT NOT NULL,
            -- Geometry: plaintext, non-sensitive (derivable from the remote size).
            header_end       INTEGER NOT NULL,
            block_size       INTEGER NOT NULL,
            cipher_padding   INTEGER NOT NULL,
            -- AES-GCM(fileKeysKEK, baseIV‖fileKey, aad = item_id‖content_revision).
            sealed_secrets   BLOB NOT NULL,
            created_at       INTEGER NOT NULL
        );
        """)
        try exec("CREATE INDEX IF NOT EXISTS bc01_header_created ON bc01_header(created_at);")
        try exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);")
        if currentSchemaVersion() == nil {
            try setMeta("schema_version", String(Self.schemaVersion))
        }
    }

    /// Drop and recreate the table on a schema-version change.
    ///
    /// Cached statements are finalized first: a prepared statement over a dropped table is
    /// invalid. They are re-prepared afterwards, so a rebuild leaves the instance usable.
    private func rebuildSchema() throws {
        Self.log.infoPublic("♻️ rebuilding BC01 header cache (schema change)")
        queue.sync { finalizeCachedStatements() }
        try exec("DROP TABLE IF EXISTS bc01_header;")
        try exec("DELETE FROM meta;")
        try createSchema()
        try setMeta("schema_version", String(Self.schemaVersion))
        try queue.sync { try prepareCachedStatements() }
    }

    private func currentSchemaVersion() -> Int? {
        (try? getMeta("schema_version")).flatMap { $0 }.flatMap(Int.init)
    }

    // MARK: - Row codec

    /// AAD binding a sealed blob to one item at one revision.
    private static func aad(itemID: String, contentRevision: String) -> Data {
        Data("\(itemID)\u{0}\(contentRevision)".utf8)
    }

    /// Serialise the sensitive half of a header as `baseIVLen ‖ baseIV ‖ fileKey`.
    private static func encodeSecrets(_ header: BC01Header) -> Data {
        var out = Data([UInt8(truncatingIfNeeded: header.baseIV.count)])
        out.append(header.baseIV)
        out.append(header.fileKey)
        return out
    }

    /// Rebuild a ``BC01Header`` from an opened secrets blob plus the row's plaintext geometry.
    ///
    /// - Returns: `nil` when the blob is truncated or internally inconsistent (treated as a miss).
    private static func decodeSecrets(_ data: Data, row: CachedHeader) -> BC01Header? {
        guard let ivLen = data.first.map(Int.init), data.count > 1 + ivLen else { return nil }
        let body = data.dropFirst()
        let baseIV = Data(body.prefix(ivLen))
        let fileKey = Data(body.dropFirst(ivLen))
        guard !fileKey.isEmpty else { return nil }
        return BC01Header(baseIV: baseIV,
                          fileKey: fileKey,
                          blockSize: Int(row.blockSize),
                          headerEnd: Int(row.headerEnd),
                          cipherPadding: Int(row.cipherPadding))
    }

    /// Fetch the row for `itemID`; caller must hold `queue`.
    ///
    /// The cached statement is reset again once the row is copied out. A statement left parked
    /// on a returned row still counts as "in progress", which blocks `VACUUM` in ``empty()`` and
    /// holds a read transaction open on the WAL.
    private func rowUnsynced(itemID: String) throws -> CachedHeader? {
        let stmt = selectStmt
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
        bindText(stmt, 1, itemID)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            sqlite3_reset(stmt)
            return nil
        }
        defer { sqlite3_reset(stmt) }
        return CachedHeader(itemID: itemID,
                            contentRevision: column(stmt, 0) ?? "",
                            headerEnd: sqlite3_column_int64(stmt, 1),
                            blockSize: sqlite3_column_int64(stmt, 2),
                            cipherPadding: sqlite3_column_int64(stmt, 3),
                            sealedSecrets: blob(stmt, 4) ?? Data(),
                            createdAt: Date(timeIntervalSince1970: Double(sqlite3_column_int64(stmt, 5))))
    }

    /// Number of rows currently held. Diagnostics and tests.
    func rowCount() throws -> Int {
        try queue.sync {
            let stmt = try prepare("SELECT COUNT(*) FROM bc01_header;")
            defer { sqlite3_finalize(stmt) }
            return sqlite3_step(stmt) == SQLITE_ROW ? Int(sqlite3_column_int64(stmt, 0)) : 0
        }
    }

    /// The stored row for `itemID` without decrypting it. Diagnostics and tests.
    func rawRow(itemID: String) throws -> CachedHeader? {
        try queue.sync { try rowUnsynced(itemID: itemID) }
    }

    /// `sqlite3_total_changes` for this connection — the counter a pure read must not move.
    var totalChanges: Int32 { queue.sync { sqlite3_total_changes(db) } }

    // MARK: - SQLite helpers

    private static let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private func exec(_ sql: String) throws { try queue.sync { try execUnsynced(sql) } }

    /// `sqlite3_exec` without acquiring `queue`; caller must already hold it.
    private func execUnsynced(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let message = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            throw BC01HeaderCacheError.step(message)
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw BC01HeaderCacheError.prepare(String(cString: sqlite3_errmsg(db)))
        }
        return stmt
    }

    private func stepDone(_ stmt: OpaquePointer?) throws {
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw BC01HeaderCacheError.step(String(cString: sqlite3_errmsg(db)))
        }
    }

    private func bindText(_ stmt: OpaquePointer?, _ idx: Int32, _ value: String) {
        sqlite3_bind_text(stmt, idx, value, -1, Self.SQLITE_TRANSIENT)
    }

    private func bindBlob(_ stmt: OpaquePointer?, _ idx: Int32, _ data: Data) {
        _ = data.withUnsafeBytes {
            sqlite3_bind_blob(stmt, idx, $0.baseAddress, Int32(data.count), Self.SQLITE_TRANSIENT)
        }
    }

    private func column(_ stmt: OpaquePointer?, _ idx: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, idx) else { return nil }
        return String(cString: c)
    }

    private func blob(_ stmt: OpaquePointer?, _ idx: Int32) -> Data? {
        guard sqlite3_column_type(stmt, idx) != SQLITE_NULL,
              let bytes = sqlite3_column_blob(stmt, idx) else { return nil }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(stmt, idx)))
    }

    private func setMeta(_ key: String, _ value: String) throws {
        try queue.sync { try setMetaUnsynced(key, value) }
    }

    private func getMeta(_ key: String) throws -> String? {
        try queue.sync { try getMetaUnsynced(key) }
    }

    private func getMetaUnsynced(_ key: String) throws -> String? {
        let stmt = try prepare("SELECT value FROM meta WHERE key = ?;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        return sqlite3_step(stmt) == SQLITE_ROW ? column(stmt, 0) : nil
    }

    private func setMetaUnsynced(_ key: String, _ value: String) throws {
        let stmt = try prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;")
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        bindText(stmt, 2, value)
        try stepDone(stmt)
    }
}
