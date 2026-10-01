/// Durable, resumable change monitoring for a OneDrive drive via the Graph delta API.
///
/// Polls `GET /me/drive/items/{rootGraphID}/delta` — scoped to the serving root, not the
/// whole drive (first run: full; subsequently from the saved
/// `@odata.deltaLink`), pages `@odata.nextLink`, and reconciles each `driveItem` into the
/// ``MetadataCache`` (upsert, or tombstone for the `deleted` facet), bumping the local
/// rank so File Provider sync anchors advance. The saved deltaLink is the resumable
/// cursor and survives process restarts.
///
/// Delta is the **durable source of truth** for change detection; webhooks (latency
/// reduction) are deferred.
/// Full crawls (first run, `410 Gone`, Rebuild Index) are generation-tagged mark-and-sweep:
/// ``MetadataCache/beginFullCrawl()`` opens a generation, every returned row is stamped with it,
/// and on reaching the deltaLink ``MetadataCache/sweepUnseen(generation:excludingGraphID:)``
/// purges live rows the crawl did not return — deletions that happened inside an expired
/// cursor's gap. Purged rows reach the system through the working-set feed as deletions.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import os.log

/// The outcome of a delta pass.
struct DeltaResult {
    /// Whether any change was reconciled (callers may signal enumerators).
    let changed: Bool
    /// `true` if a fresh full crawl also returned `410` straight after a cursor expiry. The
    /// pending generation is kept, so the next pass restarts the full crawl.
    let cursorExpired: Bool
    /// `true` if the pass stopped early because its task was cancelled. The saved cursor is a
    /// `nextLink`, so the crawl resumes from that page on the next pass — this is a *partial*
    /// pass, not a failed one, and the changes it did reconcile are still in this result.
    let cancelled: Bool
    /// Graph ids of the containers whose direct children changed this pass (the
    /// `parentReference.id` of every upserted item, plus the cached parent of every
    /// tombstoned item). The caller maps these to File Provider container identifiers
    /// and signals each so the affected folder re-enumerates. Empty when nothing changed.
    let changedParentGraphIDs: Set<String>
    /// Graph ids of parent containers that need a `/children` reconciliation pass because
    /// the delta returned a live item over a local tombstone (e.g. restored via web UI).
    /// The caller fetches `/children` for each, resurrects any tombstoned items found live
    /// there, then signals the container so Finder reflects the restored state.
    let reconcileParentGraphIDs: Set<String>

    init(changed: Bool, cursorExpired: Bool, cancelled: Bool = false,
         changedParentGraphIDs: Set<String> = [],
         reconcileParentGraphIDs: Set<String> = []) {
        self.changed = changed
        self.cursorExpired = cursorExpired
        self.cancelled = cancelled
        self.changedParentGraphIDs = changedParentGraphIDs
        self.reconcileParentGraphIDs = reconcileParentGraphIDs
    }
}

/// One reconciled delta page, emitted from inside the crawl.
///
/// A pass now crawls to completion, so the pass return value arrives only once — far
/// too coarse to drive progress on a multi-hundred-thousand-item initial crawl. This is the
/// per-page channel that replaces it: the handler signals the affected containers and publishes
/// the indexed count while the crawl is still running.
struct DeltaPageUpdate: Sendable {
    /// Graph ids of containers whose direct children changed on THIS page — not the
    /// pass-cumulative set. A per-page signal signals that page's containers.
    let changedParentGraphIDs: Set<String>
    /// Items reconciled so far this pass, across all pages. Monotonic within a pass.
    let itemsSeen: Int
    /// 1-based index of the page just reconciled.
    let page: Int
    /// `false` on the final page (Graph returned a deltaLink rather than a nextLink).
    let hasNextPage: Bool
    /// Whether this page reconciled anything into the cache. A page of pure no-ops still emits
    /// an update — the indexed count must keep advancing — but carries `false` so the handler
    /// can skip signalling work that has nothing to deliver.
    let changed: Bool
    /// Whether a full crawl is still in progress after this page: `false` for incremental
    /// passes and on a full crawl's final page (its sweep has run).
    let isFullCrawlInProgress: Bool
}

/// Notification that one delta page has been reconciled into the cache.
typealias DeltaUpdateHandler = @Sendable (DeltaPageUpdate) async -> Void

actor GraphDeltaSync {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "graph-delta")

    private let cache: MetadataCache
    private let rootGraphID: String
    /// Performs an authenticated Graph GET for an absolute or relative URL, returning bytes.
    /// The optional page-size hint is sent as `Prefer: odata.maxpagesize`, which Graph
    /// echoes into the generated nextLink so it governs the entire crawl.
    private let fetch: (URL, Int?) async throws -> Data
    /// Soft-yield hook: awaited between pages so the crawl defers to in-flight
    /// interactive (Finder-origin) requests. No-op when nothing interactive is pending.
    private let yieldToInteractive: () async -> Void
    /// Fired once per reconciled page. This is the ONLY change-notification channel for a pass:
    /// the caller no longer signals from the pass return value (see ``DeltaPageUpdate``).
    private let onDeltaUpdates: DeltaUpdateHandler?
    /// Classifies whether an item's remote size is already its exact plaintext size.
    /// Name-based only — it can never *compute* an encrypted item's plaintext length.
    private let translator: MetadataTranslator
    /// Recognises BC01 bookkeeping entries (`FolderKey.bch`) so they are never cached and
    /// never enumerated. Carried alongside ``translator``: both are name-based BC01 rules
    /// gated on the same domain algorithm, but this one *removes* an entry at the boundary
    /// rather than translating one through it.
    private let specialItem: BC01SpecialItem
    private let decoder = GraphMapping.makeDecoder()

    private static let graphBase = URL(string: "https://graph.microsoft.com/v1.0")!

    /// Guards against overlapping passes.
    private var isRunning = false

    init(cache: MetadataCache,
         rootGraphID: String,
         fetch: @escaping (URL, Int?) async throws -> Data,
         yieldToInteractive: @escaping () async -> Void = {},
         translator: MetadataTranslator = IdentityMetadataTranslator(),
         specialItem: BC01SpecialItem = BC01SpecialItem(algorithm: .plain),
         onDeltaUpdates: DeltaUpdateHandler? = nil) {
        self.cache = cache
        self.rootGraphID = rootGraphID
        self.fetch = fetch
        self.yieldToInteractive = yieldToInteractive
        self.translator = translator
        self.specialItem = specialItem
        self.onDeltaUpdates = onDeltaUpdates
    }

    /// Run one delta pass: page through changes from the saved cursor (or full) and
    /// reconcile into the cache. Idempotent and safe to call repeatedly.
    ///
    /// The pass crawls to completion: it pages until Graph returns a `deltaLink` rather than a
    /// `nextLink`. Each page's `nextLink` is still persisted as it goes, so a pass interrupted
    /// by extension suspension resumes from that page instead of restarting the crawl.
    ///
    /// Change notification happens per page via ``DeltaPageUpdate``, not from the return value:
    /// a completion-crawling pass returns once, which is far too coarse to signal or to show
    /// progress on a large initial crawl. The returned ``DeltaResult`` carries only what the
    /// caller must act on *after* the crawl — cursor expiry and the tombstone-reconcile set.
    @discardableResult
    func runPass() async throws -> DeltaResult {
        if isRunning { return DeltaResult(changed: false, cursorExpired: false) }
        isRunning = true
        defer { isRunning = false }

        // No cursor and no crawl in flight: the first crawl, opened as a generation like any
        // other full crawl so its end sweeps rows left behind by earlier writers.
        let noCursor = cache.deltaLink?.isEmpty ?? true
        var generation = cache.pendingFullCrawlGeneration
        if noCursor && generation == nil {
            generation = try cache.beginFullCrawl()
        }

        var url = startURL()
        let resuming = url.absoluteString.contains("token=")
        // Cold full crawl (nothing saved): request the largest page Graph allows via
        // `Prefer: odata.maxpagesize`, which Graph echoes into every generated nextLink so it
        // governs the whole crawl. Steady-state incremental passes (a saved deltaLink exists)
        // are tiny, so don't override paging. A pass resuming a saved *nextLink* also skips the
        // hint deliberately — the page size is already encoded in that link.
        var preferMaxPageSize: Int? = noCursor ? Self.crawlPageSize : nil
        var restartedAfterExpiry = false
        var changed = false
        var changedParents = Set<String>()
        var reconcileParents = Set<String>()
        var page = 0
        var seen = 0
        let started = DispatchTime.now()

        while true {
            // Defer to any in-flight Finder enumeration before fetching the next page so
            // the long initial crawl doesn't starve interactive requests.
            await yieldToInteractive()
            // Rebuild Index (host app) may open a newer generation while this pass runs. Adopt
            // it and restart from a fresh start URL — never the saved link, which may be this
            // crawl's nextLink written after the host cleared it: resuming it under the new
            // generation would sweep every row the skipped pages carried.
            if let pending = cache.pendingFullCrawlGeneration, pending != generation {
                Self.log.infoPublic("🔁 full crawl gen \(pending) opened mid-pass → restart")
                generation = pending
                url = startURL(fresh: true)
                preferMaxPageSize = Self.crawlPageSize
            }
            page += 1
            let data: Data
            do {
                data = try await fetch(url, preferMaxPageSize)
            } catch let error as DeltaHTTPError where error.statusCode == 410 {
                // Graph will not resume from this cursor, so the range it covered was never
                // reconciled: deletions and moves in that gap are missing from the cache. Open
                // a new crawl generation (drops cursor + completeness claim) and restart the
                // full crawl in this pass; its closing sweep purges what the gap deleted.
                // A second 410 straight after restarting is not recoverable in-pass.
                if restartedAfterExpiry {
                    Self.log.errorPublic("⛓️‍💥 delta 410 again on fresh full crawl; retry next pass")
                    return DeltaResult(changed: changed, cursorExpired: true,
                                       changedParentGraphIDs: changedParents,
                                       reconcileParentGraphIDs: reconcileParents)
                }
                Self.log.infoPublic("⛓️‍💥 delta cursor expired (410) → full crawl with sweep")
                generation = try cache.beginFullCrawl()
                restartedAfterExpiry = true
                url = startURL(fresh: true)
                preferMaxPageSize = Self.crawlPageSize
                page -= 1
                continue
            }

            // Timing metrics per 10,000 items on an M-series Mac, measured 2026-08-29
            // A crawl is network-bound, ~97% wall clock; decode + cache ~3% of wall clock.
            //
            //   network        ~20.0 s  (97%) →     500 items/sec) ← dominates; varies ±20% run to run
            //   JSON decode     ~0.3 s  ( 3%) → ~38,000 items/sec) ← with hand-rolled fast-path timestamp parser
            //   cache write     ~0.3 s  ( 3%) → ~34,000 items/sec) ← sqlite batch upsert, tombstone, rank bump
            let collection = try decoder.decode(GraphCollection<GraphDriveItem>.self, from: data)

            let (upserts, deletes, encryptedParents) = partition(collection.value)
            // `Set` de-dupes: one `meta` write per folder per pass, not per delta row.
            for parent in Set(encryptedParents) { cache.markFolderEncrypted(parent) }
            var pageParents = Set<String>()

            // Resolve a deleted item's parent from the cache *before* tombstoning it: the
            // `deleted` facet carries only an id, so the cached row is the only source of
            // its container. Collected so the caller can signal the affected folder.
            for id in deletes {
                if let parent = (try? cache.itemIncludingDeleted(graphID: id))?.parentGraphID {
                    pageParents.insert(parent)
                }
            }

            // If delta returns a live item for a locally-tombstoned row, do not clear the
            // tombstone here. Signal the parent for a /children reconciliation pass instead:
            // the caller fetches /children from Graph (authoritative), resurrects any items
            // found live there, then signals Finder. This handles both the "deleted locally,
            // delta echoes it back" race and the "restored via web UI" case correctly.
            // Batched, not one probe per upsert: a full delta page carries up to 1000 rows,
            // and the per-row form paid a serial cache-queue hop and a fresh prepared
            // statement for each one — on the shared queue that also serves interactive
            // folder reads. Tombstones are rare, so this set is normally empty.
            let tombstoned = (try? cache.tombstonedIDs(among: upserts.map(\.graphID))) ?? []
            for item in upserts where tombstoned.contains(item.graphID) {
                if let parent = item.parentGraphID { reconcileParents.insert(parent) }
            }

            let written = try cache.upsertBatch(upserts, generation: generation)
            for item in collection.value where item.isDeleted {
                if let deletedAt = item.deletedDateTime {
                    try? cache.markTrashed(graphID: item.id, deletedAt: deletedAt)
                } else {
                    try? cache.markDeleted(graphID: item.id)
                }
            }
            if written > 0 {
                for item in upserts where item.parentGraphID != nil { pageParents.insert(item.parentGraphID!) }
            }
            // Final page of a full crawl: purge live rows the crawl never returned. Runs before
            // the deltaLink is saved, so a crash here repeats the sweep rather than skipping it.
            let hasNext = collection.nextLink != nil
            var swept = false
            if !hasNext, collection.deltaLink != nil, let generation {
                let sweptParents = try cache.sweepUnseen(generation: generation, excludingGraphID: rootGraphID)
                swept = !sweptParents.isEmpty
                pageParents.formUnion(sweptParents)
            }

            let pageChanged = written > 0 || !deletes.isEmpty || swept
            if pageChanged { changed = true }
            changedParents.formUnion(pageParents)
            seen += collection.value.count

            // Resumable cursor + progress. The total page count isn't known up front
            // (Graph streams pages), so log the running page index and item tally; the
            // presence of a nextLink tells us whether more pages follow.
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000_000
            Self.log.infoPublic("⚓️ delta page \(page) (\(collection.value.count) items, \(written) changed, \(seen) total, \(hasNext ? "more…" : "final"), \(String(format: "%.1f", elapsed))s\(resuming && page == 1 ? ", resumed" : ""))")

            // Per-page change notification. Emitted for EVERY page, including one that
            // reconciled nothing, so the indexed count keeps advancing across no-op pages.
            await onDeltaUpdates?(DeltaPageUpdate(changedParentGraphIDs: pageParents,
                                                  itemsSeen: seen,
                                                  page: page,
                                                  hasNextPage: hasNext,
                                                  changed: pageChanged,
                                                  isFullCrawlInProgress: generation != nil && hasNext))

            if let next = collection.nextLink, let nextURL = URL(string: next) {
                // Persist the nextLink as a resumable cursor: the File Provider extension
                // is short-lived and may be suspended mid-crawl. Saving each page's
                // nextLink lets the next pass resume from here instead of restarting the
                // full delta from scratch (which on a large drive never completes and
                // re-crawls every item on every launch).
                // A `false` means Rebuild Index superseded this crawl; the loop-top check
                // adopts the new generation and restarts.
                _ = try? cache.saveCursor(next, generation: generation)

                // Cooperative cancellation, checked at the page boundary — the one point where
                // stopping is free. Deliberately *after* persisting `next`: the page just
                // reconciled is committed and the cursor now points at the page we have not
                // fetched, so resuming repeats no work. A long initial crawl on a large drive is
                // exactly the work a caller needs to be able to abandon (extension suspension,
                // domain removal, a bounded benchmark).
                if Task.isCancelled {
                    Self.log.infoPublic("⏹ delta pass cancelled after page \(page) (\(seen) items)")
                    return DeltaResult(changed: changed, cursorExpired: false, cancelled: true,
                                       changedParentGraphIDs: changedParents,
                                       reconcileParentGraphIDs: reconcileParents)
                }

                url = nextURL
                continue
            }
            if let delta = collection.deltaLink {
                guard try cache.saveCursor(delta, generation: generation, finishCrawl: generation != nil) else {
                    // Superseded by a newer full crawl; restart it (loop top).
                    continue
                }
                // Graph returned a deltaLink rather than a nextLink: this pass reached the end
                // of the enumeration, so every item under the serving root is now in the cache.
                // Folder navigation can stop paying a /children walk from here on.
                cache.markInitialCrawlComplete()
            }
            break
        }
        return DeltaResult(changed: changed, cursorExpired: false,
                           changedParentGraphIDs: changedParents,
                           reconcileParentGraphIDs: reconcileParents)
    }

    /// The URL to begin a pass: the saved deltaLink, else a fresh full delta requesting
    /// the largest page Graph allows (fewer round-trips on the initial full crawl).
    /// `fresh` ignores the saved link.
    ///
    /// Delta is scoped to the **serving root** (`/me/drive/items/{rootGraphID}/delta`),
    /// not the whole drive (`/me/drive/root/delta`). When the domain is rooted at a
    /// sub-folder, this confines change tracking to that subtree instead of crawling the
    /// entire OneDrive.
    private func startURL(fresh: Bool = false) -> URL {
        if !fresh, let saved = cache.deltaLink, !saved.isEmpty, let url = URL(string: saved) {
            return url
        }
        let path = "me/drive/items/\(rootGraphID)/delta"
        var components = URLComponents(url: Self.graphBase.appendingPathComponent(path),
                                       resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "$top", value: String(Self.crawlPageSize)),
            URLQueryItem(name: "$select", value: Self.selectFields),
        ]
        return components.url!
    }

    /// The driveItem fields requested per delta item. Graph captures `$select` into the
    /// generated nextLink/deltaLink, so selecting once on the start URL trims the payload
    /// for every page of the crawl *and* every future incremental pass — cutting the wire
    /// size on a 300k-item drive substantially.
    ///
    /// These map 1:1 to the columns ``partition`` writes to the metadata cache:
    /// `id`, `name`, `size`, `eTag`, `cTag`, `createdDateTime`, `lastModifiedDateTime`,
    /// `parentReference` (parent id) and `folder` (folder-vs-file discriminator).
    ///
    /// Deliberately **not** requested, because nothing reads them:
    ///   - `file` — only `folder != nil` decides folder-vs-file; the `file` facet (hashes,
    ///     mimeType) is unused. Omitting it drops a per-item object on every file.
    ///   - `webUrl`, `@microsoft.graph.downloadUrl` — downloads resolve a fresh URL on
    ///     demand; a delta-time URL would be stale and large.
    ///   - `fileSystemInfo`, `shared`, `createdBy`, `lastModifiedBy`, `photo`, `image`,
    ///     `video`, `audio`, `location`, `package`, `remoteItem`, `permissions` — none are
    ///     surfaced by the File Provider or stored.
    ///
    /// `remoteItem` is included so Personal Vault — which appears as a remote-item link, not a
    /// real folder — is detectable and skipped.
    ///
    /// `deleted` and `deletedDateTime` are **required**: `$select` suppresses the `deleted`
    /// facet on delta tombstones, and without it a deletion decodes as an ordinary item and is
    /// upserted back into the cache (verified against live Graph — a tombstone arrives with
    /// `has_deleted_facet=false` under a `$select` that omits it). Never trim these two.
    private static let selectFields =
        "id,name,size,eTag,cTag,createdDateTime,lastModifiedDateTime,parentReference,folder,remoteItem,deleted,deletedDateTime"

    /// Page size for the initial full crawl, sent both as `$top` (sizes page 1) and as
    /// `Prefer: odata.maxpagesize` (echoed into every nextLink, so it governs subsequent
    /// pages too — `$top` alone does not). Graph caps delta paging near 2000; larger pages
    /// mean far fewer sequential round-trips on a large drive. Only applied while no saved
    /// deltaLink exists; steady-state incremental passes keep the server default.
    private static let crawlPageSize = 2000

    /// Split a delta page into (upserts, deleted-ids). Deletes carry only an id + the
    /// `deleted` facet; everything else is a content upsert.
    ///
    /// Sets ``CachedItem/plaintextSize`` only where it is **exactly** known from the delta row
    /// alone: a name the translator does not claim as backend-encrypted has ciphertext length ==
    /// plaintext length, so its remote size is already exact and it never needs a header read.
    ///
    /// - Important: An encrypted (`.bc`) item is left `nil`. Its plaintext length is a function
    ///   of its BC01 header, which delta never carries, so there is nothing here to derive it
    ///   from — and the ciphertext-derived *estimate* must never be persisted: a stored value
    ///   outranks the estimate on every read, and an over-reported `documentSize` (estimate)
    ///   stays unresolved until a content fetch parses the header.
    ///
    /// BC01 bookkeeping entries are dropped entirely rather than upserted. Marking their
    /// parent as encrypted is a cache *write*, so the parents are collected and returned
    /// here and written by the caller, keeping this function pure.
    private func partition(_ items: [GraphDriveItem])
        -> (upserts: [CachedItem], deletes: [String], encryptedParents: [String]) {
        var upserts: [CachedItem] = []
        var deletes: [String] = []
        var encryptedParents: [String] = []
        upserts.reserveCapacity(items.count)
        for item in items {
            if item.isExcludedSpecialItem {
                Self.log.infoPublic("🚫 delta: skipping special item id=\(item.id) name=\(item.name ?? "<nil>")")
                continue
            } else if specialItem.isSpecial(name: item.name ?? item.id, isFolder: item.isFolder) {
                // BC01 bookkeeping, not user content: never enumerated. A *live* folder key is
                // also evidence that the parent is encrypted; a deleted one is not, and a future
                // non-key sidecar would be hidden without being evidence at all. Hence the
                // second test.
                //
                // Ordering matters: this branch sits above `isDeleted` so a *deleted*
                // FolderKey.bch is skipped too — otherwise it enters `deletes` and the cache
                // gets a tombstone for a row that was never inserted.
                if !item.isDeleted,
                   specialItem.isFolderKeyEvidence(name: item.name ?? item.id, isFolder: item.isFolder),
                   let parent = item.parentReference?.id {
                    encryptedParents.append(parent)
                }
                continue
            } else if item.isDeleted {
                deletes.append(item.id)
            } else {
                let name = item.name ?? item.id
                let remoteFileSize = item.size ?? 0
                // Exact only when the name is not backend-encrypted; never an estimate.
                let plaintextSize: Int64? =
                    (item.isFolder || translator.isBackendEncrypted(name)) ? nil : remoteFileSize
                upserts.append(CachedItem(
                    graphID: item.id,
                    parentGraphID: item.parentReference?.id,
                    name: name,
                    isFolder: item.isFolder,
                    remoteFileSize: remoteFileSize,
                    eTag: item.eTag,
                    cTag: item.cTag,
                    createdDate: item.createdDateTime,
                    modifiedDate: item.lastModifiedDateTime,
                    deleted: false,
                    rank: 0,  // assigned by the cache on upsert
                    plaintextSize: plaintextSize))
            }
        }
        return (upserts, deletes, encryptedParents)
    }
}

/// Error carrying an HTTP status so the delta loop can special-case 410.
struct DeltaHTTPError: Error {
    let statusCode: Int
}
