/// ``ProviderBackend`` implementation over the Microsoft Graph DriveItem API for
/// OneDrive Personal.
///
/// The client calls `graph.microsoft.com` directly (the extension has the
/// `network.client` entitlement) — there is no localhost HTTP hop. Every request carries
/// a bearer token minted by ``MSALTokenStore`` from the shared App Group keychain; a
/// `401` triggers one silent refresh + retry. Throttling (`429`/`503` + `Retry-After`)
/// is handled by a per-client ``GraphRateLimiter``.
///
/// The domain root is the user-chosen serving sub-path (see `/docs/backend/remote-onedrive.md#serving-root`); its
/// DriveItem id is resolved lazily on first use from ``DomainAccount/remotePath`` and
/// cached. Items are exchanged as ``DomainService/Entry`` (see ``GraphMapping``).
///
/// Scope (v1): OneDrive Personal, single drive, no shared items, server-side conflict
/// copies (412 → wrongRevision → refetch).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import FileProvider
import os.log

public final class GraphDriveClient: ProviderBackend {

    // MARK: Reserved identifiers (opaque tokens; never numeric for OneDrive)

    // Universal sentinels; translated to the serving folder's Graph DriveItem id at the
    // wire edge (see `GraphMapping.graphID(for:)`).
    public static let rootItemIdentifier: DomainService.ItemIdentifier = .root
    public static let trashItemIdentifier: DomainService.ItemIdentifier = .trash

    // MARK: Stored state

    public let displayName: String
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "graph-client")

    /// Graph DriveItem id of the serving folder; `nil` serves the drive root.
    private let servingItemID: String?
    /// The process-wide token store; the Provider's only path to a bearer token.
    ///
    /// The Provider has outbound network access and redeems tokens itself, so rotation happens
    /// **here**, in the extension. It needs no second rotation path: `MSALTokenStore`'s refresh
    /// persists through ``VaultRefreshTokenStore``, whose `store` is
    /// ``VaultKeyStore/commitRefreshToken(_:for:)`` — one writer that seals to
    /// `refreshTokenKey.pub` and overwrites `refreshToken.unwrapped` in the same operation.
    /// Sealing needs only the public half, so this works with the vault locked and the two slots
    /// cannot diverge. Reads take the unwrapped slot only; its absence is a locked vault,
    /// which reaches the OS as ``NSFileProviderError/notAuthenticated`` via
    /// `Error.toPresentableError()`.
    private let tokenStore: MSALTokenStore
    private let limiter: GraphRateLimiter

    /// Called once per reconciled delta page, mid-crawl. A pass crawls to completion, so this is
    /// the only channel that can signal changed containers or advance the indexed count while a
    /// large initial crawl is still running. Set by `Extension` alongside the two hooks above.
    var onDeltaProgress: (@Sendable (DeltaProgress) async -> Void)?
    private let session: URLSession
    private let decoder = GraphMapping.makeDecoder()

    private static let graphBase = URL(string: "https://graph.microsoft.com/v1.0")!
    /// Ciphertext up to this size uploads via simple PUT; larger use an upload session.
    static let simpleUploadLimit: Int = 4 * 1024 * 1024

    /// Rows returned per ``listFolder`` page. fileproviderd ingest is ~2ms/item regardless of
    /// page size (measured 1000 vs 5000), so larger pages add no throughput; 1000 keeps pages
    /// short so other enumerations interleave. Well under the 20000-items-per-batch ceiling.
    private static let listFolderPageSize: Int64 = 1000

    /// Max changed rows returned by one `listChanges` call.
    ///
    /// Two constraints set this. Upper bound: the File Provider framework aborts an
    /// enumeration if a single *page* (all `didUpdate` items between two
    /// `finishEnumeratingChanges` calls) exceeds 20000. Lower-is-better: during a cold-start
    /// backlog drain (first materialization of a large drive — tens of thousands of working-set
    /// changes), the framework ingests an entire page into its replica before re-driving
    /// `enumerateChanges` for the next one, and it will not service a user-interactive
    /// `fetchContents`/`item(for:)` until the in-flight page is applied. A large page (5000)
    /// blocked interactive opens for ~10 s at a time. A smaller page yields control back to the
    /// framework far more often, so user opens interleave between pages. The cache query itself
    /// is ~50 ms regardless of page size (it's a single bounded SQL read), so more pages cost
    /// negligibly while restoring interactivity during the one-time drain.
    /// Set to 500 (~1 second per page) to balance throughput and interactivity.
    private static let changesPageLimit = 500

    /// Lazily-resolved Graph DriveItem id for the serving sub-path (the domain root).
    private var rootGraphIDCache: String?
    /// In-flight resolution shared by concurrent callers, so the N parallel enumerator
    /// calls collapse into a single `/me/drive/root` request rather than racing.
    private var rootResolveTask: Task<String, Error>?

    private let domainID: String
    /// Per-domain BC01 header cache so repeat ranged content fetches skip the header GET.
    ///
    /// Persistent (the extension is killed aggressively when idle) and shared in implementation
    /// with every other backend. Lazily opened under ``setupLock``: opening touches the
    /// filesystem, and a failure must degrade to the probe path rather than fail construction.
    private var headerCacheStorage: BC01HeaderCache?
    private var headerCacheOpenFailed = false
    /// Metadata cache + delta sync, created lazily once the root id is known.
    private var cache: MetadataCache?
    private var deltaSync: GraphDeltaSync?
    /// Serialises lazy cache/delta setup.
    private let setupLock = NSLock()

    /// The domain's persistent BC01 header cache, opened on first use.
    ///
    /// - Returns: The cache, or `nil` when the store could not be opened — every caller then
    ///   takes the probe path, so a broken store degrades performance, never correctness.
    private var headerCache: BC01HeaderCache? {
        setupLock.lock(); defer { setupLock.unlock() }
        if let headerCacheStorage { return headerCacheStorage }
        guard !headerCacheOpenFailed else { return nil }
        do {
            headerCacheStorage = try BC01HeaderCache(domainID: domainID)
        } catch {
            headerCacheOpenFailed = true
            logger.errorPublic("❌ BC01 header cache unavailable: \(String(describing: error))")
        }
        return headerCacheStorage
    }

    /// Drop an item's cached BC01 header because the item is gone.
    ///
    /// Required for **deletes** only: a deleted item will never see another store, so its row
    /// must be removed explicitly. Content writes seed the row instead — see
    /// ``seedHeaderCache(from:rootGraphID:header:)``.
    ///
    /// - Parameter graphID: The Graph DriveItem id whose header row is no longer valid.
    private func invalidateCachedHeader(graphID: String) {
        try? headerCache?.invalidate(itemID: graphID)
    }

    /// Seed the header cache from an upload response.
    ///
    /// The key comes from the same ``GraphMapping`` helpers ``GraphMapping/entry(from:rootGraphID:translator:plaintextSize:)``
    /// uses (``GraphMapping/itemIdentifier(graphID:rootGraphID:)``, ``GraphMapping/contentTag(for:)``),
    /// so it matches what `downloadToFile` reads back via `cachedEntry` — never hand-built from `cTag`.
    ///
    /// - Parameters:
    ///   - item: The DriveItem the upload returned.
    ///   - rootGraphID: The serving root, for identifier mapping.
    ///   - header: The uploaded file's block context; `nil` invalidates.
    private func seedHeaderCache(from item: GraphDriveItem, rootGraphID: String, header: BC01Header?) {
        HeaderCacheSeeding.seed(headerCache, header: header,
                                itemID: GraphMapping.itemIdentifier(graphID: item.id, rootGraphID: rootGraphID).id,
                                contentIdentity: GraphMapping.contentTag(for: item))
    }

    public init(displayName: String,
                domainID: String,
                servingItemID: String?,
                tokenStore: MSALTokenStore = .shared) {
        self.displayName = displayName
        self.domainID = domainID
        self.servingItemID = servingItemID
        self.tokenStore = tokenStore
        // Exhausted throttling retries reply `serverUnreachable`; tell the system when the cool-off clears.
        self.limiter = GraphRateLimiter(
            maxInteractive: UserDefaults.sharedContainerDefaults.maxInteractiveRequests,
            onCoolOffEnded: { await ServerReachabilitySignal.resolve(domainID: domainID) })
        let config = URLSessionConfiguration.ephemeral
        // Allow parallel range-download lanes to open real concurrent connections rather
        // than queueing behind the default per-host cap.
        config.httpMaximumConnectionsPerHost =
            max(6, UserDefaults.sharedContainerDefaults.parallelDownloadLanes)
        self.session = URLSession(configuration: config)
    }

    /// Graph serves ranged content GETs (`Range: bytes=…` → 206), and `downloadToFile` maps a
    /// requested plaintext window onto the covering BC01 block range, so BRM is supported for
    /// both plain and `.bc` items.
    public var supportsByteRangeMaterialisation: Bool { true }

    /// OneDrive accepts move-to-trash (Graph `DELETE` → recycle bin). Trash enumeration
    /// is backed by `MetadataCache` tombstones; Graph has no `$trash/children` endpoint.
    public var supportsMoveToTrash: Bool { true }
    public var supportsTrashEnumeration: Bool { true }

    /// Decodes backend (Boxcryptor) names and approximates plaintext sizes for display.
    /// Gated on the `.bc` suffix; plain files and folders pass through. Keeps enumeration
    /// consistent with the materialisation path (`Extension.displayItem`).
    public func displayEntry(_ entry: DomainService.Entry) -> DomainService.Entry {
        let translator = metadataTranslator()
        let display = translator.displayEntry(entry)
        // A name-based translator cannot know an encrypted item's plaintext length, so it reports
        // the size as unknown and `displayEntry` carries the ciphertext length through unchanged
        // (`Entry.size` has no "unknown"). This is the layer that holds the authoritative value:
        // substitute the resolved `plaintext_size`. It is the read side of the persist-and-signal
        // path, and the only way a size learned during a partial fetch reaches `documentSize`.
        //
        // If the size is still unresolved there is nothing to substitute and the ciphertext length
        // stands — a deliberate over-report by header + padding. The item is published with that
        // estimate rather than withheld, so it is visible in Finder; the first content fetch
        // parses the BC01 header and persists the exact value for later reads.
        guard !translator.isDisplaySizeKnown(entry),
              let cache = try? metadataCache(),
              let row = try? cache.itemIncludingDeleted(graphID: entry.id.id),
              let exact = row.plaintextSize, exact != display.size
        else { return display }
        return DomainService.Entry(
            name: display.name, id: display.id, parent: display.parent,
            revision: display.revision, deleted: display.deleted, size: exact,
            children: display.children, type: display.type,
            metadata: display.metadata, userInfo: display.userInfo)
    }

    /// Whether a cached row may be published to the system yet.
    ///
    /// Always `true`. An encrypted row whose `plaintext_size` is still unresolved is published
    /// with the translator's ciphertext-derived *estimate* rather than withheld: withholding
    /// made such items invisible in Finder for as long as resolution lagged, and no speculative
    /// header probing remains to shorten that lag.
    ///
    /// The trade-off is a known one. The estimate over-reports by the BC01 header plus PKCS7
    /// padding, which makes `NSFileProviderPartialContentFetching` unusable for that item — the
    /// system requests tail bytes past the real EOF. The first content fetch resolves and persists
    /// the exact size, after which ``displayEntry(_:)`` substitutes it. Visible-but-approximate
    /// beats invisible.
    func isPublishable(_ row: CachedItem) -> Bool { true }

    public func isBackendEncrypted(_ entry: DomainService.Entry) -> Bool {
        metadataTranslator().isBackendEncrypted(entry.name)
    }

    /// The domain's metadata translator (BC01 name/size reframing, gated on the configured
    /// algorithm). Reads the per-domain crypto config from the shared container.
    private func metadataTranslator() -> BoxcryptorMetadataTranslator {
        let config = UserDefaults.sharedContainerDefaults.cryptoConfig(
            for: NSFileProviderDomainIdentifier(rawValue: domainID))
        return BoxcryptorMetadataTranslator(algorithm: config.algorithm)
    }

    /// The domain's BC01 special-item recogniser (`FolderKey.bch`), gated on the same
    /// configured algorithm as ``metadataTranslator()``.
    private func specialItem() -> BC01SpecialItem {
        let config = UserDefaults.sharedContainerDefaults.cryptoConfig(
            for: NSFileProviderDomainIdentifier(rawValue: domainID))
        return BC01SpecialItem(algorithm: config.algorithm)
    }

    // MARK: - Root resolution

    /// The Graph DriveItem id of the serving folder, resolved + cached on first use.
    ///
    /// When ``servingItemID`` is set (folder picked at setup) it is used directly. When
    /// `nil`, the drive root's item id is fetched via `GET /me/drive/root`.
    private func rootGraphID() async throws -> String {
        if let cached = rootGraphIDCache { return cached }
        if let id = servingItemID {
            rootGraphIDCache = id
            return id
        }

        // Coalesce concurrent resolutions: the first caller creates the resolving Task,
        // everyone else awaits it. Guarded by `setupLock` (the cache `var`s are touched
        // from multiple FP request threads).
        setupLock.lock()
        if let cached = rootGraphIDCache { setupLock.unlock(); return cached }
        if let task = rootResolveTask { setupLock.unlock(); return try await task.value }
        let task = Task<String, Error> { [self] in try await self.resolveRootGraphID() }
        rootResolveTask = task
        setupLock.unlock()

        do {
            let id = try await task.value
            setupLock.lock(); rootGraphIDCache = id; rootResolveTask = nil; setupLock.unlock()
            return id
        } catch {
            setupLock.lock(); rootResolveTask = nil; setupLock.unlock()
            throw error
        }
    }

    /// Resolve the serving-root Graph id, preferring the value persisted in this domain's
    /// ``MetadataCache`` (stable across launches) before hitting the network. Persists the
    /// resolved id so subsequent launches skip the `/me/drive/root` round-trip.
    private func resolveRootGraphID() async throws -> String {
        // The cache is per-domain (one SQLite file keyed by `domainID`), so this id is
        // scoped to this OneDrive account/domain even when several are configured.
        let cache = try metadataCache()
        if let persisted = cache.rootGraphID(), !persisted.isEmpty {
            return persisted
        }
        logger.infoPublic("🔎 resolving drive root via /me/drive/root")
        let item: GraphDriveItem = try await getJSON(path: "/me/drive/root")
        logger.infoPublic("✅ drive root resolved graphID=\(item.id)")
        try? cache.setRootGraphID(item.id) // persist for future launches; best-effort
        return item.id
    }

    /// The domain's metadata cache, opened and memoised on first use.
    private func metadataCache() throws -> MetadataCache {
        setupLock.lock()
        defer { setupLock.unlock() }
        if let cache { return cache }
        let cache = try MetadataCache(domainID: domainID)
        self.cache = cache
        return cache
    }

    /// The delta-sync engine, built once the root id and cache are known.
    private func deltaSync() async throws -> GraphDeltaSync {
        let root = try await rootGraphID()
        let cache = try metadataCache()
        setupLock.lock()
        defer { setupLock.unlock() }
        if let deltaSync { return deltaSync }
        try cache.setRootGraphID(root)
        let sync = GraphDeltaSync(cache: cache, rootGraphID: root, fetch: { [weak self] url, preferMaxPageSize in
            guard let self else { throw CommonError.internalError }
            return try await self.authedGET(url, preferMaxPageSize: preferMaxPageSize)
        }, yieldToInteractive: { [limiter] in
            await limiter.yieldToInteractiveIfNeeded()
        }, translator: metadataTranslator(),
           specialItem: specialItem(),
           onDeltaUpdates: { [weak self] update in
            self?.publishIndexedCount(fullCrawlItemsSeen: update.isFullCrawlInProgress ? update.itemsSeen : nil)
            // Project the page's Graph ids onto File Provider identifiers before handing the
            // update out, so nothing above this layer deals in Graph ids.
            guard let self, let handler = self.onDeltaProgress else { return }
            let parents = Set(update.changedParentGraphIDs.map {
                GraphMapping.itemIdentifier(graphID: $0, rootGraphID: root)
            })
            await handler(DeltaProgress(changedParentIdentifiers: parents,
                                        itemsSeen: update.itemsSeen,
                                        page: update.page,
                                        hasNextPage: update.hasNextPage,
                                        changed: update.changed))
        })
        self.deltaSync = sync
        return sync
    }

    /// Publish the live indexed-item count, plus full-crawl progress, into the progress relay
    /// for the app's menu-bar detail view. The single publisher of both figures.
    ///
    /// - Parameter fullCrawlItemsSeen: Items the in-progress full crawl has scanned this pass;
    ///   `nil` when none is in progress (clears the relay's crawl figure).
    private func publishIndexedCount(fullCrawlItemsSeen: Int?) {
        guard let count = indexedItemCount() else { return }
        ProgressStore.shared.update(domainID: domainID) { snapshot in
            snapshot.indexedCount = count
            snapshot.indexedCountUpdatedAt = Date()
            snapshot.fullCrawlItemsSeen = fullCrawlItemsSeen
        }
    }

    /// Run one delta pass into the cache (best-effort; surfaces cursor expiry).
    @discardableResult
    private func syncDelta() async throws -> DeltaResult {
        try await deltaSync().runPass()
    }

    /// ``ProviderBackend`` background-poll hook: run one delta pass and project the
    /// internal ``DeltaResult`` onto the protocol-level ``DeltaPollResult``. Overlap with
    /// enumeration-driven passes is guarded inside ``GraphDeltaSync`` (`isRunning`).
    ///
    /// When the delta returns live items over local tombstones, fetches `/children` for each
    /// affected parent (Graph is authoritative), resurrects any tombstoned items found there,
    /// and includes those parents in `changedParentIdentifiers` so Finder re-enumerates them.
    ///
    /// - Important: The returned `changedParentIdentifiers` holds **only** those post-crawl
    ///   reconcile parents. Everything the crawl itself reconciled was already signalled per page
    ///   via ``onDeltaProgress``; returning it again would signal every container twice.
    /// Live indexed-item count from the ``MetadataCache`` for the progress relay.
    /// `nil` if the cache is not yet created.
    public func indexedItemCount() -> Int? {
        guard let cache = try? metadataCache() else { return nil }
        return try? cache.indexedCount()
    }

    public func pollDelta() async throws -> DeltaPollResult {
        let root = try await rootGraphID()
        let result = try await syncDelta()

        // Eventual Consistency: Reconcile parents where delta returned a live item over a tombstone.
        var extraChanged = Set<String>()
        if !result.reconcileParentGraphIDs.isEmpty, let cache = try? metadataCache() {
            for parentGraphID in result.reconcileParentGraphIDs {
                _ = try? await fetchAndCacheChildren(parentGraphID: parentGraphID, cache: cache)
                extraChanged.insert(parentGraphID)
            }
        }

        // Only the reconcile parents are reported here. The crawl's own changed parents were
        // already signalled per page through `onDeltaProgress`; repeating them would signal every
        // container twice. These are different: `/children` was fetched AFTER the crawl emitted
        // its last page, so nothing has signalled them yet.
        let parents = Set(extraChanged.map {
            GraphMapping.itemIdentifier(graphID: $0, rootGraphID: root)
        })
        return DeltaPollResult(changed: !extraChanged.isEmpty,
                               cursorExpired: result.cursorExpired,
                               changedParentIdentifiers: parents)
    }

    /// The extension-owned domain version, derived by ``DomainVersionStore`` from the cache's
    /// rank high-water mark and the host `configEpoch`. Falls back to a fresh version if the
    /// cache can't open.
    public func domainVersion(configEpoch: Int) -> NSFileProviderDomainVersion {
        guard let cache = try? metadataCache() else { return NSFileProviderDomainVersion() }
        return DomainVersionStore(cache: cache).currentVersion(configEpoch: configEpoch)
    }

    /// Authenticated GET returning raw bytes; throws ``DeltaHTTPError`` on 410 so the
    /// delta loop can detect cursor expiry.
    private func authedGET(_ url: URL, preferMaxPageSize: Int? = nil) async throws -> Data {
        do {
            // Delta crawl / background poll: yields the rate-limiter slot to interactive
            // (Finder-origin) requests and absorbs Retry-After cool-offs on their behalf.
            let (data, _) = try await perform(priority: .background) { token in
                var req = URLRequest(url: url)
                req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                // `$top` sizes only the first delta page; the server-generated nextLink
                // ignores it. `Prefer: odata.maxpagesize` is echoed into every nextLink,
                // so it governs the whole crawl — the real lever for large drives.
                if let preferMaxPageSize {
                    req.setValue("odata.maxpagesize=\(preferMaxPageSize)", forHTTPHeaderField: "Prefer")
                }
                return req
            }
            return data
        } catch let error as CommonError {
            if case .httpError(let response) = error,
               let http = response as? HTTPURLResponse, http.statusCode == 410 {
                throw DeltaHTTPError(statusCode: 410)
            }
            throw error
        }
    }

    // MARK: - HTTP core

    /// Perform a Graph request with auth, 401-refresh-once, and throttle/backoff retries.
    ///
    /// `priority` routes the request through the rate limiter's lanes: `.interactive`
    /// (Finder enumeration, fetch, download) waits out only a short `Retry-After` window and
    /// otherwise fails fast with a retryable File Provider error; `.background` (delta/poll)
    /// honors the full `Retry-After`. Every attempt, including retries, is gated.
    private func perform(priority: GraphRateLimiter.Priority = .interactive,
                         _ build: @Sendable @escaping (String) -> URLRequest,
                         allowRefresh: Bool = true) async throws -> (Data, HTTPURLResponse) {
        try await perform(priority: priority, authenticated: true,
                          { token in build(token ?? "") }, allowRefresh: allowRefresh)
    }

    /// Throttle-aware request driver, with authentication optional.
    ///
    /// `authenticated: false` skips the bearer-token fetch and passes `nil` to `build` — for
    /// pre-authenticated URLs such as upload-session fragment PUTs, which carry their own
    /// credential in the URL and reject an `Authorization` header. Everything else — the rate
    /// limiter slot, 429/503 `Retry-After` handling, 5xx and transport backoff — applies
    /// identically, which is the point: fragment PUTs previously bypassed all of it.
    /// - Parameter body: When non-nil the request is sent via `upload(for:from:)` rather than
    ///   `data(for:)`. A streamed upload body must be re-supplied on every attempt, and letting
    ///   `URLSession` own the body is also what makes it set `Content-Length` correctly — a
    ///   hand-set `Content-Length` is dropped as a reserved header.
    private func perform(priority: GraphRateLimiter.Priority = .interactive,
                         authenticated: Bool,
                         body: Data? = nil,
                         _ build: @Sendable @escaping (String?) -> URLRequest,
                         allowRefresh: Bool = true) async throws -> (Data, HTTPURLResponse) {
        let queued = await limiter.beginRequest(priority)
        defer { Task { await limiter.endRequest(priority) } }
        var attempt = 0
        // 401 refreshes by looping, never by recursing: a nested call would queue for a second
        // interactive slot while holding this one, deadlocking at the concurrency cap.
        var canRefresh = allowRefresh
        while true {
            let slotWait = try await limiter.waitForCoolOff(priority: priority) + (attempt == 0 ? queued : 0)
            let token = authenticated ? try await tokenStore.accessToken(for: domainID) : nil
            var request = build(token)
            // Interactive (Finder-origin) transfers are latency-sensitive; ask the system
            // to schedule them responsively. Background delta/poll keeps the default.
            if priority == .interactive { request.networkServiceType = .responsiveData }
            let (data, response): (Data, URLResponse)
            // Paired with the completion log below so true request overlap (issue vs.
            // finish) is readable in the trace, separating ordering from transfer cost.
            if slotWait > 0.001 {
                logger.debugPublic("⬆️ \(request.httpMethod ?? "GET") \(request.url?.path ?? "?") [issued, limiter waited \(String(format: "%.1f", slotWait))s]")
            } else {
                logger.debugPublic("⬆️ \(request.httpMethod ?? "GET") \(request.url?.path ?? "?") [issued]")
            }
            let started = DispatchTime.now()
            do {
                if let body {
                    (data, response) = try await session.upload(for: request, from: body)
                } else {
                    (data, response) = try await session.data(for: request)
                }
            } catch {
                // Cancellation is a decision, not a fault: never retry it.
                if error is CancellationError || (error as? URLError)?.code == .cancelled {
                    throw error
                }
                if attempt < limiter.maxRetries {
                    let delay = await limiter.backoffDelay(attempt: attempt)
                    logger.warningPublic("⚠️ transport error on \(request.httpMethod ?? "GET") \(request.url?.path ?? "?") (URLError \((error as? URLError)?.code.rawValue ?? 0)), retry \(attempt + 1)/\(limiter.maxRetries) in \(String(format: "%.1f", delay))s")
                    try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                    attempt += 1
                    continue
                }
                throw error
            }
            guard let http = response as? HTTPURLResponse else { throw CommonError.internalError }
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000_000
            // Report the direction that actually carried the payload. An upload's response is a
            // few hundred bytes of JSON ack, so measuring `data.count` on a 5 MiB fragment PUT
            // reports 0 KB/s and hides the real transfer rate.
            let payloadBytes = body?.count ?? data.count
            let direction = body != nil ? "↑" : "↓"
            let throughput = elapsed > 0 ? Double(payloadBytes) / 1024 / elapsed : 0
            logger.debugPublic("🌐 \(request.httpMethod ?? "GET") \(request.url?.path ?? "?") → \(http.statusCode) (\(String(format: "%.1f", elapsed))s, \(direction)\(String(format: "%.0f", throughput)) KB/s)")

            switch http.statusCode {
            case 200...299:
                return (data, http)
            case 401 where canRefresh && authenticated:
                // Token may have just expired; retry once with a fresh fetch.
                canRefresh = false
                continue
            case 401:
                throw NSError(domain: NSFileProviderErrorDomain,
                              code: NSFileProviderError.notAuthenticated.rawValue)
            case 404:
                // Generic transport-level 404: the specific item id isn't known at this
                // layer (perform() is id-agnostic), so use a self-describing sentinel rather
                // than the opaque "graph". Callers that know the id rethrow with it.
                throw CommonError.itemNotFound(.init("<graph-404>"))
            case 412:
                throw CommonError.wrongRevision(placeholderEntry())
            case 409 where body != nil:
                // On an upload-session fragment, 409 is `nameAlreadyExists` — a terminal
                // conflict raised when the last fragment commits, not a transient lock.
                // Retrying re-sends the whole fragment to fail identically.
                throw CommonError.httpError(http)
            case 416:
                // "The client sent a fragment the server already received", or one that is not
                // at the session's expected-range cursor. Never retryable.
                throw CommonError.httpError(http)
            case 409:
                // OneDrive 409 = file locked/in-use; transient — retry with backoff.
                guard attempt < limiter.maxRetries else { throw CommonError.httpError(http) }
                logger.warningPublic("⚠️ 409 conflict on \(request.httpMethod ?? "GET") \(request.url?.path ?? "?"), attempt \(attempt + 1)/\(limiter.maxRetries)")
                let conflictDelay = await limiter.backoffDelay(attempt: attempt)
                try? await Task.sleep(nanoseconds: UInt64(conflictDelay * 1_000_000_000))
                attempt += 1
                continue
            case 429, 503:
                let retryAfter = http.value(forHTTPHeaderField: "Retry-After").flatMap(TimeInterval.init)
                let backoff = retryAfter.map { "server Retry-After \(String(format: "%.0f", $0))s" }
                    ?? "no Retry-After (exponential backoff)"
                if let retryAfter {
                    await limiter.noteRetryAfter(seconds: retryAfter,
                                                 source: "\(http.statusCode) \(request.url?.path ?? "?")")
                }
                let lane = priority.label
                guard attempt < limiter.maxRetries else {
                    logger.errorPublic("🚦 throttled \(http.statusCode) on \(request.httpMethod ?? "GET") \(request.url?.path ?? "?") [\(lane)] — \(backoff), retries exhausted")
                    throw GraphRateLimiter.throttledError
                }
                logger.warningPublic("🚦 throttled \(http.statusCode) on \(request.httpMethod ?? "GET") \(request.url?.path ?? "?") [\(lane)] — \(backoff), retry \(attempt + 1)/\(limiter.maxRetries)")
                // With Retry-After, the next iteration's cool-off gate does the waiting.
                if retryAfter == nil {
                    let delay = await limiter.backoffDelay(attempt: attempt)
                    try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                }
                attempt += 1
                continue
            default:
                throw CommonError.httpError(http)
            }
        }
    }

    private func getJSON<T: Decodable>(path: String) async throws -> T {
        let url = Self.graphBase.appendingPathComponent(path.hasPrefix("/") ? String(path.dropFirst()) : path)
        let (data, _) = try await perform { token in
            var req = URLRequest(url: url)
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            return req
        }
        return try decoder.decode(T.self, from: data)
    }

    private func getJSON<T: Decodable>(absoluteURL: URL) async throws -> T {
        let (data, _) = try await perform { token in
            var req = URLRequest(url: absoluteURL)
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            return req
        }
        return try decoder.decode(T.self, from: data)
    }

    /// Fetch a single DriveItem's metadata and write it through to the cache, so that
    /// the next operation needing it (notably ``download``) hits the cache instead of
    /// re-fetching. Returns the decoded item. Cache write is best-effort.
    private func fetchItemSeedingCache(graphID: String) async throws -> GraphDriveItem {
        let item: GraphDriveItem = try await getJSON(path: "/me/drive/items/\(graphID)")
        if let cache = try? metadataCache() {
            try? cache.upsert(Self.cachedItem(from: item, translator: self.metadataTranslator()))
        }
        return item
    }

    /// Resolve an item's entry cache-first: return the cached row when present (no
    /// network), otherwise fetch from Graph and seed the cache. Delta sync is the durable
    /// source of truth for freshness/eviction (it upserts changes and tombstones deletes
    /// keyed by `graphID`), so a present row is authoritative for metadata.
    ///
    /// Tombstoned rows (deleted=1) are surfaced directly — trashed items report
    /// `.trashContainer` as their parent via `entry(from:)`. The cache is not bypassed for
    /// tombstones; doing so would hit Graph (which returns the item as live), overwrite the
    /// tombstone, and produce a ghost in the original parent folder.
    private func cachedEntry(graphID: String, rootGraphID root: String) async throws -> DomainService.Entry {
        if let cache = try? metadataCache(),
           let row = try? cache.itemIncludingDeleted(graphID: graphID) {
            switch row.lifecycle {
            case .trashed:
                logger.debugPublic("✅ entry cache HIT (tombstone) graphID=\(graphID)")
                // Trashed: serve with .trashContainer parent.
                return entry(from: row, rootGraphID: root)
            case .purged:
                logger.debugPublic("✅ entry cache HIT (tombstone) graphID=\(graphID)")
                // Permanently deleted: item no longer exists.
                throw CommonError.itemNotFound(DomainService.ItemIdentifier(graphID))
            case .live:
                break
            }
            logger.debugPublic("✅ entry cache HIT graphID=\(graphID)")
            return entry(from: row, rootGraphID: root)
        }
        logger.debugPublic("⚠️ entry cache MISS graphID=\(graphID) → fetching metadata")
        let item = try await fetchItemSeedingCache(graphID: graphID)
        return GraphMapping.entry(from: item, rootGraphID: root, translator: self.metadataTranslator())
    }

    /// Map a wire ``GraphDriveItem`` to a ``CachedItem`` row (rank 0; delta sync owns rank).
    ///
    /// `plaintextSize` follows the same rule as the delta and `/children` seeders: exact for a
    /// non-encrypted name (plaintext == ciphertext), nil for an encrypted one. All three seeders
    /// must agree — the value is folded into the content version, so a path that leaves it nil
    /// where another sets it flips the version without any content change.
    ///
    /// Encrypted items rely on the caller: the mutation paths that use this to reseed after a
    /// write call `recordUploadedPlaintextSize` alongside it, which puts the true length back.
    private static func cachedItem(from item: GraphDriveItem,
                                   translator: BoxcryptorMetadataTranslator) -> CachedItem {
        let name = item.name ?? item.id
        let remoteFileSize = item.size ?? 0
        let plaintextSize: Int64? =
            (item.isFolder || translator.isBackendEncrypted(name)) ? nil : remoteFileSize
        return CachedItem(graphID: item.id,
                   parentGraphID: item.parentReference?.id,
                   name: name,
                   isFolder: item.isFolder,
                   remoteFileSize: remoteFileSize,
                   eTag: item.eTag, cTag: item.cTag,
                   createdDate: item.createdDateTime,
                   modifiedDate: item.lastModifiedDateTime,
                   deleted: item.isDeleted,
                   deletedAt: item.deletedDateTime,
                   rank: 0,
                   plaintextSize: plaintextSize)
    }

    /// A throwaway entry used to satisfy `wrongRevision`'s associated value; the
    /// extension treats 412 as a signal to refetch.
    private func placeholderEntry() -> DomainService.Entry {
        DomainService.Entry(name: "", id: Self.rootItemIdentifier, parent: Self.rootItemIdentifier,
                            revision: .zero, deleted: false, size: 0, children: nil,
                            type: .file, metadata: .empty, userInfo: .init(conflictCount: nil,
                            originatorName: nil, symlinkTargetPath: nil, implicitLockOwner: nil,
                            quotaRemaining: nil, quotaTotal: nil))
    }

    // MARK: - Progress bridging

    /// Run `work` on a Task and report through `block`, returning a `Progress` that
    /// cancels the task.
    private func bridge<T>(_ block: @escaping (Result<T, Error>) -> Void,
                           _ work: @escaping () async throws -> T) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let task = Task {
            do {
                let value = try await work()
                if !Task.isCancelled { block(.success(value)) }
                progress.completedUnitCount = 1
            } catch {
                self.logger.errorPublic("❌ graph op failed: \(String(describing: error))")
                block(.failure(error))
            }
        }
        progress.cancellationHandler = { task.cancel() }
        return progress
    }

    // MARK: - Enumeration

    public func fetchItem(_ identifier: DomainService.ItemIdentifier,
                          resolvingPlaintextSize: Bool,
                          _ block: @escaping (Result<DomainService.FetchItemReturn, Error>) -> Void) -> Progress {
        // The root container must materialise without a network round-trip so the domain
        // mounts even before the serving folder is resolved or the token is warm.
        if identifier == .root {
            block(.success(DomainService.FetchItemReturn(item: Self.rootEntry())))
            return Progress()
        }
        // The trash container is a synthetic virtual item backed by MetadataCache tombstones;
        // it has no Graph DriveItem id, so a live fetch would 404.
        if identifier == .trash {
            block(.success(DomainService.FetchItemReturn(item: Self.trashEntry())))
            return Progress()
        }
        return bridge(block) {
            let root = try await self.rootGraphID()
            let graphID = GraphMapping.graphID(for: identifier, rootGraphID: root)
            // `cachedEntry` seeds the row that resolution reads.
            let entry = try await self.cachedEntry(graphID: graphID, rootGraphID: root)
            guard resolvingPlaintextSize else { return DomainService.FetchItemReturn(item: entry) }
            let resolved = await self.resolvePlaintextSize(graphID: graphID, rootGraphID: root)
            return DomainService.FetchItemReturn(item: resolved ?? entry)
        }
    }

    /// Probe the BC01 header of an encrypted file whose `plaintext_size` is unresolved and
    /// record the exact length (signalling the working set on change).
    ///
    /// - Returns: The entry built from the row's stored size (already resolved, or resolved
    ///   now); `nil` when the item needs no size or resolution failed — the caller's entry
    ///   is then current.
    private func resolvePlaintextSize(graphID: String, rootGraphID root: String) async -> DomainService.Entry? {
        do {
            guard let row = try metadataCache().item(graphID: graphID) else { return nil }
            // Resolved by another path since the caller read its entry: serve the stored size.
            if row.plaintextSize != nil { return entry(from: row, rootGraphID: root) }
            guard !row.isFolder,
                  metadataTranslator().isBackendEncrypted(row.name),
                  let decryptor = try makeDecryptor(filename: row.name, encrypted: true) as? BC01Decryptor
            else { return nil }
            let entry = entry(from: row, rootGraphID: root)
            _ = try await StreamingDownload.resolvePlaintextSize(
                fetcher: GraphContentFetcher(client: self, graphID: graphID, totalSize: Int(row.remoteFileSize)),
                decryptor: decryptor,
                itemIdentifier: entry.id,
                revision: entry.revision,
                remoteSize: Int(row.remoteFileSize),
                headerCache: headerCache,
                onPlaintextSizeResolved: plaintextSizeRecorder(graphID: graphID))
            // Re-read the row so the entry carries the recorded size.
            return try metadataCache().item(graphID: graphID).map { self.entry(from: $0, rootGraphID: root) }
        } catch {
            logger.warningPublic("⚠️ plaintext size resolution failed for graphID=\(graphID): \(String(describing: error))")
            return nil
        }
    }

    /// Synthetic entry for the domain root container. Children are served by ``listFolder``.
    static func rootEntry() -> DomainService.Entry {
        DomainService.Entry(name: "OneDrive", id: rootItemIdentifier, parent: rootItemIdentifier,
                            revision: .zero, deleted: false, size: 0, children: nil,
                            type: .root, metadata: .emptyFolder,
                            userInfo: .init(conflictCount: nil, originatorName: nil,
                                            symlinkTargetPath: nil, implicitLockOwner: nil,
                                            quotaRemaining: nil, quotaTotal: nil))
    }

    /// Synthetic entry for the trash container (no Graph counterpart; backed by MetadataCache tombstones).
    static func trashEntry() -> DomainService.Entry {
        DomainService.Entry(name: "Trash", id: trashItemIdentifier, parent: trashItemIdentifier,
                            revision: .zero, deleted: false, size: 0, children: nil,
                            type: .folder, metadata: .emptyFolder,
                            userInfo: .init(conflictCount: nil, originatorName: nil,
                                            symlinkTargetPath: nil, implicitLockOwner: nil,
                                            quotaRemaining: nil, quotaTotal: nil))
    }

    /// The keyset cursor after a cache page: the last row's `graph_id` when the page is full
    /// (more rows may remain), `nil` when it is short (the result set is exhausted).
    static func nextCursor(after rows: [CachedItem], pageSize: Int64) -> DomainService.PageCursor? {
        guard Int64(rows.count) == pageSize, let last = rows.last else { return nil }
        return DomainService.PageCursor(last.graphID)
    }

    public func listFolder(_ folder: DomainService.ItemIdentifier, recursive: Bool, startingCursor: DomainService.PageCursor?,
                           _ block: @escaping (Result<DomainService.ListFolderReturn, Error>) -> Void) -> Progress {
        // Serve children from the cache immediately (no delta pass at all — see below).
        // If the cache is empty for this folder, bulk-fetch via /children and seed it.
        // Delta sync runs via the 45s `DeltaPoller` and `listChanges`, advancing the rank so
        // the enumerator's change observer picks up updates.
        bridge(block) {
            // Phase timing for folder-open latency. Each phase is logged with its own
            // elapsed time so a slow open names the segment that held it, rather than
            // reporting one opaque total.
            let t0 = DispatchTime.now()
            func since(_ mark: DispatchTime) -> Double {
                Double(DispatchTime.now().uptimeNanoseconds - mark.uptimeNanoseconds) / 1_000_000_000
            }

            let root = try await self.rootGraphID()
            let cache = try self.metadataCache()
            let tSetup = since(t0)

            // Trash is backed by MetadataCache tombstones; no Graph endpoint exists.
            if folder == .trash {
                let rows = try cache.trashedItemsPage(after: startingCursor?.rawValue,
                                                      limit: Self.listFolderPageSize)
                let nextCursor = Self.nextCursor(after: rows, pageSize: Self.listFolderPageSize)
                let entries = rows.map { self.entry(from: $0, rootGraphID: root) }
                let rank = DomainService.RankToken(rank: cache.currentRank(), tokenCheckNumber: 0)
                return DomainService.ListFolderReturn(entries: entries, deletedEntries: nil,
                                                      cursor: nextCursor, rank: rank)
            }

            let parentGraphID = GraphMapping.graphID(for: folder, rootGraphID: root)
            let pageSize = Self.listFolderPageSize

            // Cold start (first, non-recursive page of a folder): bulk-fetch and cache its
            // direct children so the first page isn't empty. The recursive working-set case
            // relies on the cache populated by delta sync — if it's empty we return an empty
            // page and the background delta pass / poller fills it for the next enumeration.
            if !recursive, startingCursor == nil {
                // A completed delta crawl is a full enumeration of the serving root, so the
                // cache holds every child of every folder and this page can be served from it
                // directly. Until that first crawl finishes the cache is only partially seeded —
                // delta reconciles pages breadth-first — so a folder opened now would show a
                // truncated listing that nothing later fills in (delta reports only *changes*
                // thereafter). Walk `/children` in that window; one round-trip per folder, and
                // only until the crawl completes.
                if !cache.isInitialCrawlComplete {
                    let tSeed = DispatchTime.now()
                    _ = try await self.fetchAndCacheChildren(parentGraphID: parentGraphID, cache: cache)
                    self.logger.infoPublic("⏱️ listFolder(\(folder.id)) seed /children \(String(format: "%.2f", since(tSeed)))s")
                }
            }
            let tAfterSeed = since(t0)

            // Fetch one page from the cache, keyset-paged on `graph_id` (the cursor is the last
            // row's id). Recursive enumeration from the serving root (the working set) is a flat
            // scan of the root-scoped cache; a recursive walk below the root uses the subtree CTE;
            // otherwise just the folder's direct children.
            let afterGraphID = startingCursor?.rawValue
            let rows: [CachedItem]
            if recursive {
                rows = parentGraphID == root
                    ? try cache.liveItemsPage(excludingGraphID: root, after: afterGraphID, limit: pageSize)
                    : try cache.descendants(ofRootGraphID: parentGraphID, after: afterGraphID, limit: pageSize)
            } else {
                rows = try cache.childrenPage(ofParentGraphID: parentGraphID, after: afterGraphID, limit: pageSize)
            }

            let nextCursor = Self.nextCursor(after: rows, pageSize: pageSize)

            let tAfterQuery = since(t0)
            let entries = rows.map { self.entry(from: $0, rootGraphID: root) }
            let rank = DomainService.RankToken(rank: cache.currentRank(), tokenCheckNumber: 0)
            self.logger.infoPublic("⏱️ listFolder(\(folder.id)) rows=\(rows.count) setup=\(String(format: "%.2f", tSetup))s seed=\(String(format: "%.2f", tAfterSeed - tSetup))s query=\(String(format: "%.2f", tAfterQuery - tAfterSeed))s map=\(String(format: "%.2f", since(t0) - tAfterQuery))s total=\(String(format: "%.2f", since(t0)))s")
            return DomainService.ListFolderReturn(entries: entries, deletedEntries: nil, cursor: nextCursor, rank: rank)
        }
    }

    /// Classify one `/children` page into cache rows plus the folders a `FolderKey.bch`
    /// proves encrypted.
    ///
    /// Extracted from ``fetchAndCacheChildren(parentGraphID:cache:)`` so the seeding *rule* is
    /// reachable without Graph auth, a `URLSession`, or the rate limiter — the paging loop keeps
    /// the I/O, this keeps the decisions. Pure and static: it returns the marks rather than
    /// writing them, which is what lets a test assert the classification directly and mirrors
    /// ``GraphDeltaSync/partition(_:)``. The two seeders MUST agree; being able to run both
    /// rules side by side under test is the point.
    ///
    /// - Parameter parentGraphID: fallback container for a row whose `parentReference` is absent.
    /// - Parameter log: injected so the pure unit does not reach for the client's logger.
    static func classifyChildrenPage(_ items: [GraphDriveItem],
                                     parentGraphID: String,
                                     translator: BoxcryptorMetadataTranslator,
                                     specialItem: BC01SpecialItem,
                                     log: (String) -> Void = { _ in })
        -> (rows: [CachedItem], encryptedParents: [String]) {
        var encryptedParents: [String] = []
        let rows = items.compactMap { item -> CachedItem? in
            guard !item.isExcludedSpecialItem else {
                log("🚫 /children: skipping special item id=\(item.id) name=\(item.name ?? "<nil>")")
                return nil
            }
            let name = item.name ?? item.id
            guard !specialItem.isSpecial(name: name, isFolder: item.isFolder) else {
                // BC01 bookkeeping: never cached. `/children` returns only live items, so
                // anything special here that is also evidence marks the enclosing folder.
                // Same rule as the delta seeder (`GraphDeltaSync.partition`) — the two MUST
                // agree, or a folder key hidden on one path reappears via the other.
                if specialItem.isFolderKeyEvidence(name: name, isFolder: item.isFolder) {
                    encryptedParents.append(item.parentReference?.id ?? parentGraphID)
                }
                return nil
            }
            let remoteFileSize = item.size ?? 0
            // Same rule as the delta seeder (`GraphDeltaSync.partition`): a name that is not
            // backend-encrypted has plaintext == ciphertext, so the size is exactly known here
            // and is recorded; anything encrypted stays nil until a header probe resolves it.
            // The two seeders MUST agree — `plaintext_size` is folded into the content version,
            // so seeding a plain file NULL here and `remoteFileSize` from delta flips every
            // such file's version once per cold folder and makes the framework re-read a set of
            // fields that did not change.
            let plaintextSize: Int64? =
                (item.isFolder || translator.isBackendEncrypted(name)) ? nil : remoteFileSize
            return CachedItem(
                graphID: item.id,
                parentGraphID: item.parentReference?.id ?? parentGraphID,
                name: name,
                isFolder: item.isFolder,
                remoteFileSize: remoteFileSize,
                eTag: item.eTag, cTag: item.cTag,
                createdDate: item.createdDateTime,
                modifiedDate: item.lastModifiedDateTime,
                deleted: false, rank: 0,
                plaintextSize: plaintextSize)
        }
        return (rows, encryptedParents)
    }

    /// Fetch all children of `parentGraphID` via paginated `/children`, seed the cache,
    /// and return the resulting rows. Pages through `@odata.nextLink` until exhausted.
    ///
    /// Graph is the authority here: if a child appears live in `/children` but is locally
    /// tombstoned (e.g. restored via the OneDrive web UI), the tombstone is cleared via
    /// `resurrectItem` before the upsert so the item reappears in Finder.
    private func fetchAndCacheChildren(parentGraphID: String, cache: MetadataCache) async throws -> [CachedItem] {
        // `$top=999` (Graph's practical ceiling) rather than the 200-item default: the walk is
        // serial on `@odata.nextLink`, so page size is a direct multiplier on how long a large
        // folder blocks its own first enumeration — 25 round-trips become 5 for 5000 children.
        var nextURL: URL? = URL(string: Self.graphBase
            .appendingPathComponent("me/drive/items/\(parentGraphID)/children")
            .absoluteString + "?$top=999")
        while let url = nextURL {
            let page: GraphCollection<GraphDriveItem> = try await getJSON(absoluteURL: url)
            // Seed each page in a single transaction. Per-row `upsert` cost one
            // `BEGIN IMMEDIATE`/`COMMIT` (and one WAL fsync) per child, which on a large
            // cold folder serialised hundreds/thousands of fsyncs on the shared cache queue
            // — the dominant cause of 10–20 s folder-population latency. `upsertBatch` does
            // one transaction and one fsync per page instead.
            let classified = Self.classifyChildrenPage(page.value,
                                                       parentGraphID: parentGraphID,
                                                       translator: metadataTranslator(),
                                                       specialItem: specialItem(),
                                                       log: { [logger] in logger.infoPublic($0) })
            let rows = classified.rows
            // `Set` de-dupes: one `meta` write per folder per page, not per child row.
            for parent in Set(classified.encryptedParents) { cache.markFolderEncrypted(parent) }
            // Graph is authoritative: resurrect any tombstoned items that appear as live
            // children (e.g. restored via OneDrive web UI). upsertBatch's MAX(deleted,…)
            // guard would otherwise keep them invisible.
            // One batched probe, not one per child: the per-row form paid a serial-queue hop
            // and a fresh prepared statement for every row, which dominated the first-open
            // latency of a large cold folder. Tombstones are rare, so `tombstoned` is
            // normally empty and this loop does nothing.
            let tombstoned = (try? cache.tombstonedIDs(among: rows.map(\.graphID))) ?? []
            for row in rows where tombstoned.contains(row.graphID) {
                try? cache.resurrectItem(graphID: row.graphID,
                                         parentGraphID: row.parentGraphID,
                                         name: row.name)
            }
            try cache.upsertBatch(rows)
            nextURL = page.nextLink.flatMap(URL.init)
        }
        return try cache.children(ofParentGraphID: parentGraphID)
    }

    public func latestRank(_ folder: DomainService.ItemIdentifier) async throws -> DomainService.LatestRankReturn {
        let cache = try metadataCache()
        return DomainService.LatestRankReturn(rank: DomainService.RankToken(rank: cache.currentRank(), tokenCheckNumber: 0))
    }

    public func listChanges(_ folder: DomainService.ItemIdentifier, recursive: Bool,
                            startingRank: DomainService.RankToken) async throws -> DomainService.ListChangesReturn {
        let root = try await rootGraphID()
        let cache = try metadataCache()

        // Pure local read: this never runs a delta pass. Fetching the remote from here
        // coupled the drain to the crawl — draining the backlog to empty triggered a pass
        // that appended ~1000 more rows, so the framework's own catch-up kept extending the
        // work it was catching up on, and during an initial crawl the two ran as a loop that
        // only ended when the whole drive was enumerated. Crawl progress belongs to
        // ``DeltaPoller`` (and the per-page signal path); this call reports what the cache
        // already holds.

        // Page the changeset. The File Provider framework caps a *page* (everything
        // between two `finishEnumeratingChanges` calls) at 20000 items, so we cap each
        // `listChanges` response below that and report the last row's rank as the resume
        // anchor; the enumerator forwards `hasMore` as `moreComing: true` and the framework
        // re-calls `enumerateChanges` from there. Rows are rank-ordered, so this is stable.
        let pageLimit = Self.changesPageLimit
        let changedRows = try cache.itemsChanged(sinceRank: startingRank.rank, limit: pageLimit + 1)
        let hasMore = changedRows.count > pageLimit
        let pageRows = hasMore ? Array(changedRows.prefix(pageLimit)) : changedRows

        var updated: [DomainService.Entry] = []
        var deleted: [DomainService.ItemIdentifier] = []
        for row in pageRows {
            switch row.lifecycle {
            case .purged:
                // Permanently deleted: tell the framework to remove it.
                deleted.append(GraphMapping.itemIdentifier(graphID: row.graphID, rootGraphID: root))
            case .trashed:
                // Emit as an update with .trashContainer parent so the framework moves the
                // item into trash rather than removing it (which leaves a ghost).
                updated.append(entry(from: row, rootGraphID: root))
            case .live:
                updated.append(entry(from: row, rootGraphID: root))
            }
        }
        // Resume anchor: last emitted row's rank when paging, else the high-water mark
        // (so a final empty page advances the client to "fully caught up").
        let resumeRank = hasMore ? (pageRows.last?.rank ?? startingRank.rank) : cache.currentRank()
        let newRank = DomainService.RankToken(rank: resumeRank, tokenCheckNumber: 0)
        return DomainService.ListChangesReturn(entries: updated,
                                               deletedEntries: deleted.isEmpty ? nil : deleted,
                                               rank: newRank, hasMore: hasMore)
    }

    /// Build a ``DomainService/Entry`` from a cached row (mirrors ``GraphMapping/entry``),
    /// overlaying any local-only metadata stored on the row — Finder `tagData` and extended
    /// attributes (which include the heart / pinned / isShared marks) — so tags and
    /// decorations resolve. The remote item carries none of these, so the row's values are
    /// the entire set. Overlaying here covers every cache read path: fetchItem, enumeration,
    /// listChanges, and the item returned by `downloadToFile` on materialisation.
    private func entry(from row: CachedItem, rootGraphID: String) -> DomainService.Entry {
        let item = GraphDriveItem(
            id: row.graphID, name: row.name, eTag: row.eTag, cTag: row.cTag, size: row.remoteFileSize,
            createdDateTime: row.createdDate, lastModifiedDateTime: row.modifiedDate,
            parentReference: GraphDriveItem.ParentReference(driveId: nil, id: row.parentGraphID, path: nil),
            file: row.isFolder ? nil : GraphDriveItem.FileFacet(mimeType: nil),
            folder: row.isFolder ? GraphDriveItem.FolderFacet(childCount: nil) : nil,
            deleted: row.deleted ? GraphDriveItem.DeletedFacet(state: "deleted") : nil
        )
        var base = GraphMapping.entry(from: item, rootGraphID: rootGraphID, translator: self.metadataTranslator(),
                                      plaintextSize: row.plaintextSize)
        // Trashed items must report .trashContainer as their parent so Finder places them
        // in the correct container and "Put Back" can detect the tombstone state.
        if row.isTrashed {
            // [trash] Every emit of a tombstoned row (working set + trash enumeration).
            // If two emits disagree on parent, or `id`/`name` show a placeholder like "graph",
            // that mismatch is symptom C (framework issues a doomed PATCH → 404 → un-restorable).
            logger.infoPublic("🗑️ [trash] entry(from:) trashed row graph_id=\(row.graphID) name=\(base.name) mapped_id=\(base.id.id) → parent=\(Self.trashItemIdentifier.id) (row.parent=\(row.parentGraphID ?? "<nil>"))")
            base = DomainService.Entry(name: base.name, id: base.id, parent: Self.trashItemIdentifier,
                                       revision: base.revision, deleted: base.deleted, size: base.size,
                                       children: base.children, type: base.type, metadata: base.metadata,
                                       userInfo: base.userInfo)
        }
        let contentError = row.localMetadata.contentError
        // `restorable` gates the custom Restore action and only applies to a tombstoned row that
        // was trashed out-of-band (no native "Put Back"). A live row never carries it.
        let isTrashed = row.isTrashed
        let restorable: Bool? = (isTrashed
                                 && row.localMetadata.restorableOutOfBand == true) ? true : nil
        let userInfo = (contentError == true || restorable == true || isTrashed)
            ? DomainService.Entry.UserInfo(
                conflictCount: base.userInfo.conflictCount,
                originatorName: base.userInfo.originatorName,
                symlinkTargetPath: base.userInfo.symlinkTargetPath,
                implicitLockOwner: base.userInfo.implicitLockOwner,
                quotaRemaining: base.userInfo.quotaRemaining,
                quotaTotal: base.userInfo.quotaTotal,
                contentError: contentError == true ? true : nil,
                restorable: restorable,
                trashed: isTrashed ? true : nil)
            : base.userInfo
        guard let overlay = Self.localOverlay(row.localMetadata) else {
            return DomainService.Entry(name: base.name, id: base.id, parent: base.parent, revision: base.revision,
                                       deleted: base.deleted, size: base.size, children: base.children,
                                       type: base.type, metadata: base.metadata, userInfo: userInfo)
        }
        let metadata = base.metadata.merge(overlay)
        return DomainService.Entry(name: base.name, id: base.id, parent: base.parent, revision: base.revision,
                                   deleted: base.deleted, size: base.size, children: base.children,
                                   type: base.type, metadata: metadata, userInfo: userInfo)
    }

    /// Build the `EntryMetadata` overlay carrying the sidecar's local-only fields, or `nil`
    /// when the sidecar is empty (nothing to merge). The single point that translates stored
    /// `LocalMetadata` back into an `EntryMetadata` for vending.
    private static func localOverlay(_ local: LocalMetadata) -> DomainService.EntryMetadata? {
        guard !local.isEmpty else { return nil }
        var valid: DomainService.EntryMetadata.ValidEntries = []
        if !local.extendedAttributes.isEmpty { valid.insert(.extendedAttributes) }
        if local.tagData != nil { valid.insert(.tagData) }
        return DomainService.EntryMetadata(
            fileSystemFlags: nil, lastUsedDate: nil, tagData: local.tagData, favoriteRank: nil,
            creationDate: nil, contentModificationDate: nil,
            extendedAttributes: local.extendedAttributes.isEmpty
                ? nil
                : DomainService.EntryMetadata.ExtendedAttributes(values: local.extendedAttributes),
            typeAndCreator: nil, validEntries: valid)
    }

    // MARK: - Lock lifecycle (advisory; OneDrive Personal has no presence locking)

    public func pingLock(_ identifier: DomainService.ItemIdentifier, owner: String, enumerationIndex: Int64) {}
    public func removeLock(_ identifier: DomainService.ItemIdentifier, enumerationIndex: Int64) {}
    public func forceLock(_ identifier: DomainService.ItemIdentifier,
                          _ block: @escaping (Result<DomainService.ForceLockReturn, Error>) -> Void) -> Progress {
        block(.failure(CommonError.notImplemented)); return Progress()
    }

    // MARK: - Content

    // OneDrive has no resource-fork store: `supportsResourceFork` defaults to `false` and
    // `fetchResourceFork` defaults to empty `Data()` with no network call (see `ProviderBackend`).
    // All content materialisation goes through `downloadToFile` below

    // MARK: - Streaming download to file (whole-file + ranged, offset writes, progress)

    public func downloadToFile(_ parameter: DomainService.DownloadItemParameter,
                               destinationURL: URL,
                               progress: Progress,
                               _ block: @escaping (Result<DomainService.DownloadToFileReturn, Error>) -> Void) -> Progress {
        // Single path for whole-file AND explicit byte-range (BRM) fetches: the shared streaming
        // pipeline fetches, decrypts, and writes plaintext at offset, threading the header cache.
        let task = Task {
            do {
                let result = try await self.downloadToFileWithRetry(
                    parameter: parameter, destinationURL: destinationURL, progress: progress)
                block(.success(result))
            } catch is CancellationError {
                try? FileManager.default.removeItem(at: destinationURL)
                block(.failure(NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)))
            } catch {
                try? FileManager.default.removeItem(at: destinationURL)
                self.logger.errorPublic("❌ downloadToFile failed: \(String(describing: error))")
                block(.failure(error))
            }
        }
        progress.cancellationHandler = { task.cancel() }
        return progress
    }

    private func downloadToFileWithRetry(
        parameter: DomainService.DownloadItemParameter,
        destinationURL: URL,
        progress: Progress,
        maxAttempts: Int = 4
    ) async throws -> DomainService.DownloadToFileReturn {
        var lastError: Error = CommonError.internalError
        for attempt in 0..<maxAttempts {
            if Task.isCancelled { throw CancellationError() }
            if attempt > 0 {
                try? FileManager.default.removeItem(at: destinationURL)
                let delay = await limiter.backoffDelay(attempt: attempt - 1)
                logger.warningPublic("⚠️ downloadToFile retry \(attempt)/\(maxAttempts - 1) for \(parameter.itemIdentifier.id) after: \(String(describing: lastError))")
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
            do {
                let root = try await self.rootGraphID()
                let graphID = GraphMapping.graphID(for: parameter.itemIdentifier, rootGraphID: root)

                // Resolve the entry concurrently with setting up the transfer; usually cached.
                async let entryTask: DomainService.Entry =
                    self.cachedEntry(graphID: graphID, rootGraphID: root)

                // A missing/failed cache row must not silently become size 0: that yields an empty
                // fetch window and a zero-byte "successful" download. The remote size is required
                // input to the transfer, so its absence is an error, not a default. A row that is
                // present and says 0 is a different thing entirely — a genuinely empty file, whose
                // correct materialisation is a 0-byte destination — so presence, not size, is the test.
                guard let cachedRow = try? self.metadataCache().item(graphID: graphID) else {
                    throw CommonError.itemNotFound(parameter.itemIdentifier)
                }
                let remoteTotalSize = cachedRow.remoteFileSize
                let entry = try await entryTask
                let isEncrypted = self.metadataTranslator().isBackendEncrypted(entry.name)
                let decryptor = try self.makeDecryptor(filename: entry.name, encrypted: isEncrypted)

                let fetcher = GraphContentFetcher(client: self, graphID: graphID, totalSize: Int(remoteTotalSize))
                let (plaintextWindow, wholeFileSize) = try await StreamingDownload.run(
                    fetcher: fetcher,
                    decryptor: decryptor,
                    isEncrypted: isEncrypted,
                    itemIdentifier: parameter.itemIdentifier,
                    // Graph always serves the current content, so key the header cache on the
                    // cached (mutation-reseeded) revision — not the OS-requested one, which is
                    // nil on materialise and would pin a stale header across saves.
                    revision: entry.revision,
                    plaintextRange: StreamingDownload.plaintextRange(from: parameter.range),
                    destinationURL: destinationURL,
                    progress: progress,
                    headerCache: self.headerCache,
                    lanes: UserDefaults.sharedContainerDefaults.parallelDownloadLanes,
                    threshold: UserDefaults.sharedContainerDefaults.parallelDownloadThreshold,
                    maxSpanBytes: UserDefaults.sharedContainerDefaults.maxDownloadSpanBytes,
                    cryptoReporter: ProgressStoreCryptoReporter(domainID: self.domainID),
                    itemName: entry.name,
                    onPlaintextSizeResolved: self.plaintextSizeRecorder(graphID: graphID))

                if Task.isCancelled { throw CancellationError() }
                // Persist the header-derived plaintext length
                await self.recordPlaintextSize(wholeFileSize, graphID: graphID)
                return DomainService.DownloadToFileReturn(
                    item: entry, plaintextWindow: plaintextWindow,
                    wholeFilePlaintextSize: wholeFileSize)
            } catch is CancellationError {
                throw CancellationError()
            } catch let nsError as NSError
                    where nsError.domain == NSFileProviderErrorDomain
                       || nsError.domain == NSCocoaErrorDomain {
                // Non-retryable: auth failures, cancellation.
                throw nsError
            } catch CommonError.itemNotFound(let id) {
                throw CommonError.itemNotFound(id)
            } catch CommonError.wrongRevision(let entry) {
                throw CommonError.wrongRevision(entry)
            } catch let streamError as ContentStreamError {
                // A truncated body is transient (early-terminated CDN response); retry the whole
                // transfer. The partial destination file is removed at the top of the next attempt.
                lastError = streamError
                logger.warningPublic("⚠️ truncated download for \(parameter.itemIdentifier.id): \(String(describing: streamError))")
                continue
            } catch CommonError.httpError(let response) {
                // Non-retryable 4xx (403, 404 etc.); 409 is already retried in perform().
                guard let http = response as? HTTPURLResponse,
                      (500...599).contains(http.statusCode) else {
                    throw CommonError.httpError(response)
                }
                lastError = CommonError.httpError(response)
                continue
            } catch let e as DecodingError {
                // Non-retryable: malformed BC01 header JSON — persist the error flag and re-throw.
                try? await self.flagContentError(itemIdentifier: parameter.itemIdentifier)
                throw e
            } catch let e as BC01Error {
                // Non-retryable: bad magic, truncation, key failure — persist the error flag and re-throw.
                try? await self.flagContentError(itemIdentifier: parameter.itemIdentifier)
                throw e
            } catch {
                lastError = error
                // Transient: network error — retry.
                continue
            }
        }
        throw lastError
    }

    /// Record an item's exact plaintext length, learned from its BC01 header during this
    /// download, and signal the working set if it changed.
    private func recordPlaintextSize(_ size: Int64, graphID: String) async {
        do {
            guard try metadataCache().setPlaintextSize(size, graphID: graphID) else { return }
        } catch {
            logger.warningPublic("⚠️ could not record plaintext size for graphID=\(graphID): \(String(describing: error))")
            return
        }
    }

    /// Sink that persists a header-derived plaintext length the moment the header is probed,
    /// keeping `plaintext_size` in step with the ``BC01HeaderCache`` row stored alongside it.
    private func plaintextSizeRecorder(graphID: String) -> @Sendable (Int64) -> Void {
        { [weak self] size in
            do {
                try self?.metadataCache().setPlaintextSize(size, graphID: graphID)
            } catch {
                self?.logger.warningPublic("⚠️ could not record plaintext size for graphID=\(graphID): \(String(describing: error))")
            }
        }
    }

    /// Record the plaintext size of a just-uploaded item, from the plaintext still on disk.
    ///
    /// An upload is the one moment the true plaintext length is known for free — no header
    /// probe, no round trip. The write clears `plaintext_size` (new cTag), and this
    /// immediately puts the right value back, so the item never shows the estimate.
    private func recordUploadedPlaintextSize(sourceURL: URL, graphID: String) {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: sourceURL.path),
              let size = (attrs[.size] as? NSNumber)?.int64Value else { return }
        try? metadataCache().setPlaintextSize(size, graphID: graphID)
    }

    /// Persist `contentError = true` in the local metadata of the given item, bumping its
    /// rank so `enumerateChanges` delivers the updated `fileError` decoration to the system.
    /// Signals `.workingSet` so Finder re-enumerates immediately without waiting for a delta poll.
    private func flagContentError(itemIdentifier: DomainService.ItemIdentifier) async throws {
        let root = try await self.rootGraphID()
        let graphID = GraphMapping.graphID(for: itemIdentifier, rootGraphID: root)
        try self.metadataCache().setContentError(true, graphID: graphID)
        logger.warningPublic("⚠️ flagged contentError for graphID=\(graphID)")
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: domainID),
                                          displayName: domainID)
        if let fpManager = NSFileProviderManager(for: domain) {
            try? await fpManager.signalEnumerator(for: .workingSet)
        }
    }

    /// Build a content decryptor for this domain, mirroring the Extension's policy gate:
    /// non-encrypted (or `.plain` algorithm) → ``PlainFileDecryptor``; BC01 → load the
    /// session RSA key. Throws ``NSFileProviderError/notAuthenticated`` if the key is missing.
    private func makeDecryptor(filename: String, encrypted: Bool) throws -> any FileDecryptor {
        guard encrypted else { return PlainFileDecryptor() }
        return try BC01DecryptorFactory.make(for: NSFileProviderDomainIdentifier(rawValue: domainID))
    }

    /// A single ranged content GET (`bytes=start-end`), retried until the body is complete.
    ///
    /// Graph (via its CDN redirect) can terminate a content response early: `URLSession` surfaces
    /// that as a **successful** request whose body is simply shorter than the requested range, with
    /// no thrown error. Accepting it silently is what materialised truncated files — plain content
    /// carries no magic, MAC, or padding for a later stage to fail on, so a short body is written
    /// to disk and reported to the OS as a complete file.
    ///
    /// Two defences: a `200` (range ignored, whole object served) is only usable when the request
    /// covered the whole object, and a short `206` body is retried with backoff before failing.
    ///
    /// "Short" is measured against what the object can actually supply, not the requested length:
    /// a caller may ask past EOF (the last span of a transfer routinely does), and the server
    /// correctly answers with the remaining bytes. `Content-Range`'s total is authoritative for
    /// that; without it the requested length is the only bound available.
    private func contentRange(url: URL, start: Int, length: Int) async throws -> Data {
        var attempt = 0
        var lastReceived = -1
        while true {
            let (data, response) = try await self.perform { token in
                var req = URLRequest(url: url)
                req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                req.setValue("bytes=\(start)-\(start + length - 1)", forHTTPHeaderField: "Range")
                return req
            }

            // A 200 means the Range header was ignored and the whole object was sent. That is only
            // the requested bytes when the request started at 0 and asked for everything.
            if response.statusCode == 200, start > 0 || data.count != length {
                guard data.count >= start + length else {
                    throw ContentStreamError.shortRead(start: start, expected: length,
                                                       received: max(0, data.count - start))
                }
                return data.subdata(in: start..<(start + length))
            }

            // Expected byte count for this request: `min(length, totalSize - start)` when the
            // server told us the object's total, else the requested length.
            let expected: Int
            if let total = Self.contentRangeTotal(response), total > start {
                expected = min(length, total - start)
            } else {
                expected = length
            }
            if data.count >= expected { return data }

            lastReceived = data.count
            guard attempt < limiter.maxRetries else { break }
            logger.warningPublic("⚠️ short ranged GET \(url.lastPathComponent) [\(start),+\(length)) got \(data.count) bytes; retry \(attempt + 1)/\(limiter.maxRetries)")
            let delay = await limiter.backoffDelay(attempt: attempt)
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            attempt += 1
        }
        throw ContentStreamError.shortRead(start: start, expected: length, received: lastReceived)
    }

    /// Total object length from a `Content-Range: bytes <start>-<end>/<total>` header, or `nil`
    /// when absent or unparseable (`*` total included).
    private static func contentRangeTotal(_ response: HTTPURLResponse) -> Int? {
        guard let value = response.value(forHTTPHeaderField: "Content-Range"),
              let slash = value.lastIndex(of: "/") else { return nil }
        return Int(value[value.index(after: slash)...].trimmingCharacters(in: .whitespaces))
    }

    public func createFolder(_ parameter: DomainService.CreateParameter,
                             _ block: @escaping (Result<DomainService.CreateReturn, Error>) async -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let task = Task {
            do {
                let root = try await self.rootGraphID()
                let parentGraphID = GraphMapping.graphID(for: parameter.parent, rootGraphID: root)
                let entry = try await self.createFolder(name: parameter.name, parentGraphID: parentGraphID,
                                                        rootGraphID: root)
                await block(.success(DomainService.CreateReturn(item: entry)))
                progress.completedUnitCount = 1
            } catch {
                await block(.failure(error))
            }
        }
        progress.cancellationHandler = { task.cancel() }
        return progress
    }

    private func createFolder(name: String, parentGraphID: String, rootGraphID: String) async throws -> DomainService.Entry {
        let url = Self.graphBase.appendingPathComponent("me/drive/items/\(parentGraphID)/children")
        let body: [String: Any] = [
            "name": name,
            "folder": [:],
            "@microsoft.graph.conflictBehavior": "rename"
        ]
        let payload = try JSONSerialization.data(withJSONObject: body)
        let (respData, _) = try await perform { token in
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payload
            return req
        }
        let item = try decoder.decode(GraphDriveItem.self, from: respData)
        // Reseed the cache with the created row so cached reads (fetchItem / enumeration)
        // and the held revision reflect the new item before delta sync catches up.
        if let cache = try? self.metadataCache() {
            _ = try? cache.upsert(Self.cachedItem(from: item, translator: self.metadataTranslator()))
        }
        return GraphMapping.entry(from: item, rootGraphID: rootGraphID, translator: self.metadataTranslator())
    }

    /// OneDrive has no resource-fork store (``supportsResourceFork`` is `false`) and file contents
    /// always upload through ``modifyContentsStreaming(_:contentsAt:originalFilename:encryptor:progress:)``,
    /// so this is never reached.
    public func modifyContents(_ parameter: DomainService.ModifyContentsParameter, data: Data?,
                               _ block: @escaping (Result<DomainService.ModifyContentsReturn, Error>) -> Void) -> Progress {
        block(.failure(CommonError.notImplemented)); return Progress()
    }

    /// Persist a metadata change. Rename / reparent go to Graph (PATCH); Finder
    /// `tagData` / extended attributes have no Graph home and go to the `local_meta`
    /// sidecar. Returns the authoritative item with both reflected.
    public func modifyMetadata(_ parameter: DomainService.ModifyMetadataParameter,
                               _ block: @escaping (Result<DomainService.ModifyMetadataReturn, Error>) -> Void) -> Progress {
        bridge(block) {
            let root = try await self.rootGraphID()
            let graphID = GraphMapping.graphID(for: parameter.itemIdentifier, rootGraphID: root)

            // Rename / move: the only metadata Graph can persist. Skip the PATCH when neither
            // is present (a tags/xattrs-only modify) — it would be an empty, pointless body.
            if parameter.filename != nil || parameter.parent != nil {
                try await self.patchRemoteMetadata(parameter, graphID: graphID, rootGraphID: root)
            }

            // Local-only fields (tags / xattrs): persist to the sidecar so they survive
            // materialisation and re-enumeration. Nothing is uploaded.
            try self.storeLocalMetadata(graphID: graphID) { $0.merging(parameter.metadata) }

            // Return the cache row (PATCH result reseeded by delta; sidecar merged on read),
            // so the authoritative item always carries the just-persisted tags/xattrs.
            let entry = try await self.cachedEntry(graphID: graphID, rootGraphID: root)
            return DomainService.ModifyMetadataReturn(item: entry, metadataWasRolledBack: false)
        }
    }

    /// PATCH a rename / reparent to Graph and reseed the resulting row into the cache.
    private func patchRemoteMetadata(_ parameter: DomainService.ModifyMetadataParameter,
                                     graphID: String, rootGraphID root: String) async throws {
        var body: [String: Any] = [:]
        if let filename = parameter.filename { body["name"] = filename }
        if let parent = parameter.parent {
            body["parentReference"] = ["id": GraphMapping.graphID(for: parent, rootGraphID: root)]
        }
        let url = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)")
        let payload = try JSONSerialization.data(withJSONObject: body)
        // No `If-Match` on rename / reparent. OneDrive bumps a freshly created item's eTag
        // server-side within a second or two of the create POST (indexing / processing), so
        // the eTag the extension is holding — the one returned by the create — is already
        // stale by the time Finder issues the "Untitled" → real-name rename. With `If-Match`
        // that PATCH 412s (`wrongRevision`), which `toPresentableError` surfaces as an opaque
        // `NSXPCConnectionReplyInvalid`; FileProvider can't retry it, so the rename is dropped
        // and the folder is stranded as "Untitled" on the backend. A rename / move can't lose
        // data the way a content PUT can, so dropping optimistic concurrency here is safe; the
        // content PUT in `modifyContents` keeps its `If-Match`.
        let (respData, _) = try await self.perform { token in
            var req = URLRequest(url: url)
            req.httpMethod = "PATCH"
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payload
            return req
        }
        let item = try self.decoder.decode(GraphDriveItem.self, from: respData)
        if let cache = try? self.metadataCache() {
            try? cache.upsert(Self.cachedItem(from: item, translator: self.metadataTranslator()))
        }
    }

    public func deleteItem(_ parameter: DomainService.DeleteItemParameter,
                           _ block: @escaping (Result<DomainService.DeleteItemReturn, Error>) -> Void) -> Progress {
        bridge(block) {
            let root = try await self.rootGraphID()
            let graphID = GraphMapping.graphID(for: parameter.itemIdentifier, rootGraphID: root)
            let cache = try self.metadataCache()

            // Empty-trash path: item is already in the OneDrive recycle bin (moved there by an
            // earlier trashItem call). Graph has no supported permanent-delete endpoint, so just
            // purge the local row — no network call needed.
            if let cached = try? cache.itemIncludingDeleted(graphID: graphID),
               cached.isTrashed {
                try? cache.purgeItem(graphID: graphID)
                self.invalidateCachedHeader(graphID: graphID)
                return DomainService.DeleteItemReturn()
            }

            // Live item: issue Graph DELETE (moves to recycle bin, not permanent).
            let url = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)")
            do {
                _ = try await self.perform { token in
                    var req = URLRequest(url: url)
                    req.httpMethod = "DELETE"
                    req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                    return req
                }
            } catch CommonError.itemNotFound {
                try? cache.purgeItem(graphID: graphID)
                self.invalidateCachedHeader(graphID: graphID)
                throw CommonError.itemNotFound(parameter.itemIdentifier)
            }
            // Tombstone without deletedAt: permanently gone from the drive tree (not in trash).
            try? cache.markDeleted(graphID: graphID)
            self.invalidateCachedHeader(graphID: graphID)
            return DomainService.DeleteItemReturn()
        }
    }

    public func trashItem(_ parameter: DomainService.TrashItemParameter,
                          _ block: @escaping (Result<DomainService.TrashItemReturn, Error>) -> Void) -> Progress {
        // OneDrive's DELETE moves items to the recycle bin; surface the post-delete item.
        bridge(block) {
            let root = try await self.rootGraphID()
            let graphID = GraphMapping.graphID(for: parameter.itemIdentifier, rootGraphID: root)
            // Fetch current metadata for the return entry (name, revision, etc.).
            let item: GraphDriveItem
            do {
                item = try await self.getJSON(path: "/me/drive/items/\(graphID)")
            } catch CommonError.itemNotFound {
                try? self.metadataCache().purgeItem(graphID: graphID)
                self.invalidateCachedHeader(graphID: graphID)
                throw CommonError.itemNotFound(parameter.itemIdentifier)
            }
            let url = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)")
            do {
                _ = try await self.perform { token in
                    var req = URLRequest(url: url)
                    req.httpMethod = "DELETE"
                    req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                    return req
                }
            } catch CommonError.itemNotFound {
                try? self.metadataCache().purgeItem(graphID: graphID)
                self.invalidateCachedHeader(graphID: graphID)
                throw CommonError.itemNotFound(parameter.itemIdentifier)
            }
            // Tombstone with deletedAt so the item appears in trash enumeration. Pass the
            // authoritative name/parent from the fresh fetch so the trashed row never surfaces
            // a stale or placeholder (graph-id) name after re-enumeration.
            try? self.metadataCache().markTrashed(graphID: graphID, deletedAt: Date(),
                                                  name: item.name,
                                                  parentGraphID: item.parentReference?.id,
                                                  outOfBand: parameter.outOfBand)
            self.invalidateCachedHeader(graphID: graphID)
            // Return the entry with .trashContainer as parent.
            var trashEntry = GraphMapping.entry(from: item, rootGraphID: root, translator: self.metadataTranslator())
            trashEntry = DomainService.Entry(name: trashEntry.name, id: trashEntry.id,
                                             parent: Self.trashItemIdentifier,
                                             revision: trashEntry.revision, deleted: trashEntry.deleted,
                                             size: trashEntry.size, children: trashEntry.children,
                                             type: trashEntry.type, metadata: trashEntry.metadata,
                                             userInfo: trashEntry.userInfo)
            return DomainService.TrashItemReturn(item: trashEntry, metadataWasRolledBack: false)
        }
    }

    public var supportsRestore: Bool { true }

    /// Returns `true` when the cached row for `identifier` is a trash tombstone
    /// (deleted=1 with a deletedAt timestamp). Used by the Extension to detect a
    /// "Put Back" restore gesture versus a normal reparent move.
    public func isItemTrashed(_ identifier: DomainService.ItemIdentifier) throws -> Bool {
        let root = rootGraphIDCache ?? ((try? metadataCache())?.rootGraphID() ?? "")
        let graphID = GraphMapping.graphID(for: identifier, rootGraphID: root)
        guard let cached = try metadataCache().itemIncludingDeleted(graphID: graphID) else {
            return false
        }
        return cached.isTrashed
    }

    public func restoreItem(_ parameter: DomainService.RestoreItemParameter,
                            _ block: @escaping (Result<DomainService.RestoreItemReturn, Error>) -> Void) -> Progress {
        bridge(block) {
            let root = try await self.rootGraphID()
            let graphID = GraphMapping.graphID(for: parameter.itemIdentifier, rootGraphID: root)
            // OneDrive's POST /restore ignores any `parentReference` in the body — it always
            // returns the item to its ORIGINAL parent. So restore unconditionally, then, if the
            // caller asked for a different destination (drag out of Trash into a new folder),
            // issue a follow-up Move (PATCH parentReference) to relocate the now-live item.
            let url = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)/restore")
            let respData = try await self.perform { token in
                var req = URLRequest(url: url)
                req.httpMethod = "POST"
                req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                req.setValue("application/json", forHTTPHeaderField: "Content-Type")
                return req
            }.0
            var restoredItem = try self.decoder.decode(GraphDriveItem.self, from: respData)
            // Explicit resurrect: upsert cannot clear tombstones (MAX(deleted,…) guard prevents
            // delta races from resurrecting deleted items), so use the dedicated restore path.
            if let cache = try? self.metadataCache() {
                try? cache.resurrectItem(graphID: restoredItem.id,
                                         parentGraphID: restoredItem.parentReference?.id,
                                         name: restoredItem.name ?? restoredItem.id)
            }

            // Relocate if the caller wants a parent other than where /restore landed it.
            if let targetParent = parameter.targetParentIdentifier {
                let targetGraphID = GraphMapping.graphID(for: targetParent, rootGraphID: root)
                if restoredItem.parentReference?.id != targetGraphID {
                    let moveParam = DomainService.ModifyMetadataParameter(
                        itemIdentifier: DomainService.ItemIdentifier(restoredItem.id),
                        existingRevision: .zero, // patchRemoteMetadata sends no If-Match
                        filename: nil, parent: targetParent,
                        metadata: DomainService.EntryMetadata(
                            fileSystemFlags: nil, lastUsedDate: nil, tagData: nil, favoriteRank: nil,
                            creationDate: nil, contentModificationDate: nil, extendedAttributes: nil,
                            typeAndCreator: nil, validEntries: []))
                    try await self.patchRemoteMetadata(moveParam, graphID: restoredItem.id, rootGraphID: root)
                    // Re-fetch so the returned entry reflects the moved parent/revision.
                    restoredItem = try await self.getJSON(path: "/me/drive/items/\(restoredItem.id)")
                }
            }
            return DomainService.RestoreItemReturn(item: GraphMapping.entry(from: restoredItem, rootGraphID: root, translator: self.metadataTranslator()))
        }
    }

    public func mark(_ parameter: DomainService.MarkParameter,
                     _ block: @escaping (Result<DomainService.MarkReturn, Error>) -> Void) -> Progress {
        // Heart / pin / share marks are local-only on OneDrive — Graph has no field for them.
        // Persist them as xattrs in the MetadataCache (read-modify-write per item) and bump
        // each row's rank so the working-set feed delivers the change; the merged xattrs are
        // then vended on every cache read via `entry(from:)`.
        //
        // `inUse` is intentionally not handled here: its decoration derives from
        // `userInfo.implicitLockOwner` (set via the lock path), not an xattr, so it has no
        // representation in this store. `mark` never carries `inUse` in practice.
        bridge(block) {
            let root = try await self.rootGraphID()
            for identifier in parameter.identifiers {
                let graphID = GraphMapping.graphID(for: identifier, rootGraphID: root)
                try self.storeLocalMetadata(graphID: graphID) { local in
                    var copy = local
                    copy.applyMark(parameter.heart, DomainService.MarkParameter.heartXattr)
                    copy.applyMark(parameter.pinned, DomainService.MarkParameter.pinnedXattr)
                    copy.applyMark(parameter.isShared, DomainService.MarkParameter.isSharedXattr)
                    return copy
                }
            }
            return DomainService.MarkReturn()
        }
    }

    /// Read-modify-write the item's `local_meta` sidecar via `transform`, writing back only
    /// when it changed. `setLocalMetadata` bumps the row's rank so the working-set feed
    /// delivers the change and `entry(from:)` re-vends it on every read — including the item
    /// `downloadToFile` returns, which is what stops Finder dropping tags on materialisation.
    /// The single sidecar-write path shared by `modifyMetadata` and `mark`.
    private func storeLocalMetadata(graphID: String,
                                    _ transform: (LocalMetadata) -> LocalMetadata) throws {
        let cache = try metadataCache()
        let current = (try? cache.item(graphID: graphID))?.localMetadata ?? .empty
        let updated = transform(current)
        guard updated != current else { return }
        try cache.setLocalMetadata(graphID: graphID, updated)
    }

    // MARK: - Thumbnails

    public func fetchThumbnail(_ parameter: DomainService.FetchThumbnailParameter,
                               _ block: @escaping (Result<(response: DomainService.FetchThumbnailReturn, data: Data), Error>) -> Void) -> Progress {
        bridge(block) {
            let root = try await self.rootGraphID()
            let graphID = GraphMapping.graphID(for: parameter.identifier, rootGraphID: root)
            // Resolve the entry first (cache hit, no network) so we can decide per-file
            // whether a server-side thumbnail can exist at all.
            let entry = try await self.cachedEntry(graphID: graphID, rootGraphID: root)

            // Content-encrypted files store ciphertext on the backend, so OneDrive has no
            // usable thumbnail and the `/thumbnails` endpoint 404s. Skip the guaranteed-
            // failing round-trip and report "no thumbnail" (empty data).
            if self.metadataTranslator().isBackendEncrypted(entry.name) {
                self.logger.debugPublic("🔒 encrypted file \(graphID): skipping thumbnail fetch")
                return (DomainService.FetchThumbnailReturn(item: entry), Data())
            }

            // medium thumbnail content
            let url = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)/thumbnails/0/medium/content")
            let (data, _) = try await self.perform { token in
                var req = URLRequest(url: url)
                req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                return req
            }
            return (DomainService.FetchThumbnailReturn(item: entry), data)
        }
    }

    public func updateThumbnail(_ parameter: DomainService.UpdateThumbnailParameter,
                                data: Data) async throws -> DomainService.UpdateThumbnailReturn {
        throw CommonError.notImplemented
    }

    // MARK: - Conflict servicing (server-side conflict copies; nothing to enumerate)

    public func conflictVersions(_ parameter: DomainService.ConflictVersionsParameter,
                                 _ block: @escaping (Result<DomainService.ConflictVersionsReturn, Error>) -> Void) -> Progress {
        block(.failure(CommonError.notImplemented)); return Progress()
    }

    public func resolveConflictVersions(_ parameter: DomainService.ResolveConflictVersionsParameter,
                                        _ block: @escaping (Result<DomainService.ResolveConflictVersionsReturn, Error>) -> Void) -> Progress {
        block(.failure(CommonError.notImplemented)); return Progress()
    }

    // MARK: - Upload sessions (large files)

    /// POST a `createUploadSession` and return the pre-authenticated fragment upload URL.
    ///
    /// `conflictBehavior: replace` is sent explicitly. The default is `fail`, which surfaces only
    /// on the **final** fragment as `409 nameAlreadyExists` — after the entire file has been
    /// uploaded. That is both the worst possible time to learn about it and inconsistent with the
    /// simple-PUT path, which overwrites via `:/content`.
    func createUploadSession(at createURL: URL, eTag: String?) async throws -> URL {
        let body = try JSONSerialization.data(withJSONObject: [
            "item": ["@microsoft.graph.conflictBehavior": "replace"]
        ])
        let (sessionData, _) = try await perform { token in
            var req = URLRequest(url: createURL)
            req.httpMethod = "POST"
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            // Optimistic concurrency is applied at session creation, not per fragment.
            if let eTag { req.setValue(eTag, forHTTPHeaderField: "If-Match") }
            req.httpBody = body
            return req
        }
        let session = try decoder.decode(GraphUploadSession.self, from: sessionData)
        guard let uploadURL = URL(string: session.uploadUrl) else { throw CommonError.internalError }
        return uploadURL
    }

    /// PUT one upload-session fragment, returning the completion body on the final fragment.
    ///
    /// Routed through `perform(authenticated: false)` so fragments inherit the rate limiter and
    /// 429/5xx backoff. The URL is pre-authenticated, so no bearer token is attached. A fragment
    /// PUT is idempotent in its `Content-Range`, so a retried fragment is safe.
    ///
    /// `Content-Length` is deliberately **not** set: it is a reserved header that `URLSession`
    /// owns. Setting it by hand is dropped or conflicts with the length CFNetwork derives from
    /// the body, and Graph answers the resulting `Content-Range`/body-length mismatch with a
    /// `416`. The body is handed over as an upload body so the framework states the length.
    func putFragment(_ bytes: Data, start: Int, totalSize: Int,
                                 uploadURL: URL) async throws -> Data? {
        // A zero-length fragment has no representable `Content-Range`; nothing to send.
        guard !bytes.isEmpty else { return nil }
        let end = start + bytes.count
        let (data, http) = try await perform(authenticated: false, body: bytes) { _ in
            var req = URLRequest(url: uploadURL)
            req.httpMethod = "PUT"
            req.setValue("bytes \(start)-\(end - 1)/\(totalSize)", forHTTPHeaderField: "Content-Range")
            return req
        }
        // 202 = fragment accepted, more expected. 200/201 = upload complete, body is the item.
        return (200...201).contains(http.statusCode) ? data : nil
    }

    /// Abandon an upload session, releasing the server-side reservation. Best-effort.
    func cancelUploadSession(_ uploadURL: URL) async {
        var req = URLRequest(url: uploadURL)
        req.httpMethod = "DELETE"
        _ = try? await session.data(for: req)
    }

    /// Simple `PUT` of a complete object to `contentURL`, returning the driveItem body.
    ///
    /// `If-Match` is applied when `eTag` is set (modify). Used by ``GraphContentPutter`` for
    /// objects within ``simpleUploadLimit``.
    func putWholeContent(_ bytes: Data, contentURL: URL, eTag: String?) async throws -> Data {
        let (respData, _) = try await perform { token in
            var req = URLRequest(url: contentURL)
            req.httpMethod = "PUT"
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            if let eTag { req.setValue(eTag, forHTTPHeaderField: "If-Match") }
            req.httpBody = bytes
            return req
        }
        return respData
    }

    /// Shared streaming upload driver for create and modify.
    ///
    /// The uploader picks a single simple `PUT` when the ciphertext fits ``simpleUploadLimit``;
    /// otherwise the putter opens an upload session on its first fragment. Only a session that
    /// was actually opened is cancelled on failure.
    private func streamUpload(target: GraphContentPutter.Target,
                              eTag: String?,
                              sourceURL: URL,
                              originalFilename: String,
                              encryptor: any FileEncryptor,
                              progress: Progress) async throws -> (item: GraphDriveItem, blockContext: BC01Header?) {
        let putter = GraphContentPutter(transport: self, target: target, eTag: eTag)
        let uploader = ContentStreamUploader(
            putter: putter,
            encryptor: encryptor,
            lanes: UserDefaults.sharedContainerDefaults.parallelUploadLanes)
        do {
            let result = try await uploader.run(from: sourceURL,
                                                originalFilename: originalFilename,
                                                progress: progress)
            return (try decoder.decode(GraphDriveItem.self, from: result.completionPayload), result.blockContext)
        } catch {
            // Release the server-side session so it doesn't linger until expiry.
            await putter.cancelSession()
            throw error
        }
    }

    public func createStreaming(_ parameter: DomainService.CreateParameter,
                                contentsAt sourceURL: URL,
                                originalFilename: String,
                                encryptor: any FileEncryptor,
                                progress: Progress) async throws -> DomainService.CreateReturn {
        let root = try await rootGraphID()
        let parentGraphID = GraphMapping.graphID(for: parameter.parent, rootGraphID: root)
        let itemPath = Self.graphBase.appendingPathComponent(
            "me/drive/items/\(parentGraphID):/\(parameter.name):")
        let target = GraphContentPutter.Target(
            contentURL: itemPath.appendingPathComponent("content"),
            createSessionURL: itemPath.appendingPathComponent("createUploadSession"))

        let (item, blockContext) = try await streamUpload(target: target, eTag: nil,
                                                          sourceURL: sourceURL,
                                                          originalFilename: originalFilename,
                                                          encryptor: encryptor, progress: progress)
        // Mandatory reseed: the eTag/cTag in this row is the source of truth for the If-Match
        // on the next content write. Delta sync alone is too slow — a save straight after a
        // create would 412.
        if let cache = try? metadataCache() { try? cache.upsert(Self.cachedItem(from: item, translator: self.metadataTranslator())) }
        seedHeaderCache(from: item, rootGraphID: root, header: blockContext)
        recordUploadedPlaintextSize(sourceURL: sourceURL, graphID: item.id)
        return DomainService.CreateReturn(item: GraphMapping.entry(from: item, rootGraphID: root, translator: self.metadataTranslator()))
    }

    public func modifyContentsStreaming(_ parameter: DomainService.ModifyContentsParameter,
                                        contentsAt sourceURL: URL,
                                        originalFilename: String,
                                        encryptor: any FileEncryptor,
                                        progress: Progress) async throws -> DomainService.ModifyContentsReturn {
        let root = try await rootGraphID()
        let graphID = GraphMapping.graphID(for: parameter.identifier, rootGraphID: root)
        let itemPath = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)")
        let target = GraphContentPutter.Target(
            contentURL: itemPath.appendingPathComponent("content"),
            createSessionURL: itemPath.appendingPathComponent("createUploadSession"))

        // Optimistic concurrency (412 on a moved server copy). Source the eTag from the cache —
        // reseeded from every mutation's response — NOT the OS `baseVersion`, which lags
        // OneDrive's async eTag bump: a second save before the OS re-materialises would carry a
        // stale baseVersion and 412 (Finder: "changed by another application"). Fall back to the
        // OS revision only on a cold-cache miss.
        let cachedETag = (try? metadataCache().item(graphID: graphID))??.eTag
        let eTag = cachedETag ?? parameter.existingRevision.metadata

        let (item, blockContext) = try await streamUpload(target: target, eTag: eTag,
                                                          sourceURL: sourceURL,
                                                          originalFilename: originalFilename,
                                                          encryptor: encryptor, progress: progress)
        if let cache = try? metadataCache() { try? cache.upsert(Self.cachedItem(from: item, translator: self.metadataTranslator())) }
        // The upload re-encrypted under a fresh file key/IV: store the new header now.
        seedHeaderCache(from: item, rootGraphID: root, header: blockContext)
        recordUploadedPlaintextSize(sourceURL: sourceURL, graphID: item.id)
        // Re-read the row so the returned version carries the plaintext size just persisted,
        // matching what enumeration will emit for this item.
        let persistedSize = (try? metadataCache())
            .flatMap { try? $0.itemIncludingDeleted(graphID: item.id) }?.plaintextSize
        let entry = GraphMapping.entry(from: item, rootGraphID: root, translator: self.metadataTranslator(), plaintextSize: persistedSize)
        return DomainService.ModifyContentsReturn(item: entry, contentAccepted: true)
    }

    /// Ranged content fetch used by ``GraphContentFetcher``. Routes through ``perform`` so it
    /// inherits auth-refresh and throttle/backoff handling.
    fileprivate func fetchContentRange(graphID: String, start: Int, length: Int) async throws -> Data {
        let url = Self.graphBase.appendingPathComponent("me/drive/items/\(graphID)/content")
        return try await contentRange(url: url, start: start, length: length)
    }
}

/// The Graph upload calls ``GraphContentPutter`` drives: a narrow seam over ``GraphDriveClient``
/// so the putter's session lifecycle is testable without a live drive.
protocol GraphUploadTransport: AnyObject {
    /// Simple `PUT` of a complete object; returns the driveItem body.
    func putWholeContent(_ bytes: Data, contentURL: URL, eTag: String?) async throws -> Data
    /// `POST createUploadSession`; returns the pre-authenticated fragment URL.
    func createUploadSession(at createURL: URL, eTag: String?) async throws -> URL
    /// `PUT` one session fragment; returns the driveItem body on the final fragment.
    func putFragment(_ bytes: Data, start: Int, totalSize: Int, uploadURL: URL) async throws -> Data?
    /// `DELETE` an upload session. Best-effort.
    func cancelUploadSession(_ uploadURL: URL) async
}

extension GraphDriveClient: GraphUploadTransport {}

/// ``ContentPutting`` adapter over Graph: a complete object within ``GraphDriveClient/simpleUploadLimit``
/// is one simple `PUT`; anything larger streams through an upload session created lazily on the
/// first fragment, so a single-request upload never pays the `createUploadSession` round trip.
///
/// Internal rather than private so the transport contract below is directly assertable from
/// `ExtensionTests` — the sequential-fragment rule is a server constraint that cannot be
/// discovered from the pipeline's own tests, so it is pinned where it is declared.
struct GraphContentPutter: ContentPutting, @unchecked Sendable {

    /// Where one item's content goes: the simple-PUT URL and the upload-session factory URL.
    struct Target: Sendable {
        let contentURL: URL
        let createSessionURL: URL
    }

    let transport: any GraphUploadTransport
    let target: Target
    /// `If-Match` for the write (modify only). Applied to the simple PUT, or at session creation
    /// — Graph checks it there, not per fragment.
    let eTag: String?
    private let session = LazyUploadSession()

    init(transport: any GraphUploadTransport, target: Target, eTag: String?) {
        self.transport = transport
        self.target = target
        self.eTag = eTag
    }

    /// Graph requires fragment starts to be multiples of 320 KiB.
    static let graphFragmentAlignment = 320 * 1024

    /// Graph does **not** accept concurrent or out-of-order fragments. See the instance
    /// property below for why; hoisted to a static so it is assertable without a live client.
    static let graphSupportsParallelFragments = false

    var fragmentAlignment: Int { Self.graphFragmentAlignment }

    /// Graph does **not** accept concurrent or out-of-order fragments.
    ///
    /// The upload-session contract is explicit: "The fragments of the file must be uploaded
    /// sequentially in order. Uploading fragments out of order results in an error." The server
    /// keeps a single expected-range cursor and answers anything that is not at that cursor with
    /// `416 Requested Range Not Satisfiable` — which is also what it returns for a fragment it
    /// has already received.
    ///
    /// Fanning fragments out in parallel therefore fails by construction: exactly one lane sits
    /// at the cursor and the rest 416. Streaming still pays off — encrypt overlaps with upload
    /// and memory stays bounded to one span — but the PUTs themselves are serial. Parallelism
    /// for OneDrive belongs *across files*, not across fragments of one file.
    var supportsParallelFragments: Bool { Self.graphSupportsParallelFragments }

    var singleRequestLimit: Int { GraphDriveClient.simpleUploadLimit }

    func putWhole(_ bytes: Data) async throws -> Data {
        try await transport.putWholeContent(bytes, contentURL: target.contentURL, eTag: eTag)
    }

    func putRange(_ bytes: Data, start: Int, totalSize: Int) async throws -> Data? {
        let uploadURL = try await session.uploadURL {
            try await transport.createUploadSession(at: target.createSessionURL, eTag: eTag)
        }
        return try await transport.putFragment(bytes, start: start, totalSize: totalSize,
                                               uploadURL: uploadURL)
    }

    /// Abandon the upload session if one was opened. No request is sent otherwise.
    func cancelSession() async {
        guard let uploadURL = await session.createdURL else { return }
        await transport.cancelUploadSession(uploadURL)
    }
}

/// Creates an upload session at most once and shares it across fragments.
private actor LazyUploadSession {
    private var task: Task<URL, Error>?
    private(set) var createdURL: URL?

    func uploadURL(_ create: @Sendable @escaping () async throws -> URL) async throws -> URL {
        if task == nil { task = Task { try await create() } }
        let url = try await task!.value
        createdURL = url
        return url
    }
}

/// ``ContentFetching`` adapter over a live ``GraphDriveClient``: each range maps to an
/// authenticated, throttle-aware ranged content GET.
private struct GraphContentFetcher: ContentFetching, @unchecked Sendable {
    let client: GraphDriveClient
    let graphID: String
    let totalSize: Int

    func fetchRange(start: Int, length: Int) async throws -> Data {
        try await client.fetchContentRange(graphID: graphID, start: start, length: length)
    }
}
