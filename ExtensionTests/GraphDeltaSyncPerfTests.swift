/// Unit tests for `GraphDeltaSyncPerf`.
//
//  GraphDeltaSyncPerfTests.swift
//  ExtensionTests
//
//  Throughput benchmark for `GraphDeltaSync.runPass()`.
//
//  Two tests, deliberately split:
//
//  - `test_reconcileThroughput_synthetic10k` is hermetic and always runs. Its `fetch` serves
//    pre-generated delta pages from memory, so it isolates decode + `partition` + `upsertBatch`
//    — the half of the crawl we actually control, and therefore the stable regression signal.
//  - `test_deltaCrawlThroughput_live10k` hits real Graph with the credential already configured
//    in the App Group, and is skipped unless `FB_PERF_ONEDRIVE=1`. It answers only "does the
//    network make this worse?".
//
//  Neither test mutates remote state (delta is a GET) or touches the user's live cache: both
//  crawl into a throwaway `MetadataCache` domain that teardown destroys.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
import os.log
@testable import Extension

final class GraphDeltaSyncPerfTests: XCTestCase {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "delta-perf")

    /// Whether the caller asked for the live (network) benchmark.
    ///
    /// Two channels, because `xcodebuild` forwards neither `KEY=VALUE` (that sets a *build*
    /// setting) nor `TEST_RUNNER_*` (a UI-test mechanism) into a host-app-hosted test process.
    /// Launch arguments after `--` do arrive, and `UserDefaults` parses them; an environment
    /// variable still works when running from an Xcode scheme.
    private static var optedIn: Bool {
        if ProcessInfo.processInfo.environment["FB_PERF_ONEDRIVE"] == "1" { return true }
        return UserDefaults.standard.string(forKey: "FB_PERF_ONEDRIVE") == "1"
    }

    /// Items the benchmark must observe before the stopwatch stops. A rate derived from a
    /// smaller sample is not comparable across runs, so falling short is a failure, not a
    /// partial result.
    private static let targetItems = 10_000

    /// Page size the shipping cold crawl uses (`GraphDeltaSync.crawlPageSize`). Mirrored here
    /// only to shape the synthetic corpus like the real one.
    private static let pageSize = 2000

    private var perfDomainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        perfDomainID = "perf-delta-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: perfDomainID)
        // A throwaway domain guarantees a cold crawl: no inherited deltaLink to resume from.
        try cache.setDeltaLink(nil)
    }

    override func tearDownWithError() throws {
        cache = nil
        if let perfDomainID { try? MetadataCache.destroy(domainID: perfDomainID) }
        perfDomainID = nil
        // MSALTokenStore is deliberately left untouched — signing out here would break the
        // user's live domain.
    }

    // MARK: - Instrumentation

    /// Collects timings from inside the crawl.
    ///
    /// The crawl loop is serial (fetch → decode → reconcile → next page), so the local leg is
    /// `wall − network` with nothing double-counted. Per-page decode/cache timings were removed
    /// from the production type once the split was established (~92% decode before the
    /// timestamp fix; ~50/50 and only ~3% of wall clock after). This end-to-end report is what
    /// catches a regression now.
    private actor Meter {
        private(set) var networkSeconds: Double = 0
        private(set) var wireBytes = 0
        private(set) var pageSeconds: [Double] = []
        private(set) var pages = 0
        private(set) var itemsSeen = 0
        /// Wall clock at the moment `itemsSeen` first crossed the target.
        private(set) var reachedTargetAt: DispatchTime?
        /// Time spent asleep honouring `Retry-After`. Excluded from every rate: one throttle
        /// would otherwise poison the measurement.
        private(set) var throttleSeconds: Double = 0

        /// Time on the wire, summed per page.
        func recordFetch(seconds: Double, bytes: Int) {
            networkSeconds += seconds
            wireBytes += bytes
        }


        func recordThrottle(seconds: Double) { throttleSeconds += seconds }

        /// Elapsed-at-end-of-page, converted to a per-page duration by differencing against the
        /// previous page's end.
        private var lastPageEnd: Double = 0

        func recordPage(_ update: DeltaPageUpdate, at now: DispatchTime, since start: DispatchTime) {
            pages = max(pages, update.page)
            itemsSeen = update.itemsSeen
            let elapsed = now.seconds(since: start)
            pageSeconds.append(elapsed - lastPageEnd)
            lastPageEnd = elapsed
            if update.itemsSeen >= GraphDeltaSyncPerfTests.targetItems, reachedTargetAt == nil {
                reachedTargetAt = now
            }
        }
    }

    /// One benchmark's finished numbers.
    private struct Report {
        let label: String
        let items: Int
        let pages: Int
        let wallSeconds: Double
        let networkSeconds: Double
        let throttleSeconds: Double
        let wireBytes: Int
        let pageSeconds: [Double]
        let cacheRows: Int

        /// Wall clock minus time on the wire: the local leg (JSON decode + cache write).
        var reconcileSeconds: Double { max(0, wallSeconds - networkSeconds) }
        var endToEndRate: Double { Double(items) / wallSeconds }
        var networkRate: Double { networkSeconds > 0 ? Double(items) / networkSeconds : 0 }
        var reconcileRate: Double { reconcileSeconds > 0 ? Double(items) / reconcileSeconds : 0 }
    }

    private func emit(_ r: Report) {
        let sorted = r.pageSeconds.sorted()
        let p50 = sorted.isEmpty ? 0 : sorted[sorted.count / 2]
        let maxPage = sorted.last ?? 0
        let netPct = r.wallSeconds > 0 ? r.networkSeconds / r.wallSeconds * 100 : 0

        func f(_ v: Double, _ places: Int = 1) -> String { String(format: "%.\(places)f", v) }
        func n(_ v: Int) -> String {
            let fmt = NumberFormatter(); fmt.numberStyle = .decimal
            return fmt.string(from: NSNumber(value: v)) ?? "\(v)"
        }

        emitLine("""

        ── \(r.label) ─────────────────────────────────
        items                 \(n(r.items))
        pages                 \(r.pages)  (page size \(Self.pageSize))
        wall clock            \(f(r.wallSeconds)) s
        end-to-end rate       \(f(r.endToEndRate, 0)) items/sec
        network               \(f(r.networkSeconds)) s  (\(f(netPct))%)   → \(f(r.networkRate, 0)) items/sec
        decode + cache write  \(f(r.reconcileSeconds)) s  (\(f(100 - netPct))%)   → \(f(r.reconcileRate, 0)) items/sec
        wire bytes            \(f(Double(r.wireBytes) / 1_048_576, 1)) MB   (\(f(Double(r.wireBytes) / Double(max(r.items, 1)) / 1024, 1)) KB/item)
        throttled             \(f(r.throttleSeconds)) s (excluded)
        per-page  p50 / max   \(f(p50)) s / \(f(maxPage)) s
        cache rows at stop    \(n(r.cacheRows))   (< items: delta rows include the root, \
        special items and tombstones, none of which become cache rows)
        ────────────────────────────────────────────────
        """)

        let json = """
        {"label":"\(r.label)","items":\(r.items),"pages":\(r.pages),\
        "wall_s":\(f(r.wallSeconds, 3)),"network_s":\(f(r.networkSeconds, 3)),\
        "reconcile_s":\(f(r.reconcileSeconds, 3)),"throttle_s":\(f(r.throttleSeconds, 3)),\
        "wire_bytes":\(r.wireBytes),"cache_rows":\(r.cacheRows),\
        "end_to_end_rate":\(f(r.endToEndRate, 2)),"network_rate":\(f(r.networkRate, 2)),\
        "reconcile_rate":\(f(r.reconcileRate, 2))}
        """
        emitLine("PERF_JSON: \(json)")
    }

    /// Emit a benchmark line everywhere it can be read.
    ///
    /// `print` alone is not enough: the test host's stdout is not forwarded by `xcodebuild`,
    /// and neither `xcodebuild KEY=VALUE` (a build setting) nor `TEST_RUNNER_*` (a UI-test
    /// mechanism) reaches this process's environment. `os_log` does escape, so the numbers are
    /// recoverable from a command-line run via:
    ///
    ///     log show --last 5m --predicate 'subsystem == "org.vaultsync.VaultSync" \
    ///         AND category == "delta-perf"' --style compact
    ///
    /// `FB_PERF_OUT` still writes a parseable file when the test is run from Xcode, where the
    /// scheme can set a real environment variable.
    private func emitLine(_ text: String) {
        print(text)
        Self.log.infoPublic(text)
        guard let path = ProcessInfo.processInfo.environment["FB_PERF_OUT"]
            ?? UserDefaults.standard.string(forKey: "FB_PERF_OUT") else { return }
        let line = Data((text + "\n").utf8)
        if let handle = FileHandle(forWritingAtPath: path) {
            handle.seekToEndOfFile()
            handle.write(line)
            try? handle.close()
        } else {
            try? line.write(to: URL(fileURLWithPath: path))
        }
    }

    /// Run one pass against `fetch`, timing to the target-item mark.
    ///
    /// Plain `DispatchTime` rather than `measure {}`: a cold crawl is neither cheap nor
    /// idempotent in cost (Graph is warmer on run 2), so a repeated-iteration average would be
    /// fiction. One run, reported honestly.
    private func runBenchmark(label: String,
                              rootGraphID: String,
                              fetch: @escaping (URL, Int?) async throws -> Data,
                              meter: Meter) async throws {
        try cache.setRootGraphID(rootGraphID)

        let start = DispatchTime.now()
        // Holds the pass's own task so the page handler can cancel it from inside the crawl.
        let passTask = TaskBox()

        let sync = GraphDeltaSync(
            cache: cache,
            rootGraphID: rootGraphID,
            fetch: fetch,
            // No-op: nothing interactive is in flight, and a real yield would add noise.
            yieldToInteractive: {},
            onDeltaUpdates: { update in
                await meter.recordPage(update, at: DispatchTime.now(), since: start)
                // Sample taken — stop the crawl. `runPass` checks cancellation at its page
                // boundary and returns the partial result rather than crawling the remaining
                // ~290k items of the drive.
                if update.itemsSeen >= Self.targetItems { await passTask.cancel() }
            })

        // Letting the pass crawl to completion would cost ~30x the measured window on a
        // 300k-item drive for no extra signal, so the page handler cancels it at the target.
        // `runPass` honours cancellation at its page boundary, returning what it reconciled.
        let task = Task { try await sync.runPass() }
        await passTask.set(task)
        let result = try await task.value
        let end = DispatchTime.now()

        XCTAssertFalse(result.cursorExpired, "delta cursor expired mid-benchmark; rerun")
        XCTAssertTrue(result.cancelled || !result.changedParentGraphIDs.isEmpty,
                      "pass returned neither a cancellation nor any reconciled container")

        let itemsSeen = await meter.itemsSeen
        guard let reachedAt = await meter.reachedTargetAt else {
            XCTFail("""
            Only \(itemsSeen) items available — need \(Self.targetItems). \
            A rate from a smaller sample is not comparable.
            """)
            return
        }

        let report = Report(
            label: label,
            items: Self.targetItems,
            pages: await meter.pages,
            wallSeconds: reachedAt.seconds(since: start) - (await meter.throttleSeconds),
            networkSeconds: await meter.networkSeconds,
            throttleSeconds: await meter.throttleSeconds,
            wireBytes: await meter.wireBytes,
            pageSeconds: await meter.pageSeconds,
            cacheRows: (try? cache.indexedCount()) ?? -1)

        emit(report)
        emitLine("(crawl stopped at \(itemsSeen) items after \(String(format: "%.1f", end.seconds(since: start))) s)")

        XCTAssertGreaterThan(report.endToEndRate, 0)
    }

    // MARK: - Synthetic (hermetic, always runs)

    /// Reconcile-only throughput: the `fetch` closure returns pre-built pages from memory, so
    /// the measured time is decode + `partition` + `upsertBatch` with no network in it.
    func test_reconcileThroughput_synthetic10k() async throws {
        let pageCount = Int(ceil(Double(Self.targetItems) / Double(Self.pageSize)))
        let pages = (0..<pageCount).map { index in
            Self.syntheticPage(index: index,
                               count: Self.pageSize,
                               isFinal: index == pageCount - 1)
        }

        let meter = Meter()
        let cursor = Cursor()
        let fetch: (URL, Int?) async throws -> Data = { _, _ in
            let index = await cursor.next()
            guard index < pages.count else { throw DeltaHTTPError(statusCode: 404) }
            let data = pages[index]
            await meter.recordFetch(seconds: 0, bytes: data.count)
            return data
        }

        try await runBenchmark(label: "synthetic reconcile (no network)",
                               rootGraphID: "root",
                               fetch: fetch,
                               meter: meter)
    }

    /// Holds the in-flight pass task so the page handler — which runs *inside* that pass — can
    /// cancel it. The handler is invoked before `runPass` returns, so the task reference has to
    /// be published through a box rather than captured.
    private actor TaskBox {
        private var task: Task<DeltaResult, Error>?
        private var cancelledEarly = false

        func set(_ task: Task<DeltaResult, Error>) {
            self.task = task
            // A target reached before `set` landed still has to take effect.
            if cancelledEarly { task.cancel() }
        }

        func cancel() {
            cancelledEarly = true
            task?.cancel()
        }
    }

    /// Hands out page indices to the stateless `fetch` closure.
    private actor Cursor {
        private var index = -1
        func next() -> Int { index += 1; return index }
    }

    /// Build one delta page shaped like a real OneDrive response: a `$select`-trimmed row set,
    /// mostly files, a folder every 32nd item, and a realistic share of `.bc` names so
    /// `partition`'s size classification does the same work it does in production.
    private static func syntheticPage(index: Int, count: Int, isFinal: Bool) -> Data {
        var rows: [String] = []
        rows.reserveCapacity(count)
        let base = index * count

        for offset in 0..<count {
            let ordinal = base + offset
            let id = "01PERF\(String(format: "%08d", ordinal))"
            let parent = ordinal < 32 ? "root" : "01PERF\(String(format: "%08d", (ordinal / 32) * 32))"
            let created = "2024-01-01T00:00:00Z"
            let modified = "2025-06-01T12:00:00Z"

            if ordinal % 32 == 0 {
                rows.append("""
                {"id":"\(id)","name":"folder-\(ordinal)","size":0,\
                "eTag":"e-\(id)","cTag":"c-\(id)",\
                "createdDateTime":"\(created)","lastModifiedDateTime":"\(modified)",\
                "parentReference":{"id":"\(parent)"},"folder":{"childCount":31}}
                """)
            } else {
                // Roughly two thirds encrypted, matching an in-use BC01 domain: the `.bc` rows
                // must leave plaintextSize unresolved, which is real work in `partition`.
                let name = ordinal % 3 == 0
                    ? "document-\(ordinal)-with-a-realistic-length-name.pdf"
                    : "document-\(ordinal)-with-a-realistic-length-name.pdf.bc"
                rows.append("""
                {"id":"\(id)","name":"\(name)","size":\(65536 + ordinal),\
                "eTag":"e-\(id)","cTag":"c-\(id)",\
                "createdDateTime":"\(created)","lastModifiedDateTime":"\(modified)",\
                "parentReference":{"id":"\(parent)"}}
                """)
            }
        }

        let link = isFinal
            ? "\"@odata.deltaLink\":\"https://graph.microsoft.com/v1.0/me/drive/items/root/delta?token=final\""
            : "\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/drive/items/root/delta?token=page\(index + 1)\""
        return Data("{\"value\":[\(rows.joined(separator: ","))],\(link)}".utf8)
    }

    // MARK: - Live Graph (opt-in)

    /// End-to-end crawl against the OneDrive account already configured in the App Group.
    ///
    /// Opt-in via `FB_PERF_ONEDRIVE=1` so `run-tests.sh` and CI stay offline. Credentials are
    /// reused, never prompted for: sign-in is an `ASWebAuthenticationSession` flow owned by the
    /// container app and has no place in an XCTest process.
    func test_deltaCrawlThroughput_live10k() async throws {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipUnless(Self.optedIn, """
        Live OneDrive benchmark. Re-run with:
          xcodebuild test -scheme VaultSync -allowProvisioningUpdates \
            -only-testing ExtensionTests/GraphDeltaSyncPerfTests/test_deltaCrawlThroughput_live10k \
            -- -FB_PERF_ONEDRIVE 1
        """)

        let (account, domainID) = try resolveAccount(env: env)
        guard MSALTokenStore.shared.hasCredential(domainID) else {
            throw XCTSkip("""
            No OneDrive credential. Sign in via VaultSync.app, then re-run with FB_PERF_ONEDRIVE=1.
            """)
        }

        // Minted once here: proves the refresh token still works, and warms the in-memory
        // access-token cache so the timed region has no auth stall in it.
        let token = try await MSALTokenStore.shared.accessToken(for: domainID)

        let rootGraphID = try await resolveRootGraphID(configured: account.remoteItemID, token: token)

        let meter = Meter()
        let fetch = Self.liveFetch(token: token, meter: meter)

        try await runBenchmark(label: "live OneDrive crawl (domain \(domainID), root \(rootGraphID))",
                               rootGraphID: rootGraphID,
                               fetch: fetch,
                               meter: meter)
    }

    /// Pick the OneDrive domain to benchmark. Explicit beats guessing: with more than one
    /// candidate and no `FB_PERF_DOMAIN_ID`, fail with the list rather than choosing.
    private func resolveAccount(env: [String: String]) throws -> (DomainAccount, String) {
        let accounts = SharedConfigStore.shared.allAccounts()
            .filter { $0.value.backendKind == .oneDrive
                      && MSALTokenStore.shared.hasCredential($0.key) }

        let wanted = env["FB_PERF_DOMAIN_ID"]
            ?? UserDefaults.standard.string(forKey: "FB_PERF_DOMAIN_ID")
        if let wanted {
            guard let account = accounts[wanted] else {
                throw XCTSkip("FB_PERF_DOMAIN_ID=\(wanted) is not a configured OneDrive domain.")
            }
            return (account, wanted)
        }
        guard !accounts.isEmpty else {
            throw XCTSkip("No OneDrive domain configured. Add one in VaultSync.app first.")
        }
        guard accounts.count == 1, let only = accounts.first else {
            let ids = accounts.keys.sorted().joined(separator: ", ")
            XCTFail("Multiple OneDrive domains — set FB_PERF_DOMAIN_ID to one of: \(ids)")
            throw XCTSkip("ambiguous domain")
        }
        return (only.value, only.key)
    }

    /// The Graph id to crawl.
    ///
    /// `FB_PERF_ROOT` (or the domain's serving folder, else the drive root). No pre-flight size
    /// check: counting descendants on a large drive costs as much as the benchmark itself, and
    /// the crawl reports what it actually found either way.
    private func resolveRootGraphID(configured: String?, token: String) async throws -> String {
        if let override = ProcessInfo.processInfo.environment["FB_PERF_ROOT"]
            ?? UserDefaults.standard.string(forKey: "FB_PERF_ROOT"), !override.isEmpty {
            return override
        }
        if let configured, !configured.isEmpty { return configured }
        return try await graphID(ofPath: "me/drive/root", token: token)
    }

    private func graphID(ofPath path: String, token: String) async throws -> String {
        let url = URL(string: "https://graph.microsoft.com/v1.0/\(path)?$select=id")!
        struct Root: Decodable { let id: String }
        return try JSONDecoder().decode(Root.self, from: try await get(url, token: token)).id
    }

    /// Authenticated Graph GET for the small setup queries above.
    private func get(_ url: URL, token: String) async throws -> Data {
        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw DeltaHTTPError(statusCode: (response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        return data
    }

    /// Authenticated Graph GET mirroring `GraphDriveClient.perform`, minus the retry policy,
    /// plus instrumentation. `Retry-After` is honoured once and its sleep is recorded
    /// separately so a single throttle does not distort the rate.
    private static func liveFetch(token: String,
                                  meter: Meter) -> (URL, Int?) async throws -> Data {
        { url, maxPageSize in
            var attempt = 0
            while true {
                var request = URLRequest(url: url)
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                if let maxPageSize {
                    request.setValue("odata.maxpagesize=\(maxPageSize)", forHTTPHeaderField: "Prefer")
                }

                let started = DispatchTime.now()
                let (data, response) = try await URLSession.shared.data(for: request)
                let elapsed = DispatchTime.now().seconds(since: started)
                let http = response as? HTTPURLResponse

                if let http, http.statusCode == 429 || http.statusCode == 503, attempt == 0 {
                    attempt += 1
                    let retryAfter = (http.value(forHTTPHeaderField: "Retry-After")
                        .flatMap(TimeInterval.init)) ?? 1
                    await meter.recordThrottle(seconds: retryAfter)
                    try await Task.sleep(nanoseconds: UInt64(retryAfter * 1_000_000_000))
                    continue
                }

                await meter.recordFetch(seconds: elapsed, bytes: data.count)

                if let http, http.statusCode >= 400 {
                    // 410 handling stays in the SUT: it owns cursor rotation.
                    throw DeltaHTTPError(statusCode: http.statusCode)
                }
                return data
            }
        }
    }
}

private extension DispatchTime {
    /// Seconds elapsed since `other`.
    func seconds(since other: DispatchTime) -> Double {
        Double(uptimeNanoseconds &- other.uptimeNanoseconds) / 1_000_000_000
    }
}
