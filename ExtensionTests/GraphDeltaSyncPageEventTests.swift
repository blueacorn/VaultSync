/// Unit tests for `GraphDeltaSyncPageEvent`.
//
//  GraphDeltaSyncPageEventTests.swift
//  ExtensionTests
//
//  A delta pass emits an event per reconciled page. That event is not a convenience:
//  since a pass crawls to completion, it returns exactly once, so per-page events
//  are the ONLY channel that can signal changed containers or advance the indexed count while a
//  large initial crawl is still running.
//
//  Also pins the `partition()` size classification. The invariant under test is narrow and
//  load-bearing: a plain item's remote size IS its plaintext size and may be recorded as exact,
//  while a `.bc` item's must stay unresolved. Persisting a ciphertext-derived estimate for the
//  latter over-reports `documentSize`, which makes `NSFileProviderPartialContentFetching` request
//  tail bytes past the real EOF forever.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

final class GraphDeltaSyncPageEventTests: XCTestCase {

    private var domainID: String!
    private var cache: MetadataCache!

    override func setUpWithError() throws {
        domainID = "deltapage-test-\(UUID().uuidString)"
        cache = try MetadataCache(domainID: domainID)
        try cache.setRootGraphID("root")
    }

    override func tearDownWithError() throws {
        cache = nil
        if let domainID { try? MetadataCache.destroy(domainID: domainID) }
        domainID = nil
    }

    // MARK: - Graph payload stubs

    /// One delta page. `nextLink` present = more pages follow; absent = final page (deltaLink).
    private func page(_ items: [String], nextLink: String?) -> Data {
        let value = items.joined(separator: ",")
        let link = nextLink.map { "\"@odata.nextLink\":\"\($0)\"" }
            ?? "\"@odata.deltaLink\":\"https://graph.microsoft.com/delta?token=final\""
        return Data("{\"value\":[\(value)],\(link)}".utf8)
    }

    private func file(_ id: String, name: String, parent: String = "root", size: Int = 8192) -> String {
        """
        {"id":"\(id)","name":"\(name)","size":\(size),"eTag":"e-\(id)","cTag":"c-\(id)",\
        "parentReference":{"id":"\(parent)"}}
        """
    }

    private func folder(_ id: String, name: String, parent: String = "root") -> String {
        """
        {"id":"\(id)","name":"\(name)","size":0,"eTag":"e-\(id)","cTag":"c-\(id)",\
        "parentReference":{"id":"\(parent)"},"folder":{"childCount":0}}
        """
    }

    /// Collects the events a pass emitted, in order.
    private actor EventLog {
        private(set) var updates: [DeltaPageUpdate] = []
        func record(_ update: DeltaPageUpdate) { updates.append(update) }
    }

    /// Drive a pass over a scripted sequence of pages.
    private func runPass(pages: [Data],
                         translator: MetadataTranslator = IdentityMetadataTranslator())
        async throws -> (DeltaResult, [DeltaPageUpdate]) {
        let log = EventLog()
        let remaining = Pages(pages)
        let sync = GraphDeltaSync(
            cache: cache,
            rootGraphID: "root",
            fetch: { _, _ in try await remaining.next() },
            translator: translator,
            onDeltaUpdates: { await log.record($0) })
        let result = try await sync.runPass()
        return (result, await log.updates)
    }

    /// Hands out scripted pages in order.
    private actor Pages {
        private var pages: [Data]
        init(_ pages: [Data]) { self.pages = pages }
        func next() throws -> Data {
            guard !pages.isEmpty else { throw StubExhausted() }
            return pages.removeFirst()
        }
    }

    private struct StubExhausted: Error {}

    // MARK: - Per-page events

    /// One event per page, numbered from 1, with `hasNextPage` false only on the last — the
    /// signal a handler uses to know the crawl is still running.
    func testFiresOncePerPage() async throws {
        let (_, updates) = try await runPass(pages: [
            page([file("a", name: "a.txt")], nextLink: "https://graph/next1"),
            page([file("b", name: "b.txt")], nextLink: "https://graph/next2"),
            page([file("c", name: "c.txt")], nextLink: nil),
        ])

        XCTAssertEqual(updates.count, 3)
        XCTAssertEqual(updates.map(\.page), [1, 2, 3])
        XCTAssertEqual(updates.map(\.hasNextPage), [true, true, false])
    }

    /// Each event carries the parents changed on THAT page, not the pass-cumulative set.
    /// Cumulative sets would re-signal every earlier container on every page — quadratic
    /// signalling across a long crawl.
    func testEventCarriesOnlyThatPagesParents() async throws {
        let (_, updates) = try await runPass(pages: [
            page([file("a", name: "a.txt", parent: "p1")], nextLink: "https://graph/next1"),
            page([file("b", name: "b.txt", parent: "p2")], nextLink: nil),
        ])

        XCTAssertEqual(updates[0].changedParentGraphIDs, ["p1"])
        XCTAssertEqual(updates[1].changedParentGraphIDs, ["p2"],
                       "page 2 must not repeat page 1's parent")
    }

    /// `itemsSeen` is the running total across pages, so a handler can publish progress directly
    /// from it without keeping its own tally.
    func testItemsSeenIsMonotonicAcrossPages() async throws {
        let (_, updates) = try await runPass(pages: [
            page([file("a", name: "a.txt"), file("b", name: "b.txt")], nextLink: "https://graph/n"),
            page([file("c", name: "c.txt")], nextLink: nil),
        ])

        XCTAssertEqual(updates.map(\.itemsSeen), [2, 3])
    }

    /// A page reconciling nothing still fires, flagged `changed: false`. Progress must not stall
    /// across no-op pages — on a re-crawl most pages are no-ops — but the handler needs to know
    /// there is nothing to signal.
    func testNoOpPageStillFiresButIsFlaggedUnchanged() async throws {
        // Seed the rows first, so the second pass re-sees identical items and writes nothing.
        _ = try await runPass(pages: [page([file("a", name: "a.txt")], nextLink: nil)])
        try cache.setDeltaLink(nil)

        let (_, updates) = try await runPass(pages: [
            page([file("a", name: "a.txt")], nextLink: nil),
        ])

        XCTAssertEqual(updates.count, 1, "a no-op page must still report progress")
        XCTAssertFalse(updates[0].changed)
        XCTAssertEqual(updates[0].itemsSeen, 1)
    }

    /// A pass with no handler reconciles exactly as one with a handler — the event is additive to
    /// the crawl, never load-bearing. Run against two independent caches so each pass sees the
    /// same cold state; reusing one cache would make the second pass a no-op and prove nothing.
    func testNilHandlerDoesNotChangeTheResult() async throws {
        let payload = { self.page([self.file("a", name: "a.txt", parent: "p1"),
                                   self.folder("f", name: "Folder", parent: "p2")],
                                  nextLink: nil) }

        let (withHandler, updates) = try await runPass(pages: [payload()])
        XCTAssertEqual(updates.count, 1, "handler ran, so the two paths differ only by the event")

        // Independent cache: same cold starting point, no handler.
        let otherDomainID = "deltapage-nohandler-\(UUID().uuidString)"
        let otherCache = try MetadataCache(domainID: otherDomainID)
        defer { try? MetadataCache.destroy(domainID: otherDomainID) }
        try otherCache.setRootGraphID("root")
        let remaining = Pages([payload()])
        let sync = GraphDeltaSync(cache: otherCache, rootGraphID: "root",
                                  fetch: { _, _ in try await remaining.next() })
        let withoutHandler = try await sync.runPass()

        XCTAssertEqual(withHandler.changed, withoutHandler.changed)
        XCTAssertEqual(withHandler.cursorExpired, withoutHandler.cursorExpired)
        XCTAssertEqual(withHandler.changedParentGraphIDs, withoutHandler.changedParentGraphIDs)
        XCTAssertEqual(withHandler.changedParentGraphIDs, ["p1", "p2"])
    }

    // MARK: - partition() size classification

    /// Under an ACTIVE BC01 translator: a plain file's remote size is its exact plaintext size
    /// and is recorded straight through. A `.bc` file has no knowable size until its header is
    /// read, so it is left unresolved until a content fetch parses one.
    func testPlainItemRecordedExactEncryptedLeftUnresolved() async throws {
        _ = try await runPass(pages: [
            page([file("plain", name: "notes.txt", size: 4096),
                  file("enc", name: "secret.bc", size: 8192)], nextLink: nil),
        ], translator: BoxcryptorMetadataTranslator(algorithm: .bc01))

        XCTAssertEqual(try cache.item(graphID: "plain")?.plaintextSize, 4096,
                       "plaintext == ciphertext for a non-.bc name; recording it is exact")
        XCTAssertNil(try cache.item(graphID: "enc")?.plaintextSize,
                     "a .bc item's size is only knowable from its BC01 header")
    }

    /// Under the identity translator no name is backend-encrypted, so every file is exact —
    /// correct for a non-encrypting domain.
    func testIdentityTranslatorRecordsEveryFileExact() async throws {
        _ = try await runPass(pages: [
            page([file("a", name: "a.txt", size: 111),
                  file("b", name: "b.bc", size: 222)], nextLink: nil),
        ])

        XCTAssertEqual(try cache.item(graphID: "a")?.plaintextSize, 111)
        XCTAssertEqual(try cache.item(graphID: "b")?.plaintextSize, 222)
    }

    /// Folders have no content, so they carry no plaintext size regardless of translator.
    func testFolderCarriesNoPlaintextSize() async throws {
        _ = try await runPass(pages: [page([folder("f", name: "Docs")], nextLink: nil)])

        XCTAssertNil(try cache.item(graphID: "f")?.plaintextSize)
    }

    /// Regression guard for the invariant tasks 35-37 were spent establishing: the delta path
    /// must NEVER persist a size for a backend-encrypted name. A stored value outranks the
    /// estimate on every read, so writing one here would launder an approximation into an
    /// authority and break partial fetch permanently.
    func testNeverPersistsASizeForABackendEncryptedName() async throws {
        let translator = BoxcryptorMetadataTranslator(algorithm: .bc01)
        _ = try await runPass(pages: [
            page([file("e1", name: "a.bc", size: 4096),
                  file("e2", name: "b.bc", size: 1_000_000),
                  file("e3", name: "c.bc", size: 8192)], nextLink: nil),
        ], translator: translator)

        for id in ["e1", "e2", "e3"] {
            let row = try XCTUnwrap(cache.item(graphID: id))
            XCTAssertTrue(translator.isBackendEncrypted(row.name))
            XCTAssertNil(row.plaintextSize,
                         "\(row.name): estimation on the delta path must stay impossible")
        }
    }

    // MARK: - Cancellation

    /// A cancelled pass must stop at the page boundary, keep what it already reconciled, and
    /// leave the cursor pointing at the first *unfetched* page — so resuming repeats no work
    /// and skips none. This is what lets a caller abandon a long initial crawl (extension
    /// suspension, domain removal) without losing or redoing the pages already committed.
    func test_cancellationStopsAtPageBoundaryAndLeavesResumableCursor() async throws {
        let pages = [
            page([file("a", name: "a.txt")], nextLink: "https://graph.microsoft.com/delta?token=p2"),
            page([file("b", name: "b.txt")], nextLink: "https://graph.microsoft.com/delta?token=p3"),
            page([file("c", name: "c.txt")], nextLink: nil),
        ]

        let cursor = PageCursor()
        let box = PassBox()

        let sync = GraphDeltaSync(
            cache: cache,
            rootGraphID: "root",
            fetch: { _, _ in
                let index = await cursor.next()
                guard index < pages.count else {
                    XCTFail("fetched past the cancellation point — pass did not stop")
                    throw DeltaHTTPError(statusCode: 404)
                }
                return pages[index]
            },
            onDeltaUpdates: { update in
                // Cancel once the second page has been reconciled.
                if update.page == 2 { await box.cancel() }
            })

        let task = Task { try await sync.runPass() }
        await box.set(task)
        let result = try await task.value

        XCTAssertTrue(result.cancelled, "pass should report it was cut short")
        XCTAssertFalse(result.cursorExpired)
        XCTAssertTrue(result.changed, "the two reconciled pages are still real changes")

        // Both fetched pages are committed; the third was never fetched.
        XCTAssertNotNil(try cache.item(graphID: "a"))
        XCTAssertNotNil(try cache.item(graphID: "b"))
        XCTAssertNil(try cache.item(graphID: "c"))

        // The cursor points at page 3 — the page not yet fetched.
        XCTAssertEqual(cache.deltaLink, "https://graph.microsoft.com/delta?token=p3")
    }

    /// Hands out page indices to a stateless fetch closure.
    private actor PageCursor {
        private var index = -1
        func next() -> Int { index += 1; return index }
    }

    /// Publishes the in-flight pass task to its own page handler.
    private actor PassBox {
        private var task: Task<DeltaResult, Error>?
        private var cancelledEarly = false
        func set(_ task: Task<DeltaResult, Error>) {
            self.task = task
            if cancelledEarly { task.cancel() }
        }
        func cancel() {
            cancelledEarly = true
            task?.cancel()
        }
    }
}
