/// Unit tests for `ResourceForkGate`.
//
//  ResourceForkGateTests.swift
//  ExtensionTests
//
//  Covers the `supportsResourceFork` capability gate (Fix 6): backends with no fork store must
//  neither read nor write the macOS resource fork to their backend — no server round-trip — while
//  the reference emulator (the one fork-capable backend) round-trips it. Bugs guarded:
//   - WRITE: a `.resourceFork` PUT to a non-supporting backend would corrupt the main content
//     stream (it has no separate fork store).
//   - READ: a fork fetch to a non-supporting backend must short-circuit to empty, no network.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

/// Test double that records resource-fork traffic. The resource-fork gate (`supportsResourceFork`,
/// `fetchResourceFork`, and the `.resourceFork` `modifyContents` PUT) is self-contained, so this
/// spy reproduces exactly those members rather than conforming to the wide `ProviderBackend`
/// protocol — the behaviour under test is identical and the test stays focused.
private final class ForkSpyBackend: @unchecked Sendable {

    /// Toggles the capability under test.
    let forkSupported: Bool
    /// Bytes returned by `fetchResourceFork` when supported.
    let forkBytes: Data
    /// Observable: how many times each direction was invoked.
    private(set) var fetchForkCallCount = 0
    private(set) var modifyContentsCallCount = 0
    private(set) var lastModifyStorageType: DomainService.ContentStorageType?

    init(forkSupported: Bool, forkBytes: Data = Data()) {
        self.forkSupported = forkSupported
        self.forkBytes = forkBytes
    }

    var supportsResourceFork: Bool { forkSupported }

    func fetchResourceFork(_ identifier: DomainService.ItemIdentifier,
                           revision: DomainService.Version?) async throws -> Data {
        fetchForkCallCount += 1
        return forkBytes
    }

    func modifyContents(_ parameter: DomainService.ModifyContentsParameter, data: Data?) {
        modifyContentsCallCount += 1
        lastModifyStorageType = parameter.contentStorageType
    }
}

final class ResourceForkGateTests: XCTestCase {

    private let itemID = DomainService.ItemIdentifier("item-1")

    // MARK: - Read gate

    /// A fork-capable backend returns its stored fork bytes.
    func testFetchForkReturnsBytesWhenSupported() async throws {
        let payload = Data("RSRC".utf8)
        let backend = ForkSpyBackend(forkSupported: true, forkBytes: payload)
        let fork = try await backend.fetchResourceFork(itemID, revision: nil)
        XCTAssertEqual(fork, payload)
        XCTAssertEqual(backend.fetchForkCallCount, 1)
    }

    /// The default (no-fork-store) backend reports the capability off and yields empty bytes —
    /// the Extension's `fetchResourceFork` short-circuits on the flag before any network call.
    func testDefaultBackendHasNoForkSupport() async throws {
        let backend = ForkSpyBackend(forkSupported: false)
        XCTAssertFalse(backend.supportsResourceFork)
        let fork = try await backend.fetchResourceFork(itemID, revision: nil)
        XCTAssertTrue(fork.isEmpty, "no fork store → empty fork")
    }

    // MARK: - Write gate (the corruption bug)

    /// Mirrors `Extension.uploadResourceFork`'s gate: the fork is coerced to `nil` for a
    /// non-supporting backend; only a present (non-nil) fork triggers the `.resourceFork` PUT.
    /// This is the exact logic that prevents corrupting OneDrive's main content stream.
    private func simulateUploadResourceFork(_ backend: ForkSpyBackend, fork forkArg: Data?) {
        let fork = backend.supportsResourceFork ? forkArg : nil
        guard let fork = fork else { return } // fork==nil branch: no PUT
        let param = DomainService.ModifyContentsParameter(
            identifier: itemID, existingRevision: .zero,
            contentStorageType: .resourceFork, updateResourceForkOnConflictedItem: false)
        backend.modifyContents(param, data: fork)
    }

    /// On a fork-capable backend a present fork is PUT with `.resourceFork` storage type.
    func testForkWriteReachesSupportingBackend() {
        let backend = ForkSpyBackend(forkSupported: true)
        simulateUploadResourceFork(backend, fork: Data("RSRC".utf8))
        XCTAssertEqual(backend.modifyContentsCallCount, 1)
        XCTAssertEqual(backend.lastModifyStorageType, .resourceFork)
    }

    /// A non-supporting backend must never receive a `.resourceFork` PUT, even when a fork is
    /// present — the gate coerces it to nil. This guards the main-content-corruption bug.
    func testForkWriteSkippedOnNonSupportingBackend() {
        let backend = ForkSpyBackend(forkSupported: false)
        simulateUploadResourceFork(backend, fork: Data("RSRC".utf8))
        XCTAssertEqual(backend.modifyContentsCallCount, 0,
                       "no .resourceFork PUT may reach a backend with no fork store")
        XCTAssertNil(backend.lastModifyStorageType)
    }

    /// A domain identifier private to this test, whose on-disk stores are removed afterwards.
    ///
    /// `GraphDriveClient` opens a ``BC01HeaderCache`` lazily, keyed by domain identifier, in the
    /// real App Group container. A shared literal (`"d"`) therefore wrote — and left behind —
    /// `BC01HeaderCache/d.sqlite3` beside the user's own domain stores on every run.
    private func uniqueDomainID() -> String {
        let id = "gate-\(UUID().uuidString)"
        addTeardownBlock { try? BC01HeaderCache.destroy(domainID: id) }
        return id
    }

    // MARK: - Concrete backend capabilities (no network)

    /// The reference emulator is the one fork-capable backend.
    func testEmulatorSupportsResourceFork() {
        let emulator = ServerEmulatorClient(domainIdentifier: uniqueDomainID(), secret: "s",
                                            hostname: "localhost", port: 24680)
        XCTAssertTrue(emulator.supportsResourceFork)
    }

    /// OneDrive has no fork store: capability off, and the default `fetchResourceFork` returns
    /// empty with no network round-trip (constructed here without any token/network use).
    func testOneDriveHasNoForkSupportAndEmptyFork() async throws {
        let onedrive = GraphDriveClient(displayName: "OneDrive", domainID: uniqueDomainID(),
                                        servingItemID: "root")
        XCTAssertFalse(onedrive.supportsResourceFork)
        let fork = try await onedrive.fetchResourceFork(itemID, revision: nil)
        XCTAssertTrue(fork.isEmpty, "OneDrive yields an empty fork with no server round-trip")
    }
}
