/// Unit tests for `AppModel`.
//
//  AppModelTests.swift
//  VaultSyncTests
//
//  Unit tests for the menu-bar `AppModel` icon-activity derivation.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import VaultSync

@MainActor
final class AppModelTests: XCTestCase {

    /// `ignoreAuthentication` is a real user-facing toggle in Preferences, living in the shared
    /// App Group suite. Tests below flip it, so its prior value is captured and restored rather
    /// than reset to the default — the developer's own setting is not necessarily the default.
    private var previousIgnoreAuthentication: Any?

    override func setUp() {
        super.setUp()
        previousIgnoreAuthentication = UserDefaults.sharedContainerDefaults
            .object(forKey: "ignoreAuthentication")
    }

    override func tearDown() {
        if let previousIgnoreAuthentication {
            UserDefaults.sharedContainerDefaults
                .set(previousIgnoreAuthentication, forKey: "ignoreAuthentication")
        } else {
            UserDefaults.sharedContainerDefaults.removeObject(forKey: "ignoreAuthentication")
        }
        previousIgnoreAuthentication = nil
        super.tearDown()
    }

    private func makeDomain(_ name: String = "Vault") -> NSFileProviderDomain {
        NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString), displayName: name)
    }

    private func makeAccount() -> DomainAccount {
        DomainAccount(displayName: "Vault", backendKind: .emulator)
    }

    func testDerivesIdleForEmptyDomains() {
        XCTAssertEqual(AppModel.deriveActivity([]), .idle)
    }

    func testDerivesIdleWhenNoProgressAndAuthenticated() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil)
        XCTAssertEqual(AppModel.deriveActivity([entry]), .idle)
    }

    func testDerivesActiveWhenProgressUnfinished() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let progress = Progress(totalUnitCount: 100)
        progress.completedUnitCount = 10
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: progress, downloadProgress: nil)
        XCTAssertEqual(AppModel.deriveActivity([entry]), .active)
    }

    func testDerivesIdleWhenProgressFinished() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let progress = Progress(totalUnitCount: 100)
        progress.completedUnitCount = 100
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: progress, downloadProgress: nil)
        XCTAssertEqual(AppModel.deriveActivity([entry]), .idle)
    }

    func testErrorTakesPrecedenceOverActive() {
        // Not-authenticated with auth enforced → error, even with progress in flight.
        UserDefaults.sharedContainerDefaults.set(false, forKey: "ignoreAuthentication")
        let progress = Progress(totalUnitCount: 100)
        progress.completedUnitCount = 10
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: progress, downloadProgress: nil)
        XCTAssertEqual(AppModel.deriveActivity([entry]), .error)
    }

    // MARK: - Lock-and-remove

    /// A vault removed from Finder by "Lock and Remove Vault" has no registered domain, so
    /// `domain.isDisconnected` is false for it. It must still count as locked, otherwise the
    /// "Unlock Vaults" menu item is hidden and the vault can never be restored.
    func testRemovedEntryCountsAsLocked() {
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil, isRemoved: true)
        XCTAssertFalse(entry.domain.isDisconnected, "precondition: an unregistered domain is not 'disconnected'")
        XCTAssertTrue(entry.locked)
        XCTAssertFalse(entry.connected)

        let model = AppModel()
        model.setDomains([entry])
        XCTAssertTrue(model.hasLockedVaults, "Unlock Vaults must be offered")
        XCTAssertFalse(model.hasUnlockedVaults, "Lock Vaults must not be offered")
    }

    /// A normal registered vault is the mirror image: unlockable actions only.
    func testRegisteredEntryCountsAsUnlocked() {
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil)
        let model = AppModel()
        model.setDomains([entry])
        XCTAssertTrue(model.hasUnlockedVaults)
        XCTAssertFalse(model.hasLockedVaults)
    }

    /// The preserved identifier is what lets `restoreVault` re-add the domain and still find its
    /// metadata cache, progress snapshot and credential — all keyed by it.
    func testRemovedEntryPreservesIdentifierAndName() {
        let domain = makeDomain("Apricot")
        let entry = DomainEntry(domain: domain, account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil, isRemoved: true)
        XCTAssertEqual(entry.id, domain.identifier.rawValue)
        XCTAssertEqual(entry.displayName, "Apricot")
    }

    // MARK: - Route pruning on domain disappearance

    /// Deleting the vault you are viewing must return you to Home — its detail route is dead.
    func testDeletedDomainPopsBackToHome() {
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil)
        let model = AppModel()
        model.setDomains([entry])
        model.path = [.domainDetail(domainID: entry.id)]

        model.setDomains([])

        XCTAssertTrue(model.path.isEmpty)
    }

    /// A file list nested under a deleted domain's detail screen goes too — keeping it would
    /// strand the child with no parent behind it.
    func testDeletedDomainPrunesNestedRoutes() {
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil)
        let model = AppModel()
        model.setDomains([entry])
        model.path = [.domainDetail(domainID: entry.id),
                      .fileList(domainID: entry.id, kind: .materialized)]

        model.setDomains([])

        XCTAssertTrue(model.path.isEmpty)
    }

    /// Deleting one vault must not disturb a route scoped to a different, surviving vault.
    func testSurvivingDomainRouteIsKept() {
        let kept = DomainEntry(domain: makeDomain("Kept"), account: makeAccount(),
                               uploadProgress: nil, downloadProgress: nil)
        let deleted = DomainEntry(domain: makeDomain("Gone"), account: makeAccount(),
                                  uploadProgress: nil, downloadProgress: nil)
        let model = AppModel()
        model.setDomains([kept, deleted])
        model.path = [.domainDetail(domainID: kept.id)]

        model.setDomains([kept])

        XCTAssertEqual(model.path, [.domainDetail(domainID: kept.id)])
    }

    /// Domain-independent routes are unaffected by domains coming and going.
    func testDomainIndependentRoutesSurvive() {
        let model = AppModel()
        model.path = [.security]
        model.setDomains([])
        XCTAssertEqual(model.path, [.security])
    }

    /// A locked-and-removed vault is still present in the list, so its detail route stays valid.
    func testRemovedButPreservedDomainKeepsItsRoute() {
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: nil, downloadProgress: nil, isRemoved: true)
        let model = AppModel()
        model.setDomains([entry])
        model.path = [.domainDetail(domainID: entry.id)]

        model.setDomains([entry])

        XCTAssertEqual(model.path, [.domainDetail(domainID: entry.id)])
    }

    func testSetDomainsPublishesActivity() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let model = AppModel()
        let progress = Progress(totalUnitCount: 100)
        progress.completedUnitCount = 10
        let entry = DomainEntry(domain: makeDomain(), account: makeAccount(),
                                uploadProgress: progress, downloadProgress: nil)
        model.setDomains([entry])
        XCTAssertEqual(model.domains.count, 1)
        XCTAssertEqual(model.activity, .active)
    }
}
