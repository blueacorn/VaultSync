/// Unit tests for `DomainDeprovisioningService`.
//
//  DomainDeprovisioningServiceTests.swift
//  CommonTests
//
//  Verifies the composite ``DefaultDomainDeprovisioningService``: every step runs, a single
//  failing step does not skip the others (and surfaces as an aggregate error), and the
//  `.standard` pipeline's per-domain steps (token sign-out, key-material forget) touch only
//  the domain being torn down — no sibling survey, no reference-counting.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
@testable import Common

/// Keychain-isolated, not merely config-isolated: the `.standard` pipeline provisions and forgets
/// real domain key material through ``VaultKeyStore``. `isolatedForTesting()` holds only the VMK
/// in memory — every slot it writes lands on the production service names — so without a test
/// namespace this suite minted a `vault.vmk.wrapped` beside the user's own vault root.
final class DomainDeprovisioningServiceTests: KeychainIsolatedTestCase {

    private let domain = NSFileProviderDomainIdentifier(rawValue: "deprovision-test-domain")

    // MARK: - Step orchestration

    /// All steps run in order on a clean teardown.
    func testAllStepsRunInOrder() async throws {
        var order: [String] = []
        let service = DefaultDomainDeprovisioningService(steps: [
            DomainCleanupStep(name: "a") { _, _ in order.append("a") },
            DomainCleanupStep(name: "b") { _, _ in order.append("b") },
            DomainCleanupStep(name: "c") { _, _ in order.append("c") }
        ])

        try await service.tearDown(domain: domain, displayName: "Test")

        XCTAssertEqual(order, ["a", "b", "c"])
    }

    /// A failing step does not abort the remaining steps; the failure surfaces as an aggregate.
    func testFailingStepDoesNotSkipOthersAndAggregates() async throws {
        struct StepError: Error {}
        var ran: [String] = []
        let service = DefaultDomainDeprovisioningService(steps: [
            DomainCleanupStep(name: "first") { _, _ in ran.append("first") },
            DomainCleanupStep(name: "boom") { _, _ in ran.append("boom"); throw StepError() },
            DomainCleanupStep(name: "last") { _, _ in ran.append("last") }
        ])

        do {
            try await service.tearDown(domain: domain, displayName: "Test")
            XCTFail("expected aggregate error")
        } catch let error as DomainDeprovisioningError {
            XCTAssertEqual(error.stepsFailed.map(\.step), ["boom"])
        }

        XCTAssertEqual(ran, ["first", "boom", "last"], "every step still ran despite the failure")
    }

    // MARK: - Credential sign-out (`.standard` pipeline)

    /// Credentials are domain-scoped: the refresh token is keyed by the domain's own
    /// identifier, so teardown signs out exactly that key and nothing else. A sibling
    /// OneDrive domain's credential is a different key and must be untouched — there is no
    /// sharing to reference-count.
    func testSignsOutOwnDomainKeyOnly() async throws {
        let store = SharedConfigStore.shared
        let domainA = NSFileProviderDomainIdentifier(rawValue: "signout-A-\(UUID().uuidString)")
        let domainB = NSFileProviderDomainIdentifier(rawValue: "signout-B-\(UUID().uuidString)")
        defer {
            store.removeAllConfiguration(for: domainA)
            store.removeAllConfiguration(for: domainB)
        }

        store.setAccount(DomainAccount(displayName: "A", backendKind: .oneDrive), for: domainA)
        store.setAccount(DomainAccount(displayName: "B", backendKind: .oneDrive), for: domainB)

        var signedOut: [String] = []
        func makeService() -> DefaultDomainDeprovisioningService {
            .standard(
                configStore: store,
                tokenSignOut: { signedOut.append($0) },
                backendResourceDestroy: { _, _ in },
                backendResourceEmpty: { _, _ in },
                keyStore: .isolatedForTesting()
            )
        }

        try await makeService().tearDown(domain: domainA, displayName: "A")
        XCTAssertEqual(signedOut, [domainA.rawValue], "signs out its own key")
        XCTAssertNil(store.account(for: domainA), "A's config cleared")
        XCTAssertNotNil(store.account(for: domainB), "B untouched")

        try await makeService().tearDown(domain: domainB, displayName: "B")
        XCTAssertEqual(signedOut, [domainA.rawValue, domainB.rawValue])
    }

    /// A backend that holds no OAuth identity (emulator/localFS) never triggers sign-out.
    func testNoCredentialNeverSignsOut() async throws {
        let store = SharedConfigStore.shared
        let domainID = NSFileProviderDomainIdentifier(rawValue: "nocred-\(UUID().uuidString)")
        defer { store.removeAllConfiguration(for: domainID) }
        store.setAccount(DomainAccount(displayName: "Emu", backendKind: .emulator), for: domainID)

        var signedOut: [String] = []
        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { signedOut.append($0) },
            backendResourceDestroy: { _, _ in },
            backendResourceEmpty: { _, _ in },
            keyStore: .isolatedForTesting()
        )

        try await service.tearDown(domain: domainID, displayName: "Emu")
        XCTAssertEqual(signedOut, [])
        XCTAssertNil(store.account(for: domainID))
    }

    // MARK: - Step ordering / backend routing (`.standard` pipeline)

    /// `config-clear` must run **after** `backend-resource-destroy`, because the destroy step
    /// resolves the domain's ``BackendKind`` from the account row. Clearing config first would
    /// erase the routing information, so this ordering is load-bearing.
    func testConfigClearRunsAfterBackendResourceDestroyAndBackendStillResolves() async throws {
        let store = SharedConfigStore.shared
        let domainID = NSFileProviderDomainIdentifier(rawValue: "ordering-\(UUID().uuidString)")
        defer { store.removeAllConfiguration(for: domainID) }
        store.setAccount(DomainAccount(displayName: "Vault", backendKind: .oneDrive), for: domainID)

        var observedBackend: BackendKind??
        var configClearedBeforeDestroy = false
        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { _ in },
            backendResourceDestroy: { domain, backend in
                observedBackend = .some(backend)
                // If config-clear had already run, the account row would be gone.
                configClearedBeforeDestroy = store.account(
                    for: NSFileProviderDomainIdentifier(rawValue: domain)) == nil
            },
            backendResourceEmpty: { _, _ in },
            keyStore: .isolatedForTesting()
        )

        try await service.tearDown(domain: domainID, displayName: "Vault")

        XCTAssertFalse(configClearedBeforeDestroy, "config-clear must run after backend-resource-destroy")
        XCTAssertEqual(observedBackend, .some(.oneDrive), "backend still resolvable in the destroy step")
        XCTAssertNil(store.account(for: domainID), "config cleared by the end of teardown")
    }

    /// A domain with no account row still gets the destroy step, with a `nil` backend: the
    /// shared stores must be removed even when routing information is unavailable.
    func testUnknownBackendStillRunsDestroyStep() async throws {
        let store = SharedConfigStore.shared
        let domainID = NSFileProviderDomainIdentifier(rawValue: "unconfigured-\(UUID().uuidString)")

        var destroyed: [String] = []
        var observedBackend: BackendKind??
        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { _ in },
            backendResourceDestroy: { domain, backend in
                destroyed.append(domain)
                observedBackend = .some(backend)
            },
            backendResourceEmpty: { _, _ in },
            keyStore: .isolatedForTesting()
        )

        try await service.tearDown(domain: domainID, displayName: "Ghost")

        XCTAssertEqual(destroyed, [domainID.rawValue], "shared stores still torn down")
        XCTAssertEqual(observedBackend, .some(nil), "no account row → nil backend")
    }

    // MARK: - Local-data-only teardown

    /// "Lock and Remove Vault" must keep the configuration that lets a vault be restored:
    /// it empties the metadata cache and touches nothing else.
    func testTearDownLocalDataPreservesConfigAndCredential() async throws {
        let store = SharedConfigStore.shared
        let domainID = NSFileProviderDomainIdentifier(rawValue: "localdata-\(UUID().uuidString)")
        defer { store.removeAllConfiguration(for: domainID) }
        store.setAccount(DomainAccount(displayName: "Vault", backendKind: .oneDrive), for: domainID)

        var signedOut: [String] = []
        var destroyed: [String] = []
        var emptied: [String] = []
        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { signedOut.append($0) },
            backendResourceDestroy: { domainID, _ in destroyed.append(domainID) },
            backendResourceEmpty: { domainID, _ in emptied.append(domainID) },
            keyStore: .isolatedForTesting()
        )

        try await service.tearDownLocalData(domain: domainID, displayName: "Vault")

        XCTAssertEqual(emptied, [domainID.rawValue], "backend resources emptied")
        XCTAssertEqual(destroyed, [], "must not delete the cache file")
        XCTAssertEqual(signedOut, [], "must not sign the credential out")
        XCTAssertNotNil(store.account(for: domainID), "config must survive so unlock can restore")
    }

    /// The full teardown keeps its existing behaviour: destroy, never empty.
    func testTearDownDestroysRatherThanEmpties() async throws {
        let store = SharedConfigStore.shared
        let domainID = NSFileProviderDomainIdentifier(rawValue: "fullteardown-\(UUID().uuidString)")
        defer { store.removeAllConfiguration(for: domainID) }
        store.setAccount(DomainAccount(displayName: "Vault", backendKind: .emulator), for: domainID)

        var destroyed: [String] = []
        var emptied: [String] = []
        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { _ in },
            backendResourceDestroy: { domainID, _ in destroyed.append(domainID) },
            backendResourceEmpty: { domainID, _ in emptied.append(domainID) },
            keyStore: .isolatedForTesting()
        )

        try await service.tearDown(domain: domainID, displayName: "Vault")

        XCTAssertEqual(destroyed, [domainID.rawValue])
        XCTAssertEqual(emptied, [])
        XCTAssertNil(store.account(for: domainID))
    }

    // MARK: - Key material forgetting

    /// Deleting a vault must forget its key material. Leaving the wrapped slots behind leaks
    /// twelve keychain items per deleted domain and leaves an orphaned `domainKey.wrapped` with
    /// no gating key ever meant to re-open it.
    func testFullTearDownForgetsKeyMaterial() async throws {
        let store = SharedConfigStore.shared
        let keyStore = VaultKeyStore.isolatedForTesting()
        let domainID = NSFileProviderDomainIdentifier(rawValue: "forget-\(UUID().uuidString)")
        defer {
            store.removeAllConfiguration(for: domainID)
            try? keyStore.forgetDomain(domainID.rawValue)
        }
        store.setAccount(DomainAccount(displayName: "Vault", backendKind: .emulator), for: domainID)

        try await keyStore.provisionDomain(userIdentityKeyDER: Data(repeating: 7, count: 64),
                                           for: domainID.rawValue)
        XCTAssertNotNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainID.rawValue),
                        "precondition: domain has wrapped material")

        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { _ in },
            backendResourceDestroy: { _, _ in },
            backendResourceEmpty: { _, _ in },
            keyStore: keyStore
        )
        try await service.tearDown(domain: domainID, displayName: "Vault")

        XCTAssertNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainID.rawValue),
                     "wrapped user identity slot forgotten")
        XCTAssertNil(try CryptoKeychain.loadWrappedFileKeysKEK(for: domainID.rawValue),
                     "wrapped file-keys KEK forgotten")
        XCTAssertNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainID.rawValue),
                     "unwrapped file-keys KEK forgotten")
    }

    /// "Lock and Remove Vault" must NOT forget key material — the vault is restored on unlock
    /// without re-provisioning, which requires the wrapped slots to survive.
    func testLocalDataTearDownPreservesKeyMaterial() async throws {
        let store = SharedConfigStore.shared
        let keyStore = VaultKeyStore.isolatedForTesting()
        let domainID = NSFileProviderDomainIdentifier(rawValue: "keep-\(UUID().uuidString)")
        defer {
            store.removeAllConfiguration(for: domainID)
            try? keyStore.forgetDomain(domainID.rawValue)
        }
        store.setAccount(DomainAccount(displayName: "Vault", backendKind: .emulator), for: domainID)

        try await keyStore.provisionDomain(userIdentityKeyDER: Data(repeating: 9, count: 64),
                                           for: domainID.rawValue)

        let service = DefaultDomainDeprovisioningService.standard(
            configStore: store,
            tokenSignOut: { _ in },
            backendResourceDestroy: { _, _ in },
            backendResourceEmpty: { _, _ in },
            keyStore: keyStore
        )
        try await service.tearDownLocalData(domain: domainID, displayName: "Vault")

        XCTAssertNotNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainID.rawValue),
                        "wrapped material must survive so unlock can restore the vault")
    }
}
