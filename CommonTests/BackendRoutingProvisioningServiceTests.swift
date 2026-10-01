/// Unit tests for `BackendRoutingProvisioningService`.
//
//  BackendRoutingProvisioningServiceTests.swift
//  CommonTests
//
//  Verifies that provisioning calls reach only the service owning the domain's backend — a
//  OneDrive vault must never be routed to the emulator's StandaloneServer, which is started
//  lazily and may have no database open (that force-unwrapped `itemDB` and crashed on delete).
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
@testable import Common

final class BackendRoutingProvisioningServiceTests: ConfigIsolatedTestCase {

    /// Records which calls it received, standing in for a real backend service.
    private final class SpyProvisioningService: DomainProvisioningService {
        var provisioned: [String] = []
        var deprovisioned: [String] = []
        var anchorsReset: [String] = []
        var indexesRebuilt: [String] = []

        func provision(domainIdentifier: String, displayName: String, remotePath: String?) throws {
            provisioned.append(domainIdentifier)
        }
        func deprovision(domainIdentifier: String) throws { deprovisioned.append(domainIdentifier) }
        func resetSyncAnchor(domainIdentifier: String) throws { anchorsReset.append(domainIdentifier) }
        func rebuildIndex(domainIdentifier: String) async throws { indexesRebuilt.append(domainIdentifier) }
    }

    private func makeService(_ spy: SpyProvisioningService,
                             kind: BackendKind?) -> BackendRoutingProvisioningService {
        BackendRoutingProvisioningService(services: [.emulator: spy], backendKind: { _ in kind })
    }

    /// The regression: a OneDrive domain must not reach the emulator service at all.
    func testOneDriveDomainNeverReachesEmulatorService() throws {
        let spy = SpyProvisioningService()
        let service = makeService(spy, kind: .oneDrive)

        try service.deprovision(domainIdentifier: "onedrive-domain")
        try service.provision(domainIdentifier: "onedrive-domain", displayName: "V", remotePath: nil)
        try service.resetSyncAnchor(domainIdentifier: "onedrive-domain")

        XCTAssertEqual(spy.deprovisioned, [])
        XCTAssertEqual(spy.provisioned, [])
        XCTAssertEqual(spy.anchorsReset, [])
    }

    /// An emulator domain still routes through, so existing behaviour is unchanged.
    func testEmulatorDomainRoutesToEmulatorService() throws {
        let spy = SpyProvisioningService()
        let service = makeService(spy, kind: .emulator)

        try service.provision(domainIdentifier: "emu", displayName: "V", remotePath: "/tmp")
        try service.deprovision(domainIdentifier: "emu")
        try service.resetSyncAnchor(domainIdentifier: "emu")

        XCTAssertEqual(spy.provisioned, ["emu"])
        XCTAssertEqual(spy.deprovisioned, ["emu"])
        XCTAssertEqual(spy.anchorsReset, ["emu"])
    }

    /// Rebuild Index reaches only the service registered for the domain's backend.
    func testRebuildIndexRoutesByBackend() async throws {
        let emulator = SpyProvisioningService()
        let oneDrive = SpyProvisioningService()
        var kinds: [String: BackendKind] = ["od": .oneDrive, "emu": .emulator]
        let service = BackendRoutingProvisioningService(
            services: [.emulator: emulator, .oneDrive: oneDrive],
            backendKind: { kinds[$0] })

        try await service.rebuildIndex(domainIdentifier: "od")
        try await service.rebuildIndex(domainIdentifier: "emu")
        kinds = [:]
        try await service.rebuildIndex(domainIdentifier: "od")

        XCTAssertEqual(oneDrive.indexesRebuilt, ["od"])
        XCTAssertEqual(emulator.indexesRebuilt, ["emu"])
    }

    /// A domain whose config is already gone resolves to no backend: a no-op, not a crash.
    func testUnknownDomainIsNoOp() throws {
        let spy = SpyProvisioningService()
        let service = makeService(spy, kind: nil)

        XCTAssertNoThrow(try service.deprovision(domainIdentifier: "vanished"))
        XCTAssertEqual(spy.deprovisioned, [])
    }

    /// A backend with no registered service (localFS) is likewise a no-op.
    func testBackendWithoutRegisteredServiceIsNoOp() throws {
        let spy = SpyProvisioningService()
        let service = makeService(spy, kind: .localFS)

        XCTAssertNoThrow(try service.deprovision(domainIdentifier: "local"))
        XCTAssertEqual(spy.deprovisioned, [])
    }

    /// The default resolver reads the shared config store, so a real domain routes correctly
    /// without the caller supplying a lookup.
    func testDefaultResolverUsesSharedConfig() throws {
        let store = SharedConfigStore.shared
        let domainID = NSFileProviderDomainIdentifier(rawValue: "routing-\(UUID().uuidString)")
        defer { store.removeAllConfiguration(for: domainID) }
        store.setAccount(DomainAccount(displayName: "Emu", backendKind: .emulator), for: domainID)

        let spy = SpyProvisioningService()
        let service = BackendRoutingProvisioningService(services: [.emulator: spy])

        try service.deprovision(domainIdentifier: domainID.rawValue)

        XCTAssertEqual(spy.deprovisioned, [domainID.rawValue])
    }
}
