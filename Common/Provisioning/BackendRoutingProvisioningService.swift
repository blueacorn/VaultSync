/// Routes provisioning calls to the service that owns the domain's backend.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider

/// A ``DomainProvisioningService`` that dispatches each call to the service registered for the
/// domain's ``BackendKind``.
///
/// Only emulator-backed domains have a `StandaloneServer` account row; cloud backends keep no
/// provisioning state of their own. Installing ``EmulatorProvisioningService`` globally meant a
/// OneDrive vault's delete reached the emulator server — which is started lazily and so may never
/// have opened its database. Routing by backend keeps each service off domains it does not own.
///
/// A domain with no configured account, or one whose backend has no registered service, is a
/// no-op: there is nothing backend-side to provision or remove.
public final class BackendRoutingProvisioningService: DomainProvisioningService {

    /// Resolves a domain identifier to its backend, normally via ``SharedConfigStore``.
    private let backendKind: (String) -> BackendKind?
    private let services: [BackendKind: any DomainProvisioningService]

    /// - Parameters:
    ///   - services: The provisioning service for each backend that has one. Backends absent
    ///     from this map need no provisioning.
    ///   - backendKind: Looks up a domain's backend. Defaults to the shared config store.
    public init(services: [BackendKind: any DomainProvisioningService],
                backendKind: @escaping (String) -> BackendKind? = { domainIdentifier in
                    SharedConfigStore.shared
                        .account(for: NSFileProviderDomainIdentifier(rawValue: domainIdentifier))?
                        .backendKind
                }) {
        self.services = services
        self.backendKind = backendKind
    }

    /// The service owning `domainIdentifier`, or `nil` when its backend needs no provisioning.
    private func service(for domainIdentifier: String) -> (any DomainProvisioningService)? {
        guard let kind = backendKind(domainIdentifier) else { return nil }
        return services[kind]
    }

    public func provision(domainIdentifier: String, displayName: String, remotePath: String?) throws {
        try service(for: domainIdentifier)?.provision(domainIdentifier: domainIdentifier,
                                                      displayName: displayName,
                                                      remotePath: remotePath)
    }

    public func deprovision(domainIdentifier: String) throws {
        try service(for: domainIdentifier)?.deprovision(domainIdentifier: domainIdentifier)
    }

    public func resetSyncAnchor(domainIdentifier: String) throws {
        try service(for: domainIdentifier)?.resetSyncAnchor(domainIdentifier: domainIdentifier)
    }

    public func rebuildIndex(domainIdentifier: String) async throws {
        try await service(for: domainIdentifier)?.rebuildIndex(domainIdentifier: domainIdentifier)
    }
}
