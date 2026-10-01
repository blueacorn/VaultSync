/// ``DomainProvisioningService`` implementation backed by ``StandaloneServer``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// Provisions emulator database rows on behalf of the host UI.
///
/// The emulator mints its own root item ID internally; no secret is injected at
/// provision time — ``DomainBackend`` pulls the secret from ``SharedConfigStore`` per-request.
public final class EmulatorProvisioningService: DomainProvisioningService {
    private let server: StandaloneServer

    public init(server: StandaloneServer) {
        self.server = server
    }

    public func provision(domainIdentifier: String, displayName: String, remotePath: String?) throws {
        try server.provisionAccount(domainIdentifier: domainIdentifier)
    }

    public func deprovision(domainIdentifier: String) throws {
        try server.removeAccount(domainIdentifier: domainIdentifier)
    }

    public func resetSyncAnchor(domainIdentifier: String) throws {
        try server.resetSyncAnchor(domainIdentifier: domainIdentifier)
    }

    /// No-op: the emulator serves live from its database; there is no remote index to rebuild.
    public func rebuildIndex(domainIdentifier: String) async throws {}
}
