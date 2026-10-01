/// Placeholder ``DomainProvisioningService`` that does nothing.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Used as a default value before a real provisioning service is injected.
public final class NoOpProvisioningService: DomainProvisioningService {
    public init() {}
    public func provision(domainIdentifier: String, displayName: String, remotePath: String?) throws {}
    public func deprovision(domainIdentifier: String) throws {}
    public func resetSyncAnchor(domainIdentifier: String) throws {}
    public func rebuildIndex(domainIdentifier: String) async throws {}
}
