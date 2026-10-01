/// Placeholder ``DomainDeprovisioningService`` that does nothing.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider

/// Used as a default value before a real deprovisioning service is injected.
public final class NoOpDeprovisioningService: DomainDeprovisioningService {
    public init() {}
    public func tearDown(domain: NSFileProviderDomainIdentifier, displayName: String) async throws {}
    public func tearDownLocalData(domain: NSFileProviderDomainIdentifier, displayName: String) async throws {}
}
