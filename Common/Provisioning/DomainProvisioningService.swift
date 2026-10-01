/// Protocol for backend-agnostic domain provisioning.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Abstracts backend-specific account creation/removal so UI layers have no
/// compile-time dependency on any concrete backend (emulator, OneDrive, etc.).
public protocol DomainProvisioningService: AnyObject {
    /// Called when a domain is saved. The backend creates or updates its internal account record.
    ///
    /// - Parameters:
    ///   - domainIdentifier: ``NSFileProviderDomainIdentifier.rawValue`` for the domain.
    ///   - displayName: Human-readable domain name.
    ///   - remotePath: Backend path (local filesystem path for emulator/localFS; remote path for cloud).
    func provision(domainIdentifier: String, displayName: String, remotePath: String?) throws

    /// Called when a domain is removed. The backend deletes its internal account record.
    ///
    /// - Parameter domainIdentifier: ``NSFileProviderDomainIdentifier.rawValue`` for the domain.
    func deprovision(domainIdentifier: String) throws

    /// Resets the sync anchor for a domain, forcing re-enumeration from scratch.
    ///
    /// - Parameter domainIdentifier: ``NSFileProviderDomainIdentifier.rawValue`` for the domain.
    func resetSyncAnchor(domainIdentifier: String) throws

    /// Rebuilds the domain's metadata index from the remote: a full re-crawl whose items replace
    /// what the index holds, dropping entries the remote no longer has. Local-only metadata
    /// (tags, resolved sizes) is kept. Backends without a remote index treat this as a no-op.
    ///
    /// - Parameter domainIdentifier: ``NSFileProviderDomainIdentifier.rawValue`` for the domain.
    func rebuildIndex(domainIdentifier: String) async throws
}
