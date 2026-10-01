/// ``DomainProvisioningService`` for OneDrive domains: host-side index maintenance.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider
import Common

/// OneDrive keeps no provisioning state of its own; its one host-side operation is
/// ``rebuildIndex(domainIdentifier:)``.
///
/// Rebuild opens a new full-crawl generation in the domain's ``MetadataCache`` and signals the
/// working set. The extension's delta poller then crawls from scratch and sweeps rows the crawl
/// did not return — the same path as a `410 Gone` recovery, with no new IPC. Opening the cache
/// from the app while the extension holds it is safe (SQLite busy timeout).
public final class OneDriveProvisioningService: DomainProvisioningService {

    private let beginFullCrawl: (String) throws -> Void
    private let signalWorkingSet: (String) async throws -> Void

    /// - Parameters:
    ///   - beginFullCrawl: Opens a full-crawl generation for a domain's cache.
    ///   - signalWorkingSet: Signals the domain's working-set enumerator.
    init(beginFullCrawl: @escaping (String) throws -> Void,
         signalWorkingSet: @escaping (String) async throws -> Void) {
        self.beginFullCrawl = beginFullCrawl
        self.signalWorkingSet = signalWorkingSet
    }

    public convenience init() {
        self.init(beginFullCrawl: { domainID in
                      try MetadataCache(domainID: domainID).beginFullCrawl()
                      // Flip the detail panel to crawl progress now, not at the first page.
                      ProgressStore.shared.update(domainID: domainID) { $0.fullCrawlItemsSeen = 0 }
                  },
                  signalWorkingSet: Self.signalWorkingSet(domainIdentifier:))
    }

    public func provision(domainIdentifier: String, displayName: String, remotePath: String?) throws {}

    public func deprovision(domainIdentifier: String) throws {}

    public func resetSyncAnchor(domainIdentifier: String) throws {}

    public func rebuildIndex(domainIdentifier: String) async throws {
        try beginFullCrawl(domainIdentifier)
        try await signalWorkingSet(domainIdentifier)
    }

    /// Signal the working set of the registered domain `domainIdentifier`; absent domain = no-op.
    private static func signalWorkingSet(domainIdentifier: String) async throws {
        let domains = try await NSFileProviderManager.domains()
        guard let domain = domains.first(where: { $0.identifier.rawValue == domainIdentifier }),
              let manager = NSFileProviderManager(for: domain) else { return }
        try await manager.signalEnumerator(for: .workingSet)
    }
}
