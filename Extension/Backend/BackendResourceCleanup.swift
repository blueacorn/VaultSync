/// Shared entry point for tearing down a domain's on-disk resources, with backend routing.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// Host-facing teardown of the on-disk stores a domain owns.
///
/// Teardown splits along the axis that actually varies:
///
/// - **Shared** — every backend has a metadata cache and a BC01 header cache
///   in the same App Group container, torn down the same way. These steps run *unconditionally*,
///   including for an unknown or `nil` backend: they are idempotent, and a domain whose config
///   was already cleared must still have its files removed.
/// - **Backend-specific** — only OneDrive has Graph delta state, only LocalFileSystem will have
///   a security-scoped bookmark. This step is additive, gated on resolving a ``BackendKind``,
///   and routed through a registry — the same idiom as ``BackendRoutingProvisioningService``,
///   so provisioning and deprovisioning share one routing pattern rather than two.
///
/// The stores are internal to the `Extension` module; this exposes just the deletion the host
/// needs when wiring a `DomainDeprovisioningService` (see `DefaultDomainDeprovisioningService.standard`).
public enum BackendResourceCleanup {

    /// Backends with on-disk state beyond the shared stores. Absent = shared steps only, which
    /// is the correct default for a backend that owns nothing of its own.
    ///
    /// Deliberately empty today:
    /// - OneDrive's delta cursor and crawl marks live in ``MetadataCache``'s `meta` table, so
    ///   they are already covered by the shared destroy/empty.
    /// - The emulator's `StandaloneServer` account row is removed by
    ///   ``BackendRoutingProvisioningService/deprovision(domainIdentifier:)`` →
    ///   `EmulatorProvisioningService.deprovision`, a separate pipeline.
    ///
    /// An entry that does nothing is the duplicate-path smell this routing exists to remove;
    /// add one the moment a backend has genuinely backend-only on-disk state (LocalFileSystem's
    /// bookmark is the next expected case).
    private static let backendSpecific: [BackendKind: any BackendResourceCleaning] = [:]

    /// Full teardown on domain deletion: unlinks every store the domain owns.
    ///
    /// Idempotent — a domain that never had a store, or a second call, is not an error. The
    /// caller must ensure no live store handle for the domain remains open.
    ///
    /// - Parameters:
    ///   - domainID: The domain identifier whose stores are being removed.
    ///   - backend: The domain's backend, resolved from configuration before the config is
    ///     cleared. `nil` runs the shared steps only.
    public static func destroy(domainID: String, backend: BackendKind?) throws {
        try MetadataCache.destroy(domainID: domainID)
        try BC01HeaderCache.destroy(domainID: domainID)
        // The progress snapshot is per-domain App Group state like the stores above, so a full
        // teardown owns it too. `empty` deliberately does not: that path keeps the domain.
        ProgressStore.shared.remove(for: domainID)
        if let backend { try backendSpecific[backend]?.destroy(domainID: domainID) }
    }

    /// Local-data-only teardown ("Lock and Remove Vault"): clears rebuildable rows in place,
    /// leaving the database files and any open handle valid.
    ///
    /// Safe to call while the Provider holds a store open — unlike ``destroy(domainID:backend:)``.
    /// The domain's configuration is preserved so unlocking can re-populate from the server.
    ///
    /// - Parameters:
    ///   - domainID: The domain identifier whose stores are being emptied.
    ///   - backend: The domain's backend. `nil` runs the shared steps only.
    public static func empty(domainID: String, backend: BackendKind?) throws {
        try MetadataCache(domainID: domainID).empty()
        // Locking destroys the domain's `fileKeysKEK`, so every retained header row would be
        // permanently unreadable ballast — emptying is correct on its own terms, not just safe.
        try BC01HeaderCache(domainID: domainID).empty()
        if let backend { try backendSpecific[backend]?.empty(domainID: domainID) }
    }
}
