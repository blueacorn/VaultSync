/// Per-backend on-disk teardown, routed by ``BackendKind``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Teardown of on-disk resources owned by ONE backend, beyond the stores every backend shares.
///
/// Implement only what is genuinely backend-specific — a Graph delta cursor, a security-scoped
/// bookmark, an emulator account row. Anything *every* backend has (the metadata cache, the
/// BC01 header cache) belongs in the shared steps of the extension-side `BackendResourceCleanup`,
/// not here: duplicating it per backend is the drift this protocol exists to avoid.
///
/// Both requirements have default no-op bodies so a backend implements only the half it needs.
public protocol BackendResourceCleaning: Sendable {

    /// Remove the backend's own on-disk state for `domainID`.
    ///
    /// Idempotent: missing state is not an error.
    func destroy(domainID: String) throws

    /// Clear the backend's rebuildable state in place, leaving files and open handles valid.
    ///
    /// Used by the local-data-only teardown ("Lock and Remove Vault"), where the domain's
    /// configuration is preserved so unlocking can re-populate from the server.
    func empty(domainID: String) throws
}

public extension BackendResourceCleaning {
    func destroy(domainID: String) throws {}
    func empty(domainID: String) throws {}
}
