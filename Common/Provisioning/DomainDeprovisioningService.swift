/// Protocol for backend-agnostic full resource teardown on domain deletion.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider

/// The inverse of ``DomainProvisioningService``: when a domain is removed from the UI,
/// every store that persisted state keyed by the domain must drop it.
///
/// Provisioning scatters a domain's state across several stores (config JSON, App Group
/// keychain, per-domain SQLite caches, security-scoped bookmarks). Deprovisioning collects
/// the inverse of each into one place so deletion can't silently orphan a store, and so new
/// backends extend cleanup by registering a step rather than editing call sites.
///
/// Implementations are idempotent and best-effort: a failure in one store is reported but
/// must not prevent the remaining stores from being cleaned.
public protocol DomainDeprovisioningService: AnyObject {

    /// Remove all persisted resources attached to `domain`.
    ///
    /// - Parameters:
    ///   - domain: Identifier of the domain being deleted.
    ///   - displayName: Human-readable name, for diagnostics.
    /// - Throws: ``DomainDeprovisioningError/stepsFailed(_:)`` if one or more cleanup steps
    ///   failed. Steps that succeeded are not rolled back.
    func tearDown(domain: NSFileProviderDomainIdentifier,
                  displayName: String) async throws

    /// Drop only a domain's **local, reconstructible** state, preserving the configuration
    /// needed to restore it later (account, credential, secret, bookmark).
    ///
    /// The partial inverse of provisioning, used by "Lock and Remove Vault": the
    /// vault's local data and metadata become unreadable, but the domain can be re-added and
    /// re-populated on unlock without re-authenticating. Remote data is never touched.
    ///
    /// Distinct from ``tearDown(domain:displayName:)``, which additionally signs the OAuth
    /// token out and clears per-domain configuration — irreversible, and wrong here.
    ///
    /// - Parameters:
    ///   - domain: Identifier of the domain whose local data is being dropped.
    ///   - displayName: Human-readable name, for diagnostics.
    /// - Throws: ``DomainDeprovisioningError`` if one or more cleanup steps failed. Steps that
    ///   succeeded are not rolled back.
    func tearDownLocalData(domain: NSFileProviderDomainIdentifier,
                           displayName: String) async throws
}

/// Aggregate error describing which cleanup steps failed during ``DomainDeprovisioningService/tearDown(domain:displayName:)``.
public struct DomainDeprovisioningError: Error, CustomStringConvertible, LocalizedError {
    /// Per-step failures keyed by the step's human-readable name.
    public let stepsFailed: [(step: String, error: Error)]

    public init(stepsFailed: [(step: String, error: Error)]) {
        self.stepsFailed = stepsFailed
    }

    public var description: String {
        let parts = stepsFailed.map { "\($0.step): \($0.error)" }
        return "domain deprovisioning failed for steps — " + parts.joined(separator: "; ")
    }

    /// Mirrors ``description``.
    ///
    /// Without this, `localizedDescription` falls back to the generic "The operation couldn't be
    /// completed. (Common.DomainDeprovisioningError error 1.)" — which named neither the failing
    /// step nor its cause, and hid a lock-and-remove that had left the entire file index on disk.
    public var errorDescription: String? { description }
}
