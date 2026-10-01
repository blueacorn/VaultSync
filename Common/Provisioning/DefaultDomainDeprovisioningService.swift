/// Composite ``DomainDeprovisioningService`` that runs an ordered list of cleanup steps.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider

/// One unit of domain teardown — e.g. "clear config", "destroy metadata cache".
///
/// Modelling each store's cleanup as a value lets backends extend deletion by appending a
/// step rather than editing a monolith. Steps run in order; each is best-effort.
public struct DomainCleanupStep {
    /// Human-readable name, used in aggregate error reporting.
    public let name: String
    /// The cleanup action for a domain being deleted.
    public let run: (_ domain: NSFileProviderDomainIdentifier, _ displayName: String) async throws -> Void

    public init(name: String,
                run: @escaping (_ domain: NSFileProviderDomainIdentifier, _ displayName: String) async throws -> Void) {
        self.name = name
        self.run = run
    }
}

/// Runs a fixed list of ``DomainCleanupStep`` in order, collecting failures so one failing
/// store doesn't orphan the rest.
///
/// The concrete steps are supplied at construction so this type stays in `Common` with no
/// dependency on `Extension` (OneDrive ``MetadataCache``) or any concrete token store: the
/// host wires those in (see ``standard(configStore:tokenSignOut:backendResourceDestroy:backendResourceEmpty:)``).
public final class DefaultDomainDeprovisioningService: DomainDeprovisioningService {

    private let steps: [DomainCleanupStep]
    private let localDataSteps: [DomainCleanupStep]

    /// - Parameters:
    ///   - steps: Full teardown, run on domain deletion.
    ///   - localDataSteps: Partial teardown, run by "Lock and Remove Vault" — only the
    ///     reconstructible local state, never configuration.
    public init(steps: [DomainCleanupStep], localDataSteps: [DomainCleanupStep] = []) {
        self.steps = steps
        self.localDataSteps = localDataSteps
    }

    public func tearDown(domain: NSFileProviderDomainIdentifier,
                         displayName: String) async throws {
        try await run(steps, domain: domain, displayName: displayName)
    }

    public func tearDownLocalData(domain: NSFileProviderDomainIdentifier,
                                  displayName: String) async throws {
        try await run(localDataSteps, domain: domain, displayName: displayName)
    }

    /// Run `steps` in order, collecting failures so one failing store doesn't orphan the rest.
    private func run(_ steps: [DomainCleanupStep],
                     domain: NSFileProviderDomainIdentifier,
                     displayName: String) async throws {
        var failures: [(step: String, error: Error)] = []
        for step in steps {
            do {
                try await step.run(domain, displayName)
            } catch {
                failures.append((step.name, error))
            }
        }
        if !failures.isEmpty {
            throw DomainDeprovisioningError(stepsFailed: failures)
        }
    }
}

public extension DefaultDomainDeprovisioningService {

    /// The standard cleanup pipeline used on domain deletion.
    ///
    /// Order:
    /// 1. **Token sign-out**. The refresh token is keyed by the domain identifier and is not
    ///    shared with any other domain, so there is nothing to reference-count.
    /// 2. **Backend resources** destroy — the domain's on-disk stores, plus any backend-specific
    ///    state routed on the ``BackendKind`` resolved from the account row.
    /// 3. **Config** — clear every per-domain entry (account, bookmark, secret, …) last.
    ///
    /// `config-clear` must stay **last**, and every step before it must run while the account
    /// row still exists: both **token-sign-out** (its own OneDrive guard reads
    /// `configStore.account(for:)?.backendKind` to decide whether to sign out at all) and
    /// **backend-resource-destroy** (resolves the domain's ``BackendKind`` the same way) would
    /// silently no-op or lose routing information if config were cleared first. This ordering is
    /// load-bearing, not incidental.
    ///
    /// - Parameters:
    ///   - configStore: The shared config store; read for the domain's backend, and mutated to
    ///     drop the domain's configuration.
    ///   - tokenSignOut: Signs out the OAuth credential keyed by a domain identifier. Injected
    ///     so `Common` needn't depend on a concrete token store. Called only for backends that
    ///     hold one.
    ///   - backendResourceDestroy: Removes a domain's on-disk stores. Injected so `Common`
    ///     needn't depend on `Extension`. Receives the resolved backend, or `nil` when the
    ///     domain has no account row — the shared stores must still be removed in that case.
    ///   - backendResourceEmpty: Clears a domain's rebuildable rows *in place*, leaving the
    ///     database files and any open handle valid. Used by the local-data-only teardown.
    ///   - keyStore: Owns the domain's wrapped/unwrapped key slots; the full teardown forgets
    ///     them. Defaults to ``VaultKeyStore/shared``.
    static func standard(
        configStore: SharedConfigStore,
        tokenSignOut: @escaping (_ domainID: String) async throws -> Void,
        backendResourceDestroy: @escaping (_ domainID: String, _ backend: BackendKind?) throws -> Void,
        backendResourceEmpty: @escaping (_ domainID: String, _ backend: BackendKind?) throws -> Void,
        keyStore: VaultKeyStore = .shared
    ) -> DefaultDomainDeprovisioningService {
        let steps: [DomainCleanupStep] = [
            DomainCleanupStep(name: "token-sign-out") { domain, _ in
                // Credentials are domain-scoped: the token is keyed by this domain's own
                // identifier and shared with nothing, so there is nothing to reference-count.
                //
                // Retained despite `key-material-forget` deleting both token keychain slots,
                // because `MSALTokenStore.signOut` also drops the token store's **in-memory**
                // access-token cache, which `forgetDomain` cannot reach. Must run before
                // `config-clear`: the guard below needs the account row to resolve backend kind.
                guard configStore.account(for: domain)?.backendKind == .oneDrive else {
                    return // No OAuth identity bound (e.g. emulator/localFS).
                }
                try await tokenSignOut(domain.rawValue)
            },
            // Resolves the backend BEFORE "config-clear" runs, which is why that step is last.
            DomainCleanupStep(name: "backend-resource-destroy") { domain, _ in
                try backendResourceDestroy(domain.rawValue, configStore.account(for: domain)?.backendKind)
            },
            // Deleting a vault must also forget its key material: `forgetDomain` removes all
            // twelve of that domain's slots. No cross-domain check is needed or wanted — every
            // one of them is scoped to this domain, so nothing else can reference them, and a
            // survey of sibling domains has no place on a delete path.
            DomainCleanupStep(name: "key-material-forget") { domain, _ in
                try keyStore.forgetDomain(domain.rawValue)
            },
            DomainCleanupStep(name: "config-clear") { domain, _ in
                configStore.removeAllConfiguration(for: domain)
            }
        ]
        // Local-data-only teardown ("Lock and Remove Vault"): drop what can be rebuilt from
        // the server, keep everything needed to restore the domain on unlock. Deliberately
        // excludes token-sign-out and config-clear.
        let localDataSteps: [DomainCleanupStep] = [
            DomainCleanupStep(name: "backend-resource-empty") { domain, _ in
                try backendResourceEmpty(domain.rawValue, configStore.account(for: domain)?.backendKind)
            }
        ]
        return DefaultDomainDeprovisioningService(steps: steps, localDataSteps: localDataSteps)
    }
}
