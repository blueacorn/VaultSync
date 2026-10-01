/// Resolves a domain's ``BackendKind`` to a concrete ``ProviderBackend``.
///
/// The extension reads the host-owned ``DomainAccount`` binding from
/// ``SharedConfigStore`` and asks the factory for the backend that services the
/// domain's content and enumeration. This is the single routing point that
/// replaces the old `requireEmulatorBackend()` guard.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import FileProvider

public enum BackendFactory {

    /// Build the backend for `domain` according to its `SharedConfig` binding.
    ///
    /// - Parameters:
    ///   - domain: The provider domain to service.
    ///   - hostname: Host for the emulator's local HTTP server.
    ///   - port: Port for the emulator's local HTTP server.
    /// - Throws: ``CommonError/notImplemented`` for backends not yet wired.
    public static func make(for domain: NSFileProviderDomain,
                            hostname: String,
                            port: in_port_t) throws -> ProviderBackend {
        let account = SharedConfigStore.shared.account(for: domain.identifier)
        let kind = account?.backendKind ?? .emulator
        switch kind {
        case .emulator:
            return ServerEmulatorClient(domain,
                                        secret: UserDefaults.sharedContainerDefaults.secret(for: domain.identifier),
                                        hostname: hostname,
                                        port: port)
        case .oneDrive:
            guard let account else { throw CommonError.parameterError }
            // The OAuth refresh token is keyed by the domain identifier; no separate
            // credential id to resolve from the account row.
            return GraphDriveClient(displayName: account.displayName,
                                    domainID: domain.identifier.rawValue,
                                    servingItemID: account.remoteItemID)
        case .localFS:
            throw CommonError.notImplemented
        }
    }
}
