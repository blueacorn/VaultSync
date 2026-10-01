// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Common
import FileProvider
import os

/// Tells the system a domain's backend is reachable again.
///
/// A `serverUnreachable` reply makes fileproviderd hold the domain's work until
/// `signalErrorResolved(.serverUnreachable)`. Any backend that fails fast on a transient
/// server condition (e.g. a throttling cool-off) calls this when the condition clears, so
/// the system resumes without waiting on the app's UI.
enum ServerReachabilitySignal {

    private static let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "extension")

    /// Signal `serverUnreachable` resolved for `domainID`. Best-effort.
    static func resolve(domainID: String) async {
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: domainID),
                                          displayName: domainID)
        guard let manager = NSFileProviderManager(for: domain) else { return }
        do {
            try await manager.signalErrorResolved(NSFileProviderError(.serverUnreachable))
            logger.infoPublic("📶 signalErrorResolved(serverUnreachable) domain=\(domainID)")
        } catch {
            logger.errorPublic("❌ signalErrorResolved(serverUnreachable) failed domain=\(domainID): \(String(describing: error))")
        }
    }
}
