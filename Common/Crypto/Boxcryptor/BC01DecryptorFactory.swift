/// Single construction point for a domain's BC01 decryptor.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import FileProvider

/// Builds a domain's ``BC01Decryptor`` from its session key, user ID and HMAC policy flag.
///
/// Shared by the Extension fetch path and every backend client so key loading and policy
/// mapping cannot drift between them.
public enum BC01DecryptorFactory {
    /// - Throws: ``NSFileProviderError/notAuthenticated`` when the session private key is not
    ///   loaded (vault locked or never provisioned).
    public static func make(for domainIdentifier: NSFileProviderDomainIdentifier) throws -> BC01Decryptor {
        guard let key = try CryptoKeychain.loadUserIdentityPrivateKey(for: domainIdentifier.rawValue) else {
            throw NSFileProviderError(.notAuthenticated)
        }
        let userID = try CryptoKeychain.loadUserId(for: domainIdentifier.rawValue)
        return BC01Decryptor(rsaPrivateKey: key, userID: userID,
                             hmacPolicy: hmacPolicy(for: domainIdentifier))
    }

    /// Maps ``FeatureFlags/bc01HeaderHMACWarnOnly`` to a ``BC01HeaderHMACPolicy``.
    public static func hmacPolicy(for domainIdentifier: NSFileProviderDomainIdentifier) -> BC01HeaderHMACPolicy {
        let warnOnly = UserDefaults.sharedContainerDefaults
            .featureFlag(for: domainIdentifier, featureFlag: FeatureFlags.bc01HeaderHMACWarnOnly)
        return warnOnly ? .warnOnly : .strict
    }
}
