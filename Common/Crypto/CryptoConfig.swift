/// Encryption algorithm selection and per-domain crypto configuration.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

public enum CryptoAlgorithm: String, Codable, CaseIterable, Equatable {
    case plain
    case bc01

    public var displayName: String {
        switch self {
        case .plain: return "No Encryption"
        case .bc01: return "Boxcryptor (BC01)"
        }
    }
}

public struct DomainCryptoConfig: Codable, Equatable {
    public var algorithm: CryptoAlgorithm
    /// User ID from `.bckey` `users[0].id`; matched against `encryptedFileKeys[x].id` in `.bc` headers.
    public var userId: String
    /// Filesystem path to the .bckey file. Cleared to `""` after successful key derivation.
    public var bckeyPath: String

    public init(algorithm: CryptoAlgorithm = .plain, userId: String = "", bckeyPath: String = "") {
        self.algorithm = algorithm
        self.userId = userId
        self.bckeyPath = bckeyPath
    }
}

extension DomainCryptoConfig {
    /// Lenient decode: absent keys keep their ``init(algorithm:userId:bckeyPath:)`` defaults.
    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        algorithm = try c.decodeIfPresent(CryptoAlgorithm.self, forKey: .algorithm) ?? algorithm
        userId = try c.decodeIfPresent(String.self, forKey: .userId) ?? userId
        bckeyPath = try c.decodeIfPresent(String.self, forKey: .bckeyPath) ?? bckeyPath
    }
}
