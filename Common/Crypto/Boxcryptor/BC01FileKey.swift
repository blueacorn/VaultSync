/// BC01 per-file key layout shared by encryptor and decryptor.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import CryptoKit

/// BC01 file key: `checksum(32) ‖ contentKey(32) ‖ macKey(32)`.
///
/// `checksum = SHA-256(contentKey ‖ macKey)`.
/// See `/docs/crypto/boxcryptor.md` §2.2.
public struct BC01FileKey: Sendable {
    /// AES-256 content key (`[32:64]`): block encryption and per-block IV derivation.
    public let contentKey: Data
    /// HMAC-SHA256 key for the JSON core header (`[64:96]`).
    public let macKey: Data

    static let partSize = 32
    static let fullSize = 96

    /// Fresh 96-byte key with a valid checksum.
    public static func generate() throws -> BC01FileKey {
        BC01FileKey(contentKey: try BC01CryptoCommon.secureRandom(partSize),
                    macKey: try BC01CryptoCommon.secureRandom(partSize))
    }

    /// Parse an RSA-unwrapped key: 96 B, checksum verified.
    ///
    /// - Throws: ``BC01Error/invalidFileKey`` on any other length or a checksum mismatch.
    public init(unwrapped: Data) throws {
        let bytes = Data(unwrapped)
        guard bytes.count == Self.fullSize else { throw BC01Error.invalidFileKey }
        let content = Data(bytes[32..<64])
        let mac = Data(bytes[64..<96])
        guard BC01CryptoCommon.timingSafeEqual(Data(bytes[0..<32]),
                                               Self.checksum(content: content, mac: mac)) else {
            throw BC01Error.invalidFileKey
        }
        self.init(contentKey: content, macKey: mac)
    }

    private init(contentKey: Data, macKey: Data) {
        self.contentKey = contentKey
        self.macKey = macKey
    }

    /// Bytes to RSA-wrap: `SHA256(content‖mac) ‖ content ‖ mac`.
    public var wrappedPlaintext: Data {
        Self.checksum(content: contentKey, mac: macKey) + contentKey + macKey
    }

    /// `HMAC-SHA256(macKey, jsonCore)`.
    public func headerHMAC(_ jsonCore: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: jsonCore, using: SymmetricKey(data: macKey)))
    }

    private static func checksum(content: Data, mac: Data) -> Data {
        Data(SHA256.hash(data: content + mac))
    }
}
