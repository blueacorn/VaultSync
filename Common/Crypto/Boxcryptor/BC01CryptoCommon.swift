/// Shared BC01 crypto primitives: constants, error types, header model, and low-level helpers.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import CryptoKit
import CommonCrypto
import Security
import os

// MARK: - Error

public enum BC01Error: Error {
    case truncatedFile
    case invalidHeader
    case rsaDecryptFailed
    case invalidFileKey
    case aesCryptFailed(CCCryptorStatus)
    case jsonParseFailed
    case rsaEncryptFailed
    case randomFailed
    /// The header (raw prefix + JSON core) exceeds the reserved region of
    /// ``BC01Framing/headerSize(plaintextSize:)``; writing it would break the ciphertext framing.
    case headerExceedsReserve(headerSize: Int, reservedSize: Int)
    /// Raw-header bytes 16–47 do not match `HMAC-SHA256(macKey, JSON core)` under
    /// ``BC01HeaderHMACPolicy/strict``.
    case headerHMACMismatch
}

// MARK: - Header HMAC

/// Outcome of checking raw-header bytes 16–47 against the on-disk JSON core.
public enum BC01HeaderHMACStatus: Sendable, Equatable {
    /// Matches `HMAC-SHA256(macKey, on-disk JSON core)`.
    case verified
    /// Does not match the on-disk JSON. Normal for ~50 % of Boxcryptor files, which HMAC a
    /// differently key-ordered serialization of the same object.
    case mismatch
}

/// How ``BC01CryptoCommon/parseHeader(_:userID:hmacPolicy:decryptFileKey:)`` treats
/// ``BC01HeaderHMACStatus/mismatch``.
public enum BC01HeaderHMACPolicy: Sendable {
    /// Log a warning and continue.
    case warnOnly
    /// Throw ``BC01Error/headerHMACMismatch``.
    case strict
}

// MARK: - Header model (full Boxcryptor-interoperable set)

public struct BCFileHeader: Codable {
    public struct Cipher: Codable {
        public let algorithm: String
        public let mac: MAC
        public let mode: String
        public let padding: String
        public let keySize: Int
        public let blockSize: Int
        public let iv: String

        public struct MAC: Codable {
            public let enabled: Bool
        }
    }
    public struct Metadata: Codable {
        public struct Name: Codable {
            public let encrypted: Bool
            public let value: String?
        }
        public let name: Name
    }
    public struct EncryptedKey: Codable {
        public let type: String
        public let id: String
        public let value: String
    }
    public let artifact: String
    public let cipher: Cipher
    public let metadata: Metadata
    public let version: Int
    public let encryptedFileKeys: [EncryptedKey]
}

// MARK: - Parsed header context

/// The per-file context needed to decrypt any ciphertext block independently: the base IV,
/// the (RSA-unwrapped) file key, the block size, the byte offset where ciphertext begins,
/// and whether the final block carries PKCS7 padding.
///
/// Ciphertext block `i` occupies `[headerEnd + i*blockSize, headerEnd + (i+1)*blockSize)`
/// and decrypts with `IV = HMAC(baseIV ‖ i_LE64, fileKey)` — see ``BC01CryptoCommon/computeBlockIV(_:blockNumber:fileKey:)``.
public struct BC01Header: Sendable {
    public let baseIV: Data
    public let fileKey: Data
    public let blockSize: Int
    public let headerEnd: Int
    public let cipherPadding: Int
    /// Result of the JSON core header HMAC check (bytes 16–47); `nil` when the header was not
    /// parsed from ciphertext (freshly written, or rebuilt from the header cache).
    public let headerHMACStatus: BC01HeaderHMACStatus?

    public init(baseIV: Data, fileKey: Data, blockSize: Int, headerEnd: Int, cipherPadding: Int,
                headerHMACStatus: BC01HeaderHMACStatus? = nil) {
        self.baseIV = baseIV
        self.fileKey = fileKey
        self.blockSize = blockSize
        self.headerEnd = headerEnd
        self.cipherPadding = cipherPadding
        self.headerHMACStatus = headerHMACStatus
    }
}

// MARK: - Shared helpers

public enum BC01CryptoCommon {
    /// BC01 file magic bytes: "bc01" in ASCII.
    public static let magic = Data([0x62, 0x63, 0x30, 0x31])
    /// BC01 chunk size: the plaintext span that each independently-IV'd block covers.
    public static let blockSize = 4096
    /// AES-CBC cipher block size (16 bytes) — the unit PKCS7 padding is measured in.
    public static let aesBlockSize = kCCBlockSizeAES128
    /// Size of the fixed raw header prefix (before JSON body).
    public static let rawHeaderLen = 48
    /// Raw-header span holding `HMAC-SHA256(macKey, JSON core)`.
    public static let headerHMACRange = 16..<48

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "bc01")

    /// Number of PKCS7 padding bytes the final AES unit of the ciphertext body carries — the
    /// value stored at raw-header offset 12.
    ///
    /// Boxcryptor pads the final block with PKCS7 (`16 - size % 16`, i.e. 1…16) only when that
    /// block is short; a plaintext that fills its last 4096-byte block exactly (including the
    /// empty file) carries no padding. Delegates to ``BC01Framing/cipherPadding(plaintextSize:)``
    /// so encryptor and size estimate share one rule — confirmed against Boxcryptor output in
    /// `data/corpus/bc01/bin/probe-pkcs7`.
    public static func cipherPadding(plaintextSize: Int) -> Int {
        Int(BC01Framing.cipherPadding(plaintextSize: Int64(plaintextSize)))
    }

    /// Ciphertext byte length of the encrypted **body** (everything after `headerEnd`) for a
    /// plaintext of `plaintextSize` bytes.
    ///
    /// Whole 4096-byte BC01 blocks map 1:1 to 4096 ciphertext bytes; the file's final block grows
    /// by its PKCS7 padding — see ``cipherPadding(plaintextSize:)`` — which is zero when that
    /// block is full.
    ///
    /// This is the geometry the streaming uploader needs *before* encrypting anything, because
    /// `Content-Range: bytes {start}-{end}/{total}` must state the exact final size up front.
    public static func ciphertextBodySize(plaintextSize: Int) -> Int {
        guard plaintextSize > 0 else { return 0 }
        return plaintextSize + cipherPadding(plaintextSize: plaintextSize)
    }

    /// Ciphertext byte length contributed by plaintext blocks `[firstBlock, firstBlock + count)`
    /// of a plaintext of `plaintextSize` bytes. Mirrors ``ciphertextBodySize(plaintextSize:)``
    /// for a sub-range, so a lane can compute its own fragment offset independently.
    public static func ciphertextBodySize(plaintextSize: Int, firstBlock: Int, count: Int) -> Int {
        let start = min(firstBlock * blockSize, plaintextSize)
        let end = min((firstBlock + count) * blockSize, plaintextSize)
        guard end > start else { return 0 }
        // The span's own length, but padding applies only if it contains the file's final block.
        let spanLength = end - start
        let reachesEnd = end == plaintextSize
        if reachesEnd { return ciphertextBodySize(plaintextSize: spanLength) }
        return spanLength   // interior spans are whole blocks: 1:1
    }

    /// Whether `prefix` begins with the BC01 magic bytes.
    ///
    /// The single shared test for "are these bytes actually BC01?". A `.bc` filename is a
    /// *declaration*, not proof: plain files can carry the suffix (e.g. copied in by hand, or
    /// left behind by a partial conversion). Callers that hold real bytes must gate on this
    /// rather than on the name alone.
    ///
    /// Returns `false` for a prefix shorter than the magic itself: fewer than 4 bytes cannot
    /// hold a BC01 header, so such an item is trivially not encrypted.
    public static func hasBC01Magic(_ prefix: Data) -> Bool {
        guard prefix.count >= magic.count else { return false }
        return Data(prefix.prefix(magic.count)) == magic
    }

    /// Exact plaintext byte length of a BC01 file, derived from its header and total remote size.
    ///
    /// The ciphertext body is the plaintext plus PKCS7 padding over the final AES unit only, so
    /// subtracting the header's stored pad count from the body length recovers the plaintext
    /// length exactly — no decryption required. This is what makes the true size available the
    /// moment the header is parsed, rather than after the last block is decrypted.
    ///
    /// - Parameters:
    ///   - header: The parsed BC01 header (supplies `headerEnd` and `cipherPadding`).
    ///   - remoteSize: Total on-backend ciphertext length of the item.
    /// - Returns: The plaintext length; `0` when the file has no body.
    public static func exactPlaintextSize(header: BC01Header, remoteSize: Int) -> Int {
        let bodySize = remoteSize - header.headerEnd
        guard bodySize > 0 else { return 0 }
        return max(0, bodySize - header.cipherPadding)
    }

    /// Parse the BC01 header from a prefix that contains at least through `headerEnd`.
    ///
    /// `prefix` must hold the Raw header (48 bytes), and Core header (JSON body)
    /// Note: the header padding is optional (empty and is discarded).
    /// The RSA-wrapped file key is unwrapped via `decryptFileKey` (full unwrapped bytes) and
    /// parsed by ``BC01FileKey``; the header HMAC is then checked against the on-disk JSON core.
    /// Throws ``BC01Error`` on bad magic / truncation / key failure / (strict) HMAC mismatch.
    /// - Parameters:
    ///   - userID: When non-nil, selects the `encryptedFileKeys` entry whose `id` matches.
    ///     Throws ``BC01Error/invalidFileKey`` immediately if no entry matches — avoids a
    ///     futile RSA decrypt attempt with the wrong key.  When nil, falls back to index 0
    ///     (legacy / test path).
    ///   - hmacPolicy: Treatment of a header HMAC that does not match the on-disk JSON.
    public static func parseHeader(_ prefix: Data,
                                   userID: String? = nil,
                                   hmacPolicy: BC01HeaderHMACPolicy = .warnOnly,
                                   decryptFileKey: (Data) throws -> Data) throws -> BC01Header {
        guard prefix.count >= 16 else { throw BC01Error.truncatedFile }
        guard Data(prefix.prefix(4)) == magic else { throw BC01Error.invalidHeader }

        let headerCoreLen = Int(prefix.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 4, as: UInt32.self)) })
        let paddingLen = Int(prefix.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 8, as: UInt32.self)) })
        let cipherPadding = Int(prefix.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 12, as: UInt32.self)) })

        let jsonStart = rawHeaderLen
        let jsonEnd = jsonStart + headerCoreLen
        let headerEnd = rawHeaderLen + headerCoreLen + paddingLen
        guard prefix.count >= jsonEnd else { throw BC01Error.truncatedFile }

        let base = prefix.startIndex
        let jsonCore = Data(prefix[(base + jsonStart)..<(base + jsonEnd)])
        let decoded = try JSONDecoder().decode(BCFileHeader.self, from: jsonCore)

        let encKey: BCFileHeader.EncryptedKey
        if let uid = userID {
            guard let match = decoded.encryptedFileKeys.first(where: { $0.id == uid }) else {
                throw BC01Error.invalidFileKey
            }
            encKey = match
        } else {
            guard !decoded.encryptedFileKeys.isEmpty else { throw BC01Error.invalidFileKey }
            encKey = decoded.encryptedFileKeys[0]
        }

        guard let encKeyData = Data(base64Encoded: encKey.value) else {
            throw BC01Error.invalidFileKey
        }
        let fileKey = try BC01FileKey(unwrapped: try decryptFileKey(encKeyData))
        guard let baseIV = Data(base64Encoded: decoded.cipher.iv) else { throw BC01Error.truncatedFile }

        let storedHMAC = Data(prefix[(base + headerHMACRange.lowerBound)..<(base + headerHMACRange.upperBound)])
        let status = headerHMACStatus(stored: storedHMAC, jsonCore: jsonCore, fileKey: fileKey)
        if status == .mismatch {
            switch hmacPolicy {
            case .strict:
                throw BC01Error.headerHMACMismatch
            case .warnOnly:
                log.warning("BC01 header HMAC does not match on-disk JSON core (keyID=\(encKey.id, privacy: .public)); continuing")
            }
        }

        return BC01Header(baseIV: baseIV, fileKey: fileKey.contentKey,
                          blockSize: decoded.cipher.blockSize,
                          headerEnd: headerEnd, cipherPadding: cipherPadding,
                          headerHMACStatus: status)
    }

    /// Classify raw-header bytes 16–47 against `HMAC-SHA256(macKey, jsonCore)`.
    public static func headerHMACStatus(stored: Data, jsonCore: Data,
                                        fileKey: BC01FileKey) -> BC01HeaderHMACStatus {
        timingSafeEqual(stored, fileKey.headerHMAC(jsonCore)) ? .verified : .mismatch
    }

    /// Decrypt one ciphertext block given the parsed header. `blockIndex` selects the IV;
    /// `isLast` enables PKCS7 unpadding when the header declared cipher padding.
    ///
    /// `block` is mutated in place (its own buffer is reused as the output), so the caller must
    /// pass an owned/uniquely-referenced `Data`. The returned value is the same (possibly
    /// shorter, after unpadding) buffer.
    public static func decryptBlock(_ block: Data, blockIndex: Int, isLast: Bool,
                                    header: BC01Header) throws -> Data {
        let iv = computeBlockIV(header.baseIV, blockNumber: blockIndex, fileKey: header.fileKey)
        var buffer = block
        try aesCBCInPlace(&buffer, key: header.fileKey, iv: iv, op: CCOperation(kCCDecrypt),
                          pkcs7: isLast && header.cipherPadding > 0)
        return buffer
    }

    /// Derives the per-block IV via HMAC-SHA256(baseIV || blockIndex_LE64, fileKey).prefix(16).
    public static func computeBlockIV(_ baseIV: Data, blockNumber: Int, fileKey: Data) -> Data {
        var buf = Data(baseIV)
        var n = UInt64(blockNumber).littleEndian
        buf.append(Data(bytes: &n, count: 8))
        let mac = HMAC<SHA256>.authenticationCode(for: buf, using: SymmetricKey(data: fileKey))
        return Data(mac).prefix(16)
    }

    /// AES-256-CBC encrypt or decrypt a single block, returning a freshly-allocated buffer.
    ///
    /// Thin wrapper over ``aesCBCInPlace(_:key:iv:op:pkcs7:)`` for callers that must keep `data`
    /// intact. Prefer the in-place variant on the hot path to avoid a per-block copy.
    public static func aesCBC(_ data: Data, key: Data, iv: Data,
                               op: CCOperation, pkcs7: Bool) throws -> Data {
        var buffer = data
        try aesCBCInPlace(&buffer, key: key, iv: iv, op: op, pkcs7: pkcs7)
        return buffer
    }

    /// AES-256-CBC encrypt or decrypt a single block **in place**, mutating `data`'s own buffer.
    ///
    /// CBC without padding preserves length (fully in place, no realloc). PKCS7 encrypt grows the
    /// final block by ≤ one AES block (headroom is reserved, then the buffer truncated to the
    /// produced length); PKCS7 decrypt shrinks it (buffer truncated). The caller must own/uniquely
    /// reference `data` (callers here pass a fresh `Data(slice)`), so the mutation cannot alias the
    /// source ciphertext span.
    public static func aesCBCInPlace(_ data: inout Data, key: Data, iv: Data,
                                     op: CCOperation, pkcs7: Bool) throws {
        let options = CCOptions(pkcs7 ? kCCOptionPKCS7Padding : 0)
        let inputCount = data.count
        // PKCS7 encrypt may add up to one block; reserve headroom so CCCrypt has room to write.
        let capacity = inputCount + kCCBlockSizeAES128
        if data.count < capacity {
            data.append(Data(count: capacity - data.count))
        }
        var outLen = 0
        let status: CCCryptorStatus = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                data.withUnsafeMutableBytes { buf -> CCCryptorStatus in
                    CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), options,
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            buf.baseAddress, inputCount,
                            buf.baseAddress, buf.count, &outLen)
                }
            }
        }
        guard status == kCCSuccess else { throw BC01Error.aesCryptFailed(status) }
        // Trim the reserved headroom (and any padding removed on decrypt) to the produced length.
        if data.count != outLen { data.removeLast(data.count - outLen) }
    }

    /// Returns `count` cryptographically random bytes.
    public static func secureRandom(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw BC01Error.randomFailed
        }
        return Data(bytes)
    }

    /// Constant-time equality check.
    public static func timingSafeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for (x, y) in zip(a, b) { result |= x ^ y }
        return result == 0
    }

    /// Imports a raw DER RSA private key as a SecKey.
    public static func importRSAPrivateKey(_ der: Data) throws -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? BC01Error.invalidFileKey
        }
        return key
    }
}
