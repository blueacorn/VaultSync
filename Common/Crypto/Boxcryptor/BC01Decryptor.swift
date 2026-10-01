/// Boxcryptor BC01 file decryption: Phase 2 (RSA-OAEP file key) + Phase 3 (AES-256-CBC blocks).
///
/// Three entry points share one block implementation (``BC01CryptoCommon/decryptBlock(_:blockIndex:isLast:header:)``):
/// - ``decrypt(_:)`` — whole blob in memory.
/// - ``decryptStream(from:outputURL:)`` — true streaming: buffers only until the header is
///   complete, then decrypts and appends each ciphertext block as it arrives (no whole-file
///   plaintext buffer).
/// - ``makeBlockContext(from:)`` — resolve the per-file header once so a caller (parallel
///   range materialisation) can decrypt fetched block spans by index.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import CryptoKit
import CommonCrypto
@preconcurrency import Security

public struct BC01Decryptor: FileDecryptor {
    let rsaPrivateKey: SecKey
    /// The user ID from the `.bckey` (`users[0].id`). When set, `parseHeader` selects the
    /// matching `encryptedFileKeys` entry and throws ``BC01Error/invalidFileKey`` fast if the
    /// file was encrypted for a different user rather than attempting an RSA decrypt.
    let userID: String?
    /// Treatment of a header HMAC that does not match the on-disk JSON core.
    let hmacPolicy: BC01HeaderHMACPolicy

    public init(rsaPrivateKey: SecKey, userID: String? = nil,
                hmacPolicy: BC01HeaderHMACPolicy = .warnOnly) {
        self.rsaPrivateKey = rsaPrivateKey
        self.userID = userID
        self.hmacPolicy = hmacPolicy
    }

    // MARK: - FileDecryptor

    public func decrypt(_ data: Data) throws -> Data {
        let header = try makeBlockContext(from: data)
        guard data.count >= header.headerEnd else { throw BC01Error.truncatedFile }
        if data.count == header.headerEnd { return Data() }

        let ciphertext = data[(data.startIndex + header.headerEnd)...]
        // The padded final block can exceed `blockSize` by up to one AES unit, so ciphertext
        // length alone cannot say where the last block starts: a 4096- and a 4097-byte plaintext
        // both yield a 4112-byte body. Recover the plaintext length from the stored pad count —
        // that is what `cipherPadding` is for — and drive the walk from the resulting block count.
        let plaintextSize = ciphertext.count - header.cipherPadding
        let blockCount = max(1, (plaintextSize + header.blockSize - 1) / header.blockSize)

        var plaintext = Data()
        var offset = ciphertext.startIndex
        var blockIndex = 0
        while offset < ciphertext.endIndex {
            let isLast = blockIndex == blockCount - 1
            let blockEnd = isLast ? ciphertext.endIndex : offset + header.blockSize
            let block = Data(ciphertext[offset..<blockEnd])
            plaintext.append(try BC01CryptoCommon.decryptBlock(block, blockIndex: blockIndex,
                                                               isLast: isLast, header: header))
            offset = blockEnd
            blockIndex += 1
        }
        return plaintext
    }

    public func decryptStream(from bytes: URLSession.AsyncBytes, outputURL: URL) async throws {
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let handle = try FileHandle(forWritingTo: outputURL)
        defer { try? handle.close() }

        var buffer = Data()
        var header: BC01Header?
        var blockIndex = 0

        // Pull the stream into `buffer`. Until the header is parsed, accumulate just enough
        // to cover `headerEnd`; afterwards, flush each whole ciphertext block as it fills so
        // memory stays bounded to ~one block rather than the whole file.
        for try await byte in bytes {
            buffer.append(byte)

            if header == nil {
                guard buffer.count >= BC01CryptoCommon.rawHeaderLen,
                      let headerEnd = Self.peekHeaderEndRaw(buffer),
                      buffer.count >= headerEnd else { continue }
                let parsed = try makeBlockContext(from: buffer)
                header = parsed
                buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + parsed.headerEnd))
            }

            // With a known header, emit any full (non-final) blocks now buffered. Keep at
            // least one block in hand so the true final block gets PKCS7 unpadding.
            if let h = header {
                while buffer.count > h.blockSize {
                    let block = Data(buffer.prefix(h.blockSize))
                    let plain = try BC01CryptoCommon.decryptBlock(block, blockIndex: blockIndex,
                                                                  isLast: false, header: h)
                    handle.write(plain)
                    buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + h.blockSize))
                    blockIndex += 1
                }
            }
        }

        // Stream ended. Whatever remains is the final (possibly padded) block.
        if let h = header {
            if !buffer.isEmpty {
                let plain = try BC01CryptoCommon.decryptBlock(buffer, blockIndex: blockIndex,
                                                              isLast: true, header: h)
                handle.write(plain)
            }
        } else {
            // Never saw a full header — truncated unless the stream was empty.
            guard buffer.isEmpty else { throw BC01Error.truncatedFile }
        }
    }

    public func decryptBlock(_ encryptedBlock: Data, blockIndex: Int) throws -> Data {
        // Header-less variant: a lone block cannot be decrypted without per-file context.
        // The streaming/range paths use the header-aware `BC01CryptoCommon.decryptBlock`
        // after `makeBlockContext`. Retained for protocol conformance only.
        throw BC01Error.invalidHeader
    }

    // MARK: - Block-range support

    /// Resolve the per-file header context from a prefix that covers `headerEnd`. Used by the
    /// parallel range path to build one context, then decrypt fetched block spans by index.
    public func makeBlockContext(from prefix: Data) throws -> BC01Header {
        try BC01CryptoCommon.parseHeader(prefix, userID: userID, hmacPolicy: hmacPolicy,
                                       decryptFileKey: decryptFileKey)
    }

    /// Read `headerEnd = rawHeaderLen + coreLen + paddingLen` from a raw prefix (≥ 48 bytes)
    /// without a full parse, so a ranged caller can size its header fetch exactly. Returns `nil`
    /// if the prefix is too short or the magic is wrong.
    public static func peekHeaderEnd(_ prefix: Data) -> Int? {
        peekHeaderEndRaw(prefix)
    }

    // MARK: - Private

    /// Read `headerEnd = rawHeaderLen + coreLen + paddingLen` from the raw prefix without a
    /// full parse, so the stream knows how many bytes to buffer before parsing the JSON body.
    private static func peekHeaderEndRaw(_ prefix: Data) -> Int? {
        guard prefix.count >= BC01CryptoCommon.rawHeaderLen,
              Data(prefix.prefix(4)) == BC01CryptoCommon.magic else { return nil }
        let coreLen = Int(prefix.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 4, as: UInt32.self)) })
        let paddingLen = Int(prefix.withUnsafeBytes {
            UInt32(littleEndian: $0.load(fromByteOffset: 8, as: UInt32.self)) })
        return BC01CryptoCommon.rawHeaderLen + coreLen + paddingLen
    }

    /// RSA-unwrap the file key, returning the full plaintext (96 B) for
    /// ``BC01FileKey/init(unwrapped:)`` to validate.
    private func decryptFileKey(_ encrypted: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(
            rsaPrivateKey,
            .rsaEncryptionOAEPSHA1,
            encrypted as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? BC01Error.rsaDecryptFailed
        }
        return plain
    }
}
