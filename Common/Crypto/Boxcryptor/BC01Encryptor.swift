/// Boxcryptor BC01 file encryption: RSA-OAEP-SHA1 file key wrap + AES-256-CBC block encrypt.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import CommonCrypto
@preconcurrency import Security

public struct BC01Encryptor: FileEncryptor {
    let rsaPublicKey: SecKey
    let userID: String

    public init(rsaPublicKey: SecKey, userID: String) {
        self.rsaPublicKey = rsaPublicKey
        self.userID = userID
    }

    // MARK: - FileEncryptor

    /// Encrypt `plaintext` in memory and return complete `.bc` bytes.
    public func encrypt(_ plaintext: Data, originalFilename: String) throws -> Data {
        let fileKey = try BC01FileKey.generate()
        let baseIV  = try BC01CryptoCommon.secureRandom(16)
        return try encryptDeterministic(plaintext: plaintext,
                                        fileKey: fileKey,
                                        baseIV: baseIV,
                                        originalFilename: originalFilename)
    }

    /// Open a streaming session with freshly generated key material.
    public func beginSession(plaintextSize: Int, originalFilename: String) throws -> any FileEncryptionSession {
        try makeSession(plaintextSize: plaintextSize,
                        fileKey: try BC01FileKey.generate(),
                        baseIV: try BC01CryptoCommon.secureRandom(16),
                        originalFilename: originalFilename)
    }

    /// Deterministic encrypt with caller-supplied key material — for test vectors only.
    ///
    /// Routes through ``BC01EncryptionSession`` so there is exactly one implementation of the
    /// block loop shared with the streaming upload path.
    public func encryptDeterministic(
        plaintext: Data,
        fileKey: BC01FileKey,
        baseIV: Data,
        originalFilename: String
    ) throws -> Data {
        let session = try makeSession(plaintextSize: plaintext.count,
                                      fileKey: fileKey,
                                      baseIV: baseIV,
                                      originalFilename: originalFilename)
        var result = session.headerBytes
        if !plaintext.isEmpty {
            result.append(try session.encryptBlocks(plaintext, firstBlock: 0, isFinal: true))
        }
        return result
    }

    /// Build a session for caller-supplied key material.
    public func makeSession(plaintextSize: Int, fileKey: BC01FileKey, baseIV: Data,
                     originalFilename: String) throws -> BC01EncryptionSession {
        precondition(baseIV.count == 16)
        let cipherPadding = BC01CryptoCommon.cipherPadding(plaintextSize: plaintextSize)
        let header = try buildHeader(fileKey: fileKey, baseIV: baseIV,
                                     plaintextSize: plaintextSize,
                                     originalFilename: originalFilename,
                                     cipherPadding: UInt32(cipherPadding))
        return BC01EncryptionSession(headerBytes: header,
                                     fileKey: fileKey.contentKey,
                                     baseIV: baseIV,
                                     plaintextSize: plaintextSize,
                                     cipherPadding: cipherPadding)
    }

    // MARK: - Private

    /// Build raw header + JSON core + padding. The JSON is encoded once and the HMAC in bytes
    /// 16–47 is computed over exactly those bytes, so our headers always verify.
    private func buildHeader(fileKey: BC01FileKey, baseIV: Data, plaintextSize: Int,
                              originalFilename: String, cipherPadding: UInt32) throws -> Data {
        let encryptedFileKey = try wrapFileKey(fileKey.wrappedPlaintext)

        let header = BCFileHeader(
            artifact: "header",
            cipher: BCFileHeader.Cipher(
                algorithm: "AES",
                mac: BCFileHeader.Cipher.MAC(enabled: false),
                mode: "CBC",
                padding: "PKCS7",
                keySize: 256,
                blockSize: BC01CryptoCommon.blockSize,
                iv: baseIV.base64EncodedString()
            ),
            metadata: BCFileHeader.Metadata(
                name: BCFileHeader.Metadata.Name(encrypted: false, value: originalFilename)
            ),
            version: 1,
            encryptedFileKeys: [
                BCFileHeader.EncryptedKey(
                    type: "data",
                    id: userID,
                    value: encryptedFileKey.base64EncodedString()
                )
            ]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let jsonData = try encoder.encode(header)

        // Reserve the header region Boxcryptor itself writes (``BC01Framing/headerSize(plaintextSize:)``)
        // so the ciphertext length frames exactly as ``BC01Framing/estimatedPlaintextSize(ciphertextSize:)``
        // inverts it. A core that outgrows the reserve is an error, never a silently unframed file.
        let rawLen = BC01CryptoCommon.rawHeaderLen
        let totalWithoutPadding = rawLen + jsonData.count
        let reservedHeaderSize = Int(BC01Framing.headerSize(plaintextSize: Int64(plaintextSize)))
        guard totalWithoutPadding <= reservedHeaderSize else {
            throw BC01Error.headerExceedsReserve(headerSize: totalWithoutPadding,
                                                 reservedSize: reservedHeaderSize)
        }
        let paddingLen = reservedHeaderSize - totalWithoutPadding

        var raw = Data(capacity: rawLen + jsonData.count + paddingLen)

        // 4-byte magic
        raw.append(contentsOf: BC01CryptoCommon.magic)
        // headerCoreLen LE uint32
        var hcl = UInt32(jsonData.count).littleEndian
        raw.append(Data(bytes: &hcl, count: 4))
        // paddingLen LE uint32
        var pl = UInt32(paddingLen).littleEndian
        raw.append(Data(bytes: &pl, count: 4))
        // cipherPadding LE uint32
        var cp = cipherPadding.littleEndian
        raw.append(Data(bytes: &cp, count: 4))
        // header_hmac = HMAC-SHA256(macKey, JSON core)
        raw.append(fileKey.headerHMAC(jsonData))
        // JSON body
        raw.append(jsonData)
        // zero padding
        raw.append(Data(count: paddingLen))

        return raw
    }

    private func wrapFileKey(_ buffer: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(
            rsaPublicKey,
            .rsaEncryptionOAEPSHA1,
            buffer as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? BC01Error.rsaEncryptFailed
        }
        return wrapped
    }
}


// MARK: - Session

/// BC01 streaming encryption session: fixed key material + header, arbitrary block ranges.
///
/// Each block is independently encrypted under `IV = HMAC(baseIV ‖ blockIndex_LE64, fileKey)`,
/// so disjoint block ranges can be produced concurrently by separate upload lanes and still
/// assemble into exactly the file a single sequential pass would write.
public struct BC01EncryptionSession: FileEncryptionSession {
    public let headerBytes: Data
    let fileKey: Data
    let baseIV: Data
    public let plaintextSize: Int
    public let cipherPadding: Int
    public var blockSize: Int { BC01CryptoCommon.blockSize }

    public var blockContext: BC01Header? {
        BC01Header(baseIV: baseIV, fileKey: fileKey, blockSize: blockSize,
                   headerEnd: headerBytes.count, cipherPadding: cipherPadding)
    }

    public func encryptBlocks(_ plaintext: Data, firstBlock: Int, isFinal: Bool) throws -> Data {
        let bs = BC01CryptoCommon.blockSize
        var result = Data(capacity: plaintext.count + 16)
        var offset = plaintext.startIndex
        var blockIndex = firstBlock

        while offset < plaintext.endIndex {
            let remaining = plaintext.endIndex - offset
            let isLastOfSpan = remaining <= bs
            let blockEnd = isLastOfSpan ? plaintext.endIndex : offset + bs
            var encrypted = Data(plaintext[offset..<blockEnd])

            let iv = BC01CryptoCommon.computeBlockIV(baseIV, blockNumber: blockIndex, fileKey: fileKey)
            // PKCS7 applies only to the file's genuinely final block, never to a lane boundary,
            // and only when that block is short (`cipherPadding > 0`): a full final block is
            // written unpadded, as Boxcryptor does.
            try BC01CryptoCommon.aesCBCInPlace(&encrypted, key: fileKey, iv: iv,
                                               op: CCOperation(kCCEncrypt),
                                               pkcs7: isFinal && isLastOfSpan && cipherPadding > 0)
            result.append(encrypted)
            offset = blockEnd
            blockIndex += 1
        }
        return result
    }
}
