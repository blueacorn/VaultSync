/// Protocol for file encryption with in-memory and streaming support.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// A key-and-header context resolved once per file, from which any block range can be encrypted
/// independently and in any order.
///
/// The mirror of ``BC01Header`` on the decrypt side: where `BC01Header` lets a downloader decrypt
/// ciphertext block `i` in isolation, a session lets an uploader *produce* block `i` in isolation.
/// That is what makes streaming, parallel-lane upload possible — see `ContentStreamUploader`.
///
/// Implementations must be value-semantic and stateless across calls: two lanes calling
/// ``encryptBlocks(_:firstBlock:isFinal:)`` concurrently for disjoint block ranges must produce
/// exactly the bytes a single sequential pass would.
public protocol FileEncryptionSession: Sendable {
    /// The complete file header, to be written at ciphertext offset 0. Empty for plain files.
    var headerBytes: Data { get }
    /// Plaintext block size this session encrypts in (BC01: 4096).
    var blockSize: Int { get }
    /// Number of padding bytes the final block carries: for BC01, the PKCS7 count in `1...16`
    /// for any non-empty plaintext (`0` only when empty); `0` for the plain passthrough session.
    var cipherPadding: Int { get }
    /// Total plaintext length this session was opened for.
    var plaintextSize: Int { get }
    /// The decrypt-side block context for the file this session writes, so an uploader can
    /// seed the header cache without re-parsing its own header. `nil` for plain files.
    var blockContext: BC01Header? { get }

    /// Encrypt the plaintext blocks starting at `firstBlock`, supplied contiguously in
    /// `plaintext`. `isFinal` must be `true` only for the span containing the file's last block,
    /// which selects PKCS7 padding.
    func encryptBlocks(_ plaintext: Data, firstBlock: Int, isFinal: Bool) throws -> Data
}

public extension FileEncryptionSession {
    /// Ciphertext offset at which plaintext block `index` begins.
    func ciphertextOffset(ofBlock index: Int) -> Int {
        headerBytes.count + index * blockSize
    }
}

public protocol FileEncryptor: Sendable {
    func encrypt(_ plaintext: Data, originalFilename: String) throws -> Data

    /// Open a streaming encrypt for a plaintext whose total size is already known.
    ///
    /// Key material and the header are generated once, here; every subsequent block range is
    /// encrypted through the returned session. Callers that hold the whole plaintext in memory
    /// should keep using ``encrypt(_:originalFilename:)``, which is implemented on top of this.
    func beginSession(plaintextSize: Int, originalFilename: String) throws -> any FileEncryptionSession
}

// MARK: - No-op encryptor

/// Passthrough session: plaintext == ciphertext, no header, no padding.
public struct PlainEncryptionSession: FileEncryptionSession {
    public let blockSize: Int
    public let plaintextSize: Int
    public var headerBytes: Data { Data() }
    public var cipherPadding: Int { 0 }
    public var blockContext: BC01Header? { nil }

    public init(plaintextSize: Int, blockSize: Int = 4096) {
        self.plaintextSize = plaintextSize
        self.blockSize = blockSize
    }

    public func encryptBlocks(_ plaintext: Data, firstBlock: Int, isFinal: Bool) throws -> Data {
        plaintext
    }
}

public struct PlainFileEncryptor: FileEncryptor {
    public init() {}

    public func encrypt(_ plaintext: Data, originalFilename: String) throws -> Data { plaintext }

    public func beginSession(plaintextSize: Int, originalFilename: String) throws -> any FileEncryptionSession {
        PlainEncryptionSession(plaintextSize: plaintextSize)
    }
}
