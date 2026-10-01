/// Protocol for file decryption with in-memory, streaming, and block-range support.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

public protocol FileDecryptor: Sendable {
    /// Decrypt an in-memory blob of encrypted data.
    func decrypt(_ data: Data) throws -> Data

    /// Stream-decrypt from async bytes, writing plaintext to outputURL.
    func decryptStream(from bytes: URLSession.AsyncBytes, outputURL: URL) async throws

    /// Decrypt a single BC01 block for byte-range-materialization.
    func decryptBlock(_ encryptedBlock: Data, blockIndex: Int) throws -> Data
}

// MARK: - No-op decryptor

public struct PlainFileDecryptor: FileDecryptor {
    public init() {}

    public func decrypt(_ data: Data) throws -> Data { data }

    public func decryptStream(from bytes: URLSession.AsyncBytes, outputURL: URL) async throws {
        let handle = try FileHandle(forWritingTo: outputURL)
        defer { try? handle.close() }
        for try await byte in bytes {
            handle.write(Data([byte]))
        }
    }

    public func decryptBlock(_ encryptedBlock: Data, blockIndex: Int) throws -> Data {
        encryptedBlock
    }
}
