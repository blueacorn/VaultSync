/// Byte-for-byte file comparison with bounded memory.
///
/// Used to verify a converted item by comparing the source plaintext with the plaintext read back
/// from the new item, without holding either file in memory: sizes are checked first, then both
/// files are read in lock-step chunks.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

enum FileContentComparator {

    /// Bytes read from each file per step. Peak memory is two chunks.
    static let chunkSize = 1024 * 1024

    /// Whether the files at `lhs` and `rhs` have identical contents.
    ///
    /// - Parameters:
    ///   - lhs: First file.
    ///   - rhs: Second file.
    ///   - chunkSize: Bytes compared per step; overridable so tests can cross chunk boundaries
    ///     with small files.
    /// - Returns: `true` when both files have the same length and bytes.
    /// - Throws: When either file cannot be opened or read.
    static func equal(_ lhs: URL, _ rhs: URL, chunkSize: Int = chunkSize) throws -> Bool {
        let lhsSize = try fileSize(lhs)
        let rhsSize = try fileSize(rhs)
        guard lhsSize == rhsSize else { return false }

        let lhsHandle = try FileHandle(forReadingFrom: lhs)
        defer { try? lhsHandle.close() }
        let rhsHandle = try FileHandle(forReadingFrom: rhs)
        defer { try? rhsHandle.close() }

        while true {
            let lhsChunk = try autoreleasepool { try lhsHandle.read(upToCount: chunkSize) ?? Data() }
            let rhsChunk = try autoreleasepool { try rhsHandle.read(upToCount: chunkSize) ?? Data() }
            guard lhsChunk == rhsChunk else { return false }
            if lhsChunk.isEmpty { return true }
        }
    }

    private static func fileSize(_ url: URL) throws -> Int64 {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs[.size] as? NSNumber)?.int64Value ?? 0
    }
}
