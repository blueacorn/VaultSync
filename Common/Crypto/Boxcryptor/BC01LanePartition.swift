/// Block-aligned ciphertext partitioning for parallel BC01 range downloads.
///
/// A parallel download splits a ciphertext region across N lanes, each fetching a contiguous
/// byte range. For an **encrypted** (BC01) file each lane must additionally hold a whole
/// number of AES-CBC blocks so it can decrypt its span independently (block `i` decrypts
/// with `IV = HMAC(baseIV ‖ i_LE64, fileKey)` — see ``BC01CryptoCommon``). This type
/// computes such block-aligned spans and is pure, deterministic logic so the lane math is
/// unit-testable without any network.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

public enum BC01LanePartition {

    /// A single lane's work unit over the ciphertext body.
    ///
    /// Byte offsets are **absolute** within the encrypted file (i.e. include the header).
    /// ``firstBlockIndex`` is the global ciphertext block index at which this span begins, so
    /// the decryptor can derive each block's IV and the plaintext write offset (global
    /// `blockIndex * blockSize`).
    public struct Span: Equatable, Sendable {
        /// Absolute byte offset of the span's first byte in the encrypted file.
        public let start: Int
        /// Span length in bytes (always a multiple of `blockSize` except possibly the last).
        public let length: Int
        /// Global ciphertext block index of the span's first block.
        public let firstBlockIndex: Int
        /// Number of ciphertext blocks in this span.
        public let blockCount: Int

        public init(start: Int, length: Int, firstBlockIndex: Int, blockCount: Int) {
            self.start = start
            self.length = length
            self.firstBlockIndex = firstBlockIndex
            self.blockCount = blockCount
        }
    }

    /// Partition the ciphertext region `[startOffset, endOffset)` into at most `lanes`
    /// contiguous, block-aligned spans.
    ///
    /// Every span except the last is a whole multiple of `blockSize` blocks; the last span
    /// carries any short final block. Block indices across the returned spans are contiguous
    /// and run `startBlockIndex ..< startBlockIndex + regionBlockCount` with no gaps or
    /// overlaps. Returns an empty array for an empty region (`endOffset == startOffset`).
    ///
    /// For a whole-file partition, `startOffset` is the header end, `endOffset` is the total
    /// encrypted size, and `startBlockIndex` is `0`. For a ranged partition over a sub-region,
    /// `startOffset`/`endOffset` bound the (block-aligned) covered ciphertext and
    /// `startBlockIndex` is the global block index of the first covered block, so each span's
    /// ``Span/firstBlockIndex`` stays globally correct for IV derivation and plaintext offsets.
    ///
    /// - Parameters:
    ///   - startOffset: Absolute byte offset where the partitioned ciphertext region begins.
    ///   - endOffset: Absolute, exclusive byte offset where the region ends.
    ///   - blockSize: AES-CBC block size (typically 4096).
    ///   - lanes: Desired lane count (clamped to `[1, regionBlockCount]`).
    ///   - startBlockIndex: Global ciphertext block index of the region's first block (default `0`).
    ///   - blockCount: Explicit number of ciphertext blocks in the region, for a region whose
    ///     byte length is NOT a reliable block count. The final block of a BC01 body carries
    ///     `blockSize + cipherPadding` bytes, so when the region reaches it, dividing the length
    ///     by `blockSize` rounds *up* and invents a block that does not exist — the caller then
    ///     reads past the fetched data. Pass the true count in that case. `nil` (the default)
    ///     keeps the inferred `ceil(length / blockSize)` for regions that end on a block boundary.
    ///   - maxSpanBytes: Upper bound on a single span's byte length, rounded down to a whole
    ///     number of blocks (at least one). When the region is large enough that an even split
    ///     across `lanes` would exceed it, the region is cut into MORE than `lanes` spans, each
    ///     within the bound; the caller then runs them `lanes`-at-a-time. This keeps per-request
    ///     size (and so retry granularity and lane skew) bounded independently of file size.
    ///     `nil` (the default) means an even split across exactly `lanes` spans.
    public static func spans(startOffset: Int, endOffset: Int, blockSize: Int, lanes: Int,
                             startBlockIndex: Int = 0,
                             blockCount: Int? = nil,
                             maxSpanBytes: Int? = nil) -> [Span] {
        precondition(blockSize > 0, "blockSize must be positive")
        precondition(endOffset >= startOffset, "endOffset must be >= startOffset")

        let bodyLength = endOffset - startOffset
        guard bodyLength > 0 else { return [] }

        // Total ciphertext blocks in this region (the final block may be short, or — when it is
        // the file's last — longer than `blockSize` by the PKCS7 padding).
        let regionBlockCount = blockCount ?? ((bodyLength + blockSize - 1) / blockSize)
        var laneCount = max(1, min(lanes, regionBlockCount))

        // Cap each span's size: if an even split across `laneCount` would exceed `maxSpanBytes`,
        // raise the span count until it doesn't. The extra spans are queued work for the same
        // lanes, not extra concurrency — the caller bounds in-flight requests separately.
        if let maxSpanBytes, maxSpanBytes > 0 {
            let maxBlocksPerSpan = max(1, maxSpanBytes / blockSize)
            let spansNeeded = (regionBlockCount + maxBlocksPerSpan - 1) / maxBlocksPerSpan
            laneCount = max(laneCount, min(spansNeeded, regionBlockCount))
        }

        // Distribute blocks as evenly as possible; earlier spans take the +1 remainder.
        let baseBlocks = regionBlockCount / laneCount
        let remainder = regionBlockCount % laneCount

        var spans: [Span] = []
        spans.reserveCapacity(laneCount)
        var localBlockIndex = 0
        for lane in 0..<laneCount {
            let blocks = baseBlocks + (lane < remainder ? 1 : 0)
            guard blocks > 0 else { continue }
            let start = startOffset + localBlockIndex * blockSize
            // Bytes spanned by `blocks` blocks. The LAST span always runs to `endOffset`: the
            // file's final block carries `blockSize + cipherPadding` ciphertext bytes, so a
            // block-multiple end would stop short of the padding and the unpad would decrypt a
            // truncated block. Interior spans keep the block-multiple bound.
            let isFinalSpan = lane == laneCount - 1 || localBlockIndex + blocks == regionBlockCount
            let end = isFinalSpan
                ? endOffset
                : min(startOffset + (localBlockIndex + blocks) * blockSize, endOffset)
            spans.append(Span(start: start,
                              length: end - start,
                              firstBlockIndex: startBlockIndex + localBlockIndex,
                              blockCount: blocks))
            localBlockIndex += blocks
        }
        return spans
    }
}
