/// Backend-neutral streaming content download + decrypt with offset writes.
///
/// Fetches an item's bytes over one or more concurrent byte-range lanes, feeds each lane's
/// span through the supplied ``FileDecryptor`` (for BC01, block-by-block by global index),
/// and writes the resulting plaintext to a destination file at its correct offset. Memory
/// stays bounded to roughly one lane-span instead of the whole file, and plaintext is written
/// incrementally so the Provider sees byte-level ``Progress``.
///
/// This is the single fetch→decrypt→offset-write pipeline shared by every backend: each backend
/// supplies a ``ContentFetching`` adapter (its authenticated, throttle-aware ranged GET) and a
/// ``FileDecryptor``; the partitioning, block decrypt, offset writes, and progress accounting are
/// identical across backends. A new backend reuses this type unchanged. The seam is unit-testable
/// with an in-memory transport over a fixture file (see `ContentStreamDownloadTests`).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// The byte-fetch seam: serve a contiguous range of an item's encrypted/plain bytes.
protocol ContentFetching: Sendable {
    /// Total item size in bytes (the encrypted on-backend size for `.bc` files).
    var totalSize: Int { get }
    /// Fetch `[start, start+length)` and return exactly those bytes (HTTP 206 equivalent).
    ///
    /// Returning fewer bytes than requested is a transport failure, not a valid short read: the
    /// caller has no other way to detect a truncated body for plain content (no magic, no MAC, no
    /// padding to fail on). Implementations must throw rather than return a short buffer; the
    /// pipeline additionally enforces this via ``ContentFetching/fetchExactRange(start:length:)``.
    func fetchRange(start: Int, length: Int) async throws -> Data
}

extension ContentFetching {
    /// ``fetchRange(start:length:)`` with the exact-length contract enforced.
    ///
    /// A backend that silently yields a partial body would otherwise have that truncation written
    /// straight to disk and reported as a complete file. Every pipeline fetch goes through here so
    /// the check cannot be forgotten at a call site.
    func fetchExactRange(start: Int, length: Int) async throws -> Data {
        let data = try await fetchRange(start: start, length: length)
        // A read may fall short only where the object genuinely ends: the caller clamps its
        // windows to `totalSize`, so anything shorter than the object's own tail is truncation.
        let available = max(0, min(start + length, totalSize) - start)
        guard data.count >= available else {
            throw ContentStreamError.shortRead(start: start, expected: available, received: data.count)
        }
        return data
    }
}

/// Failures raised by the shared download pipeline when a transfer does not satisfy its contract.
enum ContentStreamError: Error, LocalizedError {
    /// A ranged fetch returned fewer bytes than requested.
    case shortRead(start: Int, expected: Int, received: Int)
    /// The transfer completed without writing every byte of the requested window.
    case incompleteTransfer(expected: Int, written: Int)

    var errorDescription: String? {
        switch self {
        case .shortRead(let start, let expected, let received):
            return "Short read at offset \(start): expected \(expected) bytes, received \(received)"
        case .incompleteTransfer(let expected, let written):
            return "Incomplete transfer: expected \(expected) plaintext bytes, wrote \(written)"
        }
    }
}

/// Drives a streaming download for one item, whole-file or a plaintext sub-range.
struct ContentStreamDownloader {

    /// Result of a completed stream download.
    struct Result {
        /// The plaintext bytes written to the destination. `origin` is `0` for a whole-file
        /// fetch; for a ranged fetch it is the origin of the covering window the file holds
        /// (block-aligned for `.bc`, the requested lower bound for plain), so the caller can
        /// report a correct `(location, length)` return range to the OS. `length` is the final
        /// plaintext byte count written.
        let plaintextWindow: DomainService.PlaintextWindow
        /// Exact plaintext length of the whole file, regardless of the window materialised.
        /// For `.bc` this comes from the header (known without decrypting the body); for plain
        /// files it is the remote size.
        let wholeFilePlaintextSize: Int64
    }

    let fetcher: ContentFetching
    let decryptor: any FileDecryptor
    /// `true` when the item is BC01-encrypted (`decryptor` is a ``BC01Decryptor``); `false`
    /// for plain files (plaintext == ciphertext, no header).
    let isEncrypted: Bool
    /// Lane count for files at/above ``threshold``; clamped to the block count for `.bc`.
    let lanes: Int
    /// Files strictly below this size use a single lane.
    let threshold: Int
    /// Upper bound on one lane request's byte span. Spans beyond this are cut into more (not
    /// bigger) requests, run ``lanes``-at-a-time, so per-request size stays bounded regardless
    /// of file size. `0` disables the cap (an even split across ``lanes``).
    let maxSpanBytes: Int
    /// Minimum header probe size for `.bc` files: the initial fetch size to attempt header parsing.
    let minHeaderLen: Int = 4096
    /// Maximum header-probe size for `.bc` files.
    let maxHeaderLen: Int
    /// A pre-resolved BC01 header (e.g. from ``BC01HeaderCache``); when set, the header probe
    /// is skipped entirely. Ignored for plain files.
    let preResolvedHeader: BC01Header?
    /// Invoked with the BC01 header once resolved (from a probe), so the backend can populate its
    /// ``BC01HeaderCache``. Not called when ``preResolvedHeader`` already supplied one.
    let onHeaderResolved: (@Sendable (BC01Header) -> Void)?

    init(fetcher: ContentFetching,
         decryptor: any FileDecryptor,
         isEncrypted: Bool,
         lanes: Int,
         threshold: Int,
         maxSpanBytes: Int = 0,
         headerProbeLen maxHeaderLen: Int = 32 * 4096,
         preResolvedHeader: BC01Header? = nil,
         onHeaderResolved: (@Sendable (BC01Header) -> Void)? = nil) {
        self.fetcher = fetcher
        self.decryptor = decryptor
        self.isEncrypted = isEncrypted
        self.lanes = max(1, lanes)
        self.threshold = threshold
        self.maxSpanBytes = max(0, maxSpanBytes)
        self.maxHeaderLen = maxHeaderLen
        self.preResolvedHeader = preResolvedHeader
        self.onHeaderResolved = onHeaderResolved
    }

    /// Run the download, writing plaintext to `destinationURL` and advancing `progress`
    /// (totalUnitCount is set to the plaintext-equivalent byte budget). When `plaintextRange` is
    /// supplied only that plaintext window is fetched, decrypted, and written at its absolute
    /// plaintext offset (sparse file — the File Provider reads the returned URL at the range's own
    /// offset, not from 0). Throws
    /// on transport, crypto, or cancellation; partial output is the caller's to remove on failure.
    func run(to destinationURL: URL, progress: Progress,
             plaintextRange: Range<Int>? = nil) async throws -> Result {
        let remoteSize = fetcher.totalSize

        FileManager.default.createFile(atPath: destinationURL.path, contents: nil)
        let handle = try FileHandle(forWritingTo: destinationURL)
        defer { try? handle.close() }

        if isEncrypted {
            return try await runEncrypted(remoteSize: remoteSize, handle: handle,
                                          progress: progress, plaintextRange: plaintextRange)
        } else {
            return try await runPlain(remoteSize: remoteSize, handle: handle,
                                      progress: progress, plaintextRange: plaintextRange)
        }
    }

    // MARK: - Plain (plaintext == ciphertext)

    private func runPlain(remoteSize: Int, handle: FileHandle, progress: Progress,
                          plaintextRange: Range<Int>?) async throws -> Result {
        // Plaintext == ciphertext, so the whole-file plaintext length is just the remote size.
        let wholeFileSize = Int64(remoteSize)
        // For plain files plaintext == ciphertext, so a plaintext range maps 1:1 to a byte range.
        let region = clampedRegion(plaintextRange, totalSize: remoteSize)
        let regionLength = region.upperBound - region.lowerBound
        let sink = makeSink(handle: handle, base: region.lowerBound, budget: regionLength,
                            fileSize: remoteSize, progress: progress)

        guard regionLength > 0 else {
            try Task.checkCancellation()
            let finalSize = try await sink.finish()
            return Result(plaintextWindow: .init(origin: Int64(region.lowerBound), length: finalSize),
                          wholeFilePlaintextSize: wholeFileSize)
        }

        // Clamp to the byte count so we never spin up more lanes than there are bytes.
        let count = laneCount(forBudget: regionLength, maxLanes: regionLength)
        let spans = evenSpans(start: region.lowerBound, length: regionLength, lanes: count)
        try await runBounded(spans, concurrency: count) { span in
            let data = try await fetcher.fetchExactRange(start: span.start, length: span.length)
            await sink.write(data, at: span.start)
        }

        try Task.checkCancellation()
        let finalSize = try await sink.finish()
        return Result(plaintextWindow: .init(origin: Int64(region.lowerBound), length: finalSize),
                      wholeFilePlaintextSize: wholeFileSize)
    }

    /// Contiguous, even byte spans over `[start, start+length)` (no block alignment needed),
    /// each no longer than ``maxSpanBytes`` when that cap is enabled. Exceeding the cap yields
    /// more spans than `lanes`; the caller runs them `lanes`-at-a-time.
    private func evenSpans(start: Int, length: Int, lanes: Int) -> [(start: Int, length: Int)] {
        var span = (length + lanes - 1) / lanes
        if maxSpanBytes > 0 { span = min(span, maxSpanBytes) }
        span = max(1, span)
        var out: [(Int, Int)] = []
        var cursor = start
        let end = start + length
        while cursor < end {
            let l = min(span, end - cursor)
            out.append((cursor, l))
            cursor += l
        }
        return out
    }

    // MARK: - Shared sink + lane helpers

    /// Build the offset-write sink and prime `progress` for a transfer of `budget` plaintext bytes
    /// starting at plaintext offset `base`.
    ///
    /// Progress is measured in whole-file plaintext bytes (`fileSize` total): a ranged transfer
    /// starts at `base / fileSize` and ends at `(base + written) / fileSize`, never resetting to 0%
    /// or claiming 100% for a window. Centralising this guarantees `progress.totalUnitCount` is
    /// always set before the sink runs.
    private func makeSink(handle: FileHandle, base: Int = 0, budget: Int, fileSize: Int,
                          progress: Progress, tolerance: Int = 0) -> StreamSink {
        progress.totalUnitCount = Int64(max(fileSize, 1))
        progress.completedUnitCount = Int64(base)
        return StreamSink(handle: handle, base: base, totalBytes: budget, progress: progress,
                          tolerance: tolerance)
    }

    /// The number of parallel fetch lanes for a `budget`-byte transfer: a single lane below
    /// ``threshold`` (or when multi-lane is disabled), else ``lanes`` capped by `maxLanes`
    /// (e.g. the byte count, so we never open more lanes than there are bytes).
    private func laneCount(forBudget budget: Int, maxLanes: Int = .max) -> Int {
        guard budget >= threshold, lanes > 1 else { return 1 }
        return max(1, min(lanes, maxLanes))
    }

    // MARK: - Encrypted (BC01)

    private func runEncrypted(remoteSize: Int, handle: FileHandle, progress: Progress,
                              plaintextRange: Range<Int>?) async throws -> Result {
        guard let bc = decryptor as? BC01Decryptor else { throw BC01Error.invalidHeader }

        // 1. Acquire the header. This single decision also tells us whether the from-zero region
        //    was already pulled into memory (the single-GET fast path) so the decrypt below can
        //    reuse those bytes instead of re-fetching them.
        let outcome = try await acquireHeader(bc: bc, remoteSize: remoteSize, plaintextRange: plaintextRange)

        // The item was declared `.bc` by name but its bytes carry no BC01 magic — it is plain
        // content wearing the suffix. Treat it as plain rather than failing the fetch; the name
        // is a declaration, the magic is the proof. Decided on bytes already in hand, so this
        // costs no extra round-trip.
        guard case .encrypted(let resolved) = outcome else {
            return try await runPlain(remoteSize: remoteSize, handle: handle,
                                      progress: progress, plaintextRange: plaintextRange)
        }
        let header = resolved.header
        let wholeFileSize = Int64(BC01CryptoCommon.exactPlaintextSize(header: header,
                                                                     remoteSize: remoteSize))

        // 2. Compute the block geometry once.
        let plan = BC01Plan(header: header, remoteSize: remoteSize, plaintextRange: plaintextRange,
                            clamp: clampedRegion)
        guard !plan.isEmpty else {
            return try await emptyResult(handle: handle, progress: progress,
                                         windowOrigin: plan.writeBase,
                                         wholeFilePlaintextSize: wholeFileSize)
        }

        // 3. One sink; decrypt covered blocks from either the prefetched buffer (no extra I/O) or
        //    fanned-out lane fetches. Both feed the identical block-decrypt routine.
        let sink = makeSink(handle: handle, base: plan.writeBase, budget: plan.writeBudget,
                            fileSize: Int(wholeFileSize), progress: progress,
                            tolerance: plan.blockSize)
        if let buffer = resolved.prefetched, plan.endOffset <= buffer.count {
            try await decryptInMemory(plan: plan, header: header, buffer: buffer, sink: sink)
        } else {
            try await decryptLanes(plan: plan, header: header, sink: sink)
        }

        try Task.checkCancellation()
        let finalSize = try await sink.finish()
        return Result(plaintextWindow: .init(origin: Int64(plan.writeBase), length: finalSize),
                      wholeFilePlaintextSize: wholeFileSize)
    }

    // MARK: Encrypted — block decrypt (shared by the in-memory and lane paths)

    /// Decrypt every covered block from an already-fetched buffer (the single-GET fast path).
    /// `buffer` holds ciphertext from offset 0, so block bytes are sliced at absolute offsets.
    private func decryptInMemory(plan: BC01Plan, header: BC01Header,
                                 buffer: Data, sink: StreamSink) async throws {
        for globalBlockIndex in plan.firstBlock...plan.lastBlock {
            try Task.checkCancellation()
            let isLast = globalBlockIndex == plan.totalBlocks - 1
            let blockStart = header.headerEnd + globalBlockIndex * plan.blockSize
            let blockEnd = isLast ? plan.remoteSize : blockStart + plan.blockSize
            let plain = try BC01CryptoCommon.decryptBlock(
                buffer.subdata(in: blockStart..<blockEnd),
                blockIndex: globalBlockIndex, isLast: isLast, header: header)
            await sink.write(plain, at: globalBlockIndex * plan.blockSize)
        }
    }

    /// Decrypt the covered blocks across parallel byte-range lanes, fetching each lane's span on
    /// demand. Used whenever the bytes are not already in hand (large files, far-offset ranges,
    /// or a header that arrived via the probe path).
    private func decryptLanes(plan: BC01Plan, header: BC01Header, sink: StreamSink) async throws {
        let count = laneCount(forBudget: plan.writeBudget)
        // Pass the covered block count explicitly: when the window reaches the file's last block
        // the region is longer than a whole number of blocks (that block carries the PKCS7 pad),
        // and an inferred count would round up and invent a block past the fetched bytes.
        let spans = BC01LanePartition.spans(startOffset: plan.startOffset, endOffset: plan.endOffset,
                                            blockSize: plan.blockSize, lanes: count,
                                            startBlockIndex: plan.firstBlock,
                                            blockCount: plan.lastBlock - plan.firstBlock + 1,
                                            maxSpanBytes: maxSpanBytes > 0 ? maxSpanBytes : nil)
        try await runBounded(spans, concurrency: count) { span in
            let spanData = try await fetcher.fetchExactRange(start: span.start, length: span.length)
            var blockStart = spanData.startIndex
            for b in 0..<span.blockCount {
                try Task.checkCancellation()
                let globalBlockIndex = span.firstBlockIndex + b
                let isLast = globalBlockIndex == plan.totalBlocks - 1
                let blockEnd = isLast ? spanData.endIndex : blockStart + plan.blockSize
                let plain = try BC01CryptoCommon.decryptBlock(
                    Data(spanData[blockStart..<blockEnd]),
                    blockIndex: globalBlockIndex, isLast: isLast, header: header)
                await sink.write(plain, at: globalBlockIndex * plan.blockSize)
                blockStart = blockEnd
            }
        }
    }

    /// Run `body` over every span with at most `concurrency` in flight at once.
    ///
    /// The span cap decouples request size from lane count, so there are now generally more spans
    /// than lanes. A plain task group would launch all of them and let URLSession queue the
    /// excess, defeating the cap's purpose (and inflating peak memory to one buffer per span);
    /// this keeps exactly `concurrency` requests outstanding, starting the next span as each
    /// completes. Rethrows the first failure and cancels the rest via the group.
    private func runBounded<S: Sendable>(_ spans: [S], concurrency: Int,
                                         _ body: @escaping @Sendable (S) async throws -> Void)
        async throws {
        guard !spans.isEmpty else { return }
        let limit = max(1, min(concurrency, spans.count))
        try await withThrowingTaskGroup(of: Void.self) { group in
            var next = 0
            while next < limit {
                let span = spans[next]
                group.addTask { try Task.checkCancellation(); try await body(span) }
                next += 1
            }
            while try await group.next() != nil {
                guard next < spans.count else { continue }
                let span = spans[next]
                group.addTask { try Task.checkCancellation(); try await body(span) }
                next += 1
            }
        }
    }

    // MARK: Encrypted — header acquisition

    /// The outcome of resolving a BC01 header: the header itself plus, when the single-GET fast
    /// path fired, the from-zero ciphertext bytes already in memory (so the caller decrypts without
    /// a second fetch). `prefetched == nil` means the bytes must still be fetched per lane.
    private struct ResolvedHeader {
        let header: BC01Header
        let prefetched: Data?
    }

    /// What the header probe found: real BC01 content, or bytes that carry no BC01 magic and so
    /// must be served as plain despite the item's `.bc` name.
    private enum HeaderOutcome {
        case encrypted(ResolvedHeader)
        case notBC01
    }

    /// Resolve the BC01 header by the cheapest applicable means:
    /// 1. a pre-resolved (cached) header → no fetch;
    /// 2. the single-GET fast path → one `[0, end)` GET that doubles as the body bytes;
    /// 3. the shared probe ladder in ``BC01HeaderProbe`` → a small header GET, widened once if
    ///    the header exceeds the probe.
    /// A freshly-parsed header is published via ``onHeaderResolved`` for caching.
    ///
    /// Only step 2 lives here: it is a *body* optimisation (the fetched prefix is reused as
    /// body bytes), not header logic. The ladder itself lives in ``BC01HeaderProbe``.
    private func acquireHeader(bc: BC01Decryptor, remoteSize: Int,
                               plaintextRange: Range<Int>?) async throws -> HeaderOutcome {
        if let pre = preResolvedHeader {
            return .encrypted(ResolvedHeader(header: pre, prefetched: nil))
        }

        // Fast path: when the region we'd fetch from offset 0 is small (single-lane regime), a
        // separate header probe is a wasted round-trip — the probe range is a strict prefix of the
        // body range. Fetch `[0, end)` once and reuse it as both header and body. Declined when the
        // from-zero region reaches `threshold` (we'd rather fan out to lanes and/or avoid pulling a
        // large unwanted `[0, windowStart)` prefix for a far-offset range), or when `threshold == 0`
        // disables multi-lane entirely (keep behaviour identical to the streaming path).
        if threshold > 0, let fetchEnd = fastPathFetchEnd(remoteSize: remoteSize, plaintextRange: plaintextRange) {
            let buffer = try await fetcher.fetchExactRange(start: 0, length: fetchEnd)
            // Parse the bytes already in hand. A header that didn't fit `fetchEnd` widens inside
            // the shared ladder; the widened prefix is no longer a usable body buffer (it stops at
            // the header end), so only the original single GET yields `prefetched` bytes.
            let outcome = try await BC01HeaderProbe.parse(
                prefix: buffer, fetcher: fetcher, decryptor: bc, remoteSize: remoteSize,
                probeLen: fetchEnd, maxHeaderLen: maxHeaderLen)
            guard case .encrypted(let header, let prefix) = outcome else { return .notBC01 }
            onHeaderResolved?(header)
            let prefetched: Data? = prefix.count == buffer.count ? buffer : nil
            return .encrypted(ResolvedHeader(header: header, prefetched: prefetched))
        }

        // Probe path: the shared ladder — a small initial GET, then one widening refetch if the
        // header exceeds it. Its prefix is header-sized, not body-sized, so nothing is prefetched.
        let outcome = try await BC01HeaderProbe.fetchHeader(
            fetcher: fetcher, decryptor: bc, remoteSize: remoteSize,
            minHeaderLen: minHeaderLen, maxHeaderLen: maxHeaderLen)
        guard case .encrypted(let header, _) = outcome else { return .notBC01 }
        onHeaderResolved?(header)
        return .encrypted(ResolvedHeader(header: header, prefetched: nil))
    }

    /// The from-zero fetch length for the single-GET fast path, or `nil` if the path doesn't apply.
    /// The header is unknown pre-fetch, so a ranged window's ciphertext upper edge is bounded
    /// conservatively by ``maxHeaderLen``; a whole-file fetch simply needs the whole object.
    private func fastPathFetchEnd(remoteSize: Int, plaintextRange: Range<Int>?) -> Int? {
        let fetchEnd: Int
        if let range = plaintextRange {
            fetchEnd = min(remoteSize, maxHeaderLen + max(range.upperBound, 1))
        } else {
            fetchEnd = remoteSize
        }
        return fetchEnd < threshold ? fetchEnd : nil
    }

    /// Finalise an empty (zero-byte) result. `windowOrigin` is the plaintext offset the
    /// (empty) output corresponds to — the requested window's lower bound when known, else 0.
    private func emptyResult(handle: FileHandle, progress: Progress,
                             windowOrigin: Int = 0,
                             wholeFilePlaintextSize: Int64 = 0) async throws -> Result {
        let sink = makeSink(handle: handle, base: windowOrigin, budget: 0,
                            fileSize: Int(wholeFilePlaintextSize), progress: progress)
        let finalSize = try await sink.finish()
        return Result(plaintextWindow: .init(origin: Int64(windowOrigin), length: finalSize),
                      wholeFilePlaintextSize: wholeFilePlaintextSize)
    }

    /// Clamp an optional plaintext range to `[0, totalSize)`; `nil` → the whole `[0, totalSize)`.
    private func clampedRegion(_ range: Range<Int>?, totalSize: Int) -> Range<Int> {
        guard let range else { return 0..<max(totalSize, 0) }
        let lower = max(0, min(range.lowerBound, totalSize))
        let upper = max(lower, min(range.upperBound, totalSize))
        return lower..<upper
    }
}

/// BC01 block geometry for one download: the covered global block range, the ciphertext byte
/// region spanning it, and the plaintext write base/budget — all derived once from the header,
/// the remote size, and the requested plaintext window. Pure value type, no I/O, so the
/// arithmetic the streaming and single-GET paths used to duplicate is computed and tested in
/// one place.
struct BC01Plan {
    let blockSize: Int
    let remoteSize: Int
    /// Total ciphertext blocks in the file (the last may unpad to a shorter plaintext block).
    let totalBlocks: Int
    /// First/last global block indices covered by the requested window (inclusive).
    let firstBlock: Int
    let lastBlock: Int
    /// Ciphertext byte region `[startOffset, endOffset)` covering `firstBlock...lastBlock`.
    let startOffset: Int
    let endOffset: Int
    /// Destination plaintext offset of the first covered block, and the plaintext byte budget
    /// for the covered window (an upper bound; the trailing block may unpad shorter).
    let writeBase: Int
    let writeBudget: Int
    /// `true` when there is no body to decrypt (empty ciphertext or a degenerate window).
    let isEmpty: Bool

    /// - Parameter clamp: clamps the optional plaintext window to `[0, plaintextTotal)`; injected
    ///   so the downloader's existing clamp helper is the single source of truth.
    init(header: BC01Header, remoteSize: Int, plaintextRange: Range<Int>?,
         clamp: (Range<Int>?, Int) -> Range<Int>) {
        self.blockSize = header.blockSize
        self.remoteSize = remoteSize

        guard remoteSize > header.headerEnd else {
            self.totalBlocks = 0; self.firstBlock = 0; self.lastBlock = 0
            self.startOffset = header.headerEnd; self.endOffset = header.headerEnd
            self.writeBase = 0; self.writeBudget = 0; self.isEmpty = true
            return
        }

        // The final block carries 1...16 bytes of PKCS7 padding, so the body is always strictly
        // longer than the plaintext and its length alone cannot give the block count: a 4096- and
        // a 4097-byte plaintext both yield a 4112-byte body. Recover the exact plaintext length
        // from the stored pad count, then round up to whole blocks for the clamping window.
        let exactPlaintext = BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: remoteSize)
        let blocks = max(1, (exactPlaintext + blockSize - 1) / blockSize)
        let plaintextTotal = blocks * blockSize
        let window = clamp(plaintextRange, plaintextTotal)
        let first = window.lowerBound / blockSize
        let last = window.upperBound > window.lowerBound ? (window.upperBound - 1) / blockSize : first
        let covered = max(0, last - first + 1)

        self.totalBlocks = blocks
        self.firstBlock = first
        self.lastBlock = last
        self.writeBase = first * blockSize
        self.writeBudget = covered * blockSize
        self.startOffset = header.headerEnd + first * blockSize
        // Extend the window by the PKCS7 padding when it reaches the final block: that block's
        // ciphertext is `blockSize + cipherPadding` bytes, so the plain block-multiple bound is
        // short by exactly the pad whenever the plaintext fills its last block (a 4096-byte
        // plaintext has a 4112-byte body). Handing `decryptBlock` a truncated final block
        // corrupts the unpad. `min(remoteSize, …)` alone does not save it — the short bound is
        // *below* `remoteSize`, so nothing clamps it back up.
        let padOnLastBlock = last == blocks - 1 ? header.cipherPadding : 0
        self.endOffset = min(remoteSize,
                             header.headerEnd + (last + 1) * blockSize + padOnLastBlock)
        self.isEmpty = covered == 0
    }
}

/// Serialises positioned writes from concurrent lanes and emits quantised progress (~10
/// updates over the whole transfer) so the Provider isn't thrashed.
///
/// Thread-safety: `StreamSink` is an `actor`, so `write(_:at:)` and `finish()` are actor-isolated
/// and each lane's `await sink.write(...)` is serialised. The `FileHandle` seek+write pair cannot
/// interleave across lanes, and `maxOffsetEnd` is actor state mutated only inside isolated methods
/// — the actor *is* the mutual exclusion; no extra lock or atomic is required.
private actor StreamSink {
    private let handle: FileHandle
    /// Absolute plaintext offset of the window's first byte; `0` for a whole-file transfer.
    private let base: Int
    private let totalBytes: Int
    private let progress: Progress
    private let step: Int
    /// Allowance below ``totalBytes`` at completion: a BC01 final block unpads to as little as
    /// one block short of its ciphertext budget. Plain transfers must land exactly.
    private let tolerance: Int
    private var written = 0
    private var nextThreshold: Int
    private var maxOffsetEnd = 0

    init(handle: FileHandle, base: Int = 0, totalBytes: Int, progress: Progress, tolerance: Int = 0) {
        self.handle = handle
        self.base = base
        self.totalBytes = totalBytes
        self.tolerance = max(0, tolerance)
        self.progress = progress
        self.step = max(totalBytes / 10, 1)
        self.nextThreshold = max(totalBytes / 10, 1)
    }

    /// Write `data` at absolute plaintext `offset` and advance progress if a step boundary
    /// was crossed.
    func write(_ data: Data, at offset: Int) {
        guard !data.isEmpty else { return }
        try? handle.seek(toOffset: UInt64(offset))
        handle.write(data)
        written += data.count
        maxOffsetEnd = max(maxOffsetEnd, offset - base + data.count)
        if written >= nextThreshold {
            // `totalBytes` is an upper bound for BC01 (final block unpads shorter): cap at EOF.
            progress.completedUnitCount = min(Int64(base + min(written, totalBytes)), progress.totalUnitCount)
            // Advance to the next unreached step multiple (coalesces multiple crossings).
            while nextThreshold <= written { nextThreshold += step }
        }
    }

    /// Flush, finalise progress, and return the plaintext length written from ``base``.
    ///
    /// Verifies the window was fully covered before declaring success. ``maxOffsetEnd`` alone is
    /// only the furthest offset reached, so a gap (a span that never landed) would otherwise be
    /// reported as a complete file and stamped by the OS as materialised — leaving an unreadable
    /// hole no retry ever revisits.
    func finish() throws -> Int64 {
        try handle.synchronize()
        // `written` must equal the covered extent: any gap means a span never landed. The budget
        // is only an upper bound (a BC01 final block unpads shorter), so it is not the test —
        // contiguity is. `tolerance` admits that documented unpad shortfall and nothing else.
        guard written == maxOffsetEnd, maxOffsetEnd >= totalBytes - tolerance else {
            throw ContentStreamError.incompleteTransfer(expected: totalBytes, written: maxOffsetEnd)
        }
        // End at the window's end, not 100%: a ranged fetch covers only `[base, base + written)`.
        progress.completedUnitCount = min(Int64(base + maxOffsetEnd), progress.totalUnitCount)
        return Int64(maxOffsetEnd)
    }
}
