/// Backend-neutral streaming encrypt + upload with bounded memory and parallel lanes.
///
/// The mirror of ``ContentStreamDownloader``. Where the downloader fetches ciphertext ranges,
/// decrypts them block-by-block and writes plaintext at offsets, this reads plaintext ranges from
/// a local file, encrypts them block-by-block through a ``FileEncryptionSession``, and PUTs the
/// resulting ciphertext at its correct offset. Memory stays bounded to roughly one lane span
/// instead of the whole file — the previous path materialised the entire ciphertext in a single
/// `Data` before sending a byte.
///
/// Each backend supplies a ``ContentPutting`` adapter (its authenticated, throttle-aware
/// fragment PUT); the partitioning, block encrypt, offset accounting and progress are identical
/// across backends. The seam is unit-testable with an in-memory putter (see
/// `ContentStreamUploadTests`).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// The byte-put seam: accept one contiguous fragment of an item's final ciphertext.
protocol ContentPutting: Sendable {
    /// Fragment start granularity the transport requires (Graph: 320 KiB). Every non-final
    /// fragment must begin at a multiple of this.
    var fragmentAlignment: Int { get }
    /// Whether the transport tolerates concurrent, out-of-order fragments.
    var supportsParallelFragments: Bool { get }
    /// Largest ciphertext the transport accepts in one non-fragmented request. The uploader
    /// uses ``putWhole(_:)`` when the whole object fits; `0` disables the single-request path.
    var singleRequestLimit: Int { get }
    /// Upload the complete object in one request. Returns the transport's completion payload.
    func putWhole(_ bytes: Data) async throws -> Data
    /// Put `bytes` at ciphertext offset `start` of an item whose final size is `totalSize`.
    ///
    /// Returns the server's completion payload when this fragment was the one acknowledged as
    /// final (for Graph, the 200/201 body carrying the driveItem), otherwise `nil`. Returning
    /// opaque `Data` keeps this pipeline free of any backend's wire types.
    func putRange(_ bytes: Data, start: Int, totalSize: Int) async throws -> Data?
}

/// Ciphertext geometry for a streaming BC01 upload — pure, no I/O.
///
/// Every offset is computable before a single byte is encrypted, which is what lets lanes run
/// independently and what lets `Content-Range` state the exact total up front.
struct BC01UploadPlan {
    let headerSize: Int
    let plaintextSize: Int
    let blockSize: Int
    /// Number of whole-or-partial plaintext blocks.
    let blockCount: Int
    /// Total ciphertext length: header + encrypted body.
    let ciphertextSize: Int

    /// `cipherPadding` is the session's own trailing pad length (BC01: 1...16 PKCS7 bytes for a
    /// short final block, 0 when it is full or the file is empty; 0 for the plain passthrough
    /// session, where ciphertext == plaintext). Taking it from the session rather than assuming BC01 geometry keeps `ciphertextSize` — the total
    /// every `Content-Range` states up front — exact for both.
    init(headerSize: Int, plaintextSize: Int, blockSize: Int, cipherPadding: Int) {
        self.headerSize = headerSize
        self.plaintextSize = plaintextSize
        self.blockSize = blockSize
        self.blockCount = plaintextSize == 0 ? 0 : (plaintextSize + blockSize - 1) / blockSize
        self.ciphertextSize = headerSize + (plaintextSize == 0 ? 0 : plaintextSize + cipherPadding)
    }

    /// Ciphertext offset at which plaintext block `index` begins. Interior blocks map 1:1, so
    /// this is exact even though the final block may be short.
    func ciphertextOffset(ofBlock index: Int) -> Int {
        headerSize + index * blockSize
    }

    /// Ciphertext length contributed by plaintext blocks `[range)`.
    func ciphertextLength(blocks range: Range<Int>) -> Int {
        BC01CryptoCommon.ciphertextBodySize(plaintextSize: plaintextSize,
                                            firstBlock: range.lowerBound,
                                            count: range.count)
    }

    /// Partition the file into lane spans of whole blocks.
    ///
    /// Span size is capped at `maxSpanBytes` rather than being `fileSize / lanes`: memory is
    /// bounded by `lanes × maxSpanBytes` regardless of file size, so a 4 GB file yields many
    /// small spans, not a few enormous ones.
    ///
    /// Alignment is enforced in **ciphertext** space, not block space. The header rides with
    /// fragment 0, so fragment 0 is `headerSize + firstSpanBytes` long; every later fragment
    /// therefore starts at `headerSize + n*blockSize`. Since `headerSize` is block-aligned but
    /// generally *not* `alignment`-aligned, the first span is shortened so that fragment 0 ends
    /// exactly on an `alignment` boundary — after which every subsequent boundary is aligned too.
    func laneSpans(maxSpanBytes: Int, alignment: Int) -> [Range<Int>] {
        guard blockCount > 0 else { return [] }
        let unit = max(alignment, blockSize)
        let blocksPerUnit = unit / blockSize
        let unitsPerSpan = max(1, maxSpanBytes / unit)
        let blocksPerSpan = blocksPerUnit * unitsPerSpan

        // Blocks in fragment 0 such that headerSize + blocks*blockSize is a multiple of `unit`.
        // headerSize is a multiple of blockSize, so this is always a whole number of blocks.
        var firstSpanBlocks = blocksPerSpan
        if headerSize % unit != 0 {
            let deficit = unit - (headerSize % unit)
            let blocksToBoundary = (deficit + blockSize - 1) / blockSize
            // Grow to at least one full span while staying on the boundary.
            firstSpanBlocks = blocksToBoundary
            while firstSpanBlocks + blocksPerUnit <= blocksPerSpan {
                firstSpanBlocks += blocksPerUnit
            }
        }

        var spans: [Range<Int>] = []
        var start = 0
        var take = firstSpanBlocks
        while start < blockCount {
            let end = min(start + take, blockCount)
            spans.append(start..<end)
            start = end
            take = blocksPerSpan
        }
        return spans
    }
}

/// Drives a streaming encrypt+upload for one item.
struct ContentStreamUploader {

    /// Result of a completed stream upload.
    struct Result {
        /// The transport's completion payload from the final fragment (Graph: driveItem JSON).
        let completionPayload: Data
        /// Total ciphertext bytes uploaded.
        let ciphertextSize: Int
        /// Block context of the uploaded file (`nil` for plain), for seeding the header cache.
        let blockContext: BC01Header?
    }

    let putter: any ContentPutting
    let encryptor: any FileEncryptor
    /// Maximum concurrent in-flight fragments. The window never exceeds this regardless of how
    /// many spans the file partitions into.
    let lanes: Int
    /// Upper bound on a span. Peak memory ≈ `lanes × maxSpanBytes` (parallel) or two spans
    /// (serial read-ahead).
    let maxSpanBytes: Int

    /// Set when the caller pinned an exact span size, which then overrides the size
    /// ``fragmentBytes(forPlaintextSize:)`` would pick. Used by tests to force a given
    /// partition; `nil` in production, where the tier applies.
    let explicitSpanBytes: Int?

    /// Graph rejects any single fragment larger than this.
    static let transportFragmentCeiling = 60 * 1024 * 1024

    /// Fallback fragment when the plaintext size is not known up front.
    static let defaultMaxSpanBytes = 10 * 1024 * 1024

    /// Best-effort fragment size for a plaintext of `plaintextSize` bytes.
    ///
    /// Fragments are sequential on Graph, so wall-clock is
    /// `fragments × perRequestOverhead + bytes / bandwidth`: every extra fragment costs a full
    /// round trip. Bigger fragments amortise that overhead, but cost memory (the serial path
    /// holds two spans — one in flight, one being encrypted ahead) and coarsen retry, since a
    /// failed fragment re-sends its whole span.
    ///
    /// The tiers below take the amortisation win where it matters and stop climbing once the
    /// curve flattens. Microsoft recommends 5–10 MiB for typical links; larger fragments only
    /// pay off on files big enough that the round trips actually add up.
    ///
    /// | plaintext | fragment | rationale |
    /// |---|---|---|
    /// | ≤ 32 MiB | 5 MiB | few round trips either way; keep memory and retry cost low |
    /// | ≤ 256 MiB | 10 MiB | Microsoft's recommended size for stable links |
    /// | > 256 MiB | 20 MiB | round trips dominate; amortise harder, ~40 MiB working set |
    ///
    /// Always a whole multiple of 320 KiB (and of the 4096-byte BC01 block), and never above
    /// ``transportFragmentCeiling``.
    static func fragmentBytes(forPlaintextSize plaintextSize: Int) -> Int {
        let MiB = 1024 * 1024
        switch plaintextSize {
        case ..<(32 * MiB):  return 5 * MiB
        case ..<(256 * MiB): return 10 * MiB
        default:             return 20 * MiB
        }
    }

    /// - Parameter maxSpanBytes: pins the span to exactly this size, bypassing the
    ///   plaintext-size tiers. Omit in production so fragments are sized from the file.
    init(putter: any ContentPutting,
         encryptor: any FileEncryptor,
         lanes: Int,
         maxSpanBytes: Int? = nil) {
        self.explicitSpanBytes = maxSpanBytes.map {
            max(putter.fragmentAlignment, min($0, Self.transportFragmentCeiling))
        }
        let maxSpanBytes = maxSpanBytes ?? Self.transportFragmentCeiling
        self.putter = putter
        self.encryptor = encryptor
        self.lanes = max(1, lanes)
        // Never exceed the transport's per-fragment ceiling, and keep the span at least one
        // alignment unit so every non-final fragment start stays aligned.
        self.maxSpanBytes = max(putter.fragmentAlignment,
                                min(maxSpanBytes, Self.transportFragmentCeiling))
    }

    /// Encrypt `sourceURL` and upload it, advancing `progress` over the ciphertext byte budget.
    ///
    /// Throws on I/O, crypto, transport, or cancellation. Abandoning the transport's session on
    /// failure is the caller's responsibility (for Graph, `DELETE {uploadUrl}`).
    func run(from sourceURL: URL, originalFilename: String,
             progress: Progress) async throws -> Result {
        let attrs = try FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let plaintextSize = (attrs[.size] as? NSNumber)?.intValue ?? 0

        let session = try encryptor.beginSession(plaintextSize: plaintextSize,
                                                 originalFilename: originalFilename)
        let plan = BC01UploadPlan(headerSize: session.headerBytes.count,
                                  plaintextSize: plaintextSize,
                                  blockSize: session.blockSize,
                                  cipherPadding: session.cipherPadding)

        progress.totalUnitCount = Int64(max(plan.ciphertextSize, 1))

        // Single request: the whole object fits the transport's one-shot limit (always true for an
        // empty file, whose ciphertext is the header alone or nothing). Memory is bounded by
        // `singleRequestLimit`; no fragment session is ever opened.
        if plan.blockCount == 0 || plan.ciphertextSize <= putter.singleRequestLimit {
            try Task.checkCancellation()
            let bytes = try Self.readAndEncrypt(sourceURL, blocks: 0..<plan.blockCount,
                                                plan: plan, session: session)
            let payload = try await putter.putWhole(bytes)
            progress.completedUnitCount = progress.totalUnitCount
            return Result(completionPayload: payload, ciphertextSize: plan.ciphertextSize,
                          blockContext: session.blockContext)
        }

        // Size fragments from the plaintext size unless the caller pinned an explicit span.
        let spanBytes = explicitSpanBytes
            ?? min(Self.fragmentBytes(forPlaintextSize: plaintextSize), maxSpanBytes)
        let spans = plan.laneSpans(maxSpanBytes: spanBytes,
                                   alignment: putter.fragmentAlignment)
        let tracker = UploadProgressTracker(total: plan.ciphertextSize, progress: progress)

        // Read + encrypt one span into its finished ciphertext fragment. No I/O to the
        // transport, so it can be run ahead of the PUT it belongs to.
        let buildFragment: @Sendable (Range<Int>) async throws -> Data = { span in
            try Task.checkCancellation()

            return try Self.readAndEncrypt(sourceURL, blocks: span, plan: plan, session: session)
        }

        let uploadSpan: @Sendable (Range<Int>) async throws -> Data? = { span in
            let fragment = try await buildFragment(span)
            let start = span.lowerBound == 0
                ? 0 : plan.ciphertextOffset(ofBlock: span.lowerBound)
            let payload = try await putter.putRange(fragment, start: start,
                                                    totalSize: plan.ciphertextSize)
            await tracker.advance(by: fragment.count)
            return payload
        }

        var completionPayload: Data?

        if !putter.supportsParallelFragments || lanes == 1 || spans.count == 1 {
            // Serial, ascending — required by transports that reject out-of-order fragments
            // (Graph: "fragments must be uploaded sequentially in order").
            //
            // PUTs are strictly ordered, but the *encrypt* of span n+1 is overlapped with the
            // in-flight PUT of span n: a one-span read-ahead. That keeps the CPU and the link
            // busy at the same time — the whole point of streaming — at a cost of one extra
            // resident span. Without it a serial transport would alternate encrypt/upload and
            // idle one resource throughout.
            var pending: Task<Data, Error>? = spans.first.map { span in
                Task { try await buildFragment(span) }
            }
            for (index, span) in spans.enumerated() {
                guard let current = pending else { break }
                let fragment = try await current.value

                // Kick off the next encrypt before awaiting this PUT.
                pending = index + 1 < spans.count
                    ? Task { [next = spans[index + 1]] in try await buildFragment(next) }
                    : nil

                do {
                    let start = span.lowerBound == 0
                        ? 0 : plan.ciphertextOffset(ofBlock: span.lowerBound)
                    try Task.checkCancellation()
                    if let payload = try await putter.putRange(fragment, start: start,
                                                               totalSize: plan.ciphertextSize) {
                        completionPayload = payload
                    }
                    await tracker.advance(by: fragment.count)
                } catch {
                    pending?.cancel()
                    throw error
                }
            }
            pending?.cancel()
        } else {
            // Windowed task group: at most `lanes` fragments in flight at any moment. Priming
            // then refilling on each completion is what bounds memory — an unwindowed
            // `addTask` per span would spawn one task per fragment and defeat the span cap.
            var next = 0
            try await withThrowingTaskGroup(of: (Data?).self) { group in
                while next < spans.count && next < lanes {
                    let span = spans[next]
                    group.addTask { try await uploadSpan(span) }
                    next += 1
                }
                while let payload = try await group.next() {
                    if let payload { completionPayload = payload }
                    if next < spans.count {
                        let span = spans[next]
                        group.addTask { try await uploadSpan(span) }
                        next += 1
                    }
                }
            }
        }

        try Task.checkCancellation()
        progress.completedUnitCount = progress.totalUnitCount

        guard let completionPayload else { throw CommonError.internalError }
        return Result(completionPayload: completionPayload, ciphertextSize: plan.ciphertextSize,
                      blockContext: session.blockContext)
    }

    /// Read plaintext blocks `blocks` from `sourceURL` and encrypt them into one ciphertext
    /// fragment. The header rides with the fragment starting at block 0, so it never costs a
    /// round trip of its own.
    ///
    /// Opens its own handle, so concurrent spans never share a seek cursor. Memory held is one
    /// span, freed when the caller drops the result.
    private static func readAndEncrypt(_ sourceURL: URL, blocks: Range<Int>,
                                       plan: BC01UploadPlan,
                                       session: any FileEncryptionSession) throws -> Data {
        guard !blocks.isEmpty else { return blocks.lowerBound == 0 ? session.headerBytes : Data() }
        let handle = try FileHandle(forReadingFrom: sourceURL)
        defer { try? handle.close() }
        let readOffset = blocks.lowerBound * plan.blockSize
        try handle.seek(toOffset: UInt64(readOffset))
        let readLength = min(blocks.count * plan.blockSize, plan.plaintextSize - readOffset)
        let slice = try handle.read(upToCount: readLength) ?? Data()

        let body = try session.encryptBlocks(slice,
                                             firstBlock: blocks.lowerBound,
                                             isFinal: blocks.upperBound == plan.blockCount)
        return blocks.lowerBound == 0 ? session.headerBytes + body : body
    }
}

/// Serialises progress accounting across lanes and quantises to ~10 updates.
private actor UploadProgressTracker {
    private let total: Int
    private let progress: Progress
    private let step: Int
    private var sent = 0
    private var nextThreshold: Int

    init(total: Int, progress: Progress) {
        self.total = total
        self.progress = progress
        self.step = max(total / 10, 1)
        self.nextThreshold = max(total / 10, 1)
    }

    func advance(by count: Int) {
        sent += count
        if sent >= nextThreshold {
            progress.completedUnitCount = Int64(min(sent, max(total, 1)))
            while nextThreshold <= sent { nextThreshold += step }
        }
    }
}
