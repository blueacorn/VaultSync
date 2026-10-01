/// Shared backend wiring for ``ContentStreamDownloader``-based `downloadToFile`.
///
/// Every backend's streaming download performs the same steps: look up a cached ``BC01Header``
/// (so repeat ranged fetches skip the header GET), build the downloader over the backend's
/// ``ContentFetching`` adapter, run it, and publish any freshly-probed header back to the cache.
/// Factoring it here keeps each backend's `downloadToFile` a thin adapter — the single reuse seam
/// a new backend plugs into.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common
import os.log

enum StreamingDownload {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "streaming-download")

    /// The exact plaintext length of an encrypted item, from its cached or probed BC01 header.
    ///
    /// Shares the header cache key with ``run(fetcher:decryptor:isEncrypted:itemIdentifier:revision:plaintextRange:destinationURL:progress:headerCache:lanes:threshold:maxSpanBytes:cryptoReporter:itemName:)``,
    /// so a probed header is reused by the content fetch that follows.
    ///
    /// - Parameters:
    ///   - fetcher: Ranged ciphertext transport.
    ///   - decryptor: Unwraps the header's file key.
    ///   - itemIdentifier: Header cache key.
    ///   - revision: Item revision; keyed on its content identity.
    ///   - remoteSize: Total ciphertext length.
    ///   - headerCache: Per-backend header cache, if available.
    ///   - onPlaintextSizeResolved: Persists every probed length (not-BC01 included). Not called
    ///     on a header-cache hit: the cached row implies the size is already recorded; see
    ///     ``publishResolvedHeader(_:remoteSize:itemID:contentRevision:headerCache:onPlaintextSizeResolved:)``.
    /// - Returns: The plaintext length; `remoteSize` for a `.bc`-named file without BC01 magic.
    static func resolvePlaintextSize(fetcher: ContentFetching,
                                     decryptor: BC01Decryptor,
                                     itemIdentifier: DomainService.ItemIdentifier,
                                     revision: DomainService.Version,
                                     remoteSize: Int,
                                     headerCache: BC01HeaderCache?,
                                     onPlaintextSizeResolved: (@Sendable (Int64) -> Void)?) async throws -> Int64 {
        guard remoteSize > 0 else { return 0 }
        let cacheItemID = itemIdentifier.id
        let cacheRevision = revision.contentIdentity
        if let header = headerCache?.header(itemID: cacheItemID, contentRevision: cacheRevision) {
            return Int64(BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: remoteSize))
        }
        switch try await BC01HeaderProbe.fetchHeader(fetcher: fetcher, decryptor: decryptor,
                                                     remoteSize: remoteSize) {
        case .notBC01:
            let size = Int64(remoteSize)
            onPlaintextSizeResolved?(size)
            return size
        case .encrypted(let header, _):
            return publishResolvedHeader(header, remoteSize: remoteSize, itemID: cacheItemID,
                                         contentRevision: cacheRevision, headerCache: headerCache,
                                         onPlaintextSizeResolved: onPlaintextSizeResolved)
        }
    }

    /// Publish a freshly-probed header: persist its exact plaintext length, then cache it.
    ///
    /// The single write path for a probed header. Keeps the invariant that a
    /// ``BC01HeaderCache`` row implies the backend has recorded that version's plaintext size:
    /// the size is persisted first, so a failed cache store leaves only a harmless cache miss,
    /// never a cached header with an unresolved size. Best-effort by design: a cache write must
    /// never fail the download or probe it accelerates, so a throw is logged and swallowed.
    ///
    /// - Returns: The exact plaintext length derived from `header`.
    @discardableResult
    private static func publishResolvedHeader(_ header: BC01Header,
                                              remoteSize: Int,
                                              itemID: String,
                                              contentRevision: String,
                                              headerCache: BC01HeaderCache?,
                                              onPlaintextSizeResolved: (@Sendable (Int64) -> Void)?) -> Int64 {
        let size = Int64(BC01CryptoCommon.exactPlaintextSize(header: header, remoteSize: remoteSize))
        onPlaintextSizeResolved?(size)
        do {
            try headerCache?.store(header, itemID: itemID, contentRevision: contentRevision)
        } catch {
            log.debugPublic("⚠️ header cache store failed item=\(itemID): \(String(describing: error))")
        }
        return size
    }

    /// Run a streaming download/decrypt to `destinationURL` via the supplied ``ContentFetching``
    /// adapter, threading the per-domain ``BC01HeaderCache`` through so a previously-resolved
    /// header is reused and a newly-probed one is persisted.
    ///
    /// - Parameters:
    ///   - fetcher: The backend's ranged-GET transport seam.
    ///   - decryptor: BC01 or plain decryptor for this item.
    ///   - isEncrypted: Whether the item is BC01-encrypted.
    ///   - itemIdentifier: For the header-cache key.
    ///   - revision: Revision of the content actually being fetched — the header-cache key.
    ///     Must be the backend's authoritative current revision (or the explicitly requested
    ///     one, where the backend honours it), never the OS-requested revision alone: that is
    ///     `nil` on an ordinary materialise, and a constant key there serves a stale header
    ///     after any content write.
    ///   - plaintextRange: Optional requested plaintext window (`nil` = whole file).
    ///   - destinationURL: Where plaintext is written, at absolute plaintext offsets (sparse for a ranged fetch).
    ///   - progress: Byte progress sink.
    ///   - headerCache: Per-backend BC01 header cache. `nil` when the store is unavailable —
    ///     every fetch then takes the probe path, which is the pre-cache behaviour.
    ///   - lanes: Parallel lane count.
    ///   - threshold: Minimum size for multi-lane fan-out.
    ///   - maxSpanBytes: Upper bound on one lane request's byte span (`0` disables the cap).
    ///   - onPlaintextSizeResolved: Persists the exact length as soon as a header is probed —
    ///     before the body transfers, so a cancelled or failed download still records it.
    /// - Returns: The final on-disk plaintext byte length, the plaintext window origin (the
    ///   offset of the first written byte; `0` for a whole-file fetch), and the exact whole-file
    ///   plaintext length (equal to the first for a whole-file fetch).
    static func run(fetcher: ContentFetching,
                    decryptor: any FileDecryptor,
                    isEncrypted: Bool,
                    itemIdentifier: DomainService.ItemIdentifier,
                    revision: DomainService.Version,
                    plaintextRange: Range<Int>?,
                    destinationURL: URL,
                    progress: Progress,
                    headerCache: BC01HeaderCache?,
                    lanes: Int,
                    threshold: Int,
                    maxSpanBytes: Int = 0,
                    cryptoReporter: CryptoProgressReporter = NoOpCryptoProgressReporter(),
                    itemName: String? = nil,
                    onPlaintextSizeResolved: (@Sendable (Int64) -> Void)? = nil) async throws -> (plaintextWindow: DomainService.PlaintextWindow,
                                                              wholeFilePlaintextSize: Int64) {

        // Keyed on content IDENTITY, never the stamped token: the `|p<size>` stamp carries the
        // plaintext length this very fetch resolves, so keying on it would store the row under
        // the pre-resolution token and look it up under the post-resolution one — a guaranteed
        // miss, and a second full header GET, on every item's first read.
        let cacheItemID = itemIdentifier.id
        let cacheRevision = revision.contentIdentity
        var preResolved: BC01Header?
        var onResolved: (@Sendable (BC01Header) -> Void)?
        if isEncrypted, let headerCache {
            preResolved = headerCache.header(itemID: cacheItemID, contentRevision: cacheRevision)
        }
        if isEncrypted {
            let remoteSize = fetcher.totalSize
            onResolved = { (header: BC01Header) in
                Self.publishResolvedHeader(header, remoteSize: remoteSize, itemID: cacheItemID,
                                           contentRevision: cacheRevision, headerCache: headerCache,
                                           onPlaintextSizeResolved: onPlaintextSizeResolved)
            }
        }

        let downloader = ContentStreamDownloader(
            fetcher: fetcher,
            decryptor: decryptor,
            isEncrypted: isEncrypted,
            lanes: lanes,
            threshold: threshold,
            maxSpanBytes: maxSpanBytes,
            preResolvedHeader: preResolved,
            onHeaderResolved: onResolved)

        // Report crypto progress only for actual decrypts (BC01). Plain passthrough is not
        // a crypto operation. The op is registered before the run and always cleared after
        // (success or throw); byte progress is sampled from the shared `Progress`.
        let itemID = String(itemIdentifier.id)
        if isEncrypted {
            cryptoReporter.begin(itemID: itemID,
                                 name: itemName ?? itemID,
                                 direction: .decrypt)
        }
        let sampler = isEncrypted
            ? ProgressSampler(progress: progress, itemID: itemID, reporter: cryptoReporter)
            : nil
        sampler?.start()
        defer {
            sampler?.stop()
            if isEncrypted { cryptoReporter.finish(itemID: itemID) }
        }

        let result = try await downloader.run(to: destinationURL, progress: progress,
                                              plaintextRange: plaintextRange)
        return (result.plaintextWindow, result.wholeFilePlaintextSize)
    }

    /// Samples a `Progress` object's `fractionCompleted` on a background task and forwards it
    /// to a ``CryptoProgressReporter`` (which throttles cross-process publishing). Used to feed
    /// decrypt byte-progress into the app relay without coupling the stream pipeline to it.
    private final class ProgressSampler: @unchecked Sendable {
        private let progress: Progress
        private let itemID: String
        private let reporter: CryptoProgressReporter
        private var task: Task<Void, Never>?

        init(progress: Progress, itemID: String, reporter: CryptoProgressReporter) {
            self.progress = progress
            self.itemID = itemID
            self.reporter = reporter
        }

        func start() {
            task = Task { [progress, itemID, reporter] in
                while !Task.isCancelled {
                    reporter.update(itemID: itemID, fraction: progress.fractionCompleted)
                    try? await Task.sleep(nanoseconds: 250_000_000)
                }
            }
        }

        func stop() { task?.cancel(); task = nil }
    }

    /// Convert an optional `NSRange` (the File Provider's plaintext range) to a `Range<Int>`.
    static func plaintextRange(from range: NSRange?) -> Range<Int>? {
        guard let range, range.location >= 0, range.length > 0 else { return nil }
        return range.location..<(range.location + range.length)
    }
}
