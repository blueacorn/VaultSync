/// Reading a BC01 header off the wire, and the plaintext size that follows from it.
///
/// ``ContentStreamDownloader`` needs "fetch just enough of a `.bc` file to parse its header"
/// before it can decrypt a body against it, and the exact plaintext length falls out of the
/// same header — which is why size resolution costs nothing on a path that was fetching anyway.
/// The ladder — probe, magic check, widen once if the header overflows the probe — lives here
/// rather than in the downloader so it stays independently testable. Neither the ladder nor the
/// size derivation touches a file or the network directly: both go through the
/// ``ContentFetching`` seam, so both are unit-testable over an in-memory transport.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common

/// The fetch-and-parse ladder for a BC01 header.
enum BC01HeaderProbe {

    /// Default first-probe length: the initial fetch attempted before parsing.
    static let defaultMinHeaderLen = BC01CryptoCommon.blockSize
    /// Default upper bound on a header probe; also the widening fallback when `headerEnd`
    /// cannot be peeked from the prefix.
    static let defaultMaxHeaderLen = BC01CryptoCommon.blockSize * 32

    /// What a probe found at offset 0.
    enum Outcome {
        /// Real BC01 content, with the parsed header and the prefix bytes that produced it.
        case encrypted(header: BC01Header, prefix: Data)
        /// The bytes carry no BC01 magic: a `.bc`-named file that is not actually encrypted.
        /// It must be served as plain (plaintext == ciphertext), never decrypted.
        case notBC01
    }

    /// Fetch the smallest prefix that parses as a BC01 header.
    ///
    /// 1. one `[0, probeLen)` GET, where `probeLen = min(minHeaderLen, maxHeaderLen, remoteSize)`;
    /// 2. magic check — no magic short-circuits to ``Outcome/notBC01`` with no further fetch;
    /// 3. if the header does not fit the probe, one widening refetch sized by
    ///    ``BC01Decryptor/peekHeaderEnd(_:)`` (or `maxHeaderLen` when it cannot be peeked).
    ///
    /// - Returns: the parsed header plus the prefix it came from, or ``Outcome/notBC01``.
    /// - Throws: the transport's error, or ``BC01Error`` when a magic-carrying prefix still
    ///   fails to parse at the widened length.
    static func fetchHeader(fetcher: ContentFetching,
                            decryptor: BC01Decryptor,
                            remoteSize: Int,
                            minHeaderLen: Int = defaultMinHeaderLen,
                            maxHeaderLen: Int = defaultMaxHeaderLen) async throws -> Outcome {
        let probeLen = min(min(minHeaderLen, maxHeaderLen), remoteSize)
        let prefix = try await fetcher.fetchRange(start: 0, length: probeLen)
        return try await parse(prefix: prefix, fetcher: fetcher, decryptor: decryptor,
                         remoteSize: remoteSize, probeLen: probeLen, maxHeaderLen: maxHeaderLen)
    }

    /// The ladder's parse-and-widen half, for a caller that has already fetched a prefix by
    /// other means (``ContentStreamDownloader``'s single-GET fast path fetches `[0, end)` as
    /// both header and body, and falls back here when the header turns out not to fit).
    ///
    /// A prefix without BC01 magic is ``Outcome/notBC01``; one with magic that does not parse
    /// triggers the same single widening refetch as ``fetchHeader(fetcher:decryptor:remoteSize:minHeaderLen:maxHeaderLen:)``.
    static func parse(prefix: Data,
                      fetcher: ContentFetching,
                      decryptor: BC01Decryptor,
                      remoteSize: Int,
                      probeLen: Int,
                      maxHeaderLen: Int = defaultMaxHeaderLen) async throws -> Outcome {
        guard BC01CryptoCommon.hasBC01Magic(prefix) else { return .notBC01 }
        if let header = try? decryptor.makeBlockContext(from: prefix) {
            return .encrypted(header: header, prefix: prefix)
        }
        // Header exceeded the probe: refetch exactly as far as its declared end.
        let needed = BC01Decryptor.peekHeaderEnd(prefix) ?? maxHeaderLen
        let refetchLen = min(max(needed, probeLen), remoteSize)
        let wider = try await fetcher.fetchRange(start: 0, length: refetchLen)
        let header = try decryptor.makeBlockContext(from: wider)
        return .encrypted(header: header, prefix: wider)
    }
}
