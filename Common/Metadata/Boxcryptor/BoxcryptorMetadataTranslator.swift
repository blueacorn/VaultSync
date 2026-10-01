/// Boxcryptor BC01 metadata translation: the `.bc` filename suffix and the 4096-aligned
/// ciphertext framing.
///
/// Translation is gated on the `.bc` suffix: only entries whose backend name ends in `.bc`
/// are decoded (name) and re-sized (size). Folders and non-`.bc` files pass through unchanged,
/// even when BC01 is the domain's active algorithm.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

public struct BoxcryptorMetadataTranslator: MetadataTranslator {
    /// Whether BC01 rewriting is active for this domain (`algorithm == .bc01`).
    private let active: Bool

    /// Single BC01 header block size. The header is padded to a multiple of this; in practice it
    /// occupies exactly one block. A ciphertext no larger than this is therefore all header and
    /// carries no plaintext — the one encrypted case whose display size IS knowable from the size
    /// alone. See ``BC01CryptoCommon/blockSize``.
    private static let minimumHeaderSize = Int64(BC01CryptoCommon.blockSize)

    /// - Parameter algorithm: the domain's configured crypto algorithm. Rewriting only occurs
    ///   when it is ``CryptoAlgorithm/bc01`` *and* the name ends in `.bc`; otherwise identity.
    public init(algorithm: CryptoAlgorithm) {
        self.active = (algorithm == .bc01)
    }

    /// Whether a backend name is a BC01-encoded file (case-insensitive `.bc` suffix).
    public func isBackendEncrypted(_ name: String) -> Bool {
        active && name.lowercased().hasSuffix(".bc")
    }

    // MARK: Name

    /// Returns `name + ".bc"` when BC01 is active; otherwise `name` unchanged.
    public func encodeForBackend(_ name: String) -> String {
        active ? name + ".bc" : name
    }

    /// Strips a trailing `.bc` (case-insensitive) when BC01 is active; otherwise unchanged.
    public func decodeFromBackend(_ name: String) -> String {
        guard isBackendEncrypted(name) else { return name }
        return String(name.dropLast(3))
    }

    // MARK: Size

    /// Display (plaintext) size for a BC01 item, or `nil` when it is not knowable here.
    ///
    /// Only two answers are ever certain from the ciphertext length alone:
    ///  - the name is not BC01-encoded (inactive `.plain` config, or a non-`.bc` name) —
    ///    ciphertext *is* plaintext;
    ///  - the file is header-only (`<= minimumHeaderSize`) — it carries no plaintext, so `0`.
    ///
    /// Every other case is `nil` (see ``estimatedDisplaySize(forBackendSize:name:)`` for the
    /// published approximation). The exact length is the ciphertext length less the header and
    /// the PKCS7 `cipherPadding`, neither of which is derivable from the size — it needs the
    /// parsed header, via ``BC01CryptoCommon/exactPlaintextSize(header:remoteSize:)``. Returning
    /// the ciphertext length as an estimate would over-report by header + padding, and an
    /// over-reported `documentSize` breaks `NSFileProviderPartialContentFetching` outright: the
    /// system requests tail bytes past the real EOF forever. Callers substitute the value
    /// persisted in `MetadataCache.plaintext_size`.
    ///
    /// Gated on ``isBackendEncrypted(_:)``, so a plaintext name under an active BC01 domain
    /// reports its backend size exactly rather than `nil`.
    public func displaySize(forBackendSize backendSize: Int64, name: String) -> Int64? {
        guard active && isBackendEncrypted(name) else { return backendSize }
        guard backendSize > Self.minimumHeaderSize else { return 0 }
        return nil
    }

    /// Plaintext size estimated from the ciphertext length via ``BC01Framing``: at most 15 bytes
    /// above the true size (the PKCS7 padding length is only in the header), never below it.
    ///
    /// Publishing this instead of the ciphertext length keeps the pre-header `documentSize`
    /// within a few bytes of the truth, so apps that plan reads from `stat` (e.g. fixed-size
    /// chunking) almost never see the size move across a boundary when the header corrects it.
    public func estimatedDisplaySize(forBackendSize backendSize: Int64, name: String) -> Int64? {
        displaySize(forBackendSize: backendSize, name: name)
            ?? BC01Framing.estimatedPlaintextSize(ciphertextSize: backendSize)
    }
}
