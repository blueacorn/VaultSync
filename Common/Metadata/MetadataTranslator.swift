/// Backend ↔ display metadata translation (name *and* size).
///
/// The name-space analogue of ``FileEncryptor``/``FileDecryptor``: where those translate
/// file *content* between its on-disk and remote forms, a ``MetadataTranslator`` translates
/// a file's *metadata* — its display name and apparent size — between the values the user
/// sees and the backend-encoded values the remote stores (e.g. Boxcryptor's `.bc` suffix and
/// its 4096-aligned ciphertext framing).
///
/// Supersedes the name-only `FilenameTranslator`. Follows the interface-at-root,
/// implementations-in-subfolders convention: this protocol and the identity default live at
/// `Common/Metadata/`; concrete schemes live in sub-folders (e.g.
/// `Common/Metadata/Boxcryptor/`).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

public protocol MetadataTranslator: Sendable {
    /// Whether a backend name denotes a content-encrypted file under this scheme.
    ///
    /// True only when the scheme is active *and* the name matches its encoded form (for
    /// BC01: name ends in `.bc`). Lets callers decide per-file — e.g. skip a server-side
    /// thumbnail fetch that would always 404 for ciphertext — without inspecting bytes.
    func isBackendEncrypted(_ name: String) -> Bool

    /// Display name → backend-encoded name (e.g. append a scheme-specific suffix).
    func encodeForBackend(_ name: String) -> String
    /// Backend-encoded name → display name (e.g. strip a scheme-specific suffix).
    func decodeFromBackend(_ name: String) -> String

    /// Backend (ciphertext) size → display (plaintext) size, or `nil` when it is not knowable
    /// from the ciphertext length alone.
    ///
    /// `name` is the backend-encoded name: the scheme decides per-file whether the entry is
    /// content-encrypted (see ``isBackendEncrypted(_:)``), so a name the scheme does not claim
    /// is passed through exactly even while the scheme is active.
    ///
    /// For an encrypting scheme the exact plaintext size is NOT recoverable from the ciphertext
    /// size (per-file header length + PKCS7 last-block padding ambiguity), and a wrong answer is
    /// worse than no answer: an over-reported `documentSize` makes
    /// `NSFileProviderPartialContentFetching` unusable, because the system keeps requesting tail
    /// bytes past the real EOF that never arrive. So such a translator returns `nil` rather than
    /// guessing, and the caller substitutes the authoritative value persisted in `MetadataCache`
    /// (`plaintext_size`), learned by reading the file's header.
    ///
    /// There is deliberately no inverse: the backend's ciphertext size on upload is taken from
    /// the encryptor's output (the encrypted temp file's actual length), never approximated.
    /// An encrypting scheme's encryptor must frame uploads with the same header reserve its
    /// estimate assumes (BC01: ``BC01Framing/headerSize(plaintextSize:)``), so files this app
    /// writes estimate as precisely as files the original client wrote.
    func displaySize(forBackendSize backendSize: Int64, name: String) -> Int64?

    /// Best estimate of the display (plaintext) size, for publishing before the exact value is
    /// known. Equals ``displaySize(forBackendSize:name:)`` whenever that is non-`nil`.
    ///
    /// `backendSize` MUST be the ciphertext length, never an already-resolved plaintext length.
    /// An estimate is not exact, so ``isDisplaySizeKnown(_:)`` stays `false` for it and the
    /// caller still substitutes the authoritative size once resolved. `nil` when the scheme
    /// cannot estimate (the backend size is then published).
    func estimatedDisplaySize(forBackendSize backendSize: Int64, name: String) -> Int64?
}

public extension MetadataTranslator {
    /// Default: no scheme-level encryption, so no backend name is encrypted.
    func isBackendEncrypted(_ name: String) -> Bool { false }

    /// Default: no estimate beyond the exact size.
    func estimatedDisplaySize(forBackendSize backendSize: Int64, name: String) -> Int64? {
        displaySize(forBackendSize: backendSize, name: name)
    }

    /// Whether ``displayEntry(_:)`` produced a real display size for this entry, as opposed to
    /// passing the backend size through because the true size is not yet knowable.
    ///
    /// The size a caller sees is the same `Int64` either way, so this is the only way to
    /// distinguish them. A caller holding the authoritative `plaintext_size` should substitute
    /// it whenever this is `false`.
    func isDisplaySizeKnown(_ entry: DomainService.Entry) -> Bool {
        guard decodeFromBackend(entry.name) != entry.name else { return true }
        return displaySize(forBackendSize: entry.size, name: entry.name) != nil
    }

    /// Returns `entry` rewritten for display: backend name decoded and size translated.
    ///
    /// Gated on the name actually changing under ``decodeFromBackend(_:)`` — i.e. only files
    /// the scheme recognises as encoded (for BC01, names ending in `.bc`) are rewritten; every
    /// other entry, including folders, passes through untouched.
    ///
    /// When ``displaySize(forBackendSize:name:)`` returns `nil` the entry's size is carried through
    /// unchanged: `DomainService.Entry.size` cannot express "unknown". It is not estimated here —
    /// by this point `entry.size` may already be a resolved plaintext size, and estimating from it
    /// would subtract the header twice. Backends apply
    /// ``estimatedDisplaySize(forBackendSize:name:)`` where the size is known to be ciphertext
    /// (e.g. `GraphMapping.entry`). A caller with access to
    /// `MetadataCache` is expected to overwrite it with the persisted exact plaintext size —
    /// see ``isDisplaySizeKnown(forBackendSize:)``, which lets it tell the two cases apart
    /// without re-deriving the name test.
    func displayEntry(_ entry: DomainService.Entry) -> DomainService.Entry {
        let displayName = decodeFromBackend(entry.name)
        guard displayName != entry.name else { return entry }
        return DomainService.Entry(
            name: displayName, id: entry.id, parent: entry.parent,
            revision: entry.revision, deleted: entry.deleted,
            size: displaySize(forBackendSize: entry.size, name: entry.name) ?? entry.size,
            children: entry.children, type: entry.type,
            metadata: entry.metadata, userInfo: entry.userInfo)
    }
}

/// No-op translator: backend metadata equals display metadata. Used by every backend/algorithm
/// that does not rewrite names or reframe content.
public struct IdentityMetadataTranslator: MetadataTranslator {
    public init() {}
    public func encodeForBackend(_ name: String) -> String { name }
    public func decodeFromBackend(_ name: String) -> String { name }
    /// Never `nil`: with no encryption the ciphertext size *is* the plaintext size, exactly.
    public func displaySize(forBackendSize backendSize: Int64, name: String) -> Int64? { backendSize }
}
