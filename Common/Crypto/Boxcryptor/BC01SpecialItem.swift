/// Boxcryptor's special items: entries that are BC01 bookkeeping rather than user content.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Boxcryptor's special items: entries that are BC01 bookkeeping rather than user content.
///
/// The BC01 analogue of ``GraphDriveItem/isExcludedSpecialItem`` — the same question ("is
/// this the backend's own metadata?") asked of a different scheme. Both seeders ask both;
/// these are *BC01's* special items, a separate list from OneDrive's.
///
/// Gated on the domain's algorithm being ``CryptoAlgorithm/bc01``: under a `.plain` domain
/// a file with one of these names is an ordinary user file and passes through untouched.
///
/// - Important: Pure by contract. It takes a name and a type flag and returns a `Bool`; it
///   must never hold or touch a store — no `MetadataCache`, no I/O, no config reads beyond
///   the ``CryptoAlgorithm`` handed to `init`. Recording the encrypted-folder mark is the
///   *caller's* job at every call site. The emulator backend has no `MetadataCache` at all,
///   and this type lives in `Common` while `MetadataCache` is a OneDrive detail in
///   `Extension`, so a store-touching member here would both invert the dependency and
///   exclude a backend that exists today.
public struct BC01SpecialItem: Sendable {
    /// Boxcryptor's fixed folder-key filename (compared case-insensitively).
    public static let folderKeyFilename = "FolderKey.bch"

    private let active: Bool

    public init(algorithm: CryptoAlgorithm) { self.active = (algorithm == .bc01) }

    /// Whether `name` is BC01 bookkeeping and must never be enumerated to the system.
    ///
    /// - Parameter isFolder: a *folder* so named is not bookkeeping; only a file is.
    ///   Callers pass the backend's own type flag rather than guessing from the name.
    public func isSpecial(name: String, isFolder: Bool) -> Bool {
        isFolderKeyEvidence(name: name, isFolder: isFolder)
    }

    /// Whether `name` is the `FolderKey.bch` sidecar, whose presence proves its parent
    /// folder is encrypted.
    ///
    /// A strict subset of ``isSpecial(name:isFolder:)``: every folder key is special, but a
    /// future sidecar (e.g. `.bclink`) would be special while proving nothing about
    /// encryption. Kept separate so hiding and evidence never collapse into one test.
    public func isFolderKeyEvidence(name: String, isFolder: Bool) -> Bool {
        active && !isFolder
            && name.caseInsensitiveCompare(Self.folderKeyFilename) == .orderedSame
    }
}
