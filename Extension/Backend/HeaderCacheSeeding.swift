/// Shared write-side of the ``BC01HeaderCache``: seed a row from an upload.
///
/// Every content upload (create or modify) re-encrypts under a fresh file key
/// and IV, and the uploader already holds the resulting header. Writing it here makes the first
/// read after a save a cache hit instead of a header probe. The counterpart of the read side in
/// ``StreamingDownload/run(fetcher:decryptor:isEncrypted:itemIdentifier:revision:plaintextRange:destinationURL:progress:headerCache:lanes:threshold:maxSpanBytes:cryptoReporter:itemName:)``;
/// both key on ``DomainService/Version/contentIdentity``, so the row stored is the row read.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import Common
import os.log

enum HeaderCacheSeeding {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "bc01-header-cache")

    /// Store `header` for `itemID` at `contentIdentity`, or drop the item's row when that is not possible.
    ///
    /// A `nil` header (plain file, or an encrypted payload whose header could not be parsed) and a
    /// failed store (e.g. vault locked) both invalidate: after an upload any existing row describes
    /// bytes that no longer exist, so leaving it would be worse than a miss.
    ///
    /// - Parameters:
    ///   - cache: The domain's header cache; `nil` when unavailable (no-op).
    ///   - header: The uploaded file's block context.
    ///   - itemID: The backend item identifier (the cache key).
    ///   - contentIdentity: The uploaded content's identity (``DomainService/Version/contentIdentity``,
    ///     i.e. without the `|p<size>` stamp), derived by the backend's own mapping — never
    ///     hand-built — so it matches what the download path keys on.
    static func seed(_ cache: BC01HeaderCache?, header: BC01Header?,
                     itemID: String, contentIdentity: String) {
        guard let cache else { return }
        if let header {
            do {
                try cache.store(header, itemID: itemID, contentRevision: contentIdentity)
                return
            } catch {
                log.debugPublic("⚠️ header cache seed failed item=\(itemID): \(String(describing: error)) — invalidating")
            }
        }
        try? cache.invalidate(itemID: itemID)
    }
}
