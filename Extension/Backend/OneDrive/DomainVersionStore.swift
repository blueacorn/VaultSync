/// Derives the extension-owned ``NSFileProviderDomainVersion`` for a OneDrive domain from
/// state the ``MetadataCache`` already holds, keeping that policy out of the pure cache.
///
/// The system reads `domainVersion` from the extension to decide whether its view of the domain
/// is stale. We make the version a function of two monotonic integers the cache owns:
///   - `rank_hwm` — advanced on every reconciled remote change (delta upsert/delete), and
///   - a host **config epoch** — bumped by the host (feature-flag toggles, manual nudge) in
///     `config.json` and folded in here.
///
/// `NSFileProviderDomainVersion` exposes only `init()` and `next()` (no integer initializer), so
/// the version object itself is persisted — as an opaque base64 `String` in the cache's `meta`
/// table, alongside the rank and epoch it was last stamped at. On read, if either input has moved
/// past its stamp, the version is advanced `next()` once per step and restamped. The cache never
/// imports FileProvider; it only stores strings handed to it inside a ``MetadataCache/withMetaTransaction``
/// critical section, so version and stamps stay mutually consistent.
///
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import FileProvider

/// Owns the ``NSFileProviderDomainVersion`` policy for one domain, backed by a ``MetadataCache``.
struct DomainVersionStore {

    private let cache: MetadataCache

    /// `meta` keys. Private to this policy layer; the cache treats the values as opaque strings.
    private enum Key {
        static let version = "domain_version"          // base64-archived NSFileProviderDomainVersion
        static let rankStamp = "domain_version_rank"   // rank_hwm reflected in `version`
        static let epochStamp = "domain_version_epoch" // host config epoch reflected in `version`
    }

    init(cache: MetadataCache) {
        self.cache = cache
    }

    /// The current domain version, reconciled against the latest rank and the supplied host
    /// config epoch. Advances and restamps the persisted version when either input moved; a call
    /// with no movement re-reports the same version, so repeated working-set signals don't loop.
    func currentVersion(configEpoch: Int) -> NSFileProviderDomainVersion {
        cache.withMetaTransaction { meta in
            var version = decode(meta.get(Key.version)) ?? NSFileProviderDomainVersion()
            let rankStamp = meta.get(Key.rankStamp).flatMap(Int64.init) ?? 0
            let epochStamp = meta.get(Key.epochStamp).flatMap(Int.init) ?? 0

            let rank = meta.currentRank()
            // One bump if the remote tree advanced, one if host config advanced. The version is an
            // opaque monotonic token, so a single step per dirty input is sufficient and cheap.
            if rank > rankStamp { version = version.next() }
            if configEpoch > epochStamp { version = version.next() }

            if rank > rankStamp || configEpoch > epochStamp || meta.get(Key.version) == nil {
                try? meta.set(Key.version, encode(version))
                try? meta.set(Key.rankStamp, String(rank))
                try? meta.set(Key.epochStamp, String(configEpoch))
            }
            return version
        }
    }

    // MARK: - Archiving

    private func decode(_ base64: String?) -> NSFileProviderDomainVersion? {
        guard let base64, let data = Data(base64Encoded: base64) else { return nil }
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: NSFileProviderDomainVersion.self, from: data)
    }

    private func encode(_ version: NSFileProviderDomainVersion) -> String {
        let data = (try? NSKeyedArchiver.archivedData(withRootObject: version, requiringSecureCoding: true)) ?? Data()
        return data.base64EncodedString()
    }
}
