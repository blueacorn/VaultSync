/// Microsoft Graph `driveItem` wire models, shared between the container app's
/// folder picker and the Provider extension's ``GraphDriveClient``.
///
/// Mapping to ``DomainService`` currency types lives in the Extension target
/// (`GraphMapping`); only the decode-side models and a configured decoder are shared
/// here so both targets agree on the wire shape.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Graph driveItem model

/// A subset of the Graph `driveItem` resource.
public struct GraphDriveItem: Decodable {
    public let id: String
    public let name: String?
    public let eTag: String?
    public let cTag: String?
    public let size: Int64?
    public let createdDateTime: Date?
    public let lastModifiedDateTime: Date?
    public let parentReference: ParentReference?
    public let file: FileFacet?
    public let folder: FolderFacet?
    public let deleted: DeletedFacet?
    /// Top-level field on delta tombstone items; distinct from `DeletedFacet`.
    public let deletedDateTime: Date?

    public struct ParentReference: Decodable {
        public let driveId: String?
        public let id: String?
        public let path: String?
        public init(driveId: String?, id: String?, path: String?) {
            self.driveId = driveId; self.id = id; self.path = path
        }
    }
    public struct FileFacet: Decodable {
        public let mimeType: String?
        public let hashes: Hashes?
        public init(mimeType: String?, hashes: Hashes? = nil) { self.mimeType = mimeType; self.hashes = hashes }

        /// Graph content hashes. `quickXorHash` is populated on OneDrive Personal; the
        /// SHA variants are drive-dependent. Used for instrumentation of content identity.
        public struct Hashes: Decodable {
            public let quickXorHash: String?
            public let sha1Hash: String?
            public let sha256Hash: String?
            public init(quickXorHash: String?, sha1Hash: String?, sha256Hash: String?) {
                self.quickXorHash = quickXorHash; self.sha1Hash = sha1Hash; self.sha256Hash = sha256Hash
            }
        }
    }
    public struct FolderFacet: Decodable {
        public let childCount: Int?
        public init(childCount: Int?) { self.childCount = childCount }
    }
    public struct DeletedFacet: Decodable {
        public let state: String?
        public init(state: String?) { self.state = state }
    }
    public struct SpecialFolderFacet: Decodable {
        public let name: String?
        public init(name: String?) { self.name = name }
    }
    /// Opaque presence-only facet: non-nil means this item is a link into a remote drive.
    public struct RemoteItemFacet: Decodable {
        public let id: String?
        public init(id: String?) { self.id = id }
    }

    public let specialFolder: SpecialFolderFacet?
    public let remoteItem: RemoteItemFacet?

    public init(id: String, name: String?, eTag: String?, cTag: String?, size: Int64?,
                createdDateTime: Date?, lastModifiedDateTime: Date?,
                parentReference: ParentReference?, file: FileFacet?,
                folder: FolderFacet?, deleted: DeletedFacet?,
                deletedDateTime: Date? = nil, specialFolder: SpecialFolderFacet? = nil,
                remoteItem: RemoteItemFacet? = nil) {
        self.id = id; self.name = name; self.eTag = eTag; self.cTag = cTag; self.size = size
        self.createdDateTime = createdDateTime; self.lastModifiedDateTime = lastModifiedDateTime
        self.parentReference = parentReference; self.file = file
        self.folder = folder; self.deleted = deleted; self.deletedDateTime = deletedDateTime
        self.specialFolder = specialFolder; self.remoteItem = remoteItem
    }

    public var isFolder: Bool { folder != nil }
    public var isDeleted: Bool { deleted != nil }
    /// True for items that must be excluded from the user's file tree. "Personal Vault"
    /// appears in `/children` as a `remoteItem` link — it is not a real folder in
    /// the serving subtree and must be skipped at both ingestion points.
    public var isExcludedSpecialItem: Bool { remoteItem != nil }
}

/// A Graph collection page (`value` + optional `@odata.nextLink` / `@odata.deltaLink`).
public struct GraphCollection<Element: Decodable>: Decodable {
    public let value: [Element]
    public let nextLink: String?
    public let deltaLink: String?

    public enum CodingKeys: String, CodingKey {
        case value
        case nextLink = "@odata.nextLink"
        case deltaLink = "@odata.deltaLink"
    }
}

/// An upload session for large file content (`createUploadSession`).
public struct GraphUploadSession: Decodable {
    public let uploadUrl: String
    public let nextExpectedRanges: [String]?
}

// MARK: - Decoder

/// Decoding support for Graph payloads.
///
/// ## Performance
///
/// Timestamp parsing dominates the cost of decoding a delta page — a 10,000-item page carries
/// 20,000 timestamps, and everything else in a `driveItem` is a string or an integer. Measured
/// on an M-series Mac, decoding 10k items:
///
///     every date takes the fast path (current)              ~0.03 s
///     every date misses, cached formatters                  ~1.33 s
///
/// Two rules keep the current numbers:
///
/// 1. `ISO8601DateFormatter` instances stay cached as static lets.
///     Constructing formatter per decode is expensive (~2.4 s per 10k).
/// 2. ``parseISO8601``'s fast path is tried first, and only genuinely unusual shapes reach a
///    formatter. Cost scales with the miss rate, so a rare fractional value is free.
public enum GraphDecoding {

    /// ISO8601 with fractional seconds. Retained for callers that format dates and as the
    /// last-resort parse fallback — Graph itself emits whole seconds (see ``parseISO8601``).
    ///
    /// Cached deliberately: see the type's Performance note.
    public static let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Non-fractional ISO8601 — the shape Graph actually sends. Cached deliberately: see the
    /// type's Performance note.
    private static let plainFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    /// Parse a Graph timestamp.
    ///
    /// Graph emits whole-second UTC (`2025-02-21T11:55:26Z`) — verified against live delta
    /// pages, in which every `createdDateTime`/`lastModifiedDateTime` is fixed-width with no
    /// fractional part. That shape is parsed here with integer arithmetic (days-from-civil)
    /// and no `Foundation` date machinery: ~48x faster than the cached formatters across a
    /// 10k-item decode (0.03 s vs 1.33 s), and ~86x faster than the per-date formatter
    /// construction this replaced.
    ///
    /// Anything not matching the fast shape — a fractional part, an offset other than `Z` —
    /// falls back to the cached formatters, so a change on Graph's side costs speed, not
    /// correctness. Both fallbacks are tried because a miss is assumed rare; if Graph ever
    /// switches format wholesale, reorder them rather than paying both on every date.
    public static func parseISO8601(_ string: String) -> Date? {
        if let date = fastParse(string) { return date }
        return plainFormatter.date(from: string) ?? dateFormatter.date(from: string)
    }

    /// Fixed-width `yyyy-MM-ddTHH:mm:ssZ` fast path. Returns nil for any other shape —
    /// including a fractional part, a non-`Z` offset, or an out-of-range field — so a caller
    /// that gets a value back can rely on it without a formatter cross-check.
    private static func fastParse(_ string: String) -> Date? {
        var b = [UInt8]()
        b.reserveCapacity(20)
        for c in string.utf8 {
            b.append(c)
            if b.count > 20 { return nil }   // longer than the fixed shape (e.g. fractional)
        }
        guard b.count == 20, b[19] == UInt8(ascii: "Z"),
              b[4] == UInt8(ascii: "-"), b[7] == UInt8(ascii: "-"),
              b[10] == UInt8(ascii: "T"), b[13] == UInt8(ascii: ":"),
              b[16] == UInt8(ascii: ":") else { return nil }

        @inline(__always) func num(_ start: Int, _ end: Int) -> Int? {
            var value = 0
            for i in start..<end {
                let c = b[i]
                guard c >= UInt8(ascii: "0"), c <= UInt8(ascii: "9") else { return nil }
                value = value * 10 + Int(c - UInt8(ascii: "0"))
            }
            return value
        }
        guard let year = num(0, 4), let month = num(5, 7), let day = num(8, 10),
              let hour = num(11, 13), let minute = num(14, 16), let second = num(17, 19),
              month >= 1, month <= 12, day >= 1, day <= 31,
              hour < 24, minute < 60, second <= 60 else { return nil }

        // Howard Hinnant's days-from-civil: civil date → days since 1970-01-01, no Calendar.
        let y = year - (month <= 2 ? 1 : 0)
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        return Date(timeIntervalSince1970: Double(days * 86_400 + hour * 3600 + minute * 60 + second))
    }

    /// Build a JSON decoder configured for Graph timestamps.
    public static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let string = try container.decode(String.self)
            guard let date = parseISO8601(string) else {
                throw DecodingError.dataCorruptedError(in: container,
                                                       debugDescription: "bad date \(string)")
            }
            return date
        }
        return decoder
    }
}
