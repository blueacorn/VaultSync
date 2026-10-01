/// RPC protocol definitions for all File Provider operations
//
//  Abstract:
//  The parameter and return values for domain-related requests to the local HTTP server.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider


public enum JSONMethod: String {
    case GET
    case POST
    case DELETE
}

public protocol JSONParameter: Codable {
    associatedtype ReturnType: Codable
    static var method: JSONMethod { get }
    static var endpoint: String { get }
}

extension NSFileProviderFileSystemFlags: Codable {
    public init(from decoder: Decoder) throws {
        try self.init(rawValue: UInt(from: decoder))
    }

    public func encode(to encoder: Encoder) throws {
        return try self.rawValue.encode(to: encoder)
    }
}

public enum DomainService {
    public static let rootItemCodingInfoKey = CodingUserInfoKey(rawValue: "rootItemIdentifier")!
    public static let trashItemCodingInfoKey = CodingUserInfoKey(rawValue: "trashItemIdentifier")!

    public enum EntryType: String, Codable {
        case file
        case folder
        case root
        case symlink
        case alias
    }

    /// Opaque content + metadata revision tokens.
    ///
    /// The emulator derives these from its Int64 `contentVersion`/`metadataVersion`
    /// columns (stringified); OneDrive uses the Graph `cTag` (content) and `eTag`
    /// (metadata). Tokens are compared as opaque strings — never parsed except by the
    /// backend that produced them.
    public struct Version: Codable, Equatable {
        public let content: String
        public let metadata: String

        public static let zero = Version(content: "0", metadata: "0")

        public init(content: String, metadata: String) {
            self.content = content
            self.metadata = metadata
        }

        /// Convenience for integer-keyed backends (emulator).
        public init(content: Int64, metadata: Int64) {
            self.content = String(content)
            self.metadata = String(metadata)
        }

        /// The separator introducing the `|p<size>` plaintext-size stamp folded into a
        /// content token. See ``contentIdentity``.
        public static let Separator = "|p"

        /// The content token stripped of any `|p<size>` plaintext-size stamp.
        ///
        /// The stamp is deliberately part of the content version published to the OS: it is
        /// what makes `documentSize` re-read once a BC01 header reveals the true plaintext
        /// length. But the length is *derived* from the content, not an identity for it, so any
        /// cache keyed on content identity must key on this instead. Keying on the stamped token
        /// guarantees a miss on an item's first read — the row is stored before the size is
        /// known, then looked up after it is.
        public var contentIdentity: String {
            content.components(separatedBy: Self.Separator)[0]
        }

        /// The `|p<size>` stamp suffix of the content token, or nil when unstamped.
        public var plaintextSizeStamp: String? {
            content.range(of: Self.Separator).map { String(content[$0.lowerBound...]) }
        }

        /// This version with its content plaintext-size stamp replaced by `size`.
        ///
        /// The stamp must live in the CONTENT version: the system applies a corrected
        /// `documentSize` for an item being materialised only when the content version moves
        /// (a metadata-only change is ignored). Strips any existing stamp first, so the result
        /// carries exactly one. The single stamping path for every publisher of a size.
        public func stampingPlaintextSize(_ size: Int64) -> Version {
            Version(content: "\(contentIdentity)\(Self.Separator)\(size)", metadata: metadata)
        }

        /// The content token as an Int64, or 0 for non-numeric (cloud) tokens.
        public var contentInt64: Int64 { Int64(content) ?? 0 }
        /// The metadata token as an Int64, or 0 for non-numeric (cloud) tokens.
        public var metadataInt64: Int64 { Int64(metadata) ?? 0 }
    }

    public struct ConflictVersion: Codable, Equatable {
        public let conflict: Bool
        public let originatorName: String
        public let creationDate: Date
        public let contentVersion: Int64
        public let baseVersion: Int64

        public init(conflict: Bool, originatorName: String, creationDate: Date, contentVersion: Int64, baseVersion: Int64) {
            self.conflict = conflict
            self.originatorName = originatorName
            self.creationDate = creationDate
            self.contentVersion = contentVersion
            self.baseVersion = baseVersion
        }
    }

    public struct RankToken: Codable, Equatable {
        public let rank: Int64
        public let tokenCheckNumber: Int64

        public init(rank: Int64, tokenCheckNumber: Int64) {
            self.rank = rank
            self.tokenCheckNumber = tokenCheckNumber
        }
    }

    public struct ItemIdentifier: Codable, Equatable, ExpressibleByStringLiteral, Hashable {
        /// Opaque, backend-defined item identifier. The emulator uses stringified Int64
        /// SQLite row ids ("42"); OneDrive uses the Graph DriveItem id. Reserved root/trash
        /// are carried over the wire via the `.root`/`.trash` flags, not this value.
        public let id: String

        /// Universal, backend-agnostic sentinel for the domain root container.
        ///
        /// Every layer above a backend (the `NSFileProviderItemIdentifier` bridge,
        /// enumerator, item construction) speaks only this token; each backend
        /// translates it to its native id at its own wire edge. The leading `$` cannot
        /// collide with an emulator Int64 id or a Graph DriveItem id.
        public static let root: ItemIdentifier = "$root"
        /// Universal, backend-agnostic sentinel for the domain trash container.
        public static let trash: ItemIdentifier = "$trash"

        public init(_ id: String) {
            self.id = id
        }

        public init(stringLiteral value: String) {
            self.id = value
        }

        /// Convenience for the emulator's Int64-keyed database.
        public init(_ id: Int64) {
            self.id = String(id)
        }

        /// The identifier as an Int64 for backends with integer keys (emulator).
        /// Returns `nil` for non-numeric (e.g. Graph) identifiers.
        public var int64Value: Int64? { Int64(id) }

        enum CodingKeys: CodingKey {
            case id
            case root
            case trash
        }

        // When encoding ItemIdentifiers to their wire format, encode as
        // .root=true if the item is the encoding domain's root item. This
        // ensures that the recipient sees the item as their own local root item
        // identifier.
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            guard let rootIdentifier = encoder.userInfo[rootItemCodingInfoKey] as? DomainService.ItemIdentifier,
                let trashIdentifier = encoder.userInfo[trashItemCodingInfoKey] as? ItemIdentifier else {
                    try container.encode(id, forKey: .id)
                    return
            }
            if self == rootIdentifier {
                try container.encode(true, forKey: .root)
            } else if self == trashIdentifier {
                try container.encode(true, forKey: .trash)
            } else {
                try container.encode(id, forKey: .id)
            }
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            if let root = try? container.decode(Bool.self, forKey: .root),
                root {
                guard let rootIdentifier = decoder.userInfo[rootItemCodingInfoKey] as? DomainService.ItemIdentifier else {
                    throw CommonError.internalError
                }
                self = rootIdentifier
            } else if let trash = try? container.decode(Bool.self, forKey: .trash),
                trash {
                guard let trashIdentifier = decoder.userInfo[trashItemCodingInfoKey] as? DomainService.ItemIdentifier else {
                    throw CommonError.internalError
                }
                self = trashIdentifier
            } else {
                self.id = try container.decode(String.self, forKey: .id)
            }
        }
    }
}

extension DomainService {
    public struct EntryMetadata: Codable {
        public struct ValidEntries: OptionSet, Codable {
            public init(rawValue: Int) {
                self.rawValue = rawValue
            }

            public let rawValue: Int

            public static let fileSystemFlags = ValidEntries(rawValue: 1 << 0)
            public static let lastUsedDate = ValidEntries(rawValue: 1 << 1)
            public static let tagData = ValidEntries(rawValue: 1 << 2)
            public static let favoriteRank = ValidEntries(rawValue: 1 << 3)
            public static let creationDate = ValidEntries(rawValue: 1 << 4)
            public static let contentModificationDate = ValidEntries(rawValue: 1 << 5)
            public static let extendedAttributes = ValidEntries(rawValue: 1 << 6)
            public static let typeAndCreator = ValidEntries(rawValue: 1 << 7)
        }
        public struct ExtendedAttributes: Codable {
            public let values: [String: Data]

            public init(values: [String: Data]) {
                self.values = values
            }
        }

        public let fileSystemFlags: NSFileProviderFileSystemFlags?
        public let lastUsedDate: Date?
        public let tagData: Data?
        public let creationDate: Date?
        public let contentModificationDate: Date?
        public let extendedAttributes: ExtendedAttributes?
        public let typeAndCreator: UInt64?
        public let validEntries: ValidEntries

        public static let empty = EntryMetadata(fileSystemFlags: nil, lastUsedDate: nil, tagData: nil, favoriteRank: nil, creationDate: nil,
                                                contentModificationDate: nil, extendedAttributes: nil, typeAndCreator: nil, validEntries: [])
        public static let emptyFolder = EntryMetadata(fileSystemFlags: [.userExecutable, .userWritable, .userReadable], lastUsedDate: nil,
                                                      tagData: nil, favoriteRank: nil, creationDate: nil, contentModificationDate: nil,
                                                      extendedAttributes: nil, typeAndCreator: nil, validEntries: [])

        public init(fileSystemFlags: NSFileProviderFileSystemFlags?, lastUsedDate: Date?, tagData: Data?, favoriteRank: Int?, creationDate: Date?,
                    contentModificationDate: Date?, extendedAttributes: ExtendedAttributes?, typeAndCreator: UInt64?, validEntries: ValidEntries?) {
            if let validEntries = validEntries {
                self.validEntries = validEntries
            } else {
                self.validEntries = [.fileSystemFlags, .lastUsedDate, .tagData, .creationDate,
                                     .contentModificationDate, .extendedAttributes, .typeAndCreator]
            }

            self.fileSystemFlags = fileSystemFlags
            self.lastUsedDate = lastUsedDate
            self.tagData = tagData
            self.creationDate = creationDate
            self.contentModificationDate = contentModificationDate
            self.extendedAttributes = extendedAttributes
            self.typeAndCreator = typeAndCreator
        }

        public func merge(_ other: EntryMetadata) -> EntryMetadata {
            let contentModDate = other.validEntries.contains(.contentModificationDate) ? other.contentModificationDate : self.contentModificationDate
            return EntryMetadata(
                fileSystemFlags: other.validEntries.contains(.fileSystemFlags) ? other.fileSystemFlags : self.fileSystemFlags,
                lastUsedDate: other.validEntries.contains(.lastUsedDate) ? other.lastUsedDate : self.lastUsedDate,
                tagData: other.validEntries.contains(.tagData) ? other.tagData : self.tagData,
                favoriteRank: nil,
                creationDate: other.validEntries.contains(.creationDate) ? other.creationDate : self.creationDate,
                contentModificationDate: contentModDate,
                extendedAttributes: other.validEntries.contains(.extendedAttributes) ? other.extendedAttributes : self.extendedAttributes,
                typeAndCreator: other.validEntries.contains(.typeAndCreator) ? other.typeAndCreator : self.typeAndCreator,
                validEntries: nil)
        }
    }

    public struct Entry: Codable {
        public struct UserInfo: Codable {
            public let conflictCount: Int?
            public let originatorName: String?
            public let symlinkTargetPath: String?
            public let implicitLockOwner: String?
            public let quotaRemaining: String?
            public let quotaTotal: String?
            /// True when the last download attempt failed with a crypto/decode error.
            /// Local-only — drives the `fileError` decoration badge.
            public let contentError: Bool?
            /// True when this trashed item was moved to the recycle bin out-of-band (by the
            /// encrypt/decrypt bulk action) and therefore has no native "Put Back". Gates the
            /// custom Restore file-provider action; queried in `Provider/Info.plist` as
            /// `$item.userInfo.restorable == YES`. Only set for tombstoned rows.
            public let restorable: Bool?
            /// True for any tombstoned (recycle-bin) row, regardless of how it was trashed.
            /// Surfaced as `$item.userInfo.trashed` so the encrypt/decrypt action predicates can
            /// exclude items already in the Trash (OneDrive rejects mutating recycle-bin items).
            public let trashed: Bool?

            public init(conflictCount: Int?, originatorName: String?, symlinkTargetPath: String?, implicitLockOwner: String?, quotaRemaining: String?,
                        quotaTotal: String?, contentError: Bool? = nil, restorable: Bool? = nil, trashed: Bool? = nil) {
                self.conflictCount = conflictCount
                self.originatorName = originatorName
                self.symlinkTargetPath = symlinkTargetPath
                self.implicitLockOwner = implicitLockOwner
                self.quotaRemaining = quotaRemaining
                self.quotaTotal = quotaTotal
                self.contentError = contentError
                self.restorable = restorable
                self.trashed = trashed
            }
        }
        public let name: String
        public let id: ItemIdentifier
        public let parent: ItemIdentifier
        public let revision: Version
        public let deleted: Bool
        public let size: Int64
        public let children: Int?
        public let type: EntryType
        public let metadata: EntryMetadata
        public let userInfo: UserInfo

        public init(name: String, id: ItemIdentifier, parent: ItemIdentifier, revision: Version, deleted: Bool, size: Int64, children: Int?,
                    type: EntryType, metadata: EntryMetadata, userInfo: UserInfo) {
            self.name = name
            self.id = id
            self.parent = parent
            self.revision = revision
            self.deleted = deleted
            self.size = size
            self.children = children
            self.type = type
            self.metadata = metadata
            self.userInfo = userInfo
        }
    }
}

extension DomainService {
    /// Which stream of an item a content write targets.
    public enum ContentStorageType: Codable, Equatable {
        /// Serialized value for ``contents``
        private static let ContentsIdentifierKey = "contentsIdentifier"
        private static let ResourceForkIdentifierKey = "resourceForkIdentifier"

        /// The item's file contents.
        case contents
        /// The macOS resource fork (`..namedfork/rsrc`).
        case resourceFork

        public init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            let enumType = try values.decode(String.self, forKey: .type)
            switch enumType {
                case ContentStorageType.ContentsIdentifierKey:
                    self = .contents
                case ContentStorageType.ResourceForkIdentifierKey:
                    self = .resourceFork
                default:
                    print("unexpected enumType \(enumType)")
                    throw CommonError.internalError
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            switch self {
            case .contents:
                try container.encode(ContentStorageType.ContentsIdentifierKey, forKey: .type)
            case .resourceFork:
                try container.encode(ContentStorageType.ResourceForkIdentifierKey, forKey: .type)
            }
        }

        enum CodingKeys: String, CodingKey {
            case type
        }
    }

    public struct ListFolderParameter: JSONParameter {
        public typealias ReturnType = ListFolderReturn
        public static let endpoint = "list_folder"
        public static let method = JSONMethod.POST
        public let folderIdentifier: ItemIdentifier
        public let recursive: Bool
        /// `nil` starts the listing from the beginning.
        public let startingCursor: PageCursor?

        public init(folderIdentifier: ItemIdentifier, recursive: Bool, startingCursor: PageCursor? = nil) {
            self.folderIdentifier = folderIdentifier
            self.recursive = recursive
            self.startingCursor = startingCursor
        }
    }

    /// Opaque, backend-owned continuation token for a paged listing.
    ///
    /// Only the backend that issued a cursor interprets it; callers pass it back unchanged.
    /// Backends encode an immutable keyset position (e.g. the last row's key) rather than an
    /// offset, so rows inserted or removed during a walk never shift an unchanged row out of
    /// the result. Encoded on the wire as a plain JSON string.
    public struct PageCursor: Codable, Hashable, Sendable {
        public let rawValue: String

        public init(_ rawValue: String) {
            self.rawValue = rawValue
        }

        public init(from decoder: Decoder) throws {
            rawValue = try decoder.singleValueContainer().decode(String.self)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(rawValue)
        }
    }

    public struct ListFolderReturn: Codable {
        public let entries: [Entry]
        public let deletedEntries: [ItemIdentifier]?
        /// Continuation token for the next page; `nil` when the listing is exhausted.
        public let cursor: PageCursor?
        public let rank: RankToken

        public init(entries: [Entry], deletedEntries: [ItemIdentifier]?, cursor: PageCursor?, rank: RankToken) {
            self.entries = entries
            self.deletedEntries = deletedEntries
            self.cursor = cursor
            self.rank = rank
        }
    }

    public struct ListChangesParameter: JSONParameter {
        public typealias ReturnType = ListChangesReturn
        public static let endpoint = "list_changes"
        public static let method = JSONMethod.POST
        public let folderIdentifier: ItemIdentifier
        public let recursive: Bool
        public let startingRank: RankToken

        public init(folderIdentifier: ItemIdentifier, recursive: Bool, startingRank: RankToken) {
            self.folderIdentifier = folderIdentifier
            self.recursive = recursive
            self.startingRank = startingRank
        }
    }
    public struct ListChangesReturn: Codable {
        public let entries: [Entry]
        public let deletedEntries: [ItemIdentifier]?
        public let rank: RankToken
        public let hasMore: Bool

        public init(entries: [Entry], deletedEntries: [ItemIdentifier]?, rank: RankToken, hasMore: Bool) {
            self.entries = entries
            self.deletedEntries = deletedEntries
            self.rank = rank
            self.hasMore = hasMore
        }
    }

    public struct LatestRankParameter: JSONParameter {
        public typealias ReturnType = LatestRankReturn
        public static let endpoint = "rank"
        public static let method = JSONMethod.POST
        public let folderIdentifier: ItemIdentifier

        public init(folderIdentifier: ItemIdentifier) {
            self.folderIdentifier = folderIdentifier
        }
    }

    public struct LatestRankReturn: Codable {
        public let rank: RankToken

        public init(rank: RankToken) {
            self.rank = rank
        }
    }

    public struct CreateParameter: JSONParameter {
        public typealias ReturnType = CreateReturn
        public static let endpoint = "create"
        public static let method = JSONMethod.POST
        public enum ConflictStrategy: String, Codable {
            case failOnExisting
            case updateAlreadyExisting
        }

        public let parent: ItemIdentifier
        public let name: String
        public let type: EntryType
        public let metadata: EntryMetadata
        public let conflictStrategy: ConflictStrategy
        public let contentStorageType: ContentStorageType?
        /// Plaintext byte length of the content being created, when known. See
        /// ``ModifyContentsParameter/plaintextSize`` for why the backend cannot derive it.
        public let plaintextSize: Int64?

        public init(parent: ItemIdentifier,
                    name: String,
                    type: EntryType,
                    metadata: EntryMetadata,
                    conflict: ConflictStrategy,
                    contentStorageType: ContentStorageType?,
                    plaintextSize: Int64? = nil) {
            self.parent = parent
            self.name = name
            self.type = type
            self.metadata = metadata
            self.conflictStrategy = conflict
            self.contentStorageType = contentStorageType
            self.plaintextSize = plaintextSize
        }
    }

    public struct CreateReturn: Codable {
        public let item: Entry

        public init(item: Entry) {
            self.item = item
        }
    }

    // This doesn't include metadata to simulate a provider that doesn't provide
    // metadata and content modifications together. However, it does break out
    // the initial upload from subsequent updates.
    public struct ModifyContentsParameter: JSONParameter {
        public typealias ReturnType = ModifyContentsReturn
        public static let endpoint = "modifyContents"
        public static let method = JSONMethod.POST
        public let identifier: ItemIdentifier
        public let existingRevision: Version
        public let contentStorageType: ContentStorageType
        public let updateResourceForkOnConflictedItem: Bool
        /// Plaintext byte length of the content being written, when the caller knows it.
        ///
        /// The `data` accompanying this parameter is *ciphertext* for an encrypted domain, so a
        /// backend cannot recover the plaintext length from it without parsing the header it
        /// just uploaded. The Extension does know it (it read the file), and a backend that
        /// gates enumeration on a known plaintext size needs it immediately — otherwise a file
        /// the user just saved vanishes from Finder until a background probe catches up.
        public let plaintextSize: Int64?

        public init(identifier: ItemIdentifier,
                    existingRevision: Version,
                    contentStorageType: ContentStorageType,
                    updateResourceForkOnConflictedItem: Bool = false,
                    plaintextSize: Int64? = nil) {
            self.identifier = identifier
            self.existingRevision = existingRevision
            self.contentStorageType = contentStorageType
            self.updateResourceForkOnConflictedItem = updateResourceForkOnConflictedItem
            self.plaintextSize = plaintextSize
        }
    }

    public struct ModifyContentsReturn: Codable {
        public let item: Entry
        public let contentAccepted: Bool

        public init(item: Entry, contentAccepted: Bool) {
            self.item = item
            self.contentAccepted = contentAccepted
        }
    }

    public struct ModifyMetadataParameter: JSONParameter {
        public typealias ReturnType = ModifyMetadataReturn
        public static let endpoint = "modifyMetadata"
        public static let method = JSONMethod.POST
        public let itemIdentifier: ItemIdentifier
        public let existingRevision: Version
        public let filename: String?
        public let parent: ItemIdentifier?
        public let metadata: EntryMetadata

        public init(itemIdentifier: ItemIdentifier, existingRevision: Version, filename: String?, parent: ItemIdentifier?, metadata: EntryMetadata) {
            self.itemIdentifier = itemIdentifier
            self.existingRevision = existingRevision
            self.filename = filename
            self.parent = parent
            self.metadata = metadata
        }
    }

    public struct ModifyMetadataReturn: Codable {
        public let item: Entry
        public let metadataWasRolledBack: Bool

        public init(item: Entry, metadataWasRolledBack: Bool) {
            self.item = item
            self.metadataWasRolledBack = metadataWasRolledBack
        }
    }

    public struct FetchItemParameter: JSONParameter {
        public typealias ReturnType = FetchItemReturn
        public static let endpoint = "info"
        public static let method = JSONMethod.POST
        public let itemIdentifier: ItemIdentifier

        public init(itemIdentifier: ItemIdentifier) {
            self.itemIdentifier = itemIdentifier
        }
    }

    public struct FetchItemReturn: Codable {
        public let item: Entry

        public init(item: Entry) {
            self.item = item
        }
    }

    public struct DownloadItemParameter: JSONParameter {
        public typealias ReturnType = DownloadItemReturn
        public static let endpoint = "download"
        public static let method = JSONMethod.GET
        public let itemIdentifier: ItemIdentifier
        public let requestedRevision: Version?
        public let resourceFork: Bool?
        public let range: NSRange?

        public init(itemIdentifier: ItemIdentifier, requestedRevision: Version?, resourceFork: Bool = false, range: NSRange? = nil) {
            self.itemIdentifier = itemIdentifier
            self.requestedRevision = requestedRevision
            self.resourceFork = resourceFork
            self.range = range
        }
    }

    public struct DownloadItemReturn: Codable {
        public let item: Entry

        public init(item: Entry) {
            self.item = item
        }
    }

    /// Result of a streaming download-to-file (see ``ProviderBackend/downloadToFile``).
    ///
    /// The backend has already written the file's bytes to the caller-supplied destination
    /// URL; ``plaintextSize`` is the final on-disk length (post-decryption when the backend
    /// owns the content cipher), used for the returned range and display size.
    public struct DownloadToFileReturn {
        public let item: Entry
        /// The plaintext bytes actually written to the destination file, at their true offsets.
        ///
        /// Whole-file fetch: `origin == 0`, `length` == the whole plaintext. Ranged (BRM)
        /// fetch: the covering window materialised (block-aligned for `.bc`), which may be wider
        /// than the requested range — report this, never the request.
        public let plaintextWindow: PlaintextWindow
        /// Exact plaintext length of the **whole file**, independent of which window this
        /// response materialised. The value published as the item's `documentSize`. Derived
        /// from the BC01 header rather than from the decrypted bytes, so it is known even when
        /// only a sub-range was fetched.
        public let wholeFilePlaintextSize: Int64

        /// - Parameter wholeFilePlaintextSize: Required, with no fallback: defaulting it to the
        ///   window length would publish a ranged window's length as the file's size.
        public init(item: Entry, plaintextWindow: PlaintextWindow, wholeFilePlaintextSize: Int64) {
            self.item = item
            self.plaintextWindow = plaintextWindow
            self.wholeFilePlaintextSize = wholeFilePlaintextSize
        }
    }

    /// A contiguous span of plaintext bytes: `[origin, origin + length)`.
    ///
    /// `Int64`-based (file offsets) rather than `NSRange`; convert with ``nsRange`` only at the
    /// File Provider boundary.
    public struct PlaintextWindow: Equatable, Sendable {
        /// Plaintext offset of the first byte.
        public let origin: Int64
        /// Byte count.
        public let length: Int64

        public init(origin: Int64, length: Int64) {
            self.origin = origin
            self.length = length
        }

        /// One past the last byte.
        public var end: Int64 { origin + length }

        /// The window as the `NSRange` a File Provider completion reports.
        public var nsRange: NSRange { NSRange(location: Int(origin), length: Int(length)) }
    }

    public struct DeleteItemParameter: JSONParameter {
        public typealias ReturnType = DeleteItemReturn
        public static let endpoint = "delete"
        public static let method = JSONMethod.DELETE
        public let itemIdentifier: ItemIdentifier
        public let existingRevision: Version
        public let recursiveDelete: Bool
        public init(itemIdentifier: ItemIdentifier, existingRevision: Version, recursiveDelete: Bool) {
            self.itemIdentifier = itemIdentifier
            self.existingRevision = existingRevision
            self.recursiveDelete = recursiveDelete
        }
    }
    public struct DeleteItemReturn: Codable {
        public init() { }
    }

    public struct TrashItemParameter: JSONParameter {
        public typealias ReturnType = TrashItemReturn
        public static let endpoint = "trash"
        public static let method = JSONMethod.POST
        public let itemIdentifier: ItemIdentifier
        public let existingRevision: Version
        /// `true` when the trashing is initiated out-of-band by the encrypt/decrypt bulk action
        /// (Graph DELETE) rather than by a framework move-to-trash. Out-of-band trashing leaves
        /// the framework without a recorded original parent, so it gets no native "Put Back";
        /// the backend persists this so the item qualifies for the custom Restore action.
        public let outOfBand: Bool

        public init(itemIdentifier: ItemIdentifier, existingRevision: Version, outOfBand: Bool = false) {
            self.itemIdentifier = itemIdentifier
            self.existingRevision = existingRevision
            self.outOfBand = outOfBand
        }
    }
    public struct TrashItemReturn: Codable {
        public let item: Entry
        public let metadataWasRolledBack: Bool

        public init(item: Entry, metadataWasRolledBack: Bool) {
            self.item = item
            self.metadataWasRolledBack = metadataWasRolledBack
        }
    }

    public struct RestoreItemParameter: Codable {
        public let itemIdentifier: ItemIdentifier
        public let existingRevision: Version
        /// Target parent; nil = restore to original parent (Graph default).
        public let targetParentIdentifier: ItemIdentifier?

        public init(itemIdentifier: ItemIdentifier, existingRevision: Version,
                    targetParentIdentifier: ItemIdentifier?) {
            self.itemIdentifier = itemIdentifier
            self.existingRevision = existingRevision
            self.targetParentIdentifier = targetParentIdentifier
        }
    }
    public struct RestoreItemReturn: Codable {
        public let item: Entry

        public init(item: Entry) { self.item = item }
    }

    public struct UpdateThumbnailParameter: JSONParameter {
        public typealias ReturnType = UpdateThumbnailReturn
        public static let endpoint = "updateThumbnail"
        public static let method = JSONMethod.POST
        public let identifier: ItemIdentifier
        public let existingRevision: Version

        public init(identifier: ItemIdentifier, existingRevision: Version) {
            self.identifier = identifier
            self.existingRevision = existingRevision
        }
    }

    public struct UpdateThumbnailReturn: Codable {
        public let item: Entry

        public init(item: Entry) {
            self.item = item
        }
    }

    public struct FetchThumbnailParameter: JSONParameter {
        public typealias ReturnType = FetchThumbnailReturn
        public static let endpoint = "thumbnail"
        public static let method = JSONMethod.POST
        public let identifier: ItemIdentifier
        public let requestedRevision: Version?

        public init(identifier: ItemIdentifier, requestedRevision: Version?) {
            self.identifier = identifier
            self.requestedRevision = requestedRevision
        }
    }

    public struct FetchThumbnailReturn: Codable {
        public let item: Entry

        public init(item: Entry) {
            self.item = item
        }
    }

    public struct ConflictVersionsParameter: JSONParameter {
        public typealias ReturnType = ConflictVersionsReturn
        public static let endpoint = "conflicts/list"
        public static let method = JSONMethod.POST
        public let identifier: ItemIdentifier

        public init(identifier: ItemIdentifier) {
            self.identifier = identifier
        }
    }
    public struct ConflictVersionsReturn: Codable {
        public let versions: [ConflictVersion]
        public let currentVersion: Version

        public init(versions: [ConflictVersion], currentVersion: Version) {
            self.versions = versions
            self.currentVersion = currentVersion
        }
    }

    public struct ResolveConflictVersionsParameter: JSONParameter {
        public typealias ReturnType = ResolveConflictVersionsReturn
        public static let endpoint = "conflicts/resolve"
        public static let method = JSONMethod.POST
        public let identifier: ItemIdentifier
        public let versionsToKeep: [Int64]
        public let baseVersion: Version

        public init(identifier: ItemIdentifier, versionsToKeep: [Int64], baseVersion: Version) {
            self.identifier = identifier
            self.versionsToKeep = versionsToKeep
            self.baseVersion = baseVersion
        }
    }
    public struct ResolveConflictVersionsReturn: Codable {
        public init() { }
    }

    public struct CreateConflictParameter: JSONParameter {
        public typealias ReturnType = CreateConflictReturn
        public static let endpoint = "conflicts/create"
        public static let method = JSONMethod.POST
        public let identifier: ItemIdentifier
        public let originator: String

        public init(identifier: ItemIdentifier, originator: String) {
            self.identifier = identifier
            self.originator = originator
        }
    }

    public struct CreateConflictReturn: Codable {
        public let entry: Entry

        public init(entry: Entry) {
            self.entry = entry
        }
    }

    public struct MarkParameter: JSONParameter {
        public typealias ReturnType = MarkReturn
        public static let endpoint = "mark"
        public static let method = JSONMethod.POST
        public static let heartXattr: String = {
            let base = "org.vaultsync.VaultSync.heart"
            return String(cString: xattr_name_with_flags(base, XATTR_FLAG_SYNCABLE | XATTR_FLAG_NO_EXPORT))
        }()
        public static let pinnedXattr: String = {
            // This sample stores the pinning state as an xattr and syncs across domains,
            // which is quite unrealistic.
            let base = "org.vaultsync.VaultSync.pinned"
            return String(cString: xattr_name_with_flags(base, XATTR_FLAG_SYNCABLE | XATTR_FLAG_NO_EXPORT))
        }()
        public static let isSharedXattr: String = {
            let base = "org.vaultsync.VaultSync.isShared"
            return String(cString: xattr_name_with_flags(base, XATTR_FLAG_SYNCABLE | XATTR_FLAG_NO_EXPORT))
        }()

        public let identifiers: [ItemIdentifier]
        public let heart: Bool?
        public let inUse: String?
        public let pinned: Bool?
        public let isShared: Bool?

        public init(identifiers: [ItemIdentifier], heart: Bool? = nil, inUse: String? = nil, pinned: Bool? = nil, isShared: Bool? = nil) {
            self.identifiers = identifiers
            self.heart = heart
            self.inUse = inUse
            self.pinned = pinned
            self.isShared = isShared
        }
    }

    public struct MarkReturn: Codable {
        public init() { }
    }

    public struct PingLockParameter: JSONParameter {
        public typealias ReturnType = PingLockReturn
        public static let endpoint = "lock/ping"
        public static let method = JSONMethod.POST

        // This sample unlocks the file automatically if the client doesn't respond
        // before the unlock interval expires.
        public static let unlockInterval = TimeInterval(30)
        // The interval for client pings.
        public static let pingInterval = unlockInterval * (2.0 / 3.0)

        public let identifier: ItemIdentifier
        public let owner: String
        public let enumerationIndex: Int64

        public init(identifier: ItemIdentifier, owner: String, enumerationIndex: Int64) {
            self.identifier = identifier
            self.owner = owner
            self.enumerationIndex = enumerationIndex
        }
    }
    public struct PingLockReturn: Codable {
        public init() { }
    }

    public struct RemoveLockParameter: JSONParameter {
        public typealias ReturnType = RemoveLockReturn
        public static let endpoint = "lock/remove"
        public static let method = JSONMethod.POST

        public let identifier: ItemIdentifier
        public let enumerationIndex: Int64

        public init(identifier: ItemIdentifier, enumerationIndex: Int64) {
            self.identifier = identifier
            self.enumerationIndex = enumerationIndex
        }
    }

    public struct RemoveLockReturn: Codable {
        public init() { }
    }

    public struct ForceLockParameter: JSONParameter {
        public typealias ReturnType = ForceLockReturn
        public static let endpoint = "lock/force"
        public static let method = JSONMethod.POST

        public let identifier: ItemIdentifier

        public init(identifier: ItemIdentifier) {
            self.identifier = identifier
        }
    }

    public struct ForceLockReturn: Codable {
        public init() { }
    }
}

extension DomainService {
    public struct PushRegistrationParameter: JSONParameter {
        public typealias ReturnType = PushRegistrationReturn
        public static let endpoint = "push/register"
        public static let method = JSONMethod.POST
        public static let refreshInterval = TimeInterval(60 * 60 * 6)

        public let token: Data
        public let bundleIdentifier: String

        public init(token: Data, bundleIdentifier: String) {
            self.token = token
            self.bundleIdentifier = bundleIdentifier
        }
    }
    public struct PushRegistrationReturn: Codable {
        public init() { }
    }

    public struct PushDevice: Hashable {
        public typealias Token = String
        public typealias PushTopic = String
        public let token: Token
        public let topic: PushTopic

        public init(token: Token, topic: PushTopic) {
            self.token = token
            self.topic = topic
        }
    }
}

extension DomainService {
    public struct SimulatedError: Codable {
        public enum AccessType: String, Codable {
            case read
            case write
        }

        public let domain: String
        public let code: Int
        public let localizedDescription: String?

        public init(domain: String, code: Int, localizedDescription: String?) {
            self.domain = domain
            self.code = code
            self.localizedDescription = localizedDescription
        }
    }

    public struct SimulateErrorParameter: JSONParameter {
        public typealias ReturnType = SimulateErrorReturn
        public static let endpoint = "error/debug/set"
        public static let method = JSONMethod.POST

        public let identifier: ItemIdentifier
        public let accessType: SimulatedError.AccessType
        public let error: SimulatedError?

        public init(identifier: ItemIdentifier, accessType: SimulatedError.AccessType, error: SimulatedError?) {
            self.identifier = identifier
            self.error = error
            self.accessType = accessType
        }
    }
    public struct SimulateErrorReturn: Codable {
        public init() { }
    }

    public struct SimulateErrorListParameter: JSONParameter {
        public typealias ReturnType = SimulateErrorListReturn
        public static let endpoint = "error/debug/list"
        public static let method = JSONMethod.POST

        public init() { }
    }
    public struct SimulateErrorListReturn: Codable {
        public let errors: [ItemIdentifier: [SimulatedError.AccessType: SimulatedError]]

        public init(errors: [ItemIdentifier: [SimulatedError.AccessType: SimulatedError]]) {
            self.errors = errors
        }
    }

    public struct ListLocksParameter: JSONParameter {
        public typealias ReturnType = ListLocksReturn
        public static let endpoint = "lock/debug/list"
        public static let method = JSONMethod.POST

        public init() { }
    }
    public struct ListLocksReturn: Codable {
        public struct Lock: Codable {
            public let itemIdentifier: ItemIdentifier
            public let enumerationIndex: Int64
            public let timeout: Date
            public let owner: String

            public init(itemIdentifier: ItemIdentifier, enumerationIndex: Int64, timeout: Date, owner: String) {
                self.itemIdentifier = itemIdentifier
                self.enumerationIndex = enumerationIndex
                self.timeout = timeout
                self.owner = owner
            }
        }
        public let locks: [Lock]

        public init(locks: [ListLocksReturn.Lock]) {
            self.locks = locks
        }
    }
}
