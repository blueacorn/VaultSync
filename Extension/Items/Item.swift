/// NSFileProviderItem wrapper for server responses
//
//  Abstract:
//  A file system item, such as a file or directory.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common
import CoreServices
import UniformTypeIdentifiers

protocol XAttrGettable: Codable {
    var includeAsExtendedAttribute: Bool { get }
}

extension String: XAttrGettable {
    var includeAsExtendedAttribute: Bool {
        return !isEmpty
    }

}

extension Bool: XAttrGettable {
    var includeAsExtendedAttribute: Bool {
        return self
    }
}

class Item: NSObject, NSFileProviderItemProtocol, NSFileProviderItemDecorating {
    let entry: DomainService.Entry

    let itemIdentifier: NSFileProviderItemIdentifier
    let parentItemIdentifier: NSFileProviderItemIdentifier
    let itemVersion: NSFileProviderItemVersion

    /// Whether the backing backend accepts move-to-trash; gates `.allowsTrashing` so Finder
    /// only offers "Move to Trash" when the bin is real. Defaults to `false`; the producers
    /// that have a backend (`displayItem`, the enumerators) pass the backend's capability.
    let supportsMoveToTrash: Bool

    /// Whether the backing backend item is BC01-encrypted (backend name ends in `.bc` while
    /// the domain's active algorithm is BC01). Derived by the producer (`displayItem`) from the
    /// *raw backend name* before decode, since `entry.name` here is already the display name.
    /// Drives the green-padlock decoration and the encrypt/decrypt action predicates.
    let isEncrypted: Bool

    init(_ entry: DomainService.Entry, supportsMoveToTrash: Bool = false, isEncrypted: Bool = false) {
        self.entry = entry
        self.supportsMoveToTrash = supportsMoveToTrash
        self.isEncrypted = isEncrypted
        itemIdentifier = NSFileProviderItemIdentifier(entry.id)
        parentItemIdentifier = NSFileProviderItemIdentifier(entry.parent)
        itemVersion = NSFileProviderItemVersion(entry.revision)
    }

    var filename: String {
        return entry.name
    }
    var contentType: UTType {
        switch entry.type {
        case .folder, .root:
            return .folder
        case .file:
            return .item
        case .symlink:
            return .symbolicLink
        case .alias:
            return .aliasFile
        }
    }
    var typeAndCreator: NSFileProviderTypeAndCreator {
        if let typeAndCreator = entry.metadata.typeAndCreator {
            return NSFileProviderTypeAndCreator(typeAndCreator)
        } else {
            return NSFileProviderTypeAndCreator(type: 0, creator: 0)
        }
    }

    var capabilities: NSFileProviderItemCapabilities {
#if os(macOS)
        var result: NSFileProviderItemCapabilities = [
            .allowsAddingSubItems,
            .allowsContentEnumerating,
            .allowsDeleting,
            .allowsReading,
            .allowsRenaming,
            .allowsReparenting,
            .allowsWriting,
            .allowsExcludingFromSync
        ]
#else
        var result: NSFileProviderItemCapabilities = [
            .allowsAddingSubItems,
            .allowsContentEnumerating,
            .allowsDeleting,
            .allowsReading,
            .allowsRenaming,
            .allowsReparenting,
            .allowsWriting,
            .allowsEvicting
        ]
#endif
        if supportsMoveToTrash {
            result.insert(.allowsTrashing)
        }
        return result
    }

#if os(macOS)
    var contentPolicy: NSFileProviderContentPolicy {
        if let isPinned = self.userInfo?["pinned"] as? Bool, isPinned {
            return .downloadEagerlyAndKeepDownloaded
        }
        return .inherited
    }
#endif

    var documentSize: NSNumber? {
        return entry.size as NSNumber
    }

    var childItemCount: NSNumber? {
        return entry.children as NSNumber?
    }

    var lastUsedDate: Date? {
        return entry.metadata.lastUsedDate
    }

    var tagData: Data? {
        return entry.metadata.tagData
    }

    var creationDate: Date? {
        return entry.metadata.creationDate
    }

    var contentModificationDate: Date? {
        return entry.metadata.contentModificationDate
    }

    var extendedAttributes: [String: Data] {
        return entry.metadata.extendedAttributes?.values ?? [:]
    }

    static let decorationPrefix = Bundle.main.bundleIdentifier!
    static let conflictDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).hasConflict")
    static let lastEditDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).lastEdited")
    static let heartDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).heart")
    static let inUseDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).inUse")
    static let pictureFolder = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).pictureFolder")
    static let pinnedDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).pinned")
    static let encryptedDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).encrypted")
    static let fileErrorDecoration = NSFileProviderItemDecorationIdentifier(rawValue: "\(decorationPrefix).fileError")

    // This property demonstrates two ways of determining decorations: by an entry's
    // userInfo and by the presence of an extended attribute.
    var decorations: [NSFileProviderItemDecorationIdentifier]?
    {
        var decos = [NSFileProviderItemDecorationIdentifier]()

        // Set these attributes depending on keys in the entry's userInfo.
        if let conflictCount = entry.userInfo.conflictCount,
            conflictCount > 0 {
            decos.append(Item.conflictDecoration)
        }
        if entry.userInfo.originatorName != nil {
            decos.append(Item.lastEditDecoration)
        }
        if entry.userInfo.implicitLockOwner != nil {
            decos.append(Item.inUseDecoration)
        }

        // Set this attribute depending on whether a specific extended attribute is present.
        func addDecoForXattr<T: XAttrGettable>(_ deco: NSFileProviderItemDecorationIdentifier, _ type: T.Type, _ xattr: String) {
            if let fav = entry.metadata.extendedAttributes?.values[xattr] {
                if let val = try? JSONDecoder().decode(type, from: fav) {
                    if val.includeAsExtendedAttribute {
                        decos.append(deco)
                    }
                }
            }
        }
        addDecoForXattr(Item.heartDecoration, Bool.self, DomainService.MarkParameter.heartXattr)
        addDecoForXattr(Item.pinnedDecoration, Bool.self, DomainService.MarkParameter.pinnedXattr)

        if entry.userInfo.contentError == true {
            decos.append(Item.fileErrorDecoration)
        } else if isEncrypted {
            decos.append(Item.encryptedDecoration)
        }

        let pictureFolderNames = ["Images", "Pictures", "Photos"]
        if entry.type == .folder,
            pictureFolderNames.contains(entry.name) {
            decos.append(Item.pictureFolder)
        }

        return decos
    }

    public static let injectUserInfoXattr: String = {
        let base = "org.vaultsync.VaultSync.injectUserInfo"
        return String(cString: xattr_name_with_flags(base, XATTR_FLAG_SYNCABLE | XATTR_FLAG_NO_EXPORT))
    }()

    var userInfo: [AnyHashable: Any]? {
        var ret = [AnyHashable: Any]()
        // Expose keys in the entry's userInfo as part of the item. The extensions use them
        // to determine eligibility of actions for interaction predicates and
        // as input for decoration descriptions.
        if let val = entry.userInfo.conflictCount {
            ret["conflictCount"] = val
        }
        if let val = entry.userInfo.originatorName {
            ret["originatorName"] = val
        }
        if let val = entry.userInfo.implicitLockOwner {
            ret["inUse"] = val
        }
        if entry.userInfo.contentError == true {
            ret["contentError"] = true
        }
        // Out-of-band trashed item (no native "Put Back"): gates the custom Restore action's
        // interaction predicate (`$item.userInfo.restorable == YES`).
        if entry.userInfo.restorable == true {
            ret["restorable"] = true
        }
        // Any recycle-bin item: gates out the encrypt/decrypt actions in Trash
        // (`$item.userInfo.trashed != YES`), since OneDrive rejects mutating trashed items.
        if entry.userInfo.trashed == true {
            ret["trashed"] = true
        }
        if let val = entry.userInfo.quotaRemaining {
            ret["quotaRemaining"] = val
        }
        if let val = entry.userInfo.quotaTotal {
            ret["quotaTotal"] = val
        }

        // This key isn't part of the item's userInfo, but depends on an
        // extended attribute. This sample uses it to determine an action eligibility,
        // so needs to explicitly add it to the item's userInfo.
        func setInfoIfXattr<T: XAttrGettable>(_ info: String, _ type: T.Type, _ xattr: String) {
            if let fav = entry.metadata.extendedAttributes?.values[xattr],
                let val = try? JSONDecoder().decode(type, from: fav),
                val.includeAsExtendedAttribute {
                ret[info] = val
            }
        }
        // Per-item encryption state, surfaced for the encrypt/decrypt action predicates.
        // A recorded content error takes precedence: such an item reports as not encrypted so
        // the `fileError` badge is authoritative everywhere (including the Trash detail view,
        // where the system may consult userInfo rather than re-derive decorations) and the
        // encrypt/decrypt actions never treat a failed item as a clean encrypted target.
        ret["encrypted"] = (entry.userInfo.contentError == true) ? false : isEncrypted
        setInfoIfXattr("heart", Bool.self, DomainService.MarkParameter.heartXattr)
        setInfoIfXattr("pinned", Bool.self, DomainService.MarkParameter.pinnedXattr)
        setInfoIfXattr("isShared.inherited", Bool.self, DomainService.MarkParameter.isSharedXattr)

        // Read injectUserInfoXattr as a dictionary, and then find and add the entries,
        // such as `xattr -w com.example.vaultsync.injectUserInfo#PS "{
        // \"arbitrary\": \"value\" }" file.txt.`
        if let fav = entry.metadata.extendedAttributes?.values[Self.injectUserInfoXattr],
           let values = try? JSONSerialization.jsonObject(with: fav, options: []) as? [String: Any] {
            values.forEach { (key: String, value: Any) in
                if value is NSNumber || value is String {
                    ret[key] = value
                }
            }
        }
        return ret
    }

    var symlinkTargetPath: String? {
        return entry.userInfo.symlinkTargetPath
    }

    var fileSystemFlags: NSFileProviderFileSystemFlags {
        return entry.metadata.fileSystemFlags ?? []
    }
}

extension NSFileProviderItemIdentifier {
    public init(_ id: DomainService.ItemIdentifier) {
        // The system root/trash containers map to the universal sentinels. Backends
        // translate those to their native ids at their own wire edge — this bridge
        // holds no backend-specific knowledge.
        switch id {
        case .root:  self = .rootContainer
        case .trash: self = .trashContainer
        default:     self.init(id.id)
        }
    }
}

extension DomainService.ItemIdentifier {
    public init(_ id: NSFileProviderItemIdentifier) {
        switch id {
        case .rootContainer:  self = .root
        case .trashContainer: self = .trash
        default:
            // Opaque pass-through: emulator stringified Int64s, OneDrive Graph ids.
            self = DomainService.ItemIdentifier(id.rawValue)
        }
    }
}
