/// Domain management backend logic with storage location support
//
//  Abstract:
//  Domain-specific implementations of the cloud file server APIs.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation
import os.log
import FileProvider
import Common

public class DomainBackend: NSObject, DispatchBackend {
    let db: ItemDatabase
    let defaults = UserDefaults.sharedContainerDefaults
    public let encoder = JSONEncoder()
    public let decoder = JSONDecoder()
    let identifier: String
    var account: DBAccount
    public let displayName: String
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "server")
    let rootItemIdentifier: DomainService.ItemIdentifier
    let trashItemIdentifier: DomainService.ItemIdentifier
    public let queue: DispatchQueue

    static let trashItemName = ".Trash"

    var lockExpiryTimerSource: DispatchSourceTimer? = nil

    public init(identifier: String,
                database: ItemDatabase) throws {
        db = database
        account = try db.account(for: identifier)
        self.displayName = SharedConfigStore.shared.account(for: NSFileProviderDomainIdentifier(rawValue: identifier))?.displayName ?? identifier
        queue = DispatchQueue(label: "backend for \(displayName)")
        self.identifier = identifier
        let root = account.rootItem
        rootItemIdentifier = root.id

        if let trashId = try database.fetchItem(parent: root.id, DomainBackend.trashItemName)?.id {
            trashItemIdentifier = trashId
        } else {
            let (trashId, _) = try database.createFile(parent: root.id, DomainBackend.trashItemName, .folder, .emptyFolder, conflictStrategy: .reject)
            trashItemIdentifier = trashId
        }

        encoder.keyEncodingStrategy = .convertToSnakeCase
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        encoder.userInfo[DomainService.rootItemCodingInfoKey] = rootItemIdentifier
        decoder.userInfo[DomainService.rootItemCodingInfoKey] = rootItemIdentifier
        encoder.userInfo[DomainService.trashItemCodingInfoKey] = trashItemIdentifier
        decoder.userInfo[DomainService.trashItemCodingInfoKey] = trashItemIdentifier
        super.init()
        armLockExpiryTimer()
    }

    public func checkForDomainApproval(_ headers: [String: String], _ path: String) throws {
        guard !self.defaults.ignoreAuthentication else { return }
        let expected = self.defaults.secret(for: NSFileProviderDomainIdentifier(rawValue: identifier))
        if headers["x-authorization"] != expected {
            logger.error("⛔️ \(self.displayName)\(path): missing authorization")
            throw CommonError.authRequired
        }
    }

    public static func registerCalls(_ dispatch: BackendCallRegistration) {
        dispatch.registerBackendCall(DomainBackend.listFolder)
        dispatch.registerBackendCall(DomainBackend.create)
        dispatch.registerBackendCall(DomainBackend.modifyContents)
        dispatch.registerBackendCall(DomainBackend.fetchItem)
        dispatch.registerBackendCall(DomainBackend.latestRank)
        dispatch.registerBackendCall(DomainBackend.delete)
        dispatch.registerBackendCall(DomainBackend.downloadItem)
        dispatch.registerBackendCall(DomainBackend.modifyMetadata)
        dispatch.registerBackendCall(DomainBackend.fetchThumbnail)
        dispatch.registerBackendCall(DomainBackend.updateThumbnail)
        dispatch.registerBackendCall(DomainBackend.listChanges)
        dispatch.registerBackendCall(DomainBackend.mark)
        dispatch.registerBackendCall(DomainBackend.trash)
        dispatch.registerBackendCall(DomainBackend.conflictVersions)
        dispatch.registerBackendCall(DomainBackend.resolveConflicts)
        dispatch.registerBackendCall(DomainBackend.createConflict)
        dispatch.registerBackendCall(DomainBackend.pingLock)
        dispatch.registerBackendCall(DomainBackend.removeLock)
        dispatch.registerBackendCall(DomainBackend.forceLock)
        dispatch.registerBackendCall(DomainBackend.registerPush)
        dispatch.registerBackendCall(DomainBackend.setSimulateError)
        dispatch.registerBackendCall(DomainBackend.listSimulatedError)
        dispatch.registerBackendCall(DomainBackend.listLocks)
    }

    func armLockExpiryTimer() {
        if let oldSource = lockExpiryTimerSource {
            oldSource.cancel()
        }
        do {
            if let lockExpiry = try db.expireLocks() {
                let timeInterval = lockExpiry.timeIntervalSinceNow
                logger.debug("⏰ next lock expiry is in \(timeInterval)s for \(self.displayName)")
                let newSource = DispatchSource.makeTimerSource(flags: [], queue: queue)
                newSource.setEventHandler { [weak self] in
                    self?.armLockExpiryTimer()
                }
                newSource.schedule(deadline: DispatchTime.now().advanced(by: .milliseconds(Int(timeInterval * 1000.0))))
                newSource.resume()
                lockExpiryTimerSource = newSource
            } else {
                logger.debug("⏰ all locks are expired for \(self.displayName)")
                lockExpiryTimerSource = nil
            }
        } catch let error {
            fatalError("error expiring lock: \(error)")
        }

    }
}

protocol XAttrSettable: Codable {
    var includeAsExtendedAttribute: Bool { get }
}

extension String: XAttrSettable {
    var includeAsExtendedAttribute: Bool {
        return !isEmpty
    }

}

extension Bool: XAttrSettable {
    var includeAsExtendedAttribute: Bool {
        return self
    }
}

extension DomainBackend {
    func listFolder(_ param: DomainService.ListFolderParameter) throws -> DomainService.ListFolderReturn {
        // The emulator pages by keyset on `rowid`; its cursor token is that rowid in decimal.
        let startRowID = param.startingCursor.flatMap { Int64($0.rawValue) } ?? 0
        let ret = try db.listFiles(parent: param.folderIdentifier, cursor: startRowID, recursive: param.recursive)
        let rank = DomainService.RankToken(rank: db.latestRank(), tokenCheckNumber: account.tokenCheckNumber)

        let files = ret.entries
        let deleted = files.compactMap { $0.deleted ? $0.id : nil }
        return DomainService.ListFolderReturn(entries: files.filter { !$0.deleted }, deletedEntries: deleted,
                                              cursor: ret.cursor.map { DomainService.PageCursor(String($0)) }, rank: rank)
    }

    func listChanges(_ param: DomainService.ListChangesParameter) throws -> DomainService.ListChangesReturn {
        guard param.startingRank.tokenCheckNumber == account.tokenCheckNumber else { throw CommonError.tokenExpired }
        let ret = try db.listChanges(parent: param.folderIdentifier, rank: param.startingRank.rank, recursive: param.recursive)

        let files = ret.entries
        let deleted = files.compactMap { $0.deleted ? $0.id : nil }
        let rank = DomainService.RankToken(rank: ret.rank, tokenCheckNumber: account.tokenCheckNumber)
        return DomainService.ListChangesReturn(entries: files.filter { !$0.deleted }, deletedEntries: deleted, rank: rank, hasMore: ret.moreComing)
    }

    func latestRank(_ param: DomainService.LatestRankParameter) throws -> DomainService.LatestRankReturn {
        return DomainService.LatestRankReturn(rank: DomainService.RankToken(rank: db.latestRank(), tokenCheckNumber: account.tokenCheckNumber))
    }

    // Pass the content storage type in the HTTP call, and convert it to a content
    // storage type parameter to avoid the need to serialize and deserialize
    // the buffer in the JSON payload.
    private func convertStorageTypeToParameter(
        contentStorageType: DomainService.ContentStorageType?, data: Data) throws -> Data? {
        switch contentStorageType {
        case .contents?, .resourceFork?:
            return data
        case nil:
            return nil
        }
    }

    func create(_ param: DomainService.CreateParameter, _ data: Data) throws -> DomainService.CreateReturn {
        let contentStorageTypeParameter = try convertStorageTypeToParameter(contentStorageType: param.contentStorageType, data: data)
        let itemIdentifier: DomainService.ItemIdentifier
        let version: DomainService.Version
        do {
            (itemIdentifier, version) = try db.createFile(parent: param.parent, param.name, param.type, conflictStrategy: .reject)
        } catch CommonError.itemExists(let entry) {
            if param.type != entry.type ||
                param.conflictStrategy == .failOnExisting {
                throw CommonError.itemExists(entry)
            }
            if param.conflictStrategy == .updateAlreadyExisting {
                itemIdentifier = entry.id
                version = entry.revision
            } else {
                let strategy: ItemDatabase.ConflictResolutionStrategy
                let contentLength = Int64(contentStorageTypeParameter?.count ?? 0)
                if entry.size == contentLength {
                    strategy = .merge
                } else {
                    strategy = try db.conflictStrategy(for: entry, param.type, .create)
                }
                (itemIdentifier, version) = try db.createFile(parent: param.parent, param.name, param.type, conflictStrategy: strategy)
            }
        }
        let file: DomainService.Entry
        do {
            if param.type == .folder || param.type == .root {
                file = try db.updateFile(identifier: itemIdentifier, revision: version, metadata: param.metadata)
            } else {
                // If the caller doesn’t pass a contentStorageTypeParameter,
                // there’s nothing to persist in the data side. This can occur,
                // for example, when the system calls createItem without .contents in
                // the fields parameter.
                if let contentStorageTypeParameter = contentStorageTypeParameter {
                    let temp = try db.updateFile(identifier: itemIdentifier, revision: version,
                                                 contentStorageTypeParameter: contentStorageTypeParameter,
                                                 originatorName: displayName, domainIdentifier: self.identifier)
                    file = try db.updateFile(identifier: itemIdentifier, revision: temp.revision, metadata: param.metadata)
                } else {
                    file = try db.updateFile(identifier: itemIdentifier, revision: version, metadata: param.metadata)
                }
            }
            return DomainService.CreateReturn(item: file)
        } catch let error {
            // If creating the file’s content fails, delete the file entry
            // in the database.
            try db.delete(item: itemIdentifier, revision: version, recursive: true)
            throw error
        }
    }

    func modifyContents(_ param: DomainService.ModifyContentsParameter, _ data: Data) throws -> DomainService.ModifyContentsReturn {
        let contentStorageTypeParameterOptional = try convertStorageTypeToParameter(contentStorageType: param.contentStorageType, data: data)
        guard let contentStorageTypeParameter: Data = contentStorageTypeParameterOptional else {
            self.logger.error("Expected non-nil content storage type when modifying contents")
            throw CommonError.internalError
        }
        do {
            let file = try db.updateFile(identifier: param.identifier, revision: param.existingRevision,
                                         contentStorageTypeParameter: contentStorageTypeParameter,
                                         originatorName: displayName, domainIdentifier: self.identifier,
                                         conflict: param.updateResourceForkOnConflictedItem,
                                         isResourceFork: param.contentStorageType == .resourceFork)
            return DomainService.ModifyContentsReturn(item: file, contentAccepted: true)
        } catch CommonError.wrongRevision(let entry) {
            if param.contentStorageType != .resourceFork {
                let conflict = try db.updateFile(identifier: param.identifier, revision: entry.revision,
                                                 contentStorageTypeParameter: contentStorageTypeParameter,
                                                 originatorName: displayName, domainIdentifier: self.identifier, conflict: true)
                return DomainService.ModifyContentsReturn(item: conflict, contentAccepted: false)
            } else {
                throw CommonError.wrongRevision(entry)
            }
        }
    }

    func modifyMetadata(_ param: DomainService.ModifyMetadataParameter) throws -> DomainService.ModifyMetadataReturn {
        do {
            let entry = try db.updateFile(identifier: param.itemIdentifier, revision: param.existingRevision, metadata: param.metadata,
                                          parent: param.parent, itemName: param.filename)
            return DomainService.ModifyMetadataReturn(item: entry, metadataWasRolledBack: false)
        } catch CommonError.wrongRevision(let entry) {
            return DomainService.ModifyMetadataReturn(item: entry, metadataWasRolledBack: true)
        }
    }

    func fetchItem(_ param: DomainService.FetchItemParameter) throws -> DomainService.FetchItemReturn {
        return DomainService.FetchItemReturn(item: try db.fetchItem(param.itemIdentifier))
    }

    func downloadItem(_ param: DomainService.DownloadItemParameter) throws -> (DomainService.DownloadItemReturn, Data) {
        let item = try db.fetchItem(param.itemIdentifier)
        if let version = param.requestedRevision {
            guard item.revision.content == version.content else {
                throw CommonError.wrongRevision(item)
            }
        }

        let data: Data
        if param.resourceFork != true {
            data = try db.fetchItemContents(identifier: item.id, contentRevision: item.revision.contentInt64, range: param.range)
        } else {
            data = try db.fetchItemResourceFork(identifier: item.id, contentRevision: item.revision.contentInt64)
        }
        return (DomainService.DownloadItemReturn(item: item), data)
    }

    func delete(_ param: DomainService.DeleteItemParameter) throws -> DomainService.DeleteItemReturn {
        try db.delete(item: param.itemIdentifier, revision: param.existingRevision, recursive: param.recursiveDelete)

        return DomainService.DeleteItemReturn()
    }

    func trash(_ param: DomainService.TrashItemParameter) throws -> DomainService.TrashItemReturn {
        do {
            let entry = try db.updateFile(identifier: param.itemIdentifier, revision: param.existingRevision, parent: trashItemIdentifier)
            return DomainService.TrashItemReturn(item: entry, metadataWasRolledBack: false)
        } catch CommonError.wrongRevision(let entry) {
            return DomainService.TrashItemReturn(item: entry, metadataWasRolledBack: true)
        }
    }

    func updateThumbnail(_ param: DomainService.UpdateThumbnailParameter, _ data: Data) throws -> DomainService.UpdateThumbnailReturn {
        let file = try db.updateFile(identifier: param.identifier, revision: param.existingRevision, thumbnail: data)
        return DomainService.UpdateThumbnailReturn(item: file)
    }

    func fetchThumbnail(_ param: DomainService.FetchThumbnailParameter) throws -> (DomainService.FetchThumbnailReturn, Data) {
        let item = try db.fetchItem(param.identifier)
        if let version = param.requestedRevision {
            guard item.revision == version else {
                throw CommonError.wrongRevision(item)
            }
        }
        let thumbnail = try db.fetchThumbnail(param.identifier)
        return (DomainService.FetchThumbnailReturn(item: item), thumbnail)
    }

    func conflictVersions(_ param: DomainService.ConflictVersionsParameter) throws -> DomainService.ConflictVersionsReturn {
        let versions = try db.conflictVersions(item: param.identifier)
        let item = try db.fetchItem(param.identifier)
        return DomainService.ConflictVersionsReturn(versions: versions, currentVersion: item.revision)
    }

    func resolveConflicts(_ param: DomainService.ResolveConflictVersionsParameter) throws -> DomainService.ResolveConflictVersionsReturn {
        try db.keep(versions: param.versionsToKeep, of: param.identifier, baseVersion: param.baseVersion)
        return DomainService.ResolveConflictVersionsReturn()
    }

    func createConflict(_ param: DomainService.CreateConflictParameter) throws -> DomainService.CreateConflictReturn {
        let item = try db.fetchItem(param.identifier)
        let contentStorageTypeParameter = try db.fetchItemContents(identifier: item.id,
                                                                   contentRevision: item.revision.contentInt64)
        let entry = try db.updateFile(identifier: param.identifier, revision: item.revision, contentStorageTypeParameter: contentStorageTypeParameter,
                                      originatorName: param.originator, domainIdentifier: self.identifier, conflict: true)

        return DomainService.CreateConflictReturn(entry: entry)
    }

    func mark(_ param: DomainService.MarkParameter) throws -> DomainService.MarkReturn {
        for id in param.identifiers {
            let old = try db.fetchItem(id)
            var xattr: [String: Data] = old.metadata.extendedAttributes?.values ?? [String: Data]()
            func updateXattr<T: XAttrSettable>(_ value: T?, attrName: String) throws {
                if let value = value {
                    if value.includeAsExtendedAttribute {
                        xattr[attrName] = try JSONEncoder().encode(value)
                    } else {
                        xattr.removeValue(forKey: attrName)
                    }
                }
            }
            try updateXattr(param.heart, attrName: DomainService.MarkParameter.heartXattr)
            try updateXattr(param.pinned, attrName: DomainService.MarkParameter.pinnedXattr)
            try updateXattr(param.isShared, attrName: DomainService.MarkParameter.isSharedXattr)

            let updateMeta: DomainService.EntryMetadata
            if !xattr.isEmpty {
                updateMeta = DomainService.EntryMetadata(fileSystemFlags: nil, lastUsedDate: nil, tagData: nil, favoriteRank: nil, creationDate: nil,
                                                         contentModificationDate: nil,
                                                         extendedAttributes: DomainService.EntryMetadata.ExtendedAttributes(values: xattr),
                                                         typeAndCreator: nil, validEntries: [.extendedAttributes])
            } else {
                updateMeta = DomainService.EntryMetadata(fileSystemFlags: nil, lastUsedDate: nil, tagData: nil, favoriteRank: nil, creationDate: nil,
                                                         contentModificationDate: nil, extendedAttributes: nil, typeAndCreator: nil,
                                                         validEntries: [.extendedAttributes])
            }
            let meta = old.metadata.merge(updateMeta)

            _ = try db.updateFile(identifier: id, revision: old.revision, metadata: meta)
        }
        return DomainService.MarkReturn()
    }

    func pingLock(_ param: DomainService.PingLockParameter) throws -> DomainService.PingLockReturn {
        try db.updateLock(for: param.identifier, Date(timeIntervalSinceNow: DomainService.PingLockParameter.unlockInterval), param.enumerationIndex,
                          owner: param.owner)
        armLockExpiryTimer()
        return DomainService.PingLockReturn()
    }

    func removeLock(_ param: DomainService.RemoveLockParameter) throws -> DomainService.RemoveLockReturn {
        try db.removeLock(for: param.identifier, param.enumerationIndex)
        return DomainService.RemoveLockReturn()
    }

    func forceLock(_ param: DomainService.ForceLockParameter) throws -> DomainService.ForceLockReturn {
        try db.removeLock(for: param.identifier, nil)
        return DomainService.ForceLockReturn()
    }
}

extension DomainBackend {
    func registerPush(_ param: DomainService.PushRegistrationParameter) throws -> DomainService.PushRegistrationReturn {
        let deviceToken = "\(param.token.map({ String(format: "%02hhx", $0) }).joined() )"

        let providerSuffix = ".Provider"
        let bundleId = param.bundleIdentifier
        guard bundleId.hasSuffix(providerSuffix) else {
            // Only accept registration from the provider.
            throw CommonError.parameterError
        }
        let topic = bundleId.prefix(bundleId.count - providerSuffix.count).appending(".pushkit.fileprovider")

        try db.refreshPushToken(deviceToken, topic)
        logger.info("registered push token \(deviceToken) for topic \(topic)")

        return DomainService.PushRegistrationReturn()
    }

    public var registeredDevices: [DomainService.PushDevice] {
        (try? db.allPushTokens()) ?? [DomainService.PushDevice]()
    }
}

extension DomainBackend {
    func setSimulateError(_ param: DomainService.SimulateErrorParameter) throws -> DomainService.SimulateErrorReturn {
        try db.setSimulatedError(param.identifier, param.error, param.accessType)
        return DomainService.SimulateErrorReturn()
    }

    func listSimulatedError(_ param: DomainService.SimulateErrorListParameter) throws -> DomainService.SimulateErrorListReturn {
        return DomainService.SimulateErrorListReturn(errors: try db.simulatedErrors())
    }

    func listLocks(_ param: DomainService.ListLocksParameter) throws -> DomainService.ListLocksReturn {
        return DomainService.ListLocksReturn(locks: try db.allLocks())
    }
}
