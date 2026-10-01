/// Query and fetch operations on item database
//
//  Abstract:
//  The database extension for fetching items on the cloud file server.
//
//  Copyright (c) 2024 Apple Inc.
//  SPDX-License-Identifier: MIT
//

import Foundation
import SQLite
import os.log
import Common

extension ItemDatabase {
    func fetchItem(_ identifier: ItemIdentifier) throws -> Entry {
        try checkSimulatedError(for: identifier, .read)
        guard let row = try conn.pluck(itemsTable.filter(identifier == idKey && deletedKey == false && contentStorageTypeKey != .resourceFork)) else {
            throw CommonError.itemNotFound(identifier)
        }
        return Entry(row, self)
    }

    func fetchItem(parent: ItemIdentifier, _ name: String) throws -> Entry? {
        guard let row = try conn.pluck(itemsTable.filter(parentKey == parent && deletedKey == false &&
                                                         nameKey == name && contentStorageTypeKey != .resourceFork)) else { return nil }
        return Entry(row, self)
    }

    func contentsFromRow(_ contentsRow: ExpressionSubscriptable, externalIdentifier: Int64? = nil, range: NSRange? = nil) throws -> Data {
        switch contentsRow[contentStorageTypeKey] {
        case .contents, .resourceFork:
            let retData: Data
            let effectiveContentLocation = resolvedContentLocation(for: contentsRow[contentDomainKey])
            if let contentLocation = effectiveContentLocation {
                retData = try Data(contentsOf: contentLocation.appendingPathComponent("\(contentsRow[externalIdentifierKey])"))
            } else {
                retData = contentsRow[contentsKey]
            }

            //If the requestedRange length is -1, return the entire data set.
            if let requestedRange = range, requestedRange.length != -1 {
                let start = requestedRange.location
                let end = start + requestedRange.length
                return retData.subdata(in: start..<end)
            }

            return retData
        }
    }

    func fetchItemContents(identifier: ItemIdentifier, contentRevision: Int64, range: NSRange? = nil) throws -> Data {
        guard let contentsRow = try conn.pluck(contentsTable.filter(identifier == idKey && contentRevision == contentRevKey &&
                                                                    .resourceFork != contentStorageTypeKey)) else {
            logger.fault("Could not find data for contentRevKey, identifier == \(identifier), revision == \(contentRevision), contentStorageTypeKey != .resourceFork")
            throw CommonError.internalError
        }
        return try contentsFromRow(contentsRow, range: range)
    }

    func hasResourceFork(identifier: ItemIdentifier) throws -> Bool {
        guard let itemRow = try conn.pluck(itemsTable.filter(identifier == idKey && deletedKey == false)) else {
            logger.fault("Could not find undeleted item for identifier == \(identifier)")
            throw CommonError.internalError
        }
        return itemRow[resourceForkKey]
    }

    // Returns the item's resource fork, if present. Otherwise, it returns an
    // empty data object.
    func fetchItemResourceFork(identifier: ItemIdentifier, contentRevision: Int64) throws -> Data {
        if try !hasResourceFork(identifier: identifier) {
            return Data()
        }

        guard let contentsRow = try conn.pluck(contentsTable.filter(identifier == idKey && contentRevision == contentRevKey &&
                                                                    .resourceFork == contentStorageTypeKey)) else {
            logger.fault("Could not find data for contentRevKey, identifier == \(identifier), revision == \(contentRevision), contentStorageTypeKey != .resourceFork")
            throw CommonError.internalError
        }
        return try contentsFromRow(contentsRow)
    }

    func fetchThumbnail(_ identifier: ItemIdentifier) throws -> Data {
        guard let row = try conn.pluck(itemsTable.filter(identifier == idKey && deletedKey == false)) else {
            throw CommonError.itemNotFound(identifier)
        }
        return row[thumbnailKey]
    }
}
