/// NSFileProvider utility functions and conversions
//
//  Abstract:
//  Extensions on various objects for use throughout the project.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation
import FileProvider

public extension NSFileProviderDomainIdentifier {
    var port: in_port_t? {
        if let separatorPosition = rawValue.lastIndex(of: "+"),
            let port = in_port_t(rawValue[rawValue.index(after: separatorPosition)...]) {
            return port
        }
        return nil
    }
}

// Conversions to and from Int64 to use with the domain service version content.
extension Data {
    fileprivate init(_ revision: Int64) {
        self = Swift.withUnsafeBytes(of: revision) { Data($0) }
    }

    fileprivate func toInt64() -> Int64 {
        var ret: Int64 = 0
        _ = Swift.withUnsafeMutableBytes(of: &ret) { ptr in
            self.copyBytes(to: ptr)
        }
        return ret
    }
}

extension NSFileProviderItemVersion {
    public convenience init(_ version: DomainService.Version) {
        self.init(contentVersion: Data(version.content.utf8), metadataVersion: Data(version.metadata.utf8))
    }
}

extension NSFileProviderTypeAndCreator {
    public init(_ rawValue: UInt64) {
        let creator = UInt32(truncatingIfNeeded: rawValue)
        let type = UInt32(rawValue >> 32)
        self.init(type: type, creator: creator)
    }

    public func rawValue() -> UInt64 {
        var rawValue = UInt64(self.creator)
        rawValue |= UInt64(self.type) << 32
        return rawValue
    }
}

extension DomainService.Version {
    public init(_ version: NSFileProviderItemVersion) {
        let content = String(data: version.contentVersion, encoding: .utf8) ?? String(version.contentVersion.toInt64())
        let metadata = String(data: version.metadataVersion, encoding: .utf8) ?? String(version.metadataVersion.toInt64())
        self = DomainService.Version(content: content, metadata: metadata)
    }
}

extension DomainService.EntryMetadata {
    public init(_ itemTemplate: NSFileProviderItemProtocol, _ fields: NSFileProviderItemFields) {
        var valid: DomainService.EntryMetadata.ValidEntries = []
        if fields.contains(.lastUsedDate),
            let value = itemTemplate.lastUsedDate {
            self.lastUsedDate = value
            valid.insert(.lastUsedDate)
        } else {
            self.lastUsedDate = nil
        }

        if fields.contains(.fileSystemFlags),
            let value = itemTemplate.fileSystemFlags {
            self.fileSystemFlags = value
            valid.insert(.fileSystemFlags)
        } else {
            self.fileSystemFlags = nil
        }

        if fields.contains(.tagData),
            let value = itemTemplate.tagData {
            self.tagData = value
            valid.insert(.tagData)
        } else {
            self.tagData = nil
        }

        if fields.contains(.creationDate),
            let value = itemTemplate.creationDate {
            self.creationDate = value
            valid.insert(.creationDate)
        } else {
            self.creationDate = nil
        }

        if fields.contains(.contentModificationDate),
            let value = itemTemplate.contentModificationDate {
            self.contentModificationDate = value
            valid.insert(.contentModificationDate)
        } else {
            self.contentModificationDate = nil
        }

        if fields.contains(.extendedAttributes),
            let attrs = itemTemplate.extendedAttributes {
            self.extendedAttributes = ExtendedAttributes(values: attrs)
            valid.insert(.extendedAttributes)
        } else {
            self.extendedAttributes = nil
        }

        if fields.contains(.typeAndCreator),
            let osType = itemTemplate.typeAndCreator {
            self.typeAndCreator = osType.rawValue()
            valid.insert(.typeAndCreator)
        } else {
            self.typeAndCreator = nil
        }

        validEntries = valid
    }
}

extension CommonError {

    /// Translate to an error in a domain the File Provider accepts.
    ///
    /// `NSFileProviderManager` rejects any error outside `NSFileProviderErrorDomain` and
    /// `NSCocoaErrorDomain`, logging `__FILEPROVIDER_UNSUPPORTED_ERROR__` and substituting an
    /// opaque internal error — which hides the real cause from both Finder and the log. Every
    /// error crossing an `NSFileProviderReplicatedExtension` entry point must go through here.
    public var asFileProviderError: Error {
        switch self {
        case .authRequired, .tokenExpired:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.notAuthenticated.rawValue)
        case .itemNotFound:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.noSuchItem.rawValue)
        case .domainNotFound:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.providerNotFound.rawValue)
        case .insufficientQuota:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.insufficientQuota.rawValue)
        case .wrongRevision:
            // The associated entry is a placeholder at the point 412 is raised, so there is no
            // real colliding item to name. `cannotSynchronize` makes the OS refetch and retry,
            // which is exactly the recovery this needs.
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.cannotSynchronize.rawValue)
        case .itemExists:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.filenameCollision.rawValue)
        case .deletionRejected:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.deletionRejected.rawValue)
        case .timedOut:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.serverUnreachable.rawValue)
        case .httpError(let response):
            // Preserve the status code in the description so the log stays diagnosable even
            // though the domain has to change.
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteUnknownError,
                           userInfo: [NSLocalizedDescriptionKey: "HTTP \(status) from backend"])
        case .notImplemented:
            return NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError)
        case .parameterError:
            return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteInvalidFileNameError)
        case .internalError, .clientCrashingError, .accountExists, .simulatedError:
            return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteUnknownError,
                           userInfo: [NSLocalizedDescriptionKey: errorDescription ?? "\(self)"])
        }
    }
}

extension Error {

    /// The File-Provider-safe form of any error: ``CommonError`` is translated, errors already
    /// in an accepted domain pass through, anything else is wrapped.
    public var asFileProviderError: Error {
        if let common = self as? CommonError { return common.asFileProviderError }
        if self is CancellationError {
            return NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)
        }
        let ns = self as NSError
        switch ns.domain {
        case NSFileProviderErrorDomain, NSCocoaErrorDomain:
            return ns
        case NSURLErrorDomain where ns.code == NSURLErrorCancelled:
            return NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)
        case NSURLErrorDomain:
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.serverUnreachable.rawValue)
        default:
            return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteUnknownError,
                           userInfo: [NSLocalizedDescriptionKey: ns.localizedDescription])
        }
    }
}
