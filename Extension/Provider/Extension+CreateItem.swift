/// Item creation.
//
//  Abstract:
//  `NSFileProviderReplicatedExtension.createItem(basedOn:…)` — create with optional
//  BC01 encryption (streamed) and resource-fork/thumbnail follow-up.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common
import UniformTypeIdentifiers

extension Extension {
    public func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents url: URL?,
                           options: NSFileProviderCreateItemOptions = [], request: NSFileProviderRequest,
                           completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        logger.infoPublic("➡️  createItem(\(itemTemplate.filename)) parent(\(itemTemplate.parentItemIdentifier.rawValue)) fields(\(fields.rawValue)) contents(\(url != nil)) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        let progress = Progress(totalUnitCount: 100)
        Task {
            do {
                let (item, remainingFields, someBool) = try await self.createItemInternal(basedOn: itemTemplate,
                                                                                          fields: fields,
                                                                                          contents: url,
                                                                                          options: options,
                                                                                          request: request,
                                                                                          progress: progress)
                completionHandler(item, remainingFields, someBool, nil)
            } catch {
                completionHandler(nil, [], false, error.asFileProviderError)
            }
        }
        progress.cancellationHandler = { completionHandler(nil, [], false, NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }
        return progress
    }

    private func createItemInternal(basedOn itemTemplate: NSFileProviderItem,
                                    fields: NSFileProviderItemFields,
                                    contents url: URL?,
                                    options: NSFileProviderCreateItemOptions = [],
                                    request: NSFileProviderRequest,
                                    progress: Progress) async throws -> (NSFileProviderItem?, NSFileProviderItemFields, Bool) {
        try requireBackend()
        logger.debugPublic("➡️  createItemInternal() @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")

        let cryptoConfig = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)

        // Double-encrypt detection: refuse .bc/.bch files when BC01 is active.
        if cryptoConfig.algorithm == .bc01 {
            let lower = itemTemplate.filename.lowercased()
            if lower.hasSuffix(".bc") || lower.hasSuffix(".bch") {
                postDoubleEncryptNotification(filename: itemTemplate.filename)
                throw NSFileProviderError(.cannotSynchronize)
            }
        }

        let type: DomainService.EntryType
        let contentStorageType: DomainService.ContentStorageType?
        let fork: Data?
        /// Plaintext source for a non-folder item's contents: the provided URL, or a temp file
        /// holding a symlink's target. Every file-like item uploads through `createStreaming`.
        var sourceURL: URL?
        /// Temp file this call created (symlink target, or empty contents); removed on return.
        var tempSourceURL: URL?
        defer { if let tempSourceURL { try? FileManager.default.removeItem(at: tempSourceURL) } }
        /// Plaintext length of the content being created, when read from a file. See the
        /// matching local in `modifyItem`.
        var uploadPlaintextSize: Int64?
        let contentType = itemTemplate.contentType
        switch contentType {
        case .folder?:
            type = .folder
            contentStorageType = nil
            fork = nil
        case .symbolicLink?:
            type = .symlink
            if fields.contains(.contents),
                let targetPathOptional = itemTemplate.symlinkTargetPath,
                let targetPath = targetPathOptional {
                contentStorageType = .contents
                let targetURL = makeTemporaryURL("symlinkTarget")
                try targetPath.utf8Data.write(to: targetURL)
                tempSourceURL = targetURL
                sourceURL = targetURL
            } else {
                contentStorageType = nil
            }
            fork = nil
        case .aliasFile?:
            type = .alias
            if fields.contains(.contents), let url {
                contentStorageType = .contents
                sourceURL = url
            } else {
                contentStorageType = nil
            }
            fork = nil
        default:
            type = .file
            if fields.contains(.contents), let url {
                do {
                    let rsrcUrl = url.appendingPathComponent("..namedfork/rsrc")
                    fork = try Data(contentsOf: rsrcUrl, options: .alwaysMapped)
                } catch CocoaError.fileNoSuchFile, CocoaError.fileReadNoSuchFile {
                    fork = nil
                }
                contentStorageType = .contents
                sourceURL = url
                let plaintextSize = (try? FileManager.default
                    .attributesOfItem(atPath: url.path)[.size] as? NSNumber)??.intValue ?? 0
                uploadPlaintextSize = Int64(plaintextSize)
            } else {
                contentStorageType = nil
                fork = nil
            }
        }

        if options.contains(.mayAlreadyExist),
           type != .folder,
           type != .symlink,
           contentStorageType == nil {
            return (nil, [], false)
        }

        let parent = itemTemplate.parentItemIdentifier
        let backendName = BoxcryptorMetadataTranslator(algorithm: cryptoConfig.algorithm).encodeForBackend(itemTemplate.filename)
        let strategy: DomainService.CreateParameter.ConflictStrategy = options.contains(.mayAlreadyExist) ? .updateAlreadyExisting : .failOnExisting

        let param = DomainService.CreateParameter(parent: DomainService.ItemIdentifier(parent), name: backendName, type: type,
                             metadata: DomainService.EntryMetadata(itemTemplate, fields), conflict: strategy, contentStorageType: contentStorageType,
                             plaintextSize: uploadPlaintextSize)

        if type == .folder {
            return try await withCheckedThrowingContinuation { continuation in
                let callProgress = backend.createFolder(param) { result in
                    switch result {
                    case .failure(let error):
                        continuation.resume(throwing: error.toPresentableError())
                    case .success(let response):
                        continuation.resume(returning: (self.displayItem(response.item), [], false))
                    }
                }
                progress.addChild(callProgress, withPendingUnitCount: 100)
            }
        }

        // A file-like item created without contents uploads an empty body.
        if sourceURL == nil {
            let emptyURL = makeTemporaryURL("emptyContents")
            try Data().write(to: emptyURL)
            tempSourceURL = emptyURL
            sourceURL = emptyURL
        }
        guard let sourceURL else { throw CommonError.internalError }

        // Only regular files are encrypted; symlink targets and alias data pass through. A
        // configured-but-unavailable BC01 key throws `.notAuthenticated` here, failing the
        // create before any upload rather than sending plaintext to an encrypted domain.
        let encryptor: any FileEncryptor = type == .file ? try makeEncryptor() : PlainFileEncryptor()

        let uploadProgress = Progress(totalUnitCount: 100)
        progress.addChild(uploadProgress, withPendingUnitCount: fork != nil ? 90 : 100)
        let response: DomainService.CreateReturn
        do {
            response = try await backend.createStreaming(param,
                                                         contentsAt: sourceURL,
                                                         originalFilename: itemTemplate.filename,
                                                         encryptor: encryptor,
                                                         progress: uploadProgress)
        } catch {
            throw error.toPresentableError()
        }
        guard let url else {
            return (displayItem(response.item), [], false)
        }
        return try await uploadResourceFork(item: response.item,
                                            fork: fork,
                                            changedFields: [.contents],
                                            updateResourceForkOnConflictedItem: false,
                                            contentType: contentType,
                                            url: url,
                                            parentProgress: progress)
    }

    private func postDoubleEncryptNotification(filename: String) {
        let key = "org.vaultsync.VaultSync.doubleEncrypt.detected"
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(key as CFString),
            nil, nil, true)
        logger.errorPublic("⛔ Double-encrypt blocked: \(filename)")
    }
}
