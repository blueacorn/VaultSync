/// Item deletion.
//
//  Abstract:
//  `NSFileProviderReplicatedExtension.deleteItem(identifier:baseVersion:…)`.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common

extension Extension {
    public func deleteItem(identifier itemIdentifier: NSFileProviderItemIdentifier, baseVersion version: NSFileProviderItemVersion,
                           options: NSFileProviderDeleteItemOptions = [], request: NSFileProviderRequest,
                           completionHandler: @escaping (Error?) -> Void) -> Progress {
        logger.debugPublic("➡️  deleteItem(\(itemIdentifier.rawValue)) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        do { try requireBackend() } catch {
            completionHandler(error)
            return Progress()
        }

        let param = DomainService.DeleteItemParameter(itemIdentifier: DomainService.ItemIdentifier(itemIdentifier),
                                                      existingRevision: DomainService.Version(version),
                                                      recursiveDelete: options.contains(.recursive))
        let progress = backend.deleteItem(param) { result in
            switch result {
            // If the item is already gone, ignore the error.
            case .failure(CommonError.itemNotFound(_)):
                completionHandler(nil)
            case .failure(let error):
                completionHandler(error.toPresentableError())
            case .success:
                completionHandler(nil)
            }
        }
        progress.cancellationHandler = { completionHandler(NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }
        return progress
    }
}
