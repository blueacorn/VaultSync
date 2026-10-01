/// Container enumeration.
//
//  Abstract:
//  `NSFileProviderReplicatedExtension.enumerator(for:request:)` — routing a container
//  identifier to its working-set, trash, or folder enumerator.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common

extension Extension {
    public func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier,
                           request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        //logger.debugPublic("➡️  enumerator(for \(containerItemIdentifier.rawValue)) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        let backend = try requireBackend()
        switch containerItemIdentifier {
        case .workingSet:
            return WorkingSetEnumerator(backend: backend)
        case .trashContainer:
            if !backend.supportsTrashEnumeration {
                logger.debugPublic("🌀 trash not enumerable: throwing noSuchItem error")
                throw NSFileProviderError(.noSuchItem)
            }
            return TrashEnumerator(backend: backend)
        default:
            return ItemEnumerator(enumeratedItemIdentifier: containerItemIdentifier, backend: backend)
        }
    }
}
