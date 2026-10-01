/// Error formatting and presentation
//
//  Abstract:
//  An extension that provides a map from common errors to Objective-C
//              errors.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Common
import FileProvider

extension Error {
    func toPresentableError() -> NSError {
        // Crypto/decode failures: wrong user or malformed encrypted content.
        // - surface as NSFileReadNoPermissionError
        if self is DecodingError || self is BC01Error {
            return NSError(domain: NSCocoaErrorDomain,
                           code: NSFileReadCorruptFileError,
                           userInfo: [NSUnderlyingErrorKey: self as NSError,
                                      NSLocalizedDescriptionKey: "The file could not be decrypted.",
                                      NSLocalizedFailureReasonErrorKey: "The file is corrupt or was encrypted with a different key."])
        }

        // A locked vault is not a fault the OS can retry through: the credential and the key
        // material are intact but unreadable until the user unlocks. Both of its shapes —
        // `AuthError.vaultLocked` (the sealed refresh token cannot be opened) and
        // `VaultKeyStoreError.locked` (an evicted Provider-readable slot such as `fileKeysKEK`)
        // — surface as the SAME signal an absent `fileKeysKEK`/session key already produces on
        // the fetch and create paths (`Extension+FetchContent.makeEncryptor`,
        // `makeDecryptor`): `NSFileProviderError.notAuthenticated`. One locked signal, not two.
        //
        // `AuthError.notAuthenticated` joins it deliberately: from the OS's point of view "no
        // credential" and "credential unreadable" both mean this domain cannot talk to its
        // backend until the user intervenes in the app. The two are distinguished where the
        // remedy differs — in the app's UI — not here.
        if let authError = self as? AuthError {
            switch authError {
            case .vaultLocked, .notAuthenticated, .refreshRejected:
                return NSError(domain: NSFileProviderErrorDomain,
                               code: NSFileProviderError.notAuthenticated.rawValue,
                               userInfo: [NSUnderlyingErrorKey: authError as NSError])
            case .tokenEndpointFailure, .keychain:
                return NSError(domain: NSFileProviderErrorDomain,
                               code: NSFileProviderError.serverUnreachable.rawValue,
                               userInfo: [NSUnderlyingErrorKey: authError as NSError])
            }
        }
        if (self as? VaultKeyStoreError) == .locked {
            return NSError(domain: NSFileProviderErrorDomain,
                           code: NSFileProviderError.notAuthenticated.rawValue,
                           userInfo: nil)
        }

        guard let commonError = self as? CommonError else {
            let error = self as NSError
            switch (error.domain, error.code) {
            case (NSURLErrorDomain, NSURLErrorCancelled):
                return NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError, userInfo: nil)
            case (NSURLErrorDomain, _):
                return NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.serverUnreachable.rawValue, userInfo: nil)
            case (NSCocoaErrorDomain, NSUserCancelledError):
                return error
            case (NSFileProviderErrorDomain, _):
                // Already OS-meaningful (e.g. `serverUnreachable` while throttled): pass through so
                // the system backs off and waits for `signalErrorResolved`, not an IPC fault.
                return error
            default:
                return NSError(domain: NSCocoaErrorDomain, code: NSXPCConnectionReplyInvalid, userInfo: nil)
            }
        }

        switch commonError {
        case .itemExists(let entry):
            return NSError.fileProviderErrorForCollision(with: Item(entry))
        case .itemNotFound(let identifier):
            return NSError.fileProviderErrorForNonExistentItem(withIdentifier: NSFileProviderItemIdentifier(identifier))
        case .deletionRejected(let entry):
            return NSError.fileProviderErrorForRejectedDeletion(of: Item(entry))
        case .tokenExpired:
            return NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.syncAnchorExpired.rawValue, userInfo: nil)
        case .timedOut:
            return NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.serverUnreachable.rawValue, userInfo: nil)
        case .notImplemented:
            return NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError, userInfo: nil)
        case .clientCrashingError:
            exit(0) // The server requests a crash.
        case .simulatedError(let domain, let code, let localizedDescription):
            var userInfo: [String: Any]?
            if let localizedDescription = localizedDescription {
                userInfo = [NSLocalizedDescriptionKey: localizedDescription]
            }
            return NSError(domain: domain, code: code, userInfo: userInfo)
        case .authRequired:
            return NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.notAuthenticated.rawValue, userInfo: nil)
        case .insufficientQuota:
            return NSError(domain: NSFileProviderErrorDomain, code: NSFileProviderError.insufficientQuota.rawValue, userInfo: nil)
        default:
            return NSError(domain: NSCocoaErrorDomain, code: NSXPCConnectionReplyInvalid, userInfo: [NSUnderlyingErrorKey: commonError])
        }
    }
}
