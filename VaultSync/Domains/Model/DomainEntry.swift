/// Domain model for UI representation
//
//  Abstract:
//  An entry in the domain list that displays in the main window of the app.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Cocoa
import FileProvider
import Common

class DomainEntry: NSObject, Identifiable {
    var id: String {
        return domain.identifier.rawValue
    }
    let account: DomainAccount?
    var domain: NSFileProviderDomain
    /// True when this vault exists only in configuration: "Lock and Remove Vault" took it out
    /// of Finder, but its account/credential were deliberately preserved so unlocking can
    /// re-add it without re-authenticating.
    ///
    /// Such an entry has no registered `NSFileProviderDomain`, so `domain.isDisconnected` is
    /// meaningless for it — use ``locked`` rather than testing the domain directly.
    let isRemoved: Bool
    @objc dynamic var uploadProgress: Progress?
    @objc dynamic var downloadProgress: Progress?
    @objc dynamic let displayName: String
    @objc dynamic var remotePath: String { account?.remotePath ?? "" }

    @objc class var keyPathsForValuesAffectingStatus: Set<String> {
        Set(["uploadProgress.fractionCompleted", "downloadProgress.fractionCompleted",
             "uploadProgress.fileTotalCount", "downloadProgress.fileTotalCount",
             "uploadProgress.fileCompletedCount", "downloadProgress.fileCompletedCount",
             "uploadProgress.totalUnitCount", "downloadProgress.totalUnitCount"])
    }
    @objc dynamic var status: NSAttributedString {
        let ret: NSMutableAttributedString
        if account == nil {
            return NSMutableAttributedString(string: "Belongs to other process", attributes: [.foregroundColor: NSColor.gray])
        }
        if !domain.userEnabled {
            ret = NSMutableAttributedString(string: "Disabled", attributes: [.foregroundColor: NSColor.red])
        } else {
            ret = NSMutableAttributedString(string: "Enabled", attributes: nil)
        }

        if isRemoved {
            ret.append(NSAttributedString(string: ", Removed (locked)", attributes: nil))
        } else if domain.isDisconnected {
            ret.append(NSAttributedString(string: ", Disconnected", attributes: nil))
        }
        if domain.isHidden {
            ret.append(NSAttributedString(string: ", Hidden", attributes: nil))
        }
        if !UserDefaults.sharedContainerDefaults.ignoreAuthentication,
            self.authenticated {
            ret.append(NSAttributedString(string: ", Authenticated", attributes: nil))
        }
        if self.offline {
            ret.append(NSAttributedString(string: ", Offline", attributes: nil))
        }
        formatProgress(ret, self.uploadProgress, ("arrow.up.doc", "upload"))
        formatProgress(ret, self.downloadProgress, ("arrow.down.doc", "download"))
        return ret
    }
    /// Whether the vault is locked: either disconnected, or removed from Finder by
    /// "Lock and Remove Vault". The single predicate the UI and unlock flow should use.
    @objc dynamic var locked: Bool {
        return isRemoved || domain.isDisconnected
    }
    @objc dynamic var connected: Bool {
        return !locked
    }
    @objc dynamic var hidden: Bool {
        return domain.isHidden
    }
    /// Whether the domain holds a usable credential for its backend.
    ///
    /// Routed by ``BackendKind`` because "credential" means different things per backend and a
    /// single predicate would be wrong for all but one of them:
    ///
    /// - `.emulator` — the shared secret in `SharedConfig` (the same one the emulator DB row was
    ///   seeded with).
    /// - `.oneDrive` — the *sealed* refresh token in the keychain. Deliberately not the unwrapped
    ///   slot: locking deletes that slot while the sealed token survives, so testing it would
    ///   report a locked-but-authenticated vault as "Not authenticated".
    /// - `.localFS` — no credential exists; always authenticated.
    @objc dynamic var authenticated: Bool {
        guard let account else { return false }
        switch account.backendKind {
        case .emulator:
            return UserDefaults.sharedContainerDefaults.secret(for: domain.identifier) != nil
        case .oneDrive:
            return (try? CryptoKeychain.loadWrappedRefreshToken(for: id)) .map { $0 != nil } ?? false
        case .localFS:
            return true
        }
    }
    @objc dynamic var shouldWarnOnImportingToFolder: Bool {
        return UserDefaults.sharedContainerDefaults.featureFlag(for: domain.identifier, featureFlag: FeatureFlags.shouldWarnOnImportingToFolder)
    }
    @objc dynamic var pinnedFeatureEnabled: Bool {
        return UserDefaults.sharedContainerDefaults.featureFlag(for: domain.identifier, featureFlag: FeatureFlags.pinnedFeatureFlag)
    }
    @objc dynamic var offline: Bool {
        return UserDefaults.sharedContainerDefaults.offline(for: domain.identifier)
    }

    init(domain: NSFileProviderDomain, account: DomainAccount?, uploadProgress: Progress?,
         downloadProgress: Progress?, isRemoved: Bool = false) {
        self.displayName = domain.displayName
        self.domain = domain
        self.account = account
        self.isRemoved = isRemoved
        self.uploadProgress = uploadProgress
        self.downloadProgress = downloadProgress
    }

    // Only consider identifiers for equality.
    override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? DomainEntry else { return false }
        return other.id == id
    }

    private func formatProgress(_ ret: NSMutableAttributedString, _ progress: Progress?, _ direction: (name: String, desc: String)) {
        guard let progress = progress else { return }

        if !progress.isFinished {
            ret.append(NSAttributedString(string: " ", attributes: nil))
            let imageAttachment = NSTextAttachment()
            imageAttachment.image = NSImage(systemSymbolName: direction.name, accessibilityDescription: direction.desc)
            ret.append(NSAttributedString(attachment: imageAttachment))

            let countFormat = ByteCountFormatter()
            countFormat.allowedUnits = [.useBytes, .useKB, .useMB, .useGB]
            countFormat.countStyle = .file
            countFormat.allowsNonnumericFormatting = false
            let completed = countFormat.string(fromByteCount: progress.completedUnitCount)
            let total = countFormat.string(fromByteCount: progress.totalUnitCount)
            var completion = String(format: " %@ / %@ %.2f%%", completed, total, progress.fractionCompleted * 100)
            if let total = progress.fileTotalCount, let completed = progress.fileCompletedCount {
                completion.append("  (\(completed) / \(total) files)")
            }

            ret.append(NSAttributedString(string: completion, attributes: nil))
        }
    }
}
