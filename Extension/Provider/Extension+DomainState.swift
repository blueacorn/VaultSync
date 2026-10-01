/// Domain lifecycle and state management
//
//  Abstract:
//  Adds the domain version and shared user defaults to the extension.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Common
import FileProvider

// Sets the domain version and user info based on shared user defaults.
extension Extension: NSFileProviderDomainState {
    /// The domain version is **extension-owned**: the backend derives it from its local
    /// change-tracking store (OneDrive ``MetadataCache``), advancing it in lockstep with the
    /// rank on every real change — never persisting it to the shared `config.json`.
    ///
    /// Host-originated config changes can't write the version directly; instead the host bumps a
    /// monotonic `configEpoch` in `config.json` and signals the working set. Reading the version
    /// here first folds any unseen epoch into the backend's version (idempotent), so a host flag
    /// toggle is reflected the next time the system reads `domainVersion`.
    public var domainVersion: NSFileProviderDomainVersion {
        let epoch = UserDefaults.sharedContainerDefaults.configEpoch(for: self.domain.identifier)
        let version = backend.domainVersion(configEpoch: epoch)
        logger.infoPublic("➡️  domainVersion → \(version.description) configEpoch(\(epoch))")
        return version
    }
    public var userInfo: [AnyHashable: Any] {
        let shouldWarnOnImportingToFolder: Bool =
            UserDefaults.sharedContainerDefaults.featureFlag(for: self.domain.identifier, featureFlag: FeatureFlags.shouldWarnOnImportingToFolder)
        let pinnedFeatureEnabled: Bool =
            UserDefaults.sharedContainerDefaults.featureFlag(for: self.domain.identifier, featureFlag: FeatureFlags.pinnedFeatureFlag)

        logger.infoPublic("➡️  userInfo → shouldWarnOnImportingToFolder(\(shouldWarnOnImportingToFolder)) pinnedFeatureEnabled(\(pinnedFeatureEnabled))")
        return ["shouldWarnOnImportingToFolder": shouldWarnOnImportingToFolder, "pinnedFeatureEnabled": pinnedFeatureEnabled]
    }
}
