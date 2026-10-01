/// UserDefaults configuration and feature flags.
///
/// Host-local debug toggles (response delay, error rate, batch size, quota, authentication
/// bypass, etc.) remain in the App Group ``UserDefaults`` suite. Every key that the
/// Provider extension reads — connection state, secrets, per-domain offline flags,
/// feature flags, crypto config, blocked processes, suppressed identifiers, and the
/// Provider-relevant Tweaks — is delegated to ``SharedConfigStore`` so the values
/// travel via direct App Group file I/O instead of `cfprefsd`. See
/// ``SharedConfigStore`` for the rationale.
// Copyright (c) 2024 Apple Inc.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import FileProvider

/// Defaults registered in `NSRegistrationDomain` for host-local keys only.
///
/// Cross-process keys (provider-read tweaks, secrets, etc.) are NOT registered here; their
/// defaults live on ``SharedConfig`` and are served from ``SharedConfigStore``.
internal let defaultValues: [String: Any] = [
    "responseDelay": 0.0,
    "errorRate": 0.0,
    "batchSize": 200,
    "accountQuota": 0,
    "ignoreAuthentication": true,
    "contentStoredInline": false,
    "ignoreContentVersionOnDeletion": false
]

public struct FeatureFlag {
    public let name: String
    public let defaultIfNotPresent: Bool

    public init(name: String, defaultIfNotPresent: Bool) {
        self.name = name
        self.defaultIfNotPresent = defaultIfNotPresent
    }
}

public enum FeatureFlags {
    public static let pinnedFeatureFlag = FeatureFlag(name: "pinnedFeatureEnabled", defaultIfNotPresent: true)
    public static let shouldWarnOnImportingToFolder = FeatureFlag(name: "shouldWarnOnImportingToFolder", defaultIfNotPresent: true)
    /// Warn (log) instead of failing when a BC01 header HMAC does not match the on-disk JSON.
    /// Default `true`: Boxcryptor's own HMAC matches the on-disk JSON only ~50% of the time.
    public static let bc01HeaderHMACWarnOnly =
        FeatureFlag(name: "bc01HeaderHMACWarnOnly", defaultIfNotPresent: true)
}

public extension UserDefaults {

    // MARK: - Suite

    /// Shared App Group `UserDefaults` suite, used only for host-local keys. Cross-process
    /// configuration is served by ``SharedConfigStore``.
    static let sharedContainerDefaults: UserDefaults = {
        guard let defaults = UserDefaults(suiteName: AppIdentifiers.appGroupID) else {
            fatalError("could not access shared user defaults")
        }
        defaults.register(defaults: defaultValues)
        return defaults
    }()

    // MARK: - Host-local accessors

    var ignoreLoggingForEndpoints: [String] {
        stringArray(forKey: "ignoreLoggingForEndpoints") ?? [String]()
    }

    var responseDelay: TimeInterval {
        TimeInterval(float(forKey: "responseDelay") / 1000.0)
    }

    var errorRate: Float {
        float(forKey: "errorRate")
    }

    var ignoreAuthentication: Bool {
        bool(forKey: "ignoreAuthentication")
    }

    var ignoreContentVersionOnDeletion: Bool {
        bool(forKey: "ignoreContentVersionOnDeletion")
    }

    var contentStoredInline: Bool {
        bool(forKey: "contentStoredInline")
    }

    enum ErrorType: Int {
        case server
        case plugin
        case both
    }

    var errorType: ErrorType {
        ErrorType(rawValue: integer(forKey: "errorType")) ?? .server
    }

    var outgoingBandwidth: Int? {
        let key = "outgoingBandwidth"
        if object(forKey: key) == nil { return nil }
        return integer(forKey: key)
    }

    var batchSize: Int {
        let size = integer(forKey: "batchSize")
        if size == 0 { return 200 }
        return max(size, 1)
    }

    struct Holder {
        public static var quotaOverride: Int64? = nil
    }

    var accountQuota: Int64? {
        get {
            if let override = Holder.quotaOverride { return override }
            let quota = Int64(integer(forKey: "accountQuota")) * 1_048_576
            return quota > 0 ? quota : nil
        }
        set { Holder.quotaOverride = newValue }
    }

    // MARK: - Cross-process accessors (delegated to SharedConfigStore)

    var hostname: String {
        let stored = SharedConfigStore.shared.read(\.hostname)
        if !stored.isEmpty { return stored }
        #if os(macOS)
        return "localhost"
        #else
        return ""
        #endif
    }

    var syncChildrenBeforeParentMove: Bool {
        SharedConfigStore.shared.read(\.syncChildrenBeforeParentMove)
    }

    /// Partial-fetch head floor for system requests, in bytes. See `PartialFetchWindow`.
    var BRMHeadFloorSystem: Int {
        SharedConfigStore.shared.read(\.BRMHeadFloorSystemKB) * 1024
    }

    /// Partial-fetch head floor for app requests, in bytes. See `PartialFetchWindow`.
    var BRMHeadFloorStandard: Int {
        SharedConfigStore.shared.read(\.BRMHeadFloorStandardKB) * 1024
    }

    /// Partial-fetch read-ahead ceiling in bytes. See `PartialFetchWindow`.
    var BRMReadAheadCeiling: Int {
        SharedConfigStore.shared.read(\.BRMReadAheadCeilingMB) * 1_048_576
    }

    /// Partial-fetch read-ahead size as `fileSize / divisor`. See `PartialFetchWindow`.
    var BRMReadAheadFileDivisor: Int {
        SharedConfigStore.shared.read(\.BRMReadAheadFileDivisor)
    }

    /// Partial-fetch read-ahead floor in bytes. See `PartialFetchWindow`.
    var BRMReadAheadFloor: Int {
        SharedConfigStore.shared.read(\.BRMReadAheadFloorMB) * 1_048_576
    }

    /// File size (bytes) at or above which content downloads use parallel range GETs.
    var parallelDownloadThreshold: Int {
        SharedConfigStore.shared.read(\.parallelDownloadThreshold)
    }

    var parallelUploadLanes: Int {
        max(1, SharedConfigStore.shared.read(\.parallelUploadLanes))
    }

    var parallelDownloadLanes: Int {
        max(1, SharedConfigStore.shared.read(\.parallelDownloadLanes))
    }

    /// Maximum concurrent interactive Graph requests per domain.
    var maxInteractiveRequests: Int {
        max(1, SharedConfigStore.shared.read(\.maxInteractiveRequests))
    }

    /// Upper bound on a single download lane's byte-range span.
    var maxDownloadSpanBytes: Int {
        max(1, SharedConfigStore.shared.read(\.maxDownloadSpanBytes))
    }

    /// Maximum age (days) of a persisted BC01 header row before the sweep drops it.
    var headerCacheMaxAgeDays: Int {
        max(1, SharedConfigStore.shared.read(\.headerCacheMaxAgeDays))
    }

    /// Maximum number of rows retained in the BC01 header cache.
    var headerCacheMaxRows: Int {
        max(1, SharedConfigStore.shared.read(\.headerCacheMaxRows))
    }

    /// How long the unwrapped `fileKeysKEK` may stay resident between keychain re-reads.
    var headerCacheKeyResidencySeconds: TimeInterval {
        max(0, SharedConfigStore.shared.read(\.headerCacheKeyResidencySeconds))
    }

    var blockedProcesses: [String] {
        get { SharedConfigStore.shared.read(\.blockedProcesses) }
        set { SharedConfigStore.shared.write(\.blockedProcesses, newValue) }
    }

    var userInteractionSuppressedIdentifiers: [String: [String]] {
        get { SharedConfigStore.shared.read(\.userInteractionSuppressedIdentifiers) }
        set { SharedConfigStore.shared.write(\.userInteractionSuppressedIdentifiers, newValue) }
    }

    // MARK: - Per-domain accessors

    func secret(for domainIdentifier: NSFileProviderDomainIdentifier) -> String? {
        SharedConfigStore.shared.read(\.secrets)[domainIdentifier.rawValue]
    }

    func set(secret: String?, for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { config in
            if let secret {
                config.secrets[domainIdentifier.rawValue] = secret
            } else {
                config.secrets.removeValue(forKey: domainIdentifier.rawValue)
            }
        }
    }

    func offline(for domainIdentifier: NSFileProviderDomainIdentifier) -> Bool {
        SharedConfigStore.shared.read(\.offline)[domainIdentifier.rawValue] ?? false
    }

    func offline(_ value: Bool?, for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { config in
            if value == true {
                config.offline[domainIdentifier.rawValue] = true
            } else {
                config.offline.removeValue(forKey: domainIdentifier.rawValue)
            }
        }
    }

    /// Whether thumbnails should be generated and uploaded for this domain. Defaults to
    /// `false` (opt-in per domain). Callers must additionally suppress upload for
    /// encrypted domains regardless of this flag — see ``Extension/uploadThumbnail``.
    func thumbnailUpload(for domainIdentifier: NSFileProviderDomainIdentifier) -> Bool {
        SharedConfigStore.shared.read(\.thumbnailUpload)[domainIdentifier.rawValue] ?? false
    }

    func thumbnailUpload(_ value: Bool?, for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { config in
            if let value {
                config.thumbnailUpload[domainIdentifier.rawValue] = value
            } else {
                config.thumbnailUpload.removeValue(forKey: domainIdentifier.rawValue)
            }
        }
    }

    /// Whether plaintext files should be auto-encrypted when edited in this (BC01) domain.
    /// Defaults to `false` (opt-in per domain).
    func autoEncryptOnEdit(for domainIdentifier: NSFileProviderDomainIdentifier) -> Bool {
        SharedConfigStore.shared.read(\.autoEncryptOnEdit)[domainIdentifier.rawValue] ?? false
    }

    func autoEncryptOnEdit(_ value: Bool?, for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { config in
            if let value {
                config.autoEncryptOnEdit[domainIdentifier.rawValue] = value
            } else {
                config.autoEncryptOnEdit.removeValue(forKey: domainIdentifier.rawValue)
            }
        }
    }

    /// Whether the plaintext original is sent to the Trash (vs hard-deleted) after auto-encrypt.
    /// Defaults to `true` (prefer Trash when the backend supports it).
    func trashPlaintextOnAutoEncrypt(for domainIdentifier: NSFileProviderDomainIdentifier) -> Bool {
        SharedConfigStore.shared.read(\.trashPlaintextOnAutoEncrypt)[domainIdentifier.rawValue] ?? true
    }

    func trashPlaintextOnAutoEncrypt(_ value: Bool?, for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { config in
            if let value {
                config.trashPlaintextOnAutoEncrypt[domainIdentifier.rawValue] = value
            } else {
                config.trashPlaintextOnAutoEncrypt.removeValue(forKey: domainIdentifier.rawValue)
            }
        }
    }

    /// The current host config epoch for a domain. The host bumps this on any config change that
    /// should invalidate the domain; the extension folds it into its own ``NSFileProviderDomainVersion``.
    func configEpoch(for domainIdentifier: NSFileProviderDomainIdentifier) -> Int {
        SharedConfigStore.shared.read(\.configEpoch)[domainIdentifier.rawValue] ?? 0
    }

    /// Bump the host config epoch for a domain. Pair with `signalEnumerator(for: .workingSet)`
    /// so the extension re-reads it and advances the domain version. The host cannot mutate the
    /// version directly (see ``DomainVersionStore``).
    func bumpConfigEpoch(for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { config in
            config.configEpoch[domainIdentifier.rawValue, default: 0] += 1
        }
    }

    /// The current cancellation generation for a domain.
    func cancelGeneration(for domainIdentifier: NSFileProviderDomainIdentifier) -> Int {
        SharedConfigStore.shared.read(\.cancelGeneration)[domainIdentifier.rawValue] ?? 0
    }

    /// Request that the Provider cancel in-flight work for a domain, returning the new
    /// generation to wait for an acknowledgement on.
    ///
    /// The write posts ``SharedConfigStore``'s Darwin notification, which is what actually wakes
    /// the Provider. Callers await the ack via `ProgressStore` — see
    /// `AppModelActions.lockVault(_:)`.
    @discardableResult
    func requestCancellation(for domainIdentifier: NSFileProviderDomainIdentifier) -> Int {
        var generation = 0
        SharedConfigStore.shared.mutate { config in
            let next = (config.cancelGeneration[domainIdentifier.rawValue] ?? 0) + 1
            config.cancelGeneration[domainIdentifier.rawValue] = next
            generation = next
        }
        return generation
    }

    func featureFlag(for domainIdentifier: NSFileProviderDomainIdentifier,
                     featureFlag: FeatureFlag) -> Bool {
        let allFlags = SharedConfigStore.shared.read(\.featureFlag)
        guard let domainFlags = allFlags[domainIdentifier.rawValue] else {
            return featureFlag.defaultIfNotPresent
        }
        return domainFlags[featureFlag.name] ?? featureFlag.defaultIfNotPresent
    }

    func setFeatureFlag(for domainIdentifier: NSFileProviderDomainIdentifier,
                        featureFlag: FeatureFlag,
                        value: Bool) {
        SharedConfigStore.shared.mutate { config in
            var perDomain = config.featureFlag[domainIdentifier.rawValue] ?? [:]
            perDomain[featureFlag.name] = value
            config.featureFlag[domainIdentifier.rawValue] = perDomain
        }
        bumpConfigEpoch(for: domainIdentifier)
    }

    func toggleFeatureFlag(for domainIdentifier: NSFileProviderDomainIdentifier,
                           featureFlag: FeatureFlag) {
        let existing = self.featureFlag(for: domainIdentifier, featureFlag: featureFlag)
        setFeatureFlag(for: domainIdentifier, featureFlag: featureFlag, value: !existing)
    }

    // MARK: - Crypto configuration

    func cryptoConfig(for domainIdentifier: NSFileProviderDomainIdentifier) -> DomainCryptoConfig {
        SharedConfigStore.shared.read(\.cryptoConfig)[domainIdentifier.rawValue] ?? DomainCryptoConfig()
    }

    func setCryptoConfig(_ config: DomainCryptoConfig, for domainIdentifier: NSFileProviderDomainIdentifier) {
        SharedConfigStore.shared.mutate { snapshot in
            snapshot.cryptoConfig[domainIdentifier.rawValue] = config
        }
    }
}
