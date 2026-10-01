/// Cross-process shared configuration schema persisted as JSON in the App Group container.
///
/// This is the single source of truth for every key the Provider extension reads. It exists
/// because ``UserDefaults(suiteName:)`` was not working for a while (it works fine now)
/// Direct file I/O on the App Group container bypasses `cfprefsd` entirely.
///
/// Owned and serialised by ``SharedConfigStore``. Host-local debug toggles (response delay,
/// error rate, batch size, etc.) remain on ``UserDefaults.sharedContainerDefaults``.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

public extension NSNotification.Name {
    /// Posted (via ``DistributedNotificationCenter``) when the set of domain accounts changes.
    /// Drives the host's domain-list fan-out, which re-reads ``SharedConfigStore``.
    static let accountsDidChange =
        NSNotification.Name(rawValue: "org.vaultsync.VaultSync.Server.AccountsDidChange")
}

/// Backend that services a domain's item content and enumeration.
///
/// The host writes this into ``DomainAccount`` so the Provider can route content
/// operations without an account-provisioning RPC. Only ``emulator`` is wired
/// end-to-end today; the remaining cases are stubbed at the Provider routing seam.
public enum BackendKind: String, Codable, Equatable, CaseIterable {
    /// Reference `StandaloneServer` emulator reached over HTTP JSON-RPC (`:24680`).
    case emulator
    /// Microsoft Graph OneDrive Personal (see `/docs/backend/remote-onedrive.md`).
    case oneDrive
    /// Local/removable filesystem backend (future).
    case localFS

    /// Human-readable name for UI. The `rawValue` is a wire/storage token — never shown to the
    /// user, which is what surfaced `oneDrive` as a backend name in the edit form.
    public var displayName: String {
        switch self {
        case .emulator: return "Emulator (local server)"
        case .oneDrive: return "OneDrive"
        case .localFS: return "Local Filesystem"
        }
    }
}

/// Cross-process binding of an `NSFileProviderDomain` to its backend.
///
/// This is the source of truth the Provider extension reads at startup instead of
/// issuing a `ListAccount`/`CreateAccount` RPC. The host is the sole writer.
///
/// The per-domain shared secret is **not** stored here — it lives in
/// ``SharedConfig/secrets`` (single source per field). OAuth credentials are likewise absent:
/// the refresh token is keyed by the domain identifier in the App Group keychain (see
/// ``MSALTokenStore``), so `backendKind == .oneDrive` is the only account-row signal that one
/// exists.
/// Security-scoped bookmark data is stored in ``SharedConfig/bookmarks``.
public struct DomainAccount: Codable, Equatable {
    /// Human-readable domain name (mirrors `NSFileProviderDomain.displayName`).
    public var displayName: String
    /// Backend-specific path: local filesystem path for `.emulator`/`.localFS`,
    /// remote drive path for `.oneDrive`. `nil` means backend default.
    public var remotePath: String?
    /// Backend servicing this domain's content and enumeration.
    public var backendKind: BackendKind
    /// OneDrive only: the Graph DriveItem id of the serving folder, captured by the
    /// folder picker. `nil` means serve the drive root. Preferred over ``remotePath``
    /// for OneDrive since it survives folder rename/move and needs no path resolution.
    public var remoteItemID: String?

    public init(displayName: String,
                remotePath: String? = nil,
                backendKind: BackendKind = .emulator,
                remoteItemID: String? = nil) {
        self.displayName = displayName
        self.remotePath = remotePath
        self.backendKind = backendKind
        self.remoteItemID = remoteItemID
    }
}

/// Codable snapshot of every cross-process configuration value.
///
/// All members have defaults so a missing or partial `config.json` decodes cleanly.
public struct SharedConfig: Codable, Equatable {

    // MARK: - Connection

    /// Hostname of the local ``StandaloneServer`` the Provider posts JSON-RPC to.
    public var hostname: String = "localhost"

    /// Per-domain shared secrets keyed by ``NSFileProviderDomainIdentifier.rawValue``.
    public var secrets: [String: String] = [:]

    /// Per-domain offline flag.
    public var offline: [String: Bool] = [:]

    /// Per-domain monotonic config epoch. Bumped by the host on any config change that should
    /// invalidate the domain (feature-flag toggle, manual nudge). The extension folds it into its
    /// own ``NSFileProviderDomainVersion`` (see `DomainVersionStore`); the version
    /// itself is **not** stored here — it is extension-owned and rank-derived.
    public var configEpoch: [String: Int] = [:]

    /// Per-domain feature-flag map: domainID -> flagName -> value.
    public var featureFlag: [String: [String: Bool]] = [:]

    /// Per-domain encryption configuration.
    public var cryptoConfig: [String: DomainCryptoConfig] = [:]

    /// Per-domain thumbnail-upload flag. When absent, defaults to disabled (see
    /// ``UserDefaults/thumbnailUpload(for:)``). Never honored for encrypted domains —
    /// generating a thumbnail from plaintext and uploading it would leak content past
    /// the encryption boundary.
    public var thumbnailUpload: [String: Bool] = [:]

    /// Per-domain "auto-encrypt unencrypted files on edit" flag. When absent, defaults to
    /// disabled (opt-in). Only meaningful for BC01 domains. When on, editing a plaintext-named
    /// file converts it to a `.bc` item (copy-to-new, verify, remove original).
    public var autoEncryptOnEdit: [String: Bool] = [:]

    /// Per-domain policy: when auto-encrypting on edit, send the plaintext original to the
    /// Trash (if the backend supports it) instead of hard-deleting. Defaults to `true`.
    public var trashPlaintextOnAutoEncrypt: [String: Bool] = [:]

    /// Per-domain backend binding keyed by ``NSFileProviderDomainIdentifier.rawValue``.
    /// Host writes; Provider reads. Replaces the legacy `CreateAccount`/`ListAccount` RPC
    /// as the source of truth for the domain↔backend binding.
    public var accounts: [String: DomainAccount] = [:]

    /// Per-domain security-scoped bookmark data keyed by ``NSFileProviderDomainIdentifier.rawValue``.
    /// Stored here so the Local Server can resolve the bookmark
    public var bookmarks: [String: Data] = [:]

    // MARK: - UI suppression

    /// Per-domain suppressed user-interaction identifiers.
    public var userInteractionSuppressedIdentifiers: [String: [String]] = [:]

    /// Process names that should not trigger materialisation.
    public var blockedProcesses: [String] = []

    // MARK: - Provider-read Tweaks

    /// Sync children before reparenting the parent.
    public var syncChildrenBeforeParentMove: Bool = true

    /// Minimum partial-fetch window, in kilobytes, for a system or Finder read starting at
    /// offset 0 (header probes). See `PartialFetchWindow`.
    public var BRMHeadFloorSystemKB: Int = 256

    /// Minimum partial-fetch window, in kilobytes, for an app's read starting at offset 0.
    /// See `PartialFetchWindow`.
    public var BRMHeadFloorStandardKB: Int = 1024

    /// Minimum partial-fetch read-ahead window, in megabytes, for a read starting past
    /// offset 0. See `PartialFetchWindow`.
    public var BRMReadAheadFloorMB: Int = 2

    /// Maximum partial-fetch read-ahead window, in megabytes. See `PartialFetchWindow`.
    public var BRMReadAheadCeilingMB: Int = 16

    /// Read-ahead window as a fraction of file size (`fileSize / divisor`), clamped between
    /// the read-ahead floor and ceiling. See `PartialFetchWindow`.
    public var BRMReadAheadFileDivisor: Int = 16

    // MARK: - Parallel range download (OneDrive/Graph content fetch)

    /// Files at or above this size (bytes) download via parallel range GETs instead of a
    /// single stream, to raise aggregate throughput on per-request-rate-limited backends.
    ///
    /// Set high deliberately. Below this size a single GET wins: connection setup plus the BC01
    /// header probe dominate the transfer, and fanning out pays that cost once per lane for no
    /// gain. It also keeps ``ContentStreamDownloader``'s single-GET fast path — one `[0, end)`
    /// fetch serving as both header and body — live for the great majority of files, saving a
    /// whole round-trip per `.bc` download. Mirrors rclone's 256 MiB multi-thread cutoff, backed
    /// off to 64 MiB since our lanes decrypt as they arrive.
    public var parallelDownloadThreshold: Int = 64 * 1024 * 1024

    /// Number of concurrent range lanes for a parallel download. Effective concurrency is
    /// additionally capped by URLSession's `httpMaximumConnectionsPerHost`.
    ///
    /// OneDrive/SharePoint publishes no per-user concurrency limit — it throttles dynamically
    /// with 429 + `Retry-After` under a resource-unit model. The observed safe defaults elsewhere
    /// are rclone's 4 multi-thread streams and Microsoft's own 5-thread throttling sample, and
    /// rclone documents OneDrive as sensitive to high concurrency. 4 also leaves headroom under
    /// the per-host connection cap for concurrent metadata/delta calls on the same host.
    public var parallelDownloadLanes: Int = 4

    /// Upper bound (bytes) on a single download lane's byte-range span.
    ///
    /// Without this a lane's span is `fileSize / lanes`, so a 4 GB file becomes 4 × 1 GB requests:
    /// one failure discards a gigabyte of work, and any lane skew leaves a single stream running
    /// alone for the whole tail. Capping the span makes lanes recycle through many bounded
    /// requests instead — retry granularity and a level tail, at no throughput cost. Counterpart
    /// to ``ContentStreamUploader``'s `defaultMaxSpanBytes` on the upload side.
    public var maxDownloadSpanBytes: Int = 16 * 1024 * 1024

    /// Maximum concurrent interactive (Finder-origin) Graph requests per domain. Excess requests
    /// queue in the rate limiter instead of fanning out and tripping a 429 whose `Retry-After`
    /// then stalls every fetch. Sized above ``parallelDownloadLanes`` so one parallel download
    /// never starves itself.
    public var maxInteractiveRequests: Int = 8

    // MARK: - BC01 header cache (persistent, per domain)

    /// How long a persisted BC01 header row stays valid, in days.
    ///
    /// A row's validity does not decay with use — it is invalidated by a content write, which
    /// replaces the row — so the only bound is age since it was written. Past this horizon a
    /// re-probe is negligible against the cold re-open that reaches such a file at all.
    public var headerCacheMaxAgeDays: Int = 180

    /// Upper bound on rows kept in the BC01 header cache.
    ///
    /// The table holds one row per item, so this bounds *distinct items ever fetched* rather
    /// than edit history: a single frequently-saved file cannot inflate it. ~500k rows is
    /// roughly 100 MB at ~200 B/row, and a row count is far cheaper to enforce than `page_count`.
    public var headerCacheMaxRows: Int = 500_000

    /// How long the unwrapped `fileKeysKEK` may stay resident in the extension between keychain
    /// re-reads, in seconds.
    ///
    /// The Provider observes vault lock only by reading the keychain slot the app evicts, so
    /// this bounds how long a **locked** vault can still serve cache hits. `0` forces a keychain
    /// read per call (~100–500 µs) and makes lock take effect immediately in-process.
    public var headerCacheKeyResidencySeconds: TimeInterval = 5

    // MARK: - Streaming upload (OneDrive/Graph content upload)

    /// Number of concurrent fragment lanes for a streaming upload. Peak upload memory is roughly
    /// `parallelUploadLanes × ContentStreamUploader.defaultMaxSpanBytes`, independent of file size.
    public var parallelUploadLanes: Int = 4

    // MARK: - Vault lock

    /// How a domain's `domainKey` is gated at rest — the authoritative record of one vault's
    /// protection state.
    ///
    /// Exactly one `domainKey` wrapper exists per domain, and the `domainKey` is never stored
    /// unwrapped. The unlock ceremony is *derived* from this value, so there is no second field
    /// to drift out of sync with it. The keychain cannot be probed for a `.biometryCurrentSet`
    /// item without prompting, so the active gating is tracked here; the keychain holds the
    /// secrets.
    ///
    /// - `none`: device gating key — a keychain item with no access control, read silently.
    ///   Lock is a UX affordance only, not a security boundary: anything able to run code in
    ///   the App Group can unlock.
    /// - `biometric`: biometric gating key — a keychain item behind `SecAccessControl`
    ///   (`.biometryCurrentSet .or .devicePasscode`). Exportable after device-owner auth, and
    ///   bypassable with the device password.
    /// - `pin`: PIN gating key — PBKDF2-derived from the entered PIN, never stored.
    /// - `secure`: Secure Enclave — a per-domain ephemeral public key agreed against an
    ///   install-wide SE P-256 key (`.biometryCurrentSet` + `.privateKeyUsage`, **no** password
    ///   fallback). The only option whose private half is non-exportable. A Touch ID enrollment
    ///   change destroys the SE key and every `domainKey.wrapped` gated by it.
    ///
    /// Chosen **per install** and stored on ``SharedConfig/vaultGating``. See ``VaultKeyStore``
    /// and ``VaultLockController``.
    public enum VaultGating: String, Codable, Sendable, CaseIterable {
        case none
        case biometric
        case pin
        case secure
    }

    /// The unlock method protecting **every** vault on this install — authoritative, not a seed.
    ///
    /// One method is active at a time: it owns the gating keypair each domain's `domainKey` is
    /// sealed to, so changing it re-seals every domain in one step (``VaultKeyStore/setGating``).
    /// There is deliberately no per-domain copy — a second record of the same fact can only drift.
    public var vaultGating: VaultGating = .none

    /// What locking a vault does to it.
    ///
    /// - `lock`: disconnect the domain and de-materialize its content.
    /// - `lockAndRemove`: additionally remove the domain from Finder and empty its metadata
    ///   cache. Per-domain *configuration* is preserved so unlocking can restore the domain;
    ///   remote data is never touched. This affects local readability only.
    public enum VaultLockMethod: String, Codable, Sendable {
        case lock
        case lockAndRemove
    }
    public var vaultLockMethod: VaultLockMethod = .lock

    /// Whether the auto-lock policy (idle timeout + system-event triggers) is armed.
    public var autoLockEnabled: Bool = false

    /// Per-domain cancellation request counter — the app→Provider half of the graceful-teardown
    /// handshake, keyed by domain identifier `rawValue`.
    ///
    /// The app bumps this before locking-and-removing a vault; the Darwin notification posted by
    /// ``SharedConfigStore`` wakes the Provider, which cancels its in-flight operations and
    /// acknowledges via `ProgressSnapshot.cancelAckGeneration` + `providerState == .cancelled`.
    ///
    /// A monotonic counter rather than a boolean: a value left behind by a crashed process is
    /// simply one the Provider has already acknowledged, and the next request bumps past it. A
    /// stale `true` flag, by contrast, would wedge the domain.
    public var cancelGeneration: [String: Int] = [:]

    /// Idle auto-lock timeout in seconds. On expiry the vault relocks (KEK + Provider-readable
    /// unwrapped session slots evicted). Default 1 hour.
    public var lockTimeoutSeconds: Int = 3600

    /// Relock when the screen locks / screensaver engages.
    public var lockOnScreenLock: Bool = true

    /// Relock when the user session resigns active (fast-user-switch / logout).
    public var lockOnLogout: Bool = true

    /// Relock on system power-off / restart.
    public var lockOnRestart: Bool = true

    /// Relock when the app quits.
    ///
    /// Implied by every other trigger: a vault that relocks on idle or screen-lock but survives a
    /// quit would leave unwrapped slots readable by the Provider with no app left to evict them.
    /// The Security screen therefore shows it checked and read-only whenever another trigger is
    /// armed; ``quitLockIsForced`` and ``locksOnQuit`` are the one place that rule is evaluated.
    public var lockOnQuit: Bool = true

    /// Whether any trigger other than quit is armed, which *forces* ``lockOnQuit`` on.
    ///
    /// A vault that relocks on idle or screen-lock but not on quit is a contradiction: quitting
    /// removes the only process that could ever evict the slots, so the weaker triggers would
    /// promise a relock that never happens. One computed rule rather than a conditional repeated
    /// in the view and in the terminate handler — the checkbox's read-only state and the actual
    /// lock-on-quit decision are then the same answer by construction.
    public var quitLockIsForced: Bool {
        lockOnScreenLock || lockOnLogout || lockOnRestart || lockTimeoutSeconds > 0
    }

    /// Whether quitting the app must relock the vaults, honouring the forcing rule above.
    ///
    /// `false` whenever auto-lock is disarmed altogether: the user has opted out of automatic
    /// relocking, and quit is an automatic trigger like any other.
    public var locksOnQuit: Bool {
        guard autoLockEnabled else { return false }
        return lockOnQuit || quitLockIsForced
    }

    public init() {}
}

// MARK: - Tolerant decoding

extension SharedConfig {
    /// Decodes every key leniently: a key absent from `config.json` keeps its property default.
    ///
    /// The synthesized decoder throws `keyNotFound` for any missing key, so adding a field would
    /// fail the whole decode and the store would fall back to an empty config — discarding every
    /// configured domain. Encoding stays synthesized.
    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func load<T: Decodable>(_ value: inout T, _ key: CodingKeys) throws {
            if let decoded = try c.decodeIfPresent(T.self, forKey: key) { value = decoded }
        }
        try load(&hostname, .hostname)
        try load(&secrets, .secrets)
        try load(&offline, .offline)
        try load(&configEpoch, .configEpoch)
        try load(&featureFlag, .featureFlag)
        try load(&cryptoConfig, .cryptoConfig)
        try load(&thumbnailUpload, .thumbnailUpload)
        try load(&autoEncryptOnEdit, .autoEncryptOnEdit)
        try load(&trashPlaintextOnAutoEncrypt, .trashPlaintextOnAutoEncrypt)
        try load(&accounts, .accounts)
        try load(&bookmarks, .bookmarks)
        try load(&userInteractionSuppressedIdentifiers, .userInteractionSuppressedIdentifiers)
        try load(&blockedProcesses, .blockedProcesses)
        try load(&syncChildrenBeforeParentMove, .syncChildrenBeforeParentMove)
        try load(&BRMHeadFloorSystemKB, .BRMHeadFloorSystemKB)
        try load(&BRMHeadFloorStandardKB, .BRMHeadFloorStandardKB)
        try load(&BRMReadAheadFloorMB, .BRMReadAheadFloorMB)
        try load(&BRMReadAheadCeilingMB, .BRMReadAheadCeilingMB)
        try load(&BRMReadAheadFileDivisor, .BRMReadAheadFileDivisor)
        try load(&parallelDownloadThreshold, .parallelDownloadThreshold)
        try load(&parallelDownloadLanes, .parallelDownloadLanes)
        try load(&maxDownloadSpanBytes, .maxDownloadSpanBytes)
        try load(&maxInteractiveRequests, .maxInteractiveRequests)
        try load(&headerCacheMaxAgeDays, .headerCacheMaxAgeDays)
        try load(&headerCacheMaxRows, .headerCacheMaxRows)
        try load(&headerCacheKeyResidencySeconds, .headerCacheKeyResidencySeconds)
        try load(&parallelUploadLanes, .parallelUploadLanes)
        try load(&vaultGating, .vaultGating)
        try load(&vaultLockMethod, .vaultLockMethod)
        try load(&autoLockEnabled, .autoLockEnabled)
        try load(&cancelGeneration, .cancelGeneration)
        try load(&lockTimeoutSeconds, .lockTimeoutSeconds)
        try load(&lockOnScreenLock, .lockOnScreenLock)
        try load(&lockOnLogout, .lockOnLogout)
        try load(&lockOnRestart, .lockOnRestart)
        try load(&lockOnQuit, .lockOnQuit)
    }
}
