/// Cross-process store for ``SharedConfig`` backed by a JSON file in the App Group container.
///
/// **Why this exists.** `UserDefaults(suiteName:)` is the documented mechanism for sharing
/// settings between a macOS host app and a File Provider extension, but it relies on `cfprefsd`.
/// Inside the `.appex` sandbox, `cfprefsd` cannot refresh its cache after the host mutates the
/// suite plist (sandbox denies the cross-container read), producing repeated
/// `Couldn't read values in CFPrefsPlistSource … Contents Need Refresh: Yes` Faults and `nil`
/// lookups for any key that was added by the host after the extension launched.
///
/// **How this works.** The host and the extension both have the
/// `com.apple.security.application-groups` entitlement, granting unconditional read/write
/// access to `~/Library/Group Containers/<group-id>/`. We persist a single JSON document at
/// `<container>/Library/Application Support/config.json`, coordinated via `NSFileCoordinator`,
/// and notify peers of writes via a Darwin notification (`CFNotificationCenter` on the
/// process-wide Darwin notify center). The store maintains an in-memory snapshot for
/// synchronous, lock-protected reads from any thread.
///
/// **Threading.** Reads (``read(_:)``) and mutations (``mutate(_:)``) are synchronous and
/// thread-safe. Disk I/O and SwiftUI `objectWillChange` notifications dispatch asynchronously.
///
/// **Migration.** ``seedFromUserDefaultsIfNeeded(_:)`` is intended to be invoked once from the
/// host process at launch to populate `config.json` from any pre-existing
/// `UserDefaults.sharedContainerDefaults` values.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Combine
import FileProvider
import SwiftUI
import os.log

/// Identifier for the shared App Group container.
private let appGroupID = AppIdentifiers.appGroupID

/// Darwin notification name posted whenever the config changes.
private let darwinNotificationName = "org.vaultsync.VaultSync.SharedConfig.changed" as CFString

public final class SharedConfigStore: ObservableObject {

    // MARK: - Singleton

    /// The process-wide store. Production never assigns it; test suites replace it with a store
    /// on a private document — see `ConfigIsolatedTestCase`.
    nonisolated(unsafe) public static var shared = SharedConfigStore()

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "SharedConfigStore")

    // MARK: - Storage

    private let url: URL
    private let darwinName: CFString
    private let lock = NSRecursiveLock()
    private var _config: SharedConfig
    private let ioQueue = DispatchQueue(label: "SharedConfigStore.io", qos: .utility)

    // MARK: - Lifecycle

    /// - Parameter namespace: `nil` for the real `config.json`; a token for a private document.
    ///   An isolated store also posts a namespaced Darwin notification, so it never wakes the
    ///   running app to reload a document that is not its own.
    init(namespace: String? = nil) {
        let processName = ProcessInfo.processInfo.processName
        let pid = ProcessInfo.processInfo.processIdentifier
        Self.log.info("🟢 init: process=\(processName, privacy: .public) pid=\(pid)")

        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            Self.log.error("❌ containerURL(forSecurityApplicationGroupIdentifier:) returned nil for group=\(appGroupID, privacy: .public)")
            fatalError("App Group container '\(appGroupID)' unavailable; check entitlements")
        }
        Self.log.info("📦 containerURL=\(containerURL.path, privacy: .public)")

        let supportDir = containerURL.appendingPathComponent("Library/Application Support", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: supportDir, withIntermediateDirectories: true)
        } catch {
            Self.log.error("❌ createDirectory failed: \(error.localizedDescription, privacy: .public)")
        }
        self.url = supportDir.appendingPathComponent(Self.configFileName(namespace))
        self.darwinName = namespace.map { "\(darwinNotificationName as String).\($0)" as CFString }
            ?? darwinNotificationName
        Self.log.info("📄 url=\(self.url.path, privacy: .public)")

        if let loaded = Self.load(from: url) {
            Self.log.info("✅ init load succeeded")
            self._config = loaded
        } else {
            Self.log.error("⚠️ init load returned nil — falling back to default SharedConfig()")
            self._config = SharedConfig()
        }
        subscribeDarwin()
    }

    deinit {
        unsubscribeDarwin()
    }

    /// The document name for `namespace`.
    private static func configFileName(_ namespace: String?) -> String {
        namespace.map { "\($0).config.json" } ?? "config.json"
    }

    // MARK: - Public API

    /// File URL of the persisted JSON document.
    public var configFileURL: URL { url }

    /// Synchronously read a single value from the in-memory snapshot.
    public func read<T>(_ keyPath: KeyPath<SharedConfig, T>) -> T {
        lock.lock(); defer { lock.unlock() }
        return _config[keyPath: keyPath]
    }

    /// Synchronously read the full snapshot.
    public func snapshot() -> SharedConfig {
        lock.lock(); defer { lock.unlock() }
        return _config
    }

    /// Synchronously write a single value. Persists to disk asynchronously and posts a Darwin
    /// notification for peer processes.
    public func write<T: Equatable>(_ keyPath: WritableKeyPath<SharedConfig, T>, _ value: T) {
        mutate { $0[keyPath: keyPath] = value }
    }

    /// Apply an in-place mutation to the snapshot. No-op if the mutation leaves the snapshot
    /// unchanged.
    public func mutate(_ block: (inout SharedConfig) -> Void) {
        lock.lock()
        var updated = _config
        block(&updated)
        guard updated != _config else {
            lock.unlock()
            return
        }
        _config = updated
        lock.unlock()
        publishChange()
        scheduleWrite(updated)
    }

    /// Two-way SwiftUI binding into the snapshot.
    public func binding<T: Equatable>(_ keyPath: WritableKeyPath<SharedConfig, T>) -> Binding<T> {
        Binding(
            get: { self.read(keyPath) },
            set: { self.write(keyPath, $0) }
        )
    }

    // MARK: - Domain accounts

    /// Returns the backend binding for `domain`, or `nil` if the host has not written one.
    public func account(for domain: NSFileProviderDomainIdentifier) -> DomainAccount? {
        read(\.accounts)[domain.rawValue]
    }

    /// All backend bindings keyed by ``NSFileProviderDomainIdentifier.rawValue``.
    public func allAccounts() -> [String: DomainAccount] {
        read(\.accounts)
    }

    /// Writes (or replaces) the backend binding for `domain`. Host-only.
    public func setAccount(_ account: DomainAccount, for domain: NSFileProviderDomainIdentifier) {
        mutate { $0.accounts[domain.rawValue] = account }
    }

    /// Mutates the backend binding for `domain` in place, if one exists. Host-only.
    ///
    /// A read-modify-write on the whole row would drop any field a concurrent writer had just
    /// changed; this narrows the write to what `mutate` actually touches.
    ///
    /// - Parameters:
    ///   - domainIdentifier: The domain whose row is being changed.
    ///   - mutate: Applied to the existing row. Not called when the domain has no row.
    public func updateAccount(_ domainIdentifier: String,
                              _ mutate: (inout DomainAccount) -> Void) {
        self.mutate { config in
            guard var account = config.accounts[domainIdentifier] else { return }
            mutate(&account)
            config.accounts[domainIdentifier] = account
        }
    }

    /// Removes the backend binding for `domain`. Host-only.
    public func removeAccount(for domain: NSFileProviderDomainIdentifier) {
        mutate { $0.accounts.removeValue(forKey: domain.rawValue) }
    }

    // MARK: - Security-scoped bookmarks

    /// Returns the security-scoped bookmark data for `domain`, or `nil` if none is stored.
    public func bookmark(for domain: NSFileProviderDomainIdentifier) -> Data? {
        read(\.bookmarks)[domain.rawValue]
    }

    /// Stores (or replaces) the security-scoped bookmark data for `domain`. Host-only.
    public func setBookmark(_ data: Data, for domain: NSFileProviderDomainIdentifier) {
        mutate { $0.bookmarks[domain.rawValue] = data }
    }

    /// Removes the security-scoped bookmark data for `domain`. Host-only.
    public func removeBookmark(for domain: NSFileProviderDomainIdentifier) {
        mutate { $0.bookmarks.removeValue(forKey: domain.rawValue) }
    }

    // MARK: - Per-domain teardown

    /// Removes **all** per-domain configuration for `domain` in a single atomic mutation:
    /// account binding, security-scoped bookmark, shared secret, offline flag, archived
    /// domain version, feature flags, crypto config, thumbnail-upload flag, and suppressed
    /// user-interaction identifiers.
    ///
    /// Used by ``DomainDeprovisioningService`` on domain deletion. Host-only. Idempotent —
    /// keys that are absent are left untouched.
    public func removeAllConfiguration(for domain: NSFileProviderDomainIdentifier) {
        let key = domain.rawValue
        mutate { config in
            config.accounts.removeValue(forKey: key)
            config.bookmarks.removeValue(forKey: key)
            config.secrets.removeValue(forKey: key)
            config.offline.removeValue(forKey: key)
            config.configEpoch.removeValue(forKey: key)
            config.featureFlag.removeValue(forKey: key)
            config.cryptoConfig.removeValue(forKey: key)
            config.thumbnailUpload.removeValue(forKey: key)
            config.userInteractionSuppressedIdentifiers.removeValue(forKey: key)
            config.cancelGeneration.removeValue(forKey: key)
        }
    }

    // MARK: - Migration

    /// One-shot seeding from legacy ``UserDefaults.sharedContainerDefaults`` values. Safe to
    /// call multiple times — fields already present in the snapshot are preserved.
    public func seedFromUserDefaultsIfNeeded(_ defaults: UserDefaults) {
        mutate { config in
            if config.hostname.isEmpty, let host = defaults.string(forKey: "hostname") {
                config.hostname = host
            }
            if config.secrets.isEmpty,
               let raw = defaults.dictionary(forKey: "secrets") as? [String: String] {
                config.secrets = raw
            }
            if config.offline.isEmpty,
               let raw = defaults.dictionary(forKey: "offline") as? [String: Bool] {
                config.offline = raw
            }
            if config.configEpoch.isEmpty,
               let raw = defaults.dictionary(forKey: "configEpoch") as? [String: Int] {
                config.configEpoch = raw
            }
            if config.featureFlag.isEmpty,
               let raw = defaults.dictionary(forKey: "featureFlag") as? [String: [String: Bool]] {
                config.featureFlag = raw
            }
            if config.userInteractionSuppressedIdentifiers.isEmpty,
               let raw = defaults.dictionary(forKey: "userInteractionSuppressedIdentifiers")
                as? [String: [String]] {
                config.userInteractionSuppressedIdentifiers = raw
            }
            if config.blockedProcesses.isEmpty,
               let raw = defaults.stringArray(forKey: "blockedProcesses") {
                config.blockedProcesses = raw
            }
            if defaults.object(forKey: "syncChildrenBeforeParentMove") != nil {
                config.syncChildrenBeforeParentMove = defaults.bool(forKey: "syncChildrenBeforeParentMove")
            }
        }
    }

    // MARK: - Private

    private func publishChange() {
        if Thread.isMainThread {
            objectWillChange.send()
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.objectWillChange.send()
            }
        }
    }

    private func scheduleWrite(_ snapshot: SharedConfig) {
        ioQueue.async { [url, darwinName] in
            guard let data = try? Self.encoder.encode(snapshot) else { return }
            Self.coordinatedWrite(data, to: url)
            Self.postDarwinChange(darwinName)
        }
    }

    /// Blocks until every write queued so far has reached disk.
    func drainPendingWrites() {
        ioQueue.sync {}
    }

    private func reloadFromDisk() {
        guard let fresh = Self.load(from: url) else { return }
        lock.lock()
        let changed = fresh != _config
        if changed {
            _config = fresh
        }
        lock.unlock()
        if changed {
            publishChange()
        }
    }

    // MARK: - JSON I/O

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()

    private static let decoder = JSONDecoder()

    private static func load(from url: URL) -> SharedConfig? {
        let fm = FileManager.default
        let exists = fm.fileExists(atPath: url.path)
        let isReadable = fm.isReadableFile(atPath: url.path)
        let size = (try? fm.attributesOfItem(atPath: url.path)[.size] as? Int) ?? -1
        log.info("🔎 load: path=\(url.path, privacy: .public) exists=\(exists) readable=\(isReadable) size=\(size)")

        guard exists else {
            log.error("❌ load: file does not exist at expected path")
            return nil
        }

        var data: Data?
        var readError: Error?
        var coordError: NSError?
        let coordStart = Date()
        NSFileCoordinator().coordinate(readingItemAt: url, options: .withoutChanges, error: &coordError) { coordURL in
            log.info("🔁 coordinator entered block; coordURL=\(coordURL.path, privacy: .public)")
            do {
                data = try Data(contentsOf: coordURL)
            } catch {
                readError = error
            }
        }
        let coordElapsed = Date().timeIntervalSince(coordStart)
        log.info("⏱️ coordinator elapsed=\(coordElapsed, privacy: .public)s")

        if let coordError {
            log.error("❌ NSFileCoordinator error: domain=\(coordError.domain, privacy: .public) code=\(coordError.code) desc=\(coordError.localizedDescription, privacy: .public)")
        }
        if let readError {
            log.error("❌ Data(contentsOf:) error: \(readError.localizedDescription, privacy: .public)")
        }

        guard let data else {
            log.error("❌ load: no data obtained (coordError=\(coordError != nil), readError=\(readError != nil))")
            return nil
        }
        log.info("📥 load: read bytes=\(data.count)")

        do {
            let cfg = try decoder.decode(SharedConfig.self, from: data)
            log.info("✅ load: decode succeeded")
            return cfg
        } catch {
            log.error("❌ decode failed: \(error.localizedDescription, privacy: .public)")
            if let preview = String(data: data.prefix(512), encoding: .utf8) {
                log.error("📄 raw prefix: \(preview, privacy: .public)")
            }
            return nil
        }
    }

    private static func coordinatedWrite(_ data: Data, to url: URL) {
        var coordError: NSError?
        NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &coordError) { coordURL in
            do {
                try data.write(to: coordURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o644],
                                                       ofItemAtPath: coordURL.path)
            } catch {
                log.error("❌ coordinatedWrite failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        if let coordError {
            log.error("❌ write coord error: \(coordError.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Darwin notifications

    private static func postDarwinChange(_ name: CFString) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(name),
            nil, nil, true)
    }

    private func subscribeDarwin() {
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            { _, observer, _, _, _ in
                guard let observer else { return }
                let store = Unmanaged<SharedConfigStore>.fromOpaque(observer).takeUnretainedValue()
                store.reloadFromDisk()
            },
            darwinName,
            nil,
            .deliverImmediately)
    }

    private func unsubscribeDarwin() {
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterRemoveEveryObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer)
    }
}

// MARK: - ConfigStore conformance

/// ``SharedConfigStore`` is the production ``ConfigStore``: an App-Group JSON-backed,
/// cross-process store. The protocol exposes only the raw load/save/mutate seam so call
/// sites and tests can depend on the abstraction rather than the concrete store.
extension SharedConfigStore: ConfigStore {
    /// The current configuration snapshot.
    public func load() -> SharedConfig { snapshot() }

    /// Replace the entire configuration, persisting and notifying peers.
    public func save(_ config: SharedConfig) { mutate { $0 = config } }
}
