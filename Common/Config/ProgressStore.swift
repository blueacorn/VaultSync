/// Cross-process progress relay: Provider → App.
///
/// The sandboxed `Provider.appex` cannot IPC to `VaultSync.app` beyond the App Group
/// container and `DistributedNotificationCenter`. This store persists a small per-domain
/// ``ProgressSnapshot`` JSON blob in the App Group container and posts a coalesced
/// ``NSNotification/Name/progressDidChange`` after each write. The app observes the
/// notification, reads the snapshot, and publishes it into its menu-bar UI model.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import os.log

public extension NSNotification.Name {
    /// Posted (via ``DistributedNotificationCenter``) when a domain's progress snapshot
    /// changes. `object` carries the domain identifier's `rawValue`.
    static let progressDidChange =
        NSNotification.Name(rawValue: "org.vaultsync.VaultSync.Progress.DidChange")
}

/// A single in-flight crypto operation (encrypt or decrypt) for the detail view.
public struct CryptoOp: Codable, Equatable, Identifiable, Sendable {
    public enum Direction: String, Codable, Sendable { case encrypt, decrypt }

    /// Stable per-operation identity (the item identifier being processed).
    public var id: String
    public var name: String
    public var direction: Direction
    /// `nil` until the plaintext size is known (BC01 header parse — the total is
    /// indeterminate before that, see `[[plaintext-size-from-decrypt-not-estimate]]`).
    public var fractionCompleted: Double?

    public init(id: String, name: String, direction: Direction, fractionCompleted: Double?) {
        self.id = id
        self.name = name
        self.direction = direction
        self.fractionCompleted = fractionCompleted
    }
}

/// What the Provider is currently doing for a domain.
///
/// Reported by the Provider so the app can distinguish "idle" from "still winding down".
/// ``cancelled`` is the acknowledgement the app waits for before tearing down a domain's local
/// data — it is self-describing, needing no reference to which request produced it: a Provider
/// that is still running replaces it the moment it observes a new request, and one that restarts
/// reports ``idle``/``active``. A ``cancelled`` left on disk by a Provider that is no longer
/// running is simply true.
public enum ProviderState: String, Codable, Sendable {
    /// No long-running work in flight.
    case idle
    /// Sync / crypto / transfer work is running.
    case active
    /// A cancellation has been observed and in-flight work is being wound down.
    case cancelling
    /// All in-flight work has stopped; safe to tear down local data.
    case cancelled
}

/// Per-domain progress figures the OS enumerators do not surface.
public struct ProgressSnapshot: Codable, Equatable, Sendable {
    /// Live (non-tombstoned) item count from the OneDrive `MetadataCache`.
    public var indexedCount: Int
    /// When ``indexedCount`` was last computed.
    public var indexedCountUpdatedAt: Date
    /// Items a full crawl (first crawl, cursor expiry, Rebuild Index) has scanned so far in the
    /// current pass; `nil` when no full crawl is in progress. While set, ``indexedCount`` still
    /// holds the pre-crawl rows and is not a progress figure.
    public var fullCrawlItemsSeen: Int?
    /// Currently active crypto operations.
    public var cryptoOps: [CryptoOp]
    /// What the Provider is currently doing.
    public var providerState: ProviderState
    /// The `SharedConfig.cancelGeneration` value ``providerState`` refers to.
    ///
    /// Without it a `.cancelled` left behind by an earlier lock/unlock cycle reads as an
    /// acknowledgement of the *current* request, and the host tears the domain down while the
    /// Provider is still live. Pairing the state with the generation it answers makes a stale
    /// reply non-matching, so no reset to `.idle` is needed anywhere.
    public var cancelAckGeneration: Int

    public init(indexedCount: Int = 0,
                indexedCountUpdatedAt: Date = .distantPast,
                fullCrawlItemsSeen: Int? = nil,
                cryptoOps: [CryptoOp] = [],
                providerState: ProviderState = .idle,
                cancelAckGeneration: Int = 0) {
        self.indexedCount = indexedCount
        self.indexedCountUpdatedAt = indexedCountUpdatedAt
        self.fullCrawlItemsSeen = fullCrawlItemsSeen
        self.cryptoOps = cryptoOps
        self.providerState = providerState
        self.cancelAckGeneration = cancelAckGeneration
    }

    // Decoded leniently: older snapshots carry no provider state.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        indexedCount = try c.decodeIfPresent(Int.self, forKey: .indexedCount) ?? 0
        indexedCountUpdatedAt = try c.decodeIfPresent(Date.self, forKey: .indexedCountUpdatedAt) ?? .distantPast
        fullCrawlItemsSeen = try c.decodeIfPresent(Int.self, forKey: .fullCrawlItemsSeen)
        cryptoOps = try c.decodeIfPresent([CryptoOp].self, forKey: .cryptoOps) ?? []
        providerState = try c.decodeIfPresent(ProviderState.self, forKey: .providerState) ?? .idle
        cancelAckGeneration = try c.decodeIfPresent(Int.self, forKey: .cancelAckGeneration) ?? 0
    }
}

/// Reads/writes per-domain ``ProgressSnapshot`` JSON in the App Group container and posts
/// the coalesced change notification. Safe for concurrent access across processes: writes
/// are atomic file replacements; the notification is the freshness signal.
public final class ProgressStore: @unchecked Sendable {
    public static let shared = ProgressStore()

    private static let appGroupID = AppIdentifiers.appGroupID
    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "progress-store")
    private let lock = NSLock()
    private let directory: URL?

    public init() {
        let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupID)
        guard let container else {
            log.error("❌ App Group container '\(Self.appGroupID, privacy: .public)' unavailable - no progress update")
            self.directory = nil
            return
        }
        let dir = container.appendingPathComponent("Library/Application Support/Progress",
                                                   isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            log.error("❌ failed to create progress directory at \(dir.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
        self.directory = dir
    }

    private func fileURL(for domainID: String) -> URL? {
        // Sanitise the domain id (a UUID string) into a safe file name.
        let safe = domainID.replacingOccurrences(of: "/", with: "_")
        return directory?.appendingPathComponent("\(safe).json")
    }

    /// Read the snapshot for a domain, or an empty snapshot if none is stored.
    public func snapshot(for domainID: String) -> ProgressSnapshot {
        lock.lock(); defer { lock.unlock() }
        guard let url = fileURL(for: domainID),
              let data = try? Data(contentsOf: url),
              let snapshot = try? JSONDecoder.progress.decode(ProgressSnapshot.self, from: data)
        else { return ProgressSnapshot() }
        return snapshot
    }

    /// Write the snapshot for a domain and post ``NSNotification/Name/progressDidChange``.
    public func write(_ snapshot: ProgressSnapshot, for domainID: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let url = fileURL(for: domainID) else { return }
        do {
            let data = try JSONEncoder.progress.encode(snapshot)
            try data.write(to: url, options: .atomic)
        } catch {
            log.error("❌ progress snapshot write failed: \(error.localizedDescription)")
            return
        }
        DistributedNotificationCenter.default().postNotificationName(
            .progressDidChange, object: domainID, userInfo: nil, deliverImmediately: true)
    }

    /// Delete a domain's stored snapshot and post ``NSNotification/Name/progressDidChange``.
    ///
    /// The inverse of ``write(_:for:)``, for deprovisioning: a removed domain's JSON would
    /// otherwise persist in the App Group container indefinitely, and a domain identifier
    /// reissued to a new account would inherit the stale progress. Absent files are not an
    /// error, so this is safe to call unconditionally.
    ///
    /// - Parameter domainID: The domain whose snapshot to remove.
    public func remove(for domainID: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let url = fileURL(for: domainID) else { return }
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            return                                  // nothing stored: already in the target state
        } catch {
            log.error("❌ progress snapshot remove failed: \(error.localizedDescription)")
            return
        }
        DistributedNotificationCenter.default().postNotificationName(
            .progressDidChange, object: domainID, userInfo: nil, deliverImmediately: true)
    }

    /// Report the Provider's current state.
    ///
    /// The Provider→app half of the cancellation handshake: the app requests
    /// cancellation by bumping `SharedConfig.cancelGeneration` and waits here for
    /// ``ProviderState/cancelled`` *carrying that same generation*.
    ///
    /// - Parameters:
    ///   - state: The state to publish.
    ///   - generation: The cancellation generation `state` answers, for the cancellation states.
    ///     Omitted for spontaneous `.idle` / `.active` reports, which answer no request and so
    ///     leave the recorded acknowledgement untouched.
    public func reportState(_ state: ProviderState,
                            for domainID: String,
                            generation: Int? = nil) {
        update(domainID: domainID) {
            $0.providerState = state
            if let generation { $0.cancelAckGeneration = generation }
        }
    }

    /// Mutate the stored snapshot in place (read-modify-write) and persist + signal.
    public func update(domainID: String, _ mutate: (inout ProgressSnapshot) -> Void) {
        var current = snapshot(for: domainID)
        mutate(&current)
        write(current, for: domainID)
    }
}

private extension JSONEncoder {
    static let progress: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()
}

private extension JSONDecoder {
    static let progress: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
