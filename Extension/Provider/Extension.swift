/// Core NSFileProviderReplicatedExtension implementation
//
//  Abstract:
//  The main entry point for the file-syncing extension.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import Common
import Combine
import CoreServices
import QuickLookThumbnailing
import UniformTypeIdentifiers
import os.log
import PushKit


public class Extension: NSObject, NSFileProviderReplicatedExtension {
    let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "extension")

    @objc(_initializedByViewServices)
    static let _initializedByViewServices = true

    /// The backend servicing this domain's content and enumeration, resolved from the
    /// host-owned `SharedConfig` binding via ``BackendFactory``. Defaults to `.emulator`.
    ///
    /// Resolution can throw for backends not yet wired; ``backend`` traps in that case
    /// because every call site historically assumed a live connection. Operations that
    /// must fail gracefully use ``resolveBackend()``.
    var backend: ProviderBackend {
        try! resolveBackend()
    }

    /// Memoised backend for this domain. One ``Extension`` services one domain for its
    /// lifetime, so the backend (and its in-memory caches: metadata DB handle, resolved
    /// root id, in-flight resolution coalescing) must persist across FP service calls
    /// rather than being rebuilt per `item()`/`download()`/`enumerator()`. Guarded by
    /// ``backendLock`` because FP drives requests from multiple threads concurrently.
    var cachedBackend: ProviderBackend?
    let backendLock = NSLock()

    /// Periodic background delta poller for remote-change detection, started lazily for
    /// polling-capable backends (OneDrive) when the backend is first resolved and stopped
    /// in ``invalidate()``. See ``DeltaPoller``.
    var deltaPoller: DeltaPoller?

    /// Set once ``invalidate()`` runs, and never cleared: the OS is tearing this instance down
    /// and it must start no further background work.
    ///
    /// `invalidate()` nils ``cachedBackend`` and ``deltaPoller``, which is exactly the state a
    /// *fresh* instance is in — so without this flag a late call into a torn-down extension is
    /// indistinguishable from a first call, and ``resolveBackend()`` rebuilds the backend and
    /// restarts the poller against a vault that has just been locked. Guarded by ``backendLock``.
    var isInvalidated = false

    /// Coalesces per-file `.workingSet` signals emitted during a bulk encrypt/decrypt action.
    /// Each signal triggers a full recursive `enumerateChanges($root)` sweep; firing one per
    /// file caused an enumerate storm. `workingSetSignalThrottle` leads with an immediate
    /// signal, then rate-limits to one per second with a trailing signal so the last trash is
    /// never dropped. See ``signalWorkingSetNow``.
    let workingSetThrottle = SignalThrottle(minInterval: 1.0)

    /// Backend servicing this domain, read from the host-owned `SharedConfig` binding.
    /// Defaults to `.emulator` when no binding is present yet.
    var backendKind: BackendKind {
        SharedConfigStore.shared.account(for: domain.identifier)?.backendKind ?? .emulator
    }

    /// Resolve the backend for this domain, throwing ``CommonError/notImplemented`` for
    /// backends not yet wired (LocalFS).
    func resolveBackend() throws -> ProviderBackend {
        backendLock.lock()
        defer { backendLock.unlock() }
        if let cachedBackend { return cachedBackend }
        let backend = try BackendFactory.make(for: domain, hostname: hostname, port: port)
        cachedBackend = backend
        // A torn-down instance may still be called; serve the request, but never revive the
        // background work `invalidate()` just stopped.
        startPollersIfNeeded(for: backend)
        return backend
    }

    /// Start the background poller the first time a polling-capable backend is resolved.
    /// Gated to OneDrive so we don't spin pointless timers for the emulator (which inherits
    /// the no-op `pollDelta`). Caller holds ``backendLock``.
    private func startPollersIfNeeded(for backend: ProviderBackend) {
        guard !isInvalidated, backendKind == .oneDrive, deltaPoller == nil else { return }
        startDeltaPoller(for: backend)
    }

    /// Build and start the periodic delta poller, and wire the per-page crawl progress hook
    /// that signals what each delta page changed. A completion-crawling pass returns once, so
    /// the per-page hook is the only channel that can signal or publish progress while a large
    /// initial crawl is still running. Caller holds ``backendLock``.
    private func startDeltaPoller(for backend: ProviderBackend) {
        let graph = backend as? GraphDriveClient
        let manager = self.manager
        let domainID = domain.identifier
        let workingSetThrottle = self.workingSetThrottle
        // The indexed count and crawl progress are published by the backend itself, per page.
        graph?.onDeltaProgress = { progress in
            guard progress.changed else { return }
            // The working set is the replicated extension's remote-change feed: signalling it
            // drives `WorkingSetEnumerator.enumerateChanges(from:)`, which delivers the changed
            // items themselves without depending on any parent folder's `itemVersion` changing
            // (OneDrive does not bump a folder's eTag when a child is added). Throttled —
            // ~150 pages on a large drive would otherwise be ~150 recursive enumeration sweeps.
            workingSetThrottle.request {
                Task { try? await manager.signalEnumerator(for: .workingSet) }
            }
            // Container signals are not throttled: far lower volume, and a container signal
            // only refreshes a folder the user already has open, so dropping one is a visible
            // staleness bug rather than saved work.
            //for container in progress.changedParentIdentifiers.sorted(by: { $0.id < $1.id }) {
            //    try? await manager.signalEnumerator(for: NSFileProviderItemIdentifier(container.id))
            //}
        }
        let poller = DeltaPoller(backend: backend, domainID: domainID,
                                 manager: manager,
                                 workingSetThrottle: workingSetThrottle,
                                 log: logger)
        deltaPoller = poller
        Task { await poller.start() }
    }

    /// Ensure a backend is resolvable for this domain before driving an operation that
    /// assumes a live connection. Replaces the former `requireBackend()` guard;
    /// routing is now the factory's job, so this only surfaces not-yet-wired backends.
    @discardableResult
    func requireBackend() throws -> ProviderBackend {
        try resolveBackend()
    }

    let port: in_port_t
    let hostname: String
    let queue = DispatchQueue(label: "completion queue")
    let domain: NSFileProviderDomain
    var manager: NSFileProviderManager
    var blockedProcessesCancellable: AnyCancellable?

    /// Watches for host cancellation requests and winds down in-flight work.
    var cancellationCoordinator: ProviderCancellationCoordinator?

    required public init(domain: NSFileProviderDomain) {
        self.domain = domain
        port = domain.identifier.port ?? defaultPort
        hostname = UserDefaults.sharedContainerDefaults.hostname
        manager = NSFileProviderManager(for: domain)!
        logger.infoPublic("➡️  init(domain: \(domain.identifier.rawValue)) displayName(\(domain.displayName))")

        do {
            temporaryDirectoryURL = try manager.temporaryDirectoryURL()
        } catch {
            fatalError("failed to get temporary directory: \(error)")
        }
        super.init()

        // Track blocked-process changes through SharedConfigStore. The store reloads on
        // Darwin notifications posted by the host, then emits objectWillChange.
        let applyBlocked: () -> Void = {
            let blocked = SharedConfigStore.shared.read(\.blockedProcesses)
            UserDefaults().setValue(blocked, forKey: "NSFileProviderExtensionNonMaterializingProcessNames")
        }
        applyBlocked()
        blockedProcessesCancellable = SharedConfigStore.shared.objectWillChange
            .receive(on: DispatchQueue.main)
            .sink { _ in applyBlocked() }

        // Graceful teardown: the host bumps `cancelGeneration` before locking-and-removing this
        // vault, and waits for the acknowledgement written back through `ProgressStore`.
        let domainIdentifier = domain.identifier
        let coordinator = ProviderCancellationCoordinator(
            domainID: domainIdentifier.rawValue,
            readGeneration: {
                UserDefaults.sharedContainerDefaults.cancelGeneration(for: domainIdentifier)
            },
            report: { state, generation in
                ProgressStore.shared.reportState(state,
                                                 for: domainIdentifier.rawValue,
                                                 generation: generation)
            },
            stopWork: { [weak self] in await self?.stopBackgroundWork() }
        )
        cancellationCoordinator = coordinator
        coordinator.start(publisher: SharedConfigStore.shared.objectWillChange
            .receive(on: DispatchQueue.main)
            .eraseToAnyPublisher())
    }

    let temporaryDirectoryURL: URL

    func makeTemporaryURL(_ purpose: String, _ ext: String? = nil) -> URL {
        if let ext = ext {
            return temporaryDirectoryURL.appendingPathComponent("\(purpose)-\(UUID().uuidString).\(ext)")
        } else {
            return temporaryDirectoryURL.appendingPathComponent("\(purpose)-\(UUID().uuidString)")
        }
    }
}


extension Extension {
    func uploadThumbnail(item: DomainService.Entry,
                         originalContentType: UTType?,
                         url: URL,
                         remainingFields: NSFileProviderItemFields)
                            async throws -> (NSFileProviderItem?, NSFileProviderItemFields, Bool) {
        // Only attempt to upload thumbnails for files.
        guard item.type == .file else {
            return (displayItem(item), remainingFields, false)
        }

        // Per-domain opt-in. Never upload for encrypted domains: the thumbnail is
        // generated from the local plaintext and would leak content past the encryption
        // boundary if pushed to the backend.
        let cryptoConfig = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)
        let thumbnailUpload = UserDefaults.sharedContainerDefaults.thumbnailUpload(for: domain.identifier)
        guard thumbnailUpload else {
            logger.debugPublic("🖼️ thumbnail upload disabled for domain \(self.domain.identifier.rawValue); skipping \(item.id.id)")
            return (displayItem(item), remainingFields, false)
        }
        guard cryptoConfig.algorithm == .plain else {
            logger.infoPublic("🔒 encrypted domain: skipping thumbnail upload for \(item.id.id) (would leak plaintext)")
            return (displayItem(item), remainingFields, false)
        }

        let request = QLThumbnailGenerator.Request(fileAt: url, size: CGSize(width: 128, height: 128), scale: 2.0, representationTypes: [.thumbnail])
        if let originalContentType = originalContentType {
            request.contentType = originalContentType
        }

        let tempURL = makeTemporaryURL("quickLookOutput", "jpeg")
        do {
            try await QLThumbnailGenerator.shared.saveBestRepresentation(for: request, to: tempURL, contentType: UTType.jpeg.identifier)
        } catch {
            return (displayItem(item), remainingFields, false)
        }
        defer { try? FileManager().removeItem(at: tempURL) }
        defer {
            let mgr = FileManager()
            try? mgr.removeItem(at: tempURL)
        }

        guard let thumbnailData = try? Data(contentsOf: tempURL, options: .alwaysMapped) else {
            return (displayItem(item), remainingFields, false)
        }
        let param = DomainService.UpdateThumbnailParameter(identifier: item.id, existingRevision: item.revision)
        do {
            logger.infoPublic("🖼️⬆️ uploading thumbnail to remote for \(item.id.id) (\(thumbnailData.count) bytes)")
            let resp = try await self.backend.updateThumbnail(param, data: thumbnailData)
            logger.infoPublic("🖼️✅ thumbnail uploaded to remote for \(item.id.id)")
            return (displayItem(resp.item), remainingFields, false)
        } catch {
            logger.errorPublic("🖼️❌ thumbnail upload failed for \(item.id.id): \(String(describing: error))")
            return (displayItem(item), remainingFields, false)
        }
    }


    func uploadResourceFork(item: DomainService.Entry, fork forkArg: Data?, changedFields: NSFileProviderItemFields,
                                    updateResourceForkOnConflictedItem: Bool, contentType: UTType?, url: URL,
                                    parentProgress: Progress) async throws -> (NSFileProviderItem?, NSFileProviderItemFields, Bool) {
        // Backends with no fork store (OneDrive, etc.) must never receive fork bytes — a
        // `.resourceFork` PUT would land on the item's main content and corrupt it. Treat the
        // fork as absent for those backends; macOS keeps the local fork itself, so nothing is lost.
        let fork = backend.supportsResourceFork ? forkArg : nil
        guard let fork = fork else {
            if !updateResourceForkOnConflictedItem {
                return try await self.uploadThumbnail(item: item,
                                                      originalContentType: contentType,
                                                      url: url,
                                                      remainingFields: [])
            } else {
                return (displayItem(item), [], true)
            }
        }

        let contentStorageType: DomainService.ContentStorageType = .resourceFork
        let modifyContentsParameter = DomainService.ModifyContentsParameter(identifier: item.id,
                                                                            existingRevision: item.revision,
                                                                            contentStorageType: contentStorageType,
                                                                            updateResourceForkOnConflictedItem: updateResourceForkOnConflictedItem)
        return try await withCheckedThrowingContinuation { continuation in
            let callProgress = backend.modifyContents(modifyContentsParameter, data: fork) { res in
                switch res {
                case .success:
                    if !updateResourceForkOnConflictedItem {
                        Task {
                            let result = try await self.uploadThumbnail(item: item,
                                                                        originalContentType: contentType,
                                                                        url: url,
                                                                        remainingFields: [])
                            continuation.resume(returning: result)
                            return
                        }
                    } else {
                        continuation.resume(returning: (self.displayItem(item), [], true))
                        return
                    }
                case .failure(let error):
                    continuation.resume(throwing: error.toPresentableError())
                }
            }
            parentProgress.addChild(callProgress, withPendingUnitCount: 10)
        }
    }
}

extension Extension {
    /// Called when the set of *materialized* items changes — items whose contents are
    /// actually on disk (downloaded or pinned), not just placeholders.
    ///
    /// Usage: keep a server-side or local subscription list in sync with what the user
    /// physically has — subscribe to push notifications only for materialized items,
    /// narrow delta-sync scope, drive eviction policy, or recompute local disk usage.
    /// Enumerate `NSFileProviderManager.enumeratorForMaterializedItems()` from here.
    ///
    /// Placeholder no-op.
    public func materializedItemsDidChange(completionHandler: @escaping () -> Void) {
        logger.infoPublic("➡️  materializedItemsDidChange()")
        completionHandler()
    }

    /// Called when the set of items with *unsynced local changes* changes — uploads
    /// queued, sync errors, or items excluded from sync.
    ///
    /// Usage: surface upload/sync state in UI (badge counts, "N items waiting", error
    /// banners in the menu-bar app), or detect stuck/errored items for retry. Enumerate
    /// `NSFileProviderManager.enumeratorForPendingItems()`, which also exposes
    /// `domainVersion` and per-item errors.
    ///
    /// Placeholder no-op.
    public func pendingItemsDidChange(completionHandler: @escaping () -> Void) {
        logger.infoPublic("➡️  pendingItemsDidChange()")
        completionHandler()
    }

    /// Called once, when the OS finishes the initial *import* of pre-existing on-disk
    /// content into the domain — the migration pass that runs when a domain is created
    /// over an existing folder, or when a bulk import completes.
    ///
    /// Usage: gate work that must not start until every local file has an identifier and
    /// has been pushed — begin delta polling, clear a "setting up" UI state, trigger the
    /// first full reconcile.
    ///
    /// No-op here: domains in this extension start empty, so there is no import phase to
    /// wait on.
    public func importDidFinish(completionHandler: @escaping () -> Void) {
        logger.infoPublic("➡️  importDidFinish()")
        completionHandler()
    }
}
