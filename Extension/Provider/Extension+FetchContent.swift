/// Full file content fetching for the file provider extension.
///
/// Implements whole-file (`fetchContents`) materialisation and its helpers — the inline
/// download path and resource-fork handling — split out of `Extension.swift`. The
/// incremental chunk-store path lives in `Extension+IncrementalFetch.swift`; byte-range
/// materialisation lives in `Extension+FetchPartialContent.swift`.
// Copyright (c) 2024 Apple Inc.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import FileProvider
import Common
import os.log

extension Extension {
    public func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier,
                              version requestedVersion: NSFileProviderItemVersion?,
                              request: NSFileProviderRequest,
                              completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress
    {
        logger.debugPublic("➡️  fetchContents(for:\(itemIdentifier.rawValue)) @ domainVersion(\(request.domainVersion?.description ?? "<nil>"))")
        do { try requireBackend() } catch {
            completionHandler(nil, nil, error)
            return Progress()
        }

        return fetchContentsInternal(for: itemIdentifier,
                                     version: requestedVersion,
                                     range: nil,
                                     request: request,
                                     alignment: 0,
                                     completionHandler: { (url: URL?, item: NSFileProviderItem?, _, error: Error?) -> Void in
            completionHandler(url, item, error)
        })
    }

    func fetchContentsInternal(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        range: NSRange?,
        request: NSFileProviderRequest,
        alignment: Int,
        completionHandler: @escaping (URL?, NSFileProviderItem?, NSRange?,
                                      Error?) -> Void) -> Progress {

        // The download child owns every unit, so the returned fraction IS the download's
        // whole-file-relative position (a ranged fetch from 50% starts at 50%). Item lookup and
        // resource-fork steps are near-instant and carry no units.
        let progress = Progress(totalUnitCount: 100)

        let itemProgress = self.itemInternal(for: itemIdentifier) { itemOptional, errorOptional in
            if let error = errorOptional as NSError? {
                self.logger.errorPublic("Error calling item for identifier \"\(String(describing: itemIdentifier))\": \(error)")
                completionHandler(nil, nil, nil, error)
                return
            }

            guard let item = itemOptional else {
                self.logger.errorPublic("Could not find item metadata, identifier: \(String(describing: itemIdentifier))")
                completionHandler(nil, nil, nil, CommonError.internalError)
                return
            }

            guard let itemCasted = item as? Item else {
                self.logger.errorPublic("Could not cast item to Item class, identifier: \(String(describing: itemIdentifier))")
                completionHandler(nil, nil, nil, CommonError.internalError)
                return
            }

#if os(macOS)
            // Check the version when doing a partial content fetch to avoid mixing contents from different file versions.
            // Compare content identity only: the `|p<size>` plaintext-size stamp is derived, not identity.
            if let requestedVersion {
                guard DomainService.Version(requestedVersion).contentIdentity
                        == DomainService.Version(itemCasted.itemVersion).contentIdentity else {
                    self.logger.errorPublic("⚠️ requestedVersion (\(String(describing: requestedVersion))) != item.itemVersion (\(String(describing: item.itemVersion)))")
                    completionHandler(nil, nil, nil, NSFileProviderError(.versionNoLongerAvailable))
                    return
                }
            }
#endif

            let requestedRange = range
            let internalCompletionHandler = { (url: URL?, item: NSFileProviderItem?,
                                               range: NSRange?,
                                               error: Error?) -> Void in
                // Honour `alignment` on the reply: the backend reports the window it decrypted
                // (crypto-block aligned), which need not match the system's alignment.
                var range = range
                if error == nil, let requestedRange, let window = range,
                   let documentSize = item?.documentSize??.intValue {
                    guard let aligned = FetchRangeAlignment.alignedReply(
                        window, covering: requestedRange, alignment: alignment, documentSize: documentSize) else {
                        self.logger.errorPublic("⚠️ fetch reply cannot be aligned id=\(itemIdentifier.rawValue) window=(\(window.location),\(window.length)) requested=(\(requestedRange.location),\(requestedRange.length)) alignment=\(alignment) documentSize=\(documentSize)")
                        completionHandler(nil, nil, nil, CommonError.internalError)
                        return
                    }
                    range = aligned
                }
                // Diagnostics, logged only on a content-version mismatch of a successful reply:
                // the reply corrected the plaintext size (`|p<size>` stamp). A failed reply has no
                // version and is logged by the failure path. Only the stamp is shown.
                let req = requestedVersion.map(DomainService.Version.init)
                let ret = item?.itemVersion.map(DomainService.Version.init)
                if error == nil, let req, req.content != ret?.content {
                    let entry = DomainService.Version(itemCasted.itemVersion)
                    self.logger.warningPublic("""
                        ⚠️ fetch reply version mismatch id=\(itemIdentifier.rawValue) \
                        req=\(req.plaintextSizeStamp ?? "-") entry=\(entry.plaintextSizeStamp ?? "-") \
                        ret=\(ret?.plaintextSizeStamp ?? "-") range=\(range.map { "(\($0.location),\($0.length))" } ?? "nil")\
                        \(error.map { " error=\($0)" } ?? "")
                        """)
                }
                let forkProgress = self.fetchResourceFork(sourceItem: itemCasted, url: url, item: item, error: error,
                                                          completionHandler: { (url: URL?, item: NSFileProviderItem?, error: Error?) -> Void in
                    completionHandler(url, item, range, error)
                })
                if let forkProgress = forkProgress {
                    progress.addChild(forkProgress, withPendingUnitCount: 0)
                }
            }

            // Adjust the range, if necessary.
            var extent: NSRange?
            let fileSize = item.documentSize??.intValue
            if let requestedRange = range, let fileSize {
                extent = self.adjustRequestedRange(requestedRange: requestedRange, alignment: alignment,
                                                   fileSize: fileSize, request: request)
            }

            let downloadProgress = Progress(totalUnitCount: 1)
            let fetchContentsProgress = self.fetchContentsInline(
                for: itemIdentifier,
                version: requestedVersion,
                range: extent,
                request: request,
                downloadProgress: downloadProgress,
                completionHandler: internalCompletionHandler)
            progress.addChild(fetchContentsProgress, withPendingUnitCount: 100)
        }

        progress.addChild(itemProgress, withPendingUnitCount: 0)
        progress.cancellationHandler = { completionHandler(nil, nil, nil, NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }

        return progress
    }

    func fetchContentsInline(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        range: NSRange?,
        request: NSFileProviderRequest,
        downloadProgress: Progress = Progress(totalUnitCount: 1),
        completionHandler: @escaping (URL?, NSFileProviderItem?, NSRange?, Error?) -> Void) -> Progress {

        let param: DomainService.DownloadItemParameter
        if let version = requestedVersion {
            param = DomainService.DownloadItemParameter(itemIdentifier: DomainService.ItemIdentifier(itemIdentifier),
                                                        requestedRevision: DomainService.Version(version),
                                                        range: range)
        } else {
            param = DomainService.DownloadItemParameter(itemIdentifier: DomainService.ItemIdentifier(itemIdentifier),
                                                        requestedRevision: nil,
                                                        range: range)
        }

        // Single pipeline for whole-file AND explicit byte-range (BRM/partial) fetches: the
        // backend writes the plaintext file (or the requested plaintext window) to `dataURL`,
        // decrypting at offsets itself. The final plaintext length comes from the backend's
        // post-decrypt on-disk size — the enumeration size estimate (which can't know BC01
        // padding) is never relied upon.
        let dataURL = self.makeTemporaryURL("fetchedContents")
        let backendProgress = backend.downloadToFile(param, destinationURL: dataURL, progress: downloadProgress) { result in
            switch result {
            case .failure(let error):
                let presentable = error.toPresentableError()
                let since = FetchFailureTracker.shared.recordFailure(itemIdentifier.rawValue)
                self.logger.errorPublic("❌ fetch reply error id=\(itemIdentifier.rawValue) → \(presentable.domain)/\(presentable.code) sinceLastFailure=\(since.map { String(format: "%.2fs", $0) } ?? "-")")
                completionHandler(nil, nil, nil, presentable)
            case .success(let response):
                // Report the window the backend actually wrote to `dataURL`, never the request:
                // for a ranged (BRM) fetch it is the covering window (block-aligned for `.bc`),
                // NOT plaintext offset 0; reporting (0, size) would make the OS read the wrong
                // bytes for any range whose aligned start is not block 0. A whole-file fetch
                // (plain `fetchContents`, or a range `adjustRequestedRange` widened to the whole
                // file) has origin 0. Alignment of the returned extent is applied by
                // `fetchPartialContents`, the only caller that knows `alignment`.
                //
                // Publish the exact header-derived plaintext length on BOTH paths: the `|p<size>`
                // stamp moves the content version whenever it differs from the estimate the
                // system holds. The system treats that mismatch as a remote update — it adopts
                // the corrected documentSize and re-requests at the new version — which is the
                // only way a size correction lands (a size change without a content-version
                // change is ignored for an item being materialised).
                //
                // Known cost (accepted): when the true plaintext is smaller than the range the
                // system requested (Finder asks for 262,144 bytes), the reply cannot cover that
                // range and the system re-fetches once at the new version. Replies that cover the
                // requested range are accepted despite the version mismatch — no re-fetch. So the
                // extra fetch is limited to files < 256 KB, once, on first materialisation.
                // Alternatives rejected:
                //  - Content cache to serve the re-fetch locally: a new component (disk,
                //    expiry, invalidation) to save one small GET.
                //  - Background BC01 header probe of all items (~300k): ~300k ranged GETs for
                //    files mostly never opened, Graph throttling, a content-version bump per
                //    item (working-set churn), and re-probing after remote writes.
                //  - Zero-padding the reply to the advertised size: tested; still re-fetched
                //    (3 fetches instead of 2).
                // Revisit only if first-open latency on small files (~+0.7 s) is reported: probe
                // just the items whose ciphertext size puts the plaintext under the request size,
                // on folder enumeration.
                let window = response.plaintextWindow
                let wholeFileSize = response.wholeFilePlaintextSize
                let returnItem = self.displayItem(response.item, exactSize: wholeFileSize)
                self.logger.debugPublic("⬅ 📄 fetchContentsInline: name=\(response.item.name), origin=\(window.origin), length=\(window.length), fileSize=\(wholeFileSize)")
                completionHandler(dataURL, returnItem, window.nsRange, nil)
            }
        }
        return backendProgress
    }

    private func fetchResourceFork(sourceItem: Item, url: URL?, item: NSFileProviderItem?, error: Error?,
                           completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress? {
        if let error = error {
            completionHandler(url, item, error)
            return nil
        }

        guard let url = url else {
            completionHandler(nil, nil, CommonError.internalError.toPresentableError())
            return nil
        }

        // Backends with no fork store (OneDrive, etc.) short-circuit: no server round-trip, no
        // fork written. macOS keeps any local fork itself, so nothing is lost.
        guard backend.supportsResourceFork else {
            completionHandler(url, item, nil)
            return nil
        }

        let progress = Progress(totalUnitCount: 1)
        let task = Task {
            do {
                let fork = try await self.backend.fetchResourceFork(sourceItem.entry.id,
                                                                    revision: sourceItem.entry.revision)
                // Only materialise a non-empty fork; an empty one means the item has none.
                if !fork.isEmpty {
                    let forkURL = url.appendingPathComponent("..namedfork/rsrc")
                    try fork.write(to: forkURL)
                }
                progress.completedUnitCount = 1
                completionHandler(url, item, nil)
            } catch let error {
                completionHandler(nil, nil, error.toPresentableError())
            }
        }
        progress.cancellationHandler = { task.cancel() }
        return progress
    }

    /// Map the policy's extent onto the inline fetch's range convention, where
    /// `(0, -1)` requests the whole file. The head window depends on the requester.
    private func adjustRequestedRange(requestedRange: NSRange, alignment: Int, fileSize: Int,
                                      request: NSFileProviderRequest) -> NSRange {
        // system or Finder read at offset 0 is normally a header probe
        // Note: `requestingExecutable` is nil outside MDM deployments
        let isSystemRequest = request.isSystemRequest || request.isFileViewerRequest
        switch PartialFetchWindow.configured.extent(for: requestedRange, alignment: alignment,
                                                    fileSize: fileSize, isSystemRequest: isSystemRequest) {
        case .wholeFile: return NSRange(location: 0, length: -1)
        case .range(let range): return range
        }
    }

    func makeDecryptor(filename: String? = nil,
                       encryptedPrefix: Data = Data()) throws -> any FileDecryptor {
        let config = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)
        switch config.algorithm {
        case .plain:
            return PlainFileDecryptor()
        case .bc01:
            // (a) filename gate — non-.bc files pass through unmodified
            if let filename = filename, !filename.hasSuffix(".bc") {
                return PlainFileDecryptor()
            }
            // (b)+(c) header magic gate — wrong magic → pass through
            if !encryptedPrefix.isEmpty, !BC01CryptoCommon.hasBC01Magic(encryptedPrefix) {
                return PlainFileDecryptor()
            }
            // (d) session key — missing key → trigger re-auth
            return try BC01DecryptorFactory.make(for: domain.identifier)
        }
    }

    /// Builds the encryptor for this domain's configured algorithm.
    ///
    /// On a `.bc01` domain a missing session public key / user id is a **failure**, never a
    /// fallback to ``PlainFileEncryptor``: writing plaintext to a domain the user configured as
    /// encrypted silently defeats the encryption guarantee, and under a `.bc` name it produces
    /// the inverse-corruption hazard (plaintext under a `.bc` name).
    /// A locked or unavailable keychain therefore surfaces as
    /// ``NSFileProviderError/notAuthenticated``, prompting re-auth and failing the upload.
    ///
    /// - Throws: ``NSFileProviderError/notAuthenticated`` when BC01 is configured but its key
    ///   material cannot be loaded.
    func makeEncryptor() throws -> any FileEncryptor {
        let config = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)
        switch config.algorithm {
        case .plain:
            return PlainFileEncryptor()
        case .bc01:
            guard let pubKey = try? CryptoKeychain.loadUserIdentityPublicKey(for: domain.identifier.rawValue),
                  let uid    = try? CryptoKeychain.loadUserId(for: domain.identifier.rawValue)
            else { throw NSFileProviderError(.notAuthenticated) }
            return BC01Encryptor(rsaPublicKey: pubKey, userID: uid)
        }
    }

    /// The metadata translator for this domain's active crypto algorithm.
    var metadataTranslator: BoxcryptorMetadataTranslator {
        let config = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)
        return BoxcryptorMetadataTranslator(algorithm: config.algorithm)
    }

}

/// Diagnostics: time between consecutive failed fetch replies for the same item, to expose a
/// system retry loop (e.g. throttling retries exhausted). Bounded; cleared when it grows too large.
final class FetchFailureTracker: @unchecked Sendable {

    static let shared = FetchFailureTracker()

    private let lock = NSLock()
    private var lastFailure: [String: Date] = [:]
    private let maxEntries = 4096

    /// Record a failure for `id`. - Returns: Seconds since its previous failure, if any.
    func recordFailure(_ id: String) -> TimeInterval? {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        let previous = lastFailure[id]
        if lastFailure.count >= maxEntries { lastFailure.removeAll(keepingCapacity: true) }
        lastFailure[id] = now
        return previous.map { now.timeIntervalSince($0) }
    }
}
