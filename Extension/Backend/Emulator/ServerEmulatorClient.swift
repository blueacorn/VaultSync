/// IPC/RPC client for HTTP communication with main app
//
//  Abstract:
//  The HTTP client for making requests to the (local) cloud file server.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation
import CFNetwork
import Common
import os.log
import FileProvider

public struct ServerEmulatorClient {
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "server-emulator-client")
    let domainIdentifier: String
    let port: in_port_t
    let responseQueue = DispatchQueue(label: "connection response queue")
    let session: URLSession
    let secret: String
    public let displayName: String
    let hostname: String
    /// Per-domain BC01 header cache so repeat ranged content fetches skip the header GET.
    ///
    /// The same persistent store the OneDrive backend uses, keyed by this domain's identifier —
    /// there is no per-backend header-caching implementation. `nil` when the store could not be
    /// opened, which degrades to the probe path.
    let headerCache: BC01HeaderCache?

    public static func accountConnection(hostname: String, port: in_port_t) -> ServerEmulatorClient {
        return ServerEmulatorClient(domainIdentifier: "accounts", secret: nil, hostname: UserDefaults.sharedContainerDefaults.hostname, port: port)
    }

    init(_ domain: NSFileProviderDomain, secret: String?, hostname: String, port: in_port_t) {
        self.init(domainIdentifier: domain.identifier.rawValue, displayName: domain.displayName, secret: secret, hostname: hostname, port: port)
    }

    public init(domainIdentifier: String, displayName: String? = nil, secret: String?, hostname: String, port: in_port_t) {
        self.domainIdentifier = domainIdentifier
        self.port = port
        self.secret = secret ?? "no secret"
        self.displayName = displayName ?? domainIdentifier
        self.hostname = hostname
        // A store that will not open must never block account construction: the download path
        // simply probes for every header, exactly as it did before this cache existed.
        self.headerCache = try? BC01HeaderCache(domainID: self.domainIdentifier)
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = ["x-domain": self.domainIdentifier, "x-authorization": self.secret]
        session = URLSession(configuration: config)
    }

    /// The active crypto algorithm for this domain, read from the shared config store.
    var cryptoAlgorithm: CryptoAlgorithm {
        UserDefaults.sharedContainerDefaults.cryptoConfig(
            for: NSFileProviderDomainIdentifier(rawValue: domainIdentifier)).algorithm
    }

    /// Returns entry with `.bc` suffix stripped from name and plaintext size approximated when
    /// BC01 is active. Gated on the `.bc` suffix; plain files and folders pass through.
    public func displayEntry(_ entry: DomainService.Entry) -> DomainService.Entry {
        BoxcryptorMetadataTranslator(algorithm: cryptoAlgorithm).displayEntry(entry)
    }

    public func isBackendEncrypted(_ entry: DomainService.Entry) -> Bool {
        BoxcryptorMetadataTranslator(algorithm: cryptoAlgorithm).isBackendEncrypted(entry.name)
    }

    public typealias CallResult<T> = Swift.Result<T, Error>

    @discardableResult
    public func makeJSONCall<ParameterType: JSONParameter>(_ parameter: ParameterType, _ data: Data? = nil, shouldRetry: Bool = true,
                                                           _ block: @escaping (CallResult<ParameterType.ReturnType>) async -> Void)
                                                            -> Progress {
        makeJSONCallGeneric(parameter, data, shouldRetry: shouldRetry) { result in
            Task {
                await block(result.map { tuple in return tuple.0 })
            }
        }
    }

    public func makeJSONCall<ParameterType: JSONParameter>(_ parameter: ParameterType,
                                                           _ data: Data? = nil,
                                                           shouldRetry: Bool = true) async throws -> ParameterType.ReturnType {
        try await withCheckedThrowingContinuation { continuation in
            makeJSONCallGeneric(parameter, data, shouldRetry: shouldRetry) { result in
                let response = result.map { tuple in return tuple.0 }
                continuation.resume(with: response)
            }
        }
    }

    @discardableResult
    public func makeJSONCallWithReturn<ParameterType: JSONParameter>(
        _ parameter: ParameterType, _ data: Data? = nil, shouldRetry: Bool = true,
        _ block: @escaping (Swift.Result<(response: ParameterType.ReturnType, data: Data), Error>) -> Void) -> Progress {
        makeJSONCallGeneric(parameter, data, shouldRetry: shouldRetry, block)
    }

    // The extension-side root/trash identifiers are the universal sentinels; the wire
    // `.root`/`.trash` flags translate them to the Server's internal "0"/"1" during
    // JSON coding (see the encoder/decoder `userInfo` below).
    public static let rootItemIdentifier: DomainService.ItemIdentifier = .root
    public static let trashItemIdentifier: DomainService.ItemIdentifier = .trash

    @discardableResult
    private func makeJSONCallGeneric<ParameterType: JSONParameter>(
        _ parameter: ParameterType, _ data: Data? = nil, shouldRetry: Bool = true,
        _ block: @escaping (Swift.Result<(response: ParameterType.ReturnType, data: Data), Error>) -> Void) -> Progress {
        if UserDefaults.sharedContainerDefaults.offline(for: NSFileProviderDomainIdentifier(rawValue: domainIdentifier)) {
            logger.warningPublic("✋ \(displayName)\(ParameterType.endpoint): offline")
            block(.failure(CommonError.timedOut))
            return Progress()
        }
        let enc = JSONEncoder()
        let dec = JSONDecoder()
        enc.userInfo[DomainService.rootItemCodingInfoKey] = ServerEmulatorClient.rootItemIdentifier
        dec.userInfo[DomainService.rootItemCodingInfoKey] = ServerEmulatorClient.rootItemIdentifier
        enc.userInfo[DomainService.trashItemCodingInfoKey] = ServerEmulatorClient.trashItemIdentifier
        dec.userInfo[DomainService.trashItemCodingInfoKey] = ServerEmulatorClient.trashItemIdentifier
        enc.keyEncodingStrategy = .convertToSnakeCase
        dec.keyDecodingStrategy = .convertFromSnakeCase

        let args: String = String(data: try! enc.encode(parameter), encoding: .utf8)!

        let queryItem = URLQueryItem(name: "arguments", value: args)

        var urlComponents = URLComponents()
        urlComponents.scheme = "http"
        urlComponents.host = hostname
        urlComponents.port = Int(port)
        urlComponents.path = "/\(ParameterType.endpoint)"
        urlComponents.queryItems = [queryItem]

        let url = urlComponents.url!

        var request = URLRequest(url: url)

        request.httpBody = data
        request.httpMethod = ParameterType.method.rawValue

        if let data = data {
            logger.debugPublic("🌐 \(displayName)/\(ParameterType.endpoint): \(String(describing: parameter)) + \(data.count) bytes")
        } else {
            logger.debugPublic("🌐 \(displayName)/\(ParameterType.endpoint): \(String(describing: parameter))")
        }

        let handler = { (downloaded: URL?, response: URLResponse?, error: Error?) -> Void in
            if let error = error {
                let nsError = error as NSError
                if nsError.domain == NSURLErrorDomain &&
                    nsError.code == NSURLErrorNetworkConnectionLost &&
                    shouldRetry {
                    self.logger.debugPublic("❌ \(self.displayName)/\(ParameterType.endpoint): connection lost; retrying")
                    self.makeJSONCallGeneric(parameter, data, shouldRetry: false, block)
                } else {
                    self.logger.debugPublic("❌ \(self.displayName)/\(ParameterType.endpoint): connection error: \(nsError)")
                    block(.failure(error))
                }
                return
            }
            do {
                guard let response = response as? HTTPURLResponse else { return block(.failure(CommonError.internalError)) }
                guard response.statusCode == 200 else {
                    guard let data = response.value(forHTTPHeaderField: CommonError.errorHeader) else {
                        return block(.failure(CommonError.httpError(response)))
                    }
                    let ret = try dec.decode(CommonError.self, from: Data(data.utf8))
                    self.logger.debugPublic("❌ \(self.displayName)/\(ParameterType.endpoint): server error: \(String(describing: ret))")
                    return block(.failure(ret))
                }
                guard let downloaded = downloaded else {
                    return block(.failure(CommonError.internalError))
                }
                defer {
                    try! FileManager().removeItem(at: downloaded)
                }
                let data = try Data(contentsOf: downloaded, options: [.alwaysMapped])
                func finish(_ ret: ParameterType.ReturnType, _ data: Data?) {
                    if let data = data {
                        self.logger.debugPublic("💟 \(self.displayName)/\(ParameterType.endpoint): \(String(describing: ret)) + \(data.count) bytes")
                    } else {
                        self.logger.debugPublic("💟 \(self.displayName)/\(ParameterType.endpoint): \(String(describing: ret))")
                    }
                    block(.success((ret, data ?? Data())))
                }
                let ret: ParameterType.ReturnType
                if let apiResponse = response.value(forHTTPHeaderField: "API-Response"),
                   let responseData = Data(base64Encoded: apiResponse) {
                    ret = try dec.decode(ParameterType.ReturnType.self, from: responseData)
                    finish(ret, data)
                } else {
                    ret = try dec.decode(ParameterType.ReturnType.self, from: data)
                    finish(ret, nil)
                }
            } catch let error as NSError {
                self.logger.debugPublic("❌ \(self.displayName)/\(ParameterType.endpoint): error: \(error)")
                return block(.failure(error))
            }
        }

        let task = session.downloadTask(with: request, completionHandler: handler)
        task.resume()
        let progress = task.progress
        let existing = progress.cancellationHandler
        progress.cancellationHandler = {
            self.logger.debugPublic("❌ \(self.displayName)/\(ParameterType.endpoint): request was cancelled")
            existing?()
        }
        return progress
    }

    public func makeSynchronousJSONCall<ParameterType: JSONParameter>(
        _ parameter: ParameterType,
        _ data: Data? = nil,
        timeout: DispatchTimeInterval
    ) throws -> ParameterType.ReturnType {
        let sema = DispatchSemaphore(value: 0)

        var result: Swift.Result<ParameterType.ReturnType, Error>? = nil
        makeJSONCall(parameter, data) { innerResult in
            result = innerResult
            sema.signal()
        }
        if sema.wait(timeout: DispatchTime.now().advanced(by: timeout)) == .timedOut {
            throw CommonError.timedOut
        } else {
            return try result!.get()
        }
    }

    public func makeSynchronousJSONCallWithReturn<ParameterType: JSONParameter>(
        _ parameter: ParameterType,
        _ data: Data? = nil,
        timeout: DispatchTimeInterval
    ) throws -> (response: ParameterType.ReturnType, data: Data) {
        let sema = DispatchSemaphore(value: 0)

        var result: Swift.Result<(response: ParameterType.ReturnType, data: Data), Error>? = nil
        makeJSONCallWithReturn(parameter, data) { innerResult in
            result = innerResult
            sema.signal()
        }
        if sema.wait(timeout: DispatchTime.now().advanced(by: timeout)) == .timedOut {
            throw CommonError.timedOut
        } else {
            return try result!.get()
        }
    }
}

// MARK: - ProviderBackend conformance

/// The reference emulator backend: each semantic ``ProviderBackend`` operation forwards
/// to the typed JSON-RPC transport (``makeJSONCall(_:_:shouldRetry:)`` family) against
/// the local `StandaloneServer`. The generic transport stays the emulator's own
/// vocabulary; cross-backend code speaks only the operations below.
extension ServerEmulatorClient: ProviderBackend {

    public var supportsByteRangeMaterialisation: Bool { true }
    /// The reference emulator models a full recycle bin: items move to trash and the trash
    /// container is browsable.
    public var supportsMoveToTrash: Bool { true }
    public var supportsTrashEnumeration: Bool { true }

    // MARK: Enumeration

    /// Emulator sizes are always exact; `resolvingPlaintextSize` is ignored.
    public func fetchItem(_ identifier: DomainService.ItemIdentifier,
                          resolvingPlaintextSize: Bool,
                          _ block: @escaping (Result<DomainService.FetchItemReturn, Error>) -> Void) -> Progress {
        makeJSONCall(DomainService.FetchItemParameter(itemIdentifier: identifier)) { result in block(result) }
    }

    /// Drop BC01 bookkeeping entries (`FolderKey.bch`) from a proxied listing.
    ///
    /// Extracted as a pure static so the rule is testable without the emulator's HTTP
    /// transport (offline gating, retry, and snake-case coding all sit between
    /// ``makeJSONCall(_:_:shouldRetry:)`` and the wire). Applied identically by
    /// ``listFolder(_:recursive:startingCursor:_:)`` and
    /// ``listChanges(_:recursive:startingRank:)`` — the two MUST agree, or an entry hidden
    /// from a listing reappears through a change feed.
    static func visibleEntries(_ entries: [DomainService.Entry],
                               specialItem: BC01SpecialItem) -> [DomainService.Entry] {
        entries.filter { !specialItem.isSpecial(name: $0.name, isFolder: $0.type == .folder) }
    }

    /// - Note: BC01 bookkeeping entries (`FolderKey.bch`) are stripped here, on the way *out*,
    ///   rather than at ingestion as the OneDrive backend does: the emulator is stateless on
    ///   our side — it proxies straight to the standalone server and has no `MetadataCache` to
    ///   seed. For the same reason, recording the parent folder as encrypted has no store here
    ///   and is a documented no-op.
    ///
    ///   `deletedEntries` needs no filtering: an identifier for a row the system never saw is
    ///   inert.
    public func listFolder(_ folder: DomainService.ItemIdentifier, recursive: Bool, startingCursor: DomainService.PageCursor?,
                           _ block: @escaping (Result<DomainService.ListFolderReturn, Error>) -> Void) -> Progress {
        let param = DomainService.ListFolderParameter(folderIdentifier: folder, recursive: recursive, startingCursor: startingCursor)
        let specialItem = BC01SpecialItem(algorithm: cryptoAlgorithm)
        return makeJSONCall(param) { (result: CallResult<DomainService.ListFolderReturn>) in
            block(result.map { ret in
                DomainService.ListFolderReturn(
                    entries: Self.visibleEntries(ret.entries, specialItem: specialItem),
                    deletedEntries: ret.deletedEntries, cursor: ret.cursor, rank: ret.rank)
            })
        }
    }

    public func latestRank(_ folder: DomainService.ItemIdentifier) async throws -> DomainService.LatestRankReturn {
        try await makeJSONCall(DomainService.LatestRankParameter(folderIdentifier: folder))
    }

    /// - Note: Filters BC01 bookkeeping entries on the way out, for the same reason as
    ///   ``listFolder(_:recursive:startingCursor:_:)``.
    public func listChanges(_ folder: DomainService.ItemIdentifier, recursive: Bool,
                            startingRank: DomainService.RankToken) async throws -> DomainService.ListChangesReturn {
        let ret: DomainService.ListChangesReturn = try await makeJSONCall(
            DomainService.ListChangesParameter(folderIdentifier: folder, recursive: recursive, startingRank: startingRank))
        let specialItem = BC01SpecialItem(algorithm: cryptoAlgorithm)
        return DomainService.ListChangesReturn(
            entries: Self.visibleEntries(ret.entries, specialItem: specialItem),
            deletedEntries: ret.deletedEntries, rank: ret.rank, hasMore: ret.hasMore)
    }

    // MARK: Lock lifecycle

    public func pingLock(_ identifier: DomainService.ItemIdentifier, owner: String, enumerationIndex: Int64) {
        let param = DomainService.PingLockParameter(identifier: identifier, owner: owner, enumerationIndex: enumerationIndex)
        makeJSONCall(param) { _ in }
    }

    public func removeLock(_ identifier: DomainService.ItemIdentifier, enumerationIndex: Int64) {
        makeJSONCall(DomainService.RemoveLockParameter(identifier: identifier, enumerationIndex: enumerationIndex)) { _ in }
    }

    public func forceLock(_ identifier: DomainService.ItemIdentifier,
                          _ block: @escaping (Result<DomainService.ForceLockReturn, Error>) -> Void) -> Progress {
        makeJSONCall(DomainService.ForceLockParameter(identifier: identifier)) { result in block(result) }
    }

    // MARK: Content

    /// The reference emulator is the one backend with a sidecar resource-fork store (a separate
    /// `.resourceFork` content row), so it round-trips the fork.
    public var supportsResourceFork: Bool { true }

    /// Fetch the item's resource fork bytes via the ranged-less `download` JSON-RPC with the
    /// `resourceFork` flag set. The server returns empty `Data()` when the item has no fork.
    public func fetchResourceFork(_ identifier: DomainService.ItemIdentifier,
                                  revision: DomainService.Version?) async throws -> Data {
        let param = DomainService.DownloadItemParameter(
            itemIdentifier: identifier, requestedRevision: revision, resourceFork: true)
        return try await withCheckedThrowingContinuation { continuation in
            _ = self.makeJSONCallWithReturn(param) { result in
                continuation.resume(with: result.map { $0.data })
            }
        }
    }

    /// Stream an item's content (whole-file or a plaintext range) to `destinationURL`, decrypting
    /// via the shared ``ContentStreamDownloader`` pipeline — the same engine OneDrive uses. The
    /// emulator supplies an ``EmulatorContentFetcher`` adapter over its ranged JSON-RPC `download`.
    public func downloadToFile(_ parameter: DomainService.DownloadItemParameter,
                               destinationURL: URL,
                               progress: Progress,
                               _ block: @escaping (Result<DomainService.DownloadToFileReturn, Error>) -> Void) -> Progress {
        let task = Task {
            do {
                // Resolve the item entry (name → encryption gate; size → total transfer budget).
                let entry = try await self.fetchEntry(parameter.itemIdentifier)
                let isEncrypted = self.metadataTranslator().isBackendEncrypted(entry.name)
                let decryptor = try self.makeDecryptor(filename: entry.name, encrypted: isEncrypted)

                let fetcher = EmulatorContentFetcher(client: self,
                                                     itemIdentifier: parameter.itemIdentifier,
                                                     requestedRevision: parameter.requestedRevision,
                                                     totalSize: Int(entry.size))
                let (plaintextWindow, wholeFileSize) = try await StreamingDownload.run(
                    fetcher: fetcher,
                    decryptor: decryptor,
                    isEncrypted: isEncrypted,
                    itemIdentifier: parameter.itemIdentifier,
                    // The fetcher serves the requested revision when given, else current.
                    revision: parameter.requestedRevision ?? entry.revision,
                    plaintextRange: StreamingDownload.plaintextRange(from: parameter.range),
                    destinationURL: destinationURL,
                    progress: progress,
                    headerCache: self.headerCache,
                    lanes: UserDefaults.sharedContainerDefaults.parallelDownloadLanes,
                    threshold: UserDefaults.sharedContainerDefaults.parallelDownloadThreshold,
                    maxSpanBytes: UserDefaults.sharedContainerDefaults.maxDownloadSpanBytes)

                if Task.isCancelled { throw CancellationError() }
                block(.success(DomainService.DownloadToFileReturn(item: entry, plaintextWindow: plaintextWindow,
                                                                  wholeFilePlaintextSize: wholeFileSize)))
            } catch is CancellationError {
                try? FileManager.default.removeItem(at: destinationURL)
                block(.failure(NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)))
            } catch {
                try? FileManager.default.removeItem(at: destinationURL)
                self.logger.errorPublic("❌ downloadToFile failed: \(String(describing: error))")
                block(.failure(error))
            }
        }
        progress.cancellationHandler = { task.cancel() }
        return progress
    }

    /// Resolve an item's metadata entry (used by ``downloadToFile`` for name + size).
    private func fetchEntry(_ identifier: DomainService.ItemIdentifier) async throws -> DomainService.Entry {
        try await makeJSONCall(DomainService.FetchItemParameter(itemIdentifier: identifier)).item
    }

    /// Build a content decryptor mirroring the Extension's policy gate: non-encrypted (or `.plain`
    /// algorithm) → ``PlainFileDecryptor``; BC01 → load the session RSA key from the unwrapped
    /// slot. An empty slot means the vault is **locked**: the KEK has been evicted and
    /// the Provider cannot decrypt until an app-driven unlock repopulates the slot. Surfaced as
    /// ``NSFileProviderError/notAuthenticated`` so Finder reflects the unauthenticated state.
    private func makeDecryptor(filename: String, encrypted: Bool) throws -> any FileDecryptor {
        guard encrypted else { return PlainFileDecryptor() }
        return try BC01DecryptorFactory.make(for: NSFileProviderDomainIdentifier(rawValue: domainIdentifier))
    }

    /// The domain's metadata translator (BC01 name encryption gate).
    private func metadataTranslator() -> BoxcryptorMetadataTranslator {
        BoxcryptorMetadataTranslator(algorithm: cryptoAlgorithm)
    }

    /// Fetch a ciphertext byte range via the JSON-RPC `download` endpoint, exposed as `async` for
    /// the ``ContentFetching`` adapter. Routes through the callback transport and bridges it.
    fileprivate func fetchContentRange(itemIdentifier: DomainService.ItemIdentifier,
                                       requestedRevision: DomainService.Version?,
                                       start: Int, length: Int) async throws -> Data {
        let param = DomainService.DownloadItemParameter(
            itemIdentifier: itemIdentifier, requestedRevision: requestedRevision,
            range: NSRange(location: start, length: length))
        return try await withCheckedThrowingContinuation { continuation in
            _ = self.makeJSONCallWithReturn(param) { result in
                continuation.resume(with: result.map { $0.data })
            }
        }
    }

    public func createFolder(_ parameter: DomainService.CreateParameter,
                             _ block: @escaping (Result<DomainService.CreateReturn, Error>) async -> Void) -> Progress {
        makeJSONCall(parameter) { result in await block(result) }
    }

    /// Resource-fork writes only; file contents go through
    /// ``modifyContentsStreaming(_:contentsAt:originalFilename:encryptor:progress:)``.
    public func modifyContents(_ parameter: DomainService.ModifyContentsParameter, data: Data?,
                               _ block: @escaping (Result<DomainService.ModifyContentsReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter, data) { result in block(result) }
    }

    public func createStreaming(_ parameter: DomainService.CreateParameter,
                                contentsAt sourceURL: URL,
                                originalFilename: String,
                                encryptor: any FileEncryptor,
                                progress: Progress) async throws -> DomainService.CreateReturn {
        let (response, blockContext) = try await streamUpload(
            sourceURL: sourceURL, originalFilename: originalFilename,
            encryptor: encryptor, progress: progress) { body in
                try await self.makeJSONCall(parameter, body)
            }
        seedHeaderCache(entry: response.item, header: blockContext)
        return response
    }

    public func modifyContentsStreaming(_ parameter: DomainService.ModifyContentsParameter,
                                        contentsAt sourceURL: URL,
                                        originalFilename: String,
                                        encryptor: any FileEncryptor,
                                        progress: Progress) async throws -> DomainService.ModifyContentsReturn {
        let (response, blockContext) = try await streamUpload(
            sourceURL: sourceURL, originalFilename: originalFilename,
            encryptor: encryptor, progress: progress) { body in
                try await self.makeJSONCall(parameter, body)
            }
        if response.contentAccepted { seedHeaderCache(entry: response.item, header: blockContext) }
        return response
    }

    /// Run the shared ``ContentStreamUploader`` over the whole-body JSON-RPC `send`.
    ///
    /// The emulator's RPC has no fragment protocol, so ``EmulatorContentPutter`` always takes the
    /// single-request path; the typed RPC response is captured here and the uploader's opaque
    /// completion payload is ignored.
    private func streamUpload<Response: Sendable>(
        sourceURL: URL, originalFilename: String, encryptor: any FileEncryptor, progress: Progress,
        send: @escaping @Sendable (Data) async throws -> Response) async throws -> (Response, BC01Header?) {
        let captured = ResponseBox<Response>()
        let putter = EmulatorContentPutter { body in
            captured.value = try await send(body)
            return Data()
        }
        let result = try await ContentStreamUploader(putter: putter, encryptor: encryptor, lanes: 1)
            .run(from: sourceURL, originalFilename: originalFilename, progress: progress)
        guard let response = captured.value else { throw CommonError.internalError }
        return (response, result.blockContext)
    }

    /// Seed the header cache from an upload, keyed on the revision the server returned — the same
    /// revision `downloadToFile` keys on for a current-content fetch.
    private func seedHeaderCache(entry: DomainService.Entry, header: BC01Header?) {
        guard entry.type == .file else { return }
        HeaderCacheSeeding.seed(headerCache, header: header, itemID: entry.id.id,
                                contentIdentity: entry.revision.contentIdentity)
    }

    public func modifyMetadata(_ parameter: DomainService.ModifyMetadataParameter,
                               _ block: @escaping (Result<DomainService.ModifyMetadataReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter) { result in block(result) }
    }

    public func deleteItem(_ parameter: DomainService.DeleteItemParameter,
                           _ block: @escaping (Result<DomainService.DeleteItemReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter) { result in block(result) }
    }

    public func trashItem(_ parameter: DomainService.TrashItemParameter,
                          _ block: @escaping (Result<DomainService.TrashItemReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter) { result in block(result) }
    }

    public func mark(_ parameter: DomainService.MarkParameter,
                     _ block: @escaping (Result<DomainService.MarkReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter) { result in block(result) }
    }

    // MARK: Thumbnails

    public func fetchThumbnail(_ parameter: DomainService.FetchThumbnailParameter,
                               _ block: @escaping (Result<(response: DomainService.FetchThumbnailReturn, data: Data), Error>) -> Void) -> Progress {
        makeJSONCallWithReturn(parameter) { result in block(result) }
    }

    public func updateThumbnail(_ parameter: DomainService.UpdateThumbnailParameter,
                                data: Data) async throws -> DomainService.UpdateThumbnailReturn {
        try await makeJSONCall(parameter, data)
    }

    // MARK: Conflict servicing

    public func conflictVersions(_ parameter: DomainService.ConflictVersionsParameter,
                                 _ block: @escaping (Result<DomainService.ConflictVersionsReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter) { result in block(result) }
    }

    public func resolveConflictVersions(_ parameter: DomainService.ResolveConflictVersionsParameter,
                                        _ block: @escaping (Result<DomainService.ResolveConflictVersionsReturn, Error>) -> Void) -> Progress {
        makeJSONCall(parameter) { result in block(result) }
    }

}

/// ``ContentFetching`` adapter over a live ``ServerEmulatorClient``: each range maps to a ranged
/// JSON-RPC `download` against the local `StandaloneServer`. Lets the emulator reuse the shared
/// ``ContentStreamDownloader`` pipeline unchanged.
private struct EmulatorContentFetcher: ContentFetching, @unchecked Sendable {
    let client: ServerEmulatorClient
    let itemIdentifier: DomainService.ItemIdentifier
    let requestedRevision: DomainService.Version?
    let totalSize: Int

    func fetchRange(start: Int, length: Int) async throws -> Data {
        try await client.fetchContentRange(itemIdentifier: itemIdentifier,
                                            requestedRevision: requestedRevision,
                                            start: start, length: length)
    }
}

/// ``ContentPutting`` adapter over the emulator's whole-body JSON-RPC `create` / `modifyContents`.
///
/// The RPC has no fragment protocol, so ``singleRequestLimit`` is unbounded and ``putRange(_:start:totalSize:)``
/// is never reached. The ciphertext is resident for the one RPC — acceptable for a test backend;
/// the Provider-side path is identical to every other backend's.
struct EmulatorContentPutter: ContentPutting {
    let send: @Sendable (Data) async throws -> Data

    var fragmentAlignment: Int { 1 }
    var supportsParallelFragments: Bool { false }
    var singleRequestLimit: Int { .max }

    func putWhole(_ bytes: Data) async throws -> Data { try await send(bytes) }

    func putRange(_ bytes: Data, start: Int, totalSize: Int) async throws -> Data? {
        throw CommonError.notImplemented
    }
}

/// Carries a typed RPC response out of a `@Sendable` putter closure. Written once, read after the
/// upload completes.
private final class ResponseBox<Value>: @unchecked Sendable {
    var value: Value?
}
