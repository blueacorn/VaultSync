/// HTTP server exposing local JSON-RPC API on port 24680
//
//  Abstract:
//  A local HTTP server that acts as a server for cloud files.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation
import OSLog
import Common
import FileProvider

public extension NSNotification.Name {
    static let itemsChanged: NSNotification.Name =
        NSNotification.Name(rawValue: Bundle(for: StandaloneServer.self).bundleIdentifier!.appending(".ItemsChanged"))
}

public class StandaloneServer {
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "server")

    static let groupContainer = AppIdentifiers.appGroupID
    public let databaseURL: URL
    var dispatch: BackendDispatch!
    var itemDB: ItemDatabase!
    let queue = DispatchQueue(label: "notify queue")
    let notifyThrottle: Throttle

    public var port: in_port_t {
        dispatch.port
    }

    /// Whether ``run()`` has bound the server. The emulator-only server is started lazily, so
    /// callers gate (re)starts on this rather than tracking the lifecycle externally.
    public var isRunning: Bool { itemDB != nil }

    public init(_ databaseURL: URL?) {
        if let databaseURL = databaseURL {
            self.databaseURL = databaseURL
        } else {
            self.databaseURL =
                FileManager().containerURL(forSecurityApplicationGroupIdentifier: StandaloneServer.groupContainer)!.appendingPathComponent("files.db")
        }
        notifyThrottle = Throttle(timeout: .milliseconds(500), "notify throttle")

        notifyThrottle.handler = { [weak self] in
            guard let strongSelf = self else { return }
            strongSelf.didHandleRequest()
        }
    }

    /// Releases resources held by this server. Call before termination.
    ///
    /// Idempotent, and safe on a server that was never ``run()``: the notify throttle owns a
    /// `DispatchSource` that is created suspended, and releasing a suspended source traps in
    /// libdispatch. Cancelling here (and in ``Throttle/deinit``) makes an unrun server safe to
    /// discard.
    public func close() {
        notifyThrottle.cancel()
    }

    /// Called with the loaded accounts immediately before storage locations are accessed.
    /// Use this hook to resolve security-scoped bookmarks before the server opens any files.
    public var onAccountsLoaded: (() -> Void)?

    /// Errors raised by ``StandaloneServer`` account management.
    public enum StandaloneServerError: LocalizedError {
        /// An operation needing the item database was attempted before ``run()``.
        case notRunning

        public var errorDescription: String? {
            switch self {
            case .notRunning:
                return "The local file server is not running."
            }
        }
    }

    /// Provisions (or updates) the emulator DB row for a domain.
    ///
    /// The database mints its own root item ID. Identity (displayName, remotePath)
    /// lives in `config.json`; ``DomainBackend`` reads it from ``SharedConfigStore``.
    ///
    /// - Throws: ``StandaloneServerError/notRunning`` if the server has not been started.
    ///   Provisioning genuinely needs the database, so the caller must start it first.
    public func provisionAccount(domainIdentifier: String) throws {
        guard let itemDB else { throw StandaloneServerError.notRunning }
        try itemDB.setAccountRoot(for: domainIdentifier, root: nil)
    }

    /// Resets the sync anchor for a domain by re-minting its account root
    /// (keeps the existing root item ID, re-rolls the token check number).
    ///
    /// - Throws: ``StandaloneServerError/notRunning`` if the server has not been started.
    public func resetSyncAnchor(domainIdentifier: String) throws {
        guard let itemDB else { throw StandaloneServerError.notRunning }
        let account = try itemDB.account(for: domainIdentifier)
        try itemDB.setAccountRoot(for: domainIdentifier, root: account.rootItem.id)
    }

    /// Removes the emulator DB row for a domain.
    ///
    /// A no-op when the server was never started: it is started lazily, only once an
    /// emulator-backed domain exists (see `AppDelegate.updateDomains`), so deleting a vault on
    /// a cloud-only setup reaches this with no database open. There is no row to remove in that
    /// case, and deletion must not fail because of it.
    public func removeAccount(domainIdentifier: String) throws {
        guard let itemDB else { return }
        try itemDB.removeAccount(for: domainIdentifier)
    }

    public func run() throws {
        // When a database item changes, remember the item and signal notifyThrottle to send a push notification later.
        let changeListener: ItemDatabase.ChangeListener = { [weak self] id in
            guard let strongSelf = self else { return }
            strongSelf.notify(for: id)
            strongSelf.notifyThrottle.signal()
        }

        // When the database account changes, update the server-side account listeners.
        let accountListener: ItemDatabase.AccountListener = { [weak self] accounts in
            guard let strongSelf = self else { return }
            strongSelf.queue.async {
                do {
                    try strongSelf.updateListeners(accounts: accounts)
                } catch let error as NSError {
                    strongSelf.logger.info("error updating account list: \(error)")
                }
            }
        }

        itemDB = try ItemDatabase(location: databaseURL, changeListener: changeListener, accountListener: accountListener)

        let name = "VaultSync"
        dispatch = try BackendDispatch(name: name)
        let accounts = try itemDB.allAccounts()
        onAccountsLoaded?()
        try updateListeners(accounts: accounts)
        notifyThrottle.resume()
        logger.info("serving from \(self.databaseURL.path):\(self.dispatch.port)...")
    }

    func updateListeners(accounts newAccounts: [DBAccount]) throws {
        let prev = synchronized(dispatch) {
            return dispatch.backends.keys
        }

        dispatch.removeBackends(except: newAccounts.map({ $0.identifier }))

        // Log removed accounts.
        let removedIdentifiers = prev.filter { ident in !newAccounts.contains(where: { $0.identifier == ident }) }
        for ident in removedIdentifiers {
            logger.info("removed account for \(ident)")
        }

        // Sync per-account content locations into the shared database instance.
        itemDB.updateAccountContentLocations(newAccounts)

        // Create a new dispatch for each listener.
        for account in newAccounts {
            let backend = try DomainBackend(identifier: account.identifier, database: itemDB)
            dispatch[account.identifier] = backend
            if prev.contains(account.identifier) {
                logger.info("updated account for \(account.identifier)")
            } else {
                logger.info("added account for \(account.identifier)")
            }
        }
    }

    func didHandleRequest() {
        itemsToNotify.forEach { item in
            DistributedNotificationCenter.default().post(Notification(name: .itemsChanged, object: "\(item.id)"))
        }

        queue.sync {
            self.itemsToNotify.removeAll()
        }
    }

    var itemsToNotify = Set<DomainService.ItemIdentifier>()

    func notify(for itemIdentifier: DomainService.ItemIdentifier) {
        queue.async {
            self.itemsToNotify.insert(itemIdentifier)
        }
    }
}
