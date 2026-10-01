/// Lightweight Microsoft Graph folder browser for the container app's setup UI.
///
/// Lists folders under a OneDrive DriveItem so the user can pick the serving folder
/// during domain creation. The picked folder's Graph id is stored in
/// ``DomainAccount/remoteItemID``; the extension then needs no path resolution.
///
/// App-side only — uses ``MSALTokenStore`` (App Group keychain) for the access token.
/// The sandboxed extension never browses. Graph wire models are the shared
/// ``GraphDriveItem`` / ``GraphCollection`` types from Common.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Common
import os.log

/// One folder entry in the browser.
public struct OneDriveFolder: Identifiable, Equatable {
    /// Graph DriveItem id.
    public let id: String
    /// Display name.
    public let name: String
    /// Whether the folder has child folders (drives disclosure affordance).
    public let hasChildren: Bool
}

/// Browses OneDrive folders via Microsoft Graph using the domain's stored credential.
public final class OneDriveFolderBrowser {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "folder-browser")
    private static let graphBase = URL(string: "https://graph.microsoft.com/v1.0")!

    private let domainID: String
    private let tokenStore: MSALTokenStore
    private let session: URLSession

    public init(domainID: String, tokenStore: MSALTokenStore = .shared) {
        self.domainID = domainID
        self.tokenStore = tokenStore
        self.session = URLSession(configuration: .ephemeral)
    }

    /// The drive root's DriveItem id, for seeding the picker at the top of the tree.
    public func rootFolderID() async throws -> String {
        let item: GraphDriveItem = try await get(path: "/me/drive/root?$select=id")
        return item.id
    }

    /// Child folders of `parentID` (files are omitted — only navigable folders).
    public func childFolders(of parentID: String) async throws -> [OneDriveFolder] {
        let page: GraphCollection<GraphDriveItem> = try await get(
            path: "/me/drive/items/\(parentID)/children?$select=id,name,folder,childCount")
        return page.value
            .filter { $0.folder != nil }
            .map { OneDriveFolder(id: $0.id,
                                  name: $0.name ?? "(unnamed)",
                                  hasChildren: ($0.folder?.childCount ?? 0) > 0) }
    }

    // MARK: - HTTP

    private func get<T: Decodable>(path: String) async throws -> T {
        // `path` carries a query string, so build the URL by string concatenation.
        let url = URL(string: Self.graphBase.absoluteString + path)!
        let token = try await tokenStore.accessToken(for: domainID)
        var req = URLRequest(url: url)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw CommonError.internalError }
        Self.log.debugPublic("🌐 GET \(url.path) → \(http.statusCode)")
        guard (200...299).contains(http.statusCode) else {
            throw CommonError.httpError(http)
        }
        return try GraphDecoding.makeDecoder().decode(T.self, from: data)
    }
}
