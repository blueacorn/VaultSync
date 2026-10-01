/// Probe: does `$select` suppress the `deleted` facet / `deletedDateTime` on delta tombstones?
///
/// `GraphDeltaSync.selectFields` lists neither, yet `partition` branches on both. This runs a
/// real create → delta → delete → delta cycle against the configured OneDrive and reports what
/// Graph actually returns for the tombstone under each `$select`. Opt-in, like the perf test.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import os.log
@testable import Common

final class GraphDeltaSelectProbeTests: XCTestCase {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "delta-perf")

    private var optedIn: Bool {
        ProcessInfo.processInfo.environment["FB_PERF_ONEDRIVE"] == "1"
            || UserDefaults.standard.string(forKey: "FB_PERF_ONEDRIVE") == "1"
    }

    func test_selectSuppressesDeletedFacet() async throws {
        try XCTSkipUnless(optedIn, "set FB_PERF_ONEDRIVE=1")
        let token = try await Self.token()

        // Two selects: the one the crawl uses, and the same plus the deletion fields.
        let crawlSelect = "id,name,size,eTag,cTag,createdDateTime,lastModifiedDateTime,parentReference,folder,remoteItem"
        let fixedSelect = crawlSelect + ",deleted,deletedDateTime"

        for (label, select) in [("crawl $select", crawlSelect), ("with deleted", fixedSelect)] {
            // Establish a deltaLink over a small scratch folder.
            let folder = try await Self.createFolder(token: token)
            defer { Task { try? await Self.delete(id: folder, token: token) } }
            let file = try await Self.createFile(in: folder, token: token)

            var url = URL(string: "https://graph.microsoft.com/v1.0/me/drive/items/\(folder)/delta?$select=\(select)")!
            var deltaLink: String?
            while true {
                let page = try await Self.get(url, token: token)
                let obj = try JSONSerialization.jsonObject(with: page) as? [String: Any] ?? [:]
                if let next = obj["@odata.nextLink"] as? String { url = URL(string: next)!; continue }
                deltaLink = obj["@odata.deltaLink"] as? String
                break
            }
            guard let link = deltaLink else { XCTFail("no deltaLink"); return }

            try await Self.delete(id: file, token: token)

            let page = try await Self.get(URL(string: link)!, token: token)
            let text = String(decoding: page, as: UTF8.self)
            let obj = try JSONSerialization.jsonObject(with: page) as? [String: Any] ?? [:]
            let items = obj["value"] as? [[String: Any]] ?? []
            let tomb = items.first { ($0["id"] as? String) == file }

            Self.log.notice("""
            PROBE \(label, privacy: .public): tombstone_present=\(tomb != nil, privacy: .public) \
            has_deleted_facet=\(tomb?["deleted"] != nil, privacy: .public) \
            has_deletedDateTime=\(tomb?["deletedDateTime"] != nil, privacy: .public) \
            raw=\(String((tomb.map { String(describing: $0) } ?? "<none>").prefix(300)), privacy: .public)
            """)
            _ = text
            try? await Self.delete(id: folder, token: token)
        }
    }

    // MARK: - Graph helpers

    private static func token() async throws -> String {
        let wanted = ProcessInfo.processInfo.environment["FB_PERF_DOMAIN_ID"]
        let accounts = SharedConfigStore.shared.allAccounts()
        // Credentials are keyed by domain id, so the *key* is what mints the token.
        let candidates = accounts.filter { $0.value.backendKind == .oneDrive
                                           && MSALTokenStore.shared.hasCredential($0.key) }
        let domainID = wanted.flatMap { candidates[$0] != nil ? $0 : nil } ?? candidates.keys.first
        guard let domainID,
              let token = try? await MSALTokenStore.shared.accessToken(for: domainID) else {
            throw XCTSkip("no configured OneDrive account with a credential")
        }
        return token
    }

    private static func get(_ url: URL, token: String) async throws -> Data {
        var r = URLRequest(url: url)
        r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (d, resp) = try await URLSession.shared.data(for: r)
        guard (resp as? HTTPURLResponse)?.statusCode ?? 0 < 400 else {
            throw NSError(domain: "probe", code: (resp as? HTTPURLResponse)?.statusCode ?? -1)
        }
        return d
    }

    private static func createFolder(token: String) async throws -> String {
        let url = URL(string: "https://graph.microsoft.com/v1.0/me/drive/root/children")!
        var r = URLRequest(url: url); r.httpMethod = "POST"
        r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try JSONSerialization.data(withJSONObject: [
            "name": "fb-select-probe-\(UUID().uuidString.prefix(8))",
            "folder": [:] as [String: Any],
            "@microsoft.graph.conflictBehavior": "rename"])
        let (d, _) = try await URLSession.shared.data(for: r)
        let o = try JSONSerialization.jsonObject(with: d) as? [String: Any] ?? [:]
        guard let id = o["id"] as? String else { throw NSError(domain: "probe", code: 1) }
        return id
    }

    private static func createFile(in folder: String, token: String) async throws -> String {
        let url = URL(string: "https://graph.microsoft.com/v1.0/me/drive/items/\(folder):/probe.txt:/content")!
        var r = URLRequest(url: url); r.httpMethod = "PUT"
        r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        r.httpBody = Data("hello".utf8)
        let (d, _) = try await URLSession.shared.data(for: r)
        let o = try JSONSerialization.jsonObject(with: d) as? [String: Any] ?? [:]
        guard let id = o["id"] as? String else { throw NSError(domain: "probe", code: 2) }
        return id
    }

    private static func delete(id: String, token: String) async throws {
        var r = URLRequest(url: URL(string: "https://graph.microsoft.com/v1.0/me/drive/items/\(id)")!)
        r.httpMethod = "DELETE"
        r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        _ = try await URLSession.shared.data(for: r)
    }
}
