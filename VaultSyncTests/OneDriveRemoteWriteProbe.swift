/// Test helper probing OneDrive remote writes.
//
//  OneDriveRemoteWriteProbe.swift
//  VaultSyncTests
//
//  Diagnostic harness (not a pass/fail unit test) for the delta-propagation investigation.
//
//  Hosted by VaultSync.app, this target inherits the App Group keychain entitlement, so
//  it can mint a Graph access token via `MSALTokenStore.shared` exactly as the extension
//  does. It writes a uniquely-named file directly to the serving root on OneDrive, giving
//  full control over *when* a remote change happens so the live Provider.appex logs
//  (delta poll → signal → enumerate?) can be correlated precisely.
//
//  Usage: with the domain mounted and signed in, run only this test and watch the unified
//  log (Provider category) for the delta/enumeration sequence that follows the printed
//  timestamp.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
import os.log

final class OneDriveRemoteWriteProbe: XCTestCase {

    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "remote-probe")

    /// Resolve the OneDrive domain account to target. Prefers a domain that already has a host
    /// config epoch recorded (i.e. one the host has interacted with) so the probe drives the same
    /// domain whose logs are being observed; falls back to any OneDrive domain. Dict iteration
    /// order is undefined, so this preference makes the target deterministic in practice.
    private func oneDriveAccount() throws -> (domainID: String, account: DomainAccount) {
        let accounts = SharedConfigStore.shared.read(\.accounts)
        let interacted = Set(SharedConfigStore.shared.read(\.configEpoch).keys)
        let oneDrive = accounts.filter { $0.value.backendKind == .oneDrive }
        guard !oneDrive.isEmpty else {
            throw XCTSkip("No OneDrive domain configured in shared config — mount one first.")
        }
        let pick = oneDrive.first(where: { interacted.contains($0.key) }) ?? oneDrive.first!
        return (pick.key, pick.value)
    }

    /// PUT a small uniquely-named file to the serving root and report the Graph response.
    /// Skips (rather than fails) when prerequisites (domain, credential, token) are absent,
    /// so it is safe to leave in the suite.
    func test_writeFileToServingRoot() async throws {
        let (domainID, account) = try oneDriveAccount()
        // Serving root: an explicit DriveItem id when the picker captured one, else the
        // drive root (`/me/drive/root`) for a whole-drive domain.
        let rootRef = account.remoteItemID.map { "items/\($0)" } ?? "root"

        let token: String
        do {
            token = try await MSALTokenStore.shared.accessToken(for: domainID)
        } catch {
            throw XCTSkip("Could not mint access token (\(error)); ensure the app is signed in.")
        }

        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let filename = "probe-\(stamp).txt"
        let body = Data("remote-write probe @ \(stamp)\n".utf8)

        // PUT /me/drive/{root}:/{name}:/content
        let url = URL(string:
            "https://graph.microsoft.com/v1.0/me/drive/\(rootRef):/\(filename):/content")!
        var req = URLRequest(url: url)
        req.httpMethod = "PUT"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        req.httpBody = body

        log.info("🧪 PUT \(filename, privacy: .public) → serving root \(rootRef, privacy: .public) (domain \(domainID, privacy: .public))")

        let (data, response) = try await URLSession.shared.data(for: req)
        let http = try XCTUnwrap(response as? HTTPURLResponse)
        let preview = String(data: data, encoding: .utf8)?.prefix(400) ?? ""
        log.info("🧪 Graph PUT → \(http.statusCode, privacy: .public)")

        XCTAssertTrue((200...201).contains(http.statusCode),
                      "Graph PUT failed: \(http.statusCode) \(preview)")
        log.info("🧪 Remote write complete. Watch Provider logs for: 📄 delta page → 🔔 signal → ⚓️/🔁 enumerate")
    }

    /// Print the resolved binding so the operator can confirm which domain/root/credential
    /// the probe targets before triggering a write.
    func test_dumpResolvedBinding() throws {
        let (domainID, account) = try oneDriveAccount()
        log.info("""
        🧪 OneDrive binding: domainID=\(domainID, privacy: .public) \
        displayName=\(account.displayName, privacy: .public) \
        remoteItemID=\(account.remoteItemID ?? "<nil>", privacy: .public) \
        remotePath=\(account.remotePath ?? "<nil>", privacy: .public)
        """)
    }
}
