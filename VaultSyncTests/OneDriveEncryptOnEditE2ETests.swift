/// Unit tests for `OneDriveEncryptOnEditE2E`.
//
//  OneDriveEncryptOnEditE2ETests.swift
//  VaultSyncTests
//
//  End-to-end tests for the BC01 "auto-encrypt on edit" pipeline against a *live* OneDrive
//  drive, using the stored MSAL token and the per-domain BC01 session keys — exactly the
//  credentials Provider.appex uses. Hosted by VaultSync.app, this target inherits the App
//  Group keychain entitlement, so it can mint a Graph token (`MSALTokenStore`) and load the
//  BC01 RSA keys (`CryptoKeychain`).
//
//  The extension's `GraphDriveClient` lives in the Provider.appex module, which this test
//  target does not link; so the backend operations (create / PUT content / PATCH name / GET)
//  are issued directly against Microsoft Graph here — the same HTTP the client performs — and
//  the crypto is driven through `Common`'s `BC01Encryptor` / `BC01Decryptor`. This reproduces
//  the real on-edit pipeline:
//
//      create plaintext  →  encrypt edit bytes  →  PUT ciphertext  →  PATCH name to `.bc`
//                        →  GET  →  decrypt  →  assert == edited plaintext
//
//  Focus: the reported bug — after an auto-encrypt edit the *backend* name must be renamed to
//  `.bc` (so stored encryption state matches the ciphertext) while the file still round-trips.
//
//  Files are created and deleted under the serving root (names prefixed `e2e-encrypt-`). Tests
//  `XCTSkip` when prerequisites (BC01 OneDrive domain, credential, token, session keys) are
//  absent, so they are safe to leave in the suite.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
import FileProvider
import os.log

final class OneDriveEncryptOnEditE2ETests: XCTestCase {

    private let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "encrypt-e2e")
    private let graphBase = "https://graph.microsoft.com/v1.0"

    // MARK: - Fixture

    private struct Fixture {
        let domainID: String
        let token: String
        /// Graph item-id path segment of the serving root: `items/{id}` or `root`.
        let rootRef: String
        let translator: BoxcryptorMetadataTranslator
        let encryptor: BC01Encryptor
        let decryptor: BC01Decryptor
    }

    /// Resolves a BC01 OneDrive domain with credential, token and session keys, and builds the
    /// encrypt/decrypt pair from the keychain. Skips otherwise.
    private func bc01Fixture() async throws -> Fixture {
        let accounts = SharedConfigStore.shared.read(\.accounts)
        let oneDrive = accounts.filter { $0.value.backendKind == .oneDrive }
        guard !oneDrive.isEmpty else {
            throw XCTSkip("No OneDrive domain configured — mount one first.")
        }
        let bc01 = oneDrive.first { pair in
            UserDefaults.sharedContainerDefaults
                .cryptoConfig(for: NSFileProviderDomainIdentifier(rawValue: pair.key)).algorithm == .bc01
        }
        guard let (domainID, account) = bc01 else {
            throw XCTSkip("No BC01-encrypted OneDrive domain found — set one up to run this test.")
        }
        guard let pub = try? CryptoKeychain.loadUserIdentityPublicKey(for: domainID),
              let uid = try? CryptoKeychain.loadUserId(for: domainID),
              let priv = try? CryptoKeychain.loadUserIdentityPrivateKey(for: domainID) else {
            throw XCTSkip("BC01 session keys not present for \(domainID) — sign in / unlock first.")
        }
        let token: String
        do { token = try await MSALTokenStore.shared.accessToken(for: domainID) }
        catch { throw XCTSkip("Could not mint access token (\(error)); ensure the app is signed in.") }

        let rootRef = account.remoteItemID.map { "items/\($0)" } ?? "root"
        return Fixture(domainID: domainID, token: token, rootRef: rootRef,
                       translator: BoxcryptorMetadataTranslator(algorithm: .bc01),
                       encryptor: BC01Encryptor(rsaPublicKey: pub, userID: uid),
                       decryptor: BC01Decryptor(rsaPrivateKey: priv))
    }

    // MARK: - Graph helpers

    private struct GraphItem: Decodable { let id: String; let name: String; let eTag: String? }

    private func send(_ req: URLRequest, expect ok: Set<Int> = Set(200...204)) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: req)
        let http = try XCTUnwrap(response as? HTTPURLResponse)
        guard ok.contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8)?.prefix(400) ?? ""
            throw NSError(domain: "graph", code: http.statusCode,
                          userInfo: [NSLocalizedDescriptionKey: "HTTP \(http.statusCode): \(body)"])
        }
        return data
    }

    private func authed(_ url: URL, _ method: String, token: String) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return req
    }

    /// PUT new content to `{rootRef}:/{name}:/content`, creating the item. Returns the item.
    private func putNew(_ fx: Fixture, name: String, body: Data) async throws -> GraphItem {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
        let url = URL(string: "\(graphBase)/me/drive/\(fx.rootRef):/\(encoded):/content")!
        var req = authed(url, "PUT", token: fx.token)
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        return try JSONDecoder().decode(GraphItem.self, from: try await send(req, expect: [200, 201]))
    }

    /// PUT replacement content to an existing item by id.
    private func putContent(_ fx: Fixture, id: String, body: Data) async throws -> GraphItem {
        let url = URL(string: "\(graphBase)/me/drive/items/\(id)/content")!
        var req = authed(url, "PUT", token: fx.token)
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        return try JSONDecoder().decode(GraphItem.self, from: try await send(req, expect: [200, 201]))
    }

    /// PATCH an item's name (rename), optionally guarded by an `If-Match` eTag. Returns the
    /// updated item; with a `expect` override the caller can assert a precondition failure (412).
    @discardableResult
    private func patchName(_ fx: Fixture, id: String, name: String,
                           ifMatch: String? = nil, expect: Set<Int> = Set(200...204)) async throws -> Data {
        let url = URL(string: "\(graphBase)/me/drive/items/\(id)")!
        var req = authed(url, "PATCH", token: fx.token)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let ifMatch { req.setValue(ifMatch, forHTTPHeaderField: "If-Match") }
        req.httpBody = try JSONSerialization.data(withJSONObject: ["name": name])
        return try await send(req, expect: expect)
    }

    private func getItem(_ fx: Fixture, id: String) async throws -> GraphItem {
        let url = URL(string: "\(graphBase)/me/drive/items/\(id)")!
        return try JSONDecoder().decode(GraphItem.self,
                                        from: try await send(authed(url, "GET", token: fx.token)))
    }

    private func getContent(_ fx: Fixture, id: String) async throws -> Data {
        let url = URL(string: "\(graphBase)/me/drive/items/\(id)/content")!
        return try await send(authed(url, "GET", token: fx.token), expect: Set(200...206))
    }

    private func deleteItem(_ fx: Fixture, id: String) async {
        let url = URL(string: "\(graphBase)/me/drive/items/\(id)")!
        _ = try? await send(authed(url, "DELETE", token: fx.token), expect: [204, 404])
    }

    private func uniqueName(_ tag: String) -> String {
        "e2e-encrypt-\(tag)-\(UUID().uuidString.prefix(8)).txt"
    }

    // MARK: - Tests

    /// Core regression: a plaintext file edited under auto-encrypt-on-edit must end up with a
    /// `.bc` *backend* name carrying ciphertext, yet still decrypt back to the edited plaintext.
    func test_autoEncryptOnEdit_renamesBackendToBc_andRoundTrips() async throws {
        let fx = try await bc01Fixture()
        let name = uniqueName("edit")

        // 1. Create as a plain-named, plain-content file (the auto-encrypt-OFF starting state).
        let v1 = Data("plaintext v1 @ \(Date())\n".utf8)
        let created = try await putNew(fx, name: name, body: v1)
        XCTAssertFalse(fx.translator.isBackendEncrypted(created.name))
        defer { Task { await self.deleteItem(fx, id: created.id) } }

        // 2. Edit under auto-encrypt: encrypt new bytes, PUT them, THEN rename to `.bc`.
        let v2 = Data("plaintext v2 — edited under auto-encrypt @ \(Date())\n".utf8)
        let ciphertext = try fx.encryptor.encrypt(v2, originalFilename: name)
        XCTAssertEqual(Data(ciphertext.prefix(4)), BC01CryptoCommon.magic, "expected a BC01 header")

        _ = try await putContent(fx, id: created.id, body: ciphertext)
        let bcName = fx.translator.encodeForBackend(name)            // name.txt -> name.txt.bc
        let renamed = try JSONDecoder().decode(GraphItem.self,
                                               from: try await patchName(fx, id: created.id, name: bcName))

        // 3. Backend name must now carry `.bc` — both in the PATCH result and an independent GET.
        XCTAssertTrue(fx.translator.isBackendEncrypted(renamed.name),
                      "rename result must be `.bc`: \(renamed.name)")
        let refetched = try await getItem(fx, id: created.id)
        XCTAssertTrue(fx.translator.isBackendEncrypted(refetched.name),
                      "BUG: backend name not `.bc` after edit — got \(refetched.name)")

        // 4. GET stored bytes → must be ciphertext, and decrypt to the edited plaintext.
        let stored = try await getContent(fx, id: created.id)
        XCTAssertEqual(Data(stored.prefix(4)), BC01CryptoCommon.magic,
                       "stored bytes under `.bc` must be BC01 ciphertext")
        let decrypted = try fx.decryptor.decrypt(stored)
        XCTAssertEqual(decrypted, v2, "ciphertext must decrypt back to the edited plaintext")

        log.info("✅ edit→encrypt→rename round-trip OK; backend name = \(refetched.name, privacy: .public)")
    }

    /// Already-encrypted edit: a `.bc` item re-edited must keep a single `.bc` suffix (no
    /// rename needed) and still round-trip.
    func test_editAlreadyEncrypted_keepsSingleBcSuffix_andRoundTrips() async throws {
        let fx = try await bc01Fixture()
        let displayName = uniqueName("already")
        let bcName = fx.translator.encodeForBackend(displayName)

        let v1 = Data("already-encrypted v1\n".utf8)
        let c1 = try fx.encryptor.encrypt(v1, originalFilename: displayName)
        let created = try await putNew(fx, name: bcName, body: c1)
        defer { Task { await self.deleteItem(fx, id: created.id) } }
        XCTAssertTrue(fx.translator.isBackendEncrypted(created.name))

        // Re-edit: encrypt new bytes, PUT — no rename (already `.bc`).
        let v2 = Data("already-encrypted v2 edited\n".utf8)
        let c2 = try fx.encryptor.encrypt(v2, originalFilename: displayName)
        let after = try await putContent(fx, id: created.id, body: c2)
        XCTAssertFalse(after.name.lowercased().hasSuffix(".bc.bc"),
                       "must not double-suffix `.bc`: \(after.name)")
        XCTAssertTrue(fx.translator.isBackendEncrypted(after.name))

        let decrypted = try fx.decryptor.decrypt(try await getContent(fx, id: created.id))
        XCTAssertEqual(decrypted, v2)
    }

    /// Regression for the cache-staleness 412 loop: a content PUT advances the item's eTag, so
    /// the follow-up rename PATCH must use the *post-PUT* eTag. Using a *pre-PUT* (stale) eTag —
    /// which the extension's cached `fetchItem` returned before the fix — fails `If-Match` with
    /// 412, the failure that left ciphertext under a plaintext name and a Finder cloud-error loop.
    func test_renameAfterEdit_staleEtagIs412_freshEtagSucceeds() async throws {
        let fx = try await bc01Fixture()
        let name = uniqueName("etag")

        let created = try await putNew(fx, name: name, body: Data("v1\n".utf8))
        defer { Task { await self.deleteItem(fx, id: created.id) } }
        let staleEtag = try XCTUnwrap(created.eTag, "create response must carry an eTag")

        // Edit (encrypt + PUT) → advances the eTag.
        let ciphertext = try fx.encryptor.encrypt(Data("v2 edited\n".utf8), originalFilename: name)
        let afterPut = try await putContent(fx, id: created.id, body: ciphertext)
        let freshEtag = try XCTUnwrap(afterPut.eTag, "PUT response must carry an eTag")
        XCTAssertNotEqual(staleEtag, freshEtag, "content PUT must change the eTag")

        // Stale eTag → 412 (the bug). Fresh eTag → success (the fix).
        let bcName = fx.translator.encodeForBackend(name)
        try await patchName(fx, id: created.id, name: bcName, ifMatch: staleEtag, expect: [412])
        let renamed = try JSONDecoder().decode(GraphItem.self,
            from: try await patchName(fx, id: created.id, name: bcName, ifMatch: freshEtag))
        XCTAssertTrue(fx.translator.isBackendEncrypted(renamed.name),
                      "rename with fresh eTag must succeed and yield a `.bc` name")
    }

    /// Pass-through guard: with auto-encrypt OFF (no encrypt, no rename), a plaintext edit
    /// stays plaintext — never ciphertext under a plain name (the original reported corruption).
    func test_plaintextEdit_passesThrough_noCiphertextUnderPlainName() async throws {
        let fx = try await bc01Fixture()
        let name = uniqueName("plain")

        let v1 = Data("plain v1\n".utf8)
        let created = try await putNew(fx, name: name, body: v1)
        defer { Task { await self.deleteItem(fx, id: created.id) } }

        let v2 = Data("plain v2 edited\n".utf8)
        let after = try await putContent(fx, id: created.id, body: v2)
        XCTAssertFalse(fx.translator.isBackendEncrypted(after.name),
                       "plaintext edit must not acquire a `.bc` name")

        let stored = try await getContent(fx, id: created.id)
        XCTAssertEqual(stored, v2)
        XCTAssertNotEqual(Data(stored.prefix(4)), BC01CryptoCommon.magic,
                          "plaintext file must not contain BC01 ciphertext")
    }
}
