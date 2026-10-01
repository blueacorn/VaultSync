/// Unit tests for `MSALTokenStore`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
@testable import Common

/// Covers ``MSALTokenStore``'s refresh paths through the ``RefreshTokenStoring`` seam and a
/// stubbed `URLSession`, with no App Group keychain and no network.
///
/// The offline case is load-bearing for the UI: `EditDomainView`'s
/// `CredentialValidationError` distinguishes "cannot reach OneDrive" from "sign-in expired"
/// by matching an unwrapped `URLError`, which only works while `postToken` leaves transport
/// errors alone.
final class MSALTokenStoreTests: XCTestCase {

    private let domainID = "test-domain"

    // MARK: - Doubles

    /// In-memory ``RefreshTokenStoring``; the keychain is unreachable from this bundle.
    ///
    /// `sealed` models the vault's second slot: a domain listed there has a sealed token even
    /// when `read` answers `nil`, which is exactly the locked-vault shape test 14 exercises.
    private final class InMemoryRefreshTokenStore: RefreshTokenStoring, @unchecked Sendable {
        private let lock = NSLock()
        private var tokens: [String: String] = [:]
        private var sealed: Set<String> = []

        init(seeded: [String: String] = [:], sealedOnly: Set<String> = []) {
            tokens = seeded
            sealed = Set(seeded.keys).union(sealedOnly)
        }

        func read(domainIdentifier: String) throws -> String? {
            lock.lock(); defer { lock.unlock() }
            return tokens[domainIdentifier]
        }
        /// Mirrors ``VaultRefreshTokenStore``: the sealed slot always takes the write, while the
        /// readable one is only *created* by an establishing commit — a rotation against a locked
        /// domain seals and leaves it absent.
        func store(_ token: String, domainIdentifier: String, establishing: Bool) throws {
            lock.lock(); defer { lock.unlock() }
            sealed.insert(domainIdentifier)
            guard establishing || tokens[domainIdentifier] != nil else { return }
            tokens[domainIdentifier] = token
        }
        func delete(domainIdentifier: String) throws {
            lock.lock(); defer { lock.unlock() }
            tokens[domainIdentifier] = nil
            sealed.remove(domainIdentifier)
        }
        func hasSealedToken(domainIdentifier: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return sealed.contains(domainIdentifier)
        }
        func snapshot(_ domainIdentifier: String) -> String? {
            lock.lock(); defer { lock.unlock() }
            return tokens[domainIdentifier]
        }
        var storedCount: Int {
            lock.lock(); defer { lock.unlock() }
            return tokens.count + sealed.count
        }
    }

    /// Serves a canned response (or throws a canned error) for every request, counting hits.
    private final class StubURLProtocol: URLProtocol {
        struct Stub: @unchecked Sendable {
            var statusCode: Int = 200
            var body: Data = Data()
            var error: Error?
        }
        nonisolated(unsafe) static var stub = Stub()
        nonisolated(unsafe) static var requestCount = 0
        private static let lock = NSLock()

        static func reset(_ newStub: Stub) {
            lock.lock(); defer { lock.unlock() }
            stub = newStub
            requestCount = 0
        }
        static var hits: Int {
            lock.lock(); defer { lock.unlock() }
            return requestCount
        }

        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func stopLoading() {}

        override func startLoading() {
            Self.lock.lock()
            Self.requestCount += 1
            let stub = Self.stub
            Self.lock.unlock()

            if let error = stub.error {
                client?.urlProtocol(self, didFailWithError: error)
                return
            }
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: stub.statusCode,
                                           httpVersion: nil,
                                           headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: stub.body)
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    // MARK: - Fixtures

    private func makeStore(seeded: [String: String] = [:],
                           sealedOnly: Set<String> = []) -> (MSALTokenStore, InMemoryRefreshTokenStore) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)

        let config = OAuthConfig(
            clientID: "test-client",
            authorizeEndpoint: URL(string: "https://example.invalid/authorize")!,
            tokenEndpoint: URL(string: "https://example.invalid/token")!,
            redirectURI: "test://auth",
            scopes: ["Files.ReadWrite", "offline_access"])

        let refreshTokens = InMemoryRefreshTokenStore(seeded: seeded, sealedOnly: sealedOnly)
        let store = MSALTokenStore(config: config, urlSession: session, refreshTokens: refreshTokens)
        return (store, refreshTokens)
    }

    private func tokenPayload(accessToken: String,
                              refreshToken: String? = nil,
                              expiresIn: Int = 3600) -> Data {
        var parts = [
            "\"access_token\":\"\(accessToken)\"",
            "\"token_type\":\"Bearer\"",
            "\"expires_in\":\(expiresIn)"
        ]
        if let refreshToken { parts.append("\"refresh_token\":\"\(refreshToken)\"") }
        return Data("{\(parts.joined(separator: ","))}".utf8)
    }

    // MARK: - Tests

    func testNoStoredRefreshTokenThrowsNotAuthenticated() async {
        StubURLProtocol.reset(.init())
        let (store, _) = makeStore()

        do {
            _ = try await store.accessToken(for: domainID)
            XCTFail("expected notAuthenticated")
        } catch {
            XCTAssertEqual(error as? AuthError, .notAuthenticated)
        }
        XCTAssertEqual(StubURLProtocol.hits, 0, "must not hit the network without a refresh token")
    }

    func testSuccessfulRefreshReturnsAccessToken() async throws {
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-1")))
        let (store, _) = makeStore(seeded: [domainID: "refresh-1"])

        let token = try await store.accessToken(for: domainID)

        XCTAssertEqual(token, "access-1")
        XCTAssertEqual(StubURLProtocol.hits, 1)
    }

    func testRotatedRefreshTokenIsPersisted() async throws {
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-1",
                                                        refreshToken: "refresh-2")))
        let (store, refreshTokens) = makeStore(seeded: [domainID: "refresh-1"])

        _ = try await store.accessToken(for: domainID)

        XCTAssertEqual(refreshTokens.snapshot(domainID), "refresh-2",
                       "Microsoft rotates refresh tokens; the new one must replace the old")
    }

    func testInvalidGrantThrowsRefreshRejectedAndClearsStoredToken() async {
        StubURLProtocol.reset(.init(statusCode: 400,
                                    body: Data(#"{"error":"invalid_grant"}"#.utf8)))
        let (store, refreshTokens) = makeStore(seeded: [domainID: "refresh-dead"])

        do {
            _ = try await store.accessToken(for: domainID)
            XCTFail("expected refreshRejected")
        } catch {
            XCTAssertEqual(error as? AuthError, .refreshRejected)
        }
        XCTAssertNil(refreshTokens.snapshot(domainID),
                     "a dead refresh token must be dropped so the UI can prompt re-auth")
    }

    func testNonInvalidGrantHTTPFailureThrowsTokenEndpointFailure() async {
        StubURLProtocol.reset(.init(statusCode: 500, body: Data("boom".utf8)))
        let (store, refreshTokens) = makeStore(seeded: [domainID: "refresh-1"])

        do {
            _ = try await store.accessToken(for: domainID)
            XCTFail("expected tokenEndpointFailure")
        } catch AuthError.tokenEndpointFailure(let status, _) {
            XCTAssertEqual(status, 500)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(refreshTokens.snapshot(domainID), "refresh-1",
                       "a server-side blip must not discard a good refresh token")
    }

    /// Offline must reach the caller as an unwrapped `URLError` — `CredentialValidationError`
    /// keys the "Unable to contact OneDrive" message off exactly this.
    func testOfflinePropagatesURLErrorUnwrapped() async {
        StubURLProtocol.reset(.init(error: URLError(.notConnectedToInternet)))
        let (store, refreshTokens) = makeStore(seeded: [domainID: "refresh-1"])

        do {
            _ = try await store.accessToken(for: domainID)
            XCTFail("expected URLError")
        } catch let urlError as URLError {
            XCTAssertEqual(urlError.code, .notConnectedToInternet)
        } catch {
            XCTFail("offline must surface as URLError, not \(type(of: error)): \(error)")
        }
        XCTAssertEqual(refreshTokens.snapshot(domainID), "refresh-1",
                       "being offline must not discard a valid refresh token")
    }

    func testCachedAccessTokenSkipsSecondNetworkCall() async throws {
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-1")))
        let (store, _) = makeStore(seeded: [domainID: "refresh-1"])

        let first = try await store.accessToken(for: domainID)
        let second = try await store.accessToken(for: domainID)

        XCTAssertEqual(first, second)
        XCTAssertEqual(StubURLProtocol.hits, 1, "a valid cached token must not trigger a refresh")
    }

    /// Tokens within the 60 s expiry safety margin are treated as stale.
    func testNearlyExpiredAccessTokenIsRefreshed() async throws {
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-1", expiresIn: 30)))
        let (store, _) = makeStore(seeded: [domainID: "refresh-1"])

        _ = try await store.accessToken(for: domainID)
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-2", expiresIn: 3600)))
        let second = try await store.accessToken(for: domainID)

        XCTAssertEqual(second, "access-2")
        XCTAssertEqual(StubURLProtocol.hits, 1, "second call must re-refresh")
    }

    func testHasCredentialReflectsStoredToken() async {
        let (store, _) = makeStore(seeded: [domainID: "refresh-1"])
        let present = await store.hasCredential(domainID)
        let absent = await store.hasCredential("other")

        XCTAssertTrue(present)
        XCTAssertFalse(absent)
    }

    // MARK: Locked vault (task doc test 14)

    /// A `nil` read with a sealed blob present is a *locked vault*, not a missing credential.
    ///
    /// The two demand opposite remedies — "unlock this vault" versus "sign in again" — so the
    /// UI cannot be allowed to conflate them.
    func testLockedVaultThrowsVaultLockedNotNotAuthenticated() async {
        StubURLProtocol.reset(.init())
        let (store, _) = makeStore(sealedOnly: [domainID])

        do {
            _ = try await store.accessToken(for: domainID)
            XCTFail("expected vaultLocked")
        } catch {
            XCTAssertEqual(error as? AuthError, .vaultLocked)
        }
        XCTAssertEqual(StubURLProtocol.hits, 0, "a locked vault must not hit the network")
    }

    func testNoSealedTokenThrowsNotAuthenticated() async {
        StubURLProtocol.reset(.init())
        let (store, _) = makeStore()

        do {
            _ = try await store.accessToken(for: domainID)
            XCTFail("expected notAuthenticated")
        } catch {
            XCTAssertEqual(error as? AuthError, .notAuthenticated)
        }
    }

    // MARK: Pending buffer (task doc test 15)

    /// Sign-in precedes domain creation, so a `nil` `domainIdentifier` must persist nothing and
    /// hand back a handle the caller can later commit or discard.
    func testPendingExchangeBuffersInMemoryAndCommitsOnDemand() async throws {
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-1",
                                                        refreshToken: "refresh-1")))
        let (store, refreshTokens) = makeStore()

        let handle = try await store.exchangeAuthorizationCode("code", pkce: PKCE(),
                                                               domainIdentifier: nil)
        let pendingHandle = try XCTUnwrap(handle)
        XCTAssertEqual(refreshTokens.storedCount, 0,
                       "a sign-in with no domain yet must write nothing durable")

        // The buffered access token serves the folder picker before any domain exists.
        let picker = try await store.accessToken(for: pendingHandle)
        XCTAssertEqual(picker, "access-1")
        XCTAssertEqual(StubURLProtocol.hits, 1, "the cached access token must serve the picker")

        try await store.commitPendingCredential(pendingHandle, to: domainID)

        XCTAssertEqual(refreshTokens.snapshot(domainID), "refresh-1")
        // The buffer is empty: a second commit finds nothing.
        do {
            try await store.commitPendingCredential(pendingHandle, to: "other")
            XCTFail("expected the buffer entry to be gone")
        } catch {
            XCTAssertEqual(error as? AuthError, .notAuthenticated)
        }
        // The access token was re-keyed rather than re-minted.
        let committed = try await store.accessToken(for: domainID)
        XCTAssertEqual(committed, "access-1")
        XCTAssertEqual(StubURLProtocol.hits, 1)
    }

    func testDiscardPendingCredentialLeavesNothing() async throws {
        StubURLProtocol.reset(.init(body: tokenPayload(accessToken: "access-1",
                                                        refreshToken: "refresh-1")))
        let (store, refreshTokens) = makeStore()

        let issued = try await store.exchangeAuthorizationCode("code", pkce: PKCE(),
                                                               domainIdentifier: nil)
        let handle = try XCTUnwrap(issued)
        await store.discardPendingCredential(handle)

        XCTAssertEqual(refreshTokens.storedCount, 0)
        do {
            try await store.commitPendingCredential(handle, to: domainID)
            XCTFail("expected a discarded handle to hold nothing")
        } catch {
            XCTAssertEqual(error as? AuthError, .notAuthenticated)
        }
    }

    func testSignOutRemovesRefreshToken() async throws {
        let (store, refreshTokens) = makeStore(seeded: [domainID: "refresh-1"])

        try await store.signOut(domainIdentifier: domainID)

        XCTAssertNil(refreshTokens.snapshot(domainID))
    }
}
