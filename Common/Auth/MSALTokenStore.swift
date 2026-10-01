/// Hand-rolled OAuth 2.0 token store for the Microsoft identity platform.
///
/// Despite the name (kept for continuity with the design docs), this is **not** the
/// Microsoft MSAL SDK. It is a minimal, dependency-free store that:
///
/// - persists the long-lived **refresh token** sealed to the domain's `refreshTokenKey.pub`,
///   with the opened copy in the Provider-readable slot, so both the container app (which
///   performs the interactive sign-in) and the sandboxed File Provider extension (which mints
///   access tokens silently) can reach it while the vault is unlocked;
/// - caches short-lived **access tokens** in memory, per process, refreshing them via
///   the `refresh_token` grant on miss or expiry.
///
/// Tokens are keyed by the `NSFileProviderDomainIdentifier` raw value: credentials are
/// **domain-scoped**. Each domain performs its own interactive sign-in and owns exactly one
/// refresh token; nothing is shared between domains, so signing a domain out can never
/// invalidate another's session.
///
/// ## Threading
/// ``MSALTokenStore`` is an `actor`; the in-memory access-token cache and refresh
/// coalescing are isolated to it. Refresh-token persistence is synchronous and serialised
/// by the actor.
///
/// ## Testing
/// Refresh-token persistence goes through the ``RefreshTokenStoring`` seam, defaulting to
/// ``VaultRefreshTokenStore``. Tests substitute an in-memory double (the keychain is
/// unreachable from non-host bundles) together with a stubbed `URLSession`.
///
/// ## Endpoints
/// Uses the **consumers** tenant (personal Microsoft accounts) per the v1 scope:
/// OneDrive Personal only. See `/docs/backend/remote-onedrive.md#authentication`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import CryptoKit
import os.log

// MARK: - Configuration

/// Static OAuth client configuration for the VaultSync Microsoft identity app.
///
/// `clientID` must match the application (client) ID registered in the Microsoft
/// Entra / Azure portal as a **personal-accounts** app with the redirect URI below
/// registered as a custom-scheme (macOS) redirect. See `/docs/backend/remote-onedrive.md#authentication`.
public struct OAuthConfig: Sendable {

    public let clientID: String
    public let authorizeEndpoint: URL
    public let tokenEndpoint: URL
    public let redirectURI: String
    public let scopes: [String]

    public init(clientID: String,
                authorizeEndpoint: URL,
                tokenEndpoint: URL,
                redirectURI: String,
                scopes: [String]) {
        self.clientID = clientID
        self.authorizeEndpoint = authorizeEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.redirectURI = redirectURI
        self.scopes = scopes
    }

    /// The default OneDrive Personal (consumers tenant) configuration.
    ///
    /// The client ID is read from the `MSGraphClientID` key in the main bundle's
    /// `Info.plist` so it can be supplied per build without hard-coding a secret-like
    /// value in source. Falls back to a clearly-invalid placeholder.
    public static var oneDrivePersonal: OAuthConfig {
        let raw = (Bundle.main.object(forInfoDictionaryKey: "MSGraphClientID") as? String) ?? ""
        let clientID = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if clientID.isEmpty || clientID == "REPLACE_WITH_AZURE_CLIENT_ID" {
            Logger(subsystem: "org.vaultsync.VaultSync", category: "auth")
                .errorPublic("❌ MSGraphClientID is unset/placeholder — set MSGRAPH_CLIENT_ID in build settings. OneDrive auth will fail with AADSTS700016.")
        }
        return OAuthConfig(
            clientID: clientID,
            authorizeEndpoint: URL(string: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize")!,
            tokenEndpoint: URL(string: "https://login.microsoftonline.com/consumers/oauth2/v2.0/token")!,
            redirectURI: "\(AppIdentifiers.oauthRedirectScheme)://auth",
            scopes: ["Files.ReadWrite", "offline_access", "User.Read"]
        )
    }
}

// MARK: - PKCE

/// A Proof Key for Code Exchange (RFC 7636) pair using the `S256` method.
public struct PKCE: Sendable {

    /// High-entropy random verifier (43–128 chars, unreserved set).
    public let codeVerifier: String
    /// Base64URL(SHA256(codeVerifier)).
    public let codeChallenge: String
    public let method = "S256"

    public init() {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let verifier = Data(bytes).base64URLEncodedString()
        self.codeVerifier = verifier
        let digest = SHA256.hash(data: Data(verifier.utf8))
        self.codeChallenge = Data(digest).base64URLEncodedString()
    }
}

// MARK: - Token model

/// Decoded `/token` response (authorization-code or refresh-token grant).
struct TokenResponse: Decodable {
    let accessToken: String
    let refreshToken: String?
    let expiresIn: Int
    let tokenType: String

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
    }
}

/// A cached access token with its absolute expiry.
private struct CachedAccessToken {
    let token: String
    let expiresAt: Date

    /// Treat as valid only with a 60 s safety margin before true expiry.
    var isValid: Bool { Date() < expiresAt.addingTimeInterval(-60) }
}

// MARK: - Errors

public enum AuthError: Error, Equatable {
    /// No refresh token is stored for the domain — interactive sign-in required.
    case notAuthenticated
    /// A refresh token **is** sealed for the domain, but the vault is locked so it cannot be
    /// opened. The user must *unlock this vault*.
    case vaultLocked
    /// The refresh token was rejected (`invalid_grant`) — **re-authentication required**.
    case refreshRejected
    /// The token endpoint returned an unexpected response.
    case tokenEndpointFailure(status: Int, body: String)
    /// Keychain operation failed.
    case keychain(OSStatus)
}

// MARK: - Refresh-token persistence seam

/// Persistence for the long-lived refresh token.
///
/// Exists so ``MSALTokenStore`` can be unit-tested: the real implementation is the vault's
/// sealed token slots, which are unavailable to non-host test bundles (no App Group entitlement),
/// and which would otherwise short-circuit every test at `readRefreshToken` before the network is
/// reached.
protocol RefreshTokenStoring: Sendable {
    /// The token in the clear, or `nil` when the vault is locked **or** nothing is stored.
    func read(domainIdentifier: String) throws -> String?
    /// Persist `token` for the domain.
    ///
    /// - Parameter establishing: `true` only for the initial commit that follows provisioning,
    ///   which creates the Provider-readable plaintext slot. A rotation leaves this `false`, so a
    ///   commit against a locked domain seals without re-creating the slot lock deleted.
    func store(_ token: String, domainIdentifier: String, establishing: Bool) throws
    func delete(domainIdentifier: String) throws
    /// Whether a sealed token exists for the domain, regardless of lock state.
    ///
    /// Separates the two reasons ``read(domainIdentifier:)`` returns `nil`, which the caller
    /// cannot otherwise tell apart. Lives on the seam so the discrimination is testable without
    /// a keychain.
    func hasSealedToken(domainIdentifier: String) -> Bool
}

/// Vault-backed implementation of ``RefreshTokenStoring`` — the sealed/unsealed token slot pair
/// shared between the container app and the File Provider extension.
///
/// Reads the Provider-readable `refreshToken.unwrapped` slot and writes through
/// ``VaultKeyStore/commitRefreshToken(_:for:)``, which seals to `refreshTokenKey.pub`. Sealing
/// needs only the public half, so a rotation performed while locked — by the Provider, or by a
/// locked app — persists correctly with no `domainKey` held anywhere; the plaintext slot is
/// refreshed alongside it only while the domain is already open, and otherwise waits for the next
/// unlock.
struct VaultRefreshTokenStore: RefreshTokenStoring {

    /// The store commits are routed through. The process-wide instance by default; its PIN
    /// throttle is per-instance state that must not be reset by minting a second one.
    private let keyStore: VaultKeyStore

    init(keyStore: VaultKeyStore = .shared) {
        self.keyStore = keyStore
    }

    func read(domainIdentifier: String) throws -> String? {
        try CryptoKeychain.loadUnwrappedRefreshToken(for: domainIdentifier)
    }

    func store(_ token: String, domainIdentifier: String, establishing: Bool) throws {
        try keyStore.commitRefreshToken(token, for: domainIdentifier, establishing: establishing)
    }

    /// Removes both token slots for this domain, and no other domain's.
    ///
    /// The sealed slot must go too: leaving it would let the next unlock resurrect a token the
    /// user has signed out of.
    func delete(domainIdentifier: String) throws {
        try CryptoKeychain.deleteUnwrappedRefreshToken(for: domainIdentifier)
        try CryptoKeychain.deleteWrappedRefreshToken(for: domainIdentifier)
    }

    func hasSealedToken(domainIdentifier: String) -> Bool {
        ((try? CryptoKeychain.loadWrappedRefreshToken(for: domainIdentifier)) ?? nil) != nil
    }
}

// MARK: - Store

public actor MSALTokenStore {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "auth")

    private let config: OAuthConfig
    private let urlSession: URLSession
    /// Refresh-token persistence; the App Group keychain in production, a double in tests.
    private let refreshTokens: any RefreshTokenStoring

    /// In-memory access-token cache keyed by domain identifier — or, before a domain exists, by
    /// the pending handle.
    private var accessTokens: [String: CachedAccessToken] = [:]
    /// Refresh tokens from a sign-in that precedes its domain, keyed by pending handle. Never
    /// written to the keychain: an abandoned sign-in must leave nothing behind.
    private var pendingRefreshTokens: [String: String] = [:]
    /// Coalesce concurrent refreshes for the same domain.
    private var inFlightRefresh: [String: Task<String, Error>] = [:]

    public init(config: OAuthConfig = .oneDrivePersonal, urlSession: URLSession = .shared) {
        self.init(config: config, urlSession: urlSession,
                  refreshTokens: VaultRefreshTokenStore())
    }

    /// Testing seam: substitutes refresh-token persistence so the network paths can be
    /// exercised without the App Group keychain.
    init(config: OAuthConfig = .oneDrivePersonal,
         urlSession: URLSession = .shared,
         refreshTokens: any RefreshTokenStoring) {
        self.config = config
        self.urlSession = urlSession
        self.refreshTokens = refreshTokens
    }

    /// Process-wide shared store for the OneDrive Personal configuration.
    ///
    /// Microsoft rotates refresh tokens (single-use); every consumer **must** share one
    /// instance so refresh coalescing and token rotation are serialised. Constructing
    /// separate stores races concurrent refreshes and yields `refreshRejected`.
    public static let shared = MSALTokenStore()

    // MARK: Public API

    /// A valid bearer access token for `domainIdentifier`, refreshing if needed.
    ///
    /// `domainIdentifier` also accepts a pending handle returned by
    /// ``exchangeAuthorizationCode(_:pkce:domainIdentifier:)`` before the domain exists, so the
    /// folder picker can call Graph during the sign-in sheet.
    ///
    /// - Throws: ``AuthError/vaultLocked`` when a sealed token exists but the vault is locked;
    ///   ``AuthError/notAuthenticated`` when none is stored at all;
    ///   ``AuthError/refreshRejected`` when the stored refresh token is invalid.
    public func accessToken(for domainIdentifier: String) async throws -> String {
        if let cached = accessTokens[domainIdentifier], cached.isValid {
            return cached.token
        }
        if let existing = inFlightRefresh[domainIdentifier] {
            return try await existing.value
        }
        let task = Task<String, Error> { try await self.refresh(domainIdentifier: domainIdentifier) }
        inFlightRefresh[domainIdentifier] = task
        defer { inFlightRefresh[domainIdentifier] = nil }
        return try await task.value
    }

    /// Exchange an authorization `code` for tokens (PKCE).
    ///
    /// Called by the app after the interactive sign-in redirect. Sign-in runs **before** the
    /// domain exists, so `domainIdentifier` is optional:
    ///
    /// - non-`nil` — the refresh token is committed to that domain's sealed slot immediately;
    ///   `nil` is returned.
    /// - `nil` — the refresh token is held in memory under a freshly minted handle, which is
    ///   returned. Nothing reaches the keychain. The caller passes the handle to
    ///   ``commitPendingCredential(_:to:)`` once the domain is created, or to
    ///   ``discardPendingCredential(_:)`` if the sheet is abandoned.
    ///
    /// Returning the handle rather than accepting a caller-supplied one keeps the buffer key an
    /// implementation detail: there is no second identifier for a caller to invent, collide on,
    /// or forget to make unique now that `credentialID` is gone.
    ///
    /// - Returns: The pending handle when `domainIdentifier` is `nil`, otherwise `nil`.
    @discardableResult
    public func exchangeAuthorizationCode(_ code: String,
                                          pkce: PKCE,
                                          domainIdentifier: String?) async throws -> String? {
        var form = [
            "client_id": config.clientID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirectURI,
            "code_verifier": pkce.codeVerifier,
            "scope": config.scopes.joined(separator: " ")
        ]
        let response = try await postToken(form: &form)
        guard let refresh = response.refreshToken else {
            throw AuthError.tokenEndpointFailure(status: 200, body: "missing refresh_token; ensure offline_access scope")
        }
        let cached = CachedAccessToken(
            token: response.accessToken,
            expiresAt: Date().addingTimeInterval(TimeInterval(response.expiresIn))
        )
        guard let domainIdentifier else {
            let handle = UUID().uuidString
            pendingRefreshTokens[handle] = refresh
            // Cached under the handle so the folder picker can reach Graph before any domain
            // exists; re-keyed to the real identifier on commit.
            accessTokens[handle] = cached
            return handle
        }
        // An interactive sign-in establishes the credential: the plaintext slot is created here,
        // not refreshed.
        try storeRefreshToken(refresh, domainIdentifier: domainIdentifier, establishing: true)
        accessTokens[domainIdentifier] = cached
        return nil
    }

    /// Commit a buffered refresh token to a now-existing domain and drop the buffer entry.
    ///
    /// The domain must already be provisioned — ``VaultKeyStore/commitRefreshToken(_:for:)`` seals
    /// to its `refreshTokenKey.pub`, which provisioning writes.
    ///
    /// - Parameters:
    ///   - handle: The handle returned by ``exchangeAuthorizationCode(_:pkce:domainIdentifier:)``.
    ///   - domainIdentifier: The domain the credential now belongs to.
    /// - Throws: ``AuthError/notAuthenticated`` when the handle names no buffered token.
    public func commitPendingCredential(_ handle: String, to domainIdentifier: String) throws {
        guard let token = pendingRefreshTokens[handle] else { throw AuthError.notAuthenticated }
        // The first commit for a just-provisioned domain: it has no plaintext slot yet, and the
        // domain is open, so this creates it.
        try storeRefreshToken(token, domainIdentifier: domainIdentifier, establishing: true)
        pendingRefreshTokens[handle] = nil
        // Carry the already-minted access token over rather than forcing an immediate refresh.
        accessTokens[domainIdentifier] = accessTokens[handle]
        accessTokens[handle] = nil
    }

    /// Drop a buffered credential — sheet dismissed unsaved, or `saveDomain` rolled back.
    ///
    /// An abandoned sign-in must leave nothing behind; nothing was ever persisted, so forgetting
    /// the in-memory pair is the whole of it.
    public func discardPendingCredential(_ handle: String) {
        pendingRefreshTokens[handle] = nil
        accessTokens[handle] = nil
    }

    /// Whether a refresh token is readable for `domainIdentifier`.
    ///
    /// `nonisolated`: it reads only the `Sendable` persistence seam, never the actor's
    /// in-memory caches, so synchronous callers (the edit-domain form's initialiser, which
    /// must know the signed-in state before its first render) need not hop onto the actor.
    ///
    /// A locked vault answers `false` — the token is unreadable, which is what a caller deciding
    /// whether it can mint an access token needs to know. ``AuthError/vaultLocked`` is what
    /// distinguishes the two on the path where the distinction matters.
    public nonisolated func hasCredential(_ domainIdentifier: String) -> Bool {
        ((try? refreshTokens.read(domainIdentifier: domainIdentifier)) ?? nil) != nil
    }

    /// Remove all tokens for `domainIdentifier` (sign-out).
    public func signOut(domainIdentifier: String) throws {
        accessTokens[domainIdentifier] = nil
        try deleteRefreshToken(domainIdentifier: domainIdentifier)
    }

    // MARK: Refresh

    private func refresh(domainIdentifier: String) async throws -> String {
        guard let refreshToken = try readRefreshToken(domainIdentifier: domainIdentifier)
                ?? pendingRefreshTokens[domainIdentifier] else {
            // `read` returning nil means "locked" or "absent"; only the seam can tell them apart.
            throw refreshTokens.hasSealedToken(domainIdentifier: domainIdentifier)
                ? AuthError.vaultLocked
                : AuthError.notAuthenticated
        }
        var form = [
            "client_id": config.clientID,
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "redirect_uri": config.redirectURI,
            "scope": config.scopes.joined(separator: " ")
        ]
        let response: TokenResponse
        do {
            response = try await postToken(form: &form)
        } catch AuthError.refreshRejected {
            // The refresh token is dead; drop it so the UI can prompt re-auth.
            try? deleteRefreshToken(domainIdentifier: domainIdentifier)
            pendingRefreshTokens[domainIdentifier] = nil
            throw AuthError.refreshRejected
        }
        // Microsoft rotates refresh tokens; persist the new one when present. This is the only
        // rotation path — the store is hand-rolled, so there is no SDK cache-change hook to
        // observe. Because `store` routes to `VaultKeyStore.commitRefreshToken`, which
        // seals to `refreshTokenKey.pub` and writes both slots, the seal happens here on write
        // rather than being deferred to lock. A token still buffered (no domain yet) rotates in
        // the buffer, never to the keychain.
        if let rotated = response.refreshToken {
            if pendingRefreshTokens[domainIdentifier] != nil {
                pendingRefreshTokens[domainIdentifier] = rotated
            } else {
                try storeRefreshToken(rotated, domainIdentifier: domainIdentifier)
            }
        }
        let cached = CachedAccessToken(
            token: response.accessToken,
            expiresAt: Date().addingTimeInterval(TimeInterval(response.expiresIn))
        )
        accessTokens[domainIdentifier] = cached
        return cached.token
    }

    private func postToken(form: inout [String: String]) async throws -> TokenResponse {
        var request = URLRequest(url: config.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = form
            .map { "\($0.key)=\($0.value.formURLEncoded)" }
            .joined(separator: "&")
            .data(using: .utf8)

        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AuthError.tokenEndpointFailure(status: -1, body: "no HTTP response")
        }
        guard http.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? ""
            if body.contains("invalid_grant") {
                throw AuthError.refreshRejected
            }
            throw AuthError.tokenEndpointFailure(status: http.statusCode, body: body)
        }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    // MARK: Refresh-token persistence

    private func storeRefreshToken(_ token: String,
                                   domainIdentifier: String,
                                   establishing: Bool = false) throws {
        try refreshTokens.store(token, domainIdentifier: domainIdentifier, establishing: establishing)
    }

    private func readRefreshToken(domainIdentifier: String) throws -> String? {
        try refreshTokens.read(domainIdentifier: domainIdentifier)
    }

    private func deleteRefreshToken(domainIdentifier: String) throws {
        try refreshTokens.delete(domainIdentifier: domainIdentifier)
    }
}

// MARK: - Encoding helpers

public extension Data {
    /// Base64URL without padding (RFC 4648 §5).
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension String {
    /// `application/x-www-form-urlencoded` value encoding.
    var formURLEncoded: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }
}
