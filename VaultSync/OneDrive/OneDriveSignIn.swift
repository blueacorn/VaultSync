/// Interactive OneDrive (Microsoft identity) sign-in for the container app.
///
/// Runs the OAuth 2.0 authorization-code + PKCE flow via
/// `ASWebAuthenticationSession`, then hands the returned code to
/// ``MSALTokenStore`` to exchange for tokens. The resulting refresh token lands in the
/// domain's sealed App Group keychain slot, where the sandboxed File Provider extension reads
/// it — or, when the domain does not exist yet, in the token store's pending buffer until the
/// caller commits it (see ``signIn(presentingFrom:domainID:)``).
///
/// Only the container app performs interactive sign-in; the extension is silent
/// (refresh-token grant only). See `/docs/backend/remote-onedrive.md#authentication`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import AuthenticationServices
import Common
import os.log

/// Drives the interactive authorization-code + PKCE login.
@MainActor
public final class OneDriveSignIn: NSObject {

    private static let log = Logger(subsystem: "org.vaultsync.VaultSync", category: "auth")

    private let config: OAuthConfig
    private let tokenStore: MSALTokenStore
    private var session: ASWebAuthenticationSession?
    /// Retained for the lifetime of the auth session; `presentationContextProvider`
    /// is a weak reference, so without this the provider deallocates immediately.
    private var anchorProvider: AnchorProvider?

    public init(config: OAuthConfig = .oneDrivePersonal,
                tokenStore: MSALTokenStore = .shared) {
        self.config = config
        self.tokenStore = tokenStore
    }

    /// Present the system auth sheet and complete sign-in.
    ///
    /// One implementation serves both entry points; the only difference is whether a domain
    /// already exists to key the credential on:
    ///
    /// - **New domain** (`domainID == nil`) — sign-in precedes the domain, so the refresh token
    ///   is held in ``MSALTokenStore``'s in-memory pending buffer and the returned handle is the
    ///   caller's claim on it. The caller commits it once the domain is created, or discards it
    ///   if the form is abandoned. Nothing reaches the keychain in the meantime.
    /// - **Existing domain** (`domainID != nil`) — the token is sealed straight into that
    ///   domain's slot and `nil` is returned; there is nothing pending to commit.
    ///
    /// - Parameters:
    ///   - anchor: Window to anchor the auth sheet to.
    ///   - domainID: Identifier of the domain being signed in, or `nil` when it does not exist yet.
    /// - Returns: The pending credential handle when `domainID` is `nil`, otherwise `nil`.
    @discardableResult
    public func signIn(presentingFrom anchor: ASPresentationAnchor,
                       domainID: String?) async throws -> String? {
        let pkce = PKCE()
        let state = UUID().uuidString
        let authorizeURL = makeAuthorizeURL(pkce: pkce, state: state)

        let callbackURL = try await present(authorizeURL: authorizeURL, anchor: anchor)
        let code = try extractCode(from: callbackURL, expectedState: state)

        let handle = try await tokenStore.exchangeAuthorizationCode(code, pkce: pkce,
                                                                    domainIdentifier: domainID)
        Self.log.infoPublic("✅ OneDrive sign-in complete, refresh token \(handle == nil ? "stored" : "held pending")")
        return handle
    }

    // MARK: URL building

    private func makeAuthorizeURL(pkce: PKCE, state: String) -> URL {
        var components = URLComponents(url: config.authorizeEndpoint, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI),
            URLQueryItem(name: "response_mode", value: "query"),
            URLQueryItem(name: "scope", value: config.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: pkce.codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: pkce.method),
            URLQueryItem(name: "prompt", value: "select_account")
        ]
        return components.url!
    }

    private func extractCode(from callbackURL: URL, expectedState: String) throws -> String {
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let items = components.queryItems else {
            throw AuthError.tokenEndpointFailure(status: -1, body: "malformed callback URL")
        }
        if let error = items.first(where: { $0.name == "error" })?.value {
            let desc = items.first(where: { $0.name == "error_description" })?.value ?? ""
            throw AuthError.tokenEndpointFailure(status: -1, body: "\(error): \(desc)")
        }
        guard items.first(where: { $0.name == "state" })?.value == expectedState else {
            throw AuthError.tokenEndpointFailure(status: -1, body: "state mismatch")
        }
        guard let code = items.first(where: { $0.name == "code" })?.value else {
            throw AuthError.tokenEndpointFailure(status: -1, body: "missing authorization code")
        }
        return code
    }

    // MARK: Web auth session

    private func present(authorizeURL: URL, anchor: ASPresentationAnchor) async throws -> URL {
        // The callback scheme is the custom URL scheme registered in Info.plist.
        let scheme = URL(string: config.redirectURI)?.scheme

        return try await withCheckedThrowingContinuation { continuation in
            // Guard against double-resume: the completion handler and the start()-failure
            // path are mutually exclusive, and a continuation may resume only once.
            var didResume = false
            func resume(_ result: Result<URL, Error>) {
                guard !didResume else { return }
                didResume = true
                continuation.resume(with: result)
            }

            let session = ASWebAuthenticationSession(url: authorizeURL, callbackURLScheme: scheme) { callbackURL, error in
                if let error = error {
                    resume(.failure(error))
                } else if let callbackURL = callbackURL {
                    resume(.success(callbackURL))
                } else {
                    resume(.failure(AuthError.tokenEndpointFailure(status: -1, body: "no callback URL")))
                }
            }
            // Retain the provider; presentationContextProvider is weak.
            let provider = AnchorProvider(anchor: anchor)
            self.anchorProvider = provider
            session.presentationContextProvider = provider
            session.prefersEphemeralWebBrowserSession = false
            self.session = session
            if !session.start() {
                resume(.failure(AuthError.tokenEndpointFailure(status: -1, body: "failed to start auth session")))
            }
        }
    }
}

/// Supplies the presentation anchor to `ASWebAuthenticationSession`.
private final class AnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor
    init(anchor: ASPresentationAnchor) { self.anchor = anchor }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }
}
