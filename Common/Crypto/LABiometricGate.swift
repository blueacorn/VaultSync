/// LocalAuthentication-backed ``BiometricGate`` (device owner auth: Touch ID / passcode).
///
/// Only the container app should present this — `Provider.appex` has no UI and must route
/// unlock through the app.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation
import LocalAuthentication

public struct LABiometricGate: BiometricGate {
    public init() {}

    public var isAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    public func authenticate(reason: String) async throws {
        _ = try await evaluate(reason: reason)
    }

    public func authenticatedContext(reason: String) async throws -> AnyObject? {
        try await evaluate(reason: reason)
    }

    /// Invalidate the evaluated context, ending the presence it grants.
    ///
    /// `LAContext.invalidate()` drops the authenticated state immediately, so the token cannot
    /// satisfy a later ACL'd read even if a reference to it survives. Relying on deallocation
    /// alone would leave the end of that capability up to ARC.
    public func invalidateContext(_ context: AnyObject?) {
        (context as? LAContext)?.invalidate()
    }

    /// Evaluate device-owner auth and return the live, now-authenticated context. Binding this
    /// context into a keychain query (`kSecUseAuthenticationContext`) lets an ACL item be
    /// written/read under this presence without a second prompt.
    private func evaluate(reason: String) async throws -> LAContext {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw VaultKeyStoreError.biometricsUnavailable
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalError in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: evalError ?? VaultKeyStoreError.biometricsUnavailable)
                }
            }
        }
        return context
    }
}
