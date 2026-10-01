/// Build-configured identifiers shared by every process.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Build-configured identifiers shared by every process.
///
/// Values originate in `Configuration/Application.xcconfig` and are baked into the Common
/// framework's `Info.plist`, so the app, extensions and test bundles all resolve the same
/// identifiers regardless of which process's main bundle is running.
public enum AppIdentifiers {

    /// The app's bundle identifier (e.g. `com.example.VaultSync`); root of every
    /// namespaced identifier (targets, custom actions).
    public static let bundleID = value(forKey: "AppBundleIdentifier")

    /// The shared App Group container and keychain access group identifier.
    public static let appGroupID = value(forKey: "AppGroupIdentifier")

    /// URL scheme registered for the OAuth redirect (`<scheme>://auth`).
    public static let oauthRedirectScheme = value(forKey: "OAuthRedirectScheme")

    private final class BundleMarker {}

    private static func value(forKey key: String) -> String {
        guard let value = Bundle(for: BundleMarker.self).object(forInfoDictionaryKey: key) as? String,
              !value.isEmpty else {
            preconditionFailure("Common Info.plist is missing \(key); check Application.xcconfig")
        }
        return value
    }
}
