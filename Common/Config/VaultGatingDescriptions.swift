/// The single source of the four gating options' user-facing copy.
//
//  VaultGatingDescriptions.swift
//  Common
//
//  User-facing copy for the four gating options.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation

/// The single source of the four gating options' user-facing copy.
///
/// Gating is chosen once for the whole install on the Security screen; the edit-domain
/// screen shows the same copy read-only. The labels and trade-off text live here rather than
/// being written twice and drifting apart.
///
/// The `.secure` warning is **required copy**, not a nicety: enrolling or removing a fingerprint
/// destroys the Secure Enclave key and with it every `domainKey.wrapped` gated `.secure`. The design
/// accepts that loss only on the basis that the user was told at the point of choice, which is
/// why ``secureEnclaveWarning`` is split out for emphatic rendering rather than buried in prose.
extension SharedConfig.VaultGating {

    /// The option's label, as shown beside its control.
    public var displayName: String {
        switch self {
        case .none: return "No Protection"
        case .pin: return "PIN"
        case .biometric: return "Touch ID or Password"
        case .secure: return "Secure Enclave (Touch ID Only)"
        }
    }

    /// What choosing this option means, shown beneath the selection.
    ///
    /// For ``SharedConfig/VaultGating/secure`` this is the neutral half only; render
    /// ``secureEnclaveWarning`` after it with visible emphasis.
    ///
    /// Only `.secure` claims per-vault isolation, because only `.secure` has it: its gating
    /// keypair is minted per domain, while the other three share one install-wide keypair
    /// (I5′). The shared three must not imply an isolation they do not provide.
    public var unlockDescription: String {
        switch self {
        case .none:
            return "Vaults unlock automatically. Anything running on this Mac can open them. "
                 + "Auto-lock still hides vaults from Finder, but does not protect their contents."
        case .pin:
            return "Vaults unlock with a 4–8 digit PIN. The PIN is never stored — only a "
                 + "verifier used to reject a wrong entry."
        case .biometric:
            return "Vaults unlock with Touch ID, or your Mac's password if Touch ID is "
                 + "unavailable. The unlock key can be read by this app once Touch ID succeeds, "
                 + "and one unlock covers every vault."
        case .secure:
            return "Vaults unlock with Touch ID only — your Mac's password will not work. The "
                 + "key is held in the Secure Enclave and can never be read by any app. Each "
                 + "vault gets its own key, so unlocking one never exposes another."
        }
    }

    /// The unrecoverable-loss warning, for the one option that carries it.
    ///
    /// `nil` for every other case, so callers render it unconditionally without branching on
    /// `.secure`.
    public var secureEnclaveWarning: String? {
        guard self == .secure else { return nil }
        return "Adding or removing a fingerprint destroys this key: you will need to set up "
             + "these vaults again."
    }

    /// The order the four options are offered in, weakest to strongest.
    public static let displayOrder: [SharedConfig.VaultGating] = [.none, .pin, .biometric, .secure]
}

/// Copy shared by every surface that explains what locking costs.
///
/// Stated once, for all domains, rather than special-cased for `.plain`: a plaintext
/// OneDrive vault needs no key material to serve its files, but its refresh token is gated like
/// any other domain secret, so locking it stops its Provider just the same. Saying it for
/// everyone avoids a behavioural fork on the encryption algorithm.
public enum VaultLockCopy {
    /// Why a locked vault stops serving, whatever its contents are.
    public static let lockedDomainConsequence =
        "Locking a vault also gates the credential it connects with, so a locked vault stops "
        + "serving files in Finder — including vaults whose files are stored unencrypted."

    /// What the user must do about a locked vault. Never "sign in again": re-authentication
    /// cannot succeed while the credential is sealed.
    public static let lockedCallToAction = "Unlock this vault to use it again."
}
