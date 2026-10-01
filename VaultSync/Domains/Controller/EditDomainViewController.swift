/// Domain add/edit tab — NSHostingController wrapper hosting `EditDomainView`, plus the
/// `saveDomain` persistence entry point. The SwiftUI view and view model live in
/// `Domains/View/EditDomainView.swift`.
///
/// `saveDomain` runs in two phases: a **preflight** that validates the OneDrive credential,
/// unlocks the `.bckey`, and establishes the vault root without writing anything, then the
/// persistence phase. Nothing is provisioned until preflight passes, so a wrong password or a
/// dead refresh token can never leave a half-configured domain behind.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit
import SwiftUI
import FileProvider
import AuthenticationServices
import Common
import os.log


final class EditDomainViewController: NSHostingController<AnyView> {
    private let model: EditDomainViewModel

    init(domain: NSFileProviderDomain?,
         provisioningService: any DomainProvisioningService,
         allDomains: [NSFileProviderDomain],
         allAccounts: [String: DomainAccount],
         tabTitle: String,
         onClose: @escaping () -> Void) {

        let d = domain ?? NSFileProviderDomain(
            identifier: NSFileProviderDomainIdentifier(rawValue: NSUUID().uuidString),
            displayName: "")
        let m = EditDomainViewModel(domain: d, provisioningService: provisioningService,
                                    allDomains: allDomains, allAccounts: allAccounts)
        self.model = m

        // Only this NSHostingController wrapper is legacy and currently uninstantiated —
        // the static `saveDomain` below is the live save path, called by the SwiftUI
        // `AddEditDomainScreen`, which owns OneDrive sign-in via `AppModel`. Provide a
        // failing stub so sign-in here is a no-op if the wrapper is ever revived.
        super.init(rootView: AnyView(EditDomainView(
            model: m,
            onSignIn: { _ in throw OneDriveSignInRequired() },
            onClose: onClose)))
        title = tabTitle
    }

    @MainActor required dynamic init?(coder: NSCoder) {
        fatalError("init(coder:) not implemented")
    }

    // MARK: - Save (static to avoid retain cycles)

    /// Validates then persists the domain.
    ///
    /// - Parameters:
    ///   - onPreflightPassed: Invoked once validation succeeds and persistence begins, so the
    ///     UI can move from "Verifying…" to "Saving…".
    ///   - tokenStore: Injectable for tests; defaults to the process-wide shared store.
    /// - Throws: ``DuplicateDomainNameError`` if the chosen name is already used by another
    ///   domain or configured account, ``CredentialValidationError`` if the OneDrive credential cannot be
    ///   redeemed, ``BCKeyValidationError`` if the `.bckey`/password pair is missing or
    ///   invalid or the vault root cannot be established. In all cases nothing has been
    ///   persisted.
    static func saveDomain(vm: EditDomainViewModel,
                           encParams: (bckeyURL: URL, password: String)?,
                           onPreflightPassed: @MainActor () -> Void = {},
                           tokenStore: MSALTokenStore = .shared,
                           onClose: @escaping () -> Void) async throws {
        let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "edit-domain-vc")
        let displayName = vm.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !displayName.isEmpty else { return }

        // MARK: Preflight — validate everything before touching any persistent state.

        // The name must be free across both OS-registered domains and the configured accounts
        // in `config.json`. Checking only the former let a "Lock and Remove"d domain's name be
        // reused, since that flow drops the OS domain but keeps its account entry.
        //
        // The form gates Save on the same predicate; this is the authority. The add/edit flow
        // is UI-blocking, so the snapshot the view model holds cannot have gone stale.
        if EditDomainViewModel.isDuplicateName(displayName,
                                               excluding: vm.domain.identifier.rawValue,
                                               allDomains: vm.allDomains,
                                               allAccounts: vm.allAccounts) {
            logger.error("⛔️ duplicate domain name rejected: \(displayName)")
            throw DuplicateDomainNameError()
        }

        // Backend shape: reject an unsupported backend, and confirm a OneDrive sign-in has
        // happened, up front. Both were previously checked inside the persist switch — after
        // the first write for `.localFS`, and only a `guard` away from it for `.oneDrive`.
        //
        // The credential is keyed by this domain's own identifier once it exists, and by the
        // pending handle before then — ``credentialLookupKey`` answers both. Only
        // whether it redeems matters here.
        switch vm.backendKind {
        case .localFS:
            throw CommonError.notImplemented
        case .oneDrive:
            guard vm.isSignedIn else { throw OneDriveSignInRequired() }
            // Prove the stored refresh token still redeems. Without this a revoked or expired
            // credential yields a domain that only fails later, on first enumeration.
            do {
                _ = try await tokenStore.accessToken(for: vm.credentialLookupKey)
            } catch {
                logger.error("⛔️ OneDrive credential check failed: \(error.localizedDescription)")
                throw CredentialValidationError(underlying: error)
            }
        case .emulator:
            break
        }

        // Unlock the key in memory only. Holding the material proves the password is right;
        // it is committed to the keychain further down, once the domain exists.
        var derivedKey: DerivedKeyMaterial?
        if vm.algorithm == .bc01 {
            guard let enc = encParams else {
                // BC01 with no key file and/or password. This used to fall through and save
                // a BC01 domain with no key in the keychain — unusable, and silent.
                throw BCKeyValidationError(missingBckey: vm.bckeyPath.isEmpty,
                                           missingPassword: vm.password.isEmpty)
            }
            do {
                derivedKey = try CryptoConfigViewModel().deriveKey(bckeyURL: enc.bckeyURL,
                                                                   password: enc.password)
            } catch {
                logger.error("⛔️ bckey/password validation failed: \(error.localizedDescription)")
                throw BCKeyValidationError(underlying: error)
            }
        }

        // No vault root to establish. Under I5 each domain mints its own `domainKey` inside
        // `provisionDomain`, during the persist phase after `NSFileProviderManager.add` succeeds
        // — so there is nothing install-wide to create here, no mint-ordering constraint against
        // the shared config, and no orphan guard to satisfy. That provisioning runs for every
        // algorithm, `.plain` included: the `refreshTokenKey` it mints is what a OneDrive
        // credential is sealed to, encrypted or not.

        await MainActor.run { onPreflightPassed() }

        // MARK: Persist

        let newDomain = NSFileProviderDomain(identifier: vm.domain.identifier,
                                             displayName: displayName)
        let domainID = newDomain.identifier
        let store = SharedConfigStore.shared
        let defaults = UserDefaults.sharedContainerDefaults

        // Account entry that existed before this save, if any. Rollback restores it rather than
        // deleting outright, so a failed *edit* cannot wipe a working domain's configuration.
        let priorAccount = store.account(for: domainID)

        /// `true` when this save provisioned a backend that must be torn down on rollback.
        /// Only a newly created (not edited) emulator domain provisions during save.
        var didProvisionBackend = false

        /// Undoes everything this save persisted. `NSFileProviderManager.add` can reject the
        /// domain after the account is already in `config.json` (a duplicate name the preflight
        /// snapshot did not know about); without this the rejected name stayed persisted, and
        /// since the form remains open, Cancel then left the bogus entry behind for good.
        func rollBackPersistence() {
            if let priorAccount {
                store.setAccount(priorAccount, for: domainID)
            } else {
                store.removeAccount(for: domainID)
            }
            if didProvisionBackend {
                try? vm.provisioningService.deprovision(domainIdentifier: domainID.rawValue)
            }
            // Nothing persisted survives a rollback, and neither may the buffered token: the
            // form stays open, so leaving it would strand a credential with no domain.
            vm.discardPendingCredential()
        }

        // Every `throw` below this point must undo its writes via `rollBackPersistence()`;
        // validation-only failures are all handled in preflight above.
        let account: DomainAccount
        switch vm.backendKind {
        case .oneDrive:
            // Serving folder chosen via the picker; `remoteItemID == nil` serves the
            // drive root. `remotePath` carries the display label only (UI convenience).
            account = DomainAccount(displayName: displayName,
                                    remotePath: vm.remoteFolderLabel,
                                    backendKind: .oneDrive,
                                    remoteItemID: vm.remoteItemID)
            store.setAccount(account, for: domainID)

        case .localFS:
            // Rejected in preflight; unreachable.
            throw CommonError.notImplemented

        case .emulator:
            let remotePath: String? = vm.remotePath.isEmpty ? nil : vm.remotePath
            // Generate the shared secret once per domain; the backend reads it lazily per-request.
            let secret: String = defaults.secret(for: domainID) ?? String(UUID().uuidString.suffix(12))
            defaults.set(secret: secret, for: domainID)

            // Provision the backend (emulator mints root ID internally; no secret pushed).
            try vm.provisioningService.provision(domainIdentifier: domainID.rawValue,
                                                 displayName: displayName,
                                                 remotePath: remotePath)
            didProvisionBackend = priorAccount == nil

            account = DomainAccount(displayName: displayName,
                                    remotePath: remotePath,
                                    backendKind: .emulator)
            store.setAccount(account, for: domainID)
        }

        do {
            try await NSFileProviderManager.add(newDomain)
        } catch {
            rollBackPersistence()
            logger.error("⛔️ domain add failed, account rolled back: \(error.localizedDescription)")
            // Present the OS's duplicate-name rejection in the form's own terms; anything else
            // propagates unchanged.
            throw DuplicateDomainNameError.isDuplicateNameRejection(error)
                ? DuplicateDomainNameError()
                : error
        }

        // Commit the key material validated during preflight. The password is already known
        // good, so the only remaining failure is the keychain write itself; roll the domain
        // back on that so no unusable (no-key) BC01 domain lingers.
        if let material = derivedKey {
            do {
                try await CryptoConfigViewModel().store(material, for: newDomain.identifier,
                                                       keyStore: .shared)
                vm.clearPassword()
                let config = DomainCryptoConfig(algorithm: .bc01,
                                                userId: material.userId,
                                                bckeyPath: "")
                UserDefaults.sharedContainerDefaults.setCryptoConfig(config, for: newDomain.identifier)
            } catch {
                try? await NSFileProviderManager.remove(newDomain)
                rollBackPersistence()
                logger.error("⛔️ key material store failed: \(error.localizedDescription)")
                throw BCKeyValidationError(underlying: error)
            }
        } else {
            // `.plain` still provisions. The domain key material is not only about file
            // encryption: `provisionDomain` also mints the `refreshTokenKey` that the OneDrive
            // refresh token is sealed to. Skipping it here left a plain OneDrive domain with no
            // `refreshTokenKey.pub`, so the credential commit below failed with
            // `orphanedDomainKeys` and the form reported "Could not verify the OneDrive sign-in".
            do {
                // Only for a domain that has none. Re-provisioning an edit would mint a fresh
                // `domainKey` and orphan every leaf already sealed under the old one.
                if !VaultKeyStore.shared.isProvisioned(domain: domainID.rawValue) {
                    try await VaultKeyStore.shared.provisionDomain(userIdentityKeyDER: nil,
                                                                   for: domainID.rawValue)
                }
            } catch {
                try? await NSFileProviderManager.remove(newDomain)
                rollBackPersistence()
                logger.error("⛔️ domain provisioning failed: \(error.localizedDescription)")
                throw BCKeyValidationError(underlying: error)
            }
            let config = DomainCryptoConfig(algorithm: vm.algorithm)
            UserDefaults.sharedContainerDefaults.setCryptoConfig(config, for: newDomain.identifier)
        }

        // Seal the buffered refresh token now that the domain exists and its `refreshTokenKey`
        // has been provisioned. Rolls back exactly as the key-material commit above does:
        // a domain whose credential never landed is unusable, and silently so.
        if let handle = vm.pendingCredentialHandle {
            do {
                try await tokenStore.commitPendingCredential(handle, to: domainID.rawValue)
                vm.pendingCredentialHandle = nil
            } catch {
                try? await NSFileProviderManager.remove(newDomain)
                rollBackPersistence()
                logger.error("⛔️ refresh token commit failed: \(error.localizedDescription)")
                throw CredentialValidationError(underlying: error)
            }
        }

        // Thumbnail upload is per-domain and force-disabled under encryption (a plaintext
        // thumbnail would leak content past the encryption boundary).
        let thumbnailUpload = vm.algorithm == .plain && vm.thumbnailUpload
        UserDefaults.sharedContainerDefaults.thumbnailUpload(thumbnailUpload, for: newDomain.identifier)

        // Auto-encrypt-on-edit is BC01-only; force off under .plain.
        let autoEncrypt = vm.algorithm == .bc01 && vm.autoEncryptOnEdit
        UserDefaults.sharedContainerDefaults.autoEncryptOnEdit(autoEncrypt, for: newDomain.identifier)
        UserDefaults.sharedContainerDefaults.trashPlaintextOnAutoEncrypt(vm.trashPlaintextOnAutoEncrypt,
                                                                         for: newDomain.identifier)
        // Read back through the same store the extension reads, to surface any write/read
        // mismatch across the app↔appex (App Group) boundary at save time.
        let persisted = UserDefaults.sharedContainerDefaults.autoEncryptOnEdit(for: newDomain.identifier)
        logger.info("🔐 autoEncryptOnEdit write for \(newDomain.identifier.rawValue): vm=\(vm.autoEncryptOnEdit) algorithm=\(vm.algorithm.rawValue) → wrote=\(autoEncrypt) readBack=\(persisted)")

        logger.info("✅ domain saved: \(newDomain.displayName)")
        await MainActor.run { onClose() }
    }
}
