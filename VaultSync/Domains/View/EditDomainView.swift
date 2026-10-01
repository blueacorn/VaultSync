/// Domain add/edit form — SwiftUI view + view model.
///
/// The SwiftUI `EditDomainView` and its `EditDomainViewModel`, split out of
/// `EditDomainViewController.swift`. The `NSHostingController` wrapper and the
/// `saveDomain` persistence entry point remain in the controller.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit
import SwiftUI
import FileProvider
import AuthenticationServices
import Common
import os.log

// MARK: - Errors

/// Thrown when saving a OneDrive domain without a completed sign-in.
struct OneDriveSignInRequired: LocalizedError {
    var errorDescription: String? { "Sign in to OneDrive before saving." }
}

/// Thrown by ``EditDomainViewController/saveDomain`` when the chosen domain name is already
/// taken by another File Provider domain or by a configured account in `config.json`.
///
/// The name must be unique across **both** sources: a "Lock and Remove" deliberately keeps the
/// account entry after dropping the OS domain, so a name-check against registered domains alone
/// allowed a duplicate to be created while the original was locked and removed.
struct DuplicateDomainNameError: LocalizedError {
    /// Single user-facing wording, shared by the pre-save inline hint and the thrown error, so
    /// the form never shows two different phrasings for the same condition.
    static let message = "Vault name already in use - please choose another name"

    var errorDescription: String? { Self.message }

    /// `true` when `error` is the File Provider's own duplicate-name rejection.
    ///
    /// `NSFileProviderManager.add` reports a name clash as a plain `NSFileWriteFileExistsError`,
    /// which surfaces as "The file couldn't be saved because a file with the same name already
    /// exists" — accurate for files, meaningless for a vault sync. It reaches us whenever the OS
    /// knows a domain our snapshot does not (a stale `knownDomains` with no matching account
    /// entry), so preflight cannot catch every case and this backstop is required.
    static func isDuplicateNameRejection(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == NSCocoaErrorDomain
            && nsError.code == NSFileWriteFileExistsError
    }
}

/// Thrown by ``EditDomainViewController/saveDomain`` when the supplied `.bckey` + password
/// cannot be validated — missing, wrong password, or corrupt key file. Carries which
/// field(s) to flag so the form can show an inline red indication and keep the sheet open.
struct BCKeyValidationError: LocalizedError {
    /// `true` when the failure is an orphaned vault root rather than a key-file fault. The form
    /// cannot fix it by any edit, so the caller routes to the "Vault Key Missing" gate instead of
    /// flagging a field.
    private(set) var isVaultOrphaned = false

    /// Which field(s) to outline. Both can be flagged at once (e.g. neither supplied).
    struct Fields: OptionSet {
        let rawValue: Int
        static let password = Fields(rawValue: 1 << 0)
        static let bckey    = Fields(rawValue: 1 << 1)
    }
    let fields: Fields
    let message: String

    init(underlying: Error) {
        switch underlying {
        case CryptoConfigError.hmacVerificationFailed, CryptoConfigError.aesFailed:
            fields = .password
            message = "Could not unlock the key with the supplied password."
        case CryptoConfigError.noBckeyUsers,
             CryptoConfigError.invalidBase64,
             CryptoConfigError.pbkdf2Failed:
            fields = .bckey
            message = "The .bckey file is invalid or corrupt."
        case VaultKeyStoreError.orphanedDomainKeys:
            isVaultOrphaned = true
            // Not a key-file fault: the vault root is gone while vaults remain configured, so
            // minting is refused. Flag neither field — no edit here can clear it.
            fields = []
            message = "This vault's key is missing and cannot be recovered. Remove it and add it again."
        case VaultKeyStoreError.locked:
            fields = []
            message = "The vault is locked. Unlock it and try again."
        case let VaultKeyStoreError.keychain(status):
            fields = []
            message = "Could not save the key to the keychain (status \(status))."
        default:
            // RSA import / keychain / unknown → most often a corrupt key.
            fields = .bckey
            message = "Could not derive the private key from the .bckey file."
        }
    }

    /// BC01 selected but the key file and/or password was left empty. Previously this fell
    /// through and saved a BC01 domain with no key; it is now a validation failure.
    init(missingBckey: Bool, missingPassword: Bool) {
        var flagged: Fields = []
        if missingBckey { flagged.insert(.bckey) }
        if missingPassword { flagged.insert(.password) }
        fields = flagged
        switch (missingBckey, missingPassword) {
        case (true, true):  message = "Choose a .bckey file and enter its password."
        case (true, false): message = "Choose a .bckey file."
        default:            message = "Enter the .bckey password."
        }
    }

    var errorDescription: String? { message }
}

/// Thrown by ``EditDomainViewController/saveDomain`` when the stored OneDrive refresh token
/// cannot be redeemed for an access token during preflight.
///
/// Being offline is reported separately from an expired sign-in: the failure looks the same
/// but the remedy does not — offline means retry later, expired means sign in again. Only
/// ``Reason/expired`` should clear the model's signed-in flag.
struct CredentialValidationError: LocalizedError {
    enum Reason { case signInRequired, expired, offline, locked, failed }
    let reason: Reason
    let message: String

    init(underlying: Error) {
        switch underlying {
        case AuthError.notAuthenticated:
            reason = .signInRequired
            message = "Sign in to OneDrive before saving."
        case AuthError.refreshRejected:
            reason = .expired
            message = "The OneDrive sign-in has expired. Sign in again."
        case AuthError.vaultLocked:
            // Never "sign in again": the credential is intact but sealed, and a fresh
            // interactive sign-in cannot succeed until the vault is open.
            reason = .locked
            message = VaultLockCopy.lockedCallToAction
        case let urlError as URLError where Self.isOffline(urlError):
            reason = .offline
            message = "Unable to contact OneDrive. Check your internet connection and try again."
        default:
            reason = .failed
            message = "Could not verify the OneDrive sign-in."
        }
    }

    /// Transport failures that mean "the device could not reach the token endpoint", as
    /// opposed to the endpoint rejecting the credential. `MSALTokenStore` wraps only HTTP
    /// failures in ``AuthError``, so these arrive as an unwrapped `URLError`.
    private static func isOffline(_ error: URLError) -> Bool {
        switch error.code {
        case .notConnectedToInternet, .networkConnectionLost, .cannotConnectToHost,
             .cannotFindHost, .dnsLookupFailed, .timedOut, .internationalRoamingOff,
             .secureConnectionFailed:
            return true
        default:
            return false
        }
    }

    var errorDescription: String? { message }
}

// MARK: - View model

@MainActor
final class EditDomainViewModel: ObservableObject {
    @Published var displayName: String {
        didSet {
            // Any keystroke in the name field (not a programmatic auto-name) pins the name,
            // so later backend/folder selections stop overwriting the user's choice.
            if !isApplyingAutoName { userEditedName = true }
        }
    }
    /// `true` once the user has typed into the name field; suppresses auto-defaulting.
    private var userEditedName = false
    /// Guards `displayName.didSet` while we set the name programmatically.
    private var isApplyingAutoName = false
    @Published var remotePath: String
    @Published var algorithm: CryptoAlgorithm
    @Published var bckeyPath: String
    /// Per-domain: generate and upload thumbnails to the remote. Forced off whenever
    /// encryption is active — uploading a plaintext thumbnail would leak content past the
    /// encryption boundary (see ``Extension/uploadThumbnail``).
    @Published var thumbnailUpload: Bool

    /// Per-domain: auto-encrypt plaintext files when they are edited (BC01 only). Opt-in.
    @Published var autoEncryptOnEdit: Bool
    /// When auto-encrypting, send the plaintext original to the Trash (else hard-delete).
    @Published var trashPlaintextOnAutoEncrypt: Bool

    /// Whether the auto-encrypt toggles are selectable (only under BC01).
    var autoEncryptAllowed: Bool { algorithm == .bc01 }

    /// Whether the thumbnail toggle is selectable. Disabled (and shown off) under crypto.
    var thumbnailUploadAllowed: Bool { algorithm == .plain }

    /// BC01 selected without both a key file and a password. Gates Save client-side so the
    /// obvious case needs no round-trip; `saveDomain`'s preflight remains the authority.
    var encryptionFieldsIncomplete: Bool {
        algorithm == .bc01 && (bckeyPath.isEmpty || password.isEmpty)
    }

    /// `true` when ``displayName`` collides with another domain's name. Gates Save in the
    /// footer; `saveDomain`'s preflight re-asserts it before persisting.
    var displayNameIsDuplicate: Bool {
        Self.isDuplicateName(displayName,
                             excluding: domain.identifier.rawValue,
                             allDomains: allDomains,
                             allAccounts: allAccounts)
    }

    /// Inline message for a duplicate name, or `nil` when the name is free.
    ///
    /// Combines the live check against the known domains/accounts snapshot with
    /// ``nameFieldInvalid``, which a Save-time rejection sets for a clash the snapshot missed.
    var displayNameValidationMessage: String? {
        (displayNameIsDuplicate || nameFieldInvalid) ? DuplicateDomainNameError.message : nil
    }

    /// `true` when the name field should be outlined red. Set when Save is rejected for a
    /// duplicate name; cleared by ``clearNameValidationError()`` on the next keystroke.
    @Published var nameFieldInvalid = false

    /// Clears a Save-time name rejection. Called as the user edits the name.
    func clearNameValidationError() {
        nameFieldInvalid = false
    }

    /// Case- and whitespace-insensitive uniqueness check across **both** name sources:
    /// OS-registered File Provider domains and the configured accounts in `config.json`.
    ///
    /// Both are required. A "Lock and Remove" drops the OS domain but deliberately keeps
    /// the account entry (see the lock-and-remove contract), so checking `allDomains`
    /// alone let a second domain be created with a removed domain's name.
    ///
    /// - Parameter identifier: The domain being edited, excluded so an edit that leaves
    ///   the name unchanged is not flagged against itself.
    static func isDuplicateName(_ name: String,
                                excluding identifier: String,
                                allDomains: [NSFileProviderDomain],
                                allAccounts: [String: DomainAccount]) -> Bool {
        let candidate = normalizedDomainName(name)
        guard !candidate.isEmpty else { return false }

        let domainNames = allDomains
            .filter { $0.identifier.rawValue != identifier }
            .map(\.displayName)
        let accountNames = allAccounts
            .filter { $0.key != identifier }
            .map(\.value.displayName)

        return (domainNames + accountNames).contains { normalizedDomainName($0) == candidate }
    }

    /// Comparison form for domain names: whitespace-trimmed and case-folded, so
    /// "  Work " and "work" are treated as the same name.
    private static func normalizedDomainName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    @Published var password: String = ""

    /// Where Save is in its two-phase run. Preflight (`.verifying`) can take seconds —
    /// PBKDF2 plus a token round-trip — so it is surfaced distinctly from `.saving`.
    enum SaveStage { case idle, verifying, saving }
    @Published var saveStage: SaveStage = .idle

    /// `true` while Save is in progress (either phase); drives disabled state.
    var isSaving: Bool { saveStage != .idle }

    /// Save button title for the current stage.
    var saveButtonTitle: String {
        switch saveStage {
        case .idle:      return "Save"
        case .verifying: return "Verifying…"
        case .saving:    return "Saving…"
        }
    }

    @Published var errorMessage: String?

    /// Inline validation error for the `.bckey`/password fields. Set when key derivation
    /// fails on Save; the sheet stays open and the offending field is outlined red.
    @Published var bckeyError: String?
    @Published var passwordFieldInvalid = false
    @Published var bckeyFieldInvalid = false

    func clearKeyValidationErrors() {
        bckeyError = nil
        passwordFieldInvalid = false
        bckeyFieldInvalid = false
    }

    /// Backend servicing the domain. `.emulator` is the default; `.oneDrive` enables the
    /// Microsoft Graph path with an interactive sign-in and a user-chosen serving sub-path.
    @Published var backendKind: BackendKind
    /// Whether this domain has a OneDrive refresh token in the App Group keychain.
    ///
    /// Credentials are domain-scoped — keyed by ``domain``'s identifier — so there is no
    /// credential id to carry around: presence is the whole state the form needs.
    @Published var isSignedIn: Bool
    /// Whether OneDrive sign-in is in progress (drives button state).
    @Published var isSigningIn = false
    /// OneDrive: Graph DriveItem id of the chosen serving folder. `nil` = drive root.
    @Published var remoteItemID: String?
    /// OneDrive: human-readable label for the chosen folder (display only).
    @Published var remoteFolderLabel: String = EditDomainViewModel.rootFolderLabel
    /// Whether a Rebuild Index request is in flight (drives button state).
    @Published var isRebuildingIndex = false

    /// Request a full re-crawl of the domain's index from its backend. Errors land in
    /// ``errorMessage``.
    func rebuildIndex() async {
        isRebuildingIndex = true
        errorMessage = nil
        defer { isRebuildingIndex = false }
        do {
            try await provisioningService.rebuildIndex(domainIdentifier: domain.identifier.rawValue)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Label for "no sub-folder chosen — serve the drive root". Names only the folder: the
    /// field it sits in already says which backend, so prefixing it read as "OneDrive (root)".
    static let rootFolderLabel = "(root)"

    /// Handle for a refresh token held in ``MSALTokenStore``'s pending buffer.
    ///
    /// Sign-in for a new domain precedes the domain, so the token has nowhere to be
    /// sealed yet. `saveDomain` commits it once provisioning has run; abandoning the form
    /// discards it. Non-`nil` only between sign-in and commit/discard.
    var pendingCredentialHandle: String?

    /// Drop any buffered credential — the form was closed unsaved, or a save rolled back.
    ///
    /// Idempotent: an abandoned sign-in must leave nothing behind, and nothing was persisted,
    /// so forgetting the in-memory pair is the whole of it.
    func discardPendingCredential() {
        guard let handle = pendingCredentialHandle else { return }
        pendingCredentialHandle = nil
        isSignedIn = false
        Task { await MSALTokenStore.shared.discardPendingCredential(handle) }
    }

    /// The key an access token can be minted under right now: the pending handle while the
    /// domain does not yet exist, otherwise the domain's own identifier.
    ///
    /// One accessor rather than a branch at each call site — the folder picker and the save
    /// preflight both need the same answer.
    var credentialLookupKey: String {
        pendingCredentialHandle ?? domain.identifier.rawValue
    }

    let domain: NSFileProviderDomain
    /// Backend-agnostic provisioning service injected by the host.
    let provisioningService: any DomainProvisioningService

    /// Reads the host's *current* domains and accounts.
    ///
    /// A closure rather than captured arrays: this form is cached across popover teardowns
    /// (see ``AppModel/domainForm(existingDomainID:)``) while the host keeps updating its
    /// registry underneath, so anything snapshotted at construction goes stale — which is
    /// exactly how a name that was already taken passed the duplicate check and was only
    /// caught later by `NSFileProviderManager.add`.
    private let registry: () -> (domains: [NSFileProviderDomain], accounts: [String: DomainAccount])

    /// Live view of the host's registered File Provider domains.
    var allDomains: [NSFileProviderDomain] { registry().domains }
    /// Live view of the configured accounts in `config.json`, keyed by domain identifier.
    var allAccounts: [String: DomainAccount] { registry().accounts }

    /// - Parameter registry: Supplies the host's domains/accounts on demand. Must read live
    ///   state, not a captured copy — see ``registry``.
    init(domain: NSFileProviderDomain,
         provisioningService: any DomainProvisioningService,
         registry: @escaping () -> (domains: [NSFileProviderDomain], accounts: [String: DomainAccount])) {
        self.domain = domain
        self.provisioningService = provisioningService
        self.registry = registry

        self.displayName = domain.displayName
        let existing = registry().accounts[domain.identifier.rawValue]
        self.remotePath = existing?.remotePath ?? ""
        self.backendKind = existing?.backendKind ?? .emulator
        self.isSignedIn = MSALTokenStore.shared.hasCredential(domain.identifier.rawValue)
        self.remoteItemID = existing?.remoteItemID
        if existing?.backendKind == .oneDrive {
            self.remoteFolderLabel = existing?.remoteItemID == nil
                ? Self.rootFolderLabel
                : (existing?.remotePath.flatMap { $0.isEmpty ? nil : $0 } ?? "Selected folder")
        }

        let existingCrypto = UserDefaults.sharedContainerDefaults.cryptoConfig(for: domain.identifier)
        self.algorithm = existingCrypto.algorithm
        self.bckeyPath = existingCrypto.bckeyPath
        self.thumbnailUpload = UserDefaults.sharedContainerDefaults.thumbnailUpload(for: domain.identifier)
        self.autoEncryptOnEdit = UserDefaults.sharedContainerDefaults.autoEncryptOnEdit(for: domain.identifier)
        self.trashPlaintextOnAutoEncrypt = UserDefaults.sharedContainerDefaults.trashPlaintextOnAutoEncrypt(for: domain.identifier)

        // An existing (edit-mode) domain, or one seeded with a non-placeholder name, is
        // treated as user-named so auto-defaulting never clobbers it.
        if existing != nil || !displayNameIsPlaceholder(domain.displayName) {
            userEditedName = true
        }
    }

    /// Convenience initialiser for a fixed registry — tests and any caller whose domain list
    /// genuinely cannot change for the form's lifetime.
    convenience init(domain: NSFileProviderDomain,
                     provisioningService: any DomainProvisioningService,
                     allDomains: [NSFileProviderDomain],
                     allAccounts: [String: DomainAccount]) {
        self.init(domain: domain,
                  provisioningService: provisioningService,
                  registry: { (allDomains, allAccounts) })
    }

    // MARK: - Name auto-defaulting

    /// Empty names are eligible to be replaced by an auto-derived name.
    private func displayNameIsPlaceholder(_ name: String) -> Bool {
        name.isEmpty
    }

    /// Set the name programmatically without marking it user-edited.
    private func setAutoName(_ name: String) {
        guard !userEditedName, !name.isEmpty else { return }
        isApplyingAutoName = true
        displayName = name
        isApplyingAutoName = false
    }

    /// Local Folder chosen → default the name to the folder's last path component.
    func applyLocalFolderAutoName(from url: URL) {
        setAutoName(url.lastPathComponent)
    }

    /// OneDrive folder chosen → "OneDrive - <folder>" for a sub-folder; plain "OneDrive"
    /// for the drive root (`selectionName == nil`).
    func applyOneDriveFolderAutoName(selectionName: String?) {
        if let name = selectionName, !name.isEmpty {
            setAutoName("\(name)")
        } else {
            setAutoName("OneDrive")
        }
    }

    /// OneDrive sign-in completed → seed a generic default until a folder is picked.
    func applyOneDriveSignedInAutoName() {
        setAutoName("OneDrive")
    }

    /// Zeros password bytes in memory after key derivation.
    func clearPassword() {
        var mutable = password
        mutable.withUTF8 { ptr in
            guard let base = UnsafeMutableRawPointer(mutating: ptr.baseAddress), ptr.count > 0 else { return }
            memset_s(base, ptr.count, 0, ptr.count)
        }
        password = ""
    }
}

// MARK: - SwiftUI view

struct EditDomainView: View {
    @ObservedObject var model: EditDomainViewModel
    @State private var showFolderPicker = false
    @State private var showRebuildIndexConfirmation = false
    private let onClose: () -> Void
    /// Runs the interactive OneDrive sign-in, anchored off the popover. Supplied by the host so
    /// the auth flow is owned outside this (transient) view.
    ///
    /// `domainID` is `nil` for a domain that does not exist yet, in which case the returned
    /// handle names the refresh token held pending until Save commits it. An edit of an
    /// existing domain passes its identifier and gets `nil` back — nothing is left pending.
    /// See ``AppModel/signInToOneDrive(domainID:)``.
    private let onSignIn: (_ domainID: String?) async throws -> String?
    /// Invoked when Save fails because the vault root is orphaned. The host pushes the "Vault
    /// Key Missing" gate; no edit in this form could clear the condition, so there is nothing
    /// useful to show inline.
    private let onVaultOrphaned: () -> Void
    /// Routes to the Security screen — the single place the unlock method is chosen.
    private let onOpenSecurity: () -> Void

    /// The install's unlock method, shown read-only in ``unlockSection``.
    private var installGating: SharedConfig.VaultGating {
        SharedConfigStore.shared.read(\.vaultGating)
    }

    init(model: EditDomainViewModel,
         onSignIn: @escaping (_ domainID: String?) async throws -> String?,
         onVaultOrphaned: @escaping () -> Void = {},
         onOpenSecurity: @escaping () -> Void = {},
         onClose: @escaping () -> Void) {
        self.model = model
        self.onSignIn = onSignIn
        self.onVaultOrphaned = onVaultOrphaned
        self.onOpenSecurity = onOpenSecurity
        self.onClose = onClose
    }

    var body: some View {
        VStack(spacing: 0) {
            form
            Divider()
            footer
        }
        .sheet(isPresented: $showFolderPicker) {
            if model.isSignedIn {
                OneDriveFolderPicker(domainID: model.credentialLookupKey) { selection in
                    model.remoteItemID = selection?.id
                    model.remoteFolderLabel = selection?.name ?? EditDomainViewModel.rootFolderLabel
                    model.applyOneDriveFolderAutoName(selectionName: selection?.name)
                }
            }
        }
    }

    private var form: some View {
        Form {
            Section {
                let nameError = model.displayNameValidationMessage
                TextField("Vault Name", text: $model.displayName)
                    .textFieldStyle(.roundedBorder)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(Color.red, lineWidth: nameError == nil ? 0 : 1)
                    )
                    .onChange(of: model.displayName) { _ in model.clearNameValidationError() }
                if let nameError {
                    Text(nameError).foregroundStyle(.red).font(.caption)
                }

                let isEdit = model.allAccounts[model.domain.identifier.rawValue] != nil
                if !isEdit {
                    Picker("Backend", selection: $model.backendKind) {
                        Text(BackendKind.emulator.displayName).tag(BackendKind.emulator)
                        Text(BackendKind.oneDrive.displayName).tag(BackendKind.oneDrive)
                    }
                } else {
                    LabeledContent("Backend", value: model.backendKind.displayName)
                }

                switch model.backendKind {
                case .emulator:
                    if !isEdit {
                        HStack {
                            TextField("Storage Path", text: $model.remotePath)
                                .textFieldStyle(.roundedBorder)
                                .disabled(true)
                            Button("Browse…") { browseStorage() }
                        }
                    } else {
                        LabeledContent("Storage Path",
                                       value: model.remotePath.isEmpty ? "(default)" : model.remotePath)
                    }
                case .oneDrive:
                    oneDriveSection(isEdit: isEdit)
                case .localFS:
                    Text("Local filesystem backend is not available yet.")
                        .foregroundStyle(.secondary).font(.caption)
                }
            }

            unlockSection

            EncryptionConfigSection(algorithm: $model.algorithm,
                                    bckeyPath: $model.bckeyPath,
                                    password: $model.password,
                                    bckeyFieldInvalid: model.bckeyFieldInvalid,
                                    passwordFieldInvalid: model.passwordFieldInvalid,
                                    validationMessage: model.bckeyError,
                                    onEdit: { model.clearKeyValidationErrors() })

            if model.autoEncryptAllowed {
                Section("Encryption on edit") {
                    Toggle("Auto-encrypt unencrypted files on edit",
                           isOn: $model.autoEncryptOnEdit)
                    Toggle("Send plaintext copy of auto-encrypted file(s) to trash",
                           isOn: $model.trashPlaintextOnAutoEncrypt)
                        .disabled(!model.autoEncryptOnEdit)
                    Text("When on, editing a plaintext file converts it to an encrypted (.bc) copy, verifies it, then removes the original. Off: plaintext files stay plaintext.")
                        .foregroundStyle(.secondary).font(.caption)
                }
            }

            // Thumbnail upload is unsupported under backend encryption (would leak
            // plaintext), so the section is hidden entirely rather than shown disabled.
            if model.thumbnailUploadAllowed {
                Section("Thumbnails") {
                    Toggle("Upload Thumbnails to Remote", isOn: $model.thumbnailUpload)
                }
            }

            if model.allAccounts[model.domain.identifier.rawValue] != nil,
               model.backendKind == .oneDrive {
                advancedSection
            }

            if let msg = model.errorMessage {
                Text(msg).foregroundStyle(.red).font(.caption)
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    /// Maintenance actions for an existing OneDrive vault.
    private var advancedSection: some View {
        Section("Advanced") {
            Button("Rebuild Index…", role: .destructive) { showRebuildIndexConfirmation = true }
                .foregroundStyle(.red)
                .disabled(model.isRebuildingIndex)
                .confirmationDialog("Rebuild the index for this vault?",
                                    isPresented: $showRebuildIndexConfirmation) {
                    Button("Rebuild Index", role: .destructive) {
                        Task { await model.rebuildIndex() }
                    }
                }
            Text("Re-reads the whole folder from OneDrive. Tags and cached sizes are kept.")
                .foregroundStyle(.secondary).font(.caption)
        }
    }

    /// The install's unlock method, read-only, with a route to the one screen that changes it.
    ///
    /// The method is install-wide, so offering it per domain would be a second
    /// commit path onto one value — a drift source. Shown rather than hidden because
    /// it is the protection this vault will get, and the user is entitled to see it at save time.
    private var unlockSection: some View {
        Section("Unlock") {
            LabeledContent("Protection") {
                HStack(spacing: 8) {
                    Text(installGating.displayName)
                    Button("Change in Security…") { onOpenSecurity() }
                        .buttonStyle(.link)
                }
            }

            Text(installGating.unlockDescription)
                .foregroundStyle(.secondary).font(.caption)

            // Required copy, not a nicety: this is the one routine system action that costs the
            // user their vaults, and the design accepts that trade only if they were told here.
            if let warning = installGating.secureEnclaveWarning {
                Text(warning)
                    .foregroundStyle(.secondary).font(.caption).bold()
            }
        }
    }

    /// Footer panel matching the other menu-bar screens (Divider + 12/8-padded row).
    private var footer: some View {
        HStack {
            Spacer()
            Button("Cancel") {
                // Sheet closed unsaved: the buffered token must not outlive the form.
                model.discardPendingCredential()
                onClose()
            }
                .disabled(model.isSaving)
            Button(model.saveButtonTitle) { save() }
                .disabled(model.displayName.isEmpty || model.isSaving
                          || model.encryptionFieldsIncomplete
                          || model.displayNameIsDuplicate)
                .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private func oneDriveSection(isEdit: Bool) -> some View {
        if isEdit {
            LabeledContent("OneDrive Folder",
                           value: model.remotePath.isEmpty ? "(unset)" : model.remotePath)
            LabeledContent("Account", value: model.isSignedIn ? "Signed in" : "Not signed in")
        } else {
            HStack {
                Text("Account")
                Spacer()
                if model.isSignedIn {
                    Label("Signed in", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Button(model.isSigningIn ? "Signing in…" : "Sign in to OneDrive") { signIn() }
                        .disabled(model.isSigningIn)
                }
            }
            HStack {
                Text("Folder")
                Spacer()
                Text(model.remoteFolderLabel)
                    .foregroundStyle(.secondary)
                Button("Choose…") { showFolderPicker = true }
                    .disabled(!model.isSignedIn)
            }
            Text("Pick the OneDrive folder to serve, or keep the drive root.")
                .foregroundStyle(.secondary).font(.caption)
        }
    }

    private func signIn() {
        Task { @MainActor in
            model.isSigningIn = true
            model.errorMessage = nil
            defer { model.isSigningIn = false }
            do {
                // A domain being edited already owns a slot to seal into; a new one does not
                // exist yet, so its token is held pending until Save creates it.
                let isEdit = model.allAccounts[model.domain.identifier.rawValue] != nil
                model.pendingCredentialHandle =
                    try await onSignIn(isEdit ? model.domain.identifier.rawValue : nil)
                model.isSignedIn = true
                model.applyOneDriveSignedInAutoName()
            } catch {
                model.errorMessage = error.localizedDescription
            }
        }
    }

    private func browseStorage() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.prompt = "Choose"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.remotePath = url.path
        model.applyLocalFolderAutoName(from: url)
        if let bookmark = try? url.bookmarkData(options: .withSecurityScope,
                                                 includingResourceValuesForKeys: nil,
                                                 relativeTo: nil) {
            SharedConfigStore.shared.setBookmark(bookmark, for: model.domain.identifier)
        }
    }

    private func save() {
        let encParams: (bckeyURL: URL, password: String)?
        if model.algorithm == .bc01, !model.bckeyPath.isEmpty, !model.password.isEmpty {
            encParams = (URL(fileURLWithPath: model.bckeyPath), model.password)
        } else {
            encParams = nil
        }

        Task { @MainActor in
            model.saveStage = .verifying
            model.errorMessage = nil
            model.clearKeyValidationErrors()
            model.clearNameValidationError()
            do {
                try await EditDomainViewController.saveDomain(
                    vm: model,
                    encParams: encParams,
                    onPreflightPassed: { model.saveStage = .saving },
                    onClose: onClose)
            } catch let validation as BCKeyValidationError where validation.isVaultOrphaned {
                model.saveStage = .idle
                onVaultOrphaned()
            } catch let validation as BCKeyValidationError {
                // Keep the sheet open; flag the offending field(s) inline.
                model.bckeyError = validation.message
                model.passwordFieldInvalid = validation.fields.contains(.password)
                model.bckeyFieldInvalid = validation.fields.contains(.bckey)
                model.saveStage = .idle
            } catch let duplicate as DuplicateDomainNameError {
                model.nameFieldInvalid = true
                model.errorMessage = duplicate.errorDescription
                model.saveStage = .idle
            } catch where DuplicateDomainNameError.isDuplicateNameRejection(error) {
                // The OS rejected the name even though preflight passed — it knows a domain our
                // snapshot does not. Present it as the same duplicate-name failure.
                model.nameFieldInvalid = true
                model.errorMessage = DuplicateDomainNameError.message
                model.saveStage = .idle
            } catch let credential as CredentialValidationError {
                model.errorMessage = credential.message
                // An expired token needs a fresh interactive sign-in, so drop the credential
                // to bring the "Sign in to OneDrive" button back. Offline leaves it intact —
                // the credential is fine and the user can simply retry.
                if credential.reason == .expired { model.isSignedIn = false }
                model.saveStage = .idle
            } catch {
                model.errorMessage = error.localizedDescription
                model.saveStage = .idle
            }
        }
    }
}

