/// Unit tests for `EditDomainViewModelName`.
//
//  EditDomainViewModelNameTests.swift
//  VaultSyncTests
//
//  Tests for name auto-defaulting in the add/edit form.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import VaultSync

@MainActor
final class EditDomainViewModelNameTests: XCTestCase {

    private func makeModel(displayName: String,
                           existingAccount: DomainAccount? = nil) -> EditDomainViewModel {
        let domain = NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString),
                                          displayName: displayName)
        var accounts: [String: DomainAccount] = [:]
        if let existingAccount { accounts[domain.identifier.rawValue] = existingAccount }
        return EditDomainViewModel(domain: domain,
                                   provisioningService: NoOpProvisioningService(),
                                   allDomains: [domain],
                                   allAccounts: accounts)
    }

    func testLocalFolderAutoNameFromPlaceholder() {
        let model = makeModel(displayName: "🍎")
        model.applyLocalFolderAutoName(from: URL(fileURLWithPath: "/tmp/Photos"))
        XCTAssertEqual(model.displayName, "Photos")
    }

    func testAutoNameDoesNotOverrideUserEdit() {
        let model = makeModel(displayName: "🍎")
        model.displayName = "My Vault"   // simulated user keystroke
        model.applyLocalFolderAutoName(from: URL(fileURLWithPath: "/tmp/Photos"))
        XCTAssertEqual(model.displayName, "My Vault")
    }

    func testOneDriveSubfolderAutoName() {
        let model = makeModel(displayName: "🍐")
        model.applyOneDriveFolderAutoName(selectionName: "Work")
        XCTAssertEqual(model.displayName, "OneDrive - Work")
    }

    func testOneDriveRootAutoName() {
        let model = makeModel(displayName: "🍐")
        model.applyOneDriveFolderAutoName(selectionName: nil)
        XCTAssertEqual(model.displayName, "OneDrive")
    }

    func testEditModeNameNotAutoDefaulted() {
        let account = DomainAccount(displayName: "Existing", backendKind: .emulator)
        let model = makeModel(displayName: "Existing", existingAccount: account)
        model.applyLocalFolderAutoName(from: URL(fileURLWithPath: "/tmp/Photos"))
        XCTAssertEqual(model.displayName, "Existing")
    }

    // MARK: - Name uniqueness

    /// Builds a model for a *new* domain against a world of existing domains/accounts.
    private func makeAddModel(existingDomains: [NSFileProviderDomain] = [],
                              existingAccounts: [String: DomainAccount] = [:]) -> EditDomainViewModel {
        let domain = NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString),
                                          displayName: "")
        return EditDomainViewModel(domain: domain,
                                   provisioningService: NoOpProvisioningService(),
                                   allDomains: existingDomains,
                                   allAccounts: existingAccounts)
    }

    private func domain(named name: String, id: String = UUID().uuidString) -> NSFileProviderDomain {
        NSFileProviderDomain(identifier: .init(rawValue: id), displayName: name)
    }

    func testDuplicateAgainstRegisteredDomain() {
        let model = makeAddModel(existingDomains: [domain(named: "Work")])
        model.displayName = "Work"
        XCTAssertTrue(model.displayNameIsDuplicate)
        XCTAssertNotNil(model.displayNameValidationMessage)
    }

    /// The lock-and-remove regression: the OS domain is gone but the account entry remains,
    /// so the name must still be rejected.
    func testDuplicateAgainstLockedAndRemovedAccount() {
        let removed = DomainAccount(displayName: "Work", backendKind: .emulator)
        let model = makeAddModel(existingDomains: [],
                                 existingAccounts: ["removed-id": removed])
        model.displayName = "Work"
        XCTAssertTrue(model.displayNameIsDuplicate)
    }

    func testDuplicateIsCaseAndWhitespaceInsensitive() {
        let model = makeAddModel(existingDomains: [domain(named: "Work")])
        model.displayName = "  work "
        XCTAssertTrue(model.displayNameIsDuplicate)
    }

    func testUniqueNameAccepted() {
        let removed = DomainAccount(displayName: "Archive", backendKind: .emulator)
        let model = makeAddModel(existingDomains: [domain(named: "Work")],
                                 existingAccounts: ["removed-id": removed])
        model.displayName = "Photos"
        XCTAssertFalse(model.displayNameIsDuplicate)
        XCTAssertNil(model.displayNameValidationMessage)
    }

    func testEmptyNameIsNotFlaggedAsDuplicate() {
        let model = makeAddModel(existingDomains: [domain(named: "Work")])
        model.displayName = "   "
        XCTAssertFalse(model.displayNameIsDuplicate)
    }

    /// Editing a domain without renaming it must not flag the domain against itself —
    /// via either the domain list or its own account entry.
    func testEditKeepingOwnNameIsNotDuplicate() {
        let id = UUID().uuidString
        let existing = domain(named: "Work", id: id)
        let account = DomainAccount(displayName: "Work", backendKind: .emulator)
        let model = EditDomainViewModel(domain: existing,
                                        provisioningService: NoOpProvisioningService(),
                                        allDomains: [existing],
                                        allAccounts: [id: account])
        XCTAssertFalse(model.displayNameIsDuplicate)
    }

    func testEditRenamingOntoAnotherDomainIsDuplicate() {
        let id = UUID().uuidString
        let existing = domain(named: "Work", id: id)
        let model = EditDomainViewModel(domain: existing,
                                        provisioningService: NoOpProvisioningService(),
                                        allDomains: [existing, domain(named: "Photos")],
                                        allAccounts: [:])
        model.displayName = "Photos"
        XCTAssertTrue(model.displayNameIsDuplicate)
    }

    /// The staleness regression: a domain registered *after* the form was constructed must
    /// still be seen. The form is cached across popover teardowns while the host registry keeps
    /// changing, so a snapshot taken at construction misses it and Save reaches the OS.
    func testRegistryIsReadLiveNotSnapshotted() {
        var domains: [NSFileProviderDomain] = []
        let newDomain = NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString),
                                             displayName: "")
        let model = EditDomainViewModel(domain: newDomain,
                                        provisioningService: NoOpProvisioningService(),
                                        registry: { (domains, [:]) })
        model.displayName = "Work"
        XCTAssertFalse(model.displayNameIsDuplicate)

        // Host registers "Work" while the form sits open.
        domains = [domain(named: "Work")]
        XCTAssertTrue(model.displayNameIsDuplicate)
    }

    func testValidationMessageIsUserFriendly() {
        let model = makeAddModel(existingDomains: [domain(named: "Work")])
        model.displayName = "Work"
        XCTAssertEqual(model.displayNameValidationMessage,
                       "Domain name already in use - please choose another name")
    }

    /// A Save-time rejection flags the field even when the snapshot showed no clash.
    func testSaveTimeRejectionFlagsNameField() {
        let model = makeAddModel()
        model.displayName = "Work"
        XCTAssertNil(model.displayNameValidationMessage)

        model.nameFieldInvalid = true
        XCTAssertEqual(model.displayNameValidationMessage,
                       DuplicateDomainNameError.message)

        model.clearNameValidationError()
        XCTAssertNil(model.displayNameValidationMessage)
    }

    /// The File Provider reports a name clash as NSFileWriteFileExistsError; it must be
    /// recognised so the raw "file couldn't be saved…" text never reaches the user.
    func testCocoaFileExistsIsRecognisedAsDuplicateName() {
        let cocoa = NSError(domain: NSCocoaErrorDomain, code: NSFileWriteFileExistsError)
        XCTAssertTrue(DuplicateDomainNameError.isDuplicateNameRejection(cocoa))

        let unrelated = NSError(domain: NSCocoaErrorDomain, code: NSFileReadNoSuchFileError)
        XCTAssertFalse(DuplicateDomainNameError.isDuplicateNameRejection(unrelated))
    }

    func testLaterFolderPickOverridesEarlierAutoName() {
        let model = makeModel(displayName: "🍋")
        model.applyOneDriveSignedInAutoName()
        XCTAssertEqual(model.displayName, "OneDrive")
        model.applyOneDriveFolderAutoName(selectionName: "Docs")
        XCTAssertEqual(model.displayName, "OneDrive - Docs")
    }
}
