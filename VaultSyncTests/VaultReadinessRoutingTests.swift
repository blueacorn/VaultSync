/// Unit tests for `VaultReadinessRouting`.
//
//  VaultReadinessRoutingTests.swift
//  VaultSyncTests
//
//  The vault-readiness gate and the gating-commit contract behind it, under install-wide
//  gating.
//
//  Readiness is still aggregated across domains rather than read from one install-wide root: per
//  I5′ an orphaned domain names itself, so the model reports the worst state it finds and the
//  reset is scoped to the domains that are actually orphaned. Gating, by contrast, is now
//  install-wide: `SharedConfig.vaultGating` is authoritative and one commit re-protects every
//  vault. `DomainAccount.gating` no longer exists.
//
//  Both units under test are app-side (`AppModel`, and the `AppModelActions` commit that
//  `SecurityView` drives), so they live here rather than in `CommonTests` — that bundle cannot
//  see the VaultSync target. `VaultKeyStore.readiness(for:)` itself is covered in
//  `ExtensionTests`, which has the App Group entitlement the vault slots need.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import VaultSync

/// Records what the UI asked for and answers with whatever the test set up, so the commit
/// contract can be exercised in both directions without a keychain or a Touch ID prompt.
@MainActor
private final class StubActions: AppModelActions {
    /// The aggregate readiness the model reads — the worst state across the configured domains.
    var readiness: VaultReadiness = .ready
    /// Names of the orphaned vaults a reset would delete. Under I5 that is a subset of the
    /// domains, not the whole install.
    var backedNames: [String] = []
    /// When set, ``setVaultGating(_:newPIN:currentPIN:)`` throws it instead of succeeding.
    var commitError: Error?
    /// Every gating commit attempted, in order.
    private(set) var committed: [(SharedConfig.VaultGating, String?)] = []
    /// The install's gating, as the last successful commit left it — the value that protects
    /// **every** vault.
    private(set) var installGating: SharedConfig.VaultGating = .none

    /// Seed the install's gating without going through a commit.
    ///
    /// Kept distinct from ``setVaultGating(_:newPIN:currentPIN:)`` so the commit path stays the
    /// only *writer* under test: this is a precondition, not an exercise of the thing being
    /// asserted.
    func seedInstallGating(_ gating: SharedConfig.VaultGating) { installGating = gating }
    private(set) var resetCount = 0
    private(set) var unlockCount = 0
    /// Batched unlock requests — one ceremony for N vaults. Records the scope of
    /// each, so a request that widened past the vaults it was made for is visible.
    private(set) var unlockScopes: [[String]] = []
    /// PIN submissions, with the scope each was made for.
    private(set) var pinScopes: [[String]] = []

    var vaultReadiness: VaultReadiness { readiness }
    var vaultBackedDomainNames: [String] { backedNames }
    func resetVault() async { resetCount += 1 }

    /// The Security screen's single gating authority: one commit re-protects every vault.
    ///
    /// The install value moves only on success, so a cancelled ceremony never leaves the config
    /// claiming a protection the vaults lack.
    /// Contexts the re-key was handed, so a test can assert the gate's capability was borrowed
    /// rather than a second prompt being raised.
    var borrowedContexts: [AnyObject?] = []
    func setVaultGating(_ gating: SharedConfig.VaultGating,
                        newPIN: String?, currentPIN: String?,
                        presenceContext: AnyObject?) async throws {
        committed.append((gating, newPIN))
        borrowedContexts.append(presenceContext)
        if let commitError { throw commitError }
        installGating = gating
    }

    // MARK: - Unused surface

    var provisioningService: any DomainProvisioningService { NoOpProvisioningService() }
    var knownDomains: [NSFileProviderDomain] { [] }
    var knownAccounts: [String: DomainAccount] { [:] }
    /// The install's gating — this protects every vault, not just new ones.
    var vaultGating: SharedConfig.VaultGating { installGating }
    var pinRetryDelay: TimeInterval { 0 }
    func makeNewDomain() -> NSFileProviderDomain {
        NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString), displayName: "")
    }
    func openInFinder(_ entry: DomainEntry) {}
    func removeDomain(_ entry: DomainEntry) {}
    func openTweaks() {}
    func lockVaults() {}
    func unlockVaults() { unlockCount += 1 }
    func unlockVaults(domainIDs: [String]) async throws { unlockScopes.append(domainIDs) }
    func lockVault(_ entry: DomainEntry) {}
    func unlockVault(_ entry: DomainEntry) {}
    func reauthenticate(_ entry: DomainEntry) {}
    func enrollBiometricLock() {}
    func setLockMethod(_ method: SharedConfig.VaultLockMethod) {}
    func autoLockPolicyDidChange() {}
    func submitUnlockPIN(_ pin: String, domainIDs: [String]) async -> Bool {
        pinScopes.append(domainIDs); return false
    }
    /// Records gate checks so the tests can assert the gate ran without unlocking anything.
    var verifiedPINs: [String] = []
    var presenceEvaluations = 0
    /// What ``verifyUnlockPIN(_:)`` should answer.
    var pinIsCorrect = true
    /// What ``evaluateGatingPresence()`` should throw, if anything.
    var presenceError: Error?

    func verifyUnlockPIN(_ pin: String) async -> Bool {
        verifiedPINs.append(pin)
        return pinIsCorrect
    }
    /// The capability handed back by the gate, so tests can assert it is borrowed and ended.
    let presenceToken = NSObject()
    func evaluateGatingPresence() async throws -> AnyObject? {
        presenceEvaluations += 1
        if let presenceError { throw presenceError }
        return presenceToken
    }
    func pendingItemCount(for entry: DomainEntry) async -> Int? { nil }
    func confirmedLockAction(domainIDs: [String]) async {}
    func confirmedLockAndRemoveAction(domainIDs: [String]) {}
    func openSecurity() {}
    func quit() {}
}

@MainActor
final class VaultReadinessRoutingTests: XCTestCase {

    /// `AppModel.actions` is weak (the delegate owns the model in production), so the stub is
    /// retained by the test case for the duration of each test.
    private var actions: StubActions!

    /// `ignoreAuthentication` is a real user-facing toggle in Preferences, living in the shared
    /// App Group suite. Tests below flip it, so its prior value is captured and restored rather
    /// than reset to the default — the developer's own setting is not necessarily the default.
    private var previousIgnoreAuthentication: Any?

    override func setUp() {
        super.setUp()
        previousIgnoreAuthentication = UserDefaults.sharedContainerDefaults
            .object(forKey: "ignoreAuthentication")
        actions = StubActions()
    }

    override func tearDown() {
        if let previousIgnoreAuthentication {
            UserDefaults.sharedContainerDefaults
                .set(previousIgnoreAuthentication, forKey: "ignoreAuthentication")
        } else {
            UserDefaults.sharedContainerDefaults.removeObject(forKey: "ignoreAuthentication")
        }
        previousIgnoreAuthentication = nil
        actions = nil
        super.tearDown()
    }

    private func makeModel() -> AppModel {
        let model = AppModel()
        model.actions = actions
        return model
    }

    // MARK: - Add-domain routing (49.1)

    /// The ordinary case: a usable vault goes straight to the form.
    func testAddDomainPushesTheFormWhenTheVaultIsReady() {
        actions.readiness = .ready
        let model = makeModel()

        model.beginAddDomain()

        XCTAssertEqual(model.path, [.addDomain])
    }

    /// A locked vault opens the add form directly — locking does not stand between the user and
    /// adding a *new* vault.
    ///
    /// No gate here: the credential adding a vault needs is the one `provisionDomain` obtains for
    /// itself at Save, when it wraps the new domain key. Asking for it up front would be a second
    /// prompt for the same key, and the existing vaults are no part of what the user asked for.
    func testAddDomainOpensTheFormWhenLocked() {
        actions.readiness = .locked
        let model = makeModel()

        model.beginAddDomain()

        XCTAssertEqual(model.path, [.addDomain])
    }

    /// The original bug, pinned: adding a vault must not unlock the vaults that already exist.
    ///
    /// This held when the locked case routed through a gate and it holds now that it opens the
    /// form directly — the invariant is about what `beginAddDomain` may *do*, not which route it
    /// picks, so it survives either design. Routing this to `unlockVaults()` was the fault: a
    /// user who only wanted to add a vault had every locked vault opened as a side effect.
    func testAddDomainUnlocksNothingWhenLocked() {
        actions.readiness = .locked
        let model = makeModel()

        model.beginAddDomain()

        XCTAssertEqual(actions.unlockCount, 0, "adding a vault must not unlock every vault")
        XCTAssertTrue(actions.unlockScopes.isEmpty, "adding a vault must not unlock any vault")
    }

    /// A lost root routes to the same gate, which presents the reset rather than an unlock.
    func testAddDomainRoutesToTheGateWhenOrphaned() {
        actions.readiness = .orphaned
        let model = makeModel()

        model.beginAddDomain()

        XCTAssertEqual(model.path, [.vaultGate(readiness: .orphaned)])
    }

    /// The gate route is not scoped to a domain, so domains coming and going must not prune it.
    func testGateRouteSurvivesDomainChanges() {
        let model = makeModel()
        model.path = [.vaultGate(readiness: .orphaned)]

        model.setDomains([])

        XCTAssertEqual(model.path, [.vaultGate(readiness: .orphaned)])
    }

    // MARK: - Lock indication (Step 4)

    /// A locked vault reads as locked, not as the red fault badge — it is a state the user chose
    /// and can undo by unlocking.
    func testLockedDomainDerivesLockedNotError() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let domain = NSFileProviderDomain(identifier: .init(rawValue: UUID().uuidString),
                                          displayName: "Locked")
        let entry = DomainEntry(domain: domain,
                                account: DomainAccount(displayName: "Locked", backendKind: .emulator),
                                uploadProgress: nil, downloadProgress: nil, isRemoved: true)
        XCTAssertTrue(entry.locked, "precondition")

        XCTAssertEqual(AppModel.deriveActivity([entry]), .locked)
    }

    /// Locked outranks an in-flight transfer: the vault cannot serve content either way, and the
    /// remedy is the unlock.
    func testLockedTakesPrecedenceOverActive() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let progress = Progress(totalUnitCount: 100)
        progress.completedUnitCount = 10
        let account = DomainAccount(displayName: "V", backendKind: .emulator)
        let locked = DomainEntry(domain: .init(identifier: .init(rawValue: UUID().uuidString),
                                               displayName: "L"),
                                 account: account, uploadProgress: nil, downloadProgress: nil,
                                 isRemoved: true)
        let busy = DomainEntry(domain: .init(identifier: .init(rawValue: UUID().uuidString),
                                             displayName: "B"),
                               account: account, uploadProgress: progress, downloadProgress: nil)

        XCTAssertEqual(AppModel.deriveActivity([busy, locked]), .locked)
    }

    // MARK: - Orphaned vault: precedence and startup routing

    /// The vault fault outranks a locked domain. Locking is a state the user chose and can undo;
    /// an orphaned root is a fault only the reset clears, so it must not hide behind the padlock.
    func testVaultErrorOutranksLocked() {
        UserDefaults.sharedContainerDefaults.set(true, forKey: "ignoreAuthentication")
        let entry = DomainEntry(domain: .init(identifier: .init(rawValue: UUID().uuidString),
                                              displayName: "L"),
                                account: DomainAccount(displayName: "L", backendKind: .emulator),
                                uploadProgress: nil, downloadProgress: nil, isRemoved: true)
        XCTAssertTrue(entry.locked, "precondition")

        XCTAssertEqual(AppModel.deriveActivity([entry], vaultOrphaned: false), .locked)
        XCTAssertEqual(AppModel.deriveActivity([entry], vaultOrphaned: true), .vaultError)
    }

    /// Readiness is cached on the model so the icon can render without a keychain read per frame;
    /// the refresh is what keeps that cache honest.
    func testRefreshVaultReadinessDrivesTheAggregateIcon() {
        let model = makeModel()
        actions.readiness = .orphaned

        model.refreshVaultReadiness()

        XCTAssertTrue(model.vaultOrphaned)
        XCTAssertEqual(model.activity, .vaultError, "with no domains at all, the fault still shows")

        actions.readiness = .ready
        model.refreshVaultReadiness()

        XCTAssertFalse(model.vaultOrphaned)
        XCTAssertEqual(model.activity, .idle, "a reset clears the badge")
    }

    /// Opening the popover with a missing vault key lands on the gate, not on Home — the fault is
    /// what the user is shown rather than something they must go looking for.
    func testPopoverPresentationRoutesToTheGateWhenOrphaned() {
        actions.readiness = .orphaned
        let model = makeModel()

        model.prepareForPopoverPresentation()

        XCTAssertEqual(model.path, [.vaultGate(readiness: .orphaned)])
    }

    /// The ordinary case is unchanged: opening the popover resets to Home.
    func testPopoverPresentationResetsToHomeWhenReady() {
        actions.readiness = .ready
        let model = makeModel()
        model.path = [.security]

        model.prepareForPopoverPresentation()

        XCTAssertEqual(model.path, [], "Home is the root")
    }

    /// Re-opening the popover (or a second unlock attempt) must not stack duplicate gates.
    func testGateIsNotPushedTwice() {
        actions.readiness = .orphaned
        let model = makeModel()

        model.prepareForPopoverPresentation()
        XCTAssertTrue(model.routeToVaultGateIfOrphaned())

        XCTAssertEqual(model.path, [.vaultGate(readiness: .orphaned)])
    }

    /// A usable (or merely locked) vault leaves the unlock flow alone — only `.orphaned` diverts
    /// it, because only `.orphaned` cannot be resolved by unlocking.
    func testUnlockIsNotDivertedWhenNotOrphaned() {
        let model = makeModel()

        for readiness in [VaultReadiness.ready, .locked] {
            actions.readiness = readiness
            model.path = []
            XCTAssertFalse(model.routeToVaultGateIfOrphaned(), "\(readiness) must not divert")
            XCTAssertEqual(model.path, [])
        }
    }

    // MARK: - Gating commit contract (49.2)

    /// The defect: the checkbox was set before the commit, and a cancelled Touch ID enrollment
    /// left it on. The selection must revert to what the vault actually holds.
    func testFailedCommitRevertsTheSelection() {
        var selection = GatingSelection(committed: .none)

        selection.select(.biometric)
        selection.beginCommit()
        XCTAssertEqual(selection.selected, .biometric, "the attempt is shown while in flight")

        selection.commitFailed()

        XCTAssertEqual(selection.selected, .none, "a cancelled enrollment must not stay selected")
        XCTAssertEqual(selection.committed, .none, "and the vault is unchanged")
    }

    // MARK: - One intent, one prompt

    /// The whole point of ``SecurityFlow``: the capability the gate evaluated is the one the
    /// re-key spends, so changing the method costs **one** prompt rather than two.
    func testTheRekeyBorrowsTheGatesCapability() async throws {
        let model = makeModel()
        actions.seedInstallGating(.secure)
        let flow = SecurityFlow(invalidate: { _ in })
        model.securityFlow = flow

        // The gate proves presence and hands the capability to the flow.
        let context = try await actions.evaluateGatingPresence()
        flow.admit(context: context)

        // Save spends it, borrowed for the duration of the call.
        try await flow.withPresence { borrowed in
            try await actions.setVaultGating(.pin, newPIN: "4821", currentPIN: nil,
                                             presenceContext: borrowed)
        }

        XCTAssertEqual(actions.presenceEvaluations, 1,
                       "one continuous intent must raise exactly one prompt")
        XCTAssertEqual(actions.borrowedContexts.count, 1)
        XCTAssertTrue(actions.borrowedContexts[0] === actions.presenceToken,
                      "the re-key must receive the gate's own capability, not a fresh one")
    }

    /// Ending the flow drops the capability, so a later Save cannot silently reuse it.
    func testEndingTheFlowRevokesTheCapability() async throws {
        let model = makeModel()
        actions.seedInstallGating(.secure)
        let flow = SecurityFlow(invalidate: { _ in })
        model.securityFlow = flow
        flow.admit(context: try await actions.evaluateGatingPresence())

        model.endSecurityFlow()

        XCTAssertFalse(flow.hasPresence)
        XCTAssertNil(model.securityFlow)
    }

    // MARK: - Security routing

    /// A domain entry that is not locked, for the routing tests below.
    private func openDomain(named name: String) -> DomainEntry {
        DomainEntry(domain: .init(identifier: .init(rawValue: UUID().uuidString),
                                  displayName: name),
                    account: DomainAccount(displayName: name, backendKind: .emulator),
                    uploadProgress: nil, downloadProgress: nil)
    }

    /// `.none` has no gating key to produce, so there is nothing to gate on.
    func testOpenSecurityGoesStraightThroughWhenUngated() {
        let model = makeModel()
        actions.seedInstallGating(.none)
        model.setDomains([openDomain(named: "A")])

        model.openSecurity()

        XCTAssertEqual(model.path, [.security])
        XCTAssertEqual(model.securityFlow?.isCountingDown, true,
                       "the `.none` screen must still auto-close")
    }

    /// Every real gating method puts the gate in front of the screen. Domain state is irrelevant:
    /// there is no "vault unlocked" — the gating key is forgotten after every operation, and a
    /// domain holding `.unwrapped` slots says nothing about whether it can be produced again.
    func testOpenSecurityGatesUnderEveryRealMethod() {
        for method in [SharedConfig.VaultGating.pin, .biometric, .secure] {
            let model = makeModel()
            actions.seedInstallGating(method)
            let domain = openDomain(named: "A")
            model.setDomains([domain])
            XCTAssertFalse(domain.locked, "precondition: the domain holds unwrapped slots")

            model.openSecurity()

            XCTAssertEqual(model.path, [.unlock(domainIDs: [], then: .security)],
                           "\(method) must be gated regardless of domain slot state")
        }
    }

    /// The gate carries **no** domain scope: it unlocks nothing, so it has nothing to scope.
    func testTheGateHasNoDomainScope() {
        let model = makeModel()
        actions.seedInstallGating(.biometric)
        model.setDomains([openDomain(named: "A"), openDomain(named: "B")])

        model.openSecurity()

        guard case let .unlock(domainIDs, then) = model.path.first else {
            return XCTFail("expected the gate to be pushed")
        }
        XCTAssertEqual(then, .security)
        XCTAssertTrue(domainIDs.isEmpty, "a gate that opens nothing needs no scope")
    }

    /// With no domains configured the gate still applies: the method is what is being changed,
    /// and the user must still prove they can produce its key.
    func testOpenSecurityGatesEvenWithNoDomains() {
        let model = makeModel()
        actions.seedInstallGating(.biometric)
        model.setDomains([])

        model.openSecurity()

        XCTAssertEqual(model.path, [.unlock(domainIDs: [], then: .security)])
    }

    /// A selection is *dirty* until it lands, which is what gives Save something to do. The
    /// screen is a form now, so an uncommitted draft no longer traps the user — Cancel discards
    /// it — but the draft/vault distinction it rests on must still hold.
    func testSelectionIsDirtyUntilCommitted() {
        var selection = GatingSelection(committed: .none)
        XCTAssertFalse(selection.isDirty, "a fresh selection matches the vault")
        XCTAssertTrue(selection.isSettled)

        selection.select(.biometric)
        XCTAssertTrue(selection.isDirty, "an uncommitted selection is a pending change")
        XCTAssertFalse(selection.isSettled)

        selection.beginCommit()
        XCTAssertFalse(selection.isSettled, "a commit in flight is not settled")

        selection.commitSucceeded(.biometric)
        XCTAssertFalse(selection.isDirty, "a landed commit matches the vault again")
        XCTAssertTrue(selection.isSettled)
    }

    /// Reverting after a failure returns the draft to what the vault holds, so the screen stops
    /// offering to re-apply an enrollment the user cancelled.
    func testRevertRestoresSettledState() {
        var selection = GatingSelection(committed: .none)
        selection.select(.biometric)
        selection.beginCommit()
        selection.commitFailed()

        XCTAssertFalse(selection.isDirty)
        XCTAssertTrue(selection.isSettled)
    }

    /// The task-41 rule survives the move to a form: `.pin` with an unusable entry is not
    /// committable, so Save stays disabled rather than enrolling an unusable secret.
    func testPinWithInvalidEntryIsNotCommittable() {
        var selection = GatingSelection(committed: .none)
        selection.select(.pin)

        XCTAssertFalse(selection.canCommit(pinIsValid: false))
        XCTAssertTrue(selection.canCommit(pinIsValid: true))
    }

    /// A commit in flight blocks another one — the fix for the re-key storm at the model level:
    /// no second pass may start while the first is still re-wrapping domain keys.
    func testCommitInFlightBlocksAnotherCommit() {
        var selection = GatingSelection(committed: .none)
        selection.select(.pin)
        selection.beginCommit()

        XCTAssertFalse(selection.canCommit(pinIsValid: true),
                       "a re-key in flight must not be raced by a second one")

        selection.commitSucceeded(.pin)
        XCTAssertTrue(selection.canCommit(pinIsValid: true))
    }

    /// The seam the view drives: the commit is awaitable and reports failure, so the view has
    /// something to revert on.
    func testGatingCommitReportsFailure() async {
        actions.commitError = VaultKeyStoreError.biometricsUnavailable

        do {
            try await actions.setVaultGating(.biometric, newPIN: nil, currentPIN: nil)
            XCTFail("a failed enrollment must surface to the caller")
        } catch {
            XCTAssertEqual(error as? VaultKeyStoreError, .biometricsUnavailable)
        }
        XCTAssertEqual(actions.committed.count, 1, "the attempt was made")
    }

    /// The success path still lands, so reverting is confined to genuine failures.
    func testGatingCommitSucceeds() async throws {
        try await actions.setVaultGating(.pin, newPIN: "1234", currentPIN: nil)
        XCTAssertEqual(actions.committed.first?.0, .pin)
        XCTAssertEqual(actions.committed.first?.1, "1234")
    }

    // MARK: - Install-wide gating (52.2)

    /// A gating commit is **install-wide**: it moves the one value every vault is protected by.
    ///
    /// This replaces the task-51 per-domain doctrine, under which a Security-screen commit was
    /// only a default for newly added domains and left existing vaults alone. Gating is now one
    /// value, so there is no per-domain gating left to leave untouched.
    func testGatingCommitAppliesToTheWholeInstall() async throws {
        try await actions.setVaultGating(.pin, newPIN: "1234", currentPIN: nil)
        XCTAssertEqual(actions.installGating, .pin)

        try await actions.setVaultGating(.secure, newPIN: nil, currentPIN: nil)

        XCTAssertEqual(actions.installGating, .secure, "one value protects every vault")
        XCTAssertEqual(actions.vaultGating, .secure, "and the model reads that same value")
        XCTAssertEqual(actions.committed.map(\.0), [.pin, .secure])
    }

    /// A failed commit leaves the install's gating untouched, so the picker has something honest
    /// to revert to — the task-49.2 contract, now over a single install-wide value.
    func testFailedCommitLeavesTheInstallGatingUnchanged() async throws {
        try await actions.setVaultGating(.pin, newPIN: "1234", currentPIN: nil)
        actions.commitError = VaultKeyStoreError.secureEnclaveUnavailable

        do {
            try await actions.setVaultGating(.secure, newPIN: nil, currentPIN: nil)
            XCTFail("an unavailable enclave must surface to the caller")
        } catch {
            XCTAssertEqual(error as? VaultKeyStoreError, .secureEnclaveUnavailable)
        }
        XCTAssertEqual(actions.installGating, .pin, "the vaults are unchanged")
    }

    /// Unlock All is **one** batched request, not a loop over the domains — looping would
    /// re-prompt per vault.
    func testUnlockAllIsASingleBatchedRequest() async throws {
        try await actions.unlockVaults(domainIDs: ["A", "B"])
        XCTAssertEqual(actions.unlockScopes, [["A", "B"]])
        XCTAssertEqual(actions.unlockCount, 0, "the batch path is not the per-vault one")
    }

    /// `.secure` is a fourth case, so the selection machine must carry it exactly like the other
    /// three — selected, committed, and revertible on a cancelled enrollment.
    func testSecureGatingFlowsThroughTheSelectionMachine() {
        var selection = GatingSelection(committed: .none)

        selection.select(.secure)
        XCTAssertTrue(selection.isDirty, "an uncommitted selection is a pending change")

        selection.beginCommit()
        selection.commitSucceeded(.secure)

        XCTAssertEqual(selection.committed, .secure)
        XCTAssertTrue(selection.canCommit(pinIsValid: false),
                      "`.secure` needs no PIN entry on screen")
        XCTAssertTrue(selection.isSettled)
    }

    /// A destroyed enclave key (a Touch ID enrollment change) surfaces as a failed commit like
    /// any other, so the selection reverts rather than claiming a gating that was never written.
    func testSecureCommitFailureReverts() {
        var selection = GatingSelection(committed: .pin)

        selection.select(.secure)
        selection.beginCommit()
        selection.commitFailed()

        XCTAssertEqual(selection.selected, .pin)
        XCTAssertEqual(selection.committed, .pin)
    }
}
