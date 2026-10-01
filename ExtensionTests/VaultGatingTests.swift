/// Unit tests for `VaultGating`.
//
//  VaultGatingTests.swift
//  ExtensionTests
//
//  The install-wide gating ceremonies, against the **real** App Group keychain (tasks 47, 51, 52).
//
//  These need a signed host: the `.none` params slot uses `kSecUseDataProtectionKeychain`, whose
//  app-identifier entitlement `CommonTests` (no host application) does not carry. What is
//  exercised here is therefore the part `CommonTests` structurally cannot reach — a genuine
//  `SecItemAdd`/`SecItemCopyMatching` round trip through `vault.gating.none.params`, the PIN
//  record, and the `.pub`/`.wrapped` halves of the gating keypair, including the crash-window
//  ordering that keeps a vault openable.
//
//  The key-graph invariants themselves (I3/I5′, rotation, per-domain `.secure` isolation, the
//  token layer) are covered in `CommonTests.VaultKeyStoreDomainTests`, which runs unattended
//  everywhere.
//
//  - Important: **No test here may construct `LABiometricGate`.** `.biometric` params are held in
//    memory behind ``VaultKeyStore/StubBiometricGate``, and the enclave behind
//    ``StubEnclaveGate``; a live Touch ID prompt is not satisfiable by an unattended suite.
//
//  Tests that once lived here and are now deleted along with the concepts they covered:
//  `ensureVaultExists`, `resetVaultRoot` and the install-wide orphan guard. Under I5′ there is no
//  vault root to establish, reset, or guard — a missing wrapper orphans exactly its own domain,
//  which `testMissingWrapperOrphansOnlyItsOwnDomain` covers in `CommonTests`.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
@testable import Common

/// A ``SecureEnclaveGate`` backed by an in-process P-256 key.
///
/// The real enclave would prompt, which an unattended suite cannot satisfy. Substituting the
/// keypair keeps the *storage* under test real — the ephemeral public key still round-trips
/// through `vault.gating.secure.params` — while removing only the prompt.
private final class StubEnclaveGate: SecureEnclaveGate, @unchecked Sendable {
    private let priv = P256.KeyAgreement.PrivateKey()
    let available: Bool
    private(set) var agreeCount = 0
    /// The presence token each agreement was handed, so a test can assert that N domains ran
    /// under **one** evaluation rather than N.
    private(set) var contextsSeen: [AnyObject] = []

    init(available: Bool = true) { self.available = available }

    var isAvailable: Bool { available }

    func enrollEphemeral() throws -> SecureEnclaveEnrollment {
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: priv.publicKey)
        return SecureEnclaveEnrollment(ephemeralPublicKey: eph.publicKey.x963Representation,
                                       sharedSecret: shared.withUnsafeBytes { Data($0) })
    }

    func agree(withEphemeralPublicKey ephemeralPublicKey: Data,
               reason: String, context: AnyObject?) throws -> Data {
        agreeCount += 1
        if let context { contextsSeen.append(context) }
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
    }
}

/// A ``SecureEnclaveGate`` whose key can be destroyed mid-test, as a Touch ID enrollment change
/// destroys the real one.
///
/// Models the post-loss contract: `agree` throws ``VaultKeyStoreError/gatingKeyMissing`` and
/// creates nothing. The production gate reaches the same state through `SecItemCopyMatching`
/// returning `errSecItemNotFound` or the ACL error, neither of which an unattended suite can
/// provoke against a real enclave.
private final class LostKeyEnclaveGate: SecureEnclaveGate, @unchecked Sendable {
    private let priv = P256.KeyAgreement.PrivateKey()
    private var lost = false
    private(set) var agreeCount = 0

    var isAvailable: Bool { true }
    func loseKey() { lost = true }

    func enrollEphemeral() throws -> SecureEnclaveEnrollment {
        if lost { throw VaultKeyStoreError.gatingKeyMissing }
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: priv.publicKey)
        return SecureEnclaveEnrollment(ephemeralPublicKey: eph.publicKey.x963Representation,
                                       sharedSecret: shared.withUnsafeBytes { Data($0) })
    }

    func agree(withEphemeralPublicKey ephemeralPublicKey: Data,
               reason: String, context: AnyObject?) throws -> Data {
        if lost { throw VaultKeyStoreError.gatingKeyMissing }
        agreeCount += 1
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
    }
}

/// A ``BiometricGate`` that counts presence evaluations and never prompts.
///
/// The count is the assertion for "one prompt for N domains": the production gate would raise
/// exactly one Touch ID sheet per ``authenticatedContext(reason:)`` call, so counting the calls
/// counts the prompts without needing a prompt.
///
/// - Important: It returns a **non-nil** presence token, as ``LABiometricGate`` does. A gate
///   handing back `nil` is indistinguishable from "no presence available", so every ceremony
///   would evaluate again for itself — N prompts, and a count that measures the stub rather than
///   the batching under test.
private final class CountingBiometricGate: BiometricGate, @unchecked Sendable {
    /// Stands in for the evaluated `LAContext`. Only its identity matters here: the ceremonies
    /// pass it along, and the in-memory params accessors ignore it.
    private let token = NSObject()
    private(set) var contextCount = 0
    /// Tokens handed to ``invalidateContext(_:)``. A presence token that never appears here
    /// outlived the operation that raised it.
    private(set) var invalidated: [ObjectIdentifier] = []
    var isAvailable: Bool { true }
    func authenticate(reason: String) async throws {}
    func authenticatedContext(reason: String) async throws -> AnyObject? {
        contextCount += 1
        return token
    }
    func invalidateContext(_ context: AnyObject?) {
        if let context { invalidated.append(ObjectIdentifier(context)) }
    }
}

/// The gating slots are shared with the running app, so this suite must never address the real
/// ones: it deletes the install's gating triples, which on a developer machine are live.
///
/// ``KeychainIsolatedTestCase`` moves both the keychain namespace and `config.json` aside, so
/// nothing here reaches the developer's keys or configuration.
final class VaultGatingTests: KeychainIsolatedTestCase {

    private let domain = "test-gating-domain"
    private let sibling = "test-gating-sibling"
    private let third = "test-gating-third"

    /// The install's gating state — one method, plus the configured domain set.
    private var gatings: VaultKeyStore.GatingBox!

    override func setUp() {
        super.setUp()
        gatings = VaultKeyStore.GatingBox()
        // The keychain namespace is per *suite*; a gating triple inherited from the previous test
        // would be openable by nothing, so start from none.
        purgeGatingTriples()
    }

    override func tearDown() {
        purgeGatingTriples()
        gatings = nil
        super.tearDown()
    }

    /// Remove every gating triple this suite could have written, for every method and account.
    private func purgeGatingTriples() {
        for method in SharedConfig.VaultGating.allCases {
            for account in [CryptoKeychain.gatingSharedAccount, domain, sibling, third] {
                CryptoKeychain.deleteGatingTriple(method, domain: account)
            }
        }
    }

    // MARK: - Lock semantics

    /// Lock evicts the Provider-readable slots; the wrapped material survives, so the domain
    /// reopens without re-provisioning.
    func testUnlockThenLockEvictsOnlyTheUnwrappedSlots() async throws {
        let store = makeStore()
        try await provision(store, domain)
        XCTAssertTrue(store.isUnlocked(domain: domain))

        store.lock(domain: domain)

        XCTAssertFalse(store.isUnlocked(domain: domain))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domain))
        XCTAssertNotNil(try CryptoKeychain.loadWrappedDomainKey(for: domain),
                        "the wrapper must survive a lock")

        try await store.unlock(domain: domain)
        XCTAssertTrue(store.isUnlocked(domain: domain))
    }

    // MARK: - The invariant

    /// The `domainKey` is never written in the clear: the wrapper is an ECIES box, and the raw
    /// key appears in no slot.
    func testDomainKeyIsNeverStoredUnwrapped() async throws {
        let store = makeStore()
        try await provision(store, domain)

        let wrapper = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domain))
        XCTAssertGreaterThan(wrapper.count, 65 + 32,
                             "an ECIES box carries a 65-byte ephemeral plus a GCM box")

        // The gating keypair is what opens it, and its halves are separate slots. Neither the
        // public half nor the sealed private half is the key.
        let pub = try XCTUnwrap(try CryptoKeychain.loadGatingPublicKey(
            .none, domain: CryptoKeychain.gatingSharedAccount))
        XCTAssertEqual(pub.count, 65, "an x9.63 P-256 public key is 65 bytes")
        XCTAssertNotEqual(wrapper, pub)

        let sealedPrivate = try XCTUnwrap(try CryptoKeychain.loadGatingWrappedKey(
            .none, domain: CryptoKeychain.gatingSharedAccount))
        XCTAssertGreaterThan(sealedPrivate.count, 32, "the private half is sealed, not raw")
        XCTAssertNotEqual(wrapper, sealedPrivate)
    }

    /// **I4 discipline.** The gating private key exists nowhere at rest in the clear — before an
    /// unlock, during one, or after it. Only the sealed half and the public half are persisted.
    func testGatingPrivateKeyIsNeverPersistedUnwrapped() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain)

        let account = CryptoKeychain.gatingSharedAccount
        let pub = try XCTUnwrap(try CryptoKeychain.loadGatingPublicKey(.none, domain: account))
        let wrapped = try XCTUnwrap(try CryptoKeychain.loadGatingWrappedKey(.none, domain: account))
        let params = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.none, domain: account))

        // A raw P-256 private key is exactly 32 bytes; the sealed half is a larger GCM box.
        XCTAssertNotEqual(wrapped.count, 32, "the private half must be sealed, never raw")
        // And the seal is real: the params key opens it, so the two are genuinely distinct roles.
        let priv = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: try VaultKeyStore.unwrap(wrapped, with: SymmetricKey(data: params)))
        XCTAssertEqual(priv.publicKey.x963Representation, pub,
                       "the sealed half must be the mate of the published public half")
        // The raw private bytes appear in no persisted slot.
        for slot in [pub, wrapped, params,
                     try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domain))] {
            XCTAssertFalse(slot.range(of: priv.rawRepresentation) != nil,
                           "no slot may contain the clear gating private key")
        }
    }

    /// Switching to PIN deletes the `.none` triple, so no promptless path to the `domainKey`
    /// survives. This is the whole point of re-sealing rather than layering a second wrapper.
    func testPINGatingDeletesTheDeviceGatingKey() async throws {
        let store = makeStore()
        try await provision(store, domain)

        try await store.setGating(.pin, newPIN: "1234")

        let account = CryptoKeychain.gatingSharedAccount
        XCTAssertNil(try CryptoKeychain.loadGatingParams(.none, domain: account),
                     "the silently-readable device params must be gone once a PIN gates the vault")
        XCTAssertNil(try CryptoKeychain.loadGatingWrappedKey(.none, domain: account))
        XCTAssertNil(try CryptoKeychain.loadGatingPublicKey(.none, domain: account))
    }

    /// A gating change preserves every wrapped leaf — the `domainKey` is re-sealed, never
    /// re-minted, so nothing sealed under it is orphaned.
    func testGatingChangePreservesWrappedMaterial() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try store.commitRefreshToken("token", for: domain, establishing: true)

        try await store.setGating(.pin, newPIN: "1234")
        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain, pin: "1234")

        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domain),
                       Data("der".utf8))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domain), "token")
    }

    /// A wrong PIN is rejected by the throttled verifier, not by a GCM failure.
    func testWrongPINCannotUnlock() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try await store.setGating(.pin, newPIN: "1234")
        try store.evictUnwrappedSlots(for: domain)

        do {
            try await store.unlock(domain: domain, pin: "9999")
            XCTFail("a wrong PIN must not unlock")
        } catch {
            XCTAssertFalse(store.isUnlocked(domain: domain))
        }

        try await store.unlock(domain: domain, pin: "1234")
        XCTAssertTrue(store.isUnlocked(domain: domain))
    }

    /// **Regression.** `PINCeremony.open` surfaces `incorrectPIN` — not a generic unwrap failure
    /// — and each rejection grows the backoff, which is the brute-force defence.
    func testWrongPINIsRejectedAndThrottled() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try await store.setGating(.pin, newPIN: "1234")
        try store.evictUnwrappedSlots(for: domain)

        XCTAssertEqual(store.pinRetryDelay, 0, "a fresh gate imposes no delay")

        for attempt in 1...3 {
            do {
                try await store.unlock(domain: domain, pin: "9999")
                XCTFail("attempt \(attempt): a wrong PIN must not unlock")
            } catch {
                XCTAssertEqual(error as? PINGateError, .incorrectPIN,
                               "the throttled verifier rejects, not the GCM open")
            }
        }
        XCTAssertGreaterThan(store.pinRetryDelay, 0, "repeated failures must escalate the backoff")

        // A correct PIN still opens the vault and clears the backoff — throttling, not lockout.
        try await store.unlock(domain: domain, pin: "1234")
        XCTAssertTrue(store.isUnlocked(domain: domain))
        XCTAssertEqual(store.pinRetryDelay, 0)
    }

    /// Under PIN gating an unlock with no PIN cannot succeed — there is no silent fallback.
    func testPINGatingRejectsAPromptlessUnlock() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try await store.setGating(.pin, newPIN: "1234")
        try store.evictUnwrappedSlots(for: domain)

        do {
            try await store.unlock(domain: domain)
            XCTFail("unlock with no PIN must fail under PIN gating")
        } catch {
            XCTAssertEqual(error as? VaultKeyStoreError, .pinRequired)
        }
    }

    // MARK: - One prompt for N domains

    /// Presence is evaluated **once** for N domains, so Unlock All costs one prompt.
    ///
    /// Asserted through the gate seam: the production gate raises exactly one sheet per
    /// `authenticatedContext(reason:)`, so counting the calls counts the prompts. Covered for
    /// both presence-requiring methods — `.secure` derives an independent per-domain key from the
    /// single evaluation, which is what makes per-domain isolation compatible with one prompt.
    func testUnlockAllEvaluatesPresenceOnceForNDomains() async throws {
        for method in [SharedConfig.VaultGating.biometric, .secure] {
            let gate = CountingBiometricGate()
            let enclave = StubEnclaveGate()
            let store = makeStore(enclave: enclave, biometric: gate)
            gatings.set(method)
            for name in [domain, sibling, third] { try await provision(store, name) }
            try store.evictUnwrappedSlots()

            try await store.populateUnwrappedSlots(for: [domain, sibling, third])

            XCTAssertEqual(gate.contextCount, 1,
                           "\(method.rawValue): three domains must cost one presence evaluation")
            XCTAssertEqual(enclave.contextsSeen.count, method == .secure ? 3 : 0,
                           "\(method.rawValue): the enclave agrees once per domain…")
            XCTAssertLessThanOrEqual(Set(enclave.contextsSeen.map(ObjectIdentifier.init)).count, 1,
                                     "\(method.rawValue): …but always under the one presence token")
            XCTAssertEqual(gate.invalidated.count, 1,
                           "\(method.rawValue): the presence token must be invalidated when the "
                           + "unlock closes — it must not survive to open a vault unasked")
            for name in [domain, sibling, third] {
                XCTAssertTrue(store.isUnlocked(domain: name),
                              "\(method.rawValue): every domain must open from that one prompt")
            }
            purgeGatingTriples()
        }
    }

    /// A method needing no presence evaluates no ceremony at all — zero prompts for N domains.
    func testUnlockAllPromptsZeroTimesUnderNone() async throws {
        let gate = CountingBiometricGate()
        let store = makeStore(biometric: gate)
        for name in [domain, sibling, third] { try await provision(store, name) }
        try store.evictUnwrappedSlots()

        try await store.populateUnwrappedSlots(for: [domain, sibling, third])

        XCTAssertEqual(gate.contextCount, 0, "`.none` requires no presence")
        XCTAssertFalse(VaultKeyStore.requiresPresence(.none))
        XCTAssertFalse(VaultKeyStore.requiresPresence(.pin))
        for name in [domain, sibling, third] { XCTAssertTrue(store.isUnlocked(domain: name)) }
    }

    /// A `.secure` unlock whose enclave key is gone must **fail**, never mint a replacement.
    ///
    /// `SecureEnclaveKeyGate.enclavePrivateKey` used to create a key on `errSecItemNotFound`,
    /// inside the unlock path. A fresh keypair cannot open any existing `.params` ephemeral, so
    /// every derived gating key would be wrong — surfacing as a generic `unwrapFailed` instead of
    /// the destroyed-enclave cause, and silently replacing the key every `.secure` vault is
    /// gated on. Unlock must report the loss, not paper over it.
    ///
    /// Asserted through the gate seam: a gate that has lost its key throws `gatingKeyMissing`,
    /// and the domain must stay locked rather than come back under new material.
    func testSecureUnlockWithLostEnclaveKeyFailsRatherThanReMinting() async throws {
        let enclave = LostKeyEnclaveGate()
        let store = makeStore(enclave: enclave)
        gatings.set(.secure)
        try await provision(store, domain)
        let sealedBefore = try CryptoKeychain.loadGatingParams(.secure, domain: domain)
        try store.evictUnwrappedSlots()

        enclave.loseKey()
        try await store.populateUnwrappedSlots(for: [domain])

        XCTAssertFalse(store.isUnlocked(domain: domain),
                       "a vault whose enclave key is gone must stay locked")
        XCTAssertEqual(try CryptoKeychain.loadGatingParams(.secure, domain: domain), sealedBefore,
                       "the stored ephemeral must not be replaced by a re-mint")
        XCTAssertEqual(enclave.agreeCount, 0, "no agreement may run against a key that is gone")
    }

    // MARK: - Crash window and supersession

    /// Crash-window recovery: the new wrapper is written before the old gating triple is deleted,
    /// so a crash leaves a stale triple and the vault still opens. Reconciliation removes it, and
    /// only ever the non-active one — which is why this can never brick a vault.
    func testReconcileDropsTheSupersededGatingKey() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try await store.setGating(.pin, newPIN: "1234")

        // Model the crash: re-add a `.none` triple that `setGating` would have deleted.
        let account = CryptoKeychain.gatingSharedAccount
        let stale = P256.KeyAgreement.PrivateKey()
        let staleParams = Data(repeating: 3, count: 32)
        try CryptoKeychain.storeGatingParams(staleParams, method: .none, domain: account)
        try CryptoKeychain.storeGatingWrappedKey(
            try VaultKeyStore.wrap(stale.rawRepresentation, with: SymmetricKey(data: staleParams)),
            method: .none, domain: account)
        try CryptoKeychain.storeGatingPublicKey(stale.publicKey.x963Representation,
                                                method: .none, domain: account)

        store.reconcile(domain: domain)

        XCTAssertNil(try CryptoKeychain.loadGatingParams(.none, domain: account),
                     "the superseded gating triple must be dropped")
        XCTAssertNil(try CryptoKeychain.loadGatingWrappedKey(.none, domain: account))
        XCTAssertNil(try CryptoKeychain.loadGatingPublicKey(.none, domain: account))

        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain, pin: "1234")
        XCTAssertTrue(store.isUnlocked(domain: domain), "the active gating still opens the vault")
    }

    /// **Crash-window order.** A method change leaves no trace of the superseded triple, and the
    /// re-sealed wrapper is in place before it goes — every domain opens throughout.
    func testMethodChangeDeletesTheSupersededTriple() async throws {
        let store = makeStore()
        try await provision(store, domain, gating: .secure)
        try await provision(store, sibling, gating: .secure)
        let before = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domain))

        try await store.setGating(.none)

        // `.secure`'s triple is per domain, so retiring it means one deletion per domain.
        for name in [domain, sibling] {
            XCTAssertNil(try CryptoKeychain.loadGatingPublicKey(.secure, domain: name),
                         "\(name): the stale `.pub` must be gone")
            XCTAssertNil(try CryptoKeychain.loadGatingWrappedKey(.secure, domain: name),
                         "\(name): the stale `.wrapped` must be gone")
            XCTAssertNil(try CryptoKeychain.loadGatingParams(.secure, domain: name),
                         "\(name): the stale `.params` must be gone")
        }

        // Order: the new wrapper was written before any of that was deleted.
        XCTAssertNotEqual(try CryptoKeychain.loadWrappedDomainKey(for: domain), before)
        XCTAssertNotNil(try CryptoKeychain.loadGatingPublicKey(
            .none, domain: CryptoKeychain.gatingSharedAccount))

        try store.evictUnwrappedSlots()
        for name in [domain, sibling] {
            try await store.unlock(domain: name)
            XCTAssertTrue(store.isUnlocked(domain: name))
        }
    }

    /// A shared gating slot is live while **any** domain is gated onto it.
    ///
    /// Gating is install-wide, so a re-gate re-seals every domain in one step: the shared triple
    /// serving a sibling is never deleted out from under it. Re-sealing only one domain and
    /// dropping the shared key bricked every sibling.
    func testReGatingOneDomainKeepsASiblingsSharedGatingKey() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try await provision(store, sibling)

        try await store.setGating(.pin, newPIN: "1234")

        let account = CryptoKeychain.gatingSharedAccount
        XCTAssertNotNil(try CryptoKeychain.loadGatingPublicKey(.pin, domain: account),
                        "the install's active shared keypair must exist")
        XCTAssertEqual(try CryptoKeychain.loadGatingPublicKey(.pin, domain: account),
                       try CryptoKeychain.loadGatingPublicKey(.pin, domain: sibling),
                       "the sibling resolves to the same install-wide keypair")

        // And the sibling still opens — the survey that used to guard this now has one answer.
        try store.evictUnwrappedSlots(for: sibling)
        try await store.unlock(domain: sibling, pin: "1234")
        XCTAssertTrue(store.isUnlocked(domain: sibling))
    }

    /// **Atomicity.** A re-seal that fails part-way leaves **every** domain openable under
    /// the method it started on — never a half-migrated install.
    ///
    /// Modelled by deleting one domain's wrapper mid-flight is not possible from outside, so the
    /// failure is injected where the design says it must abort: Phase A, opening every domain
    /// under the *current* method. A corrupt wrapper on the third domain fails that phase before
    /// any gating slot has been touched.
    func testSetGatingIsAtomicAcrossNDomains() async throws {
        let store = makeStore()
        try await provision(store, domain)
        try await provision(store, sibling)
        try await provision(store, third)

        let goodDomain = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domain))
        let goodSibling = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: sibling))
        // A wrapper that no gating key opens: Phase A must throw on it.
        try CryptoKeychain.storeWrappedDomainKey(Data(repeating: 7, count: 120), for: third)

        do {
            try await store.setGating(.pin, newPIN: "1234")
            XCTFail("a domain that cannot be opened must abort the whole switch")
        } catch {
            // Expected — the method stays where it was.
        }

        XCTAssertEqual(store.gating(), .none, "a failed switch must not move the install")
        XCTAssertEqual(try CryptoKeychain.loadWrappedDomainKey(for: domain), goodDomain,
                       "no domain may be re-sealed when the switch aborts")
        XCTAssertEqual(try CryptoKeychain.loadWrappedDomainKey(for: sibling), goodSibling)
        XCTAssertNotNil(try CryptoKeychain.loadGatingPublicKey(
            .none, domain: CryptoKeychain.gatingSharedAccount),
            "the current method's keypair must survive an aborted switch")

        // The healthy domains still open under the method they started on.
        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain)
        XCTAssertTrue(store.isUnlocked(domain: domain))
    }

    // MARK: - `.secure` against the real params slot

    /// `.secure` stores its per-domain ephemeral public key in the clear and opens through it.
    func testSecureGatingRoundTripsThroughTheEphemeralSlot() async throws {
        let store = makeStore()
        try await provision(store, domain, gating: .secure)

        let ephemeral = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.secure, domain: domain))
        XCTAssertEqual(ephemeral.count, 65, "an x9.63 P-256 public key is 65 bytes")

        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain)
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domain),
                       Data("der".utf8))
    }

    /// **Test 17, the security half.** Re-running the `.secure` enrollment rewrites the gating
    /// keypair, and the ceremony key derived from the *previous* ephemeral must open nothing.
    ///
    /// That the stored ephemeral changes is necessary but not sufficient: what matters is that an
    /// attacker holding the old one is locked out of the new `.wrapped`. Same discipline as never
    /// reusing a nonce.
    func testSecureRewriteRetiresThePreviousGatingKey() async throws {
        let gate = StubEnclaveGate()
        let store = makeStore(enclave: gate)
        try await provision(store, domain, gating: .secure)

        // Reproduce the ceremony key the first ephemeral derives, exactly as an unlock would.
        let firstEphemeral = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.secure,
                                                                              domain: domain))
        let firstCeremonyKey = VaultKeyStore.deriveSecureGatingKey(
            sharedSecret: try gate.agree(withEphemeralPublicKey: firstEphemeral,
                                         reason: "", context: nil),
            ephemeralPublicKey: firstEphemeral,
            domainIdentifier: domain)
        let firstWrapped = try XCTUnwrap(try CryptoKeychain.loadGatingWrappedKey(.secure,
                                                                                domain: domain))
        XCTAssertNoThrow(try VaultKeyStore.unwrap(firstWrapped, with: firstCeremonyKey),
                         "precondition: the first ceremony key opens the first `.wrapped`")

        // Leave and return: `.secure`'s triple is minted afresh, ephemeral and all.
        try await store.setGating(.none)
        try await store.setGating(.secure)

        let rewritten = try XCTUnwrap(try CryptoKeychain.loadGatingWrappedKey(.secure,
                                                                             domain: domain))
        XCTAssertNotEqual(firstEphemeral,
                          try CryptoKeychain.loadGatingParams(.secure, domain: domain),
                          "the rewrite must mint a fresh ephemeral")
        XCTAssertThrowsError(try VaultKeyStore.unwrap(rewritten, with: firstCeremonyKey)) { error in
            XCTAssertEqual(error as? VaultKeyStoreError, .unwrapFailed,
                           "the retired ceremony key must open nothing")
        }

        // And the current one still does.
        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain)
        XCTAssertTrue(store.isUnlocked(domain: domain))
    }

    /// A destroyed ephemeral (the shape a Touch ID re-enrollment leaves behind) reports
    /// `gatingKeyMissing` rather than opening anything.
    func testSecureGatingWithNoEphemeralCannotUnlock() async throws {
        let store = makeStore()
        try await provision(store, domain, gating: .secure)
        try store.evictUnwrappedSlots(for: domain)
        CryptoKeychain.deleteGatingTriple(.secure, domain: domain)

        do {
            try await store.unlock(domain: domain)
            XCTFail("a destroyed `.secure` gate must not unlock")
        } catch {
            XCTAssertEqual(error as? VaultKeyStoreError, .gatingKeyMissing)
        }
    }

    /// An unavailable enclave is rejected at **enroll**, before anything is half-written.
    ///
    /// The check belongs to the ceremony, so a machine with no enclave cannot be switched to
    /// `.secure` and left with a `.pub` nothing can open.
    func testSecureUnavailableIsRejectedAtEnroll() async throws {
        let unavailable = StubEnclaveGate(available: false)
        let store = makeStore(enclave: unavailable)
        try await provision(store, domain)
        let before = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domain))

        XCTAssertFalse(SecureEnclaveCeremony(gate: unavailable).isAvailable)
        do {
            try await store.setGating(.secure)
            XCTFail("an unavailable enclave must not enroll")
        } catch {
            XCTAssertEqual(error as? VaultKeyStoreError, .secureEnclaveUnavailable)
        }

        XCTAssertNil(try CryptoKeychain.loadGatingPublicKey(.secure, domain: domain),
                     "a rejected enroll must leave no half-written triple")
        XCTAssertNil(try CryptoKeychain.loadGatingWrappedKey(.secure, domain: domain))
        XCTAssertEqual(try CryptoKeychain.loadWrappedDomainKey(for: domain), before,
                       "and the domain must stay sealed to the method it had")
        XCTAssertEqual(store.gating(), .none)

        try store.evictUnwrappedSlots(for: domain)
        try await store.unlock(domain: domain)
        XCTAssertTrue(store.isUnlocked(domain: domain))
    }

    // MARK: - Fixtures

    /// A store over the real vault slots with an in-process gating marker and in-memory PIN
    /// storage, so the suite never reads or disturbs the user's own gating settings.
    ///
    /// The `.none` params slot, the gating keypair halves and every domain slot are **real**
    /// keychain items on this run's namespace — that is what this suite exists to exercise. Only
    /// the enclave and the `.biometric` params are substituted: a live Touch ID prompt cannot be
    /// satisfied unattended, so ``LABiometricGate`` is never constructed here.
    ///
    /// - Parameters:
    ///   - enclave: The enclave seam, so a test can hold the same stub the store uses and
    ///     reproduce a ceremony key the way an unlock would.
    ///   - biometric: The presence seam, so a test can count prompts.
    private func makeStore(enclave: SecureEnclaveGate = StubEnclaveGate(),
                           biometric: BiometricGate = VaultKeyStore.StubBiometricGate())
        -> VaultKeyStore {
        final class Box: @unchecked Sendable {
            var pin: PINRecord?
        }
        let box = Box()
        let gatings = self.gatings!
        // `.biometric` params in memory: the real slot's ACL'd read raises a Touch ID prompt.
        let biometricParams = VaultKeyStore.DeviceKeyBox()
        let store = VaultKeyStore(gate: biometric,
                                  pinGate: PINGate(load: { box.pin },
                                                   save: { box.pin = $0 },
                                                   iterations: 1_000),
                                  secureGate: enclave,
                                  readGating: { gatings.value },
                                  writeGating: { gatings.set($0) },
                                  isConfiguredDomain: { gatings.contains($0) },
                                  allDomainIdentifiers: { gatings.all },
                                  readBiometricGatingKey: { _ in biometricParams.value },
                                  writeBiometricGatingKey: { raw, _ in biometricParams.value = raw },
                                  deleteBiometricGatingKey: { biometricParams.value = nil })
        addTeardownBlock {
            try? store.forgetDomain(self.domain)
            try? store.forgetDomain(self.sibling)
            try? store.forgetDomain(self.third)
        }
        return store
    }

    /// Provision `name` under the install's method, setting that method first.
    ///
    /// Gating is install-wide, so `gating` names what the whole install is switched to before the
    /// domain is added — not a per-domain choice.
    private func provision(_ store: VaultKeyStore, _ name: String,
                           gating: SharedConfig.VaultGating? = nil) async throws {
        if let gating { gatings.set(gating) }
        gatings.register(name)
        try await store.provisionDomain(userIdentityKeyDER: Data("der".utf8), for: name)
    }
}
