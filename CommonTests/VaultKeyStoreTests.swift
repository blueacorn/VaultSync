/// Unit tests for `VaultKeyStore`.
//
//  VaultKeyStoreTests.swift
//  CommonTests
//
//  The AES-GCM envelope, and the per-domain key graph it seals (tasks 47, 51).
//
//  This bundle has no host application, so it holds no App Group entitlement and cannot write
//  the one slot that needs `kSecUseDataProtectionKeychain` — the device gating key.
//  `VaultKeyStore.isolatedForTesting()` holds that single key in memory; **everything below it**
//  — every wrapper, leaf and token slot — is a real keychain item on the suite's own namespace,
//  so the wrapping under test is genuinely exercised here.
//
//  The ceremonies that need a signed host or a real enclave (`.biometric` prompts, the Secure
//  Enclave asymmetry) stay in `ExtensionTests`.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
@testable import Common

private struct StubGate: BiometricGate {
    var available = true
    var isAvailable: Bool { available }
    func authenticate(reason: String) async throws {
        if !available { throw VaultKeyStoreError.biometricsUnavailable }
    }
}

final class VaultKeyStoreTests: XCTestCase {

    // MARK: - Pure envelope

    func testWrapUnwrapRoundTrip() throws {
        let key = VaultKeyStore.generateKey()
        let plaintext = Data("session-private-key-DER".utf8)
        let wrapped = try VaultKeyStore.wrap(plaintext, with: key)
        XCTAssertNotEqual(wrapped, plaintext)
        XCTAssertEqual(try VaultKeyStore.unwrap(wrapped, with: key), plaintext)
    }

    func testUnwrapWithWrongKeyFails() throws {
        let key = VaultKeyStore.generateKey()
        let other = VaultKeyStore.generateKey()
        let wrapped = try VaultKeyStore.wrap(Data("x".utf8), with: key)
        XCTAssertThrowsError(try VaultKeyStore.unwrap(wrapped, with: other)) { error in
            XCTAssertEqual(error as? VaultKeyStoreError, .unwrapFailed)
        }
    }

    func testUnwrapCorruptBlobFails() {
        let key = VaultKeyStore.generateKey()
        XCTAssertThrowsError(try VaultKeyStore.unwrap(Data([0, 1, 2, 3]), with: key)) { error in
            XCTAssertEqual(error as? VaultKeyStoreError, .unwrapFailed)
        }
    }

    /// The AAD must be part of the seal: a box cannot be transplanted onto another context.
    func testAADMismatchFailsToOpen() throws {
        let key = VaultKeyStore.generateKey()
        let box = try VaultKeyStore.wrap(Data("secret".utf8), with: key,
                                         authenticating: Data("item-A".utf8))
        XCTAssertThrowsError(
            try VaultKeyStore.unwrap(box, with: key, authenticating: Data("item-B".utf8))
        ) { error in
            XCTAssertEqual(error as? VaultKeyStoreError, .unwrapFailed)
        }
    }

    // MARK: - Refresh-token sealing (no keychain)

    /// The ECIES seal round-trips, and the box is not the token.
    func testTokenSealRoundTrip() throws {
        let priv = P256.KeyAgreement.PrivateKey()
        let token = "refresh-token-abc123"
        let box = try VaultKeyStore.sealToken(token, to: priv.publicKey)
        XCTAssertFalse(box.contains(Data(token.utf8)), "the token must not appear in the box")
        XCTAssertEqual(try VaultKeyStore.openSealedToken(box, with: priv), token)
    }

    /// Sealing twice produces different boxes — a fresh ephemeral every time.
    func testTokenSealIsNonDeterministic() throws {
        let priv = P256.KeyAgreement.PrivateKey()
        let a = try VaultKeyStore.sealToken("t", to: priv.publicKey)
        let b = try VaultKeyStore.sealToken("t", to: priv.publicKey)
        XCTAssertNotEqual(a, b, "each seal must mint its own ephemeral")
        XCTAssertEqual(try VaultKeyStore.openSealedToken(a, with: priv), "t")
        XCTAssertEqual(try VaultKeyStore.openSealedToken(b, with: priv), "t")
    }

    /// Another domain's `refreshTokenKey` opens nothing.
    func testTokenSealedToOneKeyDoesNotOpenWithAnother() throws {
        let a = P256.KeyAgreement.PrivateKey()
        let b = P256.KeyAgreement.PrivateKey()
        let box = try VaultKeyStore.sealToken("t", to: a.publicKey)
        XCTAssertThrowsError(try VaultKeyStore.openSealedToken(box, with: b))
    }

    func testTruncatedTokenBoxFails() {
        let priv = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(try VaultKeyStore.openSealedToken(Data([0, 1, 2]), with: priv)) {
            XCTAssertEqual($0 as? VaultKeyStoreError, .unwrapFailed)
        }
    }

    /// The `.secure` HKDF binds the domain: the same shared secret and ephemeral derive a
    /// different gating key per domain (belt-and-braces against a reused ephemeral).
    func testSecureGatingKeyIsBoundToTheDomain() {
        let shared = Data(repeating: 7, count: 32)
        let eph = Data(repeating: 9, count: 65)
        let a = VaultKeyStore.deriveSecureGatingKey(sharedSecret: shared,
                                                    ephemeralPublicKey: eph,
                                                    domainIdentifier: "A")
        let b = VaultKeyStore.deriveSecureGatingKey(sharedSecret: shared,
                                                    ephemeralPublicKey: eph,
                                                    domainIdentifier: "B")
        XCTAssertNotEqual(a, b, "domainID in the HKDF info must separate the derivations")
    }
}

/// The per-domain key graph, against real keychain slots on an isolated namespace.
///
/// These are the I5 regression guards: the point is that no key reaches more than one
/// domain, and a test that only exercised one domain could not see a violation.
final class VaultKeyStoreDomainTests: KeychainIsolatedTestCase {

    private var store: VaultKeyStore!
    private let domainA = "test-domain-A"
    private let domainB = "test-domain-B"

    /// The install's gating state — one method, plus the configured domain set.
    private var gatings: VaultKeyStore.GatingBox!

    override func setUp() {
        super.setUp()
        gatings = VaultKeyStore.GatingBox()
        store = VaultKeyStore.isolatedForTesting(gatings: gatings)
        // The keychain namespace is per *suite*; the store — and with it the in-memory `.none`
        // and `.biometric` params boxes — is rebuilt per test. A gating triple inherited from the
        // previous test would be openable by nothing, so start from none.
        purgeGatingTriples()
    }

    override func tearDown() {
        try? store.forgetDomain(domainA)
        try? store.forgetDomain(domainB)
        purgeGatingTriples()
        store = nil
        gatings = nil
        super.tearDown()
    }

    /// Remove every gating triple this suite could have written, for every method and account.
    private func purgeGatingTriples() {
        for method in SharedConfig.VaultGating.allCases {
            for account in [CryptoKeychain.gatingSharedAccount, domainA, domainB] {
                CryptoKeychain.deleteGatingTriple(method, domain: account)
            }
        }
    }

    /// Provision `domain` under the install's method, setting that method first.
    ///
    /// Gating is install-wide, so `gating` names what the whole install is switched to before the
    /// domain is added — not a per-domain choice.
    private func provision(_ domain: String,
                           gating: SharedConfig.VaultGating = .none) async throws {
        gatings.set(gating)
        gatings.register(domain)
        try await store.provisionDomain(userIdentityKeyDER: Data("der-\(domain)".utf8),
                                        for: domain)
    }

    // 1. `provisionDomain` writes `domainKey.wrapped`; the blob is not the raw key.
    func testProvisionWritesWrappedDomainKey() async throws {
        try await provision(domainA)
        let wrapper = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        XCTAssertGreaterThan(wrapper.count, 32, "a GCM box is larger than the 32-byte key")
        XCTAssertEqual(try store.readiness(for: domainA), .ready)
    }

    // 2. Two domains → different `domainKey`s; A's gating key cannot open B's wrapper.
    //    *The I5 regression guard — the whole point of the task.*
    func testTwoDomainsGetIndependentDomainKeys() async throws {
        try await provision(domainA)
        try await provision(domainB)

        let a = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        let b = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainB))
        XCTAssertNotEqual(a, b, "each domain must seal its own domainKey")

        // Both are gated `.none`, so they share a gating key — yet the keys inside differ, and
        // each leaf opens only under its own. That is the isolation: it lives in the key graph.
        let derA = try XCTUnwrap(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainA))
        let derB = try XCTUnwrap(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainB))
        XCTAssertNotEqual(derA, derB)

        try await store.unlock(domain: domainA)
        try await store.unlock(domain: domainB)
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA),
                       Data("der-\(domainA)".utf8))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainB),
                       Data("der-\(domainB)".utf8))
    }

    /// `isUnlocked` must read **any** unwrapped slot, not one nominated leaf.
    ///
    /// No single slot is common to every domain: `userIdentityKey` exists only under `.bc01` and
    /// `refreshToken` only for a backend that authenticates. A predicate naming one would report a
    /// domain that legitimately lacks it as permanently locked.
    func testIsUnlockedReadsAnySlotNotOneNominatedLeaf() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)

        // Each leaf alone is sufficient — mimicking a `.plain` domain (no identity key) and a
        // non-authenticating backend (no token).
        for surviving in ["kek", "identity", "token"] {
            try store.evictUnwrappedSlots(for: domainA)
            XCTAssertFalse(store.isUnlocked(domain: domainA), "no slots ⇒ locked")

            switch surviving {
            case "kek":
                try CryptoKeychain.storeUnwrappedFileKeysKEK(Data(repeating: 1, count: 32),
                                                             for: domainA)
            case "identity":
                try CryptoKeychain.storeUnwrappedUserIdentityKey(Data("der".utf8), for: domainA)
            default:
                try CryptoKeychain.storeUnwrappedRefreshToken("t", for: domainA)
            }
            XCTAssertTrue(store.isUnlocked(domain: domainA),
                          "\(surviving) alone must read as unlocked")
        }
    }

    // 3. `unlock` populates the unwrapped slots and leaves no resident key material.
    func testUnlockPopulatesSlotsAndHoldsNoResidentKey() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)
        try store.evictUnwrappedSlots(for: domainA)
        XCTAssertFalse(store.isUnlocked(domain: domainA))

        try await store.unlock(domain: domainA)

        XCTAssertNotNil(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA))
        XCTAssertNotNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainA))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA), "token-A")

        // I3/I4: the store is stateless with respect to key material — there is no property that
        // could hold a domainKey or a refreshTokenKey between operations. Locking is therefore
        // purely a matter of the slots, which is what `isUnlocked` reads.
        XCTAssertTrue(store.isUnlocked(domain: domainA))
        try store.evictUnwrappedSlots(for: domainA)
        XCTAssertFalse(store.isUnlocked(domain: domainA))
    }

    // 4. Per-domain eviction removes only that domain's slots.
    func testEvictOneDomainLeavesTheOtherIntact() async throws {
        try await provision(domainA)
        try await provision(domainB)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)
        try store.commitRefreshToken("token-B", for: domainB, establishing: true)

        try store.evictUnwrappedSlots(for: domainA)

        XCTAssertNil(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA))

        XCTAssertNotNil(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainB))
        XCTAssertNotNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainB))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainB), "token-B")
    }

    // 5. Global eviction removes every unwrapped slot, leaves every wrapped one.
    func testGlobalEvictionLeavesWrappedMaterial() async throws {
        try await provision(domainA)
        try await provision(domainB)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)
        try store.commitRefreshToken("token-B", for: domainB, establishing: true)

        try store.evictUnwrappedSlots()

        XCTAssertFalse(store.isUnlocked(domain: domainA))
        XCTAssertFalse(store.isUnlocked(domain: domainB))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainB))
        XCTAssertNotNil(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        XCTAssertNotNil(try CryptoKeychain.loadWrappedDomainKey(for: domainB))
        XCTAssertNotNil(try CryptoKeychain.loadWrappedRefreshToken(for: domainA))

        // Everything reopens without re-provisioning.
        try await store.unlock(domain: domainA)
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA), "token-A")
    }

    // 6. A corrupt sealed token is dropped, never re-minted — a token is not regenerable.
    func testCorruptRefreshTokenIsDroppedNotMinted() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)
        try CryptoKeychain.storeWrappedRefreshToken(Data(repeating: 0xAB, count: 120),
                                                    for: domainA)
        try store.evictUnwrappedSlots(for: domainA)

        try await store.unlock(domain: domainA)

        XCTAssertNil(try CryptoKeychain.loadWrappedRefreshToken(for: domainA),
                     "the unopenable blob must be dropped")
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA),
                     "no token may be minted in its place")
        // The rest of the unlock still succeeded: one bad leaf does not fail the domain.
        XCTAssertNotNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainA))
    }

    // 7. `forgetDomain` removes all of a domain's slots; a sibling keeps its own set.
    //    Replaces the deleted deprovision refcount: isolation is structural, so no survey of
    //    sibling domains belongs on the delete path.
    func testForgetDomainLeavesSiblingFullyIntact() async throws {
        try await provision(domainA)
        try await provision(domainB)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)
        try store.commitRefreshToken("token-B", for: domainB, establishing: true)

        try store.forgetDomain(domainA)

        XCTAssertNil(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadWrappedFileKeysKEK(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadWrappedRefreshTokenKey(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadRefreshTokenKeyPublic(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadWrappedRefreshToken(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA))

        XCTAssertNotNil(try CryptoKeychain.loadWrappedDomainKey(for: domainB))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainB), "token-B")
    }

    // 8. Two domains hold different tokens: committing to A does not change what B reads.
    func testTokensAreIsolatedPerDomain() async throws {
        try await provision(domainA)
        try await provision(domainB)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)
        try store.commitRefreshToken("token-B", for: domainB, establishing: true)

        try store.commitRefreshToken("token-A-rotated", for: domainA)

        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA),
                       "token-A-rotated")
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainB), "token-B",
                       "two domains cannot address the same slot")
    }

    // 9. `commitRefreshToken` works with no unlocked state — the guarantee.
    func testCommitRefreshTokenNeedsNoUnlockedState() async throws {
        try await provision(domainA)
        try store.evictUnwrappedSlots(for: domainA)
        XCTAssertFalse(store.isUnlocked(domain: domainA))

        // Sealing uses only `refreshTokenKey.pub`, which stays in the clear. This is what lets
        // the Provider rotate a token while the vault is locked.
        try store.commitRefreshToken("rotated-while-locked", for: domainA)

        XCTAssertNotNil(try CryptoKeychain.loadWrappedRefreshToken(for: domainA))
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA),
                     "a locked domain must not gain a readable token: the rotation is sealed and "
                     + "waits for the next unlock")
    }

    /// `establishing` must not be a back door: it is the provisioning commit, and a rotation
    /// arriving after lock has swept the slot cannot use it to resurrect a readable credential.
    ///
    /// The gate is the token's **own** slot rather than ``VaultKeyStore/isUnlocked(domain:)``,
    /// which reads `fileKeysKEK.unwrapped` — an encryption-subsystem slot a `.plain` domain has no
    /// business depending on.
    func testRotationCannotRecreateASweptPlaintextSlot() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-N", for: domainA, establishing: true)
        try store.evictUnwrappedSlots(for: domainA)

        try store.commitRefreshToken("token-N+1", for: domainA)

        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA),
                     "a rotation must never re-create the slot the lock deleted")
        XCTAssertNotNil(try CryptoKeychain.loadWrappedRefreshToken(for: domainA),
                        "the sealed slot still takes every rotation")
    }

    /// The plaintext slot is refreshed in the same operation whenever the domain **is** open, so
    /// the two slots cannot diverge while the Provider can read them.
    func testCommitRefreshTokenWritesBothSlotsWhileUnlocked() async throws {
        try await provision(domainA)
        XCTAssertTrue(store.isUnlocked(domain: domainA))

        try store.commitRefreshToken("rotated-while-open", for: domainA, establishing: true)

        XCTAssertNotNil(try CryptoKeychain.loadWrappedRefreshToken(for: domainA))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA),
                       "rotated-while-open")
    }

    // 10. Rotation across a lock: seal N+1 while locked → unlock → the restored token is N+1.
    func testRotationAcrossLockRestoresTheNewestToken() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-N", for: domainA, establishing: true)
        try store.evictUnwrappedSlots(for: domainA)

        // Seals only — the domain is locked, so no plaintext slot is created.
        try store.commitRefreshToken("token-N+1", for: domainA)
        XCTAssertNil(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA))

        try await store.unlock(domain: domainA)

        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA), "token-N+1",
                       "unlock must find the newest token, not a long-dead one")
    }

    // 11. `rotateDomainKey` re-wraps all three leaves; the old `domainKey` opens none of them.
    func testRotateDomainKeyReWrapsEveryLeaf() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)

        let oldIdentity = try XCTUnwrap(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainA))
        let oldKEK = try XCTUnwrap(try CryptoKeychain.loadWrappedFileKeysKEK(for: domainA))
        let oldTokenKey = try XCTUnwrap(try CryptoKeychain.loadWrappedRefreshTokenKey(for: domainA))
        let oldWrapper = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainA))

        try await store.rotateDomainKey(for: domainA)

        XCTAssertNotEqual(try CryptoKeychain.loadWrappedUserIdentityKey(for: domainA), oldIdentity)
        XCTAssertNotEqual(try CryptoKeychain.loadWrappedFileKeysKEK(for: domainA), oldKEK)
        XCTAssertNotEqual(try CryptoKeychain.loadWrappedRefreshTokenKey(for: domainA), oldTokenKey)
        XCTAssertNotEqual(try CryptoKeychain.loadWrappedDomainKey(for: domainA), oldWrapper)

        // Every leaf still opens under the *new* key, and the token survives the re-key.
        try store.evictUnwrappedSlots(for: domainA)
        try await store.unlock(domain: domainA)
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA),
                       Data("der-\(domainA)".utf8))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA), "token-A")
    }

    // 12. Install-wide `setGating`: switching re-seals **every** domain, and all still open.
    func testSetGatingReSealsEveryDomain() async throws {
        try await provision(domainA, gating: .none)
        try await provision(domainB, gating: .none)
        let aWrapper = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        let bWrapper = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainB))

        try await store.setGating(.secure)

        XCTAssertEqual(store.gating(), .secure)
        XCTAssertNotEqual(try CryptoKeychain.loadWrappedDomainKey(for: domainA), aWrapper,
                          "A must be re-sealed to the new method")
        XCTAssertNotEqual(try CryptoKeychain.loadWrappedDomainKey(for: domainB), bWrapper,
                          "B must be re-sealed too — gating is install-wide")

        try store.evictUnwrappedSlots()
        try await store.unlock(domain: domainA)
        try await store.unlock(domain: domainB)
        XCTAssertTrue(store.isUnlocked(domain: domainA))
        XCTAssertTrue(store.isUnlocked(domain: domainB))
    }

    /// **I5′.** `.secure` mints its gating keypair **per domain**, so a gating key captured
    /// during one vault's unlock opens that vault alone.
    func testSecureGatingKeypairIsPerDomain() async throws {
        try await provision(domainA, gating: .secure)
        try await provision(domainB, gating: .secure)

        let aPub = try XCTUnwrap(try CryptoKeychain.loadGatingPublicKey(.secure, domain: domainA))
        let bPub = try XCTUnwrap(try CryptoKeychain.loadGatingPublicKey(.secure, domain: domainB))
        XCTAssertNotEqual(aPub, bPub, "each `.secure` domain gets its own gating keypair")

        let aParams = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.secure, domain: domainA))
        let bParams = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.secure, domain: domainB))
        XCTAssertNotEqual(aParams, bParams, "and its own ephemeral")
    }

    /// **I5′.** The shared three mint **one** keypair for the whole install.
    func testSharedGatingKeypairIsInstallWide() async throws {
        try await provision(domainA, gating: .none)
        try await provision(domainB, gating: .none)

        let aPub = try CryptoKeychain.loadGatingPublicKey(.none, domain: domainA)
        let bPub = try CryptoKeychain.loadGatingPublicKey(.none, domain: domainB)
        XCTAssertNotNil(aPub)
        XCTAssertEqual(aPub, bPub, "`.none` resolves to one install-wide keypair")
    }

    /// Each domain keeps its **own** `domainKey` under one shared ceremony — I5′'s second half.
    func testEachDomainKeyRemainsDistinct() async throws {
        try await provision(domainA, gating: .none)
        try await provision(domainB, gating: .none)

        let aBox = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        let bBox = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainB))
        XCTAssertNotEqual(aBox, bBox)

        // The leaves prove it: each opens to its own DER.
        try store.evictUnwrappedSlots()
        try await store.unlock(domain: domainA)
        try await store.unlock(domain: domainB)
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA),
                       Data("der-\(domainA)".utf8))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainB),
                       Data("der-\(domainB)".utf8))
    }

    /// Every Layer-2 seal carries a **fresh** ECIES ephemeral, so no two domain boxes share one.
    func testEachSealCarriesAFreshEphemeral() async throws {
        try await provision(domainA, gating: .none)
        try await provision(domainB, gating: .none)

        let aBox = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainA))
        let bBox = try XCTUnwrap(try CryptoKeychain.loadWrappedDomainKey(for: domainB))
        // An x9.63 P-256 public key is the first 65 bytes of the box.
        XCTAssertNotEqual(aBox.prefix(65), bBox.prefix(65))
    }

    /// Re-gating preserves every `domainKey`, so no leaf is orphaned.
    func testSetGatingPreservesTheDomainKey() async throws {
        try await provision(domainA)
        try store.commitRefreshToken("token-A", for: domainA, establishing: true)

        try await store.setGating(.secure)
        try store.evictUnwrappedSlots(for: domainA)
        try await store.unlock(domain: domainA)

        XCTAssertEqual(try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: domainA),
                       Data("der-\(domainA)".utf8),
                       "re-gating must re-seal the same domainKey, never mint a new one")
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainA), "token-A")
    }

    /// Every rewrite of the `.secure` keypair mints a **fresh** ephemeral. Reusing one
    /// reproduces the identical ceremony key, so an attacker holding the old one opens the new
    /// wrapper — the same discipline as never reusing a nonce.
    func testSecureReGatingMintsAFreshEphemeral() async throws {
        try await provision(domainA, gating: .secure)
        let first = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.secure, domain: domainA))

        try await store.setGating(.none)
        try await store.setGating(.secure)
        let second = try XCTUnwrap(try CryptoKeychain.loadGatingParams(.secure, domain: domainA))

        XCTAssertNotEqual(first, second, "a rewritten keypair must use a fresh ephemeral")
        try store.evictUnwrappedSlots(for: domainA)
        try await store.unlock(domain: domainA)
        XCTAssertTrue(store.isUnlocked(domain: domainA))
    }

    // 13. Crash-window reconciliation: the superseded triple goes, the active one stays.
    func testReconcileDropsTheSupersededTriple() async throws {
        try await provision(domainA, gating: .secure)
        try await provision(domainB, gating: .secure)

        try await store.setGating(.none)
        store.reconcile(domain: domainA)

        XCTAssertNil(try CryptoKeychain.loadGatingParams(.secure, domain: domainA),
                     "the superseded `.secure` triple is deleted for every domain")
        XCTAssertNil(try CryptoKeychain.loadGatingParams(.secure, domain: domainB))
        XCTAssertNotNil(try CryptoKeychain.loadGatingPublicKey(.none, domain: domainA),
                        "the active method's keypair survives")

        try store.evictUnwrappedSlots()
        try await store.unlock(domain: domainA)
        try await store.unlock(domain: domainB)
        XCTAssertTrue(store.isUnlocked(domain: domainA), "both still open under `.none`")
        XCTAssertTrue(store.isUnlocked(domain: domainB))
    }

    /// A domain can be added while the vault is **locked**, under every method, with no ceremony.
    ///
    /// The headline property of install-wide gating: sealing needs only `<m>.pub`, which is readable at any
    /// time. Counted through the enclave seam for `.secure`, the one method with a countable gate.
    func testAddDomainWhileLockedNeedsNoCeremony() async throws {
        for method in SharedConfig.VaultGating.allCases where method != .pin {
            let counting = CountingSecureEnclaveGate()
            let box = VaultKeyStore.GatingBox()
            box.set(method)
            let deviceKey = VaultKeyStore.DeviceKeyBox()
            let biometricKey = VaultKeyStore.DeviceKeyBox()
            let locked = VaultKeyStore(gate: VaultKeyStore.StubBiometricGate(),
                                       secureGate: counting,
                                       readGating: { box.value },
                                       writeGating: { box.set($0) },
                                       isConfiguredDomain: { box.contains($0) },
                                       allDomainIdentifiers: { box.all },
                                       readDeviceGatingKey: { deviceKey.value },
                                       writeDeviceGatingKey: { deviceKey.value = $0 },
                                       deleteDeviceGatingKey: { deviceKey.value = nil },
                                       readBiometricGatingKey: { _ in biometricKey.value },
                                       writeBiometricGatingKey: { raw, _ in biometricKey.value = raw },
                                       deleteBiometricGatingKey: { biometricKey.value = nil })
            let domain = "locked-add-\(method.rawValue)"
            addTeardownBlock {
                try? locked.forgetDomain(domain)
                CryptoKeychain.deleteGatingTriple(method,
                                                  domain: CryptoKeychain.gatingSharedAccount)
            }

            box.register(domain)
            // The vault is locked: no unlock has run, so no ceremony key is resident.
            try await locked.provisionDomain(userIdentityKeyDER: Data("der".utf8), for: domain)

            XCTAssertNotNil(try CryptoKeychain.loadWrappedDomainKey(for: domain),
                            "\(method.rawValue): the domain must be sealed while locked")
            XCTAssertEqual(counting.enclaveAccessCount, 0,
                           "\(method.rawValue): adding a domain must raise no prompt")
        }
    }

    /// **Asymmetry.** `.secure` enrollment is promptless; unlock prompts.
    ///
    /// This is the property that makes `.secure` work at all: enrollment agrees against the
    /// enclave's *public* key, which needs no enclave access, while unlock needs the private half
    /// and therefore Touch ID. It is the same write-silent/read-gated behaviour `SecItemAdd`
    /// gives an ACL'd item, obtained a stronger way.
    ///
    /// Counted through the gate seam rather than against a real enclave, so it runs anywhere —
    /// a genuine prompt cannot be asserted in an unattended suite.
    func testSecureEnrollmentIsPromptlessButUnlockPrompts() async throws {
        let counting = CountingSecureEnclaveGate()
        let box = VaultKeyStore.GatingBox()
        box.set(.secure)
        let deviceKey = VaultKeyStore.DeviceKeyBox()
        let biometricKey = VaultKeyStore.DeviceKeyBox()
        let counted = VaultKeyStore(gate: VaultKeyStore.StubBiometricGate(),
                                    secureGate: counting,
                                    readGating: { box.value },
                                    writeGating: { box.set($0) },
                                    isConfiguredDomain: { box.contains($0) },
                                    allDomainIdentifiers: { box.all },
                                    readDeviceGatingKey: { deviceKey.value },
                                    writeDeviceGatingKey: { deviceKey.value = $0 },
                                    deleteDeviceGatingKey: { deviceKey.value = nil },
                                    readBiometricGatingKey: { _ in biometricKey.value },
                                    writeBiometricGatingKey: { raw, _ in biometricKey.value = raw },
                                    deleteBiometricGatingKey: { biometricKey.value = nil })
        addTeardownBlock { try? counted.forgetDomain(self.domainA) }

        box.register(domainA)
        try await counted.provisionDomain(userIdentityKeyDER: Data("der".utf8), for: domainA)

        XCTAssertEqual(counting.enclaveAccessCount, 0,
                       "enrollment must not touch the enclave private key — no prompt")
        XCTAssertEqual(counting.enrollCount, 1)

        try counted.evictUnwrappedSlots(for: domainA)
        try await counted.unlock(domain: domainA)

        XCTAssertEqual(counting.enclaveAccessCount, 1,
                       "unlock must reach the enclave private key — this is the prompt")
    }

    /// A missing wrapper orphans **exactly its own domain** — the dissolution of the old
    /// install-wide orphan guard, which blocked every vault when one root went missing.
    func testMissingWrapperOrphansOnlyItsOwnDomain() async throws {
        try await provision(domainA)
        try await provision(domainB)
        try CryptoKeychain.deleteWrappedDomainKey(for: domainA)

        XCTAssertEqual(try store.readiness(for: domainA), .orphaned)
        XCTAssertEqual(try store.readiness(for: domainB), .ready)
    }
}

/// A ``SecureEnclaveGate`` that counts which half of the keypair each operation reaches.
///
/// Enrollment uses only the public key; agreement uses the private one. Counting them apart is
/// how the promptless/prompting asymmetry is asserted without a real enclave or a live prompt.
private final class CountingSecureEnclaveGate: SecureEnclaveGate, @unchecked Sendable {
    private let priv = P256.KeyAgreement.PrivateKey()
    private(set) var enrollCount = 0
    /// Incremented only where a real enclave would raise a Touch ID prompt.
    private(set) var enclaveAccessCount = 0

    var isAvailable: Bool { true }

    func enrollEphemeral() throws -> SecureEnclaveEnrollment {
        enrollCount += 1
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: priv.publicKey)
        return SecureEnclaveEnrollment(ephemeralPublicKey: eph.publicKey.x963Representation,
                                       sharedSecret: shared.withUnsafeBytes { Data($0) })
    }

    func agree(withEphemeralPublicKey ephemeralPublicKey: Data,
               reason: String, context: AnyObject?) throws -> Data {
        enclaveAccessCount += 1
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
    }
}
