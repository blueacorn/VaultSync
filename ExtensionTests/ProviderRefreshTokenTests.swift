/// Unit tests for `ProviderRefreshToken`.
//
//  ProviderRefreshTokenTests.swift
//  ExtensionTests
//
//  The Provider's side of the wrapped refresh token.
//
//  These need the App Group keychain (the token slots are real keychain items), so they live
//  here rather than in CommonTests, which has no host application.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CryptoKit
import FileProvider
@testable import Common
@testable import Extension

/// The Provider's read and rotate paths over a provisioned domain's sealed token slots.
///
/// Provisioning writes real keychain items on the current ``CryptoKeychain/serviceNamespace``;
/// ``KeychainIsolatedTestCase`` moves that namespace — and `config.json` — aside so nothing here
/// touches the developer's live vault.
final class ProviderRefreshTokenTests: KeychainIsolatedTestCase {

    /// An isolated store keeps gating deterministic and leaves the user's real gating setting
    /// untouched; the slots below it are genuine keychain items, so the sealing under test is
    /// really exercised.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()

    private let domainID = "com.test.providertoken-\(UUID().uuidString)"

    override func tearDownWithError() throws {
        try? Self.testKeyStore.forgetDomain(domainID)
        try super.tearDownWithError()
    }

    /// Provision the domain's key material (`fileKeysKEK`, `refreshTokenKey`) with `.none`
    /// gating, leaving it unlocked.
    private func provision() async throws {
        try await Self.testKeyStore.provisionDomain(userIdentityKeyDER: nil, for: domainID)
    }

    // MARK: - Test 18 — read comes only from the unwrapped slot

    /// The Provider's read path is ``VaultRefreshTokenStore/read(domainIdentifier:)``, which
    /// consults `refreshToken.unwrapped` and nothing else. Evicting that slot leaves the sealed
    /// blob intact, so the credential is not lost — only unreadable until unlock.
    func testProviderReadsOnlyTheUnwrappedSlot() async throws {
        try await provision()
        let store = VaultRefreshTokenStore(keyStore: Self.testKeyStore)

        try store.store("token-N", domainIdentifier: domainID, establishing: true)
        XCTAssertEqual(try store.read(domainIdentifier: domainID), "token-N")

        // Lock: evict the Provider-readable slots, keeping every wrapped one.
        try Self.testKeyStore.evictUnwrappedSlots(for: domainID)

        XCTAssertNil(try store.read(domainIdentifier: domainID),
                     "the Provider must not fall back to the sealed slot it cannot open")
        XCTAssertTrue(store.hasSealedToken(domainIdentifier: domainID),
                      "the sealed token survives the lock — this is `vaultLocked`, not `notAuthenticated`")
    }

    /// A locked vault must reach the OS as **one** signal whichever slot is missing: an absent
    /// `refreshToken.unwrapped` (surfacing as ``AuthError/vaultLocked``) and an absent
    /// `fileKeysKEK` (surfacing as ``VaultKeyStoreError/locked``) both map to
    /// ``NSFileProviderError/notAuthenticated``.
    func testLockedTokenAndLockedFileKeysKEKProduceTheSameProviderError() async throws {
        try await provision()
        let store = VaultRefreshTokenStore(keyStore: Self.testKeyStore)
        try store.store("token-N", domainIdentifier: domainID, establishing: true)
        try Self.testKeyStore.evictUnwrappedSlots(for: domainID)

        // What an absent `fileKeysKEK` produces (BC01HeaderCache's key provider).
        XCTAssertNil(try CryptoKeychain.loadUnwrappedFileKeysKEK(for: domainID))
        let kekError = VaultKeyStoreError.locked.toPresentableError()

        // What an absent `refreshToken.unwrapped` beside a sealed blob produces.
        XCTAssertNil(try store.read(domainIdentifier: domainID))
        XCTAssertTrue(store.hasSealedToken(domainIdentifier: domainID))
        let tokenError = AuthError.vaultLocked.toPresentableError()

        XCTAssertEqual(tokenError.domain, kekError.domain)
        XCTAssertEqual(tokenError.code, kekError.code)
        XCTAssertEqual(tokenError.domain, NSFileProviderErrorDomain)
        XCTAssertEqual(tokenError.code, NSFileProviderError.notAuthenticated.rawValue)
    }

    // MARK: - Test 19 — rotation writes both slots

    /// Rotation from the Provider goes through the one writer that owns both slots, so they can
    /// never diverge: the wrapped blob changes on every commit and the unwrapped slot reads back
    /// the new token.
    func testProviderRotationUpdatesBothSlots() async throws {
        try await provision()
        let store = VaultRefreshTokenStore(keyStore: Self.testKeyStore)

        try store.store("token-N", domainIdentifier: domainID, establishing: true)
        let sealedN = try XCTUnwrap(try CryptoKeychain.loadWrappedRefreshToken(for: domainID))
        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainID), "token-N")

        try store.store("token-N+1", domainIdentifier: domainID, establishing: false)
        let sealedNPlus1 = try XCTUnwrap(try CryptoKeychain.loadWrappedRefreshToken(for: domainID))

        XCTAssertEqual(try CryptoKeychain.loadUnwrappedRefreshToken(for: domainID), "token-N+1",
                       "the unwrapped slot must carry the rotated token")
        XCTAssertNotEqual(sealedN, sealedNPlus1,
                          "the sealed slot must be rewritten, not left holding a dead token")
        XCTAssertFalse(sealedNPlus1.isEmpty)
    }

    /// The seal-without-unlock guarantee from the Provider's position: sealing needs only `refreshTokenKey.pub`,
    /// so a rotation performed with the vault locked still persists — into the sealed slot alone.
    ///
    /// A Provider still in flight when lock sweeps the slots must not resurrect the plaintext one:
    /// that would hand back a readable credential the user just locked away. Nothing is lost, as
    /// the next unlock opens the sealed blob and finds N+1 rather than a long-dead N.
    func testRotationWhileLockedSealsOnlyAndSurvivesUnlock() async throws {
        try await provision()
        let store = VaultRefreshTokenStore(keyStore: Self.testKeyStore)
        try store.store("token-N", domainIdentifier: domainID, establishing: true)

        try Self.testKeyStore.evictUnwrappedSlots(for: domainID)
        XCTAssertNil(try store.read(domainIdentifier: domainID))

        // No `domainKey` is held; the public half alone is enough to seal.
        try store.store("token-N+1", domainIdentifier: domainID, establishing: false)

        XCTAssertNil(try store.read(domainIdentifier: domainID),
                     "the locked domain must stay unreadable to the Provider")
        let sealed = try XCTUnwrap(try CryptoKeychain.loadWrappedRefreshToken(for: domainID))
        XCTAssertFalse(sealed.isEmpty)

        try await Self.testKeyStore.unlock(domain: domainID)
        XCTAssertEqual(try store.read(domainIdentifier: domainID), "token-N+1",
                       "unlock must restore the rotation that happened while locked")
    }
}
