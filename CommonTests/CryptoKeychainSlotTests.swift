/// Unit tests for `CryptoKeychainSlot`.
//
//  CryptoKeychainSlotTests.swift
//  CommonTests
//
//  Pins which keychain slot the decrypt path reads. There is no raw session slot: the
//  private DER exists only wrapped under the VMK, plus the `unwrapped` slot that unlock
//  populates. Reading anything but that slot would resurrect the regime where key material was
//  readable with no gating at all.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

final class CryptoKeychainSlotTests: KeychainIsolatedTestCase {

    private var domainID: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        domainID = UUID().uuidString
    }

    override func tearDownWithError() throws {
        try? CryptoKeychain.deleteUnwrappedUserIdentityKey(for: domainID)
        try? CryptoKeychain.deleteWrappedUserIdentityKey(for: domainID)
        try super.tearDownWithError()
    }

    /// A freshly generated RSA private key in DER form.
    private func makeKeyDER() throws -> Data {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard let der = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return der
    }

    /// Unlocked: the unwrapped slot is the one and only source for the decrypt path.
    func testUnwrappedSlotReadable() throws {
        let der = try makeKeyDER()
        try CryptoKeychain.storeUnwrappedUserIdentityKey(der, for: domainID)

        XCTAssertNotNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: domainID))
    }

    /// Locked: the unwrapped slot is evicted and the wrapped blob is not readable without the
    /// VMK, so `nil` is the correct — and only — answer.
    func testLockedVaultYieldsNil() throws {
        try CryptoKeychain.storeWrappedUserIdentityKey(Data(repeating: 7, count: 64), for: domainID)
        try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: domainID)

        XCTAssertNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: domainID),
                     "a locked vault must not resolve a key")
    }

    /// The wrapped blob alone never satisfies the decrypt path — the regression guard at the
    /// slot level: no fallback may read key material that the active gating has not released.
    func testWrappedBlobIsNotAFallback() throws {
        let der = try makeKeyDER()
        try CryptoKeychain.storeWrappedUserIdentityKey(der, for: domainID)   // even if it were plain
        try CryptoKeychain.deleteUnwrappedUserIdentityKey(for: domainID)

        XCTAssertNil(try CryptoKeychain.loadUserIdentityPrivateKey(for: domainID),
                     "the wrapped slot must never be read as a fallback")
    }
}
