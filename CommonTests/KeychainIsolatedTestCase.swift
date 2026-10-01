/// Base XCTestCase isolating keychain items per test.
//
//  KeychainIsolatedTestCase.swift
//  CommonTests
//
//  Base class for suites that write real App Group keychain slots.
//
//  Inherits `ConfigIsolatedTestCase`, so a keychain-isolated suite is config-isolated too. The
//  two always travel together: the vault slots a suite writes are only meaningful alongside the
//  configuration naming the domains they belong to, and `VaultKeyStore.reconcile()` reads
//  `SharedConfig.vaultGating` to decide which gating keys to delete. Isolating one without the
//  other leaves a suite writing test state into the developer's live `config.json`.
//
//  `VaultKeyStore.isolatedForTesting()` isolates only the Vault Master Key, which it holds in
//  memory. Every slot it then writes — the wrapped/unwrapped identity key, the file-keys KEK,
//  the public key and the user ID — still lands on the production service names, because
//  `CryptoKeychain.serviceNamespace` is process-wide static state that defaults to
//  `.production`. A suite that provisions a domain therefore writes the developer's live
//  keychain unless it moves those names aside first.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

/// Installs a per-run ``CryptoKeychain/ServiceNamespace`` for the lifetime of each test, and
/// restores whatever was in force afterwards.
///
/// Restoration matters as much as installation: the namespace is static, so a suite that left an
/// isolated one behind would silently redirect every suite that ran after it in the same process
/// — including ones asserting against production slots.
class KeychainIsolatedTestCase: ConfigIsolatedTestCase {

    /// The namespace is installed once per suite, in `setUp`'s class-level counterpart, rather
    /// than per test.
    ///
    /// Suites here hold their ``VaultKeyStore`` in a `static let`, which is initialised lazily on
    /// first use and seeds a VMK wrapper into whatever namespace is current at that moment. A
    /// fresh namespace per test would strand that wrapper in the first test's namespace and leave
    /// every later test reading an empty slot — a locked store.
    private static var previousNamespace: CryptoKeychain.ServiceNamespace?

    override class func setUp() {
        super.setUp()
        previousNamespace = CryptoKeychain.installTestNamespace()
    }

    override class func tearDown() {
        // Restore what was in force rather than assuming `.production`: the namespace is static,
        // so hard-coding the default would clobber an enclosing suite's isolation.
        if let previousNamespace { CryptoKeychain.restoreNamespace(previousNamespace) }
        previousNamespace = nil
        super.tearDown()
    }
}
