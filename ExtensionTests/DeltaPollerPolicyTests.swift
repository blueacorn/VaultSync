/// Unit tests for `DeltaPollerPolicy`.
//
//  DeltaPollerPolicyTests.swift
//  ExtensionTests
//
//  Coverage for `DeltaPoller`'s pure policy functions — which completed passes are worth
//  relaying, and which failures are terminal. Expressed as statics so they can be pinned
//  without stubbing the 39-member `ProviderBackend` or standing up a live
//  `NSFileProviderManager`.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
import Common
@testable import Extension

/// Coverage for the delta-completion event: `DeltaPoller` relays a finished pass
/// to whatever background work keys off it. The policy is a pure function so it can be pinned
/// without stubbing the
/// 39-member `ProviderBackend` or a live `NSFileProviderManager`.
final class DeltaPassCompletionReportingTests: XCTestCase {

    private func ident(_ id: String) -> DomainService.ItemIdentifier {
        DomainService.ItemIdentifier(id)
    }

    /// A pass that reconciled changes is reported: it is the only kind that produced newly
    /// indexed rows for a consumer to act on.
    func testChangedPassIsReported() {
        let result = DeltaPollResult(changed: true,
                                     cursorExpired: false,
                                     changedParentIdentifiers: [ident("p")])

        XCTAssertTrue(DeltaPoller.shouldReportPassCompletion(for: result))
    }

    /// Cursor expiry rotates the cache and forces a full re-index, so everything is newly
    /// indexed — report it even though no parents were named.
    func testCursorExpiredPassIsReported() {
        let result = DeltaPollResult(changed: false, cursorExpired: true)

        XCTAssertTrue(DeltaPoller.shouldReportPassCompletion(for: result))
    }

    /// Regression guard: a steady-state no-op pass must NOT be reported. Relaying every 45s
    /// tick would make the event path a second redundant clock on top of the consumer's own,
    /// firing forever against nothing to do.
    func testUnchangedPassIsNotReported() {
        let result = DeltaPollResult(changed: false, cursorExpired: false)

        XCTAssertFalse(DeltaPoller.shouldReportPassCompletion(for: result))
    }
}

/// Coverage for the poll loop's terminal-failure policy.
///
/// A locked vault is not a transient fault: the key material is evicted and no backoff brings it
/// back, so the loop stops rather than retrying every interval for as long as the vault stays
/// locked. Unlocking repopulates the slots and restarts the poller.
final class DeltaPollerVaultLockedStopTests: XCTestCase {

    /// The sealed refresh token cannot be opened.
    func testAuthErrorVaultLockedStopsPolling() {
        XCTAssertTrue(DeltaPoller.isVaultLocked(AuthError.vaultLocked))
    }

    /// An evicted Provider-readable slot — the other shape a lock reaches the loop in.
    func testVaultKeyStoreLockedStopsPolling() {
        XCTAssertTrue(DeltaPoller.isVaultLocked(VaultKeyStoreError.locked))
    }

    /// Regression guard: a transient failure must keep the loop alive with its backoff. Treating
    /// offline as terminal would silently stop syncing until the extension was next relaunched.
    func testTransientFailureDoesNotStopPolling() {
        let offline = NSError(domain: NSURLErrorDomain, code: NSURLErrorNotConnectedToInternet)

        XCTAssertFalse(DeltaPoller.isVaultLocked(offline))
        XCTAssertFalse(DeltaPoller.isVaultLocked(AuthError.notAuthenticated))
        XCTAssertFalse(DeltaPoller.isVaultLocked(VaultKeyStoreError.unwrapFailed))
    }
}
