/// Unit tests for the PIN gating key derivation (tasks 41, 47).
///
/// Storage is injected, so these run entirely in memory — no keychain, no App Group container.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import CryptoKit
import XCTest
@testable import Common

final class PINGateTests: XCTestCase {

    /// Low iteration count: these tests exercise the construction, not the work factor.
    private func makeGate() -> (PINGate, () -> PINRecord?) {
        var stored: PINRecord?
        let gate = PINGate(load: { stored }, save: { stored = $0 }, iterations: 1_000)
        return (gate, { stored })
    }

    // MARK: - Policy

    func testPolicyAcceptsFourToTwentyDigits() {
        XCTAssertTrue(PINPolicy.isValid("1234"))
        XCTAssertTrue(PINPolicy.isValid("12345678"))
        XCTAssertTrue(PINPolicy.isValid(String(repeating: "1", count: PINPolicy.maxLength)))
    }

    func testPolicyRejectsOutOfRangeAndNonNumeric() {
        XCTAssertEqual(PINPolicy.validate(""), .empty)
        XCTAssertEqual(PINPolicy.validate("12a4"), .nonNumeric)
        XCTAssertEqual(PINPolicy.validate("123"), .tooShort)
        XCTAssertEqual(PINPolicy.validate(String(repeating: "1", count: PINPolicy.maxLength + 1)),
                       .tooLong)
    }

    /// The bounds themselves, so a future widening cannot silently drop the lower bound or let
    /// the upper one drift away from what the Security screen's field allows.
    func testPolicyBounds() {
        XCTAssertEqual(PINPolicy.minLength, 4)
        XCTAssertEqual(PINPolicy.maxLength, 20)
    }

    // MARK: - Enrollment and round-trip

    func testSetPINStoresRecordWithoutThePIN() throws {
        let (gate, stored) = makeGate()
        try gate.setPIN("2468")

        let record = try XCTUnwrap(stored())
        // The PIN must not be recoverable from anything persisted.
        let pinBytes = Data("2468".utf8)
        XCTAssertFalse(record.salt.contains(pinBytes))
        XCTAssertFalse(record.verifier.contains(pinBytes))
    }

    /// The gating key is re-derived, not stored: enrolling and later unlocking with the same PIN
    /// must produce the identical key, or the VMK wrapper written at enrollment cannot be opened.
    func testCorrectPINRederivesTheSameGatingKey() throws {
        let (gate, _) = makeGate()
        let enrolled = try gate.setPIN("13579")

        let recovered = try gate.deriveGatingKey(with: "13579")
        XCTAssertEqual(recovered.withUnsafeBytes { Data($0) },
                       enrolled.withUnsafeBytes { Data($0) })
    }

    func testWrongPINIsRejected() throws {
        let (gate, _) = makeGate()
        try gate.setPIN("1234")

        XCTAssertFalse(try gate.verify("4321"))
        XCTAssertThrowsError(try gate.deriveGatingKey(with: "4321")) { error in
            XCTAssertEqual(error as? PINGateError, .incorrectPIN)
        }
    }

    func testInvalidPINIsNotEnrolled() {
        let (gate, stored) = makeGate()
        XCTAssertThrowsError(try gate.setPIN("12")) { error in
            XCTAssertEqual(error as? PINGateError, .invalidPIN(.tooShort))
        }
        XCTAssertNil(stored())
    }

    func testUnwrapWithoutEnrollmentThrows() {
        let (gate, _) = makeGate()
        XCTAssertThrowsError(try gate.deriveGatingKey(with: "1234")) { error in
            XCTAssertEqual(error as? PINGateError, .notEnrolled)
        }
    }

    func testClearPINRemovesTheRecord() throws {
        let (gate, stored) = makeGate()
        try gate.setPIN("1234")
        XCTAssertTrue(gate.isEnrolled)

        try gate.clearPIN()
        XCTAssertNil(stored())
        XCTAssertFalse(gate.isEnrolled)
    }

    /// A PIN change re-salts, so the old PIN stops deriving anything and the new one derives the
    /// key the caller re-wraps the (unchanged) VMK under.
    func testChangingThePINInvalidatesTheOldOne() throws {
        let (gate, _) = makeGate()
        try gate.setPIN("1111")
        let changed = try gate.setPIN("2222")

        XCTAssertEqual(try gate.deriveGatingKey(with: "2222").withUnsafeBytes { Data($0) },
                       changed.withUnsafeBytes { Data($0) })
        XCTAssertThrowsError(try gate.deriveGatingKey(with: "1111"))
    }

    // MARK: - Backoff

    func testFailedAttemptsEscalateTheDelayAndSuccessResets() throws {
        let (gate, _) = makeGate()
        try gate.setPIN("1234")
        XCTAssertEqual(gate.throttle.currentDelay, 0)

        for _ in 0..<4 { _ = try? gate.deriveGatingKey(with: "0000") }
        XCTAssertEqual(gate.throttle.failures, 4)
        XCTAssertGreaterThan(gate.throttle.currentDelay, 0)

        _ = try gate.deriveGatingKey(with: "1234")
        XCTAssertEqual(gate.throttle.failures, 0)
        XCTAssertEqual(gate.throttle.currentDelay, 0)
    }

    /// Backoff only — the delay saturates rather than becoming a lockout.
    func testDelaySaturatesAndNeverLocksOut() throws {
        let (gate, _) = makeGate()
        try gate.setPIN("1234")
        for _ in 0..<50 { _ = try? gate.deriveGatingKey(with: "0000") }

        XCTAssertLessThanOrEqual(gate.throttle.currentDelay, 60)
        // The correct PIN still works, however many failures preceded it.
        XCTAssertNoThrow(try gate.deriveGatingKey(with: "1234"))
    }

    // MARK: - Derivation

    func testDerivationIsDeterministicAndSaltDependent() {
        let saltA = Data(repeating: 1, count: 32)
        let saltB = Data(repeating: 2, count: 32)
        let a1 = PINGate.deriveKey(pin: "1234", salt: saltA, iterations: 1_000)
        let a2 = PINGate.deriveKey(pin: "1234", salt: saltA, iterations: 1_000)
        let b = PINGate.deriveKey(pin: "1234", salt: saltB, iterations: 1_000)

        XCTAssertEqual(a1.withUnsafeBytes { Data($0) }, a2.withUnsafeBytes { Data($0) })
        XCTAssertNotEqual(a1.withUnsafeBytes { Data($0) }, b.withUnsafeBytes { Data($0) })
    }

    func testConstantTimeEqualsMatchesValueEquality() {
        XCTAssertTrue(PINGate.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(PINGate.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(PINGate.constantTimeEquals(Data([1, 2]), Data([1, 2, 3])))
    }
}
