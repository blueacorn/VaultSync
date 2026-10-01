/// PIN gating key derivation for the vault (tasks 41, 47).
///
/// One of ``SharedConfig/VaultGating``'s three ways of producing the key that wraps the Vault
/// Master Key. This type derives that key and verifies a supplied PIN; it is **not** a custodian
/// of any key material — ``VaultKeyStore`` owns each domain's `domainKey` wrapper, so there is one
/// place that decides what opens the vault.
///
/// ```
/// PIN ──PBKDF2-HMAC-SHA256(salt, iterations)──▶ gating key ──wraps──▶ domainKey[d] (VaultKeyStore)
///                                                │
///                                                ▼
///                                    verifier = HMAC(derived, "fb-pin-v1")
/// ```
///
/// The PIN is never persisted in any form that can be reversed: only the salt, the iteration
/// count and the verifier are stored. The verifier exists so a wrong PIN can be rejected without
/// attempting (and failing) an AES-GCM open, and is compared in constant time.
///
/// A low-entropy secret is only as strong as the cost of guessing it, so this type is
/// deliberately paired with ``PINAttemptThrottle``: failures impose an escalating delay. There is
/// no lockout and no forced re-provision — backoff only.
///
/// Derivation and verification are pure functions over injected storage, so the whole type is
/// unit-testable with no keychain.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import CryptoKit
import Foundation

public enum PINGateError: Error, Equatable {
    /// The supplied PIN did not match the stored verifier.
    case incorrectPIN
    /// No PIN has been enrolled.
    case notEnrolled
    /// The PIN does not satisfy ``PINPolicy``.
    case invalidPIN(PINPolicy.Violation)
    /// The stored record is missing or corrupt.
    case corruptRecord
    /// AES-GCM open failed despite a matching verifier — corrupt `domainKey` wrapper.
    case unwrapFailed
}

/// Validation rules for a user-chosen PIN. Pure, so the UI and the gate agree by construction
/// rather than by duplicated conditionals.
public enum PINPolicy {
    public static let minLength = 4
    public static let maxLength = 20

    public enum Violation: Equatable {
        case empty
        case nonNumeric
        case tooShort
        case tooLong
    }

    /// Validate `pin`, returning the first violation or `nil` when acceptable.
    public static func validate(_ pin: String) -> Violation? {
        if pin.isEmpty { return .empty }
        guard pin.allSatisfy(\.isNumber) else { return .nonNumeric }
        if pin.count < minLength { return .tooShort }
        if pin.count > maxLength { return .tooLong }
        return nil
    }

    /// Whether `pin` is acceptable. Convenience over ``validate(_:)`` for view gating.
    public static func isValid(_ pin: String) -> Bool { validate(pin) == nil }

    /// Human-readable reason for a violation, shown inline under the PIN field.
    public static func message(for violation: Violation) -> String {
        switch violation {
        case .empty:      return "Enter a PIN."
        case .nonNumeric: return "PIN must contain digits only."
        case .tooShort:   return "PIN must be at least \(minLength) digits."
        case .tooLong:    return "PIN must be at most \(maxLength) digits."
        }
    }
}

/// The persisted PIN derivation parameters. Holds no key material and no reversible copy of the
/// PIN itself — the gating key is re-derived from the entered PIN on every unlock.
public struct PINRecord: Codable, Equatable, Sendable {
    public let salt: Data
    public let iterations: Int
    /// `HMAC-SHA256(derivedKey, "fb-pin-v1")` — proves a PIN without revealing it.
    public let verifier: Data

    public init(salt: Data, iterations: Int, verifier: Data) {
        self.salt = salt
        self.iterations = iterations
        self.verifier = verifier
    }
}

/// Escalating delay after failed PIN attempts. In-memory and per-process by design: this
/// frustrates interactive guessing, which is the realistic attack on a 4–8 digit secret.
///
/// Backoff only — never a lockout, and never a forced re-provision.
public final class PINAttemptThrottle: @unchecked Sendable {
    private let lock = NSLock()
    private var failureCount = 0

    /// Delays in seconds indexed by consecutive failure count, saturating at the last entry.
    private static let schedule: [TimeInterval] = [0, 0, 1, 3, 10, 30, 60]

    public init() {}

    /// The delay to impose before the next attempt is allowed.
    public var currentDelay: TimeInterval {
        lock.lock(); defer { lock.unlock() }
        return Self.schedule[min(failureCount, Self.schedule.count - 1)]
    }

    /// Consecutive failures so far.
    public var failures: Int {
        lock.lock(); defer { lock.unlock() }
        return failureCount
    }

    public func recordFailure() {
        lock.lock(); defer { lock.unlock() }
        failureCount += 1
    }

    public func reset() {
        lock.lock(); defer { lock.unlock() }
        failureCount = 0
    }
}

/// Derives the PIN gating key and verifies a supplied PIN.
///
/// Storage is injected (`load` / `save`) so the type carries no keychain dependency and tests can
/// run entirely in memory.
public final class PINGate: @unchecked Sendable {

    /// PBKDF2 work factor. High enough to make offline guessing of a short numeric PIN costly,
    /// low enough to keep the interactive unlock responsive.
    public static let defaultIterations = 310_000
    private static let verifierContext = Data("fb-pin-v1".utf8)

    private let load: () -> PINRecord?
    private let save: (PINRecord?) throws -> Void
    private let iterations: Int

    public let throttle = PINAttemptThrottle()

    public init(load: @escaping () -> PINRecord?,
                save: @escaping (PINRecord?) throws -> Void,
                iterations: Int = PINGate.defaultIterations) {
        self.load = load
        self.save = save
        self.iterations = iterations
    }

    /// Whether a PIN is currently enrolled.
    public var isEnrolled: Bool { load() != nil }

    // MARK: - Derivation (pure)

    /// Derive the PIN key via PBKDF2-HMAC-SHA256.
    ///
    /// Implemented over CryptoKit's HMAC rather than CommonCrypto so `Common` stays free of a
    /// bridging import; the construction is standard PBKDF2 (RFC 8018 §5.2) with dkLen = 32,
    /// which needs exactly one block.
    public static func deriveKey(pin: String, salt: Data, iterations: Int) -> SymmetricKey {
        let password = SymmetricKey(data: Data(pin.utf8))
        var block = Data(salt)
        block.append(contentsOf: [0, 0, 0, 1])                      // INT(1)
        var u = Data(HMAC<SHA256>.authenticationCode(for: block, using: password))
        var result = u
        for _ in 1..<max(iterations, 1) {
            u = Data(HMAC<SHA256>.authenticationCode(for: u, using: password))
            for i in result.indices { result[i] ^= u[i] }
        }
        return SymmetricKey(data: result)
    }

    /// The verifier for a derived key: `HMAC(derived, "fb-pin-v1")`.
    public static func verifier(for derived: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: verifierContext, using: derived))
    }

    // MARK: - Enrollment

    /// Enroll `pin` with a fresh salt and return the gating key it derives.
    ///
    /// Replaces any existing record — a PIN *change* is exactly this call, and because the caller
    /// re-wraps the same `domainKey` under the returned key, no leaf material is touched.
    ///
    /// - Parameter pin: The user-chosen PIN.
    /// - Returns: The derived gating key.
    /// - Throws: ``PINGateError/invalidPIN(_:)`` if the PIN fails ``PINPolicy``.
    @discardableResult
    public func setPIN(_ pin: String) throws -> SymmetricKey {
        if let violation = PINPolicy.validate(pin) { throw PINGateError.invalidPIN(violation) }

        var salt = Data(count: 32)
        salt.withUnsafeMutableBytes { buffer in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return }
            for i in 0..<buffer.count { base[i] = UInt8.random(in: 0...255) }
        }

        let derived = Self.deriveKey(pin: pin, salt: salt, iterations: iterations)
        try save(PINRecord(salt: salt,
                           iterations: iterations,
                           verifier: Self.verifier(for: derived)))
        throttle.reset()
        return derived
    }

    /// Remove the enrolled PIN record.
    public func clearPIN() throws {
        try save(nil)
        throttle.reset()
    }

    // MARK: - Verification / derivation

    /// Whether `pin` matches the enrolled record. Constant-time comparison.
    ///
    /// Does not consume a throttle attempt — ``deriveGatingKey(with:)`` is the gating path.
    public func verify(_ pin: String) throws -> Bool {
        guard let record = load() else { throw PINGateError.notEnrolled }
        let derived = Self.deriveKey(pin: pin, salt: record.salt, iterations: record.iterations)
        return Self.constantTimeEquals(Self.verifier(for: derived), record.verifier)
    }

    /// Derive the gating key for a correct `pin`.
    ///
    /// On failure the attempt is recorded and the backoff grows; on success the throttle resets.
    /// Callers must honour ``PINAttemptThrottle/currentDelay`` before retrying.
    ///
    /// - Parameter pin: The entered PIN.
    /// - Returns: The gating key that opens the domain's `domainKey` wrapper.
    public func deriveGatingKey(with pin: String) throws -> SymmetricKey {
        guard let record = load() else { throw PINGateError.notEnrolled }
        let derived = Self.deriveKey(pin: pin, salt: record.salt, iterations: record.iterations)

        guard Self.constantTimeEquals(Self.verifier(for: derived), record.verifier) else {
            throttle.recordFailure()
            throw PINGateError.incorrectPIN
        }
        throttle.reset()
        return derived
    }

    /// Compare two byte strings without an early exit on the first differing byte.
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for (l, r) in zip(lhs, rhs) { diff |= l ^ r }
        return diff == 0
    }
}
