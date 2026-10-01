/// Lifetime of the presence capability shared by the Security gate and the settings form.
///
/// ``SecurityFlow`` exists for exactly one reason: to make "the gating key is forgotten at the end
/// of the operation" true of a capability that deliberately spans two screens. These tests assert
/// that end — that it is lent rather than handed over, and that every way out of the flow destroys
/// it — because a leak here is a live re-key capability sitting in a popover.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
@testable import VaultSync

@MainActor
final class SecurityFlowTests: XCTestCase {

    /// Records what was invalidated, standing in for a real `LAContext`.
    private final class Recorder {
        var invalidated: [ObjectIdentifier] = []
        func invalidate(_ context: AnyObject?) {
            guard let context else { return }
            invalidated.append(ObjectIdentifier(context))
        }
    }

    private func makeFlow() -> (SecurityFlow, Recorder, NSObject) {
        let recorder = Recorder()
        let flow = SecurityFlow(invalidate: { recorder.invalidate($0) })
        return (flow, recorder, NSObject())
    }

    // MARK: - Borrowing

    /// The capability is lent for the duration of a call — that is how the re-key spends it
    /// without a second prompt.
    func testWithPresenceLendsTheAdmittedContext() async {
        let (flow, _, token) = makeFlow()
        flow.admit(context: token)

        let borrowed: AnyObject? = await flow.withPresence { $0 }

        XCTAssertTrue(borrowed === token, "the re-key must receive the gate's own capability")
    }

    /// Under `.pin` there is no context: the gating key is derived from the secret, which is what
    /// the flow carries instead.
    func testPinAdmissionCarriesTheSecretAndNoContext() async {
        let (flow, _, _) = makeFlow()
        flow.admit(context: nil, pin: "4821")

        let borrowed: AnyObject? = await flow.withPresence { $0 }

        XCTAssertNil(borrowed)
        XCTAssertEqual(flow.currentPIN, "4821")
        XCTAssertFalse(flow.hasPresence)
    }

    // MARK: - Ending the capability

    /// The primary path: the intent completed, so the capability dies immediately rather than
    /// lingering while the screen is torn down.
    func testEndInvalidatesTheContext() {
        let (flow, recorder, token) = makeFlow()
        flow.admit(context: token)

        flow.end()

        XCTAssertEqual(recorder.invalidated, [ObjectIdentifier(token)])
        XCTAssertFalse(flow.hasPresence)
    }

    /// `end` is idempotent and clears the PIN too — abandoning the flow must leave nothing.
    func testEndIsIdempotentAndClearsTheSecret() {
        let (flow, recorder, token) = makeFlow()
        flow.admit(context: token, pin: "4821")

        flow.end()
        flow.end()

        XCTAssertEqual(recorder.invalidated.count, 1, "nothing to invalidate the second time")
        XCTAssertEqual(flow.currentPIN, "", "the secret does not outlive the flow either")
    }

    /// The backstop: a flow dropped without an explicit `end` — a popover torn down by a path
    /// that runs no teardown — still destroys its capability.
    func testDeinitInvalidatesAnUnendedContext() {
        let recorder = Recorder()
        let token = NSObject()
        do {
            let flow = SecurityFlow(invalidate: { recorder.invalidate($0) })
            flow.admit(context: token)
            XCTAssertTrue(recorder.invalidated.isEmpty, "precondition: still held")
        }
        XCTAssertEqual(recorder.invalidated, [ObjectIdentifier(token)],
                       "ARC must end a capability nobody ended explicitly")
    }

    /// Re-admitting must not strand the previous capability.
    func testAdmittingAgainInvalidatesThePriorContext() {
        let (flow, recorder, first) = makeFlow()
        let second = NSObject()
        flow.admit(context: first)

        flow.admit(context: second)

        XCTAssertEqual(recorder.invalidated, [ObjectIdentifier(first)],
                       "the replaced capability must not be left live")
    }

    // MARK: - Idle expiry

    /// The one case `deinit` cannot cover: a popover left open on the Security screen. The
    /// capability is dropped *before* expiry is published, so the screen can never observe itself
    /// still holding one.
    func testIdleExpiryEndsTheCapabilityAndReportsIt() async throws {
        let recorder = Recorder()
        let token = NSObject()
        // The production timeout is a minute; drive the same code path on a short one.
        let flow = SecurityFlow(idleTimeout: 0.05, invalidate: { recorder.invalidate($0) })
        flow.admit(context: token)

        try await Task.sleep(nanoseconds: 250_000_000)

        XCTAssertEqual(recorder.invalidated, [ObjectIdentifier(token)])
        XCTAssertTrue(flow.didExpire, "the screen is told to close")
        XCTAssertFalse(flow.hasPresence)
    }

    /// The `.none` install: nothing to protect, but the screen still auto-closes. The countdown
    /// doubles as the screen's dismissal, so every method behaves the same way.
    func testFlowWithoutPresenceStillExpires() async throws {
        let recorder = Recorder()
        let flow = SecurityFlow(idleTimeout: 0.05, invalidate: { recorder.invalidate($0) })

        flow.beginWithoutPresence()
        XCTAssertTrue(flow.isCountingDown)
        XCTAssertFalse(flow.hasPresence, "precondition: `.none` holds nothing")

        try await Task.sleep(nanoseconds: 250_000_000)

        XCTAssertTrue(flow.didExpire, "the screen closes even with no capability to end")
        XCTAssertTrue(recorder.invalidated.isEmpty, "there was nothing to invalidate")
    }

    /// Activity defers the `.none` auto-close too — the countdown is about the user having walked
    /// away, not about what is being held.
    func testActivityDefersExpiryWithoutPresence() async throws {
        let flow = SecurityFlow(idleTimeout: 0.2, invalidate: { _ in })
        flow.beginWithoutPresence()

        for _ in 0..<3 {
            try await Task.sleep(nanoseconds: 100_000_000)
            flow.noteActivity()
        }

        XCTAssertFalse(flow.didExpire, "activity kept the screen open")
        XCTAssertTrue(flow.isCountingDown)
    }

    /// Interaction restarts the countdown, so the timeout only catches a user who has genuinely
    /// walked away — not one part-way through filling in the form.
    func testActivityDefersExpiry() async throws {
        let recorder = Recorder()
        let flow = SecurityFlow(idleTimeout: 0.2, invalidate: { recorder.invalidate($0) })
        flow.admit(context: NSObject())

        // Three interactions inside the window: each must restart it.
        for _ in 0..<3 {
            try await Task.sleep(nanoseconds: 100_000_000)
            flow.noteActivity()
        }

        XCTAssertFalse(flow.didExpire, "activity kept the capability alive")
        XCTAssertTrue(flow.hasPresence)
    }

    /// Activity on a spent flow must not resurrect a countdown — there is nothing left to expire.
    func testActivityAfterEndDoesNotRestartTheCountdown() async throws {
        let recorder = Recorder()
        let token = NSObject()
        let flow = SecurityFlow(idleTimeout: 0.05, invalidate: { recorder.invalidate($0) })
        flow.admit(context: token)
        flow.end()

        flow.noteActivity()
        try await Task.sleep(nanoseconds: 150_000_000)

        XCTAssertFalse(flow.didExpire, "a flow with no capability has nothing to expire")
    }
}
