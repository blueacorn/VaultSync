/// Unit tests for `Throttle`.
//
//  ThrottleTests.swift
//  CommonTests
//
//  Lifecycle coverage for ``Throttle``. Its `DispatchSource` is created suspended and is only
//  resumed by `resume()`, so a throttle that is built and discarded without ever being resumed
//  used to trap in libdispatch (`_dispatch_queue_xref_dispose`) on release — which crashed the
//  test runner outright rather than failing a test.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

final class ThrottleTests: XCTestCase {

    /// The regression: build and release without ever resuming.
    func testDeallocWithoutResumeDoesNotTrap() {
        for _ in 0..<50 {
            let throttle = Throttle(timeout: .milliseconds(10), "never-resumed")
            throttle.handler = {}
        }
        XCTAssertTrue(true, "reaching here means release of a suspended source was handled")
    }

    /// A throttle with no handler at all is also safe to discard.
    func testDeallocWithoutHandlerDoesNotTrap() {
        for _ in 0..<50 {
            _ = Throttle(timeout: .milliseconds(10), "no-handler")
        }
        XCTAssertTrue(true)
    }

    /// The normal path — resumed, then released — stays safe.
    func testDeallocAfterResumeDoesNotTrap() {
        for _ in 0..<50 {
            let throttle = Throttle(timeout: .milliseconds(10), "resumed")
            throttle.handler = {}
            throttle.resume()
        }
        XCTAssertTrue(true)
    }

    /// `cancel()` is idempotent and safe both before and after `resume()`.
    func testCancelIsIdempotent() {
        let unresumed = Throttle(timeout: .milliseconds(10), "cancel-unresumed")
        unresumed.handler = {}
        unresumed.cancel()
        unresumed.cancel()

        let resumed = Throttle(timeout: .milliseconds(10), "cancel-resumed")
        resumed.handler = {}
        resumed.resume()
        resumed.cancel()
        resumed.cancel()

        XCTAssertTrue(true, "no trap from repeated cancellation")
    }

    /// `resume()` is idempotent: resuming a dispatch source twice would unbalance its
    /// suspend count and trap.
    func testResumeIsIdempotent() {
        let throttle = Throttle(timeout: .milliseconds(10), "double-resume")
        throttle.handler = {}
        throttle.resume()
        throttle.resume()
        XCTAssertTrue(true)
    }

    /// The throttle still does its job: a signal fires the handler once after the timeout.
    func testSignalFiresHandler() {
        let fired = expectation(description: "handler fired")
        let throttle = Throttle(timeout: .milliseconds(50), "firing")
        throttle.handler = { fired.fulfill() }
        throttle.resume()
        throttle.signal()
        wait(for: [fired], timeout: 2)
    }

    /// A cancelled throttle never fires, even if signalled.
    func testCancelledThrottleDoesNotFire() {
        let fired = expectation(description: "handler fired")
        fired.isInverted = true
        let throttle = Throttle(timeout: .milliseconds(20), "cancelled")
        throttle.handler = { fired.fulfill() }
        throttle.resume()
        throttle.cancel()
        throttle.signal()
        wait(for: [fired], timeout: 0.5)
    }
}
