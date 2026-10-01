/// Tests for SignalThrottle coalescing behaviour.
//
//  SignalThrottleTests.swift
//  ExtensionTests
//
//  Pins the leading + trailing coalescing behaviour of `SignalThrottle` — the guard against the
//  per-file `.workingSet` enumerate storm.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Extension

final class SignalThrottleTests: XCTestCase {

    /// A controllable clock + deferred-work queue so timing is deterministic (no real sleeps).
    private final class Harness {
        var current = Date(timeIntervalSince1970: 0)
        private(set) var pending: [(delay: TimeInterval, work: () -> Void)] = []

        func now() -> Date { current }
        func schedule(_ delay: TimeInterval, _ work: @escaping () -> Void) {
            pending.append((delay, work))
        }
        /// Advance the clock and run any scheduled trailing work whose delay has elapsed.
        func advance(_ seconds: TimeInterval) {
            current = current.addingTimeInterval(seconds)
            let due = pending
            pending.removeAll()
            due.forEach { $0.work() }
        }
    }

    private func makeThrottle(_ h: Harness, interval: TimeInterval = 1.0) -> SignalThrottle {
        SignalThrottle(minInterval: interval, now: h.now, schedule: h.schedule)
    }

    /// The first request fires immediately (leading edge).
    func testLeadingEdgeFiresImmediately() {
        let h = Harness()
        let throttle = makeThrottle(h)
        var fires = 0
        throttle.request { fires += 1 }
        XCTAssertEqual(fires, 1)
    }

    /// A burst inside the window collapses to exactly one leading + one trailing fire.
    func testBurstCollapsesToLeadingPlusTrailing() {
        let h = Harness()
        let throttle = makeThrottle(h)
        var fires = 0

        throttle.request { fires += 1 } // leading
        throttle.request { fires += 1 } // coalesced → schedules trailing
        throttle.request { fires += 1 } // coalesced → no extra schedule
        throttle.request { fires += 1 } // coalesced → no extra schedule
        XCTAssertEqual(fires, 1, "only the leading edge has fired so far")

        h.advance(1.0) // window elapses → trailing fires once
        XCTAssertEqual(fires, 2, "burst delivers exactly leading + one trailing")
    }

    /// After the window clears, a later request fires immediately again (new leading edge).
    func testRequestAfterWindowFiresImmediately() {
        let h = Harness()
        let throttle = makeThrottle(h)
        var fires = 0

        throttle.request { fires += 1 } // leading @ t=0
        h.advance(2.0)                  // well past the interval, nothing queued
        XCTAssertEqual(fires, 1)

        throttle.request { fires += 1 } // new leading @ t=2
        XCTAssertEqual(fires, 2)
    }

    /// The trailing fire is never dropped: the final request in a burst is always delivered.
    func testTrailingFireDeliversLastRequest() {
        let h = Harness()
        let throttle = makeThrottle(h)
        var lastValue = 0

        throttle.request { lastValue = 1 } // leading
        throttle.request { lastValue = 2 } // trailing captures this closure's effect boundary
        h.advance(1.0)
        XCTAssertEqual(lastValue, 2, "trailing edge delivers so the last item in the burst is signalled")
    }
}
