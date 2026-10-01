/// Tests for GraphRateLimiter cool-off gating, interactive concurrency cap, and end-of-cool-off signal.
//
//  GraphRateLimiterTests.swift
//  ExtensionTests
//
//  Pins the throttling contract that keeps Finder fetches from failing en masse after a 429:
//  interactive requests wait out cool-offs (never fail fast), the wait is cancellable,
//  the end-of-cool-off callback fires exactly once per episode, and the interactive cap queues.
//  Also pins that `toPresentableError` delivers File Provider errors unchanged.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import FileProvider
import XCTest
@testable import Extension

final class GraphRateLimiterTests: XCTestCase {

    /// Thread-safe counter for the `@Sendable` callback.
    private actor Counter {
        private(set) var value = 0
        func increment() { value += 1 }
    }

    /// No cool-off: the gate passes without waiting.
    func testNoCoolOffPassesImmediately() async throws {
        let limiter = GraphRateLimiter()
        let waited = try await limiter.waitForCoolOff(priority: .interactive)
        XCTAssertEqual(waited, 0)
    }

    /// An interactive request waits out the cool-off rather than failing.
    func testInteractiveWaitsOutCoolOff() async throws {
        let limiter = GraphRateLimiter()
        await limiter.noteRetryAfter(seconds: 0.2, source: "test")
        let waited = try await limiter.waitForCoolOff(priority: .interactive)
        XCTAssertGreaterThan(waited, 0)
    }

    /// A long cool-off wait ends promptly on cancellation (the system abandoned the fetch).
    func testCoolOffWaitIsCancellable() async throws {
        let limiter = GraphRateLimiter()
        await limiter.noteRetryAfter(seconds: 60, source: "test")
        let wait = Task { try await limiter.waitForCoolOff(priority: .interactive) }
        try await Task.sleep(nanoseconds: 50_000_000)
        wait.cancel()
        do {
            _ = try await wait.value
            XCTFail("expected CancellationError")
        } catch is CancellationError {}
    }

    /// Overlapping `Retry-After`s collapse into one episode: the callback fires once, after the last.
    func testCoolOffEndedFiresOncePerEpisode() async throws {
        let counter = Counter()
        let limiter = GraphRateLimiter(onCoolOffEnded: { await counter.increment() })
        await limiter.noteRetryAfter(seconds: 0.1, source: "a")
        await limiter.noteRetryAfter(seconds: 0.3, source: "b")
        try await Task.sleep(nanoseconds: 200_000_000)
        let midway = await counter.value
        XCTAssertEqual(midway, 0)
        try await Task.sleep(nanoseconds: 400_000_000)
        let final = await counter.value
        XCTAssertEqual(final, 1)
    }

    /// Past the cap, an interactive request queues until a slot is released.
    func testInteractiveCapQueues() async throws {
        let limiter = GraphRateLimiter(maxInteractive: 1)
        await limiter.beginRequest(.interactive)
        let second = Task { await limiter.beginRequest(.interactive) }
        try await Task.sleep(nanoseconds: 150_000_000)
        await limiter.endRequest(.interactive)
        let queued = await second.value
        XCTAssertGreaterThan(queued, 0.1)
        await limiter.endRequest(.interactive)
    }

    /// Background requests are never capped.
    func testBackgroundNotCapped() async {
        let limiter = GraphRateLimiter(maxInteractive: 1)
        await limiter.beginRequest(.interactive)
        let queued = await limiter.beginRequest(.background)
        XCTAssertEqual(queued, 0)
    }

    /// `serverUnreachable` reaches the OS unchanged, not remapped to an XPC fault (4101).
    func testPresentableKeepsFileProviderError() {
        let presentable = GraphRateLimiter.throttledError.toPresentableError()
        XCTAssertEqual(presentable.domain, NSFileProviderErrorDomain)
        XCTAssertEqual(presentable.code, NSFileProviderError.serverUnreachable.rawValue)
    }
}
