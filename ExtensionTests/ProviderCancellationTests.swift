/// Unit tests for `ProviderCancellation`.
//
//  ProviderCancellationTests.swift
//  ExtensionTests
//
//  Covers the Provider half of the graceful-teardown handshake: a bumped
//  `cancelGeneration` runs the stop routine exactly once and is acknowledged with the generation
//  it answers, so the host can tell this cycle's reply from a previous one's.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Combine
import XCTest
import Common
@testable import Extension

final class ProviderCancellationTests: XCTestCase {

    /// Drives the coordinator's wakeup by hand, standing in for the Darwin-notified
    /// `SharedConfigStore.objectWillChange`.
    private let wakeup = PassthroughSubject<Void, Never>()
    private var generation = 0
    private var reports: [(state: ProviderState, generation: Int)] = []
    private var stopCount = 0

    private func makeCoordinator(domainID: String = "domain-a") -> ProviderCancellationCoordinator {
        let coordinator = ProviderCancellationCoordinator(
            domainID: domainID,
            readGeneration: { [unowned self] in self.generation },
            report: { [unowned self] state, generation in
                self.reports.append((state, generation))
            },
            stopWork: { [unowned self] in self.stopCount += 1 })
        coordinator.start(publisher: wakeup.eraseToAnyPublisher())
        return coordinator
    }

    /// `stopWork` is async and acknowledges from a detached `Task`, so the reply is not
    /// synchronous with the wakeup.
    private func awaitAcknowledgement(file: StaticString = #filePath, line: UInt = #line) {
        let acknowledged = expectation(description: "cancellation acknowledged")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { acknowledged.fulfill() }
        wait(for: [acknowledged], timeout: 2)
    }

    // MARK: - Acknowledgement carries the requested generation

    /// The core of the fix: the reply names the generation it answers. Without it the host cannot
    /// distinguish this acknowledgement from one left by an earlier lock.
    func testAcknowledgementCarriesRequestedGeneration() {
        let coordinator = makeCoordinator()
        defer { coordinator.stop() }

        generation = 1
        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 1)
        XCTAssertEqual(reports.map(\.state), [.cancelling, .cancelled])
        XCTAssertEqual(reports.map(\.generation), [1, 1])
    }

    /// The regression this suite exists for. A second lock in the same session must produce its
    /// own acknowledgement at the new generation — the host waits for `ack >= 2`, so a reply still
    /// naming generation 1 would (correctly) fail to satisfy it, and one naming 2 must arrive only
    /// after `stopWork` has actually run again.
    func testSecondRequestIsAcknowledgedAtNewGeneration() {
        let coordinator = makeCoordinator()
        defer { coordinator.stop() }

        generation = 1
        wakeup.send()
        awaitAcknowledgement()

        reports.removeAll()

        generation = 2
        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 2, "the second lock must stop work again, not reuse the first ack")
        XCTAssertEqual(reports.map(\.state), [.cancelling, .cancelled])
        XCTAssertEqual(reports.map(\.generation), [2, 2])
    }

    // MARK: - Request de-duplication

    /// Repeated notifications at the same generation are one command, not several: the config
    /// store emits `objectWillChange` for every write, most of which are unrelated to locking.
    func testRepeatedNotificationsAtSameGenerationRunStopWorkOnce() {
        let coordinator = makeCoordinator()
        defer { coordinator.stop() }

        generation = 1
        wakeup.send()
        wakeup.send()
        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 1)
        XCTAssertEqual(reports.filter { $0.state == .cancelled }.count, 1)
    }

    /// An unrelated config change must not be mistaken for a cancellation request.
    func testNotificationWithoutGenerationBumpIsIgnored() {
        let coordinator = makeCoordinator()
        defer { coordinator.stop() }

        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 0)
        XCTAssertTrue(reports.isEmpty)
    }

    // MARK: - Launch adoption

    /// A generation already standing at launch belongs to a completed teardown (the Provider was
    /// relaunched after it), so re-running the stop routine would cancel work that just started.
    func testGenerationPresentAtLaunchIsNotReprocessed() {
        generation = 5
        let coordinator = makeCoordinator()
        defer { coordinator.stop() }

        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 0)
        XCTAssertTrue(reports.isEmpty)

        // ...but the next genuine request still lands.
        generation = 6
        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 1)
        XCTAssertEqual(reports.map(\.generation), [6, 6])
    }

    // MARK: - Teardown

    /// `stop()` unsubscribes: a request arriving afterwards is not served.
    func testStoppedCoordinatorIgnoresFurtherRequests() {
        let coordinator = makeCoordinator()
        coordinator.stop()

        generation = 1
        wakeup.send()
        awaitAcknowledgement()

        XCTAssertEqual(stopCount, 0)
    }
}
