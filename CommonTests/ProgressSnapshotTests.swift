/// Unit tests for `ProgressSnapshot`.
//
//  ProgressSnapshotTests.swift
//  CommonTests
//
//  Codable round-trip coverage for the Provider→App progress relay models.
//  The App Group file I/O in `ProgressStore` needs entitlements the test bundle lacks,
//  so the durable contract tested here is the snapshot's stable JSON encoding.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

final class ProgressSnapshotTests: XCTestCase {

    func testSnapshotRoundTrips() throws {
        let snapshot = ProgressSnapshot(
            indexedCount: 42,
            indexedCountUpdatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            cryptoOps: [
                CryptoOp(id: "1", name: "a.txt", direction: .decrypt, fractionCompleted: 0.5),
                CryptoOp(id: "2", name: "b.txt", direction: .encrypt, fractionCompleted: nil),
            ])

        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(snapshot)
        let decoded = try decoder.decode(ProgressSnapshot.self, from: data)

        XCTAssertEqual(decoded, snapshot)
        XCTAssertEqual(decoded.indexedCount, 42)
        XCTAssertEqual(decoded.cryptoOps.count, 2)
        XCTAssertNil(decoded.cryptoOps[1].fractionCompleted)
    }

    func testEmptySnapshotDefaults() {
        let snapshot = ProgressSnapshot()
        XCTAssertEqual(snapshot.indexedCount, 0)
        XCTAssertTrue(snapshot.cryptoOps.isEmpty)
        XCTAssertEqual(snapshot.providerState, .idle)
        XCTAssertEqual(snapshot.cancelAckGeneration, 0)
    }

    /// The cancellation ack must survive the round trip: the host compares it against the
    /// generation it requested, so a dropped field would silently reinstate the stale-ack bug.
    func testCancellationAckRoundTrips() throws {
        let snapshot = ProgressSnapshot(providerState: .cancelled, cancelAckGeneration: 7)

        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ProgressSnapshot.self, from: encoder.encode(snapshot))

        XCTAssertEqual(decoded.providerState, .cancelled)
        XCTAssertEqual(decoded.cancelAckGeneration, 7)
    }

    /// A snapshot written before the ack field existed decodes to generation 0, which matches no
    /// real request (`requestCancellation` returns 1 or more) — so a pre-upgrade `.cancelled`
    /// cannot acknowledge a post-upgrade lock.
    func testSnapshotWithoutAckGenerationDecodesToZero() throws {
        let json = Data(#"{"indexedCount":3,"cryptoOps":[],"providerState":"cancelled"}"#.utf8)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601

        let decoded = try decoder.decode(ProgressSnapshot.self, from: json)

        XCTAssertEqual(decoded.providerState, .cancelled)
        XCTAssertEqual(decoded.cancelAckGeneration, 0)
    }
}
