/// Timestamp parsing for Graph payloads.
///
/// Graph emits whole-second UTC, so the fast integer path carries essentially all delta
/// traffic; these pin its agreement with `ISO8601DateFormatter` and its rejection of every
/// shape it must not attempt.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
@testable import Common

final class GraphDecodingDateTests: XCTestCase {

    private func reference(_ s: String, fractional: Bool = false) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = fractional ? [.withInternetDateTime, .withFractionalSeconds]
                                     : [.withInternetDateTime]
        return f.date(from: s)
    }

    func testWholeSecondMatchesFormatter() {
        for s in ["2025-02-21T11:55:26Z", "2018-12-13T05:09:17Z", "2026-08-30T03:10:15Z",
                  "1970-01-01T00:00:00Z", "2000-02-29T23:59:59Z", "2024-02-29T12:00:00Z"] {
            XCTAssertEqual(GraphDecoding.parseISO8601(s), reference(s), "mismatch for \(s)")
        }
    }

    /// Leap-year and century boundaries are where a hand-rolled civil-date conversion breaks.
    func testCenturyAndLeapBoundaries() {
        for s in ["1900-03-01T00:00:00Z", "2000-03-01T00:00:00Z", "2100-02-28T00:00:00Z",
                  "2099-12-31T23:59:59Z", "2400-01-01T00:00:00Z"] {
            XCTAssertEqual(GraphDecoding.parseISO8601(s), reference(s), "mismatch for \(s)")
        }
    }

    /// Fractional input must still parse — the fast path declines and the formatter takes it.
    func testFractionalStillParses() {
        let s = "2025-02-21T11:55:26.123Z"
        XCTAssertEqual(GraphDecoding.parseISO8601(s), reference(s, fractional: true))
    }

    func testRejectsMalformed() {
        for s in ["", "not-a-date", "2025-02-21", "2025-02-21T11:55:26",
                  "2025-02-21T11:55:26+01:00", "20250221T115526Z", "2025-13-01T00:00:00Z",
                  "2025-02-21T25:00:00Z", "2025-02-21T11:60:00Z", "2025-XX-21T11:55:26Z"] {
            // Either nil, or whatever the formatters accept — never a wrong date from the
            // fast path. Offsets are valid ISO8601, so the fallback may legitimately parse one.
            let parsed = GraphDecoding.parseISO8601(s)
            if let parsed {
                XCTAssertEqual(parsed, reference(s) ?? reference(s, fractional: true),
                               "fast path invented a date for \(s)")
            }
        }
    }

    /// The decoder wiring, not just the free function.
    func testDecoderUsesFastPath() throws {
        struct Box: Decodable { let createdDateTime: Date }
        let json = #"{"createdDateTime":"2025-02-21T11:55:26Z"}"#.data(using: .utf8)!
        let box = try GraphDecoding.makeDecoder().decode(Box.self, from: json)
        XCTAssertEqual(box.createdDateTime, reference("2025-02-21T11:55:26Z"))
    }
}
