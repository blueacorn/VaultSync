/// Regression tests for the 20000-items-per-batch enumeration ceiling.
//
//  EnumerationBatchingTests.swift
//  ExtensionTests
//
//  Regression coverage for the 20000-items-per-batch framework ceiling. Both
//  `enumerateItems` and `enumerateChanges` must split their `didEnumerate` / `didUpdate` /
//  `didDeleteItems` calls into sub-batches via `ItemEnumerator.batchSize(suggested:)`.
//
//  This pins the bug seen with the working-set change feed: a single `didUpdate` of 277,716
//  items tripped `__FILEPROVIDER_OBSERVER_TOO_MANY_ITEMS__` (FPXEnumerator.m:171) and aborted
//  the whole enumeration, so no remote changes ever reached Finder.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import FileProvider
@testable import Extension

final class EnumerationBatchingTests: XCTestCase {

    /// The framework aborts any single batch strictly greater than this.
    private let frameworkCeiling = 20000

    /// Chunk a count of `n` items the way the enumerators do and return each batch size.
    private func batchSizes(itemCount n: Int, suggested: Int) -> [Int] {
        let chunk = ItemEnumerator.batchSize(suggested: suggested)
        var sizes: [Int] = []
        for start in stride(from: 0, to: n, by: chunk) {
            sizes.append(min(start + chunk, n) - start)
        }
        return sizes
    }

    /// `batchSize` never exceeds the hard ceiling, whatever the observer suggests — including
    /// a pathological suggestion far above the framework limit.
    func testBatchSizeNeverExceedsHardCeiling() {
        for suggested in [-1, 0, 1, 500, 1000, 2000, 5000, 50000, Int.max] {
            let chunk = ItemEnumerator.batchSize(suggested: suggested)
            XCTAssertGreaterThanOrEqual(chunk, 1)
            XCTAssertLessThanOrEqual(chunk, ItemEnumerator.maxEnumerationBatchSize)
            XCTAssertLessThan(chunk, frameworkCeiling)
        }
    }

    /// A zero/absent suggestion falls back to the default batch size.
    func testZeroSuggestionUsesDefault() {
        XCTAssertEqual(ItemEnumerator.batchSize(suggested: 0), ItemEnumerator.defaultEnumerationBatchSize)
    }

    /// The exact failure scenario: 277,716 changed items must be delivered in many bounded
    /// batches, none exceeding the framework ceiling, with no items lost or duplicated.
    func testLargeChangeSetSplitsIntoBoundedBatches() {
        let total = 277_716
        let sizes = batchSizes(itemCount: total, suggested: 0)

        XCTAssertGreaterThan(sizes.count, 1, "must split into multiple batches")
        for size in sizes {
            XCTAssertLessThan(size, frameworkCeiling)
            XCTAssertLessThanOrEqual(size, ItemEnumerator.maxEnumerationBatchSize)
        }
        XCTAssertEqual(sizes.reduce(0, +), total, "every item delivered exactly once")
    }

    /// Batching is exact at boundaries (multiple of chunk, and chunk+1).
    func testBatchingCoversBoundariesExactly() {
        let chunk = ItemEnumerator.batchSize(suggested: 0)
        for total in [0, 1, chunk - 1, chunk, chunk + 1, chunk * 3, chunk * 3 + 7] {
            let sizes = batchSizes(itemCount: total, suggested: 0)
            XCTAssertEqual(sizes.reduce(0, +), total)
            XCTAssertTrue(sizes.allSatisfy { $0 <= chunk && $0 >= (sizes.count > 1 ? 1 : 0) })
        }
    }
}
