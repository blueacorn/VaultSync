/// Unit tests for `FetchRangeAlignment`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
@testable import Extension

final class FetchRangeAlignmentTests: XCTestCase {

    func testAlignedWindowIsUnchanged() {
        let window = NSRange(location: 16384, length: 32768)
        XCTAssertEqual(FetchRangeAlignment.alignedReply(window, covering: NSRange(location: 16384, length: 16384),
                                                        alignment: 16384, documentSize: 1 << 20), window)
    }

    func testUnalignedStartIsRoundedUp() {
        let window = NSRange(location: 12288, length: 36864)   // 12 KiB block origin, 16 KiB alignment
        XCTAssertEqual(FetchRangeAlignment.alignedReply(window, covering: NSRange(location: 16384, length: 16384),
                                                        alignment: 16384, documentSize: 1 << 20),
                       NSRange(location: 16384, length: 32768))
    }

    func testUnalignedEndIsRoundedDown() {
        let window = NSRange(location: 0, length: 36864)
        XCTAssertEqual(FetchRangeAlignment.alignedReply(window, covering: NSRange(location: 0, length: 16384),
                                                        alignment: 16384, documentSize: 1 << 20),
                       NSRange(location: 0, length: 32768))
    }

    func testUnalignedEndAtDocumentSizeIsKept() {
        let window = NSRange(location: 0, length: 50362)
        XCTAssertEqual(FetchRangeAlignment.alignedReply(window, covering: NSRange(location: 0, length: 262144),
                                                        alignment: 16384, documentSize: 50362), window)
    }

    func testWindowBeyondDocumentSizeIsClipped() {
        XCTAssertEqual(FetchRangeAlignment.alignedReply(NSRange(location: 0, length: 54464),
                                                        covering: NSRange(location: 0, length: 16384),
                                                        alignment: 16384, documentSize: 50362),
                       NSRange(location: 0, length: 50362))
    }

    func testUncoverableRequestReturnsNil() {
        // Rounding the start up past the requested start would drop requested bytes.
        XCTAssertNil(FetchRangeAlignment.alignedReply(NSRange(location: 4096, length: 65536),
                                                      covering: NSRange(location: 8192, length: 4096),
                                                      alignment: 16384, documentSize: 1 << 20))
    }

    func testNonPowerOfTwoAlignmentReturnsNil() {
        XCTAssertNil(FetchRangeAlignment.alignedReply(NSRange(location: 0, length: 4096),
                                                      covering: NSRange(location: 0, length: 4096),
                                                      alignment: 3000, documentSize: 4096))
    }

    func testRoundingHelpers() {
        XCTAssertEqual(FetchRangeAlignment.roundDown(20000, to: 4096), 16384)
        XCTAssertEqual(FetchRangeAlignment.roundUp(20000, to: 4096), 20480)
        XCTAssertEqual(FetchRangeAlignment.roundUp(5 * 1_048_576, to: 16384), 5 * 1_048_576)
    }
}
