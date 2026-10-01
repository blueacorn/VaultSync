/// Unit tests for `PartialFetchWindow`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
@testable import Extension

/// Covers `PartialFetchWindow`: head window, scaled read-ahead, alignment and extension to EOF.
final class PartialFetchWindowTests: XCTestCase {

    private let kib = 1024
    private let mib = 1024 * 1024
    private let gib = 1024 * 1024 * 1024
    private let alignment = 16 * 1024
    private lazy var policy = PartialFetchWindow(headFloorSystem: 256 * kib, headFloorStandard: 1 * mib, readAheadFloor: 2 * mib,
                                                 readAheadCeiling: 16 * mib, readAheadFileDivisor: 16)

    // MARK: - Head reads

    func testHeadReadIsRaisedToHeadFloorOnly() {
        let extent = policy.extent(for: NSRange(location: 0, length: 4 * kib),
                                   alignment: alignment, fileSize: 100 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 256 * kib)))
    }

    func testHeadReadLargerThanFloorIsHonouredAligned() {
        let extent = policy.extent(for: NSRange(location: 0, length: 300 * kib + 1),
                                   alignment: alignment, fileSize: 100 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 304 * kib)))
    }

    func testUnalignedStartInsideFirstUnitCountsAsHeadRead() {
        let extent = policy.extent(for: NSRange(location: 100, length: 64 * kib),
                                   alignment: alignment, fileSize: 100 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 256 * kib)))
    }

    func testHeadReadWithRemainderWithinWindowFetchesWholeFile() {
        // Remainder 512 KiB - 256 KiB = 256 KiB ≤ head window.
        let extent = policy.extent(for: NSRange(location: 0, length: 4 * kib),
                                   alignment: alignment, fileSize: 512 * kib, isSystemRequest: true)
        XCTAssertEqual(extent, .wholeFile)
    }

    func testHeadReadWithRemainderOverWindowIsNotExtended() {
        let extent = policy.extent(for: NSRange(location: 0, length: 4 * kib),
                                   alignment: alignment, fileSize: 512 * kib + alignment, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 256 * kib)))
    }

    func testHeadReadOfMidSizedFileStaysSmall() {
        let extent = policy.extent(for: NSRange(location: 0, length: 4 * kib),
                                   alignment: alignment, fileSize: 5 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 256 * kib)))
    }

    // MARK: - App head reads

    func testAppHeadReadUsesStandardHeadFloor() {
        let extent = policy.extent(for: NSRange(location: 0, length: 4 * kib),
                                   alignment: alignment, fileSize: 128 * mib, isSystemRequest: false)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 1 * mib)))
    }

    func testAppHeadReadWithRemainderWithinWindowFetchesWholeFile() {
        // Remainder 2 MiB - 1 MiB = 1 MiB ≤ standard head floor.
        let extent = policy.extent(for: NSRange(location: 0, length: 4 * kib),
                                   alignment: alignment, fileSize: 2 * mib, isSystemRequest: false)
        XCTAssertEqual(extent, .wholeFile)
    }

    func testRequesterDoesNotChangeLaterReads() {
        let range = NSRange(location: 256 * kib, length: 4 * kib)
        XCTAssertEqual(policy.extent(for: range, alignment: alignment, fileSize: 64 * mib, isSystemRequest: false),
                       policy.extent(for: range, alignment: alignment, fileSize: 64 * mib, isSystemRequest: true))
    }

    // MARK: - Read-ahead window

    func testReadAheadWindowScalesWithFileSizeBetweenFloorAndCeiling() {
        XCTAssertEqual(policy.readAheadWindow(fileSize: 10 * mib), 2 * mib)
        XCTAssertEqual(policy.readAheadWindow(fileSize: 32 * mib), 2 * mib)
        XCTAssertEqual(policy.readAheadWindow(fileSize: 128 * mib), 8 * mib)
        XCTAssertEqual(policy.readAheadWindow(fileSize: 256 * mib), 16 * mib)
        XCTAssertEqual(policy.readAheadWindow(fileSize: 4 * gib), 16 * mib)
    }

    func testCeilingBelowFloorYieldsFloor() {
        let policy = PartialFetchWindow(headFloorSystem: 256 * kib, headFloorStandard: 1 * mib, readAheadFloor: 2 * mib,
                                        readAheadCeiling: 1 * mib, readAheadFileDivisor: 16)
        XCTAssertEqual(policy.readAheadWindow(fileSize: 4 * gib), 2 * mib)
    }

    // MARK: - Later reads

    func testLaterReadUsesScaledWindow() {
        let extent = policy.extent(for: NSRange(location: 256 * kib, length: 4 * kib),
                                   alignment: alignment, fileSize: 64 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 256 * kib, length: 4 * mib)))
    }

    func testLaterReadStartIsAlignedDown() {
        let extent = policy.extent(for: NSRange(location: 20 * kib, length: 1),
                                   alignment: alignment, fileSize: 32 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 16 * kib, length: 2 * mib)))
    }

    func testLargeFileReadIsCappedAtCeiling() {
        let extent = policy.extent(for: NSRange(location: 3 * gib, length: 4 * kib),
                                   alignment: alignment, fileSize: 4 * gib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 3 * gib, length: 16 * mib)))
    }

    // MARK: - Extension to EOF

    func testWindowPastEOFExtendsToEOF() {
        let fileSize = 10 * mib + 123
        let extent = policy.extent(for: NSRange(location: 9 * mib, length: 4 * kib),
                                   alignment: alignment, fileSize: fileSize, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 9 * mib, length: fileSize - 9 * mib)))
    }

    func testRemainderAtWindowExtendsToEOFWithoutRefetchingEarlierBytes() {
        // Window [6 MiB, 8 MiB) of a 10 MiB file leaves exactly one 2 MiB window.
        let extent = policy.extent(for: NSRange(location: 6 * mib, length: 4 * kib),
                                   alignment: alignment, fileSize: 10 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 6 * mib, length: 4 * mib)))
    }

    func testRemainderOverWindowIsNotExtended() {
        let extent = policy.extent(for: NSRange(location: 5 * mib, length: 4 * kib),
                                   alignment: alignment, fileSize: 10 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 5 * mib, length: 2 * mib)))
    }

    func testLargeFileRemainderAtCeilingExtendsToEOF() {
        let fileSize = 4 * gib
        let start = fileSize - 32 * mib
        let extent = policy.extent(for: NSRange(location: start, length: 4 * kib),
                                   alignment: alignment, fileSize: fileSize, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: start, length: 32 * mib)))
    }

    func testLargeFileRemainderJustOverCeilingIsNotExtended() {
        let fileSize = 4 * gib
        let start = fileSize - 32 * mib - alignment
        let extent = policy.extent(for: NSRange(location: start, length: 4 * kib),
                                   alignment: alignment, fileSize: fileSize, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: start, length: 16 * mib)))
    }

    // MARK: - Contract

    func testExtentAlwaysCoversRequestAndIsAligned() {
        for fileSize in [37 * mib + 4321, 700 * mib + 1] {
            for location in stride(from: 0, to: fileSize, by: fileSize / 29) {
                for length in [1, 4 * kib, 300 * kib, 3 * mib] {
                    let requested = NSRange(location: location, length: length)
                    switch policy.extent(for: requested, alignment: alignment, fileSize: fileSize, isSystemRequest: true) {
                    case .wholeFile:
                        XCTAssertLessThan(requested.location, alignment, "only a head read may fetch the whole file")
                    case .range(let range):
                        // Starts at the aligned request start: earlier bytes are never refetched.
                        XCTAssertEqual(range.location, requested.location & ~(alignment - 1))
                        XCTAssertGreaterThanOrEqual(NSMaxRange(range), min(NSMaxRange(requested), fileSize))
                        XCTAssertLessThanOrEqual(NSMaxRange(range), fileSize)
                        XCTAssertTrue(NSMaxRange(range) == fileSize || range.length % alignment == 0)
                    }
                }
            }
        }
    }

    func testWindowIsRoundedToAlignment() {
        let policy = PartialFetchWindow(headFloorSystem: 100 * kib, headFloorStandard: 1 * mib, readAheadFloor: 2 * mib,
                                        readAheadCeiling: 16 * mib, readAheadFileDivisor: 16)
        let extent = policy.extent(for: NSRange(location: 0, length: 1),
                                   alignment: 64 * kib, fileSize: 100 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 0, length: 128 * kib)))
    }

    // MARK: - Degenerate input

    func testDegenerateInputFetchesWholeFile() {
        let valid = NSRange(location: 0, length: 1)
        XCTAssertEqual(policy.extent(for: valid, alignment: alignment, fileSize: 0, isSystemRequest: true), .wholeFile)
        XCTAssertEqual(policy.extent(for: NSRange(location: 0, length: 0),
                                     alignment: alignment, fileSize: mib, isSystemRequest: true), .wholeFile)
        XCTAssertEqual(policy.extent(for: NSRange(location: mib, length: 1),
                                     alignment: alignment, fileSize: mib, isSystemRequest: true), .wholeFile)
        XCTAssertEqual(policy.extent(for: valid, alignment: 3000, fileSize: 100 * mib, isSystemRequest: true), .wholeFile)
    }

    func testNoAlignmentConstraint() {
        let extent = policy.extent(for: NSRange(location: 1000, length: 1),
                                   alignment: 0, fileSize: 64 * mib, isSystemRequest: true)
        XCTAssertEqual(extent, .range(NSRange(location: 1000, length: 4 * mib)))
    }
}
