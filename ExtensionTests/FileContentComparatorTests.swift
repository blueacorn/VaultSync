/// Unit tests for `FileContentComparator`.
//
//  FileContentComparatorTests.swift
//  ExtensionTests
//
//  Chunked, bounded-memory file comparison used by the converter's read-back verify.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Extension

final class FileContentComparatorTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("comparator-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func file(_ bytes: Data) throws -> URL {
        let url = tempDir.appendingPathComponent(UUID().uuidString)
        try bytes.write(to: url)
        return url
    }

    private func pattern(_ count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) })
    }

    func testEqualFiles() throws {
        let bytes = pattern(10_000)
        XCTAssertTrue(try FileContentComparator.equal(try file(bytes), try file(bytes)))
    }

    func testSizeMismatch() throws {
        XCTAssertFalse(try FileContentComparator.equal(try file(pattern(10)), try file(pattern(11))))
    }

    func testLastByteMismatch() throws {
        var other = pattern(10_000)
        other[other.count - 1] ^= 0xFF
        XCTAssertFalse(try FileContentComparator.equal(try file(pattern(10_000)), try file(other)))
    }

    func testEmptyFiles() throws {
        XCTAssertTrue(try FileContentComparator.equal(try file(Data()), try file(Data())))
    }

    /// Crosses several chunk boundaries, with a difference in the final partial chunk.
    func testFileLargerThanOneChunk() throws {
        let bytes = pattern(1000)
        let a = try file(bytes), b = try file(bytes)
        XCTAssertTrue(try FileContentComparator.equal(a, b, chunkSize: 64))

        var other = bytes
        other[999] ^= 0x01
        XCTAssertFalse(try FileContentComparator.equal(a, try file(other), chunkSize: 64))
    }

    /// Default chunk size: a file just over 1 MiB compares across the boundary.
    func testDefaultChunkBoundary() throws {
        let bytes = pattern(FileContentComparator.chunkSize + 1)
        XCTAssertTrue(try FileContentComparator.equal(try file(bytes), try file(bytes)))
    }
}
