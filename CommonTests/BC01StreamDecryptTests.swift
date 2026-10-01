/// Unit tests for `BC01StreamDecrypt`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import XCTest
import FileProvider
import Common

/// Validates the block-aligned lane partitioning (``BC01LanePartition``) and the
/// offset-write reassembly it enables: decrypt each lane's ciphertext span independently by
/// global block index and write plaintext at `blockIndex * blockSize`, out of order, and the
/// result must byte-equal the whole-blob `decrypt(_:)`. This is the correctness core of the
/// parallel encrypted stream-download path; it is pure logic + crypto, no network.
final class BC01StreamDecryptTests: KeychainIsolatedTestCase {

    /// Provisioning seals the session key under a VMK; an isolated store keeps that deterministic
    /// and leaves the user's real gating setting untouched.
    private static let testKeyStore = VaultKeyStore.isolatedForTesting()
    private var decryptor: BC01Decryptor?
    private let testDomainID = "com.test.bc01streamdecrypt-\(UUID().uuidString)"

    override func setUpWithError() throws {
        try super.setUpWithError()
        let projectRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let bckeyURL = projectRoot.appendingPathComponent("data/corpus/example.bckey")

        let semaphore = DispatchSemaphore(value: 0)
        var setupError: Error?
        Task {
            do {
                _ = try await CryptoConfigViewModel().deriveAndStoreKey(
                    bckeyURL: bckeyURL,
                    password: "password",
                    for: NSFileProviderDomainIdentifier(testDomainID),
                    keyStore: Self.testKeyStore
                )
                semaphore.signal()
            } catch {
                setupError = error
                semaphore.signal()
            }
        }
        semaphore.wait()
        if let error = setupError { throw error }

        let der = try CryptoKeychain.loadUnwrappedUserIdentityKeyDER(for: testDomainID)
        XCTAssertNotNil(der, "RSA private key not loaded from keychain")
        decryptor = BC01Decryptor(rsaPrivateKey: try BC01CryptoCommon.importRSAPrivateKey(der!))
    }

    override func tearDownWithError() throws {
        try Self.testKeyStore.forgetDomain(testDomainID)
        try super.tearDownWithError()
    }

    // MARK: - Partition math (pure logic)

    func testSpansAreContiguousBlockAlignedAndComplete() throws {
        // A synthetic body of 10 full blocks + a short final block.
        let blockSize = 4096
        let headerEnd = 48 + 1000
        let totalSize = headerEnd + 10 * blockSize + 123
        let expectedBlocks = 11 // 10 full + 1 short

        for lanes in [1, 2, 3, 7, 8, 16, 64] {
            let spans = BC01LanePartition.spans(startOffset: headerEnd, endOffset: totalSize,
                                                blockSize: blockSize, lanes: lanes)
            XCTAssertFalse(spans.isEmpty, "lanes=\(lanes)")
            XCTAssertLessThanOrEqual(spans.count, min(lanes, expectedBlocks), "lanes=\(lanes)")

            // Contiguous byte coverage of [headerEnd, totalSize).
            XCTAssertEqual(spans.first?.start, headerEnd, "lanes=\(lanes)")
            var cursor = headerEnd
            var blockCursor = 0
            for span in spans {
                XCTAssertEqual(span.start, cursor, "gap/overlap at lanes=\(lanes)")
                XCTAssertEqual(span.firstBlockIndex, blockCursor, "block index gap lanes=\(lanes)")
                cursor += span.length
                blockCursor += span.blockCount
                XCTAssertGreaterThan(span.blockCount, 0, "lanes=\(lanes)")
            }
            XCTAssertEqual(cursor, totalSize, "incomplete coverage lanes=\(lanes)")
            XCTAssertEqual(blockCursor, expectedBlocks, "block count mismatch lanes=\(lanes)")

            // Every span except the last covers whole blocks (length == blocks*blockSize).
            for span in spans.dropLast() {
                XCTAssertEqual(span.length, span.blockCount * blockSize,
                               "non-final span not block-aligned lanes=\(lanes)")
            }
        }
    }

    func testSpansEmptyBodyYieldsNoLanes() {
        let headerEnd = 2048
        let spans = BC01LanePartition.spans(startOffset: headerEnd, endOffset: headerEnd,
                                            blockSize: 4096, lanes: 8)
        XCTAssertTrue(spans.isEmpty)
    }

    func testSpansClampLanesToBlockCount() {
        // 3 blocks, 8 lanes requested → at most 3 spans.
        let blockSize = 4096
        let headerEnd = 100
        let totalSize = headerEnd + 3 * blockSize
        let spans = BC01LanePartition.spans(startOffset: headerEnd, endOffset: totalSize,
                                            blockSize: blockSize, lanes: 8)
        XCTAssertEqual(spans.count, 3)
        XCTAssertEqual(spans.map(\.blockCount), [1, 1, 1])
    }

    func testSpansRangedSubRegionKeepsGlobalBlockIndices() {
        // A sub-region covering global blocks 5..8 (4 blocks) of a larger file.
        let blockSize = 4096
        let headerEnd = 48 + 200
        let startBlockIndex = 5
        let startOffset = headerEnd + startBlockIndex * blockSize
        let endOffset = startOffset + 4 * blockSize

        for lanes in [1, 2, 4, 8] {
            let spans = BC01LanePartition.spans(startOffset: startOffset, endOffset: endOffset,
                                                blockSize: blockSize, lanes: lanes,
                                                startBlockIndex: startBlockIndex)
            XCTAssertFalse(spans.isEmpty, "lanes=\(lanes)")
            XCTAssertEqual(spans.first?.start, startOffset, "lanes=\(lanes)")
            XCTAssertEqual(spans.first?.firstBlockIndex, startBlockIndex, "lanes=\(lanes)")

            var cursor = startOffset
            var blockCursor = startBlockIndex
            for span in spans {
                XCTAssertEqual(span.start, cursor, "gap/overlap lanes=\(lanes)")
                XCTAssertEqual(span.firstBlockIndex, blockCursor, "global block index lanes=\(lanes)")
                cursor += span.length
                blockCursor += span.blockCount
            }
            XCTAssertEqual(cursor, endOffset, "incomplete coverage lanes=\(lanes)")
            XCTAssertEqual(blockCursor, startBlockIndex + 4, "block count mismatch lanes=\(lanes)")
        }
    }

    // MARK: - Offset reassembly against the corpus

    func testLaneDecryptOffsetWriteMatchesWholeBlob() throws {
        let decryptor = try XCTUnwrap(decryptor)
        let projectRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let encryptedDir = projectRoot.appendingPathComponent("data/corpus/bc01/bin")

        let fm = FileManager.default
        let encryptedFiles = try fm.contentsOfDirectory(at: encryptedDir, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasSuffix(".bc") }
            .sorted { $0.path < $1.path }

        for encryptedURL in encryptedFiles {
            let encrypted = try Data(contentsOf: encryptedURL)
            let header = try decryptor.makeBlockContext(from: encrypted)
            let whole = try decryptor.decrypt(encrypted)
            let name = encryptedURL.lastPathComponent

            for lanes in [1, 3, 8] {
                let plaintext = try Self.reassembleViaLanes(
                    encrypted: encrypted, header: header, totalSize: encrypted.count,
                    lanes: lanes, laneOrder: .reversed)
                XCTAssertEqual(plaintext, whole, "\(name) lanes=\(lanes) offset reassembly mismatch")
            }
        }
    }

    /// Decrypts `encrypted` via `lanes` block-aligned spans, writing each span's plaintext at
    /// its computed offset into a temp file in the given lane order (to prove order-independence),
    /// then returns the file's bytes.
    private enum LaneOrder { case forward, reversed }

    private static func reassembleViaLanes(encrypted: Data, header: BC01Header, totalSize: Int,
                                           lanes: Int, laneOrder: LaneOrder) throws -> Data {
        let spans = BC01LanePartition.spans(startOffset: header.headerEnd, endOffset: totalSize,
                                            blockSize: header.blockSize, lanes: lanes)
        let totalBlocks = spans.reduce(0) { $0 + $1.blockCount }

        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("bc01-stream-\(UUID().uuidString).bin")
        FileManager.default.createFile(atPath: tmpURL.path, contents: nil)
        let handle = try FileHandle(forWritingTo: tmpURL)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: tmpURL) }

        let ordered = laneOrder == .reversed ? Array(spans.reversed()) : spans
        for span in ordered {
            let spanData = encrypted[(encrypted.startIndex + span.start)..<(encrypted.startIndex + span.start + span.length)]
            var blockStart = spanData.startIndex
            for b in 0..<span.blockCount {
                let globalIndex = span.firstBlockIndex + b
                let isLast = globalIndex == totalBlocks - 1
                let blockEnd = isLast ? spanData.endIndex : blockStart + header.blockSize
                let block = Data(spanData[blockStart..<blockEnd])
                let plain = try BC01CryptoCommon.decryptBlock(block, blockIndex: globalIndex,
                                                              isLast: isLast, header: header)
                try handle.seek(toOffset: UInt64(globalIndex * header.blockSize))
                handle.write(plain)
                blockStart = blockEnd
            }
        }
        try handle.close()
        return try Data(contentsOf: tmpURL)
    }

    // MARK: - Span cap

    /// `maxSpanBytes` bounds each span's byte length, cutting the region into more spans than
    /// `lanes` rather than bigger ones, while keeping block indices contiguous and complete.
    func testSpansHonourMaxSpanBytes() {
        let blockSize = 4096
        let headerEnd = 512
        let blocks = 100
        let totalSize = headerEnd + blocks * blockSize
        let cap = 8 * blockSize

        let spans = BC01LanePartition.spans(startOffset: headerEnd, endOffset: totalSize,
                                            blockSize: blockSize, lanes: 4,
                                            maxSpanBytes: cap)

        XCTAssertEqual(spans.count, 13, "100 blocks capped at 8 blocks/span needs 13 spans, not 4")
        for span in spans {
            XCTAssertLessThanOrEqual(span.blockCount, 8, "no span may exceed the block cap")
        }
        // Contiguous, complete, no overlap.
        var expectedIndex = 0
        var cursor = headerEnd
        for span in spans {
            XCTAssertEqual(span.firstBlockIndex, expectedIndex)
            XCTAssertEqual(span.start, cursor)
            expectedIndex += span.blockCount
            cursor += span.length
        }
        XCTAssertEqual(expectedIndex, blocks, "spans must cover every block exactly once")
        XCTAssertEqual(cursor, totalSize, "spans must cover the region to its end")
    }

    /// A cap larger than an even lane split changes nothing — the split is already within bounds.
    func testSpansIgnoreSlackMaxSpanBytes() {
        let blockSize = 4096
        let headerEnd = 512
        let blocks = 16
        let spans = BC01LanePartition.spans(startOffset: headerEnd,
                                            endOffset: headerEnd + blocks * blockSize,
                                            blockSize: blockSize, lanes: 4,
                                            maxSpanBytes: 1024 * blockSize)
        XCTAssertEqual(spans.count, 4, "a slack cap must leave the even lane split intact")
    }
}
