/// Unit tests for `GraphContentPutter`.
//
//  GraphContentPutterTests.swift
//  ExtensionTests
//
//  `GraphContentPutter` opens its upload session lazily: a single-request upload never
//  pays `createUploadSession`, and a failed single-request upload never sends a cancel.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Extension

/// Records every Graph upload call without touching the network.
private final class FakeGraphTransport: GraphUploadTransport, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var wholePuts: [(url: URL, eTag: String?, count: Int)] = []
    private(set) var sessionsCreated: [(url: URL, eTag: String?)] = []
    private(set) var fragments: [(start: Int, count: Int, uploadURL: URL)] = []
    private(set) var cancelled: [URL] = []
    let uploadURL = URL(string: "https://upload.example/session/1")!

    func putWholeContent(_ bytes: Data, contentURL: URL, eTag: String?) async throws -> Data {
        lock.withLock { wholePuts.append((contentURL, eTag, bytes.count)) }
        return Data("{}".utf8)
    }

    func createUploadSession(at createURL: URL, eTag: String?) async throws -> URL {
        lock.withLock { sessionsCreated.append((createURL, eTag)) }
        return uploadURL
    }

    func putFragment(_ bytes: Data, start: Int, totalSize: Int, uploadURL: URL) async throws -> Data? {
        lock.withLock { fragments.append((start, bytes.count, uploadURL)) }
        return start + bytes.count >= totalSize ? Data("{}".utf8) : nil
    }

    func cancelUploadSession(_ uploadURL: URL) async {
        lock.withLock { cancelled.append(uploadURL) }
    }
}

final class GraphContentPutterTests: XCTestCase {

    private let target = GraphContentPutter.Target(
        contentURL: URL(string: "https://graph.example/items/x/content")!,
        createSessionURL: URL(string: "https://graph.example/items/x/createUploadSession")!)

    func testSingleRequestLimitIsSimpleUploadLimit() {
        let putter = GraphContentPutter(transport: FakeGraphTransport(), target: target, eTag: nil)
        XCTAssertEqual(putter.singleRequestLimit, 4 * 1024 * 1024)
    }

    func testPutWholeNeverCreatesSession() async throws {
        let transport = FakeGraphTransport()
        let putter = GraphContentPutter(transport: transport, target: target, eTag: "etag-1")
        _ = try await putter.putWhole(Data(count: 10))
        XCTAssertEqual(transport.wholePuts.count, 1)
        XCTAssertEqual(transport.wholePuts.first?.url, target.contentURL)
        XCTAssertEqual(transport.wholePuts.first?.eTag, "etag-1")
        XCTAssertTrue(transport.sessionsCreated.isEmpty)
    }

    func testFirstPutRangeCreatesExactlyOneSession() async throws {
        let transport = FakeGraphTransport()
        let putter = GraphContentPutter(transport: transport, target: target, eTag: "etag-2")
        _ = try await putter.putRange(Data(count: 10), start: 0, totalSize: 30)
        _ = try await putter.putRange(Data(count: 10), start: 10, totalSize: 30)
        _ = try await putter.putRange(Data(count: 10), start: 20, totalSize: 30)
        XCTAssertEqual(transport.sessionsCreated.count, 1)
        XCTAssertEqual(transport.sessionsCreated.first?.url, target.createSessionURL)
        XCTAssertEqual(transport.sessionsCreated.first?.eTag, "etag-2")
        XCTAssertEqual(transport.fragments.map(\.uploadURL), Array(repeating: transport.uploadURL, count: 3))
    }

    func testConcurrentFirstFragmentsShareOneSession() async throws {
        let transport = FakeGraphTransport()
        let putter = GraphContentPutter(transport: transport, target: target, eTag: nil)
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<8 {
                group.addTask { _ = try await putter.putRange(Data(count: 1), start: i, totalSize: 100) }
            }
            try await group.waitForAll()
        }
        XCTAssertEqual(transport.sessionsCreated.count, 1)
    }

    func testCancelWithoutSessionSendsNothing() async throws {
        let transport = FakeGraphTransport()
        let putter = GraphContentPutter(transport: transport, target: target, eTag: nil)
        _ = try await putter.putWhole(Data(count: 1))
        await putter.cancelSession()
        XCTAssertTrue(transport.cancelled.isEmpty)
    }

    func testCancelAfterSessionCancelsIt() async throws {
        let transport = FakeGraphTransport()
        let putter = GraphContentPutter(transport: transport, target: target, eTag: nil)
        _ = try await putter.putRange(Data(count: 1), start: 0, totalSize: 10)
        await putter.cancelSession()
        XCTAssertEqual(transport.cancelled, [transport.uploadURL])
    }

    /// End to end through the uploader: a small file is one simple PUT and no session.
    func testUploaderSmallFileUsesSimplePutOnly() async throws {
        let src = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: src) }
        try Data(count: 1000).write(to: src)
        let transport = FakeGraphTransport()
        let putter = GraphContentPutter(transport: transport, target: target, eTag: nil)
        _ = try await ContentStreamUploader(putter: putter, encryptor: PlainFileEncryptor(), lanes: 1)
            .run(from: src, originalFilename: "a.bin", progress: Progress())
        XCTAssertEqual(transport.wholePuts.count, 1)
        XCTAssertTrue(transport.sessionsCreated.isEmpty)
        XCTAssertTrue(transport.fragments.isEmpty)
    }
}
