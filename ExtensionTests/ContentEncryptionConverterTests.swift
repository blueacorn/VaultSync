/// Unit tests for `ContentEncryptionConverter`.
//
//  ContentEncryptionConverterTests.swift
//  ExtensionTests
//
//  Covers the safe file-to-file conversion primitive.
//  The converter must:
//   - produce a verified item on the happy path;
//   - never remove the original until the new item is created AND verified;
//   - roll back (delete) the new item and keep the original when verification fails;
//   - propagate a create failure (e.g. no key) without deleting anything;
//   - honour the trash-vs-delete removal policy;
//   - abort (no side effects) on a source-revision mismatch;
//   - leave no temp file behind.
//
//  The converter takes injected effect closures, so these tests drive it with file-backed fakes
//  rather than a live backend / File Provider host (see [[extract-refactor-for-testability]]).
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import Common
@testable import Extension

final class ContentEncryptionConverterTests: XCTestCase {

    // MARK: - Fixtures

    private func entry(name: String, id: String, parent: String = "p", revision: Int64 = 1) -> DomainService.Entry {
        DomainService.Entry(
            name: name,
            id: DomainService.ItemIdentifier(id),
            parent: DomainService.ItemIdentifier(parent),
            revision: DomainService.Version(content: revision, metadata: revision),
            deleted: false, size: Int64(name.count), children: nil, type: .file,
            metadata: .empty,
            userInfo: .init(conflictCount: nil, originatorName: nil, symlinkTargetPath: nil,
                            implicitLockOwner: nil, quotaRemaining: nil, quotaTotal: nil))
    }

    /// Records the effects the converter drives so each test can assert ordering/outcomes.
    private final class Recorder {
        var created: [(parent: String, name: String, contents: Data)] = []
        var deleted: [String] = []
        var trashed: [String] = []
        /// Every temp file handed to the converter by `downloadPlaintext`.
        var downloads: [URL] = []
    }

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("converter-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// Builds a converter over an in-memory store. `downloadPlaintext` writes an item's stored
    /// bytes to a fresh temp file; `createFile` stores the source file's bytes under a new id.
    private func makeConverter(recorder: Recorder,
                               sources: [String: Data],
                               createOverride: ((URL) throws -> Void)? = nil,
                               readBackOverride: Data? = nil) -> ContentEncryptionConverter {
        var store = sources
        let dir = tempDir!
        return ContentEncryptionConverter(
            downloadPlaintext: { id in
                let bytes = id.id.hasPrefix("new-") ? (readBackOverride ?? store[id.id]) : store[id.id]
                let url = dir.appendingPathComponent(UUID().uuidString)
                try (bytes ?? Data()).write(to: url)
                recorder.downloads.append(url)
                return url
            },
            createFile: { parent, name, url, _ in
                try createOverride?(url)
                let contents = try Data(contentsOf: url)
                recorder.created.append((parent.id, name, contents))
                let id = "new-\(name)"
                store[id] = contents
                return self.entry(name: name, id: id, parent: parent.id, revision: 9)
            },
            deleteItem: { id, _ in recorder.deleted.append(id.id) },
            trashItem: { id, _ in recorder.trashed.append(id.id) })
    }

    private func assertNoTempFilesLeft(_ rec: Recorder, file: StaticString = #filePath, line: UInt = #line) {
        for url in rec.downloads {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                           "temp file left behind: \(url.lastPathComponent)", file: file, line: line)
        }
    }

    // MARK: - Tests

    func testHappyPath_createsVerifiedItem_andTrashesOriginal() async throws {
        let rec = Recorder()
        let converter = makeConverter(recorder: rec, sources: ["src1": Data("hello".utf8)])
        let source = entry(name: "notes.txt", id: "src1")

        let result = try await converter.convert(source: source,
                                                 targetName: "notes.txt.bc",
                                                 encryptor: PlainFileEncryptor(),
                                                 removeOriginal: .trash)

        XCTAssertEqual(result.name, "notes.txt.bc")
        XCTAssertEqual(rec.created.map { $0.name }, ["notes.txt.bc"])
        XCTAssertEqual(rec.created.first?.contents, Data("hello".utf8))
        XCTAssertEqual(rec.trashed, ["src1"])           // original trashed
        XCTAssertTrue(rec.deleted.isEmpty)              // nothing rolled back
        XCTAssertEqual(rec.downloads.count, 2)          // source + read-back
        assertNoTempFilesLeft(rec)
    }

    func testDeletePolicy_hardDeletesOriginal() async throws {
        let rec = Recorder()
        let converter = makeConverter(recorder: rec, sources: ["src2": Data("x".utf8)])
        let source = entry(name: "a.txt", id: "src2")

        _ = try await converter.convert(source: source, targetName: "a.txt.bc",
                                        encryptor: PlainFileEncryptor(), removeOriginal: .delete)

        XCTAssertEqual(rec.deleted, ["src2"])           // original hard-deleted
        XCTAssertTrue(rec.trashed.isEmpty)
    }

    func testKeepOriginal_whenPolicyNil() async throws {
        let rec = Recorder()
        let converter = makeConverter(recorder: rec, sources: ["src3": Data("x".utf8)])
        let source = entry(name: "a.txt", id: "src3")

        _ = try await converter.convert(source: source, targetName: "a.txt copy.bc",
                                        encryptor: PlainFileEncryptor(), removeOriginal: nil)

        XCTAssertEqual(rec.created.map { $0.name }, ["a.txt copy.bc"])
        XCTAssertTrue(rec.deleted.isEmpty)              // copy action keeps original
        XCTAssertTrue(rec.trashed.isEmpty)
        assertNoTempFilesLeft(rec)
    }

    func testVerificationFailure_rollsBackNewItem_keepsOriginal() async throws {
        let rec = Recorder()
        // read-back returns the wrong bytes → verification must fail.
        let converter = makeConverter(recorder: rec, sources: ["src4": Data("good".utf8)],
                                      readBackOverride: Data("gooD".utf8))
        let source = entry(name: "a.txt", id: "src4")

        do {
            _ = try await converter.convert(source: source, targetName: "a.txt.bc",
                                            encryptor: PlainFileEncryptor(), removeOriginal: .trash)
            XCTFail("expected verificationFailed")
        } catch ContentEncryptionConverterError.verificationFailed {
            // expected
        }

        XCTAssertEqual(rec.created.map { $0.name }, ["a.txt.bc"])
        XCTAssertEqual(rec.deleted, ["new-a.txt.bc"])   // new item rolled back
        XCTAssertTrue(rec.trashed.isEmpty)              // original untouched
        assertNoTempFilesLeft(rec)
    }

    func testCreateFailure_nothingCreatedOrDeleted() async throws {
        let rec = Recorder()
        struct NoKey: Error {}
        let converter = makeConverter(recorder: rec, sources: ["src5": Data("x".utf8)],
                                      createOverride: { _ in throw NoKey() })
        let source = entry(name: "a.txt", id: "src5")

        do {
            _ = try await converter.convert(source: source, targetName: "a.txt.bc",
                                            encryptor: PlainFileEncryptor(), removeOriginal: .trash)
            XCTFail("expected create to throw")
        } catch is NoKey {
            // expected
        }

        XCTAssertTrue(rec.created.isEmpty)              // never created
        XCTAssertTrue(rec.deleted.isEmpty)              // nothing to roll back
        XCTAssertTrue(rec.trashed.isEmpty)              // original untouched
        assertNoTempFilesLeft(rec)
    }

    func testRevisionMismatch_abortsBeforeDownloadOrUpload() async throws {
        let rec = Recorder()
        let converter = makeConverter(recorder: rec, sources: ["src6": Data("x".utf8)])
        let source = entry(name: "a.txt", id: "src6", revision: 1)
        let stale = DomainService.Version(content: 2, metadata: 2)

        do {
            _ = try await converter.convert(source: source, targetName: "a.txt.bc",
                                            encryptor: PlainFileEncryptor(), removeOriginal: .trash,
                                            expectedRevision: stale)
            XCTFail("expected revisionMismatch")
        } catch ContentEncryptionConverterError.revisionMismatch {
            // expected
        }

        XCTAssertTrue(rec.downloads.isEmpty)
        XCTAssertTrue(rec.created.isEmpty)
        XCTAssertTrue(rec.deleted.isEmpty)
        XCTAssertTrue(rec.trashed.isEmpty)
    }
}
