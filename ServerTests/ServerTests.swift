/// Unit tests for `Server`.
//
//  ServerTests.swift
//  ServerTests
//
//  Created by Home on 2026-06-15.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import Common
@testable import Server

final class ServerTests: XCTestCase {

    // MARK: - Account management before `run()`

    private func makeUnrunServer() -> StandaloneServer {
        StandaloneServer(URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("\(UUID().uuidString).db"))
    }

    /// The server is started lazily, only once an emulator-backed domain exists. Deleting a
    /// cloud-only vault therefore reaches `removeAccount` with no database open — it must be a
    /// no-op rather than a crash (it force-unwrapped `itemDB` and trapped).
    func testRemoveAccountIsNoOpWhenNotRunning() throws {
        let server = makeUnrunServer()
        XCTAssertFalse(server.isRunning, "precondition: never started")
        XCTAssertNoThrow(try server.removeAccount(domainIdentifier: UUID().uuidString))
    }

    /// Provisioning genuinely needs the database, so it reports the failure instead of
    /// silently doing nothing.
    func testProvisionAccountThrowsWhenNotRunning() throws {
        let server = makeUnrunServer()
        XCTAssertThrowsError(try server.provisionAccount(domainIdentifier: UUID().uuidString))
        XCTAssertThrowsError(try server.resetSyncAnchor(domainIdentifier: UUID().uuidString))
    }

    // MARK: - Lifecycle

    /// A server that was built but never run must be safe to release. Its notify throttle owns a
    /// `DispatchSource` created suspended, and releasing a suspended source traps in libdispatch
    /// — this test crashed the whole test runner before `Throttle.deinit` cancelled it.
    func testUnrunServerIsSafeToDeallocate() throws {
        for _ in 0..<10 {
            _ = makeUnrunServer()
        }
        XCTAssertTrue(true, "reaching here means no dispatch trap on release")
    }

    /// `close()` on a server that never ran is safe and idempotent.
    func testCloseOnUnrunServerIsSafeAndIdempotent() throws {
        let server = makeUnrunServer()
        server.close()
        server.close()
        XCTAssertFalse(server.isRunning)
    }

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }

}
