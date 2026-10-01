/// Unit tests for `BC01Framing`.
//
//  BC01FramingTests.swift
//  CommonTests
//
//  Pins the empirically derived BC01 framing (reserved header size + PKCS7 padding) against
//  Boxcryptor-written files, and the inverse plaintext-size estimate.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
@testable import Common

final class BC01FramingTests: XCTestCase {

    /// (plaintext, headerEnd, ciphertext) read from Boxcryptor-written files.
    private let samples: [(p: Int64, header: Int64, c: Int64)] = [
        (0, 4096, 4096),
        (1, 4096, 4112),
        (12_044, 4096, 16_144),
        (409_600, 4096, 413_696),
        (819_100, 4096, 823_200),
        (819_101, 8192, 827_296),          // byte-exact 1% boundary
        (819_200, 8192, 827_392),
        (1_052_783, 8192, 1_060_976),
        (1_228_700, 8192, 1_236_896),
        (1_228_701, 12_288, 1_240_992),
        (1_638_300, 12_288, 1_650_592),
        (1_638_301, 16_384, 1_654_688),
        (10_485_759, 102_400, 10_588_160),
        (10_485_760, 131_072, 10_616_832), // 10 MiB: flat 128 KiB
        (16_648_927, 131_072, 16_780_000), // _MG_3913.jpg
        (94_372_871, 131_072, 94_503_952),
    ]

    func testHeaderSizeMatchesBoxcryptor() {
        for s in samples {
            XCTAssertEqual(BC01Framing.headerSize(plaintextSize: s.p), s.header, "p=\(s.p)")
        }
    }

    func testCiphertextSizeMatchesBoxcryptor() {
        for s in samples {
            XCTAssertEqual(BC01Framing.ciphertextSize(plaintextSize: s.p), s.c, "p=\(s.p)")
        }
    }

    func testCipherPadding() {
        XCTAssertEqual(BC01Framing.cipherPadding(plaintextSize: 409_600), 0, "full last block")
        XCTAssertEqual(BC01Framing.cipherPadding(plaintextSize: 11_000_000), 16, "aligned to 16, partial block")
        XCTAssertEqual(BC01Framing.cipherPadding(plaintextSize: 819_199), 1)
    }

    /// The estimate is never below the true size and at most 15 bytes above it.
    func testEstimateBoundsTrueSize() {
        for s in samples {
            guard let estimate = BC01Framing.estimatedPlaintextSize(ciphertextSize: s.c) else {
                return XCTFail("no estimate for c=\(s.c)")
            }
            XCTAssertGreaterThanOrEqual(estimate, s.p, "c=\(s.c)")
            XCTAssertLessThanOrEqual(estimate - s.p, 15, "c=\(s.c)")
        }
    }

    /// Round trip over a dense sweep: every plaintext length's ciphertext estimates back within bounds.
    func testEstimateRoundTripSweep() {
        for p in stride(from: Int64(0), through: 12_000_000, by: 9_973) {
            let estimate = BC01Framing.estimatedPlaintextSize(
                ciphertextSize: BC01Framing.ciphertextSize(plaintextSize: p))
            XCTAssertNotNil(estimate, "p=\(p)")
            XCTAssertTrue((p...(p + 15)).contains(estimate ?? -1), "p=\(p) estimate=\(String(describing: estimate))")
        }
    }

    func testNonFramedSizeHasNoEstimate() {
        XCTAssertNil(BC01Framing.estimatedPlaintextSize(ciphertextSize: 5000), "not a 16-byte multiple")
        XCTAssertNil(BC01Framing.estimatedPlaintextSize(ciphertextSize: 100), "smaller than one header")
    }

    func testTranslatorPublishesEstimateForEncryptedName() {
        let bc01 = BoxcryptorMetadataTranslator(algorithm: .bc01)
        XCTAssertEqual(bc01.estimatedDisplaySize(forBackendSize: 16_780_000, name: "_MG_3913.jpg.bc"), 16_648_927)
        XCTAssertEqual(bc01.estimatedDisplaySize(forBackendSize: 8192, name: "notes.txt"), 8192, "plain name exact")
    }
}
