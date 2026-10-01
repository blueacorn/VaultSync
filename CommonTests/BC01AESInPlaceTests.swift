/// Tests for the in-place AES-CBC primitive.
//
//  BC01AESInPlaceTests.swift
//  CommonTests
//
//  Verifies the in-place AES-CBC primitive: round-trips equal the plaintext, length behaves as
//  specified for padded vs. non-padded blocks, and the in-place path matches the allocating wrapper.
//
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import XCTest
import CommonCrypto
@testable import Common

final class BC01AESInPlaceTests: XCTestCase {

    private let key = Data((0..<32).map { UInt8($0) })          // 256-bit key
    private let iv  = Data((0..<16).map { UInt8(0xA0 &+ $0) })  // 128-bit IV

    func testNonPaddedBlockRoundTripsAndPreservesLength() throws {
        let plaintext = Data((0..<4096).map { UInt8($0 & 0xff) }) // exact block multiple

        var ct = plaintext
        try BC01CryptoCommon.aesCBCInPlace(&ct, key: key, iv: iv,
                                           op: CCOperation(kCCEncrypt), pkcs7: false)
        XCTAssertEqual(ct.count, plaintext.count, "non-padded CBC preserves length")
        XCTAssertNotEqual(ct, plaintext)

        var pt = ct
        try BC01CryptoCommon.aesCBCInPlace(&pt, key: key, iv: iv,
                                           op: CCOperation(kCCDecrypt), pkcs7: false)
        XCTAssertEqual(pt, plaintext, "round-trip must recover plaintext")
    }

    func testPaddedFinalBlockGrowsOnEncryptShrinksOnDecrypt() throws {
        let plaintext = Data((0..<100).map { UInt8($0) }) // not a block multiple

        var ct = plaintext
        try BC01CryptoCommon.aesCBCInPlace(&ct, key: key, iv: iv,
                                           op: CCOperation(kCCEncrypt), pkcs7: true)
        // PKCS7 pads up to the next 16-byte boundary (112 for 100 bytes).
        XCTAssertEqual(ct.count, 112, "PKCS7 encrypt grows to block boundary")

        var pt = ct
        try BC01CryptoCommon.aesCBCInPlace(&pt, key: key, iv: iv,
                                           op: CCOperation(kCCDecrypt), pkcs7: true)
        XCTAssertEqual(pt, plaintext, "PKCS7 decrypt shrinks back to plaintext")
    }

    func testInPlaceMatchesAllocatingWrapper() throws {
        for len in [0, 1, 15, 16, 17, 4095, 4096, 4097] {
            let plaintext = Data((0..<len).map { UInt8(($0 * 7) & 0xff) })

            let wrapped = try BC01CryptoCommon.aesCBC(plaintext, key: key, iv: iv,
                                                      op: CCOperation(kCCEncrypt), pkcs7: true)
            var inPlace = plaintext
            try BC01CryptoCommon.aesCBCInPlace(&inPlace, key: key, iv: iv,
                                               op: CCOperation(kCCEncrypt), pkcs7: true)
            XCTAssertEqual(inPlace, wrapped, "in-place must equal wrapper, len=\(len)")
        }
    }
}
