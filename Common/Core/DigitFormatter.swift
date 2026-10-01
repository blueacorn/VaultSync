/// Number input formatting
//
//  Abstract:
//  A number formatter that considers only the digits 0-9 valid.
//
//  Copyright (c) 2024 Apple Inc.
//  SPDX-License-Identifier: MIT
//

import Foundation

class DigitFormatter: NumberFormatter, @unchecked Sendable {
    override func isPartialStringValid(_ partialString: String, newEditingString _: AutoreleasingUnsafeMutablePointer<NSString?>?,
                                       errorDescription _: AutoreleasingUnsafeMutablePointer<NSString?>?) -> Bool {
        guard !partialString.isEmpty else { return true }
        return UInt(partialString) != nil // Return true if only the characters 0-9 are present.
    }
}
