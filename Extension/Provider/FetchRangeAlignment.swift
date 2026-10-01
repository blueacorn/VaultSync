/// Alignment rules for `fetchPartialContents` ranges.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Alignment rules for `fetchPartialContents` ranges.
///
/// The system passes a power-of-two `alignment` on every call; it is not stable across reboots,
/// so ranges are aligned per call, never cached. A fetched range must start on a multiple of
/// `alignment` and have a length that is a multiple of it, except that it may end unaligned
/// exactly at the item's `documentSize`. Content sits in the reply file at its absolute offset,
/// so a range can be narrowed without touching the file.
enum FetchRangeAlignment {

    /// Round `value` down to a multiple of `alignment` (a power of two).
    static func roundDown(_ value: Int, to alignment: Int) -> Int {
        value & ~(alignment - 1)
    }

    /// Round `value` up to a multiple of `alignment` (a power of two).
    static func roundUp(_ value: Int, to alignment: Int) -> Int {
        (value + alignment - 1) & ~(alignment - 1)
    }

    /// Narrow a backend-reported reply window to the largest aligned range inside it.
    ///
    /// - Parameters:
    ///   - window: The range the backend wrote to the reply file.
    ///   - requested: The range the system asked for.
    ///   - alignment: The system's alignment for this call (a power of two).
    ///   - documentSize: The `documentSize` published with the reply item; the only legal
    ///     unaligned end.
    /// - Returns: An aligned range within `window` that covers `requested` (clipped to
    ///   `documentSize`), or `nil` when no such range exists.
    static func alignedReply(_ window: NSRange, covering requested: NSRange,
                             alignment: Int, documentSize: Int) -> NSRange? {
        guard alignment > 0, alignment & (alignment - 1) == 0 else { return nil }
        let start = roundUp(window.location, to: alignment)
        let windowEnd = min(NSMaxRange(window), documentSize)
        let end = windowEnd == documentSize ? windowEnd : roundDown(windowEnd, to: alignment)
        let requiredEnd = min(NSMaxRange(requested), documentSize)
        guard start <= requested.location, end >= requiredEnd, end > start else { return nil }
        return NSRange(location: start, length: end - start)
    }
}
