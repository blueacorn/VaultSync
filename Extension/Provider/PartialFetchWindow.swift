/// Sizing policy for byte-range materialisation in `fetchPartialContents`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

/// Sizing policy for byte-range materialisation: how much of an item a
/// `fetchPartialContents` call downloads beyond the system's `minimalRange`.
///
/// The policy is static, stateless and backend-neutral. It balances three costs:
/// - **Bytes**: speculative bytes are downloaded, decrypted and kept on disk. Header
///   scanners (indexers, QuickLook, audits) read a few KiB of many files, so a read at
///   the head must stay small.
/// - **Requests**: every window is one remote round trip and counts against the backend's
///   request throttling, so sequential reads of a large file must not become many small
///   requests.
/// - **Latency**: the call completes only once the whole window is on disk, so the reading
///   app stalls for the full window; the ceiling bounds that stall.
///
/// Rules:
/// ```
/// start  = roundDown(minimalRange.location, alignment)
/// headFloor = isSystemRequest ? headFloorSystem : headFloorStandard
/// window = start == 0 ? headFloor
///          : clamp(fileSize / readAheadFileDivisor, readAheadFloor, readAheadCeiling)
/// end    = start + roundUp(max(minimalRange end - start, window), alignment)
/// fileSize - end <= window  → extend to EOF: [start, fileSize)   (start == 0 → whole file)
/// ```
/// A system or Finder read at offset 0 is a header probe and uses `headFloorSystem`. An app's
/// read at offset 0 uses `headFloorStandard`: the requesting process is not identifiable, so
/// header scanners run by apps (e.g. `bc-audit.py`) cannot be told apart from streaming reads.
/// A read past the head suggests streaming, where read-ahead pays off, scaled to the file so
/// large files take fewer requests. A remainder no larger than one window is absorbed rather
/// than left for a
/// further request; this bounds the extra bytes by the window and subsumes EOF clamping.
/// The start is never moved back: bytes before it were already delivered by earlier reads
/// and must not be downloaded twice.
struct PartialFetchWindow: Equatable {

    /// The download a partial fetch should perform.
    enum Extent: Equatable {
        /// Materialise the entire item.
        case wholeFile
        /// Materialise this range. It starts aligned and either has an aligned length or
        /// ends exactly at `fileSize`.
        case range(NSRange)
    }

    /// Window for a system or Finder read starting at offset 0, in bytes.
    let headFloorSystem: Int
    /// Window for an app's read starting at offset 0, in bytes.
    let headFloorStandard: Int
    /// Minimum window for a read starting past offset 0, in bytes.
    let readAheadFloor: Int
    /// Maximum window for a read starting past offset 0, in bytes.
    let readAheadCeiling: Int
    /// Read-ahead window before clamping is `fileSize / readAheadFileDivisor`.
    let readAheadFileDivisor: Int

    /// The policy configured in the shared container.
    static var configured: PartialFetchWindow {
        let defaults = UserDefaults.sharedContainerDefaults
        return PartialFetchWindow(headFloorSystem: defaults.BRMHeadFloorSystem,
                                  headFloorStandard: defaults.BRMHeadFloorStandard,
                                  readAheadFloor: defaults.BRMReadAheadFloor,
                                  readAheadCeiling: defaults.BRMReadAheadCeiling,
                                  readAheadFileDivisor: defaults.BRMReadAheadFileDivisor)
    }

    /// Read-ahead window for a read starting past offset 0 of a file of `fileSize` bytes.
    func readAheadWindow(fileSize: Int) -> Int {
        let scaled = fileSize / max(readAheadFileDivisor, 1)
        return min(max(scaled, readAheadFloor), max(readAheadCeiling, readAheadFloor))
    }

    /// Compute the download for one `fetchPartialContents` call.
    ///
    /// - Parameters:
    ///   - requested: The system's `minimalRange`.
    ///   - alignment: The system's alignment for this call (a power of two); values `<= 1`
    ///     mean no alignment constraint.
    ///   - fileSize: The item's current `documentSize`, in plaintext bytes.
    ///   - isSystemRequest: The request comes from the system or Finder, so a read at offset 0
    ///     uses `headFloorSystem`; otherwise `headFloorStandard`.
    /// - Returns: An extent that covers `requested` (clipped to `fileSize`).
    func extent(for requested: NSRange, alignment: Int, fileSize: Int,
                isSystemRequest: Bool) -> Extent {
        guard fileSize > 0, requested.location >= 0, requested.length > 0,
              requested.location < fileSize else {
            return .wholeFile
        }
        let unit = max(alignment, 1)
        guard unit & (unit - 1) == 0 else { return .wholeFile }

        let start = FetchRangeAlignment.roundDown(requested.location, to: unit)
        let headFloor = isSystemRequest ? headFloorSystem : headFloorStandard
        let window = start == 0 ? headFloor : readAheadWindow(fileSize: fileSize)
        // The window is rounded too: `alignment` varies per call and across reboots.
        let length = FetchRangeAlignment.roundUp(max(NSMaxRange(requested) - start, window), to: unit)

        if fileSize - (start + length) <= window {
            // EOF is a legal unaligned extent end.
            return start == 0 ? .wholeFile : .range(NSRange(location: start, length: fileSize - start))
        }
        return .range(NSRange(location: start, length: length))
    }
}
