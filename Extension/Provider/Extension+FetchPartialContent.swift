/// Byte-range materialisation (BRM) for the file provider extension.
///
/// Implements `NSFileProviderPartialContentFetching` — sparse, block-aligned downloads —
/// split out of `Extension.swift`.
// Copyright (c) 2024 Apple Inc.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import FileProvider
import Common
import os.log

#if os(macOS)

extension Extension: NSFileProviderPartialContentFetching {
    public func fetchPartialContents(for itemIdentifier: NSFileProviderItemIdentifier,
                                     version requestedVersion: NSFileProviderItemVersion,
                                     request: NSFileProviderRequest,
                                     minimalRange range: NSRange,
                                     aligningTo alignment: Int,
                                     options: NSFileProviderFetchContentsOptions,
                                     completionHandler:
                                     @escaping (URL?, NSFileProviderItem?, NSRange,
                                                NSFileProviderMaterializationFlags,
                                                Error?) -> Void) -> Progress
    {

        let resolvedBackend: ProviderBackend
        do { resolvedBackend = try requireBackend() } catch {
            completionHandler(nil, nil, range, [], error)
            return Progress()
        }

        // Capability gate: only backends that can serve an explicit plaintext byte range get
        // the range. Others fall through to whole-file materialisation via `fetchContentsInternal`.
        let requestedRange: NSRange? = resolvedBackend.supportsByteRangeMaterialisation ? range : nil

        logger.debugPublic("➡️  fetchPartialContents(for:\(itemIdentifier.rawValue)) @ range(\(range.location),\(range.length)) domainVersion(\(request.domainVersion?.description ?? "<nil>"))")

        return fetchContentsInternal(for: itemIdentifier,
                                     version: requestedVersion,
                                     range: requestedRange,
                                     request: request,
                                     alignment: alignment,
                                     completionHandler: { (url: URL?, item: NSFileProviderItem?,
                                                           returnRange: NSRange?,
                                                           error: Error?) -> Void in
            guard let returnRange = returnRange else {
                completionHandler(url, item, range, [], error)
                return
            }
            // The OS requires the returned extent to be `alignment`-aligned and to fully cover
            // the requested `minimalRange`; an unaligned extent is rejected with
            // __FILEPROVIDER_BAD_EXTENT__. The materialised window's length is a plaintext byte
            // count (for `.bc`, whatever the covering block window decrypted to) and so is not
            // aligned in general — round the end up, clamping to the item's plaintext size so we
            // never claim bytes past EOF. `documentSize` here is whatever the item carries from
            // enumeration — exact once a prior download has recorded the plaintext size
            // (MetadataCache.plaintext_size), the ciphertext-derived estimate before that. It is
            // deliberately NOT overridden on this path: see the ranged branch of
            // `fetchContentsInline` for why the system ignores a partial fetch's documentSize.
            let plaintextSize = (item?.documentSize ?? nil)?.intValue
            completionHandler(url, item,
                              Self.alignReturnedExtent(returnRange,
                                                       alignment: alignment,
                                                       plaintextSize: plaintextSize),
                              [], error)
        })
    }

    /// Round a materialised extent out to `alignment` so it satisfies the File Provider's
    /// aligned-extent contract, clamping the end to `plaintextSize` (EOF is a legal,
    /// otherwise-unaligned extent end).
    ///
    /// - Parameters:
    ///   - extent: The window actually written to disk, in plaintext bytes.
    ///   - alignment: The OS-requested alignment; `<= 1` means no alignment constraint.
    ///   - plaintextSize: The item's full decrypted length, if known.
    /// - Returns: An aligned extent containing `extent`.
    static func alignReturnedExtent(_ extent: NSRange,
                                    alignment: Int,
                                    plaintextSize: Int?) -> NSRange {
        guard alignment > 1, extent.length > 0 else { return extent }

        let alignedStart = extent.location & ~(alignment - 1)
        let end = extent.location + extent.length
        var alignedEnd = (end + alignment - 1) & ~(alignment - 1)
        if let plaintextSize = plaintextSize, alignedEnd > plaintextSize {
            alignedEnd = max(end, plaintextSize)
        }
        return NSRange(location: alignedStart, length: alignedEnd - alignedStart)
    }
}

#endif
