/// Boxcryptor BC01 file on-disk framing
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

/// Boxcryptor BC01 on-disk framing: how a plaintext length maps to a ciphertext length, and the
/// inverse estimate used before a file's header has been read.
///
/// ## Layout
///
/// ```
/// ciphertext = headerEnd + plaintext + cipherPadding
/// ```
///
/// - `headerEnd` — the reserved header region: raw header (48 B) + JSON core + zero padding.
///   The JSON core is ~1 KB; Boxcryptor reserves more so the header can grow in place.
/// - `cipherPadding` — PKCS7 padding of the final 4 KB block.
///
/// ## Reserved header size
///
/// Determined empirically from Boxcryptor-written files (92 samples, including byte-exact
/// boundary probes at 819,100/819,101, 1,228,700/1,228,701 and 1,638,300/1,638,301):
///
/// ```
/// headerEnd(p) = 128 KiB                                      if p >= 10 MiB
///              = max(4 KiB, floor(ceil(p / 100) / 4 KiB) * 4 KiB)  otherwise
/// ```
///
/// i.e. 1% of the plaintext (rounded up to a whole byte), rounded down to a 4 KiB multiple,
/// at least one 4 KiB block; a flat 128 KiB from 10 MiB up.
///
/// - Note: Older Boxcryptor versions may round the reserve *up* to the next 4 KiB multiple
///   (e.g. 102,400 instead of 98,304 for a 10,075,148-byte plaintext). For such files
///   ``estimatedPlaintextSize(ciphertextSize:)`` is ~4 KiB larger than the actual plaintext;
///   the header-derived exact size is unaffected.
///
/// ## Cipher padding
///
/// ```
/// cipherPadding(p) = 0              if p % 4096 == 0   (last block full: no padding)
///                  = 16 - p % 16    otherwise          (PKCS7: 1…16)
/// ```
///
/// ## Inverse (estimate)
///
/// From the ciphertext length alone `headerEnd` is unambiguous (verified across the corpus), but
/// `cipherPadding` is not: up to 16 plaintext lengths share one ciphertext length. The estimate
/// therefore returns the **largest** consistent plaintext length — never below the true length,
/// and at most 15 bytes above it. The exact value needs the header's `cipherPadding` field
/// (bytes 12–15), see ``BC01CryptoCommon/exactPlaintextSize(header:remoteSize:)``.
public enum BC01Framing {

    /// Header/body block size (also the reserved-header granularity).
    public static let blockSize: Int64 = 4096
    /// Reserved header size for plaintexts of ``largeFileThreshold`` bytes or more.
    public static let largeFileHeaderSize: Int64 = 128 * 1024
    /// Plaintext length from which the header reserve is ``largeFileHeaderSize``.
    public static let largeFileThreshold: Int64 = 10 * 1024 * 1024
    /// AES block size; PKCS7 padding is 1…`aesBlockSize` bytes.
    public static let aesBlockSize: Int64 = 16

    /// Every reserved header size Boxcryptor can write: 4 KiB multiples up to ``largeFileHeaderSize``.
    private static let headerCandidates: [Int64] =
        (1...(largeFileHeaderSize / blockSize)).map { $0 * blockSize }

    /// Reserved header size (`headerEnd`) Boxcryptor writes for a plaintext of `plaintextSize` bytes.
    public static func headerSize(plaintextSize p: Int64) -> Int64 {
        if p >= largeFileThreshold { return largeFileHeaderSize }
        let onePercent = (p + 99) / 100                                   // ceil(p / 100)
        return max(blockSize, onePercent / blockSize * blockSize)         // floor to 4 KiB
    }

    /// PKCS7 padding appended to a plaintext of `plaintextSize` bytes.
    public static func cipherPadding(plaintextSize p: Int64) -> Int64 {
        p % blockSize == 0 ? 0 : aesBlockSize - p % aesBlockSize
    }

    /// Ciphertext length of a plaintext of `plaintextSize` bytes.
    public static func ciphertextSize(plaintextSize p: Int64) -> Int64 {
        headerSize(plaintextSize: p) + p + cipherPadding(plaintextSize: p)
    }

    /// Estimated plaintext length for a ciphertext of `ciphertextSize` bytes: the largest
    /// plaintext length that frames to exactly that ciphertext length.
    ///
    /// - Returns: The estimate (exact to within 15 bytes, never below the true length), or `nil`
    ///   when no plaintext length frames to `ciphertextSize` (not a Boxcryptor-framed file).
    ///
    /// Error rate: an app that plans reads from `stat` in fixed chunks of `B` bytes fails when
    /// `ceil(estimate / B) != ceil(true / B)`, i.e. when a chunk boundary lies within the
    /// overestimate `e = cipherPadding - 1` (uniform 0…15, mean 7.5 B). `P(fail) ≈ 7.5 / B`:
    /// for Ente (`B` = 4 MiB) ≈ 1 in 560,000 files (vs ≈ 3% publishing the ciphertext length
    /// with a 128 KiB header). Zero once the exact size is resolved.
    public static func estimatedPlaintextSize(ciphertextSize c: Int64) -> Int64? {
        var best: Int64?
        for header in headerCandidates where header <= c {
            let body = c - header
            // Plaintext is `body` (no padding) or `body - 1 … body - 16` (PKCS7).
            for p in stride(from: body, through: max(0, body - aesBlockSize), by: -1)
            where ciphertextSize(plaintextSize: p) == c {
                best = max(best ?? p, p)
                break
            }
        }
        return best
    }
}
