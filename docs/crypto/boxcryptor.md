# Boxcryptor Reference

VaultSync reads and writes the Boxcryptor-compatible **BC01** format. Boxcryptor is a
third-party product; VaultSync is not affiliated with it. This document specifies the on-disk
layouts and the file encrypt/decrypt algorithms as VaultSync implements them.

Contents:
- [1. Key file — `.bckey`](#1-key-file--bckey)
- [2. Encrypted file — `.bc`](#2-encrypted-file--bc)
- [3. Decrypting a file](#3-decrypting-a-file)
- [4. Encrypting a file](#4-encrypting-a-file)
- [5. Folder key — `FolderKey.bch`](#5-folder-key--folderkeybch)
- [6. Implementation notes](#6-implementation-notes)

Related: [boxcryptor-keys.md](/docs/crypto/boxcryptor-keys.md) (key chain inside `.bckey`),
[boxcryptor-filename.md](/docs/crypto/boxcryptor-filename.md) (filename encryption, reference
only), [application.md](/docs/crypto/application.md) (how VaultSync stores the keys).

Byte ranges use slice notation `[start:stop]`, e.g. `[0:32]` = bytes 0–31. Integers are
little-endian.

## 1. Key file — `.bckey`

JSON. Holds the user's key chain. Fields VaultSync reads are marked `*`.

```
{
  "artifact": "keyfile",
  "version": 1,
  "users": [
    {
      "id":            "<user id>",                                    *
      "publicKey":     "<base64 RSA public key, DER SubjectPublicKeyInfo>",
      "privateKey":    "<base64 wrapped blob, key = pwdKey; plaintext = base64(PKCS#1 DER)>",  *
      "aesKey":        "<base64 RSA-OAEP-SHA1 ciphertext>",
      "wrappingKey":   "<base64 wrapped blob, key = pwdKey>",
      "keys": {
        "filename":    "<base64 wrapped blob, key = wrappingKey>",
        ...
      },
      "salt":          "<base64 PBKDF2 salt>",                          *
      "kdfIterations": 10000,                                           *
      ...
    }
  ],
  ...
}
```

VaultSync uses `users[0]` only. Wrapped-blob layout and the unwrap chain are in
[boxcryptor-keys.md](/docs/crypto/boxcryptor-keys.md).

## 2. Encrypted file — `.bc`

### 2.1 Layout

```
Offset                     Size             Field
0                          48               Raw header
48                         header_core_len  JSON core header
48 + header_core_len       header_pad_len   Zero padding (reserved header space)
header_end                 ...              Encrypted content blocks

header_end = 48 + header_core_len + header_pad_len      (multiple of 4096; §2.6)
ciphertext_size = header_end + plaintext_size + cipher_padding
```

### 2.2 Raw header

```
Offset  Size  Type       Field
0       4     ASCII      magic "bc01" (62 63 30 31)
4       4     uint32 LE  header_core_len
8       4     uint32 LE  header_pad_len
12      4     uint32 LE  cipher_padding   PKCS7 byte count of the last block, 0…16 (§2.5)
16      32    bytes      header_hmac = HMAC-SHA256(file_key.mac, JSON core bytes)
```

`header_hmac` is written although the JSON says `"mac": {"enabled": false}`. Boxcryptor
serialises the JSON core with non-deterministic key order, and for roughly half its files the
HMAC matches a differently ordered serialisation rather than the on-disk bytes, so it cannot be
verified from the file alone. VaultSync therefore classifies it:

| Status | Condition |
|---|---|
| `verified` | matches the on-disk JSON core |
| `mismatch` | anything else |

`mismatch` is logged and accepted by default. The per-domain feature flag
`bc01HeaderHMACWarnOnly` (default `true`) set to `false` makes it fatal. VaultSync-written files
always verify: the HMAC is computed over the exact bytes written.

### 2.3 JSON core header

```json
{
  "artifact": "header",
  "cipher": {
    "algorithm": "AES",
    "blockSize": 4096,
    "iv": "<base64 base_iv, 16 B>",
    "keySize": 256,
    "mac": { "enabled": false },
    "mode": "CBC",
    "padding": "PKCS7"
  },
  "encryptedFileKeys": [
    { "id": "<users[].id>", "type": "data", "value": "<base64 RSA-OAEP-SHA1(file key)>" }
  ],
  "metadata": { "name": { "encrypted": false, "value": "<original filename>" } },
  "version": 1
}
```

- A shared file carries one `encryptedFileKeys` entry per recipient. Decrypt selects the entry
  whose `id` equals the stored `users[0].id`, and fails fast without an RSA operation when none
  matches.
- `metadata.name` may be encrypted in Boxcryptor-written files
  ([boxcryptor-filename.md](/docs/crypto/boxcryptor-filename.md)). VaultSync never reads it; the
  display name comes from the backend filename with `.bc` stripped. VaultSync writes it
  unencrypted.

### 2.4 File key

Stored in JSON core header field `encryptedFileKeys[].value`. RSA-OAEP-SHA1 plaintext:

```
96-byte key:
  [0:32]   checksum = SHA-256(file_key[32:96])
  [32:64]  content key  AES-256: block encryption and per-block IV derivation
  [64:96]  mac key      HMAC-SHA256 key for header_hmac
```

A 96-byte key with a bad checksum, or any other length, is rejected. VaultSync writes only
96-byte keys. Implementation: [BC01FileKey.swift](/Common/Crypto/Boxcryptor/BC01FileKey.swift).

### 2.5 `cipher_padding`

```
plaintext_size % 4096 == 0   →  0               last block full (or empty file): no PKCS7
otherwise                    →  16 − size % 16  PKCS7, 1…16
```

PKCS7 is measured in 16-byte AES units but applied only to a **short** last block. A last block
of 16 or 4080 bytes takes a full 16-byte pad; a full 4096-byte last block takes none. The field
is a byte count, not a flag. Decrypt unpads the last block iff `cipher_padding > 0`.

### 2.6 Reserved header size

The header region is sized from the plaintext length so the header can grow in place (the JSON
core is ~1 KB):

```
header_end(p) = 128 KiB                                             if p ≥ 10 MiB
              = max(4 KiB, floor(ceil(p / 100) / 4 KiB) · 4 KiB)    otherwise
```

1% of the plaintext, rounded down to a 4 KiB multiple, at least 4 KiB; flat 128 KiB from
10,485,760 B. Older Boxcryptor versions may round *up* instead (e.g. 102,400 rather than 98,304
for a 10,075,148 B plaintext); only the pre-header size estimate is affected.

VaultSync writes exactly this reserve, and refuses to write a header whose core does not fit it
(`BC01Error.headerExceedsReserve`), so every file it produces frames like a Boxcryptor file.

### 2.7 Plaintext size from ciphertext size

- **Exact** (header parsed): `plaintext = ciphertext_size − header_end − cipher_padding`.
- **Estimate** (size only): `header_end` is unambiguous, but up to 16 plaintext lengths share one
  ciphertext length. The estimate takes the largest: never below the truth, at most 15 B above.
  Used only until the header is read; a ciphertext ≤ 4096 B is header-only and reports 0.

Implementation: [BC01Framing.swift](/Common/Metadata/Boxcryptor/BC01Framing.swift),
[BoxcryptorMetadataTranslator.swift](/Common/Metadata/Boxcryptor/BoxcryptorMetadataTranslator.swift).

Observed values (Boxcryptor-written files):

```
plaintext   .bc size   header_end  cipher_padding
        0       4096        4096        0
        1       4112        4096       15
       15       4112        4096        1
       16       4128        4096       16
     4080       8192        4096       16
     4081       8192        4096       15
     4095       8192        4096        1
     4096       8192        4096        0
     4097       8208        4096       15
     8192      12288        4096        0
   819100     823200        4096        4
   819101     827296        8192        3
  1048576    1056768        8192        0
 10485759   10588160      102400        1
 10485760   10616832      131072        0
```

### 2.8 Content blocks

```
block i covers plaintext [i·4096, (i+1)·4096)
interior block: 4096 B plaintext → 4096 B ciphertext, no padding
last block:     remaining plaintext (1…4096 B) + cipher_padding B PKCS7

block_iv(i) = HMAC-SHA256(key = content_key, data = base_iv ‖ uint64_LE(i))[0:16]
block_ct(i) = AES-256-CBC(content_key, block_iv(i), block_pt(i))
```

Every block has its own IV, so any block decrypts independently of the others. This is what
allows ranged reads and parallel lanes (§6).

## 3. Decrypting a file

Input: `.bc` bytes, the RSA private key and `users[0].id` (from the unlocked vault).

```
1. check magic == "bc01"; read header_core_len, header_pad_len, cipher_padding
2. JSON-decode bytes [48 : 48 + header_core_len]
3. pick encryptedFileKeys[id == users[0].id]            no match → fail, no RSA op
4. file_key = RSA-OAEP-SHA1-decrypt(base64(value))      SecKey, .rsaEncryptionOAEPSHA1
5. parse file_key (§2.3); classify header_hmac (§2.2)
6. base_iv = base64(cipher.iv); header_end = 48 + core_len + pad_len
7. body       = file[header_end:]
   plain_len  = len(body) − cipher_padding
   block_count = max(1, ceil(plain_len / 4096))
   for i in 0 ..< block_count:
       last  = (i == block_count − 1)
       chunk = body[i·4096 : (last ? end : (i+1)·4096)]
       out  += AES-256-CBC-decrypt(content_key, block_iv(i), chunk,
                                   PKCS7 unpad iff last and cipher_padding > 0)
```

The last block is located from `cipher_padding`, **not** from the ciphertext length: a padded
last block may be exactly 4096 B (plaintext 4081–4095 B) or longer than 4096 B, so "shorter than
4096" does not identify it.

A file named `.bc` without the magic is served as plain bytes, never decrypted
([BC01HeaderProbe.swift](/Extension/Backend/BC01HeaderProbe.swift)).

Implementation: [BC01Decryptor.swift](/Common/Crypto/Boxcryptor/BC01Decryptor.swift),
[BC01CryptoCommon.swift](/Common/Crypto/Boxcryptor/BC01CryptoCommon.swift).

## 4. Encrypting a file

Input: plaintext, the RSA public key and `users[0].id`. Neither needs the vault unlocked; both
are stored in plain slots ([application.md §4](/docs/crypto/application.md#4-keychain-slot-map)).

```
1. file_key = 96-byte key: content(32) and mac(32) from SecRandomCopyBytes, checksum prepended
2. base_iv  = SecRandomCopyBytes(16)
3. wrapped  = RSA-OAEP-SHA1-encrypt(public_key, file_key)       single recipient: users[0].id
4. json     = JSONEncoder(.sortedKeys) of the §2.4 object, name unencrypted
5. reserve  = header_end(plaintext_size)                         §2.6; overflow → error
   pad_len  = reserve − 48 − len(json)
6. raw      = "bc01" ‖ u32(len(json)) ‖ u32(pad_len) ‖ u32(cipher_padding(size))
              ‖ HMAC-SHA256(mac_key, json)
7. header   = raw ‖ json ‖ zero(pad_len)
8. for each 4096-byte block i:
       ct += AES-256-CBC-encrypt(content_key, block_iv(i), block,
                                 PKCS7 iff genuinely final block and cipher_padding > 0)
```

The final ciphertext size is known before any byte is encrypted (§2.7), which a resumable upload
needs for `Content-Range`. Disjoint block ranges can be encrypted by separate upload lanes and
concatenate into exactly the file a sequential pass would write; PKCS7 is applied only to the
file's final block, never at a lane boundary.

Implementation: [BC01Encryptor.swift](/Common/Crypto/Boxcryptor/BC01Encryptor.swift)
(`BC01EncryptionSession`).

## 5. Folder key — `FolderKey.bch`

Boxcryptor places a `FolderKey.bch` file in each encrypted folder. VaultSync does **not** parse
it. Under a BC01 domain a *file* with that name (case-insensitive) is:

- hidden from enumeration, and
- taken as evidence that its parent folder is encrypted.

Under a `.plain` domain it is an ordinary file. Implementation:
[BC01SpecialItem.swift](/Common/Crypto/Boxcryptor/BC01SpecialItem.swift).

## 6. Implementation notes

- **Filenames.** A BC01 domain appends `.bc` on upload and strips a trailing `.bc`
  (case-insensitive) for display. Folders and non-`.bc` files pass through. Boxcryptor's
  encrypted filenames are not implemented.
- **Ranged and parallel reads.** A read fetches the header (a 4096 B probe, widened once if the
  header is larger), then block-aligned ciphertext spans. `BC01LanePartition` splits the body
  into whole-block spans per lane; each lane derives its IVs from the global block index.
  Parsed headers are cached, sealed, per domain
  ([application.md §7](/docs/crypto/application.md#7-bc01-header-cache-sealing)).
- **Constant-time comparisons.** File-key checksum and header HMAC use `timingSafeEqual`.
- **RSA.** OAEP with SHA-1 (Boxcryptor's choice, required for interoperability) via `SecKey`;
  the platform implementation applies blinding.
- **Randomness.** File keys and base IVs come from `SecRandomCopyBytes`.
- **Integrity.** BC01 content is AES-CBC without a MAC over the body; `header_hmac` covers only
  the JSON core. BC01 gives confidentiality, not tamper detection of content.
