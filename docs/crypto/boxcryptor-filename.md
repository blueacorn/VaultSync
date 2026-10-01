# BC01 Filename Encryption Reference

How Boxcryptor-compatible clients encrypt filenames. Boxcryptor is a third-party product;
VaultSync is not affiliated with it.

> **Not implemented in VaultSync.** VaultSync neither encrypts nor decrypts filenames: it appends
> `.bc` on upload, strips it for display, and writes `metadata.name` unencrypted
> ([boxcryptor.md §6](/docs/crypto/boxcryptor.md#6-implementation-notes)). A
> folder whose files carry encrypted names therefore shows the encoded names. This page records
> the scheme for interoperability; the reference decoder is
> [tools/bc01/bc-decrypt-filename.py](/tools/bc01/bc-decrypt-filename.py).

Byte ranges use slice notation `[start:stop]`.

## 1. Where encrypted names appear

- as the backend filename: `base4k(blob) + ".bc"`
- in the `.bc` JSON core: `metadata.name.value`, with `metadata.name.encrypted == true`

```
blob = [0x01 0x01] ‖ nonce (5 B) ‖ ciphertext (N B)        N == len(UTF-8 name)
```

The cipher is an EncFS-style two-pass AES-256-CFB128 stream: no padding, length-preserving. The
nonce is deterministic, so a given name always encrypts identically on every device.

## 2. Keys

`filenameKey` (64 B) is unwrapped from `users[].keys.filename` via `pwdKey → wrappingKey`
([boxcryptor-keys.md](/docs/crypto/boxcryptor-keys.md)).

```
fn_crypto = filenameKey[0:32]    AES-256-CFB128 key
fn_hmac   = filenameKey[32:64]   HMAC-SHA256 key
```

## 3. base4k

Packs bytes into CJK codepoints so the result is a valid filename.

- Body characters `U+6000 + g`, where `g` is a 12-bit group: 2 characters carry 3 bytes.
  Even-index character: high 8 bits of `g` form one byte. Odd-index character: the previous
  group's low 4 bits and this group's top 4 bits form one byte, and its low 8 bits another.
- One terminator character in `U+4000..U+40FF` carries the remainder:
  even index → one full byte `t − 0x4000`;
  odd index → one byte `(previous group << 4 | (t − 0x4000) & 0x0F) & 0xFF`.
- The `.bc` suffix is plain text and is removed before decoding.

## 4. IV derivation

IVs depend only on the stored nonce; decryption does not need the plaintext name.

```
base = HMAC-SHA256(fn_hmac, nonce)[0:16]
X[i] = base[i] ^ base[i+8]                                   i = 0..7
seed = base[7] ‖ X[6] ‖ X[5] ‖ X[4] ‖ X[3] ‖ X[2] ‖ X[1] ‖ X[0]      8 B
iv1  = HMAC-SHA256(fn_crypto, base ‖ seed)[0:16]
iv2  = HMAC-SHA256(fn_crypto, base ‖ (seed[0]+1 mod 256) ‖ seed[1:8])[0:16]
```

## 5. Primitives

```
shuffle(b):    out[0] = b[0];  out[i] = b[i] ^ out[i−1]     forward running XOR
unshuffle(b):  for i = len−1 down to 1: b[i] ^= b[i−1]      in place, high → low
flip64(b):     reverse byte order within each 64-byte chunk (last chunk may be shorter)
CFB(k, iv):    AES-256-CFB128 (128-bit feedback, not CFB8), no padding
```

## 6. Decrypt

```
blob       = base4k_decode(name without ".bc")
require      blob[0:2] == 01 01
nonce, ct  = blob[2:7], blob[7:]
t          = unshuffle(CFB_decrypt(fn_crypto, iv2, ct))
t          = flip64(t)
name       = unshuffle(CFB_decrypt(fn_crypto, iv1, t))
require      HMAC-SHA256(fn_hmac, name)[0:5] == nonce          constant-time
```

The final nonce check authenticates the result: a wrong key or corrupted name fails here.

## 7. Encrypt

```
nonce      = HMAC-SHA256(fn_hmac, name)[0:5]
iv1, iv2   = §4 from nonce
t          = CFB_encrypt(fn_crypto, iv1, shuffle(name))
t          = shuffle(flip64(t))
ct         = CFB_encrypt(fn_crypto, iv2, t)
stored     = base4k_encode(01 01 ‖ nonce ‖ ct) + ".bc"
```

## 8. Design rationale

- **Deterministic.** A synthetic nonce keeps a re-encrypted name byte-identical, so sync does not
  see a rename. The cost: equal names are recognisable as equal.
- **Length-preserving.** A stream mode adds no padding; overhead is a fixed 7 bytes before
  base4k expansion, which matters under filesystem name-length limits.
- **5-byte nonce.** Saves name capacity. Collisions between distinct names are rare and
  non-fatal, since the nonce is also re-checked after decryption.
- **No per-name KDF.** PBKDF2 runs once to reach `filenameKey`; each name costs one HMAC and two
  short CFB passes.
