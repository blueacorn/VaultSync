# Boxcryptor Key Chain Reference

The key chain inside a Boxcryptor-compatible `.bckey` file and how each key is unwrapped.
Boxcryptor is a third-party product; VaultSync is not affiliated with it. Container layouts are
in [boxcryptor.md](/docs/crypto/boxcryptor.md).

**VaultSync uses only the RSA private key** (to unwrap per-file keys) and `users[0].id`. The
`wrappingKey` / `aesKey` / filename-key branch is documented for completeness; VaultSync does
not unwrap it.

Byte ranges use slice notation `[start:stop]`.

## 1. Hierarchy

```
master password
   │ PBKDF2-HMAC-SHA512(salt, kdfIterations) → 64 B
   ▼
pwdKey  [0:32] AES key │ [32:64] HMAC key
   │
   │
   ├─ unwrap wrappingKey ─▶ wrappingKey (64 B)
   │                         │
   │                         └─ unwrap keys.filename ─▶ filenameKey (64 B)
   │
   └─ unwrap privateKey ─▶ RSA private key (PKCS#1 DER)
                             │
                             ├─ decrypt aesKey (RSA-OAEP-SHA1) ─▶ aesKey (96 B)
                             │
                             └─ decrypt .bc encryptedFileKeys[id == users[0].id].value
                                  (RSA-OAEP-SHA1) ─▶ per-file key (96 B)
                                                      │
                                                      └─▶ .bc header HMAC + content
```

### 1.1 Layout

| Key Blob  | Wrapped by | Blob layout | Blob size | Key layout | Key size |
|---|---|---|---|---|---|
|  `pwdKey` | master password | (not stored) | — | `AES key[32] ‖ HMAC key[32]` | 64 B |
| `wrappingKey`  | `pwdKey`| (§3 wrapped blob) | 128 B | `AES key[32] ‖ HMAC key[32]` | 64 B |
| `keys.filename` <br/>(filenameKey) | `wrappingKey` | (§3&nbsp;wrapped&nbsp;blob) | 128 B | `AES key[32] ‖ HMAC key[32]` | 64 B |
| `privateKey` <br/> (RSA private key) | `pwdKey`| (§3 wrapped blob) | 48 + ⌈(n+1)/16⌉·16 B, n = base64 length | `base64(PKCS#1 DER)`, ASCII | varies |
| `publicKey` <br/>(RSA public key) | none | (cleartext) | varies | DER SubjectPublicKeyInfo | varies |
| `aesKey`| RSA public key | RSA-OAEP-SHA1 | RSA modulus size <br/>(256 B RSA-2048, 512 B RSA-4096) | `SHA-256(filenameKey)[32] ‖ filenameKey[64]` | 96 B |
| `encryptedFileKeys[]` <br/>(.bc header file key) | RSA public key| RSA-OAEP-SHA1 | RSA modulus size <br/>(256 B RSA-2048, 512 B RSA-4096) | `SHA-256(content_key ‖ mac_key)[32]` ` ‖ content_key[32] ‖ mac_key[32]` | 96 B |


## 2. Password key

```
pwdKey = PBKDF2-HMAC-SHA512(password, salt = base64(users[0].salt),
                            iterations = users[0].kdfIterations, length = 64)
```

The iteration count is whatever the file stores (commonly 10,000). That is far below current
guidance for new password hashing; it is a property of the format, and VaultSync must honour it
to open existing key files. The `.bckey` password is used once, at provisioning; VaultSync does
not store it.

## 3. Wrapped blob

Shared by `privateKey`, `wrappingKey` and `keys.*`, each with its own 64-byte wrapping key `W`:

```
[0:16]   IV
[16:48]  HMAC-SHA256(key = W[32:64], data = ciphertext)
[48:]    ciphertext = AES-256-CBC(key = W[0:32], IV = [0:16], PKCS7(plaintext))
```

Unwrap: verify the HMAC with a constant-time compare **before** decrypting, then decrypt and
unpad. A wrong password fails at the HMAC check, so no padding oracle is exposed.

Note: The HMAC does not cover the IV. Because `P₁ = AES⁻¹(C₁) ⊕ IV`, editing the IV flips the same
bits of the first 16 plaintext bytes without failing the HMAC. This is a property of the format.
VaultSync compensates for the only blob it uses, `privateKey`: it decodes the base64 plaintext
strictly and requires the unwrapped key's public half to equal `users[0].publicKey`
(`keyPairMismatch` otherwise). A forged matching pair needs the private key itself.

| Blob | Wrapping key `W` |
|---|---|
| `privateKey` | `pwdKey` |
| `wrappingKey` | `pwdKey` |
| `keys.filename` | `wrappingKey` |

## 4. RSA private key

The `privateKey` plaintext is `base64(DER)`, so a second base64 decode yields the key. The DER is
a bare **PKCS#1** `RSAPrivateKey` (`SEQUENCE { version, modulus, … }`), not PKCS#8. Tools that
re-wrap the key must re-serialise as PKCS#1; a PKCS#8 round-trip changes the plaintext length and
the ciphertext.

VaultSync imports it with `SecKeyCreateWithData` (`kSecAttrKeyTypeRSA`, private), keeps the DER
wrapped in the keychain, and uses it only for RSA-OAEP-SHA1 decryption of .bc header per-file keys.

Implementation: [CryptoConfigViewModel.swift](/Common/Crypto/CryptoConfigViewModel.swift)
(`deriveKey`), [application.md §6.1](/docs/crypto/application.md#61-provisioning-a-domain).

## 5. `aesKey` integrity binding

`aesKey` decrypts (RSA-OAEP-SHA1) to 96 bytes:

```
aesKey[0:32]  = SHA-256(aesKey[32:96])
aesKey[32:96] = filenameKey              (equals the keys.filename plaintext)
```

Boxcryptor rejects a key file where either relation fails, so a tool that changes the filename
key must rebuild `aesKey` and re-wrap `keys.filename` together.

## 6. Filename key

```
filenameKey[0:32]   AES-256-CFB128 key for the name cipher
filenameKey[32:64]  HMAC-SHA256 key for the synthetic nonce
```

See [boxcryptor-filename.md](/docs/crypto/boxcryptor-filename.md).


## 7. File key

```
  [0:32]   checksum = SHA-256(file_key[32:96])
  [32:64]  content key  AES-256: block encryption and per-block IV derivation
  [64:96]  mac key      HMAC-SHA256 key for header_hmac
```

See [boxcryptor.md §2.4](/docs/crypto/boxcryptor.md#24-file-key).