#!/usr/bin/env python3
"""Decrypt the metadata.name.value of a Boxcryptor .bc file.

Walks the full key chain:
  1. Master password + PBKDF2-SHA512 → AES + HMAC key (from .bckey salt/iterations)
  2. Verify HMAC-SHA256 over users[0].privateKey, AES-256-CBC decrypt → base64(DER RSA key)
  3. RSA-OAEP-SHA1 decrypt users[0].aesKey → 64-byte (cryptoKey || hmacKey)
  4. Verify HMAC-SHA256 over users[0].keys.filename, AES-256-CBC decrypt → base64(filename key blob)
  5. Extract filename crypto+HMAC key halves
  6. Parse .bc core header, decrypt metadata.name.value using filename key

Usage:
    bc-decrypt-filename.py <file.bc> <file.bckey> [--password <master_password>]
    PASSWORD env var used if --password not given; prompts if neither set.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("bc_file")
    p.add_argument("bckey_file")
    p.add_argument("--password")
    return p.parse_args()


def resolve_password(cli: str | None) -> str:
    if cli:
        return cli
    env = os.environ.get("PASSWORD", "")
    if env:
        return env
    return getpass.getpass("Master password: ")


def aes_cbc_decrypt_pkcs7(key: bytes, iv: bytes, ct: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    unp = sym_padding.PKCS7(128).unpadder()
    return unp.update(pt) + unp.finalize()


def unwrap_split_key_blob(blob: bytes, crypto_key: bytes, hmac_key: bytes, label: str) -> bytes:
    """Verify HMAC + AES-256-CBC decrypt the IV(16)||HMAC(32)||CT(*) layout."""
    iv, given_mac, ct = blob[:16], blob[16:48], blob[48:]
    computed = hmac.new(hmac_key, ct, "sha256").digest()
    if not hmac.compare_digest(computed, given_mac):
        sys.exit(f"Error: HMAC mismatch unwrapping {label}")
    return aes_cbc_decrypt_pkcs7(crypto_key, iv, ct)


def windows(blob: bytes) -> list[tuple[str, bytes]]:
    """All aligned 32-byte windows of a key blob, labelled by byte offset."""
    return [(f"[{o}:{o+32}]", blob[o:o+32]) for o in range(0, len(blob) - 31, 32)]


def try_unwrap(blob: bytes, crypto_key: bytes, hmac_key: bytes,
               mac_input: str, algo: str) -> bytes | None:
    """Non-fatal IV||HMAC||CT unwrap. mac_input: 'ct' or 'iv+ct'. Returns pt on match."""
    iv, given_mac, ct = blob[:16], blob[16:48], blob[48:]
    if len(ct) == 0 or len(ct) % 16 != 0:
        return None
    data = ct if mac_input == "ct" else iv + ct
    if not hmac.compare_digest(hmac.new(hmac_key, data, algo).digest()[:32], given_mac):
        return None
    try:
        return aes_cbc_decrypt_pkcs7(crypto_key, iv, ct)
    except Exception:
        return None


def probe_blob(name: str, blob: bytes, key_candidates: dict[str, bytes]) -> bytes | None:
    """Brute every (crypto-window, hmac-window, mac_input, algo) against blob."""
    print(f"  [{name}] {len(blob)} bytes  iv={blob[:16].hex()}  ct_len={len(blob)-48}")
    for kname, kblob in key_candidates.items():
        wins = windows(kblob)
        for ck_lbl, ck in wins:
            for hk_lbl, hk in wins:
                for mac_input in ("ct", "iv+ct"):
                    for algo in ("sha256", "sha1"):
                        pt = try_unwrap(blob, ck, hk, mac_input, algo)
                        if pt is not None:
                            print(f"    MATCH key={kname} crypto={ck_lbl} hmac={hk_lbl} "
                                  f"mac_input={mac_input} algo={algo} -> {len(pt)} bytes")
                            return pt
    print(f"    no HMAC match for [{name}] against {list(key_candidates)}")
    return None


def derive_pbkdf2_keys(password: str, salt: bytes, iters: int) -> tuple[bytes, bytes]:
    d = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iters, 64)
    return d[:32], d[32:64]


def rsa_oaep_sha1_decrypt(priv, ct: bytes) -> bytes:
    return priv.decrypt(
        ct,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )


def load_core_header(bc_path: str) -> dict:
    with open(bc_path, "rb") as f:
        raw = f.read(16)
    if raw[:4] != b"bc01":
        sys.exit("Error: not a bc01 file")
    core_len = struct.unpack_from("<I", raw, 4)[0]
    with open(bc_path, "rb") as f:
        f.seek(48)
        core_bytes = f.read(core_len)
    m = re.search(r"\{.*\}", core_bytes.decode("utf-8", errors="replace"), re.S)
    if not m:
        sys.exit("Error: cannot parse core header JSON")
    return json.loads(m.group(0))


def _aes_cfb_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _shuffle(buf: bytes) -> bytes:
    """EncFS shuffleBytes: out[i] = in[i] ^ out[i-1] (running prefix XOR)."""
    o = bytearray(buf)
    for i in range(1, len(o)):
        o[i] ^= o[i - 1]
    return bytes(o)


def _unshuffle(buf: bytes) -> bytes:
    """Inverse of `_shuffle`: out[i] = in[i] ^ in[i-1] (high→low)."""
    o = bytearray(buf)
    for i in range(len(o) - 1, 0, -1):
        o[i] ^= o[i - 1]
    return bytes(o)


def _flip(buf: bytes) -> bytes:
    """EncFS flipBytes: reverse byte order within each 64-byte chunk."""
    o = bytearray(len(buf))
    off = 0
    left = len(buf)
    while left:
        n = min(64, left)
        for i in range(n):
            o[off + i] = buf[off + n - 1 - i]
        off += n
        left -= n
    return bytes(o)


def _derive_name_ivs(nonce: bytes, fn_crypto: bytes, fn_hmac: bytes) -> tuple[bytes, bytes]:
    """Derive the two AES-CFB IVs for the EncFS two-pass name cipher from the
    stored 5-byte nonce. (Recovered by instrumenting the Boxcryptor client.)

      base = HMAC-SHA256(fn_hmac, nonce)[:16]
      X    = base[i] ^ base[i+8]      (i = 0..7)
      seed = base[7] ‖ X[6] X[5] X[4] X[3] X[2] X[1] X[0]
      iv1  = HMAC-SHA256(fn_crypto, base ‖ seed)[:16]
      iv2  = HMAC-SHA256(fn_crypto, base ‖ (seed[0]+1 mod 256) ‖ seed[1:])[:16]
    """
    base = hmac.new(fn_hmac, nonce, "sha256").digest()[:16]
    x = bytes(base[i] ^ base[i + 8] for i in range(8))
    seed = bytes([base[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]])
    iv1 = hmac.new(fn_crypto, base + seed, "sha256").digest()[:16]
    seed2 = bytes([(seed[0] + 1) & 0xFF]) + seed[1:]
    iv2 = hmac.new(fn_crypto, base + seed2, "sha256").digest()[:16]
    return iv1, iv2


def decrypt_filename(enc_name: str, fn_key: bytes) -> str:
    """Decrypt a Boxcryptor encrypted filename (`metadata.name.value`).

    `fn_key` is the 64-byte filename key (`fn_crypto = fn_key[0:32]`,
    `fn_hmac = fn_key[32:64]`). The scheme is an EncFS-derived, deterministic
    two-pass stream cipher (AES-256-CFB128, no padding):

      blob = base4k_decode(value) = [0x01 0x01][ nonce (5) ][ ciphertext ]
      decode: CFB⁻¹(iv2) → unshuffle → flip → CFB⁻¹(iv1) → unshuffle

    The 5-byte nonce equals `HMAC-SHA256(fn_hmac, name)[:5]`; recomputing it on
    the recovered name authenticates the result. See /docs/crypto/boxcryptor-keys.md §5.
    """
    fn_crypto, fn_hmac = fn_key[:32], fn_key[32:64]
    blob = base4k_decode(enc_name)
    if blob[:2] != b"\x01\x01":
        raise ValueError(f"unexpected name version tag {blob[:2].hex()}")
    nonce, ct = blob[2:7], blob[7:]
    iv1, iv2 = _derive_name_ivs(nonce, fn_crypto, fn_hmac)
    pt = _flip(_unshuffle(_aes_cfb_decrypt(fn_crypto, iv2, ct)))
    name = _unshuffle(_aes_cfb_decrypt(fn_crypto, iv1, pt))
    if hmac.new(fn_hmac, name, "sha256").digest()[:5] != nonce:
        raise ValueError("nonce mismatch — wrong key or corrupt name")
    return name.decode("utf-8", errors="replace")


def base4k_decode(enc_name: str, base1: int = 0x6000) -> bytes:
    """Decode a secomba/base4k string to raw bytes.

    base4k packs the byte stream into 12-bit big-endian groups, each rendered
    as `0x6000 + group` (3 bytes ↔ 2 chars). A trailing terminator char in
    `0x4000..0x40FF` carries the leftover byte (even index) or nibble (odd
    index). Ref: https://github.com/secomba/base4k. The literal `.bc` suffix
    is plaintext and is stripped first.
    """
    if enc_name.endswith(".bc"):
        enc_name = enc_name[:-3]
    cps = [ord(c) for c in enc_name]
    out = bytearray()
    prev = 0
    for i, c in enumerate(cps):
        if c >= base1:                       # 12-bit body group
            code = c - base1
            if i % 2 == 0:
                out.append((code >> 4) & 0xFF)
            else:
                out.append(((prev << 4) | ((code & 0x0F00) >> 8)) & 0xFF)
                out.append(code & 0xFF)
            prev = code
        else:                                # 0x40xx terminator
            code = c - 0x4000
            if i % 2 == 0:
                out.append(code & 0xFF)      # full leftover byte
            else:
                out.append(((prev << 4) | (code & 0x0F)) & 0xFF)  # leftover nibble
            break
    return bytes(out)


def main() -> None:
    args = parse_args()
    password = resolve_password(args.password).strip()
    if not password:
        sys.exit("Error: no password provided")

    bk = json.load(open(args.bckey_file))
    user = bk["users"][0]

    # Step 1+2: derive RSA private key (PROVEN path — also confirms the password).
    aes_k, mac_k = derive_pbkdf2_keys(
        password, base64.b64decode(user["salt"]), int(user["kdfIterations"])
    )
    rsa_der_b64 = unwrap_split_key_blob(
        base64.b64decode(user["privateKey"]), aes_k, mac_k, "privateKey"
    )
    rsa_der = base64.b64decode(rsa_der_b64)
    priv_rsa = serialization.load_der_private_key(rsa_der, password=None)
    print("[1] RSA private key unwrapped — password OK")

    # Step 3: RSA-decrypt the symmetric key fields.
    aes_key_blob = rsa_oaep_sha1_decrypt(priv_rsa, base64.b64decode(user["aesKey"]))
    print(f"[2] aesKey RSA-decrypted: {len(aes_key_blob)} bytes = {aes_key_blob.hex()}")

    # Candidate wrapping-key pool: password-derived key (same as privateKey),
    # the RSA-recovered aesKey, and the unwrapped wrappingKey.
    candidates: dict[str, bytes] = {
        "pwdKey": aes_k + mac_k,    # derived[0:32] || derived[32:64]
        "aesKey": aes_key_blob,
    }
    wk = probe_blob("wrappingKey", base64.b64decode(user["wrappingKey"]), candidates)
    if wk is not None:
        try:
            wk = base64.b64decode(wk)
        except Exception:
            pass
        print(f"      wrappingKey -> {len(wk)} bytes = {wk.hex()}")
        candidates["wrappingKey"] = wk

    # Step 4: discover how keys.filename is wrapped.
    print("[3] probing keys.filename wrapping:")
    fn_unwrapped = probe_blob("keys.filename", base64.b64decode(user["keys"]["filename"]), candidates)
    if fn_unwrapped is None:
        sys.exit("Could not unwrap keys.filename with known candidates — see probe output above.")
    try:
        fn_key_blob = base64.b64decode(fn_unwrapped)
    except Exception:
        fn_key_blob = fn_unwrapped
    print(f"    keys.filename -> {len(fn_key_blob)} bytes = {fn_key_blob.hex()}")

    # Step 5: read metadata.name.value from .bc and decrypt
    core = load_core_header(args.bc_file)
    name_meta = core.get("metadata", {}).get("name", {})
    enc_name = name_meta.get("value", "")
    if not name_meta.get("encrypted"):
        print(f"[4] metadata.name not encrypted: {enc_name}")
        return
    print(f"[4] encrypted filename ({len(enc_name)} chars): {enc_name}")
    try:
        plaintext = decrypt_filename(enc_name, fn_key_blob)
        print(f"[5] decrypted filename: {plaintext}")
    except Exception as e:
        sys.exit(f"[5] filename decrypt failed: {e}\n"
                 f"    fn_key_blob={fn_key_blob.hex()}")


if __name__ == "__main__":
    main()
