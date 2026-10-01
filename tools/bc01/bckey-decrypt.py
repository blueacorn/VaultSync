#!/usr/bin/env python3
"""Decrypt Boxcryptor Key Hierarchy and display key bytes in hex.

Usage:
    bckey-decrypt.py <file.bckey> [file.bc] [--password <master_password>] [-v|--verbose]
    PASSWORD env var used if --password not supplied; prompts if neither set.
    --verbose additionally prints all seed values: KDF salt/iterations, every
    wrapped-blob IV + HMAC + ciphertext, and the RSA ciphertext blobs.

    Decrypts and prints all .bckey keys in hex, and verifies the aesKey integrity
    invariants ( aesKey[0:32] == SHA256(aesKey[32:96]) and aesKey[32:96] == keys.filename ).
    Prints "Error:" for each failed check and exits non-zero if any fail.
      bckey-decrypt.py vaultfile.bckey

    Also decrypts .bc file DEK keys.
      bckey-decrypt.py vaultfile.bckey file.bc

Requires: cryptography (pip install cryptography)
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
import subprocess
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
except ImportError:
    answer = input("Required package 'cryptography' is not installed. Install now? [y/N] ").strip().lower()
    if answer != "y":
        sys.exit("Aborted.")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("bckey_file", help="Boxcryptor .bckey file")
    p.add_argument("bc_file",    help="Encrypted .bc file (optional)", nargs="?", default=None)
    p.add_argument("--password", help="Master password (overrides PASSWORD env var)")
    p.add_argument("--out",      help="Decrypt .bc file content to this path (requires bc_file)", default=None)
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print all seed values: salt, kdfIterations, per-blob IVs, HMACs, and ciphertext")
    return p.parse_args()


def resolve_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    env = os.environ.get("PASSWORD", "")
    if env:
        return env
    return getpass.getpass("Master password: ")


def load_bckey(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    return data["users"][0]


VERBOSE = False


def vprint_blob(label: str, iv: bytes, given_hmac: bytes, ciphertext: bytes) -> None:
    """Dump the wrapped-blob seed/auth components when --verbose is set."""
    if VERBOSE:
        print(f"  [verbose] {label} IV         : {iv.hex()}")
        print(f"  [verbose] {label} HMAC       : {given_hmac.hex()}")
        print(f"  [verbose] {label} ciphertext : {ciphertext.hex()}")


def aes_cbc_unwrap(blob: bytes, wrap_key: bytes, label: str = "blob") -> bytes:
    """Unwrap AES-CBC+HMAC blob: [IV(16)][HMAC(32)][ciphertext]."""
    iv         = blob[0:16]
    given_hmac = blob[16:48]
    ciphertext = blob[48:]

    vprint_blob(label, iv, given_hmac, ciphertext)

    computed = hmac.new(wrap_key[32:64], ciphertext, "sha256").digest()
    if not hmac.compare_digest(computed, given_hmac):
        sys.exit("Error: HMAC verification failed — wrong password or corrupted key")

    cipher = Cipher(algorithms.AES(wrap_key[0:32]), modes.CBC(iv))
    dec = cipher.decryptor().update(ciphertext)
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dec) + unpadder.finalize()


def unwrap_private_key(enc_b64: str, pwd_key: bytes) -> bytes:
    """AES-CBC unwrap → base64-decode → RSA DER bytes."""
    raw = aes_cbc_unwrap(base64.b64decode(enc_b64), pwd_key, "privateKey")
    return base64.b64decode(raw)


def rsa_decrypt(ciphertext: bytes, rsa_key) -> bytes:
    return rsa_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def load_bc_header(path: str) -> tuple[bytes, dict, int]:
    """Parse bc01 header; return (encryptedFileKey bytes, parsed JSON header dict, ciphertext_offset)."""
    with open(path, "rb") as f:
        raw = f.read(16)
    core_len    = struct.unpack_from("<I", raw, 4)[0]
    padding_len = struct.unpack_from("<I", raw, 8)[0]
    with open(path, "rb") as f:
        f.seek(48)
        core_bytes = f.read(core_len)
    text = core_bytes.decode("utf-8", errors="replace")
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        sys.exit("Error: cannot find JSON in bc header")
    hdr = json.loads(m.group(0))
    keys = hdr.get("encryptedFileKeys", [])
    if not keys:
        sys.exit("Error: no encryptedFileKeys in header")
    enc_key = base64.b64decode(keys[0]["value"])
    cipher_offset = 48 + core_len + padding_len
    return enc_key, hdr, cipher_offset


BC01_BLOCK_SIZE = 4096


def _block_iv(base_iv: bytes, block_index: int, file_key: bytes) -> bytes:
    """HMAC-SHA256(baseIV || blockIndex_LE64, fileKey)[0:16]."""
    msg = base_iv + struct.pack("<Q", block_index)
    return hmac.new(file_key, msg, "sha256").digest()[:16]


def decrypt_bc_content(path: str, hdr: dict, cipher_offset: int,
                       file_key_raw: bytes, out_path: str) -> None:
    """Decrypt AES-256-CBC bc01 ciphertext blocks to out_path.

    file_key_raw is the full RSA plaintext (≥64 bytes); AES key is [32:64].
    Block IV = HMAC-SHA256(baseIV || blockIndex_LE64, aes_key)[0:16].
    Last block is PKCS7-unpadded when cipherPadding > 0.
    """
    aes_key  = file_key_raw[32:64]
    base_iv  = base64.b64decode(hdr["cipher"]["iv"])
    cipher_padding = struct.unpack_from("<I", open(path, "rb").read(16), 12)[0]

    with open(path, "rb") as fin, open(out_path, "wb") as fout:
        fin.seek(cipher_offset)
        block_index = 0
        prev_block: bytes | None = None

        while True:
            chunk = fin.read(BC01_BLOCK_SIZE)
            if not chunk:
                break
            # We need to know if the *next* read is empty to identify the last block,
            # so buffer one block behind.
            if prev_block is not None:
                iv = _block_iv(base_iv, block_index - 1, aes_key)
                dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
                plain = dec.update(prev_block) + dec.finalize()
                fout.write(plain)
            prev_block = chunk
            block_index += 1

        # Final block — apply PKCS7 unpadding when cipherPadding > 0.
        if prev_block:
            iv = _block_iv(base_iv, block_index - 1, aes_key)
            dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
            raw = dec.update(prev_block) + dec.finalize()
            if cipher_padding > 0:
                unpadder = padding.PKCS7(128).unpadder()
                raw = unpadder.update(raw) + unpadder.finalize()
            fout.write(raw)


def hexline(label: str, data: bytes) -> None:
    print(f"  {label:<30}: {data.hex()}")


def main() -> None:
    global VERBOSE
    args = parse_args()
    VERBOSE = args.verbose

    password = resolve_password(args.password)
    if not password:
        sys.exit("Error: no password provided")

    user = load_bckey(args.bckey_file)

    # --- Phase 1: derive pwdKey from master password ---
    salt       = base64.b64decode(user["salt"])
    iterations = int(user["kdfIterations"])
    pwd_key    = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, dklen=64)

    if VERBOSE:
        print("=== KDF seed ===")
        hexline("salt", salt)
        print(f"  {'kdfIterations':<30}: {iterations}")
        print()

    print("=== pwdKey ===")
    hexline("pwd_crypto [0:32]", pwd_key[0:32])
    hexline("pwd_hmac   [32:64]", pwd_key[32:64])

    # --- Phase 2: unwrap RSA private key ---
    rsa_der = unwrap_private_key(user["privateKey"], pwd_key)
    rsa_key = serialization.load_der_private_key(rsa_der, password=None)
    pub_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    modulus_bytes = rsa_key.public_key().public_numbers().n.to_bytes(
        (rsa_key.key_size + 7) // 8, "big"
    )
    print("\n=== RSA Private Key ===")
    print(f"  {'key size':<30}: {rsa_key.key_size} bits")
    print(f"  {'modulus SHA-256':<30}: {hashlib.sha256(modulus_bytes).hexdigest()}")
    print(f"  {'public key SHA-256 (DER)':<30}: {hashlib.sha256(pub_der).hexdigest()}")

    # --- Phase 3: unwrap wrappingKey (AES-CBC, keyed by pwdKey) ---
    wrapping_key = aes_cbc_unwrap(base64.b64decode(user["wrappingKey"]), pwd_key, "wrappingKey")
    print("\n=== wrappingKey ===")
    hexline("wk_crypto  [0:32]", wrapping_key[0:32])
    hexline("wk_hmac    [32:64]", wrapping_key[32:64])

    # --- Phase 4: RSA-decrypt aesKey (96 bytes) ---
    aes_key_blob = base64.b64decode(user["aesKey"])
    if VERBOSE:
        print(f"\n  [verbose] aesKey RSA ciphertext ({len(aes_key_blob)} B): {aes_key_blob.hex()}")
    aes_key_raw = rsa_decrypt(aes_key_blob, rsa_key)
    print("\n=== aesKey (RSA-decrypted, 96 bytes) ===")
    hexline("checksum    [0:32]", aes_key_raw[0:32])
    hexline("fn_crypto  [32:64]", aes_key_raw[32:64])
    hexline("fn_hmac    [64:96]", aes_key_raw[64:96])

    # Integrity: aesKey[0:32] must equal SHA256(aesKey[32:96]). A stale or random
    # checksum makes Boxcryptor reject the vault on load.
    errors: list[str] = []
    expected_checksum = hashlib.sha256(aes_key_raw[32:96]).digest()
    if aes_key_raw[0:32] == expected_checksum:
        print(f"  {'checksum == SHA256(aesKey[32:96])':<30}: OK")
    else:
        msg = "aesKey[0:32] != SHA256(aesKey[32:96]) — checksum mismatch"
        errors.append(msg)
        print(f"  Error: {msg}")
        hexline("expected checksum", expected_checksum)

    # --- Phase 5: unwrap keys.* (AES-CBC, keyed by wrappingKey) ---
    vault_keys = user.get("keys", {})

    filename_key = None
    if "filename" in vault_keys:
        filename_key = aes_cbc_unwrap(base64.b64decode(vault_keys["filename"]), wrapping_key, "keys.filename")
        print("\n=== keys.filename (filenameKey) ===")
        hexline("fn_crypto  [0:32]", filename_key[0:32])
        hexline("fn_hmac    [32:64]", filename_key[32:64])

        if filename_key == aes_key_raw[32:96]:
            print(f"  {'aesKey[32:96] == filenameKey':<30}: OK")
        else:
            msg = "aesKey[32:96] != keys.filename plaintext — filename key mismatch"
            errors.append(msg)
            print(f"  Error: {msg}")

    for name in ("groupMembership", "analytics"):
        if name in vault_keys:
            key = aes_cbc_unwrap(base64.b64decode(vault_keys[name]), wrapping_key, f"keys.{name}")
            print(f"\n=== keys.{name} ===")
            hexline("[0:32]", key[0:32])
            hexline("[32:64]", key[32:64])

    # --- Phase 6 (optional): decrypt .bc file DEK ---
    if args.bc_file:
        enc_file_key, bc_hdr, cipher_offset = load_bc_header(args.bc_file)
        if VERBOSE:
            print(f"\n  [verbose] DEK RSA ciphertext ({len(enc_file_key)} B): {enc_file_key.hex()}")
        file_key = rsa_decrypt(enc_file_key, rsa_key)

        if len(file_key) < 64:
            sys.exit(f"Error: file key too short ({len(file_key)} bytes, expected ≥ 64)")

        print("\n=== File DEK (.bc) ===")
        hexline("mac_key    [0:32]", file_key[0:32])
        hexline("aes_key    [32:64]", file_key[32:64])

        if args.out:
            decrypt_bc_content(args.bc_file, bc_hdr, cipher_offset, file_key, args.out)
            print(f"\n  Decrypted content written to: {args.out}")
    elif args.out:
        sys.exit("Error: --out requires a .bc file argument")

    if errors:
        print(f"\n{len(errors)} integrity error(s) found — Boxcryptor will reject this vault.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
