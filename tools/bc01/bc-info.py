#!/usr/bin/env python3
"""Parse and display Boxcryptor file headers (bc01).

Usage:
    bc-info.py <file.bc> [--bckey vault.bckey [--password PW]]

Without --bckey: raw header, reserved bytes 16–47, framing check, JSON core.
With --bckey:    also unwraps the 96-byte file key and checks its SHA-256 checksum and the
                 JSON header HMAC stored in bytes 16–47.
"""

import argparse
import getpass
import hashlib
import hmac
import importlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RAW_HEADER_LEN = 48
BLOCK = 4096
AES_BLOCK = 16
LARGE_HEADER = 128 * 1024
LARGE_THRESHOLD = 10 * 1024 * 1024


# --- Framing (mirrors Common/Metadata/Boxcryptor/BC01Framing.swift) ---

def header_size(p):
    if p >= LARGE_THRESHOLD:
        return LARGE_HEADER
    return max(BLOCK, ((p + 99) // 100) // BLOCK * BLOCK)


def cipher_padding(p):
    return 0 if p % BLOCK == 0 else AES_BLOCK - p % AES_BLOCK


def ciphertext_size(p):
    return header_size(p) + p + cipher_padding(p)


def estimated_plaintext_size(c):
    best = None
    for header in range(BLOCK, LARGE_HEADER + 1, BLOCK):
        if header > c:
            break
        body = c - header
        for p in range(body, max(0, body - AES_BLOCK) - 1, -1):
            if ciphertext_size(p) == c:
                best = p if best is None else max(best, p)
                break
    return best


def ok(flag):
    return "OK" if flag else "MISMATCH"


# --- Output ---

def print_bc01_header(file_path, bckey=None, password=None):
    """Parse and display bc01 header."""
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        raw = f.read(RAW_HEADER_LEN)
        core_len = struct.unpack("<I", raw[4:8])[0]
        pad_len = struct.unpack("<I", raw[8:12])[0]
        cipher_pad = struct.unpack("<I", raw[12:16])[0]
        reserved = raw[16:48]
        core = f.read(core_len)

    header_end = RAW_HEADER_LEN + core_len + pad_len
    exact = max(0, size - header_end - cipher_pad) if size > header_end else 0

    print("=== bc01 HEADER (48 bytes) ===")
    print(f"Magic (hex):           {raw[0:4].hex()}")
    print(f"Header Core Length:    {core_len}")
    print(f"Header Padding Length: {pad_len}")
    print(f"Cipher Padding Length: {cipher_pad}")
    print(f"Header HMAC (16–47):   {reserved.hex()}"
          + ("  (all zero: not written)" if reserved == bytes(32) else ""))

    print()
    print("--- Framing (BC01Framing) ---")
    est = estimated_plaintext_size(size)
    print(f"Ciphertext size:       {size}")
    print(f"Header end:            {header_end}  expected {header_size(exact)}  "
          f"{ok(header_end == header_size(exact))}")
    print(f"Cipher padding:        {cipher_pad}  expected {cipher_padding(exact)}  "
          f"{ok(cipher_pad == cipher_padding(exact))}")
    print(f"Exact plaintext:       {exact}")
    if est is None:
        print("Estimated plaintext:   none (size not BC01-framed)")
    else:
        print(f"Estimated plaintext:   {est}  (+{est - exact} B)")

    if bckey:
        print()
        print("--- File key / HMAC ---")
        print_key_checks(bckey, password, core, reserved)

    print()
    print("--- Core Header (JSON) ---")
    try:
        print(json.dumps(json.loads(core), indent=2))
    except (json.JSONDecodeError, UnicodeDecodeError):
        print(core.decode("utf-8", errors="replace"))


def print_key_checks(bckey, password, core, reserved):
    """Unwrap the file key and verify its checksum and the JSON header HMAC."""
    audit = importlib.import_module("bc-audit-padding")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    import base64

    rsa_key = audit.unwrap_vault_key(bckey, password or getpass.getpass("Master password: "))
    oaep = asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    header = json.loads(core)
    key = None
    for entry in header.get("encryptedFileKeys", []):
        try:
            key = rsa_key.decrypt(base64.b64decode(entry["value"]), oaep)
            print(f"Key entry id:          {entry.get('id')}")
            break
        except ValueError:
            continue
    if key is None:
        print("File key:              no entry decrypts with this vault")
        return

    print(f"File key length:       {len(key)} B")
    checksum_ok = hashlib.sha256(key[32:]).digest() == key[:32]
    print(f"key[0:32] checksum:    SHA-256(key[32:])  {ok(checksum_ok)}")
    if len(key) < 96:
        print("MAC key:               absent (64-byte key: written by a pre-HMAC encryptor)")
        return

    mac = hmac.new(key[64:96], core, hashlib.sha256).digest()
    if mac == reserved:
        print("Header HMAC:           HMAC-SHA256(key[64:96], JSON core)  OK")
    else:
        print("Header HMAC:           MISMATCH vs on-disk JSON "
              "(expected ~50% for Boxcryptor: MAC taken over a different key order)")


def print_bc02_header(file_path):
    """Parse and display bc02 header."""
    print("=== bc02 HEADER (UNKNOWN FORMAT) ===")
    print("Dumping first 256 bytes for analysis:")
    print()

    with open(file_path, "rb") as f:
        data = f.read(256)

    # Mimic xxd -g 1 -l 256 output
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{i:08x}: {hex_part:<48}  {ascii_part}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", help=".bc file")
    p.add_argument("--bckey", help="vault .bckey: enables file-key and HMAC checks")
    p.add_argument("--password", help="master password (prompted if omitted)")
    args = p.parse_args()

    if not os.path.isfile(args.file):
        print(f"File not found: {args.file}")
        sys.exit(1)

    with open(args.file, "rb") as f:
        magic_hex = f.read(4).hex()

    if magic_hex == "62633031":
        print_bc01_header(args.file, args.bckey, args.password)
    elif magic_hex == "62633032":
        print_bc02_header(args.file)
    else:
        print(f"Unknown file format. Magic bytes: {magic_hex}")


if __name__ == "__main__":
    main()
