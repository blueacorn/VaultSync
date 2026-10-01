#!/usr/bin/env python3
"""Create or update a Boxcryptor .bckey vault file.

Usage:
    bckey-tool.py new    [options] <file.bckey>
    bckey-tool.py update [options] <file.bckey>

Commands:
    new     Create a new .bckey file with a fresh RSA-4096 key pair.
    update  Re-wrap keys under a new password / new PBKDF2 parameters.

Options:
    --pass <password>      Current master password.
                           Priority: BC_PASSWORD env var → --pass → interactive prompt.
    --new-pass <password>  New master password (update only).
                           Priority: BC_NEW_PASSWORD env var → --new-pass → interactive prompt.
                           Prompted twice for confirmation.
    --keep-pass            Reuse current password as new password
    --keep-wrapping        Reuse the existing wrapping key
    --keep-iv              Re-use the existing IV for each wrapped blob (requires --keep-wrapping)
    --keep-salt            Reuse the existing KDF salt (new pwdKey still derived if password/iterations change)
    --keep-iterations      Keep the stored iteration count (default: upgrade to --iterations value)
    --keep-aes-key         Re-use the existing RSA-encrypted aesKey blob verbatim (skip re-encryption).
    --new-rsa-key          Generate a fresh RSA-4096 key pair (update only). The aesKey is
                           decrypted with the old key and re-encrypted to the new public key.
                           Combine with --keep-* to rebuild a file with all other params kept.
                           Mutually exclusive with --keep-aes-key.
    --new-filename-key     Generate a fresh 64-byte filename key (update only). Re-wraps
                           keys.filename and rebuilds aesKey as
                           SHA256(filenameKey) ‖ filenameKey.
                           Mutually exclusive with --keep-aes-key.
    --out <file.bckey>     Write the result here instead of modifying the input in place.
    --iterations <n>       PBKDF2-SHA512 iterations (default 600000, min 10000).
    --id <user-id>         User ID for 'new' command (default: random 16-digit decimal).

Requires: cryptography  (pip install cryptography)
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import struct
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    answer = input("Required package 'cryptography' is not installed. Install now? [y/N] ").strip().lower()
    if answer != "y":
        sys.exit("Aborted.")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("command", choices=["new", "update"], help="Command to run")
    p.add_argument("bckey_file", metavar="file.bckey", help="Target .bckey file path")
    p.add_argument("--pass", dest="password",
                   help="Current master password (WARNING: visible in process list)")
    p.add_argument("--new-pass", dest="new_password",
                   help="New master password (WARNING: visible in process list)")
    p.add_argument("--keep-pass", action="store_true",
                   help="Keep current password as new password")
    p.add_argument("--keep-wrapping", dest="keep_wrapping", action="store_true",
                   help="Keep the existing wrapping key (default: generate a new one)")
    p.add_argument("--keep-iv", dest="keep_iv", action="store_true",
                   help="Re-use existing IVs when re-wrapping blobs (requires --keep-wrapping)")
    p.add_argument("--keep-salt", dest="keep_salt", action="store_true",
                   help="Keep the existing KDF salt instead of generating a new one")
    p.add_argument("--keep-iterations", dest="keep_iterations", action="store_true",
                   help="Keep the stored iteration count (default: upgrade to --iterations value)")
    p.add_argument("--keep-aes-key", dest="keep_aes_key", action="store_true",
                   help="Keep the existing RSA-encrypted aesKey blob verbatim")
    p.add_argument("--new-rsa-key", dest="new_rsa_key", action="store_true",
                   help="Generate a fresh RSA-4096 key pair (update only); aesKey re-encrypted to new key")
    p.add_argument("--new-filename-key", dest="new_filename_key", action="store_true",
                   help="Generate a fresh filename key (update only); re-wraps keys.filename and aesKey")
    p.add_argument("--out", dest="out", default=None,
                   help="Write result to this path instead of modifying the input in place")
    p.add_argument("--iterations", type=int, default=None,
                   help="PBKDF2 iterations (new: default 600000; update: default preserves stored value)")
    p.add_argument("--id", dest="user_id", default=None,
                   help="User ID for 'new' command (default: random 16-digit decimal)")
    args = p.parse_args()

    if args.iterations is not None and args.iterations < 10000:
        p.error("--iterations must be >= 10000")

    if args.keep_aes_key and (args.new_rsa_key or args.new_filename_key):
        p.error("--keep-aes-key cannot be combined with --new-rsa-key/--new-filename-key "
                "(aesKey is RSA-encrypted to the public key and must be re-encrypted when either of its "
                "inputs — the RSA key or filename key — changes)")

    return args


# ---------------------------------------------------------------------------
# Password resolution
# ---------------------------------------------------------------------------

def _warn_cmdline(name: str) -> None:
    print(f"WARNING: {name} specified on command line — visible in process list.", file=sys.stderr)


def resolve_current_password(cli_value: str | None) -> str:
    env = os.environ.get("BC_PASSWORD", "")
    if env:
        return env
    if cli_value:
        _warn_cmdline("--pass")
        return cli_value
    return getpass.getpass("Current master password: ")


def resolve_new_password(cli_value: str | None, keep: bool, current: str) -> str:
    if keep:
        return current
    env = os.environ.get("BC_NEW_PASSWORD", "")
    if env:
        return env
    if cli_value:
        _warn_cmdline("--new-pass")
        return cli_value
    while True:
        p1 = getpass.getpass("New master password (Enter to keep current): ")
        if p1 == "":
            return current
        p2 = getpass.getpass("Confirm new master password: ")
        if p1 == p2:
            return p1
        print("Passwords do not match. Try again.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------

def derive_pwd_key(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, dklen=64)


def aes_cbc_wrap(plaintext: bytes, wrap_key: bytes, iv: bytes | None = None) -> bytes:
    """Wrap plaintext using AES-256-CBC + HMAC-SHA256.

    Layout: [IV(16)][HMAC-SHA256(32)][ciphertext]
    HMAC is over ciphertext only, keyed by wrap_key[32:64].
    """
    iv = iv if iv is not None else secrets.token_bytes(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(wrap_key[0:32]), modes.CBC(iv))
    ciphertext = cipher.encryptor().update(padded)

    mac = hmac.new(wrap_key[32:64], ciphertext, "sha256").digest()
    return iv + mac + ciphertext


def aes_cbc_unwrap(blob: bytes, wrap_key: bytes) -> bytes:
    """Unwrap AES-CBC+HMAC blob: [IV(16)][HMAC(32)][ciphertext]."""
    iv         = blob[0:16]
    given_hmac = blob[16:48]
    ciphertext = blob[48:]

    computed = hmac.new(wrap_key[32:64], ciphertext, "sha256").digest()
    if not hmac.compare_digest(computed, given_hmac):
        sys.exit("Error: HMAC verification failed — wrong password or corrupted key")

    cipher = Cipher(algorithms.AES(wrap_key[0:32]), modes.CBC(iv))
    decrypted = cipher.decryptor().update(ciphertext)
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()


def rsa_encrypt(plaintext: bytes, public_key) -> bytes:
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# Key generation helpers
# ---------------------------------------------------------------------------

def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def private_key_to_der(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1; matches Boxcryptor's stored format
        serialization.NoEncryption(),
    )


def public_key_to_der(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def random_user_id() -> str:
    return str(secrets.randbelow(10**16)).zfill(16)


# ---------------------------------------------------------------------------
# .bckey JSON construction
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def aes_key_checksum(filename_key: bytes) -> bytes:
    """Return aesKey[0:32], the SHA-256 checksum that binds the filename key.

    The 96-byte RSA-decrypted ``aesKey`` plaintext is ``SHA256(filenameKey) ‖ filenameKey``.
    Boxcryptor verifies ``aesKey[0:32] == SHA256(aesKey[32:96])`` on load; a mismatch (random
    bytes, or a stale checksum after rotating the filename key) makes the vault fail to open.
    """
    return hashlib.sha256(filename_key).digest()


def build_user_record(
    user_id: str,
    rsa_private_key,
    wrapping_key: bytes,
    filename_key: bytes,
    group_key: bytes,
    analytics_key: bytes,
    pwd_key: bytes,
    salt: bytes,
    iterations: int,
    password_hash: str,
) -> dict:
    pub_key = rsa_private_key.public_key()
    priv_der = private_key_to_der(rsa_private_key)
    pub_der  = public_key_to_der(pub_key)

    # aesKey = SHA256(filenameKey) (32 B) + filenameKey (64 B) = 96 bytes total
    aes_key_plaintext = aes_key_checksum(filename_key) + filename_key

    wrapped_priv_key    = aes_cbc_wrap(base64.b64encode(priv_der), pwd_key)
    wrapped_wrapping_key = aes_cbc_wrap(wrapping_key, pwd_key)
    wrapped_filename_key = aes_cbc_wrap(filename_key, wrapping_key)
    wrapped_group_key    = aes_cbc_wrap(group_key, wrapping_key)
    wrapped_analytics_key = aes_cbc_wrap(analytics_key, wrapping_key)
    encrypted_aes_key   = rsa_encrypt(aes_key_plaintext, pub_key)

    return {
        "id": user_id,
        "firstname": "Boxcryptor",
        "lastname": "Local",
        "username": "local@boxcryptor.com",
        "country": "en",
        "language": "en",
        "publicKey": b64(pub_der),
        "privateKey": b64(wrapped_priv_key),
        "aesKey": b64(encrypted_aes_key),
        "wrappingKey": b64(wrapped_wrapping_key),
        "keys": {
            "filename":        b64(wrapped_filename_key),
            "groupMembership": b64(wrapped_group_key),
            "analytics":       b64(wrapped_analytics_key),
        },
        "salt": b64(salt),
        "kdfIterations": iterations,
        "password": password_hash,
        "organization": "0",
    }


def build_bckey(user_record: dict) -> dict:
    return {
        "license": None,
        "artifact": "keyfile",
        "version": 1,
        "users": [user_record],
        "groups": [],
        "groupMemberships": [],
        "organization": {
            "id": "0",
            "name": "Boxcryptor",
            "keys": {},
        },
    }


def write_bckey(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
        f.write("\n")


# ---------------------------------------------------------------------------
# Backup helper
# ---------------------------------------------------------------------------

def backup_existing(path: str) -> None:
    p = Path(path)
    if not p.exists():
        return
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = p.with_suffix(f".{ts}.bak")
    shutil.copy2(path, backup)
    print(f"Backup: {backup}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Command: new
# ---------------------------------------------------------------------------

def cmd_new(args: argparse.Namespace) -> None:
    path = args.bckey_file
    if Path(path).exists():
        sys.exit(f"Error: {path} already exists. Use 'update' to modify an existing file.")

    password = resolve_current_password(args.password)
    if not password:
        sys.exit("Error: password required")

    iterations = args.iterations if args.iterations is not None else 600000
    salt       = secrets.token_bytes(24)
    pwd_key    = derive_pwd_key(password, salt, iterations)

    print("Generating RSA-4096 key pair…", file=sys.stderr)
    rsa_key       = generate_rsa_key()
    wrapping_key  = secrets.token_bytes(64)
    filename_key  = secrets.token_bytes(64)
    group_key     = secrets.token_bytes(64)
    analytics_key = secrets.token_bytes(64)

    user_id = args.user_id or random_user_id()

    # password field in .bckey is a base64-encoded random token (not the actual password)
    password_token = b64(secrets.token_bytes(48))

    user = build_user_record(
        user_id       = user_id,
        rsa_private_key = rsa_key,
        wrapping_key  = wrapping_key,
        filename_key  = filename_key,
        group_key     = group_key,
        analytics_key = analytics_key,
        pwd_key       = pwd_key,
        salt          = salt,
        iterations    = iterations,
        password_hash = password_token,
    )

    data = build_bckey(user)
    write_bckey(path, data)
    print(f"Created: {path}", file=sys.stderr)
    print(f"  user id   : {user_id}", file=sys.stderr)
    print(f"  iterations: {iterations}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Command: update
# ---------------------------------------------------------------------------

def cmd_update(args: argparse.Namespace) -> None:
    path = args.bckey_file
    if not Path(path).exists():
        sys.exit(f"Error: {path} not found. Use 'new' to create a new file.")

    with open(path) as f:
        vault = json.load(f)

    user = vault["users"][0]

    # --- resolve current password and verify it ---
    current_password = resolve_current_password(args.password)
    if not current_password:
        sys.exit("Error: current password required")

    salt_bytes = base64.b64decode(user["salt"])
    old_iter   = int(user["kdfIterations"])
    old_pwd_key = derive_pwd_key(current_password, salt_bytes, old_iter)

    # Verify current password by attempting to unwrap the private key
    priv_key_blob = base64.b64decode(user["privateKey"])
    try:
        priv_der_b64 = aes_cbc_unwrap(priv_key_blob, old_pwd_key)
        priv_der     = base64.b64decode(priv_der_b64)
        rsa_key      = serialization.load_der_private_key(priv_der, password=None)
    except SystemExit:
        sys.exit("Error: current password incorrect")
    except Exception as e:
        sys.exit(f"Error: failed to load private key — {e}")

    # Unwrap wrappingKey with old pwdKey
    wrapping_key_blob = base64.b64decode(user["wrappingKey"])
    wrapping_key = aes_cbc_unwrap(wrapping_key_blob, old_pwd_key)

    # Unwrap all keys.* with old wrappingKey; also preserve their IVs for --keep-iv
    vault_keys = user.get("keys", {})
    unwrapped_keys: dict[str, bytes] = {}
    key_ivs: dict[str, bytes] = {}
    for name, blob_b64 in vault_keys.items():
        blob = base64.b64decode(blob_b64)
        key_ivs[name] = blob[0:16]
        unwrapped_keys[name] = aes_cbc_unwrap(blob, wrapping_key)

    # --- resolve new password ---
    new_password = resolve_new_password(args.new_password, args.keep_pass, current_password)
    if not new_password:
        sys.exit("Error: new password cannot be empty")

    new_iterations = old_iter if args.keep_iterations else (args.iterations if args.iterations is not None else 600000)
    new_salt       = salt_bytes if args.keep_salt else secrets.token_bytes(24)
    new_pwd_key    = derive_pwd_key(new_password, new_salt, new_iterations)

    # --- decrypt aesKey plaintext with the CURRENT (old) RSA key before any key rotation ---
    # aesKey is RSA-encrypted to the user's public key. To rotate the RSA key we must recover
    # the plaintext now (with the old private key), then re-encrypt to the new public key below.
    aes_key_plaintext = None
    if not args.keep_aes_key:
        try:
            aes_key_plaintext = rsa_decrypt(base64.b64decode(user["aesKey"]), rsa_key)
        except Exception as e:
            sys.exit(f"Error: failed to decrypt aesKey — {e}")

        # aesKey plaintext = SHA256(filenameKey) ‖ filenameKey(64). The leading 32 bytes are a
        # checksum, not independent key material, so they are always recomputed from filenameKey.
        filename_key = aes_key_plaintext[32:96]
        if args.new_filename_key:
            print("Generating new filename key…", file=sys.stderr)
            filename_key = secrets.token_bytes(64)
            unwrapped_keys["filename"] = filename_key      # re-wrapped below under wrappingKey
            key_ivs.pop("filename", None)                  # force fresh IV (plaintext changed)
        aes_key_plaintext = aes_key_checksum(filename_key) + filename_key

    # --- rotate RSA key pair if requested ---
    if args.new_rsa_key:
        print("Generating new RSA-4096 key pair…", file=sys.stderr)
        rsa_key = generate_rsa_key()

    # --- resolve output path and backup before writing ---
    out_path = args.out if args.out else path
    backup_existing(out_path)

    # --- re-wrap everything under new pwdKey / wrappingKey ---
    pub_key  = rsa_key.public_key()
    priv_der = private_key_to_der(rsa_key)
    pub_der  = public_key_to_der(pub_key)

    if not args.keep_wrapping:
        wrapping_key = secrets.token_bytes(64)

    # IV reuse for privateKey/wrappingKey is safe only when pwdKey is identical,
    # which requires the same password, salt, and iterations.
    pwd_key_unchanged = (new_pwd_key == old_pwd_key)

    if args.keep_iv and not args.keep_wrapping:
        print("Warning: --keep-iv has no effect on keys.* without --keep-wrapping (new wrapping key)", file=sys.stderr)
    if args.keep_iv and not pwd_key_unchanged:
        print("Warning: --keep-iv has no effect on privateKey/wrappingKey (pwdKey changed)", file=sys.stderr)

    priv_iv     = priv_key_blob[0:16]     if (args.keep_iv and pwd_key_unchanged) else None
    wrapping_iv = wrapping_key_blob[0:16] if (args.keep_iv and pwd_key_unchanged) else None

    wrapped_priv_key     = aes_cbc_wrap(base64.b64encode(priv_der), new_pwd_key, priv_iv)
    wrapped_wrapping_key = aes_cbc_wrap(wrapping_key, new_pwd_key, wrapping_iv)

    # keys.* are encrypted under wrappingKey. IV reuse is safe only when the wrapping
    # key is unchanged (--keep-wrapping) and the plaintext is unchanged. Without
    # --keep-wrapping the old IVs must not be reused under the new key.
    new_wrapped_keys: dict[str, str] = {}
    for name, raw in unwrapped_keys.items():
        iv = key_ivs.get(name) if (args.keep_iv and args.keep_wrapping) else None
        new_wrapped_keys[name] = b64(aes_cbc_wrap(raw, wrapping_key, iv))

    # aesKey: keep existing blob verbatim, or re-encrypt the recovered plaintext under the
    # (possibly rotated) public key.
    if args.keep_aes_key:
        encrypted_aes_key_b64 = user["aesKey"]
    else:
        encrypted_aes_key_b64 = b64(rsa_encrypt(aes_key_plaintext, pub_key))

    updated_user = {
        **user,
        "publicKey":     b64(pub_der),
        "privateKey":    b64(wrapped_priv_key),
        "aesKey":        encrypted_aes_key_b64,
        "wrappingKey":   b64(wrapped_wrapping_key),
        "keys":          new_wrapped_keys,
        "salt":          b64(new_salt),
        "kdfIterations": new_iterations,
    }

    vault["users"][0] = updated_user
    write_bckey(out_path, vault)

    print(f"Updated: {out_path}", file=sys.stderr)
    print(f"  iterations: {old_iter} → {new_iterations}", file=sys.stderr)
    if new_password != current_password:
        print("  password changed", file=sys.stderr)
    if args.new_rsa_key:
        print("  RSA key pair rotated", file=sys.stderr)
    if args.new_filename_key:
        print("  filename key rotated (keys.filename + aesKey checksum)", file=sys.stderr)
    if not args.keep_wrapping:
        print("  wrapping key rotated", file=sys.stderr)
    if args.keep_aes_key:
        print("  aesKey preserved verbatim", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("new", "update"):
        print(__doc__)
        sys.exit(0)

    args = parse_args()

    if args.command == "new":
        cmd_new(args)
    elif args.command == "update":
        cmd_update(args)


if __name__ == "__main__":
    main()
