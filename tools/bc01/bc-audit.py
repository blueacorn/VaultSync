#!/usr/bin/env python3
"""Audit .bc files for BC01 header defects. Reads only the header prefix and the file size.

Usage:
    bc-audit.py [path ...] [--recursive] [--exclude PATTERN ...] [--jobs N] [--header-size] [--quiet/--all]
                [--keyfile vault.bckey [--password PW] [--hmac-check]]

Checks (always):
    hmac-zero      JSON header HMAC bytes 16–47 are zeroed (pre-HMAC writer)
    padding        cipher padding (bytes 12–15) inconsistent with body length / BC01Framing
                   (a self-consistent wrong count needs bc-audit-padding.py)
Checks (opt-in):
    header-size    --header-size: header end != BC01Framing.headerSize(plaintext)
    key-length     --keyfile: unwrapped file key is not 96 B (64 B = prior implementation)
    key-checksum   --hmac-check: key[0:32] != SHA-256(key[32:96])
    hmac-mismatch  --hmac-check: bytes 16–47 != HMAC-SHA256(key[64:96], on-disk JSON)
                   (expected for ~50% of genuine Boxcryptor files)

Paths default to the current directory. Exit status 1 when any file has a finding.
"""

import argparse
import base64
import collections
import concurrent.futures
import fnmatch
import getpass
import hashlib
import hmac
import importlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
info = importlib.import_module("bc-info")          # framing mirror of BC01Framing.swift

MAGIC = b"bc01"
MAX_CORE_LEN = info.LARGE_HEADER                   # JSON core cannot exceed the header reserve


# --- Discovery ---

def is_excluded(name, excludes):
    """True when `name` (a basename) matches any glob in `excludes`."""
    return any(fnmatch.fnmatch(name, pattern) for pattern in excludes)


def find_bc_files(paths, recursive, excludes=()):
    """Yield `("dir", (path, file_count))` on entering a folder (recursive only) and
    `("file", path)` per .bc file under `paths` (files are taken as given).

    Files and folders whose basename matches an `excludes` glob are skipped; excluded folders
    are not descended into.
    """
    for path in paths:
        if os.path.isfile(path):
            yield "file", path
        elif recursive:
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not is_excluded(d, excludes))
                names = [n for n in sorted(files)
                         if n.endswith(".bc") and not is_excluded(n, excludes)]
                yield "dir", (root, len(names))
                for name in names:
                    yield "file", os.path.join(root, name)
        else:
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                if (name.endswith(".bc") and not is_excluded(name, excludes)
                        and os.path.isfile(full)):
                    yield "file", full


# --- Header probe ---

class Header:
    """Raw header fields + JSON core, read from the file prefix only."""

    def __init__(self, path):
        self.size = os.path.getsize(path)
        with open(path, "rb") as f:
            raw = f.read(info.RAW_HEADER_LEN)
            if raw[:4] != MAGIC:
                raise ValueError(f"not BC01 (magic {raw[:4].hex() or 'empty'})")
            if len(raw) < info.RAW_HEADER_LEN:
                raise ValueError(f"truncated raw header ({len(raw)} B)")
            self.core_len, self.pad_len, self.cipher_pad = struct.unpack("<III", raw[4:16])
            self.stored_hmac = raw[16:48]
            if self.core_len > MAX_CORE_LEN:
                raise ValueError(f"implausible core length {self.core_len}")
            self.core = f.read(self.core_len)
        if len(self.core) < self.core_len:
            raise ValueError("truncated JSON core")
        self.header_end = info.RAW_HEADER_LEN + self.core_len + self.pad_len
        if self.header_end > self.size:
            raise ValueError(f"header end {self.header_end} beyond file size {self.size}")
        self.plaintext = max(0, self.size - self.header_end - self.cipher_pad)


# --- Checks ---

def framing_findings(h, check_header_size):
    findings = []
    if h.stored_hmac == bytes(32):
        findings.append("hmac-zero")
    # The pad count is checked against the body length it implies. A wrong count that is still
    # self-consistent (e.g. legacy flag 1 over a 16-byte body) is only detectable by decrypting
    # the final block — see bc-audit-padding.py.
    body = h.size - h.header_end
    expected_pad = info.cipher_padding(h.plaintext)
    if (h.cipher_pad > info.AES_BLOCK or body < h.cipher_pad or body % info.AES_BLOCK
            or h.cipher_pad != expected_pad):
        findings.append(f"padding: {h.cipher_pad} over body {body}, expected {expected_pad}")
    if check_header_size:
        expected_end = info.header_size(h.plaintext)
        if h.header_end != expected_end:
            findings.append(f"header-size: {h.header_end}, expected {expected_end}")
    return findings


def key_findings(h, rsa_key, check_hmac):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    oaep = asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA1()),
                             algorithm=hashes.SHA1(), label=None)
    try:
        entries = json.loads(h.core).get("encryptedFileKeys", [])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ["json: unparseable core"]
    key = None
    for entry in entries:
        try:
            key = rsa_key.decrypt(base64.b64decode(entry["value"]), oaep)
            break
        except (ValueError, KeyError):
            continue
    if key is None:
        return ["key: no encryptedFileKeys entry unwraps with this keyfile"]

    findings = []
    if len(key) != 96:
        findings.append(f"key-length: {len(key)} B"
                        + (" (prior implementation)" if len(key) == 64 else ""))
    if check_hmac and len(key) == 96:
        if hashlib.sha256(key[32:96]).digest() != key[:32]:
            findings.append("key-checksum")
        if h.stored_hmac != bytes(32):
            mac = hmac.new(key[64:96], h.core, hashlib.sha256).digest()
            if mac != h.stored_hmac:
                findings.append("hmac-mismatch")
    return findings


# --- Audit ---

def audit_file(path, args, rsa_key):
    """Audit one file. Returns `(status, line)`; status is "ok", "flag" or "error"."""
    try:
        h = Header(path)
    except (OSError, ValueError) as e:
        return "error", f"ERROR  {path}: {e}"
    findings = framing_findings(h, args.header_size)
    if rsa_key is not None:
        findings += key_findings(h, rsa_key, args.hmac_check)
    if findings:
        return "flag", f"FLAG   {path}: {'; '.join(findings)}"
    return "ok", f"OK     {path}"


def audit_in_order(entries, args, rsa_key):
    """Yield `(status, payload)` per discovery entry, in discovery order, auditing up to
    `args.jobs` files concurrently. A bounded look-ahead keeps output incremental."""
    window = collections.deque()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for kind, value in entries:
            if kind == "dir":
                window.append(("dir", value))
            else:
                window.append(pool.submit(audit_file, value, args, rsa_key))
            while len(window) > args.jobs * 2 or (window and isinstance(window[0], tuple)):
                head = window.popleft()
                yield head if isinstance(head, tuple) else head.result()
        while window:
            head = window.popleft()
            yield head if isinstance(head, tuple) else head.result()


# --- Output ---

class Reporter:
    """Prints results with a per-folder `DIR path  [done/count]` line.

    On a terminal the DIR line counts up in place; a result line printed mid-folder freezes it
    and the DIR line is redrawn below. When piped, the DIR line prints once with its file count.
    """

    def __init__(self, stream=sys.stdout, show_dirs=True):
        self.stream = stream
        self.show_dirs = show_dirs      # False: print result lines only
        self.live = stream.isatty()
        self.dir = None                 # (path, count) of the current folder
        self.done = 0
        self.open_line = False          # live DIR line on screen without a newline

    def enter_dir(self, path, count):
        self._close_line()
        self.dir, self.done = (path, count), 0
        if not self.show_dirs:
            return
        if self.live:
            self._draw_dir()
        else:
            self._write(f"DIR    {path}  [{count}]\n")

    def file_done(self, line=None):
        self.done += 1
        if line is not None:
            self._close_line()
            self._write(line + "\n")
        if self.live and self.dir and self.show_dirs:
            self._draw_dir()

    def finish(self):
        self._close_line()

    def _draw_dir(self):
        path, count = self.dir
        self._write(f"\r\033[KDIR    {path}  [{self.done}/{count}]")
        self.open_line = True

    def _close_line(self):
        if self.open_line:
            self._write("\n")
            self.open_line = False

    def _write(self, text):
        self.stream.write(text)
        self.stream.flush()


# --- Main ---

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*", default=["."], help="files or folders (default: .)")
    p.add_argument("--recursive", "-r", action="store_true", help="descend into subfolders")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="skip files/folders whose name matches this glob (repeatable)")
    p.add_argument("--jobs", "-j", type=int, default=1, metavar="N",
                   help="audit N files in parallel (default: 1)")
    p.add_argument("--header-size", action="store_true", help="check reserved header size")
    p.add_argument("--hmac-check", action="store_true",
                   help="check file-key checksum and JSON header HMAC (needs --keyfile)")
    p.add_argument("--keyfile", help="vault .bckey: enables key-length check")
    p.add_argument("--password", help="master password (prompted if omitted)")
    p.add_argument("--all", action="store_true", help="also list files with no findings")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="omit DIR progress lines; print only findings and errors")
    args = p.parse_args()

    if args.hmac_check and not args.keyfile:
        p.error("--hmac-check requires --keyfile")
    if args.jobs < 1:
        p.error("--jobs must be >= 1")

    rsa_key = None
    if args.keyfile:
        audit_padding = importlib.import_module("bc-audit-padding")
        rsa_key = audit_padding.unwrap_vault_key(
            args.keyfile, args.password or getpass.getpass("Master password: "))

    scanned = flagged = errors = 0
    reporter = Reporter(show_dirs=not args.quiet)
    entries = find_bc_files(args.paths, args.recursive, args.exclude)
    for status, payload in audit_in_order(entries, args, rsa_key):
        if status == "dir":
            reporter.enter_dir(*payload)
            continue
        scanned += 1
        errors += status == "error"
        flagged += status == "flag"
        reporter.file_done(payload if status != "ok" or args.all else None)
    reporter.finish()

    print(f"\n{scanned} scanned, {flagged} flagged, {errors} errors")
    sys.exit(1 if flagged or errors else 0)


if __name__ == "__main__":
    main()
