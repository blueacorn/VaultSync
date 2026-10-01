#!/usr/bin/env python3
"""Classify project files vs INDEX.yaml checksums; emit structured metadata for changed/new files only."""

import binascii, json, os, re, subprocess, sys
from pathlib import Path

INDEX = Path("INDEX.yaml")
INCLUDE_EXT = {".swift", ".md", ".xcconfig"}
PRUNE_DIRS = {".build", "DerivedData", "xcuserdata"}

def crc32(path):
    val = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            val = binascii.crc32(chunk, val)
    return format(val & 0xFFFFFFFF, "08x")

def should_include(rel_path):
    p = Path(rel_path)
    for part in p.parts[:-1]:
        if part.startswith(".") or part in PRUNE_DIRS or part.endswith(".xcassets"):
            return False
    return p.suffix in INCLUDE_EXT

def extract_swift_meta(path):
    with open(path) as f:
        lines = f.readlines()
    meta = {}

    if lines and lines[0].startswith("/// "):
        meta["purpose"] = lines[0][4:].strip()

    content = "".join(lines)
    classes = re.findall(r"^\s*(?:(?:public|open|internal|fileprivate|private)\s+)?(?:final\s+)?(?:class|struct|enum)\s+(\w+)", content, re.MULTILINE)
    protocols = re.findall(r"^\s*(?:(?:public|open)\s+)?protocol\s+(\w+)", content, re.MULTILINE)
    extensions = re.findall(r"^extension\s+(\w+)", content, re.MULTILINE)
    functions = re.findall(r"^(?:(?:public|open|internal)\s+)?func\s+(\w+\s*\()", content, re.MULTILINE)

    if classes:    meta["classes"]       = list(dict.fromkeys(classes))
    if protocols:  meta["protocols"]     = list(dict.fromkeys(protocols))
    if extensions: meta["extensions"]    = list(dict.fromkeys(extensions))
    if functions:  meta["key_functions"] = list(dict.fromkeys(f.strip() for f in functions))
    return meta

raw = subprocess.run(["yq", "-o", "json", str(INDEX)], capture_output=True, text=True, check=True).stdout
index = json.loads(raw)

stored = {}
for e in index.get("files", []):
    stored[e["path"]] = str(e.get("checksum", ""))
for section in ("tests", "configuration"):
    for e in index.get(section, []):
        if "checksum" in e:
            stored[e["path"]] = str(e["checksum"])
for e in index.get("documentation", []):
    if "checksum" in e:
        stored[e["path"]] = str(e["checksum"])
    if "checksums" in e:
        base = e["path"].rstrip("/")
        for fname, cs in e["checksums"].items():
            stored[f"{base}/{fname}"] = str(cs)

ondisk = {}
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if not d.startswith(".") and d not in PRUNE_DIRS]
    for fname in files:
        rel = os.path.relpath(os.path.join(root, fname), ".")
        if should_include(rel):
            ondisk[rel] = crc32(os.path.join(root, fname))

for path in stored:
    if path not in ondisk:
        print(f"DELETED\t{path}")

for path, checksum in sorted(ondisk.items()):
    stored_cs = stored.get(path, "")
    if checksum == stored_cs:
        print(f"UNCHANGED\t{path}")
        continue

    state = "NEW" if not stored_cs else "CHANGED"
    mtime = int(os.path.getmtime(path))
    print(f"{state}\t{path}")
    print(f"CHECKSUM\t{checksum}")
    print(f"MTIME\t{mtime}")

    if path.endswith(".swift"):
        meta = extract_swift_meta(path)
        for k, v in meta.items():
            if isinstance(v, list):
                for item in v:
                    print(f"{k.upper()}\t{item}")
            else:
                print(f"{k.upper()}\t{v}")
    print("---")
