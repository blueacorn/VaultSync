---
name: update-index
description: Update INDEX.yaml checksums and metadata for changed files only
disable-model-invocation: true
allowed-tools: Bash Read Write
---

## Run

```bash
python3 .claude/skills/update-index/scripts/scan.py
```

## Output format

```
UNCHANGED   path/to/file
CHANGED     path/to/file
CHECKSUM    <crc32>
MTIME       <unix>
PURPOSE     <from /// line 1>
CLASS       ClassName
PROTOCOL    ProtoName
EXTENSION   TypeName
KEY_FUNCTION funcName()
---
NEW         path/to/file
DELETED     path/to/file
```

## Claude's role

1. Run scan.py → receive structured diff only
2. CHANGED/NEW: update INDEX.yaml entry using emitted metadata
3. DELETED: remove entry
4. UNCHANGED: no action

## Sections tracked

scan.py compares all on-disk files against checksums from every INDEX.yaml section:

| Section         | Entry shape |
|-----------------|-------------|
| `files[]`       | `path` + `checksum` per entry |
| `tests[]`       | `path` + `checksum` per entry |
| `configuration[]` | `path` + `checksum` per entry |
| `documentation[]` | `path` + `checksum` per entry **or** `path` (directory) + `checksums: {filename: md5}` for grouped directories |

## Purpose field (Swift files only)

- Script extracts from `/// ` line 1 of Swift file
- If absent: use existing purpose from INDEX.yaml, add to line 1 of swift file, and re-calculate checksum and mtime
- If new file: add new summary to line 1 of swift file, and re-calculate checksum and mtime
- Always update checksum and mtime alongside purpose (all three are emitted together for CHANGED files)

## Entry formats

**files / tests / configuration** — full entry:
```yaml
path: relative/path/to/file
purpose: One-line description
target: target-id        # files only
module: Framework.name   # files only
checksum: <crc32, 8 hex>
mtime: <unix_timestamp>
classes: [Name]
protocols: [Name]
key_functions: [name()]
extensions: [Name]
```

**documentation** — individual file:
```yaml
path: docs/foo/bar.md
purpose: One-line description
checksum: <crc32, 8 hex>
mtime: <unix_timestamp>
topics: [...]
```

**documentation** — grouped directory:
```yaml
path: docs/skills/
purpose: One-line description
contents: [filename.md, ...]
checksums:
  filename.md: <crc32, 8 hex>
```

## Invariants

- Preserve existing values on parse error
- No duplicates
- Checksums: CRC32
