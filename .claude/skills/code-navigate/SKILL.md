---
name: code-navigate
description: Efficiently navigate codebase using INDEX.yaml instead of reading file content. Use during planning, code exploration, and implementation when you need to understand codebase.
---

rules:
- Query INDEX.yaml with `yq`; do NOT load code file contents into context
- Use file:line references when known
- If query is ambiguous, ask for clarification
- Cross-file text search → `rg`
- Git history → `git`

## INDEX.yaml schema

```
targets[]:
  id, name, description, type, module

files[]:
  path, target, purpose, module, checksum, mtime, classes[], protocols[], keyFunctions[], extensions[], interfaces[]

tests[]:
  path, purpose, checksum, mtime, classes[]

documentation[]:
  path, purpose, mtime, topics[], contents[]
```

## Example yq patterns (v4)

```bash
# Find files by purpose keyword
yq '.files[] | select(.purpose | contains("database")) | .path + ": " + .purpose' INDEX.yaml

# Find file defining a class/struct (array-member filter)
yq '.files[] | select(.classes[] | contains("Extension")) | .path' INDEX.yaml

# Files in a target
yq '.files[] | select(.target == "server") | .path + ": " + .purpose' INDEX.yaml
```
