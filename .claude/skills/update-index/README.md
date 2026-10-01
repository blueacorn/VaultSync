# Update Index Skill

Keeps `INDEX.yaml` current using checksum-based change detection — only re-parses files that have actually changed.

## Usage

```
/update-index                          # update all changed files
/update-index Extension/               # scope to a directory
/update-index Extension/Extension.swift  # single file
```

## Output

```
INDEX.yaml Update Report
========================
Changed:    5  (Extension.swift, ItemDatabase.swift, ...)
New:        1  (docs/skills/new-skill.md)
Deleted:    0
Unchanged: 56

INDEX.yaml updated ✓  (62 files, 2.3s)
```

## When to Run

- After implementing a feature
- Before creating an implementation plan (`/code-navigate` depends on a fresh index)
- As a pre-commit step (configurable via hooks in `settings.json`)

## Pair Skills

| Skill              | Relationship                        |
|--------------------|-------------------------------------|
| `code-navigate`    | Consumes INDEX.yaml output          |
| `update-index`     | Update summaries in INDEX.yaml      |

## Troubleshooting

| Symptom                          | Cause / Fix                                          |
|----------------------------------|------------------------------------------------------|
| File unchanged but re-parsed     | Whitespace/line-ending change — correct behavior     |
| New file not picked up           | Must match `*.swift`, `*.md`, or `*.xcconfig`        |
| Stale metadata after rename      | Old path deleted, new path added automatically       |

## Target File

`/INDEX.yaml`
