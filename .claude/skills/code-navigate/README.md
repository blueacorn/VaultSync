# README - developer notes (not parsed by AI)

**Skill:** codebase-navigator
**Pair skill:** update-index (maintains the INDEX.yaml you use)
**Base reference:** /Users/home/Code/VaultSync/INDEX.yaml

## Capabilities

This skill helps you:
1. **Find files by purpose** - "Show me all file provider UI files"
2. **Locate implementations** - "Which file implements NSFileProviderEnumerator?"
3. **Understand module structure** - "What's in the Server framework?"
4. **Check interfaces/protocols** - "Show me files implementing DomainService"
5. **Traverse dependencies** - "What imports this class?"
6. **Navigate to specific code** - Get clickable links to files

## How It Works

When invoked, this skill:

1. **Reads INDEX.yaml** - Gets current file metadata without loading entire codebase
2. **Parses YAML structure** - Efficiently queries file purposes, classes, and interfaces
3. **Responds with targeted information** - Only shows relevant metadata, not full file contents
4. **Provides navigation links** - Returns clickable file references for IDE navigation

## Usage Examples

```
Find Extension framework files:
/codebase-navigator Show me all files in Extension.framework

Locate protocol implementations:
/codebase-navigator Which files implement NSFileProviderReplicatedExtension?

Understand a module:
/codebase-navigator Explain the Server framework structure

Find a specific class:
/codebase-navigator Where is the StandaloneServer class?

Check dependencies:
/codebase-navigator What files depend on DomainService?

Navigate to code:
/codebase-navigator Show me the path to fetchContents implementation
```

## Search Commands (yq v4, INDEX.yaml)

```bash
# All files with descriptions
yq '.files | map(.path + ": " + .purpose) | .[]' INDEX.yaml

# All targets with descriptions
yq '.targets | map(.name + " (" + .id + "): " + .description) | .[]' INDEX.yaml

# Files in a target
yq '.files[] | select(.target == "extension") | .path' INDEX.yaml

# Files in a target with descriptions
yq '.files[] | select(.target == "extension") | .path + ": " + .purpose' INDEX.yaml

# Files grouped by target
yq '.files | group_by(.target) | map({"target": .[0].target, "files": map(.path)})' INDEX.yaml

# File count per target
yq '.files | group_by(.target) | map({"target": .[0].target, "count": length})' INDEX.yaml

# Total file count
yq '.files | length' INDEX.yaml

# Find files by purpose keyword
yq '.files[] | select(.purpose | contains("database")) | .path + ": " + .purpose' INDEX.yaml

# Find file defining a class
yq '.files[] | select(.classes[] | contains("Extension")) | .path' INDEX.yaml

# All classes by file
yq '.files[] | select(.classes) | {"path": .path, "classes": .classes}' INDEX.yaml

# All key functions by file
yq '.files[] | select(.keyFunctions) | {"path": .path, "functions": .keyFunctions}' INDEX.yaml

# All Swift extensions (partial implementations)
yq '.files[] | select(.extensions) | {"path": .path, "extensions": .extensions}' INDEX.yaml

# Find file implementing a specific interface
yq '.files[] | select(.interfaces[]? == "NSFileProviderReplicatedExtension protocol") | .path' INDEX.yaml

# All interfaces
yq '[.files[].interfaces[]?] | unique | .[]' INDEX.yaml

# All protocols and interfaces
yq '([.files[].interfaces[]?] + [.files[].protocols[]?]) | unique | .[]' INDEX.yaml

# Files with checksums
yq '.files[] | select(.checksum) | {"path": .path, "checksum": .checksum}' INDEX.yaml
```

## Query Types Supported

- **By framework**: "Show files in Extension.framework"
- **By purpose**: "Show me authentication-related files"
- **By class/protocol**: "Where is NSFileProviderItem implemented?"
- **By interface**: "Which files implement the RPC protocol?"
- **By directory**: "What's in the Common folder?"
- **By function**: "Where is the downloadItem function?"
- **Change history**: "What files changed recently?"

## Integration with Planning

When planning a feature or bug fix:

1. **Ask for file list** - "List all files that handle file enumeration"
2. **Get structure** - "Show me the dependency chain for domain management"
3. **Understand scope** - "What needs to change for X feature?"
4. **Find entry points** - "Where do new requests enter the system?"

## Efficiency Notes

- Uses INDEX.yaml checksums for change detection
- Does NOT load entire file contents into context
- Provides file:line references for deeper investigation
- Returns structured YAML for machine parsing

## Metadata Provided

For each file, the skill can show:
- **path** - Relative file path
- **purpose** - What the file does
- **module** - Framework it belongs to
- **classes** - Classes/structs defined
- **protocols** - Protocols/interfaces
- **key_functions** - Primary public functions
- **interfaces** - External APIs it implements
- **checksum** - For change detection
- **mtime** - Modification timestamp


## Architecture Navigation

This skill is particularly useful for understanding:

```
Finder → Provider.appex
         ↓
    HTTP localhost:24680
         ↓
    VaultSync.app (StandaloneServer)
         ↓
    Server.framework (ItemDatabase, Backends)
         ↓
    Common.framework (DomainService protocol)
         ↓
    Extension.framework (NSFileProvider impl.)
```

Use the skill to locate files at each layer.

---
