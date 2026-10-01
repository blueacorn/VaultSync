# Item Modification (modifyItem)

## Trigger

An existing item changes locally: a save (content), a rename or move (metadata), tags or
extended attributes, a move to Trash, or "Put Back". NSFileProvider calls `modifyItem` with
the item template, its `baseVersion`, and `changedFields`.

Related: [/docs/workflows/createItem.md](/docs/workflows/createItem.md) (shared upload
pipeline), [/docs/design/architecture.md](/docs/design/architecture.md),
[/docs/backend/remote-onedrive.md](/docs/backend/remote-onedrive.md),
[/docs/backend/local-server-emulator.md](/docs/backend/local-server-emulator.md),
[/docs/crypto/boxcryptor.md](/docs/crypto/boxcryptor.md).

## Dispatch

`modifyItemInternal` picks one branch, checked in this order:

```
modifyItem(item, baseVersion, changedFields, contents)
  │
  ├─ item already trashed && not a restore gesture ──▶ no-op: return trashed entry, []
  │
  ├─ .contents ─────────────────────────────────────▶ Content write
  │
  ├─ .parentItemIdentifier → trash ─────────────────▶ Move to Trash
  │
  ├─ .parentItemIdentifier, item currently trashed ─▶ Restore ("Put Back")
  │
  ├─ .parentItemIdentifier (syncChildrenBeforeParentMove, default on)
  │       waitForChanges(below: item) ──────────────▶ Metadata modify
  │
  └─ anything else (rename, tags, xattrs, …) ───────▶ Metadata modify
```

"Restore gesture" means `.parentItemIdentifier` is set to a container other than trash.
A recycle-bin item accepts no other mutation. Forwarding one to Graph would `404`, and the
framework would retry it forever. Every other modify on a trashed item therefore succeeds
without doing anything.

## Content Write

```
encryptionPlanForEdit(item)
  │  .plain domain / symlink          → encrypt = false
  │  backend name already .bc         → encrypt = true,  renameToBc = false
  │  plaintext name, autoEncryptOnEdit → encrypt = on,   renameToBc = on
  ▼
source = contents URL (or temp file with the symlink target)
encryptor = plan.encrypt ? makeEncryptor() : PlainFileEncryptor
  ▼
backend.modifyContentsStreaming(param(existingRevision: baseVersion, plaintextSize), …)
  │  ── OneDrive ──────────────────────────────────────────────────────────
  │  target = PUT /items/{id}/content  |  POST /items/{id}/createUploadSession
  │  If-Match = MetadataCache eTag  ?? baseVersion.metadata (cold-cache miss only)
  │  ContentStreamUploader (same as create)
  │  MetadataCache.upsert(returned item)
  │  header cache seeded with the new header (fresh file key + IV)
  │  plaintext size recorded from the source file
  │  returned entry carries the persisted plaintext size
  │  ── Emulator ──────────────────────────────────────────────────────────
  │  JSON-RPC modifyContents with the whole body; header cache seeded if accepted
  ▼
respItem = response item with contentModificationDate replaced by the template's
  ▼
contentAccepted == false (server kept its copy) → fork only, onto that item; return
  ▼
uploadResourceFork → uploadThumbnail          → remainingFields = []
  ▼
plan.renameToBc → renameBackendItemToEncrypted (in-place rename to "<name>.bc")
  ▼
completionHandler(item, [], false, nil)
```

### Rules

- **`If-Match` comes from MetadataCache, not `baseVersion`.** Every mutation response
  reseeds the cached eTag. The OS `baseVersion` lags OneDrive's eTag bump after a write, so
  a second save before the OS re-materialises would carry a stale eTag, get `412`, and show
  "changed by another application". `baseVersion` is used only when the cache has no row.
- **Echo the client's modification date.** The server stamps its own clock on write. That
  time is later than the mtime the open document holds, and returning it makes the OS see
  the file change underneath it.
- **`remainingFields` is `[]` on success.** The second completion argument lists fields
  that were *not* applied. Leaving `.contentModificationDate` in it made Finder report a
  change by another application.
- **Plaintext names stay plaintext.** In a BC01 domain with auto-encrypt off, a
  plaintext-named item is uploaded unencrypted. Encrypting it under a plaintext name would
  corrupt it for every reader.
- **Auto-encrypt renames after the write.** The content PUT runs first, then the backend
  item is renamed to `.bc` in place (same identifier). The display name does not change,
  because decoding strips `.bc`, so File Provider sees no rename. If the name is already
  `.bc` (a concurrent converter), the rename is skipped.

## Metadata Modify (rename / reparent / tags / xattrs)

```
backendFilename(forNewDisplayName:)          (only when .filename changed)
  │  current backend name ends .bc → displayName + ".bc"
  │  otherwise                     → displayName unchanged
  ▼
backend.modifyMetadata(ModifyMetadataParameter(filename, parent, metadata))
  │  ── OneDrive ──────────────────────────────────────────────────────────
  │  filename or parent set → PATCH /items/{id} {name, parentReference}, no If-Match
  │                           → MetadataCache.upsert(returned item)
  │  tags / xattrs          → local_meta sidecar in MetadataCache (rank bumped)
  │  return cachedEntry (row + sidecar overlay)
  │  ── Emulator ──────────────────────────────────────────────────────────
  │  JSON-RPC modifyMetadata
  ▼
completionHandler(displayItem(entry), [], false, nil)
```

### Rules

- **The rename keeps the item's current encryption state.** The backend name is the source
  of truth, not the domain default. `encodeForBackend` always appends `.bc` in a BC01
  domain. For a plaintext passthrough item (kept unencrypted, or restored with "Put Back"
  after an Encrypt action), that would put plaintext under a `.bc` name, and the next read
  would fail to decrypt.
- **No `If-Match` on rename or reparent.** OneDrive bumps a new item's eTag within seconds
  of the create. The eTag the create returned is stale when Finder renames "Untitled".
  A `412` there cannot be retried by File Provider, so the rename would be lost. A rename
  cannot lose data the way a content PUT can.
- **Tags and xattrs have no Graph field.** They live in the MetadataCache `local_meta`
  sidecar and are overlaid on every cache read (enumeration, fetchItem, downloadToFile).

## Trash and Restore

| Operation | OneDrive | Cache effect |
|---|---|---|
| Move to Trash | `GET` item, then `DELETE /items/{id}` (to the recycle bin) | `markTrashed(deletedAt:, name:, parent:)`; header row dropped |
| Already trashed | no request | none; returns the trashed entry |
| Backend lacks trash | `fetchItem`; returns the item at its current parent, so the OS moves it back | none |
| Restore | `POST /items/{id}/restore`; if the target parent differs, then `PATCH parentReference` | `resurrectItem` (upsert cannot clear a tombstone) |
| `404` on trash | — | `purgeItem`, header row dropped, `itemNotFound` |

Trash and restore return `changedFields` without `.parentItemIdentifier`, so any other
changed field is reported as not applied.

## Cache Invariant (OneDrive)

Every Graph mutation writes its result into MetadataCache before completing:

| Mutation | Cache write |
|---|---|
| Folder create, file create, content write, rename / move PATCH | `upsert(returned item)` |
| Move to Trash | `markTrashed` |
| Delete of a live item | `markDeleted` |
| Delete of a trashed item (empty Trash) | `purgeItem` (no network) |
| Restore | `resurrectItem` |
| Tags / xattrs / marks | `setLocalMetadata` |

Delta sync reconciles parents and remote changes later. The item's own row must be current
immediately, because the next `If-Match` read and the next enumeration depend on it.

## Error Handling

| Failure | Behaviour |
|---|---|
| BC01 key unavailable (encrypting write) | `.notAuthenticated`, no upload |
| Modify on a trashed item (not a restore) | Success, nothing done |
| Any error leaving `modifyItem` | `asFileProviderError` |
