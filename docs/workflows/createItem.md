# Item Creation (createItem)

## Trigger

A new file, folder, symlink or alias appears in a domain: a new document, a drag-in copy,
"New Folder", or an app's first save. NSFileProvider calls `createItem`. Every file-like
item uploads through one streaming path. The plaintext stays on disk and is encrypted
during upload by the shared `ContentStreamUploader`, so memory does not grow with file
size.

Related: [/docs/design/architecture.md](/docs/design/architecture.md),
[/docs/backend/remote-onedrive.md](/docs/backend/remote-onedrive.md),
[/docs/backend/local-server-emulator.md](/docs/backend/local-server-emulator.md),
[/docs/crypto/boxcryptor.md](/docs/crypto/boxcryptor.md),
[/docs/workflows/modifyItem.md](/docs/workflows/modifyItem.md).

## Block Diagram

```
┌──────────────────────────┐
│ Finder / app "save as"   │
└────────────┬─────────────┘
             │ NSFileProvider
             ▼
┌──────────────────────────────────────────────────────────┐
│ Provider.appex — Extension                               │
│  double-encrypt gate → type switch → name encoding       │
│  encryptor choice (BC01 | Plain)                         │
└──────┬───────────────────────────────────┬───────────────┘
       │ folder                            │ file / symlink / alias
       │ backend.createFolder              │ backend.createStreaming(param, contentsAt:, encryptor:)
       ▼                                   ▼
┌────────────────────┐        ┌────────────────────────────────────┐
│ OneDrive:          │        │ ContentStreamUploader (shared)     │
│ POST /children     │        │  ciphertext ≤ singleRequestLimit ? │
│ conflict: rename   │        │   yes → putter.putWhole            │
│ Emulator: RPC      │        │   no  → putter.putRange fragments  │
└─────────┬──────────┘        └───────────────┬────────────────────┘
          │                                   │
          ▼                                   ▼
   MetadataCache.upsert (OneDrive)    MetadataCache.upsert (OneDrive)
                                      BC01HeaderCache seed (both backends)
                                      plaintext size recorded (OneDrive)
          └───────────────┬───────────────────┘
                          ▼
               displayItem(entry) → completionHandler(item, [], false, nil)
```

The backend receives a plaintext URL, a name that already carries `.bc`, and an opaque
`FileEncryptor`. It never decides whether to encrypt and never sees key material.

## Flow

```
createItem(basedOn:fields:contents:options:request:)
  │  Progress(100) returned at once; work runs in a Task
  │  errors → asFileProviderError; cancellation → NSUserCancelledError
  ▼
createItemInternal
  ├─▶ requireBackend()
  ├─▶ double-encrypt gate (BC01 domain): name ends .bc / .bch
  │       → Darwin notification + NSFileProviderError(.cannotSynchronize)
  ├─▶ type switch on template.contentType
  │       .folder        → no content
  │       .symbolicLink  → target path written to a temp file (if .contents set)
  │       .aliasFile     → contents URL
  │       default (.file)→ contents URL; resource fork read from url/..namedfork/rsrc;
  │                        plaintext size taken from the file
  ├─▶ placeholder short-circuit
  │       mayAlreadyExist && type ∉ {folder, symlink} && no contents → return (nil, [], false)
  ├─▶ name: BoxcryptorMetadataTranslator.encodeForBackend  ("a.pdf" → "a.pdf.bc" on BC01)
  └─▶ conflict: mayAlreadyExist ? .updateAlreadyExisting : .failOnExisting
  ▼
CreateParameter(parent, name, type, metadata, conflict, contentStorageType, plaintextSize)
  ├── folder → backend.createFolder → displayItem → done
  └── file-like
        │  no contents → an empty temp file is uploaded
        │  encryptor: .file → makeEncryptor()   (.plain → Plain, .bc01 → BC01Encryptor;
        │                     BC01 key missing → .notAuthenticated before any upload)
        │             symlink / alias → PlainFileEncryptor
        ▼
      backend.createStreaming(param, contentsAt:, originalFilename:, encryptor:, progress:)
        ▼
      ContentStreamUploader.run
        │  stat source → plaintextSize
        │  encryptor.beginSession → header + key material, once
        │  BC01UploadPlan → ciphertextSize, block offsets
        ├── blockCount == 0 || ciphertextSize ≤ singleRequestLimit
        │     read + encrypt whole file → putter.putWhole
        └── else  spans = plan.laneSpans(fragmentBytes, alignment)
              serial path (transport rejects parallel fragments):
                encrypt span n+1 while span n is in flight → putter.putRange
              parallel path (transport allows it): windowed task group, ≤ lanes in flight
        ▼
      Result(completionPayload, ciphertextSize, blockContext)
        ▼
      backend post-processing (see table)
        ▼
      no contents URL (symlink / empty create) → displayItem → done
        ▼
      uploadResourceFork   — dropped when backend.supportsResourceFork == false
        ▼
      uploadThumbnail      — files only; domain opt-in; skipped for any encrypted domain
        ▼
      completionHandler(item, [], false, nil)
```

## Backend Post-Processing

| Step | OneDrive | Emulator |
|---|---|---|
| Folder create | `POST /items/{parent}/children`, `conflictBehavior: rename`; cache upsert | JSON-RPC `create` |
| File target | `PUT …/items/{parent}:/{name}:/content` or `…:/createUploadSession` | JSON-RPC `create` with the whole body |
| `singleRequestLimit` | 4 MiB | unlimited (`putRange` unreachable) |
| `ConflictStrategy` | not used; Graph `rename` (folders) / `replace` (files) | enforced by the server |
| MetadataCache | mandatory `upsert` of the returned item | none |
| Header cache | seeded from `blockContext` | seeded from `blockContext` (files only) |
| Plaintext size | `setPlaintextSize` from the source file's size | none |
| Resource fork | dropped | uploaded via `modifyContents(.resourceFork)` |

## Strategy

### Ciphertext geometry

Every offset is known before encryption, so `Content-Range` can state the exact total
up front:

```
headerEnd       = |header|                      (block-aligned, built once per file)
block i         → ciphertext [headerEnd + i*4096, …)
ciphertextSize  = headerEnd + plaintextSize + padding
padding         = 0 when the last block is full, else PKCS7 1…16 bytes
```

The padding comes from the session (`cipherPadding`), so the same plan is exact for the
plain passthrough session too (padding 0). See
[/docs/crypto/boxcryptor.md](/docs/crypto/boxcryptor.md).

### Fragment alignment (OneDrive)

Graph requires each non-final fragment to start on a 320 KiB multiple. The header rides with
fragment 0, so later fragments start at `headerEnd + n*4096`. `headerEnd` is block-aligned
but usually not 320 KiB-aligned. `BC01UploadPlan.laneSpans` therefore shortens the first
span so fragment 0 ends exactly on a 320 KiB boundary. Every later boundary is then aligned.

### Fragment size

Fragments are sequential, so each extra fragment costs a round trip.
`ContentStreamUploader.fragmentBytes(forPlaintextSize:)`:

| Plaintext | Fragment |
|---|---|
| < 32 MiB | 5 MiB |
| < 256 MiB | 10 MiB |
| ≥ 256 MiB | 20 MiB |

All sizes are multiples of 320 KiB and 4096 bytes, and never exceed Graph's 60 MiB ceiling.

### Fragments are sequential

A Graph upload session keeps one expected-range cursor. A fragment that is out of order, or
already received, gets `416`. `GraphContentPutter.supportsParallelFragments` is `false`,
so the uploader takes the serial path whatever `parallelUploadLanes` says. It overlaps the
encryption of span n+1 with the PUT of span n, which costs one extra resident span.

### Upload session lifecycle (OneDrive)

- `LazyUploadSession` creates the session on the first `putRange`, at most once. A
  single-request upload never pays that round trip.
- `createUploadSession` sends `conflictBehavior: replace`. The default, `fail`, reports
  `409` only when the final fragment commits.
- `If-Match` (modify only) is sent on the simple PUT or on session creation, never per
  fragment.
- Fragment PUTs go through `perform(authenticated: false, body:)`. They inherit rate
  limiting and 429/5xx backoff, and carry no bearer token (the URL is pre-authenticated).
  The body is passed as an upload body, so `URLSession` sets `Content-Length`. Setting it
  by hand causes a length mismatch that Graph answers with `416`.
- On failure, `cancelSession` sends `DELETE {uploadUrl}`, but only if a session exists.

### Cache reseed (OneDrive)

A successful create upserts the returned item into MetadataCache. The row's eTag is the
`If-Match` source for the next content write. Waiting for delta sync is too slow: a save
straight after a create would get `412`. The upsert is best-effort (`try?`).

### Encryption boundary

- `makeEncryptor()` fails closed. On a BC01 domain with no key available, the create fails
  with `.notAuthenticated` before any request. Plaintext is never written to an encrypted
  domain.
- Symlink targets and alias data use `PlainFileEncryptor`.
- Thumbnails are never uploaded from an encrypted domain. They are derived from plaintext.

## Error Handling

| Failure | Behaviour |
|---|---|
| No backend | `requireBackend()` throws |
| `.bc` / `.bch` name on a BC01 domain | Notification + `.cannotSynchronize` |
| BC01 key unavailable | `.notAuthenticated`, no upload |
| Placeholder create without contents | `(nil, [], false)` |
| HTTP 429 / 5xx (POST, simple PUT, session POST, fragment PUT) | Retried in `perform` |
| HTTP 4xx | Not retried; mapped by `toPresentableError()` |
| Upload failure after a session was created | `DELETE {uploadUrl}`; error propagates |
| No fragment returned a completion body | `CommonError.internalError` |
| Cancellation | `NSUserCancelledError` |
| Any error leaving `createItem` | `asFileProviderError`, so the framework does not replace it with an opaque internal error |

## Notes

- `contentStorageType` is `.contents` for file-like items and `nil` for folders.
  `modifyContents(_:data:)` is used only for `.resourceFork`.
- A create never needs a follow-up rename: the `.bc` name is applied up front.
