# Backends — Overview

A *backend* is the remote store a File Provider domain is bound to. The extension talks to
every backend through one protocol, and shares one content pipeline across all of them.
Backend-specific behaviour is additive on that shared path, never a parallel fork of it.

Backends today:

| `BackendKind` | Implementation | Transport | Doc |
|---|---|---|---|
| `.oneDrive` | `GraphDriveClient` | HTTPS to Microsoft Graph, direct from the extension | [remote-onedrive.md](/docs/backend/remote-onedrive.md) |
| `.emulator` | `ServerEmulatorClient` | HTTP JSON-RPC to the app-hosted `StandaloneServer` | [local-server-emulator.md](/docs/backend/local-server-emulator.md) |
| `.localFS` | — | — | Declared in `BackendKind`; `BackendFactory` throws `notImplemented`. |

See also: [architecture.md](/docs/design/architecture.md),
[application.md](/docs/crypto/application.md),
[fetchcontents.md](/docs/workflows/fetchcontents.md),
[createItem.md](/docs/workflows/createItem.md).

## Layering

```
 NSFileProviderReplicatedExtension (Extension, Enumerator, Extension+*)
          │  DomainService value types (Entry, ItemIdentifier, Version, *Return)
          ▼
   ProviderBackend  ◄── BackendFactory.make(for:hostname:port:)
     │                    (reads DomainAccount.backendKind from SharedConfigStore)
     ├── GraphDriveClient ─────► Graph (MetadataCache, GraphDeltaSync, GraphRateLimiter)
     └── ServerEmulatorClient ─► StandaloneServer :24680 (ItemDatabase)
          │
          ▼  shared, backend-neutral
   StreamingDownload ─► ContentStreamDownloader ─► ContentFetching   (per-backend adapter)
   ContentStreamUploader ───────────────────────► ContentPutting    (per-backend adapter)
   BC01HeaderCache / BC01HeaderProbe / HeaderCacheSeeding
```

## `ProviderBackend`

[Extension/Backend/ProviderBackend.swift](/Extension/Backend/ProviderBackend.swift)

The seam exchanges the existing `DomainService` types, so a backend is a transport swap, not a
new item model. Operations the framework drives through `Progress` (fetch, list, download,
create folder, metadata, delete, trash, thumbnails, conflicts) take a result block and return
`Progress`; the rest are `async throws`.

Groups:

- **Reserved identifiers** — `rootItemIdentifier`, `trashItemIdentifier`. Both backends use the
  universal `.root` / `.trash` sentinels and translate at their wire edge.
- **Capabilities** — opt-in flags, all defaulting to `false`:
  `supportsMoveToTrash`, `supportsTrashEnumeration`, `supportsRestore`,
  `supportsResourceFork`, `supportsByteRangeMaterialisation`. The extension gates behaviour on
  these instead of on the backend's concrete type. Trash acceptance and trash enumeration are
  separate because a store can accept deletes into a bin without being able to list it.
- **Display rewriting** — `displayEntry` (decode BC01 names, substitute known plaintext size)
  and `isBackendEncrypted`, evaluated on the raw name because decoding strips the signal.
- **Enumeration** — `fetchItem`, `listFolder` (paged by an opaque, backend-owned `PageCursor`),
  `latestRank`, `listChanges` (rank-based sync anchors).
- **Background change detection** — `pollDelta`, `indexedItemCount`, `domainVersion`.
  Defaults are no-ops for backends without a remote to poll. The extension only starts a
  `DeltaPoller` for backends that poll.
- **Content** — `downloadToFile` is the single materialisation path (whole-file and byte-range).
  `createStreaming` / `modifyContentsStreaming` are the single upload path for file contents.
  `createFolder` creates folders; `modifyContents` only replaces resource forks.
- **Metadata / lifecycle** — `modifyMetadata` must persist *every* field, locally if the remote
  has no home for it; `deleteItem`, `trashItem`, `isItemTrashed`, `restoreItem`, `mark`.
- **Locks, thumbnails, conflicts** — presentation locks, thumbnail fetch/update, conflict
  versions. Backends without a native concept implement these as no-ops or `notImplemented`.

### Encryption boundary

The extension passes an opaque `FileEncryptor` / `FileDecryptor` across the seam. Backends
never see key material. Fail-closed is enforced extension-side: an unavailable key throws
`notAuthenticated` before any backend call, so plaintext never reaches an encrypted domain.
See [application.md](/docs/crypto/application.md).

## Shared content pipeline

| Unit | Role |
|---|---|
| [ContentStreamDownloader](/Extension/Backend/ContentStreamDownloader.swift) | Fetch → decrypt → offset-write over one or more concurrent range lanes. Memory bounded to ~one lane span. |
| `ContentFetching` | Per-backend adapter: `totalSize` + `fetchRange(start:length:)`. A short read is a transport failure; the pipeline enforces this via `fetchExactRange`. |
| [StreamingDownload](/Extension/Backend/StreamingDownload.swift) | Thin wiring each backend's `downloadToFile` calls: header-cache lookup, run the downloader, publish a freshly probed header and exact plaintext size. |
| [ContentStreamUploader](/Extension/Backend/ContentStreamUploader.swift) | Read plaintext ranges → encrypt block-by-block → PUT ciphertext at its offset. Uses one request when the ciphertext fits `singleRequestLimit`, fragments otherwise. |
| `ContentPutting` | Per-backend adapter: `fragmentAlignment`, `supportsParallelFragments`, `singleRequestLimit`, `putWhole`, `putRange`. |
| [BC01HeaderProbe](/Extension/Backend/BC01HeaderProbe.swift) | Probe a prefix, check magic, widen once if the header overflows. A `.bc` name without BC01 magic is served as plain. |
| [BC01HeaderCache](/Extension/Backend/BC01HeaderCache.swift) | Per-domain SQLite store of parsed headers, keyed by item id and bound to the content identity. Secrets sealed under a per-domain KEK; a locked vault is a cache miss, never an error. |
| [HeaderCacheSeeding](/Extension/Backend/HeaderCacheSeeding.swift) | Every upload re-encrypts under a fresh file key, so the uploader's header is written straight to the cache (or the row invalidated). |

Why a shared pipeline: partitioning, block decrypt/encrypt, offset accounting, progress, and
the exact-plaintext-size rule are identical for every backend. Two copies would drift.

The exact plaintext size of a BC01 file is only known after its header is parsed; it is never
derived from the ciphertext length. A resolved size must move the item's content version or
the framework keeps the stale `documentSize` (see `Version.stampingPlaintextSize`).

## Resource cleanup

[Extension/Backend/BackendResourceCleanup.swift](/Extension/Backend/BackendResourceCleanup.swift)

- `destroy(domainID:backend:)` — domain deletion. Unlinks the per-domain stores (metadata
  cache, BC01 header cache, progress snapshot).
- `empty(domainID:backend:)` — "Lock and Remove Vault". Clears rebuildable rows in place so a
  still-open extension handle stays valid.

Shared steps run unconditionally and are idempotent. Backend-specific steps are routed by
`BackendKind` through a registry (same idiom as `BackendRoutingProvisioningService`); the
registry is empty today because no backend has on-disk state outside the shared stores.

## Adding a backend

1. Add a `BackendKind` case and route it in
   [BackendFactory](/Extension/Backend/BackendFactory.swift).
2. Implement `ProviderBackend`. Opt into capabilities explicitly; inherit defaults otherwise.
3. Implement `downloadToFile` via `StreamingDownload` with a `ContentFetching` adapter.
4. Implement the streaming upload methods via `ContentStreamUploader` with a `ContentPutting`
   adapter. Declare the transport's real fragment constraints.
5. Seed/invalidate `BC01HeaderCache` on every upload and delete.
6. If the backend needs host-side provisioning or has backend-only on-disk state, register it
   in the provisioning / cleanup registries rather than special-casing callers.
7. If the backend keeps a local change store, implement `pollDelta`, `indexedItemCount` and
   `domainVersion`; otherwise inherit the no-op defaults.

Keep shared protocols vendor-neutral: name things for the second and third implementor.

A local-filesystem backend (`.localFS`) is planned; nothing beyond the enum case exists.
