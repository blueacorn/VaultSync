# OneDrive Backend (Microsoft Graph)

`GraphDriveClient` implements `ProviderBackend` over the Graph DriveItem API for
**OneDrive Personal** (consumers tenant, single drive, no shared items).
Shared protocol and pipeline: [overview.md](/docs/backend/overview.md).

| File | Role |
|---|---|
| [Extension/Backend/OneDrive/GraphDriveClient.swift](/Extension/Backend/OneDrive/GraphDriveClient.swift) | `ProviderBackend` impl, HTTP core, upload/download adapters |
| [Extension/Backend/OneDrive/GraphDeltaSync.swift](/Extension/Backend/OneDrive/GraphDeltaSync.swift) | Delta crawl → cache reconciliation |
| [Extension/Backend/OneDrive/MetadataCache.swift](/Extension/Backend/OneDrive/MetadataCache.swift) | Per-domain SQLite metadata mirror, ranks, delta cursor |
| [Extension/Backend/OneDrive/DomainVersionStore.swift](/Extension/Backend/OneDrive/DomainVersionStore.swift) | `NSFileProviderDomainVersion` policy |
| [Extension/Backend/OneDrive/GraphRateLimiter.swift](/Extension/Backend/OneDrive/GraphRateLimiter.swift) | Throttling, priority lanes, backoff |
| [Extension/Backend/OneDrive/GraphMapping.swift](/Extension/Backend/OneDrive/GraphMapping.swift) | `driveItem` → `DomainService.Entry`, identifier/version mapping |
| [Common/OneDrive/GraphModels.swift](/Common/OneDrive/GraphModels.swift) | Graph wire models, fast timestamp decoding |
| [Common/Auth/MSALTokenStore.swift](/Common/Auth/MSALTokenStore.swift) | OAuth config, PKCE, token store |
| [VaultSync/OneDrive/](/VaultSync/OneDrive/) | App-side sign-in and serving-folder picker |
| [Extension/Polling/DeltaPoller.swift](/Extension/Polling/DeltaPoller.swift) | Periodic `pollDelta` driver |

## Topology

The extension calls `https://graph.microsoft.com/v1.0` **directly**. It holds the
`network.client` entitlement, so there is no localhost hop through the app (unlike the
emulator, see [local-server-emulator.md](/docs/backend/local-server-emulator.md)).

```
 VaultSync.app                              Provider.appex
 ─────────────                              ──────────────
 OneDriveSignIn (PKCE, interactive)         GraphDriveClient
 OneDriveFolderPicker / FolderBrowser         ├─ MSALTokenStore (refresh grant, silent)
        │                                     ├─ GraphRateLimiter
        │ refresh token (keychain,            ├─ MetadataCache (SQLite, App Group)
        │ keyed by domain id)                 ├─ GraphDeltaSync ◄── DeltaPoller (45 s ±20%)
        ▼                                     └─ BC01HeaderCache
   DomainAccount (config.json)                         │
   remoteItemID = serving folder                       ▼
                                          graph.microsoft.com/v1.0
```

Only the app performs interactive sign-in. The extension only redeems refresh tokens.

## Setup prerequisites

1. Register an application in Microsoft Entra for **personal Microsoft accounts**.
2. Add a mobile/desktop (custom scheme) redirect URI `<OAUTH_REDIRECT_SCHEME>://auth`.
   `OAUTH_REDIRECT_SCHEME` defaults to the lower-cased bundle id in
   [Configuration/Application.xcconfig](/Configuration/Application.xcconfig).
3. Set `MSGRAPH_CLIENT_ID` in `Application.xcconfig`. It is surfaced as the `MSGraphClientID`
   Info.plist key in **both** the app and `Provider/Info.plist`, because each process reads its
   own main bundle and the extension refreshes tokens itself. An empty or placeholder value
   logs an error and sign-in fails with `AADSTS700016`.
4. The redirect scheme reaches code via the `OAuthRedirectScheme` key in the Common
   framework's Info.plist (`AppIdentifiers.oauthRedirectScheme`) and is registered as a URL
   scheme in the app's Info.plist.

Scopes: `Files.ReadWrite offline_access User.Read`. `offline_access` is required; a token
response without a refresh token is rejected.

## Authentication

`MSALTokenStore` is a hand-rolled OAuth 2.0 client, **not** the MSAL SDK (name is historical).

- **Flow** — authorization code + PKCE (`S256`) via `ASWebAuthenticationSession`, with a random
  `state` checked on callback. Endpoints: `login.microsoftonline.com/consumers/oauth2/v2.0/*`.
- **Domain-scoped credentials** — the refresh token is keyed by the
  `NSFileProviderDomainIdentifier` raw value. Each domain signs in separately; signing one out
  cannot invalidate another.
- **Sign-in before the domain exists** — the token is held in an in-memory pending buffer and
  the app receives a handle; `commitPendingCredential` writes it once the domain is created,
  `discardPendingCredential` drops it if setup is abandoned. Nothing reaches the keychain
  meanwhile.
- **Storage** — `VaultRefreshTokenStore` keeps two data-protection-keychain slots per domain:
  a sealed copy (sealed to the domain's `refreshTokenKey.pub`) and an unwrapped,
  Provider-readable copy that exists only while the vault is unlocked. Sealing needs only the
  public half, so a rotated token can be persisted while the vault is locked. A missing
  unwrapped slot means a locked vault and surfaces as `notAuthenticated`. Sign-out removes both
  slots. See [application.md](/docs/crypto/application.md).
- **Access tokens** — in-memory per process, refreshed on miss/expiry with concurrent refreshes
  coalesced (the store is an `actor`). A `401` triggers one forced refresh and a single retry.
- **Locked vault** — `DeltaPoller` stops on `AuthError.vaultLocked` /
  `VaultKeyStoreError.locked` instead of backing off; unlock restarts it.

## Serving root

A domain maps to a user-chosen folder, not necessarily the drive root. The picker stores the
folder's DriveItem id in `DomainAccount.remoteItemID`; `BackendFactory` passes it as
`servingItemID`.

- `nil` → resolve `GET /me/drive/root` once, persist the id in the cache's `meta`
  (`root_graph_id`) so later launches skip the round trip. Concurrent callers share one
  in-flight resolution.
- Why a sub-folder root matters: delta is scoped to `/me/drive/items/{root}/delta`, so change
  tracking and the initial crawl cover only that subtree, not the whole drive.

## Identifiers and versioning

- The serving root maps to `.root`; every other item's identifier is its opaque DriveItem id.
  `GraphMapping.graphID(for:rootGraphID:)` translates back at the wire edge.
- `DomainService.Version`:

  ```
  content  = cTag (fallback eTag)  + "|p<displaySize>"   ← stampingPlaintextSize
  metadata = eTag
  ```

  `eTag` changes on any metadata or content change; `cTag` only on content.
- **Plaintext size in the content version.** `cTag`/`eTag` describe ciphertext and do not move
  when the exact BC01 plaintext length is resolved locally. The framework re-reads fields only
  when the version changes, so the published size is stamped into the content version from the
  same expression that sets `documentSize`; they cannot disagree.
- **File hashes are unused.** `quickXorHash`/`sha*` are decoded but play no role in versioning
  or concurrency: they hash ciphertext (meaningless for plaintext identity) and are not
  uniformly available across account types.

### Plaintext size

- Plain (non-`.bc`) files: `plaintext_size = remote size`, recorded at seed time.
- `.bc` files: `NULL` until a header is parsed (content fetch, `fetchItem(resolvingPlaintextSize: true)`,
  or upload). Until then the translator's estimate is published — a deliberate over-report,
  so the item is visible in Finder rather than withheld.
- Only exact values are persisted; an estimate stored as authority would outrank the real size
  on every later read.

## Concurrency (`If-Match`)

| Operation | `If-Match` | Why |
|---|---|---|
| Content PUT (simple) | yes, eTag | Prevent overwriting a newer server copy. |
| Upload session | yes, on `createUploadSession` only | Graph checks it at session creation, not per fragment. |
| Rename / move `PATCH` | **no** | OneDrive bumps a new item's eTag asynchronously after create. The held eTag is stale by the time Finder renames "untitled folder", the PATCH 412s, the framework cannot retry, and the item is stranded. A rename cannot lose data. |
| Create | n/a | `conflictBehavior: rename` (folders), `replace` (upload sessions). |

The eTag for a content write comes from the **MetadataCache row**, falling back to the
OS-supplied `existingRevision` only on a cache miss. The OS `baseVersion` lags OneDrive's async
eTag bump, so a quick second save would 412 and Finder would report "changed by another
application".

`412` maps to `CommonError.wrongRevision`.

## Mutation → cache rule

Every Graph mutation writes its response back into `MetadataCache` immediately; delta is too
slow to be the only path.

| Mutation | Cache effect |
|---|---|
| Create folder (`POST …/children`) | upsert returned item |
| Create / modify content | upsert returned item, seed BC01 header, record plaintext size |
| Rename / move (`PATCH`) | upsert returned item |
| Trash (`DELETE`) | `markTrashed` with name/parent from a fresh GET |
| Delete live item (`DELETE`) | `markDeleted` |
| Delete trashed item | `purgeItem` only (no network) |
| Restore (`POST …/restore`) | `resurrectItem`, then optional move `PATCH` |
| Any `404` during delete/trash | `purgeItem` and rethrow `itemNotFound` |

Parent-folder freshness is left to delta. Deletes also drop the item's BC01 header row.

## MetadataCache

SQLite (system `SQLite3`, no package) at `<AppGroup>/OneDriveCache/<domainID>.sqlite3`. A
metadata-only, **rebuildable** mirror of the serving subtree. Graph stays the source of truth.

Purpose: fast enumeration and offline browsing, the resumable delta cursor, and monotonic
local ranks that back File Provider sync anchors.

```
items                                         meta (key/value)
  graph_id  TEXT PK                             schema_version
  parent_id TEXT         idx_items_parent       root_graph_id
  name, is_folder                               delta_link          (nextLink or deltaLink)
  remote_file_size       (ciphertext length)    initial_crawl_complete
  etag, ctag                                    rank_hwm
  created, modified                             domain_version, domain_version_rank,
  deleted, deleted_at                           domain_version_epoch
  rank                   idx_items_rank         bcfolder:<parentID> (encrypted-folder mark)
  local_meta   BLOB (JSON: tagData, xattrs, marks, flags)
  plaintext_size         (NULL = unresolved)
  is_trashed   GENERATED (deleted=1 AND deleted_at NOT NULL) VIRTUAL
```

- **Schema change** → drop and rebuild; the next crawl repopulates.
- **WAL + `synchronous=NORMAL`** — skips per-commit fsync. A lost last commit after power loss
  is re-applied by the next delta pass.
- **`busy_timeout` 5 s** — the app empties the cache ("Lock and Remove") while the extension may
  hold a writer.
- **Local-only metadata** (`local_meta`) — Finder tags, extended attributes, heart/pinned/shared
  marks. Graph has no field for them; they are merged on read and never clobbered by delta.
- **BC01 bookkeeping files** (e.g. folder keys) are never cached; their presence marks the
  enclosing folder encrypted. `/children` seeding and delta apply the identical rule
  (`classifyChildrenPage` / `partition`) — divergence would hide or resurface items depending
  on which path saw them first. Items with a `remoteItem` facet (shared) are skipped.

### Tombstone lifecycle

```
            markTrashed(deletedAt)            purgeItem
   live ─────────────────────────► trashed ─────────────► purged
 deleted=0                        deleted=1              deleted=1
                                  deleted_at set         deleted_at NULL
     ▲            resurrectItem      │
     └───────────────────────────────┘
   live ── markDeleted ──────────────────────────────────► purged
```

`LifecycleState` (`live` / `trashed` / `purged`) is derived once from `deleted`/`deleted_at`;
SQL reads `is_trashed`. Never respell the predicate.

- `listChanges`: purged → `deletedEntries`; trashed → update with parent `.trash` (removing it
  instead leaves a ghost); live → update.
- Tombstones are sticky: `upsertBatch` uses `MAX(deleted, …)` and freezes a trashed row's name,
  parent and size, so a delayed delta echo cannot resurrect a deleted item. Only
  `resurrectItem` clears a tombstone.
- If delta returns a live item over a local tombstone, its parent is queued for a `/children`
  reconcile after the crawl; items Graph lists live there are resurrected (covers restore via
  the OneDrive web UI).
- Purged rows remain so the deletion can be emitted through `listChanges`.

### Cold-seed batching

Until the first delta crawl completes (`initial_crawl_complete`), opening a folder walks
`/children?$top=999` and seeds each page with **one** `upsertBatch` transaction. Per-row
upserts cost one transaction and fsync per child and caused 10–20 s cold-folder opens.
Tombstone probes are batched (`tombstonedIDs(among:)`) for the same reason. After the crawl
completes, folders are served from the cache with no network call.

## Delta sync

`GraphDeltaSync` (actor), driven by `DeltaPoller` every 45 s (±20% jitter, exponential backoff
to 5 min on failure).

```
no cursor + no pending gen → beginFullCrawl()
start: saved delta_link ?? /me/drive/items/{root}/delta?$top=2000&$select=…
loop:
  yield to interactive requests
  pending gen changed (Rebuild Index) → adopt it, restart from fresh start URL
  GET page ─ 410 ─► beginFullCrawl(), restart from fresh start URL
                    (second 410 in the same pass → return cursorExpired)
  partition → upsertBatch(gen) / markTrashed (deletedDateTime) / markDeleted
  final page of a full crawl → sweepUnseen(gen)
  emit DeltaPageUpdate (changed parents, itemsSeen)  → extension signals working set
  nextLink?  saveCursor(gen); stop here if cancelled; continue
  deltaLink? saveCursor(gen, finish) — clears pending gen; mark initial_crawl_complete; done
```

- **Crawl to completion, resumable.** Each `nextLink` is persisted, so an extension killed
  mid-crawl resumes from the next unfetched page instead of restarting.
- **Page size.** A cold crawl sends `Prefer: odata.maxpagesize=2000`, which Graph echoes into
  every `nextLink` (`$top` affects only the first page). Incremental passes keep the default.
- **Per-page signalling.** A pass returns once, too coarse for a large initial crawl, so each
  page reports its changed parents and running item count. `pollDelta` returns only the
  post-crawl reconcile parents, to avoid signalling every container twice.
- **Single-flight.** Overlapping passes return immediately (`isRunning`).
- **`listChanges` never triggers delta.** Coupling the framework's backlog drain to the crawl
  made each drain extend the work it was draining.
- **Full crawl = mark-and-sweep.** `beginFullCrawl()` bumps `crawl_gen`, records
  `pending_full_crawl_gen`, and clears `delta_link` + `initial_crawl_complete` (folder opens
  fall back to `/children` walks). Each crawl page stamps `seen_gen = gen` on every returned
  row — unchanged rows get the stamp only, no rank bump. At the deltaLink, `sweepUnseen` purges
  live non-root rows with `seen_gen < gen` (`deleted=1, deleted_at=NULL`, new rank); the
  working-set feed emits them as deletions. No cache wipe: `local_meta`, `plaintext_size`,
  `bcfolder:*` marks and `rank_hwm` survive. Trashed rows are not swept.
- **410 Gone** — Graph will not resume from the cursor: a new full crawl starts in the same
  pass and its sweep removes items deleted during the gap. A cancelled crawl keeps its pending
  generation and resumes from the saved `nextLink`; nothing is swept until it completes.
- **Non-crawl writers.** `/children` seeding and mutations leave `seen_gen` untouched on
  update and stamp fresh inserts with the pending generation — current remote state the crawl
  may already have paged past.
- **Cursor writes are generation-checked.** `saveCursor` writes only while the pending
  generation matches the pass's, so a pass superseded by Rebuild Index never restores its old
  cursor under the new generation.
- **Rebuild Index** (Edit Vault → Advanced, OneDrive only). `OneDriveProvisioningService`
  (routed by `BackendRoutingProvisioningService`) calls `beginFullCrawl()` from the app and
  signals the working set; the extension's next pass crawls and sweeps. No new IPC.

## Domain version

`DomainVersionStore` derives `NSFileProviderDomainVersion` from two monotonic inputs: the
cache's `rank_hwm` and the host's per-domain `configEpoch` (from `config.json`). The version
object is archived into `meta` with the stamps it reflects and advanced by `next()` once per
moved input. No movement re-reports the same version, so repeated working-set signals do not
loop. It is never written to `config.json`.

## Enumeration batching

| Path | Limit | Why |
|---|---|---|
| `listFolder` page | 1000 rows, keyset on `graph_id` | Framework ingest is ~2 ms/item regardless of page size; short pages let enumerations interleave. |
| `listChanges` page | 500 rows, rank-ordered, `hasMore` | The framework aborts a page > 20000 items, and will not serve interactive `fetchContents` until the in-flight page is applied. Small pages keep opens responsive during a cold backlog drain. |
| Trash (`listFolder(.trash)`) | 1000, from tombstones | Graph Personal has no recycle-bin listing endpoint. |

Recursive enumeration of the root (working set) is a flat scan of live rows; recursive below
the root uses a subtree query. The final `listChanges` page returns `rank_hwm` as the anchor.

## Content

### Download

`downloadToFile` runs `StreamingDownload` with a `GraphContentFetcher` over
`GET /me/drive/items/{id}/content` with `Range`. Byte-range materialisation is supported for
plain and `.bc` items. The header cache is keyed on the **cached** content identity, since
Graph always serves the current content. A missing cache row is an error, never size 0. A `200`
to a ranged request is accepted only when it is exactly the requested bytes. Parallel range
lanes use `parallelDownloadLanes` (per-host connection cap raised to match).

See [fetchcontents.md](/docs/workflows/fetchcontents.md).

### Upload

`createStreaming` / `modifyContentsStreaming` → `ContentStreamUploader` → `GraphContentPutter`.

| Ciphertext size | Path |
|---|---|
| ≤ 4 MiB (`simpleUploadLimit`) | single `PUT …/content` |
| > 4 MiB | `POST …/createUploadSession` (lazily, on first fragment) + fragment `PUT`s |

Upload-session rules:

- Fragment starts are multiples of **320 KiB**.
- Fragments are **sequential** (`supportsParallelFragments = false`). Graph rejects
  out-of-order fragments with `416`; parallelism for OneDrive belongs across files.
- `conflictBehavior: replace` is explicit. The default `fail` surfaces only on the final
  fragment as `409 nameAlreadyExists`, after the whole file was sent.
- Fragment PUTs go to a pre-authenticated URL with no `Authorization` header, but still pass
  through the rate limiter and retry policy. A session is cancelled on failure.
- Final fragment `200/201` carries the driveItem; `202` means more expected.

Create paths: `PUT /me/drive/items/{parent}:/{name}:/content`. See
[createItem.md](/docs/workflows/createItem.md).

## Throttling and retries

`perform(priority:authenticated:body:…)` is the single request driver.

| Status | Handling |
|---|---|
| 2xx | return |
| 401 | refresh token, retry once; then `notAuthenticated` |
| 404 | `CommonError.itemNotFound` |
| 409 (upload fragment) | terminal (`nameAlreadyExists`) |
| 409 (other) | transient lock, backoff retry |
| 412 | `wrongRevision` |
| 416 | terminal |
| 429 / 503 | record `Retry-After`, retry up to 5; then `serverUnreachable` |
| transport error | backoff retry (not cancellation) |

`GraphRateLimiter` (one per client):

- **Lanes.** `.interactive` (Finder enumeration, fetch, download, mutations) and `.background`
  (delta). Background waits out the full `Retry-After`; interactive waits at most 5 s, then
  fails fast with `serverUnreachable` so the system reschedules instead of Finder stalling.
- **Cool-off gate before every attempt**, so retries never fire inside a throttle window.
- **Soft yield.** Between delta pages the crawl pauses up to 1 s while interactive requests are
  in flight.
- **Backoff** `min(2^attempt, 30)` s with jitter in `[base/2, base]`, avoiding synchronized
  retry bursts from parallel lanes.

## Trash semantics

- `supportsMoveToTrash = true`: Graph `DELETE` moves to the OneDrive recycle bin.
- `supportsTrashEnumeration = true`: served from cache tombstones, since
  `$trash/children` is unavailable on Personal. Items trashed outside this domain (web UI, other
  clients) appear via delta `deletedDateTime`.
- `restoreItem`: `POST …/restore` always returns the item to its **original** parent (a
  `parentReference` in the body is ignored), so a restore to a different folder is followed by
  a move `PATCH`.
- Emptying the trash (delete of a trashed item) only purges the local row; no Graph call is made.
- Trashing from the encrypt/decrypt bulk action sets `restorableOutOfBand`, gating a custom
  Restore action because the framework has no recorded original parent.

## Thumbnails

`GET …/thumbnails/0/medium/content` for plain files. `.bc` files return empty data without a
request: Graph only sees ciphertext and would `404`.

## Not supported

Resource forks (`supportsResourceFork = false`; macOS keeps them locally), presentation locks
(ping/remove are no-ops, `forceLock` is `notImplemented`), conflict versions (OneDrive creates
server-side conflict copies), thumbnail upload, shared items, business accounts.
