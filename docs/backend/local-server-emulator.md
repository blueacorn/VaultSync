# Emulator Backend (Local Server)

The emulator is the reference and development backend: a complete remote store hosted inside
VaultSync.app and reached by the extension over localhost HTTP. It exercises every
`ProviderBackend` capability (trash, resource forks, conflicts, locks, byte ranges) and offers
fault injection, without a cloud account. Shared protocol and pipeline:
[overview.md](/docs/backend/overview.md).

## Why it lives in the app

`Provider.appex` is sandboxed without `network.server`, so it cannot host a listening socket or
open user-selected storage locations. The app can. The server therefore runs in VaultSync.app
and the extension is a plain HTTP client.

```
 Provider.appex                                VaultSync.app
 ──────────────                                ─────────────
 ServerEmulatorClient ── HTTP :24680 ────────► StandaloneServer
   (ProviderBackend)     x-domain                BackendDispatch (Swifter HttpServer)
                         x-authorization           └─ DomainBackend (one per account)
                                                        └─ ItemDatabase (SQLite files.db)
                        ◄── DistributedNotification ─ StandaloneServer (.itemsChanged)
```

| File | Role |
|---|---|
| [Extension/Backend/Emulator/ServerEmulatorClient.swift](/Extension/Backend/Emulator/ServerEmulatorClient.swift) | `ProviderBackend` impl + JSON-RPC client |
| [Common/Service/DomainService.swift](/Common/Service/DomainService.swift) | RPC contract: parameter/return types, endpoints, methods |
| [Server/HTTP/StandaloneServer.swift](/Server/HTTP/StandaloneServer.swift) | Lifecycle, accounts → backends, change notifications |
| [Server/Dispatch/BackendDispatch.swift](/Server/Dispatch/BackendDispatch.swift) | Routing, request lifecycle, fault injection, bandwidth throttle |
| [Server/Dispatch/DispatchBackend.swift](/Server/Dispatch/DispatchBackend.swift) | Backend registration protocols |
| [Server/HTTP/Errors.swift](/Server/HTTP/Errors.swift) | `CommonError` → HTTP status |
| [Server/Emulator/DomainBackend.swift](/Server/Emulator/DomainBackend.swift) | Per-domain RPC handlers, auth check, lock expiry |
| [Server/Emulator/ItemDatabase.swift](/Server/Emulator/ItemDatabase.swift) (+ extensions) | SQLite store |
| [Server/Provisioning/Emulator/EmulatorProvisioningService.swift](/Server/Provisioning/Emulator/EmulatorProvisioningService.swift) | Host provisioning hook |

## Lifecycle and provisioning

- `StandaloneServer` is constructed at app launch but only `run()` when at least one emulator
  domain is configured. Binding when none exists would hold the port and collide with another
  instance.
- `run()` opens `ItemDatabase` (`files.db` in the App Group container), starts
  `BackendDispatch` on `defaultPort` (24680), publishes Bonjour `_vaultsync._tcp.`, and builds
  one `DomainBackend` per account row. Account changes rebuild the backend set.
- Provisioning is routed by `BackendKind` through `BackendRoutingProvisioningService`; only
  `.emulator` maps to `EmulatorProvisioningService`, so a OneDrive domain never touches the
  emulator.

| `EmulatorProvisioningService` | `StandaloneServer` | Effect |
|---|---|---|
| `provision` | `provisionAccount` | Create/replace the account row; DB mints a root item |
| `deprovision` | `removeAccount` | Delete the row; no-op if the server never ran |
| `resetSyncAnchor` | `resetSyncAnchor` | Keep root, re-roll `tokenCheckNumber` |

Identity (display name, storage path) is not stored in the DB; `DomainBackend` reads it from
`SharedConfigStore` (`config.json`). The per-domain secret likewise lives in shared config.

## Transport

- HTTP/1.1, `http://<hostname>:24680/<endpoint>`. `hostname` comes from shared config
  (default `localhost`).
- Ephemeral `URLSession` with fixed headers:
  - `x-domain` — domain identifier; selects the `DomainBackend`.
  - `x-authorization` — per-domain secret from shared config.
- Responses close the connection (`Connection: Close`).
- A domain flagged offline in shared config fails every call locally with `timedOut` without
  sending anything.
- On `NSURLErrorNetworkConnectionLost` the client retries once.

### Request envelope

```
<METHOD> /<endpoint>?arguments=<percent-encoded JSON of the *Parameter struct>
x-domain: <domain id>
x-authorization: <secret>

<optional binary body: file content for create / modifyContents / updateThumbnail>
```

JSON uses snake_case keys. The universal `.root` / `.trash` identifiers are translated to the
server's own root/trash item ids during coding (`rootItemCodingInfoKey` /
`trashItemCodingInfoKey`), so neither side hard-codes the other's ids.

### Response envelope

| Case | Status | Headers | Body |
|---|---|---|---|
| Success, no payload | 200 | — | JSON `*Return` |
| Success with payload (download, thumbnail) | 200 | `API-Response: <base64 JSON *Return>`, `Content-Length` | raw bytes |
| Error | per table below | `CommonError.errorHeader`: JSON-encoded `CommonError` | empty |

A non-200 without the error header surfaces as `CommonError.httpError`.

## Request lifecycle

`BackendDispatch.withRequest`:

```
x-domain present? ─no─► parameterError
backend registered? ─no─► domainNotFound
checkForDomainApproval (x-authorization == secret, unless ignoreAuthentication) ─► authRequired
parse ?arguments= ─► decode Parameter ─fail─► parameterError
sleep(responseDelay)
random < errorRate ? ─► internalError (server) | clientCrashingError (plugin)
backend.queue.sync { handler }   ← one serial queue per domain
encode Return (+ payload through throttlingWriter)
```

Handlers are serialised per domain, so the database sees one writer per domain at a time.

## Error mapping

| `CommonError` | HTTP |
|---|---|
| `parameterError` | 400 |
| `authRequired`, `insufficientQuota` | 401 |
| `itemNotFound`, `domainNotFound` | 404 |
| `timedOut` | 408 |
| `itemExists`, `wrongRevision`, `accountExists`, `tokenExpired`, `deletionRejected` | 409 |
| `internalError`, `notImplemented`, `clientCrashingError`, `simulatedError` | 500 |

The extension maps these to File Provider errors in
[Extension/Errors/Error+Presentable.swift](/Extension/Errors/Error+Presentable.swift), e.g.
`tokenExpired` → `syncAnchorExpired`, `itemNotFound` → `noSuchItem`, `clientCrashingError` → deliberate extension exit (crash testing).

## API

Endpoints are declared on each `DomainService.*Parameter` (`endpoint`, `method`).

| Endpoint | Method | Parameter | Purpose |
|---|---|---|---|
| `list_folder` | POST | `ListFolderParameter` | Page children (keyset on `rowid`) |
| `list_changes` | POST | `ListChangesParameter` | Changes since a rank |
| `rank` | POST | `LatestRankParameter` | Current sync anchor |
| `info` | POST | `FetchItemParameter` | Item metadata |
| `download` | GET | `DownloadItemParameter` | Content or resource fork, optional `range` |
| `create` | POST | `CreateParameter` + body | Create item |
| `modifyContents` | POST | `ModifyContentsParameter` + body | Replace contents / fork |
| `modifyMetadata` | POST | `ModifyMetadataParameter` | Rename, move, attributes |
| `delete` | DELETE | `DeleteItemParameter` | Permanent delete |
| `trash` | POST | `TrashItemParameter` | Move to `.Trash` |
| `mark` | POST | `MarkParameter` | Heart / pinned / shared |
| `thumbnail` | POST | `FetchThumbnailParameter` | Thumbnail bytes |
| `updateThumbnail` | POST | `UpdateThumbnailParameter` + body | Store thumbnail |
| `conflicts/list` | POST | `ConflictVersionsParameter` | Conflict versions |
| `conflicts/resolve` | POST | `ResolveConflictVersionsParameter` | Keep versions |
| `conflicts/create` | POST | `CreateConflictParameter` | Inject a conflict (testing) |
| `lock/ping` | POST | `PingLockParameter` | Refresh presentation lock |
| `lock/remove` | POST | `RemoveLockParameter` | Release lock |
| `lock/force` | POST | `ForceLockParameter` | Break lock |
| `lock/debug/list` | POST | `ListLocksParameter` | List locks |
| `push/register` | POST | `PushRegistrationParameter` | Store push token/topic |
| `error/debug/set` | POST | `SimulateErrorParameter` | Inject per-item fault |
| `error/debug/list` | POST | `SimulateErrorListParameter` | List injected faults |

Unregistered paths return `notImplemented`.

## Client-side behaviour

`ServerEmulatorClient` is stateless on the extension side: no metadata cache, no poller.

- **Change detection** — the server posts a throttled (500 ms) `.itemsChanged` distributed
  notification per changed item; the app observes it and signals enumerators. `pollDelta` is
  the no-op default.
- **Sync anchors** — `RankToken(rank, tokenCheckNumber)`. A mismatched `tokenCheckNumber`
  (after `resetSyncAnchor`) returns `tokenExpired`, forcing a full re-enumeration.
- **BC01** — names/sizes decoded by `BoxcryptorMetadataTranslator`; bookkeeping files are
  filtered on the way out of `listFolder` / `listChanges` (there is no cache to filter at
  ingestion). `fetchItem` ignores `resolvingPlaintextSize`.
- **Download** — `StreamingDownload` over `EmulatorContentFetcher`: each range is a ranged
  `download` RPC with the requested content revision (mismatch → `wrongRevision`). Shares
  `BC01HeaderCache` with every other backend.
- **Upload** — `ContentStreamUploader` over `EmulatorContentPutter`. The RPC has no fragment
  protocol: `singleRequestLimit = .max`, so every upload is one `create` / `modifyContents`
  body with the full ciphertext in memory. Acceptable for a test backend; the extension-side
  path is identical to OneDrive's.
- **Capabilities** — move-to-trash, trash enumeration, resource forks, byte ranges. Restore is
  not supported (default).

## ItemDatabase

SQLite via SQLite.swift. Authoritative state for every emulator domain; one instance shared
by all `DomainBackend`s. On `dbVersion` mismatch all tables and stored content are dropped and
recreated (prototype policy, no migration).

```
items                         contents                          accounts
  id PK                          externalIdentifier PK             account PK
  name, parent                   id ─► items.id                    accountIdentifier UNIQUE
  metadataVersion                contentStorageType                rootItem ─► items.id
  contentVersion                 contentVersion, baseVersion       tokenCheckNumber
  deleted, rank                  contents (inline blob)
  type, resourceFork             externalSize, conflict          unlock
  thumbnail                      date, originatorName              id, expiry,
  metadata (JSON EntryMetadata)  domainIdentifier                  enumerationIndex UNIQUE, owner
  idx(name,parent), idx(rank)    idx(id)
                                                                 simulated_errors
push_tokens                                                        id, errorDomain, errorCode,
  token, topic, expiry                                             errorLocalizedDescription, accessType
```

- **Reserved ids** `0–9`; real items start at 10. Each account gets its own root item (whose
  parent is itself) and a `.Trash` folder under it, created on first backend init.
- **Versioning** — separate metadata and content version integers give optimistic concurrency
  (`wrongRevision`).
- **Ranks** — one monotonic counter across the database; every mutation allocates a new rank,
  which drives `list_changes` and sync anchors.
- **Conflicts** — multiple `contents` rows per item; reject / bounce / merge strategies.
- **Content bytes** — stored as a blob in `contents.contents` when `contentStoredInline` is set;
  otherwise as an external file named by `externalIdentifier`, under the account's configured
  storage path (`<path>/items/`) or `contents/` next to `files.db`. Resource forks are separate
  `contents` rows.
- **Locks** — expiring presentation locks; a per-backend timer re-arms on the next expiry.

## Fault injection and debug knobs

Host-local `UserDefaults` in the shared suite (read per request, so changes apply live):

| Key | Effect |
|---|---|
| `responseDelay` | Delay every request (ms) |
| `errorRate` | Percent of requests failing randomly |
| `errorType` | `0` server (`internalError`), `1` plugin (`clientCrashingError`), `2` both |
| `outgoingBandwidth` | KB/s cap on payload responses; `0` stalls until changed; unset = unlimited |
| `ignoreAuthentication` | Skip the `x-authorization` check |
| `ignoreLoggingForEndpoints` | Suppress per-request debug logs for listed paths |
| `contentStoredInline` | Store content as DB blobs instead of files |
| `batchSize` | `list_folder` page size (default 200) |

Plus per-domain `offline` in shared config (client-side) and per-item faults via
`error/debug/set` (returned as `simulatedError`).
