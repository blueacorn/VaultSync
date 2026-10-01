# Enumeration and Change Delivery

## Trigger

- **Items**: Finder opens a folder, or the system walks the working set or Trash.
  NSFileProvider calls `enumerator(for:)` and then `enumerateItems(for:startingAt:)`.
- **Changes**: the system holds a sync anchor and calls `currentSyncAnchor` /
  `enumerateChanges(for:from:)`. It does so after the extension signals the working set, or
  on its own schedule.
- **Remote changes (OneDrive)**: `DeltaPoller` runs a Graph delta pass every ~45 s,
  reconciles it into MetadataCache, and signals the working set.

Related: [/docs/design/architecture.md](/docs/design/architecture.md),
[/docs/backend/remote-onedrive.md](/docs/backend/remote-onedrive.md),
[/docs/backend/local-server-emulator.md](/docs/backend/local-server-emulator.md),
[/docs/workflows/fetchcontents.md](/docs/workflows/fetchcontents.md).

## Block Diagram (OneDrive)

```
 Graph /items/{root}/delta                 Finder / fileproviderd
          │                                          │
          ▼                                          │ enumerator(for:)
┌──────────────────────┐                             ▼
│ DeltaPoller (actor)  │            ┌─────────────────────────────────┐
│  45 s ±20%, backoff  │            │ ItemEnumerator                  │
│  pollDelta()         │            │  WorkingSetEnumerator (root, ⟳) │
└─────────┬────────────┘            │  TrashEnumerator                │
          ▼                         └──────┬───────────────┬──────────┘
┌──────────────────────┐   per page        │ listFolder    │ latestRank / listChanges
│ GraphDeltaSync       │── onDeltaProgress │               │
│  runPass: pages,     │        │          ▼               ▼
│  upsertBatch, tomb-  │        │   ┌───────────────────────────────────┐
│  stones, deltaLink   │        │   │ MetadataCache (SQLite)            │
└─────────┬────────────┘        │   │  items: rank, lifecycle,          │
          └────── writes ───────┼──▶│  plaintext_size, local_meta       │
                                │   │  meta: rank_hwm, deltaLink, crawl │
                                ▼   └───────────────────────────────────┘
                      SignalThrottle (1 s, leading + trailing)
                                │
                                ▼
               signalEnumerator(for: .workingSet)
```

All enumeration reads are served from MetadataCache. Graph is contacted only by the delta
crawl, and by `/children` for a folder opened before the first crawl completes.

## Enumerators

`Extension.enumerator(for:)` routes:

| Container | Enumerator | Notes |
|---|---|---|
| `.workingSet` | `WorkingSetEnumerator` | root, `recursive: true` |
| `.trashContainer` | `TrashEnumerator` | `noSuchItem` if `!backend.supportsTrashEnumeration` |
| any other | `ItemEnumerator` | non-recursive; tracks presentation (lock pings) for open files |

### enumerateItems

```
backend.listFolder(container, recursive:, startingCursor: page.pageCursor)
  │  OneDrive:
  │    trash        → cache.trashedItemsPage            (tombstones with deletedAt)
  │    non-recursive first page, crawl not complete
  │                 → GET /children?$top=999 (paged) → upsertBatch, resurrect tombstoned
  │    recursive at root   → cache.liveItemsPage        (flat scan)
  │    recursive below     → cache.descendants          (subtree CTE)
  │    otherwise           → cache.childrenPage
  │    keyset page of 1000 rows on graph_id; cursor = last graph_id when the page is full
  ▼
Item(backend.displayEntry(entry), isEncrypted:)     ← name decoded, plaintext size substituted
  ▼
observer.didEnumerate in chunks of batchSize(suggestedPageSize)   (default 1000, max 2000)
  ▼
finishEnumerating(upTo: next page | nil)
```

Before the first crawl finishes, the cache holds only part of the tree. Serving a folder
from it would show a truncated listing that nothing later completes, because delta reports
only changes after that point. `/children` covers that window. Once a crawl reaches a
`deltaLink`, folders are served from the cache alone.

### currentSyncAnchor

Returns `RankToken(rank: cache.currentRank())` (the rank high-water mark), JSON-encoded.

**It never returns `nil`.** A `nil` anchor turns off `enumerateChanges` for that enumerator,
and remote changes stop arriving without any error. On failure it returns a zero anchor.
The next change enumeration then replays the whole cache, which is safe only because
delivery is batched.

### enumerateChanges

```
RankToken(anchor)        undecodable → NSFileProviderError.syncAnchorExpired
  ▼
backend.listChanges(container, recursive:, startingRank:)
  │  OneDrive: pure cache read, never runs a delta pass
  │    rows = itemsChanged(sinceRank:, limit: 501)
  │    hasMore = rows > 500 → page = first 500, anchor = last row's rank
  │    else anchor = current high-water mark
  │    .purged  → deletedEntries
  │    .trashed → update with parent = trash container
  │    .live    → update
  ▼
didDeleteItems  in chunks of batchSize(suggestedBatchSize)
didUpdate       in chunks of batchSize(suggestedBatchSize)
  ▼
finishEnumeratingChanges(upTo: anchor, moreComing: hasMore)
```

Batching rule: a single `didEnumerate`, `didUpdate` or `didDeleteItems` call with more than
20000 items fails with `__FILEPROVIDER_OBSERVER_TOO_MANY_ITEMS__` and aborts the whole
enumeration. Every observer call is chunked through `ItemEnumerator.batchSize` (at most
2000). Pages are capped at 500 rows, well under the framework's per-page limit.

`listChanges` does not trigger a delta pass. If it did, draining the backlog would start a
pass that adds more rows, and during an initial crawl the two would loop until the whole
drive was enumerated. The crawl belongs to `DeltaPoller`.

A trashed row is emitted as an update with the trash parent, not as a deletion. Deleting it
would leave a ghost and break "Put Back".

## Ranks

Every MetadataCache write that changes what the system should see allocates a fresh rank.
This includes `upsert` / `upsertBatch` (only when the row differs), `markTrashed`,
`markDeleted`, `purgeItem`, `resurrectItem`, `setPlaintextSize`, `setContentError` and
`setLocalMetadata`. `enumerateChanges` returns rows with a rank above the anchor.
An upsert of an identical row is skipped, so a full re-crawl does not replay the tree.

## Working-Set Signalling

The working set is the replicated extension's remote-change feed. Signalling it runs
`WorkingSetEnumerator.enumerateChanges`, which delivers changed items directly. It does not
depend on the parent folder's version changing, and OneDrive does not bump a folder's eTag
when a child is added.

Signal sources, all going through the one `Extension.workingSetThrottle`
(`SignalThrottle`, 1 s):

| Source | When |
|---|---|
| `onDeltaProgress` (per delta page) | the page changed something |
| `DeltaPoller` (per pass) | reconcile parents were refreshed, or the cursor expired |
| Encrypt / decrypt action | per item, coalesced |
| `flagContentError` (OneDrive download) | direct, not throttled |

`SignalThrottle` fires at once if 1 s has passed since the last fire. Otherwise it queues a
single trailing fire at the end of the window. Each signal triggers a full recursive
`enumerateChanges` sweep, so a burst of N sources must not produce N sweeps. The trailing
fire ensures the last change in a burst is delivered.

## Delta Sync (OneDrive)

```
DeltaPoller.run  (started once, for OneDrive only, when the backend is first resolved)
  loop:
    backend.pollDelta()
      GraphDeltaSync.runPass()          (re-entry guarded: a concurrent call returns no-op)
        url = saved deltaLink/nextLink, else /items/{root}/delta?$top&$select
        cold crawl → Prefer: odata.maxpagesize
        per page:
          yield to interactive requests
          partition → upserts, deletes, FolderKey evidence
          live item over a local tombstone → parent added to reconcile set
          upsertBatch(upserts, generation)   (full crawl: stamps seen_gen)
          deleted facet: deletedDateTime → markTrashed, else markDeleted
          onDeltaUpdates → onDeltaProgress (signal + indexed count)
          nextLink → persisted as the resumable cursor; stop here if cancelled
        deltaLink → full crawl: sweepUnseen(gen); saveCursor (clears pending gen);
                    markInitialCrawlComplete
        410 Gone → beginFullCrawl (new gen, clears cursor + completeness), restart in-pass;
                   second 410 → cursorExpired = true
      reconcile parents → GET /children, resurrect items live on Graph
    changed || cursorExpired → signal working set
    sleep: 45 s × [0.8, 1.2]; after failures 45 s × 2^n, capped at 5 min
    vault locked → loop stops until unlock restarts it
```

The emulator inherits the no-op `pollDelta`, so no poller is started for it.

## Plaintext Size Reporting

An encrypted item's plaintext length cannot be derived from its name or ciphertext size.

| State | `documentSize` | Content version |
|---|---|---|
| Unresolved | estimate from the ciphertext size (`estimatedDisplaySize`), else the ciphertext size | `cTag|p<estimate>` |
| Resolved | `plaintext_size` from MetadataCache | `cTag|p<exact>` |

- Plain files: seeders (delta, `/children`, mutation reseed) store the exact size, since
  plaintext equals ciphertext. All three seeders must agree, because a disagreement moves the
  version with no content change.
- Encrypted files: resolved by the first content fetch (header parse), by
  `fetchItem(resolvingPlaintextSize: true)`, or at upload from the source file.
- The size is stamped into the *content* version. `documentSize` is re-read only when the
  version changes, so a resolved size reaches the system only through a version change.
- A size learned during a partial fetch reaches `documentSize` through enumeration.
  `setPlaintextSize` bumps the row's rank, so the next `enumerateChanges` delivers it.
