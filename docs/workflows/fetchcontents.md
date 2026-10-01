# File Materialisation (fetchContents)

## Trigger

A consumer (Finder, QuickLook, an app) reads a dataless file. NSFileProvider calls
`fetchContents` (whole file) or `fetchPartialContents` (byte range). Both converge on one
fetch → decrypt → offset-write pipeline. There is no in-memory blob path for file content.

Related: [/docs/design/architecture.md](/docs/design/architecture.md),
[/docs/backend/remote-onedrive.md](/docs/backend/remote-onedrive.md),
[/docs/backend/local-server-emulator.md](/docs/backend/local-server-emulator.md),
[/docs/crypto/boxcryptor.md](/docs/crypto/boxcryptor.md).

## Block Diagram

```
┌──────────────────────────┐
│ Finder / QuickLook / app │  read dataless file
└────────────┬─────────────┘
             │ NSFileProvider
             ▼
┌──────────────────────────────────────────────────────────┐
│ Provider.appex — Extension                               │
│  fetchContents / fetchPartialContents                    │
│  item lookup → version gate → PartialFetchWindow         │
│  → temp plaintext URL → reply alignment                  │
└────────────┬─────────────────────────────────────────────┘
             │ backend.downloadToFile(param, destinationURL:, progress:)
             ▼
┌──────────────────────────────────────────────────────────┐
│ Backend adapter (GraphDriveClient | ServerEmulatorClient)│
│  entry + remote size · encryption gate · decryptor       │
└────────────┬─────────────────────────────────────────────┘
             │ StreamingDownload.run(fetcher:decryptor:…)
             ▼
┌──────────────────────────────────────────────────────────┐
│ StreamingDownload + ContentStreamDownloader (shared)     │
│  BC01HeaderCache · BC01HeaderProbe · BC01Plan            │
│  bounded parallel lanes · StreamSink positioned writes   │
└──────┬──────────────────────────────────┬────────────────┘
       │ ContentFetching.fetchRange       │ positioned writes
       ▼                                  ▼
┌────────────────────────┐        ┌────────────────────────┐
│ GraphContentFetcher    │        │ plaintext temp file    │
│ EmulatorContentFetcher │        │ (dataURL, sparse for   │
└───────────┬────────────┘        │  a ranged fetch)       │
            ▼                     └───────────┬────────────┘
   Graph / local server                       ▼
                               completionHandler(url, item, range, nil)
```

Everything from `StreamingDownload` down is shared. A backend contributes only a
`ContentFetching` adapter (its authenticated ranged read) and its entry/size lookup.

## Flow

```
fetchContents(for:version:request:)            fetchPartialContents(…minimalRange:aligningTo:)
  range = nil, alignment = 0                     range = minimalRange only if
  │                                              backend.supportsByteRangeMaterialisation
  └──────────────────────┬───────────────────────┘
                         ▼
fetchContentsInternal(for:version:range:request:alignment:)
  │  Progress(100) — all units owned by the download child
  ├─▶ itemInternal(for:) → Item                  (missing / wrong type → internalError)
  ├─▶ version gate (macOS): requested.contentIdentity != item.contentIdentity
  │                         → NSFileProviderError(.versionNoLongerAvailable)
  │                         (`|p<size>` stamp ignored — it is derived, not identity)
  ├─▶ adjustRequestedRange (ranged only) → PartialFetchWindow.extent(...)
  │       .wholeFile → NSRange(0, -1)  (treated as "whole file" below)
  │       .range(r)  → r
  ▼
fetchContentsInline
  │  dataURL = makeTemporaryURL("fetchedContents")
  │  DownloadItemParameter(itemIdentifier, requestedRevision, range)
  ▼
backend.downloadToFile  ── see "Backend adapters"
  ▼
StreamingDownload.run
  │  header-cache lookup keyed (itemID, revision.contentIdentity)
  │  CryptoProgressReporter begin/finish + ProgressSampler (BC01 only)
  ▼
ContentStreamDownloader.run(to:progress:plaintextRange:)
  ├── plain ─▶ runPlain: even spans over the requested region → lanes → StreamSink
  └── .bc ──▶ runEncrypted
        ├─ acquireHeader (cached | single-GET fast path | probe)
        │    no BC01 magic → served as plain (runPlain), no extra round trip
        ├─ BC01Plan: covered blocks, ciphertext [startOffset, endOffset), writeBase
        ├─ decryptInMemory  (fast-path buffer already covers the plan)
        └─ decryptLanes     (BC01LanePartition spans, bounded concurrency)
  ▼
Result(plaintextWindow(origin, length), wholeFilePlaintextSize)
  ▼
fetchContentsInline completion
  │  returnItem = displayItem(entry, exactSize: wholeFilePlaintextSize)   ← both paths
  │  reply range = plaintextWindow
  ▼
fetchContentsInternal reply handler (ranged only)
  │  FetchRangeAlignment.alignedReply(window, covering: requested, alignment:, documentSize:)
  │  no aligned range inside the window → internalError
  ▼
fetchResourceFork
  │  backend.supportsResourceFork == false → pass-through, no round trip
  │  true (emulator) → fetch fork, write to url/..namedfork/rsrc if non-empty
  ▼
fetchPartialContents only: alignReturnedExtent (round out to alignment, clamp to size)
  ▼
completionHandler(dataURL, item, range, nil) → NSFileProvider materialises
```

## Backend Adapters

| Aspect | OneDrive (`GraphDriveClient`) | Emulator (`ServerEmulatorClient`) |
|---|---|---|
| Entry lookup | `cachedEntry` — MetadataCache first; miss → `GET /items/{id}` + seed; `.purged` → `itemNotFound`; `.trashed` served with trash parent | `fetchEntry` — `FetchItemParameter` RPC every call |
| Remote (ciphertext) size | MetadataCache row `remoteFileSize`; missing row → `itemNotFound` (never size 0) | `entry.size` |
| Header-cache revision key | cached entry revision (Graph always serves current content) | `requestedRevision ?? entry.revision` |
| Transport | `GET /me/drive/items/{id}/content` + `Range`, via `perform(.interactive)` | JSON-RPC `download` with `range` |
| Retry | `downloadToFileWithRetry`, 4 attempts | none |
| Plaintext size persistence | `plaintext_size` written as soon as the header is parsed, and again after the run | none |
| `contentError` flag | set on `BC01Error` / `DecodingError`, then `.workingSet` signal | none |
| Crypto progress | `ProgressStoreCryptoReporter` | no-op reporter |
| Resource fork | none (`supportsResourceFork == false`) | sidecar store |

Both declare `supportsByteRangeMaterialisation == true` and build their decryptor via
`BC01DecryptorFactory` (missing key → `NSFileProviderError.notAuthenticated`).

## Strategy

### Partial fetch window

`PartialFetchWindow` decides how much a `fetchPartialContents` call downloads beyond
`minimalRange`, trading bytes, request count and stall latency:

```
start  = roundDown(minimalRange.location, alignment)
window = start == 0 && (isHeaderProbe || !headReadAhead) ? headFloor
         : clamp(fileSize / readAheadFileDivisor, readAheadFloor, readAheadCeiling)
end    = start + roundUp(max(minimalRange end - start, window), alignment)
fileSize - end <= window → extend to EOF   (start == 0 → whole file)
```

- `isHeaderProbe` = `request.isSystemRequest || request.isFileViewerRequest`.
- Defaults (shared config): head floor 256 KiB, read-ahead 2–16 MiB, divisor 16,
  `headReadAhead` on.
- The start never moves back — earlier bytes were already delivered.

### Header acquisition (BC01)

Cheapest first:

1. **Cached** — `BC01HeaderCache` hit on `(itemID, contentIdentity)`; no fetch.
2. **Single-GET fast path** — whole-file fetches, and ranges whose ciphertext end is bounded
   by `maxHeaderLen + range.upperBound`: one `[0, end)` GET serves header and body.
3. **Probe** — `BC01HeaderProbe`: one 4 KiB GET; no magic → plain; header larger than the
   probe → one widening GET sized by the declared header end.

A newly parsed header is published through one path: plaintext size first, then cache
store. A cache row therefore always implies the size is recorded. Store failures are logged
and ignored.

The key is `contentIdentity` (the content token without its `|p<size>` stamp). Keying on the
stamped token would store under the pre-resolution token and look up under the
post-resolution one.

### Block alignment

```
plaintext window   [-------------]
blocks           |----|----|----|----|
covered          firstBlock ... lastBlock
ciphertext GET   headerEnd + firstBlock*B  →  covering block end
writeBase        firstBlock * B        ← reported as plaintextWindow.origin
```

The destination file holds the covering window at absolute plaintext offsets. Reporting
`(0, length)` for a ranged fetch would make the OS read the wrong bytes.

### Lanes and memory

Below `parallelDownloadThreshold` (default 64 MiB) a transfer uses one lane. Otherwise
up to `parallelDownloadLanes` (default 4) requests run at once. Each request is capped at
`maxDownloadSpanBytes` (default 16 MiB): large files get more spans, not bigger ones. Peak
memory is about `lanes × span`. `StreamSink` (an actor) serialises seek and write.
Progress is measured in whole-file plaintext bytes, so a ranged fetch from 50% starts
at 50%.

### Short reads

Every fetch goes through `fetchExactRange`. A body shorter than the object can supply
throws `ContentStreamError.shortRead`. Plain content has no MAC or padding to catch
truncation later, so a short body would otherwise land on disk as a complete file.
On OneDrive, `contentRange` also retries short `206` bodies. It accepts a `200` only
when the request covered the whole object.

### Plaintext size

The size returned to the OS is `wholeFilePlaintextSize`, derived from the BC01 header or,
for plain files, the remote size. It is never the enumeration estimate. It is stamped into
the content version (`|p<size>`) on every reply, whole-file or ranged. The system re-reads
`documentSize` only when the version changes, so a size correction lands only through a
version change. Cost: when the true plaintext is smaller than the range the system asked
for, the system re-fetches once at the new version.

## Error Handling

| Failure | Behaviour |
|---|---|
| Item unresolvable / not an `Item` | `CommonError.internalError` |
| Content-identity mismatch (macOS) | `NSFileProviderError(.versionNoLongerAvailable)` |
| Reply window cannot be aligned to cover the request | `CommonError.internalError` |
| Item purged (OneDrive) / no cache row | `CommonError.itemNotFound` — not retried |
| Missing BC01 key | `NSFileProviderError.notAuthenticated` |
| `BC01Error` / `DecodingError` (OneDrive) | Not retried; `contentError` set, `.workingSet` signalled → `fileError` decoration |
| `ContentStreamError` (truncated body, OneDrive) | Retried, partial file removed first |
| HTTP 5xx / transport error (OneDrive) | Retried up to 4 attempts with limiter backoff |
| HTTP 4xx (OneDrive) | Not retried |
| Cancellation | Partial `dataURL` removed → `NSUserCancelledError` |

## Counterpart: Upload

Upload mirrors this pipeline; see [/docs/workflows/createItem.md](/docs/workflows/createItem.md).
Both rely on the BC01 property that block `i` depends only on `i`, the base IV and the file
key.

| Download | Upload |
|---|---|
| `ContentStreamDownloader` | `ContentStreamUploader` |
| `ContentFetching` (ranged read) | `ContentPutting` (whole / fragment write) |
| `BC01Plan` | `BC01UploadPlan` |
| `BC01Header` (parsed) | `FileEncryptionSession` (generated) |
| Header cache read | Header cache seeded from the upload (`HeaderCacheSeeding`) |

## Notes

- A `.bc`-named file whose bytes carry no BC01 magic is served as plain. The name declares
  encryption; the magic proves it.
- Non-`.bc` files, and every file in a `.plain` domain, use `PlainFileDecryptor`; the header
  logic is skipped.
- OneDrive has no resource-fork store and no in-memory `download` path.
