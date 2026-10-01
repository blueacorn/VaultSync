# Architecture

VaultSync is a macOS menu-bar app that mounts remote storage in Finder through a File Provider
**replicated extension**, with optional client-side Boxcryptor-compatible (BC01) encryption.
Backends today: **OneDrive** (Microsoft Graph) and a local **Emulator** server. A local-file-system
backend is declared (`BackendKind.localFS`) but not wired.

## Targets

| Target | Kind | Responsibility |
|---|---|---|
| `VaultSync` | App (`LSUIElement` agent) | Menu-bar UI, domain add/edit/remove, OneDrive sign-in, vault unlock ceremonies, hosts the emulator `StandaloneServer` |
| `Provider` | File Provider extension (`.appex`) | Thin bundle; principal class is `Extension.Extension` |
| `Extension` | Framework | `NSFileProviderReplicatedExtension` implementation, backends, content pipeline, delta polling |
| `Common` | Framework | Shared config, crypto, metadata translation, provisioning protocols, vault key store, wire types |
| `Server` | Framework | Emulator: HTTP JSON-RPC server + SQLite item database |
| `Action` | File Provider UI extension (`.appex`) | Finder actions UI (e.g. "Other Versions" conflict view) |

`Provider/main.swift` is intentionally empty; all extension code lives in `Extension.framework`
so the app and Action extension can link the same code (e.g. the app uses `BackendResourceCleanup`).

## Module dependencies

```
            ┌──────────── VaultSync.app ────────────┐
            │                                        │
            ▼                ▼                       ▼
         Server ──────▶   Common   ◀────────── Extension ◀── Provider.appex (principal class)
                            ▲                        ▲
                            └──────── Action.appex ──┘
```

`Common` depends on nothing in-repo. `Extension` and `Server` depend only on `Common`; they never
depend on each other. Only the app links `Server`.

## Process and sandbox model

All targets are sandboxed (`ENABLE_APP_SANDBOX`). Capabilities come from build settings plus
`*.entitlements`:

| Target | Network | Other |
|---|---|---|
| VaultSync | incoming + outgoing | user-selected files read/write; App Group; keychain access group |
| Provider | outgoing only | App Group; keychain access group |
| Action | outgoing only | App Group |

App Group id: `$(APP_GROUP_ID)` = `group.$(APP_BUNDLE_ID)`
([Configuration/Application.xcconfig](/Configuration/Application.xcconfig)). The keychain access
group is `$(AppIdentifierPrefix)$(APP_GROUP_ID)`, so app and Provider share data-protection
keychain items.

Consequences:

- The Provider cannot listen on ports or reach user-chosen folders. Anything needing that lives in
  the app.
- The Provider **can** make outgoing HTTPS calls, so the OneDrive backend talks to Graph
  directly from the extension.

### Extension ↔ app traffic

```
OneDrive domain:   Finder ─▶ Provider.appex ─HTTPS─▶ Microsoft Graph
Emulator domain:   Finder ─▶ Provider.appex ─HTTP JSON-RPC (localhost)─▶ VaultSync.app
                                                                         StandaloneServer ─▶ ItemDatabase (SQLite)
```

HTTP JSON-RPC applies **only** to the Emulator backend (`ServerEmulatorClient` →
`StandaloneServer`). Wire types live in [Common/Service/DomainService.swift](/Common/Service/DomainService.swift).
Protocol details: [/docs/backend/local-server-emulator.md](/docs/backend/local-server-emulator.md).
OneDrive: [/docs/backend/remote-onedrive.md](/docs/backend/remote-onedrive.md).

## Configuration sharing

The app owns configuration; the Provider reads it.

- **`SharedConfigStore`** ([Common/Config/SharedConfigStore.swift](/Common/Config/SharedConfigStore.swift)):
  one JSON document (`SharedConfig`) in the App Group container under
  `Library/Application Support/`, written with `NSFileCoordinator`, change-notified to peers via
  a Darwin notification, served from an in-memory snapshot.
  *Why:* `UserDefaults(suiteName:)` relies on `cfprefsd`, which inside the `.appex` sandbox fails
  to refresh after the host writes, yielding stale or `nil` values.
- **`SharedConfig`** holds per-domain `DomainAccount` rows (including `BackendKind`), crypto
  config, feature flags and Provider-relevant tweaks.
- **`Defaults`** ([Common/Config/Defaults.swift](/Common/Config/Defaults.swift)): host-local debug
  toggles stay in App Group `UserDefaults`; every Provider-read key delegates to `SharedConfigStore`.
- **`ProgressStore`**: the reverse channel — the Provider publishes per-domain progress / state
  snapshots into the App Group container for the app's UI.

Domain identifiers are app-chosen and stable; configuration survives OS domain removal, so the
app's domain list is the union of OS-registered domains and configured accounts.

## Swappable seams

Design rule: shared workflow, backend- or scheme-specific behaviour **added** on top, never a
parallel path.

```
                 Extension (NSFileProviderReplicatedExtension)
                               │
          BackendFactory.make(domain) ── by DomainAccount.backendKind
                               │
             ┌─────────────────┼──────────────────┐
             ▼                 ▼                  ▼
   ServerEmulatorClient   GraphDriveClient    (localFS: not wired)
             │                 │
             └── ContentFetching / ContentPutting adapters ──┐
                                                             ▼
                 ContentStreamDownloader / ContentStreamUploader  (shared)
                                   │
                    FileDecryptor / FileEncryptor  +  MetadataTranslator
                       (Plain* | BC01*)              (Identity | Boxcryptor)
```

| Seam | Interface | Implementations | Selected by |
|---|---|---|---|
| Backend | `ProviderBackend` ([Extension/Backend/ProviderBackend.swift](/Extension/Backend/ProviderBackend.swift)) | `ServerEmulatorClient`, `GraphDriveClient` | `BackendFactory` |
| Content crypto | `FileEncryptor` / `FileEncryptionSession`, `FileDecryptor` | `Plain*`, `BC01Encryptor`, `BC01Decryptor` | domain `CryptoAlgorithm` |
| Metadata | `MetadataTranslator` | `IdentityMetadataTranslator`, `BoxcryptorMetadataTranslator` | domain `CryptoAlgorithm` |
| Content transport | `ContentFetching`, `ContentPutting` | per-backend adapters | backend |
| Provisioning | `DomainProvisioningService` | `EmulatorProvisioningService`, `NoOpProvisioningService` | `BackendRoutingProvisioningService` |
| Deprovisioning | `DomainDeprovisioningService` | `DefaultDomainDeprovisioningService`, `NoOpDeprovisioningService` | app wiring |

Notes:

- **`ProviderBackend`** declares capabilities rather than the extension checking backend type:
  `supportsMoveToTrash`, `supportsTrashEnumeration`, `supportsResourceFork`,
  `supportsByteRangeMaterialisation`, plus display rewriting (`displayEntry`,
  `isBackendEncrypted`) and an optional `pollDelta()` hook (default no-op).
- **Content pipeline.** Every backend downloads and decrypts through one
  `ContentStreamDownloader` (concurrent byte-range lanes, block decrypt, offset writes, bounded
  memory, byte-level progress) and uploads through `ContentStreamUploader`. A backend only supplies
  its authenticated ranged GET / PUT. See [/docs/workflows/fetchcontents.md](/docs/workflows/fetchcontents.md)
  and [/docs/workflows/createItem.md](/docs/workflows/createItem.md).
- **`MetadataTranslator`** is the metadata analogue of the content crypto: display name and
  apparent size vs. backend-encoded name (`.bc`) and ciphertext size. Plaintext size of a BC01
  file is known only after parsing its header, never estimated.
- **Provisioning routing.** `BackendRoutingProvisioningService` dispatches by `BackendKind` to a
  registry (today only `.emulator`). *Why:* installing the emulator service globally let a
  OneDrive domain's delete reach the lazily-started emulator server. Backends with no service are
  no-ops.
- **Deprovisioning** (`DefaultDomainDeprovisioningService.standard`) runs ordered cleanup steps:
  config, OAuth token sign-out, backend resource destroy/empty (`BackendResourceCleanup`, which
  the app links from `Extension`).

Crypto formats: [/docs/crypto/boxcryptor.md](/docs/crypto/boxcryptor.md).

## Vault lock and key gating

Each domain has a `domainKey`, always wrapped at rest. Unlocking runs a gating ceremony in the app
(none / PIN / Touch ID / Secure Enclave — `GatingCeremony`), opens the domain key and populates
Provider-readable "unwrapped" keychain slots; locking evicts those slots. The Provider can lock
(plain `SecItemDelete`) but never unlock. Policy (idle timeout, system-event relock) is
install-wide in `VaultLockController`; keys are per domain in `VaultKeyStore`. Only the
data-protection keychain is used.

Details: [/docs/crypto/application.md](/docs/crypto/application.md).

## Change detection

`DeltaPoller` ([Extension/Polling/DeltaPoller.swift](/Extension/Polling/DeltaPoller.swift)) is an
actor owned by `Extension` per domain. It calls `ProviderBackend.pollDelta()` on a jittered
interval with exponential backoff on transient errors, and on changes signals the **working set**
enumerator (throttled).

*Why polling:* the sandboxed extension has no public endpoint for Graph webhooks; delta remains
the source of truth either way.
*Why the working set:* in a replicated extension, remote changes are delivered through
`.workingSet` `enumerateChanges`; OneDrive does not bump a folder's eTag when a child changes, so
relying on parent-container versions misses updates.

For OneDrive, delta pages reconcile into `MetadataCache` (SQLite, metadata only, one DB per domain
in the App Group container), which also provides monotonic ranks backing sync anchors. The
emulator inherits the no-op `pollDelta`, so no poller runs for it.

## Menu-bar UI

The app is an accessory (`LSUIElement`) agent started from [VaultSync/main.swift](/VaultSync/main.swift).
`StatusItemController` owns the `NSStatusItem` and a transient `NSPopover` hosting a SwiftUI
navigation stack driven by `AppModel`. Every screen (home, domain detail, add/edit domain,
security, unlock, file list) is a route in that stack: header + self-sizing content + footer, no
scroll containers. A few legacy AppKit window controllers remain (enumeration debug view, domain
removal, interaction-suppression editor). The status icon reflects aggregate `StatusActivity`
(idle / active / error).
