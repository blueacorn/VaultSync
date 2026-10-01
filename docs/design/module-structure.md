# Module Structure

Source layout per target. See [architecture.md](/docs/design/architecture.md) for how the pieces
interact.

## Convention: interface at root, implementation in subfolder

A swappable seam's protocol (and any identity/no-op default) sits at the root of its folder;
each concrete scheme or backend lives in a named subfolder. Adding an implementation adds a
subfolder, not an edit to the shared path.

| Interface (root) | Implementations (subfolder) |
|---|---|
| [Common/Metadata/MetadataTranslator.swift](/Common/Metadata/MetadataTranslator.swift) | `Common/Metadata/Boxcryptor/` |
| [Common/Crypto/FileEncryptor.swift](/Common/Crypto/FileEncryptor.swift), [FileDecryptor.swift](/Common/Crypto/FileDecryptor.swift) | `Common/Crypto/Boxcryptor/` |
| [Common/Provisioning/DomainProvisioningService.swift](/Common/Provisioning/DomainProvisioningService.swift), [DomainDeprovisioningService.swift](/Common/Provisioning/DomainDeprovisioningService.swift) | `Common/Provisioning/NoOp/`, `Server/Provisioning/Emulator/` |
| [Extension/Backend/ProviderBackend.swift](/Extension/Backend/ProviderBackend.swift) | `Extension/Backend/OneDrive/`, `Extension/Backend/Emulator/` |

Backend-neutral shared units (content streaming, header cache, factory) also sit at the root of
`Extension/Backend/`.

## Common (framework)

| Path | Responsibility |
|---|---|
| `Auth/MSALTokenStore.swift` | OAuth (PKCE) token acquisition/refresh for OneDrive; refresh token held in the vault |
| `Config/SharedConfig.swift` | `SharedConfig`, `DomainAccount`, `BackendKind` |
| `Config/SharedConfigStore.swift` | App Group JSON config store with cross-process change notification |
| `Config/ConfigStore.swift` | Protocol over the config store |
| `Config/Defaults.swift` | Host-local `UserDefaults` keys and feature flags; Provider-read keys delegate to `SharedConfigStore` |
| `Config/ProgressStore.swift` | Provider → app progress/state snapshots in the App Group container |
| `Config/AppIdentifiers.swift` | Bundle / App Group identifiers |
| `Config/VaultGatingDescriptions.swift` | User-facing vault lock copy |
| `Core/` | Errors, logging, formatting, throttling, File Provider helpers, materialized-item eviction |
| `Crypto/FileEncryptor.swift`, `FileDecryptor.swift` | Content crypto seam + plaintext pass-through |
| `Crypto/CryptoConfig.swift`, `CryptoConfigViewModel.swift` | Per-domain algorithm config; key-file import and key derivation |
| `Crypto/VaultKeyStore.swift` | Per-domain wrapped keys and Provider-readable unwrapped slots |
| `Crypto/CryptoKeychain.swift` | Data-protection keychain access |
| `Crypto/GatingCeremony.swift`, `PINGate.swift`, `LABiometricGate.swift`, `SecureEnclaveGate.swift` | Unlock ceremonies |
| `Crypto/Boxcryptor/` | BC01 encryptor/decryptor, file key, header, lane partitioning, special items |
| `Metadata/MetadataTranslator.swift` | Display ↔ backend name/size seam + identity default |
| `Metadata/Boxcryptor/` | `.bc` naming and ciphertext framing/size mapping |
| `OneDrive/GraphModels.swift` | Graph JSON models shared by app and extension |
| `Provisioning/` | (De)provisioning protocols, `BackendRoutingProvisioningService`, default deprovisioning, `BackendResourceCleaning` |
| `Service/DomainService.swift` | Backend-neutral item/entry types and emulator JSON-RPC wire parameters |
| `UI/View/EnumerationView.swift` | Shared SwiftUI enumeration list |
| `VaultLock/VaultLockController.swift` | Lock/unlock policy: gating changes, idle timeout, system-event relock |

## Extension (framework, loaded by Provider.appex)

| Path | Responsibility |
|---|---|
| `Provider/Extension.swift` | `NSFileProviderReplicatedExtension` root; resolves backend, starts delta poller |
| `Provider/Extension+*.swift` | One file per File Provider entry point: item, enumerator, fetch (full/partial), create, modify, delete, thumbnails, custom/encryption actions, servicing, domain state, suppression, invalidate |
| `Provider/ContentEncryptionConverter.swift` | Encrypt/decrypt an existing item in place (custom action) |
| `Provider/PartialFetchWindow.swift`, `FetchRangeAlignment.swift` | Byte-range materialisation window and alignment |
| `Provider/FileContentComparator.swift`, `SignalThrottle.swift`, `ProviderCancellation.swift`, `EncryptionProgressReporter.swift` | Helpers for the entry points |
| `Backend/ProviderBackend.swift` | Backend protocol and capability flags |
| `Backend/BackendFactory.swift` | `BackendKind` → backend |
| `Backend/ContentStreamDownloader.swift`, `ContentStreamUploader.swift`, `StreamingDownload.swift` | Shared fetch→decrypt and encrypt→put pipelines |
| `Backend/BC01HeaderCache.swift`, `BC01HeaderProbe.swift`, `HeaderCacheSeeding.swift` | BC01 header caching for exact plaintext sizes |
| `Backend/CryptoProgressReporter.swift` | Crypto progress → `ProgressStore` |
| `Backend/BackendResourceCleanup.swift` | Per-backend local resource teardown (used by the app on domain delete) |
| `Backend/OneDrive/` | `GraphDriveClient`, delta sync, `MetadataCache` (SQLite), rate limiter, Graph→entry mapping, domain version store |
| `Backend/Emulator/ServerEmulatorClient.swift` | JSON-RPC client to the app's `StandaloneServer` |
| `Items/Item.swift`, `Items/Enumerator.swift` | `NSFileProviderItem`; item, working-set and trash enumerators |
| `Polling/DeltaPoller.swift` | Periodic change detection |
| `Errors/Error+Presentable.swift` | Error mapping for File Provider |

## Server (framework, app only)

| Path | Responsibility |
|---|---|
| `HTTP/StandaloneServer.swift` | Localhost HTTP JSON-RPC server |
| `Dispatch/` | Method dispatch to backend handlers |
| `Emulator/` | `DomainBackend` and SQLite `ItemDatabase` (accounts, create/update, fetch) |
| `Provisioning/Emulator/EmulatorProvisioningService.swift` | Creates/removes emulator accounts |

## Provider (app extension)

`Provider/main.swift` (empty entry point), `Info.plist` (principal class `Extension.Extension`),
entitlements, icon assets.

## Action (File Provider UI extension)

`ActionViewController.swift` routes to `ConflictViewController.swift` ("Other Versions") and
`AuthenticationViewController.swift`.

## VaultSync (app)

| Path | Responsibility |
|---|---|
| `main.swift`, `AppDelegate*.swift` | Explicit entry point; service wiring, domain lifecycle, error presentation |
| `MenuBar/` | Status item, popover navigation stack (`AppModel`), home/detail/add-edit/security/unlock/file-list views |
| `Domains/` | Domain edit model/view and removal controller |
| `OneDrive/` | Sign-in and remote folder picker |
| `Security/` | System lock event sources and lock scheduler |
| `Preferences/` | Encryption config section, tweaks, interaction-suppression editor, config ↔ defaults mirror |
| `Enumeration/` | Enumeration inspection window |
| `Shared/` | Shared SwiftUI components |

## Other top-level

| Path | Responsibility |
|---|---|
| `Configuration/Application.xcconfig` | Bundle id and App Group id |
| `tools/` | Dev scripts (environment reset, logs, app ids) |
| `tools/bc01/` | BC01 inspection, audit and key tools (Python) |
| `data/corpus/` | Reference encrypted/plain sample corpus |
