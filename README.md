# VaultSync

End-to-end encrypted cloud storage in Finder, on macOS.

VaultSync is a menu-bar app that mounts remote storage as a Finder location through Apple's
File Provider framework. Files are encrypted on your Mac before upload and decrypted on demand when
opened. The storage provider only ever sees ciphertext.

> **Status:** under development.

## Features

- **Native Finder integration.** Replicated File Provider extension: files appear in the Finder
  sidebar, download on demand (dataless placeholders), support partial reads, and sync edits,
  renames, moves, and deletes both ways.
- **Client-side encryption.** Reads and writes the Boxcryptor-compatible **BC01** format
  (AES-256 content, RSA-OAEP wrapped file keys). Existing Boxcryptor vaults can be opened with
  their `.bckey` file. Non-encrypted files pass through unchanged.
- **Vault locking.** Keys stay in the data-protection keychain. Unlock with no protection, a PIN,
  Touch ID / password, or a Secure Enclave key (Touch ID only). Lock manually or on idle timeout.
- **Multiple accounts.** Each account is its own File Provider domain with its own backend and
  vault.
- **Swappable backend:**

  | Backend | Status | Transport |
  |---|---|---|
  | OneDrive (Personal) | supported | Microsoft Graph, delta-based change polling |
  | Emulator | (development/testing) | HTTP JSON-RPC to a local server hosted by the app |
  | Local file system | planned | — |


- **Swappable end-to-end encryption:**

  | Encryption | Status | Capability |
  |---|---|---|
  | Boxcryptor | supported | Full file encryption/decryption (.bc and .bckey files) |
  | Other crypto | planned | — |

## Requirements

- macOS 13 or later
- Xcode with an Apple Developer team (App Groups and File Provider entitlements require signing)
- For OneDrive: a Microsoft Entra app registration (public client)

## Build

All identifiers derive from [Configuration/Application.xcconfig](/Configuration/Application.xcconfig).
To build your own copy, create `Configuration/Local.xcconfig` (gitignored) from the template.

Set any of these in `Local.xcconfig`; unset values fall back to `Application.xcconfig`:

| Setting | Purpose |
|---|---|
| `DEVELOPMENT_TEAM` | Your Apple Developer team ID (can use Personal Team for local development)|
| `BUNDLE_ID_PREFIX` | Unique prefix; bundle IDs, App Group, keychain group and OAuth scheme derive from it |
| `MSGRAPH_CLIENT_ID` | Entra application (client) ID. Register with redirect URI `<bundle-id-lowercased>://auth` and "Personal Microsoft accounts" |

Then open `VaultSync.xcodeproj` and run the **VaultSync** scheme.

## Usage

1. Launch VaultSync; it runs in the menu bar.
2. Add an account: choose a backend (sign in to OneDrive, or use the Emulator).
3. For an encrypted vault, import your `.bckey` and choose an unlock method.
4. Open the new location in the Finder sidebar.

Locking a vault makes encrypted content unavailable to Finder until it is unlocked again.
Removing an account tears down its File Provider domain and local caches.

## Project layout

| Target | Kind | Responsibility |
|---|---|---|
| `VaultSync` | App (menu-bar agent) | UI, account management, OneDrive sign-in, unlock ceremonies, hosts the emulator server |
| `Provider` | File Provider extension | Thin bundle; principal class lives in `Extension` |
| `Extension` | Framework | `NSFileProviderReplicatedExtension`, backends, content pipeline, delta sync |
| `Common` | Framework | Config, crypto, metadata, provisioning, vault key store, wire types |
| `Server` | Framework | Emulator backend: HTTP JSON-RPC server + SQLite item store |
| `Action` | File Provider UI extension | Finder actions (e.g. conflict "Other Versions") |

```
            ┌──────────── VaultSync.app ────────────┐
            ▼                ▼                       ▼
         Server ──────▶   Common   ◀────────── Extension ◀── Provider.appex
                            ▲                        ▲
                            └──────── Action.appex ──┘
```

`Provider.appex` is sandboxed and cannot present authentication UI. The app performs all gated
key operations and shares unlocked keys with the extension through the App Group keychain.

## Testing

```sh
./run-tests.sh                 # all tests
./run-tests.sh --integration   # BC01 integration tests
./run-tests.sh --perf          # OneDrive delta-sync benchmark (requires a configured account)
```

Diagnostic helpers are in [tools/](/tools/) (`show-logs.sh`, `reset-env.sh`, `cat-env.sh`, BC01
utilities).

## Documentation

| Topic | Document |
|---|---|
| Architecture | [docs/design/architecture.md](/docs/design/architecture.md), [module-structure.md](/docs/design/module-structure.md) |
| Backends | [overview](/docs/backend/overview.md), [OneDrive](/docs/backend/remote-onedrive.md), [Emulator](/docs/backend/local-server-emulator.md) |
| Crypto | [key custody & locking](/docs/crypto/application.md), [BC01 format](/docs/crypto/boxcryptor.md), [key chain](/docs/crypto/boxcryptor-keys.md), [filenames](/docs/crypto/boxcryptor-filename.md) |
| Workflows | [enumeration](/docs/workflows/enumeration.md), [fetchContents](/docs/workflows/fetchcontents.md), [createItem](/docs/workflows/createItem.md), [modifyItem](/docs/workflows/modifyItem.md) |

## License

[PolyForm Noncommercial 1.0.0](/LICENSE.txt). Copyright © 2026 Jay Jones.
Third-party notices: [ACKNOWLEDGMENTS.txt](/ACKNOWLEDGMENTS.txt).

VaultSync is not affiliated with Boxcryptor or Microsoft.
