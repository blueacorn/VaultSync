# VaultSync App Crypto

Key custody, lock gating and cross-process key sharing between **VaultSync.app** and
**Provider.appex**.

Scope: VaultSync's own choices only. The Boxcryptor-compatible BC01 container format (file keys,
base IV, header layout, RSA-OAEP envelope) is specified in
[boxcryptor.md](/docs/crypto/boxcryptor.md) and
[boxcryptor-keys.md](/docs/crypto/boxcryptor-keys.md). Nothing here changes that format; this
document covers how the app holds the keys the format consumes.

## 1. Why the split exists

`Provider.appex` is a sandboxed File Provider extension. It cannot present Touch ID or a PIN
prompt and cannot reach the app's memory, yet it is the process that decrypts file content on
demand.

Key release is therefore split:

- **VaultSync.app** performs every gated operation (biometric prompt, PIN entry, enclave
  agreement, gating changes). It is the only process that reads a gating key.
- **Provider.appex** performs no gating. It reads plain App Group keychain items the app has
  populated, and treats an *absent* item as "vault locked".

The App Group `group.org.vaultsync.VaultSync` is the only channel. Every item below lives in that
access group in the **data-protection keychain** (`kSecUseDataProtectionKeychain`), class
`kSecClassGenericPassword`, `account` = the `NSFileProviderDomainIdentifier` raw value unless
stated otherwise.

The Provider does have outbound network access and redeems OAuth tokens itself (§5.3). What the
sandbox denies it is user-selected storage and listening ports, which is why file operations for
local backends route over JSON-RPC to the app's `StandaloneServer`.

## 2. Key hierarchy

Each domain owns a random AES-256 `domainKey`, always sealed at rest. One gating method is active
per install (`SharedConfig.vaultGating`); it owns a P-256 **gating keypair**. The public half
seals every domain's `domainKey` and is not secret, so a domain can be added while the vault is
locked. The private half is sealed under whatever that method's ceremony produces.

```
 CEREMONY (one method, install-wide)          GATING KEYPAIR                 DOMAIN ROOT
 ───────────────────────────────────          ──────────────                 ───────────
 none       32B, no ACL           ┐
 pin        PBKDF2(PIN)           ├──▶ ceremony key ──AES-GCM open──▶ vault.gating.<m>.wrapped
 biometric  32B, ACL              │   (from vault.gating.<m>.params)     (P-256 private)
 secure     SE ECDH + HKDF        ┘                                           │
                                                vault.gating.<m>.pub ◀── keypair
                                                (not secret)                  │
                                                     │ ECIES seal             │ ECIES open
                                                     ▼                        ▼
                                              domain.domainKey.wrapped[d] ──▶ domainKey[d]
                                                                              (memory only)
                              ┌───────────────────────────────┬───────────────┴──────────────┐
                              ▼ AES-GCM                       ▼ AES-GCM                      ▼ AES-GCM
                 userIdentityKey.wrapped          fileKeysKEK.wrapped         refreshTokenKey.wrapped
                   (RSA private DER)                 (AES-256)                   (P-256 private)
                              │ unlock                        │ unlock                       │ unlock
                              ▼                               ▼                              ▼
                 userIdentityKey.unwrapped        fileKeysKEK.unwrapped      refreshTokenKey (memory)
                     (Provider reads)               (Provider reads)                   │ ECIES open
                                                                                       ▼
                                                                refreshToken.wrapped ──▶ refreshToken.unwrapped
                                                                                           (Provider reads)

 Not secret, outside the hierarchy:
   domain.userIdentityKey.pub      encrypt path keeps working while locked
   domain.userIdentityKey.userId   selects the BC01 encryptedFileKeys entry
   domain.refreshTokenKey.pub      seals a rotated token without unlocking
   vault.gating.<m>.pub            seals every domainKey without a ceremony
   vault.gating.secure.params      ephemeral public key; the SE private key never leaves the enclave
```

`vault.gating.<m>.*` is **one triple per install** for `.none`, `.pin`, `.biometric` (account
`vault`) and **one triple per domain** for `.secure` (account = domain identifier).

| Leaf | Job |
|---|---|
| `userIdentityKey` | RSA-OAEP-SHA1 unwrap of each BC01 file key |
| `fileKeysKEK` | AES-GCM seal/open of BC01 header-cache rows (§7) |
| `refreshTokenKey` | ECIES open of the sealed OAuth refresh token (§5) |

### 2.1 Invariants

> **I1.** No key is at rest unwrapped, except the three Provider-readable `*.unwrapped` slots,
> which exist only between an unlock and the next lock.
>
> **I2.** No key that opens a wrapper is persisted in the plain. The gating private key is
> persisted only sealed under the ceremony key. (`<m>.pub` only seals.) For `.none` and
> `.biometric` the ceremony key *is* the `.params` item, protected only by that item's access
> policy (§3.3).
>
> **I3.** `domainKey[d]` is never persisted unwrapped and is a local in every operation that
> uses it; it is dropped when that operation returns.
>
> **I4.** The gating private key and the `refreshTokenKey` private key are locals, dropped once
> the material they open has been opened.
>
> **I5.** Isolation is per gating method. `.secure` mints a gating keypair per domain, so a
> captured gating key opens exactly one vault. `.none`, `.pin` and `.biometric` share one
> install-wide keypair. In every case each domain owns its own `domainKey`, and no leaf secret is
> shared.

I5 states what the gating choice buys. `.pin` cannot be per-domain without per-domain PINs, and
`.none`/`.biometric` hold a single install-wide ceremony key; the design does not fake an
isolation those methods lack, and keeps it where it is real. Below the gating layer nothing is
shared, so a captured `domainKey` opens exactly one vault.

`VaultKeyStore` holds **no** resident key material. Lock state is derived from the presence of
a domain's `*.unwrapped` slots (`isUnlocked` = any of the three present), not from an in-memory
flag that could drift.

| Secret | Scope | Minted by | Survives lock? |
|---|---|---|---|
| `domainKey` | per domain | `VaultKeyStore.provisionDomain` | yes, sealed |
| gating keypair (P-256) | per domain (`.secure`); per install (others) | `mintGatingKeypair` via `GatingCeremony.enroll` | yes: `.pub` plain, `.wrapped` sealed |
| ceremony key | per gating triple | `GatingCeremony.enroll` | `.none`/`.biometric`: stored as `.params`; `.pin`: re-derived; `.secure`: re-agreed with the enclave |
| `userIdentityKey` (RSA private DER) | per domain | from the user's `.bckey` (`CryptoConfigViewModel.deriveKey`) | yes, wrapped |
| `fileKeysKEK` (AES-256) | per domain | `provisionDomain`; re-minted if absent or unopenable | yes, wrapped |
| `refreshTokenKey` (P-256) | per domain | `provisionDomain` | yes, wrapped |
| refresh token | per domain | OAuth token endpoint, every redemption | yes, ECIES-sealed |

`fileKeysKEK` is an **independent random key**, not derived from `domainKey`, so the header
cache can be discarded and re-keyed without touching the wrapped user identity DER.

Reference: [VaultKeyStore.swift](/Common/Crypto/VaultKeyStore.swift),
[CryptoKeychain.swift](/Common/Crypto/CryptoKeychain.swift),
[GatingCeremony.swift](/Common/Crypto/GatingCeremony.swift),
[SecureEnclaveGate.swift](/Common/Crypto/SecureEnclaveGate.swift),
[PINGate.swift](/Common/Crypto/PINGate.swift).

### 2.2 Rotation

Re-keying a leaf under the same `domainKey` is pointless: a `domainKey` captured during an
earlier unlock window still opens it. `VaultKeyStore.rotateDomainKey(for:)` is the rotation
primitive: open under the current gating, mint a fresh `domainKey`, re-wrap every existing leaf,
then re-seal `domainKey.wrapped` to the active `<m>.pub`. The gating keypair is unchanged, so no
prompt beyond the one that opened the old key. No UI path invokes it today.

Every ECIES seal (§5.1) mints its own ephemeral key, and every `.secure` keypair mint enrolls a
fresh enclave ephemeral. Reusing a stored ephemeral would reproduce the same ceremony key.

## 3. Gating

One enum, `SharedConfig.VaultGating`, names both the keychain regime and the unlock ceremony:
the wrapper *is* the gating. It is install-wide and authoritative; there is no per-domain copy.

| Case | UI label | Ceremony key obtained by | Isolation | Password fallback | Survives Touch ID re-enrollment |
|---|---|---|---|---|---|
| `.none` | No Protection | silent read of `vault.gating.none.params` (`AfterFirstUnlockThisDeviceOnly`, no ACL) | install | n/a | yes |
| `.pin` | PIN | PBKDF2 over the entered PIN; `.params` holds salt/iterations/verifier only | install | n/a | yes |
| `.biometric` | Touch ID or Password | ACL'd read of `vault.gating.biometric.params`: `.biometryCurrentSet .or .devicePasscode`, `WhenUnlockedThisDeviceOnly` | install | **yes** | no, the ACL invalidates |
| `.secure` | Secure Enclave (Touch ID Only) | SE P-256 ECDH against `vault.gating.secure.params[d]` → HKDF; SE key `.privateKeyUsage + .biometryCurrentSet`, `WhenUnlockedThisDeviceOnly` | **per domain** | **no** | no, the SE key is destroyed |

`.params` is the **only** slot that differs between methods. UI copy for all four lives in
[VaultGatingDescriptions.swift](/Common/Config/VaultGatingDescriptions.swift), so the Security
screen and the edit-domain screen cannot drift.

**Invariant:** exactly one wrapper exists per domain. Switching method re-seals that wrapper;
no promptlessly-openable copy remains.

`VaultKeyStore.gating()` reads the config marker, never the keychain: a `.biometryCurrentSet`
item cannot be probed without a prompt.

### 3.1 Gating triples and their deletion

`CryptoKeychain.gatingAccount(_:domain:)` is the single resolver: `vault` for the shared three,
the domain identifier for `.secure`.

`deleteGatingKeys(except:)` retires every non-active method: one triple for each shared method,
one per configured domain for `.secure`. It only removes the non-active method, so it cannot
brick a vault. `reconcile(domain:)` runs it at launch to clean up after a crash mid-`setGating`.

`NoneCeremony.enroll` **reuses** an existing `none.params` key: re-minting would strand every
domain sealed to the matching keypair. `sealDomainKey` reuses a gating keypair only when **both**
`.pub` and `.wrapped` exist: a `.pub` whose `.wrapped` is gone can still seal, but nothing could
open the result.

### 3.2 How `.secure` works

One SE P-256 key per install (tag `org.vaultsync.VaultSync.vault.gating.secure.sekey`), created on
first enrollment; one ephemeral public key per domain. Isolation comes from the per-domain
ephemeral. N enclave keys would buy nothing (same finger) and multiply the re-enrollment blast
radius.

Enrollment (promptless: uses only the SE public key):

```
eph        = fresh P-256 key
shared     = ECDH(eph.priv, SE_pub)
ceremony   = HKDF-SHA256(shared, salt: eph.pub(x9.63), info: domainID, 32 B)
store        vault.gating.secure.params[d] = eph.pub
gating     = fresh P-256 key
store        vault.gating.secure.wrapped[d] = AES-GCM(gating.priv, ceremony)
store        vault.gating.secure.pub[d]     = gating.pub
store        domain.domainKey.wrapped[d]    = ECIES(domainKey → gating.pub)
```

Unlock (prompts: needs the enclave private key):

```
shared     = SecKeyCopyKeyExchangeResult(SE_priv, params[d])   Touch ID, no password fallback
ceremony   = HKDF-SHA256(shared, salt: eph.pub, info: domainID)
gating.priv= AES-GCM.open(wrapped[d], ceremony)
domainKey  = ECIES.open(domain.domainKey.wrapped[d], gating.priv)
```

`domainID` in the HKDF `info` ensures a wrongly reused ephemeral still yields a distinct key per
domain.

The `.wrapped` keypair layer is redundant for `.secure` (the ceremony key could seal `domainKey`
directly). It is kept so every method shares one Layer-2 path and no consumer branches on
`.secure`.

Promptless enrollment is not a hole: any App Group process can seal new material to the enclave's
public half, but gains nothing from a vault it cannot open.

**One prompt, N domains.** Presence is evaluated once into an `LAContext` and threaded through
every domain: as `kSecUseAuthenticationContext` for the `.biometric` read, and into
`SecureEnclaveGate.agree` for each `.secure` agreement. An evaluated context is a presence token,
not a per-item unlock; isolation lives in the key graph, not in the prompt count. The context is
invalidated when the operation ends (`withPresenceContext`).

### 3.3 Trade-offs, stated plainly

- **`.secure` enrollment loss is total.** A Touch ID enrollment change destroys the SE key and
  every `.secure` wrapper. The domains must be set up again (`.bckey`, sign-in). The UI renders
  `VaultGating.secureEnclaveWarning` separately for emphasis. A recovery wrapper under a second
  method is rejected: it would open the vault without the strict gate.
- **`.biometric` is exportable after auth.** Its ceremony key is 32 bytes in an ACL'd item;
  after device-owner auth `SecItemCopyMatching` returns them to the process. `.secure` is the
  non-exportable alternative.
- **`.none` is not a security boundary.** Any App Group process can read `none.params` silently.
  Lock and idle timeout under `.none` are a UX affordance.

A biometric item read without a context uses `kSecUseAuthenticationUISkip`: an unexpected caller
gets "absent", never a prompt.

### 3.4 PIN

```
PIN ──PBKDF2-HMAC-SHA256(salt, iterations)──▶ ceremony key ──opens──▶ vault.gating.pin.wrapped
                                                  │
                                                  ▼
                                      verifier = HMAC-SHA256(derived, "fb-pin-v1")
```

- PBKDF2-HMAC-SHA256, 310,000 iterations, 32-byte random salt, 32-byte output. Implemented over
  CryptoKit HMAC.
- `vault.gating.pin.params` stores `{salt, iterations, verifier}` only. No key material.
- The verifier rejects a wrong PIN (constant-time compare) before any AES-GCM open.
- `PINPolicy`: digits only, 4–20 characters.
- `PINAttemptThrottle`: escalating delay `[0, 0, 1, 3, 10, 30, 60]` s by consecutive failure,
  in-memory, per process. Backoff only, no lockout.
- A PIN change is `setGating(.pin, newPIN:currentPIN:)`: fresh salt, new install-wide keypair,
  every domain re-sealed. Leaves are untouched; works while locked.

## 4. Keychain slot map

Service names are prefixed `org.vaultsync.VaultSync.`. All items are data-protection keychain,
App Group access group. Non-ACL items use `AfterFirstUnlockThisDeviceOnly`.

| Service suffix | Account | Holds | Format | Read by | Cleared on lock |
|---|---|---|---|---|---|
| `vault.gating.{none,pin,biometric}.pub` | `vault` | gating P-256 public key | x9.63 | app | no |
| `vault.gating.{none,pin,biometric}.wrapped` | `vault` | gating P-256 private key | AES-256-GCM box under ceremony key | app | no |
| `vault.gating.none.params` | `vault` | **the ceremony key** | 32 B, no ACL | app | no |
| `vault.gating.pin.params` | `vault` | PIN record, no key material | JSON `salt`, `iterations`, `verifier` | app | no |
| `vault.gating.biometric.params` | `vault` | **the ceremony key** | 32 B, `SecAccessControl` | app | no |
| `vault.gating.secure.pub` | domain | gating P-256 public key | x9.63 | app | no |
| `vault.gating.secure.wrapped` | domain | gating P-256 private key | AES-256-GCM box under ceremony key | app | no |
| `vault.gating.secure.params` | domain | ephemeral P-256 public key | x9.63 | app | no |
| `domain.domainKey.wrapped` | domain | `domainKey` | ECIES box (§5.1) to active `<m>.pub` | app | no |
| `domain.userIdentityKey.wrapped` | domain | RSA private DER | AES-256-GCM box under `domainKey` | app | no |
| `domain.userIdentityKey.unwrapped` | domain | RSA private DER | PKCS#1 DER | **Provider** | **yes** |
| `domain.userIdentityKey.pub` | domain | RSA public key | DER | app + Provider (encrypt) | no |
| `domain.userIdentityKey.userId` | domain | `.bckey` `users[0].id` | UTF-8 | app + Provider | no |
| `domain.fileKeysKEK.wrapped` | domain | `fileKeysKEK` | AES-256-GCM box under `domainKey` | app | no |
| `domain.fileKeysKEK.unwrapped` | domain | `fileKeysKEK` | 32 B | **Provider** | **yes** |
| `domain.refreshTokenKey.wrapped` | domain | refresh-token P-256 private key | AES-256-GCM box under `domainKey` | app | no |
| `domain.refreshTokenKey.pub` | domain | refresh-token P-256 public key | x9.63 | app + Provider | no |
| `domain.refreshToken.wrapped` | domain | refresh token | ECIES box (§5.1) | app + Provider | no |
| `domain.refreshToken.unwrapped` | domain | refresh token | UTF-8 | **Provider** | **yes** |

The Secure Enclave key itself is a `SecKey` with `kSecAttrTokenIDSecureEnclave`, not a
generic-password slot.

`<m>.params` is not uniformly harmless: for `.pin` and `.secure` it holds non-secret inputs; for
`.none` and `.biometric` it holds the unwrapping key. Never log it.

The three `*.unwrapped` services are the entire app→Provider key channel.

### 4.1 Keychain mechanics

- **Data-protection keychain only.** On macOS `SecItem*` defaults to the legacy file-based
  keychain, where items carry an ACL naming the writing code signature: a slot written under one
  signature rejects another's `SecItemDelete`, and `kSecAttrAccessGroup` is not honoured. Only
  the data-protection keychain shares slots with `Provider.appex` and accepts ACL'd items
  reliably.
- **Upsert.** `CryptoKeychain.upsert` deletes then adds; on `errSecDuplicateItem` it falls back
  to `SecItemUpdate`, so a store stays idempotent across re-signings.
- **Account-less delete loops** until `errSecItemNotFound` (bounded at 1024). A single
  `SecItemDelete` matching several items removes only one; without the loop a global lock would
  leave every domain but one unlocked.
- **Absent means locked.** `loadUnwrapped*` return `nil` for an absent slot, with no fallback
  source. The header cache treats absence as a miss; the token store distinguishes "locked" from
  "never signed in" via the sealed slot (§5.4).

## 5. The refresh token

### 5.1 Two layers, one ECIES

```
provision (any lock state):
    refreshTokenKey = fresh P-256 keypair
    store domain.refreshTokenKey.pub     = pub
    store domain.refreshTokenKey.wrapped = AES-GCM(priv, domainKey)

every rotation (app or Provider, locked or not):
    store domain.refreshToken.wrapped    = ECIES(token → refreshTokenKey.pub)
    overwrite domain.refreshToken.unwrapped, only if it already exists (§5.3)

unlock (app):
    priv  = AES-GCM.open(refreshTokenKey.wrapped, domainKey)
    token = ECIES.open(refreshToken.wrapped, priv)
    store domain.refreshToken.unwrapped  = token

lock:
    delete domain.refreshToken.unwrapped (with the other two unwrapped slots)
```

Both asymmetric layers (gating keypair, `refreshTokenKey`) exist for one reason: the material
must be **sealable while locked but openable only while unlocked**. A domain is added to a locked
vault; a token rotates in the Provider while the vault may be locked. Sealing to a public half
needs no ceremony. The leaves under `domainKey` stay symmetric because nothing writes under a
`domainKey` while locked.

**ECIES construction** (`VaultKeyStore.seal(_:to:)` / `openSealed(_:with:)`), used for both
`domainKey` and the token:

```
eph   = fresh P-256 key
key   = HKDF-SHA256(ECDH(eph.priv, pub), salt: eph.pub(x9.63), info: empty, 32 B)
box   = eph.pub(65 B, x9.63) ‖ AES-GCM(key, plaintext).combined   (nonce ‖ ct ‖ tag)
```

Hand-rolled because CryptoKit `HPKE` requires macOS 14 and the deployment target is macOS 13.

### 5.2 Seal on write

`refreshToken.wrapped` is rewritten the moment a new token is returned, not at lock. Sealing only
at lock would lose the newest token to a crash or force-quit in between.

### 5.3 Rotation from the Provider

`VaultKeyStore.commitRefreshToken(_:for:establishing:)`:

- always writes the sealed slot (needs only the public half);
- **overwrites** `refreshToken.unwrapped` only if it already exists. A locked domain had that
  slot deleted deliberately; recreating it would leave a readable credential behind the user's
  lock. A rotation that loses this race is still in the sealed slot and surfaces at next unlock.
- `establishing: true` is passed only for the first commit after provisioning, where the slot
  legitimately does not exist yet.

One writer updates both slots in one operation, so the next unlock opens token N+1, not a stale N.

### 5.4 Keyed by domain

Each domain owns a separate refresh token, including two domains signed into the same account;
no sharing, no reference counting. `MSALTokenStore`
([MSALTokenStore.swift](/Common/Auth/MSALTokenStore.swift)) reads through
`VaultRefreshTokenStore`: `read` is the unwrapped slot, `store` is `commitRefreshToken`. When
`read` returns `nil`, `hasSealedToken` decides the error: sealed blob present →
`AuthError.vaultLocked` ("unlock this vault"); absent → `AuthError.notAuthenticated`. Conflating
them would send a locked user through a sign-in that cannot succeed.

### 5.5 Sign-in precedes the domain

Sign-in runs before the domain exists. `exchangeAuthorizationCode(_:pkce:domainIdentifier:)`
with `nil` returns a pending handle; the token stays in memory only.
`commitPendingCredential(_:to:)` seals it once the domain is added;
`discardPendingCredential(_:)` drops it on cancel. An abandoned sign-in leaves nothing in the
keychain.

### 5.6 Plain domains are gated too

A `.plain` OneDrive domain needs no file keys, but its refresh token is a credential and is gated
like any other secret, so locking stops its Provider. `provisionDomain` runs for every algorithm;
the UI states the consequence once for all domains (`VaultLockCopy.lockedDomainConsequence`).

## 6. Lifecycle

### 6.1 Provisioning a domain

```
.bckey + password
   → CryptoConfigViewModel.deriveKey   PBKDF2-SHA512 → HMAC-SHA256 verify → AES-256-CBC → RSA DER
   → CryptoConfigViewModel.store       userIdentityKey.pub + .userId (plain)
   → VaultKeyStore.provisionDomain     mint domainKey
                                       DER  ─wrap→ userIdentityKey.wrapped, and → .unwrapped
                                       mint ─wrap→ fileKeysKEK.wrapped,     and → .unwrapped
                                       mint ─wrap→ refreshTokenKey.wrapped  + .pub
                                       seal to vault.gating.<m>.pub → domainKey.wrapped   ← LAST
   → MSALTokenStore.commitPendingCredential   seal the buffered refresh token (§5.5)
```

- `store` is all-or-nothing: a sealing failure rolls back the public key and user ID.
- Sealing needs only `<m>.pub`, so provisioning runs **without a ceremony or prompt, from a locked
  vault, for all four methods**. The first domain under a method mints its keypair on the way
  (promptless for every method; `.pin` needs the PIN if its keypair is not yet minted).
- The wrapper is written last so a crash leaves a detectable orphan, not a wrapper naming leaves
  that were never written.
- `fileKeysKEK` is released immediately: a domain added while already unlocked may see no unlock
  for hours, and an absent slot reads as locked to the header cache.

### 6.2 Readiness and orphans

```
wrapper present? ─ yes ─▶ any unwrapped slot present? ─ yes ─▶ .ready
                                                      └─ no ─▶ .locked
                 └─ no ──▶ domain configured? ─ no ─▶ .ready  (nothing to open)
                                              └─ yes ▶ .orphaned
```

`VaultKeyStore.orphanedDomainIDs()` lists configured domains with no wrapper so the UI names them.
The fix is to remove and re-add that domain. The check reads configuration, not key material, so
every reported orphan is one the user can clear.

### 6.3 Deprovisioning

Two teardowns share one pipeline
([DefaultDomainDeprovisioningService](/Common/Provisioning/DefaultDomainDeprovisioningService.swift)),
differing only in which steps run.

**Delete Vault** (permanent):

```
token-sign-out            sign out the OAuth credential (OneDrive)
backend-resource-destroy  remove MetadataCache + BC01HeaderCache files and WAL/SHM sidecars
key-material-forget       VaultKeyStore.forgetDomain: every slot scoped to this domain
                            vault.gating.secure.{pub,wrapped,params}[d]
                            domain.domainKey.wrapped
                            domain.userIdentityKey.{wrapped,unwrapped,pub,userId}
                            domain.fileKeysKEK.{wrapped,unwrapped}
                            domain.refreshTokenKey.{wrapped,pub}
                            domain.refreshToken.{wrapped,unwrapped}
config-clear              remove the domain's configuration        ← LAST
```

**Lock and Remove Vault** (restorable): clears rebuildable cache rows in place and keeps every
wrapped slot, so unlock restores the vault without re-provisioning or re-authenticating.

`forgetDomain` needs no cross-domain check because every slot it deletes names this domain. The
install-wide triples are never touched by it; only `setGating` retires them. `forgetDomain`
attempts every delete and reports only surviving `*.unwrapped` slots, so one failure cannot
strand plaintext key material.

`config-clear` runs last because `backend-resource-destroy` resolves `BackendKind` from the
account row.

### 6.4 Changing gating (`VaultKeyStore.setGating`)

Install-wide: one presence evaluation, every domain re-sealed, superseded triples deleted.

```
context = one presence evaluation under the CURRENT method (nil for .none/.pin),
          or a borrowed, already-evaluated context from the Security screen gate
A  open every provisioned domain's domainKey under the CURRENT method
     ↳ any failure throws here, before anything is written          ← atomicity
B  mint the TARGET keypair   (shared three: once; .secure: per domain inside C)
C  re-seal every opened domainKey to <target>.pub                    ← new wrappers first
   write SharedConfig.vaultGating = target
   deleteGatingKeys(except: target)                                  ← old material last
```

- A crash between C and the delete leaves two gating keypairs but one valid wrapper per domain;
  every vault still opens and `reconcile` cleans up at launch. The reverse order could lock the
  user out.
- No `domainKey` changes, so every leaf blob stays valid. Changing gating is not rotation.
- `VaultLockController.setGating` then repopulates the unwrapped slots for **every** configured
  domain; repopulating one would leave the rest locked.
- There is no "unenroll": `setGating(.none)` is an ordinary switch.

### 6.5 Unlock

```
method  = SharedConfig.vaultGating
context = one presence evaluation if requiresPresence(method) (.biometric, .secure)

per domain:
  ceremony    = GatingCeremony(method).open(domain:pin:reason:context:)     ← Layer 1
     .none      silent read of none.params
     .pin       PINGate.deriveGatingKey (verifier + throttle)
     .biometric ACL'd read of biometric.params under the context
     .secure    SE ECDH + HKDF under the context
  gating.priv = AES-GCM.open(vault.gating.<m>.wrapped, ceremony)           ← Layer 2, shared
  domainKey   = ECIES.open(domain.domainKey.wrapped, gating.priv)
  populate userIdentityKey.unwrapped, fileKeysKEK.unwrapped, refreshToken.unwrapped
  drop gating.priv, refreshTokenKey priv, domainKey
then: reconnect domains, arm idle timer
```

`populateUnwrappedSlots(for:pin:)` evaluates presence once for the whole list, never for an empty
list, and logs and skips a domain whose ceremony fails; one failure is not an error for others.

### 6.6 Lock

```
evictUnwrappedSlots()   delete every userIdentityKey / fileKeysKEK / refreshToken .unwrapped
                        (account-less looping delete, §4.1)
onLock                  disconnect File Provider domains
```

- No in-memory key to drop (I3). `evictUnwrappedSlots(for:)` locks one domain without touching
  another's slots.
- Every eviction is a plain `SecItemDelete` on non-ACL items, so any App Group process can lock.
  Only unlocking needs the app.
- All three deletions are attempted; failures are reported together, never masking each other.
- Under `.none` any App Group process can re-read `none.params`, so a lock is reversible without
  the user (§3.3).

Relock triggers ([VaultLockController.Trigger](/Common/VaultLock/VaultLockController.swift)):
`manual`, `idleTimeout`, `screenLock`, `sessionResign` (fast user switch; follows the screen-lock
flag), `powerOff` (logout or restart; either flag arms it). All but `manual` are disabled by the
`autoLockEnabled` master switch. System events come from
[WorkspaceLockEvents.swift](/VaultSync/Security/WorkspaceLockEvents.swift); the idle timer from
[SystemLockScheduler.swift](/VaultSync/Security/SystemLockScheduler.swift).

Lock policy is install-wide by design: one timeout, one trigger set, and expiry locks every
domain. Per-domain timeouts add UI with no security gain; isolation already lives in the
per-domain `domainKey`s.

### 6.7 Failure handling

All per domain, decided by whether the lost secret is regenerable:

- **User identity blob unopenable** at unlock: dropped and logged; the domain must be provisioned
  again from the `.bckey`.
- **`fileKeysKEK` unopenable or absent**: a fresh one is minted. The rows it sealed are
  unreadable anyway.
- **Refresh token unopenable**: sealed blob dropped and logged, never re-minted; the domain signs
  in again.
- **Wrapper or gating key lost**: total loss for that domain alone. This is the trade that gives
  gating meaning, and why `.biometric` and `.secure` invalidation are stated in the UI.

## 7. BC01 header cache sealing

[BC01HeaderCache](/Extension/Backend/BC01HeaderCache.swift) persists parsed BC01 headers per
domain (SQLite, App Group container) so ranged reads skip a header GET.

- Sensitive half `len(baseIV) ‖ baseIV ‖ fileKey` is AES-256-GCM sealed under `fileKeysKEK` with
  AAD = `itemID ‖ 0x00 ‖ contentRevision` (UTF-8). The AAD is not stored: a row cannot be
  transplanted onto another item or revision. Geometry (`headerEnd`, `blockSize`,
  `cipherPadding`) stays plaintext; it is derivable from the remote size.
- A revision mismatch drops the row before any crypto runs.
- The Provider observes lock only via `fileKeysKEK.unwrapped`. The resolved KEK is memoised for
  `SharedConfig.headerCacheKeyResidencySeconds` (default 5 s), so hits can outlive a lock by at
  most that window. A locked vault is a cache miss, never an error; misses fall back to
  `BC01HeaderProbe`.

Possessing the unlocked cache yields nothing beyond what `userIdentityKey.unwrapped` already
yields.

## 8. Primitives

| Purpose | Primitive |
|---|---|
| `domainKey` seal to `vault.gating.<m>.pub` | ECIES: P-256 ECDH → HKDF-SHA256 (salt = eph pub) → AES-256-GCM, 65 B eph pub prefixed |
| Gating private key under ceremony key | AES-256-GCM combined box |
| Leaf wrapping under `domainKey` | AES-256-GCM combined box |
| `.secure` ceremony key | Secure Enclave P-256 ECDH → HKDF-SHA256, salt = eph pub, info = domain ID |
| Refresh-token seal | same ECIES as `domainKey` |
| Header-cache rows | AES-256-GCM, AAD = `itemID ‖ 0x00 ‖ contentRevision` |
| PIN derivation | PBKDF2-HMAC-SHA256, 310,000 iterations, 32 B salt |
| PIN verifier | HMAC-SHA256(derived, `"fb-pin-v1"`), constant-time compare |
| `.bckey` unwrap | PBKDF2-HMAC-SHA512 → HMAC-SHA256 verify → AES-256-CBC (see [boxcryptor-keys.md](/docs/crypto/boxcryptor-keys.md)) |
| User identity key | RSA private key, PKCS#1 DER, imported via `SecKeyCreateWithData` |
