# Phase 2 Prep — Enclave Messaging RPC Surface

> **Purpose:** everything needed to start Phase 2 immediately, without re-deriving
> the codebase. Written 2026-06-18 against `main` @ `18008fc`. Line numbers are
> as-of that commit — re-confirm with a quick grep if files have shifted.
>
> **Read order for the next session:** this doc → skim the plan's "Phase 2"
> section (`C:\Users\Lukium\.claude\plans\validated-marinating-metcalfe.md`) →
> start implementing. The memory file `ats-messaging-project-state.md` has the
> cross-session status.

---

## 0. Where we are

- **Phase 0** (hardening) + **Phase 1** (messaging core) are merged to `main` and
  deployed. Fork `@lukium/libsignal-protocol-typescript@0.2.0-beta.2` is a pinned
  dependency. CI green on Node 20.x/22.x.
- **Phase 1 delivered** `src/v2/signal.ts`: a per-user `StorageType` adapter +
  prekey/bundle generation over MKEK-wrapped IndexedDB stores. It is **dormant**
  — nothing imports it yet, so esbuild tree-shakes it out of the deployed bundle.
- **Phase 2 makes it reachable**: add the RPC methods that wire `signal.ts` into
  `worker.ts`, behind a capability/session model. This is the commit where the
  messaging code first enters the deployed enclave.

### Conventions / guardrails (do not violate)
- **`CLAUDE.md` FORBIDS `git checkout` / `git restore`** without explicit per-file
  user approval. To move `main` without checkout: `git push origin <branch>:main`
  (fast-forward) — but we now work **directly on `main`** (no feature branches).
- **Direct-to-`main` workflow.** Commit + push straight to `main`. A push to
  `main` triggers `deploy.yml` → **deploys to kms.ats.run** (separate workflow,
  not gated on the test job). So `main` must always be green + deployable.
- **Pre-commit gate (mandatory):** `make` is unavailable on Windows — run the
  three directly: `pnpm test:coverage` (≥80% global, vitest), `pnpm typecheck`,
  `pnpm lint`. All must pass before committing.
- **Node ≥ 20** only (fork needs X25519/Ed25519 WebCrypto).
- **Crypto tests must use the `node` vitest env**: add `// @vitest-environment node`
  at the top of any test that exercises X25519/Ed25519 (happy-dom lacks them).
  See `tests/v2/signal.test.ts` as the template.
- ESLint: `recommendedTypeChecked` + `no-explicit-any: error`,
  `no-floating-promises: error`, `explicit-function-return-type: warn`. `JSON.parse(x) as T`
  is the accepted cast pattern. `noUncheckedIndexedAccess` is on (array `[i]` is
  `T | undefined` — use `!` or a guard).

---

## 1. Phase 2 scope (from the plan)

New RPC methods to add:
`setupMessaging`, `getMessagingBundle`, `openMessaging`, `closeMessaging`,
`encryptMessage`, `decryptMessage` (+ optional `batchDecrypt`), `rotatePrekeys`,
`getPrekeyCount`.

**Capability/session model (memory-only KEK):**
- `openMessaging(credentials)` runs **one** `withUnlock`, mints a `sid` (UUID) +
  an **Ed25519 capability JWT** `{sid, scope:'messaging', iat, exp ≤ 1h}` signed
  by a dedicated capability key (separate from the UAK), and holds the **MKEK in a
  Worker-memory `Map` keyed by `sid`** — **never** `putMeta` (memory-only, unlike
  the VAPID `sessionKEKCache` which persists to IDB for background push).
- Each later messaging RPC carries `{sid, token}`, validated: signature (Ed25519
  verify), `exp > now`, `sid` live in the map, `scope` includes `messaging`.
- `closeMessaging` / idle / expiry drops the MKEK from the map, revokes `sid`,
  audits.

**MVP ratchet handling:** read-modify-write per message under
`withSessionLock(userId, peerAddress, fn)` (unwrap → cipher → rewrap → write).
No dirty in-memory ratchet cache (avoids losing state on crash/close).

**Message shapes:** `encryptMessage` returns `{type, body}` (1|3 → server
`message_type`); a type-3 `decryptMessage` consumes a one-time prekey + establishes
the session. Validators reject oversized inputs and bound counts.

**Exit criteria:** open a session and encrypt/decrypt across the postMessage
boundary; a second enclave instance decrypts it (integration test driving two
enclave instances via RPC).

---

## 2. The `signal.ts` API Phase 2 calls (confirmed, Phase 1)

All in `src/v2/signal.ts`. The `mkek` is the `CryptoKey` from `withUnlock` /
held in the per-`sid` map.

```ts
createSignalProtocolStore(userId: string, mkek: CryptoKey): StorageType
generateIdentity(userId, mkek, registrationId?: number): Promise<SignalIdentityRecord>   // idempotent
generateSignedPrekey(userId, mkek, keyId: number): Promise<SignalSignedPrekeyRecord>
generateOneTimePrekeys(userId, mkek, startKeyId: number, count: number): Promise<SignalOnetimePrekeyRecord[]>
getPublicBundle(userId: string): Promise<PublicPreKeyBundle>   // public bytes only, NO mkek needed
```

`PublicPreKeyBundle = { registrationId, identityKey(33B X25519), identitySigningKey(32B Ed25519),
signedPreKey:{keyId,publicKey,signature(64B)}, oneTimePreKeys:[{keyId,publicKey}] }`.

**Fork classes** (from `@lukium/libsignal-protocol-typescript`, re-exported at root):
```ts
new SignalProtocolAddress(name: string, deviceId: number)   // .toString() => "name.deviceId"
new SessionBuilder(store, addr).processPreKey(device: DeviceType): Promise<void>
new SessionCipher(store, addr).encrypt(buf: ArrayBuffer): Promise<{type:1|3, body:string, registrationId?}>
  .decryptPreKeyWhisperMessage(body: string, 'binary'): Promise<ArrayBuffer>   // type 3, consumes 1-time prekey
  .decryptWhisperMessage(body: string, 'binary'): Promise<ArrayBuffer>         // type 1
```
`DeviceType = { identityKey, identitySigningKey, registrationId?, signedPreKey:{keyId,publicKey,signature}, preKey?:{keyId,publicKey} }`.
Build it from a peer's `PublicPreKeyBundle` (pick one `oneTimePreKeys[i]` as `preKey`).

---

## 3. Storage / unlock / audit primitives available

**`src/v2/storage.ts`** (Phase 0):
- `withSessionLock(userId, peerAddress, fn): Promise<T>` (~601) — per-peer RMW gate. **Wrap encrypt/decrypt ops in this.**
- `countUnconsumedOnetimePrekeys(userId): Promise<number>` (~558) — `getPrekeyCount`.
- `wrapBlob(bytes, mkek, aad)`/`unwrapBlob(blob, mkek, expectedAad?)` (~455/482).
- get/put accessors for every Signal store (~514–656). `getSignal*` / `putSignal*`.

**`src/v2/unlock.ts`:**
- `withUnlock<T>(credentials: AuthCredentials, op: (mkek: CryptoKey, ms: Uint8Array) => Promise<T>): Promise<UnlockOperationResult<T>>` (444–484).
- `deriveMKEKFromMS(ms): Promise<CryptoKey>` (421–433) — non-extractable AES-GCM, usages encrypt/decrypt/wrapKey/unwrapKey.
- **Key fact:** the `mkek` derived inside `withUnlock` is a non-extractable `CryptoKey` that **survives** after `ms` is zeroised, and **can be stored in a JS `Map`** (it's a handle, not bytes). So `openMessaging` does `withUnlock(creds, async (mkek) => { messagingMkekMap.set(sid, mkek); await ensureAuditKey(mkek); ... })` and the `mkek` stays valid for later RPCs.

**`AuthCredentials`** (types.ts:52–55):
```ts
type AuthCredentials =
  | { method:'passphrase'; passphrase:string; userId:string }
  | { method:'passkey-prf'; prfOutput:ArrayBuffer; userId:string }
  | { method:'passkey-gate'; userId:string };
```

**`src/v2/audit.ts`:**
- `ensureAuditKey(mkek): Promise<void>` (97–159) — loads/creates UAK as `activeSigner` (module state). Call once during `openMessaging` so later messaging ops can `logOperation`.
- `logOperation(op: AuditOperation): Promise<AuditEntryV2>` (429–521). `AuditOperation = {op,kid,requestId,userId,origin?,leaseId?,details?,unlockTime?,lockTime?,duration?}`.
- `verifyAuditChain(): Promise<{valid,verified,errors}>` (588–688) — reference for Ed25519 verify usage.
- Ed25519 primitives in use: sign `crypto.subtle.sign('Ed25519', privKey, data)` (→64B, audit.ts:483); verify `crypto.subtle.verify('Ed25519', pubKey, sig, data)` (audit.ts:669).
- Ed25519 keygen + wrap-under-MKEK template: `ensureAuditKey` body (132–158) — `crypto.subtle.generateKey({name:'Ed25519'}, true, ['sign','verify'])` then `wrapKey(privateKey, mkek, kid, {name:'Ed25519'}, ['sign'], {alg:'EdDSA', purpose:..., publicKeyRaw})`.

---

## 4. RPC plumbing template (4-file flow)

Trace the existing `issueVAPIDJWTs` as the model. Each new method touches all 4:

**(a) `src/v2/types.ts`**
- Add the method name to the `RPCMethod` union (479–511).
- `RPCRequest<TParams>={id,method,params}` / `RPCResponse<TResult>={id,result?,error?}` (466–476).

**(b) `src/v2/rpc-validation.ts`**
- Add `validateXxx(params: unknown): {...typed}` using helpers `validateParamsObject` (32),
  `validateString` (42), `validateNumber` (60), `validateOptionalString` (52). Throw
  `RPCValidationError` (17). Bound sizes/counts here (reject oversized ciphertext, cap prekey counts).

**(c) `src/v2/worker.ts`**
- Add a `case 'xxx': result = await handleXxx(validators.validateXxx(params), id); break;`
  to the `handleMessage` switch (927–1064).
- Implement `async function handleXxx(params, requestId): Promise<...>` following
  `handleIssueVAPIDJWT` (2311–2484): do work, then `await logOperation({...})`.
- **Per-`sid` MKEK map** — declare near the `sessionKEKCache` (113):
  ```ts
  const messagingMkekMap = new Map<string, { mkek: CryptoKey; userId: string; exp: number; capPubKey: CryptoKey }>();
  ```
  **Memory-only** — do NOT persist to IDB (unlike `sessionKEKCache`, which has an
  IDB fallback at 2421–2430 for background push). Messaging is foreground/present-user.

**(d) `src/v2/kms-user.ts`**
- Add `async xxx(params): Promise<...> { return this.sendRequest<...>('xxx', params); }`
  mirroring `issueVAPIDJWTs` (1493). `sendRequest` (374–414) handles id/timeout/postMessage.

Worker message entry: `self.addEventListener('message', ...)` (777–910) →
`handleMessage(request)` (920–1070).

---

## 5. What must be built from scratch (no existing code)

1. **Capability JWT mint** — build `{sid, scope:['messaging'], iat, exp}` →
   base64url(header).base64url(payload).base64url(Ed25519 sig). Header `{typ:'JWT', alg:'EdDSA'}`.
   (The VAPID JWT builder in `handleIssueVAPIDJWT` 2311–2484 is the ES256 analog — copy the
   base64url-join shape, swap to Ed25519.) Use `arrayBufferToBase64url` (crypto-utils).
2. **Capability JWT verify** — decode, check `exp>now` + `scope` + `sid` in map, Ed25519-verify
   the sig against the capability public key. A small `requireCapability(sid, token)` helper called
   at the top of each messaging handler.
3. **Dedicated capability signing key** — **DECISION TO MAKE** (see §6).
4. **Per-`sid` MKEK map** + lifecycle (open/close/idle-expiry eviction).
5. **The 8 handlers** themselves.

---

## 6. Open sub-decisions to settle first (quick)

1. **Capability signing key lifetime/storage.** Options:
   - (A, recommended) A **persistent** Ed25519 capability keypair, generated at
     `setupMessaging`, wrapped under MKEK in the `keys` store (purpose `cap-signing`),
     loaded during `openMessaging`; cache the **public** key in the per-`sid` map for
     cheap verify. Survives worker restarts; one keypair per user.
   - (B) **Per-session** keypair generated fresh in `openMessaging`, public key held in
     the map, discarded on close. Simpler revocation, no persistence, but tokens die on
     worker restart (acceptable for foreground sessions).
   Recommendation: **B** for MVP (memory-only matches the "memory-only KEK" thesis and
   needs no new persisted key), revisit if cross-restart tokens are wanted.
2. **Audit signer for messaging ops.** Use the UAK via `ensureAuditKey(mkek)` at
   `openMessaging` (like `generateVAPID`); messaging `logOperation` calls then use the
   loaded `activeSigner`. (No LAK/lease needed.)
3. **`getPrekeyCount` / `getMessagingBundle` auth.** These read only public/counts —
   decide whether they require `{sid,token}` or are unauthenticated-but-user-scoped.
   Recommend: no unlock, but still take `userId` (and maybe `sid` for consistency).

---

## 7. Suggested implementation order

1. **Types + validators** for all 8 methods (cheap, unblocks the rest).
2. **Capability helpers** (`mintCapabilityToken`, `requireCapability`) + the per-`sid`
   map + the chosen capability-key approach (§6.1). Unit-test mint→verify, exp, bad-sig,
   wrong-scope, unknown-sid.
3. **`setupMessaging`** (one `withUnlock`: generateIdentity + generateSignedPrekey +
   generateOneTimePrekeys; return `getPublicBundle` for upload). **`getMessagingBundle`**
   = `getPublicBundle`. **`getPrekeyCount`** = `countUnconsumedOnetimePrekeys`.
4. **`openMessaging`** (withUnlock → map.set(sid,{mkek,...}) + ensureAuditKey + mint token →
   return `{sid, token}`) / **`closeMessaging`** (evict + audit).
5. **`encryptMessage`** / **`decryptMessage`** — `requireCapability` → build
   `createSignalProtocolStore(userId, mkek)` → `withSessionLock(userId, peer, () => …)` →
   SessionCipher encrypt/decrypt → audit. For encrypt with no existing session, accept the
   peer's bundle/DeviceType param and `SessionBuilder.processPreKey` first.
6. **`rotatePrekeys`** (generateSignedPrekey + top-up generateOneTimePrekeys).
7. **Wire `kms-user.ts`** client methods for each.
8. **Tests** (see §8), then `pnpm test:coverage && pnpm typecheck && pnpm lint`, commit, push.

---

## 8. Testing

- Mirror `tests/v2/signal.test.ts`: **`// @vitest-environment node`**, `beforeEach`
  `globalThis.indexedDB = new IDBFactory(); await initDB();`, `afterEach closeDB()`.
- **Unit:** capability mint/verify (good, expired, tampered sig, wrong scope, unknown sid);
  validators (oversized ciphertext rejected, count bounds); each handler happy + error paths.
- **Integration (exit gate):** drive two "enclaves" via the RPC handlers (or two
  `createSignalProtocolStore` + cipher flows behind `openMessaging`): Alice `setupMessaging`
  → Bob `setupMessaging` → Alice `openMessaging` → `encryptMessage` (type 3) → Bob
  `openMessaging` → `decryptMessage` → assert plaintext; then a type-1 reply. Assert the
  consumed one-time prekey is gone and `getPrekeyCount` drops.
- Coverage gate is **global 80%** (`all:true`, `src/v2/**`). New handlers need tests or
  they drag the global down. `worker.ts` is large — focus tests on the new handlers.

---

## 9. Key file:line index (as of `18008fc` — re-verify if drifted)

| What | File | Line |
|---|---|---|
| RPCMethod union | types.ts | 479–511 |
| RPCRequest/Response | types.ts | 466–476 |
| AuthCredentials | types.ts | 52–55 |
| validator helpers / RPCValidationError | rpc-validation.ts | 17–65 |
| validateIssueVAPIDJWTs (template) | rpc-validation.ts | 453–467 |
| handleMessage switch | worker.ts | 920–1070 |
| handleIssueVAPIDJWT (full template) | worker.ts | 2311–2484 |
| sessionKEKCache (map template) | worker.ts | 113 |
| message listener | worker.ts | 777–910 |
| kms-user issueVAPIDJWTs + sendRequest | kms-user.ts | 1493 / 374–414 |
| withUnlock / deriveMKEKFromMS | unlock.ts | 444–484 / 421–433 |
| ensureAuditKey / logOperation / verifyAuditChain | audit.ts | 97 / 429 / 588 |
| Ed25519 sign / verify | audit.ts | 483 / 669 |
| signal.ts (all Phase 2 calls) | signal.ts | (whole file) |
| withSessionLock / countUnconsumedOnetimePrekeys | storage.ts | 601 / 558 |

---

## 10. First actions for the next session
1. Read this doc + the plan's Phase 2 section.
2. `git -C C:\Users\Lukium\Dev\ats-kms-enclave status` — confirm on `main`, clean.
3. Quick-verify the §9 line refs (grep a couple) in case files drifted.
4. Settle §6 decisions (capability key = per-session B is the default).
5. Implement in the §7 order; gate with `pnpm test:coverage && pnpm typecheck && pnpm lint`;
   commit + push to `main`; watch CI + deploy.
