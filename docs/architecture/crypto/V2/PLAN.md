# KMS V2: Complete Implementation Plan

**Version**: 2.0
**Status**: Implementation Guide
**Date**: 2025-01-24
**Purpose**: Step-by-step path from zero to fully functional KMS V2

This plan takes you from creating the first file to a production-ready KMS. Follow phases sequentially. Use checkpoints to verify against TARGET.md and design docs.

---

## Overview

**Build Order**: Bottom-up (infrastructure → domain → orchestration → UI)

```
Phase 1: Foundation (crypto-utils, storage) - Pure utilities, no business logic
Phase 2: Core Domain (unlock, audit)        - Master secret and logging
Phase 3: Orchestration (worker)             - RPC routing and operations
Phase 4: Bridge (client)                    - Iframe message forwarding
Phase 5: User Interface (kms-user)          - PWA-facing API
Phase 6: Integration Testing                - End-to-end flows
Phase 7: Build System                       - Reproducible builds, SRI
Phase 8: Deployment                         - Production readiness
```

**Time Estimates**: Each phase 1-3 days (depending on complexity)

---

## Phase 1: Foundation Layer (Infrastructure)

**Goal**: Build pure utility functions and storage layer with zero dependencies on domain logic.

**Reference Docs**:
- `TARGET.md` - Module Architecture section
- `design/01-primitives.md` - Crypto primitives
- `module-architecture.md` - Layer 0 specifications

### 1.1: Project Setup

**Objective**: Initialize repository structure and tooling

**Steps**:
1. Create directory structure:
   ```
   src/
     crypto-utils.ts
     storage.ts
     unlock.ts
     audit.ts
     worker.ts
     client.ts
     kms-user.ts
     types.ts
   tests/
     unit/
       crypto-utils.test.ts
       storage.test.ts
       unlock.test.ts
       audit.test.ts
       worker.test.ts
     integration/
     e2e/
   ```

2. Initialize TypeScript configuration:
   - Strict mode enabled
   - ES2022 target
   - DOM and WebWorker lib types
   - Path aliases for clean imports

3. Setup testing framework (Vitest):
   - Coverage thresholds: 80% (lines, branches, functions, statements)
   - Browser mode for WebCrypto tests
   - Mocking utilities for IndexedDB

4. Setup linting (ESLint):
   - TypeScript rules
   - Import order rules
   - No circular dependencies check

**Success Criteria**:
- [ ] `pnpm install` works
- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` runs (even with no tests)
- [ ] `pnpm lint` passes

**Checkpoint**: Verify `Makefile` targets work (from CLAUDE.md)

---

### 1.2: Type Definitions (`src/types.ts`)

**Objective**: Define all TypeScript interfaces and types for the entire system

**Steps**:
1. Define auth credential types:
   ```typescript
   type AuthCredentials =
     | { method: 'passphrase'; passphrase: string }
     | { method: 'passkey-prf'; prfOutput: ArrayBuffer }
     | { method: 'passkey-gate'; pepper: ArrayBuffer };
   ```

2. Define config schemas:
   - `PassphraseConfigV2`
   - `PasskeyPRFConfigV2`
   - `PasskeyGateConfigV2`
   - `EnrollmentIndex`

3. Define key storage types:
   - `WrappedKeyV2`
   - `KeyMetadata`

4. Define audit types:
   - `AuditEntryV2`
   - `AuditOperation`
   - `VerificationResult`

5. Define RPC types:
   - `RPCRequest`
   - `RPCResponse`
   - `RPCMethod`

6. Define operation result types:
   - `UnlockOperationResult<T>`
   - `SetupResult`
   - `VAPIDKeyPair`

7. Define VAPID lease types (MVP):
   - `LeaseRecord`
   - `QuotaState`
   - `VAPIDPayload`

**Reference**: `TARGET.md` Storage Schema section

**Success Criteria**:
- [ ] All types compile without errors
- [ ] Types match TARGET.md schemas exactly
- [ ] JSDoc comments for all public interfaces
- [ ] Export all types from barrel export

**Checkpoint**: Compare types against `TARGET.md` Storage Schema - ensure 1:1 match

---

### 1.3: Crypto Utilities (`src/crypto-utils.ts`)

**Objective**: Implement pure cryptographic utility functions with no side effects

**Reference**:
- `design/01-primitives.md`
- `TARGET.md` Module Architecture (crypto-utils section)

**Implementation Order**:

#### 1.3.1: Encoding Utilities
```typescript
// Base64url encoding/decoding (no padding)
export function arrayBufferToBase64url(buffer: ArrayBuffer): string
export function base64urlToArrayBuffer(base64url: string): ArrayBuffer

// Hex encoding/decoding
export function arrayBufferToHex(buffer: ArrayBuffer): string
export function hexToArrayBuffer(hex: string): ArrayBuffer
```

**Tests**: Roundtrip conversions, edge cases (empty buffers, special chars)

#### 1.3.2: JWK Thumbprint (RFC 7638)
```typescript
// P-256 JWK thumbprint
export async function jwkThumbprintP256(jwk: JsonWebKey): Promise<string>

// Convert raw public key to JWK
export function rawP256ToJwk(rawPublicKey: Uint8Array): JsonWebKey
```

**Tests**: Known test vectors from RFC 7638, determinism

#### 1.3.3: AAD Construction (V2 New)
```typescript
// Master secret encryption AAD
export function buildMSEncryptionAAD(config: MSAADConfig): ArrayBuffer

// Key wrap AAD
export function buildKeyWrapAAD(metadata: KeyWrapAADConfig): ArrayBuffer
```

**Tests**: Deterministic output, JSON canonicalization

#### 1.3.4: KCV (Key Check Value - V2 New)
```typescript
// Compute KCV for passphrase verification
export async function computeKCV(kek: CryptoKey): Promise<ArrayBuffer>

// Verify KCV (constant-time comparison)
export function verifyKCV(computed: ArrayBuffer, stored: ArrayBuffer): boolean

// Timing-safe comparison
export function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean
```

**Tests**: Timing attack resistance (statistical tests), correct/incorrect password

#### 1.3.5: Deterministic Salts (V2 New)
```typescript
// Derive deterministic salt from context string
export async function deriveDeterministicSalt(context: string): Promise<ArrayBuffer>
```

**Tests**: Determinism, uniqueness per context, collision resistance

#### 1.3.6: PBKDF2 Calibration (V2 New)
```typescript
interface CalibrationResult {
  iterations: number;
  measuredMs: number;
  lastCalibratedAt: number;
  platformHash: string;
}

export async function calibratePBKDF2Iterations(
  targetMs?: { min: number; max: number; mid: number }
): Promise<CalibrationResult>

export function getPlatformHash(): string
```

**Tests**: Target timing achieved, clamping works, platform hash stability

#### 1.3.7: Signature Format Utilities
```typescript
// Detect signature format
export function detectSignatureFormat(
  signature: Uint8Array
): 'DER' | 'P-1363' | 'unknown'

// Convert DER to P-1363 (for edge cases)
export function derToP1363(signature: Uint8Array): Uint8Array

// Convert P-1363 to DER (for compatibility)
export function p1363ToDer(signature: Uint8Array): Uint8Array
```

**Tests**: Format detection, conversion roundtrips, edge cases (leading zeros)

**Success Criteria**:
- [ ] All functions pure (no side effects)
- [ ] 80% test coverage
- [ ] No dependencies on other modules
- [ ] All tests pass in browser environment
- [ ] Performance: PBKDF2 calibration works across devices

**Checkpoint**: Review against `design/01-primitives.md` - verify all utilities match spec

---

### 1.4: Storage Layer (`src/storage.ts`)

**Objective**: Implement IndexedDB operations for keys, configs, and audit entries

**Reference**:
- `TARGET.md` Storage Schema section
- `module-architecture.md` Layer 0

**Implementation Order**:

#### 1.4.1: Database Initialization
```typescript
export async function initDB(): Promise<void>
```

**Implementation**:
- Database name: `kms-v2`
- Version: 2
- Object stores:
  - `keys` (primary: kid)
  - `meta` (primary: key)
  - `audit` (primary: seqNum, index: timestamp)

**Tests**: Database creation, version upgrade, schema validation

#### 1.4.2: Key Wrapping/Unwrapping
```typescript
export async function wrapKey(
  key: CryptoKey,
  wrappingKey: CryptoKey,
  kid: string,
  algorithm?: AlgorithmIdentifier,
  usages?: KeyUsage[],
  metadata?: KeyMetadata
): Promise<void>

export async function unwrapKey(
  kid: string,
  wrappingKey: CryptoKey,
  algorithm: AlgorithmIdentifier,
  usages?: KeyUsage[]
): Promise<CryptoKey>

export async function getWrappedKey(kid: string): Promise<WrappedKey | null>
export async function getAllWrappedKeys(): Promise<WrappedKey[]>
```

**Implementation Details**:
- Generate unique IV per wrap operation
- Build AAD using `buildKeyWrapAAD` from crypto-utils
- Store AAD alongside wrapped key (needed for unwrap)
- Validate AAD on unwrap

**Tests**: Wrap/unwrap roundtrip, AAD mismatch detection, non-existent key

#### 1.4.3: Metadata Storage
```typescript
export async function getMeta<T>(key: string): Promise<T | null>
export async function putMeta(key: string, value: unknown): Promise<void>
export async function deleteMeta(key: string): Promise<void>
export async function getAllMeta(): Promise<Array<{ key: string; value: unknown }>>
```

**Tests**: CRUD operations, type safety, key patterns (enrollment:*, vapid:*, etc.)

#### 1.4.4: Audit Storage
```typescript
export async function storeAuditEntry(entry: AuditEntryV2): Promise<void>
export async function getAllAuditEntries(): Promise<AuditEntryV2[]>
export async function getLastAuditEntry(): Promise<AuditEntryV2 | null>
export async function getAuditEntriesSince(seqNum: number): Promise<AuditEntryV2[]>
```

**Implementation**:
- Enforce sequential seqNum (detect gaps)
- Index by timestamp for efficient querying
- Return entries sorted by seqNum

**Tests**: Sequential writes, gap detection, query performance

**Success Criteria**:
- [ ] All CRUD operations work
- [ ] 80% test coverage
- [ ] AAD validation prevents ciphertext swapping
- [ ] IndexedDB transactions atomic
- [ ] No data races in concurrent operations

**Checkpoint**: Verify storage schema matches `TARGET.md` exactly (field names, types, indexes)

---

## Phase 2: Core Domain Layer

**Goal**: Implement business logic for master secret management and audit logging

**Reference**:
- `TARGET.md` Master Secret Setup and Unlock Context sections
- `design/02-master-secret.md`
- `design/03-unlock-context.md`
- `design/05-audit-log.md`

### 2.1: Unlock Module (`src/unlock.ts`)

**Objective**: Implement master secret encryption, unlock context, and per-operation authentication

**Reference**:
- `TARGET.md` Unlock Context section
- `design/02-master-secret.md`
- `design/03-unlock-context.md`

**Implementation Order**:

#### 2.1.1: Master Secret Generation
```typescript
export function generateMasterSecret(): Uint8Array
```

**Implementation**:
- 32 bytes from `crypto.getRandomValues()`
- Never stored unencrypted
- Exists only during operations

**Tests**: Entropy quality, length validation

#### 2.1.2: MKEK Derivation
```typescript
export async function deriveMKEKFromMS(
  ms: Uint8Array,
  version?: number
): Promise<CryptoKey>
```

**Implementation**:
- HKDF-SHA256
- Salt: `SHA-256("ATS/KMS/MKEK/salt/v2")` (deterministic, non-zero)
- Info: `"ATS/KMS/MKEK/v2"`
- Output: 256-bit AES-GCM key
- Usage: `['wrapKey', 'unwrapKey']`
- Extractable: false

**Tests**: Determinism, non-extractable, correct usage flags

#### 2.1.3: Passphrase Setup
```typescript
export async function setupPassphrase(
  passphrase: string,
  existingMS?: Uint8Array
): Promise<{ enrollmentId: string; ms: Uint8Array }>
```

**Implementation Steps**:
1. Generate or reuse MS
2. Run PBKDF2 calibration (if not cached)
3. Generate random salt (16 bytes)
4. Derive KEK with calibrated iterations
5. Compute KCV for password verification
6. Build AAD for MS encryption
7. Generate random IV (12 bytes)
8. Encrypt MS with AES-256-GCM (KEK, IV, AAD)
9. Store PassphraseConfigV2 in meta
10. Return enrollment ID and MS

**Tests**: Setup/unlock roundtrip, wrong password detection (KCV), AAD validation

#### 2.1.4: Passkey PRF Setup
```typescript
export async function setupPasskeyPRF(
  credentialId: ArrayBuffer,
  prfOutput: ArrayBuffer,
  rpId: string,
  existingMS?: Uint8Array
): Promise<{ enrollmentId: string; ms: Uint8Array }>
```

**Implementation Steps**:
1. Generate or reuse MS
2. Generate random appSalt (32 bytes, for PRF eval.first)
3. Derive hkdfSalt deterministically (distinct from appSalt)
4. Derive KEK via HKDF (prfOutput as IKM, hkdfSalt, info)
5. Build AAD for MS encryption
6. Generate random IV (12 bytes)
7. Encrypt MS with AES-256-GCM
8. Store PasskeyPRFConfigV2 in meta
9. Return enrollment ID and MS

**Tests**: Multi-enrollment (same MS, different credentials), PRF uniqueness

#### 2.1.5: Passkey Gate Setup (Fallback)
```typescript
export async function setupPasskeyGate(
  credentialId: ArrayBuffer,
  passphrase: string,
  rpId: string,
  existingMS?: Uint8Array
): Promise<{ enrollmentId: string; ms: Uint8Array }>
```

**Implementation Steps**:
1. Generate random pepper (32 bytes)
2. Encrypt pepper (released only after WebAuthn ceremony)
3. Derive KEK via HKDF (passphrase || pepper as IKM)
4. Encrypt MS
5. Store PasskeyGateConfigV2

**Tests**: Pepper uniqueness, WebAuthn gate requirement

#### 2.1.6: Unlock Operations
```typescript
export async function unlockWithPassphrase(
  passphrase: string,
  enrollmentId?: string
): Promise<{ ms: Uint8Array; enrollmentId: string }>

export async function unlockWithPasskeyPRF(
  prfOutput: ArrayBuffer,
  enrollmentId?: string
): Promise<{ ms: Uint8Array; enrollmentId: string }>

export async function unlockWithPasskeyGate(
  pepper: ArrayBuffer,
  enrollmentId?: string
): Promise<{ ms: Uint8Array; enrollmentId: string }>
```

**Implementation**:
- Retrieve config from storage
- Derive KEK from credentials
- Verify KCV (if passphrase)
- Decrypt MS with AAD verification
- Return MS and enrollment ID

**Tests**: Wrong password, AAD mismatch, missing config

#### 2.1.7: withUnlock Context
```typescript
export async function withUnlock<T>(
  credentials: AuthCredentials,
  operation: (mkek: CryptoKey) => Promise<T>
): Promise<UnlockOperationResult<T>>
```

**Implementation**:
```typescript
const unlockTime = Date.now();
let ms: Uint8Array | null = null;

try {
  // 1. Unlock (decrypt MS from credentials)
  const unlockResult = await unlockByMethod(credentials);
  ms = unlockResult.ms;

  // 2. Derive MKEK from MS
  const mkek = await deriveMKEKFromMS(ms);

  // 3. Execute operation with MKEK
  const result = await operation(mkek);

  // 4. Return with timing
  const lockTime = Date.now();
  return {
    result,
    unlockTime,
    lockTime,
    duration: lockTime - unlockTime
  };
} finally {
  // GUARANTEED CLEANUP
  if (ms) {
    ms.fill(0);  // Overwrite with zeros
    ms = null;    // Clear reference
  }
  // MKEK garbage collected automatically
}
```

**Tests**:
- Cleanup happens even on errors
- MS lifetime tracking
- Operation success/failure handling
- Finally block always executes

#### 2.1.8: Status/Query Operations
```typescript
export async function isSetup(): Promise<boolean>
export async function getEnrollments(): Promise<EnrollmentIndex>
export async function removeEnrollment(enrollmentId: string): Promise<void>
```

**Success Criteria**:
- [ ] All setup methods work
- [ ] All unlock methods work
- [ ] withUnlock guarantees cleanup
- [ ] Multi-enrollment works (same MS, different credentials)
- [ ] KCV verification works (V2)
- [ ] AAD validation works (V2)
- [ ] PBKDF2 calibration achieves target timing
- [ ] MS lifetime < 200ms typical
- [ ] 80% test coverage

**Checkpoint 1**: Compare implementation against `TARGET.md` Master Secret Setup section
- Verify all 6 steps implemented correctly
- Verify AAD used everywhere
- Verify KCV used for passphrase
- Verify deterministic HKDF salts

**Checkpoint 2**: Compare against `design/02-master-secret.md` - verify algorithms, parameters, key sizes match exactly

**Checkpoint 3**: Test multi-enrollment
- Setup passphrase (creates MS)
- Setup passkey PRF with same MS
- Unlock with either credential
- Verify same MKEK derived

---

### 2.2: Audit Module (`src/audit.ts`)

**Objective**: Implement tamper-evident audit logging with Ed25519 signatures

**Reference**:
- `TARGET.md` Audit Log section
- `design/05-audit-log.md`

**Implementation Order**:

#### 2.2.1: Audit Key Generation
```typescript
export async function initAuditLogger(): Promise<void>
```

**Implementation**:
1. Check if audit key exists
2. If not, generate Ed25519 keypair
3. Wrap private key with MKEK (requires unlock)
4. Store wrapped key in storage
5. Store public key in meta (for verification)
6. Generate keyId (SHA-256 of public key)

**Tests**: Key generation, non-extractable private key, public key retrieval

#### 2.2.2: Audit Entry Creation
```typescript
export async function logOperation(
  op: AuditOperation,
  mkek: CryptoKey
): Promise<void>
```

**Implementation**:
1. Get last audit entry (for seqNum and previousHash)
2. Increment seqNum (or start at 0)
3. Build entry (without chainHash/signature)
4. Canonicalize entry (JSON.stringify with sorted keys)
5. Compute chainHash = SHA-256(canonical + previousHash)
6. Unwrap audit private key with MKEK
7. Sign chainHash with Ed25519
8. Add signature and auditKeyId to entry
9. Store entry

**Tests**: Sequence numbers, chain integrity, signature validity

#### 2.2.3: Chain Verification
```typescript
export async function verifyAuditChain(): Promise<VerificationResult>
```

**Implementation**:
1. Get all audit entries (sorted by seqNum)
2. Initialize: previousHash = "0000...0000", expectedSeqNum = 0
3. For each entry:
   - Verify seqNum === expectedSeqNum
   - Compute expected chainHash
   - Verify chainHash matches
   - Verify Ed25519 signature
   - Update previousHash, increment expectedSeqNum
4. Return result with count and errors

**Tests**: Valid chain, tampered entry, truncated chain, out-of-order entries

#### 2.2.4: Audit Key Export
```typescript
export async function exportAuditKey(
  mkek: CryptoKey
): Promise<string>
```

**Implementation**:
- Unwrap audit private key
- Export as JWK
- Base64url encode
- Return

**Tests**: Export/import roundtrip, requires authentication

#### 2.2.5: Query Operations
```typescript
export async function getAuditPublicKey(): Promise<{ publicKey: string }>
export async function getRecentOperations(limit: number): Promise<AuditEntryV2[]>
export async function getOperationsByKid(kid: string): Promise<AuditEntryV2[]>
```

**Success Criteria**:
- [ ] Audit key generation works
- [ ] Logging preserves chain integrity
- [ ] Verification detects tampering
- [ ] Verification detects truncation (seqNum gaps)
- [ ] Ed25519 signatures valid
- [ ] Export requires authentication
- [ ] 80% test coverage

**Checkpoint**: Compare against `TARGET.md` Audit Log section
- Verify V2 improvements implemented:
  - Sequence numbers ✓
  - Non-extractable key ✓
  - Key ID reference (not embedded pubkey) ✓
  - Explicit versioning ✓

---

## Phase 3: Orchestration Layer

**Goal**: Implement RPC routing, policy enforcement, and operation coordination

**Reference**:
- `TARGET.md` Module Architecture (worker.ts section)
- `module-architecture.md` Layer 2

### 3.1: Worker Module (`src/worker.ts`)

**Objective**: RPC handler that coordinates unlock, audit, storage, and crypto operations

**Implementation Order**:

#### 3.1.1: RPC Message Handling
```typescript
// Worker message listener
self.addEventListener('message', async (event: MessageEvent) => {
  const request = event.data as RPCRequest;
  const response = await handleMessage(request);
  self.postMessage(response);
});

export async function handleMessage(request: RPCRequest): Promise<RPCResponse>
```

**Implementation**:
- Parse request
- Route to handler based on method
- Catch errors and format response
- Include requestId in response

**Tests**: Valid requests, invalid requests, error handling

#### 3.1.2: Setup Operations
```typescript
async function handleSetupPassphrase(
  params: { passphrase: string },
  requestId: string
): Promise<RPCResponse>

async function handleSetupPasskey(
  params: { credentialId: ArrayBuffer; prfOutput: ArrayBuffer; rpId: string },
  requestId: string
): Promise<RPCResponse>

async function handleAddEnrollment(
  params: { method: string; credentials: AuthCredentials; ... },
  requestId: string
): Promise<RPCResponse>
```

**Implementation**:
1. Validate parameters
2. Call appropriate setup function from unlock.ts
3. Log setup operation to audit
4. Return success/error

**Tests**: First setup, additional enrollments, invalid params

#### 3.1.3: VAPID Operations
```typescript
async function handleGenerateVAPID(
  params: { credentials: AuthCredentials },
  requestId: string
): Promise<RPCResponse>
```

**Implementation**:
1. Use withUnlock context
2. Inside operation:
   - Generate ECDSA P-256 keypair
   - Export public key (raw format, 65 bytes)
   - Compute kid (JWK thumbprint)
   - Wrap private key with MKEK (with AAD)
   - Store wrapped key
3. Log operation with unlock timing
4. Return kid and public key

**Tests**: Key generation, wrapping, storage, audit logging

```typescript
async function handleSignJWT(
  params: { kid: string; payload: VAPIDPayload; credentials: AuthCredentials },
  requestId: string
): Promise<RPCResponse>
```

**Implementation**:
1. Validate payload (aud, sub, exp)
2. Use withUnlock context
3. Inside operation:
   - Unwrap private key with MKEK
   - Build JWT header and payload
   - Sign with ECDSA-SHA256
   - Validate signature format (64 bytes)
   - Build final JWT string
4. Log operation
5. Return JWT

**Tests**: Valid JWT, expired payload, invalid kid, signature format validation

#### 3.1.4: VAPID Lease Operations (MVP)
```typescript
async function handleCreateLease(
  params: {
    userId: string;
    subs: Array<{ url: string; aud: string; eid: string }>;
    ttlHours: number;
    credentials: AuthCredentials;
  },
  requestId: string
): Promise<RPCResponse>
```

**Implementation**:
1. Validate params (ttl ≤ 24h)
2. Generate lease ID
3. Initialize quota state
4. Store lease record
5. Log lease creation
6. Return lease metadata

**Tests**: Lease creation, quota initialization, TTL validation

```typescript
async function handleIssueVAPIDJWT(
  params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
  },
  requestId: string
): Promise<RPCResponse>
```

**Implementation**:
1. Retrieve lease record
2. Verify lease not expired
3. Check quota (per-lease and per-endpoint)
4. Build JWT payload (aud, sub, exp, uid, eid, jti)
5. Sign JWT (uses handleSignJWT internally)
6. Update quota state
7. Log issuance
8. Return JWT, jti, exp

**Tests**: Quota enforcement, expiration, audience binding, rate limits

#### 3.1.5: Status/Query Operations
```typescript
async function handleIsSetup(): Promise<RPCResponse>
async function handleGetEnrollments(): Promise<RPCResponse>
async function handleVerifyAuditChain(): Promise<RPCResponse>
async function handleGetPublicKey(params: { kid: string }): Promise<RPCResponse>
```

#### 3.1.6: Management Operations
```typescript
async function handleResetKMS(): Promise<RPCResponse>
async function handleRemoveEnrollment(
  params: { enrollmentId: string; credentials: AuthCredentials }
): Promise<RPCResponse>
```

**Success Criteria**:
- [ ] All RPC methods implemented
- [ ] All operations use withUnlock where required
- [ ] All operations logged to audit
- [ ] Error handling comprehensive
- [ ] Policy enforcement (quotas, expirations)
- [ ] 80% test coverage

**Checkpoint 1**: Verify all operations in `TARGET.md` VAPID Operations section implemented

**Checkpoint 2**: Test full flow:
1. Setup passphrase
2. Generate VAPID key
3. Create lease
4. Issue JWT
5. Verify audit chain
6. Check quota state

---

## Phase 4: Bridge Layer

**Goal**: Implement iframe message forwarding between PWA and Worker

**Reference**:
- `TARGET.md` Module Architecture (client.ts section)
- `design/11-iframe-isolation.md`

### 4.1: Client Module (`src/client.ts`)

**Objective**: Minimal bridge that validates origins and forwards messages

**Implementation**:

#### 4.1.1: Worker Initialization
```typescript
export class KMSClient {
  private worker: Worker | null = null;
  private parentOrigin: string;

  constructor(config: { parentOrigin: string }) {
    this.parentOrigin = config.parentOrigin;
  }

  async init(): Promise<void> {
    // Create Worker
    this.worker = new Worker(new URL('./worker.ts', import.meta.url), {
      type: 'module'
    });

    // Setup Worker message handler
    this.worker.addEventListener('message', this.handleWorkerResponse.bind(this));

    // Setup parent window message handler
    window.addEventListener('message', this.handleParentMessage.bind(this));

    // Signal ready to parent
    window.parent.postMessage({ type: 'kms:ready' }, this.parentOrigin);
  }
}
```

**Tests**: Worker creation, message handler setup, ready signal

#### 4.1.2: Message Forwarding
```typescript
private handleParentMessage(event: MessageEvent): void {
  // Validate origin
  if (event.origin !== this.parentOrigin) {
    console.warn('Rejected message from invalid origin:', event.origin);
    return;
  }

  // Forward to Worker
  if (this.worker) {
    this.worker.postMessage(event.data);
  }
}

private handleWorkerResponse(event: MessageEvent): void {
  // Forward to parent
  window.parent.postMessage(event.data, this.parentOrigin);
}
```

**Tests**: Origin validation, message forwarding, invalid origins rejected

#### 4.1.3: HTML Bootstrap
Create `public/kms.html`:
```html
<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; frame-ancestors https://allthe.services;">
<title>ATS KMS Enclave</title>
<script type="module" src="/client.js"></script>
```

**Success Criteria**:
- [ ] Worker created successfully
- [ ] Origin validation works
- [ ] Messages forwarded correctly
- [ ] Invalid origins rejected
- [ ] Minimal logic (bridge only)
- [ ] Tests pass

**Checkpoint**: Verify against `TARGET.md` System Overview - ensure bridge layer isolation correct

---

## Phase 5: User Interface Layer

**Goal**: Implement PWA-facing API with WebAuthn ceremonies

**Reference**:
- `TARGET.md` Module Architecture (kms-user.ts section)
- `module-architecture.md` Layer 4

### 5.1: KMS User Module (`src/kms-user.ts`)

**Objective**: User-facing API that runs in PWA context (allthe.services)

**Implementation Order**:

#### 5.1.1: Client Initialization
```typescript
export class KMSUser {
  private iframe: HTMLIFrameElement | null = null;
  private pendingRequests: Map<string, PendingRequest> = new Map();
  private kmsOrigin: string;

  constructor(config: { kmsOrigin: string }) {
    this.kmsOrigin = config.kmsOrigin;
  }

  async init(): Promise<void> {
    // Create iframe
    this.iframe = document.createElement('iframe');
    this.iframe.src = `${this.kmsOrigin}/kms.html`;
    this.iframe.sandbox.add('allow-scripts', 'allow-same-origin');
    this.iframe.allow = 'publickey-credentials-get; publickey-credentials-create';

    // Setup message handler
    window.addEventListener('message', this.handleMessage.bind(this));

    // Append to DOM
    document.body.appendChild(this.iframe);

    // Wait for ready signal
    await this.waitForReady();
  }
}
```

**Tests**: Iframe creation, sandbox attributes, ready signal

#### 5.1.2: RPC Communication
```typescript
private async sendRequest<T>(
  method: string,
  params: unknown,
  timeout: number = 10000
): Promise<T> {
  const requestId = crypto.randomUUID();

  return new Promise((resolve, reject) => {
    // Setup timeout
    const timeoutId = setTimeout(() => {
      this.pendingRequests.delete(requestId);
      reject(new Error(`Request timeout: ${method}`));
    }, timeout);

    // Store pending request
    this.pendingRequests.set(requestId, {
      resolve: (result) => {
        clearTimeout(timeoutId);
        this.pendingRequests.delete(requestId);
        resolve(result);
      },
      reject: (error) => {
        clearTimeout(timeoutId);
        this.pendingRequests.delete(requestId);
        reject(error);
      }
    });

    // Send request
    this.iframe?.contentWindow?.postMessage(
      { id: requestId, method, params },
      this.kmsOrigin
    );
  });
}

private handleMessage(event: MessageEvent): void {
  // Validate origin
  if (event.origin !== this.kmsOrigin) return;

  const response = event.data as RPCResponse;
  const pending = this.pendingRequests.get(response.id);

  if (pending) {
    if ('error' in response) {
      pending.reject(new Error(response.error));
    } else {
      pending.resolve(response.result);
    }
  }
}
```

**Tests**: Request/response correlation, timeouts, concurrent requests

#### 5.1.3: Setup Methods (with WebAuthn)
```typescript
async setupPassphrase(passphrase: string): Promise<SetupResult> {
  return this.sendRequest('setup:passphrase', { passphrase });
}

async setupPasskey(config: {
  name: string;
  rpId: string;
  userId: string;
}): Promise<SetupResult> {
  // WebAuthn create ceremony (runs in parent context)
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: config.rpId, name: 'ATS KMS' },
      user: {
        id: new TextEncoder().encode(config.userId),
        name: config.name,
        displayName: config.name
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'required'
      },
      extensions: {
        prf: { eval: { first: crypto.getRandomValues(new Uint8Array(32)) } }
      }
    }
  }) as PublicKeyCredential;

  // Extract PRF output
  const prfExt = credential.getClientExtensionResults().prf;
  const prfOutput = prfExt?.results?.first;

  if (!prfOutput) {
    throw new Error('PRF extension not supported');
  }

  // Send to KMS
  return this.sendRequest('setup:passkey-prf', {
    credentialId: credential.rawId,
    prfOutput,
    rpId: config.rpId
  });
}
```

**Tests**: WebAuthn mocking, PRF extension, credential creation

#### 5.1.4: Unlock Methods
```typescript
async unlockWithPassphrase(passphrase: string): Promise<UnlockResult> {
  return this.sendRequest('unlock:passphrase', { passphrase });
}

async unlockWithPasskey(rpId: string): Promise<UnlockResult> {
  // WebAuthn get ceremony
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      extensions: {
        prf: { eval: { first: /* stored appSalt */ } }
      }
    }
  }) as PublicKeyCredential;

  const prfOutput = assertion.getClientExtensionResults().prf?.results?.first;

  return this.sendRequest('unlock:passkey-prf', {
    credentialId: assertion.rawId,
    prfOutput
  });
}

async unlock(rpId: string, passphrase?: string): Promise<UnlockResult> {
  // Auto-fallback: Try passkey, fallback to passphrase
  try {
    return await this.unlockWithPasskey(rpId);
  } catch (err) {
    if (passphrase) {
      return await this.unlockWithPassphrase(passphrase);
    }
    throw err;
  }
}
```

**Tests**: Unlock flows, auto-fallback, missing credentials

#### 5.1.5: VAPID Operations
```typescript
async generateVAPID(credentials?: AuthCredentials): Promise<VAPIDKeyPair> {
  return this.sendRequest('vapid:generate', { credentials });
}

async signJWT(
  kid: string,
  payload: VAPIDPayload,
  credentials?: AuthCredentials
): Promise<{ jwt: string }> {
  return this.sendRequest('vapid:sign', { kid, payload, credentials });
}

async getPublicKey(kid: string): Promise<{ publicKey: string | null }> {
  return this.sendRequest('vapid:getPublicKey', { kid });
}
```

#### 5.1.6: VAPID Lease Operations (MVP)
```typescript
async createLease(params: {
  userId: string;
  subs: Array<{ url: string; aud: string; eid: string }>;
  ttlHours: number;
  credentials?: AuthCredentials;
}): Promise<LeaseResult> {
  return this.sendRequest('vapid:lease:create', params);
}

async issueJWT(params: {
  leaseId: string;
  endpoint: { url: string; aud: string; eid: string };
}): Promise<{ jwt: string; jti: string; exp: number }> {
  return this.sendRequest('vapid:lease:issue', params);
}

async extendLease(leaseId: string, ttlHours: number): Promise<void> {
  return this.sendRequest('vapid:lease:extend', { leaseId, ttlHours });
}

async revokeLease(leaseId: string): Promise<void> {
  return this.sendRequest('vapid:lease:revoke', { leaseId });
}
```

#### 5.1.7: Status/Management
```typescript
async isSetup(): Promise<{ isSetup: boolean }> {
  return this.sendRequest('status:isSetup', {});
}

async verifyAuditChain(): Promise<VerificationResult> {
  return this.sendRequest('audit:verify', {});
}

async resetKMS(): Promise<{ success: boolean }> {
  return this.sendRequest('management:reset', {});
}
```

**Success Criteria**:
- [ ] All API methods implemented
- [ ] WebAuthn ceremonies work (mocked in tests)
- [ ] Request/response correlation correct
- [ ] Timeouts work
- [ ] Origin validation secure
- [ ] 80% test coverage

**Checkpoint**: Compare API against `TARGET.md` - ensure all operations accessible from PWA

---

## Phase 6: Integration Testing

**Goal**: Test end-to-end flows across all layers

**Reference**: All design docs

### 6.1: Core Flow Tests

**Test Suites**:

#### 6.1.1: Setup and Unlock
```typescript
describe('Setup and Unlock', () => {
  it('should setup passphrase and unlock', async () => {
    // 1. Setup
    await kmsUser.setupPassphrase('test-password-123');

    // 2. Verify stored
    const { isSetup } = await kmsUser.isSetup();
    expect(isSetup).toBe(true);

    // 3. Unlock
    const result = await kmsUser.unlockWithPassphrase('test-password-123');
    expect(result.success).toBe(true);
  });

  it('should reject wrong password', async () => {
    await kmsUser.setupPassphrase('correct');
    await expect(
      kmsUser.unlockWithPassphrase('wrong')
    ).rejects.toThrow('INVALID_PASSPHRASE');
  });
});
```

#### 6.1.2: Multi-Enrollment
```typescript
describe('Multi-Enrollment', () => {
  it('should unlock with any enrolled credential', async () => {
    // 1. Setup passphrase (creates MS)
    await kmsUser.setupPassphrase('password');

    // 2. Add passkey (reuses same MS)
    await kmsUser.setupPasskey({
      name: 'Test Key',
      rpId: 'localhost',
      userId: 'user-123'
    });

    // 3. Unlock with passphrase
    const result1 = await kmsUser.unlockWithPassphrase('password');

    // 4. Unlock with passkey
    const result2 = await kmsUser.unlockWithPasskey('localhost');

    // 5. Both should work
    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);
  });
});
```

#### 6.1.3: VAPID Key Lifecycle
```typescript
describe('VAPID Operations', () => {
  it('should generate, store, and sign with VAPID key', async () => {
    // 1. Setup
    await kmsUser.setupPassphrase('password');

    // 2. Generate VAPID key
    const { kid, publicKey } = await kmsUser.generateVAPID({
      method: 'passphrase',
      passphrase: 'password'
    });

    expect(kid).toBeTruthy();
    expect(publicKey).toHaveLength(65); // Uncompressed P-256

    // 3. Sign JWT
    const { jwt } = await kmsUser.signJWT(
      kid,
      {
        aud: 'https://fcm.googleapis.com',
        sub: 'mailto:admin@example.com',
        exp: Math.floor(Date.now() / 1000) + 3600
      },
      { method: 'passphrase', passphrase: 'password' }
    );

    expect(jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/); // JWT format

    // 4. Verify JWT externally (using jose library)
    const verified = await verifyJWT(jwt, publicKey);
    expect(verified).toBe(true);
  });
});
```

#### 6.1.4: VAPID Leases (MVP)
```typescript
describe('VAPID Leases', () => {
  it('should create lease and issue JWTs', async () => {
    // 1. Setup
    await kmsUser.setupPassphrase('password');

    // 2. Generate VAPID key
    const { kid } = await kmsUser.generateVAPID({
      method: 'passphrase',
      passphrase: 'password'
    });

    // 3. Create lease
    const lease = await kmsUser.createLease({
      userId: 'user-123',
      subs: [
        {
          url: 'https://fcm.googleapis.com/fcm/send/abc',
          aud: 'https://fcm.googleapis.com',
          eid: 'ep-1'
        }
      ],
      ttlHours: 12,
      credentials: { method: 'passphrase', passphrase: 'password' }
    });

    expect(lease.leaseId).toBeTruthy();
    expect(lease.exp).toBeGreaterThan(Date.now());

    // 4. Issue JWT
    const { jwt, jti, exp } = await kmsUser.issueJWT({
      leaseId: lease.leaseId,
      endpoint: {
        url: 'https://fcm.googleapis.com/fcm/send/abc',
        aud: 'https://fcm.googleapis.com',
        eid: 'ep-1'
      }
    });

    expect(jwt).toBeTruthy();
    expect(jti).toBeTruthy();

    // 5. Verify quota updated
    // (implementation-specific query)
  });

  it('should enforce quotas', async () => {
    // Setup and create lease with low quota
    const lease = await kmsUser.createLease({
      userId: 'user-123',
      subs: [/* ... */],
      ttlHours: 1,
      credentials: { method: 'passphrase', passphrase: 'password' }
    });

    // Issue JWTs until quota exceeded
    for (let i = 0; i < 100; i++) {
      await kmsUser.issueJWT({
        leaseId: lease.leaseId,
        endpoint: {/* ... */}
      });
    }

    // Next request should fail
    await expect(
      kmsUser.issueJWT({/* ... */})
    ).rejects.toThrow('QUOTA_EXCEEDED');
  });
});
```

#### 6.1.5: Audit Chain
```typescript
describe('Audit Chain', () => {
  it('should maintain valid chain across operations', async () => {
    // 1. Setup
    await kmsUser.setupPassphrase('password');

    // 2. Perform multiple operations
    await kmsUser.generateVAPID({
      method: 'passphrase',
      passphrase: 'password'
    });

    const { kid } = await kmsUser.generateVAPID({
      method: 'passphrase',
      passphrase: 'password'
    });

    await kmsUser.signJWT(kid, {/* payload */}, {/* creds */});

    // 3. Verify chain
    const { valid, verified, errors } = await kmsUser.verifyAuditChain();

    expect(valid).toBe(true);
    expect(verified).toBeGreaterThan(0);
    expect(errors).toHaveLength(0);
  });

  it('should detect tampering', async () => {
    // 1. Setup and perform operations
    await kmsUser.setupPassphrase('password');
    await kmsUser.generateVAPID({/* ... */});

    // 2. Tamper with audit log (directly in IndexedDB)
    // (implementation-specific - modify chainHash or signature)

    // 3. Verification should fail
    const { valid, errors } = await kmsUser.verifyAuditChain();

    expect(valid).toBe(false);
    expect(errors).toContain('Chain hash mismatch');
  });
});
```

### 6.2: Security Tests

#### 6.2.1: AAD Validation
```typescript
describe('AAD Security', () => {
  it('should reject ciphertext swapping', async () => {
    // 1. Setup two enrollments
    await kmsUser.setupPassphrase('password1');

    // Get config 1
    const config1 = await storage.getMeta('enrollment:enroll-001:config');

    // Setup second enrollment
    await kmsUser.setupPassphrase('password2');

    // Get config 2
    const config2 = await storage.getMeta('enrollment:enroll-002:config');

    // 2. Swap encryptedMS between configs
    const swapped = { ...config1, encryptedMS: config2.encryptedMS };
    await storage.putMeta('enrollment:enroll-001:config', swapped);

    // 3. Unlock should fail (AAD mismatch)
    await expect(
      kmsUser.unlockWithPassphrase('password1')
    ).rejects.toThrow('Decryption failed');
  });
});
```

#### 6.2.2: Timing Attacks
```typescript
describe('Timing Attack Resistance', () => {
  it('should have constant-time KCV comparison', async () => {
    await kmsUser.setupPassphrase('correct-password');

    const times: number[] = [];

    // Try wrong passwords with varying lengths
    for (let i = 0; i < 100; i++) {
      const wrongPass = 'wrong'.repeat(i + 1);
      const start = performance.now();
      try {
        await kmsUser.unlockWithPassphrase(wrongPass);
      } catch {}
      times.push(performance.now() - start);
    }

    // Statistical analysis - times should not correlate with password length
    const correlation = pearsonCorrelation(times, times.map((_, i) => i));
    expect(Math.abs(correlation)).toBeLessThan(0.1); // Low correlation
  });
});
```

### 6.3: Performance Tests

```typescript
describe('Performance', () => {
  it('should unlock in < 300ms (passphrase)', async () => {
    await kmsUser.setupPassphrase('password');

    const start = performance.now();
    await kmsUser.unlockWithPassphrase('password');
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(300);
  });

  it('should sign JWT in < 50ms', async () => {
    await kmsUser.setupPassphrase('password');
    const { kid } = await kmsUser.generateVAPID({/* ... */});

    const start = performance.now();
    await kmsUser.signJWT(kid, {/* payload */}, {/* creds */});
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(50);
  });
});
```

**Success Criteria**:
- [ ] All core flows work end-to-end
- [ ] Multi-enrollment works
- [ ] VAPID lifecycle complete
- [ ] VAPID leases work (MVP)
- [ ] Audit chain valid
- [ ] Security tests pass (AAD, timing)
- [ ] Performance targets met

**Checkpoint**: Review all tests against `TARGET.md` flows - ensure complete coverage

---

## Phase 7: Build System

**Goal**: Implement reproducible builds, content-addressing, and SRI

**Reference**:
- `design/04-build-pipeline.md`
- `design/11-iframe-isolation.md`

### 7.1: Deterministic Build

**Implementation**:

#### 7.1.1: esbuild Configuration
Create `build/esbuild.config.ts`:
```typescript
import * as esbuild from 'esbuild';

export async function buildKMS(): Promise<void> {
  // Worker build
  await esbuild.build({
    entryPoints: ['src/worker.ts'],
    bundle: true,
    format: 'esm',
    target: 'es2022',
    platform: 'browser',
    outfile: 'dist/worker.js',
    minify: true,
    sourcemap: false,
    treeShaking: true,
    // Deterministic settings
    define: {
      'process.env.NODE_ENV': '"production"',
      'process.env.BUILD_TIME': `"${process.env.SOURCE_DATE_EPOCH || Date.now()}"`
    },
    banner: {
      js: '// ATS KMS Worker - DO NOT MODIFY'
    }
  });

  // Client build
  await esbuild.build({
    entryPoints: ['src/client.ts'],
    bundle: true,
    format: 'esm',
    target: 'es2022',
    platform: 'browser',
    outfile: 'dist/client.js',
    minify: true,
    sourcemap: false,
    treeShaking: true
  });
}
```

**Tests**: Build reproducibility (run twice, compare hashes)

#### 7.1.2: Content-Addressing
Create `build/content-address.ts`:
```typescript
import { createHash } from 'crypto';
import { readFileSync, renameSync } from 'fs';

export function contentAddressFile(filePath: string): string {
  // Read file
  const content = readFileSync(filePath);

  // Compute SHA-256
  const hash = createHash('sha256').update(content).digest('hex');
  const shortHash = hash.slice(0, 8);

  // Generate new filename
  const newPath = filePath.replace(/\.js$/, `-v2.0.0-${shortHash}.mjs`);

  // Rename file
  renameSync(filePath, newPath);

  return newPath;
}
```

#### 7.1.3: SRI Hash Generation
```typescript
export function generateSRIHash(filePath: string): string {
  const content = readFileSync(filePath);
  const hash = createHash('sha256').update(content).digest('base64');
  return `sha256-${hash}`;
}
```

#### 7.1.4: HTML Generation
Create `build/generate-html.ts`:
```typescript
export function generateKMSHTML(scriptPath: string, sriHash: string): string {
  return `<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; style-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; child-src 'none'; form-action 'none'; frame-ancestors https://allthe.services; base-uri 'none'; manifest-src 'none'">
<title>ATS KMS Enclave</title>
<script type="module" integrity="${sriHash}" src="/${scriptPath}"></script>
`;
}
```

#### 7.1.5: Build Script
Create `build/build.ts`:
```typescript
export async function build(): Promise<void> {
  // 1. Clean dist
  await rm('dist', { recursive: true, force: true });
  await mkdir('dist', { recursive: true });

  // 2. Build bundles
  await buildKMS();

  // 3. Content-address files
  const clientPath = contentAddressFile('dist/client.js');
  const workerPath = contentAddressFile('dist/worker.js');

  // 4. Generate SRI hashes
  const clientSRI = generateSRIHash(clientPath);

  // 5. Generate HTML
  const html = generateKMSHTML(
    path.basename(clientPath),
    clientSRI
  );

  writeFileSync('dist/kms.html', html);

  // 6. Generate manifest
  const manifest = {
    version: '2.0.0',
    buildTime: new Date().toISOString(),
    files: {
      client: {
        path: path.basename(clientPath),
        sri: clientSRI,
        size: statSync(clientPath).size
      },
      worker: {
        path: path.basename(workerPath),
        size: statSync(workerPath).size
      },
      html: {
        path: 'kms.html',
        size: statSync('dist/kms.html').size
      }
    }
  };

  writeFileSync('dist/manifest.json', JSON.stringify(manifest, null, 2));

  console.log('Build complete:', manifest);
}
```

**Tests**: Full build, verify SRI, verify reproducibility

**Success Criteria**:
- [ ] Build is deterministic (same input → same output)
- [ ] Content-addressed filenames include hash
- [ ] SRI hashes generated correctly
- [ ] HTML minimal and correct
- [ ] Manifest complete

**Checkpoint**: Build twice from same source, compare all file hashes - should be identical

---

### 7.2: Runtime Self-Check

**Implementation** (in `src/client.ts`):
```typescript
async function verifySelfIntegrity(): Promise<boolean> {
  try {
    // 1. Fetch own source
    const response = await fetch(import.meta.url);
    const sourceCode = await response.arrayBuffer();

    // 2. Compute hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', sourceCode);
    const hash = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // 3. Get expected hash from filename
    const expectedHash = import.meta.url.match(/-([0-9a-f]{8})\.mjs$/)?.[1];

    if (!expectedHash) {
      console.error('Could not extract hash from filename');
      return false;
    }

    // 4. Compare (first 8 chars)
    const shortHash = hash.slice(0, 8);

    if (shortHash !== expectedHash) {
      console.error('Self-check failed:', { computed: shortHash, expected: expectedHash });
      return false;
    }

    return true;
  } catch (error) {
    console.error('Self-check error:', error);
    return false;
  }
}

// Run on load
const integrityValid = await verifySelfIntegrity();
if (!integrityValid) {
  // HALT - refuse all operations
  throw new Error('KMS integrity check failed');
}
```

**Tests**: Valid hash, tampered code detection

**Checkpoint**: Verify self-check against `design/11-iframe-isolation.md` Layer 6

---

## Phase 8: Deployment & Production Readiness

**Goal**: Prepare for production deployment

### 8.1: Browser Compatibility Testing

**Test Matrix**:
- Chrome 120+ (Windows, macOS, Linux)
- Firefox 120+
- Safari 17+ (macOS, iOS)
- Edge 120+

**Test Cases**:
1. WebCrypto support (all algorithms)
2. IndexedDB reliability
3. Worker support
4. WebAuthn PRF extension
5. Performance on low-end devices

**Tools**:
- BrowserStack for cross-browser testing
- Playwright for automated tests

**Success Criteria**:
- [ ] All tests pass on all target browsers
- [ ] Performance acceptable on low-end devices
- [ ] WebAuthn PRF support detected gracefully

---

### 8.2: Security Audit Preparation

**Checklist**:
- [ ] All security properties documented
- [ ] Threat model complete (`design/08-security-model.md`)
- [ ] All crypto parameters justified
- [ ] All AAD usages documented
- [ ] Timing attack mitigations documented
- [ ] Audit log integrity verified

**Deliverables**:
- Security whitepaper
- Threat model document
- Audit checklist

---

### 8.3: Documentation

**Required Documentation**:

1. **User Guide**:
   - How to setup KMS
   - How to use VAPID keys
   - How to manage enrollments
   - How to verify audit chain

2. **API Reference**:
   - All public methods documented
   - Type definitions
   - Usage examples

3. **Deployment Guide**:
   - Hosting requirements
   - CSP headers
   - CORS configuration
   - DNS setup (kms.ats.run)

4. **Verification Guide**:
   - How to verify build artifacts
   - How to reproduce builds
   - How to verify SRI hashes

**Success Criteria**:
- [ ] All docs complete
- [ ] Examples tested
- [ ] Hosted on GitHub Pages

---

### 8.4: Production Deployment

**Steps**:

1. **Build production artifacts**:
   ```bash
   pnpm build:reproducible
   ```

2. **Verify build**:
   - Reproducibility check
   - SRI hash validation
   - Self-check works

3. **Sign artifacts** (future - Sigstore):
   ```bash
   cosign sign-blob --key cosign.key dist/client-*.mjs
   ```

4. **Publish to transparency log** (future - Rekor):
   ```bash
   rekor-cli upload --artifact dist/manifest.json
   ```

5. **Deploy to CDN**:
   - Upload to static hosting (Cloudflare Pages, Vercel, etc.)
   - Set immutable cache headers
   - Verify CSP headers

6. **DNS Configuration**:
   - Point `kms.ats.run` to CDN
   - Enable HTTPS (Let's Encrypt)
   - Verify CORS headers

7. **Update main PWA**:
   - Update iframe src to production URL
   - Update CSP to allow kms.ats.run
   - Test integration

**Success Criteria**:
- [ ] Production deployment live
- [ ] HTTPS working
- [ ] CSP headers correct
- [ ] SRI verification working
- [ ] Integration with PWA working

---

## Summary: Complete Checklist

### Phase 1: Foundation ✓
- [ ] Project setup
- [ ] Type definitions
- [ ] Crypto utilities (80% coverage)
- [ ] Storage layer (80% coverage)

### Phase 2: Core Domain ✓
- [ ] Unlock module (setup, unlock, withUnlock)
- [ ] Multi-enrollment support
- [ ] Audit module (logging, verification)

### Phase 3: Orchestration ✓
- [ ] Worker RPC handler
- [ ] All operations implemented
- [ ] VAPID operations
- [ ] VAPID leases (MVP)
- [ ] Policy enforcement

### Phase 4: Bridge ✓
- [ ] Client module (message forwarding)
- [ ] Origin validation
- [ ] HTML bootstrap

### Phase 5: User Interface ✓
- [ ] KMS User API
- [ ] WebAuthn integration
- [ ] All public methods

### Phase 6: Integration Testing ✓
- [ ] Core flows
- [ ] Multi-enrollment
- [ ] VAPID lifecycle
- [ ] VAPID leases
- [ ] Audit chain
- [ ] Security tests
- [ ] Performance tests

### Phase 7: Build System ✓
- [ ] Reproducible builds
- [ ] Content-addressing
- [ ] SRI generation
- [ ] Runtime self-check

### Phase 8: Production ✓
- [ ] Browser compatibility
- [ ] Security audit prep
- [ ] Documentation
- [ ] Production deployment

---

## Daily Workflow During Implementation

**Each Day**:
1. Pick a phase/section
2. Implement functions
3. Write tests (TDD recommended)
4. Run `make pre-commit` (typecheck, test, lint)
5. Commit when all checks pass
6. Move to next section

**At Each Checkpoint**:
1. Review TARGET.md relevant section
2. Review design docs
3. Compare implementation vs specification
4. Verify all requirements met
5. Document any deviations

**Weekly**:
1. Run full integration tests
2. Check coverage (should be 80%)
3. Review audit log for any issues
4. Update progress tracking

---

## Estimated Timeline

**Conservative Estimate** (1 developer, 6-8 weeks):

- **Week 1**: Phase 1 (Foundation)
- **Week 2-3**: Phase 2 (Core Domain)
- **Week 3-4**: Phase 3 (Orchestration)
- **Week 4**: Phase 4-5 (Bridge + UI)
- **Week 5-6**: Phase 6 (Integration Testing)
- **Week 7**: Phase 7 (Build System)
- **Week 8**: Phase 8 (Production Prep)

**Aggressive Estimate** (2 developers, 4-5 weeks):

- **Week 1**: Phases 1-2 parallel
- **Week 2**: Phases 3-4 parallel
- **Week 3**: Phase 5-6 parallel
- **Week 4**: Phase 7-8 parallel
- **Week 5**: Buffer for issues/refinement

---

## Success Criteria for "Done"

The KMS V2 is **complete and production-ready** when:

✅ All 8 phases complete
✅ 80% test coverage (lines, branches, functions, statements)
✅ All checkpoints verified against TARGET.md/design docs
✅ Performance targets met (unlock <300ms, sign <50ms)
✅ Security tests pass (AAD, timing, audit)
✅ Multi-enrollment works
✅ VAPID leases work (MVP)
✅ Browser compatibility verified
✅ Documentation complete
✅ Reproducible builds working
✅ SRI verification working
✅ Production deployment successful
✅ Integration with PWA working

**Final Checkpoint**: Review entire implementation against TARGET.md - should match 80%

---

**Next**: Begin Phase 1.1 - Project Setup
