# KMS V2: Module Architecture & Separation of Concerns

**Version**: 2.0
**Date**: 2025-10-24
**Status**: Design

---

## Overview

The KMS V2 architecture follows a strict separation of concerns across seven core modules. Each module has a well-defined responsibility and clear boundaries with other modules.

### Design Principles

1. **Single Responsibility**: Each module handles one concern (crypto, storage, audit, etc.)
2. **Clear Boundaries**: Modules communicate through well-defined interfaces
3. **Testability**: Each module can be tested in isolation
4. **Security Layers**: Modules enforce different security boundaries
5. **No Circular Dependencies**: Dependency flow is unidirectional

---

## Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────┐
│                        MODULE ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                               │
│  │  kms-user.ts │  (PWA - allthe.services)                      │
│  │  Parent      │  - User-facing API                            │
│  │  Window      │  - WebAuthn ceremonies                        │
│  └──────┬───────┘  - postMessage sender                         │
│         │                                                       │
│         │ postMessage (cross-origin)                            │
│         ▼                                                       │
│  ┌──────────────┐                                               │
│  │  client.ts   │  (KMS Iframe - kms.ats.run)                   │
│  │  Iframe      │  - Receives postMessage from PWA              │
│  │  Main Thread │  - Forwards to Worker                         │
│  └──────┬───────┘  - Returns responses to PWA                   │
│         │                                                       │
│         │ postMessage (Worker)                                  │
│         ▼                                                       │
│  ┌──────────────┐                                               │
│  │  worker.ts   │  (KMS Worker)                                 │
│  │  Orchestrator│  - RPC request routing                        │
│  │              │  - Policy enforcement                         │
│  │              │  - Operation coordination                     │
│  └──┬───────┬───┘                                               │
│     │       │                                                   │
│     │       └──────────────────┐                                │
│     │                          │                                │
│     ▼                          ▼                                │
│  ┌──────────────┐      ┌──────────────┐                         │
│  │  unlock.ts   │      │  audit.ts    │                         │
│  │  Unlock      │      │  Audit Log   │                         │
│  │  Context     │      │  & Chain     │                         │
│  └──────┬───────┘      └──────┬───────┘                         │
│         │                     │                                 │
│         │                     │                                 │
│         └──────┬──────────────┘                                 │
│                │                                                │
│                ▼                                                │
│         ┌──────────────┐                                        │
│         │ crypto-utils │                                        │
│         │ Crypto Ops   │                                        │
│         └──────┬───────┘                                        │
│                │                                                │
│                ▼                                                │
│         ┌──────────────┐                                        │
│         │ storage.ts   │                                        │
│         │ IndexedDB    │                                        │
│         └──────────────┘                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Specifications

### 1. `kms-user.ts` (PWA - Parent Window)

**Location**: Runs in **allthe.services** (main PWA, parent window context)

**Responsibility**: Client-side operations that require parent context

**Key Functions**:
- User-facing API (setup, unlock, crypto operations)
- WebAuthn ceremonies (passkey create/get)
- postMessage communication with KMS iframe
- Request/response correlation (pending requests map)
- Timeout handling

**Public API**:
```typescript
class KMSUser {
  // Setup
  setupPassphrase(passphrase: string): Promise<SetupResult>
  setupPasskey(config: PasskeyConfig): Promise<SetupResult>

  // Unlock
  unlockWithPassphrase(passphrase: string): Promise<UnlockResult>
  unlockWithPasskey(rpId: string): Promise<UnlockResult>
  unlock(rpId: string, passphrase?: string): Promise<UnlockResult>

  // Operations (require credentials)
  generateVAPID(credentials?: AuthCredentials): Promise<VAPIDKeyPair>
  signJWT(kid: string, payload: JWTPayload, credentials?: AuthCredentials): Promise<{ jwt: string }>
  getPublicKey(kid: string): Promise<{ publicKey: string | null }>

  // Status
  isUnlockSetup(): Promise<{ isSetup: boolean }>
  verifyAuditChain(): Promise<VerificationResult>
  getPasskeyConfig(): Promise<PasskeyConfig | null>

  // Management
  resetKMS(): Promise<{ success: boolean }>
}
```

**Dependencies**:
- **None** (communicates via postMessage only)

**Security Boundary**: Cross-origin isolation from KMS iframe

**Why in Parent?**:
- WebAuthn requires top-level context (user gesture, navigator.credentials)
- User-facing operations need access to main window for UI/prompts

---

### 2. `client.ts` (KMS Iframe Main Thread)

**Location**: Runs in **kms.ats.run** iframe main thread

**Responsibility**: Bridge between parent window and KMS Worker

**Key Functions**:
- Receive postMessage from kms-user.ts (validate origin)
- Create and manage Worker instance
- Forward RPC requests to Worker
- Send Worker responses back to parent
- Worker lifecycle management

**Public API**:
```typescript
class KMSClient {
  // Initialization
  constructor(config: KMSClientConfig)
  init(): Promise<void>

  // Internal (not exposed to parent directly)
  private handleParentMessage(event: MessageEvent): void
  private forwardToWorker(request: RPCRequest): void
  private handleWorkerResponse(response: RPCResponse): void
}
```

**Dependencies**:
- **worker.ts** (creates Worker instance)

**Security Boundary**:
- Validates parent origin on postMessage
- Sandboxed iframe (allow-scripts allow-same-origin)
- No crypto operations (all in Worker)

**Why Separate from kms-user?**:
- Cross-origin: parent can't directly access iframe internals
- Worker must be created from iframe context
- Origin validation enforced at iframe boundary

---

### 3. `worker.ts` (KMS Worker - Orchestrator)

**Location**: Runs in **KMS Dedicated Worker**

**Responsibility**: RPC routing, policy enforcement, operation orchestration

**Key Functions**:
- Handle RPC requests from client.ts
- Route to appropriate handler (setup, unlock, crypto ops)
- Enforce policies (JWT expiration, rate limits, etc.)
- Coordinate between unlock.ts, audit.ts, storage.ts
- No direct crypto operations (delegates to other modules)

**Public API**:
```typescript
// RPC handler (called by Worker message listener)
export async function handleMessage(request: RPCRequest): Promise<RPCResponse>

// Internal operation handlers
async function setupPassphraseMethod(passphrase: string, ...): Promise<SetupResult>
async function unlockWithPassphraseMethod(passphrase: string, ...): Promise<UnlockResult>
async function generateVAPID(requestId: string, ...): Promise<VAPIDKeyPair>
async function signJWT(kid: string, payload: JWTPayload, ...): Promise<{ jwt: string }>
// ... other operations
```

**Dependencies**:
- **unlock.ts** (setup, unlock, withUnlock)
- **audit.ts** (logOperation, verifyAuditChain)
- **storage.ts** (wrapKey, unwrapKey, getMeta, putMeta)
- **crypto-utils.ts** (derToP1363, jwkThumbprint, etc.)

**Security Boundary**:
- No DOM access (Worker context)
- No postMessage to parent (only to client.ts)
- Per-operation authentication enforcement

**Why in Worker?**:
- Isolation from DOM (no phishing vector)
- Separate JavaScript context
- Cannot access parent window or iframe document

---

### 4. `unlock.ts` (Unlock Context Manager)

**Location**: Imported by worker.ts

**Responsibility**: Master Secret encryption/decryption, unlock context management

**Key Functions**:
- Setup authentication methods (passphrase, passkey-prf, passkey-gate)
- Unlock operations (decrypt MS from credentials)
- Derive MKEK from MS
- `withUnlock()` context (single unlock gate)
- MS zeroization and cleanup

**Public API**:
```typescript
// Setup (first method or add method)
export async function setupPassphrase(
  passphrase: string,
  existingMS?: Uint8Array
): Promise<UnlockResult>

export async function setupPasskeyPRF(
  credentialId: ArrayBuffer,
  prfOutput: ArrayBuffer,
  existingMS?: Uint8Array
): Promise<UnlockResult>

export async function setupPasskeyGate(
  credentialId: ArrayBuffer,
  existingMS?: Uint8Array
): Promise<UnlockResult>

// Unlock (decrypt MS)
export async function unlockWithPassphrase(passphrase: string): Promise<UnlockResult>
export async function unlockWithPasskeyPRF(prfOutput: ArrayBuffer): Promise<UnlockResult>
export async function unlockWithPasskeyGate(): Promise<UnlockResult>

// Status
export async function isSetup(): Promise<boolean>
export async function isPassphraseSetup(): Promise<boolean>
export async function isPasskeySetup(): Promise<boolean>

// MKEK derivation
export async function deriveMKEKFromMS(
  ms: Uint8Array,
  salt?: Uint8Array
): Promise<CryptoKey>

// Single unlock gate
export async function withUnlock<T>(
  credentials: AuthCredentials,
  operation: (mkek: CryptoKey) => Promise<T>
): Promise<UnlockOperationResult<T>>

// Types
export type UnlockResult =
  | { success: true; ms: Uint8Array }
  | { success: false; error: string }

export type AuthCredentials =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer }
  | { method: 'passkey-gate' }

export interface UnlockOperationResult<T> {
  result: T;
  unlockTime: number;
  lockTime: number;
  duration: number;
}
```

**Dependencies**:
- **storage.ts** (getMeta, putMeta for configs)
- **crypto-utils.ts** (calibration, KCV, AAD, HKDF salts)
- **Web Crypto API** (PBKDF2, HKDF, AES-GCM)

**Does NOT depend on**:
- **worker.ts** (unlock.ts is lower-level)
- **audit.ts** (worker.ts handles audit logging)

**Security Properties**:
- MS never persisted unencrypted
- MS lifetime: milliseconds (only in withUnlock)
- Guaranteed cleanup (finally block)
- All KEKs and MKEK are non-extractable

---

### 5. `audit.ts` (Audit Log & Chain)

**Location**: Imported by worker.ts

**Responsibility**: Tamper-evident audit logging with chain hash

**Key Functions**:
- Initialize audit logger (generate Ed25519 key)
- Log operations with chain hash
- Verify audit chain integrity
- Manage audit key (non-extractable)
- Export audit key (with auth)

**Public API**:
```typescript
// Initialization
export async function initAuditLogger(): Promise<void>

// Logging
export async function logOperation(op: AuditOperation): Promise<void>

// Verification
export async function verifyAuditChain(): Promise<VerificationResult>

// Key management
export async function getAuditPublicKey(): Promise<{ publicKey: string }>
export async function exportAuditKey(credentials: AuthCredentials): Promise<string>

// Reset (for testing)
export function resetAuditLogger(): void

// Types
export interface AuditOperation {
  op: string;
  kid: string;
  requestId: string;
  origin?: string;
  details?: Record<string, unknown>;
  unlockTime?: number;
  lockTime?: number;
  duration?: number;
}

export interface AuditEntryV2 {
  kmsVersion: 2;
  seqNum: number;
  timestamp: number;
  op: string;
  kid: string;
  requestId: string;
  origin?: string;
  unlockTime?: number;
  lockTime?: number;
  duration?: number;
  details?: Record<string, unknown>;
  previousHash: string;
  chainHash: string;
  signature: string;
  auditKeyId: string;
}

export interface VerificationResult {
  valid: boolean;
  verified: number;
  errors: string[];
}
```

**Dependencies**:
- **storage.ts** (getMeta, putMeta for audit entries and key)
- **Web Crypto API** (Ed25519 for signatures, SHA-256 for chain hash)

**Does NOT depend on**:
- **worker.ts** (audit.ts is lower-level)
- **unlock.ts** (orthogonal concerns)

**Security Properties**:
- Ed25519 audit key is non-extractable by default
- Chain hash prevents tampering
- Sequence numbers detect truncation
- Canonical JSON for deterministic hashing

---

### 6. `storage.ts` (IndexedDB Operations)

**Location**: Imported by worker.ts, unlock.ts, audit.ts

**Responsibility**: All IndexedDB operations (CRUD for keys, configs, audit)

**Key Functions**:
- Database initialization (create object stores)
- Key wrapping/unwrapping (with AAD)
- Config storage (setup/unlock configs)
- Audit entry storage
- Query operations

**Public API**:
```typescript
// Initialization
export async function initDB(): Promise<void>

// Key wrapping/unwrapping
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

// Metadata storage (configs, audit entries)
export async function getMeta<T>(key: string): Promise<T | null>
export async function putMeta(key: string, value: unknown): Promise<void>
export async function deleteMeta(key: string): Promise<void>
export async function getAllMeta(): Promise<Array<{ key: string; value: unknown }>>

// Audit storage
export async function storeAuditEntry(entry: AuditEntryV2): Promise<void>
export async function getAllAuditEntries(): Promise<AuditEntryV2[]>
export async function getLastAuditEntry(): Promise<AuditEntryV2 | null>

// Types
export interface WrappedKey {
  kid: string;
  kmsVersion: number;
  wrappedKey: ArrayBuffer;
  iv: ArrayBuffer;
  aad: ArrayBuffer;
  publicKeyRaw?: ArrayBuffer;
  alg: string;
  purpose: string;
  createdAt: number;
  lastUsedAt?: number;
}

export interface KeyMetadata {
  publicKeyRaw?: ArrayBuffer;
  alg: string;
  purpose: string;
}
```

**Dependencies**:
- **IndexedDB API** (browser built-in)
- **Web Crypto API** (wrapKey, unwrapKey)

**Does NOT depend on**:
- **worker.ts**, **unlock.ts**, **audit.ts** (storage is lowest level)

**Security Properties**:
- All keys stored wrapped (never plaintext)
- AAD prevents ciphertext swapping
- Versioning enables migration
- Atomic transactions where possible

---

### 7. `crypto-utils.ts` (Crypto Primitives)

**Location**: Imported by worker.ts, unlock.ts, audit.ts

**Responsibility**: Pure crypto utility functions (no state, no I/O)

**Key Functions**:
- Signature format conversion (DER ↔ P-1363)
- JWK thumbprint (RFC 7638)
- Base64url encoding/decoding
- AAD construction
- KCV computation
- Deterministic salt derivation
- PBKDF2 calibration
- Constant-time comparison

**Public API**:
```typescript
// Signature conversion
export function derToP1363(signature: Uint8Array): Uint8Array
export function p1363ToDer(signature: Uint8Array): Uint8Array
export function detectSignatureFormat(signature: Uint8Array): 'DER' | 'P-1363' | 'unknown'

// JWK thumbprint (RFC 7638)
export async function jwkThumbprintP256(jwk: JsonWebKey): Promise<string>
export function rawP256ToJwk(rawPublicKey: Uint8Array): JsonWebKey

// Encoding
export function arrayBufferToBase64url(buffer: ArrayBuffer): string
export function base64urlToArrayBuffer(base64url: string): ArrayBuffer
export function arrayBufferToHex(buffer: ArrayBuffer): string
export function hexToArrayBuffer(hex: string): ArrayBuffer

// V2: AAD construction
export function buildMSEncryptionAAD(config: MSAADConfig): ArrayBuffer
export function buildKeyWrapAAD(metadata: KeyWrapAADConfig): ArrayBuffer

// V2: KCV (Key Check Value)
export async function computeKCV(kek: CryptoKey): Promise<ArrayBuffer>
export function verifyKCV(computed: ArrayBuffer, stored: ArrayBuffer): boolean
export function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean

// V2: Deterministic salts
export async function deriveDeterministicSalt(context: string): Promise<ArrayBuffer>

// V2: PBKDF2 calibration
export async function calibratePBKDF2Iterations(
  targetMs?: { min: number; max: number; mid: number }
): Promise<{ iterations: number; measuredMs: number }>

// V2: Platform fingerprint (coarse)
export function getPlatformHash(): string

// Types
export interface MSAADConfig {
  kmsVersion: number;
  method: string;
  algVersion: number;
  credentialId?: ArrayBuffer;
  purpose: string;
}

export interface KeyWrapAADConfig {
  kmsVersion: number;
  kid: string;
  alg: string;
  purpose: string;
  createdAt: number;
  keyType: string;
}
```

**Dependencies**:
- **Web Crypto API** (SHA-256, HMAC, PBKDF2, etc.)
- **No other modules** (pure utilities)

**Does NOT depend on**:
- Any other KMS modules (crypto-utils is lowest level)

**Security Properties**:
- Pure functions (no side effects)
- Constant-time operations where needed (timingSafeEqual)
- Well-tested primitives
- No secrets in memory after function returns

---

## Module Communication Patterns

### 1. RPC Request Flow (PWA → Worker)

```
kms-user.ts (PWA)
  └─ postMessage(request, kmsOrigin)
       ↓
client.ts (Iframe)
  └─ validateOrigin()
  └─ worker.postMessage(request)
       ↓
worker.ts (Worker)
  └─ handleMessage(request)
  └─ route to operation handler
       ↓
  ┌─ unlock.ts (if needs auth)
  │   └─ withUnlock(credentials, operation)
  │
  ├─ storage.ts (for data)
  │   └─ wrapKey(), unwrapKey(), getMeta()
  │
  ├─ crypto-utils.ts (for crypto)
  │   └─ derToP1363(), jwkThumbprint()
  │
  └─ audit.ts (for logging)
      └─ logOperation()
       ↓
worker.ts
  └─ return response
       ↓
client.ts
  └─ postMessage(response, parentOrigin)
       ↓
kms-user.ts
  └─ resolve pending request
```

### 2. Setup Flow (First Method)

```
kms-user.ts
  └─ setupPassphrase(passphrase)
       ↓ (RPC)
worker.ts
  └─ setupPassphraseMethod()
       ↓
unlock.ts
  └─ setupPassphrase(passphrase)
  └─ calibratePBKDF2Iterations() ──────────▶ crypto-utils.ts
  └─ deriveKEK()
  └─ computeKCV() ─────────────────────────▶ crypto-utils.ts
  └─ buildMSEncryptionAAD() ───────────────▶ crypto-utils.ts
  └─ encrypt MS with KEK
  └─ putMeta(config) ──────────────────────▶ storage.ts
       ↓
audit.ts
  └─ logOperation({ op: 'setup' })
  └─ storeAuditEntry() ────────────────────▶ storage.ts
```

### 3. Operation Flow (with Per-Operation Auth)

```
kms-user.ts
  └─ signJWT(kid, payload, credentials)
       ↓ (RPC with credentials)
worker.ts
  └─ signJWT(kid, payload, credentials)
       ↓
unlock.ts
  └─ withUnlock(credentials, async (mkek) => {
       ↓
storage.ts
  └─ unwrapKey(kid, mkek)
       ↓
worker.ts
  └─ sign JWT with unwrapped key
  └─ derToP1363() ────────────────────────▶ crypto-utils.ts
       ↓
audit.ts
  └─ logOperation({ op: 'sign', duration })
       ↓
unlock.ts
  └─ }) // finally: clear MS
```

---

## Testing Strategy

### Unit Tests (Per Module)

Each module should have comprehensive unit tests:

**unlock.ts**:
- Setup flows (passphrase, passkey-prf, passkey-gate)
- Unlock flows (decrypt MS)
- MKEK derivation (deterministic)
- withUnlock context (cleanup, timing)
- Multi-enrollment (add/remove methods)

**audit.ts**:
- Chain hash computation
- Sequence numbers (monotonic)
- Signature verification
- Truncation detection
- Export audit key (with auth)

**storage.ts**:
- Key wrapping/unwrapping (with AAD)
- Metadata CRUD
- AAD mismatch handling
- Version detection

**crypto-utils.ts**:
- Signature conversion (DER ↔ P-1363)
- JWK thumbprint (RFC 7638)
- AAD construction (deterministic)
- KCV (constant-time)
- Calibration algorithm
- Timing-safe comparison

**worker.ts**:
- RPC routing
- Policy enforcement
- Error handling
- Invalid requests

**client.ts**:
- Origin validation
- Message forwarding
- Worker lifecycle

**kms-user.ts**:
- Request/response correlation
- Timeout handling
- WebAuthn ceremonies (mocked)

### Integration Tests

**Full Flow Tests**:
- Setup → Unlock → Generate VAPID → Sign JWT
- Multi-enrollment flows
- Session lifecycle (open → ops → close)
- Audit chain verification
- V1 → V2 migration detection

**Security Tests**:
- XSS resilience (PWA compromise scenarios)
- Token validation (expired, wrong scope)
- AAD mismatch (ciphertext swapping)
- Timing attacks (KCV verification)

---

## File Size Budgets

To maintain simplicity and auditability:

| Module | Target Size | Max Size | Rationale |
|--------|-------------|----------|-----------|
| crypto-utils.ts | 500 lines | 800 lines | Pure utilities, well-factored |
| storage.ts | 300 lines | 500 lines | Simple CRUD, minimal logic |
| unlock.ts | 600 lines | 1000 lines | Core unlock logic, withUnlock |
| audit.ts | 400 lines | 600 lines | Chain hash, signatures |
| worker.ts | 800 lines | 1200 lines | RPC routing, handlers |
| client.ts | 200 lines | 300 lines | Minimal bridge logic |
| kms-user.ts | 500 lines | 700 lines | User-facing API |
| **Total** | **3300 lines** | **5100 lines** | Small enough to audit |

---

## Import Rules

To prevent circular dependencies and maintain clean architecture:

### ✅ Allowed Imports

```typescript
// worker.ts
import { withUnlock, setupPassphrase, ... } from './unlock.js'
import { logOperation, verifyAuditChain } from './audit.js'
import { wrapKey, unwrapKey, getMeta, putMeta } from './storage.js'
import { derToP1363, jwkThumbprint, ... } from './crypto-utils.js'

// unlock.ts
import { getMeta, putMeta } from './storage.js'
import { calibratePBKDF2, computeKCV, buildMSEncryptionAAD, ... } from './crypto-utils.js'

// audit.ts
import { getMeta, putMeta, storeAuditEntry, ... } from './storage.js'

// storage.ts
// No KMS imports (lowest level)

// crypto-utils.ts
// No KMS imports (lowest level, pure utilities)

// client.ts
import { handleMessage } from './worker.js'

// kms-user.ts
// No imports from other KMS modules (cross-origin boundary)
```

### ❌ Forbidden Imports

```typescript
// unlock.ts CANNOT import
import { handleMessage } from './worker.js'  // ❌ worker depends on unlock
import { logOperation } from './audit.js'    // ❌ worker handles audit calls

// audit.ts CANNOT import
import { withUnlock } from './unlock.js'     // ❌ orthogonal concerns
import { handleMessage } from './worker.js'  // ❌ worker depends on audit

// storage.ts CANNOT import
import { ... } from './worker.js'            // ❌ storage is lowest level
import { ... } from './unlock.js'            // ❌ storage is lowest level
import { ... } from './audit.js'             // ❌ storage is lowest level

// crypto-utils.ts CANNOT import ANY KMS modules
// (must remain pure utilities)
```

---

## Dependency Layers

```
Layer 4: User Interface
  └─ kms-user.ts (PWA)
       │
       ↓ postMessage
       │
Layer 3: Bridge
  └─ client.ts (Iframe)
       │
       ↓ Worker message
       │
Layer 2: Orchestration
  └─ worker.ts (Worker)
       │
       ├────────────┬───────────┐
       ↓            ↓           ↓
Layer 1: Domain Logic
  └─ unlock.ts   audit.ts    (other domain modules)
       │            │
       ├────────────┤
       ↓            ↓
Layer 0: Infrastructure
  └─ storage.ts   crypto-utils.ts
```

**Rules**:
- Higher layers can import from lower layers
- Lower layers CANNOT import from higher layers
- Same-layer imports allowed if no circular dependency

---

## Adding New Modules

When adding a new module (e.g., Signal Protocol), follow these guidelines:

### 1. Determine Layer

- **Layer 2** (Domain): signal.ts (Signal-specific logic)
- Depends on: unlock.ts, storage.ts, crypto-utils.ts
- Used by: worker.ts

### 2. Define Interface

```typescript
// signal.ts
export async function generateIdentityKey(mkek: CryptoKey): Promise<IdentityKey>
export async function generateSignedPrekey(mkek: CryptoKey, ...): Promise<SignedPrekey>
export async function initSignalSession(peerId: string, mkek: CryptoKey): Promise<void>
export async function encryptMessage(peerId: string, plaintext: ArrayBuffer, mkek: CryptoKey): Promise<ArrayBuffer>
export async function decryptMessage(peerId: string, ciphertext: ArrayBuffer, mkek: CryptoKey): Promise<ArrayBuffer>
```

### 3. Update Dependencies

```typescript
// worker.ts
import { initSignalSession, encryptMessage, decryptMessage } from './signal.js'

// signal.ts
import { wrapKey, unwrapKey } from './storage.js'
import { buildKeyWrapAAD } from './crypto-utils.js'
```

### 4. Add Tests

- Unit tests for signal.ts (isolated)
- Integration tests (worker → signal → storage)

---

## Summary

### Key Takeaways

1. **7 Core Modules**: Each with single responsibility
2. **Clear Boundaries**: postMessage (kms-user ↔ client), Worker message (client ↔ worker)
3. **Dependency Flow**: Top-down (user → worker → domain → infrastructure)
4. **No Circular Deps**: Enforced by layer architecture
5. **Testable**: Each module tested in isolation
6. **Auditable**: Small file sizes, clear responsibilities

### Quick Reference

| Need to... | Use Module | Function |
|------------|------------|----------|
| Setup passphrase | unlock.ts | `setupPassphrase()` |
| Decrypt MS | unlock.ts | `unlockWithPassphrase()` |
| Execute with MKEK | unlock.ts | `withUnlock()` |
| Log operation | audit.ts | `logOperation()` |
| Verify audit chain | audit.ts | `verifyAuditChain()` |
| Wrap key | storage.ts | `wrapKey()` |
| Store config | storage.ts | `putMeta()` |
| Convert signature | crypto-utils.ts | `derToP1363()` |
| Compute JWK thumbprint | crypto-utils.ts | `jwkThumbprintP256()` |
| Build AAD | crypto-utils.ts | `buildMSEncryptionAAD()` |
| Calibrate PBKDF2 | crypto-utils.ts | `calibratePBKDF2Iterations()` |
| Route RPC | worker.ts | `handleMessage()` |
| WebAuthn ceremony | kms-user.ts | `setupPasskey()` |
| Bridge to worker | client.ts | `forwardToWorker()` |

---

**Status**: Complete architectural specification

**Next**: Use this as reference during implementation to maintain separation of concerns.
