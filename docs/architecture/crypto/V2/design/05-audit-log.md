# Audit Log (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-01-25

---

## Table of Contents

1. [Overview](#overview)
2. [Audit Entry Schema](#audit-entry-schema)
3. [Audit Key Delegation Architecture](#audit-key-delegation-architecture)
4. [Chain Integrity](#chain-integrity)
5. [Sequence Numbers](#sequence-numbers)
6. [Ed25519 Signatures](#ed25519-signatures)
7. [Periodic Anchors](#periodic-anchors)
8. [Audit Key Management](#audit-key-management)
9. [Verification](#verification)
10. [Implementation](#implementation)
11. [Security Analysis](#security-analysis)

---

## Overview

The audit log is a **tamper-evident record** of all cryptographic operations in KMS V2. Each entry is cryptographically signed and chained to previous entries.

### V2 Improvements

1. **Sequence Numbers**: Monotonic counter detects truncation attacks
2. **Delegated Audit Keys**: UAK/LAK/KIAK architecture for background operations
3. **Enhanced Chain**: SHA-256 hash of previous entry's `chainHash`
4. **Periodic Anchors**: Checkpoint entries every N operations
5. **Key Reference**: `signerId` instead of embedding public key
6. **LRK Management**: Lease Root Key for wrapping LAK/KIAK

### Security Properties

✅ **Tamper-evident**: Any modification breaks chain
✅ **Truncation-resistant**: Sequence numbers detect log truncation
✅ **Replay-resistant**: Each entry has unique timestamp + requestId
✅ **Verifiable**: Ed25519 signatures can be verified externally
✅ **Background-capable**: LAK/KIAK enable logging without user auth
✅ **Authorized**: All audit keys trace back to UAK via delegation certificates

### The Audit Delegation Problem

In V2 SessionKEK architecture, we have a fundamental conflict:

1. **Audit integrity requires**: Audit signing key must be wrapped under MS to prevent forgery
2. **Background operations require**: Lease-based JWT issuance happens WITHOUT user authentication
3. **The conflict**: Can't unwrap audit key to sign entries during lease-based operations

**Solution**: Three types of audit signers with explicit delegation:

- **UAK (User Audit Key)**: For user-authenticated operations, wrapped under MS
- **LAK (Lease Audit Key)**: Per-lease, delegated via UAK-signed cert, wrapped under LRK
- **KIAK (KMS Instance Audit Key)**: Per-installation, delegated via UAK-signed cert, wrapped under LRK

---

## Audit Entry Schema

### V2 Entry Structure

All entries use this unified format regardless of signer:

```typescript
interface AuditEntryV2 {
  // Version and identification
  kmsVersion: 2;
  seqNum: number;              // Monotonic sequence (0, 1, 2, ...)
  timestamp: number;           // Unix timestamp (ms)

  // Operation details
  op: string;                  // Operation type (e.g., "vapid:sign")
  kid: string;                 // Key ID involved (if applicable)
  requestId: string;           // UUID for this operation
  origin?: string;             // Origin of request (if available)

  // Lease context (if applicable)
  leaseId?: string;            // Present if operation is lease-related

  // Unlock timing (for user-authenticated operations)
  unlockTime?: number;         // Unlock start (ms since epoch)
  lockTime?: number;           // Unlock end (ms since epoch)
  duration?: number;           // Duration (ms, high-resolution)

  // Additional context
  details?: Record<string, unknown>;  // Operation-specific data
  jti?: string;                // JWT Token ID (for VAPID issuance, anti-replay tracking)

  // Chain integrity
  previousHash: string;        // SHA-256 of previous entry's chainHash (base64url)
  chainHash: string;           // SHA-256 of this entry's canonical form (base64url)

  // Signer identification (V2 DELEGATION SUPPORT)
  signer: 'UAK' | 'LAK' | 'KIAK';
  signerId: string;            // base64url(SHA-256(publicKey))

  // Authorization proof (for LAK, optional for KIAK)
  cert?: AuditDelegationCert;  // Delegation certificate

  // Signature (V2: renamed from 'signature')
  sig: string;                 // Ed25519 signature of chainHash (base64url)
  sigNew?: string;             // For rotation entries: second signature from new key
}
```

### Delegation Certificate Schema

```typescript
interface AuditDelegationCert {
  type: 'audit-delegation';
  version: 1;
  signerKind: 'LAK' | 'KIAK';
  leaseId?: string;            // Present for LAK, absent for KIAK
  instanceId?: string;         // Present for KIAK, absent for LAK
  delegatePub: string;         // base64url Ed25519 public key
  scope: string[];             // e.g., ["vapid.issue", "lease.expire"] or ["system.*"]
  notBefore: number;           // Unix timestamp (ms)
  notAfter: number | null;     // Unix timestamp (ms), null = no expiration
  codeHash: string;            // KMS code hash at delegation time
  manifestHash: string;        // KMS manifest hash
  kmsVersion: string;          // e.g., "v2.0.0"
  sig: string;                 // base64url signature by UAK
}
```

### Operation Types

```typescript
// Operation type examples
type AuditOperation =
  | 'unlock'                   // Generic unlock (if no specific op)
  | 'vapid:generate'           // Generate VAPID keypair
  | 'vapid:sign'               // Sign VAPID JWT (user-authenticated)
  | 'vapid:issue'              // Issue VAPID JWT (V2 lease-based, LAK-signed)
  | 'vapid:export'             // Export VAPID public key
  | 'audit:generate'           // Generate audit keypair
  | 'audit:export'             // Export audit public key (for backup)
  | 'audit:delegate'           // Create delegation certificate
  | 'audit:rotate'             // Rotate audit key
  | 'enrollment:add'           // Add new credential
  | 'enrollment:remove'        // Remove credential
  | 'lease:create'             // Create VAPID lease
  | 'lease:expire'             // Lease expiration
  | 'backup:export'            // Export backup bundle
  | 'backup:import'            // Import backup bundle
  | 'recalibrate:pbkdf2'       // Recalibrate PBKDF2 iterations
  | 'boot'                     // System boot (KIAK-signed)
  | 'fail-secure'              // Fail-secure transition (KIAK-signed)
  | 'anchor'                   // Periodic anchor entry
  ;
```

### Example Entries

**User-authenticated operation (UAK):**
```json
{
  "kmsVersion": 2,
  "seqNum": 42,
  "timestamp": 1729700000000,
  "op": "lease:create",
  "kid": "",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "origin": "https://allthe.services",
  "leaseId": "lease-abc123",
  "unlockTime": 1729700000100,
  "lockTime": 1729700000350,
  "duration": 250,
  "details": {
    "userId": "user-xyz",
    "ttlHours": 12,
    "quotas": { "maxIssue": 1000 }
  },
  "previousHash": "pQ7YQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5fGhIj",
  "chainHash": "zQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5fGhIjKlM",
  "signer": "UAK",
  "signerId": "b64u(pk_uak)",
  "sig": "A3bC4dE5fGhIjKlMnOpQrStUvWxYzA1bC2dE3fGhIjKlMnOpQrStUvWxYzA1b..."
}
```

**Lease-delegated operation (LAK):**
```json
{
  "kmsVersion": 2,
  "seqNum": 43,
  "timestamp": 1729700300000,
  "op": "vapid:issue",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "requestId": "660e8400-e29b-41d4-a716-446655440001",
  "leaseId": "lease-abc123",
  "details": {
    "endpoint": "https://fcm.googleapis.com/fcm/send/xyz",
    "jti": "jwt-789",
    "exp": 1729703900,
    "aud": "https://fcm.googleapis.com"
  },
  "jti": "jwt-789",
  "previousHash": "zQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5fGhIjKlM",
  "chainHash": "mNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBc",
  "signer": "LAK",
  "signerId": "b64u(pk_lak)",
  "cert": {
    "type": "audit-delegation",
    "version": 1,
    "signerKind": "LAK",
    "leaseId": "lease-abc123",
    "delegatePub": "b64u(pk_lak)",
    "scope": ["vapid:issue", "lease:expire"],
    "notBefore": 1729700000000,
    "notAfter": 1729743200000,
    "codeHash": "sha256-...",
    "manifestHash": "sha256-...",
    "kmsVersion": "v2.0.0",
    "sig": "b64u(sig_uak)"
  },
  "sig": "b64u(sig_lak)"
}
```

**System event (KIAK):**
```json
{
  "kmsVersion": 2,
  "seqNum": 1,
  "timestamp": 1729600000000,
  "op": "boot",
  "kid": "",
  "requestId": "770e8400-e29b-41d4-a716-446655440002",
  "details": {
    "version": "v2.0.0",
    "codeHash": "sha256-...",
    "manifestHash": "sha256-...",
    "priorChainHead": null
  },
  "previousHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "chainHash": "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPq",
  "signer": "KIAK",
  "signerId": "b64u(pk_kiak)",
  "sig": "b64u(sig_kiak)"
}
```

---

## Audit Key Delegation Architecture

### Overview

The delegation architecture solves the catch-22 of audit logging during background operations:

**Problem**: Audit signing key wrapped under MS prevents logging when user is not authenticated (e.g., lease-based JWT issuance).

**Solution**: Three-tier audit key hierarchy:
1. **UAK**: Wrapped under MS, signs user-authenticated operations
2. **LAK**: Wrapped under LRK, delegated per-lease for background operations
3. **KIAK**: Wrapped under LRK, delegated per-installation for system events

### 1. User Audit Key (UAK)

**Purpose:** Sign audit entries for user-authenticated operations

**Lifecycle:**
- Generated during setup alongside MS
- Wrapped under MS (same as application keys)
- Unwrapped when user authenticates
- Available while MS is unlocked

**Signs:**
- Setup/enrollment
- Lease creation
- Delegation certificate issuance
- Manual key operations
- Unlock events

**Storage:**
```typescript
{
  kid: "audit-user",
  kmsVersion: 2,
  wrappedKey: ArrayBuffer,      // UAK private key wrapped under MS
  iv: ArrayBuffer(12),
  aad: ArrayBuffer,             // AAD: { kmsVersion: 2, kid: "audit-user", purpose: "audit-user" }
  publicKeyRaw: ArrayBuffer,    // Ed25519 public key (32 bytes raw)
  alg: "EdDSA",
  purpose: "audit",
  createdAt: number
}
```

**Generation:**
```typescript
async function generateUAK(ms: Uint8Array): Promise<void> {
  // Derive MKEK from MS
  const mkek = await deriveMKEK(ms);

  // Generate UAK keypair
  const uak = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,  // temporarily extractable for wrapping
    ["sign", "verify"]
  );

  // Export public key
  const publicKeyRaw = await crypto.subtle.exportKey("raw", uak.publicKey);

  // Build AAD
  const aad = buildAAD({
    kmsVersion: 2,
    kid: "audit-user",
    alg: "EdDSA",
    purpose: "audit",
    createdAt: Date.now(),
    keyType: "audit-user"
  });

  // Wrap private key under MKEK
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = await crypto.subtle.wrapKey(
    "jwk",
    uak.privateKey,
    mkek,
    { name: "AES-GCM", iv, additionalData: aad }
  );

  // Store
  await storage.put("keys", {
    kid: "audit-user",
    kmsVersion: 2,
    wrappedKey,
    iv,
    aad,
    publicKeyRaw,
    alg: "EdDSA",
    purpose: "audit",
    createdAt: Date.now()
  });
}
```

### 2. Lease Audit Key (LAK)

**Purpose:** Sign audit entries for lease-scoped operations without user present

**Lifecycle:**
- Generated during lease creation (when user IS authenticated)
- Delegated via certificate signed by UAK
- Wrapped under LRK (not MS!) so available anytime
- Deleted when lease expires/revoked
- Lifetime = lease TTL (no mid-lease rotation)

**Signs:**
- VAPID JWT issuance
- Quota enforcement
- Lease expiration
- Operations under that lease

**Certificate Generation Flow:**
```
1. User authenticates, creates lease
2. MS is unwrapped, UAK is available
3. Generate LAK keypair (Ed25519, non-extractable)
4. Create delegation cert with:
   - leaseId
   - pk_lak
   - scope: ["vapid:issue", "lease:expire"]
   - validity: [now, leaseExp]
5. Sign cert with UAK private key
6. Wrap sk_lak under LRK (not MS!)
7. Store: { leaseId, wrappedKey(LRK), cert, exp }
```

**Storage:**
```typescript
interface LeaseAuditKeyRecord {
  leaseId: string;              // Primary key
  wrappedKey: ArrayBuffer;      // LAK private key wrapped under LRK
  iv: ArrayBuffer;
  aad: ArrayBuffer;
  publicKeyRaw: ArrayBuffer;    // LAK public key
  delegationCert: AuditDelegationCert;
  expiresAt: number;
  createdAt: number;
}
// Stored in IndexedDB: lease-audit-keys store
```

**Usage During JWT Issuance:**
```typescript
async function issueVAPIDJWT({ leaseId, endpoint }): Promise<string> {
  // 1. Retrieve LAK for leaseId
  const lakRecord = await storage.get("lease-audit-keys", leaseId);

  // 2. Unwrap LAK using LRK (always available!)
  const lrk = await storage.getMeta("LRK");
  const lak = await crypto.subtle.unwrapKey(
    "jwk",
    lakRecord.wrappedKey,
    lrk,
    { name: "AES-GCM", iv: lakRecord.iv, additionalData: lakRecord.aad },
    { name: "Ed25519" },
    false,  // non-extractable
    ["sign"]
  );

  // 3. Issue JWT (omitted for brevity)
  const jwt = await signVAPIDJWT(...);

  // 4. Create audit entry
  const entry = {
    seq: await getNextSeq(),
    timestamp: Date.now(),
    op: "vapid:issue",
    kid: jwt.kid,
    requestId: crypto.randomUUID(),
    leaseId,
    details: { endpoint, jti: jwt.jti, exp: jwt.exp },
    jti: jwt.jti,
    previousHash: await getChainHead(),
    chainHash: "",  // computed below
    signer: "LAK",
    signerId: base64url(SHA256(lakRecord.publicKeyRaw)),
    cert: lakRecord.delegationCert  // Include full cert for portability
  };

  entry.chainHash = await computeChainHash(entry);

  // 5. Sign with LAK
  const sigBytes = await crypto.subtle.sign(
    "Ed25519",
    lak,
    new TextEncoder().encode(entry.chainHash)
  );
  entry.sig = base64url(new Uint8Array(sigBytes));

  // 6. Append to audit log
  await appendAuditEntry(entry);

  return jwt;
}
```

### 3. KMS Instance Audit Key (KIAK)

**Purpose:** Sign system events not tied to any user/lease

**Lifecycle:**
- Generated once per KMS installation (first run)
- Wrapped under LRK (always available)
- Delegated via certificate signed by UAK during first setup
- Rotated on clear triggers (90 days, code change, attestation change, or compromise)

**Signs:**
- KMS boot/initialization
- Attestation status changes
- Fail-secure transitions
- Instance reset events
- KIAK rotation events

**Delegation & Authorization:**

Unlike LAK (delegated per-lease), KIAK is delegated once per installation during initial setup:

1. User completes first setup (generates MS, UAK)
2. Generate KIAK (if not exists)
3. Create KIAK delegation cert signed by UAK:
   ```typescript
   {
     type: "audit-delegation",
     version: 1,
     signerKind: "KIAK",
     instanceId: "inst-...",
     delegatePub: pk_kiak,
     scope: ["system.*", "attestation.*", "boot", "fail-secure"],
     notBefore: now,
     notAfter: null,  // No expiration for instance key
     codeHash, manifestHash, kmsVersion,
     sig: sig_uak  // Signed by UAK
   }
   ```
4. Append delegation cert as audit entry (op: "audit:delegate")

This ensures KIAK authority traces back to user's MS ownership.

**Storage:**
```typescript
{
  kid: "audit-instance",
  kmsVersion: 2,
  instanceId: string,           // Unique per installation
  wrappedKey: ArrayBuffer,      // KIAK private key wrapped under LRK
  iv: ArrayBuffer,
  aad: ArrayBuffer,
  publicKeyRaw: ArrayBuffer,    // KIAK public key
  kiakKeyId: string,            // base64url(SHA-256(publicKeyRaw))
  delegationCert: AuditDelegationCert,  // UAK-signed delegation
  alg: "EdDSA",
  purpose: "audit-instance",
  createdAt: number,
  codeHash: string,             // Current KMS code hash
  manifestHash: string          // Current manifest hash
}
```

**Wrapping Pattern (LRK-based for portability):**

```typescript
// First run initialization
async function initKIAK(): Promise<void> {
  // 1. Ensure LRK exists
  let lrk = await storage.getMeta("LRK");
  if (!lrk) {
    lrk = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,  // non-extractable
      ["wrapKey", "unwrapKey"]
    );
    await storage.putMeta("LRK", lrk);
  }

  // 2. Generate KIAK (temporarily extractable for wrapping)
  const kiak = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,  // extractable: true (only for wrapping!)
    ["sign", "verify"]
  );

  // 3. Build AAD
  const instanceId = crypto.randomUUID();
  const aad = buildAAD({
    kmsVersion: 2,
    instanceId,
    purpose: "kiak",
    keyType: "audit-instance"
  });

  // 4. Wrap KIAK under LRK
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKiak = await crypto.subtle.wrapKey(
    "jwk",
    kiak.privateKey,
    lrk,
    { name: "AES-GCM", iv, additionalData: aad }
  );

  // 5. Export public key
  const publicKeyRaw = await crypto.subtle.exportKey("raw", kiak.publicKey);

  // 6. Store wrapped KIAK
  await storage.put("keys", {
    kid: "audit-instance",
    kmsVersion: 2,
    instanceId,
    wrappedKey: wrappedKiak,
    iv,
    aad,
    publicKeyRaw,
    kiakKeyId: await computeKeyId(publicKeyRaw),
    alg: "EdDSA",
    purpose: "audit-instance",
    createdAt: Date.now(),
    codeHash: await getCurrentCodeHash(),
    manifestHash: await getCurrentManifestHash()
  });

  // 7. Discard extractable handle immediately
  // (JS GC will clean up)
}

// Runtime unwrap (returns non-extractable handle)
async function unwrapKIAK(): Promise<CryptoKey> {
  const record = await storage.get("keys", "audit-instance");
  const lrk = await storage.getMeta("LRK");

  return await crypto.subtle.unwrapKey(
    "jwk",
    record.wrappedKey,
    lrk,
    { name: "AES-GCM", iv: record.iv, additionalData: record.aad },
    { name: "Ed25519" },
    false,  // non-extractable at runtime!
    ["sign"]
  );
}
```

**Rotation Policy:**

Rotate KIAK on any of these triggers:
- **Scheduled:** Every 90 days
- **Code change:** New KMS version deployed
- **Attestation change:** Manifest hash changes
- **Compromise:** Suspected key compromise or fail-secure recovery

**Rotation Process:**
```typescript
async function rotateKIAK(): Promise<void> {
  // 1. Get old KIAK
  const oldKiak = await unwrapKIAK();
  const oldRecord = await storage.get("keys", "audit-instance");

  // 2. Generate new KIAK (same pattern as initKIAK)
  const newKiak = await generateAndWrapKIAK();

  // 3. Create rotation entry with DUAL signatures
  const entry = {
    seq: await getNextSeq(),
    timestamp: Date.now(),
    op: "audit:rotate",
    kid: "audit-instance",
    requestId: crypto.randomUUID(),
    details: {
      oldKeyId: oldRecord.kiakKeyId,
      newKeyId: newKiak.kiakKeyId,
      reason: "scheduled" | "code-change" | "compromise",
      oldCodeHash: oldRecord.codeHash,
      newCodeHash: await getCurrentCodeHash()
    },
    previousHash: await getChainHead(),
    chainHash: "",
    signer: "KIAK",
    signerId: oldRecord.kiakKeyId  // Old key signs
  };

  entry.chainHash = await computeChainHash(entry);

  // 4. Sign with BOTH keys (proves continuity)
  const sigOld = await crypto.subtle.sign(
    "Ed25519",
    oldKiak,
    new TextEncoder().encode(entry.chainHash)
  );
  const sigNew = await crypto.subtle.sign(
    "Ed25519",
    newKiak.privateKey,
    new TextEncoder().encode(entry.chainHash)
  );

  entry.sig = base64url(new Uint8Array(sigOld));
  entry.sigNew = base64url(new Uint8Array(sigNew));

  await appendAuditEntry(entry);

  // 5. Create new delegation cert (requires user auth to get UAK!)
  // This step requires MS to be unlocked
  const newDelegationCert = await createKIAKDelegation(newKiak.publicKeyRaw);
  await appendAuditEntry({
    op: "audit:delegate",
    details: { signerKind: "KIAK", cert: newDelegationCert },
    signer: "UAK"
  });

  // 6. Update storage
  await storage.put("keys", "audit-instance", newKiak);
}
```

### 4. Lease Root Key (LRK)

**Purpose:** Wrapping key for LAK and KIAK private keys

**Why needed:** LAK and KIAK must be available for signing without user authentication. Wrapping them under MS would require authentication to unwrap. Solution: wrap under LRK, which is always available.

**Lifecycle:**
- Generated once on first run
- Stored as non-extractable CryptoKey in IndexedDB
- Never rotated (rotation would invalidate all LAK/KIAK)
- Backed up as part of KMS backup bundle

**Generation:**
```typescript
async function ensureLRK(): Promise<CryptoKey> {
  let lrk = await storage.getMeta("LRK");

  if (!lrk) {
    lrk = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,  // non-extractable
      ["wrapKey", "unwrapKey"]
    );

    await storage.putMeta("LRK", lrk);
  }

  return lrk;
}
```

**Security Note:** LRK compromise requires KMS code compromise (protected by SRI). Accepted residual risk for background operation capability.

**Distinction from SessionKEK:**

LRK and SessionKEK are DIFFERENT keys with different purposes:

| Aspect | LRK (Lease Root Key) | SessionKEK (Session Key Encryption Key) |
|--------|----------------------|----------------------------------------|
| **Purpose** | Wrap audit keys (LAK/KIAK) | Wrap VAPID key for background JWT signing |
| **Scope** | Global (single key for entire KMS) | Per-lease (unique key for each lease) |
| **Lifecycle** | Permanent (generated once on first run) | Temporary (expires with lease, 8-24 hours) |
| **Generation** | `generateKey()` (random AES-GCM key) | `HKDF(MS, leaseSalt, "SessionKEK/v1")` (derived) |
| **Storage** | `meta:LRK` (single entry) | `meta:sessionkek:{leaseId}` (one per lease) |
| **Use case** | Background audit logging | Background push notifications |
| **Documentation** | This file (05-audit-log.md) | [12-vapid-leases.md](./12-vapid-leases.md) |

**Why both needed:**
- **LRK** enables audit logging during background operations (no user auth available)
- **SessionKEK** enables VAPID JWT signing during background operations (no user auth available)
- Both solve the same problem (background operations) for different subsystems (audit vs VAPID)

---

## Chain Integrity

### Chain Structure

```
Entry 0 (genesis)
  ↓
  chainHash₀ = SHA256(canonical(entry₀))
  ↓
Entry 1
  previousHash₁ = chainHash₀
  chainHash₁ = SHA256(canonical(entry₁))
  ↓
Entry 2
  previousHash₂ = chainHash₁
  chainHash₂ = SHA256(canonical(entry₂))
  ↓
...
```

### Canonical Form

To ensure consistent hashing, entries are serialized in **canonical JSON** with sorted keys:

```typescript
/**
 * Build canonical form of audit entry for hashing.
 *
 * CANONICAL JSON:
 * - All keys sorted alphabetically
 * - No whitespace
 * - Deterministic serialization
 *
 * INCLUDED FIELDS:
 * - All fields except sig/sigNew (signatures cover chainHash)
 *
 * @param entry Audit entry (without sig/sigNew)
 * @returns Canonical JSON string
 */
function canonicalizeAuditEntry(entry: Omit<AuditEntryV2, 'sig' | 'sigNew'>): string {
  // Build object with sorted keys
  const canonical: Record<string, any> = {
    cert: entry.cert || null,
    chainHash: entry.chainHash,
    details: entry.details || null,
    duration: entry.duration,
    jti: entry.jti,
    kid: entry.kid,
    kmsVersion: entry.kmsVersion,
    leaseId: entry.leaseId,
    lockTime: entry.lockTime,
    op: entry.op,
    origin: entry.origin || null,
    previousHash: entry.previousHash,
    requestId: entry.requestId,
    seqNum: entry.seqNum,
    signer: entry.signer,
    signerId: entry.signerId,
    timestamp: entry.timestamp,
    unlockTime: entry.unlockTime
  };

  // Remove undefined/null fields
  Object.keys(canonical).forEach(key => {
    if (canonical[key] === undefined) {
      delete canonical[key];
    }
  });

  // Stringify with sorted keys
  return JSON.stringify(canonical, Object.keys(canonical).sort());
}
```

### Chain Hash Computation

```typescript
/**
 * Compute chain hash for audit entry.
 *
 * ALGORITHM:
 * 1. Canonicalize entry (sorted JSON)
 * 2. SHA-256 hash
 * 3. Base64url encode
 *
 * @param entry Audit entry (partial, before chainHash computed)
 * @returns Base64url-encoded SHA-256 hash
 */
async function computeChainHash(
  entry: Omit<AuditEntryV2, 'chainHash' | 'sig' | 'sigNew'>
): Promise<string> {
  // Canonical JSON
  const canonical = canonicalizeAuditEntry({
    ...entry,
    chainHash: ''  // Placeholder (will be replaced)
  });

  // SHA-256 hash
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );

  // Base64url encode
  return base64url.encode(new Uint8Array(hash));
}
```

### Previous Hash Lookup

```typescript
/**
 * Get previousHash for new audit entry.
 *
 * CASES:
 * - Genesis entry (seqNum=0): previousHash = "0" (64-char hex string)
 * - Subsequent entries: previousHash = chainHash of seqNum-1
 *
 * @param seqNum Sequence number of new entry
 * @returns previousHash value
 */
async function getPreviousHash(seqNum: number): Promise<string> {
  if (seqNum === 0) {
    return '0'.repeat(64);  // Genesis entry
  }

  // Load previous entry
  const prevEntry = await audit.getBySeqNum(seqNum - 1);
  if (!prevEntry) {
    throw new Error(`Missing previous audit entry: seqNum=${seqNum - 1}`);
  }

  return prevEntry.chainHash;
}
```

---

## Sequence Numbers

### V2 IMPROVEMENT: Truncation Detection

**V1 Problem**: Attacker could truncate audit log (delete recent entries) without detection.
**V2 Solution**: Monotonic sequence numbers. Missing seqNum indicates truncation.

### Sequence Tracking

```typescript
/**
 * Audit log state (stored separately from entries).
 */
interface AuditState {
  nextSeqNum: number;          // Next sequence number to assign
  totalEntries: number;        // Total entries written (sanity check)
  lastTimestamp: number;       // Last entry timestamp (ordering check)
  lastChainHash: string;       // Last entry chainHash (quick access)
  lastAnchor: number;          // Sequence number of last anchor
}

/**
 * Get next sequence number and increment.
 */
async function getNextSeqNum(): Promise<number> {
  const state = await storage.get('audit:state') || {
    nextSeqNum: 0,
    totalEntries: 0,
    lastTimestamp: 0,
    lastChainHash: '0'.repeat(64),
    lastAnchor: 0
  };

  const seqNum = state.nextSeqNum;

  // Increment for next entry
  await storage.put('audit:state', {
    ...state,
    nextSeqNum: seqNum + 1
  });

  return seqNum;
}
```

### Verification Check

```typescript
/**
 * Verify audit log sequence is complete (no gaps).
 *
 * CHECKS:
 * 1. Sequence numbers are consecutive (0, 1, 2, ...)
 * 2. Total count matches nextSeqNum
 * 3. No duplicate sequence numbers
 *
 * @returns { valid, gaps, duplicates }
 */
async function verifySequence(): Promise<{
  valid: boolean;
  gaps: number[];
  duplicates: number[];
}> {
  const entries = await audit.getAll();
  const state = await storage.get('audit:state');

  // Extract sequence numbers
  const seqNums = entries.map(e => e.seqNum).sort((a, b) => a - b);

  // Check for gaps
  const gaps: number[] = [];
  for (let i = 0; i < state.nextSeqNum; i++) {
    if (!seqNums.includes(i)) {
      gaps.push(i);
    }
  }

  // Check for duplicates
  const seen = new Set<number>();
  const duplicates: number[] = [];
  for (const seqNum of seqNums) {
    if (seen.has(seqNum)) {
      duplicates.push(seqNum);
    }
    seen.add(seqNum);
  }

  return {
    valid: gaps.length === 0 && duplicates.length === 0,
    gaps,
    duplicates
  };
}
```

---

## Ed25519 Signatures

### Signing Flow

```
withUnlock → Unwrap Audit Key → Sign chainHash → Attach Signature
```

For LAK/KIAK, no withUnlock needed (wrapped under LRK, always available).

### Implementation

```typescript
/**
 * Sign audit entry with appropriate audit key.
 *
 * WHAT IS SIGNED: The chainHash (32-byte SHA-256)
 * WHY: chainHash already commits to all entry fields
 *
 * @param entry Audit entry (with chainHash computed)
 * @param signer Which audit key to use
 * @param mkek Master Key Encryption Key (from unlock context, if UAK)
 * @returns Ed25519 signature (64 bytes, base64url-encoded)
 */
async function signAuditEntry(
  entry: Omit<AuditEntryV2, 'sig'>,
  signer: 'UAK' | 'LAK' | 'KIAK',
  mkek?: CryptoKey  // Required for UAK, not for LAK/KIAK
): Promise<string> {
  let auditKey: CryptoKey;

  switch (signer) {
    case 'UAK':
      if (!mkek) throw new Error('MKEK required for UAK signing');
      // Load UAK and unwrap with MKEK
      const uakConfig = await storage.get('keys', 'audit-user');
      auditKey = await crypto.subtle.unwrapKey(
        'jwk',
        uakConfig.wrappedKey,
        mkek,
        { name: 'AES-GCM', iv: uakConfig.iv, additionalData: uakConfig.aad },
        { name: 'Ed25519' },
        false,
        ['sign']
      );
      break;

    case 'LAK':
      // Load LAK and unwrap with LRK
      const lakRecord = await storage.get('lease-audit-keys', entry.leaseId!);
      const lrk = await storage.getMeta('LRK');
      auditKey = await crypto.subtle.unwrapKey(
        'jwk',
        lakRecord.wrappedKey,
        lrk,
        { name: 'AES-GCM', iv: lakRecord.iv, additionalData: lakRecord.aad },
        { name: 'Ed25519' },
        false,
        ['sign']
      );
      break;

    case 'KIAK':
      // Unwrap KIAK with LRK
      auditKey = await unwrapKIAK();
      break;
  }

  // Sign chainHash
  const signature = await crypto.subtle.sign(
    'Ed25519',
    auditKey,
    new TextEncoder().encode(entry.chainHash)
  );

  // Base64url encode signature
  return base64url.encode(new Uint8Array(signature));
}
```

### Verification

```typescript
/**
 * Verify audit entry signature.
 *
 * @param entry Complete audit entry (including sig)
 * @param publicKey Audit public key (raw Ed25519, 32 bytes)
 * @returns true if signature valid
 */
async function verifyAuditSignature(
  entry: AuditEntryV2,
  publicKey: ArrayBuffer
): Promise<boolean> {
  // Import public key
  const pubKey = await crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  // Verify signature
  const valid = await crypto.subtle.verify(
    'Ed25519',
    pubKey,
    base64url.decode(entry.sig),
    new TextEncoder().encode(entry.chainHash)
  );

  return valid;
}
```

---

## Periodic Anchors

### Purpose

**Anchors** are special audit entries that serve as checkpoints:
- Summarize recent activity
- Reference external verification (e.g., timestamp from transparency log)
- Detect rollback attacks (attacker replaces recent entries)

### Anchor Frequency

```typescript
const ANCHOR_FREQUENCY = 100;  // Every 100 operations

/**
 * Check if anchor should be inserted.
 */
function shouldInsertAnchor(seqNum: number): boolean {
  return seqNum > 0 && seqNum % ANCHOR_FREQUENCY === 0;
}
```

### Anchor Entry

```typescript
interface AnchorEntry extends AuditEntryV2 {
  op: 'anchor';
  signer: 'KIAK';  // Anchors signed by KIAK
  details: {
    anchorType: 'periodic';
    sinceSeqNum: number;        // Start of range (last anchor)
    untilSeqNum: number;        // End of range (this anchor)
    operationCount: number;     // Number of ops since last anchor
    keyOperations: {            // Summary by key
      [kid: string]: number;    // Count per key
    };
    externalTimestamp?: string; // RFC 3161 timestamp (future)
    rekorEntry?: string;        // Rekor transparency log entry (future)
  };
}

/**
 * Create periodic anchor entry.
 */
async function createAnchor(
  seqNum: number,
  previousHash: string
): Promise<AnchorEntry> {
  const state = await storage.get('audit:state');

  // Compute summary statistics
  const recentEntries = await audit.getRange(state.lastAnchor + 1, seqNum - 1);
  const keyOperations: Record<string, number> = {};

  for (const entry of recentEntries) {
    if (entry.kid) {
      keyOperations[entry.kid] = (keyOperations[entry.kid] || 0) + 1;
    }
  }

  const kiakRecord = await storage.get('keys', 'audit-instance');

  const anchor: Omit<AnchorEntry, 'chainHash' | 'sig'> = {
    kmsVersion: 2,
    seqNum,
    timestamp: Date.now(),
    op: 'anchor',
    kid: '',
    requestId: crypto.randomUUID(),
    unlockTime: 0,
    lockTime: 0,
    duration: 0,
    details: {
      anchorType: 'periodic',
      sinceSeqNum: state.lastAnchor,
      untilSeqNum: seqNum,
      operationCount: recentEntries.length,
      keyOperations
    },
    previousHash,
    signer: 'KIAK',
    signerId: kiakRecord.kiakKeyId
  };

  // Compute chainHash
  const chainHash = await computeChainHash(anchor);

  // Sign with KIAK
  const sig = await signAuditEntry({ ...anchor, chainHash }, 'KIAK');

  return { ...anchor, chainHash, sig };
}
```

---

## Audit Key Management

### UAK Generation

```typescript
/**
 * Generate User Audit Key during setup.
 *
 * SECURITY:
 * - Wrapped under MS for authorization
 * - Non-extractable at runtime
 * - Public key stored for verification
 *
 * @param mkek Master Key Encryption Key (derived from MS)
 * @returns UAK key ID
 */
export async function generateUAK(mkek: CryptoKey): Promise<string> {
  // Generate keypair
  const uak = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,  // temporarily extractable for wrapping
    ['sign', 'verify']
  );

  // Export public key
  const publicKeyRaw = await crypto.subtle.exportKey('raw', uak.publicKey);

  // Build AAD
  const aad = buildAAD({
    kmsVersion: 2,
    kid: 'audit-user',
    alg: 'EdDSA',
    purpose: 'audit',
    createdAt: Date.now(),
    keyType: 'audit-user'
  });

  // Wrap private key
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = await crypto.subtle.wrapKey(
    'jwk',
    uak.privateKey,
    mkek,
    { name: 'AES-GCM', iv, additionalData: aad }
  );

  // Store
  await storage.put('keys', {
    kid: 'audit-user',
    kmsVersion: 2,
    wrappedKey,
    iv,
    aad,
    publicKeyRaw,
    alg: 'EdDSA',
    purpose: 'audit',
    createdAt: Date.now()
  });

  return 'audit-user';
}
```

### LAK Generation (During Lease Creation)

```typescript
/**
 * Generate Lease Audit Key during lease creation.
 *
 * SECURITY:
 * - Delegated via UAK-signed certificate
 * - Wrapped under LRK (available without auth)
 * - Expires with lease
 *
 * @param leaseId Lease identifier
 * @param ttlHours Lease TTL in hours
 * @param uak UAK private key (unwrapped during user auth)
 * @returns LAK record
 */
export async function generateLAK(
  leaseId: string,
  ttlHours: number,
  uak: CryptoKey
): Promise<LeaseAuditKeyRecord> {
  const now = Date.now();
  const expiresAt = now + (ttlHours * 3600 * 1000);

  // 1. Generate LAK keypair
  const lak = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,  // temporarily extractable for wrapping
    ['sign', 'verify']
  );

  // 2. Export public key
  const publicKeyRaw = await crypto.subtle.exportKey('raw', lak.publicKey);

  // 3. Create delegation certificate
  const delegationCert: AuditDelegationCert = {
    type: 'audit-delegation',
    version: 1,
    signerKind: 'LAK',
    leaseId,
    delegatePub: base64url.encode(new Uint8Array(publicKeyRaw)),
    scope: ['vapid:issue', 'lease:expire'],
    notBefore: now,
    notAfter: expiresAt,
    codeHash: await getCurrentCodeHash(),
    manifestHash: await getCurrentManifestHash(),
    kmsVersion: 'v2.0.0',
    sig: ''  // Will be filled below
  };

  // 4. Sign delegation cert with UAK
  const certCanonical = canonicalizeJSON({
    ...delegationCert,
    sig: undefined
  });
  const certSig = await crypto.subtle.sign(
    'Ed25519',
    uak,
    new TextEncoder().encode(certCanonical)
  );
  delegationCert.sig = base64url.encode(new Uint8Array(certSig));

  // 5. Wrap LAK under LRK
  const lrk = await storage.getMeta('LRK');
  const aad = buildAAD({
    kmsVersion: 2,
    leaseId,
    purpose: 'lak',
    keyType: 'lease-audit-key'
  });
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = await crypto.subtle.wrapKey(
    'jwk',
    lak.privateKey,
    lrk,
    { name: 'AES-GCM', iv, additionalData: aad }
  );

  // 6. Create record
  const record: LeaseAuditKeyRecord = {
    leaseId,
    wrappedKey,
    iv,
    aad,
    publicKeyRaw,
    delegationCert,
    expiresAt,
    createdAt: now
  };

  // 7. Store
  await storage.put('lease-audit-keys', record);

  return record;
}
```

### KIAK Initialization

See [Audit Key Delegation Architecture](#audit-key-delegation-architecture) section above for complete KIAK initialization and rotation code.

### Delegation Certificate Creation

```typescript
/**
 * Create and sign delegation certificate.
 *
 * @param signerKind Type of delegated signer
 * @param delegatePub Public key of delegated signer
 * @param scope Authorized operations
 * @param notBefore Validity start
 * @param notAfter Validity end (null for no expiration)
 * @param uak UAK private key for signing
 * @param leaseId Lease ID (for LAK only)
 * @param instanceId Instance ID (for KIAK only)
 * @returns Signed delegation certificate
 */
async function createDelegationCert(
  signerKind: 'LAK' | 'KIAK',
  delegatePub: ArrayBuffer,
  scope: string[],
  notBefore: number,
  notAfter: number | null,
  uak: CryptoKey,
  leaseId?: string,
  instanceId?: string
): Promise<AuditDelegationCert> {
  const cert: Omit<AuditDelegationCert, 'sig'> = {
    type: 'audit-delegation',
    version: 1,
    signerKind,
    leaseId,
    instanceId,
    delegatePub: base64url.encode(new Uint8Array(delegatePub)),
    scope,
    notBefore,
    notAfter,
    codeHash: await getCurrentCodeHash(),
    manifestHash: await getCurrentManifestHash(),
    kmsVersion: 'v2.0.0'
  };

  // Canonicalize and sign
  const canonical = canonicalizeJSON(cert);
  const sigBytes = await crypto.subtle.sign(
    'Ed25519',
    uak,
    new TextEncoder().encode(canonical)
  );

  return {
    ...cert,
    sig: base64url.encode(new Uint8Array(sigBytes))
  };
}
```

---

## Verification

### Key Rotation and Chain Verification

**Critical insight: You never need old private keys for verification.**

The audit log is self-sufficient:

1. **Delegation entries introduce keys**: Contain full public key + UAK signature
2. **Regular entries reference keys by ID**: Use `signerId` to look up delegation
3. **Key rotation adds new delegation**: New public key embedded in log
4. **Old private keys deleted safely**: Only public keys needed for verification
5. **Bundle-local verification**: No external registry needed

### Verification Algorithm

```typescript
/**
 * Verify complete audit chain with delegation support.
 *
 * @param entries All audit entries (sorted by seqNum)
 * @param uakPublicKey UAK public key
 * @param kiakPublicKey KIAK public key (current)
 * @returns Verification result
 */
export async function verifyAuditChain(
  entries: AuditEntryV2[],
  uakPublicKey: ArrayBuffer,
  kiakPublicKey: ArrayBuffer
): Promise<VerificationResult> {
  let previousHash = '0'.repeat(64); // Genesis
  const errors: string[] = [];
  const lakKeys = new Map<string, CryptoKey>(); // Cache verified LAK keys

  // Import UAK and KIAK public keys
  const uakPubKey = await crypto.subtle.importKey(
    'raw',
    uakPublicKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  const kiakPubKey = await crypto.subtle.importKey(
    'raw',
    kiakPublicKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // 1. Check sequence continuity
    if (entry.seqNum !== i) {
      errors.push(`Sequence gap at ${i}: expected ${i}, got ${entry.seqNum}`);
      break;
    }

    // 2. Check chain continuity
    if (entry.previousHash !== previousHash) {
      errors.push(`Chain break at ${i}: previousHash mismatch`);
      break;
    }

    // 3. Recompute chainHash
    const computedChainHash = await computeChainHash(entry);
    if (computedChainHash !== entry.chainHash) {
      errors.push(`Chain hash mismatch at ${i}`);
      break;
    }

    // 4. Verify signature based on signer type
    let signatureValid = false;

    switch (entry.signer) {
      case 'UAK':
        signatureValid = await verifyAuditSignature(entry, uakPublicKey);
        if (!signatureValid) {
          errors.push(`UAK signature invalid at ${i}`);
        }
        break;

      case 'LAK':
        // Must have delegation cert
        if (!entry.cert) {
          errors.push(`LAK entry missing cert at ${i}`);
          break;
        }

        // Verify delegation cert signed by UAK
        const certValid = await verifyDelegationCert(entry.cert, uakPubKey);
        if (!certValid) {
          errors.push(`LAK delegation cert invalid at ${i}`);
          break;
        }

        // Check cert scope covers operation
        if (!entry.cert.scope.includes(entry.op) &&
            !entry.cert.scope.some(s => s.endsWith('*'))) {
          errors.push(`Operation ${entry.op} not in LAK scope at ${i}`);
          break;
        }

        // Check cert validity period
        if (entry.timestamp < entry.cert.notBefore ||
            (entry.cert.notAfter && entry.timestamp > entry.cert.notAfter)) {
          errors.push(`LAK cert expired at ${i}`);
          break;
        }

        // Import and cache LAK public key
        if (!lakKeys.has(entry.signerId)) {
          const lakPubBytes = base64url.decode(entry.cert.delegatePub);
          const lakPubKey = await crypto.subtle.importKey(
            'raw',
            lakPubBytes,
            { name: 'Ed25519' },
            false,
            ['verify']
          );
          lakKeys.set(entry.signerId, lakPubKey);
        }

        // Verify entry signature with LAK
        const lakPubKey = lakKeys.get(entry.signerId)!;
        const lakPubBytes = await crypto.subtle.exportKey('raw', lakPubKey);
        signatureValid = await verifyAuditSignature(entry, lakPubBytes);
        if (!signatureValid) {
          errors.push(`LAK signature invalid at ${i}`);
        }
        break;

      case 'KIAK':
        signatureValid = await verifyAuditSignature(entry, kiakPublicKey);
        if (!signatureValid) {
          errors.push(`KIAK signature invalid at ${i}`);
        }
        break;

      default:
        errors.push(`Unknown signer type at ${i}: ${entry.signer}`);
    }

    // 5. Update previousHash for next iteration
    previousHash = entry.chainHash;
  }

  return {
    valid: errors.length === 0,
    verified: entries.length,
    errors
  };
}

/**
 * Verify delegation certificate signature.
 *
 * @param cert Delegation certificate
 * @param uakPublicKey UAK public key (CryptoKey)
 * @returns true if signature valid
 */
async function verifyDelegationCert(
  cert: AuditDelegationCert,
  uakPublicKey: CryptoKey
): Promise<boolean> {
  // Reconstruct canonical cert for verification
  const { sig, ...unsigned } = cert;
  const canonical = canonicalizeJSON(unsigned);
  const sigBytes = base64url.decode(sig);

  return await crypto.subtle.verify(
    'Ed25519',
    uakPublicKey,
    sigBytes,
    new TextEncoder().encode(canonical)
  );
}
```

---

## Implementation

### Logging Function

```typescript
/**
 * Log operation to audit trail.
 *
 * FLOW:
 * 1. Determine signer type (UAK if unlocked, LAK if lease, KIAK if system)
 * 2. Get next sequence number
 * 3. Get previousHash
 * 4. Build entry (without chainHash/sig)
 * 5. Compute chainHash
 * 6. Sign chainHash with appropriate key
 * 7. Store entry
 * 8. Check if anchor needed
 *
 * @param data Operation data
 * @param mkek Master Key Encryption Key (from unlock context, if UAK)
 * @param leaseId Lease ID (if LAK)
 */
export async function logAudit(
  data: {
    op: string;
    kid?: string;
    requestId: string;
    leaseId?: string;
    unlockTime?: number;
    lockTime?: number;
    duration?: number;
    details?: Record<string, unknown>;
    jti?: string;
  },
  options?: {
    mkek?: CryptoKey;  // For UAK
    leaseId?: string;  // For LAK
  }
): Promise<void> {
  // Determine signer type
  let signer: 'UAK' | 'LAK' | 'KIAK';
  let signerId: string;
  let cert: AuditDelegationCert | undefined;

  if (options?.mkek) {
    // User-authenticated operation → UAK
    signer = 'UAK';
    const uakRecord = await storage.get('keys', 'audit-user');
    signerId = await computeKeyId(uakRecord.publicKeyRaw);
  } else if (options?.leaseId) {
    // Lease-scoped operation → LAK
    signer = 'LAK';
    const lakRecord = await storage.get('lease-audit-keys', options.leaseId);
    signerId = await computeKeyId(lakRecord.publicKeyRaw);
    cert = lakRecord.delegationCert;
  } else {
    // System operation → KIAK
    signer = 'KIAK';
    const kiakRecord = await storage.get('keys', 'audit-instance');
    signerId = kiakRecord.kiakKeyId;
  }

  // Get sequence number
  const seqNum = await getNextSeqNum();

  // Get previousHash
  const previousHash = await getPreviousHash(seqNum);

  // Build entry (partial)
  const partial: Omit<AuditEntryV2, 'chainHash' | 'sig'> = {
    kmsVersion: 2,
    seqNum,
    timestamp: Date.now(),
    op: data.op,
    kid: data.kid || '',
    requestId: data.requestId,
    origin: self.location?.origin,
    leaseId: data.leaseId,
    unlockTime: data.unlockTime || 0,
    lockTime: data.lockTime || 0,
    duration: data.duration || 0,
    details: data.details,
    jti: data.jti,
    previousHash,
    signer,
    signerId,
    cert
  };

  // Compute chainHash
  const chainHash = await computeChainHash(partial);

  // Sign
  const sig = await signAuditEntry({ ...partial, chainHash }, signer, options?.mkek);

  // Complete entry
  const entry: AuditEntryV2 = {
    ...partial,
    chainHash,
    sig
  };

  // Store
  await storage.put(`audit:${seqNum}`, entry);

  // Update state
  const state = await storage.get('audit:state');
  await storage.put('audit:state', {
    ...state,
    totalEntries: state.totalEntries + 1,
    lastTimestamp: entry.timestamp,
    lastChainHash: chainHash
  });

  // Check if anchor needed
  if (shouldInsertAnchor(seqNum)) {
    await insertAnchor();
  }
}
```

---

## Security Analysis

### Threat Model

**Protected Against**:
- ✅ **Entry modification**: Signature verification fails
- ✅ **Entry deletion**: Chain break (previousHash mismatch)
- ✅ **Log truncation**: Sequence number gaps detected
- ✅ **Replay attacks**: Unique requestId + timestamp
- ✅ **Forgery (without key)**: Ed25519 signature required
- ✅ **Unauthorized background operations**: LAK scope enforcement
- ✅ **Rogue lease operations**: Delegation cert proves user authorization

**NOT Protected Against**:
- ❌ **Forgery (with UAK)**: If attacker gets UAK, can forge entries and delegations
- ❌ **LRK compromise**: Attacker can unwrap LAK/KIAK and forge background entries
- ❌ **Complete deletion**: If entire log deleted, no evidence remains
- ❌ **Rollback (with anchor)**: Attacker could regenerate chain from checkpoint

### Mitigation for Key Compromise

1. **Non-Extractable**: All audit keys non-extractable at runtime
2. **MS Protection**: UAK wrapped under MS (requires user auth to access)
3. **LRK Isolation**: LRK compromise requires KMS code compromise (SRI detects)
4. **Periodic Rotation**: KIAK rotates every 90 days or on code change
5. **External Anchors**: Timestamp anchors to external transparency logs (future)

### Delegation Security

**Authorization Chain**:
```
User owns MS → Unwraps UAK → Signs delegation cert → Authorizes LAK/KIAK
```

**Scope Enforcement**:
- LAK limited to lease operations (`vapid:issue`, `lease:expire`)
- KIAK limited to system operations (`boot`, `fail-secure`, etc.)
- Verifiers check `cert.scope` includes `entry.op`

**Validity Windows**:
- LAK: `notAfter` = lease expiration (enforced)
- KIAK: `notAfter` = null (open-ended, rotated periodically)
- Verifiers check `cert.notBefore <= entry.timestamp <= cert.notAfter`

### Residual Risk: LRK Compromise

**Accepted risk**: LRK compromise enables forging background operation entries.

**Justification**:
- LRK compromise requires KMS code compromise (protected by SRI)
- Background operations already trust KMS code
- Alternative (no background logging) worse for auditability
- Detection via periodic UAK-signed anchors

---

## References

- **Ed25519**: RFC 8032
- **Tamper-Evident Logging**: Schneier, "Applied Cryptography"
- **Audit Trails**: NIST SP 800-92
- **Transparency Logs**: Rekor, Certificate Transparency
- **Delegation Architecture**: [V2 README](../README.md), [SessionKEK](./12-vapid-leases.md)

---

**Next**: [06-multi-enrollment.md](./06-multi-enrollment.md) - Multiple credentials wrapping same MS
