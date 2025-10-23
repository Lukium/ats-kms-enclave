# Audit Logging and Unlock Mechanisms

**Phase:** 1 (Production Enclave)
**Status:** Design complete, implementation pending

## Overview

The KMS enclave implements a **local-only, tamper-evident audit log** that records all cryptographic operations (unwraps, signs, resets) and enforces an **explicit unlock mechanism** (passkey or passphrase) before any private key can be used.

This design makes **covert key extraction much harder** by requiring the attacker to either:
1. Subvert the KMS code itself (detectable via SRI/reproducible builds)
2. Compromise the host OS/browser AND force the KMS to unlock keys (which creates signed audit entries)
3. Delete the audit log (which is detectable via chain discontinuity)

## Goals

1. **Detect and log all key access**: Any unwrap/sign operation creates a signed, tamper-evident audit entry
2. **Require explicit unlock**: Keys cannot be used without user authentication (passkey or passphrase)
3. **Tamper-evident local storage**: Hash-chained, signed entries that detect deletion/modification
4. **User-visible evidence**: PWA displays audit log with verification status
5. **No server dependency**: Works entirely locally for everyday users

## Non-Goals

1. **Prevent extraction by fully compromised OS**: Cannot defend against kernel-level compromise
2. **Remote backup/sync**: Not included in Phase 1 (local-only)
3. **Advanced forensics**: Keep it simple and auditable (~500 lines for audit system)

## Threat Model

### What This Defends Against

✅ **Malicious scripts in parent PWA**
- Cross-origin isolation prevents direct key access
- Must go through postMessage RPC (auditable)

✅ **Covert key extraction attempts**
- All unwraps are logged and signed
- Cannot extract keys without creating audit trail

✅ **Silent key usage**
- Requires explicit unlock (user presence)
- Every sign operation creates audit entry

✅ **Audit log tampering**
- Signatures verify with non-extractable audit key
- Hash chain detects deletions
- Chain head comparison detects resets

### What This Does NOT Defend Against

❌ **Fully compromised OS/browser**
- Can force unlock and suppress UI
- Can delete entire IndexedDB
- **Mitigation:** Chain head comparison detects resets

❌ **User approving malicious unlock**
- User biometric/passphrase still required
- **Mitigation:** Rate limits and suspicious pattern alerts

❌ **Offline attacks on passphrase**
- If attacker extracts wrapped keys and passphrase hash, can brute-force
- **Mitigation:** Use strong PBKDF2 parameters or passkey (hardware-backed)

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         KMS Enclave                             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    KMS Worker                             │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │          Unlock Manager                          │    │  │
│  │  │                                                  │    │  │
│  │  │  State:                                          │    │  │
│  │  │  - isUnlocked: boolean                          │    │  │
│  │  │  - unlockExpiry: timestamp                      │    │  │
│  │  │  - unwrapKey: CryptoKey (ephemeral)             │    │  │
│  │  │                                                  │    │  │
│  │  │  Methods:                                        │    │  │
│  │  │  - unlock(method, credential)                   │    │  │
│  │  │  - lock()                                        │    │  │
│  │  │  - isUnlocked(): boolean                        │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                        ↓                                  │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │          Key Storage                             │    │  │
│  │  │                                                  │    │  │
│  │  │  IndexedDB 'keys' store:                        │    │  │
│  │  │  - kid → WrappedKey                             │    │  │
│  │  │  - wrappedKey: ArrayBuffer                      │    │  │
│  │  │  - wrapParams: { alg, salt, iv }                │    │  │
│  │  │                                                  │    │  │
│  │  │  Methods:                                        │    │  │
│  │  │  - wrap(key, unwrapKey)                         │    │  │
│  │  │  - unwrap(kid, unwrapKey) → logs to audit       │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                        ↓                                  │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │          Audit Logger                            │    │  │
│  │  │                                                  │    │  │
│  │  │  IndexedDB 'audit' store:                       │    │  │
│  │  │  - AuditEntry[] (append-only)                   │    │  │
│  │  │                                                  │    │  │
│  │  │  Meta store:                                     │    │  │
│  │  │  - auditSigningKey (non-extractable)            │    │  │
│  │  │  - chainHead: string                            │    │  │
│  │  │                                                  │    │  │
│  │  │  Methods:                                        │    │  │
│  │  │  - append(op, kid, details)                     │    │  │
│  │  │  - verify() → { ok, head, total }               │    │  │
│  │  │  - tail(n) → AuditEntry[]                       │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓ postMessage RPC
┌─────────────────────────────────────────────────────────────────┐
│                         Main PWA                                │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │             Security Dashboard                            │  │
│  │                                                           │  │
│  │  Sections:                                                │  │
│  │  - Chain Status: ✅ Verified / ❌ Broken                  │  │
│  │  - Chain Head: c7a1...9d [Copy]                          │  │
│  │  - Recent Events:                                         │  │
│  │    • 🔓 Unlocked key vapid-abc (passkey)                 │  │
│  │    • ✍️ Signed JWT for fcm.googleapis.com               │  │
│  │    • ♻️ Reset key vapid-abc                             │  │
│  │                                                           │  │
│  │  Actions:                                                 │  │
│  │  - [Export Audit Log JSON]                               │  │
│  │  - [Copy Chain Head]                                     │  │
│  │  - [Clear Old Entries]                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Unlock Mechanisms

### First-Time Setup Flow

**When user first initializes KMS:**

```
1. User visits PWA for first time
2. PWA loads KMS iframe
3. KMS detects no unlock mechanism configured
4. KMS sends event: { type: 'needsSetup' }
5. PWA shows setup modal:
   ┌─────────────────────────────────────────┐
   │ Secure Your Keys                        │
   │                                         │
   │ Choose how to protect your keys:        │
   │                                         │
   │ [🔑 Use Passkey (Recommended)]         │
   │ Hardware-backed, no password to         │
   │ remember                                │
   │                                         │
   │ [🔒 Use Passphrase]                    │
   │ Works everywhere, but you must          │
   │ remember your passphrase                │
   │                                         │
   │ [Learn More]                            │
   └─────────────────────────────────────────┘

6. User chooses method:

   A. Passkey:
      - PWA triggers WebAuthn registration
      - On success, generates unwrapKey
      - Sends unwrapKey to KMS
      - KMS wraps all future keys with unwrapKey
      - KMS logs: "Setup complete (passkey)"

   B. Passphrase:
      - PWA prompts for passphrase (min 12 chars)
      - PWA derives unwrapKey: PBKDF2(passphrase, salt, 600000)
      - Sends unwrapKey to KMS
      - KMS wraps all future keys with unwrapKey
      - KMS logs: "Setup complete (passphrase)"

7. KMS creates first audit entry (genesis)
```

### Unlock Flow (Passkey)

```
1. User action requires key usage (e.g., generate VAPID keypair)
2. KMS checks: isUnlocked()
3. If locked:
   a. KMS sends: { type: 'needsUnlock', method: 'passkey' }
   b. PWA shows: "Unlock KMS" modal with fingerprint icon
   c. PWA triggers WebAuthn assertion
   d. On success, PWA sends unwrapKey to KMS
   e. KMS verifies and caches unwrapKey (5 min TTL)
   f. KMS logs: "Unlocked (passkey)"
4. KMS performs requested operation
5. KMS logs: "Sign JWT (kid=..., aud=...)"
6. KMS returns result
```

### Unlock Flow (Passphrase)

```
1. User action requires key usage
2. KMS checks: isUnlocked()
3. If locked:
   a. KMS sends: { type: 'needsUnlock', method: 'passphrase' }
   b. PWA shows: "Enter passphrase" modal
   c. User enters passphrase
   d. PWA derives unwrapKey: PBKDF2(passphrase, salt, 600000)
   e. PWA sends unwrapKey to KMS
   f. KMS verifies by attempting unwrap
   g. If successful, caches unwrapKey (5 min TTL)
   h. KMS logs: "Unlocked (passphrase)"
4. KMS performs requested operation
5. KMS logs: "Sign JWT (kid=..., aud=...)"
6. KMS returns result
```

### Unlock State Management

**In-memory state (worker):**
```typescript
interface UnlockState {
  isUnlocked: boolean;
  method: 'passkey' | 'passphrase' | null;
  unwrapKey: CryptoKey | null;  // ephemeral, never stored
  unlockExpiry: number;           // timestamp
  unlockCount: number;            // for rate limiting
}
```

**Unlock TTL:** 5 minutes (configurable)

**Auto-lock triggers:**
- Expiry timestamp reached
- User navigates away from PWA (visibilitychange)
- User explicit lock action
- Suspicious pattern detected (too many unwraps)

## Audit Log Design

### Audit Entry Structure

```typescript
interface AuditEntry {
  version: 1;
  timestamp: string;              // ISO 8601
  op: 'setup' | 'unlock' | 'unwrap' | 'sign' | 'reset' | 'export_attempt';
  kid: string;                    // key ID
  requestId: string;              // correlates to RPC call
  origin: 'https://ats.run';     // parent origin (verified)
  clientInfo: {
    ua: string;                   // user agent (truncated)
    url: string;                  // page URL
  };
  prevHash: string;               // sha256-... of previous entry
  nonce: string;                  // 24 random hex chars
  details?: Record<string, any>; // operation-specific data
  sig: string;                    // base64url ES256 signature
}
```

**Example entries:**

```json
{
  "version": 1,
  "timestamp": "2025-10-23T15:30:00.000Z",
  "op": "setup",
  "kid": "audit-genesis",
  "requestId": "setup-001",
  "origin": "https://ats.run",
  "clientInfo": {
    "ua": "Chrome/120.0.0.0",
    "url": "/app/settings"
  },
  "prevHash": "sha256-0000000000000000000000000000000000000000000000000000000000000000",
  "nonce": "a1b2c3d4e5f6g7h8i9j0k1l2",
  "details": {
    "method": "passkey"
  },
  "sig": "base64url..."
}

{
  "version": 1,
  "timestamp": "2025-10-23T15:31:00.000Z",
  "op": "unlock",
  "kid": "vapid-abc123",
  "requestId": "req-001",
  "origin": "https://ats.run",
  "clientInfo": {
    "ua": "Chrome/120.0.0.0",
    "url": "/app/notifications"
  },
  "prevHash": "sha256-7f8a9b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
  "nonce": "m1n2o3p4q5r6s7t8u9v0w1x2",
  "details": {
    "method": "passkey"
  },
  "sig": "base64url..."
}

{
  "version": 1,
  "timestamp": "2025-10-23T15:31:05.000Z",
  "op": "sign",
  "kid": "vapid-abc123",
  "requestId": "req-002",
  "origin": "https://ats.run",
  "clientInfo": {
    "ua": "Chrome/120.0.0.0",
    "url": "/app/notifications"
  },
  "prevHash": "sha256-c7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
  "nonce": "y1z2a3b4c5d6e7f8g9h0i1j2",
  "details": {
    "payloadHash": "sha256-abc...",
    "aud": "https://fcm.googleapis.com",
    "exp": "2025-10-23T16:31:00.000Z"
  },
  "sig": "base64url..."
}
```

### Canonicalization

**Stable JSON ordering** for hashing and signing:

```typescript
function canonicalizeJSON(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJSON).join(',') + ']';
  }

  // Sort keys lexicographically
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `"${k}":${canonicalizeJSON(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}
```

**Entry hash computation:**

```typescript
async function computeEntryHash(entry: AuditEntry): Promise<string> {
  // Remove signature field for hashing
  const { sig, ...unsigned } = entry;
  const canonical = canonicalizeJSON(unsigned);
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );
  return 'sha256-' + bytesToHex(new Uint8Array(hash));
}
```

### Signing

```typescript
async function signEntry(entry: AuditEntry, privateKey: CryptoKey): Promise<string> {
  const { sig, ...unsigned } = entry;
  const canonical = canonicalizeJSON(unsigned);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(canonical)
  );
  return bytesToB64u(new Uint8Array(signature));
}
```

### Verification

```typescript
async function verifyChain(
  entries: AuditEntry[],
  publicKey: CryptoKey
): Promise<{ ok: boolean; head: string; brokenAt?: number }> {
  let prevHash = 'sha256-' + '0'.repeat(64); // Genesis

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // Check chain continuity
    if (entry.prevHash !== prevHash) {
      return { ok: false, head: prevHash, brokenAt: i };
    }

    // Verify signature
    const { sig, ...unsigned } = entry;
    const canonical = canonicalizeJSON(unsigned);
    const sigBytes = b64uToBytes(sig);

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes,
      new TextEncoder().encode(canonical)
    );

    if (!valid) {
      return { ok: false, head: prevHash, brokenAt: i };
    }

    // Compute next prevHash
    prevHash = await computeEntryHash(entry);
  }

  return { ok: true, head: prevHash };
}
```

### Audit Signing Key

**Generation (first run):**

```typescript
async function initAuditKey(): Promise<void> {
  // Check if already exists
  const existing = await idb.get('meta', 'auditSigningKey');
  if (existing) {
    auditPrivateKey = existing;
    return;
  }

  // Generate non-extractable key
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,  // non-extractable
    ['sign', 'verify']
  );

  auditPrivateKey = keypair.privateKey;
  auditPublicKey = keypair.publicKey;

  // Store private key (non-extractable, stored as handle)
  await idb.put('meta', keypair.privateKey, 'auditSigningKey');

  // Export and store public key (for verification)
  const pubKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
  await idb.put('meta', pubKeyRaw, 'auditPublicKey');
}
```

**Public key export (for verification in PWA):**

```typescript
async function getAuditPublicKey(): Promise<ArrayBuffer> {
  return await idb.get('meta', 'auditPublicKey');
}
```

## Key Wrapping

### Wrapping Algorithm

**Algorithm:** AES-GCM with 256-bit key derived from unlock credential

```typescript
interface WrapParams {
  alg: 'AES-GCM';
  keySize: 256;
  salt: ArrayBuffer;  // 16 bytes
  iv: ArrayBuffer;    // 12 bytes
  iterations: number; // PBKDF2 iterations (600000 for passphrase)
}

interface WrappedKey {
  kid: string;
  wrappedKey: ArrayBuffer;
  wrapParams: WrapParams;
  wrappedAt: string;  // ISO timestamp
}
```

### Wrap Flow

```typescript
async function wrapKey(
  key: CryptoKey,
  unwrapKey: CryptoKey,
  kid: string
): Promise<WrappedKey> {
  // Generate random IV (12 bytes for AES-GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Wrap the key
  const wrappedKeyBytes = await crypto.subtle.wrapKey(
    'raw',
    key,
    unwrapKey,
    { name: 'AES-GCM', iv }
  );

  // Store wrapped key with metadata
  const wrapped: WrappedKey = {
    kid,
    wrappedKey: wrappedKeyBytes,
    wrapParams: {
      alg: 'AES-GCM',
      keySize: 256,
      salt: unlockState.salt,
      iv,
      iterations: unlockState.iterations
    },
    wrappedAt: new Date().toISOString()
  };

  await idb.put('keys', wrapped, kid);

  return wrapped;
}
```

### Unwrap Flow (with audit logging)

```typescript
async function unwrapKey(
  kid: string,
  unwrapKey: CryptoKey
): Promise<CryptoKey> {
  // Retrieve wrapped key
  const wrapped = await idb.get('keys', kid);
  if (!wrapped) {
    throw new Error(`Key not found: ${kid}`);
  }

  // Unwrap
  const key = await crypto.subtle.unwrapKey(
    'raw',
    wrapped.wrappedKey,
    unwrapKey,
    { name: 'AES-GCM', iv: wrapped.wrapParams.iv },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,  // non-extractable
    ['sign']
  );

  // Log unwrap operation
  await auditLog.append('unwrap', kid, {
    method: unlockState.method
  });

  return key;
}
```

## IndexedDB Schema

### Database: `kms-enclave`

**Object Stores:**

1. **`keys`** (keyPath: `kid`)
   ```typescript
   interface KeyStore {
     kid: string;
     wrappedKey: ArrayBuffer;
     wrapParams: WrapParams;
     wrappedAt: string;
   }
   ```

2. **`audit`** (keyPath: `timestamp`, autoIncrement index)
   ```typescript
   interface AuditStore {
     version: 1;
     timestamp: string;
     op: string;
     kid: string;
     requestId: string;
     origin: string;
     clientInfo: { ua: string; url: string };
     prevHash: string;
     nonce: string;
     details?: any;
     sig: string;
   }
   ```
   **Indexes:**
   - `by-kid` (kid)
   - `by-op` (op)
   - `by-timestamp` (timestamp)

3. **`meta`** (keyPath: `key`)
   ```typescript
   interface MetaStore {
     key: 'auditSigningKey' | 'auditPublicKey' | 'chainHead' | 'unlockMethod' | 'unlockSalt';
     value: any;
   }
   ```

**Retention Policy:**
- Keep last **500** entries OR last **30 days**, whichever is larger
- Never drop below **50** entries
- Cleanup runs on startup and periodically

## PWA Integration

### RPC Methods (KMS → PWA)

```typescript
// Audit log access
interface AuditAPI {
  getSummary(): Promise<{
    headHash: string;        // short hex (first 16 chars)
    fullHeadHash: string;    // complete hash
    total: number;
    verified: boolean;
    firstTimestamp: string;
    lastTimestamp: string;
  }>;

  tail(n: number): Promise<AuditEntry[]>;  // newest first

  exportAll(): Promise<AuditEntry[]>;

  getPublicKey(): Promise<ArrayBuffer>;    // for verification
}

// Unlock management
interface UnlockAPI {
  needsSetup(): Promise<boolean>;

  setup(method: 'passkey' | 'passphrase', credential: UnlockCredential): Promise<void>;

  isUnlocked(): Promise<boolean>;

  unlock(method: 'passkey' | 'passphrase', credential: UnlockCredential): Promise<void>;

  lock(): Promise<void>;
}
```

### Events (KMS → PWA)

```typescript
interface KMSEvents {
  needsSetup: {};

  needsUnlock: {
    method: 'passkey' | 'passphrase';
    reason: string;  // e.g., "generate VAPID keypair"
  };

  unlocked: {
    method: 'passkey' | 'passphrase';
    expiresAt: string;
  };

  locked: {
    reason: 'expired' | 'manual' | 'suspicious';
  };

  auditEntry: {
    op: string;
    kid: string;
    timestamp: string;
  };
}
```

### Security Dashboard UI

**Location:** `/app/settings/security`

**Sections:**

1. **Lock Status**
   ```
   🔓 Unlocked (Passkey)
   Expires in 3m 42s
   [Lock Now]
   ```

2. **Chain Verification**
   ```
   Chain Status: ✅ Verified
   - 247 entries
   - All signatures valid
   - Chain continuous from genesis

   Chain Head: c7a1b2c3...d8e9f0a1
   [Copy] [Compare with Backup]
   ```

3. **Recent Events** (last 20)
   ```
   Today, 3:31 PM  ✍️  Signed JWT for fcm.googleapis.com
   Today, 3:30 PM  🔓  Unlocked key vapid-abc (passkey)
   Today, 10:15 AM ✍️  Signed JWT for fcm.googleapis.com
   Yesterday       ♻️  Reset key vapid-abc

   [View All (247)] [Export JSON]
   ```

4. **Settings**
   ```
   Unlock Method: Passkey
   [Change to Passphrase]

   Auto-lock: 5 minutes
   [Change Duration]

   Audit Retention: 500 entries / 30 days
   [Configure]

   [Reset KMS] ⚠️ Deletes all keys and logs
   ```

### Entry Display Format

```typescript
function formatAuditEntry(entry: AuditEntry): string {
  const time = new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  }).format(new Date(entry.timestamp));

  const icon = {
    setup: '🎉',
    unlock: '🔓',
    unwrap: '🔑',
    sign: '✍️',
    reset: '♻️',
    export_attempt: '⚠️'
  }[entry.op];

  const kidShort = entry.kid.slice(0, 12);

  switch (entry.op) {
    case 'setup':
      return `${time}  ${icon}  Setup complete (${entry.details?.method})`;

    case 'unlock':
      return `${time}  ${icon}  Unlocked key ${kidShort} (${entry.details?.method})`;

    case 'sign':
      const aud = entry.details?.aud || 'unknown';
      const audShort = aud.replace('https://', '').split('/')[0];
      return `${time}  ${icon}  Signed JWT for ${audShort}`;

    case 'reset':
      return `${time}  ${icon}  Reset key ${kidShort}`;

    case 'export_attempt':
      return `${time}  ${icon}  Export attempt (blocked)`;

    default:
      return `${time}  ${icon}  ${entry.op}`;
  }
}
```

## Implementation Checklist

### Phase 1 Tasks

- [ ] **Audit Logger** (`src/audit.ts`)
  - [ ] AuditEntry type and schema
  - [ ] Canonical JSON serialization
  - [ ] Hash chain computation
  - [ ] Signature generation/verification
  - [ ] IndexedDB storage
  - [ ] Retention policy enforcement
  - [ ] Tests (100% coverage)

- [ ] **Audit Signing Key** (`src/audit.ts`)
  - [ ] Non-extractable key generation
  - [ ] Key storage and retrieval
  - [ ] Public key export
  - [ ] Tests

- [ ] **Unlock Manager** (`src/unlock.ts`)
  - [ ] Unlock state management
  - [ ] TTL enforcement
  - [ ] Passphrase PBKDF2 derivation
  - [ ] Passkey WebAuthn integration
  - [ ] Auto-lock triggers
  - [ ] Tests (100% coverage)

- [ ] **Key Wrapping** (`src/storage.ts`)
  - [ ] AES-GCM wrap/unwrap
  - [ ] Integration with unlock manager
  - [ ] Unwrap audit logging
  - [ ] Tests (100% coverage)

- [ ] **Worker Integration** (`src/worker.ts`)
  - [ ] Check unlock before operations
  - [ ] Trigger unlock flow if needed
  - [ ] Log all sign operations
  - [ ] Tests

- [ ] **PWA Client** (`src/client.ts`)
  - [ ] Audit API methods
  - [ ] Unlock API methods
  - [ ] Event handling
  - [ ] Tests

- [ ] **Security Dashboard UI** (main PWA)
  - [ ] Chain verification display
  - [ ] Chain head comparison
  - [ ] Recent events list
  - [ ] Export JSON functionality
  - [ ] Lock/unlock controls
  - [ ] Settings panel

- [ ] **First-Time Setup Flow** (main PWA)
  - [ ] Setup modal UI
  - [ ] Passkey registration
  - [ ] Passphrase derivation
  - [ ] Integration with KMS
  - [ ] Tests

## Security Considerations

### Rate Limiting

**Unlock attempts:**
- Max 5 unlock failures per 5 minutes
- After 5 failures: require 1-hour cooldown
- Log all failed attempts

**Sign operations:**
- Max 100 signs per hour per key
- Alert user if >50 signs in 10 minutes
- Log all signs with payload hash

### Suspicious Pattern Detection

**Triggers:**
- Many unlocks in short time (>10 per hour)
- Unlocks from unexpected origins (not ats.run)
- Export attempts (always blocked, but logged)
- Many signs for unusual audiences

**Response:**
- Auto-lock immediately
- Show alert in PWA: "Suspicious activity detected"
- Log with `details: { suspicious: true }`

### Chain Head Pinning

**PWA stores last known chain head:**

```typescript
// In PWA's localStorage (ats.run origin)
interface ChainPin {
  head: string;           // full hash
  pinnedAt: string;       // ISO timestamp
  entryCount: number;     // total entries at pin time
}
```

**On PWA load:**
1. Fetch current chain summary from KMS
2. Compare with pinned head:
   - If **match** → ✅ "Chain unchanged"
   - If **advanced** with valid chain → ✅ "Chain advanced"
   - If **reset/unrelated** → ❌ "Chain discontinuity detected"
3. Update pin on successful verification

**Reset detection banner:**
```
⚠️ Audit Log Reset Detected

The KMS audit log does not continue from the last known state.
This may indicate:
- Browser storage was cleared
- KMS was reset
- Potential tampering

Last known head: c7a1b2c3...d8e9f0a1
Current head:    8d9e0f1a...b2c3d4e5

[View Details] [Dismiss]
```

## Example Flows

### Flow 1: First-Time Setup (Passkey)

```
1. User visits https://ats.run for first time
2. PWA loads KMS iframe (kms.ats.run)
3. KMS worker starts, checks meta store
4. No unlock method found
5. KMS → PWA: { type: 'needsSetup' }
6. PWA shows setup modal
7. User clicks "Use Passkey"
8. PWA calls navigator.credentials.create({
     publicKey: {
       challenge: randomBytes(32),
       rp: { id: 'ats.run', name: 'AllTheServices' },
       user: { id: userId, name: email, displayName: name },
       pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
       authenticatorSelection: {
         authenticatorAttachment: 'platform',
         userVerification: 'required'
       }
     }
   })
9. User completes biometric (Touch ID, Face ID, etc.)
10. Credential created
11. PWA generates unwrapKey: randomBytes(32)
12. PWA encrypts unwrapKey with credential public key (or stores on server)
13. PWA → KMS: setup({ method: 'passkey', unwrapKey })
14. KMS stores unwrapKey in meta (for this session)
15. KMS derives AES-GCM key from unwrapKey
16. KMS logs: "Setup complete (passkey)"
17. KMS → PWA: { type: 'setupComplete' }
18. PWA shows success: "Your keys are now protected with passkey"
```

### Flow 2: Generate VAPID Key (Requires Unlock)

```
1. User navigates to /app/notifications
2. PWA → KMS: generateVAPID()
3. KMS checks: unlockState.isUnlocked
4. isUnlocked === false
5. KMS → PWA: { type: 'needsUnlock', method: 'passkey', reason: 'generate VAPID keypair' }
6. PWA shows unlock modal:
   ┌────────────────────────────────────┐
   │ Unlock KMS                         │
   │                                    │
   │ Touch the fingerprint sensor to    │
   │ generate your notification key     │
   │                                    │
   │     [👆 Touch ID Icon]            │
   │                                    │
   │ [Cancel]                           │
   └────────────────────────────────────┘
7. User touches sensor
8. PWA calls navigator.credentials.get({ publicKey: { challenge, ... } })
9. Assertion succeeds
10. PWA retrieves unwrapKey (from local encryption or server)
11. PWA → KMS: unlock({ method: 'passkey', unwrapKey })
12. KMS sets unlockState:
    - isUnlocked = true
    - unwrapKey = (cached in memory)
    - unlockExpiry = now + 5 minutes
13. KMS logs: "Unlocked (passkey)"
14. KMS proceeds with generateVAPID():
    a. Generate ECDSA P-256 keypair (non-extractable)
    b. Wrap private key with unwrapKey
    c. Store wrapped key in IndexedDB
    d. Log: "Generated key vapid-abc123"
    e. Export public key
15. KMS → PWA: { kid: 'vapid-abc123', publicKey: '...' }
16. PWA shows success: "Notification key created"
```

### Flow 3: Sign JWT (Already Unlocked)

```
1. User enables notifications
2. PWA → KMS: signJWT({ payload: { aud, sub, exp } })
3. KMS checks: unlockState.isUnlocked
4. isUnlocked === true && now < unlockExpiry
5. KMS retrieves wrapped key from IndexedDB
6. KMS unwraps key using cached unwrapKey
7. KMS logs: "Unwrap key vapid-abc123"
8. KMS signs JWT payload
9. KMS logs: "Sign JWT (kid=vapid-abc123, aud=fcm..., exp=...)"
10. KMS → PWA: { jwt: 'eyJ...' }
11. PWA subscribes to push with public key and JWT
```

### Flow 4: Audit Log Verification

```
1. User opens /app/settings/security
2. PWA → KMS: audit.getSummary()
3. KMS worker:
   a. Fetches all audit entries from IndexedDB
   b. Verifies signatures with auditPublicKey
   c. Verifies hash chain continuity
   d. Computes chain head
4. KMS → PWA: {
     headHash: 'c7a1b2c3',
     fullHeadHash: 'c7a1b2c3d4e5f6a7...',
     total: 247,
     verified: true,
     firstTimestamp: '2025-10-01T10:00:00Z',
     lastTimestamp: '2025-10-23T15:31:05Z'
   }
5. PWA retrieves last pinned head from localStorage
6. PWA compares:
   - lastPinned: 'c7a1b2c3d4e5f6a7...'
   - current:    'c7a1b2c3d4e5f6a7...'
   - Match: ✅
7. PWA displays:
   ┌─────────────────────────────────────┐
   │ Audit Log                           │
   │                                     │
   │ Chain Status: ✅ Verified           │
   │ - 247 entries                       │
   │ - All signatures valid              │
   │ - Chain continuous                  │
   │                                     │
   │ Chain Head: c7a1b2c3...d8e9f0a1     │
   │ [Copy] [Export JSON]                │
   │                                     │
   │ Recent Events:                      │
   │ Oct 23, 3:31 PM  ✍️ Signed JWT     │
   │ Oct 23, 3:30 PM  🔓 Unlocked key   │
   │ Oct 23, 10:15 AM ✍️ Signed JWT     │
   │ ...                                 │
   └─────────────────────────────────────┘
8. PWA updates pin:
   localStorage.setItem('kms-chain-pin', JSON.stringify({
     head: 'c7a1b2c3d4e5f6a7...',
     pinnedAt: new Date().toISOString(),
     entryCount: 247
   }))
```

## Related Documentation

- [README](../README.md) - Architecture overview
- [Design](../design.md) - Design index
- [01 - Overview](./01-overview-and-architecture.md) - High-level architecture
- [03 - Component Design](./03-component-design.md) - Worker, main, storage
- [06 - Implementation Guide](./06-implementation-guide.md) - Production-ready utilities

## References

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [PBKDF2 Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Hash Chain Integrity](https://en.wikipedia.org/wiki/Hash_chain)
- [RFC 7638 - JWK Thumbprint](https://tools.ietf.org/html/rfc7638)
