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

## Unlock Policy

**All high-stakes cryptographic operations require an unlocked state:**

- **VAPID key generation** - Requires unlock
- **VAPID key regeneration** - Requires unlock
- **JWT signing** - Requires unlock
- **Key export** (public keys only) - No unlock required (public data)
- **Audit log access** - No unlock required (read-only, publicly verifiable)

**Unlock mechanisms:**

### 1. Passphrase (PBKDF2 + HKDF)
Software-based, requires strong password (≥8 characters).

**Key derivation:**
```
PBKDF2(passphrase, salt, 600k iterations, SHA-256) → 256 bits raw material
  ↓
HKDF(raw material, salt, info="ATS/KMS/KEK-wrap/v1", SHA-256) → K_wrap (AES-GCM 256)
```

### 2. Passkey with PRF Extension (Recommended)
Hardware-backed, phishing-resistant, uses WebAuthn PRF extension.

**Key derivation:**
```
WebAuthn PRF(appSalt) → 256 bits from authenticator
  ↓
HKDF(PRF output, appSalt, info="ATS/KMS/KEK-wrap/v1", SHA-256) → K_wrap (AES-GCM 256)
```

The KEK is wrapped with K_wrap and stored. On unlock, K_wrap is derived again and used to unwrap the KEK.

### 3. Passkey Gate-Only Mode (Fallback)
For authenticators that don't support the PRF extension.

**Behavior:**
- WebAuthn assertion (user verification required) starts a 5-minute session
- Fresh KEK is generated and kept in Worker memory (not wrapped at rest)
- On session expiry or page sleep, KEK is zeroized and new assertion is required
- **Note**: At-rest protection comes from IndexedDB + OS storage; passkey provides use-control only

**Important:** When using passkey assertions for verification, the signature is DER format and must be converted to P-1363 for WebCrypto.

## Key Derivation Architecture

All unlock methods follow a consistent two-step pattern:

### Step 1: Derive Raw Key Material
Different sources, same output size (256 bits):

```
Passphrase:  PBKDF2-HMAC-SHA-256(password, salt, 600k) → 32 bytes
Passkey PRF: WebAuthn PRF(appSalt) → 32 bytes  (from authenticator)
```

### Step 2: HKDF with Purpose Label
Unified key derivation with domain separation:

```
K_wrap = HKDF-SHA-256(
  ikm = raw_material,     // From step 1
  salt = salt/appSalt,    // Same salt as step 1
  info = "ATS/KMS/KEK-wrap/v1",  // Purpose label (versioned)
  L = 32 bytes             // Output length
)
```

### Why This Pattern?

1. **Domain separation**: The `info` parameter ensures K_wrap can only be used for KEK wrapping
2. **Future agility**: Can derive additional keys (e.g., `"ATS/login-token/v1"`) without re-running expensive PBKDF2
3. **Consistent pattern**: Both passphrase and passkey PRF use identical HKDF step
4. **Safe reuse**: No risk of using the same bits for different purposes

### Implementation (WebCrypto)

```typescript
// Step 1: Get raw material (passphrase example)
const ikmKey = await crypto.subtle.importKey('raw', passphraseBytes, 'PBKDF2', false, ['deriveBits']);
const ikm = await crypto.subtle.deriveBits(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 },
  ikmKey,
  256  // 32 bytes
);

// Step 2: HKDF with purpose label
const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
const K_wrap = await crypto.subtle.deriveKey(
  {
    name: 'HKDF',
    hash: 'SHA-256',
    salt,
    info: new TextEncoder().encode('ATS/KMS/KEK-wrap/v1')
  },
  hkdfKey,
  { name: 'AES-GCM', length: 256 },
  false,  // non-extractable
  ['wrapKey', 'unwrapKey']
);
```

## Signature Format Reference

Understanding signature formats is critical for implementing unlock and JWT signing correctly:

| Context | Format | Length (P-256) | Notes |
|---------|--------|----------------|-------|
| **WebCrypto `sign()`** | P-1363 | 64 bytes | Raw r\|\|s concatenation |
| **WebCrypto `verify()`** | P-1363 | 64 bytes | Expects raw r\|\|s |
| **WebAuthn (passkeys)** | DER (ASN.1) | ~70-72 bytes | Variable length, starts with 0x30 |
| **JWS ES256 (JWT)** | P-1363 | 64 bytes | Base64url-encoded raw r\|\|s |
| **Some server libs (Node.js default)** | DER | ~70-72 bytes | May need P-1363 → DER conversion |

**When conversion is needed:**

1. ✅ **WebAuthn unlock** - DER (from passkey) → P-1363 (for WebCrypto verify)
2. ❌ **JWT signing** - No conversion (WebCrypto sign already returns P-1363)
3. ⚠️ **Server interop** - May need P-1363 → DER (if server expects DER)

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

   A. Passkey with PRF (Recommended):
      - KMS triggers WebAuthn credential creation with `extensions: { prf: {} }`
      - Browser/authenticator creates passkey
      - KMS checks if `prf.enabled === true` in response
      - If PRF supported:
        * Generate random appSalt (32 bytes)
        * Get PRF assertion with `prf: { eval: { first: appSalt } }`
        * Derive: K_wrap = HKDF(PRF(appSalt), appSalt, "ATS/KMS/KEK-wrap/v1")
        * Generate random KEK (AES-GCM 256)
        * Wrap KEK with K_wrap
        * Store: credentialId, appSalt, wrappedKEK, wrapIV
        * KMS logs: "Setup complete (passkey-prf)"
      - If PRF not supported, fallback to gate-only mode

   B. Passkey Gate-Only (Fallback):
      - KMS triggers WebAuthn credential creation (no PRF extension)
      - Browser/authenticator creates passkey
      - Generate random KEK (AES-GCM 256, not wrapped)
      - Keep KEK in Worker memory for 5-minute session
      - Store: credentialId, sessionDuration
      - KMS logs: "Setup complete (passkey-gate)"

   C. Passphrase:
      - User enters passphrase (min 8 chars)
      - Generate random salt (16 bytes)
      - Derive: PBKDF2(passphrase, salt, 600k) → 256 bits
      - Derive: K_wrap = HKDF(PBKDF2 output, salt, "ATS/KMS/KEK-wrap/v1")
      - Hash PBKDF2 output for verification
      - Store: salt, iterations, verificationHash
      - KMS logs: "Setup complete (passphrase)"

7. KMS creates first audit entry (genesis)
```

### Unlock Flow (Passkey with PRF)

```
1. User action requires key usage (e.g., generate VAPID keypair)
2. KMS Worker checks: isUnlocked
3. If locked:
   a. Load unlock config from IndexedDB meta store
   b. Trigger WebAuthn assertion with PRF extension:
      navigator.credentials.get({
        publicKey: {
          challenge: random32Bytes,
          rpId,
          allowCredentials: [{ type: 'public-key', id: credentialId }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: appSalt } } }
        }
      })
   c. Get PRF output from assertion response
   d. Derive: K_wrap = HKDF(PRF output, appSalt, "ATS/KMS/KEK-wrap/v1")
   e. Unwrap KEK: unwrapKey('raw', wrappedKEK, K_wrap, { name: 'AES-GCM', iv })
   f. Store KEK in Worker memory
   g. Set isUnlocked = true
   h. KMS logs: "Unlocked (passkey-prf)"
4. KMS performs requested operation with KEK
5. KMS logs: "Sign JWT (kid=..., aud=...)"
6. KMS returns result
```

### Unlock Flow (Passkey Gate-Only)

```
1. User action requires key usage
2. KMS Worker checks: isUnlocked && sessionExpiry > now
3. If locked or session expired:
   a. Load unlock config from IndexedDB meta store
   b. Trigger WebAuthn assertion:
      navigator.credentials.get({
        publicKey: {
          challenge: random32Bytes,
          rpId,
          allowCredentials: [{ type: 'public-key', id: credentialId }],
          userVerification: 'required'
        }
      })
   c. Generate fresh KEK (AES-GCM 256, not wrapped)
   d. Store KEK in Worker memory
   e. Set session expiry = now + 5 minutes
   f. Start auto-clear timer
   g. Set isUnlocked = true
   h. KMS logs: "Unlocked (passkey-gate)"
4. KMS performs requested operation with KEK
5. KMS logs: "Sign JWT (kid=..., aud=...)"
6. On session expiry: zeroize KEK, set isUnlocked = false
```

### Unlock Flow (Passphrase)

```
1. User action requires key usage
2. KMS Worker checks: isUnlocked
3. If locked:
   a. Load unlock config from IndexedDB meta store
   b. User enters passphrase
   c. Derive: PBKDF2(passphrase, salt, iterations) → 256 bits
   d. Verify: SHA-256(derived bits) === verificationHash
   e. If match:
      - Derive: K_wrap = HKDF(PBKDF2 output, salt, "ATS/KMS/KEK-wrap/v1")
      - Store K_wrap in Worker memory
      - Set isUnlocked = true
      - KMS logs: "Unlocked (passphrase)"
   f. If mismatch: return error "INCORRECT_PASSPHRASE"
4. KMS performs requested operation with K_wrap
5. KMS logs: "Sign JWT (kid=..., aud=...)"
6. KMS returns result
```

### Unlock State Management

**In-memory state (worker):**
```typescript
// Primary unlock state (in worker.ts)
let wrappingKey: CryptoKey | null = null;  // K_wrap or KEK depending on method
let isUnlocked: boolean = false;

// Gate-only session state (in unlock.ts)
let gateSessionKey: CryptoKey | null = null;
let gateSessionExpiry: number | null = null;
let gateSessionTimer: ReturnType<typeof setTimeout> | null = null;
```

**Stored configuration (IndexedDB meta store):**
```typescript
type UnlockConfig =
  | {
      method: 'passphrase';
      salt: ArrayBuffer;           // 16 bytes for PBKDF2 and HKDF
      iterations: number;           // 600000
      verificationHash: string;     // SHA-256 of PBKDF2 output
    }
  | {
      method: 'passkey-prf';
      credentialId: ArrayBuffer;
      appSalt: ArrayBuffer;         // 32 bytes for PRF evaluation
      wrappedKEK: ArrayBuffer;      // KEK wrapped with K_wrap from PRF
      wrapIV: ArrayBuffer;          // 12 bytes for AES-GCM
    }
  | {
      method: 'passkey-gate';
      credentialId: ArrayBuffer;
      sessionDuration: number;      // 5 * 60 * 1000 (5 minutes)
    };
```

**Gate-only session TTL:** 5 minutes (hardcoded)

**Session clear triggers (gate-only mode):**
- Session expiry timestamp reached
- Worker reset
- Explicit lock action

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

### Flow 1: First-Time Setup (Passkey with PRF)

```
1. User visits https://ats.run for first time
2. PWA loads KMS iframe (kms.ats.run)
3. KMS worker starts, checks meta store
4. No unlock method found
5. PWA → KMS: isUnlockSetup() → { isSetup: false }
6. PWA shows setup modal
7. User clicks "Use Passkey (Recommended)"
8. PWA → KMS: setupPasskeyPRF({ rpId: 'ats.run', rpName: 'AllTheServices' })
9. KMS calls navigator.credentials.create({
     publicKey: {
       challenge: randomBytes(32),
       rp: { id: 'ats.run', name: 'AllTheServices' },
       user: { id: randomBytes(16), name: 'kms-user', displayName: 'KMS User' },
       pubKeyCredParams: [
         { alg: -7, type: 'public-key' },   // ES256
         { alg: -257, type: 'public-key' }  // RS256
       ],
       authenticatorSelection: {
         authenticatorAttachment: 'platform',
         userVerification: 'required',
         residentKey: 'preferred'
       },
       extensions: { prf: {} }  // Request PRF extension
     }
   })
10. User completes biometric (Touch ID, Face ID, etc.)
11. Credential created
12. KMS checks: getClientExtensionResults().prf.enabled === true
13. If PRF supported:
    a. Generate appSalt: randomBytes(32)
    b. Get assertion with PRF: navigator.credentials.get({ extensions: { prf: { eval: { first: appSalt } } } })
    c. Extract PRF output (32 bytes from authenticator)
    d. Derive: K_wrap = HKDF(PRF output, appSalt, "ATS/KMS/KEK-wrap/v1")
    e. Generate KEK: randomBytes(32) as AES-GCM key
    f. Wrap KEK with K_wrap
    g. Store: { method: 'passkey-prf', credentialId, appSalt, wrappedKEK, wrapIV }
    h. Log audit entry: "Setup complete (passkey-prf)"
    i. KMS → PWA: { success: true }
14. PWA shows success: "Your keys are protected with passkey"
```

### Flow 2: Generate VAPID Key (Requires Unlock with PRF Passkey)

```
1. User navigates to /app/notifications
2. PWA → KMS: generateVAPID()
3. KMS Worker checks: isUnlocked === false
4. KMS loads unlock config from IndexedDB: { method: 'passkey-prf', credentialId, appSalt, wrappedKEK, wrapIV }
5. KMS calls navigator.credentials.get({
     publicKey: {
       challenge: randomBytes(32),
       rpId: 'ats.run',
       allowCredentials: [{ type: 'public-key', id: credentialId }],
       userVerification: 'required',
       extensions: { prf: { eval: { first: appSalt } } }
     }
   })
6. User touches fingerprint sensor / Face ID
7. Assertion succeeds, PRF output extracted (32 bytes)
8. KMS derives: K_wrap = HKDF(PRF output, appSalt, "ATS/KMS/KEK-wrap/v1")
9. KMS unwraps: KEK = unwrapKey('raw', wrappedKEK, K_wrap, { name: 'AES-GCM', iv: wrapIV })
10. KMS sets: wrappingKey = KEK, isUnlocked = true
11. KMS logs audit entry: "Unlocked (passkey-prf)"
12. KMS proceeds with generateVAPID():
    a. Generate ECDSA P-256 keypair (non-extractable)
    b. Export raw public key (65 bytes uncompressed)
    c. Compute kid from JWK thumbprint (RFC 7638)
    d. Wrap private key with KEK
    e. Store wrapped key in IndexedDB: { kid, wrappedKey, wrapParams }
    f. Log audit entry: "Generate key vapid-<kid>"
    g. Return: { kid, publicKey: base64url(rawPublicKey) }
13. KMS → PWA: { kid: 'vapid-abc123...', publicKey: 'BHj8...' }
14. PWA shows success: "Notification key created"
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
