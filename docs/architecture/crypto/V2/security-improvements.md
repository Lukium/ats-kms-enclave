# V2 Security Improvements: Detailed Rationale

**Version**: 2.0
**Date**: 2025-01-24

This document explains the security rationale for each V2 improvement over V1, with specific attacks prevented and implementation guidance.

---

## Table of Contents

1. [Calibrated KDF](#1-calibrated-kdf)
2. [AES-GCM AAD (Metadata Binding)](#2-aes-gcm-aad-metadata-binding)
3. [Standard Key Check Value (KCV)](#3-standard-key-check-value-kcv)
4. [Deterministic HKDF Salts](#4-deterministic-hkdf-salts)
5. [Hardened Audit Log](#5-hardened-audit-log)
6. [Multi-Enrollment Support](#6-multi-enrollment-support)
7. [Enhanced Passkey Gate-Only](#7-enhanced-passkey-gate-only)
8. [Extractability Window Management](#8-extractability-window-management)
9. [Proper Type Safety](#9-proper-type-safety)
10. [Explicit Versioning](#10-explicit-versioning)

---

## 1. Calibrated KDF

### Problem in V1

```typescript
// V1: Fixed iteration count
const iterations = 600_000; // Same for all devices
```

**Issues:**
- **Desktop**: 600k iterations may be too weak (completes in <50ms on fast CPUs)
- **Mobile**: 600k iterations causes poor UX (2-5 seconds on budget phones)
- **Inconsistent security**: Wide variance in actual work factor across devices

### V2 Solution

```typescript
// V2: Device-specific calibration
const { iterations, measuredMs } = await calibratePBKDF2Iterations({
  min: 150,
  max: 300,
  mid: 220
});
// Result: 50,000 to 2,000,000 iterations, tuned to 150-300ms
```

**Calibration Algorithm:**

```typescript
export async function calibratePBKDF2Iterations(
  targetMs = { min: 150, max: 300, mid: 220 }
): Promise<{ iterations: number; measuredMs: number }> {
  const subtle = crypto.subtle;
  const te = new TextEncoder();

  // Test inputs
  const password = te.encode("calibration-password");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const baseKey = await subtle.importKey(
    "raw", password, { name: "PBKDF2" }, false, ["deriveBits"]
  );

  // Timing function
  async function timeFor(iterations: number): Promise<number> {
    const t0 = performance.now();
    await subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey, 256
    );
    return performance.now() - t0;
  }

  // Warm-up (stabilize JIT)
  await timeFor(10_000);

  // Probe
  const probeIters = 100_000;
  const probeMs = await timeFor(probeIters);

  // Scale to target
  let est = Math.round(probeIters * (targetMs.mid / Math.max(1, probeMs)));
  let iters = clamp(round5k(est), 50_000, 2_000_000);

  // Verify once
  let ms = await timeFor(iters);
  if (ms < targetMs.min || ms > targetMs.max) {
    const scaled = Math.round(iters * (targetMs.mid / Math.max(1, ms)));
    iters = clamp(round5k(scaled), 50_000, 2_000_000);
    ms = await timeFor(iters);
  }

  return { iterations: iters, measuredMs: ms };
}

function clamp(n: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, n));
}

function round5k(n: number) {
  return Math.max(1, Math.round(n / 5_000)) * 5_000;
}
```

**Benefits:**
- **Consistent security**: ~200ms work factor across all devices
- **Better UX**: Fast on mobile (target met), still strong on desktop
- **Adaptive**: Can adjust over time as device performance changes

**Recalibration Strategy:**

```typescript
// Opportunistic adjustment during unlocks
interface CalibrationState {
  iterations: number;
  ema: number;  // Exponential moving average of observed times
  samples: number;
  lastCalibratedAt: number;
  platformHash: string;
}

// After each unlock:
const observed = unlockDuration; // from withUnlock
state.ema = 0.4 * observed + 0.6 * state.ema;
state.samples++;

// Adjust if drift detected
if (state.samples >= 5 && (state.ema < 150 || state.ema > 300)) {
  if (state.ema < 150) {
    state.iterations = Math.round(state.iterations * 1.10); // +10%
  } else {
    state.iterations = Math.round(state.iterations * 0.90); // -10%
  }
  state.samples = 0;
  await saveCalibration(state);
}

// Periodic full recalibration
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
if (Date.now() - state.lastCalibratedAt > THIRTY_DAYS) {
  const { iterations, measuredMs } = await calibratePBKDF2Iterations();
  state.iterations = iterations;
  state.ema = measuredMs;
  state.lastCalibratedAt = Date.now();
  await saveCalibration(state);
}
```

### Alternative: Argon2id (Optional)

For even better security, V2 supports **Argon2id via WASM** (progressive enhancement):

```typescript
// If available, use Argon2id instead of PBKDF2
import { hash } from '@noble/hashes/argon2';

// Calibrate memory parameter (same approach)
const kek = hash(passphrase, salt, {
  t: 2,           // iterations
  m: 65536,       // 64 MB memory (calibrated)
  p: 1,           // parallelism
  hashLen: 32,    // 256 bits
  type: argon2id
});
```

**When to use:**
- If `typeof WebAssembly !== 'undefined'`
- For high-security applications
- When memory cost > iteration cost (Argon2id's main benefit)

---

## 2. AES-GCM AAD (Metadata Binding)

### Problem in V1

```typescript
// V1: No AAD
const encryptedMS = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: msIV },
  kek,
  ms
);
```

**Attack Scenarios:**

1. **Ciphertext Swapping**:
   ```
   User has two methods: passphrase and passkey-prf
   Attacker swaps encryptedMS between configs
   → Wrong method decrypts, but MS still works
   → Breaks authentication invariant
   ```

2. **Ciphertext Replay**:
   ```
   User updates passphrase (new KEK, re-encrypts MS)
   Attacker replaces new encryptedMS with old one
   → Old passphrase still works
   → Password change ineffective
   ```

3. **Metadata Tampering**:
   ```
   Attacker modifies config.iterations (lower value)
   encryptedMS still decrypts correctly
   → Weaker KDF accepted
   ```

### V2 Solution

```typescript
// V2: AAD binds encryption to metadata
const aad = new TextEncoder().encode(JSON.stringify({
  kmsVersion: 2,
  method: 'passphrase',
  algVersion: 1,
  purpose: 'master-secret-wrap',
  // For passkey methods, include credentialId
  credentialId: credentialId ? base64url(credentialId) : undefined
}));

const encryptedMS = await crypto.subtle.encrypt(
  {
    name: 'AES-GCM',
    iv: msIV,
    additionalData: aad  // ← Cryptographically binds metadata
  },
  kek,
  ms
);

// Store AAD with config
config.msAAD = aad;
```

**How AAD Prevents Attacks:**

1. **Swapping**: Decryption fails because AAD differs (method mismatch)
2. **Replay**: Decryption fails if any metadata changed (algVersion, etc.)
3. **Tampering**: Changing config.iterations doesn't help (not in AAD, but KDF fails)

**AAD Construction Rules:**

```typescript
// For MS encryption
interface MSEncryptionAAD {
  kmsVersion: number;        // Always 2
  method: string;            // 'passphrase' | 'passkey-prf' | 'passkey-gate'
  algVersion: number;        // Algorithm version (allows upgrades)
  purpose: 'master-secret-wrap';
  credentialId?: string;     // For passkey methods (base64url)
}

// For application key wrapping
interface KeyWrapAAD {
  kmsVersion: number;
  kid: string;               // Key ID
  alg: string;               // 'ES256' | 'EdDSA'
  purpose: string;           // 'vapid' | 'audit' | 'identity'
  createdAt: number;         // Timestamp
  keyType: 'application-key';
}
```

**Storage:**

```typescript
// Must store AAD to decrypt later
interface ConfigWithAAD {
  // ... other fields
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;  // ← Store AAD bytes
}

// On decrypt
const ms = await crypto.subtle.decrypt(
  {
    name: 'AES-GCM',
    iv: config.msIV,
    additionalData: config.msAAD  // ← Use stored AAD
  },
  kek,
  config.encryptedMS
);
```

---

## 3. Standard Key Check Value (KCV)

### Problem in V1

```typescript
// V1: Custom verification scheme
// Derive 512 bits from PBKDF2
// First 256 bits = KEK
// SHA-256(all 512 bits) = verification hash
const verificationHash = SHA256(fullDerivedBits);
```

**Issues:**
- **Non-standard**: Custom scheme, harder to audit
- **Complexity**: Requires deriving 512 bits instead of 256
- **No constant-time compare**: Risk of timing attacks
- **Unclear security properties**: What does the hash actually prove?

### V2 Solution

```typescript
// V2: Standard KCV (NIST-style)
// 1. Derive KEK normally (256 bits via PBKDF2)
const kek = await deriveKEK(passphrase, salt, iterations);

// 2. Compute KCV = HMAC(KEK, constant)
const kcvKey = await crypto.subtle.importKey(
  'raw',
  await crypto.subtle.exportKey('raw', kek),
  { name: 'HMAC', hash: 'SHA-256' },
  false,
  ['sign']
);

const kcv = await crypto.subtle.sign(
  'HMAC',
  kcvKey,
  new TextEncoder().encode('ATS/KMS/KCV/v2')
);

// 3. Store KCV (32 bytes)
config.kcv = kcv;

// 4. Verify with constant-time comparison
function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const ua = new Uint8Array(a);
  const ub = new Uint8Array(b);
  if (ua.length !== ub.length) return false;

  let diff = 0;
  for (let i = 0; i < ua.length; i++) {
    diff |= ua[i] ^ ub[i];
  }
  return diff === 0;
}

if (!timingSafeEqual(computedKCV, storedKCV)) {
  throw new Error('INVALID_PASSPHRASE');
}
```

**Benefits:**
- **Standard approach**: HMAC-based KCV is well-understood
- **Constant-time**: Prevents timing attacks on password verification
- **Simpler**: No custom 512-bit derivation
- **Clear semantics**: "This KEK matches the stored config"

**Why HMAC?**

HMAC provides:
- Keyed hash (only correct KEK produces correct KCV)
- Deterministic (same KEK → same KCV)
- Indistinguishable from random (doesn't leak KEK)
- Standard construction (NIST approved)

**Timing Attack Prevention:**

```typescript
// BAD: Early exit on first mismatch
function unsafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;  // ← Timing leak!
  }
  return true;
}

// GOOD: Constant-time (always checks all bytes)
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];  // ← XOR accumulates differences
  }
  return diff === 0;  // ← Single final comparison
}
```

---

## 4. Deterministic HKDF Salts

### Problem in V1

```typescript
// V1: All-zero salt for MKEK derivation
const mkek = await crypto.subtle.deriveKey(
  {
    name: 'HKDF',
    salt: new Uint8Array(32),  // ← All zeros
    info: new TextEncoder().encode('ATS/KMS/MKEK/v1'),
    hash: 'SHA-256'
  },
  msKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['wrapKey', 'unwrapKey']
);
```

**Issues:**
- **Suboptimal security**: HKDF with zero salt is *safe* but not *ideal*
- **No domain separation**: Can't easily derive multiple keys from same MS
- **No rotation path**: Can't version MKEK derivation without changing MS
- **RFC 5869**: "salt should be random... but may be all-zeros"

### V2 Solution

```typescript
// V2: Deterministic non-zero salt
const mkekSalt = await crypto.subtle.digest(
  'SHA-256',
  new TextEncoder().encode('ATS/KMS/MKEK/salt/v2')
);

const mkek = await crypto.subtle.deriveKey(
  {
    name: 'HKDF',
    salt: mkekSalt,  // ← Deterministic but non-zero
    info: new TextEncoder().encode('ATS/KMS/MKEK/v2'),
    hash: 'SHA-256'
  },
  msKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['wrapKey', 'unwrapKey']
);
```

**Benefits:**

1. **Better entropy extraction**: Non-zero salt improves HKDF's extract phase
2. **Domain separation**: Can derive different keys with different salts
3. **Rotation paths**: Can bump version in salt string for migration
4. **Deterministic**: Same MS → same MKEK (required for per-operation auth)

**HKDF Two-Phase Process:**

```
HKDF(IKM, salt, info) = HKDF-Expand(HKDF-Extract(IKM, salt), info)

Extract phase: PRK = HMAC(salt, IKM)
  → Better entropy if salt is non-zero
  → Zero salt makes PRK = HMAC(zeros, IKM)

Expand phase: OKM = HMAC(PRK, info || 0x01)
  → info provides context separation
```

**Versioned Salt Strategy:**

```typescript
// Current version
const v2Salt = SHA256('ATS/KMS/MKEK/salt/v2');

// Future migration path
const v3Salt = SHA256('ATS/KMS/MKEK/salt/v3');

// Can derive both and re-wrap keys
const mkekV2 = deriveKey(ms, v2Salt, 'ATS/KMS/MKEK/v2');
const mkekV3 = deriveKey(ms, v3Salt, 'ATS/KMS/MKEK/v3');

// Re-wrap: unwrap with v2, wrap with v3
const key = await unwrapKey(wrappedKeyV2, mkekV2);
const wrappedKeyV3 = await wrapKey(key, mkekV3);
```

**Domain Separation Example:**

```typescript
// Can derive multiple keys from same MS
const mkek = deriveKey(ms, SHA256('ATS/KMS/MKEK/salt/v2'), 'ATS/KMS/MKEK/v2');
const backupKey = deriveKey(ms, SHA256('ATS/KMS/Backup/salt/v1'), 'ATS/KMS/Backup/v1');
const exportKey = deriveKey(ms, SHA256('ATS/KMS/Export/salt/v1'), 'ATS/KMS/Export/v1');
```

---

## 5. Hardened Audit Log

### Problems in V1

```typescript
// V1 Issues:
{
  // 1. Embedded public key in each entry (32 bytes × N entries)
  publicKey: string,

  // 2. Extractable audit signing key (can be stolen and forged)
  // auditKeypair generated with extractable: true

  // 3. No sequence numbers (vulnerable to truncation)
  // Attacker can delete recent entries

  // 4. No periodic anchors (hard to detect missing entries)
}
```

### V2 Solution

```typescript
// V2: Hardened Audit Entry
interface AuditEntryV2 {
  kmsVersion: 2;
  seqNum: number;            // ← Monotonic sequence (detects truncation)
  timestamp: number;

  // Operation
  op: string;
  kid: string;
  requestId: string;
  origin?: string;

  // Unlock timing
  unlockTime: number;
  lockTime: number;
  duration: number;

  details?: Record<string, unknown>;

  // Chain integrity
  previousHash: string;
  chainHash: string;

  // Signature (Ed25519)
  signature: string;
  auditKeyId: string;        // ← Reference to key (not embedded pubkey)
}

// Audit key stored separately (non-extractable by default)
interface AuditKeyConfig {
  keyId: string;             // SHA-256 hash of public key
  publicKey: string;         // Ed25519 public key (32 bytes)
  privateKeyWrapped: ArrayBuffer;  // Wrapped with special audit KEK
  extractable: false;        // ← Non-extractable in normal use
  createdAt: number;
}
```

**Improvements:**

### 5.1. Non-Extractable Audit Key

```typescript
// V1: Extractable (risky)
const auditKeypair = await crypto.subtle.generateKey(
  { name: 'Ed25519' },
  true,  // ← Extractable!
  ['sign', 'verify']
);

// V2: Non-extractable (with explicit export ceremony)
const auditKeypair = await crypto.subtle.generateKey(
  { name: 'Ed25519' },
  false,  // ← Non-extractable by default
  ['sign', 'verify']
);

// Explicit export only when user requests backup
async function exportAuditKey(credentials: AuthCredentials): Promise<string> {
  // Requires user authentication
  const { result } = await withUnlock(credentials, async (mkek) => {
    // Generate temporary exportable key
    const tempKeypair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,  // Temporarily exportable
      ['sign']
    );

    // Export as JWK
    const jwk = await crypto.subtle.exportKey('jwk', tempKeypair.privateKey);

    // Re-import as non-extractable for continued use
    const nonExtractable = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'Ed25519' },
      false,
      ['sign']
    );

    // Store non-extractable version
    await storeAuditKey(nonExtractable, mkek);

    // Return JWK for backup
    return JSON.stringify(jwk);
  });

  return result;
}
```

### 5.2. Sequence Numbers (Truncation Detection)

```typescript
// V2: Monotonic sequence
let nextSeqNum = 0;  // Persisted in IndexedDB

async function logOperation(op: AuditOperation): Promise<void> {
  // Increment sequence
  const seqNum = nextSeqNum++;

  // Create entry
  const entry: AuditEntryV2 = {
    kmsVersion: 2,
    seqNum,  // ← Monotonic
    timestamp: Date.now(),
    // ... other fields
  };

  // Compute chain hash
  entry.previousHash = await getLastChainHash();
  entry.chainHash = await computeChainHash(entry);

  // Sign
  entry.signature = await signChainHash(entry.chainHash);

  // Store
  await storeAuditEntry(entry);
  await persistSequenceCounter(nextSeqNum);
}

// Verification detects gaps
async function verifyAuditChain(): Promise<VerificationResult> {
  const entries = await getAllAuditEntries();

  for (let i = 0; i < entries.length; i++) {
    // Check sequence continuity
    if (entries[i].seqNum !== i) {
      return {
        valid: false,
        error: `Missing entry: expected seqNum ${i}, got ${entries[i].seqNum}`
      };
    }

    // Check chain hash
    // ... (same as V1)
  }

  return { valid: true };
}
```

### 5.3. Periodic Anchors

```typescript
// V2: Anchor chain hash periodically
interface AuditAnchor {
  seqNum: number;          // Sequence number of anchored entry
  chainHash: string;       // Chain hash at this point
  timestamp: number;
  method: 'local' | 'server' | 'file';
  location?: string;       // URL or file path
}

// Anchor every N entries or M milliseconds
const ANCHOR_EVERY_N = 100;
const ANCHOR_EVERY_MS = 24 * 60 * 60 * 1000;  // Daily

async function logOperation(op: AuditOperation): Promise<void> {
  // ... create entry, compute chain hash, sign

  // Store entry
  await storeAuditEntry(entry);

  // Check if anchor needed
  const lastAnchor = await getLastAnchor();
  const shouldAnchor =
    (entry.seqNum - lastAnchor.seqNum >= ANCHOR_EVERY_N) ||
    (entry.timestamp - lastAnchor.timestamp >= ANCHOR_EVERY_MS);

  if (shouldAnchor) {
    await anchorChainHash({
      seqNum: entry.seqNum,
      chainHash: entry.chainHash,
      timestamp: entry.timestamp,
      method: 'local'  // Or 'server', 'file'
    });
  }
}

// Verification checks anchors
async function verifyAuditChain(): Promise<VerificationResult> {
  const entries = await getAllAuditEntries();
  const anchors = await getAllAnchors();

  for (const anchor of anchors) {
    const entry = entries.find(e => e.seqNum === anchor.seqNum);
    if (!entry) {
      return {
        valid: false,
        error: `Missing entry at anchor seqNum ${anchor.seqNum}`
      };
    }

    if (entry.chainHash !== anchor.chainHash) {
      return {
        valid: false,
        error: `Anchor mismatch at seqNum ${anchor.seqNum}`
      };
    }
  }

  return { valid: true };
}
```

### 5.4. Canonical JSON for Chain Hash

```typescript
// V2: Stable, reproducible canonicalization
function canonicalizeEntry(entry: Partial<AuditEntryV2>): string {
  // Extract fields in deterministic order (exclude signature/chainHash)
  const canonical = {
    kmsVersion: entry.kmsVersion,
    seqNum: entry.seqNum,
    timestamp: entry.timestamp,
    op: entry.op,
    kid: entry.kid,
    requestId: entry.requestId,
    origin: entry.origin,
    unlockTime: entry.unlockTime,
    lockTime: entry.lockTime,
    duration: entry.duration,
    details: entry.details ? sortKeys(entry.details) : undefined,
    previousHash: entry.previousHash,
    auditKeyId: entry.auditKeyId
  };

  // Stringify with sorted keys, no whitespace
  return JSON.stringify(canonical, Object.keys(canonical).sort());
}

function sortKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = obj[key];
  }
  return sorted;
}

async function computeChainHash(entry: Partial<AuditEntryV2>): Promise<string> {
  const canonical = canonicalizeEntry(entry);
  const input = canonical + entry.previousHash;
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return arrayBufferToHex(hash);
}
```

---

## 6. Multi-Enrollment Support

### Problem in V1

```typescript
// V1: Single passphrase OR single passkey
// To add second method:
// 1. Must be unlocked (persistent state)
// 2. Reuse in-memory MS
// 3. If lost unlock, must RESET (data loss!)
```

**Scenarios:**

1. User sets up passphrase, wants to add passkey → must enter passphrase, stay "unlocked", then add passkey
2. User has passkey on phone, gets new phone → can't add second passkey without reset
3. User wants multiple passkeys (phone + YubiKey) → V1 doesn't support

### V2 Solution

```typescript
// V2: Multi-enrollment (N credentials → 1 MS)
interface MultiEnrollmentConfig {
  kmsVersion: 2;
  enrollments: Array<EnrollmentConfig>;
}

type EnrollmentConfig =
  | PassphraseConfig
  | PasskeyPrfConfig
  | PasskeyGateConfig;

// Each enrollment has same MS, different KEK
// MS stored encrypted N times (once per KEK)
```

**Setup Flow:**

```typescript
// 1. First enrollment (generates MS)
const passphraseResult = await setupPassphrase('my-password');
// passphraseResult.ms is the generated MS

// 2. Second enrollment (reuses MS)
// User must authenticate with first method
const credentials: AuthCredentials = {
  method: 'passphrase',
  passphrase: 'my-password'
};

// Unlock to get MS
const { result: ms } = await withUnlock(credentials, async (mkek) => {
  // Inside unlock context, we have MS
  // Export MS for re-encryption (only time MS is "extracted")
  return ms;  // MS is returned but immediately re-encrypted
});

// Setup second method with existing MS
const passkeyResult = await setupPasskeyPRF({
  rpId: 'example.com',
  rpName: 'Example',
  existingMS: ms  // ← Reuse MS
});

// Now user can unlock with either method
```

**Storage Structure:**

```typescript
// IndexedDB: meta store
{
  'passphraseConfig': {
    kmsVersion: 2,
    method: 'passphrase',
    encryptedMS: ArrayBuffer,  // MS encrypted with passphrase KEK
    // ... other fields
  },

  'passkeyPrfConfig_abc123': {
    kmsVersion: 2,
    method: 'passkey-prf',
    credentialId: 'abc123',
    encryptedMS: ArrayBuffer,  // SAME MS, encrypted with passkey KEK
    // ... other fields
  },

  'passkeyPrfConfig_def456': {
    kmsVersion: 2,
    method: 'passkey-prf',
    credentialId: 'def456',
    encryptedMS: ArrayBuffer,  // SAME MS, different KEK
    // ... other fields
  }
}
```

**Security Properties:**

- **Same MS**: All methods decrypt to identical MS (deterministic MKEK)
- **Independent KEKs**: Compromising one method doesn't compromise others
- **Flexible unlock**: User can use any enrolled method
- **Graceful degradation**: If passkey stops working, fall back to passphrase

**Enrollment Management:**

```typescript
// Add new enrollment (requires auth with existing method)
async function addEnrollment(
  newMethod: 'passphrase' | 'passkey-prf' | 'passkey-gate',
  newMethodParams: unknown,
  existingCredentials: AuthCredentials
): Promise<{ success: boolean }> {
  // 1. Unlock with existing credentials to get MS
  const { result: ms } = await withUnlock(existingCredentials, async (mkek) => {
    // MS is available here
    // (This is the only time MS is "exported" from withUnlock)
    return new Uint8Array(ms);  // Copy MS bytes
  });

  try {
    // 2. Setup new method with existing MS
    switch (newMethod) {
      case 'passphrase':
        await setupPassphrase(newMethodParams.passphrase, ms);
        break;
      case 'passkey-prf':
        await setupPasskeyPRF(newMethodParams.credentialId, newMethodParams.prfOutput, ms);
        break;
      case 'passkey-gate':
        await setupPasskeyGate(newMethodParams.credentialId, ms);
        break;
    }

    return { success: true };
  } finally {
    // Clear MS immediately
    ms.fill(0);
  }
}

// Remove enrollment (requires auth with remaining method)
async function removeEnrollment(
  methodToRemove: string,
  authCredentials: AuthCredentials
): Promise<{ success: boolean }> {
  // Verify auth with different method
  if (authCredentials.method === methodToRemove) {
    throw new Error('Cannot remove method used for authentication');
  }

  // Verify can still unlock
  await withUnlock(authCredentials, async (mkek) => {
    // Unlock successful, safe to remove other method
  });

  // Delete config
  await deleteMeta(`${methodToRemove}Config`);
  return { success: true };
}
```

---

## 7. Enhanced Passkey Gate-Only

### Problem in V1

```typescript
// V1: Gate-only mode
// KEK = HKDF(passphrase, salt, info)
// MS encrypted with KEK

// Issue: If authenticator lacks PRF, user provides passphrase
// → Offline attack surface is entire passphrase entropy
// → WebAuthn ceremony provides NO cryptographic material
```

### V2 Solution: Pepper-Based Gate

```typescript
// V2: Enhance gate-only with random pepper
// Setup:
// 1. Generate random pepper (32 bytes)
// 2. Store pepper encrypted, gated by WebAuthn ceremony
// 3. KEK = HKDF(passphrase || pepper, salt, info)

// Unlock:
// 1. User performs WebAuthn ceremony (proves possession)
// 2. On success, release encrypted pepper
// 3. User provides passphrase
// 4. Derive KEK from (passphrase || pepper)
// 5. Decrypt MS

interface PasskeyGateConfigV2 {
  kmsVersion: 2;
  method: 'passkey-gate';

  credentialId: ArrayBuffer;    // For gate ceremony
  rpId: string;

  // Pepper protection
  encryptedPepper: ArrayBuffer;  // Encrypted with gate-specific KEK
  pepperIV: ArrayBuffer;
  pepperAAD: ArrayBuffer;

  // MS encryption (KEK derived from passphrase || pepper)
  kdf: {
    algorithm: 'HKDF-SHA256';
    salt: ArrayBuffer(32);
    info: 'ATS/KMS/KEK-gate/v2';
  };
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;

  createdAt: number;
  updatedAt: number;
}
```

**Setup Algorithm:**

```typescript
async function setupPasskeyGate(
  credentialId: ArrayBuffer,
  passphrase: string,
  existingMS?: Uint8Array
): Promise<{ success: boolean; ms: Uint8Array }> {
  // 1. Generate random pepper
  const pepper = crypto.getRandomValues(new Uint8Array(32));

  // 2. Derive gate KEK (from credential ID hash, deterministic)
  const gateKEK = await deriveGateKEK(credentialId);

  // 3. Encrypt pepper with gate KEK
  const pepperIV = crypto.getRandomValues(new Uint8Array(12));
  const pepperAAD = new TextEncoder().encode(JSON.stringify({
    kmsVersion: 2,
    purpose: 'pepper-wrap',
    credentialId: arrayBufferToBase64url(credentialId)
  }));

  const encryptedPepper = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: pepperIV,
      additionalData: pepperAAD
    },
    gateKEK,
    pepper
  );

  // 4. Derive MS KEK from (passphrase || pepper)
  const combined = new Uint8Array(passphrase.length + pepper.length);
  combined.set(new TextEncoder().encode(passphrase), 0);
  combined.set(pepper, passphrase.length);

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const msKEK = await deriveKEK(combined, salt, 'ATS/KMS/KEK-gate/v2');

  // 5. Encrypt MS (generate new if first method, reuse if second)
  const ms = existingMS || crypto.getRandomValues(new Uint8Array(32));
  const msIV = crypto.getRandomValues(new Uint8Array(12));
  const msAAD = new TextEncoder().encode(JSON.stringify({
    kmsVersion: 2,
    method: 'passkey-gate',
    algVersion: 1,
    credentialId: arrayBufferToBase64url(credentialId),
    purpose: 'master-secret-wrap'
  }));

  const encryptedMS = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: msIV,
      additionalData: msAAD
    },
    msKEK,
    ms
  );

  // 6. Store config
  await putMeta('passkeyGateConfig', {
    kmsVersion: 2,
    method: 'passkey-gate',
    credentialId,
    rpId: config.rpId,
    encryptedPepper,
    pepperIV: pepperIV.buffer,
    pepperAAD: pepperAAD.buffer,
    kdf: {
      algorithm: 'HKDF-SHA256',
      salt: salt.buffer,
      info: 'ATS/KMS/KEK-gate/v2'
    },
    encryptedMS,
    msIV: msIV.buffer,
    msAAD: msAAD.buffer,
    createdAt: Date.now(),
    updatedAt: Date.now()
  });

  return { success: true, ms };
}
```

**Unlock Algorithm:**

```typescript
async function unlockWithPasskeyGate(
  passphrase: string
): Promise<{ success: boolean; ms: Uint8Array }> {
  const config = await getMeta<PasskeyGateConfigV2>('passkeyGateConfig');

  // 1. Derive gate KEK (deterministic from credential ID)
  const gateKEK = await deriveGateKEK(config.credentialId);

  // 2. Decrypt pepper (WebAuthn gate already passed by client)
  const pepperBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(config.pepperIV),
      additionalData: new Uint8Array(config.pepperAAD)
    },
    gateKEK,
    config.encryptedPepper
  );
  const pepper = new Uint8Array(pepperBuffer);

  try {
    // 3. Derive MS KEK from (passphrase || pepper)
    const combined = new Uint8Array(passphrase.length + pepper.length);
    combined.set(new TextEncoder().encode(passphrase), 0);
    combined.set(pepper, passphrase.length);

    const msKEK = await deriveKEK(
      combined,
      new Uint8Array(config.kdf.salt),
      config.kdf.info
    );

    // 4. Decrypt MS
    const msBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(config.msIV),
        additionalData: new Uint8Array(config.msAAD)
      },
      msKEK,
      config.encryptedMS
    );

    return { success: true, ms: new Uint8Array(msBuffer) };
  } finally {
    // Clear pepper
    pepper.fill(0);
  }
}
```

**Security Analysis:**

**Without pepper (V1):**
- Attacker with local IndexedDB access can enumerate passphrases
- Work factor = HKDF only (negligible)
- No benefit from WebAuthn (just a gate, no crypto material)

**With pepper (V2):**
- Attacker needs:
  1. Local IndexedDB access (encryptedMS, encryptedPepper)
  2. Credential ID (for deriving gate KEK)
  3. WebAuthn ceremony success (to decrypt pepper)
- Work factor = WebAuthn ceremony + passphrase entropy
- Much harder to attack offline

**Trade-offs:**
- Still weaker than PRF (pepper is stored locally)
- Better than V1 gate (adds second factor)
- Best available for authenticators without PRF support

---

## 8. Extractability Window Management

### Problem in V1

```typescript
// V1: Key generated as extractable for wrapping
const keypair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,  // ← Extractable!
  ['sign', 'verify']
);

// Small window where key is extractable in memory
await wrapKey(keypair.privateKey, mkek, kid);
// After wrapping, reference dropped, but was extractable during generation
```

**Risk:**
- If attacker has code execution during this window, can export key
- All EC keys for wrapping *must* be generated as `extractable: true`
- WebCrypto requirement: `wrapKey('jwk', ...)` needs extractable key

### V2 Improvements

**Document and minimize:**

```typescript
// V2: Minimize extractability window
async function generateAndWrapVAPID(mkek: CryptoKey): Promise<VAPIDKeyPair> {
  // EXTRACTABILITY WINDOW BEGINS
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,  // Must be true for wrapKey('jwk', ...)
    ['sign', 'verify']
  );

  // Export public key immediately
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
  const kid = await generateKid(new Uint8Array(publicKeyRaw));

  // Wrap private key immediately (inside withUnlock context)
  const wrappedKey = await crypto.subtle.wrapKey(
    'jwk',
    keypair.privateKey,
    mkek,
    {
      name: 'AES-GCM',
      iv: crypto.getRandomValues(new Uint8Array(12)),
      additionalData: new TextEncoder().encode(JSON.stringify({
        kmsVersion: 2,
        kid,
        alg: 'ES256',
        purpose: 'vapid',
        createdAt: Date.now(),
        keyType: 'application-key'
      }))
    }
  );

  // EXTRACTABILITY WINDOW ENDS (reference dropped)
  // Private key object is now unreachable, garbage collected

  // Store wrapped key
  await storeWrappedKey(kid, wrappedKey, publicKeyRaw);

  return {
    kid,
    publicKey: arrayBufferToBase64url(publicKeyRaw)
  };
}
```

**Alternative Pattern (if paranoid):**

```typescript
// Generate → Export JWK → Import non-extractable → Wrap
async function generateAndWrapVAPIDAlternative(mkek: CryptoKey): Promise<VAPIDKeyPair> {
  // 1. Generate as extractable
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );

  // 2. Export as JWK immediately
  const jwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);

  // 3. Re-import as NON-extractable
  const nonExtractableKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,  // ← Non-extractable!
    ['sign']
  );

  // 4. Wrap the non-extractable key
  // (Still uses JWK format internally, but key object is non-extractable)
  const wrappedKey = await crypto.subtle.wrapKey(
    'jwk',
    nonExtractableKey,
    mkek,
    { name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) }
  );

  // Original keypair and JWK no longer referenced
  return { kid, wrappedKey };
}
```

**Threat Model Documentation:**

```markdown
## Extractability Window

**Risk**: EC private keys generated for wrapping must be `extractable: true` due to WebCrypto API constraints. This creates a small window where the key could be exported if an attacker gains code execution in the worker.

**Window Duration**: ~5-50ms (generate + wrap + drop reference)

**Mitigations**:
1. Operations inside `withUnlock` (MS/MKEK only exist during this window)
2. Worker isolation (no DOM, sandboxed iframe, cross-origin)
3. Immediate wrapping (minimize window)
4. Reference dropped after wrap (garbage collection)
5. Non-extractable after unwrap (persistent form is safe)

**Attack Requirements**:
- Code execution in worker context
- Timing: within ~50ms of key generation
- Ability to call `crypto.subtle.exportKey()` before reference dropped

**Defense Layers**:
1. Cross-origin isolation (blocks XSS from PWA)
2. Sandboxed iframe (blocks navigation, forms, popups)
3. Dedicated Worker (no DOM, no phishing surface)
4. CSP (blocks inline scripts)
5. SRI (blocks code tampering)
6. Runtime self-check (detects modified worker.js)
```

---

## 9. Proper Type Safety

### Problem in V1

```typescript
// V1: Incorrect Uint8Array type
let ms: Uint8Array<ArrayBuffer> | null = null;
//                  ^^^^^^^^^^^^^ Not valid!

// Uint8Array doesn't have a generic parameter
```

**Issues:**
- TypeScript error in strict mode
- Confusing type signature
- Doesn't actually enforce ArrayBuffer backing

### V2 Solution

```typescript
// V2: Correct types
let ms: Uint8Array | null = null;

// Uint8Array is always backed by ArrayBuffer
// TypedArrays have .buffer property: ArrayBuffer
```

**Proper TypedArray Usage:**

```typescript
// Creating Uint8Array
const ms = crypto.getRandomValues(new Uint8Array(32));
// ms.buffer is ArrayBuffer
// ms.byteOffset is 0
// ms.byteLength is 32

// Decrypting to ArrayBuffer, wrapping in Uint8Array
const msBuffer: ArrayBuffer = await crypto.subtle.decrypt(/*...*/);
const ms: Uint8Array = new Uint8Array(msBuffer);

// Accessing underlying buffer
console.log(ms.buffer === msBuffer);  // true

// Zeroizing
ms.fill(0);  // Overwrites backing ArrayBuffer
```

**postMessage and Buffer Transfer:**

```typescript
// IMPORTANT: Never postMessage buffers with secrets!
// If you must, transfer ownership:

// BAD: Copies buffer, sender retains access
postMessage({ ms: ms.buffer }, '*');
// Attacker can still access ms in sender!

// GOOD: Transfer ownership (sender loses access)
postMessage({ ms: ms.buffer }, '*', [ms.buffer]);
// ms.buffer is now detached, cannot access

// BEST: Don't postMessage secrets at all
// Keep MS local to worker, never send to parent/iframe
```

---

## 10. Explicit Versioning

### Problem in V1

```typescript
// V1: No version metadata
interface Config {
  method: 'passphrase';
  salt: ArrayBuffer;
  iterations: 600000;
  encryptedMS: ArrayBuffer;
  // ... no version fields!
}

// How to migrate? How to detect old configs?
```

### V2 Solution

```typescript
// V2: Explicit versioning everywhere
interface ConfigV2 {
  kmsVersion: 2;               // Major KMS version
  algVersion: 1;               // Algorithm version (per method)
  method: 'passphrase';

  // Algorithm parameters (versioned)
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';  // Explicit
    iterations: number;
    salt: ArrayBuffer;
    // If we switch to Argon2id later:
    // algorithm: 'Argon2id';
    // t: 2; m: 65536; p: 1;
  };

  // Encryption metadata
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: 1;                // Re-encryption tracking

  // Timestamps
  createdAt: number;
  updatedAt: number;
}
```

**Migration Strategy:**

```typescript
// Detect version
async function loadConfig(key: string): Promise<ConfigV2> {
  const raw = await getMeta(key);

  // Check version
  if (!raw.kmsVersion) {
    // V1 config - must migrate or reset
    throw new Error('V1_CONFIG_DETECTED: Please reset KMS');
  }

  if (raw.kmsVersion === 2) {
    return raw as ConfigV2;
  }

  throw new Error(`UNKNOWN_VERSION: ${raw.kmsVersion}`);
}

// Future: V2 → V3 migration
async function migrateV2ToV3(configV2: ConfigV2, credentials: AuthCredentials): Promise<ConfigV3> {
  // 1. Unlock with V2
  const { result: ms } = await withUnlockV2(credentials, async (mkek) => ms);

  // 2. Re-encrypt with V3 parameters
  const kekV3 = await deriveKEKV3(/*...*/);
  const encryptedMSV3 = await encryptMSV3(ms, kekV3);

  // 3. Create V3 config
  return {
    kmsVersion: 3,
    algVersion: 1,
    // ... V3 fields
    encryptedMS: encryptedMSV3,
    migratedFrom: {
      kmsVersion: 2,
      migratedAt: Date.now()
    }
  };
}
```

**Version Compatibility Matrix:**

```typescript
const SUPPORTED_VERSIONS = {
  kmsVersion: [2],           // Current major version
  algVersion: {
    passphrase: [1],         // PBKDF2 with calibration
    'passkey-prf': [1],      // HKDF-SHA256
    'passkey-gate': [1]      // Enhanced with pepper
  },
  auditVersion: [2]          // Hardened audit log
};

function isSupported(config: unknown): boolean {
  return (
    SUPPORTED_VERSIONS.kmsVersion.includes(config.kmsVersion) &&
    SUPPORTED_VERSIONS.algVersion[config.method].includes(config.algVersion)
  );
}
```

---

## Summary: Don't Ship Without These

### Critical (Must Fix)

1. **AAD everywhere** - Prevents ciphertext replay/swap
2. **KCV for password verification** - Constant-time, standard
3. **Calibrated PBKDF2** - Consistent security across devices
4. **Deterministic HKDF salts** - Enables rotation paths
5. **Audit sequence numbers** - Detects truncation
6. **Non-extractable audit key** - Prevents forgery

### Important (Strongly Recommended)

7. **Multi-enrollment** - Better UX, recovery options
8. **Enhanced gate-only** - Pepper protects offline attacks
9. **Versioning** - Future-proof, migration-ready
10. **Type safety** - Correct TypeScript types

### Nice to Have (Optional)

- Argon2id support (progressive enhancement)
- Periodic audit anchors (external checkpoints)
- Export ceremonies (backup/restore)

---

**Next**: See [implementation-checklist.md](./implementation-checklist.md) for step-by-step implementation guide.
