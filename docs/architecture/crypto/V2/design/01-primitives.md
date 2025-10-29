# Cryptographic Primitives (V2)

**Status**: Design Phase
**Version**: V2
**Date**: 2025-10-24

---

## Overview

This document specifies all cryptographic primitives used in the KMS V2 architecture, including algorithms, parameters, and implementation details for each primitive.

**V2 Improvements:**
- Calibrated PBKDF2 (device-specific iterations targeting 150-300ms)
- Standard KCV (Key Check Value) instead of custom verification
- AAD (Additional Authenticated Data) for all AES-GCM operations
- Deterministic HKDF salts (non-zero, versioned)
- Hardened audit with Ed25519 non-extractable keys

---

## 1. Key Derivation Functions (KDFs)

### 1.1 PBKDF2-HMAC-SHA256 (Passphrase → KEK)

**Purpose**: Derive encryption key from user passphrase

**Algorithm**: PBKDF2 (Password-Based Key Derivation Function 2)

**Parameters:**
```typescript
{
  algorithm: 'PBKDF2',
  hash: 'SHA-256',          // PRF: HMAC-SHA256
  salt: ArrayBuffer(16),    // 128-bit random salt (unique per user)
  iterations: number,        // Calibrated per device (see calibration.md)
  length: 256                // Output: 256-bit key
}
```

**V2 Changes:**
- **Calibrated iterations** (NOT fixed 600,000)
- Target: 150-300ms on current device
- Stored in config: `{ iterations, lastCalibratedAt, platformHash }`
- Floor: 50,000, Ceiling: 2,000,000

**Implementation:**
```typescript
async function deriveKEKFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  const kek = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,  // non-extractable
    ['encrypt', 'decrypt']
  );

  return kek;
}
```

**Security Properties:**
- ✅ Calibrated iterations resist offline attacks proportional to device performance
- ✅ 128-bit salt prevents rainbow tables
- ✅ HMAC-SHA256 provides good mixing
- ✅ Non-extractable output key

**Considerations:**
- Prefer **Argon2id** if WASM is acceptable (memory-hard, better resistance)
- Calibration algorithm in [07-calibration.md](./07-calibration.md)
- Re-calibrate every 30 days or on platform change

---

### 1.2 HKDF-SHA256 (Expand-Only)

**Purpose**: Derive keys from high-entropy input (PRF output, MS)

**Algorithm**: HKDF (HMAC-based Key Derivation Function) - Expand-only mode

**Use Cases:**
1. Passkey PRF output → KEK
2. Master Secret (MS) → MKEK (Master Key Encryption Key)
3. Future: Session key derivation

**Parameters:**
```typescript
{
  algorithm: 'HKDF',
  hash: 'SHA-256',
  salt: ArrayBuffer(32),     // Non-zero, deterministic (V2 change!)
  info: string,              // Context-specific label
  length: 256                // Output: 256-bit key
}
```

**V2 Changes:**
- **Non-zero salts** (deterministic, versioned)
- **Distinct salts** for each use case
- Salt derivation: `SHA-256("ATS/KMS/<context>/salt/v1")`

**Example Salts:**
```typescript
// MKEK derivation from MS
const MKEK_SALT = SHA256("ATS/KMS/MKEK/salt/v2");  // 32 bytes, deterministic

// KEK derivation from passkey PRF
const PRF_KEK_SALT = SHA256("ATS/KMS/KEK-wrap/salt/v2");  // 32 bytes, deterministic
```

**Implementation:**
```typescript
async function deriveKEKFromPRF(
  prfOutput: Uint8Array,  // 32 bytes from WebAuthn PRF
  salt: Uint8Array,       // 32 bytes, deterministic
  info: string            // e.g., "ATS/KMS/KEK-wrap/v2"
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    'raw',
    prfOutput,
    'HKDF',
    false,
    ['deriveKey']
  );

  const kek = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt,
      info: new TextEncoder().encode(info),
      hash: 'SHA-256'
    },
    ikm,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,  // non-extractable
    ['encrypt', 'decrypt']
  );

  return kek;
}
```

**Security Properties:**
- ✅ Domain separation via `info` strings
- ✅ Deterministic salt allows key rotation paths
- ✅ SHA-256 provides strong mixing
- ✅ Non-extractable output keys

**Info Strings (V2):**
```typescript
// KEK derivation
"ATS/KMS/KEK-wrap/v2"       // Passkey PRF → KEK
"ATS/KMS/KEK-gate/v2"       // Gate-only fallback

// MKEK derivation
"ATS/KMS/MKEK/v2"           // MS → MKEK

// Future
"ATS/KMS/Session/<sid>/v2"  // Session key derivation
```

---

### 1.3 WebAuthn PRF Requirements

**Purpose**: Define security requirements for WebAuthn PRF-based key derivation.

**CRITICAL**: When WebAuthn PRF is available, user verification (UV) MUST be required for all operations.

#### UV Requirement

```typescript
/**
 * WebAuthn PRF credential creation.
 *
 * SECURITY REQUIREMENTS:
 * - userVerification: "required" (MUST be set)
 * - Biometric or PIN verification enforced
 * - Platform authenticator recommended (device-bound)
 * - PRF extension enabled
 */
async function createPasskeyWithPRF(
  userId: string,
  userName: string
): Promise<{ credentialId: ArrayBuffer; appSalt: Uint8Array }> {
  // Generate deterministic app salt for PRF
  const appSalt = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`ATS/KMS/PRF-salt/${userId}/v2`)
  );

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: 'kms.ats.run', name: 'ATS KMS' },
      user: {
        id: new TextEncoder().encode(userId),
        name: userName,
        displayName: userName
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256
      authenticatorSelection: {
        userVerification: 'required',    // CRITICAL: UV required
        residentKey: 'required',
        authenticatorAttachment: 'platform'
      },
      extensions: {
        prf: {}  // Enable PRF extension
      }
    }
  });

  return {
    credentialId: credential.rawId,
    appSalt: new Uint8Array(appSalt)
  };
}

/**
 * WebAuthn PRF unlock attempt.
 *
 * SECURITY REQUIREMENTS:
 * - userVerification: "required" (MUST be set)
 * - PRF eval with deterministic appSalt
 */
async function unlockWithPRF(
  credentialId: ArrayBuffer,
  appSalt: Uint8Array
): Promise<Uint8Array> {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      rpId: 'kms.ats.run',
      userVerification: 'required',    // CRITICAL: UV required
      extensions: {
        prf: {
          eval: {
            first: appSalt
          }
        }
      }
    }
  });

  // Extract PRF output
  const prfResults = assertion.getClientExtensionResults().prf;
  if (!prfResults?.results?.first) {
    throw new Error('PRF extension not available or failed');
  }

  return new Uint8Array(prfResults.results.first);
}
```

#### Fallback "Gate-Only" Mode

**When PRF is NOT available**, a fallback "gate-only" mode MAY be used:

```typescript
/**
 * Gate-only mode: WebAuthn gates pepper decryption, no PRF.
 *
 * SECURITY CONSIDERATIONS:
 * - Less secure than PRF (pepper stored encrypted, not derived)
 * - Rate-limited to prevent abuse
 * - Flagged in telemetry and UI
 * - User must understand security trade-off
 */
async function unlockWithGateOnly(
  credentialId: ArrayBuffer,
  passphrase: string,
  encryptedPepper: EncryptedPepper
): Promise<CryptoKey> {
  // Step 1: WebAuthn assertion (gates access, no PRF)
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      rpId: 'kms.ats.run',
      userVerification: 'required'  // Still require UV
    }
  });

  // WebAuthn success means user verified
  // (but we don't have PRF output to derive key)

  // Step 2: Decrypt pepper with passphrase-derived key
  // (Pepper was encrypted during setup)
  const pepperKey = await deriveKEKFromPassphrase(
    passphrase,
    encryptedPepper.salt,
    encryptedPepper.iterations
  );

  const pepper = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: encryptedPepper.iv,
      additionalData: encryptedPepper.aad
    },
    pepperKey,
    encryptedPepper.ciphertext
  );

  // Step 3: Combine passphrase + pepper → KEK
  const combined = new Uint8Array(
    passphrase.length + pepper.byteLength
  );
  combined.set(new TextEncoder().encode(passphrase), 0);
  combined.set(new Uint8Array(pepper), passphrase.length);

  const kek = await deriveKEKFromPassphrase(
    new TextDecoder().decode(combined),
    encryptedPepper.kekSalt,
    encryptedPepper.kekIterations
  );

  // Zero sensitive data
  combined.fill(0);

  return kek;
}
```

#### Rate Limiting for Gate-Only Mode

```typescript
/**
 * Rate limit gate-only unlock attempts.
 *
 * RATIONALE:
 * - Gate-only is less secure than PRF
 * - Pepper may be weaker than PRF output
 * - Limit attempts to prevent brute force
 */
interface GateOnlyRateLimiter {
  attemptsLastHour: number;
  maxAttemptsPerHour: 20;  // Stricter than PRF mode
  lastAttempt: number;
}

function enforceGateOnlyRateLimit(): boolean {
  const state = loadRateLimitState();
  const now = Date.now();

  // Reset counter if more than 1 hour passed
  if (now - state.lastAttempt > 3600_000) {
    state.attemptsLastHour = 0;
  }

  if (state.attemptsLastHour >= state.maxAttemptsPerHour) {
    return false; // Rate limit exceeded
  }

  state.attemptsLastHour++;
  state.lastAttempt = now;
  saveRateLimitState(state);

  return true;
}
```

#### Telemetry and UI Flags

**Gate-only mode MUST be clearly indicated:**

```typescript
interface UnlockTelemetry {
  method: 'passkey-prf' | 'passkey-gate';
  uvPerformed: boolean;
  prfAvailable: boolean;
  gateOnlyMode: boolean;
  timestamp: number;
}

// Log to audit
await audit.log({
  op: 'unlock',
  method: telemetry.method,
  gateOnlyMode: telemetry.gateOnlyMode,  // Flag for review
  uvPerformed: telemetry.uvPerformed
});

// UI warning (if gate-only)
if (telemetry.gateOnlyMode) {
  console.warn('⚠️ Gate-only mode: PRF not available, using fallback');
  // Display in-app badge: "Enhanced security unavailable"
}
```

---

## 2. Symmetric Encryption

### 2.1 AES-256-GCM

**Purpose**: Authenticated encryption for MS, wrapped keys, and data

**Algorithm**: AES in Galois/Counter Mode (GCM)

**Parameters:**
```typescript
{
  name: 'AES-GCM',
  length: 256,               // 256-bit key
  iv: ArrayBuffer(12),       // 96-bit IV (unique per encryption!)
  additionalData: ArrayBuffer, // AAD (V2: REQUIRED for all encryptions)
  tagLength: 128             // 128-bit authentication tag
}
```

**V2 Changes:**
- **AAD REQUIRED** for all encryptions (metadata binding)
- **Fresh IV** on every encryption (never reuse with same key)
- **Version tracking** (msVersion, keyVersion) for re-encryption

**AAD Construction:**

**For encrypted MS:**
```typescript
function buildMSEncryptionAAD(config: {
  kmsVersion: number;
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  algVersion: number;
  purpose: 'master-secret-wrap';
  credentialId?: string;  // For passkey methods
}): ArrayBuffer {
  // Canonical JSON (sorted keys, no whitespace)
  const aadObj = {
    algVersion: config.algVersion,
    credentialId: config.credentialId || null,
    kmsVersion: config.kmsVersion,
    method: config.method,
    purpose: config.purpose
  };

  const aadJson = JSON.stringify(aadObj);  // Keys already sorted
  return new TextEncoder().encode(aadJson);
}
```

**For wrapped application keys:**
```typescript
function buildKeyWrapAAD(meta: {
  kid: string;
  alg: 'ES256' | 'EdDSA';
  purpose: 'vapid' | 'audit' | 'identity';
  createdAt: number;
  kmsVersion: number;
}): ArrayBuffer {
  const aadObj = {
    alg: meta.alg,
    createdAt: meta.createdAt,
    kid: meta.kid,
    kmsVersion: meta.kmsVersion,
    purpose: meta.purpose
  };

  const aadJson = JSON.stringify(aadObj);
  return new TextEncoder().encode(aadJson);
}
```

**Implementation:**
```typescript
async function encryptMS(
  ms: Uint8Array,
  kek: CryptoKey,
  aad: ArrayBuffer
): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }> {
  // Generate fresh IV (96 bits)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt with AAD
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,  // V2: Required!
      tagLength: 128
    },
    kek,
    ms
  );

  return { ciphertext, iv };
}

async function decryptMS(
  ciphertext: ArrayBuffer,
  kek: CryptoKey,
  iv: ArrayBuffer,
  aad: ArrayBuffer
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,  // V2: Must match encryption AAD!
      tagLength: 128
    },
    kek,
    ciphertext
  );

  return new Uint8Array(plaintext);
}
```

**Security Properties:**
- ✅ Authenticated encryption (confidentiality + integrity)
- ✅ AAD binds ciphertext to metadata (prevents swapping)
- ✅ 128-bit tag provides strong authentication
- ✅ GCM mode is parallelizable (fast)

**Critical Requirements:**
- ⚠️ **NEVER reuse IV** with same key (catastrophic failure)
- ⚠️ **AAD must be identical** for encrypt/decrypt
- ⚠️ **Generate fresh IV** on every encryption (even re-encrypting same data)

---

### 2.2 AES-GCM AAD Schemas

**Purpose**: Define exact AAD structure for all AES-GCM operations to ensure consistency and prevent mismatches.

**Version**: All AAD uses `aadVersion: 1` for V2.

#### AAD Schema for MS Ciphertext

```typescript
interface MSEncryptionAAD {
  aadVersion: 1;
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  kdf: 'pbkdf2' | 'argon2id' | 'webauthn-prf';
  kdfParams: string;    // Stable-serialized parameters (JSON with sorted keys)
  kmsVersion: 2;
}
```

**Example:**
```json
{
  "aadVersion": 1,
  "method": "passphrase",
  "kdf": "pbkdf2",
  "kdfParams": "{\"hash\":\"SHA-256\",\"iterations\":240000}",
  "kmsVersion": 2
}
```

#### AAD Schema for Wrapped Keys

```typescript
interface WrappedKeyAAD {
  aadVersion: 1;
  recordType: 'wrapped-key';
  kid: string;          // Base64url key identifier
  alg: 'ES256' | 'EdDSA';
  purpose: 'vapid' | 'signal' | 'audit';
  kmsVersion: 2;
  createdAt: number;    // Unix timestamp (ms)
}
```

**Example:**
```json
{
  "aadVersion": 1,
  "recordType": "wrapped-key",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "alg": "ES256",
  "purpose": "vapid",
  "kmsVersion": 2,
  "createdAt": 1704067200000
}
```

#### Canonicalization Rules

**CRITICAL**: AAD must be canonicalized identically for encryption and decryption.

```typescript
/**
 * Build canonical AAD for AES-GCM operations.
 *
 * RULES:
 * - UTF-8 encoded JSON
 * - Object keys sorted alphabetically
 * - No whitespace (compact JSON)
 * - Consistent field ordering
 */
function buildCanonicalAAD(aad: object): Uint8Array {
  // Sort keys alphabetically
  const sorted = Object.keys(aad).sort();

  // Build canonical JSON (no whitespace)
  const canonical = JSON.stringify(aad, sorted);

  // UTF-8 encode
  return new TextEncoder().encode(canonical);
}
```

#### AAD Mismatch Behavior

**Decryption MUST FAIL if AAD mismatches:**

```typescript
/**
 * Decrypt with AAD verification.
 *
 * SECURITY: Any AAD mismatch causes decryption to fail.
 * This includes:
 * - Different aadVersion
 * - Different field values
 * - Different field ordering
 * - Missing or extra fields
 */
async function decryptWithAAD(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  iv: ArrayBuffer,
  aad: ArrayBuffer
): Promise<Uint8Array> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad,  // Must match encryption AAD exactly
        tagLength: 128
      },
      key,
      ciphertext
    );
    return new Uint8Array(plaintext);
  } catch (err) {
    // GCM authentication tag verification failed
    // This indicates:
    // 1. Wrong key
    // 2. Corrupted ciphertext
    // 3. AAD mismatch
    // 4. IV mismatch
    throw new Error('Decryption failed: AAD or key mismatch');
  }
}
```

#### Tests for AAD

```typescript
describe('AAD Verification', () => {
  it('should decrypt successfully with exact AAD', async () => {
    const aad = buildCanonicalAAD({
      aadVersion: 1,
      method: 'passphrase',
      kdf: 'pbkdf2',
      kdfParams: '{"hash":"SHA-256","iterations":240000}',
      kmsVersion: 2
    });

    const { ciphertext, iv } = await encrypt(data, key, aad);
    const decrypted = await decrypt(ciphertext, key, iv, aad);

    expect(decrypted).toEqual(data);
  });

  it('should fail if any AAD field changes', async () => {
    const originalAAD = buildCanonicalAAD({
      aadVersion: 1,
      method: 'passphrase',
      kdf: 'pbkdf2',
      kdfParams: '{"hash":"SHA-256","iterations":240000}',
      kmsVersion: 2
    });

    const { ciphertext, iv } = await encrypt(data, key, originalAAD);

    // Change iterations
    const modifiedAAD = buildCanonicalAAD({
      aadVersion: 1,
      method: 'passphrase',
      kdf: 'pbkdf2',
      kdfParams: '{"hash":"SHA-256","iterations":250000}',  // Changed!
      kmsVersion: 2
    });

    await expect(decrypt(ciphertext, key, iv, modifiedAAD))
      .rejects.toThrow('AAD or key mismatch');
  });

  it('should fail if aadVersion changes', async () => {
    const v1AAD = buildCanonicalAAD({ aadVersion: 1, ...fields });
    const { ciphertext, iv } = await encrypt(data, key, v1AAD);

    const v2AAD = buildCanonicalAAD({ aadVersion: 2, ...fields });

    await expect(decrypt(ciphertext, key, iv, v2AAD))
      .rejects.toThrow('AAD or key mismatch');
  });

  it('should fail if unknown aadVersion used', async () => {
    const unknownAAD = buildCanonicalAAD({ aadVersion: 99, ...fields });

    await expect(encrypt(data, key, unknownAAD))
      .rejects.toThrow('Unknown aadVersion');
  });
});
```

---

### 2.3 Key Check Value (KCV)

**Purpose**: Verify passphrase correctness without decrypting MS

**Algorithm**: HMAC-SHA256

**V2 Change**: Replace custom "verification hash" with standard KCV

**Implementation:**
```typescript
async function computeKCV(kek: CryptoKey): Promise<ArrayBuffer> {
  // Convert KEK to HMAC key (requires re-import from raw bytes)
  // Note: KEK is non-extractable, so we need to derive it again
  // This is done during setup when we have the passphrase

  const kcvKey = await crypto.subtle.importKey(
    'raw',
    await crypto.subtle.exportKey('raw', kek),  // Only during setup!
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  );

  const kcv = await crypto.subtle.sign(
    'HMAC',
    kcvKey,
    new TextEncoder().encode('ATS/KMS/KCV/v2')
  );

  return kcv;  // 32 bytes
}
```

**Alternative (if KEK is non-extractable):**
```typescript
// Derive KCV material alongside KEK during PBKDF2
async function deriveKEKWithKCV(
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<{ kek: CryptoKey; kcv: ArrayBuffer }> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive 512 bits total
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    512  // 64 bytes
  );

  // Split: first 32 bytes = KEK, last 32 bytes = KCV material
  const kekBytes = bits.slice(0, 32);
  const kcvMaterial = bits.slice(32, 64);

  // Import KEK as non-extractable
  const kek = await crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // Compute KCV from material
  const kcv = await crypto.subtle.digest('SHA-256', kcvMaterial);

  // Zero sensitive bytes
  new Uint8Array(bits).fill(0);
  new Uint8Array(kekBytes).fill(0);

  return { kek, kcv };
}
```

**Verification (constant-time):**
```typescript
function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const ua = new Uint8Array(a);
  const ub = new Uint8Array(b);

  if (ua.length !== ub.length) return false;

  let diff = 0;
  for (let i = 0; i < ua.length; i++) {
    diff |= ua[i] ^ ub[i];  // XOR accumulates differences
  }

  return diff === 0;  // Only true if all bytes match
}
```

**Usage:**
```typescript
// During setup
const { kek, kcv } = await deriveKEKWithKCV(passphrase, salt, iterations);
await storeMeta('passphraseConfig', {
  kcv: arrayBufferToHex(kcv),
  // ... other config
});

// During unlock (before attempting decryption)
const config = await getMeta('passphraseConfig');
const { kek, kcv } = await deriveKEKWithKCV(passphrase, config.salt, config.iterations);

if (!timingSafeEqual(kcv, hexToArrayBuffer(config.kcv))) {
  throw new Error('Invalid passphrase');  // Fast rejection without decryption
}

// Proceed with decryption...
```

**Benefits:**
- ✅ Standard approach (HMAC-based)
- ✅ Constant-time comparison (timing-safe)
- ✅ Fast rejection of wrong passphrase
- ✅ No custom crypto

---

## 3. Asymmetric Cryptography

### 3.1 ECDSA with P-256 (ES256)

**Purpose**: VAPID key generation and JWT signing

**Algorithm**: Elliptic Curve Digital Signature Algorithm

**Curve**: P-256 (secp256r1, NIST P-256)

**Parameters:**
```typescript
{
  name: 'ECDSA',
  namedCurve: 'P-256',
  hash: 'SHA-256'  // For ES256
}
```

**Key Generation:**
```typescript
async function generateVAPIDKeypair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,  // Temporarily extractable for wrapping only
    ['sign', 'verify']
  );
}
```

**Public Key Export:**
```typescript
async function exportPublicKeyRaw(publicKey: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(raw);
}

// Format: Uncompressed point (65 bytes)
// Byte 0: 0x04 (uncompressed indicator)
// Bytes 1-32: x-coordinate (big-endian)
// Bytes 33-64: y-coordinate (big-endian)
```

**Signing:**
```typescript
async function signES256(
  data: Uint8Array,
  privateKey: CryptoKey
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    privateKey,
    data
  );

  // Modern browsers return P-1363 format (64 bytes)
  // Validate format
  const signatureBytes = new Uint8Array(signature);
  if (signatureBytes.length !== 64) {
    throw new Error(`Invalid signature length: ${signatureBytes.length}`);
  }
  return signatureBytes;
}
```

**Signature Format Utilities:**

Modern browsers return P-1363 format natively. Utilities provided for edge cases:

```typescript
function convertDERtoP1363(derSig: Uint8Array): Uint8Array {
  // DER format: SEQUENCE { r INTEGER, s INTEGER }
  // P-1363 format: r || s (32 bytes each for P-256)

  if (derSig.length === 64) {
    return derSig;  // Already P-1363
  }

  // Parse DER
  let offset = 0;

  // SEQUENCE tag
  if (derSig[offset++] !== 0x30) {
    throw new Error('Invalid DER signature');
  }

  // SEQUENCE length
  const seqLen = derSig[offset++];

  // Parse r
  if (derSig[offset++] !== 0x02) {
    throw new Error('Invalid DER signature (r tag)');
  }
  const rLen = derSig[offset++];
  const r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s
  if (derSig[offset++] !== 0x02) {
    throw new Error('Invalid DER signature (s tag)');
  }
  const sLen = derSig[offset++];
  const s = derSig.slice(offset, offset + sLen);

  // Pad to 32 bytes if needed (remove leading zeros, then pad)
  const rPadded = padTo32Bytes(r);
  const sPadded = padTo32Bytes(s);

  // Concatenate
  const p1363 = new Uint8Array(64);
  p1363.set(rPadded, 0);
  p1363.set(sPadded, 32);

  return p1363;
}

function padTo32Bytes(value: Uint8Array): Uint8Array {
  // Remove leading zero bytes (DER encoding may add them)
  let start = 0;
  while (start < value.length && value[start] === 0) {
    start++;
  }

  const trimmed = value.slice(start);

  if (trimmed.length > 32) {
    throw new Error('Value too large for P-256');
  }

  // Pad with leading zeros to 32 bytes
  const padded = new Uint8Array(32);
  padded.set(trimmed, 32 - trimmed.length);

  return padded;
}
```

**Security Properties:**
- ✅ 128-bit security level (P-256)
- ✅ NIST-approved curve
- ✅ Wide browser support
- ✅ Compatible with Web Push / VAPID

**Note:** P-1363 conversion is **critical** for JWT interoperability!

---

### 3.2 Ed25519 (EdDSA)

**Purpose**: Audit log signing

**Algorithm**: Edwards-curve Digital Signature Algorithm with Curve25519

**Parameters:**
```typescript
{
  name: 'Ed25519'
}
```

**Key Generation:**
```typescript
async function generateAuditKeypair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'Ed25519'
    },
    false,  // V2: Non-extractable by default (with explicit backup ceremony)
    ['sign', 'verify']
  );
}
```

**Signing:**
```typescript
async function signAuditEntry(
  data: Uint8Array,
  privateKey: CryptoKey
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    'Ed25519',
    privateKey,
    data
  );

  return new Uint8Array(signature);  // 64 bytes, no conversion needed
}
```

**Verification:**
```typescript
async function verifyAuditSignature(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: CryptoKey
): Promise<boolean> {
  return await crypto.subtle.verify(
    'Ed25519',
    publicKey,
    signature,
    data
  );
}
```

**Security Properties:**
- ✅ 128-bit security level
- ✅ Fast signing and verification
- ✅ Deterministic signatures (no nonce generation)
- ✅ Smaller signatures (64 bytes)
- ✅ Simpler implementation (no DER conversion)

**Why Ed25519 for audit?**
- Faster than ECDSA (important for high-frequency logging)
- Deterministic (no RNG failure mode)
- Smaller public keys and signatures

---

## 4. Hash Functions

### 4.1 SHA-256

**Purpose**: General-purpose hashing, chain integrity, key fingerprints

**Uses:**
- Audit chain hashes
- JWK thumbprints (kid generation)
- Deterministic salt derivation
- KCV computation

**Implementation:**
```typescript
async function sha256(data: Uint8Array): Promise<ArrayBuffer> {
  return await crypto.subtle.digest('SHA-256', data);
}
```

**Properties:**
- Output: 256 bits (32 bytes)
- Collision resistance: ~128-bit security
- Pre-image resistance: 256-bit security

---

## 5. Encoding Utilities

### 5.1 Base64url

**Purpose**: URL-safe encoding for JWTs, keys, signatures

**Implementation:**
```typescript
function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);

  // Convert to URL-safe
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');  // Remove padding
}

function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
  // Add padding if needed
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const padding = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padding);

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}
```

---

## 6. Key Wrapping

### 6.1 AES-GCM Key Wrapping

**Purpose**: Wrap application keys under MKEK

**Implementation:**
```typescript
async function wrapKey(
  keyToWrap: CryptoKey,
  wrappingKey: CryptoKey,  // MKEK
  aad: ArrayBuffer
): Promise<{ wrappedKey: ArrayBuffer; iv: ArrayBuffer }> {
  // Generate fresh IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Wrap with AES-GCM
  const wrappedKey = await crypto.subtle.wrapKey(
    'jwk',  // Export as JWK before wrapping
    keyToWrap,
    wrappingKey,
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad  // V2: Bind to metadata
    }
  );

  return { wrappedKey, iv };
}

async function unwrapKey(
  wrappedKey: ArrayBuffer,
  wrappingKey: CryptoKey,  // MKEK
  iv: ArrayBuffer,
  aad: ArrayBuffer,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  return await crypto.subtle.unwrapKey(
    'jwk',
    wrappedKey,
    wrappingKey,
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad  // V2: Must match wrapping AAD!
    },
    algorithm,
    false,  // non-extractable after unwrapping
    usages
  );
}
```

**Extractability Window:**

During key generation, keys are temporarily extractable for wrapping:

```typescript
// 1. Generate (extractable: true)
const keypair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,  // Temporarily extractable
  ['sign', 'verify']
);

// 2. Immediately wrap
const { wrappedKey, iv } = await wrapKey(keypair.privateKey, mkek, aad);

// 3. Clear reference
keypair.privateKey = null;  // Garbage collected

// 4. Later unwrap as non-extractable
const privateKey = await unwrapKey(
  wrappedKey, mkek, iv, aad,
  { name: 'ECDSA', namedCurve: 'P-256' },
  ['sign']  // Non-extractable!
);
```

**Window duration:** Milliseconds (wrapped immediately after generation)

---

## 7. Summary Table

| Primitive | Algorithm | Key Size | Use Case | Notes |
|-----------|-----------|----------|----------|-------|
| **KDF (Passphrase)** | PBKDF2-HMAC-SHA256 | 256-bit output | Passphrase → KEK | Calibrated iterations (150-300ms) |
| **KDF (PRF/MS)** | HKDF-SHA256 | 256-bit output | High-entropy expansion | Deterministic salts (V2) |
| **Encryption** | AES-256-GCM | 256-bit key | MS, wrapped keys | AAD required (V2) |
| **KCV** | HMAC-SHA256 | 256-bit output | Passphrase verification | Standard approach (V2) |
| **Signing (VAPID)** | ECDSA P-256 | 256-bit | JWT signing | DER→P-1363 conversion! |
| **Signing (Audit)** | Ed25519 | 256-bit | Audit log | Faster than ECDSA |
| **Hashing** | SHA-256 | 256-bit output | General purpose | Chain integrity, kids |
| **Key Wrapping** | AES-GCM | 256-bit | Wrap under MKEK | AAD binding (V2) |

---

## Related Documentation

- [02-master-secret.md](./02-master-secret.md) - MS generation and encryption
- [03-unlock-context.md](./03-unlock-context.md) - withUnlock implementation
- [07-calibration.md](./07-calibration.md) - PBKDF2 calibration algorithm
- [Security Improvements](../security-improvements.md) - V2 rationale

---

**End of Cryptographic Primitives Specification**
