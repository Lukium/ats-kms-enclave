# Master Secret Management (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-01-24

---

## Table of Contents

1. [Overview](#overview)
2. [Master Secret (MS)](#master-secret-ms)
3. [KEK Derivation Methods](#kek-derivation-methods)
4. [Key Check Value (KCV)](#key-check-value-kcv)
5. [MS Encryption](#ms-encryption)
6. [MKEK Derivation](#mkek-derivation)
7. [Application Key Wrapping](#application-key-wrapping)
8. [Multi-Enrollment](#multi-enrollment)
9. [Configuration Schemas](#configuration-schemas)
10. [Security Analysis](#security-analysis)
11. [Implementation Guide](#implementation-guide)

---

## Overview

The Master Secret (MS) is the root cryptographic secret in the KMS V2 architecture. All application keys are derived from or wrapped by keys derived from the MS.

### Key Hierarchy

```
User Authentication (passphrase, passkey PRF, passkey gate)
    ↓
KEK (Key Encryption Key)
    ↓
MS (Master Secret, 32 bytes) ← encrypted with KEK + AAD
    ↓
MKEK (Master Key Encryption Key) ← derived via HKDF
    ↓
Application Keys (VAPID, audit, identity) ← wrapped with MKEK + AAD
```

### V2 Security Improvements

1. **Standard KCV**: `HMAC(KEK, "ATS/KMS/KCV/v2")` replaces custom verification hash
2. **Mandatory AAD**: All AES-GCM encryptions include metadata binding
3. **Calibrated PBKDF2**: Device-specific iterations (150-300ms target)
4. **Deterministic HKDF Salt**: `SHA256("ATS/KMS/MKEK/salt/v2")` for MKEK derivation
5. **Multi-Enrollment Support**: Single MS wrapped by N credentials
6. **Explicit Versioning**: `kmsVersion`, `algVersion`, `msVersion` tracking

---

## Master Secret (MS)

### Generation

The Master Secret is 32 bytes (256 bits) of cryptographically secure random data.

```typescript
/**
 * Generate a new Master Secret.
 *
 * SECURITY:
 * - Uses Web Crypto API getRandomValues (CSPRNG)
 * - 256 bits of entropy (exceeds NIST SP 800-57 recommendations)
 * - Must be generated in secure context (HTTPS or localhost)
 *
 * @returns 32-byte Uint8Array
 */
export function generateMasterSecret(): Uint8Array {
  const ms = new Uint8Array(32);
  crypto.getRandomValues(ms);
  return ms;
}
```

### Properties

- **Size**: 32 bytes (256 bits)
- **Entropy**: Full 256 bits from CSPRNG
- **Lifetime**: Milliseconds (only exists during unlock)
- **Storage**: Never stored directly, always encrypted
- **Derivation**: Used via HKDF to derive MKEK

### Security Rationale

**Why 32 bytes?**
- Matches AES-256 key size
- Exceeds NIST SP 800-57 recommendations for symmetric keys (minimum 128 bits)
- Provides 256-bit security level for all derived keys

**Why CSPRNG?**
- Browser's `crypto.getRandomValues()` uses OS entropy sources
- Seeded from hardware RNG, timing jitter, user input
- Meets FIPS 140-2 requirements

---

## KEK Derivation Methods

The Key Encryption Key (KEK) is derived from user authentication. V2 supports three methods:

1. **Passphrase**: PBKDF2 with calibrated iterations
2. **Passkey PRF**: WebAuthn PRF extension → HKDF
3. **Passkey Gate** (future): WebAuthn PRF → decrypt pepper → PBKDF2

### Method 1: Passphrase

```typescript
/**
 * Derive KEK from passphrase using calibrated PBKDF2.
 *
 * V2 IMPROVEMENT: Device-specific iteration counts (150-300ms target)
 * V1 used fixed 600,000 iterations (too slow on mobile, too fast on desktop)
 *
 * @param passphrase User's passphrase
 * @param salt 16-byte random salt (generated during setup)
 * @param iterations Calibrated iteration count (stored in config)
 * @returns KEK (32 bytes) as CryptoKey
 */
export async function deriveKEKFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  // Import passphrase as key material
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive 32 bytes for KEK
  const kekBytes = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    256  // 32 bytes
  );

  // Import as AES-GCM key
  const kek = await crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,  // Non-extractable KEK
    ['encrypt', 'decrypt']
  );

  return kek;
}
```

**Passphrase Configuration**:

```typescript
interface PassphraseConfig {
  kmsVersion: 2;
  algVersion: 1;
  method: 'passphrase';

  // KDF parameters (stored for verification and recalibration)
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    iterations: number;         // Calibrated per device (e.g., 180,000)
    salt: ArrayBuffer;          // 16 bytes random
    lastCalibratedAt: number;   // Timestamp (for periodic recalibration)
    platformHash: string;       // Coarse device fingerprint (for migration detection)
  };

  // Key Check Value (password verification)
  kcv: ArrayBuffer;             // 32 bytes (see KCV section)

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer;     // 32-byte MS + 16-byte tag = 48 bytes
  msIV: ArrayBuffer;            // 12 bytes (AES-GCM IV)
  msAAD: ArrayBuffer;           // AAD for metadata binding
  msVersion: 1;                 // Re-encryption tracking

  createdAt: number;            // Unix timestamp (ms)
  updatedAt: number;            // Unix timestamp (ms)
}
```

### Method 2: Passkey PRF

**SECURITY REQUIREMENT**: User verification (UV) MUST be set to `"required"` for all WebAuthn PRF operations. See [WebAuthn PRF Requirements](./01-primitives.md#13-webauthn-prf-requirements) for details.

```typescript
/**
 * Derive KEK from WebAuthn PRF extension.
 *
 * SECURITY:
 * - userVerification: "required" MUST be set (see 01-primitives.md)
 * - PRF output is deterministic for same credential + salt
 * - 32 bytes of entropy from authenticator's HMAC-SHA256
 * - HKDF expands to KEK with proper domain separation
 * - Two distinct salts: appSalt (for PRF) and hkdfSalt (for HKDF)
 *
 * @param credentialId WebAuthn credential ID
 * @param rpId Relying Party ID (e.g., "kms.ats.run")
 * @param appSalt 32-byte salt for PRF eval.first
 * @param hkdfSalt 32-byte salt for HKDF (distinct from appSalt)
 * @returns KEK (32 bytes) as CryptoKey
 */
export async function deriveKEKFromPasskeyPRF(
  credentialId: ArrayBuffer,
  rpId: string,
  appSalt: Uint8Array,     // For PRF eval.first
  hkdfSalt: Uint8Array     // For HKDF (different from appSalt)
): Promise<CryptoKey> {
  // Step 1: WebAuthn assertion with PRF extension
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      rpId: rpId,
      userVerification: 'required',
      extensions: {
        prf: {
          eval: {
            first: appSalt  // Deterministic PRF input
          }
        }
      }
    }
  });

  if (!assertion.getClientExtensionResults().prf?.results?.first) {
    throw new Error('PRF extension not supported or failed');
  }

  // Step 2: Extract PRF output (32 bytes)
  const prfOutput = new Uint8Array(
    assertion.getClientExtensionResults().prf.results.first
  );

  // Step 3: HKDF to derive KEK with domain separation
  const prfKey = await crypto.subtle.importKey(
    'raw',
    prfOutput,
    'HKDF',
    false,
    ['deriveBits']
  );

  const kekBytes = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: hkdfSalt,           // Distinct from appSalt
      info: new TextEncoder().encode('ATS/KMS/KEK-wrap/v2'),
      hash: 'SHA-256'
    },
    prfKey,
    256  // 32 bytes
  );

  // Step 4: Import as AES-GCM key
  const kek = await crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,  // Non-extractable
    ['encrypt', 'decrypt']
  );

  return kek;
}
```

**Passkey PRF Configuration**:

```typescript
interface PasskeyPRFConfig {
  kmsVersion: 2;
  algVersion: 1;
  method: 'passkey-prf';

  // WebAuthn credential
  credentialId: ArrayBuffer;
  rpId: string;              // e.g., "kms.ats.run"

  // KDF parameters
  kdf: {
    algorithm: 'HKDF-SHA256';
    appSalt: ArrayBuffer;    // 32 bytes (for PRF eval.first)
    hkdfSalt: ArrayBuffer;   // 32 bytes (for HKDF, distinct from appSalt)
    info: 'ATS/KMS/KEK-wrap/v2';
  };

  // No KCV needed (WebAuthn provides authentication)

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: 1;

  createdAt: number;
  updatedAt: number;
}
```

### Method 3: Passkey Gate (Future)

Enhanced two-factor authentication combining WebAuthn with PBKDF2.

```typescript
/**
 * Derive KEK from passkey gate (WebAuthn + passphrase).
 *
 * ARCHITECTURE:
 * 1. User provides passphrase
 * 2. WebAuthn assertion unlocks encrypted pepper
 * 3. Pepper + passphrase → PBKDF2 → KEK
 *
 * SECURITY:
 * - Two-factor locally (something you know + something you have)
 * - Pepper encrypted with PRF-derived key (WebAuthn gate)
 * - Cannot derive KEK without both passphrase AND authenticator
 *
 * @param passphrase User's passphrase
 * @param credentialId WebAuthn credential ID
 * @param encryptedPepper Pepper encrypted with PRF-derived key
 * @param kdfParams PBKDF2 parameters (salt, iterations)
 * @returns KEK (32 bytes) as CryptoKey
 */
export async function deriveKEKFromPasskeyGate(
  passphrase: string,
  credentialId: ArrayBuffer,
  encryptedPepper: { ciphertext: ArrayBuffer; iv: ArrayBuffer; aad: ArrayBuffer },
  kdfParams: { salt: Uint8Array; iterations: number }
): Promise<CryptoKey> {
  // Step 1: Derive pepper decryption key from WebAuthn PRF
  const prfKey = await deriveKEKFromPasskeyPRF(
    credentialId,
    'kms.ats.run',
    kdfParams.appSalt,
    kdfParams.hkdfSalt
  );

  // Step 2: Decrypt pepper
  const pepper = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: encryptedPepper.iv,
      additionalData: encryptedPepper.aad
    },
    prfKey,
    encryptedPepper.ciphertext
  );

  // Step 3: Combine passphrase + pepper
  const combined = new Uint8Array(
    new TextEncoder().encode(passphrase).length + pepper.byteLength
  );
  combined.set(new TextEncoder().encode(passphrase), 0);
  combined.set(new Uint8Array(pepper), new TextEncoder().encode(passphrase).length);

  // Step 4: PBKDF2 with calibrated iterations
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    combined,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const kekBytes = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: kdfParams.salt,
      iterations: kdfParams.iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    256
  );

  // Step 5: Import as AES-GCM key
  const kek = await crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // Zero out sensitive data
  combined.fill(0);

  return kek;
}
```

**Passkey Gate Configuration**:

```typescript
interface PasskeyGateConfig {
  kmsVersion: 2;
  algVersion: 1;
  method: 'passkey-gate';

  // WebAuthn credential (gates pepper decryption)
  credentialId: ArrayBuffer;
  rpId: string;

  // Encrypted pepper (unlocked by WebAuthn)
  encryptedPepper: {
    ciphertext: ArrayBuffer;  // 32-byte pepper + 16-byte tag
    iv: ArrayBuffer;          // 12 bytes
    aad: ArrayBuffer;         // Metadata binding
  };

  // PRF parameters for pepper decryption
  prfKdf: {
    algorithm: 'HKDF-SHA256';
    appSalt: ArrayBuffer;     // 32 bytes
    hkdfSalt: ArrayBuffer;    // 32 bytes
    info: 'ATS/KMS/pepper-gate/v2';
  };

  // PBKDF2 parameters for KEK derivation
  kek: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    iterations: number;       // Calibrated
    salt: ArrayBuffer;        // 16 bytes
  };

  // Key Check Value (for passphrase verification)
  kcv: ArrayBuffer;

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: 1;

  createdAt: number;
  updatedAt: number;
}
```

---

## Key Check Value (KCV)

**V2 IMPROVEMENT**: Replaces custom verification hash with standard cryptographic approach.

### What is KCV?

Key Check Value is a standard method for verifying that a password-derived key is correct **without storing the key itself**.

### V1 vs V2

**V1 (custom, non-standard)**:
```typescript
// BAD: Custom verification hash (not a standard practice)
const verificationHash = SHA256(KEK || "verification-context");
```

**V2 (standard KCV)**:
```typescript
// GOOD: Standard KCV using HMAC
const kcv = HMAC-SHA256(KEK, "ATS/KMS/KCV/v2");
```

### Implementation

```typescript
/**
 * Generate Key Check Value for KEK verification.
 *
 * STANDARD: This follows industry-standard KCV practices:
 * - HMAC with fixed message (not encryption of zero block)
 * - Domain-separated context string
 * - 32-byte output (full HMAC-SHA256)
 *
 * V1 CHANGE: Replaces custom SHA256(KEK || "verification") approach
 *
 * @param kek Key Encryption Key (CryptoKey)
 * @returns 32-byte KCV (ArrayBuffer)
 */
export async function generateKCV(kek: CryptoKey): Promise<ArrayBuffer> {
  // Import KEK for HMAC (re-import with HMAC usage)
  const kekBytes = await crypto.subtle.exportKey('raw', kek);
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // HMAC fixed message with domain separator
  const kcv = await crypto.subtle.sign(
    'HMAC',
    hmacKey,
    new TextEncoder().encode('ATS/KMS/KCV/v2')
  );

  return kcv;
}

/**
 * Verify password by comparing KEK-derived KCV.
 *
 * SECURITY:
 * - Constant-time comparison (crypto.subtle.timingSafeEqual)
 * - No side-channel timing leaks
 *
 * @param kek Candidate KEK derived from user input
 * @param storedKCV KCV from configuration
 * @returns true if KCV matches
 */
export async function verifyKCV(
  kek: CryptoKey,
  storedKCV: ArrayBuffer
): Promise<boolean> {
  const candidateKCV = await generateKCV(kek);

  // Constant-time comparison
  return crypto.subtle.timingSafeEqual(
    new Uint8Array(candidateKCV),
    new Uint8Array(storedKCV)
  );
}
```

### Security Properties

✅ **Standard approach**: HMAC-based KCV is industry standard
✅ **No key storage**: KCV doesn't reveal KEK
✅ **Fast verification**: Single HMAC operation
✅ **Timing-safe**: Constant-time comparison prevents side channels
✅ **Domain-separated**: Context string prevents cross-protocol attacks

---

## MS Encryption

The Master Secret is encrypted with KEK using AES-256-GCM with mandatory AAD.

### V2 IMPROVEMENT: Metadata Binding

**V1 Problem**: No Additional Authenticated Data (AAD) → ciphertexts could be swapped
**V2 Solution**: AAD includes metadata (method, version, credentialId) → prevents replay attacks

**See**: [AAD Schemas](./01-primitives.md#22-aes-gcm-aad-schemas) in 01-primitives.md for exact AAD structure, versioning, and canonicalization rules.

**CRITICAL**: Decrypt MUST FAIL if AAD mismatches any field or `aadVersion`. This includes:
- Different `method`, `kdf`, `kdfParams`, or `kmsVersion` values
- Different field ordering (though canonicalization ensures consistency)
- Missing or extra fields
- Unknown `aadVersion` (must reject)

### Encryption Flow

```typescript
/**
 * Encrypt Master Secret with KEK and AAD.
 *
 * V2 IMPROVEMENT: Mandatory AAD for metadata binding
 * - Prevents ciphertext swapping between configs
 * - Binds encryption to method, version, credential
 * - Detects tampering with configuration metadata
 *
 * @param ms Master Secret (32 bytes)
 * @param kek Key Encryption Key
 * @param aad Additional Authenticated Data (metadata binding)
 * @returns { ciphertext, iv, aad }
 */
export async function encryptMasterSecret(
  ms: Uint8Array,
  kek: CryptoKey,
  aad: Uint8Array
): Promise<{
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
  aad: ArrayBuffer;
}> {
  // Generate random IV (12 bytes for AES-GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt MS with AAD
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aad,  // MANDATORY in V2
      tagLength: 128        // 16-byte authentication tag
    },
    kek,
    ms
  );

  return {
    ciphertext,       // 48 bytes (32-byte MS + 16-byte tag)
    iv: iv.buffer,    // 12 bytes
    aad: aad.buffer   // Variable (store for decryption)
  };
}

/**
 * Decrypt Master Secret with KEK and AAD.
 *
 * SECURITY:
 * - AAD must match exactly (including order)
 * - GCM authentication tag verified before decryption
 * - Tampering with metadata causes decryption failure
 *
 * @param ciphertext Encrypted MS (48 bytes)
 * @param kek Key Encryption Key
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional Authenticated Data (must match encryption AAD)
 * @returns Master Secret (32 bytes)
 * @throws Error if authentication fails
 */
export async function decryptMasterSecret(
  ciphertext: ArrayBuffer,
  kek: CryptoKey,
  iv: ArrayBuffer,
  aad: ArrayBuffer
): Promise<Uint8Array> {
  const ms = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aad,  // Must match encryption AAD
      tagLength: 128
    },
    kek,
    ciphertext
  );

  return new Uint8Array(ms);
}
```

### AAD Construction

```typescript
/**
 * Build AAD for MS encryption.
 *
 * STRUCTURE: Canonical JSON with sorted keys
 * - Deterministic (same inputs → same AAD)
 * - Includes all critical metadata
 * - Version-tagged for future evolution
 *
 * @param config Configuration metadata
 * @returns AAD as ArrayBuffer
 */
export function buildMSEncryptionAAD(config: {
  kmsVersion: number;
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  algVersion: number;
  purpose: 'master-secret';
  credentialId?: ArrayBuffer;
}): ArrayBuffer {
  // Convert credentialId to base64url if present
  const credId = config.credentialId
    ? base64url.encode(new Uint8Array(config.credentialId))
    : null;

  // Canonical JSON with sorted keys
  const aadObj = {
    algVersion: config.algVersion,
    credentialId: credId,
    kmsVersion: config.kmsVersion,
    method: config.method,
    purpose: config.purpose
  };

  // Stringify with sorted keys
  const aadJSON = JSON.stringify(aadObj, Object.keys(aadObj).sort());

  return new TextEncoder().encode(aadJSON);
}
```

**Example AAD**:
```json
{
  "algVersion": 1,
  "credentialId": null,
  "kmsVersion": 2,
  "method": "passphrase",
  "purpose": "master-secret"
}
```

### Security Analysis

**What AAD Protects Against**:
- ✅ Ciphertext swapping (moving encryptedMS between configs)
- ✅ Cross-method replay (passphrase ciphertext used for passkey config)
- ✅ Metadata tampering (changing credentialId without re-encrypting)
- ✅ Version downgrade (using V2 ciphertext in V1 config)

**What AAD Does NOT Protect**:
- ❌ Weak passwords (PBKDF2 calibration + strength requirements needed)
- ❌ Phishing (origin checks + user education needed)
- ❌ Brute-force offline attacks (password strength + iteration count)

---

## MKEK Derivation

The Master Key Encryption Key (MKEK) is derived from MS using HKDF with a **deterministic salt**.

### V2 IMPROVEMENT: Deterministic Salt

**V1 Problem**: HKDF salt was all zeros (weak, non-standard)
**V2 Solution**: Deterministic salt derived from context string

```typescript
/**
 * Derive MKEK from Master Secret using HKDF.
 *
 * V2 IMPROVEMENT: Deterministic non-zero salt
 * - Salt = SHA256("ATS/KMS/MKEK/salt/v2")
 * - Proper domain separation
 * - Versioned for future evolution
 *
 * @param ms Master Secret (32 bytes)
 * @returns MKEK as CryptoKey (AES-256-GCM)
 */
export async function deriveMKEK(ms: Uint8Array): Promise<CryptoKey> {
  // Import MS as HKDF key material
  const msKey = await crypto.subtle.importKey(
    'raw',
    ms,
    'HKDF',
    false,
    ['deriveBits']
  );

  // Deterministic salt (V2 improvement)
  const salt = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('ATS/KMS/MKEK/salt/v2')
  );

  // Derive MKEK
  const mkekBytes = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: salt,
      info: new TextEncoder().encode('ATS/KMS/MKEK/v2'),
      hash: 'SHA-256'
    },
    msKey,
    256  // 32 bytes
  );

  // Import as AES-GCM key
  const mkek = await crypto.subtle.importKey(
    'raw',
    mkekBytes,
    { name: 'AES-GCM', length: 256 },
    false,  // Non-extractable (only exists during unlock)
    ['wrapKey', 'unwrapKey']
  );

  return mkek;
}
```

### Deterministic Salt Rationale

**Why not random salt?**
- MS is already random (256 bits of entropy)
- MKEK must be reproducible from same MS
- Deterministic salt provides domain separation without requiring storage

**Why not zero salt?**
- Violates RFC 5869 recommendations
- Reduces security margin
- Non-standard practice

**Why hash of context string?**
- Deterministic (same input → same output)
- Unique per context (domain separation)
- Versioned (allows future changes)
- Standard practice (used in Signal Protocol, etc.)

---

## Application Key Wrapping

Application keys (VAPID, audit, identity) are wrapped with MKEK using AES-KW or AES-GCM.

### V2 IMPROVEMENT: AAD for All Wrapping

```typescript
/**
 * Wrap application key with MKEK and AAD.
 *
 * V2 IMPROVEMENT: Mandatory AAD for metadata binding
 * - Binds wrapping to key metadata (kid, alg, purpose)
 * - Prevents key substitution attacks
 * - Detects tampering with wrapped key metadata
 *
 * @param key Application key (CryptoKey, extractable=true during wrapping window)
 * @param mkek Master Key Encryption Key
 * @param metadata Key metadata (kid, alg, purpose, createdAt)
 * @returns { wrappedKey, iv, aad }
 */
export async function wrapApplicationKey(
  key: CryptoKey,
  mkek: CryptoKey,
  metadata: {
    kid: string;
    alg: 'ES256' | 'EdDSA';
    purpose: 'vapid' | 'audit' | 'identity';
    createdAt: number;
    kmsVersion: number;
  }
): Promise<{
  wrappedKey: ArrayBuffer;
  iv: ArrayBuffer;
  aad: ArrayBuffer;
}> {
  // Build AAD from metadata
  const aad = buildKeyWrappingAAD(metadata);

  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Wrap key with MKEK + AAD
  const wrappedKey = await crypto.subtle.wrapKey(
    'raw',     // Export format (raw private key bytes)
    key,       // Key to wrap
    mkek,      // Wrapping key
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aad,
      tagLength: 128
    }
  );

  return {
    wrappedKey,
    iv: iv.buffer,
    aad: aad.buffer
  };
}

/**
 * Unwrap application key with MKEK and AAD.
 *
 * @param wrappedKey Wrapped key data
 * @param mkek Master Key Encryption Key
 * @param iv Initialization vector
 * @param aad Additional Authenticated Data (must match wrapping AAD)
 * @param metadata Key metadata (for import)
 * @returns Unwrapped CryptoKey (non-extractable)
 */
export async function unwrapApplicationKey(
  wrappedKey: ArrayBuffer,
  mkek: CryptoKey,
  iv: ArrayBuffer,
  aad: ArrayBuffer,
  metadata: {
    alg: 'ES256' | 'EdDSA';
    purpose: 'vapid' | 'audit' | 'identity';
  }
): Promise<CryptoKey> {
  // Determine algorithm parameters
  const algorithm = metadata.alg === 'ES256'
    ? { name: 'ECDSA', namedCurve: 'P-256' }
    : { name: 'Ed25519' };

  const keyUsages = metadata.purpose === 'vapid'
    ? ['sign']
    : metadata.purpose === 'audit'
    ? ['sign']
    : ['sign'];  // identity keys also sign

  // Unwrap key
  const key = await crypto.subtle.unwrapKey(
    'raw',         // Import format
    wrappedKey,    // Wrapped key data
    mkek,          // Unwrapping key
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aad,  // Must match wrapping AAD
      tagLength: 128
    },
    algorithm,
    false,         // extractable=false (non-extractable after unwrap)
    keyUsages
  );

  return key;
}

/**
 * Build AAD for key wrapping.
 */
function buildKeyWrappingAAD(metadata: {
  kid: string;
  alg: string;
  purpose: string;
  createdAt: number;
  kmsVersion: number;
}): ArrayBuffer {
  const aadObj = {
    alg: metadata.alg,
    createdAt: metadata.createdAt,
    kid: metadata.kid,
    kmsVersion: metadata.kmsVersion,
    purpose: metadata.purpose
  };

  const aadJSON = JSON.stringify(aadObj, Object.keys(aadObj).sort());
  return new TextEncoder().encode(aadJSON);
}
```

---

## Multi-Enrollment

**V2 FEATURE**: Single Master Secret can be wrapped by multiple credentials.

### Architecture

```
MS (single 32-byte secret)
 ├─ Wrapped by Passphrase (KEK₁)
 ├─ Wrapped by Passkey #1 (KEK₂)
 ├─ Wrapped by Passkey #2 (KEK₃)
 └─ Wrapped by Passkey Gate (KEK₄)
```

### Benefits

- **Redundancy**: Multiple ways to unlock same keys
- **Migration**: Add new method before removing old
- **Recovery**: Backup passkey if primary device lost
- **Flexibility**: Use different methods on different devices

### Implementation

```typescript
/**
 * Add enrollment (wrap MS with new credential).
 *
 * WORKFLOW:
 * 1. User unlocks with existing credential
 * 2. MS is available during unlock window
 * 3. User sets up new credential
 * 4. MS is wrapped with new KEK
 * 5. Both credentials now work
 *
 * @param ms Master Secret (from current unlock)
 * @param newKEK KEK derived from new credential
 * @param method New credential method
 * @param metadata Method-specific metadata
 * @returns New configuration
 */
export async function addEnrollment(
  ms: Uint8Array,
  newKEK: CryptoKey,
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate',
  metadata: any
): Promise<PassphraseConfig | PasskeyPRFConfig | PasskeyGateConfig> {
  // Build AAD for new enrollment
  const aad = buildMSEncryptionAAD({
    kmsVersion: 2,
    method: method,
    algVersion: 1,
    purpose: 'master-secret',
    credentialId: metadata.credentialId
  });

  // Encrypt MS with new KEK
  const { ciphertext, iv } = await encryptMasterSecret(ms, newKEK, new Uint8Array(aad));

  // Generate KCV if passphrase-based
  const kcv = (method === 'passphrase' || method === 'passkey-gate')
    ? await generateKCV(newKEK)
    : undefined;

  // Build configuration
  const config = {
    kmsVersion: 2,
    algVersion: 1,
    method,
    encryptedMS: ciphertext,
    msIV: iv,
    msAAD: aad,
    msVersion: 1,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...metadata,
    ...(kcv && { kcv })
  };

  return config;
}

/**
 * Remove enrollment (delete credential configuration).
 *
 * SAFETY:
 * - Require at least 1 enrollment remains
 * - Confirm with current authentication
 * - Audit the removal
 *
 * @param enrollmentId Configuration ID to remove
 */
export async function removeEnrollment(enrollmentId: string): Promise<void> {
  const configs = await loadAllConfigs();

  if (configs.length <= 1) {
    throw new Error('Cannot remove last enrollment');
  }

  // Delete configuration
  await storage.delete(`config:${enrollmentId}`);

  // Audit removal
  await audit.log({
    op: 'enrollment:remove',
    enrollmentId,
    remainingCount: configs.length - 1
  });
}
```

### Storage Strategy

```typescript
// Multiple configs in IndexedDB
interface EnrollmentStore {
  'config:passphrase': PassphraseConfig;
  'config:passkey:abc123': PasskeyPRFConfig;
  'config:passkey:def456': PasskeyPRFConfig;
  'config:gate:ghi789': PasskeyGateConfig;
}

// All configs share same MS (different wrappings)
```

---

## Configuration Schemas

### Passphrase Config (Complete)

```typescript
interface PassphraseConfig {
  // Version tracking
  kmsVersion: 2;
  algVersion: 1;
  method: 'passphrase';

  // KDF parameters
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    iterations: number;         // Device-specific (e.g., 180,000)
    salt: ArrayBuffer;          // 16 bytes random
    lastCalibratedAt: number;   // Unix timestamp (ms)
    platformHash: string;       // Coarse device ID (for migration)
  };

  // Key Check Value
  kcv: ArrayBuffer;             // 32 bytes (HMAC(KEK, "ATS/KMS/KCV/v2"))

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer;     // 48 bytes (32 + 16 tag)
  msIV: ArrayBuffer;            // 12 bytes
  msAAD: ArrayBuffer;           // Variable (JSON)
  msVersion: 1;                 // Re-encryption counter

  // Metadata
  createdAt: number;
  updatedAt: number;
}
```

### Passkey PRF Config (Complete)

```typescript
interface PasskeyPRFConfig {
  // Version tracking
  kmsVersion: 2;
  algVersion: 1;
  method: 'passkey-prf';

  // WebAuthn credential
  credentialId: ArrayBuffer;
  rpId: string;

  // KDF parameters
  kdf: {
    algorithm: 'HKDF-SHA256';
    appSalt: ArrayBuffer;       // 32 bytes (for PRF eval.first)
    hkdfSalt: ArrayBuffer;      // 32 bytes (for HKDF, distinct)
    info: 'ATS/KMS/KEK-wrap/v2';
  };

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: 1;

  // Metadata
  createdAt: number;
  updatedAt: number;
}
```

### Passkey Gate Config (Complete)

```typescript
interface PasskeyGateConfig {
  // Version tracking
  kmsVersion: 2;
  algVersion: 1;
  method: 'passkey-gate';

  // WebAuthn credential
  credentialId: ArrayBuffer;
  rpId: string;

  // Encrypted pepper (gated by WebAuthn)
  encryptedPepper: {
    ciphertext: ArrayBuffer;    // 48 bytes (32 + 16 tag)
    iv: ArrayBuffer;            // 12 bytes
    aad: ArrayBuffer;           // Metadata binding
  };

  // PRF parameters (for pepper decryption)
  prfKdf: {
    algorithm: 'HKDF-SHA256';
    appSalt: ArrayBuffer;
    hkdfSalt: ArrayBuffer;
    info: 'ATS/KMS/pepper-gate/v2';
  };

  // PBKDF2 parameters (for KEK derivation)
  kekKdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    iterations: number;
    salt: ArrayBuffer;          // 16 bytes
  };

  // Key Check Value
  kcv: ArrayBuffer;

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: 1;

  // Metadata
  createdAt: number;
  updatedAt: number;
}
```

### Wrapped Key Config (Complete)

```typescript
interface WrappedKeyConfig {
  // Identifier
  kid: string;                  // JWK thumbprint

  // Version tracking
  kmsVersion: 2;

  // Wrapped key data
  wrappedKey: ArrayBuffer;      // Variable size + 16-byte tag
  iv: ArrayBuffer;              // 12 bytes
  aad: ArrayBuffer;             // Metadata binding (JSON)

  // Public key and metadata
  publicKeyRaw: ArrayBuffer;    // Raw public key bytes
  alg: 'ES256' | 'EdDSA';
  purpose: 'vapid' | 'audit' | 'identity';

  // Usage tracking
  createdAt: number;
  lastUsedAt?: number;
}
```

---

## Security Analysis

### Threat Model

**Protected Against**:
- ✅ **Offline brute-force**: Calibrated PBKDF2 + strong passwords
- ✅ **Ciphertext swapping**: AAD binds encryption to metadata
- ✅ **Version downgrade**: `kmsVersion` in AAD
- ✅ **Key substitution**: AAD includes kid, alg, purpose
- ✅ **Metadata tampering**: GCM authentication tag covers AAD

**NOT Protected Against**:
- ❌ **Weak passwords**: User responsibility (+ strength meter recommended)
- ❌ **Phishing**: User must verify origin (+ WebAuthn helps)
- ❌ **Compromised device**: OS-level access defeats all protections
- ❌ **Browser bugs**: Sandbox escapes, crypto implementation flaws

### Key Properties

| Property | V1 | V2 | Improvement |
|----------|----|----|-------------|
| MS encryption | AES-GCM | AES-GCM + AAD | Metadata binding |
| Password verification | Custom hash | Standard KCV | Industry standard |
| PBKDF2 iterations | Fixed 600k | Calibrated 150-300ms | Device-adaptive |
| HKDF salt | All zeros | Deterministic hash | Proper domain separation |
| Key wrapping | AES-GCM | AES-GCM + AAD | Prevents substitution |
| Multi-enrollment | No | Yes | Redundancy + flexibility |
| Versioning | Implicit | Explicit | Clear migration path |

---

## Implementation Guide

### Setup Flow (Passphrase)

```typescript
async function setupPassphrase(passphrase: string): Promise<PassphraseConfig> {
  // Step 1: Calibrate PBKDF2 iterations
  const { iterations, measuredMs } = await calibratePBKDF2Iterations();

  // Step 2: Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Step 3: Derive KEK
  const kek = await deriveKEKFromPassphrase(passphrase, salt, iterations);

  // Step 4: Generate KCV
  const kcv = await generateKCV(kek);

  // Step 5: Generate Master Secret
  const ms = generateMasterSecret();

  // Step 6: Build AAD
  const aad = buildMSEncryptionAAD({
    kmsVersion: 2,
    method: 'passphrase',
    algVersion: 1,
    purpose: 'master-secret'
  });

  // Step 7: Encrypt MS
  const { ciphertext, iv } = await encryptMasterSecret(ms, kek, new Uint8Array(aad));

  // Step 8: Build configuration
  const config: PassphraseConfig = {
    kmsVersion: 2,
    algVersion: 1,
    method: 'passphrase',
    kdf: {
      algorithm: 'PBKDF2-HMAC-SHA256',
      iterations,
      salt: salt.buffer,
      lastCalibratedAt: Date.now(),
      platformHash: await getCoarsePlatformHash()
    },
    kcv,
    encryptedMS: ciphertext,
    msIV: iv,
    msAAD: aad,
    msVersion: 1,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };

  // Step 9: Store configuration
  await storage.put('config:passphrase', config);

  return config;
}
```

### Unlock Flow (Passphrase)

```typescript
async function unlockWithPassphrase(
  passphrase: string,
  config: PassphraseConfig
): Promise<Uint8Array> {
  // Step 1: Derive KEK from passphrase
  const kek = await deriveKEKFromPassphrase(
    passphrase,
    new Uint8Array(config.kdf.salt),
    config.kdf.iterations
  );

  // Step 2: Verify KCV (fast password check)
  const valid = await verifyKCV(kek, config.kcv);
  if (!valid) {
    throw new Error('Invalid passphrase');
  }

  // Step 3: Decrypt Master Secret
  const ms = await decryptMasterSecret(
    config.encryptedMS,
    kek,
    config.msIV,
    config.msAAD
  );

  return ms;
}
```

### Key Generation Flow

```typescript
async function generateVAPIDKey(ms: Uint8Array): Promise<WrappedKeyConfig> {
  // Step 1: Derive MKEK from MS
  const mkek = await deriveMKEK(ms);

  // Step 2: Generate VAPID keypair (extractable during wrapping window)
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,   // extractable=true (temporarily, for wrapping)
    ['sign', 'verify']
  );

  // Step 3: Export public key
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Step 4: Compute kid (JWK thumbprint)
  const kid = await computeJWKThumbprint(keypair.publicKey);

  // Step 5: Build metadata
  const metadata = {
    kid,
    alg: 'ES256' as const,
    purpose: 'vapid' as const,
    createdAt: Date.now(),
    kmsVersion: 2
  };

  // Step 6: Wrap private key
  const { wrappedKey, iv, aad } = await wrapApplicationKey(
    keypair.privateKey,
    mkek,
    metadata
  );

  // Step 7: Build configuration
  const config: WrappedKeyConfig = {
    kid,
    kmsVersion: 2,
    wrappedKey,
    iv,
    aad,
    publicKeyRaw,
    alg: 'ES256',
    purpose: 'vapid',
    createdAt: Date.now()
  };

  // Step 8: Store configuration
  await storage.put(`key:${kid}`, config);

  return config;
}
```

---

## References

- **PBKDF2**: RFC 8018, NIST SP 800-132
- **HKDF**: RFC 5869
- **AES-GCM**: NIST SP 800-38D
- **Key Check Value**: ANSI X9.24-1:2009
- **WebAuthn PRF**: W3C WebAuthn Level 3 (draft)
- **AAD Usage**: NIST SP 800-38D Section 7

---

**Next**: [03-unlock-context.md](./03-unlock-context.md) - `withUnlock` implementation
