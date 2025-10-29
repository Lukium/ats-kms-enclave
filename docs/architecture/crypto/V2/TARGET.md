# KMS V2: Implementation Target Diagram

**Version**: 2.0
**Status**: Design Complete → Implementation Target
**Date**: 2025-10-24
**Purpose**: Visual map of complete V2 system for implementation reference

This diagram represents **what we are building now** (omits future Signal/Argon2 enhancements). Use as implementation guide alongside detailed design docs.

**Key V2 Improvements**: Calibrated KDF, AAD everywhere, KCV, deterministic salts, multi-enrollment, hardened audit, VAPID leases

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KMS V2 ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PWA (allthe.services)                                                      │
│  ┌────────────────────────────────────────────────────────────────┐         │
│  │  kms-user.ts                                                   │         │
│  │  - Setup/unlock API                                            │         │
│  │  - WebAuthn ceremonies (passkey create/get)                    │         │
│  │  - VAPID lease management                                      │         │
│  └──────────────┬─────────────────────────────────────────────────┘         │
│                 │ postMessage (cross-origin)                                │
│                 ↓                                                           │
│  KMS Iframe (kms.ats.run) - Separate Origin                                 │
│  ┌────────────────────────────────────────────────────────────────┐         │
│  │  kms.html (~5 lines, SRI-pinned module)                        │         │
│  │  ┌──────────────────────────────────────────────────────────┐  │         │
│  │  │  client.ts (iframe main thread)                          │  │         │
│  │  │  - Origin validation                                     │  │         │
│  │  │  - Message forwarding (PWA ↔ Worker)                     │  │         │
│  │  └──────────────┬───────────────────────────────────────────┘  │         │
│  │                 │ postMessage (Worker)                         │         │
│  │                 ↓                                              │         │
│  │  ┌──────────────────────────────────────────────────────────┐  │         │
│  │  │  worker.ts (KMS Worker - Crypto Operations)              │  │         │
│  │  │                                                          │  │         │
│  │  │  Orchestrator:                                           │  │         │
│  │  │    - RPC routing                                         │  │         │
│  │  │    - Policy enforcement (quotas, leases)                 │  │         │
│  │  │    - Operation coordination                              │  │         │
│  │  │                                                          │  │         │
│  │  │  Core Modules:                                           │  │         │
│  │  │    unlock.ts    → Master Secret encryption/unlock        │  │         │
│  │  │    audit.ts     → Tamper-evident logging                 │  │         │
│  │  │    storage.ts   → IndexedDB (keys, configs, audit)       │  │         │
│  │  │    crypto-utils → Crypto primitives (sig utils, KCV)     │  │         │
│  │  │                                                          │  │         │
│  │  │  Security:                                               │  │         │
│  │  │    ✓ No DOM access (Worker context)                      │  │         │
│  │  │    ✓ Non-extractable keys                                │  │         │
│  │  │    ✓ Per-operation authentication                        │  │         │
│  │  │    ✓ No persistent unlock state                          │  │         │
│  │  └──────────────────────────────────────────────────────────┘  │         │
│  └────────────────────────────────────────────────────────────────┘         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Security Layers (Defense in Depth):
  1. Cross-origin isolation    → Browser-enforced boundary
  2. Sandboxed iframe          → Restricted capabilities
  3. Dedicated Worker          → No DOM, no phishing vector
  4. Non-extractable keys      → Browser crypto subsystem enforcement
  5. SRI verification          → Hash-verified code execution
  6. Runtime self-check        → Fail-secure integrity validation
```

---

## Master Secret Setup (V2)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MASTER SECRET (MS) SETUP - V2                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STEP 1: Generate Master Secret                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ MS = crypto.getRandomValues(new Uint8Array(32))                     │    │
│  │ Size: 32 bytes (256 bits)                                           │    │
│  │ Lifetime: Milliseconds (only during withUnlock operations)          │    │
│  │ Storage: NEVER stored unencrypted                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 2: Calibrate KDF (Passphrase Only) - V2 NEW                           │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Target: 150-300 ms per derivation (device-specific)                 │    │
│  │                                                                     │    │
│  │ Algorithm: calibratePBKDF2Iterations()                              │    │
│  │   1. Warm-up: 10k iterations                                        │    │
│  │   2. Probe: Time 100k iterations → t_probe                          │    │
│  │   3. Scale: iterations = round(100k * 220ms / t_probe)              │    │
│  │   4. Clamp: 50,000 ≤ iterations ≤ 2,000,000                         │    │
│  │   5. Verify: Adjust if outside [150, 300]ms                         │    │
│  │                                                                     │    │
│  │ Result: { iterations, measuredMs, lastCalibratedAt, platformHash }  │    │
│  │ Recalibration: Every 30 days or platform change                     │    │
│  │                                                                     │    │
│  │ Future-ready: Drop-in replacement with Argon2id (via WASM)          │    │
│  │   - Same interface (calibration → target timing)                    │    │
│  │   - Memory-hard KDF for GPU/ASIC resistance                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 3: Derive KEK per Authentication Method - V2 ENHANCED                 │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ MULTI-ENROLLMENT: Single MS wrapped by N credentials                │    │
│  │                                                                     │    │
│  │       Master Secret (32 bytes)                                      │    │
│  │              |                                                      │    │
│  │   ┌──────────┼──────────┬──────────┬──────────┐                     │    │
│  │   │          │          │          │          │                     │    │
│  │ KEK₁     KEK₂      KEK₃      KEK₄      KEK₅                         │    │
│  │ (pass)  (pkey#1) (pkey#2) (pkey#3) (gate)                           │    │
│  │   │          │          │          │          │                     │    │
│  │ Config₁  Config₂   Config₃   Config₄   Config₅                      │    │
│  │                                                                     │    │
│  │ User can unlock with ANY enrolled credential                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ METHOD 1: Passphrase → KEK                                          │    │
│  │ ─────────────────────────────────────────────────────────────────   │    │
│  │ Algorithm: PBKDF2-HMAC-SHA256                                       │    │
│  │   - Password: UTF-8 encoded passphrase                              │    │
│  │   - Salt: 16 bytes random (stored)                                  │    │
│  │   - Iterations: Calibrated (e.g., 150k-1.5M, device-specific)       │    │
│  │   - Hash: SHA-256                                                   │    │
│  │   - Output: 256-bit AES-GCM key (non-extractable)                   │    │
│  │                                                                     │    │
│  │ V2 NEW: Key Check Value (KCV) - Standard Verification               │    │
│  │   kcv = HMAC-SHA256(KEK, "ATS/KMS/KCV/v2")                          │    │
│  │   Store kcv (32 bytes) for fast password verification               │    │
│  │   Constant-time comparison prevents timing attacks                  │    │
│  │                                                                     │    │
│  │ Storage: enrollment:enroll-{id}:config → PassphraseConfigV2         │    │
│  │   {                                                                 │    │
│  │     kmsVersion: 2, algVersion: 1,                                   │    │
│  │     method: 'passphrase',                                           │    │
│  │     kdf: {                                                          │    │
│  │       algorithm: 'PBKDF2-HMAC-SHA256',                              │    │
│  │       iterations: number,    // Calibrated                          │    │
│  │       salt: ArrayBuffer(16), // Random                              │    │
│  │       lastCalibratedAt: number,                                     │    │
│  │       platformHash: string   // Coarse device fingerprint           │    │
│  │     },                                                              │    │
│  │     kcv: ArrayBuffer(32),         // Key Check Value                │    │
│  │     encryptedMS: ArrayBuffer,     // 32-byte MS + 16-byte GCM tag   │    │
│  │     msIV: ArrayBuffer(12),        // AES-GCM IV (unique)            │    │
│  │     msAAD: ArrayBuffer,           // V2 NEW: Metadata binding       │    │
│  │     msVersion: 1,                                                   │    │
│  │     createdAt: number, updatedAt: number                            │    │
│  │   }                                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ METHOD 2: Passkey PRF → KEK (Preferred)                             │    │
│  │ ─────────────────────────────────────────────────────────────────   │    │
│  │ Algorithm: HKDF-SHA256                                              │    │
│  │   - IKM: PRF output from WebAuthn (32 bytes)                        │    │
│  │   - Salt: Deterministic (SHA-256("ATS/KMS/KEK-wrap/salt/v2"))       │    │
│  │   - Info: "ATS/KMS/KEK-wrap/v2"                                     │    │
│  │   - Output: 256-bit AES-GCM key (non-extractable)                   │    │
│  │                                                                     │    │
│  │ WebAuthn PRF Extension:                                             │    │
│  │   eval.first: appSalt (32 bytes, random at setup, stored)           │    │
│  │   Output: 32 bytes → HKDF IKM                                       │    │
│  │                                                                     │    │
│  │ Storage: enrollment:enroll-{id}:config → PasskeyPRFConfigV2         │    │
│  │   {                                                                 │    │
│  │     kmsVersion: 2, algVersion: 1,                                   │    │
│  │     method: 'passkey-prf',                                          │    │
│  │     credentialId: ArrayBuffer, rpId: string,                        │    │
│  │     kdf: {                                                          │    │
│  │       algorithm: 'HKDF-SHA256',                                     │    │
│  │       appSalt: ArrayBuffer(32),  // For PRF eval.first              │    │
│  │       hkdfSalt: ArrayBuffer(32), // For HKDF (distinct!)            │    │
│  │       info: 'ATS/KMS/KEK-wrap/v2'                                   │    │
│  │     },                                                              │    │
│  │     encryptedMS: ArrayBuffer, msIV: ArrayBuffer(12),                │    │
│  │     msAAD: ArrayBuffer, msVersion: 1,                               │    │
│  │     createdAt: number, updatedAt: number                            │    │
│  │   }                                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ METHOD 3: Passkey Gate-Only (Fallback, no PRF)                      │    │
│  │ ─────────────────────────────────────────────────────────────────   │    │
│  │ V2 Enhanced: WebAuthn + pepper for offline guessing resistance      │    │
│  │   1. Generate random pepper (32 bytes) at setup                     │    │
│  │   2. Store pepper encrypted, released only after WebAuthn get()     │    │
│  │   3. Derive KEK = HKDF(passphrase || pepper, salt, info)            │    │
│  │                                                                     │    │
│  │ Note: Weaker than PRF but significantly better than V1              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 4: Encrypt MS with KEK - V2 WITH AAD                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: AES-256-GCM                                              │    │
│  │   Key: KEK (from step 3)                                            │    │
│  │   IV: 12 bytes random (MUST be unique per encryption)               │    │
│  │   Plaintext: MS (32 bytes)                                          │    │
│  │   AAD: Metadata binding (V2 NEW - prevents replay/swap)             │    │
│  │   Tag: 128 bits (appended to ciphertext)                            │    │
│  │                                                                     │    │
│  │ AAD Construction (JSON):                                            │    │
│  │   {                                                                 │    │
│  │     kmsVersion: 2,                                                  │    │
│  │     method: 'passphrase' | 'passkey-prf' | 'passkey-gate',          │    │
│  │     algVersion: 1,                                                  │    │
│  │     credentialId?: base64url(credentialId),  // if passkey          │    │
│  │     purpose: 'master-secret-wrap'                                   │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │ Result: encryptedMS (48 bytes = 32 ciphertext + 16 tag)             │    │
│  │                                                                     │    │
│  │ Security: AAD prevents ciphertext swapping between configs          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 5: Derive MKEK from MS - V2 WITH DETERMINISTIC SALT                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: HKDF-SHA256                                              │    │
│  │   IKM: MS (32 bytes)                                                │    │
│  │   Salt: SHA-256("ATS/KMS/MKEK/salt/v2") [V2: Non-zero!]             │    │
│  │   Info: "ATS/KMS/MKEK/v2"                                           │    │
│  │   Output: 256-bit AES-GCM key                                       │    │
│  │   Usage: ['wrapKey', 'unwrapKey']                                   │    │
│  │   Extractable: false                                                │    │
│  │                                                                     │    │
│  │ Purpose: MKEK wraps application keys (VAPID, audit)                 │    │
│  │ V2 Improvement: Deterministic salt enables rotation/versioning      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 6: Wrap Application Keys - V2 WITH AAD                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: AES-GCM (via WebCrypto wrapKey)                          │    │
│  │   Wrapping Key: MKEK                                                │    │
│  │   Key to Wrap: VAPID private key (ECDSA P-256)                      │    │
│  │   Format: 'jwk'                                                     │    │
│  │   AAD: Key metadata binding (V2 NEW)                                │    │
│  │                                                                     │    │
│  │ AAD Construction:                                                   │    │
│  │   {                                                                 │    │
│  │     kmsVersion: 2, kid: string, alg: 'ES256',                       │    │
│  │     purpose: 'vapid', createdAt: number,                            │    │
│  │     keyType: 'application-key'                                      │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │ Storage: keys:{kid} → WrappedKeyV2                                  │    │
│  │   {                                                                 │    │
│  │     kid: string, kmsVersion: 2,                                     │    │
│  │     wrappedKey: ArrayBuffer, iv: ArrayBuffer(12),                   │    │
│  │     aad: ArrayBuffer,        // V2 NEW: Store for unwrap            │    │
│  │     publicKeyRaw: ArrayBuffer(65), // Uncompressed P-256            │    │
│  │     alg: 'ES256', purpose: 'vapid',                                 │    │
│  │     createdAt: number, lastUsedAt?: number                          │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │ Extractability Window: Created with extractable:true for wrapping,  │    │
│  │                        unwrapped as extractable:false               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Unlock Context (withUnlock) - V2

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              UNLOCK CONTEXT (withUnlock) - V2 COMPLETE                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LOCATION: unlock.ts                                                        │
│  PURPOSE: Single unlock gate for all authenticated operations               │
│                                                                             │
│  INPUTS:                                                                    │
│    credentials: AuthCredentials                                             │
│      | { method: 'passphrase'; passphrase: string }                         │
│      | { method: 'passkey-prf'; prfOutput: ArrayBuffer }                    │
│      | { method: 'passkey-gate'; pepper: ArrayBuffer }                      │
│    operation: (mkek: CryptoKey) => Promise<T>                               │
│                                                                             │
│  OUTPUT: UnlockOperationResult<T>                                           │
│    { result: T, unlockTime: number, lockTime: number, duration: number }    │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  PHASE 1: UNLOCK (Decrypt MS)                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ const unlockTime = Date.now()                                       │    │
│  │ let ms: Uint8Array | null = null                                    │    │
│  │                                                                     │    │
│  │ try {                                                               │    │
│  │   // 1. Retrieve config from IndexedDB                              │    │
│  │   config = await getMeta('enrollment:enroll-{id}:config')           │    │
│  │                                                                     │    │
│  │   // 2. Derive KEK from credentials                                 │    │
│  │   switch (credentials.method) {                                     │    │
│  │     case 'passphrase':                                              │    │
│  │       kek = PBKDF2(pass, salt, calibrated_iters)                    │    │
│  │       // V2: Verify KCV before decrypt (fast-fail wrong password)   │    │
│  │       if (!verifyKCV(kek, config.kcv)) throw 'INVALID_PASS'         │    │
│  │       break                                                         │    │
│  │     case 'passkey-prf':                                             │    │
│  │       kek = HKDF(prfOutput, hkdfSalt, info)                         │    │
│  │       break                                                         │    │
│  │     case 'passkey-gate':                                            │    │
│  │       kek = HKDF(pass || pepper, salt, info)                        │    │
│  │       break                                                         │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │   // 3. Decrypt MS (with AAD verification - V2)                     │    │
│  │   ms = AES-GCM-256.decrypt(                                         │    │
│  │     key: kek,                                                       │    │
│  │     iv: config.msIV,                                                │    │
│  │     ciphertext: config.encryptedMS,                                 │    │
│  │     additionalData: config.msAAD  // V2: Validates metadata         │    │
│  │   )                                                                 │    │
│  │                                                                     │    │
│  │   // 4. Derive MKEK from MS (with deterministic salt - V2)          │    │
│  │   mkek = HKDF-SHA256(                                               │    │
│  │     ikm: ms,                                                        │    │
│  │     salt: SHA-256("ATS/KMS/MKEK/salt/v2"),  // V2: Non-zero         │    │
│  │     info: "ATS/KMS/MKEK/v2",                                        │    │
│  │     length: 256                                                     │    │
│  │   )                                                                 │    │
│  │   // MKEK: non-extractable, usage: ['wrapKey', 'unwrapKey']         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  PHASE 2: OPERATE (Execute with MKEK)                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │   // MS and MKEK now in memory (milliseconds only)                  │    │
│  │   const operationResult = await operation(mkek)                     │    │
│  │                                                                     │    │
│  │   // Operations can:                                                │    │
│  │   // - unwrapKey(kid, mkek, aad) to get application keys            │    │
│  │   // - wrapKey(newKey, mkek, aad) to store new keys                 │    │
│  │   // - sign/encrypt with unwrapped keys                             │    │
│  │   // - generate new keys and wrap them                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  PHASE 3: LOCK (Guaranteed Cleanup)                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │   const lockTime = Date.now()                                       │    │
│  │   const duration = lockTime - unlockTime                            │    │
│  │                                                                     │    │
│  │   return { result: operationResult, unlockTime, lockTime, duration }│    │
│  │                                                                     │    │
│  │ } finally {                                                         │    │
│  │   // GUARANTEED CLEANUP: Runs even if operation throws              │    │
│  │   if (ms) {                                                         │    │
│  │     ms.fill(0)    // Overwrite MS bytes with zeros                  │    │
│  │     ms = null      // Clear reference                               │    │
│  │   }                                                                 │    │
│  │   // MKEK is CryptoKey object, GC'd automatically                   │    │
│  │   // No persistent unlock state remains                             │    │
│  │ }                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  SECURITY PROPERTIES (V2):                                                  │
│    ✓ MS lifetime: ~50-100ms (only during operation)                         │
│    ✓ Guaranteed cleanup: finally block always executes                      │
│    ✓ No persistent state: No unlock state between operations                │
│    ✓ Timing tracked: Exact unlock duration logged                           │
│    ✓ Single gate: All operations must use withUnlock                        │
│    ✓ AAD verification: Prevents ciphertext replay/swap (V2)                 │
│    ✓ KCV fast-fail: Wrong password detected before decrypt (V2)             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## VAPID Operations (MVP Use Case)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   VAPID KEY GENERATION & JWT SIGNING                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PRIMARY USE CASE: KMS-issued VAPID for user-run relays                     │
│    - Long-lived leases (8-12h) for relay authorization                      │
│    - Short-lived JWTs (10-15min) for push service requests                  │
│    - Relay-agnostic (seamless failover)                                     │
│    - Quota enforcement (per-lease, per-endpoint)                            │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  VAPID KEY GENERATION                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: ECDSA P-256 (secp256r1)                                  │    │
│  │                                                                     │    │
│  │ 1. Generate Keypair:                                                │    │
│  │    keypair = crypto.subtle.generateKey(                             │    │
│  │      { name: 'ECDSA', namedCurve: 'P-256' },                        │    │
│  │      true,  // temporarily extractable for wrapping                 │    │
│  │      ['sign', 'verify']                                             │    │
│  │    )                                                                │    │
│  │                                                                     │    │
│  │ 2. Export Public Key:                                               │    │
│  │    publicKeyRaw = exportKey('raw', keypair.publicKey)               │    │
│  │    Format: 65 bytes (0x04 || x || y) uncompressed P-256 point       │    │
│  │                                                                     │    │
│  │ 3. Generate kid (RFC 7638 JWK Thumbprint):                          │    │
│  │    a. Convert to JWK: { kty:"EC", crv:"P-256", x:"..", y:".." }     │    │
│  │    b. Canonicalize: {"crv":"P-256","kty":"EC","x":"...","y":"..."}  │    │
│  │    c. Hash: kid = base64url(SHA-256(canonical))                     │    │
│  │    Result: Content-derived, deterministic identifier                │    │
│  │                                                                     │    │
│  │ 4. Wrap Private Key (inside withUnlock):                            │    │
│  │    wrappedKey = wrapKey(                                            │    │
│  │      'jwk', keypair.privateKey, mkek,                               │    │
│  │      { name: 'AES-GCM', iv: random(12), aad: metadata }  // V2: AAD │    │
│  │    )                                                                │    │
│  │                                                                     │    │
│  │ 5. Store in IndexedDB: keys:{kid} → WrappedKeyV2                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  JWT SIGNING (ES256)                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Standard: RFC 7515 (JWS), RFC 8292 (VAPID)                          │    │
│  │                                                                     │    │
│  │ 1. Unwrap Private Key (inside withUnlock):                          │    │
│  │    privateKey = unwrapKey(                                          │    │
│  │      'jwk', wrappedKeyData, mkek,                                   │    │
│  │      { name: 'AES-GCM', iv: stored, aad: stored },  // V2: AAD      │    │
│  │      { name: 'ECDSA', namedCurve: 'P-256' },                        │    │
│  │      false,  // non-extractable                                     │    │
│  │      ['sign']                                                       │    │
│  │    )                                                                │    │
│  │                                                                     │    │
│  │ 2. Construct JWT:                                                   │    │
│  │    header = { typ: 'JWT', alg: 'ES256', kid: kid }                  │    │
│  │    payload = {                                                      │    │
│  │      aud: 'https://fcm.googleapis.com',  // Push service origin     │    │
│  │      sub: 'mailto:admin@example.com',    // Contact                 │    │
│  │      exp: now + 900,                     // 15min (≤24h RFC 8292)   │    │
│  │      // V2 Private claims (for telemetry):                          │    │
│  │      uid: 'user-123',                    // User ID                 │    │
│  │      eid: 'ep-1',                        // Endpoint ID             │    │
│  │      jti: 'jwt-xyz',                     // JWT ID (correlation)    │    │
│  │      rid?: 'relay-abc'                   // Optional relay ID       │    │
│  │    }                                                                │    │
│  │    signatureInput = base64url(header) + '.' + base64url(payload)    │    │
│  │                                                                     │    │
│  │ 3. Sign with ECDSA:                                                 │    │
│  │    signature = crypto.subtle.sign(                                  │    │
│  │      { name: 'ECDSA', hash: 'SHA-256' },                            │    │
│  │      privateKey,                                                    │    │
│  │      new TextEncoder().encode(signatureInput)                       │    │
│  │    )                                                                │    │
│  │    // Modern browsers return P-1363 format (64 bytes = r || s)      │    │
│  │    // JWS ES256 requires P-1363 format - typically no conversion    │    │
│  │    // needed. DER↔P-1363 utilities available for edge cases.        │    │
│  │                                                                     │    │
│  │ 4. Final JWT:                                                       │    │
│  │    jwt = base64url(header) + '.' +                                  │    │
│  │          base64url(payload) + '.' +                                 │    │
│  │          base64url(signature)                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  VAPID LEASES (MVP Model)                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Lease: Long-lived permission for JWT issuance                       │    │
│  │   - Duration: 8-12h (renewable, ≤24h cap)                           │    │
│  │   - Relay-agnostic (not bound to specific relay)                    │    │
│  │   - Bound to: { userId, subs[], scope: "notifications:send" }       │    │
│  │   - Includes quotas: tokensPerHour, sendsPerMinute, etc.            │    │
│  │                                                                     │    │
│  │ Flow:                                                               │    │
│  │   1. PWA → KMS: leases.create({ userId, subs, ttlHours: 12 })       │    │
│  │   2. KMS: Create lease, initialize quotas, log to audit             │    │
│  │   3. KMS → PWA: { leaseId, exp, quotas }                            │    │
│  │   4. Relay → PWA: Request JWT for endpoint                          │    │
│  │   5. PWA → KMS: vapid.issue({ leaseId, endpoint })                  │    │
│  │   6. KMS: Check quota, sign JWT, log issuance, update quota         │    │
│  │   7. KMS → PWA: { jwt, pk, jti, exp }                               │    │
│  │   8. PWA → Relay: Forward JWT                                       │    │
│  │   9. Relay: Use JWT in Authorization header for push requests       │    │
│  │                                                                     │    │
│  │ Security:                                                           │    │
│  │   ✓ VAPID private key never leaves KMS                              │    │
│  │   ✓ JWTs are short-lived (10-15min)                                 │    │
│  │   ✓ Audience-bound (tied to push service origin)                    │    │
│  │   ✓ Quota enforcement (per-lease, per-endpoint)                     │    │
│  │   ✓ Full audit trail (every issuance logged)                        │    │
│  │   ✓ Relay-agnostic (graceful failover)                              │    │
│  │                                                                     │    │
│  │ Storage:                                                            │    │
│  │   - leases/{leaseId} → LeaseRecord                                  │    │
│  │   - quotas/{leaseId} → QuotaState                                   │    │
│  │   - audit/vapid-issuance → AuditEntry[] (tamper-evident)            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Audit Log (V2 Hardened)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   AUDIT LOG (V2 - TAMPER-EVIDENT CHAIN)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PURPOSE: Verifiable record of all KMS operations                           │
│                                                                             │
│  V2 IMPROVEMENTS:                                                           │
│    ✓ Sequence numbers (detect truncation)                                   │
│    ✓ Delegated audit keys (UAK/LAK/KIAK) - see design/05-audit-log.md       │
│    ✓ LRK (Lease Root Key) for wrapping LAK/KIAK                             │
│    ✓ Key ID reference (signerId instead of embedding pubkey)                │
│    ✓ Delegation certificates (UAK-signed authorization)                     │
│    ✓ Explicit versioning (kmsVersion: 2)                                    │
│                                                                             │
│  AUDIT DELEGATION ARCHITECTURE:                                             │
│    • UAK (User Audit Key): Signs user-authenticated operations              │
│      - Wrapped under MS (requires user auth to unwrap)                      │
│      - Used for: setup, lease creation, manual operations                   │
│    • LAK (Lease Audit Key): Signs lease-scoped background operations        │
│      - Wrapped under LRK (always available, no user auth needed)            │
│      - Used for: JWT issuance, quota enforcement, lease expiration          │
│      - Delegated via UAK-signed certificate, expires with lease             │
│    • KIAK (KMS Instance Audit Key): Signs system events                     │
│      - Wrapped under LRK (always available)                                 │
│      - Used for: boot, fail-secure transitions, attestation changes         │
│      - Delegated via UAK-signed certificate, rotates every 90 days          │
│                                                                             │
│  NOTE: See ./design/05-audit-log.md for complete delegation details         │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  AUDIT SIGNING KEYS (Ed25519)                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: Ed25519 (EdDSA with Curve25519)                          │    │
│  │                                                                     │    │
│  │ UAK (User Audit Key):                                               │    │
│  │   - Generated during setup alongside MS                             │    │
│  │   - Wrapped with MKEK (derived from MS)                             │    │
│  │   - Available only when user is authenticated                       │    │
│  │                                                                     │    │
│  │ LAK (Lease Audit Key):                                              │    │
│  │   - Generated during lease creation (per-lease)                     │    │
│  │   - Wrapped with LRK (always available)                             │    │
│  │   - Delegated via UAK-signed certificate                            │    │
│  │   - Expires with lease (no mid-lease rotation)                      │    │
│  │                                                                     │    │
│  │ KIAK (KMS Instance Audit Key):                                      │    │
│  │   - Generated once per installation                                 │    │
│  │   - Wrapped with LRK (always available)                             │    │
│  │   - Delegated via UAK-signed certificate                            │    │
│  │   - Rotates every 90 days or on code/attestation change             │    │
│  │                                                                     │    │
│  │ LRK (Lease Root Key):                                               │    │
│  │   - AES-GCM 256-bit key for wrapping LAK/KIAK                       │    │
│  │   - Stored as non-extractable CryptoKey in IndexedDB                │    │
│  │   - Always available (enables background audit logging)             │    │
│  │                                                                     │    │
│  │ Why Ed25519? Fast signing/verification, smaller sigs than ECDSA     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  AUDIT ENTRY STRUCTURE (V2 with Delegation)                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ {                                                                   │    │
│  │   // V2: Versioning and sequence                                    │    │
│  │   kmsVersion: 2,                                                    │    │
│  │   seqNum: number,              // Monotonic (detects truncation)    │    │
│  │   timestamp: number,            // Unix timestamp (ms)              │    │
│  │                                                                     │    │
│  │   // Operation metadata                                             │    │
│  │   op: string,                   // 'vapid:issue'|'lease:create'|... │    │
│  │   kid: string,                  // Key ID involved                  │    │
│  │   requestId: string,            // RPC correlation                  │    │
│  │   origin?: string,              // Caller origin (if provided)      │    │
│  │   leaseId?: string,             // Present if lease-related         │    │
│  │                                                                     │    │
│  │   // Unlock timing (for user-authenticated operations)              │    │
│  │   unlockTime?: number,          // When MS decrypted                │    │
│  │   lockTime?: number,            // When MS cleared                  │    │
│  │   duration?: number,            // MS lifetime in memory            │    │
│  │                                                                     │    │
│  │   // Operation-specific details                                     │    │
│  │   details?: {                                                       │    │
│  │     // For JWT signing                                              │    │
│  │     aud?: string, endpoint?: string, jti?: string, exp?: number,    │    │
│  │     // For lease operations                                         │    │
│  │     userId?: string, ttlHours?: number, quotas?: object,            │    │
│  │     // For system events                                            │    │
│  │     version?: string, codeHash?: string, manifestHash?: string,     │    │
│  │   },                                                                │    │
│  │                                                                     │    │
│  │   // Chain integrity                                                │    │
│  │   previousHash: string,         // SHA-256 of previous chainHash    │    │
│  │   chainHash: string,            // SHA-256 of this entry            │    │
│  │                                                                     │    │
│  │   // V2 DELEGATION SUPPORT                                          │    │
│  │   signer: 'UAK' | 'LAK' | 'KIAK',  // Which audit key signed this   │    │
│  │   signerId: string,             // base64url(SHA-256(publicKey))    │    │
│  │   cert?: AuditDelegationCert,   // For LAK: delegation certificate  │    │
│  │                                                                     │    │
│  │   // Ed25519 signature (V2: renamed from 'signature')               │    │
│  │   sig: string,                  // Ed25519(chainHash) (base64url)   │    │
│  │   sigNew?: string               // For rotation: dual signatures    │    │
│  │ }                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  CHAIN HASH COMPUTATION (V2)                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ For entry N:                                                        │    │
│  │   1. Canonicalize (without signature/chainHash):                    │    │
│  │      canonical = JSON.stringify({                                   │    │
│  │        kmsVersion, seqNum, timestamp, op, kid, requestId,           │    │
│  │        unlockTime, lockTime, duration, details, previousHash        │    │
│  │      })                                                             │    │
│  │                                                                     │    │
│  │   2. Concatenate with previous:                                     │    │
│  │      input = canonical + previousHash                               │    │
│  │                                                                     │    │
│  │   3. Compute SHA-256:                                               │    │
│  │      chainHash[N] = SHA-256(input)                                  │    │
│  │                                                                     │    │
│  │   4. Sign with Ed25519:                                             │    │
│  │      signature[N] = Ed25519.sign(auditPrivateKey, chainHash[N])     │    │
│  │                                                                     │    │
│  │ Genesis Entry:                                                      │    │
│  │   seqNum = 0, previousHash = "0000...0000" (64 hex zeros)           │    │
│  │                                                                     │    │
│  │ V2 Truncation Detection:                                            │    │
│  │   - Sequence numbers must be consecutive (0, 1, 2, ...)             │    │
│  │   - Any gap indicates deleted entries                               │    │
│  │   - Verification fails if seqNum jumps                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  VERIFICATION PROCESS (V2 with Delegation)                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ async function verifyAuditChain(entries, uakPubKey, kiakPubKey) {   │    │
│  │   let previousHash = "0000...0000"                                  │    │
│  │   let expectedSeqNum = 0                                            │    │
│  │   const lakKeys = new Map()  // Cache LAK public keys               │    │
│  │                                                                     │    │
│  │   for (entry of allEntries) {                                       │    │
│  │     // V2: Check sequence continuity                                │    │
│  │     if (entry.seqNum !== expectedSeqNum) return false               │    │
│  │                                                                     │    │
│  │     // Verify chain hash                                            │    │
│  │     computed = SHA-256(canonicalize(entry))                         │    │
│  │     if (computed !== entry.chainHash) return false                  │    │
│  │                                                                     │    │
│  │     // V2 DELEGATION: Verify based on signer type                   │    │
│  │     switch (entry.signer) {                                         │    │
│  │       case 'UAK':                                                   │    │
│  │         valid = Ed25519.verify(uakPubKey, entry.sig, chainHash)     │    │
│  │         break                                                       │    │
│  │                                                                     │    │
│  │       case 'LAK':                                                   │    │
│  │         // Verify delegation cert signed by UAK                     │    │
│  │         if (!verifyDelegationCert(entry.cert, uakPubKey))           │    │
│  │           return false                                              │    │
│  │         // Check cert scope & validity                              │    │
│  │         if (!entry.cert.scope.includes(entry.op)) return false      │    │
│  │         if (entry.timestamp > entry.cert.notAfter) return false     │    │
│  │         // Verify entry signature with LAK                          │    │
│  │         lakPubKey = importKey(entry.cert.delegatePub)               │    │
│  │         valid = Ed25519.verify(lakPubKey, entry.sig, chainHash)     │    │
│  │         break                                                       │    │
│  │                                                                     │    │
│  │       case 'KIAK':                                                  │    │
│  │         valid = Ed25519.verify(kiakPubKey, entry.sig, chainHash)    │    │
│  │         break                                                       │    │
│  │     }                                                               │    │
│  │     if (!valid) return false                                        │    │
│  │                                                                     │    │
│  │     previousHash = entry.chainHash                                  │    │
│  │     expectedSeqNum++                                                │    │
│  │   }                                                                 │    │
│  │   return true                                                       │    │
│  │ }                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  SECURITY PROPERTIES (V2):                                                  │
│    ✓ Tamper detection: Any modification invalidates chain                   │
│    ✓ Truncation detection: Sequence numbers must be consecutive (V2)        │
│    ✓ Non-extractable key: Audit key can't be exported without auth (V2)     │
│    ✓ Backup capability: Can export audit key for recovery (V2)              │
│    ✓ Timing visibility: Every operation's MS lifetime logged                │
│    ✓ Attribution: requestId, origin, details for correlation                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Boundaries (Defense in Depth)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SECURITY BOUNDARIES & ISOLATION                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 1: Cross-Origin Isolation (Browser-Enforced)                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Main PWA Origin:    https://allthe.services                         │    │
│  │ KMS Enclave Origin: https://kms.ats.run                             │    │
│  │                                                                     │    │
│  │ Browser Enforcement:                                                │    │
│  │   ✓ Separate security contexts                                      │    │
│  │   ✓ No shared DOM                                                   │    │
│  │   ✓ No shared JavaScript                                            │    │
│  │   ✓ Only postMessage for communication                              │    │
│  │   ✓ Same-origin policy prevents PWA from accessing iframe internals │    │
│  │                                                                     │    │
│  │ Benefit: XSS in PWA cannot access KMS memory or keys                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  LAYER 2: Sandboxed Iframe                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ <iframe src="https://kms.ats.run/kms.html"                          │    │
│  │         sandbox="allow-scripts allow-same-origin"                   │    │
│  │         referrerpolicy="no-referrer"                                │    │
│  │         allow="publickey-credentials-get;                           │    │
│  │                publickey-credentials-create">                       │    │
│  │                                                                     │    │
│  │ Sandbox Restrictions:                                               │    │
│  │   ✓ allow-scripts: Required for Worker execution                    │    │
│  │   ✓ allow-same-origin: Safe because cross-origin                    │    │
│  │   ✗ allow-forms: Disabled                                           │    │
│  │   ✗ allow-popups: Disabled                                          │    │
│  │   ✗ allow-top-navigation: Disabled                                  │    │
│  │                                                                     │    │
│  │ Permissions Policy:                                                 │    │
│  │   ✓ publickey-credentials-*: Required for WebAuthn                  │    │
│  │   ✗ All others: Denied                                              │    │
│  │                                                                     │    │
│  │ Why allow-same-origin is safe:                                      │    │
│  │   - KMS iframe is on DIFFERENT origin                               │    │
│  │     (kms.ats.run ≠ allthe.services)                                 │    │
│  │   - Browser enforces isolation regardless of sandbox flags          │    │
│  │   - Necessary for runtime self-check (fetch own source)             │    │
│  │   - Necessary for reliable IndexedDB                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  LAYER 3: Dedicated Worker (No DOM Access)                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Location: Created by KMS iframe                                     │    │
│  │ Type: Dedicated Worker (not SharedWorker)                           │    │
│  │                                                                     │    │
│  │ Isolation Properties:                                               │    │
│  │   ✓ No DOM access (no document, window)                             │    │
│  │   ✓ No phishing vector (cannot create UI)                           │    │
│  │   ✓ Separate JavaScript context                                     │    │
│  │   ✓ Communication only via postMessage                              │    │
│  │                                                                     │    │
│  │ Crypto Operations:                                                  │    │
│  │   ✓ All WebCrypto operations in Worker                              │    │
│  │   ✓ MS and MKEK only exist in Worker memory                         │    │
│  │   ✓ No key material in iframe or PWA                                │    │
│  │                                                                     │    │
│  │ Benefit: Even if iframe compromised, cannot display phishing UI     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  LAYER 4: Non-Extractable CryptoKeys (Browser Subsystem)                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ All keys created with extractable: false                            │    │
│  │                                                                     │    │
│  │   KEKs (encrypt MS):         extractable: false                     │    │
│  │   MKEK (wrap app keys):      extractable: false                     │    │
│  │   VAPID private keys:        extractable: false (after unwrap)      │    │
│  │   Audit private key:         extractable: false (with export API)   │    │
│  │                                                                     │    │
│  │ Browser Enforcement:                                                │    │
│  │   ✓ crypto.subtle.exportKey() throws error                          │    │
│  │   ✓ Cannot extract key material                                     │    │
│  │   ✓ Can only use via crypto.subtle API (sign/encrypt/wrap)          │    │
│  │   ✓ Enforced at browser crypto subsystem level                      │    │
│  │                                                                     │    │
│  │ Benefit: Even compromised Worker cannot export keys                 │    │
│  │                                                                     │    │
│  │ V2 Note: Extractability window during wrapping (documented)         │    │
│  │   - Key generated as extractable:true for wrapKey()                 │    │
│  │   - Immediately wrapped, then reference dropped                     │    │
│  │   - When unwrapped, created as extractable:false                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  LAYER 5: SRI Verification (Code Integrity)                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Subresource Integrity (SRI) on module load:                         │    │
│  │                                                                     │    │
│  │ <script type="module"                                               │    │
│  │    integrity="sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU="  │    │
│  │    src="/kms-v2.0.0-7f8a9b0c.mjs">                                  │    │
│  │ </script>                                                           │    │
│  │                                                                     │    │
│  │ Browser Behavior:                                                   │    │
│  │   1. Fetch module from src URL                                      │    │
│  │   2. Compute SHA-256 hash of fetched content                        │    │
│  │   3. Compare with integrity attribute                               │    │
│  │   4. If mismatch: REFUSE to execute, throw error                    │    │
│  │   5. If match: Execute module                                       │    │
│  │                                                                     │    │
│  │ Why not on <iframe>?                                                │    │
│  │   - Browsers ignore integrity attribute on iframe tags              │    │
│  │   - Must apply SRI to <script> tags INSIDE kms.html                 │    │
│  │   - Runtime self-check provides additional layer                    │    │
│  │                                                                     │    │
│  │ Benefit: Detects CDN tampering, supply chain attacks                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  LAYER 6: Runtime Self-Check (Fail-Secure Verification)                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ On module load:                                                     │    │
│  │   1. Fetch own source: fetch(import.meta.url)                       │    │
│  │   2. Compute SHA-256 of fetched content                             │    │
│  │   3. Compare with expected hash (from build manifest)               │    │
│  │   4. If mismatch: HALT (refuse all crypto operations)               │    │
│  │   5. If match: Initialize Worker and accept RPC                     │    │
│  │                                                                     │    │
│  │ Why necessary?                                                      │    │
│  │   - SRI only checks at load time                                    │    │
│  │   - Runtime check validates running code                            │    │
│  │   - Provides additional verification layer                          │    │
│  │                                                                     │    │
│  │ Requires allow-same-origin:                                         │    │
│  │   - fetch(import.meta.url) needs same-origin request                │    │
│  │   - Safe because iframe is on different origin                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  LAYER 7: Content Security Policy (Zero External Resources)                 │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Content-Security-Policy (in kms.html <meta> tag):                   │    │
│  │                                                                     │    │
│  │   default-src 'none';                                               │    │
│  │   script-src 'self';                                                │    │
│  │   connect-src 'self';                                               │    │
│  │   worker-src 'self';                                                │    │
│  │   style-src 'none';                                                 │    │
│  │   img-src 'none';                                                   │    │
│  │   font-src 'none';                                                  │    │
│  │   object-src 'none';                                                │    │
│  │   media-src 'none';                                                 │    │
│  │   frame-src 'none';                                                 │    │
│  │   child-src 'none';                                                 │    │
│  │   form-action 'none';                                               │    │
│  │   frame-ancestors https://allthe.services;                          │    │
│  │   base-uri 'none';                                                  │    │
│  │   manifest-src 'none';                                              │    │
│  │                                                                     │    │
│  │ What this blocks:                                                   │    │
│  │   ✗ External scripts (no CDN dependencies)                          │    │
│  │   ✗ External connections (no analytics, telemetry)                  │    │
│  │   ✗ Inline scripts (prevents injection)                             │    │
│  │   ✗ All media, fonts, objects                                       │    │
│  │   ✓ Only same-origin scripts, connects, workers allowed             │    │
│  │   ✓ Can only be embedded in allthe.services                         │    │
│  │                                                                     │    │
│  │ Benefit: Eliminates supply chain attack surface                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  COMBINED EFFECT:                                                           │
│    ✓ PWA compromise → Cannot access KMS (Layer 1)                           │
│    ✓ Iframe compromise → Cannot display phishing UI (Layer 3)               │
│    ✓ Worker compromise → Cannot export keys (Layer 4)                       │
│    ✓ CDN compromise → SRI verification fails (Layer 5)                      │
│    ✓ Runtime tampering → Self-check fails (Layer 6)                         │
│    ✓ External dependencies → CSP blocks (Layer 7)                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Architecture (Separation of Concerns)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MODULE ARCHITECTURE (V2)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 4: USER INTERFACE                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ kms-user.ts (PWA - allthe.services)                                 │    │
│  │   - Setup/unlock API                                                │    │
│  │   - WebAuthn ceremonies (passkey create/get)                        │    │
│  │   - VAPID lease management                                          │    │
│  │   - Request/response correlation                                    │    │
│  │   - Timeout handling                                                │    │
│  └─────────────────────────────────┬───────────────────────────────────┘    │
│                                    │ postMessage (cross-origin)             │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                    ↓                                        │
│  LAYER 3: BRIDGE                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ client.ts (Iframe - kms.ats.run)                                    │    │
│  │   - Origin validation                                               │    │
│  │   - Message forwarding (PWA ↔ Worker)                               │    │
│  │   - Worker lifecycle management                                     │    │
│  │   - Minimal logic (bridge only)                                     │    │
│  └─────────────────────────────────┬───────────────────────────────────┘    │
│                                    │ postMessage (Worker)                   │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                    ↓                                        │
│  LAYER 2: ORCHESTRATION                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ worker.ts (KMS Worker)                                              │    │
│  │   - RPC request routing                                             │    │
│  │   - Policy enforcement (quotas, leases, rate limits)                │    │
│  │   - Operation coordination                                          │    │
│  │   - Error handling and validation                                   │    │
│  │   - Delegates to domain modules (no direct crypto)                  │    │
│  └───────────┬────────────────────┬────────────────────┬───────────────┘    │
│              │                    │                    │                    │
│  ═══════════════════════════════════════════════════════════════════════    │
│              │                    │                    │                    │
│  LAYER 1: DOMAIN LOGIC                                                      │
│  ┌───────────▼────────────┐ ┌─────▼──────────┐ ┌─────▼──────────┐           │
│  │ unlock.ts              │ │ audit.ts       │ │ (future)       │           │
│  │ - Setup methods        │ │ - Log ops      │ │ signal.ts      │           │
│  │ - Unlock (decrypt MS)  │ │ - Verify chain │ │ - E2EE msgs    │           │
│  │ - withUnlock gate      │ │ - Ed25519 sig  │ │ - Double       │           │
│  │ - MKEK derivation      │ │ - Sequence #s  │ │   Ratchet      │           │
│  │ - Multi-enrollment     │ │ - Export key   │ │                │           │
│  └────────────┬───────────┘ └────────┬───────┘ └────────────────┘           │
│               │                      │                                      │
│               └──────────┬───────────┘                                      │
│  ═══════════════════════════════════════════════════════════════════════    │
│                          │                                                  │
│  LAYER 0: INFRASTRUCTURE                                                    │
│  ┌──────────────────────▼──────────────────────┐                            │
│  │ storage.ts                                  │                            │
│  │ - IndexedDB CRUD                            │                            │
│  │ - Key wrapping/unwrapping (with AAD)        │                            │
│  │ - Metadata storage (configs, audit)         │                            │
│  │ - Query operations                          │                            │
│  └───────────────────────────────────────────┬─┘                            │
│                          │                   │                              │
│  ┌───────────────────────▼───────────────────▼─┐                            │
│  │ crypto-utils.ts (Pure Utilities)            │                            │
│  │ - Signature format utilities (DER↔P-1363)   │                            │
│  │ - JWK thumbprint (RFC 7638)                 │                            │
│  │ - AAD construction                          │                            │
│  │ - KCV computation                           │                            │
│  │ - Deterministic salt derivation             │                            │
│  │ - PBKDF2 calibration                        │                            │
│  │ - Constant-time comparison                  │                            │
│  │ - Base64url encoding/decoding               │                            │
│  └─────────────────────────────────────────────┘                            │
│                                                                             │
│  DEPENDENCY RULES:                                                          │
│    ✓ Higher layers import from lower layers                                 │
│    ✗ Lower layers CANNOT import from higher layers                          │
│    ✓ Same-layer imports OK if no circular deps                              │
│                                                                             │
│  FILE SIZE TARGETS (Auditability):                                          │
│    crypto-utils.ts:  500 lines (max 800)                                    │
│    storage.ts:       300 lines (max 500)                                    │
│    unlock.ts:        600 lines (max 1000)                                   │
│    audit.ts:         400 lines (max 600)                                    │
│    worker.ts:        800 lines (max 1200)                                   │
│    client.ts:        200 lines (max 300)                                    │
│    kms-user.ts:      500 lines (max 700)                                    │
│    TOTAL:           3300 lines (max 5100)                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Storage Schema (V2)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INDEXEDDB STORAGE SCHEMA (V2)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Database: kms-v2                                                           │
│  Version: 2                                                                 │
│                                                                             │
│  OBJECT STORES:                                                             │
│                                                                             │
│  1. keys (Primary: kid)                                                     │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ kid: string              // JWK thumbprint (RFC 7638)           │     │
│     │ kmsVersion: 2                                                   │     │
│     │ wrappedKey: ArrayBuffer  // AES-GCM wrapped JWK                 │     │
│     │ iv: ArrayBuffer(12)      // AES-GCM IV                          │     │
│     │ aad: ArrayBuffer         // V2: Metadata binding                │     │
│     │ publicKeyRaw: ArrayBuffer // 65 bytes (uncompressed P-256)      │     │
│     │ alg: 'ES256' | 'EdDSA'                                          │     │
│     │ purpose: 'vapid' | 'audit' | 'identity'                         │     │
│     │ createdAt: number                                               │     │
│     │ lastUsedAt?: number                                             │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  2. meta (Primary: key)                                                     │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Keys:                                                           │     │
│     │   enrollment:index             → EnrollmentIndex                │     │
│     │   enrollment:enroll-{id}:config→ PassphraseConfigV2 |           │     │
│     │                                  PasskeyPRFConfigV2             │     │
│     │   ms:metadata                  → { createdAt, version }         │     │
│     │   audit:public-key             → { keyId, publicKey }           │     │
│     │   calibration:pbkdf2           → CalibrationResult              │     │
│     │   vapid:lease-{id}             → LeaseRecord                    │     │
│     │   vapid:quota-{id}             → QuotaState                     │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  3. audit (Primary: seqNum, Index: timestamp)                               │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ seqNum: number           // V2: Monotonic sequence              │     │
│     │ kmsVersion: 2                                                   │     │
│     │ timestamp: number                                               │     │
│     │ op: string                                                      │     │
│     │ kid: string                                                     │     │
│     │ requestId: string                                               │     │
│     │ origin?: string                                                 │     │
│     │ unlockTime?: number                                             │     │
│     │ lockTime?: number                                               │     │
│     │ duration?: number                                               │     │
│     │ details?: Record<string, unknown>                               │     │
│     │ previousHash: string                                            │     │
│     │ chainHash: string                                               │     │
│     │ signature: string                                               │     │
│     │ auditKeyId: string       // V2: Key ID reference                │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  MIGRATION FROM V1:                                                         │
│    - V1 → V2 is BREAKING (incompatible data structures)                     │
│    - Users must reset and re-setup                                          │
│    - V1 data can be exported for archival (public keys, audit)              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## References & Standards

**Crypto Primitives**:
- PBKDF2: RFC 8018, NIST SP 800-132
- HKDF: RFC 5869
- AES-GCM: NIST SP 800-38D
- ECDSA P-256: FIPS 186-4, SEC 1
- Ed25519: RFC 8032

**Web Standards**:
- WebCrypto API: W3C Recommendation
- WebAuthn: W3C Level 2
- IndexedDB: W3C Recommendation
- Web Workers: W3C Recommendation

**JWT/VAPID**:
- JWS: RFC 7515
- JWT: RFC 7519
- VAPID: RFC 8292
- JWK Thumbprint: RFC 7638

**Security**:
- CSP: W3C Level 3
- SRI: W3C Recommendation
- Sandbox: HTML5 Specification

**Design References**:
- Complete specifications: `docs/architecture/crypto/V2/design/`
- Implementation guide: `docs/architecture/crypto/design/06-implementation-guide.md`
- Security model: `docs/architecture/crypto/V2/design/08-security-model.md`
- VAPID leases: `docs/architecture/crypto/V2/design/12-vapid-leases.md`

---

## Implementation Checklist

**Critical Items** (Must be done correctly):
- [ ] PBKDF2 calibration (150-300ms target)
- [ ] AAD for all AES-GCM operations
- [ ] KCV for passphrase verification
- [ ] Deterministic HKDF salts
- [ ] Signature format validation (ensure P-1363)
- [ ] Multi-enrollment storage schema
- [ ] Sequence numbers in audit log
- [ ] Non-extractable audit key (with export API)
- [ ] Lease-based VAPID authorization
- [ ] Quota enforcement (per-lease, per-endpoint)

**Testing Requirements**:
- [ ] Unit tests for all modules (>95% coverage)
- [ ] Integration tests (setup → unlock → ops)
- [ ] Security tests (AAD mismatch, timing attacks)
- [ ] Browser compatibility (Chrome, Firefox, Safari)
- [ ] Performance targets (unlock <300ms, sign <50ms)

**Documentation**:
- [ ] API reference for kms-user.ts
- [ ] Module architecture guide
- [ ] Migration guide (V1 → V2)
- [ ] Deployment instructions

---

**Status**: Design Complete → Ready for Implementation

Use this diagram alongside detailed design docs in `docs/architecture/crypto/V2/design/` for complete specifications.
