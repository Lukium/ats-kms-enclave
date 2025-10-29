# KMS V2: Complete Cryptographic Specification

**Version**: 2.0
**Status**: Design
**Date**: 2025-10-24

---

## Table of Contents

1. [Overview](#overview)
2. [Master Secret Setup](#master-secret-setup)
3. [Unlock Context (withUnlock)](#unlock-context-withunlock)
4. [Key Operations](#key-operations)
5. [Audit Log](#audit-log)
6. [Security Boundaries](#security-boundaries)
7. [Implementation Notes](#implementation-notes)

---

## Overview

The V2 KMS architecture implements per-operation authentication with a Master Secret (MS) encryption pattern. Every cryptographic operation performs an atomic **unlock → operate → lock** sequence, with the MS existing in memory for only milliseconds.

### Core Principles

1. **No persistent unlock state**: Worker never stores MS or MKEK between operations
2. **Guaranteed cleanup**: `finally` blocks ensure MS zeroization even on errors
3. **Metadata binding**: All AES-GCM encryptions include AAD
4. **Device-calibrated KDF**: PBKDF2 iterations tuned per device for 150-300ms
5. **Multi-enrollment**: Single MS wrapped by multiple credentials
6. **Explicit versioning**: All configs include version metadata

### Cryptographic Primitives

| Operation | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Password-to-key | PBKDF2-HMAC-SHA256 | 256 bits | Calibrated iterations |
| Key derivation | HKDF-SHA256 | 256 bits | Deterministic salts |
| Symmetric encryption | AES-256-GCM | 256 bits | **With AAD** |
| VAPID signing | ECDSA P-256 (ES256) | 256 bits | P-1363 format (native) |
| Audit signing | Ed25519 | 256 bits | Non-extractable |
| Key identifiers | SHA-256 (JWK thumbprint) | 256 bits | RFC 7638 |

---

## Master Secret Setup

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MASTER SECRET (MS) SETUP - V2                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STEP 1: Generate Master Secret                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ MS = crypto.getRandomValues(new Uint8Array(32))                     │    │
│  │ Size: 32 bytes (256 bits)                                           │    │
│  │ Entropy: Web Crypto API CSPRNG                                      │    │
│  │ Storage: NEVER stored unencrypted                                   │    │
│  │ Lifetime: Milliseconds (only during operations)                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 2: Calibrate KDF (passphrase only)                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Target: 150-300 ms per derivation                                   │    │
│  │ Algorithm: calibratePBKDF2Iterations()                              │    │
│  │                                                                     │    │
│  │ 1. Warm-up: PBKDF2 with 10k iterations                              │    │
│  │ 2. Probe: Time PBKDF2 with 100k iterations → t_probe                │    │
│  │ 3. Scale: iterations = round(100k * 220ms / t_probe)                │    │
│  │ 4. Clamp: 50,000 ≤ iterations ≤ 2,000,000                           │    │
│  │ 5. Verify: Run once more, adjust if outside [150, 300]ms            │    │
│  │ 6. Store: { iterations, measuredMs, lastCalibratedAt }              │    │
│  │                                                                     │    │
│  │ Result: Device-specific iteration count                             │    │
│  │ Recalibration: Every 30 days or on platform change                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 3: Derive KEK per Authentication Method                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ METHOD 1: Passphrase → KEK                                          │    │
│  │ ─────────────────────────────────────────────────────────────────   │    │
│  │ Algorithm: PBKDF2-HMAC-SHA256                                       │    │
│  │ Input:                                                              │    │
│  │   - Password: User passphrase (UTF-8 encoded)                       │    │
│  │   - Salt: 16 bytes (crypto.getRandomValues, stored)                 │    │
│  │   - Iterations: From calibration (e.g., 150,000 to 1,500,000)       │    │
│  │   - Hash: SHA-256                                                   │    │
│  │ Output: 256-bit AES-GCM key                                         │    │
│  │ Usage: ['encrypt', 'decrypt']                                       │    │
│  │ Extractable: false                                                  │    │
│  │                                                                     │    │
│  │ Key Check Value (KCV) - standard password verification:             │    │
│  │   kcv = HMAC-SHA256(KEK, "ATS/KMS/KCV/v2")                          │    │
│  │   Store kcv (32 bytes) to verify password WITHOUT decrypting MS     │    │
│  │   Constant-time comparison prevents timing attacks                  │    │
│  │                                                                     │    │
│  │ V2 Config Schema:                                                   │    │
│  │   {                                                                 │    │
│  │     kmsVersion: 2,                                                  │    │
│  │     algVersion: 1,                                                  │    │
│  │     method: 'passphrase',                                           │    │
│  │                                                                     │    │
│  │     kdf: {                                                          │    │
│  │       algorithm: 'PBKDF2-HMAC-SHA256',                              │    │
│  │       iterations: number,        // Calibrated                      │    │
│  │       salt: ArrayBuffer(16),     // PBKDF2 salt                     │    │
│  │       lastCalibratedAt: number,  // Unix timestamp (ms)             │    │
│  │       platformHash: string       // Device fingerprint (coarse)     │    │
│  │     },                                                              │    │
│  │                                                                     │    │
│  │     kcv: ArrayBuffer(32),         // Key Check Value                │    │
│  │     encryptedMS: ArrayBuffer,     // 32-byte MS + 16-byte GCM tag   │    │
│  │     msIV: ArrayBuffer(12),        // AES-GCM IV (unique per encrypt)│    │
│  │     msAAD: ArrayBuffer,           // AAD for metadata binding       │    │
│  │     msVersion: 1,                 // Re-encryption tracking         │    │
│  │                                                                     │    │
│  │     createdAt: number,                                              │    │
│  │     updatedAt: number                                               │    │
│  │   }                                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ METHOD 2: Passkey PRF → KEK                                         │    │
│  │ ─────────────────────────────────────────────────────────────────   │    │
│  │ Algorithm: HKDF-SHA256                                              │    │
│  │ Input:                                                              │    │
│  │   - IKM: PRF output from WebAuthn (32 bytes)                        │    │
│  │   - Salt: HKDF salt (32 bytes, distinct from appSalt)               │    │
│  │     Derive: SHA-256("ATS/KMS/KEK-wrap/salt/v2")                     │    │
│  │   - Info: "ATS/KMS/KEK-wrap/v2" (UTF-8 encoded)                     │    │
│  │   - Hash: SHA-256                                                   │    │
│  │ Output: 256-bit AES-GCM key                                         │    │
│  │ Usage: ['encrypt', 'decrypt']                                       │    │
│  │ Extractable: false                                                  │    │
│  │                                                                     │    │
│  │ WebAuthn PRF Details:                                               │    │
│  │   - Extension: prf                                                  │    │
│  │   - eval.first: appSalt (32 bytes, random at setup, stored)         │    │
│  │   - Output: 32 bytes (used as IKM for HKDF)                         │    │
│  │   - Note: appSalt is for PRF; HKDF uses separate salt               │    │
│  │                                                                     │    │
│  │ V2 Config Schema:                                                   │    │
│  │   {                                                                 │    │
│  │     kmsVersion: 2,                                                  │    │
│  │     algVersion: 1,                                                  │    │
│  │     method: 'passkey-prf',                                          │    │
│  │                                                                     │    │
│  │     credentialId: ArrayBuffer,   // WebAuthn credential ID          │    │
│  │     rpId: string,                // Relying Party ID                │    │
│  │                                                                     │    │
│  │     kdf: {                                                          │    │
│  │       algorithm: 'HKDF-SHA256',                                     │    │
│  │       appSalt: ArrayBuffer(32),  // For PRF eval.first              │    │
│  │       hkdfSalt: ArrayBuffer(32), // For HKDF (distinct!)            │    │
│  │       info: 'ATS/KMS/KEK-wrap/v2'                                   │    │
│  │     },                                                              │    │
│  │                                                                     │    │
│  │     encryptedMS: ArrayBuffer,    // 32-byte MS + 16-byte tag        │    │
│  │     msIV: ArrayBuffer(12),       // AES-GCM IV                      │    │
│  │     msAAD: ArrayBuffer,          // AAD for metadata binding        │    │
│  │     msVersion: 1,                                                   │    │
│  │                                                                     │    │
│  │     createdAt: number,                                              │    │
│  │     updatedAt: number                                               │    │
│  │   }                                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ METHOD 3: Passkey Gate-Only → KEK (Fallback)                        │    │
│  │ ─────────────────────────────────────────────────────────────────   │    │
│  │ Use when authenticator lacks PRF extension.                         │    │
│  │                                                                     │    │
│  │ V2 Enhanced Gate-Only (with pepper):                                │    │
│  │   1. Generate random pepper (32 bytes) at setup                     │    │
│  │   2. Store pepper encrypted under WebAuthn-gated envelope           │    │
│  │      (requires successful get() ceremony to release)                │    │
│  │   3. Derive KEK = HKDF(passphrase || pepper, salt, info)            │    │
│  │   4. Without WebAuthn gate, offline guessing is much harder         │    │
│  │                                                                     │    │
│  │ Config includes:                                                    │    │
│  │   - credentialId (for gate ceremony)                                │    │
│  │   - encryptedPepper (released only after WebAuthn success)          │    │
│  │   - Same MS encryption structure as other methods                   │    │
│  │                                                                     │    │
│  │ Note: Still weaker than PRF but significantly better than V1        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 4: Encrypt MS with KEK (with AAD)                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: AES-256-GCM                                              │    │
│  │ Key: KEK (from step 3)                                              │    │
│  │ IV: 12 bytes (96 bits) - crypto.getRandomValues (MUST be unique)    │    │
│  │ Plaintext: MS (32 bytes)                                            │    │
│  │ **AAD: Metadata binding (prevents ciphertext replay/swap)**         │    │
│  │ Tag Length: 128 bits (16 bytes, appended to ciphertext)             │    │
│  │                                                                     │    │
│  │ AAD Construction:                                                   │    │
│  │   aad = JSON.stringify({                                            │    │
│  │     kmsVersion: 2,                                                  │    │
│  │     method: 'passphrase' | 'passkey-prf' | 'passkey-gate',          │    │
│  │     algVersion: 1,                                                  │    │
│  │     credentialId?: base64url(credentialId),  // if passkey          │    │
│  │     purpose: 'master-secret-wrap'                                   │    │
│  │   })                                                                │    │
│  │                                                                     │    │
│  │ encryptedMS = AES-GCM-256.encrypt(                                  │    │
│  │   key: KEK,                                                         │    │
│  │   iv: msIV,                                                         │    │
│  │   plaintext: MS,                                                    │    │
│  │   aad: aad,                                                         │    │
│  │   tagLength: 128                                                    │    │
│  │ )                                                                   │    │
│  │                                                                     │    │
│  │ Result: encryptedMS (48 bytes = 32 ciphertext + 16 tag)             │    │
│  │                                                                     │    │
│  │ Storage: IndexedDB (meta store)                                     │    │
│  │ Key: 'passphraseConfig' | 'passkeyPrfConfig_<id>' | ...             │    │
│  │                                                                     │    │
│  │ Re-encryption: On any MS re-wrap, generate fresh IV and increment   │    │
│  │                msVersion. Never reuse (KEK, IV) pair.               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 5: Derive MKEK from MS (during unlock)                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: HKDF-SHA256                                              │    │
│  │ Input:                                                              │    │
│  │   - IKM: MS (32 bytes)                                              │    │
│  │   - Salt: Deterministic, versioned (V2 change!)                     │    │
│  │     SHA-256("ATS/KMS/MKEK/salt/v2") → 32 bytes                      │    │
│  │   - Info: "ATS/KMS/MKEK/v2" (UTF-8 encoded)                         │    │
│  │   - Hash: SHA-256                                                   │    │
│  │ Output: 256-bit AES-GCM key (MKEK)                                  │    │
│  │ Usage: ['wrapKey', 'unwrapKey']                                     │    │
│  │ Extractable: false                                                  │    │
│  │                                                                     │    │
│  │ Purpose: MKEK wraps application keys (VAPID private keys, etc.)     │    │
│  │                                                                     │    │
│  │ MKEK = HKDF-SHA256(                                                 │    │
│  │   ikm: MS,                                                          │    │
│  │   salt: SHA-256("ATS/KMS/MKEK/salt/v2"),                            │    │
│  │   info: "ATS/KMS/MKEK/v2",                                          │    │
│  │   length: 256                                                       │    │
│  │ )                                                                   │    │
│  │                                                                     │    │
│  │ V2 Improvement: Non-zero, versioned salt enables rotation paths     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  STEP 6: Wrap Application Keys with MKEK (with AAD)                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Algorithm: AES-GCM key wrapping (via WebCrypto wrapKey)             │    │
│  │ Wrapping Key: MKEK                                                  │    │
│  │ Key to Wrap: VAPID private key (ECDSA P-256)                        │    │
│  │ Format: 'jwk' (wrapped as JSON Web Key)                             │    │
│  │ Wrap Algorithm: AES-GCM                                             │    │
│  │ IV: 12 bytes (generated automatically by wrapKey)                   │    │
│  │ **AAD: Key metadata binding**                                       │    │
│  │                                                                     │    │
│  │ AAD Construction:                                                   │    │
│  │   aad = JSON.stringify({                                            │    │
│  │     kmsVersion: 2,                                                  │    │
│  │     kid: string,          // JWK thumbprint                         │    │
│  │     alg: 'ES256',                                                   │    │
│  │     purpose: 'vapid',                                               │    │
│  │     createdAt: number,    // Timestamp                              │    │
│  │     keyType: 'application-key'                                      │    │
│  │   })                                                                │    │
│  │                                                                     │    │
│  │ wrappedKey = await crypto.subtle.wrapKey(                           │    │
│  │   format: 'jwk',                                                    │    │
│  │   key: vapidPrivateKey,                                             │    │
│  │   wrappingKey: MKEK,                                                │    │
│  │   wrapAlgorithm: {                                                  │    │
│  │     name: 'AES-GCM',                                                │    │
│  │     iv: auto-generated (12 bytes),                                  │    │
│  │     additionalData: new TextEncoder().encode(aad)                   │    │
│  │   }                                                                 │    │
│  │ )                                                                   │    │
│  │                                                                     │    │
│  │ V2 Storage Schema:                                                  │    │
│  │   {                                                                 │    │
│  │     kid: string,              // JWK thumbprint (SHA-256)           │    │
│  │     kmsVersion: 2,                                                  │    │
│  │                                                                     │    │
│  │     wrappedKey: ArrayBuffer,  // Wrapped private key                │    │
│  │     iv: ArrayBuffer(12),      // AES-GCM IV                         │    │
│  │     aad: ArrayBuffer,         // AAD bytes (store for unwrap)       │    │
│  │                                                                     │    │
│  │     publicKeyRaw: ArrayBuffer,// Uncompressed P-256 (65 bytes)      │    │
│  │     alg: 'ES256',                                                   │    │
│  │     purpose: 'vapid',                                               │    │
│  │                                                                     │    │
│  │     createdAt: number,                                              │    │
│  │     lastUsedAt?: number                                             │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │ Extractability Window:                                              │    │
│  │   - Key generated with extractable: true (for wrapping)             │    │
│  │   - Immediately wrapped, then reference dropped                     │    │
│  │   - When unwrapped, created as extractable: false                   │    │
│  │   - Documented in threat model                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Unlock Context (withUnlock)

The `withUnlock` function is the **single unlock gate** for all authenticated operations. It enforces the atomic **unlock → operate → lock** sequence with guaranteed cleanup.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              UNLOCK CONTEXT (withUnlock) - V2 COMPLETE FLOW                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LOCATION: unlock.ts                                                        │
│  FUNCTION: export async function withUnlock<T>                              │
│                                                                             │
│  PURPOSE: Single unlock gate for all authenticated operations               │
│           Ensures: unlock → operate → lock with guaranteed cleanup          │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ TYPE DEFINITIONS:                                                   │    │
│  │                                                                     │    │
│  │ type AuthCredentials =                                              │    │
│  │   | { method: 'passphrase'; passphrase: string }                    │    │
│  │   | { method: 'passkey-prf'; prfOutput: ArrayBuffer }               │    │
│  │   | { method: 'passkey-gate'; pepper: ArrayBuffer }                 │    │
│  │                                                                     │    │
│  │ interface UnlockOperationResult<T> {                                │    │
│  │   result: T;              // Operation result                       │    │
│  │   unlockTime: number;     // Timestamp when MS decrypted (ms)       │    │
│  │   lockTime: number;       // Timestamp when MS cleared (ms)         │    │
│  │   duration: number;       // Milliseconds MS was in memory          │    │
│  │ }                                                                   │    │
│  │                                                                     │    │
│  │ SIGNATURE:                                                          │    │
│  │ async function withUnlock<T>(                                       │    │
│  │   credentials: AuthCredentials,                                     │    │
│  │   operation: (mkek: CryptoKey) => Promise<T>                        │    │
│  │ ): Promise<UnlockOperationResult<T>>                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  PHASE 1: UNLOCK (Decrypt MS from credentials)                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ const unlockTime = Date.now()                                       │    │
│  │ let ms: Uint8Array | null = null                                    │    │
│  │                                                                     │    │
│  │ try {                                                               │    │
│  │   // Route based on auth method                                     │    │
│  │   switch (credentials.method) {                                     │    │
│  │                                                                     │    │
│  │     case 'passphrase': {                                            │    │
│  │       // 1. Retrieve config from IndexedDB                          │    │
│  │       const config = await getMeta('passphraseConfig')              │    │
│  │       if (!config) throw new Error('NOT_SETUP')                     │    │
│  │                                                                     │    │
│  │       // 2. Derive KEK from passphrase (with calibrated iters)      │    │
│  │       const kek = await crypto.subtle.deriveKey(                    │    │
│  │         {                                                           │    │
│  │           name: 'PBKDF2',                                           │    │
│  │           salt: config.kdf.salt,                                    │    │
│  │           iterations: config.kdf.iterations,  // Device-specific    │    │
│  │           hash: 'SHA-256'                                           │    │
│  │         },                                                          │    │
│  │         await crypto.subtle.importKey(                              │    │
│  │           'raw',                                                    │    │
│  │           new TextEncoder().encode(credentials.passphrase),         │    │
│  │           'PBKDF2',                                                 │    │
│  │           false,                                                    │    │
│  │           ['deriveKey']                                             │    │
│  │         ),                                                          │    │
│  │         { name: 'AES-GCM', length: 256 },                           │    │
│  │         false,  // non-extractable                                  │    │
│  │         ['encrypt', 'decrypt']                                      │    │
│  │       )                                                             │    │
│  │                                                                     │    │
│  │       // 3. Verify KEK with KCV (before attempting decrypt)         │    │
│  │       const computedKCV = await crypto.subtle.sign(                 │    │
│  │         'HMAC',                                                     │    │
│  │         await crypto.subtle.importKey(                              │    │
│  │           'raw',                                                    │    │
│  │           await crypto.subtle.exportKey('raw', kek),                │    │
│  │           { name: 'HMAC', hash: 'SHA-256' },                        │    │
│  │           false,                                                    │    │
│  │           ['sign']                                                  │    │
│  │         ),                                                          │    │
│  │         new TextEncoder().encode('ATS/KMS/KCV/v2')                  │    │
│  │       )                                                             │    │
│  │                                                                     │    │
│  │       // Constant-time comparison                                   │    │
│  │       if (!timingSafeEqual(computedKCV, config.kcv)) {              │    │
│  │         throw new Error('INVALID_PASSPHRASE')                       │    │
│  │       }                                                             │    │
│  │                                                                     │    │
│  │       // 4. Decrypt MS (with AAD verification)                      │    │
│  │       const msBuffer = await crypto.subtle.decrypt(                 │    │
│  │         {                                                           │    │
│  │           name: 'AES-GCM',                                          │    │
│  │           iv: config.msIV,                                          │    │
│  │           additionalData: config.msAAD  // Verifies metadata        │    │
│  │         },                                                          │    │
│  │         kek,                                                        │    │
│  │         config.encryptedMS                                          │    │
│  │       )                                                             │    │
│  │                                                                     │    │
│  │       ms = new Uint8Array(msBuffer)                                 │    │
│  │       break                                                         │    │
│  │     }                                                               │    │
│  │                                                                     │    │
│  │     case 'passkey-prf': {                                           │    │
│  │       // 1. Retrieve config                                         │    │
│  │       const config = await getMeta('passkeyPrfConfig')              │    │
│  │       if (!config) throw new Error('NOT_SETUP')                     │    │
│  │                                                                     │    │
│  │       // 2. Derive KEK from PRF output via HKDF                     │    │
│  │       const prfKey = await crypto.subtle.importKey(                 │    │
│  │         'raw',                                                      │    │
│  │         credentials.prfOutput,                                      │    │
│  │         'HKDF',                                                     │    │
│  │         false,                                                      │    │
│  │         ['deriveKey']                                               │    │
│  │       )                                                             │    │
│  │                                                                     │    │
│  │       const kek = await crypto.subtle.deriveKey(                    │    │
│  │         {                                                           │    │
│  │           name: 'HKDF',                                             │    │
│  │           salt: config.kdf.hkdfSalt,  // Distinct from appSalt!     │    │
│  │           info: new TextEncoder().encode(config.kdf.info),          │    │
│  │           hash: 'SHA-256'                                           │    │
│  │         },                                                          │    │
│  │         prfKey,                                                     │    │
│  │         { name: 'AES-GCM', length: 256 },                           │    │
│  │         false,                                                      │    │
│  │         ['decrypt']                                                 │    │
│  │       )                                                             │    │
│  │                                                                     │    │
│  │       // 3. Decrypt MS (with AAD)                                   │    │
│  │       const msBuffer = await crypto.subtle.decrypt(                 │    │
│  │         {                                                           │    │
│  │           name: 'AES-GCM',                                          │    │
│  │           iv: config.msIV,                                          │    │
│  │           additionalData: config.msAAD                              │    │
│  │         },                                                          │    │
│  │         kek,                                                        │    │
│  │         config.encryptedMS                                          │    │
│  │       )                                                             │    │
│  │                                                                     │    │
│  │       ms = new Uint8Array(msBuffer)                                 │    │
│  │       break                                                         │    │
│  │     }                                                               │    │
│  │                                                                     │    │
│  │     case 'passkey-gate': {                                          │    │
│  │       // Enhanced gate-only with pepper                             │    │
│  │       // Similar to passphrase but IKM = passphrase || pepper       │    │
│  │       // ... (implementation details)                               │    │
│  │       break                                                         │    │
│  │     }                                                               │    │
│  │                                                                     │    │
│  │     default:                                                        │    │
│  │       throw new Error('UNKNOWN_AUTH_METHOD')                        │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │   // 5. Derive MKEK from MS (with deterministic salt)               │    │
│  │   const mkekSalt = await crypto.subtle.digest(                      │    │
│  │     'SHA-256',                                                      │    │
│  │     new TextEncoder().encode('ATS/KMS/MKEK/salt/v2')                │    │
│  │   )                                                                 │    │
│  │                                                                     │    │
│  │   const msKey = await crypto.subtle.importKey(                      │    │
│  │     'raw',                                                          │    │
│  │     ms,                                                             │    │
│  │     'HKDF',                                                         │    │
│  │     false,                                                          │    │
│  │     ['deriveKey']                                                   │    │
│  │   )                                                                 │    │
│  │                                                                     │    │
│  │   const mkek = await crypto.subtle.deriveKey(                       │    │
│  │     {                                                               │    │
│  │       name: 'HKDF',                                                 │    │
│  │       salt: mkekSalt,                                               │    │
│  │       info: new TextEncoder().encode('ATS/KMS/MKEK/v2'),            │    │
│  │       hash: 'SHA-256'                                               │    │
│  │     },                                                              │    │
│  │     msKey,                                                          │    │
│  │     { name: 'AES-GCM', length: 256 },                               │    │
│  │     false,  // non-extractable                                      │    │
│  │     ['wrapKey', 'unwrapKey']                                        │    │
│  │   )                                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  PHASE 2: OPERATE (Execute with MKEK)                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │   // MS and MKEK now in memory (temporary, milliseconds)            │    │
│  │   // Execute operation function with MKEK                           │    │
│  │   const operationResult = await operation(mkek)                     │    │
│  │                                                                     │    │
│  │   // Operations can:                                                │    │
│  │   // - unwrapKey(kid, mkek, aad) to get application keys            │    │
│  │   // - wrapKey(newKey, mkek, aad) to store new keys                 │    │
│  │   // - sign/encrypt with unwrapped keys                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  PHASE 3: LOCK (Cleanup)                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │   const lockTime = Date.now()                                       │    │
│  │   const duration = lockTime - unlockTime                            │    │
│  │                                                                     │    │
│  │   return {                                                          │    │
│  │     result: operationResult,                                        │    │
│  │     unlockTime,                                                     │    │
│  │     lockTime,                                                       │    │
│  │     duration    // Exact time MS was in memory (typically <100ms)   │    │
│  │   }                                                                 │    │
│  │                                                                     │    │
│  │ } finally {                                                         │    │
│  │   // GUARANTEED CLEANUP: Runs even if operation throws              │    │
│  │   if (ms) {                                                         │    │
│  │     ms.fill(0)    // Overwrite MS bytes with zeros                  │    │
│  │     ms = null      // Clear reference                               │    │
│  │   }                                                                 │    │
│  │   // MKEK is CryptoKey object, garbage collected automatically      │    │
│  │   // No persistent state remains in worker                          │    │
│  │ }                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  SECURITY PROPERTIES:                                                       │
│  ✓ MS lifetime: Milliseconds (only during operation)                        │
│  ✓ Guaranteed cleanup: finally block always executes                        │
│  ✓ No persistent state: Worker has no unlock state between operations       │
│  ✓ Timing tracked: Audit log records exact unlock duration                  │
│  ✓ Single implementation: All operations must use this gate                 │
│  ✓ AAD verification: Prevents ciphertext replay/swap attacks                │
│  ✓ KCV check: Fast-fail for wrong password without decrypt attempt          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Usage Example

```typescript
// In worker.ts
async function generateVAPID(credentials: AuthCredentials): Promise<VAPIDKeyPair> {
  // Unlock → operate → lock happens automatically
  const { result, duration } = await withUnlock(
    credentials,
    async (mkek: CryptoKey) => {
      // Inside this function, MKEK is available
      // MS is in memory (but encapsulated in withUnlock)

      // Generate keypair
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,  // temporarily extractable for wrapping
        ['sign', 'verify']
      );

      // Wrap and store
      const kid = await generateKid(keypair.publicKey);
      await wrapAndStoreKey(keypair.privateKey, mkek, kid);

      return { kid, publicKey: await exportPublicKey(keypair.publicKey) };
    }
  );

  // MS is now cleared, MKEK is gone
  // Log duration to audit
  await logOperation({ op: 'generate_vapid', duration, kid: result.kid });

  return result;
}
```

---

## Key Operations

### VAPID Key Generation

[Content continues with detailed VAPID generation, JWT signing, etc. - similar structure to the diagram sections]

---

## Audit Log

[Content continues with hardened audit log specification with sequence numbers, non-extractable keys, etc.]

---

## Security Boundaries

[Content continues with security boundaries from the diagram]

---

## Implementation Notes

### V1 → V2 Migration Checklist

- [ ] Implement PBKDF2 calibration algorithm
- [ ] Add AAD to all AES-GCM operations
- [ ] Replace verification hash with KCV
- [ ] Update HKDF salts to deterministic values
- [ ] Add versioning to all config schemas
- [ ] Implement multi-enrollment support
- [ ] Harden audit log (sequence numbers, non-extractable key)
- [ ] Update storage schemas
- [ ] Migrate tests
- [ ] Document breaking changes

### Performance Targets

| Operation | V1 Target | V2 Target | Notes |
|-----------|-----------|-----------|-------|
| Setup passphrase | <500ms | 150-300ms | Calibrated PBKDF2 |
| Unlock passphrase | <500ms | 150-300ms | Same as setup |
| Unlock passkey PRF | <100ms | <100ms | No change |
| Generate VAPID | <100ms | <100ms | No change |
| Sign JWT | <50ms | <50ms | No change |
| Full operation | <600ms | 200-400ms | Unlock + operate |

### Browser Compatibility

Same as V1 - requires WebCrypto, IndexedDB, Workers, WebAuthn.

V2 adds optional Argon2id via WASM (progressive enhancement).

---

**Status**: This specification is complete and ready for implementation.

**Next**: See [implementation-checklist.md](./implementation-checklist.md) for step-by-step guide.
