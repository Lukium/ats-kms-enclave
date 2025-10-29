# Key Operations (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Overview](#overview)
2. [VAPID Keypair Generation](#vapid-keypair-generation)
3. [JWT Signing (ES256)](#jwt-signing-es256)
4. [DER ↔ P-1363 Conversion](#der--p-1363-conversion)
5. [Public Key Export](#public-key-export)
6. [Key Wrapping](#key-wrapping)
7. [Audit Key Operations](#audit-key-operations)
8. [Complete Implementation](#complete-implementation)
9. [Testing Strategy](#testing-strategy)

---

## Overview

Key operations are the core functionality of KMS V2. The primary use case (MVP) is **VAPID JWT signing** for push notification authorization.

### Supported Operations

1. **VAPID Keys**: ECDSA P-256 keypairs for Web Push
2. **JWT Signing**: ES256 signatures for VAPID authentication
3. **Audit Keys**: Ed25519 keypairs for audit log signing (future)
4. **Identity Keys**: Ed25519/X25519 for Signal Protocol (future)

### Critical Challenges

⚠️ **PUBLIC KEY FORMAT MISMATCH**:
- WebCrypto exports **SPKI format** (~91 bytes with ASN.1 wrapper)
- `PushManager.subscribe()` expects **raw format** (65 bytes uncompressed)
- **Passing SPKI to push API will fail**

⚠️ **SIGNATURE FORMAT** (typically not an issue):
- Modern browsers return **P-1363 format** (exactly 64 bytes: r || s)
- JWS ES256 requires **P-1363 format** - no conversion needed
- Utilities provided for edge cases or legacy compatibility

This document provides production-ready solutions to both challenges.

---

## VAPID Keypair Generation

### Overview

VAPID (Voluntary Application Server Identification) keys are ECDSA P-256 keypairs used to sign JWTs for push notification authorization per RFC 8292.

### Generation Flow

```
withUnlock → Generate P-256 → Export Public Key → Wrap Private Key → Store
```

### Implementation

```typescript
/**
 * Generate VAPID keypair.
 *
 * ALGORITHM: ECDSA with P-256 curve (secp256r1)
 * PURPOSE: Sign VAPID JWTs for push notification authorization
 * STANDARD: RFC 8292 (VAPID), RFC 7518 (ES256)
 *
 * SECURITY:
 * - Private key temporarily extractable (for wrapping only)
 * - After wrapping, stored as non-extractable
 * - Public key exported in raw format (65 bytes uncompressed)
 * - kid = JWK thumbprint (SHA-256 of canonical JWK)
 *
 * @param credential User credential for unlock
 * @returns { kid, publicKey, wrappedKey }
 */
export async function generateVAPIDKeypair(
  credential: Credential
): Promise<{
  kid: string;
  publicKey: ArrayBuffer;  // 65 bytes (0x04 || x || y)
}> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Generate P-256 keypair (temporarily extractable)
      const keypair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256'  // Also known as secp256r1, prime256v1
        },
        true,  // extractable=true (for wrapping window)
        ['sign', 'verify']
      );

      // Export public key (raw format for VAPID)
      const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

      // Compute kid (JWK thumbprint)
      const kid = await computeJWKThumbprint(keypair.publicKey);

      // Build metadata for wrapping
      const metadata = {
        kid,
        alg: 'ES256' as const,
        purpose: 'vapid' as const,
        createdAt: Date.now(),
        kmsVersion: 2
      };

      // Wrap private key with MKEK + AAD
      const { wrappedKey, iv, aad } = await wrapApplicationKey(
        keypair.privateKey,
        ctx.mkek,
        metadata
      );

      // Store wrapped key configuration
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

      await storage.put(`key:${kid}`, config);

      return {
        kid,
        publicKey: publicKeyRaw
      };
    },
    {
      timeout: 10_000,  // 10s (generous for key generation)
      purpose: 'vapid:generate'
    }
  );
}
```

### JWK Thumbprint

```typescript
/**
 * Compute JWK thumbprint (kid) per RFC 7638.
 *
 * ALGORITHM:
 * 1. Export key as JWK
 * 2. Build canonical JWK (required members only, sorted keys)
 * 3. SHA-256 hash
 * 4. Base64url encode
 *
 * CANONICAL JWK FOR P-256:
 * {
 *   "crv": "P-256",
 *   "kty": "EC",
 *   "x": "<base64url>",
 *   "y": "<base64url>"
 * }
 *
 * @param publicKey CryptoKey (public key)
 * @returns kid (base64url-encoded SHA-256)
 */
export async function computeJWKThumbprint(
  publicKey: CryptoKey
): Promise<string> {
  // Export as JWK
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);

  // Build canonical JWK (required members only, sorted keys)
  const canonical = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  };

  // Stringify with sorted keys
  const canonicalJSON = JSON.stringify(canonical, ['crv', 'kty', 'x', 'y']);

  // SHA-256 hash
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalJSON)
  );

  // Base64url encode
  return base64url.encode(new Uint8Array(hash));
}
```

---

## JWT Signing (ES256)

### JWT Structure

```
JWT = Base64url(Header) || '.' || Base64url(Payload) || '.' || Base64url(Signature)
```

**Header**:
```json
{
  "typ": "JWT",
  "alg": "ES256"
}
```

**Payload** (VAPID-specific):
```json
{
  "aud": "https://fcm.googleapis.com",
  "sub": "mailto:ops@allthe.services",
  "exp": 1704067200,
  "iat": 1704063600,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Signing Flow

```
withUnlock → Unwrap Private Key → Sign (P-1363) → Build JWT
```

### Implementation

```typescript
/**
 * Sign VAPID JWT with ES256.
 *
 * Modern browsers return P-1363 format (64 bytes) which is
 * the required format for JWS ES256. No conversion needed.
 *
 * FLOW:
 * 1. Unlock and unwrap private key
 * 2. Build JWT header and payload
 * 3. Sign with ECDSA-SHA256 (returns P-1363 in modern browsers)
 * 4. Validate signature format (64 bytes)
 * 5. Build final JWT string
 *
 * @param credential User credential for unlock
 * @param payload JWT payload (aud, sub, exp, etc.)
 * @param kid Key identifier
 * @returns JWT string
 */
export async function signVAPIDJWT(
  credential: Credential,
  payload: VAPIDPayload,
  kid: string
): Promise<string> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Load wrapped key configuration
      const keyConfig = await storage.get(`key:${kid}`);
      if (!keyConfig || keyConfig.purpose !== 'vapid') {
        throw new Error(`VAPID key not found: ${kid}`);
      }

      // Unwrap private key with MKEK
      const privateKey = await unwrapApplicationKey(
        keyConfig.wrappedKey,
        ctx.mkek,
        keyConfig.iv,
        keyConfig.aad,
        { alg: 'ES256', purpose: 'vapid' }
      );

      // Build JWT header
      const header = {
        typ: 'JWT',
        alg: 'ES256'
      };

      // Build signing input
      const headerB64 = base64url.encode(
        new TextEncoder().encode(JSON.stringify(header))
      );
      const payloadB64 = base64url.encode(
        new TextEncoder().encode(JSON.stringify(payload))
      );
      const signingInput = `${headerB64}.${payloadB64}`;

      // Sign with ECDSA-SHA256 (returns P-1363 in modern browsers)
      const signature = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: 'SHA-256'
        },
        privateKey,
        new TextEncoder().encode(signingInput)
      );

      // Validate signature format (should be 64 bytes for P-256 P-1363)
      const signatureBytes = new Uint8Array(signature);
      if (signatureBytes.length !== 64) {
        throw new Error(`Invalid signature length: ${signatureBytes.length} (expected 64)`);
      }

      // Base64url encode signature
      const signatureB64 = base64url.encode(signatureBytes);

      // Build final JWT
      const jwt = `${signingInput}.${signatureB64}`;

      // Update last used timestamp
      await storage.update(`key:${kid}`, {
        lastUsedAt: Date.now()
      });

      return jwt;
    },
    {
      timeout: 5_000,  // 5s (signing is fast)
      purpose: 'vapid:sign'
    }
  );
}
```

### VAPID Payload Type

```typescript
/**
 * VAPID JWT payload per RFC 8292.
 */
interface VAPIDPayload {
  aud: string;      // Push service origin (e.g., "https://fcm.googleapis.com")
  sub: string;      // Contact URI (e.g., "mailto:ops@allthe.services")
  exp: number;      // Expiration time (Unix timestamp, seconds)
  iat: number;      // Issued at (Unix timestamp, seconds)
  jti: string;      // JWT ID (UUID, prevents replay)

  // Optional private claims (for attribution)
  uid?: string;     // User ID
  eid?: string;     // Endpoint ID
  rid?: string;     // Relay ID
}
```

---

## Signature Format Utilities (DER ↔ P-1363)

### Context

**Modern browsers** return P-1363 format from WebCrypto ECDSA operations:
```
r (exactly 32 bytes) || s (exactly 32 bytes)
Total: exactly 64 bytes
```

This is the format required by **JWS ES256** per RFC 7518, so no conversion is needed.

However, **edge cases or legacy compatibility** may require handling DER format:
```
SEQUENCE {
  r INTEGER (32-33 bytes with optional leading 0x00)
  s INTEGER (32-33 bytes with optional leading 0x00)
}
Total: ~70-72 bytes
```

The utilities below handle both formats for robustness.

### DER Structure

```
30 [len] 02 [rLen] [r bytes] 02 [sLen] [s bytes]
^^       ^^                   ^^
SEQUENCE INTEGER (r)          INTEGER (s)
```

**Examples**:
```
# Typical (70 bytes)
30 44 02 20 [32-byte r] 02 20 [32-byte s]

# With leading zeros (72 bytes)
30 46 02 21 00 [32-byte r] 02 21 00 [32-byte s]
```

### Conversion Implementation

```typescript
/**
 * Convert DER-encoded ECDSA signature to P-1363 format.
 *
 * DER FORMAT: SEQUENCE { r INTEGER, s INTEGER }
 * P-1363 FORMAT: r (32 bytes) || s (32 bytes)
 *
 * CRITICAL FOR: ES256 JWT signatures (WebCrypto → JWS)
 *
 * HANDLES:
 * - Leading 0x00 in integers (high bit set)
 * - Variable-length integers (31-33 bytes)
 * - Padding to exactly 32 bytes each
 *
 * @param derSig DER-encoded signature (70-72 bytes typically)
 * @returns P-1363 signature (exactly 64 bytes)
 * @throws Error if DER parsing fails
 */
export function convertDERtoP1363(derSig: Uint8Array): Uint8Array {
  // Validate DER structure
  if (derSig[0] !== 0x30) {
    throw new Error('Invalid DER signature: not a SEQUENCE');
  }

  let offset = 2;  // Skip SEQUENCE tag and length

  // Parse r
  if (derSig[offset] !== 0x02) {
    throw new Error('Invalid DER signature: r not an INTEGER');
  }
  offset++;

  const rLen = derSig[offset];
  offset++;

  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // Remove leading 0x00 if present (used when high bit is set)
  if (r[0] === 0x00 && r.length === 33) {
    r = r.slice(1);
  }

  // Validate r length
  if (r.length > 32) {
    throw new Error(`Invalid r length: ${r.length} (expected ≤32)`);
  }

  // Pad r to 32 bytes if needed
  const rPadded = new Uint8Array(32);
  rPadded.set(r, 32 - r.length);  // Right-align (leading zeros)

  // Parse s
  if (derSig[offset] !== 0x02) {
    throw new Error('Invalid DER signature: s not an INTEGER');
  }
  offset++;

  const sLen = derSig[offset];
  offset++;

  let s = derSig.slice(offset, offset + sLen);

  // Remove leading 0x00 if present
  if (s[0] === 0x00 && s.length === 33) {
    s = s.slice(1);
  }

  // Validate s length
  if (s.length > 32) {
    throw new Error(`Invalid s length: ${s.length} (expected ≤32)`);
  }

  // Pad s to 32 bytes if needed
  const sPadded = new Uint8Array(32);
  sPadded.set(s, 32 - s.length);

  // Concatenate: r || s
  const p1363 = new Uint8Array(64);
  p1363.set(rPadded, 0);
  p1363.set(sPadded, 32);

  return p1363;
}

/**
 * Convert P-1363 signature to DER format.
 *
 * REVERSE OPERATION: Needed if importing external ES256 signatures.
 *
 * @param p1363Sig P-1363 signature (exactly 64 bytes)
 * @returns DER-encoded signature
 */
export function convertP1363toDER(p1363Sig: Uint8Array): Uint8Array {
  if (p1363Sig.length !== 64) {
    throw new Error(`Invalid P-1363 signature length: ${p1363Sig.length} (expected 64)`);
  }

  const r = p1363Sig.slice(0, 32);
  const s = p1363Sig.slice(32, 64);

  // Add leading 0x00 if high bit is set (to keep INTEGER positive)
  const rBytes = r[0] & 0x80 ? new Uint8Array([0x00, ...r]) : r;
  const sBytes = s[0] & 0x80 ? new Uint8Array([0x00, ...s]) : s;

  // Build DER: SEQUENCE { r INTEGER, s INTEGER }
  const der = new Uint8Array(
    2 +           // SEQUENCE tag + length
    2 + rBytes.length +  // INTEGER tag + length + r
    2 + sBytes.length    // INTEGER tag + length + s
  );

  let offset = 0;

  // SEQUENCE tag
  der[offset++] = 0x30;

  // SEQUENCE length
  der[offset++] = der.length - 2;

  // r INTEGER
  der[offset++] = 0x02;
  der[offset++] = rBytes.length;
  der.set(rBytes, offset);
  offset += rBytes.length;

  // s INTEGER
  der[offset++] = 0x02;
  der[offset++] = sBytes.length;
  der.set(sBytes, offset);

  return der;
}
```

### Test Cases

```typescript
describe('DER ↔ P-1363 conversion', () => {
  it('should convert typical DER (70 bytes) to P-1363 (64 bytes)', () => {
    // DER: 30 44 02 20 [32-byte r] 02 20 [32-byte s]
    const der = new Uint8Array([
      0x30, 0x44,
      0x02, 0x20, ...new Uint8Array(32).fill(0xAA),
      0x02, 0x20, ...new Uint8Array(32).fill(0xBB)
    ]);

    const p1363 = convertDERtoP1363(der);

    expect(p1363.length).toBe(64);
    expect(p1363.slice(0, 32)).toEqual(new Uint8Array(32).fill(0xAA));
    expect(p1363.slice(32, 64)).toEqual(new Uint8Array(32).fill(0xBB));
  });

  it('should handle DER with leading zeros (72 bytes)', () => {
    // DER: 30 46 02 21 00 [32-byte r] 02 21 00 [32-byte s]
    const der = new Uint8Array([
      0x30, 0x46,
      0x02, 0x21, 0x00, ...new Uint8Array(32).fill(0xFF),  // High bit set
      0x02, 0x21, 0x00, ...new Uint8Array(32).fill(0xFF)
    ]);

    const p1363 = convertDERtoP1363(der);

    expect(p1363.length).toBe(64);
    expect(p1363.slice(0, 32)).toEqual(new Uint8Array(32).fill(0xFF));
    expect(p1363.slice(32, 64)).toEqual(new Uint8Array(32).fill(0xFF));
  });

  it('should handle short r or s values', () => {
    // DER with 31-byte r (leading byte < 0x80)
    const der = new Uint8Array([
      0x30, 0x43,
      0x02, 0x1F, ...new Uint8Array(31).fill(0x7F),  // 31 bytes
      0x02, 0x20, ...new Uint8Array(32).fill(0xBB)
    ]);

    const p1363 = convertDERtoP1363(der);

    expect(p1363.length).toBe(64);
    // r should be padded with leading zero
    expect(p1363[0]).toBe(0x00);
    expect(p1363.slice(1, 32)).toEqual(new Uint8Array(31).fill(0x7F));
  });

  it('should roundtrip DER ↔ P-1363', () => {
    const originalDER = new Uint8Array([
      0x30, 0x44,
      0x02, 0x20, ...crypto.getRandomValues(new Uint8Array(32)),
      0x02, 0x20, ...crypto.getRandomValues(new Uint8Array(32))
    ]);

    const p1363 = convertDERtoP1363(originalDER);
    const reconstructedDER = convertP1363toDER(p1363);

    // May differ in length due to leading zeros, but should verify same signature
    expect(reconstructedDER.length).toBeGreaterThanOrEqual(70);
    expect(reconstructedDER.length).toBeLessThanOrEqual(72);
  });
});
```

---

## Public Key Export

### VAPID Public Key Format

**For `PushManager.subscribe()`**:
- **Format**: Uncompressed raw (65 bytes)
- **Structure**: `0x04 || x (32 bytes) || y (32 bytes)`

**WebCrypto default export** (SPKI):
- **Format**: ASN.1-wrapped (~91 bytes)
- **Not compatible** with `PushManager.subscribe()`

### Implementation

```typescript
/**
 * Export VAPID public key in raw format for PushManager.
 *
 * FORMAT: Uncompressed raw (65 bytes)
 * STRUCTURE: 0x04 || x || y
 *
 * This is the format expected by PushManager.subscribe():
 * ```js
 * registration.pushManager.subscribe({
 *   applicationServerKey: vapidPublicKey  // 65-byte Uint8Array
 * })
 * ```
 *
 * @param kid Key identifier
 * @returns 65-byte Uint8Array (0x04 || x || y)
 */
export async function exportVAPIDPublicKey(kid: string): Promise<Uint8Array> {
  const keyConfig = await storage.get(`key:${kid}`);
  if (!keyConfig || keyConfig.purpose !== 'vapid') {
    throw new Error(`VAPID key not found: ${kid}`);
  }

  // Public key stored as raw format (65 bytes)
  return new Uint8Array(keyConfig.publicKeyRaw);
}

/**
 * Export VAPID public key as base64url (for VAPID header).
 *
 * RFC 8292 VAPID header format:
 * ```
 * vapid t=<jwt>, k=<base64url(publicKey)>
 * ```
 *
 * @param kid Key identifier
 * @returns Base64url-encoded public key
 */
export async function exportVAPIDPublicKeyBase64url(kid: string): Promise<string> {
  const raw = await exportVAPIDPublicKey(kid);
  return base64url.encode(raw);
}
```

### VAPID Header Construction

```typescript
/**
 * Build VAPID authorization header per RFC 8292.
 *
 * FORMAT:
 * ```
 * vapid t=<jwt>, k=<base64url(publicKey)>
 * ```
 *
 * USAGE:
 * ```js
 * fetch(pushEndpoint, {
 *   headers: {
 *     'Authorization': vapidHeader,
 *     'Content-Type': 'application/json'
 *   },
 *   body: JSON.stringify({ ... })
 * })
 * ```
 *
 * @param jwt Signed VAPID JWT
 * @param kid Key identifier (for public key lookup)
 * @returns VAPID header string
 */
export async function buildVAPIDHeader(
  jwt: string,
  kid: string
): Promise<string> {
  const publicKeyB64 = await exportVAPIDPublicKeyBase64url(kid);
  return `vapid t=${jwt}, k=${publicKeyB64}`;
}
```

---

## Key Wrapping

### AAD for Wrapped Keys

**All key wrapping operations use mandatory AAD for metadata binding.**

**See**: [AAD Schemas - Wrapped Key AAD](./01-primitives.md#aad-schema-for-wrapped-keys) in 01-primitives.md for exact AAD structure (aadVersion: 1).

**AAD Schema Reference**:
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

**CRITICAL**: Unwrap MUST FAIL if AAD mismatches any field. This prevents:
- Key substitution attacks (wrong `kid` or `purpose`)
- Algorithm confusion (wrong `alg`)
- Version downgrade (wrong `kmsVersion`)
- Replay attacks (AAD binds to creation timestamp)

### Wrapping Flow

```
Generate Key (extractable=true) → Wrap with MKEK+AAD → Store → Set extractable=false
```

### Implementation

Already covered in [02-master-secret.md](./02-master-secret.md#application-key-wrapping), but here's the key operations perspective:

```typescript
/**
 * Wrap application key with MKEK.
 *
 * WINDOW: Private key is extractable ONLY during wrapping.
 * After wrapping, key is stored as non-extractable when unwrapped.
 *
 * @param key Application key (CryptoKey, extractable=true)
 * @param mkek Master Key Encryption Key
 * @param metadata Key metadata (kid, alg, purpose)
 * @returns { wrappedKey, iv, aad }
 */
export async function wrapApplicationKey(
  key: CryptoKey,
  mkek: CryptoKey,
  metadata: KeyMetadata
): Promise<{ wrappedKey: ArrayBuffer; iv: ArrayBuffer; aad: ArrayBuffer }> {
  // Build AAD from metadata
  const aad = buildKeyWrappingAAD(metadata);

  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Wrap key with MKEK + AAD
  const wrappedKey = await crypto.subtle.wrapKey(
    'raw',     // Export format
    key,       // Key to wrap
    mkek,      // Wrapping key
    {
      name: 'AES-GCM',
      iv,
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
 * Unwrap application key with MKEK.
 *
 * CRITICAL: Unwrapped key has extractable=false.
 * This ensures keys cannot be extracted after unwrapping.
 *
 * @param wrappedKey Wrapped key data
 * @param mkek Master Key Encryption Key
 * @param iv Initialization vector
 * @param aad Additional Authenticated Data
 * @param metadata Key metadata
 * @returns CryptoKey (non-extractable)
 */
export async function unwrapApplicationKey(
  wrappedKey: ArrayBuffer,
  mkek: CryptoKey,
  iv: ArrayBuffer,
  aad: ArrayBuffer,
  metadata: { alg: 'ES256' | 'EdDSA'; purpose: string }
): Promise<CryptoKey> {
  const algorithm = metadata.alg === 'ES256'
    ? { name: 'ECDSA', namedCurve: 'P-256' }
    : { name: 'Ed25519' };

  const keyUsages = ['sign'];

  const key = await crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    mkek,
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,
      tagLength: 128
    },
    algorithm,
    false,  // extractable=false (CRITICAL)
    keyUsages
  );

  return key;
}
```

---

## Audit Key Operations

### Audit Keypair Generation

```typescript
/**
 * Generate Ed25519 audit keypair.
 *
 * ALGORITHM: Ed25519 (EdDSA)
 * PURPOSE: Sign audit log entries
 * SECURITY: Non-extractable after wrapping
 *
 * @param credential User credential for unlock
 * @returns { kid, publicKey }
 */
export async function generateAuditKeypair(
  credential: Credential
): Promise<{ kid: string; publicKey: ArrayBuffer }> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Generate Ed25519 keypair
      const keypair = await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,  // Temporarily extractable
        ['sign', 'verify']
      );

      // Export public key (raw format, 32 bytes)
      const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

      // Compute kid
      const kid = await computeEd25519Thumbprint(keypair.publicKey);

      // Build metadata
      const metadata = {
        kid,
        alg: 'EdDSA' as const,
        purpose: 'audit' as const,
        createdAt: Date.now(),
        kmsVersion: 2
      };

      // Wrap private key
      const { wrappedKey, iv, aad } = await wrapApplicationKey(
        keypair.privateKey,
        ctx.mkek,
        metadata
      );

      // Store configuration
      const config: WrappedKeyConfig = {
        kid,
        kmsVersion: 2,
        wrappedKey,
        iv,
        aad,
        publicKeyRaw,
        alg: 'EdDSA',
        purpose: 'audit',
        createdAt: Date.now()
      };

      await storage.put(`key:${kid}`, config);

      return { kid, publicKey: publicKeyRaw };
    },
    { timeout: 10_000, purpose: 'audit:generate' }
  );
}
```

---

## Complete Implementation

### Full VAPID Flow (End-to-End)

```typescript
/**
 * Complete VAPID flow: Generate key → Sign JWT → Build header.
 *
 * USAGE: Setup VAPID for push notifications.
 */
export async function setupVAPID(credential: Credential): Promise<{
  kid: string;
  publicKey: Uint8Array;
  jwt: string;
  vapidHeader: string;
}> {
  // Step 1: Generate VAPID keypair
  const { kid, publicKey } = await generateVAPIDKeypair(credential);

  // Step 2: Build JWT payload
  const payload: VAPIDPayload = {
    aud: 'https://fcm.googleapis.com',
    sub: 'mailto:ops@allthe.services',
    exp: Math.floor(Date.now() / 1000) + 3600,  // 1 hour from now
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID()
  };

  // Step 3: Sign JWT
  const jwt = await signVAPIDJWT(credential, payload, kid);

  // Step 4: Build VAPID header
  const vapidHeader = await buildVAPIDHeader(jwt, kid);

  return {
    kid,
    publicKey: new Uint8Array(publicKey),
    jwt,
    vapidHeader
  };
}

/**
 * Issue new VAPID JWT (for rotation/renewal).
 *
 * USAGE: Renew expired JWT without regenerating keypair.
 */
export async function renewVAPIDJWT(
  credential: Credential,
  kid: string,
  aud: string
): Promise<{ jwt: string; vapidHeader: string }> {
  // Build payload
  const payload: VAPIDPayload = {
    aud,
    sub: 'mailto:ops@allthe.services',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID()
  };

  // Sign JWT
  const jwt = await signVAPIDJWT(credential, payload, kid);

  // Build header
  const vapidHeader = await buildVAPIDHeader(jwt, kid);

  return { jwt, vapidHeader };
}
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('VAPID key operations', () => {
  it('should generate P-256 keypair', async () => {
    const { kid, publicKey } = await generateVAPIDKeypair(testCredential);

    expect(kid).toMatch(/^[A-Za-z0-9_-]{43}$/);  // Base64url SHA-256
    expect(publicKey.byteLength).toBe(65);       // Uncompressed raw
    expect(new Uint8Array(publicKey)[0]).toBe(0x04);  // Uncompressed prefix
  });

  it('should sign JWT with ES256', async () => {
    const { kid } = await generateVAPIDKeypair(testCredential);

    const payload: VAPIDPayload = {
      aud: 'https://push.example.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID()
    };

    const jwt = await signVAPIDJWT(testCredential, payload, kid);

    // Verify structure
    const parts = jwt.split('.');
    expect(parts).toHaveLength(3);

    // Verify header
    const header = JSON.parse(atob(parts[0]));
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');

    // Verify payload
    const decoded = JSON.parse(atob(parts[1]));
    expect(decoded.aud).toBe('https://push.example.com');

    // Verify signature length (64 bytes = 86 base64url chars)
    expect(parts[2].length).toBe(86);
  });

  it('should convert DER to P-1363', () => {
    const der = new Uint8Array([
      0x30, 0x44,
      0x02, 0x20, ...new Uint8Array(32).fill(0xAA),
      0x02, 0x20, ...new Uint8Array(32).fill(0xBB)
    ]);

    const p1363 = convertDERtoP1363(der);

    expect(p1363.length).toBe(64);
    expect(p1363.slice(0, 32).every(b => b === 0xAA)).toBe(true);
    expect(p1363.slice(32, 64).every(b => b === 0xBB)).toBe(true);
  });
});
```

### Integration Tests

```typescript
describe('VAPID integration', () => {
  it('should complete full VAPID flow', async () => {
    const result = await setupVAPID(testCredential);

    // Verify all components returned
    expect(result.kid).toBeDefined();
    expect(result.publicKey).toBeInstanceOf(Uint8Array);
    expect(result.jwt).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(result.vapidHeader).toStartWith('vapid t=');

    // Verify JWT can be verified externally
    const verified = await verifyJWTExternal(result.jwt, result.publicKey);
    expect(verified).toBe(true);
  });

  it('should renew JWT without regenerating key', async () => {
    const { kid } = await generateVAPIDKeypair(testCredential);

    const jwt1 = await renewVAPIDJWT(testCredential, kid, 'https://push1.example.com');
    const jwt2 = await renewVAPIDJWT(testCredential, kid, 'https://push2.example.com');

    // Different JWTs (different aud, jti)
    expect(jwt1.jwt).not.toBe(jwt2.jwt);

    // Same kid (same keypair)
    expect(jwt1.jwt.split('.')[0]).toBe(jwt2.jwt.split('.')[0]);  // Same header
  });
});
```

---

## Security Considerations

### Private Key Lifetime

**Window**: Extractable only during wrapping
**After**: Non-extractable (cannot be exported)
**Benefit**: Limits key exposure to milliseconds

### Signature Format

**Modern browsers**: Return P-1363 format natively (64 bytes)
**Validation**: Verify signature length is exactly 64 bytes
**Testing**: Verify JWTs with external libraries (JWT.io, jose library)

### Public Key Format

**Push API**: Requires raw format (65 bytes)
**VAPID Header**: Requires base64url encoding
**Storage**: Store raw bytes, encode on demand

### Key Rotation

**Best Practice**: Rotate VAPID keys periodically (30-90 days)
**Implementation**: Generate new key, update subscriptions
**Backward Compat**: Keep old key for existing subscriptions during transition

---

## References

- **VAPID**: RFC 8292
- **ES256**: RFC 7518 Section 3.4
- **JWS**: RFC 7515
- **JWK Thumbprint**: RFC 7638
- **SEC1**: Standards for Efficient Cryptography (DER encoding)
- **P-1363**: IEEE 1363-2000 (signature format)

---

**Next**: [05-audit-log.md](./05-audit-log.md) - Hardened audit log with sequence numbers
