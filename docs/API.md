# KMS V2 API Reference

**Version:** 2.0.0
**Last Updated:** 2025-10-26

This document provides complete API documentation for the KMS V2 implementation, based on the actual working code and integration tests.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Key Concepts](#key-concepts)
4. [Authentication](#authentication)
5. [API Methods](#api-methods)
   - [Setup Operations](#setup-operations)
   - [VAPID Key Management](#vapid-key-management)
   - [VAPID Lease Operations](#vapid-lease-operations)
   - [Status and Query Operations](#status-and-query-operations)
   - [Management Operations](#management-operations)
6. [Types Reference](#types-reference)
7. [Error Handling](#error-handling)
8. [Security Model](#security-model)

---

## Overview

The KMS V2 provides a browser-based, verifiable Key Management System that runs in a sandboxed cross-origin iframe. It manages non-extractable cryptographic keys using the WebCrypto API and provides cryptographic services to the main PWA via postMessage.

**Key Features:**
- **Per-operation authentication** - No persistent unlock sessions
- **Lease-based authorization** - Long-lived JWTs without re-authentication
- **Tamper-evident audit log** - Every operation is cryptographically logged
- **Multiple enrollment methods** - Passphrase, Passkey PRF, Passkey Gate
- **JWT stashing** - Batch issuance with staggered expirations for seamless rotation

---

## Architecture

```
PWA (allthe.services)
    ↓ postMessage (cross-origin)
KMSUser (kms-user.ts)
    ↓ postMessage
KMSClient (iframe @ kms.ats.run)
    ↓ postMessage (Worker)
Worker (worker.ts - crypto operations)
```

**Components:**

1. **KMSUser** - PWA-facing API (runs in parent context)
2. **KMSClient** - Iframe bridge (runs in KMS iframe)
3. **Worker** - Crypto orchestrator (runs in Dedicated Worker)
4. **Storage** - IndexedDB persistence layer
5. **Unlock** - Authentication and key derivation
6. **Audit** - Tamper-evident logging

---

## ⚠️ CRITICAL: KMSClient Auto-Initialization

**The KMSClient automatically initializes when imported in a browser environment.** This is intentional and provides a better developer experience by eliminating manual initialization code.

### ✅ CORRECT Usage (Iframe Entry Point)

When creating your KMS iframe entry point (e.g., `kms.ts`), simply import the client module:

```typescript
// kms.ts - Iframe entry point
import '@/client';  // Auto-initializes KMSClient

console.log('[KMS] Ready (using auto-initialized KMSClient)');
```

The auto-initialization will:
- Create a single KMSClient instance
- Create a single dedicated worker
- Set up message handlers automatically
- Export the instance to `window.__kmsClient` for debugging

### ❌ INCORRECT Usage

**DO NOT manually create a KMSClient instance in your iframe entry point.** This will create duplicate instances and cause duplicate message processing:

```typescript
// ❌ WRONG - Creates duplicate instance and worker!
import { KMSClient } from '@/client';
const client = new KMSClient({ parentOrigin: '...' });
await client.init();  // Second worker created - messages processed twice!
```

### Symptoms of Duplicate Instances

If you accidentally create a second KMSClient instance, you'll see:
- Duplicate log messages in console (same request ID logged twice)
- "No pending request for ID" errors
- Race conditions between workers
- Inconsistent behavior (first worker's response wins, second is ignored)

### For Testing/Manual Control

If you need manual control (e.g., in unit tests), the auto-initialization only runs in browser environments (`typeof window !== 'undefined'`). In Node/test environments, you must manually create instances.

---

## Key Concepts

### Per-Operation Authentication

V2 uses **per-operation authentication** instead of session-based unlocking. This means:

- No persistent unlock state in memory
- Credentials passed to each sensitive operation
- Master Secret (MS) derived on-demand and immediately zeroed
- Enhanced security with minimal UX impact (leases solve the UX problem)

### VAPID Leases

**Leases** provide long-lived authorization for JWT issuance without requiring user credentials:

1. **Create Lease**: User authenticates to create a lease (requires credentials)
2. **Issue JWTs**: Use lease to issue JWTs (NO credentials needed)
3. **SessionKEK**: Lease-specific key derived from MS for JWT signing
4. **Quotas**: Rate limiting enforced per lease
5. **LAK (Lease Audit Key)**: Dedicated audit key for lease operations

### Audit Chain

Every operation is logged to a **tamper-evident audit chain**:

- **UAK (User Audit Key)**: Signs user-authenticated operations
- **LAK (Lease Audit Key)**: Signs lease-scoped operations (no credentials needed)
- **KIAK (KMS Instance Audit Key)**: Signs system events
- **Chain Hash**: Each entry hashes the previous entry
- **Delegation Certificates**: LAK/KIAK authorized by UAK

### JWT Stashing

**Batch JWT issuance** with staggered expirations for seamless rotation:

- TTL = 900s (15 minutes)
- Stagger interval = 60% of TTL = 540s (9 minutes)
- JWT[0]: exp = T+15min
- JWT[1]: exp = T+24min (staggered by 9min)
- JWT[2]: exp = T+33min (staggered by 9min)

When JWT[0] reaches 60% TTL, switch to JWT[1] (already valid).

---

## Authentication

### AuthCredentials Type

```typescript
type AuthCredentials =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer }
  | { method: 'passkey-gate' };
```

### Enrollment Methods

1. **Passphrase** - PBKDF2-derived key encryption
2. **Passkey PRF** - WebAuthn PRF extension for deterministic key derivation
3. **Passkey Gate** - Fallback for passkeys without PRF support

**Multi-enrollment supported**: Same Master Secret can be unlocked with multiple methods.

---

## API Methods

All methods are called on the `KMSUser` class instance:

```typescript
import { KMSUser } from '@/kms-user';

const kmsUser = new KMSUser({
  kmsOrigin: 'http://localhost:5177',
});

await kmsUser.init();
```

---

### Setup Operations

#### `setupPassphrase(passphrase: string)`

Setup KMS with passphrase authentication. Creates Master Secret (if first enrollment) and generates initial VAPID keypair.

**Parameters:**
- `passphrase: string` - User passphrase (min 8 characters)

**Returns:**
```typescript
{
  success: true,
  enrollmentId: string,        // "enrollment:passphrase:v2"
  vapidPublicKey: string,       // base64url-encoded raw public key (65 bytes)
  vapidKid: string              // JWK thumbprint (key ID)
}
```

**Example:**
```typescript
const result = await kmsUser.setupPassphrase('my-secure-passphrase-123');
console.log(result.vapidKid); // "abc123..."
console.log(result.vapidPublicKey); // "BFkj..."
```

**Performance:** 100-5000ms (includes PBKDF2 calibration + VAPID generation)

**Audit Entry:** Signed by UAK (User Audit Key)

---

#### `setupPasskeyPRF(config)`

Setup KMS with passkey PRF authentication. Orchestrates WebAuthn credential creation and generates VAPID keypair.

**Parameters:**
```typescript
{
  name: string,      // Display name for credential
  rpId: string,      // Relying Party ID (e.g., "example.com")
  userId: string     // User ID
}
```

**Returns:**
```typescript
{
  success: true,
  enrollmentId: string,        // "enrollment:passkey-prf:v2"
  vapidPublicKey: string,       // base64url-encoded raw public key
  vapidKid: string              // JWK thumbprint
}
```

**Example:**
```typescript
const result = await kmsUser.setupPasskeyPRF({
  name: 'user@example.com',
  rpId: 'example.com',
  userId: 'user-123',
});
```

**Notes:**
- Requires browser support for WebAuthn PRF extension
- Stores appSalt in localStorage for unlock operations

---

#### `setupPasskeyGate(config)`

Setup KMS with passkey gate authentication (fallback for non-PRF passkeys).

**Parameters:**
```typescript
{
  name: string,      // Display name for credential
  rpId: string,      // Relying Party ID
  userId: string     // User ID
}
```

**Returns:**
```typescript
{
  success: true,
  enrollmentId: string,        // "enrollment:passkey-gate:v2"
  vapidPublicKey: string,       // base64url-encoded raw public key
  vapidKid: string              // JWK thumbprint
}
```

---

#### `addEnrollment(method, credentials, newCredentials)`

Add additional enrollment method to existing Master Secret (multi-enrollment). All enrollments share the same Master Secret (MS), encrypted with different Key Encryption Keys (KEKs).

**Architecture:**
```
         Master Secret (32 bytes)
                 |
  ┌──────────────┼──────────────┐
  │              │              │
KEK₁          KEK₂          KEK₃
(passphrase)  (passkey PRF)  (passkey gate)
```

**Parameters:**
- `method: 'passphrase' | 'passkey-prf' | 'passkey-gate'` - Method to add
- `credentials: AuthCredentials` - Current credentials to unlock and authorize
- `newCredentials: any` - New method credentials (method-specific structure)

**newCredentials Structure:**

**For Passphrase:**
```typescript
{
  passphrase: string  // Min 8 characters
}
```

**For Passkey PRF:**
```typescript
{
  credentialId: ArrayBuffer,  // From credential.rawId
  prfOutput: ArrayBuffer,     // From credential.getClientExtensionResults().prf
  rpId: string               // Relying Party ID (e.g., "localhost", "example.com")
}
```

**For Passkey Gate:**
```typescript
{
  credentialId: ArrayBuffer,  // From credential.rawId
  rpId: string               // Relying Party ID
}
```

**Returns:**
```typescript
{
  success: true,
  enrollmentId: string  // e.g., "enrollment:passphrase:v2"
}
```

**Examples:**

**1. Add Passphrase to Existing Passkey Enrollment:**
```typescript
// Unlock with existing passkey PRF
const prfOutput = /* ... from WebAuthn get assertion ... */;

await kmsUser.addEnrollment(
  'passphrase',
  { method: 'passkey-prf', prfOutput },
  { passphrase: 'my-new-secure-passphrase-123' }
);
```

**2. Add Passkey to Existing Passphrase Enrollment:**
```typescript
// Unlock with existing passphrase
const passphraseCredentials = {
  method: 'passphrase',
  passphrase: 'my-current-passphrase',
};

// Create new WebAuthn credential
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { id: 'localhost', name: 'Demo' },
    user: {
      id: new TextEncoder().encode('user-123'),
      name: 'Demo User',
      displayName: 'Demo User',
    },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      userVerification: 'required',
    },
    extensions: {
      prf: {
        eval: {
          first: crypto.getRandomValues(new Uint8Array(32)),  // appSalt
        },
      },
    },
  },
}) as PublicKeyCredential;

// Check if PRF succeeded
const prfExt = (credential as any).getClientExtensionResults().prf;
const prfOutput = prfExt?.results?.first;

if (prfOutput) {
  // PRF available - use passkey-prf
  await kmsUser.addEnrollment(
    'passkey-prf',
    passphraseCredentials,
    {
      credentialId: credential.rawId,
      prfOutput,
      rpId: 'localhost',
    }
  );
} else {
  // PRF not available - fallback to passkey-gate
  await kmsUser.addEnrollment(
    'passkey-gate',
    passphraseCredentials,
    {
      credentialId: credential.rawId,
      rpId: 'localhost',
    }
  );
}
```

**How It Works:**

1. **Unlock with Existing Credentials**: Authenticates user and retrieves Master Secret
2. **Derive New KEK**: Generates KEK for new authentication method
3. **Wrap Master Secret**: Encrypts same MS with new KEK
4. **Store Enrollment**: Saves new enrollment record to IndexedDB
5. **Audit Logging**: Logs operation with UAK (User Audit Key)

**Security Properties:**

- **Single Master Secret**: All enrollments decrypt to the same MS
- **Independent KEKs**: Compromising one enrollment doesn't compromise others
- **Key Isolation**: Each enrollment uses different key derivation parameters
- **Enrollment Independence**: Can remove any enrollment (except last) without affecting others

**Important Notes:**

- Cannot remove the last enrollment (would lock user out)
- PRF/Gate auto-detection recommended for optimal UX (see example 2)
- Always request PRF extension during WebAuthn create, check if succeeded
- Store `appSalt` in localStorage for PRF enrollments (needed for unlock)
- Different user IDs recommended for multiple passkeys (avoid conflicts)

**Performance:** < 2000ms (includes unlock + key derivation + wrapping)

**Audit Entry:** Signed by UAK

---

#### Multi-Enrollment Implementation Guide

This section provides a complete guide to implementing multi-enrollment UI that works correctly in both directions (passphrase→WebAuthn and WebAuthn→passphrase).

**Step 1: Check Enrollment Status**

Use `isSetup()` to determine what's already enrolled:

```typescript
const status = await kmsUser.isSetup();
// status = { isSetup: boolean, methods: string[] }
```

**CRITICAL**: The `methods` array returns **generic method types**, not specific variants:
- Returns `'passphrase'` for passphrase enrollments
- Returns `'passkey'` for **any** passkey enrollment (PRF or Gate)
- Does NOT return `'passkey-prf'` or `'passkey-gate'`

**Example status values:**
```typescript
// No enrollment:
{ isSetup: false, methods: [] }

// Passphrase only:
{ isSetup: true, methods: ['passphrase'] }

// WebAuthn only (could be PRF or Gate):
{ isSetup: true, methods: ['passkey'] }

// Both enrolled:
{ isSetup: true, methods: ['passphrase', 'passkey'] }
```

**Step 2: Detect Existing Method and Unlock**

When adding a second enrollment, you must first unlock with the existing method:

```typescript
async function addSecondEnrollment(
  status: { isSetup: boolean; methods: string[] },
  newMethod: 'passphrase' | 'passkey'
) {
  // Get the existing method (first in array)
  const existingMethod = status.methods[0];
  let unlockCredentials: any;

  if (existingMethod === 'passphrase') {
    // Unlock with passphrase
    const passphrase = prompt('Enter your CURRENT passphrase:');
    unlockCredentials = { method: 'passphrase', passphrase };

  } else if (existingMethod === 'passkey') {
    // Unlock with WebAuthn (auto-detect PRF vs Gate)
    const appSalt = localStorage.getItem('kms:appSalt');

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: 'localhost',
        userVerification: 'required',
        extensions: appSalt ? {
          prf: {
            eval: {
              first: new Uint8Array(appSalt.split(',').map(n => parseInt(n, 10))),
            },
          },
        } : undefined,
      },
    }) as PublicKeyCredential;

    // Check if PRF succeeded
    const prfExt = (assertion as any).getClientExtensionResults().prf;
    const prfOutput = prfExt?.results?.first;

    if (prfOutput) {
      unlockCredentials = { method: 'passkey-prf', prfOutput };
    } else {
      unlockCredentials = { method: 'passkey-gate' };
    }
  }

  // Now add the new enrollment using unlockCredentials
  // (see Step 3)
}
```

**Key Points:**
- Check for `'passkey'` (not `'passkey-prf'` or `'passkey-gate'`)
- Auto-detect PRF vs Gate by checking the WebAuthn assertion result
- Always include PRF extension in the `get()` request if `appSalt` exists
- The `prfOutput` presence determines which method was used

**Step 3: Add New Enrollment**

After unlocking, add the new enrollment:

**Adding Passphrase (when passkey exists):**
```typescript
const newPassphrase = prompt('Enter NEW passphrase:');

await kmsUser.addEnrollment(
  'passphrase',
  unlockCredentials,  // From Step 2
  { passphrase: newPassphrase }
);
```

**Adding WebAuthn (when passphrase exists):**
```typescript
// Create new WebAuthn credential
const appSalt = crypto.getRandomValues(new Uint8Array(32));

const credential = await navigator.credentials.create({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { id: 'localhost', name: 'My App' },
    user: {
      id: new TextEncoder().encode('user-123'),
      name: 'Demo User',
      displayName: 'Demo User',
    },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'required',
    },
    extensions: {
      prf: {
        eval: { first: appSalt },
      },
    },
  },
}) as PublicKeyCredential;

// Check if PRF succeeded
const prfExt = (credential as any).getClientExtensionResults().prf;
const prfOutput = prfExt?.results?.first;

if (prfOutput) {
  // PRF available
  await kmsUser.addEnrollment(
    'passkey-prf',
    unlockCredentials,  // From Step 2
    {
      credentialId: credential.rawId,
      prfOutput,
      rpId: 'localhost',
    }
  );

  // Store appSalt for future unlocks
  localStorage.setItem('kms:appSalt', Array.from(appSalt).toString());
} else {
  // Fallback to Gate
  await kmsUser.addEnrollment(
    'passkey-gate',
    unlockCredentials,  // From Step 2
    {
      credentialId: credential.rawId,
      rpId: 'localhost',
    }
  );
}
```

**Step 4: Update UI**

After adding enrollment, refresh the UI:

```typescript
const status = await kmsUser.isSetup();

// Display enrolled methods
const hasPassphrase = status.methods.includes('passphrase');
const hasPasskey = status.methods.includes('passkey');

if (hasPassphrase) {
  console.log('✅ Passphrase enrolled');
}
if (hasPasskey) {
  console.log('✅ WebAuthn enrolled');
}
```

**Common Mistakes to Avoid:**

1. ❌ Checking for `'passkey-prf'` or `'passkey-gate'` in `methods` array
   - ✅ Always check for `'passkey'`

2. ❌ Assuming passphrase is always first enrollment
   - ✅ Check `status.methods[0]` to determine existing method

3. ❌ Not including PRF extension when unlocking with passkey
   - ✅ Always try PRF if `appSalt` exists, then check result

4. ❌ Hardcoding unlock method in double enrollment flow
   - ✅ Detect existing method dynamically from `isSetup()` result

**Complete Working Example:**

See `/example/phase-1/full/parent.ts` for a complete implementation with UI.

---

### VAPID Key Management

#### `generateVAPID(credentials: AuthCredentials)`

Generate new VAPID keypair (ECDSA P-256). Private key wrapped with MKEK and stored in IndexedDB.

**Parameters:**
- `credentials: AuthCredentials` - Authentication credentials

**Returns:**
```typescript
{
  kid: string,          // JWK thumbprint (key ID)
  publicKey: string     // base64url-encoded raw public key (65 bytes)
}
```

**Example:**
```typescript
const vapid = await kmsUser.generateVAPID({
  method: 'passphrase',
  passphrase: 'my-passphrase',
});
console.log(vapid.kid); // "abc123..."
```

**Performance:** < 1000ms

**Audit Entry:** Signed by UAK

---

#### `signJWT(kid: string, payload: VAPIDPayload, credentials: AuthCredentials)`

Sign JWT with VAPID private key (ES256 algorithm). Implements RFC 7515 (JWS) and RFC 8292 (VAPID).

**Parameters:**
- `kid: string` - Key ID (JWK thumbprint)
- `payload: VAPIDPayload` - JWT payload
- `credentials: AuthCredentials` - Authentication credentials

**VAPIDPayload Type:**
```typescript
{
  aud: string,      // Audience (push service URL)
  sub: string,      // Subject (mailto: or https: URL)
  exp: number,      // Expiration (Unix timestamp, max 24h per RFC 8292)
  jti: string,      // JWT ID (unique identifier)
  [key: string]: any  // Additional claims
}
```

**Returns:**
```typescript
{
  jwt: string       // Complete JWT (header.payload.signature)
}
```

**Example:**
```typescript
const result = await kmsUser.signJWT(
  'abc123...',
  {
    aud: 'https://fcm.googleapis.com',
    sub: 'mailto:kms@example.com',
    exp: Math.floor(Date.now() / 1000) + 900, // 15 min
    jti: crypto.randomUUID(),
  },
  { method: 'passphrase', passphrase: 'my-passphrase' }
);
console.log(result.jwt); // "eyJ..."
```

**Performance:** < 500ms

**Audit Entry:** Signed by UAK

---

#### `getPublicKey(kid: string)`

Get public key for VAPID key (read-only operation, no credentials needed).

**Parameters:**
- `kid: string` - Key ID (JWK thumbprint)

**Returns:**
```typescript
{
  publicKey: string     // base64url-encoded raw public key
}
```

**Example:**
```typescript
const result = await kmsUser.getPublicKey('abc123...');
console.log(result.publicKey); // "BFkj..."
```

**Audit Entry:** None (read-only operation)

---

### VAPID Lease Operations

#### `createLease(params)`

Create VAPID lease for long-lived JWT issuance authorization. Derives SessionKEK from Master Secret and wraps VAPID key for credential-free JWT signing.

**Parameters:**
```typescript
{
  userId: string,
  subs: Array<{
    url: string,      // Push endpoint URL
    aud: string,      // Audience (push service)
    eid: string       // Endpoint ID
  }>,
  ttlHours: number,   // Lease TTL (max 24 hours)
  credentials: AuthCredentials
}
```

**Returns:**
```typescript
{
  leaseId: string,        // "lease-{uuid}"
  exp: number,            // Expiration (Unix timestamp in ms)
  quotas: {
    tokensPerHour: number,           // 100
    sendsPerMinute: number,          // 10
    burstSends: number,              // 20
    sendsPerMinutePerEid: number     // 5
  }
}
```

**Example:**
```typescript
const lease = await kmsUser.createLease({
  userId: 'user-123',
  subs: [
    {
      url: 'https://fcm.googleapis.com/fcm/send/abc123',
      aud: 'https://fcm.googleapis.com',
      eid: 'ep-1',
    },
  ],
  ttlHours: 12,
  credentials: { method: 'passphrase', passphrase: 'my-passphrase' },
});
console.log(lease.leaseId); // "lease-abc-def-..."
console.log(lease.exp);     // 1698765432000
```

**How it works:**
1. Generates random lease salt (32 bytes)
2. Derives SessionKEK from MS + lease salt via HKDF
3. Unwraps VAPID private key using MKEK
4. Re-wraps VAPID key with SessionKEK
5. Stores SessionKEK in IndexedDB + memory cache
6. Generates LAK (Lease Audit Key) with delegation certificate

**Audit Entry:** Signed by UAK (lease creation requires credentials)

---

#### `issueVAPIDJWT(params)`

Issue VAPID JWT using lease authorization. **NO credentials required** - the lease IS the authorization.

**Parameters:**
```typescript
{
  leaseId: string,
  endpoint: {
    url: string,      // Must match one of the lease's subs
    aud: string,
    eid: string
  },
  kid?: string        // Optional - auto-detected if not provided
}
```

**Returns:**
```typescript
{
  jwt: string,          // Complete JWT
  jti: string,          // JWT ID
  exp: number,          // Expiration (Unix timestamp in seconds)
  auditEntry: {         // Immediate audit entry (not from separate query)
    seqNum: number,
    signer: 'LAK',
    op: 'sign',
    chainHash: string,
    sig: string,
    // ... (see AuditEntryV2 type)
  }
}
```

**Example:**
```typescript
const jwt = await kmsUser.issueVAPIDJWT({
  leaseId: 'lease-abc-def-...',
  endpoint: {
    url: 'https://fcm.googleapis.com/fcm/send/abc123',
    aud: 'https://fcm.googleapis.com',
    eid: 'ep-1',
  },
});
console.log(jwt.jwt);  // "eyJ..."
console.log(jwt.exp);  // 1698765432
```

**How it works:**
1. Validates lease exists and is not expired
2. Loads LAK (Lease Audit Key) for audit logging
3. Checks endpoint is authorized in lease
4. Enforces quota (tokens per hour)
5. Retrieves SessionKEK from cache or IndexedDB
6. Unwraps VAPID key using SessionKEK (NOT MKEK - no credentials!)
7. Signs JWT with VAPID key
8. Logs operation with LAK (returns audit entry immediately)

**Performance:** < 500ms

**Audit Entry:** Signed by LAK (Lease Audit Key)

---

#### `issueVAPIDJWTs(params)`

Issue multiple VAPID JWTs with staggered expirations for seamless rotation (JWT stashing).

**Parameters:**
```typescript
{
  leaseId: string,
  endpoint: {
    url: string,
    aud: string,
    eid: string
  },
  count: number,        // 1-10 (hard limit)
  kid?: string          // Optional - auto-detected
}
```

**Returns:**
```typescript
Array<{
  jwt: string,
  jti: string,
  exp: number,          // Staggered by 540s (9 minutes)
  auditEntry: AuditEntryV2
}>
```

**Staggering Strategy:**
- TTL = 900s (15 minutes)
- Stagger interval = 60% of TTL = 540s (9 minutes)
- JWT[0]: exp = now + 900s (T+15min)
- JWT[1]: exp = now + 1440s (T+24min)
- JWT[2]: exp = now + 1980s (T+33min)

**Example:**
```typescript
const jwts = await kmsUser.issueVAPIDJWTs({
  leaseId: 'lease-abc-def-...',
  endpoint: {
    url: 'https://fcm.googleapis.com/fcm/send/abc123',
    aud: 'https://fcm.googleapis.com',
    eid: 'ep-1',
  },
  count: 3,
});

console.log(jwts[0].exp); // 1698765432
console.log(jwts[1].exp); // 1698765432 + 540
console.log(jwts[2].exp); // 1698765432 + 1080
```

**Use Case:**
Generate multiple JWTs upfront. When JWT[0] reaches 60% TTL (9 minutes), switch to JWT[1], which is already valid and has 15 minutes remaining. This ensures no service interruption when rotating relays or credentials.

**Audit Entries:** One LAK-signed entry per JWT (sequential)

---

### Status and Query Operations

#### `isSetup()`

Check if KMS is setup (has at least one enrollment).

**Returns:**
```typescript
{
  isSetup: boolean,
  methods: string[]     // e.g., ["passphrase", "passkey"]
}
```

**Example:**
```typescript
const status = await kmsUser.isSetup();
if (!status.isSetup) {
  // Show setup wizard
}
```

---

#### `getEnrollments()`

Get list of all enrollment methods.

**Returns:**
```typescript
{
  enrollments: string[]   // e.g., ["enrollment:passphrase:v2"]
}
```

---

#### `verifyAuditChain()`

Verify integrity of audit chain (cryptographic verification).

**Returns:**
```typescript
{
  valid: boolean,
  entries: number       // Number of entries verified
}
```

**Example:**
```typescript
const result = await kmsUser.verifyAuditChain();
console.log(result.valid);    // true
console.log(result.entries);  // 42
```

**Verification Process:**
1. Checks sequential seqNum
2. Verifies chainHash continuity
3. Validates Ed25519 signatures
4. Verifies delegation certificates (for LAK/KIAK)

---

#### `getAuditLog()`

Get all audit log entries.

**Returns:**
```typescript
{
  entries: AuditEntryV2[]
}
```

**Example:**
```typescript
const log = await kmsUser.getAuditLog();
log.entries.forEach(entry => {
  console.log(`${entry.seqNum}: ${entry.op} (${entry.signer})`);
});
```

---

#### `getAuditPublicKey()`

Get audit public key for external chain verification.

**Returns:**
```typescript
{
  publicKey: string     // base64url-encoded Ed25519 public key
}
```

---

### Management Operations

#### `resetKMS()`

**DANGER:** Delete all KMS data (database wipe). Cannot be undone.

**Returns:**
```typescript
{
  success: true
}
```

**Example:**
```typescript
if (confirm('Delete all KMS data?')) {
  await kmsUser.resetKMS();
}
```

**Note:** After reset, worker reinitializes and logs KIAK initialization event.

---

#### `removeEnrollment(enrollmentId: string, credentials: AuthCredentials)`

Remove specific enrollment method.

**Parameters:**
- `enrollmentId: string` - e.g., "enrollment:passphrase:v2"
- `credentials: AuthCredentials` - Current credentials to authorize removal

**Returns:**
```typescript
{
  success: true
}
```

**Example:**
```typescript
await kmsUser.removeEnrollment(
  'enrollment:passphrase:v2',
  { method: 'passkey-prf', prfOutput: ... }
);
```

**Warning:** Cannot remove last enrollment (would lock user out).

---

## Types Reference

### AuthCredentials

```typescript
type AuthCredentials =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer }
  | { method: 'passkey-gate' };
```

### VAPIDPayload

```typescript
interface VAPIDPayload {
  aud: string;      // Audience (push service URL)
  sub: string;      // Subject (mailto: or https: URL)
  exp: number;      // Expiration (Unix timestamp in seconds)
  jti: string;      // JWT ID (unique identifier)
  uid?: string;     // User ID (added by lease operations)
  eid?: string;     // Endpoint ID (added by lease operations)
  [key: string]: any;
}
```

### LeaseRecord

```typescript
interface LeaseRecord {
  leaseId: string;
  userId: string;
  subs: Array<{
    url: string;
    aud: string;
    eid: string;
  }>;
  ttlHours: number;
  createdAt: number;
  exp: number;
  quotas: QuotaState;
  wrappedLeaseKey: ArrayBuffer;       // VAPID key wrapped with SessionKEK
  wrappedLeaseKeyIV: ArrayBuffer;
  leaseSalt: ArrayBuffer;             // For SessionKEK derivation
  kid: string;                        // VAPID key ID
  lakDelegationCert: AuditDelegationCert;
}
```

### QuotaState

```typescript
interface QuotaState {
  tokensPerHour: number;            // 100 (default)
  sendsPerMinute: number;           // 10 (default)
  burstSends: number;               // 20 (default)
  sendsPerMinutePerEid: number;     // 5 (default)
}
```

### AuditEntryV2

```typescript
interface AuditEntryV2 {
  kmsVersion: 2;
  seqNum: number;
  timestamp: number;
  op: string;                       // 'setup', 'sign', 'generate', etc.
  kid: string;
  requestId: string;
  origin?: string;
  leaseId?: string;                 // Present for lease operations
  unlockTime?: number;
  lockTime?: number;
  duration?: number;
  details?: Record<string, unknown>;
  previousHash: string;
  chainHash: string;

  // Delegation support
  signer: 'UAK' | 'LAK' | 'KIAK';  // UAK: user ops, LAK: lease ops, KIAK: system
  signerId: string;                 // base64url(SHA-256(publicKey))
  cert?: AuditDelegationCert;       // Delegation certificate (for LAK/KIAK)

  // Signature
  sig: string;                      // base64url Ed25519 signature
}
```

### AuditDelegationCert

```typescript
interface AuditDelegationCert {
  type: 'audit-delegation';
  version: 1;
  signerKind: 'LAK' | 'KIAK';
  leaseId?: string;                 // Present for LAK
  instanceId?: string;              // Present for KIAK
  delegatePub: string;              // base64url Ed25519 public key
  scope: string[];                  // Authorized operations
  notBefore: number;                // Unix timestamp (ms)
  notAfter: number | null;          // null = no expiration
  codeHash: string;
  manifestHash: string;
  kmsVersion: string;
  sig: string;                      // Signed by UAK
}
```

---

## Error Handling

All methods return promises that reject with `Error` objects:

```typescript
try {
  await kmsUser.setupPassphrase('weak');
} catch (err) {
  console.error(err.message); // "Passphrase must be at least 8 characters"
}
```

**Common Errors:**

- `"KMS not initialized. Call init() first."` - Need to call `kmsUser.init()`
- `"Passphrase must be at least 8 characters"` - Invalid passphrase
- `"Invalid passphrase"` - Wrong passphrase (KCV check failed)
- `"Decryption failed"` - Wrong credentials
- `"Lease not found: {id}"` - Invalid lease ID
- `"Lease expired"` - Lease TTL exceeded
- `"Endpoint not authorized for this lease"` - Endpoint not in lease's subs
- `"Quota exceeded: tokens per hour"` - Rate limit hit
- `"Request timeout: {method} ({timeout}ms)"` - RPC timeout

---

## Security Model

### Trust Boundaries

1. **Cross-origin isolation**: Browser enforces KMS iframe cannot access parent PWA
2. **Sandboxed iframe**: `sandbox="allow-scripts allow-same-origin"` (safe due to cross-origin)
3. **Dedicated Worker**: Crypto operations isolated from DOM
4. **Non-extractable keys**: WebCrypto `extractable: false` enforced by browser
5. **Per-operation auth**: Master Secret never persists in memory

### Key Hierarchy

```
Master Secret (MS) - 32 bytes, randomly generated
    ↓ HKDF
Master Key Encryption Key (MKEK) - AES-GCM 256-bit
    ↓ wrapKey
VAPID Private Key - ECDSA P-256, non-extractable
    ↓ sign
JWT - ES256 signature
```

### Lease Security

```
Master Secret (MS) + Lease Salt (random 32 bytes)
    ↓ HKDF
SessionKEK - AES-GCM 256-bit (lease-specific)
    ↓ wrapKey
VAPID Private Key (lease-wrapped) - ECDSA P-256
    ↓ sign (no credentials needed!)
JWT - ES256 signature
```

**SessionKEK Properties:**
- Memory-only (cleared on worker restart)
- Unique per lease (different salt)
- Expires with lease
- Stored in IndexedDB as CryptoKey (persists across restarts)

### Audit Chain Security

```
User Audit Key (UAK) - Ed25519, derived from MKEK
    ↓ signs
Lease Audit Key (LAK) delegation certificate
    ↓ authorizes
LAK - Ed25519, random per lease
    ↓ signs
Lease operation audit entries
```

**Chain Properties:**
- Sequential seqNum (detects missing entries)
- Chain hash (each entry hashes previous)
- Ed25519 signatures (cryptographic integrity)
- Delegation certificates (chain of trust to UAK)

---

## Performance Benchmarks

Based on integration tests (from `/home/lukium/Dev/ats-kms/example/phase-1/iframe-isolation/integration-tests.ts`):

| Operation | Target | Typical |
|-----------|--------|---------|
| Setup Passphrase | < 5000ms | 100-300ms (PBKDF2) |
| Generate VAPID | < 1000ms | 200-500ms |
| Sign JWT | < 500ms | 50-200ms |
| Issue Lease JWT | < 500ms | 50-200ms |

**Notes:**
- Setup includes PBKDF2 calibration (targets 150-300ms derivation)
- VAPID generation includes P-256 keypair generation + wrapping
- JWT signing includes unwrapping + ECDSA signature
- Lease JWT is fast (SessionKEK already in memory, no MKEK unwrap)

---

## Example: Complete Workflow

```typescript
import { KMSUser } from '@/kms-user';

// 1. Initialize KMS
const kmsUser = new KMSUser({
  kmsOrigin: 'http://localhost:5177',
});
await kmsUser.init();

// 2. Setup (first time)
const setup = await kmsUser.setupPassphrase('my-secure-passphrase');
console.log('VAPID key created:', setup.vapidKid);

// 3. Create lease (requires credentials)
const lease = await kmsUser.createLease({
  userId: 'user-123',
  subs: [
    {
      url: 'https://fcm.googleapis.com/fcm/send/abc123',
      aud: 'https://fcm.googleapis.com',
      eid: 'ep-1',
    },
  ],
  ttlHours: 12,
  credentials: { method: 'passphrase', passphrase: 'my-secure-passphrase' },
});
console.log('Lease created:', lease.leaseId);

// 4. Issue JWT (NO credentials needed!)
const jwt = await kmsUser.issueVAPIDJWT({
  leaseId: lease.leaseId,
  endpoint: {
    url: 'https://fcm.googleapis.com/fcm/send/abc123',
    aud: 'https://fcm.googleapis.com',
    eid: 'ep-1',
  },
});
console.log('JWT issued:', jwt.jwt);

// 5. Batch issue JWTs for rotation (JWT stashing)
const jwts = await kmsUser.issueVAPIDJWTs({
  leaseId: lease.leaseId,
  endpoint: {
    url: 'https://fcm.googleapis.com/fcm/send/abc123',
    aud: 'https://fcm.googleapis.com',
    eid: 'ep-1',
  },
  count: 3,
});
console.log('Stashed JWTs:', jwts.length);

// 6. Verify audit chain
const audit = await kmsUser.verifyAuditChain();
console.log('Audit valid:', audit.valid);

// 7. Cleanup
await kmsUser.terminate();
```

---

## Testing Reference

Integration tests demonstrate all API features:

**Location:** `/home/lukium/Dev/ats-kms/example/phase-1/iframe-isolation/integration-tests.ts`

**Test Groups:**
1. Setup Operations
2. VAPID Lease Lifecycle
3. Audit Chain Integrity
4. Performance Benchmarks

**Run Tests:**
```bash
# Navigate to example
cd example/phase-1/iframe-isolation

# Start dev servers (in separate terminals)
pnpm vite-kms    # KMS iframe (port 5177)
pnpm vite-parent # Parent PWA (port 5178)

# Open http://localhost:5178 and click "Run Tests"
```

---

## Version History

### v2.0.0 (Current)
- Per-operation authentication
- VAPID lease system
- JWT stashing with staggered expirations
- Audit delegation (UAK/LAK/KIAK)
- Multi-enrollment support

---

**End of API Reference**
