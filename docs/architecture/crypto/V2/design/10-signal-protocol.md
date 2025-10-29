# Signal Protocol Integration in KMS V2

**Version**: 2.0
**Date**: 2025-10-24
**Status**: Future Roadmap (not current implementation)
**Timeline**: After VAPID leases MVP is production-ready

---

> **⚠️ FUTURE ENHANCEMENT**
>
> This document describes a **future enhancement** to KMS V2. The current implementation focuses on **VAPID leases for user-run relays** (see [12-vapid-leases.md](./12-vapid-leases.md)).
>
> Signal Protocol integration will be added in a subsequent release after the VAPID MVP is stable and deployed to production. This design is documented now to ensure the core KMS architecture supports future Signal Protocol requirements (key types, capability tokens, audit patterns).

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [Capability Token System](#capability-token-system)
4. [Signal Crypto in Worker](#signal-crypto-in-worker)
5. [Storage Schema](#storage-schema)
6. [Session Lifecycle](#session-lifecycle)
7. [RPC Interface](#rpc-interface)
8. [Streaming & Performance](#streaming--performance)
9. [Audit & Metrics](#audit--metrics)
10. [Implementation Guide](#implementation-guide)

---

## Overview

Signal Protocol provides end-to-end encrypted messaging with forward secrecy and break-in recovery. This document specifies how to integrate Signal Protocol into the KMS V2 architecture while maintaining the same security properties:

- **No persistent unlock state**: Capability tokens authorize short-lived sessions
- **All crypto in Worker**: Identity keys, prekeys, and ratchet states never leave Worker
- **Per-operation authentication**: Opening a messaging session requires user auth
- **Tamper-evident audit**: All operations logged with chain hash
- **Multi-enrollment**: Same MS wraps Signal keys and VAPID keys

### Signal Protocol Primer

Signal uses:
- **Identity Key** (Ed25519): Long-term identity (one per user)
- **Signed Prekey** (X25519): Medium-term key, rotated periodically, signed by identity
- **One-Time Prekeys** (X25519): Short-term keys, consumed on session start
- **Double Ratchet**: Per-peer session state with symmetric ratchet + DH ratchet
- **Message Keys**: Derived from ratchet state, single-use per message

**Key Properties**:
- Forward secrecy: Old messages can't be decrypted if current state compromised
- Break-in recovery: New DH ratchet heals from compromise
- Out-of-order messages: Message keys buffered for reordering

---

## Architecture Principles

### 1. Capabilities, Not Keys

```
┌──────────────────────────────────────────────────────────────────┐
│  OLD MODEL (Persistent Unlock)                                   │
├──────────────────────────────────────────────────────────────────┤
│  1. User unlocks KMS                                             │
│  2. MS/MKEK stay in memory                                       │
│  3. PWA can call decrypt() anytime                               │
│  4. Risk: Unlimited time window for attacks                      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  NEW MODEL (Capability Tokens)                                   │
├──────────────────────────────────────────────────────────────────┤
│  1. User opens Messaging (requires auth)                         │
│  2. KMS issues capability token (Ed25519-signed JWT)             │
│  3. Token grants access to specific scope for limited time       │
│  4. Token binds to MessageChannel session (sid)                  │
│  5. Session closes: token invalidated, MS cleared                │
│  6. Risk: Limited to ≤1h window, specific scope only             │
└──────────────────────────────────────────────────────────────────┘
```

**Benefits**:
- **Time-limited**: Token expires (≤1h), forces re-auth
- **Scope-limited**: Token only grants messaging ops, not VAPID
- **Session-bound**: Token tied to specific MessageChannel (sid)
- **Auditable**: Token issuance and usage logged
- **Revocable**: Close session → invalidate token immediately

### 2. All Crypto in Worker

```
┌─────────────────────────────────────────────────────────────────┐
│                     SIGNAL CRYPTO BOUNDARY                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PWA (allthe.services)                     KMS Worker           │
│  ──────────────────                        ──────────           │
│                                                                 │
│  - Renders UI                              - Identity key       │
│  - Shows plaintext                         - Signed prekey      │
│  - Never sees keys                         - One-time prekeys   │
│  - Never sees ratchet state                - Per-peer sessions  │
│                                             - Double Ratchet    │
│                                                                 │
│  Sends: ciphertext, metadata               Sends: plaintext     │
│  Receives: plaintext                       Receives: ciphertext │
│                                                                 │
│  ┌────────────────────────┐               ┌──────────────────┐  │
│  │ Message { ciphertext } │ ────────────▶ │ Decrypt          │  │
│  │                        │               │ Advance ratchet  │  │
│  │ Message { plaintext }  │ ◀──────────── │ Return plaintext │  │
│  └────────────────────────┘               └──────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Security Properties**:
- PWA never has access to keys or ratchet state
- XSS in PWA cannot steal Signal keys
- Compromised PWA can only forward ciphertexts (no decryption)
- Worker isolation prevents DOM-based attacks

### 3. Storage & Wrapping

All Signal state stored wrapped under MKEK:

```typescript
// Identity Key (long-term)
{
  type: 'signal-identity',
  kmsVersion: 2,
  algVersion: 1,
  wrappedBlob: ArrayBuffer,     // Ed25519 private key + public key
  iv: ArrayBuffer(12),
  aad: ArrayBuffer,             // {type, algVersion, kmsVersion, createdAt}
  publicKey: ArrayBuffer,       // Ed25519 public key (32 bytes, for export)
  createdAt: number
}

// Signed Prekey (medium-term, rotated)
{
  type: 'signal-signed-prekey',
  kmsVersion: 2,
  algVersion: 1,
  prekeyId: number,
  wrappedBlob: ArrayBuffer,     // X25519 private key + signature
  iv: ArrayBuffer(12),
  aad: ArrayBuffer,             // {type, prekeyId, algVersion, kmsVersion}
  publicKey: ArrayBuffer,       // X25519 public key (32 bytes)
  signature: ArrayBuffer,       // Ed25519 signature by identity key
  createdAt: number,
  expiresAt: number             // Rotation timestamp
}

// One-Time Prekey (short-term, consumed)
{
  type: 'signal-onetime-prekey',
  kmsVersion: 2,
  algVersion: 1,
  prekeyId: number,
  wrappedBlob: ArrayBuffer,     // X25519 private key
  iv: ArrayBuffer(12),
  aad: ArrayBuffer,             // {type, prekeyId, algVersion, kmsVersion}
  publicKey: ArrayBuffer,       // X25519 public key (32 bytes)
  createdAt: number,
  consumed: boolean             // Marked true after use
}

// Per-Peer Session (Double Ratchet state)
{
  type: 'signal-session',
  kmsVersion: 2,
  algVersion: 1,
  peerId: string,               // Peer identifier (JID, UUID, etc.)
  wrappedBlob: ArrayBuffer,     // Serialized ratchet state
  iv: ArrayBuffer(12),
  aad: ArrayBuffer,             // {type, peerId, algVersion, kmsVersion}
  createdAt: number,
  updatedAt: number,            // Last ratchet advancement
  messageCount: number          // Messages exchanged (for rotation)
}
```

**AAD Construction**:

```typescript
// For identity key
const aad = JSON.stringify({
  kmsVersion: 2,
  type: 'signal-identity',
  algVersion: 1,
  createdAt: config.createdAt,
  purpose: 'signal-identity-key'
});

// For per-peer session
const aad = JSON.stringify({
  kmsVersion: 2,
  type: 'signal-session',
  peerId: session.peerId,
  algVersion: 1,
  purpose: 'signal-session-state'
});
```

---

## Capability Token System

### Token Structure

```typescript
interface MessagingCapability {
  // Standard JWT fields
  typ: 'JWT';
  alg: 'EdDSA';               // Ed25519

  // Capability claims
  sid: string;                // Session ID (random UUID)
  scope: 'messaging';         // Only grants messaging ops
  aud: 'https://allthe.services';  // Audience (PWA origin)
  origin: string;             // Caller origin (for audit)
  iat: number;                // Issued at (Unix timestamp)
  exp: number;                // Expires (iat + ≤1h)

  // Optional constraints
  threads?: string[];         // Limit to specific peer IDs
  operations?: string[];      // Limit to specific operations
}
```

### Token Lifecycle

```
┌──────────────────────────────────────────────────────────────────┐
│                   CAPABILITY TOKEN LIFECYCLE                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. ISSUANCE (requires user auth)                                │
│     ┌────────────────────────────────────────────────────────┐   │
│     │ PWA: openMessaging({ threads: [peerId], credentials }) │   │
│     │ KMS: withUnlock(credentials, async (mkek) => {         │   │
│     │   - Verify auth                                        │   │
│     │   - Generate random sid (UUID)                         │   │
│     │   - Create JWT with sid, scope, exp=now+1h             │   │
│     │   - Sign with Ed25519 capability key                   │   │
│     │   - Store { sid, issuedAt, expiresAt, scope }          │   │
│     │   - Create MessageChannel, bind to sid                 │   │
│     │   - Return { sid, token, port1 }                       │   │
│     │ })                                                     │   │
│     └────────────────────────────────────────────────────────┘   │
│                                                                  │
│  2. USAGE (token in every RPC)                                   │
│     ┌─────────────────────────────────────────────────────────┐  │
│     │ PWA: port1.postMessage({                                │  │
│     │   method: 'batchDecrypt',                               │  │
│     │   sid: sid,                                             │  │
│     │   token: jwt,  // ← Token included                      │  │
│     │   params: { peerId, items }                             │  │
│     │ })                                                      │  │
│     │                                                         │  │
│     │ Worker: validateToken(token, sid):                      │  │
│     │   - Verify Ed25519 signature                            │  │
│     │   - Check exp > now                                     │  │
│     │   - Check sid matches channel                           │  │
│     │   - Check scope='messaging'                             │  │
│     │   - Check not revoked                                   │  │
│     └─────────────────────────────────────────────────────────┘  │
│                                                                  │
│  3. EXPIRATION (automatic or explicit)                           │
│     ┌─────────────────────────────────────────────────────────┐  │
│     │ Triggers:                                               │  │
│     │   - exp < now (time-based expiry)                       │  │
│     │   - closeMessaging({ sid }) (explicit close)            │  │
│     │   - Tab close / navigation (browser event)              │  │
│     │   - Idle timeout (5-10 min no activity)                 │  │
│     │                                                         │  │
│     │ Cleanup:                                                │  │
│     │   - Rewrap updated session states                       │  │
│     │   - Zero MS and MKEK                                    │  │
│     │   - Close MessageChannel                                │  │
│     │   - Mark token as revoked                               │  │
│     │   - Log closure to audit                                │  │
│     └─────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Token Validation

```typescript
async function validateCapabilityToken(
  token: string,
  expectedSid: string,
  expectedScope: string
): Promise<{ valid: boolean; claims?: MessagingCapability; error?: string }> {
  try {
    // 1. Parse JWT
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const claims = JSON.parse(base64urlDecode(payloadB64));

    // 2. Check basic fields
    if (claims.alg !== 'EdDSA') {
      return { valid: false, error: 'INVALID_ALGORITHM' };
    }

    // 3. Verify signature
    const signatureInput = `${headerB64}.${payloadB64}`;
    const signature = base64urlDecode(signatureB64);

    const capabilityKey = await loadCapabilitySigningKey();
    const valid = await crypto.subtle.verify(
      'Ed25519',
      capabilityKey,
      signature,
      new TextEncoder().encode(signatureInput)
    );

    if (!valid) {
      return { valid: false, error: 'INVALID_SIGNATURE' };
    }

    // 4. Check expiration
    if (claims.exp < Date.now() / 1000) {
      return { valid: false, error: 'TOKEN_EXPIRED' };
    }

    // 5. Check session ID
    if (claims.sid !== expectedSid) {
      return { valid: false, error: 'SID_MISMATCH' };
    }

    // 6. Check scope
    if (claims.scope !== expectedScope) {
      return { valid: false, error: 'INVALID_SCOPE' };
    }

    // 7. Check not revoked
    const revoked = await isTokenRevoked(claims.sid);
    if (revoked) {
      return { valid: false, error: 'TOKEN_REVOKED' };
    }

    return { valid: true, claims };
  } catch (error) {
    return { valid: false, error: 'VALIDATION_FAILED' };
  }
}
```

---

## Signal Crypto in Worker

### Ratchet State Management

```typescript
// In-memory session cache (during capability session)
interface SessionCache {
  [peerId: string]: {
    ratchetState: DoubleRatchetState;
    dirty: boolean;           // True if state changed (needs rewrap)
    lastUsed: number;
    messageCount: number;
  };
}

// Session lifecycle
class SignalSession {
  private sid: string;
  private sessions: SessionCache = {};
  private mkek: CryptoKey | null = null;

  // Open session (with auth)
  async open(threads: string[], credentials: AuthCredentials): Promise<string> {
    const { result, unlockTime, lockTime, duration } = await withUnlock(
      credentials,
      async (mkek: CryptoKey) => {
        // Store MKEK for session lifetime
        this.mkek = mkek;

        // Generate session ID
        this.sid = crypto.randomUUID();

        // Unwrap needed sessions
        for (const peerId of threads) {
          const wrapped = await getWrappedSession(peerId);
          if (wrapped) {
            const ratchetState = await unwrapSession(wrapped, mkek);
            this.sessions[peerId] = {
              ratchetState,
              dirty: false,
              lastUsed: Date.now(),
              messageCount: wrapped.messageCount
            };
          }
        }

        return this.sid;
      }
    );

    // Log session open to audit
    await logOperation({
      op: 'open_messaging',
      sid: this.sid,
      threads,
      unlockTime,
      lockTime,
      duration
    });

    return result;
  }

  // Decrypt message (uses cached ratchet)
  async decrypt(peerId: string, ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
    const session = this.sessions[peerId];
    if (!session) {
      throw new Error('SESSION_NOT_LOADED');
    }

    // Advance ratchet and decrypt
    const plaintext = await session.ratchetState.decrypt(ciphertext);

    // Mark dirty (needs rewrap)
    session.dirty = true;
    session.lastUsed = Date.now();
    session.messageCount++;

    return plaintext;
  }

  // Encrypt message (uses cached ratchet)
  async encrypt(peerId: string, plaintext: ArrayBuffer): Promise<ArrayBuffer> {
    const session = this.sessions[peerId];
    if (!session) {
      throw new Error('SESSION_NOT_LOADED');
    }

    // Advance ratchet and encrypt
    const ciphertext = await session.ratchetState.encrypt(plaintext);

    // Mark dirty
    session.dirty = true;
    session.lastUsed = Date.now();
    session.messageCount++;

    return ciphertext;
  }

  // Close session (rewrap and cleanup)
  async close(): Promise<void> {
    if (!this.mkek) {
      return;
    }

    // Rewrap dirty sessions
    for (const [peerId, session] of Object.entries(this.sessions)) {
      if (session.dirty) {
        await rewrapSession(peerId, session.ratchetState, this.mkek, session.messageCount);
      }
    }

    // Clear MKEK (garbage collected, non-extractable)
    this.mkek = null;

    // Clear sessions
    this.sessions = {};

    // Log closure
    await logOperation({
      op: 'close_messaging',
      sid: this.sid
    });
  }
}
```

### Key Operations

```typescript
// Generate identity key (once per user)
async function generateIdentityKey(mkek: CryptoKey): Promise<{ publicKey: ArrayBuffer }> {
  // Generate Ed25519 keypair
  const keypair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,  // Temporarily extractable for wrapping
    ['sign', 'verify']
  );

  // Export public key
  const publicKey = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Wrap private key
  const aad = new TextEncoder().encode(JSON.stringify({
    kmsVersion: 2,
    type: 'signal-identity',
    algVersion: 1,
    createdAt: Date.now(),
    purpose: 'signal-identity-key'
  }));

  const wrapped = await wrapSignalKey(keypair.privateKey, mkek, 'signal-identity', aad);

  // Store
  await storeSignalKey({
    type: 'signal-identity',
    kmsVersion: 2,
    algVersion: 1,
    wrappedBlob: wrapped.wrappedKey,
    iv: wrapped.iv,
    aad: aad.buffer,
    publicKey,
    createdAt: Date.now()
  });

  return { publicKey };
}

// Generate signed prekey (rotated periodically)
async function generateSignedPrekey(mkek: CryptoKey, prekeyId: number): Promise<{ publicKey: ArrayBuffer; signature: ArrayBuffer }> {
  // Generate X25519 keypair
  const keypair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,
    ['deriveKey']
  );

  // Export public key
  const publicKey = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Sign public key with identity key
  const identityKey = await unwrapSignalKey('signal-identity', mkek);
  const signature = await crypto.subtle.sign(
    'Ed25519',
    identityKey,
    publicKey
  );

  // Wrap private key
  const aad = new TextEncoder().encode(JSON.stringify({
    kmsVersion: 2,
    type: 'signal-signed-prekey',
    prekeyId,
    algVersion: 1,
    purpose: 'signal-signed-prekey'
  }));

  const wrapped = await wrapSignalKey(keypair.privateKey, mkek, `signal-signed-prekey-${prekeyId}`, aad);

  // Store
  await storeSignalKey({
    type: 'signal-signed-prekey',
    kmsVersion: 2,
    algVersion: 1,
    prekeyId,
    wrappedBlob: wrapped.wrappedKey,
    iv: wrapped.iv,
    aad: aad.buffer,
    publicKey,
    signature,
    createdAt: Date.now(),
    expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000)  // 30 days
  });

  return { publicKey, signature };
}

// Generate one-time prekeys (batch)
async function generateOnetimePrekeys(mkek: CryptoKey, count: number, startId: number): Promise<Array<{ prekeyId: number; publicKey: ArrayBuffer }>> {
  const prekeys = [];

  for (let i = 0; i < count; i++) {
    const prekeyId = startId + i;

    // Generate X25519 keypair
    const keypair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveKey']
    );

    // Export public key
    const publicKey = await crypto.subtle.exportKey('raw', keypair.publicKey);

    // Wrap private key
    const aad = new TextEncoder().encode(JSON.stringify({
      kmsVersion: 2,
      type: 'signal-onetime-prekey',
      prekeyId,
      algVersion: 1,
      purpose: 'signal-onetime-prekey'
    }));

    const wrapped = await wrapSignalKey(keypair.privateKey, mkek, `signal-onetime-prekey-${prekeyId}`, aad);

    // Store
    await storeSignalKey({
      type: 'signal-onetime-prekey',
      kmsVersion: 2,
      algVersion: 1,
      prekeyId,
      wrappedBlob: wrapped.wrappedKey,
      iv: wrapped.iv,
      aad: aad.buffer,
      publicKey,
      createdAt: Date.now(),
      consumed: false
    });

    prekeys.push({ prekeyId, publicKey });
  }

  return prekeys;
}
```

---

## RPC Interface

### MessageChannel Setup

```typescript
// 1. PWA requests messaging capability
const { sid, port1 } = await kmsUser.openMessaging({
  threads: ['peer-alice', 'peer-bob'],
  credentials: {
    method: 'passphrase',
    passphrase: userPassphrase
  }
});

// 2. Use port1 for all messaging RPCs
port1.postMessage({
  method: 'batchDecrypt',
  sid,
  params: {
    peerId: 'peer-alice',
    items: [{ messageId, ciphertext, headers }]
  }
});

// 3. Receive results
port1.onmessage = (event) => {
  const { method, result, error } = event.data;
  if (method === 'batchDecrypt') {
    for await (const item of result) {
      // Stream plaintext to UI
      displayMessage(item.messageId, item.plaintext);
    }
  }
};
```

### RPC Methods

```typescript
// Open messaging session
interface OpenMessagingRequest {
  method: 'openMessaging';
  params: {
    threads: string[];           // Peer IDs to load
    credentials: AuthCredentials;
  };
}

interface OpenMessagingResponse {
  sid: string;                   // Session ID
  token: string;                 // Ed25519-signed JWT
  expiresAt: number;             // Unix timestamp
}

// Batch decrypt (for loading history)
interface BatchDecryptRequest {
  method: 'batchDecrypt';
  sid: string;
  token: string;
  params: {
    peerId: string;
    items: Array<{
      messageId: string;
      ciphertext: ArrayBuffer;
      headers: MessageHeaders;
    }>;
  };
}

interface BatchDecryptResponse {
  // AsyncIterable for streaming
  result: AsyncIterable<{
    messageId: string;
    plaintext: ArrayBuffer;
    error?: string;
  }>;
}

// Encrypt message
interface EncryptRequest {
  method: 'encrypt';
  sid: string;
  token: string;
  params: {
    peerId: string;
    plaintext: ArrayBuffer;
    headers: MessageHeaders;
  };
}

interface EncryptResponse {
  ciphertext: ArrayBuffer;
  headers: MessageHeaders;
}

// Ingest incoming message
interface IngestIncomingRequest {
  method: 'ingestIncoming';
  sid: string;
  token: string;
  params: {
    peerId: string;
    items: Array<{
      messageId: string;
      ciphertext: ArrayBuffer;
      headers: MessageHeaders;
    }>;
  };
}

interface IngestIncomingResponse {
  // AsyncIterable for streaming
  result: AsyncIterable<{
    messageId: string;
    plaintext: ArrayBuffer;
    error?: string;
  }>;
}

// Rotate prekeys
interface RotatePrekeysRequest {
  method: 'rotatePrekeys';
  sid: string;
  token: string;
  params: {
    signedPrekey?: boolean;      // Rotate signed prekey
    onetimeCount?: number;       // Generate N one-time prekeys
  };
}

interface RotatePrekeysResponse {
  signedPrekey?: {
    prekeyId: number;
    publicKey: ArrayBuffer;
    signature: ArrayBuffer;
  };
  onetimePrekeys?: Array<{
    prekeyId: number;
    publicKey: ArrayBuffer;
  }>;
}

// Close messaging session
interface CloseMessagingRequest {
  method: 'closeMessaging';
  sid: string;
  token: string;
}

interface CloseMessagingResponse {
  status: 'closed';
  sessionsRewrapped: number;
}

// Message headers (Signal Protocol metadata)
interface MessageHeaders {
  version: number;               // Protocol version
  counter: number;               // Ratchet counter
  previousCounter: number;       // For out-of-order handling
  dhPublicKey?: ArrayBuffer;     // If DH ratchet step
}
```

---

## Streaming & Performance

### Batch Decrypt with Streaming

```typescript
// Worker side: Stream results as they complete
async function* batchDecrypt(
  session: SignalSession,
  peerId: string,
  items: CipherItem[]
): AsyncIterable<PlainItem> {
  const MAX_IN_FLIGHT = 50;  // Back-pressure limit
  const queue = [...items];
  const inFlight = new Set<Promise<PlainItem>>();

  while (queue.length > 0 || inFlight.size > 0) {
    // Fill in-flight queue
    while (queue.length > 0 && inFlight.size < MAX_IN_FLIGHT) {
      const item = queue.shift()!;
      const promise = decryptItem(session, peerId, item);
      inFlight.add(promise);

      // Yield as soon as one completes
      promise.then(() => inFlight.delete(promise));
    }

    // Wait for at least one to complete
    const completed = await Promise.race(Array.from(inFlight));
    yield completed;
  }
}

async function decryptItem(
  session: SignalSession,
  peerId: string,
  item: CipherItem
): Promise<PlainItem> {
  try {
    const plaintext = await session.decrypt(peerId, item.ciphertext);
    return {
      messageId: item.messageId,
      plaintext
    };
  } catch (error) {
    return {
      messageId: item.messageId,
      plaintext: new ArrayBuffer(0),
      error: error instanceof Error ? error.message : 'DECRYPT_FAILED'
    };
  }
}
```

### PWA Side: Incremental Rendering

```typescript
// Stream results to UI as they arrive
async function loadThreadHistory(peerId: string, messages: CipherItem[]) {
  const response = await sendRPC('batchDecrypt', {
    peerId,
    items: messages
  });

  // Render incrementally
  for await (const item of response.result) {
    if (item.error) {
      console.error(`Failed to decrypt ${item.messageId}: ${item.error}`);
      renderErrorMessage(item.messageId);
    } else {
      const text = new TextDecoder().decode(item.plaintext);
      renderMessage(item.messageId, text);
    }
  }
}
```

### Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Open messaging | 200-400ms | Includes auth + unwrap N sessions |
| Decrypt (single) | <10ms | Per message, in-memory ratchet |
| Decrypt (batch) | <500ms | 50 messages, streamed |
| Encrypt | <10ms | Per message |
| Rotate prekeys | <200ms | Signed prekey + 100 one-time |
| Close messaging | <100ms | Rewrap dirty sessions |

---

## Audit & Metrics

### Audit Entry for Messaging

```typescript
interface MessagingAuditEntry extends AuditEntryV2 {
  // Standard fields
  kmsVersion: 2;
  seqNum: number;
  timestamp: number;
  op: 'open_messaging' | 'batch_decrypt' | 'encrypt' | 'ingest_incoming' | 'rotate_prekeys' | 'close_messaging';
  requestId: string;

  // Messaging-specific
  sid: string;                   // Session ID
  peerId?: string;               // Peer involved
  messageCount?: number;         // Number of messages processed
  threads?: string[];            // Threads opened (for open_messaging)

  // Timing
  unlockTime: number;
  lockTime: number;
  duration: number;

  // Chain integrity
  previousHash: string;
  chainHash: string;
  signature: string;
  auditKeyId: string;
}
```

### Example Audit Entries

```typescript
// Open messaging
{
  kmsVersion: 2,
  seqNum: 1042,
  timestamp: 1706140800000,
  op: 'open_messaging',
  sid: 'a1b2c3d4-...',
  threads: ['peer-alice', 'peer-bob'],
  requestId: 'req-5678',
  unlockTime: 1706140800100,
  lockTime: 1706140800350,
  duration: 250,
  previousHash: '7f8e9d...',
  chainHash: 'a1b2c3...',
  signature: 'd4e5f6...',
  auditKeyId: 'audit-key-1'
}

// Batch decrypt
{
  kmsVersion: 2,
  seqNum: 1043,
  timestamp: 1706140801000,
  op: 'batch_decrypt',
  sid: 'a1b2c3d4-...',
  peerId: 'peer-alice',
  messageCount: 50,
  requestId: 'req-5679',
  // No unlockTime/lockTime (session already open)
  previousHash: 'a1b2c3...',
  chainHash: 'b2c3d4...',
  signature: 'e5f6g7...',
  auditKeyId: 'audit-key-1'
}

// Close messaging
{
  kmsVersion: 2,
  seqNum: 1044,
  timestamp: 1706141200000,
  op: 'close_messaging',
  sid: 'a1b2c3d4-...',
  requestId: 'req-5680',
  details: {
    sessionsRewrapped: 2,
    totalMessages: 157
  },
  previousHash: 'b2c3d4...',
  chainHash: 'c3d4e5...',
  signature: 'f6g7h8...',
  auditKeyId: 'audit-key-1'
}
```

---

## Implementation Guide

### Phase 1: Foundation (Week 1)

**Tasks**:
- [ ] Define Signal storage schemas (identity, prekeys, sessions)
- [ ] Implement capability token system (JWT signing/verification)
- [ ] Add Ed25519 capability signing key (separate from audit key)
- [ ] Create session management class (SignalSession)
- [ ] Implement token validation middleware

**Acceptance Criteria**:
- Can generate and verify capability tokens
- Session lifecycle (open/close) works
- Token expiration enforced

### Phase 2: Key Management (Week 2)

**Tasks**:
- [ ] Implement `generateIdentityKey()`
- [ ] Implement `generateSignedPrekey()`
- [ ] Implement `generateOnetimePrekeys()`
- [ ] Add key wrapping with AAD for Signal keys
- [ ] Implement key rotation logic
- [ ] Add prekey consumption tracking

**Acceptance Criteria**:
- Identity key generated and wrapped
- Signed prekey rotation works
- One-time prekeys consumed correctly

### Phase 3: Double Ratchet (Week 3)

**Tasks**:
- [ ] Integrate Signal Protocol library or implement ratchet
- [ ] Implement session initialization (X3DH)
- [ ] Implement encrypt/decrypt with ratchet advancement
- [ ] Add session rewrapping on close
- [ ] Handle out-of-order messages

**Acceptance Criteria**:
- Can establish session with peer
- Messages encrypt/decrypt correctly
- Forward secrecy maintained (old messages undecryptable)
- Out-of-order messages handled

### Phase 4: RPC Interface (Week 4)

**Tasks**:
- [ ] Implement `openMessaging()` RPC
- [ ] Implement `batchDecrypt()` with streaming
- [ ] Implement `encrypt()` RPC
- [ ] Implement `ingestIncoming()` with streaming
- [ ] Implement `rotatePrekeys()` RPC
- [ ] Implement `closeMessaging()` RPC
- [ ] Add back-pressure control (MAX_IN_FLIGHT)

**Acceptance Criteria**:
- All RPC methods work
- Streaming delivers results incrementally
- Back-pressure prevents memory issues

### Phase 5: Audit & Testing (Week 5)

**Tasks**:
- [ ] Add audit logging for all messaging ops
- [ ] Test open/close lifecycle
- [ ] Test batch decrypt with 100+ messages
- [ ] Test session rewrapping
- [ ] Test token expiration and revocation
- [ ] Performance testing (meet targets)
- [ ] Security testing (XSS resilience, token validation)

**Acceptance Criteria**:
- All audit entries recorded
- Performance targets met
- Security properties verified
- 100% test coverage

### Phase 6: Integration (Week 6)

**Tasks**:
- [ ] Integrate with PWA UI (allthe.services)
- [ ] Add message rendering with streaming
- [ ] Implement session timeout (idle, tab close)
- [ ] Add prekey rotation UI
- [ ] Test cross-tab behavior
- [ ] Document user workflows

**Acceptance Criteria**:
- End-to-end messaging works
- UI responsive during batch operations
- Session cleanup on tab close
- Prekey rotation accessible

---

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ XSS in PWA (keys never in PWA context)
- ✅ Compromised PWA (can only forward ciphertexts)
- ✅ Persistent unlock attacks (tokens expire ≤1h)
- ✅ Scope confusion (tokens bound to messaging scope)
- ✅ Token replay (tokens bound to sid)
- ✅ Forward secrecy loss (ratchet state properly advanced)

**NOT Protected Against**:
- ❌ Compromised Worker (can decrypt during session)
- ❌ Malicious browser (full memory access)
- ❌ Compromised OS (memory dumps)
- ❌ Peer impersonation (requires separate identity verification)

### Key Lifetimes

| Key Type | Lifetime | Rotation |
|----------|----------|----------|
| Identity | Permanent | Only on explicit user action |
| Signed Prekey | 30 days | Automatic rotation |
| One-Time Prekey | Single use | Consumed on session start |
| Ratchet Chain Key | Per message | Advanced with each message |
| Ratchet Root Key | Per DH ratchet | Advanced on DH step |

### Best Practices

1. **Rotate signed prekeys regularly** (30 days max)
2. **Maintain pool of one-time prekeys** (≥100 unconsumed)
3. **Close sessions promptly** (don't leave open overnight)
4. **Audit token usage** (detect abnormal patterns)
5. **Test ratchet advancement** (ensure forward secrecy)
6. **Verify peer identity** (out-of-band verification)

---

## Next Steps

1. **Review this design** with security team
2. **Choose Signal implementation**: Integrate existing library or implement minimal ratchet
3. **Prototype capability tokens**: Verify JWT performance
4. **Test session lifecycle**: Ensure proper cleanup
5. **Begin Phase 1 implementation**: Foundation and key management

---

**Status**: Ready for implementation review.

**Dependencies**: V2 core architecture (withUnlock, AAD, versioning) must be complete first.

**Estimated Timeline**: 6 weeks for full Signal integration.
