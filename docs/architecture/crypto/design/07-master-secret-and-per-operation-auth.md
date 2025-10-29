# ADR: Master Secret Pattern and Per-Operation Authentication

**Status**: Adopted
**Date**: 2025-10-24
**Decision**: Implement Master Secret (MS) encryption pattern and eliminate persistent unlocked state

---

## Context

The initial implementation used a pattern where:
1. The Master KEK (MKEK) was stored as a `CryptoKey` object
2. To support dual unlock (passphrase + passkey), we needed to wrap the MKEK with multiple KEKs
3. This required making the MKEK `extractable: true` so it could be wrapped
4. Once unlocked, the MKEK remained in memory until explicit lock action
5. Operations could be performed without re-authentication while unlocked

**Problems with this approach:**
- Making MKEK extractable expands attack surface (enables `exportKey()` API)
- Persistent unlocked state increases risk window
- If attacker gains code execution in Worker, they can export keys or perform unlimited operations
- No per-operation authentication means one compromise = full access

---

## Decision

We implement two architectural changes together:

### 1. Master Secret (MS) Encryption Pattern

**Store encrypted bytes instead of wrapped CryptoKeys:**

```
┌─────────────────────────────────────────────────────────┐
│ OLD PATTERN (wrapped CryptoKeys)                        │
├─────────────────────────────────────────────────────────┤
│ 1. Generate MKEK as CryptoKey (extractable:true)       │
│ 2. Wrap MKEK with KEK_passphrase → store wrapped bytes │
│ 3. Wrap MKEK with KEK_passkey → store wrapped bytes    │
│ 4. On unlock: unwrapKey() → MKEK in memory             │
│ 5. Problem: MKEK must be extractable for wrapKey()     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ NEW PATTERN (encrypted Master Secret)                   │
├─────────────────────────────────────────────────────────┤
│ 1. Generate MS as random bytes (32 bytes)              │
│ 2. Encrypt MS with KEK_passphrase → store ciphertext   │
│ 3. Encrypt MS with KEK_passkey → store ciphertext      │
│ 4. On unlock: decrypt MS → derive MKEK from MS         │
│ 5. Benefit: No CryptoKey needs extractable:true        │
└─────────────────────────────────────────────────────────┘
```

**Implementation:**
- MS = 32 random bytes (256 bits), never stored unencrypted
- Each unlock method stores `encryptedMS` (AES-GCM ciphertext)
- On unlock: decrypt MS with method-specific KEK
- Derive MKEK from MS using HKDF: `HKDF(MS, salt, info="MKEK v1") → AES-GCM key`
- MKEK is `extractable: false`, only exists in memory temporarily

### 2. Per-Operation Authentication (No Persistent Unlock)

**Eliminate persistent unlocked state:**

```
┌─────────────────────────────────────────────────────────┐
│ OLD FLOW (persistent unlock)                            │
├─────────────────────────────────────────────────────────┤
│ 1. User unlocks KMS                                     │
│ 2. MKEK stored in memory                                │
│ 3. Operations performed without re-auth                 │
│ 4. MKEK persists until explicit lock                    │
│ 5. Risk: Long-lived in-memory keys                      │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ NEW FLOW (per-operation auth)                           │
├─────────────────────────────────────────────────────────┤
│ 1. User requests operation (e.g., "sign JWT")           │
│ 2. Worker requests authentication from client           │
│ 3. Client performs WebAuthn/passphrase prompt           │
│ 4. Worker decrypts MS, derives MKEK                     │
│ 5. Perform operation(s)                                 │
│ 6. IMMEDIATELY clear MKEK from memory                   │
│ 7. Next operation requires new authentication           │
└─────────────────────────────────────────────────────────┘
```

**Key principles:**
- No persistent unlocked state in Worker
- Each operation batch requires authentication
- MKEK lifetime: milliseconds (just long enough for operation)
- Multiple operations can be batched in single auth (e.g., generate VAPID + sign JWT)

---

## Rationale

### Security Benefits

**1. No Extractable KEKs**
- MS is bytes, not a CryptoKey → no `wrapKey()` needed
- All CryptoKeys (KEKs, MKEK) are `extractable: false`
- Removes `exportKey()` attack vector entirely

**2. Minimal Key Lifetime**
- MKEK exists in memory only during operation (milliseconds)
- Reduces window for memory dump attacks
- Limits impact of Worker compromise

**3. Defense in Depth**
- Even if attacker gains code execution in Worker:
  - Cannot export keys (non-extractable)
  - Cannot perform operations without user auth
  - Cannot maintain persistent access
- Each operation requires user presence (passkey) or knowledge (passphrase)

**4. Audit Trail**
- Every operation logged with authentication event
- Clear correlation: auth → operation → lock
- Easier to detect unauthorized access attempts

### Usability Considerations

**Potential concern**: Too many auth prompts

**Mitigations**:
1. **Operation batching**: Group related operations (e.g., generate + sign)
2. **WebAuthn is fast**: Passkey auth takes <1 second
3. **Clear UX**: "Authenticate to sign JWT" is clearer than "Unlock KMS"
4. **Security-first**: This is a KMS, not a general-purpose app

**User mental model**: More like `sudo` (auth per command) than session login

---

## Implementation Details

### Data Structures

```typescript
// IndexedDB: Encrypted MS per unlock method
type UnlockPassphraseConfig = {
  method: 'passphrase';
  salt: ArrayBuffer;
  iterations: number;
  encryptedMS: ArrayBuffer;  // MS encrypted with passphrase-derived KEK
  msIV: ArrayBuffer;
  verificationHash: string;
};

type UnlockPasskeyPRFConfig = {
  method: 'passkey-prf';
  credentialId: ArrayBuffer;
  appSalt: ArrayBuffer;
  encryptedMS: ArrayBuffer;  // MS encrypted with PRF-derived KEK
  msIV: ArrayBuffer;
};
```

### Setup Flow (First Method)

```typescript
// 1. Generate random MS (never stored unencrypted)
const ms = crypto.getRandomValues(new Uint8Array(32));

// 2. Derive KEK from passphrase/passkey
const kek = await deriveKEK(/* method-specific params */);

// 3. Encrypt MS with KEK (not wrapKey!)
const msIV = crypto.getRandomValues(new Uint8Array(12));
const encryptedMS = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: msIV },
  kek,
  ms
);

// 4. Store encrypted MS
await putMeta('passphraseConfig', {
  method: 'passphrase',
  encryptedMS,
  msIV: msIV.buffer,
  // ... other fields
});

// 5. Clear MS from memory immediately
ms.fill(0);
```

### Setup Flow (Second Method)

```typescript
// 1. Require authentication to get MS
const { ms } = await authenticateAndGetMS('passphrase', userPassphrase);

// 2. Derive new KEK for second method
const kek2 = await deriveKEK(/* passkey params */);

// 3. Encrypt same MS with new KEK
const msIV = crypto.getRandomValues(new Uint8Array(12));
const encryptedMS = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: msIV },
  kek2,
  ms
);

// 4. Store second method's encrypted MS
await putMeta('passkeyConfig', {
  method: 'passkey-prf',
  encryptedMS,
  msIV: msIV.buffer,
  // ... other fields
});

// 5. Clear MS immediately
ms.fill(0);
```

### Operation Flow (Per-Operation Auth)

```typescript
// Example: signJWT operation

// Worker handler
async function handleSignJWT(request: SignJWTRequest) {
  // 1. Request authentication from client
  const authRequest = {
    operation: 'signJWT',
    kid: request.kid,
    requiresAuth: true
  };

  // Send auth request to client, wait for credentials
  const credentials = await requestAuthentication(authRequest);

  // 2. Decrypt MS using provided credentials
  const ms = await decryptMS(credentials);

  // 3. Derive MKEK from MS (non-extractable, in memory only)
  const mkek = await deriveMKEKFromMS(ms);

  // 4. Unwrap application key
  const signingKey = await unwrapKey(request.kid, mkek);

  // 5. Perform operation
  const jwt = await signJWT(signingKey, request.payload);

  // 6. IMMEDIATELY clear sensitive material
  ms.fill(0);  // Clear MS bytes
  // mkek automatically garbage collected (non-extractable CryptoKey)

  return { jwt };
}
```

### Combined Operation Flow (Batching)

```typescript
// Example: Generate VAPID + Sign JWT (single auth)

async function handleGenerateAndSignVAPID(request: GenerateAndSignRequest) {
  // 1. Single authentication for both operations
  const credentials = await requestAuthentication({
    operations: ['generateVAPID', 'signJWT']
  });

  // 2. Decrypt MS once
  const ms = await decryptMS(credentials);
  const mkek = await deriveMKEKFromMS(ms);

  // 3. Generate VAPID keypair
  const vapidKeypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,  // extractable only for immediate wrapping
    ['sign']
  );

  // 4. Wrap VAPID key with MKEK
  await wrapKey(vapidKeypair.privateKey, mkek, vapidKid);

  // 5. Sign JWT with VAPID key
  const jwt = await signJWT(vapidKeypair.privateKey, request.payload);

  // 6. Clear everything
  ms.fill(0);

  return { kid: vapidKid, publicKey, jwt };
}
```

---

## Migration Path

### Phase 1: Implement MS Pattern (Breaking Change)
- Update unlock.ts to use MS encryption
- Update storage config types
- Require users to reset and re-setup (one-time)

### Phase 2: Implement Per-Operation Auth (Breaking Change)
- Remove persistent unlock state from worker.ts
- Update RPC protocol to include authentication in operation requests
- Update kms-user.ts to handle auth prompts
- Update client.ts to coordinate auth + operation

### Phase 3: Update Tests
- Unit tests for MS encryption/decryption
- Integration tests for per-operation auth flow
- Security tests for key lifetime

---

## Security Guarantees

### What This Protects Against

✅ **XSS in Worker**: Cannot export keys (non-extractable), cannot perform operations without user auth

✅ **Memory dump (cold boot)**: Minimal exposure window (keys only exist during operation)

✅ **Compromised worker code**: Cannot maintain persistent access, each operation requires user

✅ **Replay attacks**: Each auth can be single-use (nonce in WebAuthn challenge)

### What This Does NOT Protect Against

❌ **Malicious browser**: Browser can access all memory and bypass all protections

❌ **Compromised OS**: OS can read process memory, intercept WebAuthn

❌ **User credential theft**: Stolen passphrase/passkey = full access

❌ **Simultaneous attack**: Attacker who intercepts credentials during operation can perform that operation

---

## Trade-offs

### Advantages
- Eliminates extractable CryptoKeys entirely
- Minimal in-memory key lifetime
- Clear security boundary per operation
- Better audit trail
- Matches user mental model ("auth to perform action")

### Disadvantages
- More frequent auth prompts (mitigated by operation batching)
- Slightly more complex RPC protocol
- Cannot perform operations in background without user presence
- Breaking change (requires re-setup)

---

## Decision

**We adopt both changes**:
1. Master Secret encryption pattern (no more wrapped CryptoKeys)
2. Per-operation authentication (no persistent unlock state)

This significantly strengthens the security model while maintaining usability through operation batching.

---

## Extension: SessionKEK for VAPID Leases

### Context

While per-operation authentication provides strong security, some use cases require operations without user interaction:
- **VAPID JWT signing**: Push notifications may need JWTs when user is not present
- **Background sync**: Operations triggered by Service Worker
- **High-frequency operations**: Signing many JWTs in short time (e.g., batch notifications)

The **lease model** with **SessionKEK** provides time-bounded authorization for these scenarios.

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ SessionKEK Pattern (Exception to Per-Operation Auth)        │
├──────────────────────────────────────────────────────────────┤
│ CREATE LEASE (user present):                                │
│  1. User authenticates → get MS                             │
│  2. Generate random 32-byte Lease Salt (LS)                 │
│  3. Derive SessionKEK:                                       │
│     SessionKEK = HKDF(MS, LS, "ATS/KMS/SessionKEK/v1")     │
│  4. Unwrap VAPID key with MKEK                              │
│  5. Wrap VAPID key with SessionKEK → wrappedLeaseKey       │
│  6. Store lease: {leaseId, wrappedLeaseKey, LS, exp, ...}  │
│  7. Store SessionKEK in IndexedDB (CryptoKey persists)      │
│  8. Cache SessionKEK in memory Map                          │
│  9. Clear MS immediately                                     │
│                                                              │
│ ISSUE JWT (no user interaction):                            │
│  1. Retrieve SessionKEK from cache or IndexedDB             │
│  2. Check lease expiration                                   │
│  3. Enforce quotas (tokens/hour, sends/min, etc.)           │
│  4. Unwrap VAPID key using SessionKEK                       │
│  5. Sign JWT                                                 │
│  6. Clear unwrapped VAPID key                               │
│  7. SessionKEK remains cached for next JWT                  │
└──────────────────────────────────────────────────────────────┘
```

### Security Properties

**Time-bounded authorization**:
- Lease has expiration time (typ. 8-12 hours, max 24 hours)
- SessionKEK is useless after lease expires
- User must re-authenticate to create new lease

**Quota enforcement**:
- Limits per hour: tokens issued
- Limits per minute: sends, burst sends
- Per-endpoint limits: prevents abuse of single subscription
- Hard limits even if SessionKEK is compromised

**Lease-scoped keys**:
- Each lease has unique salt → unique SessionKEK
- SessionKEK cannot be used for other leases
- Revoking lease = SessionKEK becomes useless

**Separation of concerns**:
- **MS**: Never persisted, only during lease creation
- **MKEK**: Derived from MS, used to wrap application keys
- **SessionKEK**: Lease-scoped, derived per-lease, wraps copies of VAPID key
- **VAPID key**: Main copy wrapped with MKEK (requires user auth)
- **Wrapped lease key**: Lease-specific copy wrapped with SessionKEK (no auth)

### Implementation

```typescript
// === LEASE CREATION (with user auth) ===

async function handleCreateLease(params: {
  userId: string;
  subs: Subscription[];
  ttlHours: number;
  credentials: AuthCredentials;
}): Promise<{ leaseId: string; exp: number }> {
  // 1. Authenticate and get MS
  const result = await withUnlock(credentials, async (mkek, ms) => {
    // 2. Generate unique lease salt
    const leaseSalt = crypto.getRandomValues(new Uint8Array(32));
    const leaseId = `lease-${crypto.randomUUID()}`;

    // 3. Derive SessionKEK from MS + lease salt
    const sessionKEK = await deriveSessionKEK(ms, leaseSalt);
    //   SessionKEK = HKDF-SHA256(
    //     ikm = MS,
    //     salt = leaseSalt,
    //     info = "ATS/KMS/SessionKEK/v1",
    //     length = 256
    //   )

    // 4. Unwrap VAPID private key with MKEK (main storage)
    const vapidPrivateKey = await unwrapKey(
      vapidKid,
      mkek,
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign']
    );

    // 5. Wrap VAPID key with SessionKEK (lease-specific copy)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const exportedKey = await crypto.subtle.exportKey('pkcs8', vapidPrivateKey);
    const wrappedLeaseKey = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      sessionKEK,
      exportedKey
    );

    return { leaseId, wrappedLeaseKey, iv, leaseSalt, sessionKEK };
  });

  // 6. Store SessionKEK in IndexedDB (persists across worker restarts)
  await putMeta(`sessionkek:${result.leaseId}`, result.sessionKEK);

  // 7. Cache in memory for performance
  sessionKEKCache.set(result.leaseId, result.sessionKEK);

  // 8. Create and store lease record
  const lease: LeaseRecord = {
    leaseId: result.leaseId,
    userId: params.userId,
    subs: params.subs,
    ttlHours: params.ttlHours,
    exp: Date.now() + params.ttlHours * 3600 * 1000,
    wrappedLeaseKey: result.wrappedLeaseKey,
    wrappedLeaseKeyIV: result.iv,
    leaseSalt: result.leaseSalt,
    kid: vapidKid,
    quotas: { /* ... */ }
  };
  await putMeta(`lease:${result.leaseId}`, lease);

  return { leaseId: result.leaseId, exp: lease.exp };
}

// === JWT ISSUANCE (no user auth) ===

async function handleIssueVAPIDJWT(params: {
  leaseId: string;
  endpoint: { url: string; aud: string; eid: string };
}): Promise<{ jwt: string; jti: string; exp: number }> {
  // 1. Retrieve lease
  const lease = await getMeta<LeaseRecord>(`lease:${params.leaseId}`);
  if (!lease) throw new Error('Lease not found');

  // 2. Check expiration
  if (Date.now() >= lease.exp) throw new Error('Lease expired');

  // 3. Enforce quotas
  await enforceQuotas(params.leaseId, lease.quotas);

  // 4. Get SessionKEK (from cache or IndexedDB)
  let sessionKEK = sessionKEKCache.get(params.leaseId);
  if (!sessionKEK) {
    sessionKEK = await getMeta<CryptoKey>(`sessionkek:${params.leaseId}`);
    if (!sessionKEK) throw new Error('SessionKEK not found');
    sessionKEKCache.set(params.leaseId, sessionKEK);
  }

  // 5. Unwrap VAPID key using SessionKEK (no user auth needed!)
  const iv = new Uint8Array(lease.wrappedLeaseKeyIV);
  const decryptedKeyData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    sessionKEK,
    lease.wrappedLeaseKey
  );

  // 6. Import as ECDSA private key
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    decryptedKeyData,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // not extractable
    ['sign']
  );

  // 7. Sign JWT
  const jti = crypto.randomUUID();
  const exp = Math.floor(Date.now() / 1000) + 900; // 15 min
  const payload = { aud: params.endpoint.aud, sub: '...', exp, jti };

  const header = { typ: 'JWT', alg: 'ES256', kid: lease.kid };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signatureInput = `${headerB64}.${payloadB64}`;

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(signatureInput)
  );

  const jwt = `${headerB64}.${payloadB64}.${base64url(signature)}`;

  // 8. Private key garbage collected
  // 9. SessionKEK remains cached for next JWT

  return { jwt, jti, exp };
}
```

### Key Derivation Formula

```
SessionKEK = HKDF-SHA256(
  ikm = MS (32 bytes),
  salt = LeaseSalt (32 bytes, random per lease),
  info = "ATS/KMS/SessionKEK/v1" (UTF-8 encoded),
  length = 256 bits
)
```

**Properties**:
- Unique per lease (different salt)
- Cannot be derived without MS (requires user auth during lease creation)
- Forward secrecy: Old SessionKEKs useless after lease expires

### Storage Schema

```typescript
// IndexedDB meta store:

// SessionKEK (CryptoKey, persists across worker restarts)
"sessionkek:{leaseId}": CryptoKey {
  type: "secret",
  algorithm: { name: "AES-GCM", length: 256 },
  extractable: false,
  usages: ["wrapKey", "unwrapKey"]
}

// Lease record
"lease:{leaseId}": {
  leaseId: string;
  userId: string;
  subs: Subscription[];
  exp: number;
  wrappedLeaseKey: ArrayBuffer;   // VAPID key wrapped with SessionKEK
  wrappedLeaseKeyIV: ArrayBuffer;  // IV for AES-GCM encryption
  leaseSalt: ArrayBuffer;          // Salt used to derive SessionKEK
  kid: string;                     // VAPID key ID
  quotas: QuotaState;
}

// Main VAPID key (still wrapped with MKEK, requires auth)
"keys": WrappedKey {
  kid: string;
  wrappedKey: ArrayBuffer;  // Wrapped with MKEK (requires user auth)
  // ...
}
```

### Security Analysis

**Attack Scenarios**:

1. **Attacker steals SessionKEK from IndexedDB**:
   - ✅ Can only issue JWTs until lease expires
   - ✅ Quota limits prevent unlimited abuse
   - ✅ Cannot create new leases (requires MS)
   - ✅ Cannot access other leases (unique SessionKEK per lease)

2. **Attacker with worker code execution during lease**:
   - ✅ Same as above (SessionKEK stored, can issue JWTs)
   - ✅ Time-limited by lease expiration
   - ✅ Quota-limited by hard limits
   - ❌ Can issue JWTs without user knowing (trade-off for convenience)

3. **Attacker after lease expiry**:
   - ✅ SessionKEK useless (lease expired)
   - ✅ Must compromise user credentials to create new lease
   - ✅ Main VAPID key still requires MKEK (user auth)

**Trade-offs**:

| Aspect | Per-Operation Auth | SessionKEK Leases |
|--------|-------------------|-------------------|
| User interaction | Required per operation | Required per lease creation (8-12h) |
| Security level | Highest (always auth) | High (time + quota bounded) |
| Background ops | Not possible | Possible during lease |
| Attack window | Milliseconds | Hours (lease duration) |
| Suitable for | High-value operations | Push notifications, batch operations |

### When to Use SessionKEK

**Use SessionKEK leases when**:
- Operations need to happen without user present (push notifications)
- High frequency operations (many JWTs)
- Background Service Worker operations
- User explicitly authorizes time-bounded access

**Use per-operation auth when**:
- High-value operations (key generation, account changes)
- Infrequent operations
- Operations user directly triggers
- Maximum security required

### Lease Lifecycle

```
1. CREATE LEASE (user auth required)
   ↓
2. ACTIVE (0-24 hours)
   - Issue JWTs without auth
   - Enforce quotas
   - SessionKEK in cache + IndexedDB
   ↓
3. EXPIRE (automatic)
   - SessionKEK still in storage but useless
   - Quota checks fail (lease expired)
   - Must create new lease
   ↓
4. CLEANUP (periodic)
   - Delete expired lease records
   - Delete expired SessionKEKs
   - Clear from cache
```

### Future Enhancements

**Revocation**:
- Explicit `revokeLease()` method
- User can revoke specific lease before expiration
- Deletes SessionKEK immediately

**Refresh**:
- `refreshLease()` extends expiration (requires auth)
- Useful for long-running apps
- Resets quotas

**Multiple leases**:
- User can have multiple concurrent leases
- Different leases for different apps/devices
- Each with own SessionKEK and quotas

---

## References

- WebCrypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- HKDF (RFC 5869): https://www.rfc-editor.org/rfc/rfc5869
- WebAuthn: https://www.w3.org/TR/webauthn-2/
- NIST SP 800-132 (Key Derivation): https://csrc.nist.gov/publications/detail/sp/800-132/final
- VAPID (RFC 8292): https://www.rfc-editor.org/rfc/rfc8292
