# KMS-Issued VAPID for User-Run Relays (MVP)

**Status**: Design Phase
**Version**: V2
**Date**: 2025-10-24
**Priority**: High (Primary KMS use case until Signal Protocol)

---

## Overview

Give the PWA a **long-lived lease** (hours) per user that authorizes minting **short-lived VAPID JWTs** (minutes) from the KMS.
Leases are **relay-agnostic** for seamless relay switching. VAPID JWTs are **audience-bound** and **endpoint-scoped**; relays never see private keys.

**This is the primary use case for the KMS** until Signal Protocol is implemented. It provides:
- Secure VAPID key management (private keys never leave KMS)
- Flexible relay switching (same lease works across relays)
- Quota enforcement and abuse prevention
- Full auditability (every JWT issuance logged)

---

## Entities

* **PWA (allthe.services)**: Brokers requests between relay and KMS over WSS/MessageChannel.
* **KMS (kms.ats.run iframe + worker)**: Holds VAPID private key; issues JWTs; enforces policy; audits.
* **Relay (user-run server)**: Connected to PWA via **WSS**; sends pushes to Web Push endpoints.
* **Push Service**: e.g., FCM (Google), Mozilla Push, Apple Push Notification Service.

---

## Core Model

### Lease (hours)

Permission the PWA holds to request VAPID JWTs for a user's **subscription endpoint(s)**.

**Properties:**
- **Relay-agnostic** for MVP (not bound to specific relay)
- Bound to `{userId, subs[], scope:"notifications:send"}`
- Includes quotas and expiration
- Can be extended, revoked, or allowed to expire

**Lifecycle:** 8-12 hours (≤24h cap)

### VAPID JWT (minutes)

ES256 token bound to `{aud, eid}` with short expiration and private claims for telemetry.

**Properties:**
- **Short-lived**: 10-15 minutes
- **Audience-bound**: Tied to origin of subscription endpoint (e.g., `https://fcm.googleapis.com`)
- **Endpoint-scoped**: Tied to specific push subscription
- **Quota-enforced**: KMS tracks usage per lease and endpoint
- **Audited**: Every issuance logged with tamper-evident chain

**Lifecycle:** Issued on-demand, renewed at ~60% TTL, pre-minted for stashing

---

## Security Properties (MVP)

✅ **VAPID private key stays in KMS**
- Wrapped under MKEK (see [02-master-secret.md](./02-master-secret.md))
- Non-extractable CryptoKey in Worker
- Never exposed to PWA or relays

✅ **JWTs are short-lived and audience-bound**
- 10-15 minute expiration (configurable)
- `aud` claim tied to push service origin
- Cannot be reused across different push services

✅ **Per-lease and per-endpoint quotas**
- Cap blast radius if relay compromised
- Prevent abuse (spam, DoS)
- Configurable limits

✅ **Full attribution and auditability**
- Private claims: `uid`, `eid`, `jti`, optional `rid`
- KMS audit log records every issuance
- Relay logs can correlate with KMS logs via `jti`

✅ **Relay-agnostic design**
- PWA can switch relays without new lease
- Same lease works across multiple relays
- Graceful failover (30-60s drain)

---

## SessionKEK Architecture

### Context

While per-operation authentication (see [03-unlock-context.md](./03-unlock-context.md)) provides strong security, **VAPID leases require operations without user interaction**:
- **Push notifications**: May need JWTs when user is not present
- **Background sync**: Operations triggered by Service Worker
- **High-frequency operations**: Signing many JWTs in short time (e.g., batch notifications)

The **SessionKEK (Session Key Encryption Key)** provides time-bounded authorization for these scenarios.

### Pattern Overview

```
┌──────────────────────────────────────────────────────────────┐
│ SessionKEK Pattern (Exception to Per-Operation Auth)         │
├──────────────────────────────────────────────────────────────┤
│ CREATE LEASE (user present, requires authentication):        │
│  1. User authenticates → get MS                              │
│  2. Generate random 32-byte Lease Salt (LS)                  │
│  3. Derive SessionKEK:                                       │
│     SessionKEK = HKDF(MS, LS, "ATS/KMS/SessionKEK/v1")       │
│  4. Unwrap VAPID key with MKEK                               │
│  5. Wrap VAPID key with SessionKEK → wrappedLeaseKey         │
│  6. Store lease: {leaseId, wrappedLeaseKey, LS, exp, ...}    │
│  7. Store SessionKEK in IndexedDB (CryptoKey persists)       │
│  8. Cache SessionKEK in memory Map                           │
│  9. Clear MS immediately                                     │
│                                                              │
│ ISSUE JWT (no user interaction, uses cached SessionKEK):     │
│  1. Retrieve SessionKEK from cache or IndexedDB              │
│  2. Check lease expiration                                   │
│  3. Enforce quotas (tokens/hour, sends/min, etc.)            │
│  4. Unwrap VAPID key using SessionKEK                        │
│  5. Sign JWT                                                 │
│  6. Clear unwrapped VAPID key                                │
│  7. SessionKEK remains cached for next JWT                   │
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
- **MKEK**: Derived from MS, used to wrap application keys in main storage
- **SessionKEK**: Lease-scoped, derived per-lease, wraps copies of VAPID key
- **VAPID key main copy**: Wrapped with MKEK (requires user auth to unwrap)
- **VAPID key lease copy**: Wrapped with SessionKEK (no auth needed for JWT signing)

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

### Trade-offs vs Per-Operation Auth

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
- High frequency operations (many JWTs in short time)
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

---

## Architecture Diagram

```
                (Relay-agnostic lease; PWA brokers everything)

┌─────────────────────┐         WSS (server ↔ client)          ┌───────────────────────────┐
│   Relay (user-run)  │  ───────────────────────────────────▶  │  PWA (allthe.services)    │
│                     │ ◀────────────────────────────────────  │  - Health scoring         │
│  - Sends pushes     │                                        │  - Token stashes          │
│  - Never sees keys  │                                        │  - Brokers KMS RPCs       │
└──────────▲──────────┘                                        └───────────▲───────────────┘
           │                                                               │ MessageChannel
           │                                                               │ (per session)
           │                                                               │
           │  need VAPID (endpoint E)                                      │
           │──────────────────────────────────────────────────────────────▶
           │                                                               │  vapid.issue({ leaseId, E })
           │                                                               │ ─────────────────────────────▶
           │                                                               │  { jwt, pk, jti, exp }
           │ ◀─────────────────────────────────────────────────────────────│ ◀─────────────────────────────
           │  { jwt, pk, jti, exp }                                        │
           │                                                               │
           │  POST push (JWT in Authorization header)                      │
           └───────────────────────────────────────────────────────────────┘
                                                                           │
                                                                           ↓
                          ┌────────────────────────────────────────────────────┐
                          │  KMS iframe (kms.ats.run)                          │
                          │                                                    │
                          │  ┌──────────────────────────────────────────────┐  │
                          │  │  Worker (crypto operations)                  │  │
                          │  │                                              │  │
                          │  │  - Holds VAPID private key (wrapped)         │  │
                          │  │  - Enforces quotas (per-lease, per-endpoint) │  │
                          │  │  - Issues JWTs (ES256)                       │  │
                          │  │  - Audits issuance (tamper-evident log)      │  │
                          │  │                                              │  │
                          │  │  IndexedDB:                                  │  │
                          │  │    - leases/{leaseId} → Lease                │  │
                          │  │    - audit/vapid-issuance → AuditEntry[]     │  │
                          │  │    - keys/vapid → WrappedKey                 │  │
                          │  │    - quotas/{leaseId} → QuotaState           │  │
                          │  └──────────────────────────────────────────────┘  │
                          └────────────────────────────────────────────────────┘
                                             │
                                             │ Web Push API
                                             ↓
                          ┌────────────────────────────────────────────────────┐
                          │  Push Services (FCM, Mozilla, APNS)                │
                          │                                                    │
                          │  - Verify VAPID signature                          │
                          │  - Check audience (`aud` = service origin)         │
                          │  - Deliver to subscription endpoint                │
                          └────────────────────────────────────────────────────┘
```

---

## Flows

### Flow 0: Session Start / Provisioning

**Initial setup** when user first connects relay or PWA loads.

```
1. PWA → KMS: leases.create({
     userId: "user-123",
     subs: [
       { url: "https://fcm.googleapis.com/fcm/send/abc123", aud: "https://fcm.googleapis.com", eid: "ep-1" },
       { url: "https://updates.push.services.mozilla.com/push/v1/xyz789", aud: "https://updates.push.services.mozilla.com", eid: "ep-2" }
     ],
     ttlHours: 12
   })

2. KMS:
   a. Verify user is authenticated (via withUnlock context)
   b. Create lease record in IndexedDB
   c. Initialize quota state
   d. Log lease creation

3. KMS → PWA: {
     leaseId: "lease-abc123def",
     exp: 1735123456000,  // 12 hours from now
     quotas: {
       tokensPerHour: 120,
       sendsPerMinute: 60,
       burstSends: 100,
       sendsPerMinutePerEid: 30
     }
   }

4. PWA:
   a. Store leaseId in memory (session state)
   b. Optionally share opaque connection id with active relay
```

### Flow 1: On-Demand Token Issuance

**Runtime flow** when relay needs a fresh JWT (every 10-15 minutes).

```
1. Relay → PWA (WSS): {
     type: "vapid-request",
     endpoint: "https://fcm.googleapis.com/fcm/send/abc123"
   }

2. PWA → KMS (MessageChannel): vapid.issue({
     leaseId: "lease-abc123def",
     endpoint: { url: "https://fcm.googleapis.com/fcm/send/abc123", aud: "https://fcm.googleapis.com", eid: "ep-1" }
   })

3. KMS validates:
   a. Lease exists and not expired
   b. Endpoint is in lease.subs[]
   c. Quotas not exceeded (tokensPerHour, sendsPerMinutePerEid)

4. KMS builds JWT (ES256 with required claims):
   a. Header: { alg: "ES256", typ: "JWT", kid: "vapid-key-1" }
   b. Payload Claims (required unless noted):
      - aud: "https://fcm.googleapis.com" (canonical origin of push endpoint)
      - sub: "mailto:ops@allthe.services" (admin contact, RFC 8292)
      - iat: <now-seconds> (issued at, REQUIRED)
      - nbf: <now-seconds> (not before, optional, defaults to iat)
      - exp: <now+600..900> (expires, ≤ 15 minutes from iat)
      - jti: "<uuid-v4>" (unique token id, REQUIRED for anti-replay)
      - eid: "<endpoint-fingerprint>" (private: stable per subscription)
      - rid: "<relay-id>" (private: optional, soft relay connection id)

   NOTE: Canonical `aud` is exact scheme+host of the push endpoint origin.
   Examples:
     - FCM: "https://fcm.googleapis.com"
     - Mozilla: "https://updates.push.services.mozilla.com"
     - Apple: "https://api.push.apple.com"

5. KMS signs JWT with VAPID private key (ES256)

6. KMS updates quota state (increment counters)

7. KMS logs issuance to audit trail

8. KMS → PWA: {
     jwt: "eyJhbGc...signature",
     vapidPublicKey: "BKxT...base64url" (uncompressed 65-byte P-256 public key),
     jti: "jti-uuid-123",
     exp: 1735049856000
   }

9. PWA → Relay (WSS): {
     type: "vapid-response",
     jwt: "eyJhbGc...signature",
     publicKey: "BKxT...base64url",
     jti: "jti-uuid-123",
     exp: 1735049856000
   }

10. Relay uses JWT to send push:
    POST https://fcm.googleapis.com/fcm/send/abc123
    Authorization: vapid t=eyJhbGc...signature, k=BKxT...base64url
    ...
```

### Flow 2: Continuous Operation (Hours)

**Token renewal and stashing** for uninterrupted service.

```
PWA maintains token stashes per lease:

Active relay (primary):
  - 6-8 overlapping tokens with staggered expiries
  - Renew at ~60% of JWT TTL (6-9 minutes for 10-15min tokens)
  - Example: tokens expiring at T+6min, T+7min, T+8min, ..., T+13min

Standby relay (backup):
  - 3 tokens with staggered expiries
  - Used for failover without gap

Renewal loop (in PWA):
  setInterval(() => {
    for (const relay of [active, standby]) {
      const stash = getStash(relay);
      const needed = getStashTarget(relay) - stash.length;

      if (needed > 0) {
        // Top up the stash
        for (let i = 0; i < needed; i++) {
          const token = await kms.vapid.issue({ leaseId, endpoint });
          stash.push(token);
        }
      }

      // Prune expired tokens
      stash = stash.filter(t => t.exp > Date.now() + 60_000); // Keep 1min buffer
    }
  }, 60_000); // Check every minute
```

### Flow 3: Dynamic Relay Switching

**Seamless failover** based on health scoring.

```
PWA tracks relay health:

healthScore = {
  latency: movingAverage(requestDuration, window=10),
  errors: errorRate(window=10),
  jitter: stddev(requestDuration, window=10),
  queueHints: relay.reportedQueueDepth
};

Switching decision:
  if (standby.healthScore > active.healthScore * 1.2 for 10 seconds) {
    // Promote standby to active

    1. Update routing: send new notifications to standby relay
    2. Hand standby the active relay's token stash
    3. Stop topping up old active's stash
    4. Grace period: 30-60s for old active to drain in-flight
    5. After grace: ignore/revoke old active's stash (optional)

    // No new lease needed - same leaseId works!
  }

Benefits:
  - Zero downtime (stash ensures tokens available)
  - No KMS interaction during switch (lease is relay-agnostic)
  - Graceful drain (old relay finishes in-flight pushes)
```

### Flow 4: Background Handling

**Pre-minting strategy** for offline/background operation.

```
Challenge: iOS/mobile browsers suspend PWA in background

Solution: Pre-mint token stash before going to background

PWA lifecycle hooks:

  document.addEventListener('visibilitychange', async () => {
    if (document.hidden) {
      // Going to background - top up stash
      await topUpStash(active, target=8);
      await topUpStash(standby, target=3);
    } else {
      // Coming to foreground - prune and refresh
      pruneExpiredTokens();
      await topUpStash(active, target=6);
      await topUpStash(standby, target=3);
    }
  });

Stash sizing:
  - Active: 6-8 tokens = 60-120 minutes of coverage (10-15min each)
  - Standby: 3 tokens = 30-45 minutes of coverage
  - Total: ~11 tokens × 10min = 110 minutes offline capability

Reality check:
  - If PWA suspended >1.5h, tokens expire
  - On resume: request fresh tokens
  - Relay queues notifications until tokens available
```

---

## Quotas & Policy (Enforced by KMS)

### Quota Types

**Per-lease quotas** (prevent single user abuse):
- `tokensPerHour`: Max JWT issuances per hour (default: 120)
- `sendsPerMinute`: Max pushes per minute across all endpoints (default: 60)
- `burstSends`: Max concurrent in-flight pushes (default: 100)

**Per-endpoint quotas** (prevent endpoint-specific spam):
- `sendsPerMinutePerEid`: Max pushes per minute per subscription (default: 30)

**Global caps (new):**
- **Per-user/day**: Total sends/day across all leases (soft cap with alert at 80%, hard throttle at 100%)
- **Per-relay/hour**: Total sends/hour across all leases using this relay (soft cap + alert)

**Typed errors**: Quota exceeded errors include specific scope and retry-after hints (see Error Model section below)

### Enforcement Algorithm

```typescript
interface QuotaState {
  leaseId: string;

  // Sliding window counters
  tokensIssuedLastHour: { timestamp: number; count: number }[];
  sendsLastMinute: { timestamp: number; count: number }[];
  sendsPerEndpoint: Map<string, { timestamp: number; count: number }[]>;

  // Burst tracking
  currentlyInflight: number;

  lastChecked: number;
}

async function enforceQuotas(
  leaseId: string,
  endpoint: Endpoint,
  quotas: Quotas
): Promise<{ allowed: boolean; reason?: string }> {
  const state = await getQuotaState(leaseId);
  const now = Date.now();

  // Prune old entries (outside window)
  state.tokensIssuedLastHour = state.tokensIssuedLastHour
    .filter(e => now - e.timestamp < 3600_000);
  state.sendsLastMinute = state.sendsLastMinute
    .filter(e => now - e.timestamp < 60_000);

  // Check per-lease limits
  const tokensLastHour = state.tokensIssuedLastHour.length;
  if (tokensLastHour >= quotas.tokensPerHour) {
    return { allowed: false, reason: 'tokensPerHour exceeded' };
  }

  const sendsLastMinute = state.sendsLastMinute.length;
  if (sendsLastMinute >= quotas.sendsPerMinute) {
    return { allowed: false, reason: 'sendsPerMinute exceeded' };
  }

  if (state.currentlyInflight >= quotas.burstSends) {
    return { allowed: false, reason: 'burstSends exceeded' };
  }

  // Check per-endpoint limits
  const endpointSends = state.sendsPerEndpoint.get(endpoint.eid) || [];
  const endpointSendsLastMinute = endpointSends
    .filter(e => now - e.timestamp < 60_000).length;

  if (endpointSendsLastMinute >= quotas.sendsPerMinutePerEid) {
    return { allowed: false, reason: 'sendsPerMinutePerEid exceeded' };
  }

  return { allowed: true };
}
```

### Dynamic Adjustments

**Suspicious usage detection:**
```typescript
// If quota violations detected, shorten JWT TTL
if (violations > 3 in last hour) {
  jwtTTL = Math.max(5 * 60 * 1000, jwtTTL / 2); // Half TTL, min 5 minutes
}

// If sustained violations, refuse issuance
if (violations > 10 in last hour) {
  return { error: 'QUOTA_SUSPENDED', message: 'Lease suspended due to abuse' };
}
```

### Revocation

```typescript
// Revoke specific lease
await kms.leases.revoke({ leaseId: 'lease-abc123' });

// Suspend patterns globally (admin action)
await kms.leases.suspendPattern({ userIdPattern: 'bot-*' });
```

---

## API (KMS RPCs via MessageChannel)

### Lease Management

#### `POST leases.create`

**Request:**
```typescript
{
  userId: string;
  subs: Endpoint[];
  ttlHours: number; // ≤24
  quotas?: Partial<Quotas>; // Optional overrides
}

interface Endpoint {
  url: string;              // Full push subscription URL
  aud: string;              // Origin of push service (for JWT aud claim)
  eid: string;              // Stable fingerprint (hash of url or user-provided)
}

interface Quotas {
  tokensPerHour: number;
  sendsPerMinute: number;
  burstSends: number;
  sendsPerMinutePerEid: number;
}
```

**Response:**
```typescript
{
  leaseId: string;
  exp: number;              // Unix timestamp (ms)
  quotas: Quotas;
}
```

**Errors:**
- `UNAUTHORIZED` - No valid authentication
- `INVALID_TTL` - ttlHours > 24
- `TOO_MANY_SUBS` - subs.length > limit

---

#### `POST leases.extend`

**Request:**
```typescript
{
  leaseId: string;
  addHours: number;         // Additional hours (total ≤24 from original creation)
}
```

**Response:**
```typescript
{
  exp: number;              // New expiration
}
```

**Errors:**
- `LEASE_NOT_FOUND`
- `LEASE_EXPIRED`
- `EXTENSION_EXCEEDS_LIMIT` - Would exceed 24h total

---

#### `POST leases.revoke`

**Request:**
```typescript
{
  leaseId: string;
}
```

**Response:**
```typescript
{
  status: 'revoked';
  effectiveAt: number;    // Unix timestamp (ms) when revocation took effect
}
```

**Errors:**
- `LEASE_NOT_FOUND`

### Revocation Semantics

**`leases.revoke(leaseId)` takes effect immediately:**

1. **KMS refusal**: KMS refuses new `vapid.issue*` calls for `leaseId`
   - All future issuance requests return `LEASE_REVOKED` error
   - Existing tokens in PWA stash remain valid until expiration

2. **Emergency mode (optional, configurable N=10 minutes)**:
   - KMS maintains a rolling blacklist of `jti` values it issued for this lease in the last N minutes
   - Issuance checks fail for those `jti`s if somehow requested
   - Verification endpoints can reject them if surfaced (optional external validation)

3. **Response is typed**:
   ```typescript
   {
     status: 'revoked',
     effectiveAt: 1704067200000  // Unix ms when revocation applied
   }
   ```

**Implementation:**

```typescript
/**
 * Revoke lease immediately.
 *
 * SEMANTICS:
 * - Mark lease as revoked (revokedAt timestamp)
 * - Refuse new issuance for this leaseId
 * - Optionally maintain jti blacklist for emergency mode
 *
 * @param leaseId Lease to revoke
 * @returns { status: 'revoked', effectiveAt }
 */
export async function revokeLease(leaseId: string): Promise<{
  status: 'revoked';
  effectiveAt: number;
}> {
  const now = Date.now();

  // Load lease
  const lease = await storage.get(`lease:${leaseId}`);
  if (!lease) {
    throw new Error('LEASE_NOT_FOUND');
  }

  // Mark as revoked
  lease.revokedAt = now;
  await storage.put(`lease:${leaseId}`, lease);

  // (Optional) Add to revoked leases list for jti blacklist
  const revokedLeases = await storage.get('revoked-leases') || [];
  revokedLeases.push({
    leaseId,
    revokedAt: now,
    expiresAt: now + 600_000  // 10 minutes emergency window
  });
  await storage.put('revoked-leases', revokedLeases);

  // Audit revocation
  await audit.log({
    op: 'lease:revoke',
    leaseId,
    userId: lease.userId,
    revokedAt: now,
    reason: 'user-requested'  // or 'abuse-detected', 'security-incident', etc.
  });

  return {
    status: 'revoked',
    effectiveAt: now
  };
}
```

**Revocation checking in issuance:**

```typescript
/**
 * Check lease is not revoked before issuing.
 */
async function checkLeaseNotRevoked(leaseId: string): Promise<void> {
  const lease = await storage.get(`lease:${leaseId}`);

  if (!lease) {
    throw buildError('LEASE_NOT_FOUND', `Lease ${leaseId} not found`);
  }

  if (lease.revokedAt) {
    throw buildError(
      'LEASE_REVOKED',
      `Lease revoked at ${new Date(lease.revokedAt).toISOString()}`,
      { revokedAt: lease.revokedAt }
    );
  }
}
```

---

### VAPID JWT Issuance

#### `POST vapid.issue`

**Request:**
```typescript
{
  leaseId: string;
  endpoint: Endpoint;
}
```

**Response:**
```typescript
{
  jwt: string;              // ES256 JWT (header.payload.signature)
  vapidPublicKey: string;   // Base64url uncompressed P-256 public key (65 bytes)
  jti: string;              // Unique token id (for tracking)
  exp: number;              // Unix timestamp (ms)
}
```

**Errors:**
- `LEASE_NOT_FOUND`
- `LEASE_EXPIRED`
- `ENDPOINT_NOT_IN_LEASE` - endpoint.eid not in lease.subs[]
- `QUOTA_EXCEEDED` - One or more quotas exceeded
- `QUOTA_SUSPENDED` - Lease suspended due to abuse

---

#### `POST vapid.issueBatch` (Optional - Efficiency)

**Request:**
```typescript
{
  leaseId: string;
  endpoint: Endpoint;
  count: number;            // Number of tokens to mint (≤10)
}
```

**Response:**
```typescript
{
  tokens: Array<{
    jwt: string;
    jti: string;
    exp: number;
  }>;
  vapidPublicKey: string;   // Same for all tokens (same key)
}
```

**Use case:** Pre-mint stash in single RPC instead of N individual calls.

**Quota enforcement:** Batch counts as `count` issuances against `tokensPerHour`.

---

### Anti-Replay and Uniqueness

**KMS MUST record every `jti` it issues for the token TTL window and MUST NOT re-issue a token with the same `jti` within that window (best-effort protection against broker replay).**

```typescript
/**
 * Issuance rule: Check jti not already issued.
 *
 * ANTI-REPLAY PROTECTION:
 * - Before issuing JWT, check if jti already used in last TTL window
 * - If jti exists in recent audit entries → reject with error
 * - This prevents accidental re-issuance and broker replay attacks
 *
 * @param jti Token ID to check
 * @param ttlSeconds Token TTL in seconds (typically 600-900)
 * @returns true if jti is safe to use
 */
async function checkJTIUnique(jti: string, ttlSeconds: number): Promise<boolean> {
  const windowStart = Date.now() - (ttlSeconds * 1000);

  // Query audit log for recent jti usage
  const recentIssuances = await audit.getByOp('vapid:issue', windowStart);

  for (const entry of recentIssuances) {
    if (entry.jti === jti) {
      // This jti was issued recently - reject
      console.error('JTI already issued:', jti, 'at', entry.timestamp);
      return false;
    }
  }

  return true;
}

/**
 * Updated issuance flow with jti uniqueness check.
 */
async function issueVAPIDWithAntiReplay(
  leaseId: string,
  endpoint: Endpoint
): Promise<VAPIDToken> {
  // Generate jti
  const jti = crypto.randomUUID();
  const ttlSeconds = 15 * 60; // 15 minutes

  // Check jti not already issued (anti-replay)
  const jtiUnique = await checkJTIUnique(jti, ttlSeconds);
  if (!jtiUnique) {
    throw buildError(
      'JTI_COLLISION',
      'Token ID already issued (anti-replay protection)',
      { jti, retryAfterMs: 1000 }
    );
  }

  // Continue with normal issuance...
  // (sign JWT, store audit entry with jti, return token)
}
```

**Audit entries include `jti` for tracking:**

As documented in [05-audit-log.md](./05-audit-log.md#vapid-issuance-with-jti-field), all VAPID issuance audit entries MUST include the `jti` field for correlation and anti-replay verification.

---

### Typed Error Model

**All lease and VAPID endpoints return typed errors with specific codes:**

```typescript
/**
 * Error codes for lease and VAPID operations.
 */
type LeaseErrorCode =
  | 'quota.exceeded.lease'       // Per-lease quota exceeded
  | 'quota.exceeded.endpoint'    // Per-endpoint quota exceeded
  | 'quota.exceeded.user'        // Global per-user quota exceeded
  | 'quota.exceeded.relay'       // Global per-relay quota exceeded
  | 'lease.expired'              // Lease TTL expired
  | 'lease.not.found'            // Lease doesn't exist
  | 'lease.revoked'              // Lease was revoked
  | 'endpoint.not.in.lease'      // Endpoint not in lease.subs[]
  | 'aud.mismatch'               // Audience doesn't match endpoint
  | 'eid.unknown'                // Endpoint ID not recognized
  | 'attestation.failed'         // Boot verification failed
  | 'unlock.denied'              // Authentication failed
  | 'jti.collision'              // JTI already issued (anti-replay)
  | 'internal'                   // Unexpected error
  ;

/**
 * Typed error response.
 */
interface ErrorResponse {
  error: {
    code: LeaseErrorCode;
    message: string;               // Human-readable description
    retryAfterMs: number | null;   // Hint for retry (null = don't retry)
    details: Record<string, unknown>; // Non-sensitive context
  };
}

/**
 * Build typed error for lease operations.
 */
function buildError(
  code: LeaseErrorCode,
  message: string,
  details?: Record<string, unknown>,
  retryAfterMs?: number
): ErrorResponse {
  return {
    error: {
      code,
      message,
      retryAfterMs: retryAfterMs || null,
      details: details || {}
    }
  };
}
```

**Example error responses:**

```typescript
// Quota exceeded (with retry hint)
{
  error: {
    code: 'quota.exceeded.lease',
    message: 'Lease tokensPerHour quota exceeded (120/hour)',
    retryAfterMs: 600_000,  // Retry in 10 minutes
    details: {
      leaseId: 'lease-abc123',
      tokensLastHour: 120,
      limit: 120
    }
  }
}

// Lease revoked (no retry)
{
  error: {
    code: 'lease.revoked',
    message: 'Lease was revoked at 2025-10-24T12:00:00Z',
    retryAfterMs: null,  // Don't retry
    details: {
      leaseId: 'lease-abc123',
      revokedAt: 1704067200000,
      reason: 'user-requested'
    }
  }
}

// Endpoint not in lease
{
  error: {
    code: 'endpoint.not.in.lease',
    message: 'Endpoint ep-5 not authorized for this lease',
    retryAfterMs: null,
    details: {
      leaseId: 'lease-abc123',
      requestedEid: 'ep-5',
      authorizedEids: ['ep-1', 'ep-2', 'ep-3']
    }
  }
}
```

**Error handling in issuance:**

```typescript
/**
 * Enforce quotas with typed errors.
 */
async function enforceQuotasTyped(
  leaseId: string,
  endpoint: Endpoint,
  quotas: Quotas
): Promise<{ allowed: true } | ErrorResponse> {
  const state = await getQuotaState(leaseId);
  const now = Date.now();

  // Check per-lease tokens/hour
  const tokensLastHour = state.tokensIssuedLastHour
    .filter(e => now - e.timestamp < 3600_000).length;

  if (tokensLastHour >= quotas.tokensPerHour) {
    const oldestToken = Math.min(...state.tokensIssuedLastHour.map(e => e.timestamp));
    const retryAfterMs = 3600_000 - (now - oldestToken);

    return buildError(
      'quota.exceeded.lease',
      `Lease tokensPerHour quota exceeded (${tokensLastHour}/${quotas.tokensPerHour})`,
      { leaseId, tokensLastHour, limit: quotas.tokensPerHour },
      retryAfterMs
    );
  }

  // Check per-endpoint sends/minute
  const endpointSends = state.sendsPerEndpoint.get(endpoint.eid) || [];
  const endpointSendsLastMinute = endpointSends
    .filter(e => now - e.timestamp < 60_000).length;

  if (endpointSendsLastMinute >= quotas.sendsPerMinutePerEid) {
    return buildError(
      'quota.exceeded.endpoint',
      `Endpoint sendsPerMinute quota exceeded (${endpointSendsLastMinute}/${quotas.sendsPerMinutePerEid})`,
      { eid: endpoint.eid, sendsLastMinute: endpointSendsLastMinute, limit: quotas.sendsPerMinutePerEid },
      60_000  // Retry after 1 minute
    );
  }

  return { allowed: true };
}
```

**Ensure `withUnlock` attaches a stable `requestId`:**

As documented in [03-unlock-context.md](./03-unlock-context.md#error-propagation-to-pwa), all unlock operations should attach a `requestId` for audit correlation and error tracking.

---

### Background Constraints (iOS/Android)

**Mobile platforms (iOS, Android) may suspend JS execution; KMS cannot mint while suspended.**

**Environmental Constraints:**

- **iOS**: Background execution extremely limited (5-30 seconds)
- **Android**: More lenient but Doze mode suspends after inactivity
- **Impact**: PWA must maintain foreground stash for ~1 hour operation

**PWA Stashing Strategy:**

```typescript
/**
 * Background token stashing for mobile platforms.
 *
 * PWA SHOULD maintain:
 * - Active relay: 6-8 overlapping tokens (60-120 min coverage)
 * - Standby relay: 2-3 tokens (20-45 min coverage)
 *
 * Lifecycle hooks:
 * - visibilitychange: Top up before backgrounding, refresh on foreground
 */
document.addEventListener('visibilitychange', async () => {
  if (document.hidden) {
    // Going to background - top up stash
    console.log('Backgrounding: pre-minting token stash');
    await topUpStash(activeRelay, target = 8);
    await topUpStash(standbyRelay, target = 3);
  } else {
    // Returning to foreground - prune and refresh
    console.log('Foregrounded: refreshing tokens');
    pruneExpiredTokens();
    await topUpStash(activeRelay, target = 6);
    await topUpStash(standbyRelay, target = 3);
  }
});
```

**Stash Sizing:**
- **Active relay**: 6-8 tokens (10-15min each) = 60-120 minutes offline capability
- **Standby relay**: 2-3 tokens = 20-45 minutes coverage
- **Total**: ~11 tokens = ~110 minutes worst-case coverage

**On Resume:**
- If PWA suspended >1.5 hours, all tokens expire
- PWA MUST top up stashes and prune expired tokens
- Brief notification delay acceptable (user was away)

---

### Interoperability Tests (Web Push)

**CI tests MUST validate JWT format and claims for major push services:**

```typescript
describe('VAPID JWT Interoperability', () => {
  it('should generate valid JWT for FCM', async () => {
    const endpoint = {
      url: 'https://fcm.googleapis.com/fcm/send/abc123',
      aud: 'https://fcm.googleapis.com',
      eid: 'ep-1'
    };

    const jwt = await kms.vapid.issue({ leaseId, endpoint });

    // Decode JWT
    const [headerB64, payloadB64, signatureB64] = jwt.split('.');
    const header = JSON.parse(atob(headerB64));
    const payload = JSON.parse(atob(payloadB64));

    // Validate header
    expect(header.alg).toBe('ES256');
    expect(header.kid).toBeDefined();

    // Validate payload claims
    expect(payload.aud).toBe('https://fcm.googleapis.com');
    expect(payload.sub).toMatch(/^mailto:/);
    expect(payload.iat).toBeDefined();
    expect(payload.nbf).toBeDefined();
    expect(payload.exp).toBeDefined();
    expect(payload.jti).toBeDefined();

    // Validate timing (exp ≤ 15 minutes)
    const ttl = payload.exp - payload.iat;
    expect(ttl).toBeLessThanOrEqual(900);  // ≤ 15 minutes

    // Validate signature format (P-1363, 64 bytes)
    const signatureBytes = base64urlDecode(signatureB64);
    expect(signatureBytes.length).toBe(64);  // ES256 P-1363 format
  });

  it('should generate valid JWT for Mozilla Push', async () => {
    const endpoint = {
      url: 'https://updates.push.services.mozilla.com/push/v1/xyz789',
      aud: 'https://updates.push.services.mozilla.com',
      eid: 'ep-2'
    };

    const jwt = await kms.vapid.issue({ leaseId, endpoint });

    const [, payloadB64] = jwt.split('.');
    const payload = JSON.parse(atob(payloadB64));

    // Validate aud derivation
    expect(payload.aud).toBe('https://updates.push.services.mozilla.com');
  });

  it('should validate JWT sizes within limits', async () => {
    const jwt = await kms.vapid.issue({ leaseId, endpoint });

    // JWT should be reasonable size (<500 bytes typical)
    expect(jwt.length).toBeLessThan(1000);

    // Header + payload should be valid base64url
    const [headerB64, payloadB64] = jwt.split('.');
    expect(() => atob(headerB64)).not.toThrow();
    expect(() => atob(payloadB64)).not.toThrow();
  });

  // Optional: End-to-end push test (requires secrets)
  it.skip('should send push via FCM (E2E)', async () => {
    // Requires:
    // - Valid subscription (from PushManager.subscribe())
    // - FCM credentials in CI secrets
    // - Test endpoint

    const jwt = await kms.vapid.issue({ leaseId, endpoint });
    const publicKey = await kms.vapid.exportPublicKey();

    const response = await fetch(endpoint.url, {
      method: 'POST',
      headers: {
        'Authorization': `vapid t=${jwt}, k=${publicKey}`,
        'Content-Type': 'application/octet-stream',
        'TTL': '60'
      },
      body: encryptedPayload
    });

    expect(response.status).toBe(201);  // Created
  });
});
```

**Test Coverage:**
- ✅ Header + payload sizes within limits
- ✅ ES256 signature in P-1363 format (64 bytes)
- ✅ `aud` derivation from example endpoints (FCM, Mozilla, Apple)
- ✅ `iat`/`nbf`/`exp` timing windows (exp ≤ 900s)
- ✅ JWT structure (3 base64url parts, valid JSON)
- ⏸️ (Optional) End-to-end push to test subscriptions in staging (secret-gated CI flag)

---

## Data Stored in KMS

### Lease Records

**Table:** `leases/{leaseId}`

```typescript
interface Lease {
  leaseId: string;          // UUID
  userId: string;           // User identifier
  subs: Endpoint[];         // Subscription endpoints
  scope: 'notifications:send';
  exp: number;              // Expiration timestamp (ms)
  quotas: Quotas;

  // SessionKEK fields (enables JWT signing without user auth)
  wrappedLeaseKey: ArrayBuffer;   // VAPID private key wrapped with SessionKEK
  wrappedLeaseKeyIV: ArrayBuffer; // IV for AES-GCM encryption
  leaseSalt: ArrayBuffer;         // Salt used to derive SessionKEK
  kid: string;                    // VAPID key ID (JWK thumbprint)

  createdAt: number;
  updatedAt: number;
  revokedAt?: number;       // If revoked
}
```

**Note**: The SessionKEK itself is stored separately in the meta store at `sessionkek:{leaseId}` as a non-extractable CryptoKey.

### Quota State

**Table:** `quotas/{leaseId}`

```typescript
interface QuotaState {
  leaseId: string;
  tokensIssuedLastHour: { timestamp: number; count: number }[];
  sendsLastMinute: { timestamp: number; count: number }[];
  sendsPerEndpoint: Map<string, { timestamp: number; count: number }[]>;
  currentlyInflight: number;
  violations: number;       // Cumulative quota violations
  lastChecked: number;
}
```

### VAPID Key

**Table:** `keys/vapid`

```typescript
interface WrappedVAPIDKey {
  kid: string;              // Key identifier (JWK thumbprint)
  kmsVersion: 2;
  wrappedKey: ArrayBuffer;  // Private key wrapped under MKEK
  iv: ArrayBuffer;
  aad: ArrayBuffer;         // {kid, alg: 'ES256', purpose: 'vapid', ...}
  publicKeyRaw: ArrayBuffer;// Uncompressed P-256 public key (65 bytes)
  alg: 'ES256';
  purpose: 'vapid';
  createdAt: number;
  lastUsedAt?: number;
}
```

**Note**: This is the main VAPID key storage. Requires user authentication (MKEK) to unwrap.

### SessionKEK Storage

**Table:** `sessionkek:{leaseId}`

```typescript
// Stored as CryptoKey object in IndexedDB meta store
CryptoKey {
  type: "secret",
  algorithm: { name: "AES-GCM", length: 256 },
  extractable: false,
  usages: ["encrypt", "decrypt"]
}
```

**Properties**:
- Non-extractable (cannot be exported)
- Persists across worker restarts
- Cached in memory for performance
- Automatically useless after lease expires
- Deleted during periodic cleanup

**Security**: Even if attacker gains access to IndexedDB, they can only:
- Use SessionKEK to issue JWTs until lease expires (time-bounded)
- Limited by quota enforcement (rate-bounded)
- Cannot derive MS or MKEK from SessionKEK (one-way HKDF)
- Cannot use SessionKEK for other leases (unique salt per lease)

### Audit Log (Tamper-Evident)

**Table:** `audit/vapid-issuance`

```typescript
interface VAPIDIssuanceAuditEntry {
  kmsVersion: 2;
  seqNum: number;           // Monotonic sequence
  timestamp: number;

  // Operation
  op: 'vapid.issue';
  leaseId: string;
  userId: string;
  endpoint: Endpoint;

  // Token details
  jti: string;              // Unique token id
  aud: string;              // Audience (push service origin)
  exp: number;              // Token expiration
  kid: string;              // VAPID key used
  rid?: string;             // Optional relay id (soft binding)

  // Quota state snapshot
  quotasSnapshot: {
    tokensLastHour: number;
    sendsLastMinute: number;
    sendsPerEndpointLastMinute: number;
  };

  // Chain integrity
  previousHash: string;     // SHA-256 of previous entry
  chainHash: string;        // SHA-256 of this entry

  // Signature
  signature: string;        // Ed25519 signature of chainHash
  auditKeyId: string;       // Reference to audit key
}
```

**Properties:**
- **Tamper-evident**: Any modification breaks `chainHash` verification
- **Sequential**: `seqNum` detects truncation
- **Signed**: Ed25519 signature proves authenticity
- **Correlatable**: `jti` links to relay logs

---

## Recommended Defaults

### Timing

- **Lease TTL**: 8–12 hours (≤24h cap)
- **JWT TTL**: 10–15 minutes
- **Renewal trigger**: 60% of JWT TTL (6-9 minutes)
- **Stash sizes**: Active relay 6-8 tokens, standby relay 3 tokens

### Quotas

**Conservative defaults** (can be tuned per deployment):

```typescript
const DEFAULT_QUOTAS: Quotas = {
  tokensPerHour: 120,           // ~2 per minute average
  sendsPerMinute: 60,           // 1 per second average
  burstSends: 100,              // Allow short bursts
  sendsPerMinutePerEid: 30,     // 1 per 2 seconds per endpoint
};
```

**Aggressive defaults** (for high-volume deployments):

```typescript
const AGGRESSIVE_QUOTAS: Quotas = {
  tokensPerHour: 240,           // ~4 per minute
  sendsPerMinute: 120,          // 2 per second
  burstSends: 200,
  sendsPerMinutePerEid: 60,
};
```

### Relay Switching

- **Health score differential**: 20% better for 10 seconds
- **Grace period**: 30-60 seconds for old relay drain
- **Health check interval**: Every 5 seconds
- **Metrics window**: Last 10 requests (moving average)

---

## Implementation

### Worker RPC Handler

**File:** `src/worker.ts`

```typescript
import { handleVAPIDIssue, handleVAPIDBatchIssue } from './vapid.js';
import { handleLeaseCreate, handleLeaseExtend, handleLeaseRevoke } from './leases.js';

async function handleMessage(request: RPCRequest): Promise<RPCResponse> {
  // Boot verification check
  if (bootStatus.decision === 'FAIL_SECURE') {
    return {
      requestId: request.id,
      error: 'KMS_LOCKED',
      details: { reason: 'Integrity verification failed' }
    };
  }

  // Route to handlers
  switch (request.method) {
    case 'leases.create':
      return await handleLeaseCreate(request);

    case 'leases.extend':
      return await handleLeaseExtend(request);

    case 'leases.revoke':
      return await handleLeaseRevoke(request);

    case 'vapid.issue':
      return await handleVAPIDIssue(request);

    case 'vapid.issueBatch':
      return await handleVAPIDBatchIssue(request);

    default:
      return {
        requestId: request.id,
        error: 'UNKNOWN_METHOD',
        details: { method: request.method }
      };
  }
}
```

### Lease Creation Handler (with SessionKEK generation)

**File:** `src/leases.ts`

```typescript
import { withUnlock } from './unlock.js';
import { unwrapKey, putMeta, getMeta } from './storage.js';
import { deriveSessionKEK } from './crypto-utils.js';

// Memory cache for SessionKEKs (performance optimization)
const sessionKEKCache = new Map<string, CryptoKey>();

/**
 * Create a new VAPID lease with SessionKEK for background JWT issuance.
 *
 * REQUIRES USER AUTHENTICATION (withUnlock context).
 */
export async function handleLeaseCreate(params: {
  userId: string;
  subs: Endpoint[];
  ttlHours: number;
  credentials: AuthCredentials;
}): Promise<{ leaseId: string; exp: number; quotas: Quotas }> {

  // Validate TTL
  if (params.ttlHours > 24) {
    throw new Error('TTL exceeds maximum of 24 hours');
  }

  const leaseId = `lease-${crypto.randomUUID()}`;
  const vapidKid = 'vapid'; // Key ID for main VAPID key

  // 1. Authenticate and derive SessionKEK from MS
  const result = await withUnlock(params.credentials, async (mkek, ms) => {
    // 2. Generate unique lease salt (32 bytes)
    const leaseSalt = crypto.getRandomValues(new Uint8Array(32));

    // 3. Derive SessionKEK from MS using lease-specific salt
    const sessionKEK = await deriveSessionKEK(ms, leaseSalt);
    //   SessionKEK = HKDF-SHA256(
    //     ikm = MS (32 bytes),
    //     salt = leaseSalt (32 bytes),
    //     info = "ATS/KMS/SessionKEK/v1",
    //     length = 256 bits
    //   )

    // 4. Unwrap VAPID private key with MKEK (from main storage)
    const vapidPrivateKey = await unwrapKey(
      vapidKid,
      mkek,
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign']
    );

    // 5. Export VAPID key (for wrapping with SessionKEK)
    const exportedKey = await crypto.subtle.exportKey('pkcs8', vapidPrivateKey);

    // 6. Wrap VAPID key with SessionKEK (lease-specific copy)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrappedLeaseKey = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      sessionKEK,
      exportedKey
    );

    return { sessionKEK, wrappedLeaseKey, iv, leaseSalt };
  });

  // 7. Store SessionKEK in IndexedDB (persists across worker restarts)
  await putMeta(`sessionkek:${leaseId}`, result.sessionKEK);

  // 8. Cache SessionKEK in memory for performance
  sessionKEKCache.set(leaseId, result.sessionKEK);

  // 9. Create and store lease record
  const exp = Date.now() + params.ttlHours * 3600 * 1000;
  const quotas = {
    tokensPerHour: 120,
    sendsPerMinute: 60,
    burstSends: 100,
    sendsPerMinutePerEid: 30,
  };

  const lease: Lease = {
    leaseId,
    userId: params.userId,
    subs: params.subs,
    scope: 'notifications:send',
    exp,
    quotas,
    wrappedLeaseKey: result.wrappedLeaseKey,
    wrappedLeaseKeyIV: result.iv,
    leaseSalt: result.leaseSalt,
    kid: vapidKid,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  await putMeta(`lease:${leaseId}`, lease);

  // 10. Initialize quota state
  await putMeta(`quotas:${leaseId}`, {
    leaseId,
    tokensIssuedLastHour: [],
    sendsLastMinute: [],
    sendsPerEndpoint: new Map(),
    currentlyInflight: 0,
    violations: 0,
    lastChecked: Date.now(),
  });

  // 11. Log lease creation
  await logAudit({
    op: 'lease.create',
    leaseId,
    userId: params.userId,
    ttlHours: params.ttlHours,
    exp,
  });

  return { leaseId, exp, quotas };
}
```

### VAPID Issue Handler (uses SessionKEK, NO user auth)

**File:** `src/vapid.ts`

```typescript
import { enforceQuotas } from './quotas.js';
import { logAudit } from './audit.js';
import { getLease } from './leases.js';
import { getWrappedKey, getMeta } from './storage.js';
import { buildVAPIDJWT } from './crypto-utils.js';

// SessionKEK cache (imported from leases.ts or shared)
declare const sessionKEKCache: Map<string, CryptoKey>;

export async function handleVAPIDIssue(request: RPCRequest): Promise<RPCResponse> {
  const { leaseId, endpoint } = request.params;

  // 1. Get lease
  const lease = await getLease(leaseId);
  if (!lease) {
    return { requestId: request.id, error: 'LEASE_NOT_FOUND' };
  }

  if (lease.exp < Date.now()) {
    return { requestId: request.id, error: 'LEASE_EXPIRED' };
  }

  if (lease.revokedAt) {
    return { requestId: request.id, error: 'LEASE_REVOKED' };
  }

  // 2. Verify endpoint in lease
  const endpointInLease = lease.subs.find(s => s.eid === endpoint.eid);
  if (!endpointInLease) {
    return { requestId: request.id, error: 'ENDPOINT_NOT_IN_LEASE' };
  }

  // 3. Enforce quotas
  const quotaCheck = await enforceQuotas(leaseId, endpoint, lease.quotas);
  if (!quotaCheck.allowed) {
    return {
      requestId: request.id,
      error: 'QUOTA_EXCEEDED',
      details: { reason: quotaCheck.reason }
    };
  }

  // 4. Get SessionKEK (from cache or IndexedDB) - NO user auth needed!
  let sessionKEK = sessionKEKCache.get(leaseId);
  if (!sessionKEK) {
    sessionKEK = await getMeta<CryptoKey>(`sessionkek:${leaseId}`);
    if (!sessionKEK) {
      return { requestId: request.id, error: 'SESSIONKEK_NOT_FOUND' };
    }
    sessionKEKCache.set(leaseId, sessionKEK);
  }

  // 5. Unwrap VAPID key using SessionKEK (no user auth!)
  const iv = new Uint8Array(lease.wrappedLeaseKeyIV);
  const decryptedKeyData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    sessionKEK,
    lease.wrappedLeaseKey
  );

  // 6. Import as ECDSA private key
  const vapidPrivateKey = await crypto.subtle.importKey(
    'pkcs8',
    decryptedKeyData,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // not extractable
    ['sign']
  );

  // 7. Build JWT claims (ES256, RFC 8292 VAPID)
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (15 * 60); // 15 minutes (≤ 900s per spec)
  const jti = crypto.randomUUID();

  const claims = {
    aud: endpoint.aud,                      // Push service origin (canonical)
    sub: 'mailto:ops@allthe.services',      // Admin contact (RFC 8292)
    iat: now,                               // Issued at (REQUIRED)
    nbf: now,                               // Not before (optional, defaults to iat)
    exp,                                    // Expires (REQUIRED, ≤ 15 min)
    jti,                                    // Token ID (REQUIRED for anti-replay)
    // Private claims (for attribution/telemetry)
    eid: endpoint.eid,                      // Endpoint fingerprint
    rid: request.params.relayId || undefined, // Relay connection id (optional)
  };

  // 8. Sign JWT
  const jwt = await buildVAPIDJWT(claims, vapidPrivateKey, lease.kid);

  // 9. Get public key for response
  const wrappedMeta = await getWrappedKey('vapid');
  const vapidPublicKey = arrayBufferToBase64url(wrappedMeta.publicKeyRaw);

  // 10. Update quota state
  await updateQuotaState(leaseId, endpoint);

  // 11. Log to audit
  await logAudit({
    op: 'vapid.issue',
    leaseId,
    userId: lease.userId,
    endpoint,
    jti,
    aud: endpoint.aud,
    exp: exp * 1000,
    kid: lease.kid,
    rid: request.params.relayId,
    quotasSnapshot: await getQuotasSnapshot(leaseId, endpoint),
  });

  // 12. Return JWT (private key garbage collected, SessionKEK remains cached)
  return {
    requestId: request.id,
    data: {
      jwt,
      vapidPublicKey,
      jti,
      exp: exp * 1000,
    },
  };
}
```

### Crypto Utilities

**File:** `src/crypto-utils.ts`

```typescript
import { derToP1363 } from './signature-conversion.js';

/**
 * Derive SessionKEK from Master Secret for a specific lease.
 *
 * SessionKEK = HKDF-SHA256(MS, leaseSalt, "ATS/KMS/SessionKEK/v1")
 *
 * @param ms Master Secret (32 bytes)
 * @param leaseSalt Unique salt for this lease (32 bytes)
 * @returns SessionKEK as non-extractable CryptoKey
 */
export async function deriveSessionKEK(
  ms: Uint8Array,
  leaseSalt: Uint8Array
): Promise<CryptoKey> {
  // Import MS as HKDF key material
  const msKey = await crypto.subtle.importKey(
    'raw',
    ms,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  // Derive SessionKEK using HKDF
  const sessionKEK = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: leaseSalt,
      info: new TextEncoder().encode('ATS/KMS/SessionKEK/v1'),
    },
    msKey,
    { name: 'AES-GCM', length: 256 },
    false, // not extractable
    ['encrypt', 'decrypt']
  );

  return sessionKEK;
}

/**
 * Builds and signs a VAPID JWT (ES256).
 */
export async function buildVAPIDJWT(
  claims: object,
  privateKey: CryptoKey,
  kid: string
): Promise<string> {
  // Header
  const header = {
    alg: 'ES256',
    typ: 'JWT',
    kid,
  };

  // Base64url encode header and claims
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedClaims = base64urlEncode(JSON.stringify(claims));

  // Signing input
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);

  // Sign with ECDSA P-256
  const signatureDER = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    signingInputBytes
  );

  // Validate P-1363 format (modern browsers return this natively)
  const signatureP1363 = derToP1363(new Uint8Array(signatureDER));

  // Base64url encode signature
  const encodedSignature = base64urlEncode(signatureP1363);

  // Build final JWT
  return `${signingInput}.${encodedSignature}`;
}

function base64urlEncode(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
```

### Batch Issuance (Optional)

**File:** `src/vapid.ts`

```typescript
export async function handleVAPIDBatchIssue(request: RPCRequest): Promise<RPCResponse> {
  const { leaseId, endpoint, count } = request.params;

  if (count > 10) {
    return { requestId: request.id, error: 'BATCH_TOO_LARGE', details: { max: 10 } };
  }

  const tokens = [];

  for (let i = 0; i < count; i++) {
    const result = await handleVAPIDIssue({
      ...request,
      id: `${request.id}-${i}`,
    });

    if (result.error) {
      return { requestId: request.id, error: result.error };
    }

    tokens.push({
      jwt: result.data.jwt,
      jti: result.data.jti,
      exp: result.data.exp,
    });
  }

  // Public key is same for all tokens
  const wrappedMeta = await getWrappedKey('vapid');
  const vapidPublicKey = arrayBufferToBase64url(wrappedMeta.publicKeyRaw);

  return {
    requestId: request.id,
    data: {
      tokens,
      vapidPublicKey,
    },
  };
}
```

---

## Security Considerations

### Attribution & Privacy

**Attribution (relay logs):**
- Include `uid`, `eid`, `jti` as private JWT claims
- Relay logs record `jti` for each push sent
- KMS audit log records `jti` for each issuance
- Cross-reference to correlate relay activity with KMS authorizations

**Privacy (payloads):**
- Web Push payloads are encrypted upstream (before reaching relay)
- Relays see only encrypted blobs (cannot read content)
- JWT private claims (`uid`, `eid`) visible to push service but not relay
- Push service can correlate but cannot decrypt payloads

### Abuse Prevention

**Quota enforcement:**
- Strict limits prevent spam/DoS
- Per-endpoint limits prevent single-target harassment
- Dynamic TTL reduction for suspicious patterns
- Lease suspension for sustained violations

**Relay binding (future):**
- Current design: soft `rid` (optional relay id in JWT)
- Future: hard binding (lease tied to specific relay public key)
- Allows per-relay quotas and revocation

### Future: Registered Relays

**Current (MVP):** Relay-agnostic leases (any relay can use)

**Future enhancement:** Registered relay model

```typescript
interface RegisteredRelay {
  relayId: string;
  publicKey: ArrayBuffer;   // Ed25519 or ECDSA public key
  owner: string;            // User who registered
  reputation: number;       // Trust score
  quotas: Quotas;           // Per-relay quotas
}

// Lease bound to specific relay
interface BoundLease extends Lease {
  relayId: string;          // Only this relay can use lease
  relaySignature: string;   // Relay signs lease request
}
```

**Benefits:**
- Per-relay reputation and quotas
- Relay revocation (ban misbehaving relays)
- Relay attestation (proof of relay identity)

**Trade-offs:**
- Less flexible (can't switch relays easily)
- More complex (relay registration flow)

**Decision:** Defer to post-MVP (relay-agnostic simpler for initial deployment)

---

## Testing Checklist

### Unit Tests

- [ ] JWT building and signing (ES256)
- [ ] P-1363 signature format validation
- [ ] Quota enforcement (all limit types)
- [ ] Lease creation, extension, revocation
- [ ] Quota state sliding window
- [ ] Audit log chain integrity

### Integration Tests

- [ ] E2E: Create lease → Issue JWT → Verify with push service
- [ ] E2E: Quota exceeded → JWT issuance fails
- [ ] E2E: Lease expired → JWT issuance fails
- [ ] E2E: Batch issuance → Multiple JWTs returned
- [ ] E2E: Relay switching → Same lease works with new relay

### Security Tests

- [ ] VAPID private key never exposed to PWA
- [ ] JWT signature validates with public key
- [ ] JWT `aud` matches endpoint origin
- [ ] Quota bypass attempts fail
- [ ] Revoked lease cannot issue JWTs
- [ ] Audit log tampering detected

### Performance Tests

- [ ] JWT issuance <50ms (p99)
- [ ] Batch issuance (10 tokens) <200ms (p99)
- [ ] Quota check <10ms (p99)
- [ ] Lease lookup <5ms (p99)

---

## Related Documentation

- [Master Secret & Unlock Context](./02-master-secret.md) - MKEK derivation for key wrapping
- [Unlock Context](./03-unlock-context.md) - `withUnlock()` implementation
- [Key Operations](./04-key-operations.md) - VAPID key generation (V1, to be updated)
- [Audit Log](./05-audit-log.md) - Tamper-evident logging
- [Module Architecture](../module-architecture.md) - Worker, storage, crypto-utils separation

---

## Migration from V1

**V1 approach** (current implementation):
- KMS generates full JWT
- PWA forwards JWT to relay
- Relay uses JWT directly

**V2 approach** (this design):
- KMS issues **leases** (long-lived, relay-agnostic)
- KMS generates JWTs **on-demand** per endpoint
- Quotas enforced per lease and endpoint
- Full audit trail of all issuances

**Breaking changes:**
- API: `generateVAPID()` → `leases.create()` + `vapid.issue()`
- Storage: Add lease records, quota state
- Audit: Add VAPID issuance entries

**Migration path:**
1. Implement V2 VAPID APIs (this doc)
2. Update PWA to use lease-based flow
3. Deprecate V1 `generateVAPID()` API
4. Remove V1 code after migration complete

---

**End of KMS-Issued VAPID for User-Run Relays Specification**
