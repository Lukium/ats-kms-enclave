# Post-MVP Security Hardening

**Status**: Design Phase
**Version**: V2
**Date**: 2025-10-24
**Priority**: Medium (Post-MVP improvements)

---

## Overview

The V2 KMS design is secure and ready for MVP launch. It implements least privilege, tight origin isolation, and short token lifetimes that keep blast radius small without compromising UX. This document catalogs **remaining attack surfaces** and their **lightweight mitigations** for post-MVP hardening.

### What's Already Implemented ✅

The following security improvements were successfully integrated into the V2 design:

- ✅ **AAD schemas + versioning** (01-primitives.md, 02-master-secret.md, 04-key-operations.md)
  - `aadVersion: 1` with fixed field names
  - Explicit decrypt failure on any AAD mismatch

- ✅ **Non-zero HKDF salt for MKEK** (02-master-secret.md)
  - Switched from zeros to deterministic, versioned salt: `SHA256("ATS/KMS/MKEK/salt/v2")`

- ✅ **Unlock + typed errors** (03-unlock-context.md)
  - `withUnlock` maintains zeroization guarantees
  - Typed error propagation with `requestId` correlation
  - Rate-limit hooks documented

- ✅ **Wrapped-key AAD** (04-key-operations.md)
  - All wrapped keys carry AAD with `alg`/`purpose`/`kid`/`kmsVersion`/`createdAt`
  - Decrypt MUST fail on AAD drift

- ✅ **Audit includes `jti`** (05-audit-log.md)
  - All VAPID issuance operations include `jti` for anti-replay tracking

- ✅ **PBKDF2 calibration** (07-calibration.md)
  - Device-time calibration with `iterations` storage and periodic recalibration

- ✅ **PRF UV required + environment notes** (08-security-model.md)
  - WebAuthn PRF requires `userVerification: "required"`
  - iOS/Android background constraints documented

- ✅ **Attestation TTL & 2-of-3 quorum** (11-iframe-isolation.md)
  - Bootloader checks expiring badge
  - Multi-signal decision (badge + manifest + actual hash)
  - Last-good badge cache to prevent flapping

- ✅ **VAPID & leases enhancements** (12-vapid-leases.md)
  - JWT claims include `iat` and optional `nbf`; `exp ≤ 15m`
  - Canonical `aud` derivation from endpoint origin
  - Relay-agnostic leases (hours) with per-lease and per-endpoint quotas
  - Revocation semantics + emergency `jti` blacklist window
  - Anti-reissue for `jti` within TTL
  - Global caps (per-user/day, per-relay/hour)
  - Typed error model with retry hints
  - Background stash guidance and resume top-up
  - Interop tests for FCM/Mozilla and P-1363 conversion

**Conclusion**: The design is cohesive and ship-able for MVP.

---

## Remaining Attack Surfaces

These are the last edges to tighten post-MVP. None conflict with UX goals.

### 1. XSS in PWA Attempting Mass Token Minting

**Risk Level**: Medium
**Attack Vector**: If the PWA UI is compromised (XSS), an attacker can request many short-lived JWTs under an existing lease to spam a user's endpoint. Push payloads remain opaque (encrypted), but the push provider sees high traffic.

**Current Mitigations**:
- Per-lease quotas (`tokensPerHour`)
- Per-endpoint quotas (`sendsPerMinutePerEid`)
- Burst limits (`burstSends`)

**Gaps**:
- Short burst windows can still allow aggressive minting
- No foreground/background enforcement
- Limited feedback from push service errors

**Post-MVP Hardening**:

#### 1a. Tighten Burst Windows

```typescript
/**
 * Enforce per-lease token issuance ceilings over short windows.
 *
 * ENHANCEMENT: Add 90-second burst window in addition to hourly limit.
 */
interface TightenedQuotas extends Quotas {
  tokensPerHour: number;        // Existing (e.g., 120)
  tokensPer90s: number;         // NEW: Max 3 tokens per 90 seconds per lease
  burstWindowMs: 90_000;        // NEW: 90-second rolling window
}

async function enforceShortBurstWindow(
  leaseId: string,
  state: QuotaState
): Promise<{ allowed: boolean; reason?: string }> {
  const now = Date.now();
  const windowStart = now - 90_000; // 90 seconds

  // Count tokens issued in last 90 seconds
  const recentTokens = state.tokensIssuedLastHour
    .filter(e => e.timestamp >= windowStart);

  if (recentTokens.length >= 3) {
    const oldestInWindow = Math.min(...recentTokens.map(e => e.timestamp));
    const retryAfterMs = 90_000 - (now - oldestInWindow);

    return {
      allowed: false,
      reason: 'Short burst limit exceeded (3 tokens/90s)',
      retryAfterMs
    };
  }

  return { allowed: true };
}
```

#### 1b. Sliding Cool-Off on Push Service Errors

```typescript
/**
 * Add cool-off when lease hits repeated 4xx errors from push services.
 *
 * RATIONALE: If relay reports push service rejections, temporarily
 * throttle token issuance for that lease to prevent spam.
 */
interface LeaseErrorState {
  leaseId: string;
  errorCount4xx: number;        // Count of 4xx responses in last 10 minutes
  lastErrorAt: number;
  coolOffUntil?: number;        // Timestamp when cool-off expires
}

async function checkPushServiceCoolOff(leaseId: string): Promise<boolean> {
  const errorState = await storage.get(`lease-errors:${leaseId}`);
  if (!errorState) return true; // No errors, allow

  const now = Date.now();

  // Reset error count if more than 10 minutes passed
  if (now - errorState.lastErrorAt > 600_000) {
    errorState.errorCount4xx = 0;
    await storage.put(`lease-errors:${leaseId}`, errorState);
    return true;
  }

  // Check cool-off
  if (errorState.coolOffUntil && now < errorState.coolOffUntil) {
    return false; // Still in cool-off
  }

  // Trigger cool-off after 3+ errors in 10 minutes
  if (errorState.errorCount4xx >= 3) {
    errorState.coolOffUntil = now + 300_000; // 5-minute cool-off
    await storage.put(`lease-errors:${leaseId}`, errorState);
    return false;
  }

  return true;
}

/**
 * PWA reports push service error back to KMS (via RPC).
 */
async function reportPushError(
  leaseId: string,
  statusCode: number,
  endpoint: string
): Promise<void> {
  if (statusCode >= 400 && statusCode < 500) {
    const errorState = await storage.get(`lease-errors:${leaseId}`) || {
      leaseId,
      errorCount4xx: 0,
      lastErrorAt: Date.now()
    };

    errorState.errorCount4xx++;
    errorState.lastErrorAt = Date.now();

    await storage.put(`lease-errors:${leaseId}`, errorState);

    // Log for audit
    await audit.log({
      op: 'push.error.reported',
      leaseId,
      statusCode,
      endpoint,
      errorCount: errorState.errorCount4xx
    });
  }
}
```

#### 1c. Foreground Check for Stash Top-Up

```typescript
/**
 * Require foreground (tab visible) for increasing stash size.
 *
 * RATIONALE: Allow spending stash when backgrounded, but don't allow
 * XSS to silently pre-mint tokens in background.
 */
async function enforceStashTopUpForeground(
  requestedCount: number,
  currentStashSize: number
): Promise<boolean> {
  // Allow spending existing stash in background
  if (requestedCount <= currentStashSize) {
    return true;
  }

  // Increasing stash requires foreground
  if (document.hidden) {
    throw buildError(
      'foreground.required',
      'Stash top-up requires foreground visibility',
      { requestedCount, currentStashSize }
    );
  }

  return true;
}

/**
 * Modified vapid.issueBatch with foreground check.
 */
async function issueBatchWithForegroundCheck(
  leaseId: string,
  endpoint: Endpoint,
  count: number
): Promise<VAPIDTokenBatch> {
  const currentStash = await getStashSize(leaseId, endpoint.eid);

  // Enforce foreground for stash increases
  await enforceStashTopUpForeground(count, currentStash);

  // Proceed with batch issuance
  return await issueBatch(leaseId, endpoint, count);
}
```

---

### 2. Token Stash Theft/Misuse by Relay

**Risk Level**: Low-Medium
**Attack Vector**: A compromised relay that receives a batch of short-lived tokens can use them all aggressively (still bounded by JWT expiration and `aud`, but within that window can spam).

**Current Mitigations**:
- Short JWT TTL (10-15 minutes)
- Audience binding (`aud` tied to push service origin)
- Small recommended stash sizes (6-8 active, 2-3 standby)

**Gaps**:
- No relay accountability beyond audit logs
- No way to revoke tokens already issued to relay

**Post-MVP Hardening**:

#### 2a. Soft Relay ID (`rid`) for Throttling

```typescript
/**
 * Embed soft relay ID in JWT private claims for throttling.
 *
 * ENHANCEMENT: Already in design, but add explicit throttling logic.
 */
interface VAPIDJWTClaims {
  aud: string;
  sub: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  eid: string;
  rid?: string;  // Soft relay connection id (opaque to push service)
}

/**
 * Track relay abuse patterns.
 */
interface RelayAbuseState {
  rid: string;
  tokensIssuedLast10Min: number;
  pushErrors4xx: number;
  lastSeenAt: number;
  throttledUntil?: number;
}

async function checkRelayThrottle(rid: string): Promise<boolean> {
  if (!rid) return true; // No rid = allow (legacy)

  const abuseState = await storage.get(`relay-abuse:${rid}`);
  if (!abuseState) return true;

  const now = Date.now();

  // Check if throttled
  if (abuseState.throttledUntil && now < abuseState.throttledUntil) {
    return false; // Relay is throttled
  }

  // Trigger throttle if suspicious pattern
  if (abuseState.tokensIssuedLast10Min > 50 || abuseState.pushErrors4xx > 10) {
    abuseState.throttledUntil = now + 600_000; // 10-minute throttle
    await storage.put(`relay-abuse:${rid}`, abuseState);

    await audit.log({
      op: 'relay.throttled',
      rid,
      reason: 'Suspicious token usage',
      tokensIssued: abuseState.tokensIssuedLast10Min,
      pushErrors: abuseState.pushErrors4xx
    });

    return false;
  }

  return true;
}
```

#### 2b. Keep Stash Sizes Small (Documentation)

**Add to 12-vapid-leases.md:**

```markdown
### Stash Size Guidelines

**SECURITY**: Keep stashes small to limit relay misuse window.

**Recommended sizes**:
- **Active relay**: 6-8 tokens (60-120 minutes worst-case)
- **Standby relay**: 2-3 tokens (20-45 minutes)
- **Maximum**: Never exceed 10 tokens per relay stash

**Rationale**: If a relay is compromised, smaller stashes limit the damage window.
A compromised relay with 8 tokens (15 min each) can spam for at most 2 hours,
vs. unlimited access if stashes were unbounded.

**Implementation**: PWA MUST enforce maximum stash size and reject relay requests
for stash top-ups beyond the maximum.
```

---

### 3. Endpoint Mix-Up at Broker Boundary

**Risk Level**: Low
**Attack Vector**: A buggy or malicious relay asks for a token for endpoint E but posts it to endpoint F (same push provider). Push service might accept the POST; the client drops the message (payload decryption fails), but noise is generated.

**Current Mitigations**:
- KMS binds issuance to concrete `eid` (endpoint fingerprint)
- Only issues tokens if `eid ∈ lease.subs`

**Gaps**:
- PWA doesn't enforce pairing of token with `eid` when handing to relay
- No warning if relay reports delivery to different `eid`

**Post-MVP Hardening**:

```typescript
/**
 * Pair each token with its eid when handing to relay.
 *
 * PWA Enhancement: Track which eid each token was issued for.
 */
interface TokenStashEntry {
  jwt: string;
  jti: string;
  exp: number;
  eid: string;        // NEW: Endpoint this token is valid for
  issuedAt: number;
}

/**
 * When relay reports delivery, verify eid matches.
 */
async function handleRelayDeliveryReport(report: {
  jti: string;
  eid: string;
  statusCode: number;
  timestamp: number;
}) {
  // Look up token in stash
  const token = stash.find(t => t.jti === report.jti);

  if (!token) {
    console.warn('Delivery report for unknown jti:', report.jti);
    return;
  }

  // Verify eid matches
  if (token.eid !== report.eid) {
    console.error('Endpoint mismatch!', {
      expected: token.eid,
      reported: report.eid,
      jti: report.jti
    });

    // Alert user and log security event
    await logSecurityEvent({
      type: 'endpoint.mismatch',
      jti: report.jti,
      expectedEid: token.eid,
      reportedEid: report.eid,
      relayId: currentRelayId
    });

    // Consider revoking relay access
    if (getEndpointMismatchCount(currentRelayId) > 3) {
      await disconnectRelay(currentRelayId, 'Repeated endpoint mismatches');
    }
  }

  // Remove from stash (consumed)
  stash = stash.filter(t => t.jti !== report.jti);
}
```

---

### 4. Batch-Size Abuse & Memory Pressure

**Risk Level**: Medium
**Attack Vector**: A malicious relay (or compromised PWA) could request very large batches to stress the KMS worker (memory pressure, CPU).

**Current Mitigations**:
- Batch size limit in `vapid.issueBatch` (≤10 documented)

**Gaps**:
- No in-flight request limit
- No back-pressure mechanism
- No global memory/CPU throttling

**Post-MVP Hardening**:

```typescript
/**
 * Cap RPC batch size and maintain in-flight limits.
 */
const MAX_BATCH_SIZE = 50;        // Per RPC call
const MAX_INFLIGHT_OPS = 200;     // Global across all RPCs

let inflightOperations = 0;

async function enforceBatchLimits(
  batchSize: number
): Promise<void> {
  // Check batch size
  if (batchSize > MAX_BATCH_SIZE) {
    throw buildError(
      'batch.too.large',
      `Batch size exceeds maximum (${batchSize} > ${MAX_BATCH_SIZE})`,
      { requestedSize: batchSize, maxSize: MAX_BATCH_SIZE }
    );
  }

  // Check in-flight operations
  if (inflightOperations + batchSize > MAX_INFLIGHT_OPS) {
    const retryAfterMs = 1000; // Retry after 1 second

    throw buildError(
      'too.many.requests',
      'KMS is processing too many operations, retry later',
      {
        inflightOperations,
        maxInflight: MAX_INFLIGHT_OPS,
        requestedBatch: batchSize
      },
      retryAfterMs
    );
  }

  // Reserve in-flight slots
  inflightOperations += batchSize;
}

/**
 * Release in-flight slots after operation completes.
 */
function releaseInflightSlots(count: number): void {
  inflightOperations = Math.max(0, inflightOperations - count);
}

/**
 * Updated batch handler with limits.
 */
async function handleVAPIDBatchIssue(request: RPCRequest): Promise<RPCResponse> {
  const { leaseId, endpoint, count } = request.params;

  try {
    // Enforce limits
    await enforceBatchLimits(count);

    // Process batch
    const result = await issueBatch(leaseId, endpoint, count);

    return {
      requestId: request.id,
      data: result
    };
  } finally {
    // Always release slots
    releaseInflightSlots(count);
  }
}
```

---

### 5. Clock Skew Problems (JWT `nbf`/`exp`)

**Risk Level**: Low
**Attack Vector**: Users with skewed device clocks suffer intermittent push failures right after token minting (`nbf` not yet valid or `exp` already passed).

**Current Mitigations**:
- JWT includes `iat`, `nbf`, `exp`
- Push services typically allow some skew tolerance

**Gaps**:
- No explicit skew window in KMS implementation
- Could lead to support burden (intermittent failures)

**Post-MVP Hardening**:

```typescript
/**
 * Allow clock skew window when setting nbf/exp.
 *
 * ENHANCEMENT: Set nbf slightly in the past, exp slightly in the future.
 */
const CLOCK_SKEW_SECONDS = 30; // Allow ±30 seconds

function buildJWTClaimsWithSkew(): JWTClaims {
  const now = Math.floor(Date.now() / 1000);

  return {
    aud: endpoint.aud,
    sub: 'mailto:ops@allthe.services',
    iat: now,
    nbf: now - CLOCK_SKEW_SECONDS,      // 30 seconds in the past
    exp: now + (15 * 60) + CLOCK_SKEW_SECONDS, // 15 min + 30s buffer
    jti: crypto.randomUUID(),
    eid: endpoint.eid
  };
}
```

**Add to 12-vapid-leases.md:**

```markdown
### Clock Skew Tolerance

**Problem**: Device clock skew can cause premature JWT rejection.

**Solution**: Allow ±30 second skew window:
- `nbf = iat - 30s` (valid 30 seconds before issuance)
- `exp = iat + 15m + 30s` (valid 30 seconds after nominal expiration)

**Trade-off**: Slightly longer token lifetime (15m 30s vs 15m) in exchange
for better reliability on devices with skewed clocks.
```

---

### 6. Truncation & Wipe Attacks on Audit Log

**Risk Level**: Medium
**Attack Vector**: Local attacker with device access wipes IndexedDB, destroying audit log. In-chain edits are detected, but truncation (empty log) is not immediately obvious.

**Current Mitigations**:
- Tamper-evident audit chain (sequential, chained hashes)
- Ed25519 signatures on entries

**Gaps**:
- No external checkpoint to detect truncation
- Empty log after wipe looks like fresh install

**Post-MVP Hardening**:

```typescript
/**
 * Lightweight anchors: Persist chainHash to separate origin.
 *
 * RATIONALE: Not a trust anchor, just a cheap way to spot truncation.
 */
const ANCHOR_INTERVAL = 500; // Every 500 audit entries

async function maybeAnchorChainHash(
  seqNum: number,
  chainHash: string
): Promise<void> {
  if (seqNum % ANCHOR_INTERVAL === 0) {
    // Persist to PWA's server (blind blob, keyed by userId)
    await fetch('https://allthe.services/api/audit-anchor', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: currentUserId,
        seqNum,
        chainHash,
        timestamp: Date.now()
      })
    });

    // Also persist to separate IndexedDB store (cross-origin backup)
    await anchorStorage.put(`anchor:${seqNum}`, {
      seqNum,
      chainHash,
      timestamp: Date.now()
    });

    await audit.log({
      op: 'audit.anchor',
      seqNum,
      chainHash
    });
  }
}

/**
 * On startup, verify last anchor matches.
 */
async function verifyAuditLogIntegrity(): Promise<boolean> {
  const latestEntry = await audit.getLatest();
  if (!latestEntry) {
    // Empty log, check for anchors
    const anchors = await anchorStorage.getAll();
    if (anchors.length > 0) {
      // Had anchors but log is empty = truncation attack
      console.error('Audit log truncation detected!');
      return false;
    }
    return true; // Fresh install
  }

  // Find last anchor
  const lastAnchorSeq = Math.floor(latestEntry.seqNum / ANCHOR_INTERVAL) * ANCHOR_INTERVAL;
  const anchor = await anchorStorage.get(`anchor:${lastAnchorSeq}`);

  if (!anchor) {
    // No anchor found, acceptable if log is short
    return latestEntry.seqNum < ANCHOR_INTERVAL;
  }

  // Verify chain continuity from anchor to current
  const anchorEntry = await audit.getBySeqNum(lastAnchorSeq);
  if (!anchorEntry || anchorEntry.chainHash !== anchor.chainHash) {
    console.error('Audit chain broken at anchor', lastAnchorSeq);
    return false;
  }

  return true;
}
```

---

### 7. MessageChannel Misuse Across Navigations

**Risk Level**: Low-Medium
**Attack Vector**: Stale MessageChannel ports reused after navigation could accept requests without fresh capability checks.

**Current Mitigations**:
- Origin verification on postMessage
- MessageChannel used for RPC

**Gaps**:
- No explicit lifecycle management for ports
- No session ID tying capability to page lifecycle

**Post-MVP Hardening**:

```typescript
/**
 * Tie capability sid to page lifecycle.
 *
 * ENHANCEMENT: Close ports on navigation and require fresh capability request.
 */
interface RPCSession {
  sid: string;              // Session ID (UUID)
  port: MessagePort;
  origin: string;
  createdAt: number;
  lastUsedAt: number;
  pageLifecycleId: string;  // Unique to current page instance
}

let currentSession: RPCSession | null = null;
let pageLifecycleId = crypto.randomUUID();

/**
 * Close session on page lifecycle events.
 */
window.addEventListener('pagehide', () => {
  if (currentSession) {
    currentSession.port.close();
    currentSession = null;
  }
});

/**
 * Detect navigation and invalidate session.
 */
window.addEventListener('pageshow', (event) => {
  if (event.persisted) {
    // Page restored from bfcache, generate new lifecycle ID
    pageLifecycleId = crypto.randomUUID();

    if (currentSession) {
      // Invalidate old session
      currentSession.port.close();
      currentSession = null;
    }
  }
});

/**
 * RPC handler verifies session lifecycle.
 */
async function handleRPCRequest(
  request: RPCRequest,
  session: RPCSession
): Promise<RPCResponse> {
  // Verify session is for current page lifecycle
  if (session.pageLifecycleId !== pageLifecycleId) {
    return {
      requestId: request.id,
      error: {
        code: 'session.invalid',
        message: 'Session invalidated by navigation, request new capability',
        retryAfterMs: null,
        details: { reason: 'page-lifecycle-changed' }
      }
    };
  }

  // Update last used timestamp
  session.lastUsedAt = Date.now();

  // Route to handler
  return await routeRPCRequest(request);
}
```

**Add test:**

```typescript
it('should invalidate session on navigation', async () => {
  // Create session
  const session = await kms.requestCapability();

  // Simulate navigation (pageshow event)
  window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));

  // Attempt RPC with old session
  const result = await kms.rpc(session, { method: 'vapid.issue', params: {} });

  expect(result.error.code).toBe('session.invalid');
});
```

---

### 8. Side-Channel/Timing Leakage

**Risk Level**: Low
**Attack Vector**: Timing variance on KCV compare and unlock errors leaks bits to a same-origin attacker (e.g., malicious PWA code measuring unlock timing).

**Current Mitigations**:
- KCV verification mentioned
- Constant-time compare recommended

**Gaps**:
- Not enforced consistently across all MAC compares
- No error timing normalization

**Post-MVP Hardening**:

```typescript
/**
 * Enforce constant-time comparison for all MAC checks.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

/**
 * Normalize error timing with randomized delay.
 *
 * RATIONALE: Prevent timing side-channels on authentication failures.
 */
async function normalizeErrorTiming(): Promise<void> {
  // Random delay between 0-50ms on failures
  const delayMs = Math.floor(Math.random() * 50);
  await new Promise(resolve => setTimeout(resolve, delayMs));
}

/**
 * Updated unlock with timing normalization.
 */
async function unlockWithTimingProtection(
  credentials: AuthCredentials
): Promise<UnlockResult> {
  try {
    return await unlock(credentials);
  } catch (error) {
    // Normalize timing on all failures
    await normalizeErrorTiming();
    throw error;
  }
}
```

**Add to 01-primitives.md:**

```markdown
### Timing-Safe MAC Comparison

**CRITICAL**: All MAC comparisons MUST use constant-time compare to prevent timing attacks.

**Implementation**: Use `timingSafeEqual()` for all:
- KCV verification
- Audit signature verification
- AAD verification (implicit in GCM, but explicit checks if any)
- Any other MAC/signature comparisons

**Error timing**: Authentication failures MUST normalize timing with a small
randomized delay (0-50ms) to prevent timing side-channels from leaking
password strength or credential validity.
```

---

### 9. Attestation as DoS Lever

**Risk Level**: Low
**Attack Vector**: If GitHub or the attestation host has a transient outage, KMS could drop into fail-secure too eagerly, blocking legitimate users.

**Current Mitigations**:
- Last-known-good badge cache
- Fail-secure by default

**Gaps**:
- No exponential backoff before flipping to fail-secure
- Immediate failure on fetch errors (not expired badges)

**Post-MVP Hardening**:

```typescript
/**
 * Exponential backoff before fail-secure on fetch failures.
 *
 * ENHANCEMENT: Distinguish transient fetch errors from negative/expired badges.
 */
interface AttestationBackoff {
  consecutiveFetchErrors: number;
  lastFetchError: number;
  backoffMs: number;  // Current backoff delay (exponential)
}

const INITIAL_BACKOFF_MS = 60_000;    // 1 minute
const MAX_BACKOFF_MS = 240_000;       // 4 minutes
const MAX_FETCH_ERRORS_BEFORE_FAIL = 3;

async function fetchBadgeWithBackoff(): Promise<BadgeData | null> {
  const backoffState = await storage.get('attestation-backoff') || {
    consecutiveFetchErrors: 0,
    lastFetchError: 0,
    backoffMs: INITIAL_BACKOFF_MS
  };

  const now = Date.now();

  try {
    const response = await fetch('/badge.json', {
      cache: 'no-store',
      signal: AbortSignal.timeout(5000) // 5-second timeout
    });

    if (!response.ok) {
      throw new Error(`Badge fetch failed: ${response.status}`);
    }

    const badge = await response.json();

    // Success: reset backoff
    if (backoffState.consecutiveFetchErrors > 0) {
      await storage.put('attestation-backoff', {
        consecutiveFetchErrors: 0,
        lastFetchError: 0,
        backoffMs: INITIAL_BACKOFF_MS
      });
    }

    return badge;
  } catch (error) {
    console.warn('Badge fetch error:', error);

    // Increment consecutive errors
    backoffState.consecutiveFetchErrors++;
    backoffState.lastFetchError = now;

    // Exponential backoff: 1min → 2min → 4min
    backoffState.backoffMs = Math.min(
      backoffState.backoffMs * 2,
      MAX_BACKOFF_MS
    );

    await storage.put('attestation-backoff', backoffState);

    // Only fail secure after multiple errors AND no cached badge
    if (backoffState.consecutiveFetchErrors >= MAX_FETCH_ERRORS_BEFORE_FAIL) {
      const cachedBadge = await loadCachedBadge();
      if (!cachedBadge || now >= cachedBadge.expires_at) {
        // No valid cache, fail secure
        return null;
      }

      // Have valid cache, use it
      console.warn('Using cached badge due to persistent fetch errors');
      return cachedBadge;
    }

    // Still within retry tolerance, use cache if available
    const cachedBadge = await loadCachedBadge();
    if (cachedBadge && now < cachedBadge.expires_at) {
      return cachedBadge;
    }

    return null;
  }
}
```

**Decision logic update in 11-iframe-isolation.md:**

```markdown
### Attestation Fetch Failure Handling

**Policy**:
1. On **first fetch error**: Log warning, use cached badge if valid
2. On **second fetch error** (within backoff window): Log error, use cached badge if valid
3. On **third fetch error**: Enter fail-secure ONLY if cached badge is expired/missing

**Backoff schedule**:
- 1st error: Retry after 1 minute
- 2nd error: Retry after 2 minutes
- 3rd error: Retry after 4 minutes
- Beyond 3rd: Fail secure if no valid cache

**Rationale**: Transient network issues shouldn't immediately block users.
Use cached attestation as long as it's fresh, with exponential backoff to
avoid hammering unreachable endpoints.
```

---

### 10. Multi-Tab Race Conditions

**Risk Level**: Low-Medium
**Attack Vector**: Two browser tabs both managing leases/token stashes step on each other (IndexedDB contention, duplicate token requests, stale state).

**Current Mitigations**:
- IndexedDB transactions provide some isolation

**Gaps**:
- No leader election
- No coordination between tabs
- Potential for duplicate lease creation or stash corruption

**Post-MVP Hardening**:

```typescript
/**
 * Elect leader tab to manage leases and stash top-ups.
 *
 * ENHANCEMENT: Use BroadcastChannel for leader election.
 */
interface LeaderState {
  tabId: string;
  electedAt: number;
  heartbeatAt: number;
}

const broadcastChannel = new BroadcastChannel('kms-coordination');
const TAB_ID = crypto.randomUUID();
const HEARTBEAT_INTERVAL_MS = 3000;
const LEADER_TIMEOUT_MS = 10000;

let isLeader = false;
let leaderState: LeaderState | null = null;

/**
 * Leader election on startup.
 */
async function electLeader(): Promise<void> {
  // Check for existing leader
  const currentLeader = await storage.get('leader-state');

  if (currentLeader) {
    const now = Date.now();
    const age = now - currentLeader.heartbeatAt;

    if (age < LEADER_TIMEOUT_MS) {
      // Leader is alive, we're a follower
      isLeader = false;
      leaderState = currentLeader;
      console.log('Tab is follower, leader:', currentLeader.tabId);
      return;
    }

    // Leader timed out, we can become leader
  }

  // Become leader
  isLeader = true;
  leaderState = {
    tabId: TAB_ID,
    electedAt: Date.now(),
    heartbeatAt: Date.now()
  };

  await storage.put('leader-state', leaderState);
  console.log('Tab elected as leader');

  // Start heartbeat
  startHeartbeat();

  // Broadcast leadership
  broadcastChannel.postMessage({
    type: 'leader-elected',
    tabId: TAB_ID
  });
}

/**
 * Leader heartbeat to maintain leadership.
 */
function startHeartbeat(): void {
  setInterval(async () => {
    if (!isLeader) return;

    leaderState!.heartbeatAt = Date.now();
    await storage.put('leader-state', leaderState);

    broadcastChannel.postMessage({
      type: 'leader-heartbeat',
      tabId: TAB_ID
    });
  }, HEARTBEAT_INTERVAL_MS);
}

/**
 * Listen for leadership changes.
 */
broadcastChannel.onmessage = (event) => {
  if (event.data.type === 'leader-elected' && event.data.tabId !== TAB_ID) {
    // Another tab became leader
    isLeader = false;
    leaderState = null;
    console.log('Leadership transferred to', event.data.tabId);
  }

  if (event.data.type === 'leader-heartbeat' && event.data.tabId !== TAB_ID) {
    // Update follower's view of leader
    leaderState = {
      tabId: event.data.tabId,
      electedAt: leaderState?.electedAt || Date.now(),
      heartbeatAt: Date.now()
    };
  }
};

/**
 * Request token from leader (if follower).
 */
async function requestTokenFromLeader(
  leaseId: string,
  endpoint: Endpoint
): Promise<VAPIDToken> {
  if (isLeader) {
    // We're leader, issue directly
    return await kms.vapid.issue({ leaseId, endpoint });
  }

  // We're follower, request from leader via BroadcastChannel
  const requestId = crypto.randomUUID();

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Leader request timeout'));
    }, 5000);

    const handler = (event: MessageEvent) => {
      if (event.data.type === 'token-response' && event.data.requestId === requestId) {
        clearTimeout(timeout);
        broadcastChannel.removeEventListener('message', handler);
        resolve(event.data.token);
      }
    };

    broadcastChannel.addEventListener('message', handler);

    // Send request to leader
    broadcastChannel.postMessage({
      type: 'token-request',
      requestId,
      leaseId,
      endpoint,
      fromTabId: TAB_ID
    });
  });
}

/**
 * Leader handles token requests from followers.
 */
broadcastChannel.onmessage = async (event) => {
  if (isLeader && event.data.type === 'token-request') {
    try {
      const token = await kms.vapid.issue({
        leaseId: event.data.leaseId,
        endpoint: event.data.endpoint
      });

      broadcastChannel.postMessage({
        type: 'token-response',
        requestId: event.data.requestId,
        token
      });
    } catch (error) {
      broadcastChannel.postMessage({
        type: 'token-error',
        requestId: event.data.requestId,
        error: error.message
      });
    }
  }
};

/**
 * On page unload, relinquish leadership.
 */
window.addEventListener('beforeunload', () => {
  if (isLeader) {
    storage.delete('leader-state');
    broadcastChannel.postMessage({
      type: 'leader-resigned',
      tabId: TAB_ID
    });
  }
});
```

---

## Implementation Priority

**High Priority** (MVP+1):
1. XSS token minting limits (1a, 1b, 1c)
2. Batch size limits (4)
3. Timing normalization (8)
4. Multi-tab coordination (10)

**Medium Priority** (MVP+2):
5. Relay throttling (2a)
6. Endpoint mix-up detection (3)
7. Clock skew tolerance (5)
8. Audit anchors (6)

**Low Priority** (MVP+3):
9. MessageChannel lifecycle (7)
10. Attestation backoff (9)

---

## Testing Strategy

Each hardening should include:

1. **Unit tests** - Verify new limits/checks work correctly
2. **Integration tests** - Test under load/abuse conditions
3. **Security tests** - Verify attack is prevented
4. **Performance tests** - Ensure hardening doesn't degrade UX

Example test structure:

```typescript
describe('Post-MVP Hardening', () => {
  describe('XSS Token Minting', () => {
    it('should enforce 90-second burst limit', async () => {
      // Issue 3 tokens rapidly
      await kms.vapid.issue({ leaseId, endpoint });
      await kms.vapid.issue({ leaseId, endpoint });
      await kms.vapid.issue({ leaseId, endpoint });

      // 4th request should fail
      await expect(kms.vapid.issue({ leaseId, endpoint }))
        .rejects.toMatchObject({
          error: {
            code: 'quota.exceeded.burst',
            retryAfterMs: expect.any(Number)
          }
        });
    });

    it('should allow top-up only in foreground', async () => {
      // Simulate background
      Object.defineProperty(document, 'hidden', {
        value: true,
        writable: true
      });

      await expect(kms.vapid.issueBatch({ leaseId, endpoint, count: 10 }))
        .rejects.toMatchObject({
          error: {
            code: 'foreground.required'
          }
        });
    });
  });

  describe('Timing Side-Channels', () => {
    it('should normalize error timing', async () => {
      const timings: number[] = [];

      // Collect timing for wrong password attempts
      for (let i = 0; i < 100; i++) {
        const start = performance.now();
        try {
          await kms.unlock({ method: 'passphrase', passphrase: 'wrong' });
        } catch {}
        timings.push(performance.now() - start);
      }

      // Verify timing variance is low (randomized delay working)
      const mean = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
      const stddev = Math.sqrt(variance);

      // Standard deviation should be small (tight timing distribution)
      expect(stddev).toBeLessThan(20); // <20ms stddev
    });
  });
});
```

---

## Conclusion

The V2 KMS design is **production-ready for MVP launch**. The hardening items above are polish that can be incrementally added post-launch based on operational feedback and threat modeling updates.

**Key strengths preserved**:
- ✅ Least privilege (minimal KMS capabilities)
- ✅ Origin isolation (cross-origin iframe)
- ✅ Short token lifetimes (10-15 minutes)
- ✅ Fail-secure by default
- ✅ Full auditability

**Post-MVP focus**: Limits, lifecycle management, and back-pressure to make the system harder to abuse or misconfigure.

---

**Related Documentation**:
- [Security Model](./08-security-model.md) - Core security boundaries
- [VAPID Leases](./12-vapid-leases.md) - Lease and quota management
- [Unlock Context](./03-unlock-context.md) - Authentication and error handling
- [Audit Log](./05-audit-log.md) - Tamper-evident logging
