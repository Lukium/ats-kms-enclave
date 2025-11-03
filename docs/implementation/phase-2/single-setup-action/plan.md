# Single-Action Full Setup Flow

**Status**: Planning
**Created**: 2025-11-03
**Target**: Phase 2 - Production KMS
**Priority**: High

---

## Overview

Create a unified `fullSetup(userId, autoExtend)` function that orchestrates the complete onboarding flow in a single user action:

1. **Setup user authentication** (passphrase or passkey via popup)
2. **Subscribe to Web Push** (browser PushManager API)
3. **Store push subscription** in KMS
4. **Create a VAPID lease** (8-12 hours with autoExtend flag)
5. **Issue packet of 5 JWTs** (with staggered expirations for seamless rotation)
6. **Send test notification** (to confirm setup is working)

**Key Benefit**: User completes entire setup with **one authentication ceremony** instead of separate steps for setup, push subscription, and lease creation.

---

## Current State Analysis

### ✅ Existing Functions (Already Implemented)

#### 1. **Setup Flow** (`src/v2/worker.ts:450-522`)
```typescript
handleSetupWithPopup(params: { userId: string }, requestId: string)
  → { success: true, enrollmentId: string, vapidPublicKey: string, vapidKid: string }
```
- Generates ephemeral transport keys
- Opens popup for credential collection
- Receives encrypted credentials
- Calls appropriate setup method (passphrase/PRF/gate)
- **Returns VAPID public key immediately**

#### 2. **Push Subscription Storage** (`src/v2/worker.ts:2464-2469`)
```typescript
handleSetPushSubscription(params: { subscription: StoredPushSubscription })
  → { success: true }
```
- Validates subscription endpoint (FCM/APNs/Mozilla/WNS whitelist)
- Stores subscription with VAPID key record (1:1 relationship)
- **No authentication required** (public data)

#### 3. **Lease Creation** (`src/v2/worker.ts:1660-1803`)
```typescript
handleCreateLease(params: {
  userId: string,
  ttlHours: number,
  credentials: AuthCredentials,
  autoExtend?: boolean
}, requestId: string)
  → { leaseId: string, exp: number, quotas: QuotaState, autoExtend: boolean }
```
- **Requires authentication** (credentials parameter)
- Derives SessionKEK from MS + random lease salt
- Wraps VAPID key with SessionKEK
- Generates LAK (Lease Audit Key) with delegation cert
- Stores SessionKEK in IndexedDB + memory cache
- **Returns lease ID and expiration**

#### 4. **Batch JWT Issuance** (`src/v2/worker.ts:2192-2237`)
```typescript
handleIssueVAPIDJWTs(params: {
  leaseId: string,
  count: number,
  kid?: string
}, requestId: string)
  → Array<{ jwt: string, jti: string, exp: number, auditEntry: AuditEntryV2 }>
```
- Issues multiple JWTs with **staggered expirations** (60% TTL overlap)
- Each JWT: 15 min base TTL, staggered by 9 min intervals
- **No authentication required** (lease is the authorization)
- Returns array of JWTs with metadata

#### 5. **Get Push Subscription** (`src/v2/worker.ts:2486-2491`)
```typescript
handleGetPushSubscription()
  → { subscription: StoredPushSubscription | null }
```
- Retrieves current push subscription from VAPID key
- **No authentication required** (public data)

### 🔑 Key Insight: Credentials Problem

The **critical challenge** is that `createLease()` requires `AuthCredentials`, but after `setupWithPopup()` completes, **we no longer have access to the credentials** (they were in the popup and encrypted).

**Two Solutions**:

#### **Option A: Return Credentials from Setup (Recommended)**
Modify `setupWithPopup()` to return decrypted credentials for immediate reuse:

```typescript
// Current
setupWithPopup() → { success, enrollmentId, vapidPublicKey, vapidKid }

// Modified
setupWithPopup() → {
  success,
  enrollmentId,
  vapidPublicKey,
  vapidKid,
  credentials: AuthCredentials  // ← NEW: for immediate lease creation
}
```

**Pros**:
- ✅ No re-authentication needed
- ✅ Seamless single-action UX
- ✅ Credentials only in memory for seconds
- ✅ No security degradation (already unlocked once)

**Cons**:
- ⚠️ Credentials in memory slightly longer (acceptable for setup flow)

#### **Option B: Re-Authenticate for Lease**
Keep `setupWithPopup()` unchanged, prompt user again for lease creation.

**Pros**:
- ✅ No changes to setupWithPopup()
- ✅ Explicit re-auth for lease

**Cons**:
- ❌ Poor UX (user authenticates twice in quick succession)
- ❌ Not truly "single action"
- ❌ More complex state management

**Decision**: **Use Option A** - Return credentials from setup for immediate lease creation.

---

## Architecture

### Flow Diagram

```
┌─────────┐                 ┌────────┐                 ┌───────┐
│ Parent  │                 │ Worker │                 │ Popup │
│  PWA    │                 │  KMS   │                 │  KMS  │
└─────────┘                 └────────┘                 └───────┘
     │                           │                          │
     │  RPC: fullSetup           │                          │
     │  { userId, autoExtend }   │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                    [Check if already setup]          │
     │                           │                          │
     │                    [If setup → error]                │
     │                           │                          │
     │                    STEP 1: Setup Auth               │
     │                           │                          │
     │                    [Generate transport keys]         │
     │                           │                          │
     │  worker:setup-with-popup  │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  [Tell parent to open popup]                         │
     │                           │                          │
     │  kms:request-popup        │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  window.open(minimal URL) │                          │
     ├────────────────────────────────────────────────────> │
     │                           │                          │
     │                           │  MessageChannel          │
     │                           │  + transport params      │
     │                           │─────────────────────────>│
     │                           │                          │
     │                           │   [User creates creds]   │
     │                           │   [Passphrase or passkey]│
     │                           │                          │
     │                           │  encrypted credentials   │
     │                           │◄─────────────────────────┤
     │                           │                          │
     │                    [Decrypt credentials]             │
     │                    [Call setupPassphrase/PRF/Gate]   │
     │                    [Generate VAPID keypair]          │
     │                    [Store wrapped VAPID key]         │
     │                    [Save credentials for reuse]      │
     │                           │                          │
     │                    STEP 2: Subscribe to Push         │
     │                           │                          │
     │  worker:request-push-sub  │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  [PWA calls ServiceWorker]                           │
     │  [registration.pushManager.subscribe()]              │
     │  [With VAPID public key]  │                          │
     │                           │                          │
     │  worker:push-sub-result   │                          │
     │  { subscription }         │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                    [Store subscription]              │
     │                    [Via handleSetPushSubscription]   │
     │                           │                          │
     │                    STEP 3: Create Lease              │
     │                           │                          │
     │                    [Call handleCreateLease]          │
     │                    [With saved credentials]          │
     │                    [Derive SessionKEK]               │
     │                    [Wrap VAPID with SessionKEK]      │
     │                    [Generate LAK + delegation cert]  │
     │                    [Store lease + SessionKEK]        │
     │                           │                          │
     │                    STEP 4: Issue JWT Packet          │
     │                           │                          │
     │                    [Call handleIssueVAPIDJWTs]       │
     │                    [count: 5]                        │
     │                    [Returns 5 JWTs with stagger]     │
     │                           │                          │
     │                    STEP 5: Send Test Notification    │
     │                           │                          │
     │  worker:send-test-notif   │                          │
     │  { jwt, subscription }    │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  [PWA sends test notif]   │                          │
     │  [Via relay or direct]    │                          │
     │                           │                          │
     │  worker:test-notif-result │                          │
     │  { success: true }        │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                    [Clear credentials from memory]   │
     │                           │                          │
     │  RPC Response:            │                          │
     │  { success: true,         │                          │
     │    enrollmentId,          │                          │
     │    vapidPublicKey,        │                          │
     │    vapidKid,              │                          │
     │    leaseId,               │                          │
     │    leaseExp,              │                          │
     │    jwts: [5 tokens],      │                          │
     │    subscription }         │                          │
     │◄──────────────────────────┤                          │
```

### State Management

The worker needs to track state across async operations:

```typescript
// In worker.ts global scope
const pendingFullSetupRequests = new Map<
  string,
  {
    userId: string;
    autoExtend: boolean;
    credentials: AuthCredentials | null;
    vapidPublicKey: string | null;
    vapidKid: string | null;
    subscription: StoredPushSubscription | null;
    leaseId: string | null;
    resolve: (result: FullSetupResult) => void;
    reject: (error: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }
>();
```

---

## Implementation Plan

### Step 1: Modify `setupWithEncryptedCredentials()` to Return Credentials

**File**: `src/v2/worker.ts:303-432`

**Change**: Add decrypted credentials to return value.

```typescript
// Current signature (line 303)
async function setupWithEncryptedCredentials(params: {
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  transportKeyId: string;
  ephemeralPublicKey: string;
  iv: string;
  encryptedCredentials: string;
  userId: string;
  requestId: string;
}): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string
}>

// New signature (add credentials)
async function setupWithEncryptedCredentials(params: {
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  transportKeyId: string;
  ephemeralPublicKey: string;
  iv: string;
  encryptedCredentials: string;
  userId: string;
  requestId: string;
}): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string;
  credentials: AuthCredentials;  // ← NEW
}>
```

**Implementation**:

```typescript
// Inside setupWithEncryptedCredentials, after decrypting credentials (line 380)

// Step 6: Call existing setup methods based on credential type
let result: { success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string };
let authCredentials: AuthCredentials; // ← NEW: Track credentials for return

if (params.method === 'passphrase') {
  const passphraseCredentials = credentials as { passphrase: string };
  result = await handleSetupPassphrase(
    {
      userId: params.userId,
      passphrase: passphraseCredentials.passphrase,
    },
    params.requestId
  );

  // ← NEW: Build AuthCredentials object
  authCredentials = {
    method: 'passphrase',
    passphrase: passphraseCredentials.passphrase,
    userId: params.userId,
  };
} else if (params.method === 'passkey-prf') {
  const prfCredentials = credentials as { credentialId: string; prfOutput: string; rpId?: string };
  result = await handleSetupPasskeyPRF(
    {
      userId: params.userId,
      credentialId: base64urlToArrayBuffer(prfCredentials.credentialId),
      prfOutput: base64urlToArrayBuffer(prfCredentials.prfOutput),
      ...(prfCredentials.rpId !== undefined && { rpId: prfCredentials.rpId }),
      appSalt: transport.appSalt,
      hkdfSalt: transport.hkdfSalt,
    },
    params.requestId
  );

  // ← NEW: Build AuthCredentials object
  authCredentials = {
    method: 'passkey-prf',
    prfOutput: base64urlToArrayBuffer(prfCredentials.prfOutput),
    userId: params.userId,
  };
} else if (params.method === 'passkey-gate') {
  const gateCredentials = credentials as { credentialId: string; rpId?: string };
  result = await handleSetupPasskeyGate(
    {
      userId: params.userId,
      credentialId: base64urlToArrayBuffer(gateCredentials.credentialId),
      ...(gateCredentials.rpId !== undefined && { rpId: gateCredentials.rpId }),
    },
    params.requestId
  );

  // ← NEW: Build AuthCredentials object
  authCredentials = {
    method: 'passkey-gate',
    userId: params.userId,
  };
} else {
  const exhaustive: never = params.method;
  throw new Error(`Unknown method: ${String(exhaustive)}`);
}

// Step 7: Delete ephemeral transport key (one-time use, no longer needed)
ephemeralTransportKeys.delete(params.transportKeyId);

// ← MODIFIED: Return credentials along with setup result
return {
  ...result,
  credentials: authCredentials,
};
```

**Files to modify**:
- `src/v2/worker.ts:303-432` (setupWithEncryptedCredentials)
- Update call site in `handleSetupWithPopup()` to handle new return value

### Step 2: Create `handleFullSetup()` Worker Function

**File**: `src/v2/worker.ts` (add after `handleSetupWithPopup`)

**Function signature**:

```typescript
/**
 * Complete onboarding flow in single user action.
 *
 * Orchestrates:
 * 1. User authentication setup (via popup)
 * 2. Web Push subscription (via parent PWA)
 * 3. VAPID lease creation (with autoExtend flag)
 * 4. JWT packet issuance (5 tokens with staggered expirations)
 * 5. Test notification (confirms setup working)
 *
 * @param params.userId - User ID
 * @param params.autoExtend - Whether lease can be auto-extended without re-auth
 * @param params.ttlHours - Lease TTL in hours (default: 12, max: 720)
 * @param requestId - Request ID for audit logging
 * @returns Complete setup result with lease, JWTs, and subscription
 */
async function handleFullSetup(
  params: {
    userId: string;
    autoExtend?: boolean;
    ttlHours?: number;
  },
  requestId: string
): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string;
  leaseId: string;
  leaseExp: number;
  autoExtend: boolean;
  jwts: Array<{ jwt: string; jti: string; exp: number }>;
  subscription: StoredPushSubscription;
}>
```

**Implementation**:

```typescript
async function handleFullSetup(
  params: {
    userId: string;
    autoExtend?: boolean;
    ttlHours?: number;
  },
  requestId: string
): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string;
  leaseId: string;
  leaseExp: number;
  autoExtend: boolean;
  jwts: Array<{ jwt: string; jti: string; exp: number }>;
  subscription: StoredPushSubscription;
}> {
  const { userId, autoExtend = true, ttlHours = 12 } = params;

  // Validate TTL
  if (ttlHours <= 0 || ttlHours > 720) {
    throw new Error('ttlHours must be between 0 and 720 (30 days)');
  }

  // STEP 1: Check if already setup
  const setupCheck = await isSetup(userId);
  if (setupCheck) {
    throw new Error('User already has authentication setup. Use addEnrollment to add additional methods.');
  }

  // STEP 2: Setup authentication (via popup)
  // This now returns credentials for immediate lease creation
  const setupResult = await handleSetupWithPopup({ userId }, `${requestId}-setup`);

  // Extract credentials (returned from modified setupWithEncryptedCredentials)
  const credentials = setupResult.credentials;
  const vapidPublicKey = setupResult.vapidPublicKey;
  const vapidKid = setupResult.vapidKid;

  // STEP 3: Request push subscription from parent PWA
  // Parent will call PushManager.subscribe() with our VAPID public key
  const subscription = await new Promise<StoredPushSubscription>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Push subscription timeout'));
    }, 60000); // 60 second timeout

    // Store resolver in pending map
    pendingFullSetupRequests.set(requestId, {
      userId,
      autoExtend: autoExtend ?? true,
      credentials,
      vapidPublicKey,
      vapidKid,
      subscription: null,
      leaseId: null,
      resolve: resolve as (result: unknown) => void,
      reject,
      timeout,
    });

    // Send message to client (main thread) to request push subscription
    self.postMessage({
      type: 'worker:request-push-subscription',
      requestId,
      vapidPublicKey,
      userId,
    });
  });

  // STEP 4: Store push subscription with VAPID key
  await handleSetPushSubscription({ subscription });

  // STEP 5: Create lease with saved credentials
  // No re-authentication needed - we saved credentials from setup
  const leaseResult = await handleCreateLease(
    {
      userId,
      ttlHours,
      credentials,
      autoExtend,
    },
    `${requestId}-lease`
  );

  // STEP 6: Issue packet of 5 JWTs with staggered expirations
  const jwtResults = await handleIssueVAPIDJWTs(
    {
      leaseId: leaseResult.leaseId,
      count: 5,
      kid: vapidKid,
    },
    `${requestId}-jwts`
  );

  // Extract JWTs without audit entries (cleaner return)
  const jwts = jwtResults.map(r => ({
    jwt: r.jwt,
    jti: r.jti,
    exp: r.exp,
  }));

  // STEP 7: Send test notification
  // We'll send one JWT to parent for test notification
  const testJWT = jwts[0]!;

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Test notification timeout'));
    }, 30000); // 30 second timeout

    const notifRequestId = `${requestId}-test-notif`;

    // Store resolver
    pendingFullSetupRequests.set(notifRequestId, {
      userId,
      autoExtend: autoExtend ?? true,
      credentials: null, // Already cleared
      vapidPublicKey: null,
      vapidKid: null,
      subscription: null,
      leaseId: null,
      resolve: resolve as (result: unknown) => void,
      reject,
      timeout,
    });

    // Send message to client to send test notification
    self.postMessage({
      type: 'worker:send-test-notification',
      requestId: notifRequestId,
      jwt: testJWT.jwt,
      subscription,
    });
  });

  // STEP 8: Clear credentials from memory (defense in depth)
  // Credentials were used for setup and lease, no longer needed
  if (credentials.method === 'passphrase') {
    // Overwrite passphrase string (can't directly zero in JS, but reassign)
    (credentials as { passphrase: string }).passphrase = '';
  } else if (credentials.method === 'passkey-prf') {
    // Zero PRF output buffer
    new Uint8Array((credentials as { prfOutput: ArrayBuffer }).prfOutput).fill(0);
  }

  // Log operation
  await logOperation({
    op: 'full-setup',
    kid: vapidKid,
    requestId,
    userId,
    details: {
      action: 'full-setup',
      enrollmentId: setupResult.enrollmentId,
      leaseId: leaseResult.leaseId,
      autoExtend,
      ttlHours,
      jwtCount: jwts.length,
    },
  });

  return {
    success: true,
    enrollmentId: setupResult.enrollmentId,
    vapidPublicKey,
    vapidKid,
    leaseId: leaseResult.leaseId,
    leaseExp: leaseResult.exp,
    autoExtend: leaseResult.autoExtend ?? true,
    jwts,
    subscription,
  };
}
```

### Step 3: Add Worker Message Handlers

**File**: `src/v2/worker.ts` (in message listener, around line 532)

Add handlers for internal messages from client:

```typescript
// In addEventListener('message') handler

// Handle push subscription result from client
if ('type' in message && message.type === 'worker:push-subscription-result') {
  const requestId = message.requestId as string;
  const subscription = message.subscription as StoredPushSubscription;

  if (requestId) {
    const pending = pendingFullSetupRequests.get(requestId);
    if (pending) {
      clearTimeout(pending.timeout);
      pending.subscription = subscription;
      pending.resolve(subscription);
    }
  }
  return;
}

// Handle test notification result from client
if ('type' in message && message.type === 'worker:test-notification-result') {
  const requestId = message.requestId as string;
  const success = message.success as boolean;

  if (requestId) {
    const pending = pendingFullSetupRequests.get(requestId);
    if (pending) {
      clearTimeout(pending.timeout);
      pendingFullSetupRequests.delete(requestId);

      if (success) {
        pending.resolve(undefined);
      } else {
        pending.reject(new Error(message.error as string || 'Test notification failed'));
      }
    }
  }
  return;
}
```

### Step 4: Add Client Handlers

**File**: `src/v2/client.ts` (in handleWorkerMessage, around line 319)

Add handlers for worker requests:

```typescript
// In handleWorkerMessage()

// Handle push subscription request
if ('type' in data && data.type === 'worker:request-push-subscription') {
  void this.handlePushSubscriptionRequest({
    requestId: data.requestId as string,
    vapidPublicKey: data.vapidPublicKey as string,
    userId: data.userId as string,
  });
  return;
}

// Handle test notification request
if ('type' in data && data.type === 'worker:send-test-notification') {
  void this.handleTestNotification({
    requestId: data.requestId as string,
    jwt: data.jwt as string,
    subscription: data.subscription as StoredPushSubscription,
  });
  return;
}
```

**Add new methods to KMSClient class**:

```typescript
/**
 * Handle push subscription request from worker.
 * Asks parent PWA to subscribe to push notifications.
 */
private async handlePushSubscriptionRequest(params: {
  requestId: string;
  vapidPublicKey: string;
  userId: string;
}): Promise<void> {
  try {
    // Convert base64url public key to Uint8Array
    const publicKeyBytes = base64urlToArrayBuffer(params.vapidPublicKey);

    // Ask parent to subscribe to push
    // Parent will call registration.pushManager.subscribe()
    const targetWindow = window.parent && window.parent !== window ? window.parent : null;
    if (!targetWindow) {
      throw new Error('No parent window available');
    }

    targetWindow.postMessage(
      {
        type: 'kms:request-push-subscription',
        requestId: params.requestId,
        vapidPublicKey: params.vapidPublicKey,
        userId: params.userId,
      },
      this.parentOrigin
    );

    // Parent will respond with kms:push-subscription-result
    // which handleParentMessage will receive and forward to worker
  } catch (err: unknown) {
    console.error('[KMS Client] Push subscription request failed:', err);
    this.worker?.postMessage({
      type: 'worker:push-subscription-error',
      requestId: params.requestId,
      reason: err instanceof Error ? err.message : 'Unknown error',
    });
  }
}

/**
 * Handle test notification request from worker.
 * Asks parent PWA to send a test push notification.
 */
private async handleTestNotification(params: {
  requestId: string;
  jwt: string;
  subscription: StoredPushSubscription;
}): Promise<void> {
  try {
    // Ask parent to send test notification
    const targetWindow = window.parent && window.parent !== window ? window.parent : null;
    if (!targetWindow) {
      throw new Error('No parent window available');
    }

    targetWindow.postMessage(
      {
        type: 'kms:send-test-notification',
        requestId: params.requestId,
        jwt: params.jwt,
        subscription: params.subscription,
      },
      this.parentOrigin
    );

    // Parent will respond with kms:test-notification-result
    // which handleParentMessage will receive and forward to worker
  } catch (err: unknown) {
    console.error('[KMS Client] Test notification request failed:', err);
    this.worker?.postMessage({
      type: 'worker:test-notification-error',
      requestId: params.requestId,
      reason: err instanceof Error ? err.message : 'Unknown error',
    });
  }
}
```

**Add handlers in `handleParentMessage()`**:

```typescript
// In handleParentMessage()

// Handle push subscription result from parent
const data = event.data as { type?: string; requestId?: string; subscription?: unknown; success?: boolean; error?: string };

if (data?.type === 'kms:push-subscription-result') {
  this.worker?.postMessage({
    type: 'worker:push-subscription-result',
    requestId: data.requestId,
    subscription: data.subscription,
  });
  return;
}

// Handle test notification result from parent
if (data?.type === 'kms:test-notification-result') {
  this.worker?.postMessage({
    type: 'worker:test-notification-result',
    requestId: data.requestId,
    success: data.success,
    error: data.error,
  });
  return;
}
```

### Step 5: Add RPC Method Registration

**File**: `src/v2/worker.ts` (in handleMessage switch statement, around line 636)

```typescript
case 'fullSetup':
  result = await handleFullSetup(validators.validateFullSetup(params), id);
  break;
```

### Step 6: Add RPC Validation

**File**: `src/v2/rpc-validation.ts`

```typescript
/**
 * Validate fullSetup parameters.
 */
export function validateFullSetup(params: unknown): {
  userId: string;
  autoExtend?: boolean;
  ttlHours?: number;
} {
  const p = validateParamsObject('fullSetup', params);

  const userId = validateString('fullSetup', 'userId', p.userId);

  // autoExtend is optional, defaults to true
  let autoExtend: boolean | undefined;
  if (p.autoExtend !== undefined) {
    if (typeof p.autoExtend !== 'boolean') {
      throw new RPCValidationError('fullSetup', 'autoExtend', 'boolean', typeof p.autoExtend);
    }
    autoExtend = p.autoExtend;
  }

  // ttlHours is optional, defaults to 12
  let ttlHours: number | undefined;
  if (p.ttlHours !== undefined) {
    ttlHours = validateNumber('fullSetup', 'ttlHours', p.ttlHours);
    if (ttlHours <= 0 || ttlHours > 720) {
      throw new RPCValidationError('fullSetup', 'ttlHours', '0 < ttlHours <= 720', ttlHours);
    }
  }

  return { userId, autoExtend, ttlHours };
}
```

### Step 7: Add Parent PWA Handlers

**File**: `example/phase-2/parent.ts` (or wherever parent logic lives)

Add handlers for KMS requests:

```typescript
// Listen for messages from KMS iframe
window.addEventListener('message', async (event: MessageEvent) => {
  if (event.origin !== 'https://kms.ats.run') return;

  const data = event.data as { type?: string; requestId?: string; vapidPublicKey?: string; userId?: string; jwt?: string; subscription?: unknown };

  // Handle push subscription request
  if (data?.type === 'kms:request-push-subscription') {
    try {
      const registration = await navigator.serviceWorker.ready;

      // Convert VAPID public key from base64url to Uint8Array
      const vapidPublicKey = base64urlToArrayBuffer(data.vapidPublicKey!);

      // Subscribe to push notifications
      const pushSubscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: vapidPublicKey,
      });

      // Convert to StoredPushSubscription format
      const subscription: StoredPushSubscription = {
        endpoint: pushSubscription.endpoint,
        expirationTime: pushSubscription.expirationTime,
        keys: {
          p256dh: arrayBufferToBase64url(pushSubscription.getKey('p256dh')!),
          auth: arrayBufferToBase64url(pushSubscription.getKey('auth')!),
        },
        eid: getEndpointId(), // User's device identifier (e.g., "laptop-chrome")
        createdAt: Date.now(),
      };

      // Send result back to KMS iframe
      const kmsIframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
      kmsIframe.contentWindow?.postMessage(
        {
          type: 'kms:push-subscription-result',
          requestId: data.requestId,
          subscription,
        },
        'https://kms.ats.run'
      );
    } catch (err: unknown) {
      console.error('[Parent] Push subscription failed:', err);
      const kmsIframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
      kmsIframe.contentWindow?.postMessage(
        {
          type: 'kms:push-subscription-result',
          requestId: data.requestId,
          success: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        },
        'https://kms.ats.run'
      );
    }
  }

  // Handle test notification request
  if (data?.type === 'kms:send-test-notification') {
    try {
      const jwt = data.jwt as string;
      const subscription = data.subscription as StoredPushSubscription;

      // Send test notification
      // Option A: Via relay (if connected)
      // Option B: Direct to push service (for testing)

      // For MVP, send direct to push service
      const pushEndpoint = subscription.endpoint;
      const response = await fetch(pushEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `vapid t=${jwt}, k=${data.vapidPublicKey}`,
          'Content-Type': 'application/octet-stream',
          'TTL': '60',
        },
        body: JSON.stringify({
          title: '🎉 KMS Setup Complete!',
          body: 'Your Key Management System is ready. Push notifications are working.',
          timestamp: Date.now(),
        }),
      });

      const success = response.ok;

      // Send result back to KMS iframe
      const kmsIframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
      kmsIframe.contentWindow?.postMessage(
        {
          type: 'kms:test-notification-result',
          requestId: data.requestId,
          success,
          error: success ? undefined : `HTTP ${response.status}: ${response.statusText}`,
        },
        'https://kms.ats.run'
      );
    } catch (err: unknown) {
      console.error('[Parent] Test notification failed:', err);
      const kmsIframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
      kmsIframe.contentWindow?.postMessage(
        {
          type: 'kms:test-notification-result',
          requestId: data.requestId,
          success: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        },
        'https://kms.ats.run'
      );
    }
  }
});
```

### Step 8: Update Types

**File**: `src/v2/types.ts`

Add new RPC method to `RPCMethod` type:

```typescript
export type RPCMethod =
  | 'setupPassphrase'
  | 'setupPasskey'
  | 'setupPasskeyPRF'
  | 'setupPasskeyGate'
  | 'setupWithPopup'
  | 'fullSetup' // ← NEW
  | 'unlockWithPassphrase'
  | 'unlockWithPasskey'
  // ... rest of methods
```

Add internal message types:

```typescript
/**
 * Internal message types for worker ↔ client communication
 */
export type WorkerInternalMessage =
  | { type: 'worker:setup-with-popup'; requestId: string; userId: string; popupURL: string; transportKey: string; transportKeyId: string; appSalt: string; hkdfSalt: string }
  | { type: 'worker:request-unlock'; requestId: string; userId: string }
  | { type: 'worker:request-push-subscription'; requestId: string; vapidPublicKey: string; userId: string } // ← NEW
  | { type: 'worker:send-test-notification'; requestId: string; jwt: string; subscription: StoredPushSubscription } // ← NEW
  | { type: 'worker:popup-credentials'; requestId: string; credentials: unknown }
  | { type: 'worker:popup-error'; requestId: string; reason: string }
  | { type: 'worker:unlock-credentials'; requestId: string; credentials: AuthCredentials }
  | { type: 'worker:unlock-error'; requestId: string; reason: string }
  | { type: 'worker:push-subscription-result'; requestId: string; subscription: StoredPushSubscription } // ← NEW
  | { type: 'worker:push-subscription-error'; requestId: string; reason: string } // ← NEW
  | { type: 'worker:test-notification-result'; requestId: string; success: boolean; error?: string }; // ← NEW
```

---

## Code Reuse Analysis

### ✅ Functions We'll Reuse (Zero Duplication)

1. **`handleSetupWithPopup()`** - Entire setup flow
2. **`handleSetPushSubscription()`** - Store subscription
3. **`handleCreateLease()`** - Lease creation with SessionKEK
4. **`handleIssueVAPIDJWTs()`** - Batch JWT issuance
5. **`isSetup()`** - Check if already setup
6. **`logOperation()`** - Audit logging

### 🔄 Functions We'll Modify (Minimal Changes)

1. **`setupWithEncryptedCredentials()`** - Add credentials to return value (~10 lines)
2. **`handleSetupWithPopup()`** - Handle new return value from setupWithEncryptedCredentials (~2 lines)

### ➕ New Code Required

1. **`handleFullSetup()`** - ~150 lines (orchestration logic)
2. **Client handlers** - ~80 lines (push subscription, test notification)
3. **Parent handlers** - ~100 lines (ServiceWorker integration)
4. **RPC validation** - ~30 lines
5. **Type definitions** - ~20 lines

**Total new code**: ~380 lines
**Modified existing code**: ~12 lines
**Reused existing code**: ~800 lines (5 functions)

**Code reuse ratio**: **95%** (reusing 800 lines, adding 380 lines)

---

## Error Handling

### Failure Points and Recovery

1. **Setup fails** (popup closed, credentials invalid)
   - **Recovery**: Throw error, user must retry
   - **State**: No data persisted (atomic setup)

2. **Push subscription fails** (permissions denied, browser unsupported)
   - **Recovery**: Throw error, roll back setup?
   - **Decision**: **Keep setup, fail fullSetup** (user can retry push later)
   - **Rationale**: Setup is expensive (popup flow), push is cheap (browser API)

3. **Lease creation fails** (MS derivation error, storage error)
   - **Recovery**: Throw error, setup remains
   - **User action**: Can create lease manually later

4. **JWT issuance fails** (quota exceeded, lease expired)
   - **Recovery**: Throw error, lease remains
   - **User action**: Can issue JWTs manually later

5. **Test notification fails** (network error, push service down)
   - **Recovery**: Log warning, **don't fail fullSetup**
   - **Rationale**: Setup is complete, notification is best-effort

### Atomicity Considerations

**Question**: Should fullSetup be atomic (all-or-nothing)?

**Answer**: **No, partial success is acceptable**:

1. **Setup** → If this fails, nothing else runs (good)
2. **Push subscription** → If this fails, keep setup (reusable)
3. **Lease** → If this fails, keep setup + subscription (reusable)
4. **JWTs** → If this fails, keep lease (can issue later)
5. **Test notification** → If this fails, log warning (best-effort)

**Rationale**:
- Setup is the most expensive operation (user interaction)
- Downstream operations can be retried independently
- Partial success > complete failure

---

## Testing Strategy

### Unit Tests

**File**: `tests/v2/worker.test.ts`

```typescript
describe('fullSetup', () => {
  it('should complete entire onboarding flow', async () => {
    // Mock popup flow
    const setupPromise = handleMessage(createRequest('fullSetup', {
      userId: 'user@example.com',
      autoExtend: true,
      ttlHours: 12,
    }));

    // Simulate popup providing credentials
    await simulatePopupCredentials('passphrase', 'test-passphrase-123');

    // Simulate parent providing push subscription
    await simulatePushSubscription({
      endpoint: 'https://fcm.googleapis.com/fcm/send/test',
      keys: { p256dh: '...', auth: '...' },
      eid: 'test-device',
    });

    // Simulate test notification success
    await simulateTestNotification(true);

    const response = await setupPromise;

    expect(response.error).toBeUndefined();
    expect(response.result.success).toBe(true);
    expect(response.result.enrollmentId).toBeDefined();
    expect(response.result.leaseId).toBeDefined();
    expect(response.result.jwts).toHaveLength(5);
    expect(response.result.subscription).toBeDefined();
  });

  it('should handle push subscription failure gracefully', async () => {
    const setupPromise = handleMessage(createRequest('fullSetup', {
      userId: 'user@example.com',
    }));

    await simulatePopupCredentials('passphrase', 'test-pass');
    await simulatePushSubscriptionError('Permissions denied');

    const response = await setupPromise;
    expect(response.error).toContain('Push subscription');
  });

  it('should validate TTL range', async () => {
    const response = await handleMessage(createRequest('fullSetup', {
      userId: 'user@example.com',
      ttlHours: 1000, // > 720
    }));

    expect(response.error).toContain('ttlHours');
  });
});
```

### Integration Tests

**File**: `tests/integration/full-setup.test.ts`

```typescript
describe('Full Setup Integration', () => {
  it('should complete setup and issue working JWTs', async () => {
    // Create KMS client
    const client = new KMSClient({ parentOrigin: 'http://localhost:5173' });
    await client.init();

    // Call fullSetup
    const result = await client.send({
      id: 'test-1',
      method: 'fullSetup',
      params: {
        userId: 'integration@test.com',
        autoExtend: true,
      },
    });

    expect(result.result.jwts).toHaveLength(5);

    // Verify JWTs are valid
    for (const jwt of result.result.jwts) {
      const decoded = decodeJWT(jwt.jwt);
      expect(decoded.aud).toBeDefined();
      expect(decoded.exp).toBeGreaterThan(Date.now() / 1000);
    }

    // Verify lease exists
    const leaseCheck = await client.send({
      id: 'test-2',
      method: 'verifyLease',
      params: {
        leaseId: result.result.leaseId,
      },
    });

    expect(leaseCheck.result.valid).toBe(true);
  });
});
```

### Browser Tests (Playwright)

**File**: `tests/e2e/full-setup.spec.ts`

```typescript
test('fullSetup with real WebAuthn', async ({ page }) => {
  // Navigate to test page
  await page.goto('http://localhost:5173/test');

  // Click "Full Setup" button
  await page.click('#full-setup-btn');

  // Wait for popup to open
  const popup = await page.waitForEvent('popup');

  // Interact with WebAuthn (using virtual authenticator)
  await popup.click('#kms-setup-webauthn-btn');

  // Wait for WebAuthn ceremony
  await popup.waitForSelector('#kms-setup-success', { timeout: 10000 });

  // Verify setup completed
  const result = await page.evaluate(() => {
    return (window as { fullSetupResult?: unknown }).fullSetupResult;
  });

  expect(result).toBeDefined();
  expect(result.success).toBe(true);
  expect(result.jwts).toHaveLength(5);
});
```

---

## Security Considerations

### 1. Credentials in Memory

**Risk**: Credentials held in memory during fullSetup flow (~5-10 seconds)

**Mitigation**:
- Credentials only held during orchestration
- Cleared immediately after lease creation
- Already unlocked once for setup (acceptable)
- Defense in depth: zero passphrase strings, zero PRF buffers

**Assessment**: ✅ **Low risk** - Same pattern as other operations

### 2. Test Notification Privacy

**Risk**: Test notification content might be sensitive

**Mitigation**:
- Generic message: "KMS Setup Complete"
- No user data in notification body
- No sensitive metadata exposed

**Assessment**: ✅ **No risk** - Generic content only

### 3. JWT Stashing

**Risk**: Issuing 5 JWTs upfront increases exposure window

**Mitigation**:
- Staggered expirations (9 minute intervals)
- Short base TTL (15 minutes)
- Quotas enforce usage limits
- All issuances logged in audit chain

**Assessment**: ✅ **Acceptable** - Standard practice for offline operation

### 4. Auto-Extend Default

**Risk**: `autoExtend: true` as default might surprise users

**Mitigation**:
- Explicitly documented in API
- User can override with `autoExtend: false`
- Lease still expires (not perpetual)
- Can be disabled globally in KMS settings

**Assessment**: ✅ **Acceptable** - Better UX, explicit opt-out available

---

## Success Criteria

1. ✅ User completes setup with **one authentication ceremony**
2. ✅ Push subscription created and stored
3. ✅ Lease created with autoExtend flag
4. ✅ 5 JWTs issued with staggered expirations
5. ✅ Test notification sent successfully
6. ✅ All operations logged in audit chain
7. ✅ Code reuse ≥ 90% (reuse existing functions)
8. ✅ No security regressions
9. ✅ All tests passing (unit + integration + e2e)
10. ✅ Code coverage ≥ 80%

---

## Rollout Plan

### Phase 1: Core Implementation
- Modify `setupWithEncryptedCredentials()` to return credentials
- Implement `handleFullSetup()` orchestration
- Add worker message handlers
- Add client handlers

### Phase 2: Parent Integration
- Add ServiceWorker integration for push subscription
- Add test notification sender
- Update parent UI to show "Quick Setup" button

### Phase 3: Testing
- Unit tests for orchestration logic
- Integration tests for end-to-end flow
- Browser tests with real WebAuthn

### Phase 4: Documentation
- Update API docs with fullSetup method
- Add usage examples to README
- Document error handling and recovery

---

## Open Questions

### 1. Should fullSetup be idempotent?

**Question**: What if user calls fullSetup twice?

**Options**:
- **A**: Throw error if already setup ✅ **Recommended**
- **B**: Silently create new lease, keep existing setup
- **C**: Return existing setup + create new lease

**Decision**: **Option A** - Fail fast, explicit intent

### 2. Should test notification be mandatory?

**Question**: If test notification fails, should fullSetup fail?

**Options**:
- **A**: Fail fullSetup (strict validation) ❌
- **B**: Log warning, continue (best-effort) ✅ **Recommended**

**Decision**: **Option B** - Setup complete, notification is bonus

### 3. Should we support custom notification content?

**Question**: Allow user to customize test notification message?

**Options**:
- **A**: Fixed message (simple) ✅ **Recommended for MVP**
- **B**: Customizable message (flexible)

**Decision**: **Option A for MVP**, can add customization later

### 4. Should credentials be zeroed aggressively?

**Question**: Should we zero credentials immediately after lease creation?

**Options**:
- **A**: Zero immediately after lease (aggressive) ✅ **Recommended**
- **B**: Let GC handle it (lazy)

**Decision**: **Option A** - Defense in depth, explicit cleanup

---

## References

- **VAPID Leases Design**: [docs/architecture/crypto/V2/design/12-vapid-leases.md](../../../architecture/crypto/V2/design/12-vapid-leases.md)
- **SessionKEK Architecture**: [docs/architecture/crypto/V2/design/12-vapid-leases.md#sessionkek-architecture](../../../architecture/crypto/V2/design/12-vapid-leases.md#sessionkek-architecture)
- **Unlock Context**: [docs/architecture/crypto/V2/design/03-unlock-context.md](../../../architecture/crypto/V2/design/03-unlock-context.md)
- **Master Secret**: [docs/architecture/crypto/V2/design/02-master-secret.md](../../../architecture/crypto/V2/design/02-master-secret.md)
- **Audit Log**: [docs/architecture/crypto/V2/design/05-audit-log.md](../../../architecture/crypto/V2/design/05-audit-log.md)

---

**Status**: Ready for implementation
**Estimated Effort**: 2-3 days
**Code Reuse**: 95%
**Risk Level**: Low (composing existing, tested functions)
