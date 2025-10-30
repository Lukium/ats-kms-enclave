# Push Notifications Implementation Plan

**Status**: Planning Phase
**Created**: 2025-10-30
**Updated**: 2025-10-30 (Simplified Phase C - removed separate mock server)
**Target**: Phase 1 Full Demo with real Web Push subscriptions

---

## Revision History

### 2025-10-30 Update: Simplified Mock Push Approach
- **Changed**: Phase C no longer creates separate `mock-push-server.ts` file
- **Rationale**: Parent PWA can validate JWTs and send mock pushes directly to service worker
- **Benefits**:
  - Simpler architecture (fewer files)
  - Self-contained demo (everything in parent.ts)
  - Still demonstrates complete security flow (JWT signing → validation → delivery)
  - More educational (console logs show validation steps)
- **Impact**: Reduced Phase C timeline from 1-2 days to 1 day

### 2025-10-30 Update: Added Push Service Whitelist Validation
- **Added**: Endpoint validation in `validatePushSubscription()` now whitelists known push services
- **Rationale**: Security - prevents malicious endpoint injection
- **Whitelisted services**:
  - FCM (Google) - Chrome, Edge, Opera
  - APNs (Apple) - Safari
  - Mozilla Push - Firefox
  - WNS (Microsoft) - Legacy Edge
- **Impact**: More secure subscription storage; clear error messages for unsupported endpoints

### 2025-10-30 Update: Simplified to Single Subscription + Auto-Populate Leases
- **Changed**: `WrappedKey.subscription` is now **singular** (not an array)
- **Rationale**: One KMS instance = one device = one push subscription
- **Changed**: `LeaseRecord` no longer has `subs` array - leases automatically use subscription from VAPID key
- **Changed**: `createLease()` no longer requires `subs` parameter - worker reads from VAPID key
- **Changed**: `issueVAPIDJWT()` no longer requires `endpoint` parameter - worker reads from VAPID key
- **Benefits**:
  - Simpler API (no array operations, fewer parameters)
  - No redundant data (single source of truth)
  - Clearer semantics (one device = one subscription)
  - More secure (parent can't specify arbitrary endpoints)
  - Auto-populates lease and JWT with current subscription
- **Impact**: Cleaner implementation; fewer parameters to manage; more secure

---

## Executive Summary

This plan adds **real Web Push notification functionality** to the Phase 1 Full Demo. Instead of using dummy subscription data, the demo will:

1. Create actual `PushSubscription` objects via `PushManager.subscribe()`
2. Store subscriptions with VAPID key records (not in leases)
3. Register a service worker to receive and display push events
4. Validate VAPID JWTs in the parent PWA (simulating relay server validation)
5. Send mock push notifications directly from parent to service worker
6. Demonstrate the complete end-to-end flow: subscribe → create lease → issue JWT → validate JWT → send push → display notification

**Key Architectural Decision**: Subscriptions are **stored with the VAPID key record**, not in leases, because:
- Subscriptions are tightly coupled to the VAPID public key
- When VAPID key is regenerated, all subscriptions become invalid
- Leases have 24-hour TTL; subscriptions should persist longer
- This avoids requiring re-subscription every 24 hours

---

## Current State Analysis

### Existing Data Structures

#### `WrappedKey` (src/v2/types.ts:110-121)
```typescript
export interface WrappedKey {
  kid: string;                    // JWK thumbprint
  kmsVersion: number;
  wrappedKey: ArrayBuffer;        // MEK-wrapped private key
  iv: ArrayBuffer;
  aad: ArrayBuffer;
  publicKeyRaw?: ArrayBuffer;     // 65-byte uncompressed P-256 key
  alg: string;                    // "ES256"
  purpose: string;                // "vapid"
  createdAt: number;
  lastUsedAt?: number;
}
```

**Current State**: No field for storing push subscriptions.

#### `LeaseRecord` (src/v2/types.ts:286-305)
```typescript
export interface LeaseRecord {
  leaseId: string;
  userId: string;
  subs: Array<{                   // Dummy subscription data
    url: string;                  // Push endpoint URL
    aud: string;                  // Audience (push service origin)
    eid: string;                  // Endpoint ID (user-defined)
  }>;
  ttlHours: number;
  createdAt: number;
  exp: number;
  quotas: QuotaState;
  wrappedLeaseKey: ArrayBuffer;
  wrappedLeaseKeyIV: ArrayBuffer;
  leaseSalt: ArrayBuffer;
  kid: string;
  lakDelegationCert: AuditDelegationCert;
}
```

**Current State**: `subs` array contains **dummy data** (not real `PushSubscription` objects).

#### Current Demo Flow (example/phase-1/full/parent.ts:495-560)
```typescript
// Current dummy subscriptions
const subs = [
  {
    url: 'https://demo-push-endpoint.example.com/subscription-1',
    aud: 'https://demo-push-endpoint.example.com',
    eid: 'sub-001',
  },
];

const result = await kmsUser.createLease({ userId, subs, ttlHours });
```

**Problem**: No actual push subscription is created, so notifications cannot be received.

---

## Proposed Architecture

### 1. Subscription Storage Strategy

**Decision**: Store `PushSubscription` objects **with the VAPID key record**.

**New Data Structure**:

```typescript
// src/v2/types.ts - Add new interface
export interface StoredPushSubscription {
  endpoint: string;               // Push service endpoint URL
  expirationTime: number | null;  // When subscription expires (milliseconds)
  keys: {
    p256dh: string;               // Client public key (base64url)
    auth: string;                 // Authentication secret (base64url)
  };
  eid: string;                    // Endpoint ID (user-defined, e.g., "laptop-chrome")
  createdAt: number;              // When subscription was created
}

// src/v2/types.ts - Extend WrappedKey
export interface WrappedKey {
  // ... existing fields ...
  subscription?: StoredPushSubscription; // NEW: Single active push subscription (optional)
}
```

**Why this structure?**
- `StoredPushSubscription` matches the shape of `PushSubscription` from the Web Push API
- `eid` (endpoint ID) allows labeling the device ("laptop-chrome", "phone-firefox")
- `createdAt` helps track subscription age
- **Single subscription** (not array) because one KMS instance = one device = one subscription
- Optional field for backward compatibility with existing VAPID keys

### 2. Lease Schema Update

**Current Problem**: `LeaseRecord.subs` contains dummy subscription data passed from parent.

**Solution**: **Remove `subs` array entirely** - leases automatically use subscription from VAPID key.

```typescript
// src/v2/types.ts - Update LeaseRecord
export interface LeaseRecord {
  leaseId: string;
  userId: string;
  // REMOVED: subs array - no longer needed
  ttlHours: number;
  createdAt: number;
  exp: number;
  quotas: QuotaState;
  wrappedLeaseKey: ArrayBuffer;
  wrappedLeaseKeyIV: ArrayBuffer;
  leaseSalt: ArrayBuffer;
  kid: string;
  lakDelegationCert: AuditDelegationCert;
}
```

**Why?**
- **Single source of truth**: Subscription lives in VAPID key record
- **No redundancy**: Lease doesn't duplicate subscription data
- **Automatic**: Worker reads subscription from VAPID key when creating lease
- **Simpler**: Parent doesn't need to pass subscription info to `createLease()`
- When VAPID key is regenerated, subscription is deleted automatically

### 3. Storage API Extensions

**New functions to add to `src/v2/storage.ts`**:

```typescript
/**
 * Set or update the push subscription for the VAPID key
 * Replaces any existing subscription
 * Throws if VAPID key doesn't exist
 */
export async function setPushSubscription(
  subscription: StoredPushSubscription
): Promise<void>;

/**
 * Remove the push subscription from the VAPID key
 * Silent if no subscription exists
 */
export async function removePushSubscription(): Promise<void>;

/**
 * Get the push subscription for the VAPID key
 * Returns null if no VAPID key or no subscription
 */
export async function getPushSubscription(): Promise<StoredPushSubscription | null>;
```

**Implementation notes**:
- `setPushSubscription`: Load VAPID key, set `subscription` field, save (replaces existing)
- `removePushSubscription`: Load VAPID key, delete `subscription` field, save
- `getPushSubscription`: Load VAPID key, return `subscription ?? null`
- All functions are async and use the existing `getDB()` pattern
- Simple singular operations (no array management needed)

### 4. Worker RPC API Extensions

**New RPC methods to add to `src/v2/worker.ts`**:

```typescript
// RPC method: 'setPushSubscription'
// Params: { subscription: StoredPushSubscription, credentials: AuthCredentials }
// Response: { success: true }
// Audit: Yes (operation: 'setPushSubscription')

// RPC method: 'removePushSubscription'
// Params: { credentials: AuthCredentials }
// Response: { success: true }
// Audit: Yes (operation: 'removePushSubscription')

// RPC method: 'getPushSubscription'
// Params: { credentials: AuthCredentials }
// Response: { subscription: StoredPushSubscription | null }
// Audit: No (read-only operation)
```

**RPC Validation** (add to `src/v2/rpc-validation.ts`):

```typescript
export function validateSetPushSubscription(params: unknown): {
  subscription: StoredPushSubscription;
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('setPushSubscription', params);
  return {
    subscription: validatePushSubscription('setPushSubscription', p.subscription),
    credentials: validateAuthCredentials('setPushSubscription', p.credentials),
  };
}

export function validateRemovePushSubscription(params: unknown): {
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('removePushSubscription', params);
  return {
    credentials: validateAuthCredentials('removePushSubscription', p.credentials),
  };
}

export function validateGetPushSubscription(params: unknown): {
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('getPushSubscription', params);
  return {
    credentials: validateAuthCredentials('getPushSubscription', p.credentials),
  };
}

function validatePushSubscription(
  method: string,
  value: unknown
): StoredPushSubscription {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${method}: subscription must be an object`);
  }
  const sub = value as Partial<StoredPushSubscription>;

  // Validate endpoint
  if (typeof sub.endpoint !== 'string' || !sub.endpoint) {
    throw new Error(`${method}: subscription.endpoint must be a non-empty string`);
  }

  // Validate HTTPS
  if (!sub.endpoint.startsWith('https://')) {
    throw new Error(`${method}: subscription.endpoint must use HTTPS`);
  }

  // Whitelist known push services (security: prevent malicious endpoints)
  const knownPushServices = [
    'fcm.googleapis.com',                    // Google FCM (Chrome, Edge, Opera, etc.)
    'web.push.apple.com',                    // Apple APNs (Safari)
    'updates.push.services.mozilla.com',     // Mozilla Push (Firefox)
    'notify.windows.com',                    // Windows Push (legacy Edge)
  ];

  const endpointUrl = new URL(sub.endpoint);
  const isKnownService = knownPushServices.some(service =>
    endpointUrl.hostname === service || endpointUrl.hostname.endsWith(`.${service}`)
  );

  if (!isKnownService) {
    throw new Error(
      `${method}: subscription.endpoint must be from a known push service ` +
      `(FCM, APNs, Mozilla Push, or WNS). Got: ${endpointUrl.hostname}`
    );
  }

  // Validate expiration time
  if (sub.expirationTime !== null && typeof sub.expirationTime !== 'number') {
    throw new Error(`${method}: subscription.expirationTime must be null or number`);
  }

  // Validate keys
  if (typeof sub.keys !== 'object' || sub.keys === null) {
    throw new Error(`${method}: subscription.keys must be an object`);
  }
  if (typeof sub.keys.p256dh !== 'string' || !sub.keys.p256dh) {
    throw new Error(`${method}: subscription.keys.p256dh must be a non-empty string`);
  }
  if (typeof sub.keys.auth !== 'string' || !sub.keys.auth) {
    throw new Error(`${method}: subscription.keys.auth must be a non-empty string`);
  }

  // Validate endpoint ID
  if (typeof sub.eid !== 'string' || !sub.eid) {
    throw new Error(`${method}: subscription.eid must be a non-empty string`);
  }

  // Validate creation timestamp
  if (typeof sub.createdAt !== 'number') {
    throw new Error(`${method}: subscription.createdAt must be a number`);
  }

  return sub as StoredPushSubscription;
}
```

### 5. Client API Extensions

**New methods to add to `src/v2/client.ts` (KMSUser class)**:

```typescript
/**
 * Set/replace the push subscription for the VAPID key (singular)
 * Requires authentication (triggers modal if locked)
 */
async setPushSubscription(
  subscription: StoredPushSubscription
): Promise<{ success: boolean }>;

/**
 * Remove the push subscription from the VAPID key
 * Requires authentication (triggers modal if locked)
 */
async removePushSubscription(): Promise<{ success: boolean }>;

/**
 * Get the push subscription from the VAPID key
 * Requires authentication (triggers modal if locked)
 */
async getPushSubscription(): Promise<{ subscription: StoredPushSubscription | null }>;
```

**Usage pattern**:
```typescript
// Parent PWA calls PushManager.subscribe()
const rawSub = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: vapidPublicKeyUint8Array,
});

// Convert to StoredPushSubscription
const subscription: StoredPushSubscription = {
  endpoint: rawSub.endpoint,
  expirationTime: rawSub.expirationTime,
  keys: {
    p256dh: arrayBufferToBase64Url(rawSub.getKey('p256dh')),
    auth: arrayBufferToBase64Url(rawSub.getKey('auth')),
  },
  eid: 'laptop-chrome', // User-defined label
  createdAt: Date.now(),
};

// Store in KMS (replaces any existing subscription)
await kmsUser.setPushSubscription(subscription);
```

---

## Implementation Phases

### Phase A: Core Storage and API Layer

**Goal**: Add subscription storage to VAPID key records and expose RPC/client APIs.

**Files to Modify**:

1. **src/v2/types.ts**
   - Add `StoredPushSubscription` interface
   - Add `subscriptions?: StoredPushSubscription[]` field to `WrappedKey`

2. **src/v2/storage.ts**
   - Add `addPushSubscription()` function
   - Add `removePushSubscription()` function
   - Add `getPushSubscriptions()` function
   - Add `getPushSubscription()` function

3. **src/v2/rpc-validation.ts**
   - Add `validateAddPushSubscription()` function
   - Add `validateRemovePushSubscription()` function
   - Add `validateGetPushSubscriptions()` function
   - Add `validatePushSubscription()` helper

4. **src/v2/worker.ts**
   - Add case for `'addPushSubscription'` in message handler
   - Add case for `'removePushSubscription'` in message handler
   - Add case for `'getPushSubscriptions'` in message handler
   - Add handler functions: `handleAddPushSubscription()`, `handleRemovePushSubscription()`, `handleGetPushSubscriptions()`

5. **src/v2/client.ts**
   - Add `addPushSubscription()` method to `KMSUser` class
   - Add `removePushSubscription()` method to `KMSUser` class
   - Add `getPushSubscriptions()` method to `KMSUser` class

**Test Coverage**:
- Unit tests for storage functions (add/remove/get subscriptions)
- RPC validation tests (valid/invalid subscription objects)
- Worker handler tests (end-to-end RPC flow)
- Client tests (mocked iframe communication)

**Acceptance Criteria**:
- ✅ Can store subscriptions with VAPID key record
- ✅ Can retrieve subscriptions by endpoint
- ✅ Can list all subscriptions
- ✅ Can remove subscriptions
- ✅ Duplicate subscriptions are rejected
- ✅ 80%+ test coverage maintained

---

### Phase B: Service Worker and Push Registration

**Goal**: Add service worker to receive push events and update demo to create real subscriptions.

**Files to Create**:

1. **example/phase-1/full/service-worker.js**
   ```javascript
   // Service worker to handle push events
   self.addEventListener('push', (event) => {
     const data = event.data ? event.data.json() : {};
     const title = data.title || 'ATS KMS Demo Push';
     const options = {
       body: data.body || 'Test notification from KMS demo',
       icon: data.icon || '/icon.png',
       badge: data.badge || '/badge.png',
       tag: data.tag || 'ats-kms-demo',
       data: data.data || {},
     };
     event.waitUntil(self.registration.showNotification(title, options));
   });

   self.addEventListener('notificationclick', (event) => {
     event.notification.close();
     event.waitUntil(clients.openWindow('/'));
   });
   ```

2. **example/phase-1/full/push-utils.ts**
   ```typescript
   // Utility functions for push subscription management
   export async function registerServiceWorker(): Promise<ServiceWorkerRegistration>;
   export async function subscribeToPush(
     registration: ServiceWorkerRegistration,
     vapidPublicKey: Uint8Array
   ): Promise<PushSubscription>;
   export async function unsubscribeFromPush(
     registration: ServiceWorkerRegistration
   ): Promise<void>;
   export function convertPushSubscriptionToStored(
     rawSub: PushSubscription,
     eid: string
   ): StoredPushSubscription;
   ```

**Files to Modify**:

3. **example/phase-1/full/parent.ts**
   - Import push utilities
   - Add service worker registration on page load
   - Update `createLease()` function to:
     1. Call `PushManager.subscribe()` to get real subscription
     2. Call `kmsUser.addPushSubscription()` to store in KMS
     3. Pass subscription endpoints to `createLease()` (not full objects)
   - Add "Subscribe to Push" button in UI
   - Add "Unsubscribe from Push" button in UI
   - Display active subscriptions in VAPID key info section

4. **example/phase-1/full/index.html**
   - Add push subscription UI elements
   - Add notification permission request button

**Implementation Details**:

```typescript
// In parent.ts - Service worker registration
async function initPushSupport(): Promise<void> {
  if (!('serviceWorker' in navigator)) {
    console.warn('[Full Demo] Service workers not supported');
    return;
  }
  if (!('PushManager' in window)) {
    console.warn('[Full Demo] Push API not supported');
    return;
  }

  try {
    await registerServiceWorker();
    console.log('[Full Demo] Service worker registered');
  } catch (error) {
    console.error('[Full Demo] Service worker registration failed:', error);
  }
}

// Updated createLease() function
async function createLease(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  try {
    console.log('[Full Demo] Creating VAPID lease...');

    // Get VAPID public key
    const vapidInfo = await kmsUser.getVAPIDKey();
    if (!vapidInfo) {
      throw new Error('No VAPID key exists');
    }

    // Get service worker registration
    const registration = await navigator.serviceWorker.ready;

    // Create real push subscription
    const rawSub = await subscribeToPush(
      registration,
      base64UrlToUint8Array(vapidInfo.publicKey)
    );

    // Convert to stored format
    const eid = 'demo-device'; // Or prompt user for device name
    const storedSub = convertPushSubscriptionToStored(rawSub, eid);

    // Store subscription in KMS (separate from lease - stored with VAPID key)
    await kmsUser.setPushSubscription(storedSub);

    // Create lease (NO subs parameter - worker reads subscription from VAPID key)
    const userId = 'demouser@ats.run';
    const ttlHours = 24;

    const result = await kmsUser.createLease({ userId, ttlHours });
    console.log('[Full Demo] Lease created:', result);

    // Display success
    // ... (existing UI update code)
  } catch (error) {
    console.error('[Full Demo] Lease creation failed:', error);
    alert(`Lease creation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}
```

**Test Coverage**:
- Manual browser testing (push notifications require real browser)
- Integration test for service worker registration
- Unit tests for push utility functions

**Acceptance Criteria**:
- ✅ Service worker registers successfully
- ✅ Push permission can be requested
- ✅ Real `PushSubscription` is created via `PushManager.subscribe()`
- ✅ Subscription is stored in KMS VAPID key record
- ✅ Lease references subscription by endpoint
- ✅ UI displays active subscriptions

---

### Phase C: JWT Validation and Mock Push Delivery

**Goal**: Add JWT validation in parent PWA and send mock push notifications directly to service worker.

**Why in-parent validation?**
- Simulates the relay server's role (validates JWT before forwarding to push service)
- Demonstrates complete security flow: signing → validation → delivery
- Self-contained: no separate mock server needed
- Educational: users can see validation steps in console

**Approach**: Parent PWA validates JWT, then sends mock push to service worker via postMessage.

**Files to Modify**:

1. **example/phase-1/full/parent.ts**

   Add JWT validation utility:
   ```typescript
   /**
    * Validate VAPID JWT (simulates relay server validation)
    *
    * Validates:
    * - JWT format (3 parts: header.payload.signature)
    * - Algorithm (must be ES256)
    * - Claims (exp, aud, sub)
    * - Signature (ECDSA-P256 verification against VAPID public key)
    */
   async function validateVAPIDJWT(
     jwt: string,
     expectedAudience: string
   ): Promise<{
     valid: boolean;
     reason?: string;
     claims?: Record<string, unknown>;
   }> {
     try {
       // Split JWT into parts
       const parts = jwt.split('.');
       if (parts.length !== 3) {
         return { valid: false, reason: 'Invalid JWT format (expected 3 parts)' };
       }

       const [headerB64, payloadB64, signatureB64] = parts;

       // Decode and validate header
       const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')));
       if (header.alg !== 'ES256') {
         return { valid: false, reason: `Unsupported algorithm: ${header.alg}` };
       }

       // Decode and validate payload
       const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
       const now = Math.floor(Date.now() / 1000);

       // Check expiration
       if (!payload.exp || typeof payload.exp !== 'number') {
         return { valid: false, reason: 'Missing exp claim' };
       }
       if (payload.exp < now) {
         return { valid: false, reason: 'JWT expired' };
       }

       // Check audience
       if (!payload.aud || payload.aud !== expectedAudience) {
         return {
           valid: false,
           reason: `Invalid audience (expected ${expectedAudience}, got ${payload.aud})`
         };
       }

       // Check subject
       if (!payload.sub || typeof payload.sub !== 'string') {
         return { valid: false, reason: 'Missing sub claim' };
       }

       // Get VAPID public key for signature verification
       const vapidInfo = await kmsUser.getVAPIDKey();
       if (!vapidInfo) {
         return { valid: false, reason: 'No VAPID key available' };
       }

       // Import public key
       const publicKeyBytes = base64UrlToUint8Array(vapidInfo.publicKey);
       const publicKey = await crypto.subtle.importKey(
         'raw',
         publicKeyBytes,
         { name: 'ECDSA', namedCurve: 'P-256' },
         false,
         ['verify']
       );

       // Verify signature
       const signatureBytes = base64UrlToUint8Array(signatureB64);
       const dataToVerify = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

       const valid = await crypto.subtle.verify(
         { name: 'ECDSA', hash: 'SHA-256' },
         publicKey,
         signatureBytes,
         dataToVerify
       );

       if (!valid) {
         return { valid: false, reason: 'Signature verification failed' };
       }

       return { valid: true, claims: payload };
     } catch (error) {
       return {
         valid: false,
         reason: `Validation error: ${error instanceof Error ? error.message : String(error)}`
       };
     }
   }
   ```

   Add send test push function:
   ```typescript
   async function sendTestPush(): Promise<void> {
     try {
       console.log('[Full Demo] Sending test push...');

       // Get subscription to retrieve endpoint for validation
       const sub = await kmsUser.getPushSubscription();
       if (!sub) {
         throw new Error('No push subscription available');
       }

       const pushServiceUrl = new URL(sub.endpoint);

       // Issue JWT - worker automatically uses subscription from VAPID key
       const leaseId = '[get from current lease]';
       const jwtResult = await kmsUser.issueVAPIDJWT({
         leaseId,
         // NO endpoint parameter needed - worker reads from VAPID key!
       });

       console.log('[Full Demo] JWT issued:', jwtResult.jwt.substring(0, 50) + '...');

       // **VALIDATE JWT (simulates relay server validation)**
       console.log('[Full Demo] Validating JWT...');
       const validation = await validateVAPIDJWT(jwtResult.jwt, pushServiceUrl.origin);

       if (!validation.valid) {
         throw new Error(`JWT validation failed: ${validation.reason}`);
       }

       console.log('[Full Demo] ✅ JWT validated successfully', validation.claims);

       // Send mock push to service worker
       const registration = await navigator.serviceWorker.ready;
       if (!registration.active) {
         throw new Error('No active service worker');
       }

       const messageChannel = new MessageChannel();
       await new Promise((resolve, reject) => {
         messageChannel.port1.onmessage = (event) => {
           if (event.data.success) {
             resolve(event.data);
           } else {
             reject(new Error(event.data.error));
           }
         };

         registration.active.postMessage(
           {
             type: 'mock-push',
             endpoint: sub.endpoint,
             jwt: jwtResult.jwt,
             payload: {
               title: 'ATS KMS Demo',
               body: 'Test notification - JWT validated successfully!',
               tag: 'test-push',
               data: { timestamp: Date.now() },
             },
           },
           [messageChannel.port2]
         );
       });

       console.log('[Full Demo] ✅ Push notification sent successfully');
       alert('Push notification sent! Check your notifications.\n\nJWT was validated before delivery.');
     } catch (error) {
       console.error('[Full Demo] Failed to send push:', error);
       alert(`Push send failed: ${error instanceof Error ? error.message : String(error)}`);
     }
   }
   ```

   Update service worker message handler:
   ```javascript
   // In service-worker.js - Add message handler for mock pushes
   self.addEventListener('message', (event) => {
     if (event.data.type === 'mock-push') {
       const { payload } = event.data;
       const title = payload.title || 'ATS KMS Demo Push';
       const options = {
         body: payload.body || 'Test notification',
         icon: payload.icon,
         badge: payload.badge,
         tag: payload.tag || 'ats-kms-demo',
         data: payload.data || {},
       };

       event.waitUntil(
         self.registration.showNotification(title, options).then(() => {
           event.ports[0].postMessage({ success: true });
         }).catch((error) => {
           event.ports[0].postMessage({ success: false, error: error.message });
         })
       );
     }
   });
   ```

   Add "Send Test Push" button to operations section in index.html

**What Gets Validated**:
1. ✅ JWT format (3 parts: header.payload.signature)
2. ✅ Algorithm (must be ES256)
3. ✅ Expiration (`exp` claim must be in future)
4. ✅ Audience (`aud` claim must match push service origin)
5. ✅ Subject (`sub` claim must be present)
6. ✅ Signature (ECDSA-P256 verification against VAPID public key)

**Test Coverage**:
- Manual browser testing (notifications require user interaction)
- Unit tests for JWT validation logic (can test in Node.js with WebCrypto polyfill)
- Integration test for service worker message handling

**Acceptance Criteria**:
- ✅ JWT validation function catches all invalid JWTs (format, claims, signature)
- ✅ Validation logs detailed output to console
- ✅ Service worker receives mock push message after successful validation
- ✅ Browser displays notification with correct content
- ✅ Notification click opens demo page
- ✅ UI provides "Send Test Push" button
- ✅ User sees clear success/error messages

---

### Phase D: UI Enhancements and Documentation

**Goal**: Polish the UI, add subscription management features, and document the flow.

**Files to Modify**:

1. **example/phase-1/full/parent.ts**
   - Add subscription list display in VAPID key info section
   - Add "Unsubscribe" button for each subscription
   - Add "Add New Subscription" button (prompts for device name)
   - Update `displayVAPIDKeyInfo()` to show subscriptions
   - Add subscription expiration warnings

2. **example/phase-1/full/styles.css**
   - Add styles for subscription cards
   - Add styles for notification permission prompt
   - Add styles for mock push controls

3. **example/phase-1/full/README.md**
   - Document new push notification features
   - Add screenshots/diagrams of push flow
   - Document browser compatibility requirements
   - Add troubleshooting guide

**UI Enhancements**:

```typescript
// Display subscriptions in VAPID key info
async function displayVAPIDKeyInfo(): Promise<void> {
  // ... existing code ...

  // Add subscriptions section
  const subs = await kmsUser.getPushSubscriptions();
  if (subs.length > 0) {
    subscriptionsHTML = `
      <div class="subscriptions-section">
        <h4>📱 Active Push Subscriptions (${subs.length})</h4>
        ${subs.map(sub => `
          <div class="subscription-card">
            <div class="subscription-label">${sub.eid}</div>
            <div class="subscription-endpoint">${truncateEndpoint(sub.endpoint)}</div>
            <div class="subscription-meta">
              Created: ${new Date(sub.createdAt).toLocaleString()}
              ${sub.expirationTime ? `<br>Expires: ${new Date(sub.expirationTime).toLocaleString()}` : ''}
            </div>
            <button class="unsubscribe-btn" data-endpoint="${sub.endpoint}">
              🗑️ Remove
            </button>
          </div>
        `).join('')}
      </div>
    `;
  }

  // ... rest of display logic ...
}
```

**Documentation Additions**:

4. **example/phase-1/full/README.md** - Add new sections:

```markdown
## Push Notifications

The Full Demo now includes **real Web Push notification support**:

### Features

- ✅ Real push subscriptions via `PushManager.subscribe()`
- ✅ Subscriptions stored with VAPID key (persist beyond lease expiration)
- ✅ Service worker registration for background notifications
- ✅ Mock push server for testing (no backend required)
- ✅ Multiple subscriptions per user (e.g., laptop + phone)
- ✅ Subscription management UI (add/remove subscriptions)

### Push Flow

1. **Subscribe**: Click "Create Lease" → Browser requests notification permission → Creates push subscription → Stores in KMS
2. **Create Lease**: Lease references subscription endpoints (24-hour TTL)
3. **Issue JWT**: Click "Issue JWTs" → KMS signs JWT for push endpoint
4. **Send Push**: Click "Send Test Push" → Mock server sends notification → Service worker displays it

### Browser Requirements

- Chrome/Edge 120+ (recommended)
- Firefox 120+ (supported)
- Safari 16.4+ on macOS/iOS (supported)
- Service workers enabled
- Notification permission granted

### Troubleshooting

**"Service worker registration failed"**
- Ensure you're accessing via `http://localhost` (not file://)
- Check browser console for detailed error

**"Push subscription failed"**
- Grant notification permission when prompted
- Check if third-party cookies are blocked (some browsers require)

**"No notification displayed"**
- Ensure notification permission is granted
- Check browser notification settings (may be blocked at OS level)
- Try opening browser notification tray manually
```

**Test Coverage**:
- Manual UI testing for all subscription operations
- Accessibility testing (keyboard navigation, screen readers)
- Cross-browser testing (Chrome, Firefox, Safari)

**Acceptance Criteria**:
- ✅ Subscriptions displayed in VAPID key info section
- ✅ Can add/remove subscriptions via UI
- ✅ Subscription expiration warnings displayed
- ✅ Complete documentation with troubleshooting guide
- ✅ UI is polished and intuitive

---

## Migration and Backward Compatibility

### Data Migration

**No migration needed** because:
- `WrappedKey.subscriptions` field is optional (`subscriptions?: StoredPushSubscription[]`)
- Existing VAPID keys without subscriptions will be treated as having empty array
- New field is additive, doesn't break existing data

**Forward compatibility**:
```typescript
// In storage.ts - When loading VAPID key
export async function getWrappedKey(kid: string): Promise<WrappedKey | null> {
  const db = await getDB();
  const tx = db.transaction('keys', 'readonly');
  const store = tx.objectStore('keys');
  const result = await promisifyRequest<WrappedKey>(store.get(kid));

  // Ensure subscriptions array exists (backward compatibility)
  if (result && !result.subscriptions) {
    result.subscriptions = [];
  }

  return result ?? null;
}
```

### Lease Schema Compatibility

**Current `LeaseRecord.subs` structure**:
```typescript
subs: Array<{
  url: string;    // Dummy endpoint (currently)
  aud: string;    // Push service origin
  eid: string;    // Endpoint ID
}>;
```

**New `LeaseRecord.subs` structure**:
```typescript
subs: Array<{
  endpoint: string;  // RENAMED: Real push endpoint URL
  aud: string;       // UNCHANGED: Push service origin
  eid: string;       // UNCHANGED: Endpoint ID
}>;
```

**Breaking change**: Field `url` renamed to `endpoint`.

**Migration strategy**:
1. Update all code to use `endpoint` instead of `url`
2. Existing leases with `url` will fail validation
3. This is acceptable because:
   - Demo is in development phase
   - Leases expire after 24 hours anyway
   - No production users yet

**If backward compatibility is required**:
```typescript
// In rpc-validation.ts - Support both field names
function validateSubscriptions(method: string, value: unknown): Array<{
  endpoint: string;
  aud: string;
  eid: string;
}> {
  // ... validation logic ...
  return subs.map(sub => ({
    endpoint: sub.endpoint || sub.url, // Support both field names
    aud: sub.aud,
    eid: sub.eid,
  }));
}
```

---

## Testing Strategy

### Unit Tests

**New test files to create**:

1. **tests/v2/storage-push-subscriptions.test.ts**
   - Test `addPushSubscription()` with valid subscription
   - Test duplicate subscription rejection
   - Test `removePushSubscription()` removes correctly
   - Test `getPushSubscriptions()` returns all subscriptions
   - Test `getPushSubscription()` finds by endpoint
   - Test subscriptions persist with VAPID key
   - Test subscriptions deleted when VAPID key regenerated

2. **tests/v2/rpc-validation-push.test.ts**
   - Test `validateAddPushSubscription()` with valid input
   - Test validation rejects missing fields
   - Test validation rejects invalid types
   - Test validation rejects empty strings
   - Test validation accepts null expirationTime

3. **tests/v2/worker-push-subscriptions.test.ts**
   - Test `addPushSubscription` RPC method
   - Test `removePushSubscription` RPC method
   - Test `getPushSubscriptions` RPC method
   - Test audit entries created for add/remove operations
   - Test authentication required for all operations

4. **tests/v2/client-push-subscriptions.test.ts**
   - Test `KMSUser.addPushSubscription()` sends correct RPC
   - Test `KMSUser.removePushSubscription()` sends correct RPC
   - Test `KMSUser.getPushSubscriptions()` sends correct RPC
   - Test authentication flow triggered when locked

**Coverage goal**: 80%+ for all new code.

### Integration Tests

**Demo-specific tests** (manual testing required for browser APIs):

1. **Service worker registration**
   - Service worker installs successfully
   - Service worker activates and takes control
   - Service worker survives page reload

2. **Push subscription flow**
   - Notification permission can be requested
   - `PushManager.subscribe()` creates subscription
   - Subscription stored in KMS successfully
   - Subscription appears in UI

3. **Push delivery**
   - Mock push server validates JWT
   - Service worker receives push message
   - Notification displayed with correct content
   - Notification click opens correct URL

4. **Subscription lifecycle**
   - Can add multiple subscriptions
   - Can remove specific subscription
   - Subscriptions persist after page reload
   - Subscriptions deleted when VAPID key regenerated

### Browser Compatibility Testing

**Target browsers**:
- Chrome 120+ (primary)
- Firefox 120+ (secondary)
- Safari 17+ macOS (if available)
- Chrome Android (if available)

**Test checklist**:
- ✅ Service worker registration
- ✅ Push subscription creation
- ✅ Notification permission flow
- ✅ Notification display
- ✅ Notification click handling
- ✅ Subscription persistence

---

## File Structure Summary

```
ats-kms/
├── src/v2/
│   ├── types.ts                          # MODIFY: Add StoredPushSubscription interface
│   ├── storage.ts                        # MODIFY: Add push subscription storage functions
│   ├── rpc-validation.ts                 # MODIFY: Add push subscription validators
│   ├── worker.ts                         # MODIFY: Add push subscription RPC handlers
│   └── client.ts                         # MODIFY: Add push subscription client methods
│
├── example/phase-1/full/
│   ├── index.html                        # MODIFY: Add push subscription UI elements
│   ├── parent.ts                         # MODIFY: Integrate push flow + JWT validation
│   ├── styles.css                        # MODIFY: Add subscription card styles
│   ├── service-worker.js                 # CREATE: Service worker for push events
│   ├── push-utils.ts                     # CREATE: Push subscription utilities
│   └── README.md                         # MODIFY: Document push notification features
│
├── tests/v2/
│   ├── storage-push-subscriptions.test.ts  # CREATE: Storage layer tests
│   ├── rpc-validation-push.test.ts         # CREATE: Validation tests
│   ├── worker-push-subscriptions.test.ts   # CREATE: Worker RPC tests
│   └── client-push-subscriptions.test.ts   # CREATE: Client API tests
│
└── docs/implementation/phase-1/push-notifications/
    └── plan.md                           # THIS FILE
```

---

## Implementation Checklist

### Phase A: Core Storage and API Layer
- [ ] Add `StoredPushSubscription` interface to `src/v2/types.ts`
- [ ] Add `subscriptions` field to `WrappedKey` interface
- [ ] Implement `addPushSubscription()` in `src/v2/storage.ts`
- [ ] Implement `removePushSubscription()` in `src/v2/storage.ts`
- [ ] Implement `getPushSubscriptions()` in `src/v2/storage.ts`
- [ ] Implement `getPushSubscription()` in `src/v2/storage.ts`
- [ ] Add validation functions to `src/v2/rpc-validation.ts`
- [ ] Add RPC handlers to `src/v2/worker.ts`
- [ ] Add client methods to `src/v2/client.ts`
- [ ] Write unit tests for storage layer
- [ ] Write unit tests for validation layer
- [ ] Write unit tests for worker handlers
- [ ] Write unit tests for client methods
- [ ] Verify 80%+ test coverage

### Phase B: Service Worker and Push Registration
- [ ] Create `example/phase-1/full/service-worker.js`
- [ ] Create `example/phase-1/full/push-utils.ts`
- [ ] Update `example/phase-1/full/parent.ts` for service worker registration
- [ ] Update `createLease()` to call `PushManager.subscribe()`
- [ ] Update `createLease()` to store subscription in KMS
- [ ] Add push subscription UI to `example/phase-1/full/index.html`
- [ ] Add "Subscribe to Push" button
- [ ] Add "Unsubscribe from Push" button
- [ ] Test service worker registration in browser
- [ ] Test push subscription creation in browser
- [ ] Verify subscriptions stored correctly

### Phase C: JWT Validation and Mock Push Delivery
- [ ] Add `validateVAPIDJWT()` function to `parent.ts`
- [ ] Add `sendTestPush()` function to `parent.ts`
- [ ] Add message handler to service worker for mock pushes
- [ ] Add "Send Test Push" button to `example/phase-1/full/index.html`
- [ ] Test JWT validation (valid/invalid format, claims, signature)
- [ ] Test notification delivery in browser
- [ ] Test notification click handling
- [ ] Verify console logging for validation steps

### Phase D: UI Enhancements and Documentation
- [ ] Update `displayVAPIDKeyInfo()` to show subscriptions
- [ ] Add subscription cards to UI
- [ ] Add "Remove" button for each subscription
- [ ] Add subscription expiration warnings
- [ ] Update `example/phase-1/full/styles.css`
- [ ] Update `example/phase-1/full/README.md` with push features
- [ ] Add troubleshooting section to README
- [ ] Add screenshots/diagrams to README
- [ ] Test UI in multiple browsers
- [ ] Test keyboard navigation
- [ ] Test screen reader compatibility

---

## Risk Assessment

### Technical Risks

1. **Browser API Limitations**
   - **Risk**: Push API behavior varies across browsers
   - **Mitigation**: Test on all target browsers early; document incompatibilities
   - **Fallback**: Feature detection with graceful degradation

2. **Service Worker Complexity**
   - **Risk**: Service worker lifecycle can be tricky (install/activate/fetch events)
   - **Mitigation**: Use minimal service worker (only push event); test thoroughly
   - **Fallback**: Log detailed errors; provide troubleshooting guide

3. **Notification Permissions**
   - **Risk**: Users may block notifications; can't be bypassed
   - **Mitigation**: Clear UI prompts explaining why permission is needed
   - **Fallback**: Detect blocked state; show helpful message

4. **IndexedDB Schema Evolution**
   - **Risk**: Adding `subscriptions` field to existing VAPID keys
   - **Mitigation**: Field is optional; existing data still works
   - **Fallback**: Initialize to empty array if missing

### Security Risks

1. **Push Endpoint Validation**
   - **Risk**: Malicious push endpoint URLs could be injected
   - **Mitigation**: Validate endpoints are HTTPS URLs from known push services
   - **Enhancement**: Whitelist known push service origins (fcm.googleapis.com, etc.)

2. **JWT Validation**
   - **Risk**: JWT validation logic could have bugs (incorrect signature verification, claim checks)
   - **Mitigation**: Comprehensive validation with detailed error messages; unit tests for validation logic
   - **Note**: Validation is done in parent PWA (simulating relay server); production relay must implement same checks

3. **Subscription Lifetime**
   - **Risk**: Expired subscriptions not automatically cleaned up
   - **Mitigation**: Check `expirationTime` before using subscription
   - **Enhancement**: Add periodic cleanup task

### UX Risks

1. **Permission Prompts**
   - **Risk**: Unexpected permission prompts frustrate users
   - **Mitigation**: Clear explanation before requesting permission; opt-in flow
   - **Best practice**: Two-step flow (explain → request)

2. **Notification Overload**
   - **Risk**: Demo sends too many test notifications
   - **Mitigation**: Rate limiting on "Send Test Push" button; clear UI feedback
   - **Note**: Production system has quota enforcement

3. **Cross-Browser Differences**
   - **Risk**: UI/behavior differs between browsers
   - **Mitigation**: Test on all platforms; document differences
   - **Fallback**: Feature detection with clear messaging

---

## Dependencies and Prerequisites

### Browser APIs Required
- ✅ Service Worker API (already supported by target browsers)
- ✅ Push API (already supported by target browsers)
- ✅ Notification API (already supported by target browsers)
- ✅ IndexedDB (already in use)
- ✅ Web Crypto API (already in use)

### External Dependencies
- ❌ No new npm packages required
- ❌ No backend infrastructure required (using mock push server)
- ✅ Existing dependencies sufficient (TypeScript, Vitest, esbuild)

### Development Prerequisites
- Modern browser with dev tools (Chrome recommended)
- Local dev server with HTTPS or localhost (required for service workers)
- Notification permission not blocked at OS level

---

## Success Metrics

### Functional Metrics
- ✅ Real `PushSubscription` objects created via browser API
- ✅ Subscriptions persist beyond 24-hour lease expiration
- ✅ Notifications display correctly on all target browsers
- ✅ JWT signing flow works end-to-end
- ✅ Multiple subscriptions per VAPID key supported

### Quality Metrics
- ✅ 80%+ test coverage maintained (existing requirement)
- ✅ No TypeScript errors (`pnpm typecheck` passes)
- ✅ No linting errors (`pnpm lint` passes)
- ✅ All existing tests continue to pass

### User Experience Metrics
- ✅ Clear UI for subscription management
- ✅ Helpful error messages for common issues
- ✅ Permission prompts have clear explanations
- ✅ Documentation complete with troubleshooting

### Performance Metrics
- ⏱️ Service worker registration < 500ms
- ⏱️ Push subscription creation < 1s
- ⏱️ Notification display < 100ms after mock push
- 💾 Minimal storage overhead (subscriptions ~200 bytes each)

---

## Future Enhancements (Out of Scope)

These features are **not** part of this implementation plan but could be added later:

1. **Real Push Service Integration**
   - Replace mock server with relay server
   - Integrate with FCM/APNs/etc.
   - Handle push service errors (410 Gone, 404 Not Found)

2. **Subscription Auto-Renewal**
   - Monitor `expirationTime` and auto-resubscribe
   - Handle push service key rotation

3. **Rich Notifications**
   - Action buttons in notifications
   - Custom notification icons/badges
   - Notification grouping/tagging

4. **Background Sync**
   - Queue notifications when offline
   - Sync state when connection restored

5. **Push Analytics**
   - Track notification delivery rate
   - Track notification click-through rate
   - Monitor subscription churn

6. **Multi-User Support**
   - Per-user subscriptions (currently demo is single-user)
   - User-specific notification preferences

---

## Questions and Clarifications

### Open Questions

1. **Subscription Expiration Handling**
   - Should expired subscriptions be automatically removed?
   - Should we auto-resubscribe when a subscription expires?
   - **Proposed answer**: Remove expired subscriptions; require manual resubscription

2. **Multiple Subscriptions per Lease**
   - Should one lease support multiple subscriptions?
   - **Current answer**: Yes, `LeaseRecord.subs` is already an array

3. **Subscription Endpoint Validation**
   - Should we whitelist known push service origins?
   - Or accept any HTTPS endpoint?
   - **Proposed answer**: For demo, accept any HTTPS endpoint; add origin validation in Phase C

4. **Device Name Input**
   - Should we prompt user for device name (eid)?
   - Or auto-generate (e.g., "Device 1", "Device 2")?
   - **Proposed answer**: Use auto-generated name for demo; prompt for name in Phase D enhancement

### Assumptions

1. **Single VAPID Key**: Demo assumes one active VAPID key at a time
2. **Desktop/Mobile**: Demo targets desktop browsers (mobile may have different UX)
3. **HTTPS/Localhost**: Service workers require secure context (localhost OK for dev)
4. **No Real Backend**: Using mock push server; no actual HTTP requests to push services

---

## Approval and Next Steps

### Review Checklist

Before implementation begins, verify:
- [ ] Plan aligns with current codebase structure
- [ ] All file paths are correct
- [ ] Type definitions match existing patterns
- [ ] Test coverage requirements understood (80%+)
- [ ] UI/UX approach approved
- [ ] Documentation scope sufficient

### Implementation Order

**Recommended order**:
1. Phase A (Core API) - Can be implemented and tested independently
2. Phase B (Service Worker) - Requires Phase A complete
3. Phase C (JWT Validation) - Requires Phase B complete
4. Phase D (UI Polish) - Can overlap with Phase C

**Estimated timeline**:
- Phase A: 2-3 days (API + tests)
- Phase B: 2-3 days (Service worker + integration)
- Phase C: 1 day (JWT validation + mock push delivery)
- Phase D: 1-2 days (UI + documentation)
- **Total**: ~6-9 days for full implementation

### Sign-off

- [ ] Technical approach approved
- [ ] Data model approved
- [ ] UI/UX approach approved
- [ ] Test strategy approved
- [ ] Ready to begin implementation

---

**Last Updated**: 2025-10-30
**Status**: Awaiting approval to begin implementation
