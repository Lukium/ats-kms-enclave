[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [kms-user](../README.md) / KMSUser

# Class: KMSUser

Defined in: [kms-user.ts:168](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L168)

KMS User API

Main entry point for PWA to interact with KMS.

## Constructors

### Constructor

> **new KMSUser**(`config`): `KMSUser`

Defined in: [kms-user.ts:182](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L182)

Create a new KMS user API instance

#### Parameters

##### config

[`KMSUserConfig`](../interfaces/KMSUserConfig.md)

Configuration

#### Returns

`KMSUser`

## Methods

### Setup Operations

#### addEnrollment()

> **addEnrollment**(`userId`, `credentials`): `Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Defined in: [kms-user.ts:740](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L740)

Add an additional authentication method (multi-enrollment).

Allows users to enroll multiple authentication methods (e.g., passphrase + passkey).
This provides flexibility and redundancy - if one method is unavailable, another
can be used. Requires authentication with an existing method to add a new one.

**Use Cases:**
- Add passkey after initial passphrase setup
- Add backup authentication method
- Support multiple devices with different auth capabilities

##### Parameters

###### userId

`string`

User ID for the enrollment

###### credentials

[`AuthCredentials`](../../types/type-aliases/AuthCredentials.md)

Current credentials to authenticate (proves ownership)

##### Returns

`Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Promise resolving to setup result

##### Throws

Authentication failed with current credentials

##### Throws

Method already enrolled

##### Throws

KMS not initialized

##### Example

```typescript
// Add passkey PRF after initial passphrase setup
const result = await kmsUser.addEnrollment(
  'user@example.com',
  { passphrase: 'my-current-passphrase' }  // Existing auth - used to unlock
);

console.log('Added enrollment:', result.enrollmentId);
```

This method uses the stateless popup flow:
1. Unlocks with existing credentials to get Master Secret
2. Opens popup to collect new authentication method
3. Re-wraps Master Secret with new KEK from popup
4. Returns enrollment ID for the newly added method

##### See

 - [getEnrollments](#getenrollments) to list all enrolled methods
 - [removeEnrollment](#removeenrollment) to remove a method

***

#### setupPasskeyGate()

> **setupPasskeyGate**(`config`): `Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Defined in: [kms-user.ts:649](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L649)

Setup KMS with WebAuthn gate authentication.

Creates a WebAuthn credential that acts as a "gate" for accessing the KMS. Unlike
PRF mode, gate mode does not derive keys from the authenticator - it simply verifies
user presence before allowing KMS access. The Master Secret is randomly generated
and stored encrypted.

**How it works:**
1. WebAuthn credential creation ceremony runs in parent PWA context
2. Credential ID stored as enrollment method
3. Future operations require WebAuthn assertion to prove possession
4. Master Secret is randomly generated (not derived from authenticator)

**Use Cases:**
- Simpler WebAuthn integration (no PRF extension required)
- Works with more authenticators
- Good for additional auth factor (after passphrase)

##### Parameters

###### config

Passkey gate configuration

###### name

`string`

Display name for credential

###### rpId

`string`

Relying Party ID (domain, e.g., "ats.run")

###### userId

`string`

User identifier for enrollment

##### Returns

`Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Promise resolving to setup result

##### Throws

WebAuthn not supported

##### Throws

User cancelled WebAuthn ceremony

##### Throws

KMS not initialized

##### Example

```typescript
const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
await kmsUser.init();

const result = await kmsUser.setupPasskeyGate({
  userId: 'user@example.com',
  name: 'My Security Key',
  rpId: 'ats.run',
});

console.log('Passkey Gate setup complete');
console.log('Enrollment ID:', result.enrollmentId);
```

##### See

 - [setupPassphrase](#setuppassphrase) for passphrase-based setup
 - [setupPasskeyPRF](#setuppasskeyprf) for WebAuthn PRF mode
 - [addEnrollment](#addenrollment) to add additional auth methods

***

#### setupPasskeyPRF()

> **setupPasskeyPRF**(`config`): `Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Defined in: [kms-user.ts:525](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L525)

Setup KMS with WebAuthn PRF (Pseudo-Random Function) authentication.

Creates a WebAuthn credential with PRF extension support, deriving a cryptographic
key from the authenticator's PRF output. The PRF output is deterministic based on
the credential and salt, providing a secure key derivation mechanism.

**How it works:**
1. WebAuthn credential creation ceremony runs in parent PWA context
2. PRF extension extracts deterministic output from authenticator
3. PRF output sent to KMS and used to derive KEK
4. Master Secret encrypted with PRF-derived KEK
5. App salt stored in localStorage for future authentication

**Requirements:**
- Authenticator must support PRF extension (most platform authenticators do)
- Requires user presence verification
- Platform authenticator recommended (biometrics)

##### Parameters

###### config

Passkey PRF configuration

###### name

`string`

Display name for credential

###### rpId

`string`

Relying Party ID (domain, e.g., "ats.run")

###### userId

`string`

User identifier for enrollment

##### Returns

`Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Promise resolving to setup result

##### Throws

WebAuthn not supported

##### Throws

PRF extension not supported or failed

##### Throws

User cancelled WebAuthn ceremony

##### Throws

KMS not initialized

##### Example

```typescript
const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
await kmsUser.init();

try {
  const result = await kmsUser.setupPasskeyPRF({
    userId: 'user@example.com',
    name: 'My Device',
    rpId: 'ats.run',
  });

  console.log('Passkey PRF setup complete');
  console.log('Enrollment ID:', result.enrollmentId);
} catch (err) {
  if (err.message.includes('PRF extension not supported')) {
    console.error('Your authenticator does not support PRF');
  }
}
```

##### See

 - [setupPassphrase](#setuppassphrase) for passphrase-based setup
 - [setupPasskeyGate](#setuppasskeygate) for WebAuthn gate mode
 - [addEnrollment](#addenrollment) to add additional auth methods

***

#### setupPassphrase()

> **setupPassphrase**(`userId`, `passphrase`): `Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Defined in: [kms-user.ts:460](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L460)

Setup KMS with passphrase authentication.

Creates the Master Secret (if first enrollment) and generates initial VAPID keypair.
The passphrase is hashed using PBKDF2 with calibrated iterations (150-300ms target).

**Security Notes:**
- Passphrase must be at least 8 characters (recommended: 12+ characters)
- PBKDF2 iterations are calibrated on first call for device performance
- Master Secret is randomly generated (32 bytes) and encrypted with passphrase-derived KEK

##### Parameters

###### userId

`string`

User identifier for enrollment

###### passphrase

`string`

User passphrase (minimum 8 characters, recommended 12+)

##### Returns

`Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Promise resolving to setup result

##### Throws

Passphrase must be at least 8 characters

##### Throws

KMS not initialized (call init() first)

##### Throws

Request timeout (>10s)

##### Throws

IndexedDB access denied

##### Example

```typescript
const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
await kmsUser.init();

const result = await kmsUser.setupPassphrase(
  'user@example.com',
  'my-secure-passphrase-123'
);

console.log('Enrollment ID:', result.enrollmentId);
```

##### See

 - [setupPasskeyPRF](#setuppasskeyprf) for WebAuthn PRF setup
 - [setupPasskeyGate](#setuppasskeygate) for WebAuthn gate setup
 - [addEnrollment](#addenrollment) to add additional auth methods

***

#### setupWithPopup()

> **setupWithPopup**(`params`): `Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Defined in: [kms-user.ts:902](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L902)

Setup user authentication via popup (iframe-managed flow).

This method allows the iframe KMS to directly manage popup communication.
Parent only assists with window.open() - all cryptographic operations
and credential exchange bypass the parent entirely.

**Security Benefits:**
- Parent never sees transport parameters
- Parent never receives encrypted credentials
- Direct same-origin communication between iframe and popup
- Reduced attack surface (parent out of credential path)

**Flow:**
1. Parent calls this method (RPC to iframe)
2. Iframe requests parent to open popup (kms:request-popup)
3. Parent opens popup with minimal URL and notifies iframe (kms:popup-opened)
4. Popup signals ready to iframe (kms:popup-ready, same-origin)
5. Iframe establishes MessageChannel with popup (kms:connect + transport params)
6. Popup collects and encrypts credentials
7. Popup sends credentials to iframe directly (via MessagePort)
8. Iframe processes setup and returns result to parent

**Parent Visibility:**
- Parent only sees minimal popup URL: `https://kms.ats.run/?mode=setup`
- Parent does NOT see: transport keys, salts, credentials, setup method

**Comparison with setupWithEncryptedCredentials:**
- Old: Parent mediates all communication (parent ↔ popup ↔ iframe)
- New: Direct communication (popup ↔ iframe), parent only opens window

##### Parameters

###### params

###### userId

`string`

User ID to setup authentication for

##### Returns

`Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Setup result with enrollment ID and VAPID key info

##### Throws

If popup is blocked by browser

##### Throws

If popup never responds (timeout)

##### Throws

If credential collection fails in popup

##### Throws

If setup processing fails in iframe

##### Example

```typescript
// In parent PWA:
const result = await kmsUser.setupWithPopup({
  userId: 'user@example.com'
});
console.log('Setup complete:', result.enrollmentId);
```

### VAPID Key Management

#### getPublicKey()

> **getPublicKey**(`kid`): `Promise`\<\{ `publicKey`: `string`; \}\>

Defined in: [kms-user.ts:1087](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1087)

Get public key for a specific VAPID key by key ID.

Retrieves the public key portion of a VAPID keypair given its key ID (kid).
The public key is returned in raw format (65 bytes, uncompressed P-256 point)
encoded as base64url, suitable for use with PushManager.subscribe().

**Note:** Most applications should use `getVAPIDPublicKey()` instead, which
automatically retrieves the current VAPID key without needing to know the kid.

##### Parameters

###### kid

`string`

Key ID (JWK thumbprint) of the VAPID key

##### Returns

`Promise`\<\{ `publicKey`: `string`; \}\>

Promise resolving to public key

##### Throws

KMS not initialized

##### Throws

Key not found

##### Example

```typescript
// Get public key by kid (if you know the kid)
const { publicKey } = await kmsUser.getPublicKey('kid-abc-123');
console.log('Public Key:', publicKey);

// Use with PushManager (convert to Uint8Array)
const pubKeyBytes = base64urlToUint8Array(publicKey);
const subscription = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: pubKeyBytes,
});
```

##### See

[getVAPIDPublicKey](#getvapidpublickey) to get current VAPID key without knowing kid

***

#### getVAPIDPublicKey()

> **getVAPIDPublicKey**(`_userId`): `Promise`\<\{ `kid`: `string`; `publicKey`: `string`; \}\>

Defined in: [kms-user.ts:1151](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1151)

Get VAPID public key for the current user (convenience method).

Retrieves the user's VAPID public key without requiring the key ID. This is the
recommended method for most applications, as it automatically finds the current
VAPID key and returns both the public key and its kid.

**Implementation:** Internally calls getVAPIDKid() to get the key ID, then
calls getPublicKey() with that kid.

**Use Cases:**
- Subscribe to Web Push notifications
- Display VAPID key info to user
- Verify key exists before creating leases

##### Parameters

###### \_userId

`string`

User ID (currently unused, kept for API consistency)

##### Returns

`Promise`\<\{ `kid`: `string`; `publicKey`: `string`; \}\>

Promise resolving to VAPID key information

##### Throws

KMS not initialized

##### Throws

No VAPID key found (user needs to setup or regenerate)

##### Throws

Multiple VAPID keys found (data corruption - should not happen)

##### Example

```typescript
// Get current VAPID public key
const { publicKey, kid } = await kmsUser.getVAPIDPublicKey('user@example.com');

console.log('VAPID Key ID:', kid);
console.log('Public Key:', publicKey);

// Use with PushManager.subscribe()
const pubKeyBytes = base64urlToUint8Array(publicKey);
const registration = await navigator.serviceWorker.ready;
const subscription = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: pubKeyBytes,
});

// Store subscription in KMS
await kmsUser.setPushSubscription({
  endpoint: subscription.endpoint,
  expirationTime: subscription.expirationTime,
  keys: {
    p256dh: arrayBufferToBase64url(subscription.getKey('p256dh')),
    auth: arrayBufferToBase64url(subscription.getKey('auth')),
  },
  eid: 'my-device',
  createdAt: Date.now(),
});
```

##### See

 - [getPublicKey](#getpublickey) to get public key by kid (if you know the kid)
 - [regenerateVAPID](#regeneratevapid) to generate a new VAPID key

***

#### regenerateVAPID()

> **regenerateVAPID**(`params`): `Promise`\<[`VAPIDKeyResult`](../interfaces/VAPIDKeyResult.md)\>

Defined in: [kms-user.ts:1025](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1025)

Unlock KMS with passphrase

Note: This only validates the passphrase. Actual operations require

/**
Regenerate VAPID keypair, invalidating all existing leases.

Deletes the current VAPID key and generates a new one with a new key ID (kid).
This is a destructive operation that invalidates:
- All existing leases (they reference the old kid)
- All JWT stashes (signed with old key)
- Push subscription (stored on the old key)

**When to use:**
- VAPID key suspected to be compromised
- Rotating keys as security best practice
- Resetting authorization state

**What happens:**
1. User authenticates via iframe modal
2. Old VAPID key(s) deleted from storage
3. New P-256 ECDSA keypair generated
4. New kid computed (JWK thumbprint)
5. All leases invalidated (wrong-key)
6. Push subscription lost (must call setPushSubscription again)

**Security:** Credentials are ALWAYS collected in KMS iframe. The parent
MUST NOT pass credentials - doing so would bypass iframe isolation.

##### Parameters

###### params

Regeneration parameters

###### userId

`string`

User ID for authentication (REQUIRED for iframe modal)

##### Returns

`Promise`\<[`VAPIDKeyResult`](../interfaces/VAPIDKeyResult.md)\>

Promise resolving to new VAPID key information

##### Throws

KMS not initialized

##### Throws

User not setup (no enrollments)

##### Throws

Authentication cancelled by user

##### Throws

IndexedDB access denied

##### Example

```typescript
// Regenerate VAPID key (triggers auth modal)
const newKey = await kmsUser.regenerateVAPID({
  userId: 'user@example.com',
});

console.log('New VAPID Key ID:', newKey.kid);
console.log('New Public Key:', newKey.publicKey);

// All leases are now invalid - verify and clean up
const { leases } = await kmsUser.getUserLeases('user@example.com');
for (const lease of leases) {
  const result = await kmsUser.verifyLease(lease.leaseId, true);
  console.log(`Lease ${lease.leaseId}:`, result.valid ? 'VALID' : 'INVALID');
}

// Push subscription lost - must re-register
const { subscription } = await kmsUser.getPushSubscription();
console.log('Subscription:', subscription);  // null

// Re-subscribe to push
await kmsUser.setPushSubscription(newSubscription);

// Create new lease with new key
await kmsUser.createLease({ userId: 'user@example.com', subs: [...], ttlHours: 12 });
```

##### See

 - [verifyLease](#verifylease) to check which leases are now invalid
 - [getUserLeases](#getuserleases) to get all leases for cleanup
 - [setPushSubscription](#setpushsubscription) to re-register push subscription

### VAPID Lease Operations

#### createLease()

> **createLease**(`params`): `Promise`\<[`LeaseResult`](../interfaces/LeaseResult.md)\>

Defined in: [kms-user.ts:1240](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1240)

Create VAPID lease for long-lived JWT issuance authorization.

Leases allow issuing JWTs without re-authentication by deriving a session-specific KEK
from the Master Secret. The VAPID private key is re-wrapped with this SessionKEK and
stored in memory, enabling credential-free JWT signing until lease expiration.

**Authentication:** This operation triggers iframe modal for user authentication.
Credentials are collected inside the KMS iframe and NEVER exposed to parent PWA.

**Push Subscription:** The lease automatically uses the push subscription stored on
the VAPID key. Call `setPushSubscription()` before creating leases if you need
push notification support.

**Quotas:** Each lease has rate limits enforced by the worker:
- 100 tokens per hour
- 10 sends per minute (burst: 20)
- 5 sends per minute per endpoint ID

##### Parameters

###### params

Lease creation parameters

###### subs

`object`[]

Array of push subscription endpoints to authorize

###### ttlHours

`number`

Lease time-to-live in hours (max 720 hours / 30 days)

###### userId

`string`

User ID for authentication (REQUIRED for iframe modal)

##### Returns

`Promise`\<[`LeaseResult`](../interfaces/LeaseResult.md)\>

Promise resolving to lease information

##### Throws

KMS not initialized

##### Throws

User not setup (no enrollments)

##### Throws

No VAPID key found

##### Throws

No push subscription found (call setPushSubscription first)

##### Throws

Invalid subs format

##### Throws

ttlHours exceeds maximum (720 hours)

##### Throws

Authentication cancelled by user

##### Example

```typescript
// Ensure push subscription is set
await kmsUser.setPushSubscription(subscription);

// Create lease (triggers auth modal)
const lease = await kmsUser.createLease({
  userId: 'user@example.com',
  subs: [
    {
      url: 'https://fcm.googleapis.com/fcm/send/abc123',
      aud: 'https://fcm.googleapis.com',
      eid: 'endpoint-1',
    },
  ],
  ttlHours: 12,
});

console.log('Lease ID:', lease.leaseId);
console.log('Expires:', new Date(lease.exp));

// Now can issue JWTs without re-authentication
const jwt = await kmsUser.issueVAPIDJWT({
  leaseId: lease.leaseId,
  endpoint: { url: '...', aud: '...', eid: 'endpoint-1' },
});
```

##### See

 - [issueVAPIDJWT](#issuevapidjwt) to issue single JWT from lease
 - [issueVAPIDJWTs](#issuevapidjwts) to batch issue JWTs from lease
 - [verifyLease](#verifylease) to check lease validity
 - [getUserLeases](#getuserleases) to list all user leases
 - [setPushSubscription](#setpushsubscription) to configure push subscription

***

#### extendLeases()

> **extendLeases**(`leaseIds`, `userId`, `options?`): `Promise`\<[`ExtendLeasesResult`](../interfaces/ExtendLeasesResult.md)\>

Defined in: [kms-user.ts:1318](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1318)

Extend one or more existing leases.

Updates lease expirations to 30 days from now. This method accepts an array of lease IDs
and processes them in batch, returning detailed results for each lease.

**Auto-Extend Behavior:**
- `autoExtend=true` (default): Extension works without authentication
- `autoExtend=false`: Requires authentication OR will be skipped if `requestAuth` not set

**Smart Skipping:** If `requestAuth` is not set, the worker will automatically skip
non-extendable leases (autoExtend=false) and return them with status='skipped'. This
allows "Extend All Leases" to gracefully handle mixed lease types.

**Single Authentication:** When `requestAuth=true`, the user authenticates once and
all leases (both extendable and non-extendable) are processed with credentials.

**Security Note:** Leases must be for the current VAPID key. If the VAPID key has
been regenerated, extensions will fail and new leases must be created.

##### Parameters

###### leaseIds

`string`[]

Array of lease IDs to extend

###### userId

`string`

The user ID who owns the leases

###### options?

Extension options

###### requestAuth?

`boolean`

Set to true to request user authentication for all leases

##### Returns

`Promise`\<[`ExtendLeasesResult`](../interfaces/ExtendLeasesResult.md)\>

Promise resolving to batch result with per-lease details

##### Throws

KMS not initialized

##### Example

```typescript
// Extend multiple auto-extendable leases (skips non-extendable)
const result = await kmsUser.extendLeases(
  ['lease-abc-123', 'lease-def-456', 'lease-ghi-789'],
  'user@example.com'
);
console.log(`Extended: ${result.extended}, Skipped: ${result.skipped}`);

// Extend with authentication (processes all leases)
const result = await kmsUser.extendLeases(
  ['lease-abc-123', 'lease-def-456'],
  'user@example.com',
  { requestAuth: true }
);
```

##### See

 - [createLease](#createlease) to create a new lease
 - [verifyLease](#verifylease) to verify lease validity

***

#### getUserLeases()

> **getUserLeases**(`userId`): `Promise`\<\{ `leases`: [`LeaseRecord`](../../types/interfaces/LeaseRecord.md)[]; \}\>

Defined in: [kms-user.ts:1750](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1750)

Get all leases for a user.

Returns all lease records associated with the user, including lease IDs, expiration
timestamps, VAPID key IDs, and authorized endpoints. This is useful for:
- Displaying active leases in UI
- Bulk lease verification/cleanup
- Monitoring lease expiration
- Debugging authorization issues

**Note:** This method returns all leases regardless of validity. Use `verifyLease()`
to check if individual leases are still valid (not expired, correct VAPID key).

##### Parameters

###### userId

`string`

User ID to query leases for

##### Returns

`Promise`\<\{ `leases`: [`LeaseRecord`](../../types/interfaces/LeaseRecord.md)[]; \}\>

Promise resolving to array of lease records

##### Throws

KMS not initialized

##### Throws

Request timeout

##### Example

```typescript
// Get all leases for a user
const { leases } = await kmsUser.getUserLeases('user@example.com');

console.log(`Found ${leases.length} leases`);
leases.forEach(lease => {
  console.log('Lease ID:', lease.leaseId);
  console.log('Expires:', new Date(lease.exp));
  console.log('VAPID Key:', lease.kid);
  console.log('Endpoints:', lease.subs.map(s => s.eid).join(', '));

  // Check if expired
  if (lease.exp < Date.now()) {
    console.log('  ⚠️ EXPIRED');
  }
});

// Verify and clean up invalid leases
for (const lease of leases) {
  await kmsUser.verifyLease(lease.leaseId, true); // Delete if invalid
}
```

##### See

 - [verifyLease](#verifylease) to check individual lease validity
 - [createLease](#createlease) to create new leases

***

#### issueVAPIDJWT()

> **issueVAPIDJWT**(`params`): `Promise`\<[`JWTResult`](../interfaces/JWTResult.md)\>

Defined in: [kms-user.ts:1413](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1413)

Issue a single VAPID JWT for an endpoint using lease authorization.

Uses an existing lease to sign a JWT without requiring re-authentication. The JWT
is signed with the VAPID private key and includes RFC 8292 VAPID headers for push
service authorization.

**No Credentials Required:** The lease IS the authorization. Once a lease exists,
JWTs can be issued freely until the lease expires.

**Automatic Verification:** Automatically verifies the lease is valid before issuing
the JWT. This prevents JWT issuance against expired or invalidated leases.

**JWT Format:** RFC 8292 compliant with:
- Header: `{ typ: 'JWT', alg: 'ES256' }`
- Payload: `{ aud, exp, sub }`
- Signature: ECDSA P-256 (P-1363 format, 64 bytes)
- Default TTL: 15 minutes (900 seconds)

##### Parameters

###### params

JWT issuance parameters

###### endpoint

\{ `aud`: `string`; `eid`: `string`; `url`: `string`; \}

Push endpoint details

###### endpoint.aud

`string`

Audience (push service origin, e.g., "https://fcm.googleapis.com")

###### endpoint.eid

`string`

Endpoint identifier for quota tracking

###### endpoint.url

`string`

Push service URL (e.g., FCM endpoint)

###### kid?

`string`

Optional VAPID key ID (auto-detected if not provided)

###### leaseId

`string`

Lease ID for authorization

##### Returns

`Promise`\<[`JWTResult`](../interfaces/JWTResult.md)\>

Promise resolving to JWT result

##### Throws

Cannot issue JWT: lease expired

##### Throws

Cannot issue JWT: lease wrong-key

##### Throws

Cannot issue JWT: lease not-found

##### Throws

KMS not initialized

##### Throws

Lease not found in worker memory

##### Throws

Quota exceeded (rate limits)

##### Example

```typescript
// Issue a single JWT using a lease
const jwt = await kmsUser.issueVAPIDJWT({
  leaseId: 'lease-abc-123',
  endpoint: {
    url: 'https://fcm.googleapis.com/fcm/send/abc123',
    aud: 'https://fcm.googleapis.com',
    eid: 'device-1',
  },
});

console.log('JWT:', jwt.jwt);
console.log('Expires:', new Date(jwt.exp));

// Use JWT in push notification Authorization header
const vapidHeader = `vapid t=${jwt.jwt}, k=${vapidPublicKey}`;
```

##### See

 - [issueVAPIDJWTs](#issuevapidjwts) to batch issue multiple JWTs
 - [createLease](#createlease) to create a lease first
 - [verifyLease](#verifylease) to check lease validity

***

#### issueVAPIDJWTs()

> **issueVAPIDJWTs**(`params`): `Promise`\<[`JWTResult`](../interfaces/JWTResult.md)[]\>

Defined in: [kms-user.ts:1493](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1493)

Issue multiple VAPID JWTs with staggered expirations for JWT rotation.

Generates N JWTs for the same endpoint with intelligent expiration staggering to enable
seamless JWT rotation without gaps. This is useful for "JWT stashing" where the client
pre-fetches multiple JWTs to avoid needing to call the KMS for every push notification.

**Staggered Expirations:**
- JWT[0]: expires at T+100min (6000s)
- JWT[1]: expires at T+160min (6000s + 3600s stagger)
- JWT[2]: expires at T+220min (6000s + 7200s stagger)

The stagger interval is 60% of the JWT TTL (3600s for 6000s TTL), ensuring seamless
rotation: when JWT[0] reaches 60% TTL, JWT[1] is already valid.

**Automatic Verification:** Automatically verifies the lease is valid before issuing JWTs.
This prevents JWT issuance against expired or invalidated leases.

##### Parameters

###### params

Batch issuance parameters

###### count

`number`

Number of JWTs to issue (1-10, hard limit enforced by worker)

###### endpoint

\{ `aud`: `string`; `eid`: `string`; `url`: `string`; \}

Push endpoint details

###### endpoint.aud

`string`

Audience (push service origin)

###### endpoint.eid

`string`

Endpoint identifier for quota tracking

###### endpoint.url

`string`

Push service URL

###### kid?

`string`

Optional VAPID key ID (auto-detected if not provided)

###### leaseId

`string`

Lease ID for authorization

##### Returns

`Promise`\<[`JWTResult`](../interfaces/JWTResult.md)[]\>

Promise resolving to array of JWT results with staggered expirations

##### Throws

Cannot issue JWTs: lease expired

##### Throws

Cannot issue JWTs: lease wrong-key

##### Throws

Cannot issue JWTs: lease not-found

##### Throws

KMS not initialized

##### Throws

count must be between 1 and 10

##### Throws

Quota exceeded (rate limits)

##### Example

```typescript
// Issue 5 staggered JWTs for JWT rotation
const jwts = await kmsUser.issueVAPIDJWTs({
  leaseId: 'lease-abc-123',
  endpoint: {
    url: 'https://fcm.googleapis.com/fcm/send/abc123',
    aud: 'https://fcm.googleapis.com',
    eid: 'device-1',
  },
  count: 5,
});

console.log('Generated', jwts.length, 'JWTs');
jwts.forEach((jwt, i) => {
  console.log(`JWT[${i}] expires:`, new Date(jwt.exp));
});

// Store JWTs for rotation
localStorage.setItem('jwt-stash', JSON.stringify(jwts));
```

##### See

 - [issueVAPIDJWT](#issuevapidjwt) to issue a single JWT
 - [createLease](#createlease) to create a lease first
 - [verifyLease](#verifylease) to check lease validity

***

#### verifyLease()

> **verifyLease**(`leaseId`, `deleteIfInvalid?`): `Promise`\<[`LeaseVerificationResult`](../../types/interfaces/LeaseVerificationResult.md)\>

Defined in: [kms-user.ts:1811](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1811)

Verify lease validity against current VAPID key.

Checks if a lease is valid by verifying:
1. Lease exists in storage
2. Lease has not expired (exp > Date.now())
3. Lease kid matches current VAPID key kid

This is a **read-only** operation that does not modify lease state or produce audit entries.

**Optional Deletion:** If `deleteIfInvalid` is true, invalid leases (expired or wrong kid)
are automatically deleted from storage. This is useful for cleanup after VAPID key regeneration.

##### Parameters

###### leaseId

`string`

Lease identifier to verify

###### deleteIfInvalid?

`boolean`

If true, delete lease if invalid (default: false)

##### Returns

`Promise`\<[`LeaseVerificationResult`](../../types/interfaces/LeaseVerificationResult.md)\>

Promise resolving to verification result

##### Throws

KMS not initialized

##### Throws

Request timeout

##### Example

```typescript
// Basic verification
const result = await kmsUser.verifyLease('lease-abc-123');

if (result.valid) {
  console.log('Lease is valid');
} else {
  console.log('Lease is invalid:', result.reason);
  // reason can be: "expired", "wrong-key", or "not-found"
}

// Verify and clean up invalid leases
const resultWithCleanup = await kmsUser.verifyLease('lease-abc-123', true);
if (!resultWithCleanup.valid) {
  console.log('Invalid lease was automatically deleted');
}

// Bulk cleanup after VAPID regeneration
const { leases } = await kmsUser.getUserLeases('user@example.com');
for (const lease of leases) {
  await kmsUser.verifyLease(lease.leaseId, true); // Delete if invalid
}
```

##### See

 - [getUserLeases](#getuserleases) to get all user leases
 - [createLease](#createlease) to create new leases
 - [regenerateVAPID](#regeneratevapid) invalidates all leases

### Push Notifications

#### getPushSubscription()

> **getPushSubscription**(): `Promise`\<\{ `subscription`: [`StoredPushSubscription`](../../types/interfaces/StoredPushSubscription.md) \| `null`; \}\>

Defined in: [kms-user.ts:2084](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L2084)

Get the push subscription stored on the VAPID key.

Returns the Web Push subscription currently associated with the VAPID key, or null if
no subscription has been set. The subscription is stored on the VAPID key's `subscription`
field (1:1 relationship).

**Use Cases:**
- Check if push notifications are configured before creating leases
- Verify subscription hasn't expired
- Display current subscription endpoint to user
- Check subscription exists before issuing JWTs

##### Returns

`Promise`\<\{ `subscription`: [`StoredPushSubscription`](../../types/interfaces/StoredPushSubscription.md) \| `null`; \}\>

Promise resolving to object containing subscription or null

##### Throws

KMS not initialized (call init() first)

##### Throws

No VAPID key found

##### Throws

Multiple VAPID keys found (ambiguous which to read from)

##### Example

```typescript
// Check if subscription exists
const { subscription } = await kmsUser.getPushSubscription();

if (subscription) {
  console.log('Push endpoint:', subscription.endpoint);
  console.log('Endpoint ID:', subscription.eid);

  // Check if expired
  if (subscription.expirationTime && subscription.expirationTime < Date.now()) {
    console.warn('Subscription expired, need to renew');
  }
} else {
  console.log('No subscription configured');
  // Need to call setPushSubscription()
}
```

##### See

 - [setPushSubscription](#setpushsubscription) to store a subscription
 - [removePushSubscription](#removepushsubscription) to delete the subscription
 - [createLease](#createlease) requires subscription to be set first

***

#### removePushSubscription()

> **removePushSubscription**(): `Promise`\<\{ `success`: `boolean`; \}\>

Defined in: [kms-user.ts:2034](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L2034)

Remove the Web Push subscription from the VAPID key.

Removes the subscription field from the VAPID key record. The VAPID key itself is **not**
deleted - only the subscription field is removed. This operation is idempotent (calling
when no subscription exists does not throw an error).

**Behavior:**
- Subscription field deleted from VAPID key
- VAPID key remains (can still sign JWTs if subscription not needed)
- Existing leases remain valid but cannot issue JWTs until subscription is re-added
- Idempotent: safe to call multiple times

##### Returns

`Promise`\<\{ `success`: `boolean`; \}\>

Promise resolving to success status

##### Throws

KMS not initialized (call init() first)

##### Throws

No VAPID key found

##### Throws

Multiple VAPID keys found (ambiguous which to update)

##### Example

```typescript
// Unsubscribe from push in browser first
const registration = await navigator.serviceWorker.ready;
const subscription = await registration.pushManager.getSubscription();
if (subscription) {
  await subscription.unsubscribe();
}

// Remove subscription from KMS storage
await kmsUser.removePushSubscription();

// Verify removal
const { subscription: stored } = await kmsUser.getPushSubscription();
console.log('Subscription is now:', stored);  // null
```

##### See

 - [setPushSubscription](#setpushsubscription) to store a new subscription
 - [getPushSubscription](#getpushsubscription) to check if subscription exists
 - [regenerateVAPID](#regeneratevapid) regenerates key (also loses subscription)

***

#### setPushSubscription()

> **setPushSubscription**(`subscription`): `Promise`\<\{ `success`: `boolean`; \}\>

Defined in: [kms-user.ts:1984](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1984)

Store or update Web Push subscription on VAPID key.

The subscription is stored on the `WrappedKey` record in IndexedDB, establishing a 1:1
relationship between VAPID key and push subscription. This allows leases and JWTs to
automatically use the subscription data without passing it on every call.

**Storage Location:** The subscription is stored on the VAPID key's `subscription` field,
NOT in lease records. All leases for a VAPID key use the same subscription (single source of truth).

**Security:** Endpoints are validated against a whitelist of known push services:
- Firebase Cloud Messaging (FCM)
- Apple Push Notification service (APNs)
- Mozilla Push Service
- Windows Push Notification Services (WNS)

##### Parameters

###### subscription

[`StoredPushSubscription`](../../types/interfaces/StoredPushSubscription.md)

Push subscription object from PushManager.subscribe()

##### Returns

`Promise`\<\{ `success`: `boolean`; \}\>

Promise resolving to success status

##### Throws

No VAPID key found (call generateVAPID first)

##### Throws

Multiple VAPID keys found (ambiguous which to update)

##### Throws

Endpoint must use HTTPS

##### Throws

Endpoint must be from a known push service (whitelist check failed)

##### Throws

keys.p256dh must be base64url string of exactly 65 decoded bytes

##### Throws

keys.auth must be base64url string of exactly 16 decoded bytes

##### Example

```typescript
// Generate VAPID key first
const vapid = await kmsUser.generateVAPID(credentials);

// Subscribe to push in browser
const registration = await navigator.serviceWorker.ready;
const pushSub = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: vapid.publicKey,
});

// Convert and store in KMS
await kmsUser.setPushSubscription({
  endpoint: pushSub.endpoint,
  expirationTime: pushSub.expirationTime,
  keys: {
    p256dh: arrayBufferToBase64url(pushSub.getKey('p256dh')),
    auth: arrayBufferToBase64url(pushSub.getKey('auth')),
  },
  eid: 'my-laptop-chrome',
  createdAt: Date.now(),
});
```

##### See

 - [getPushSubscription](#getpushsubscription) to retrieve subscription
 - [removePushSubscription](#removepushsubscription) to delete subscription
 - [issueVAPIDJWT](#issuevapidjwt) uses subscription for JWT generation

### Status and Query Operations

#### getAuditLog()

> **getAuditLog**(): `Promise`\<\{ `entries`: [`AuditEntryV2`](../../types/interfaces/AuditEntryV2.md)[]; \}\>

Defined in: [kms-user.ts:1666](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1666)

Get all audit log entries.

Returns the complete audit log showing all cryptographic operations performed
by the KMS. Each entry includes operation type, timestamp, parameters, and
cryptographic signature.

##### Returns

`Promise`\<\{ `entries`: [`AuditEntryV2`](../../types/interfaces/AuditEntryV2.md)[]; \}\>

Promise resolving to audit log entries

##### Throws

KMS not initialized

##### Example

```typescript
const { entries } = await kmsUser.getAuditLog();

console.log(`Audit log: ${entries.length} entries`);
entries.forEach(entry => {
  console.log(`[${new Date(entry.timestamp)}] ${entry.operation}`);
  if (entry.params) {
    console.log('  Params:', JSON.stringify(entry.params, null, 2));
  }
});
```

##### See

[verifyAuditChain](#verifyauditchain) to verify integrity

***

#### getAuditPublicKey()

> **getAuditPublicKey**(): `Promise`\<\{ `publicKey`: `string`; \}\>

Defined in: [kms-user.ts:1695](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1695)

Get the audit log's Ed25519 public key.

Returns the public key used to verify audit log signatures. This key is
generated once during first KMS operation and used for all subsequent
audit entries.

##### Returns

`Promise`\<\{ `publicKey`: `string`; \}\>

Promise resolving to public key

##### Throws

KMS not initialized

##### Example

```typescript
const { publicKey } = await kmsUser.getAuditPublicKey();
console.log('Audit Public Key:', publicKey);

// Can be used to independently verify audit signatures
```

##### See

[verifyAuditChain](#verifyauditchain) to verify audit integrity

***

#### getEnrollments()

> **getEnrollments**(): `Promise`\<\{ `enrollments`: `string`[]; \}\>

Defined in: [kms-user.ts:1598](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1598)

Get list of all enrolled authentication methods.

Returns the enrollment IDs for all authentication methods that have been registered
with the KMS. This includes passphrase, passkey-PRF, and passkey-gate enrollments.

##### Returns

`Promise`\<\{ `enrollments`: `string`[]; \}\>

Promise resolving to array of enrollment IDs

##### Throws

KMS not initialized

##### Example

```typescript
const { enrollments } = await kmsUser.getEnrollments();

console.log('Enrolled methods:', enrollments);
enrollments.forEach(eid => {
  if (eid.startsWith('enrollment:passphrase:')) {
    console.log('  - Passphrase');
  } else if (eid.startsWith('enrollment:passkey-prf:')) {
    console.log('  - WebAuthn PRF');
  } else if (eid.startsWith('enrollment:passkey-gate:')) {
    console.log('  - WebAuthn Gate');
  }
});
```

##### See

 - [isSetup](#issetup) to check if any enrollments exist
 - [addEnrollment](#addenrollment) to add additional methods
 - [removeEnrollment](#removeenrollment) to remove a method

***

#### isSetup()

> **isSetup**(`userId?`): `Promise`\<[`StatusResult`](../interfaces/StatusResult.md)\>

Defined in: [kms-user.ts:1560](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1560)

Check if KMS is setup for the current user.

Returns whether the KMS has been initialized with at least one enrollment method.
If setup is complete, also returns the list of enrolled authentication methods.
Optionally includes lease information if a userId is provided.

**Use Cases:**
- Check if user needs to complete setup before using KMS
- Display enrolled authentication methods to user
- Monitor lease status

##### Parameters

###### userId?

`string`

Optional user ID to fetch leases for

##### Returns

`Promise`\<[`StatusResult`](../interfaces/StatusResult.md)\>

Promise resolving to setup status

##### Throws

KMS not initialized

##### Example

```typescript
// Check if setup (without leases)
const status = await kmsUser.isSetup();

if (status.isSetup) {
  console.log('KMS is setup');
  console.log('Enrolled methods:', status.methods);
} else {
  console.log('KMS not setup - need to call setupPassphrase() or setupPasskeyPRF()');
}

// Check with leases
const statusWithLeases = await kmsUser.isSetup('user@example.com');
if (statusWithLeases.leases) {
  console.log(`User has ${statusWithLeases.leases.length} active leases`);
}
```

##### See

 - [setupPassphrase](#setuppassphrase) to setup with passphrase
 - [setupPasskeyPRF](#setuppasskeyprf) to setup with WebAuthn PRF
 - [getEnrollments](#getenrollments) to get full enrollment list

***

#### verifyAuditChain()

> **verifyAuditChain**(): `Promise`\<[`AuditVerificationResult`](../interfaces/AuditVerificationResult.md)\>

Defined in: [kms-user.ts:1632](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1632)

Verify the integrity of the audit log chain.

Verifies cryptographic signatures and hash chains to ensure the audit log has not
been tampered with. Each audit entry is signed with an Ed25519 key and includes
a hash of the previous entry, forming an immutable chain.

##### Returns

`Promise`\<[`AuditVerificationResult`](../interfaces/AuditVerificationResult.md)\>

Promise resolving to verification result

##### Throws

KMS not initialized

##### Example

```typescript
const result = await kmsUser.verifyAuditChain();

if (result.valid) {
  console.log(`✓ Audit chain valid (${result.entries} entries)`);
} else {
  console.error('⚠️ Audit chain integrity compromised!');
}
```

##### See

 - [getAuditLog](#getauditlog) to retrieve all audit entries
 - [getAuditPublicKey](#getauditpublickey) to get the verification key

### Management Operations

#### removeEnrollment()

> **removeEnrollment**(`enrollmentId`, `credentials`): `Promise`\<\{ `success`: `boolean`; \}\>

Defined in: [kms-user.ts:1905](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1905)

Remove a specific enrollment method.

Deletes an authentication method from the KMS. Requires authentication with
current credentials to prove ownership before removal. Cannot remove the last
enrollment method (at least one must remain).

**Use Cases:**
- Remove compromised passphrase
- Remove lost/stolen hardware key
- Clean up unused authentication methods

##### Parameters

###### enrollmentId

`string`

Enrollment ID to remove (e.g., "enrollment:passphrase:v2")

###### credentials

[`AuthCredentials`](../../types/type-aliases/AuthCredentials.md)

Current authentication credentials (proves ownership)

##### Returns

`Promise`\<\{ `success`: `boolean`; \}\>

Promise resolving to success status

##### Throws

Authentication failed

##### Throws

Cannot remove last enrollment method

##### Throws

Enrollment not found

##### Throws

KMS not initialized

##### Example

```typescript
// Remove a passphrase enrollment
await kmsUser.removeEnrollment(
  'enrollment:passphrase:v2',
  { passphrase: 'current-passphrase' }
);

console.log('Passphrase enrollment removed');

// Verify removal
const { enrollments } = await kmsUser.getEnrollments();
console.log('Remaining methods:', enrollments);
```

##### See

 - [getEnrollments](#getenrollments) to list all enrollment methods
 - [addEnrollment](#addenrollment) to add a new method

***

#### resetKMS()

> **resetKMS**(): `Promise`\<\{ `success`: `boolean`; \}\>

Defined in: [kms-user.ts:1857](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L1857)

Reset KMS and delete all data.

**DESTRUCTIVE OPERATION** - Permanently deletes all KMS data including:
- All enrollment methods (passphrase, passkeys)
- Master Secret and derived keys
- VAPID keypairs
- All leases
- Push subscriptions
- Audit log

This operation cannot be undone. Use for testing, debugging, or complete account reset.

**Security:** No authentication required - this is a nuclear option for complete reset.

##### Returns

`Promise`\<\{ `success`: `boolean`; \}\>

Promise resolving to success status

##### Throws

KMS not initialized

##### Throws

IndexedDB access denied

##### Example

```typescript
// ⚠️ WARNING: This deletes everything!
const result = await kmsUser.resetKMS();
console.log('KMS reset complete - all data deleted');

// After reset, user must setup again
await kmsUser.setupPassphrase('user@example.com', 'new-passphrase');
```

##### See

[setupPassphrase](#setuppassphrase) to setup after reset

### Other

#### addEnrollmentWithPopup()

> **addEnrollmentWithPopup**(`userId`): `Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Defined in: [kms-user.ts:829](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L829)

Add additional authentication method using popup flow (reversed order).
Opens popup FIRST to collect new credentials, then unlocks with existing.
This method preserves the user gesture for popup opening.

Multi-enrollment enables:
- Multiple authentication methods for same Master Secret
- Add passkey after initial passphrase setup
- Add additional passkey on new device

**Required**: KMS must already be set up (see [isSetup](#issetup))

**Flow**:
1. Opens popup to collect NEW authentication credentials (user gesture preserved)
2. Shows unlock modal to collect EXISTING credentials
3. Unlocks with existing credentials to get Master Secret
4. Re-wraps Master Secret with new KEK from popup
5. Returns enrollment ID

**Popup Window**: The method opens a popup window (`kms.ats.run`) for credential
collection. The popup must not be blocked by the browser. Call this method
directly from a user gesture (button click) to ensure popup success.

##### Parameters

###### userId

`string`

User identifier (must match existing setup)

##### Returns

`Promise`\<[`SetupResult`](../interfaces/SetupResult.md)\>

Promise resolving to setup result

##### Throws

Popup was blocked by browser

##### Throws

Authentication failed with existing credentials

##### Throws

Method already enrolled

##### Throws

KMS not initialized

##### Example

```typescript
// Add passkey after initial passphrase setup
async function addPasskey() {
  try {
    const result = await kmsUser.addEnrollmentWithPopup('user@example.com');
    console.log('Added enrollment:', result.enrollmentId);
  } catch (error) {
    if (error.message.includes('blocked')) {
      alert('Please allow popups for this site');
    }
  }
}

// Call from button click to preserve user gesture
button.addEventListener('click', addPasskey);
```

##### See

 - [addEnrollment](#addenrollment) for credential-first flow (may be blocked)
 - [getEnrollments](#getenrollments) to list all enrolled methods
 - [removeEnrollment](#removeenrollment) to remove a method

***

#### fullSetup()

> **fullSetup**(`params`): `Promise`\<\{ `autoExtend`: `boolean`; `enrollmentId`: `string`; `jwts`: `object`[]; `leaseExp`: `number`; `leaseId`: `string`; `subscription`: [`StoredPushSubscription`](../../types/interfaces/StoredPushSubscription.md); `success`: `true`; `vapidKid`: `string`; `vapidPublicKey`: `string`; \}\>

Defined in: [kms-user.ts:926](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L926)

Full Setup - Complete onboarding in one action.

Orchestrates:
1. User authentication setup (via popup)
2. Web Push subscription (via parent PWA)
3. VAPID lease creation (with autoExtend flag)
4. JWT packet issuance (5 tokens with staggered expirations)
5. Test notification (confirms setup working)

All with a single user authentication!

##### Parameters

###### params

Setup parameters

###### autoExtend?

`boolean`

Whether lease can be auto-extended (default: true)

###### ttlHours?

`number`

Lease TTL in hours (default: 12, max: 720)

###### userId

`string`

User ID

##### Returns

`Promise`\<\{ `autoExtend`: `boolean`; `enrollmentId`: `string`; `jwts`: `object`[]; `leaseExp`: `number`; `leaseId`: `string`; `subscription`: [`StoredPushSubscription`](../../types/interfaces/StoredPushSubscription.md); `success`: `true`; `vapidKid`: `string`; `vapidPublicKey`: `string`; \}\>

Complete setup result with lease, JWTs, and subscription

***

#### init()

> **init**(): `Promise`\<`void`\>

Defined in: [kms-user.ts:202](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L202)

Initialize the KMS by creating and loading the iframe

##### Returns

`Promise`\<`void`\>

##### Throws

If already initialized or iframe creation fails

***

#### terminate()

> **terminate**(): `void`

Defined in: [kms-user.ts:297](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L297)

Terminate the KMS iframe
Clears all pending requests without rejecting them to avoid unhandled rejection errors

##### Returns

`void`
