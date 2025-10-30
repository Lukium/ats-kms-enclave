# KMS V2 API Reference

**Version:** 2.0.0
**Last Updated:** 2025-10-30

Complete API documentation for the KMS V2 implementation, generated from TypeScript source code using TypeDoc.

---

## Quick Start

### Main API Documentation

- **[KMSUser Class](generated/kms-user/classes/KMSUser.md)** - Complete API reference with all methods
- **[Type Definitions](generated/types/README.md)** - All TypeScript interfaces and types

### Browse by Category

The KMSUser class provides methods organized into logical categories:

1. **[Setup Operations](#setup-operations)** - Initialize KMS with authentication
2. **[VAPID Key Management](#vapid-key-management)** - Generate and manage VAPID keys
3. **[VAPID Lease Operations](#vapid-lease-operations)** - Create leases and issue JWTs
4. **[Push Notifications](#push-notifications)** - Manage push subscriptions
5. **[Status and Query Operations](#status-and-query-operations)** - Check KMS state
6. **[Management Operations](#management-operations)** - Reset, audit, and cleanup

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

## Setup Operations

Initialize the KMS with one or more authentication methods.

| Method | Description | Documentation |
|--------|-------------|---------------|
| **setupPassphrase** | Setup with passphrase authentication | [View](generated/kms-user/classes/KMSUser.md#setuppassphrase) |
| **setupPasskeyPRF** | Setup with WebAuthn PRF | [View](generated/kms-user/classes/KMSUser.md#setuppasskeyprf) |
| **setupPasskeyGate** | Setup with WebAuthn gate authentication | [View](generated/kms-user/classes/KMSUser.md#setuppasskeygate) |
| **addEnrollment** | Add additional authentication method | [View](generated/kms-user/classes/KMSUser.md#addenrollment) |
| **removeEnrollment** | Remove an authentication method | [View](generated/kms-user/classes/KMSUser.md#removeenrollment) |

**Example:**

```typescript
const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
await kmsUser.init();

// Setup with passphrase
const result = await kmsUser.setupPassphrase(
  'user@example.com',
  'my-secure-passphrase-123'
);

console.log('Enrollment ID:', result.enrollmentId);
```

---

## VAPID Key Management

Generate and manage VAPID (Voluntary Application Server Identification) keys for Web Push.

| Method | Description | Documentation |
|--------|-------------|---------------|
| **regenerateVAPID** | Generate new VAPID keypair (invalidates leases) | [View](generated/kms-user/classes/KMSUser.md#regeneratevapid) |
| **getPublicKey** | Get VAPID public key (raw P-256 format) | [View](generated/kms-user/classes/KMSUser.md#getpublickey) |
| **getVAPIDPublicKey** | Get VAPID public key (convenience method) | [View](generated/kms-user/classes/KMSUser.md#getvapidpublickey) |

**Example:**

```typescript
// Generate new VAPID key
const vapidResult = await kmsUser.regenerateVAPID(
  { type: 'passphrase', passphrase: 'my-passphrase' }
);

console.log('VAPID kid:', vapidResult.kid);
console.log('Public key (base64url):', vapidResult.publicKeyBase64url);
```

---

## VAPID Lease Operations

Create leases for credential-free JWT issuance with quota management.

| Method | Description | Documentation |
|--------|-------------|---------------|
| **createLease** | Create a lease for JWT issuance | [View](generated/kms-user/classes/KMSUser.md#createlease) |
| **verifyLease** | Verify lease validity | [View](generated/kms-user/classes/KMSUser.md#verifylease) |
| **issueVAPIDJWT** | Issue a single VAPID JWT | [View](generated/kms-user/classes/KMSUser.md#issuevapidJWT) |
| **issueVAPIDJWTs** | Issue multiple JWTs with staggered expiration | [View](generated/kms-user/classes/KMSUser.md#issuevapidJWTs) |
| **getUserLeases** | List all leases for user | [View](generated/kms-user/classes/KMSUser.md#getuserleases) |

**Lease System Overview:**

Leases enable credential-free JWT issuance by deriving a SessionKEK from authentication. The VAPID key is wrapped with the SessionKEK and stored in the lease record, allowing JWT issuance without re-authentication until the lease expires or quota is exhausted.

**Example:**

```typescript
// Create a lease
const leaseResult = await kmsUser.createLease(
  { type: 'passphrase', passphrase: 'my-passphrase' },
  86400000  // 24 hours
);

// Issue JWTs without authentication
const jwtResult = await kmsUser.issueVAPIDJWT(
  leaseResult.leaseId,
  'https://push.example.com',
  'mailto:admin@example.com',
  3600  // 1 hour expiration
);
```

---

## Push Notifications

Manage Web Push subscriptions associated with VAPID keys.

| Method | Description | Documentation |
|--------|-------------|---------------|
| **setPushSubscription** | Store push subscription with VAPID key | [View](generated/kms-user/classes/KMSUser.md#setpushsubscription) |
| **getPushSubscription** | Retrieve stored push subscription | [View](generated/kms-user/classes/KMSUser.md#getpushsubscription) |
| **removePushSubscription** | Remove push subscription | [View](generated/kms-user/classes/KMSUser.md#removepushsubscription) |

**See also:** [StoredPushSubscription Type](generated/types/interfaces/StoredPushSubscription.md)

**Example:**

```typescript
// Subscribe to push notifications
const registration = await navigator.serviceWorker.ready;
const pushSub = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: vapidPublicKey,
});

// Store subscription with KMS
await kmsUser.setPushSubscription({
  endpoint: pushSub.endpoint,
  expirationTime: pushSub.expirationTime,
  keys: {
    p256dh: arrayBufferToBase64url(pushSub.getKey('p256dh')),
    auth: arrayBufferToBase64url(pushSub.getKey('auth')),
  },
  eid: 'laptop-chrome',
  createdAt: Date.now(),
});
```

---

## Status and Query Operations

Check KMS state and retrieve information.

| Method | Description | Documentation |
|--------|-------------|---------------|
| **isSetup** | Check if KMS is initialized | [View](generated/kms-user/classes/KMSUser.md#issetup) |
| **getEnrollments** | List all authentication enrollments | [View](generated/kms-user/classes/KMSUser.md#getenrollments) |
| **verifyAuditChain** | Verify audit log integrity | [View](generated/kms-user/classes/KMSUser.md#verifyauditchain) |
| **getAuditLog** | Retrieve audit log entries | [View](generated/kms-user/classes/KMSUser.md#getauditlog) |
| **getAuditPublicKey** | Get audit signing public key | [View](generated/kms-user/classes/KMSUser.md#getauditpublickey) |

**Example:**

```typescript
// Check if KMS is initialized
const status = await kmsUser.isSetup();
if (status.isSetup) {
  console.log('KMS is ready');
  console.log('Enrollments:', status.enrollments);
  console.log('Active leases:', status.leases.length);
}
```

---

## Management Operations

Administrative operations for KMS management.

| Method | Description | Documentation |
|--------|-------------|---------------|
| **resetKMS** | ⚠️ Destroy all KMS data | [View](generated/kms-user/classes/KMSUser.md#resetkms) |

**Example:**

```typescript
// Reset KMS (requires authentication)
await kmsUser.resetKMS(
  { type: 'passphrase', passphrase: 'my-passphrase' }
);
console.log('KMS reset complete');
```

---

## Types Reference

Complete TypeScript type definitions for all API operations.

### Core Types

- **[KMSUserConfig](generated/kms-user/interfaces/KMSUserConfig.md)** - Configuration for KMSUser instance
- **[AuthCredentials](generated/types/type-aliases/AuthCredentials.md)** - Authentication credentials (passphrase/PRF/gate)
- **[StoredPushSubscription](generated/types/interfaces/StoredPushSubscription.md)** - Push subscription data

### Return Types

- **[SetupResult](generated/kms-user/interfaces/SetupResult.md)** - Result from setup operations
- **[UnlockResult](generated/kms-user/interfaces/UnlockResult.md)** - Result from unlock operations
- **[VAPIDKeyResult](generated/kms-user/interfaces/VAPIDKeyResult.md)** - VAPID key information
- **[LeaseResult](generated/kms-user/interfaces/LeaseResult.md)** - Lease creation result
- **[JWTResult](generated/kms-user/interfaces/JWTResult.md)** - JWT issuance result
- **[StatusResult](generated/kms-user/interfaces/StatusResult.md)** - KMS status information
- **[AuditVerificationResult](generated/kms-user/interfaces/AuditVerificationResult.md)** - Audit chain verification

### Internal Types

- **[LeaseRecord](generated/types/interfaces/LeaseRecord.md)** - Lease storage format
- **[LeaseVerificationResult](generated/types/interfaces/LeaseVerificationResult.md)** - Lease validation result
- **[QuotaState](generated/types/interfaces/QuotaState.md)** - JWT issuance quota tracking
- **[VAPIDPayload](generated/types/interfaces/VAPIDPayload.md)** - RFC 8292 VAPID JWT payload
- **[WrappedKey](generated/types/interfaces/WrappedKey.md)** - Encrypted key storage format

**[View All Types →](generated/types/README.md)**

---

## Error Handling

All KMS operations throw errors with descriptive messages. Common error scenarios:

### Authentication Errors
```typescript
try {
  await kmsUser.setupPassphrase('user@example.com', 'short');
} catch (error) {
  // Error: Passphrase must be at least 8 characters
}
```

### Timeout Errors
```typescript
try {
  await kmsUser.createLease(credentials, 86400000);
} catch (error) {
  // Error: Request timeout (>10s)
}
```

### State Errors
```typescript
try {
  await kmsUser.getPublicKey();
} catch (error) {
  // Error: No VAPID key exists - call regenerateVAPID() first
}
```

---

## Security Model

### Key Hierarchy

```
Master Secret (MS) - 32 bytes random
    ↓ HKDF
Master Key Encryption Key (MKEK)
    ↓ wraps
VAPID Private Key (ECDSA P-256)
    ↓ derives (per-lease)
Session KEK (SessionKEK)
    ↓ wraps (for lease)
VAPID Private Key (wrapped in lease)
```

### Security Properties

1. **Non-extractable keys** - VAPID private keys use `extractable: false`
2. **Cross-origin isolation** - KMS runs in separate origin (`kms.ats.run`)
3. **Per-operation authentication** - No persistent unlock sessions
4. **Tamper-evident audit log** - Ed25519-signed chain
5. **Quota limits** - Rate limiting on JWT issuance (default: 100 JWTs per lease)

### Trust Boundaries

- **Browser vendor** - Must trust WebCrypto implementation
- **OS** - Must trust platform security
- **KMS iframe** - Isolated by cross-origin policy
- **Service Worker** - Cannot access KMS internals

For complete security documentation, see [Architecture Docs](../architecture/crypto/README.md).

---

## Performance Benchmarks

Typical performance on modern hardware (2023 laptop):

| Operation | Duration | Notes |
|-----------|----------|-------|
| PBKDF2 (passphrase) | 150-300ms | Calibrated per-device |
| VAPID key generation | 20-50ms | ECDSA P-256 |
| JWT signing | 5-15ms | ECDSA signature |
| Lease creation | 200-350ms | Includes PBKDF2 + crypto |
| JWT issuance (with lease) | 5-15ms | No authentication needed |

---

## Complete Workflow Example

```typescript
import { KMSUser } from '@ats/kms-enclave';

// 1. Initialize KMS
const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
await kmsUser.init();

// 2. Setup with passphrase
const setupResult = await kmsUser.setupPassphrase(
  'user@example.com',
  'my-secure-passphrase'
);
console.log('Enrollment ID:', setupResult.enrollmentId);

// 3. Generate VAPID key
const vapidResult = await kmsUser.regenerateVAPID(
  { type: 'passphrase', passphrase: 'my-secure-passphrase' }
);
console.log('VAPID kid:', vapidResult.kid);

// 4. Subscribe to push notifications
const registration = await navigator.serviceWorker.ready;
const pushSub = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: base64urlToUint8Array(vapidResult.publicKeyBase64url),
});

// 5. Store push subscription
await kmsUser.setPushSubscription({
  endpoint: pushSub.endpoint,
  expirationTime: pushSub.expirationTime,
  keys: {
    p256dh: arrayBufferToBase64url(pushSub.getKey('p256dh')),
    auth: arrayBufferToBase64url(pushSub.getKey('auth')),
  },
  eid: 'laptop-chrome',
  createdAt: Date.now(),
});

// 6. Create a lease for credential-free JWT issuance
const leaseResult = await kmsUser.createLease(
  { type: 'passphrase', passphrase: 'my-secure-passphrase' },
  86400000  // 24 hours
);

// 7. Issue VAPID JWTs without re-authentication
const jwtResult = await kmsUser.issueVAPIDJWT(
  leaseResult.leaseId,
  'https://fcm.googleapis.com',
  'mailto:admin@example.com',
  3600  // 1 hour
);

// 8. Use JWT to authorize with push service
console.log('VAPID Authorization:', jwtResult.authorizationHeader);
```

---

## Testing Reference

The KMS implementation includes comprehensive test coverage:

- **Unit tests** - Crypto operations, key derivation, validation
- **Integration tests** - End-to-end workflows, error scenarios
- **Browser tests** - Playwright E2E tests with real browser environments

Run tests:
```bash
pnpm test              # Unit tests
pnpm test:browser      # Browser integration tests
pnpm test:coverage     # Coverage report (80% required)
```

---

## Documentation Generation

This documentation is automatically generated from TypeScript source code using TypeDoc.

**Regenerate documentation:**
```bash
pnpm docs              # Generate docs
pnpm docs:watch        # Watch mode for development
```

**Configuration:** See [typedoc.json](../../typedoc.json) for TypeDoc settings.

---

## Version History

### 2.0.0 (2025-10-30)
- **NEW:** TypeDoc-generated API documentation
- **NEW:** Comprehensive JSDoc comments on all public methods
- **NEW:** Push notification subscription management
- **IMPROVED:** Lease verification with automatic cleanup
- **IMPROVED:** VAPID key regeneration invalidates leases and subscriptions

### 1.0.0 (2025-10-29)
- Initial V2 implementation
- Per-operation authentication
- Lease-based JWT issuance
- Tamper-evident audit log

---

## Additional Resources

- **[Architecture Documentation](../architecture/crypto/README.md)** - Complete design and security model
- **[Implementation Guide](../architecture/crypto/design/06-implementation-guide.md)** - Production-ready utilities
- **[GitHub Repository](https://github.com/your-org/ats-kms)** - Source code and issue tracker

---

**Questions or Issues?** Check the [GitHub Issues](https://github.com/your-org/ats-kms/issues) or review the [Architecture Docs](../architecture/crypto/README.md).
