[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / WrappedKey

# Interface: WrappedKey

Defined in: [types.ts:243](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L243)

Wrapped application key stored in IndexedDB.

Application keys (e.g., VAPID signing keys) are encrypted with the Master Key
Encryption Key (MKEK) derived from the Master Secret. The wrapped key is stored
with metadata and optional push subscription data.

**Encryption:**
- Algorithm: AES-GCM
- KEK: MKEK (derived from Master Secret via HKDF)
- AAD: Binds metadata to ciphertext (prevents swapping attacks)

**Storage:**
- Location: IndexedDB `wrappedKeys` object store
- Key path: `kid` (Key ID - JWK thumbprint)
- Indexed by: `purpose` for efficient queries

**Push Subscription:**
- VAPID keys can have an optional `subscription` field
- Establishes 1:1 relationship between VAPID key and push subscription
- Lost when VAPID key is regenerated

## Example

```typescript
const wrappedVapidKey: WrappedKey = {
  kid: 'vapid-key-123',
  kmsVersion: 2,
  wrappedKey: ArrayBuffer, // Encrypted VAPID private key
  iv: ArrayBuffer,         // AES-GCM IV
  aad: ArrayBuffer,        // Additional Authenticated Data
  publicKeyRaw: ArrayBuffer, // P-256 public key (65 bytes, uncompressed)
  alg: 'ES256',
  purpose: 'vapid',
  createdAt: Date.now(),
  lastUsedAt: Date.now(),
  subscription: { ... },   // Optional push subscription
};
```

## Properties

### aad

> **aad**: `ArrayBuffer`

Defined in: [types.ts:253](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L253)

Additional Authenticated Data (binds metadata to ciphertext)

***

### alg

> **alg**: `string`

Defined in: [types.ts:257](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L257)

Algorithm (e.g., "ES256" for ECDSA P-256, "Ed25519" for audit keys)

***

### createdAt

> **createdAt**: `number`

Defined in: [types.ts:261](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L261)

Creation timestamp in milliseconds

***

### iv

> **iv**: `ArrayBuffer`

Defined in: [types.ts:251](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L251)

Initialization vector for AES-GCM encryption

***

### kid

> **kid**: `string`

Defined in: [types.ts:245](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L245)

Key ID (JWK thumbprint) - unique identifier

***

### kmsVersion

> **kmsVersion**: `number`

Defined in: [types.ts:247](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L247)

KMS version (currently 2)

***

### lastUsedAt?

> `optional` **lastUsedAt**: `number`

Defined in: [types.ts:263](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L263)

Last usage timestamp in milliseconds (optional)

***

### publicKeyRaw?

> `optional` **publicKeyRaw**: `ArrayBuffer`

Defined in: [types.ts:255](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L255)

Public key in raw format (optional, for asymmetric keys like VAPID)

***

### purpose

> **purpose**: `string`

Defined in: [types.ts:259](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L259)

Key purpose (e.g., "vapid", "audit-user", "audit-lease")

***

### subscription?

> `optional` **subscription**: [`StoredPushSubscription`](StoredPushSubscription.md)

Defined in: [types.ts:265](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L265)

Optional push subscription for VAPID keys (1:1 relationship)

***

### wrappedKey

> **wrappedKey**: `ArrayBuffer`

Defined in: [types.ts:249](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L249)

Encrypted private key (AES-GCM ciphertext)
