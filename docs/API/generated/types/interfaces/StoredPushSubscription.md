[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / StoredPushSubscription

# Interface: StoredPushSubscription

Defined in: [types.ts:175](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L175)

Web Push subscription data stored with VAPID key.

Represents a push notification subscription returned by `PushManager.subscribe()`.
The subscription establishes a 1:1 relationship with the VAPID key - each VAPID
key can have exactly one subscription. Stored on the `WrappedKey.subscription` field.

**Storage:** Stored with VAPID key, NOT in lease records. All leases for a VAPID
key use the same subscription (single source of truth).

**Lifecycle:** Lost when VAPID key is regenerated. Must call `setPushSubscription()`
again after `regenerateVAPID()`.

**Security:** Endpoints are validated against a whitelist of known push services:
FCM, APNs, Mozilla Push, Windows Push Notification Services.

## Example

```typescript
// Browser push subscription converted to StoredPushSubscription
const registration = await navigator.serviceWorker.ready;
const pushSub = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: vapidPublicKey,
});

const storedSub: StoredPushSubscription = {
  endpoint: pushSub.endpoint,
  expirationTime: pushSub.expirationTime,
  keys: {
    p256dh: arrayBufferToBase64url(pushSub.getKey('p256dh')),
    auth: arrayBufferToBase64url(pushSub.getKey('auth')),
  },
  eid: 'my-laptop-chrome',
  createdAt: Date.now(),
};
```

## Properties

### createdAt

> **createdAt**: `number`

Defined in: [types.ts:190](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L190)

Creation timestamp in milliseconds

***

### eid

> **eid**: `string`

Defined in: [types.ts:188](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L188)

Endpoint ID - user-defined label for this device/browser (e.g., "laptop-chrome")

***

### endpoint

> **endpoint**: `string`

Defined in: [types.ts:177](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L177)

Push service endpoint URL (must be HTTPS and whitelisted: FCM/APNs/Mozilla/WNS)

***

### expirationTime

> **expirationTime**: `number` \| `null`

Defined in: [types.ts:179](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L179)

When subscription expires in milliseconds (null = no expiry)

***

### keys

> **keys**: `object`

Defined in: [types.ts:181](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L181)

Client encryption keys for push message encryption

#### auth

> **auth**: `string`

Authentication secret (base64url-encoded, 16 bytes decoded)

#### p256dh

> **p256dh**: `string`

Client public key (base64url-encoded, 65 bytes decoded)
