[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / VAPIDPayload

# Interface: VAPIDPayload

Defined in: [types.ts:594](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L594)

VAPID JWT payload structure (RFC 8292 compliant).

The JWT payload for VAPID (Voluntary Application Server Identification)
authentication with push services. Conforms to RFC 8292 requirements.

**Required Claims:**
- `aud`: Push service origin (e.g., "https://fcm.googleapis.com")
- `exp`: Expiration timestamp (max 24 hours from issuance)
- `sub`: Subject (typically "mailto:admin@example.com" or origin URL)
- `jti`: JWT ID (unique identifier to prevent replay)

**Additional claims** can be included via index signature.

## Example

```typescript
const payload: VAPIDPayload = {
  aud: 'https://fcm.googleapis.com',
  exp: Date.now() + (15 * 60 * 1000), // 15 minutes
  sub: 'mailto:admin@ats.run',
  jti: crypto.randomUUID(),
};
```

## Indexable

\[`claim`: `string`\]: `unknown`

Additional custom claims

## Properties

### aud

> **aud**: `string`

Defined in: [types.ts:596](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L596)

Audience - push service origin (e.g., "https://fcm.googleapis.com")

***

### exp

> **exp**: `number`

Defined in: [types.ts:598](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L598)

Expiration time in seconds since epoch

***

### jti

> **jti**: `string`

Defined in: [types.ts:602](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L602)

JWT ID - unique identifier for this token

***

### sub

> **sub**: `string`

Defined in: [types.ts:600](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L600)

Subject - typically "mailto:admin@example.com" or origin URL
