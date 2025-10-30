[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / VAPIDPayload

# Interface: VAPIDPayload

Defined in: [types.ts:587](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L587)

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

Defined in: [types.ts:589](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L589)

Audience - push service origin (e.g., "https://fcm.googleapis.com")

***

### exp

> **exp**: `number`

Defined in: [types.ts:591](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L591)

Expiration time in seconds since epoch

***

### jti

> **jti**: `string`

Defined in: [types.ts:595](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L595)

JWT ID - unique identifier for this token

***

### sub

> **sub**: `string`

Defined in: [types.ts:593](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L593)

Subject - typically "mailto:admin@example.com" or origin URL
