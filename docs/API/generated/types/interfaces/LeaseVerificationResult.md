[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / LeaseVerificationResult

# Interface: LeaseVerificationResult

Defined in: [types.ts:552](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L552)

Result of lease verification check.

Returned by `verifyLease()` to indicate whether a lease is valid.
A lease is valid if:
1. It exists in storage
2. It has not expired (`exp > Date.now()`)
3. Its `kid` matches the current VAPID key

## Example

```typescript
const result: LeaseVerificationResult = {
  leaseId: 'lease-abc-123',
  valid: false,
  reason: 'expired',
  kid: 'old-vapid-key-id',
};

// Possible reasons: 'expired', 'wrong-key', 'not-found'
```

## Properties

### kid

> **kid**: `string`

Defined in: [types.ts:560](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L560)

Key ID from the lease

***

### leaseId

> **leaseId**: `string`

Defined in: [types.ts:554](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L554)

Lease ID being verified (echoed from input)

***

### reason?

> `optional` **reason**: `string`

Defined in: [types.ts:558](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L558)

Reason for invalidity if `valid: false` ("expired" | "wrong-key" | "not-found")

***

### valid

> **valid**: `boolean`

Defined in: [types.ts:556](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L556)

Whether the lease is valid
