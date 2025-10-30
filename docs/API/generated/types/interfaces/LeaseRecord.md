[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / LeaseRecord

# Interface: LeaseRecord

Defined in: [types.ts:480](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L480)

VAPID lease record for credential-free JWT issuance.

A lease allows issuing VAPID JWTs without re-authentication by wrapping the VAPID
private key with a session-specific KEK (SessionKEK) derived from the Master Secret.
The wrapped key is stored in worker memory, enabling JWT signing until lease expiration.

**Security Model:**
- SessionKEK derived from: MS + random leaseSalt via HKDF
- VAPID private key wrapped with SessionKEK (not MKEK)
- Wrapped key stored in memory only (not IndexedDB)
- Lease invalidated when VAPID key regenerated (kid mismatch)

**Push Subscription:**
- Subscription data is NOT stored in lease
- Worker reads subscription from VAPID key's `subscription` field
- All leases for a VAPID key share the same subscription

**Quotas:**
- 100 tokens per hour (global)
- 10 sends per minute (burst: 20)
- 5 sends per minute per endpoint ID

## Example

```typescript
// Lease stored in worker memory after createLease()
const lease: LeaseRecord = {
  leaseId: 'lease-abc-123',
  userId: 'user@example.com',
  ttlHours: 12,
  createdAt: Date.now(),
  exp: Date.now() + (12 * 60 * 60 * 1000),
  quotas: {
    tokensPerHour: 100,
    sendsPerMinute: 10,
    burstSends: 20,
    sendsPerMinutePerEid: 5,
  },
  wrappedLeaseKey: ArrayBuffer, // VAPID private key wrapped with SessionKEK
  wrappedLeaseKeyIV: ArrayBuffer,
  leaseSalt: ArrayBuffer, // Used to derive SessionKEK
  kid: 'vapid-key-id',
  lakDelegationCert: { ... }, // LAK authorization
};
```

## Properties

### createdAt

> **createdAt**: `number`

Defined in: [types.ts:490](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L490)

Creation timestamp in milliseconds

***

### exp

> **exp**: `number`

Defined in: [types.ts:492](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L492)

Expiration timestamp in milliseconds

***

### kid

> **kid**: `string`

Defined in: [types.ts:503](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L503)

Key ID (JWK thumbprint) of the VAPID keypair

***

### lakDelegationCert

> **lakDelegationCert**: [`AuditDelegationCert`](AuditDelegationCert.md)

Defined in: [types.ts:506](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L506)

LAK delegation certificate authorizing this lease to sign audit entries

***

### leaseId

> **leaseId**: `string`

Defined in: [types.ts:482](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L482)

Unique lease identifier (format: "lease-{uuid}")

***

### leaseSalt

> **leaseSalt**: `ArrayBuffer`

Defined in: [types.ts:501](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L501)

Random salt used to derive SessionKEK from Master Secret via HKDF

***

### quotas

> **quotas**: [`QuotaState`](QuotaState.md)

Defined in: [types.ts:494](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L494)

Rate limit quotas for this lease

***

### ttlHours

> **ttlHours**: `number`

Defined in: [types.ts:488](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L488)

Lease time-to-live in hours (max 720 hours / 30 days)

***

### userId

> **userId**: `string`

Defined in: [types.ts:484](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L484)

User ID associated with this lease

***

### wrappedLeaseKey

> **wrappedLeaseKey**: `ArrayBuffer`

Defined in: [types.ts:497](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L497)

VAPID private key wrapped with SessionKEK (AES-GCM)

***

### wrappedLeaseKeyIV

> **wrappedLeaseKeyIV**: `ArrayBuffer`

Defined in: [types.ts:499](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L499)

IV used for AES-GCM encryption of wrappedLeaseKey
