[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / AuditEntryV2

# Interface: AuditEntryV2

Defined in: [types.ts:327](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L327)

V2 audit entry with delegation support

Entries can be signed by three types of keys:
- UAK: User Audit Key (user-authenticated operations)
- LAK: Lease Audit Key (lease-scoped background operations)
- KIAK: KMS Instance Audit Key (system events)

## Properties

### cert?

> `optional` **cert**: [`AuditDelegationCert`](AuditDelegationCert.md)

Defined in: [types.ts:347](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L347)

***

### chainHash

> **chainHash**: `string`

Defined in: [types.ts:342](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L342)

***

### details?

> `optional` **details**: `Record`\<`string`, `unknown`\>

Defined in: [types.ts:340](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L340)

***

### duration?

> `optional` **duration**: `number`

Defined in: [types.ts:339](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L339)

***

### kid

> **kid**: `string`

Defined in: [types.ts:332](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L332)

***

### kmsVersion

> **kmsVersion**: `2`

Defined in: [types.ts:328](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L328)

***

### leaseId?

> `optional` **leaseId**: `string`

Defined in: [types.ts:336](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L336)

***

### lockTime?

> `optional` **lockTime**: `number`

Defined in: [types.ts:338](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L338)

***

### op

> **op**: `string`

Defined in: [types.ts:331](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L331)

***

### origin?

> `optional` **origin**: `string`

Defined in: [types.ts:335](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L335)

***

### previousHash

> **previousHash**: `string`

Defined in: [types.ts:341](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L341)

***

### requestId

> **requestId**: `string`

Defined in: [types.ts:333](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L333)

***

### seqNum

> **seqNum**: `number`

Defined in: [types.ts:329](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L329)

***

### sig

> **sig**: `string`

Defined in: [types.ts:350](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L350)

***

### signer

> **signer**: `"LAK"` \| `"KIAK"` \| `"UAK"`

Defined in: [types.ts:345](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L345)

***

### signerId

> **signerId**: `string`

Defined in: [types.ts:346](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L346)

***

### sigNew?

> `optional` **sigNew**: `string`

Defined in: [types.ts:351](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L351)

***

### timestamp

> **timestamp**: `number`

Defined in: [types.ts:330](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L330)

***

### unlockTime?

> `optional` **unlockTime**: `number`

Defined in: [types.ts:337](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L337)

***

### userId

> **userId**: `string`

Defined in: [types.ts:334](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L334)
