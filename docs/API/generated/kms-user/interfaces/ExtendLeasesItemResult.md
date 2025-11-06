[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [kms-user](../README.md) / ExtendLeasesItemResult

# Interface: ExtendLeasesItemResult

Defined in: [kms-user.ts:120](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L120)

Individual lease result in batch operation

## Properties

### leaseId

> **leaseId**: `string`

Defined in: [kms-user.ts:121](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L121)

***

### reason?

> `optional` **reason**: `string`

Defined in: [kms-user.ts:123](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L123)

***

### result?

> `optional` **result**: [`ExtendLeaseResult`](ExtendLeaseResult.md)

Defined in: [kms-user.ts:124](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L124)

***

### status

> **status**: `"extended"` \| `"skipped"`

Defined in: [kms-user.ts:122](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L122)
