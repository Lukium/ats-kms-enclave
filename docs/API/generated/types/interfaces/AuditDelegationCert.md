[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / AuditDelegationCert

# Interface: AuditDelegationCert

Defined in: [types.ts:303](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L303)

Audit delegation certificate

Authorizes a signing key (LAK or KIAK) to sign audit entries.
Signed by UAK to create chain of trust back to user's Master Secret.

## Properties

### codeHash

> **codeHash**: `string`

Defined in: [types.ts:313](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L313)

***

### delegatePub

> **delegatePub**: `string`

Defined in: [types.ts:309](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L309)

***

### instanceId?

> `optional` **instanceId**: `string`

Defined in: [types.ts:308](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L308)

***

### kmsVersion

> **kmsVersion**: `string`

Defined in: [types.ts:315](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L315)

***

### leaseId?

> `optional` **leaseId**: `string`

Defined in: [types.ts:307](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L307)

***

### manifestHash

> **manifestHash**: `string`

Defined in: [types.ts:314](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L314)

***

### notAfter

> **notAfter**: `number` \| `null`

Defined in: [types.ts:312](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L312)

***

### notBefore

> **notBefore**: `number`

Defined in: [types.ts:311](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L311)

***

### scope

> **scope**: `string`[]

Defined in: [types.ts:310](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L310)

***

### sig

> **sig**: `string`

Defined in: [types.ts:316](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L316)

***

### signerKind

> **signerKind**: `"LAK"` \| `"KIAK"`

Defined in: [types.ts:306](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L306)

***

### type

> **type**: `"audit-delegation"`

Defined in: [types.ts:304](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L304)

***

### version

> **version**: `1`

Defined in: [types.ts:305](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L305)
