[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [kms-user](../README.md) / KMSUserConfig

# Interface: KMSUserConfig

Defined in: [kms-user.ts:39](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L39)

Configuration for KMSUser

## Properties

### autoInit?

> `optional` **autoInit**: `boolean`

Defined in: [kms-user.ts:55](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L55)

Whether to auto-initialize on construction

#### Default

```ts
false
```

***

### defaultTimeout?

> `optional` **defaultTimeout**: `number`

Defined in: [kms-user.ts:49](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L49)

Default timeout for RPC requests in milliseconds

#### Default

```ts
10000 (10 seconds)
```

***

### kmsOrigin

> **kmsOrigin**: `string`

Defined in: [kms-user.ts:43](https://github.com/your-org/ats-kms/blob/main/src/v2/kms-user.ts#L43)

Origin of the KMS iframe (e.g., 'https://kms.ats.run')
