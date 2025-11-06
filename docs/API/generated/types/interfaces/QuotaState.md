[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / QuotaState

# Interface: QuotaState

Defined in: [types.ts:527](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L527)

Rate limit quotas enforced by the KMS worker for lease operations.

Quotas prevent abuse by limiting JWT issuance rates. Enforced in worker
memory using token bucket and sliding window algorithms.

**Default Limits:**
- `tokensPerHour`: 100 (global rate limit)
- `sendsPerMinute`: 10 (burst: 20)
- `sendsPerMinutePerEid`: 5 (per-endpoint limit)

## Properties

### burstSends

> **burstSends**: `number`

Defined in: [types.ts:533](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L533)

Maximum burst sends (allows short bursts above sustained rate)

***

### sendsPerMinute

> **sendsPerMinute**: `number`

Defined in: [types.ts:531](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L531)

Maximum push sends per minute (sustained rate)

***

### sendsPerMinutePerEid

> **sendsPerMinutePerEid**: `number`

Defined in: [types.ts:535](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L535)

Maximum sends per minute per endpoint ID (prevents single endpoint abuse)

***

### tokensPerHour

> **tokensPerHour**: `number`

Defined in: [types.ts:529](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L529)

Maximum tokens that can be issued per hour (global limit)
