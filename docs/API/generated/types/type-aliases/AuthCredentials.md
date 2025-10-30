[**@ats/kms-enclave v0.0.0**](../../README.md)

***

[@ats/kms-enclave](../../README.md) / [types](../README.md) / AuthCredentials

# Type Alias: AuthCredentials

> **AuthCredentials** = \{ `method`: `"passphrase"`; `passphrase`: `string`; `userId`: `string`; \} \| \{ `method`: `"passkey-prf"`; `prfOutput`: `ArrayBuffer`; `userId`: `string`; \} \| \{ `method`: `"passkey-gate"`; `userId`: `string`; \}

Defined in: [types.ts:52](https://github.com/your-org/ats-kms/blob/main/src/v2/types.ts#L52)

Authentication credentials for KMS operations.

Discriminated union supporting three authentication methods:
- **Passphrase**: User-provided password (PBKDF2-derived KEK)
- **Passkey PRF**: WebAuthn PRF extension output (deterministic key derivation)
- **Passkey Gate**: WebAuthn credential as authentication gate (random MS)

## Example

```typescript
// Passphrase authentication
const creds: AuthCredentials = {
  method: 'passphrase',
  passphrase: 'my-secure-password',
  userId: 'user@example.com',
};

// Passkey PRF authentication
const creds: AuthCredentials = {
  method: 'passkey-prf',
  prfOutput: prfOutputBuffer,
  userId: 'user@example.com',
};

// Passkey Gate authentication
const creds: AuthCredentials = {
  method: 'passkey-gate',
  userId: 'user@example.com',
};
```
