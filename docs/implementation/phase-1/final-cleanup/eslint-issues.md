# ESLint Issues After Disabling Broad Exceptions

**Date**: 2025-10-29
**Total Issues**: 173 errors (0 warnings)

This document catalogs all ESLint type safety violations that were hidden by broad exception rules in `eslint.config.js` lines 76-94.

## Exception Rules Temporarily Disabled

The following rules were re-enabled to expose underlying issues:

- `@typescript-eslint/no-explicit-any` (CRITICAL)
- `@typescript-eslint/no-unsafe-assignment` (HIGH)
- `@typescript-eslint/no-unsafe-member-access` (HIGH)
- `@typescript-eslint/no-unsafe-call` (HIGH)
- `@typescript-eslint/no-unsafe-argument` (HIGH)
- `@typescript-eslint/no-unsafe-return` (HIGH)
- `@typescript-eslint/no-misused-promises` (CRITICAL)
- `@typescript-eslint/no-floating-promises` (CRITICAL)
- `@typescript-eslint/prefer-promise-reject-errors` (MEDIUM)

## Summary by File

| File | Total Errors | no-explicit-any | no-unsafe-* | no-floating-promises | no-misused-promises |
|------|-------------|-----------------|-------------|----------------------|---------------------|
| `client.ts` | 84 | 14 | 68 | 2 | 0 |
| `worker.ts` | 56 | 5 | 48 | 1 | 1 + 1 prefer-promise-reject |
| `kms-user.ts` | 23 | 7 | 16 | 0 | 0 |
| `crypto-utils.ts` | 9 | 3 | 6 | 0 | 0 |
| `storage.ts` | 6 | 1 | 5 | 0 | 0 |
| `types.ts` | 3 | 3 | 0 | 0 | 0 |
| **TOTAL** | **181** | **33** | **143** | **3** | **2 + 1** |

## Detailed Issues by Category

### 1. CRITICAL: Floating Promises (3 instances)

These are the most dangerous - async operations that can fail silently without error handling:

#### `client.ts:288`
```
error: Promises must be awaited, end with a call to .catch, end with a call to .then with a rejection handler or be explicitly marked as ignored with the `void` operator
```
**Context**: `this.handlePassphraseUnlock(passphraseInput.value);` called without await

#### `client.ts:772`
```
error: Promises must be awaited, end with a call to .catch, end with a call to .then with a rejection handler or be explicitly marked as ignored with the `void` operator
```
**Context**: `this.handlePassphraseSetup(passphraseInput.value, passphraseConfirmInput.value);` called without await

#### `worker.ts:1434`
```
error: Promises must be awaited, end with a call to .catch, end with a call to .then with a rejection handler or be explicitly marked as ignored with the `void` operator
```
**Context**: Likely module-level initialization code

### 2. CRITICAL: Misused Promises (1 instance)

Promise returned where void expected - can cause race conditions:

#### `worker.ts:148`
```
error: Promise returned in function argument where a void return was expected
```
**Context**: Likely an event listener or callback that was made async

### 3. HIGH: Explicit `any` Types (33 instances)

Direct use of `any` type defeating TypeScript safety:

#### `client.ts` (14 instances)
- Line 94, 136, 159, 188, 196: Error handling catch blocks typed as `any`
- Line 341, 679, 849, 870: WebAuthn `getClientExtensionResults()` - browser API returns `any`
- Line 387, 432, 697, 946, 1063: More catch blocks
- Line 910, 1030: Message handler response typed as `any`
- Line 1208, 1209: Window object properties `__kmsClient` and `__kmsContext`

#### `worker.ts` (5 instances)
- Line 167, 264: Error catch blocks
- Line 513: RPC method signature
- Line 1027, 1237: Storage/state access typed as `any`

#### `kms-user.ts` (7 instances)
- Line 58: postMessage data parameter
- Line 204, 459, 508, 526: Error catch blocks
- Line 330: RPC response parameter
- Line 734, 735: Initialization options

#### `crypto-utils.ts` (3 instances)
- Line 242, 255, 276: WebAuthn credential data
- Line 405: Navigator.hardwareConcurrency (browser API)

#### `storage.ts` (1 instance)
- Line 317: IndexedDB objectStore name and key

#### `types.ts` (3 instances)
- Line 243, 248: RPC request/response `data` and `error` fields
- Line 311: Demo context typed as `any`

### 4. HIGH: Unsafe Operations on `any` (143 instances)

These are consequences of the explicit `any` types - accessing properties, calling methods, etc. on untyped values:

#### `client.ts` (68 unsafe operations)
**Patterns**:
- **Error message access** (8x): `.message` on catch block errors
- **WebAuthn PRF extension** (20x): `getClientExtensionResults()`, `.prf`, `.results`, `.enabled`
- **RPC response handling** (18x): `.id`, `.error`, `.result`, `.enrollments`, `.userId`
- **Worker communication** (6x): `.postMessage()` on worker
- **Window properties** (2x): `.__kmsClient`, `.__kmsContext`

#### `worker.ts` (48 unsafe operations)
**Patterns**:
- **RPC routing** (18x): Unsafe arguments passed to typed handler functions
- **Credentials destructuring** (8x): `.passphrase`, `.credentialId`, `.prfOutput`, `.rpId`
- **Error handling** (3x): `.message` on catch blocks
- **Rate limiting state** (5x): `.lastResetAt`, `.tokensIssued` on storage values

#### `kms-user.ts` (16 unsafe operations)
**Patterns**:
- **WebAuthn PRF** (6x): Similar to client.ts
- **Message handling** (4x): `.type` on postMessage data
- **Error handling** (3x): `.message` access
- **Response handling** (3x): Response object property access

#### `crypto-utils.ts` (6 unsafe operations)
**Patterns**:
- **WebAuthn credential data** (4x): `.credentialId` access and credential arguments
- **Navigator API** (2x): `.hardwareConcurrency` on navigator

#### `storage.ts` (5 unsafe operations)
**Patterns**:
- **IndexedDB metadata** (5x): `.name`, `.startsWith()` on objectStore

### 5. MEDIUM: Promise Rejection Errors (1 instance)

#### `worker.ts:1382`
```
error: Expected the Promise rejection reason to be an Error
```
**Context**: Rejecting promise with non-Error value (loses stack trace)

## Root Causes Analysis

### 1. External Browser APIs Return `any`
Many issues stem from browser APIs that TypeScript types as `any`:
- **WebAuthn**: `credential.getClientExtensionResults()` returns `any`
- **IndexedDB**: Some metadata properties
- **Navigator**: Certain properties

**Solution**: Add proper type guards and interfaces

### 2. RPC Protocol Handling
The worker message handlers receive `any` typed data from postMessage:
- `worker.ts:163`: Destructuring RPC params without type validation
- Pattern repeats across all RPC method dispatches

**Solution**: Runtime validation with type guards at RPC boundary

### 3. Error Handling Pattern
Consistent pattern of `catch (err: any)` throughout codebase:
- 14 instances across all files
- Always accessing `.message` property unsafely

**Solution**: Use `unknown` type for errors with proper type narrowing

### 4. Promise Handling in Event Listeners
Event handlers calling async methods without awaiting:
- `client.ts:288`: onclick calling async unlock
- `client.ts:772`: onclick calling async setup

**Solution**: Explicit `.catch()` handlers or `void` operator

## Files Not Affected

These files already follow strict typing:
- `audit.ts` - ✅ No issues
- `unlock.ts` - ✅ No issues

These files had exceptions but have minimal issues because they follow better patterns.

## Next Steps

See `eslint-resolution-plan.md` for the systematic approach to fixing these issues.
