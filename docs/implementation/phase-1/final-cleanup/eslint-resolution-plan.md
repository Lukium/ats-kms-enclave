# ESLint Type Safety Resolution Plan

**Date**: 2025-10-29
**Goal**: Fix all 173 type safety violations and remove broad ESLint exceptions
**Approach**: Systematic, file-by-file with incremental testing

## Overview

This plan addresses all type safety issues exposed after disabling broad ESLint exceptions. The work is organized by priority (critical issues first) and grouped by file to minimize test churn.

## Guiding Principles

1. **Type at boundaries**: Add type guards where external data enters the system (RPC, browser APIs)
2. **Fail fast**: Validate and throw clear errors rather than propagating `any`
3. **Use `unknown` for errors**: Never type catch blocks as `any`
4. **Explicit promise handling**: All promises must be awaited or have `.catch()` handlers
5. **Incremental progress**: Fix file-by-file, run tests after each file
6. **No new runtime behavior**: Only add types, don't change logic

## Priority 1: CRITICAL Issues (Must Fix First)

### 1.1 Floating Promises (3 instances) - HIGHEST PRIORITY

**Risk**: Silent failures in crypto operations, lost errors, race conditions

#### Fix: `client.ts:288` - Unlock modal Enter key handler
```typescript
// Current (line 286-290):
passphraseInput.onkeydown = (e): void => {
  if (e.key === 'Enter') {
    this.handlePassphraseUnlock(passphraseInput.value);  // ❌ Promise ignored
  }
};

// Fixed:
passphraseInput.onkeydown = (e): void => {
  if (e.key === 'Enter') {
    void this.handlePassphraseUnlock(passphraseInput.value)
      .catch((err: unknown) => {
        console.error('[KMS Client] Passphrase unlock failed:', err);
        this.showUnlockError(err instanceof Error ? err.message : 'Unknown error');
      });
  }
};
```

#### Fix: `client.ts:772` - Setup modal Enter key handler
```typescript
// Current (line 771-773):
const handleEnter = (): void => {
  this.handlePassphraseSetup(passphraseInput.value, passphraseConfirmInput.value);  // ❌ Promise ignored
};

// Fixed:
const handleEnter = (): void => {
  void this.handlePassphraseSetup(passphraseInput.value, passphraseConfirmInput.value)
    .catch((err: unknown) => {
      console.error('[KMS Client] Passphrase setup failed:', err);
      this.showSetupError(err instanceof Error ? err.message : 'Unknown error');
    });
};
```

#### Fix: `worker.ts:1434` - Module initialization
```typescript
// Need to see the actual code, likely:
// initializeWorker();  // ❌ Promise ignored

// Fixed:
void initializeWorker().catch((err: unknown) => {
  console.error('[KMS Worker] Initialization failed:', err);
  // Worker can't recover from init failure - this is fatal
});
```

**Testing**: After fixing, verify unlock/setup flows still work and errors display properly

---

### 1.2 Misused Promises (1 instance)

**Risk**: Race conditions, unexpected async behavior in sync contexts

#### Fix: `worker.ts:148` - Promise in void context
```typescript
// Need to examine actual code - likely an event listener made async
// Pattern is usually:
// addEventListener('message', async (event) => { ... });  // ❌ Returns Promise<void>

// Should be:
addEventListener('message', (event) => {
  void handleMessage(event).catch(err => {
    console.error('[KMS Worker] Message handling failed:', err);
  });
});

async function handleMessage(event: MessageEvent): Promise<void> {
  // async logic here
}
```

**Testing**: Verify worker message handling still processes all messages correctly

---

## Priority 2: Error Handling Pattern (14 instances across all files)

**Current pattern**:
```typescript
catch (err: any) {
  throw new Error(`Something failed: ${err.message}`);
}
```

**Problem**: `any` type bypasses safety, unsafe `.message` access

**Solution - Create utility function**:
```typescript
// Add to src/v2/error-utils.ts (new file):

/**
 * Extract error message from unknown error value
 * Handles Error objects, strings, and other types safely
 */
export function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (typeof err === 'string') {
    return err;
  }
  return String(err);
}

/**
 * Wrap unknown error in Error object if needed
 * Preserves Error objects, wraps others
 */
export function toError(err: unknown): Error {
  if (err instanceof Error) {
    return err;
  }
  return new Error(getErrorMessage(err));
}
```

**Apply pattern to all catch blocks**:
```typescript
// Before:
catch (err: any) {
  throw new Error(`Operation failed: ${err.message}`);
}

// After:
catch (err: unknown) {
  throw new Error(`Operation failed: ${getErrorMessage(err)}`);
}
```

**Files to update** (in order):
1. `src/v2/error-utils.ts` - Create utility (new file)
2. `src/v2/client.ts` - Fix 8 catch blocks
3. `src/v2/worker.ts` - Fix 2 catch blocks
4. `src/v2/kms-user.ts` - Fix 3 catch blocks

**Testing**: After each file, run full test suite

---

## Priority 3: WebAuthn API Type Safety

**Problem**: `credential.getClientExtensionResults()` returns `any` in TypeScript

**Solution - Create type guards**:
```typescript
// Add to src/v2/webauthn-types.ts (new file):

/**
 * WebAuthn PRF extension result structure
 * See: https://w3c.github.io/webauthn/#prf-extension
 */
export interface PRFExtensionResults {
  enabled?: boolean;
  results?: {
    first: ArrayBuffer;
    second?: ArrayBuffer;
  };
}

/**
 * All extension results returned by getClientExtensionResults()
 */
export interface ClientExtensionResults {
  prf?: PRFExtensionResults;
  // Add other extensions as needed
}

/**
 * Type guard for PRF extension results
 */
export function isPRFResult(value: unknown): value is PRFExtensionResults {
  if (typeof value !== 'object' || value === null) return false;
  const prf = value as Partial<PRFExtensionResults>;

  // enabled is optional boolean
  if ('enabled' in prf && typeof prf.enabled !== 'boolean') return false;

  // results is optional object with ArrayBuffer properties
  if ('results' in prf) {
    if (typeof prf.results !== 'object' || prf.results === null) return false;
    const results = prf.results as Record<string, unknown>;
    if ('first' in results && !(results.first instanceof ArrayBuffer)) return false;
    if ('second' in results && !(results.second instanceof ArrayBuffer)) return false;
  }

  return true;
}

/**
 * Safely extract PRF results from credential
 */
export function getPRFResults(credential: PublicKeyCredential): PRFExtensionResults | undefined {
  const extensions = credential.getClientExtensionResults() as ClientExtensionResults;
  const prf = extensions.prf;

  if (!prf) return undefined;
  if (!isPRFResult(prf)) {
    console.warn('[WebAuthn] Invalid PRF extension result structure:', prf);
    return undefined;
  }

  return prf;
}
```

**Apply to all WebAuthn PRF usage** (20 instances in `client.ts`, 6 in `kms-user.ts`):
```typescript
// Before:
const prfExt = (credential as any).getClientExtensionResults().prf;
const prfResults = prfExt?.results;

// After:
import { getPRFResults } from './webauthn-types';
const prfExt = getPRFResults(credential);
const prfResults = prfExt?.results;
```

**Testing**:
- Test WebAuthn unlock with PRF
- Test WebAuthn setup with PRF checking
- Verify fallback to gate method when PRF unavailable

---

## Priority 4: RPC Protocol Type Safety

**Problem**: Worker receives `any` typed params from postMessage, passes them unsafely to typed functions

**Solution - Add runtime validation at RPC boundary**:

```typescript
// Add to src/v2/rpc-validation.ts (new file):

import type { RPCRequest, RPCParams } from './types';

/**
 * Validation error for RPC parameter mismatches
 */
export class RPCValidationError extends Error {
  constructor(method: string, param: string, expected: string, received: unknown) {
    super(`RPC ${method}: Invalid ${param} - expected ${expected}, got ${typeof received}`);
    this.name = 'RPCValidationError';
  }
}

/**
 * Validate and extract typed parameters from RPC request
 * Throws RPCValidationError if validation fails
 */
export function validateUnlockPassphraseParams(params: unknown): {
  userId: string;
  passphrase: string;
  existingMS?: Uint8Array;
} {
  if (typeof params !== 'object' || params === null) {
    throw new RPCValidationError('unlockPassphrase', 'params', 'object', params);
  }

  const p = params as Record<string, unknown>;

  if (typeof p.userId !== 'string') {
    throw new RPCValidationError('unlockPassphrase', 'userId', 'string', p.userId);
  }

  if (typeof p.passphrase !== 'string') {
    throw new RPCValidationError('unlockPassphrase', 'passphrase', 'string', p.passphrase);
  }

  if (p.existingMS !== undefined && !(p.existingMS instanceof Uint8Array)) {
    throw new RPCValidationError('unlockPassphrase', 'existingMS', 'Uint8Array', p.existingMS);
  }

  return {
    userId: p.userId,
    passphrase: p.passphrase,
    existingMS: p.existingMS as Uint8Array | undefined,
  };
}

// Similar validators for each RPC method...
```

**Apply to worker.ts RPC dispatcher** (lines 163-260):
```typescript
// Before (line 172):
case 'unlockPassphrase':
  result = await unlockPassphrase(params);  // ❌ params is any

// After:
case 'unlockPassphrase':
  result = await unlockPassphrase(validateUnlockPassphraseParams(params));
```

**Files to update**:
1. Create `src/v2/rpc-validation.ts` with all validators (18 methods)
2. Update `src/v2/worker.ts` RPC dispatcher to use validators
3. Update tests to expect `RPCValidationError` for invalid params

**Testing**: Add test cases for invalid RPC params, verify proper error messages

---

## Priority 5: Storage and State Access

**Problem**: IndexedDB and localStorage return `any`, rate limiting state untyped

**Solution - Type guards for stored data**:

```typescript
// Add to src/v2/storage-types.ts (new file):

/**
 * Rate limit state structure stored in IndexedDB
 */
export interface RateLimitState {
  tokensIssued: number;
  lastResetAt: number; // Unix timestamp
}

/**
 * Type guard for rate limit state
 */
export function isRateLimitState(value: unknown): value is RateLimitState {
  if (typeof value !== 'object' || value === null) return false;
  const state = value as Partial<RateLimitState>;
  return (
    typeof state.tokensIssued === 'number' &&
    typeof state.lastResetAt === 'number'
  );
}

/**
 * Safely load rate limit state, with default fallback
 */
export function loadRateLimitState(rawState: unknown): RateLimitState {
  if (isRateLimitState(rawState)) {
    return rawState;
  }
  // Return default state if invalid
  return {
    tokensIssued: 0,
    lastResetAt: Date.now(),
  };
}
```

**Apply to worker.ts rate limiting** (lines 1027-1040):
```typescript
// Before:
const state = await storage.get('rateLimit') as any;
if (state.tokensIssued >= limit) { ... }

// After:
const rawState = await storage.get('rateLimit');
const state = loadRateLimitState(rawState);
if (state.tokensIssued >= limit) { ... }
```

**Testing**: Test rate limiting with valid/invalid stored state

---

## Priority 6: Types File Cleanup

**Problem**: `types.ts` has `any` in core type definitions (lines 243, 248, 311)

**Solution - Use generics for RPC types**:

```typescript
// Current (line 243-248):
export interface RPCRequest {
  id: string;
  method: string;
  data?: any;  // ❌
}

export interface RPCResponse {
  id: string;
  error?: any;  // ❌
  result?: any;  // ❌
}

// Fixed - Generic types:
export interface RPCRequest<TData = unknown> {
  id: string;
  method: string;
  data?: TData;
}

export interface RPCResponse<TResult = unknown, TError = Error> {
  id: string;
  error?: TError;
  result?: TResult;
}

// Method-specific types:
export interface UnlockPassphraseRequest extends RPCRequest<{
  userId: string;
  passphrase: string;
  existingMS?: Uint8Array;
}> {
  method: 'unlockPassphrase';
}

export interface UnlockPassphraseResponse extends RPCResponse<{
  credentials: AuthCredentials;
}> {
  method: 'unlockPassphrase';
}

// Union type of all requests:
export type KMSRPCRequest =
  | UnlockPassphraseRequest
  | UnlockPasskeyPRFRequest
  | UnlockPasskeyGateRequest
  // ... etc
;

export type KMSRPCResponse =
  | UnlockPassphraseResponse
  | UnlockPasskeyPRFResponse
  | UnlockPasskeyGateResponse
  // ... etc
;
```

**Testing**: TypeScript compilation must pass, RPC calls remain type-safe

---

## Priority 7: Window Object Properties

**Problem**: `client.ts:1208-1209` - accessing `(window as any).__kmsClient`

**Solution - Extend Window interface**:

```typescript
// Add to src/v2/client.ts at top:

declare global {
  interface Window {
    __kmsClient?: KMSClient;
    __kmsContext?: {
      parentOrigin: string;
      debugMode?: boolean;
    };
  }
}

// Then usage becomes type-safe:
window.__kmsClient = client;  // ✅ No error
```

**Testing**: Verify debug context still works

---

## Priority 8: Navigator and Misc Browser APIs

**Problem**: `crypto-utils.ts:405` - accessing `navigator.hardwareConcurrency` as `any`

**Solution - Proper type checking**:

```typescript
// Before (line 405):
const cores = (navigator as any).hardwareConcurrency || 1;

// After:
const cores = (typeof navigator !== 'undefined' && 'hardwareConcurrency' in navigator)
  ? navigator.hardwareConcurrency || 1
  : 1;
```

**Testing**: Verify PBKDF2 parallelization still works

---

## Implementation Order

### Phase 1: Critical Fixes (1-2 hours)
1. ✅ Fix 3 floating promises in `client.ts` and `worker.ts`
2. ✅ Fix 1 misused promise in `worker.ts`
3. ✅ Run full test suite

### Phase 2: Error Handling (2-3 hours)
4. ✅ Create `src/v2/error-utils.ts` with utilities
5. ✅ Fix catch blocks in `client.ts` (8 instances)
6. ✅ Fix catch blocks in `worker.ts` (2 instances)
7. ✅ Fix catch blocks in `kms-user.ts` (3 instances)
8. ✅ Run tests after each file

### Phase 3: WebAuthn Type Safety (3-4 hours)
9. ✅ Create `src/v2/webauthn-types.ts` with guards
10. ✅ Fix WebAuthn usage in `client.ts` (20 instances)
11. ✅ Fix WebAuthn usage in `kms-user.ts` (6 instances)
12. ✅ Test WebAuthn unlock and setup flows

### Phase 4: RPC Validation (4-5 hours)
13. ✅ Create `src/v2/rpc-validation.ts` with validators
14. ✅ Update `worker.ts` RPC dispatcher (18 methods)
15. ✅ Add validation error tests
16. ✅ Test all RPC methods

### Phase 5: Storage Type Safety (1-2 hours)
17. ✅ Create `src/v2/storage-types.ts` with guards
18. ✅ Fix storage access in `worker.ts` and `storage.ts`
19. ✅ Test rate limiting and storage

### Phase 6: Core Types Refactor (2-3 hours)
20. ✅ Refactor `types.ts` with generics
21. ✅ Update all RPC usage sites
22. ✅ Verify TypeScript compilation

### Phase 7: Misc Fixes (1 hour)
23. ✅ Fix Window interface extension
24. ✅ Fix Navigator API access
25. ✅ Fix promise rejection error (worker.ts:1382)

### Phase 8: Remove Exceptions (1 hour)
26. ✅ Remove all exceptions from `eslint.config.js` lines 76-94
27. ✅ Run `pnpm lint` - should pass with 0 errors
28. ✅ Run `make pre-commit` - full green

### Phase 9: Documentation
29. ✅ Update CLAUDE.md with new patterns
30. ✅ Document type guard usage
31. ✅ Create commit with comprehensive changes

---

## Estimated Timeline

**Total effort**: 15-20 hours
**Recommended schedule**: 3-4 focused sessions

---

## Testing Strategy

After each phase:
1. Run `pnpm test` - all tests must pass
2. Run `pnpm typecheck` - no TypeScript errors
3. Run `pnpm lint` - verify fixed issues don't regress
4. Manual testing of affected features in demo

After complete:
1. Full `make pre-commit` must pass
2. Test all unlock methods (passphrase, passkey PRF, passkey gate)
3. Test all setup flows
4. Test VAPID operations
5. Test lease management

---

## Risk Mitigation

1. **Incremental commits**: Commit after each phase passes tests
2. **Rollback plan**: Keep broad exceptions until ALL phases complete
3. **Feature flags**: If needed, can gate new validation behind flag
4. **Pair with manual testing**: Don't rely solely on unit tests

---

## Success Criteria

- ✅ 0 ESLint errors with strict rules enabled
- ✅ All tests passing
- ✅ No `any` types in production code (except test utilities)
- ✅ All promises explicitly handled
- ✅ Type guards at all external boundaries
- ✅ Broad ESLint exceptions removed from config

---

## Notes

- Some `any` usage may be legitimately unavoidable (e.g., JSON.parse results) - these should have immediate type guards
- The goal is not zero `any` at all costs, but rather type safety at boundaries with proper validation
- Runtime validation is CRITICAL - TypeScript types are erased at runtime, so validate external data
