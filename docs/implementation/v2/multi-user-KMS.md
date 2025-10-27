# Multi-User KMS Implementation Plan

**Status**: Planning
**Created**: 2025-10-27
**Breaking Change**: Yes - Requires migration of existing data

## Overview

This document outlines the plan to refactor the KMS V2 to support multiple users within a single browser instance. Currently, the KMS supports only one set of authentication credentials (shared globally), which limits it to effectively serving a single user per browser.

The multi-user refactor will enable:
- Multiple users with independent authentication credentials in one browser
- Each user maintains their own passphrase/passkey enrollment
- Each user has their own leases isolated from other users
- Parent applications can manage multiple user sessions simultaneously

## Current Architecture

### Current Limitations

```typescript
// One global authentication
setupPassphrase(passphrase) → stores at 'enrollment:passphrase:v2'
setupPasskeyPRF(config) → stores at 'enrollment:passkey-prf:v2'

// Leases are per-user, but auth is not
createLease({ userId: 'user1@example.com', credentials: { method: 'passphrase', passphrase: 'global' }})
createLease({ userId: 'user2@example.com', credentials: { method: 'passphrase', passphrase: 'global' }})
// ❌ Both users must use the same passphrase!
```

### Storage Structure (Current)

```
IndexedDB: kms-v2
├── meta
│   ├── enrollment:passphrase:v2 → PassphraseConfig (GLOBAL)
│   ├── enrollment:passkey-prf:v2 → PasskeyPRFConfig (GLOBAL)
│   └── enrollment:passkey-gate:v2 → PasskeyGateConfig (GLOBAL)
└── leases
    ├── lease-123 → { userId: 'user1@example.com', ... }
    └── lease-456 → { userId: 'user2@example.com', ... }
```

**Problem**: Authentication is global, leases are per-user → architectural mismatch.

## Target Architecture

### Design Goals

1. **Per-User Authentication**: Each user has their own passphrase/passkey
2. **Backward Compatible API**: Minimize changes to existing RPC interface where possible
3. **Storage Isolation**: User credentials stored in separate namespaces
4. **Clear userId Propagation**: userId flows explicitly through all operations

### Storage Structure (Target)

```
IndexedDB: kms-v2
├── meta
│   ├── enrollment:passphrase:v2:user1@example.com → PassphraseConfig
│   ├── enrollment:passphrase:v2:user2@example.com → PassphraseConfig
│   ├── enrollment:passkey-prf:v2:user1@example.com → PasskeyPRFConfig
│   └── enrollment:passkey-prf:v2:user2@example.com → PasskeyPRFConfig
└── leases
    ├── lease-123 → { userId: 'user1@example.com', ... }
    └── lease-456 → { userId: 'user2@example.com', ... }
```

**Solution**: Both authentication and leases are namespaced by userId.

## Implementation Plan

### Phase 1: Type System Updates

**File**: `src/v2/types.ts`

#### Update AuthCredentials Type

```typescript
// Before
export type AuthCredentials =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer }
  | { method: 'passkey-gate' };

// After
export type AuthCredentials =
  | { method: 'passphrase'; passphrase: string; userId: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer; userId: string }
  | { method: 'passkey-gate'; userId: string };
```

**Impact**: All code that creates or consumes `AuthCredentials` must include `userId`.

### Phase 2: Storage Layer Updates

**File**: `src/v2/unlock.ts`

#### Update Setup Functions

```typescript
// Before
export async function setupPassphrase(
  passphrase: string,
  existingMS?: Uint8Array
): Promise<UnlockResult>

// After
export async function setupPassphrase(
  passphrase: string,
  userId: string,
  existingMS?: Uint8Array
): Promise<UnlockResult>
```

**Changes Required**:
- `setupPassphrase(passphrase, userId, existingMS?)`
- `setupPasskeyPRF(credentialId, prfOutput, userId, existingMS?, rpId?)`
- `setupPasskeyGate(credentialId, userId, existingMS?, rpId?)`

#### Update Unlock Functions

```typescript
// Before
export async function unlockWithPassphrase(
  passphrase: string
): Promise<UnlockResult>

// After
export async function unlockWithPassphrase(
  passphrase: string,
  userId: string
): Promise<UnlockResult>
```

**Changes Required**:
- `unlockWithPassphrase(passphrase, userId)`
- `unlockWithPasskeyPRF(prfOutput, userId)`
- `unlockWithPasskeyGate(userId)`

#### Update Setup Check Functions

```typescript
// Before
export async function isPassphraseSetup(): Promise<boolean>
export async function isPasskeySetup(): Promise<boolean>
export async function isSetup(): Promise<boolean>

// After
export async function isPassphraseSetup(userId: string): Promise<boolean>
export async function isPasskeySetup(userId: string): Promise<boolean>
export async function isSetup(userId: string): Promise<boolean>
```

**Note**: `isSetup(userId)` already implemented in worker.ts, but underlying storage functions need updates.

#### Update Storage Key Functions

All enrollment storage keys must be namespaced:

```typescript
// Before
function getEnrollmentKey(method: string): string {
  return `enrollment:${method}:v2`;
}

// After
function getEnrollmentKey(method: string, userId: string): string {
  return `enrollment:${method}:v2:${userId}`;
}
```

**Affected Keys**:
- `enrollment:passphrase:v2` → `enrollment:passphrase:v2:${userId}`
- `enrollment:passkey-prf:v2` → `enrollment:passkey-prf:v2:${userId}`
- `enrollment:passkey-gate:v2` → `enrollment:passkey-gate:v2:${userId}`

### Phase 3: Worker Layer Updates

**File**: `src/v2/worker.ts`

#### Update Setup Handlers

```typescript
// Before
async function handleSetupPassphrase(
  params: { passphrase: string; existingMS?: Uint8Array },
  requestId: string
): Promise<SetupResult>

// After
async function handleSetupPassphrase(
  params: { passphrase: string; userId: string; existingMS?: Uint8Array },
  requestId: string
): Promise<SetupResult>
```

**Changes Required**:
- `handleSetupPassphrase`: Add `userId` to params, pass to `setupPassphrase()`
- `handleSetupPasskeyPRF`: Add `userId` to params, pass to `setupPasskeyPRF()`
- `handleSetupPasskeyGate`: Add `userId` to params, pass to `setupPasskeyGate()`
- `handleAddEnrollment`: Extract `userId` from credentials, pass to setup functions

#### Update withUnlock Helper

The `withUnlock` helper function needs to extract `userId` from credentials:

```typescript
// Before
async function withUnlock<T>(
  credentials: AuthCredentials,
  operation: (ms: Uint8Array) => Promise<T>
): Promise<T>

// After
async function withUnlock<T>(
  credentials: AuthCredentials,
  operation: (ms: Uint8Array) => Promise<T>
): Promise<T> {
  const { userId } = credentials; // Extract userId from credentials

  let ms: Uint8Array;
  if (credentials.method === 'passphrase') {
    const result = await unlockWithPassphrase(credentials.passphrase, userId);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-prf') {
    const result = await unlockWithPasskeyPRF(credentials.prfOutput, userId);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-gate') {
    const result = await unlockWithPasskeyGate(userId);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else {
    throw new Error('Invalid credentials method');
  }

  return operation(ms);
}
```

#### Update isSetup Handler

Already updated to accept optional `userId` parameter. The underlying storage layer functions need updating to match:

```typescript
async function handleIsSetup(
  params?: { userId?: string }
): Promise<{ isSetup: boolean; methods: string[]; leases?: LeaseRecord[] }> {
  // When userId provided, check that specific user's setup
  if (params?.userId) {
    const setupResult = await isSetup(params.userId); // ← Pass userId to storage
    const methods: string[] = [];

    if (await isPassphraseSetup(params.userId)) methods.push('passphrase');
    if (await isPasskeySetup(params.userId)) methods.push('passkey');

    const leases = setupResult ? await getUserLeases(params.userId) : undefined;
    return { isSetup: setupResult, methods, leases };
  }

  // Without userId, check if ANY user is setup (backward compat)
  // Implementation TBD - might list all enrollment keys?
}
```

### Phase 4: KMS User API Updates

**File**: `src/v2/kms-user.ts`

#### Update Setup Methods

```typescript
// Before
async setupPassphrase(passphrase: string): Promise<SetupResult>

// After
async setupPassphrase(passphrase: string, userId: string): Promise<SetupResult> {
  return this.sendRequest<SetupResult>('setupPassphrase', { passphrase, userId });
}
```

**Changes Required**:
- `setupPassphrase(passphrase, userId)`
- `setupPasskeyPRF(config, userId)` - add userId to config
- `setupPasskeyGate(config, userId)` - add userId to config
- `addEnrollment(method, credentials, newCredentials, userId)` - ensure credentials include userId

**Note**: The userId should come from the parent application, not stored in KMSUser.

### Phase 5: Demo Updates

**File**: `example/phase-1/full/parent.ts`

All operations need to pass userId:

```typescript
const DEMO_USER_ID = 'demouser@ats.run';

// Setup
await kmsUser.setupPassphrase(passphrase, DEMO_USER_ID);

// Unlock (if needed as separate operation)
await kmsUser.unlockWithPassphrase(passphrase, DEMO_USER_ID);

// Create lease
await kmsUser.createLease({
  userId: DEMO_USER_ID,
  subs: [...],
  ttlHours: 1,
  credentials: {
    method: 'passphrase',
    passphrase: 'secret123',
    userId: DEMO_USER_ID  // ← Add this
  }
});

// Check setup
const status = await kmsUser.isSetup(DEMO_USER_ID);
```

## Migration Strategy

### Data Migration

**Challenge**: Existing data uses non-namespaced keys.

**Options**:

1. **Automatic Migration** (Recommended for demo):
   ```typescript
   // On first load, detect old keys and migrate
   const oldKey = 'enrollment:passphrase:v2';
   const config = await getMeta(oldKey);
   if (config) {
     const defaultUserId = 'migrated-user@local';
     await setMeta(`enrollment:passphrase:v2:${defaultUserId}`, config);
     await deleteMeta(oldKey);
   }
   ```

2. **Manual Reset** (Acceptable for early development):
   - Clear all IndexedDB data
   - Users re-enroll with new userId-namespaced storage

3. **No Migration** (Clean break):
   - Breaking change - users must re-setup
   - Document in release notes

**Recommendation**: For V2 development phase, use **Manual Reset**. Implement automatic migration before production release.

### API Compatibility

**Breaking Changes**:
- All setup methods require `userId` parameter
- All `AuthCredentials` objects must include `userId`

**Non-Breaking**:
- `isSetup()` still works without userId (checks if ANY user is setup)
- Existing leases already have `userId` field

## Testing Strategy

### Unit Tests

**File**: `test/unit/unlock.test.ts`

Test each updated function with userId parameter:

```typescript
describe('Multi-user setup', () => {
  it('should store passphrase config namespaced by userId', async () => {
    await setupPassphrase('secret', 'user1@example.com');
    await setupPassphrase('different', 'user2@example.com');

    // Each user can unlock with their own passphrase
    const result1 = await unlockWithPassphrase('secret', 'user1@example.com');
    expect(result1.success).toBe(true);

    const result2 = await unlockWithPassphrase('different', 'user2@example.com');
    expect(result2.success).toBe(true);

    // Cross-user auth should fail
    const result3 = await unlockWithPassphrase('secret', 'user2@example.com');
    expect(result3.success).toBe(false);
  });
});
```

### Integration Tests

**File**: `test/integration/multi-user.test.ts` (new)

```typescript
describe('Multi-user KMS', () => {
  it('should support multiple users with independent credentials', async () => {
    const user1 = 'alice@example.com';
    const user2 = 'bob@example.com';

    // Setup user 1
    await kmsUser.setupPassphrase('alice-secret', user1);
    const status1 = await kmsUser.isSetup(user1);
    expect(status1.isSetup).toBe(true);

    // Setup user 2
    await kmsUser.setupPassphrase('bob-secret', user2);
    const status2 = await kmsUser.isSetup(user2);
    expect(status2.isSetup).toBe(true);

    // Create leases for each user
    const lease1 = await kmsUser.createLease({
      userId: user1,
      subs: [{ url: 'https://push.example.com', aud: 'https://push.example.com', eid: 'endpoint-1' }],
      ttlHours: 1,
      credentials: { method: 'passphrase', passphrase: 'alice-secret', userId: user1 }
    });

    const lease2 = await kmsUser.createLease({
      userId: user2,
      subs: [{ url: 'https://push.example.com', aud: 'https://push.example.com', eid: 'endpoint-2' }],
      ttlHours: 1,
      credentials: { method: 'passphrase', passphrase: 'bob-secret', userId: user2 }
    });

    // Verify lease isolation
    const user1Status = await kmsUser.isSetup(user1);
    expect(user1Status.leases).toHaveLength(1);
    expect(user1Status.leases![0].leaseId).toBe(lease1.leaseId);

    const user2Status = await kmsUser.isSetup(user2);
    expect(user2Status.leases).toHaveLength(1);
    expect(user2Status.leases![0].leaseId).toBe(lease2.leaseId);
  });

  it('should reject auth with wrong userId', async () => {
    await kmsUser.setupPassphrase('alice-secret', 'alice@example.com');

    await expect(
      kmsUser.createLease({
        userId: 'alice@example.com',
        subs: [...],
        ttlHours: 1,
        credentials: {
          method: 'passphrase',
          passphrase: 'alice-secret',
          userId: 'bob@example.com'  // Wrong userId!
        }
      })
    ).rejects.toThrow();
  });
});
```

### Demo Test

**Manual Testing Checklist**:

1. ✅ Setup user1 with passphrase
2. ✅ Setup user2 with different passphrase
3. ✅ Create lease for user1 with user1 credentials
4. ✅ Create lease for user2 with user2 credentials
5. ✅ Verify `isSetup(user1)` returns only user1 leases
6. ✅ Verify `isSetup(user2)` returns only user2 leases
7. ❌ Try to create lease for user1 with user2 credentials (should fail)
8. ✅ Reset KMS and verify both users are cleared

## Implementation Checklist

### Phase 1: Type System
- [ ] Update `AuthCredentials` type in `src/v2/types.ts`
- [ ] Run `pnpm typecheck` to find all affected code

### Phase 2: Storage Layer
- [ ] Update `setupPassphrase()` signature in `src/v2/unlock.ts`
- [ ] Update `setupPasskeyPRF()` signature
- [ ] Update `setupPasskeyGate()` signature
- [ ] Update `unlockWithPassphrase()` signature
- [ ] Update `unlockWithPasskeyPRF()` signature
- [ ] Update `unlockWithPasskeyGate()` signature
- [ ] Update `isPassphraseSetup()` signature
- [ ] Update `isPasskeySetup()` signature
- [ ] Update `isSetup()` signature
- [ ] Update storage key generation to namespace by userId
- [ ] Update all `getMeta()` / `setMeta()` calls with namespaced keys

### Phase 3: Worker Layer
- [ ] Update `handleSetupPassphrase()` in `src/v2/worker.ts`
- [ ] Update `handleSetupPasskeyPRF()`
- [ ] Update `handleSetupPasskeyGate()`
- [ ] Update `handleAddEnrollment()`
- [ ] Update `withUnlock()` to extract userId from credentials
- [ ] Update `handleIsSetup()` to pass userId to storage layer
- [ ] Update all other handlers that call unlock functions

### Phase 4: KMS User API
- [ ] Update `setupPassphrase()` in `src/v2/kms-user.ts`
- [ ] Update `setupPasskeyPRF()`
- [ ] Update `setupPasskeyGate()`
- [ ] Update `addEnrollment()`
- [ ] Update `isSetup()` (already done, verify)
- [ ] Add JSDoc comments documenting userId requirement

### Phase 5: Demo
- [ ] Update all setup calls in `example/phase-1/full/parent.ts`
- [ ] Update all credential objects to include userId
- [ ] Add userId constant at top of file

### Phase 6: Tests
- [ ] Update `test/unit/unlock.test.ts`
- [ ] Update `test/integration/worker.test.ts`
- [ ] Create `test/integration/multi-user.test.ts`
- [ ] Update any other test files that create credentials

### Phase 7: Verification
- [ ] Run `pnpm typecheck`
- [ ] Run `pnpm test`
- [ ] Run `pnpm test:coverage` (ensure 80%+ coverage)
- [ ] Manual test in demo
- [ ] Verify multiple users can coexist

## Risks and Mitigations

### Risk 1: Large Codebase Impact
**Impact**: Touches many files, high chance of breaking existing functionality
**Mitigation**:
- Implement incrementally with typecheck after each phase
- Write tests before changing implementation
- Use TypeScript compiler to find all affected code

### Risk 2: Data Migration Complexity
**Impact**: Existing dev environments have data that won't work
**Mitigation**:
- Document reset procedure clearly
- Add migration code for production (future)
- Accept breaking change for V2 development phase

### Risk 3: Backward Compatibility
**Impact**: Parent apps must update all calls
**Mitigation**:
- This is V2 - breaking changes acceptable
- Document changes clearly
- Provide migration example in demo

### Risk 4: Security Implications
**Impact**: userId must be trusted, cross-user attacks possible if userId not validated
**Mitigation**:
- Parent application owns userId - KMS trusts it
- Document that parent must validate userId
- Consider adding userId validation in future (e.g., signature-based proof)

## Open Questions

1. **Q**: Should `isSetup()` without userId check if ANY user is setup, or require userId?
   **A**: Support both - no userId checks any user, with userId checks specific user

2. **Q**: How to handle enrollment listing? Should `getEnrollments()` list all users?
   **A**: Add optional userId parameter, default to requiring userId for security

3. **Q**: Should we support deleting a user's enrollment entirely?
   **A**: Yes, add `removeUser(userId)` method in future enhancement

4. **Q**: What happens to VAPID keys? Are they per-user or global?
   **A**: VAPID keys are per-user (already stored in leases). No change needed.

5. **Q**: Should audit log entries include userId?
   **A**: Yes, add userId to audit entries for multi-user audit trails (future enhancement)

## References

- [V2 Architecture Overview](../../architecture/crypto/README.md)
- [Current State](../../architecture/crypto/current-state.md)
- [Design Document](../../architecture/crypto/design.md)
- [Types Definition](../../../src/v2/types.ts)
- [Unlock Implementation](../../../src/v2/unlock.ts)
- [Worker Implementation](../../../src/v2/worker.ts)

## Changelog

- 2025-10-27: Initial plan created
