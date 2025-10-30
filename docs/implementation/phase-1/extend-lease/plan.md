# Extend Lease Implementation Plan

## Overview

Add the ability to extend existing VAPID leases with optional auto-extension permission. This enables a better UX by default (auto-extension enabled) while preserving a strict security mode for security-conscious users.

## Goals

1. **Best UX by default**: Leases can be auto-extended without re-authentication
2. **User choice**: Users can opt into strict mode requiring re-auth for extensions
3. **Explicit control**: Parent must explicitly call `extendLease` with a `leaseId`
4. **Security preservation**: Auto-extend only works for existing leases, can't create new permissions

## Changes Required

### 1. Lease Duration Update

**Change lease expiration from 24 hours to 30 days**

**Files to modify**:
- `src/v2/worker.ts`: Update `createLease` to use 30 days instead of 24 hours
- `tests/v2/worker.test.ts`: Update test expectations for 30-day expiration

**Current**:
```typescript
const exp = now + 24 * 60 * 60; // 24 hours from now
```

**New**:
```typescript
const exp = now + 30 * 24 * 60 * 60; // 30 days from now
```

### 2. Storage Schema Update

**Add `autoExtend` field to lease storage**

**Files to modify**:
- `src/v2/storage.ts`: Update `StoredLease` interface

**Current schema**:
```typescript
interface StoredLease {
  leaseId: string;
  userId: string;
  kid: string;
  exp: number;
  iat: number;
}
```

**New schema**:
```typescript
interface StoredLease {
  leaseId: string;
  userId: string;
  kid: string;
  exp: number;
  iat: number;
  autoExtend: boolean; // NEW: Can parent extend without re-auth?
}
```

**Migration considerations**:
- Existing leases without `autoExtend` should default to `false` (strict mode)
- New leases default to `true` (best UX)

### 3. RPC Protocol Update

**Add `autoExtend` parameter to `createLease` request**

**Files to modify**:
- `src/v2/rpc-validation.ts`: Update `CreateLeaseRequest` schema

**Current**:
```typescript
const CreateLeaseRequestSchema = z.object({
  method: z.literal('createLease'),
  userId: z.string().min(1),
});
```

**New**:
```typescript
const CreateLeaseRequestSchema = z.object({
  method: z.literal('createLease'),
  userId: z.string().min(1),
  autoExtend: z.boolean().optional().default(true), // NEW
});
```

**Add new `extendLease` RPC method**:
```typescript
const ExtendLeaseRequestSchema = z.object({
  method: z.literal('extendLease'),
  leaseId: z.string().min(1),
});

type ExtendLeaseRequest = z.infer<typeof ExtendLeaseRequestSchema>;

interface ExtendLeaseResponse {
  leaseId: string;
  exp: number; // New expiration timestamp
  iat: number; // New issuance timestamp
  kid: string;
  autoExtend: boolean;
}
```

### 4. Worker Implementation

**Update `createLease` to store `autoExtend` flag**

**Files to modify**:
- `src/v2/worker.ts`: Update `createLease` handler

**Changes**:
```typescript
async function createLease(request: CreateLeaseRequest): Promise<CreateLeaseResponse> {
  // ... existing validation ...

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 30 * 24 * 60 * 60; // 30 days (UPDATED)
  const autoExtend = request.autoExtend ?? true; // Default to true

  const lease: StoredLease = {
    leaseId,
    userId: request.userId,
    kid,
    exp,
    iat: now,
    autoExtend, // NEW
  };

  // ... store lease ...

  return {
    leaseId: lease.leaseId,
    exp: lease.exp,
    iat: lease.iat,
    kid: lease.kid,
    autoExtend: lease.autoExtend, // NEW
  };
}
```

**Add new `extendLease` handler**:
```typescript
async function extendLease(request: ExtendLeaseRequest): Promise<ExtendLeaseResponse> {
  const unlockStatus = getUnlockStatus();
  if (!unlockStatus.unlocked) {
    throw new KMSError(
      'KMS_LOCKED',
      'KMS must be unlocked to extend leases',
      { leaseId: request.leaseId }
    );
  }

  // Fetch existing lease
  const existingLease = await getLeaseById(request.leaseId);
  if (!existingLease) {
    throw new KMSError(
      'LEASE_NOT_FOUND',
      'Lease not found',
      { leaseId: request.leaseId }
    );
  }

  // Verify lease is for current VAPID key
  const vapidKey = await getVAPIDKey();
  if (!vapidKey) {
    throw new KMSError('VAPID_NOT_FOUND', 'VAPID key not found');
  }

  const currentKid = await computeKid(vapidKey.publicKey);
  if (existingLease.kid !== currentKid) {
    throw new KMSError(
      'LEASE_INVALID_KID',
      'Lease is for a different VAPID key',
      { leaseKid: existingLease.kid, currentKid }
    );
  }

  // Check if auto-extend is allowed
  // Note: If autoExtend=false, this call should have been intercepted by client
  // and require user authentication. But we check here defensively.
  if (!existingLease.autoExtend) {
    // This is actually OK - it means the user just authenticated to extend
    console.log('[KMS Worker] Extending lease with explicit authentication');
  }

  // Extend the lease
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 30 * 24 * 60 * 60; // 30 days from now

  const updatedLease: StoredLease = {
    ...existingLease,
    exp,
    iat: now,
    // Preserve autoExtend flag
  };

  await storeLease(updatedLease);

  // Audit log
  await addAuditEntry({
    timestamp: Date.now(),
    operation: 'extendLease',
    details: {
      leaseId: updatedLease.leaseId,
      userId: updatedLease.userId,
      kid: updatedLease.kid,
      exp: updatedLease.exp,
      autoExtend: updatedLease.autoExtend,
    },
  });

  return {
    leaseId: updatedLease.leaseId,
    exp: updatedLease.exp,
    iat: updatedLease.iat,
    kid: updatedLease.kid,
    autoExtend: updatedLease.autoExtend,
  };
}
```

**Add RPC handler registration**:
```typescript
// In the message handler switch statement
case 'extendLease': {
  const result = await extendLease(request);
  return result;
}
```

### 5. Client Authentication Interceptor

**Intercept `extendLease` only if `autoExtend=false`**

**Files to modify**:
- `src/v2/client.ts`: Update authentication interceptor logic

**Challenge**: The client doesn't know the `autoExtend` flag without fetching the lease first.

**Solution**: Add a new method to fetch lease metadata, OR have `extendLease` fail with a specific error code if auth is required.

**Recommended approach**: Check the lease `autoExtend` flag in the worker, and if `false`, return a special error code that triggers the auth modal in the client.

**Worker change**:
```typescript
async function extendLease(request: ExtendLeaseRequest): Promise<ExtendLeaseResponse> {
  // Fetch existing lease
  const existingLease = await getLeaseById(request.leaseId);
  if (!existingLease) {
    throw new KMSError('LEASE_NOT_FOUND', 'Lease not found', { leaseId: request.leaseId });
  }

  // If autoExtend is false, check unlock status
  if (!existingLease.autoExtend) {
    const unlockStatus = getUnlockStatus();
    if (!unlockStatus.unlocked) {
      throw new KMSError(
        'AUTH_REQUIRED',
        'Authentication required to extend this lease',
        { leaseId: request.leaseId, reason: 'autoExtend disabled' }
      );
    }
  }

  // ... rest of extension logic ...
}
```

**Client change**:
```typescript
// In the client message handler
if (error.code === 'AUTH_REQUIRED') {
  // Show auth modal
  const authenticated = await showAuthModal(request);
  if (authenticated) {
    // Retry the request
    return await sendToWorker(request);
  } else {
    // User cancelled
    throw new KMSError('AUTH_CANCELLED', 'User cancelled authentication');
  }
}
```

**Alternative simpler approach**: Always check unlock status in worker for `extendLease`, and let the client always intercept `extendLease` to show the modal. The worker will just accept or reject based on unlock status.

**Recommended**: Use the simpler approach - always intercept `extendLease` in client if not unlocked.

### 6. KMSUser API Update

**Add `extendLease` method to `KMSUser` class**

**Files to modify**:
- `src/v2/kms-user.ts`: Add `extendLease` method

```typescript
/**
 * Extend an existing lease
 *
 * If the lease has autoExtend=true, this can be called without re-authentication.
 * If autoExtend=false, the user will be prompted to unlock the KMS.
 *
 * @param leaseId - The ID of the lease to extend
 * @returns Extended lease information
 */
async extendLease(leaseId: string): Promise<ExtendLeaseResponse> {
  const response = await this.client.sendRequest<ExtendLeaseResponse>({
    method: 'extendLease',
    leaseId,
  });

  return response;
}
```

### 7. Demo UI Update

**Add checkbox for auto-extend permission**

**Files to modify**:
- `example/phase-1/full/parent.ts`: Update lease creation UI

**UI changes**:
```typescript
// In renderLeaseUI function, add checkbox before "Create Lease" button
<div style="margin-bottom: 1rem;">
  <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
    <input
      type="checkbox"
      id="auto-extend-checkbox"
      checked
      style="width: 16px; height: 16px; cursor: pointer;"
    />
    <span style="font-size: 0.9rem;">
      Allow automatic lease renewal (recommended)
    </span>
  </label>
  <div class="info-message" style="margin-top: 0.25rem; font-size: 0.85rem; color: #888;">
    ℹ️ When unchecked, you'll need to unlock again when the lease expires.
    Notifications will stop working until you re-authorize.
  </div>
</div>
```

**Update `createLease` call**:
```typescript
async function createLease(): Promise<void> {
  try {
    const autoExtend = (document.getElementById('auto-extend-checkbox') as HTMLInputElement)?.checked ?? true;

    const lease = await kmsUser.createLease(userId, autoExtend);

    // ... rest of logic ...
  } catch (error) {
    // ... error handling ...
  }
}
```

**Add "Extend Lease" button** (optional, for testing):
```typescript
<button id="extend-lease-btn" class="operation-btn">⏰ Extend Lease</button>
```

```typescript
document.getElementById('extend-lease-btn')?.addEventListener('click', async () => {
  const leaseId = prompt('Enter lease ID to extend:');
  if (leaseId) {
    try {
      const result = await kmsUser.extendLease(leaseId);
      alert(`Lease extended! New expiration: ${new Date(result.exp * 1000).toLocaleString()}`);
      await displayVAPIDKeyInfo();
      await loadAuditLog();
    } catch (error) {
      alert(`Failed to extend lease: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
});
```

### 8. Testing

**Files to modify**:
- `tests/v2/worker.test.ts`: Add `extendLease` tests
- `tests/v2/kms-user.test.ts`: Add `extendLease` integration tests
- `tests/v2/storage.test.ts`: Add tests for `autoExtend` field

**Test cases for `extendLease`**:

1. **Basic extension (autoExtend=true)**:
   - Create lease with autoExtend=true
   - Call extendLease
   - Verify exp and iat are updated
   - Verify autoExtend flag is preserved
   - Verify leaseId remains the same

2. **Extension with auth required (autoExtend=false)**:
   - Create lease with autoExtend=false
   - Lock the KMS
   - Call extendLease
   - Verify error is thrown (AUTH_REQUIRED or KMS_LOCKED)
   - Unlock the KMS
   - Call extendLease again
   - Verify extension succeeds

3. **Lease not found**:
   - Call extendLease with non-existent leaseId
   - Verify LEASE_NOT_FOUND error

4. **Wrong kid (VAPID key changed)**:
   - Create lease
   - Regenerate VAPID key
   - Call extendLease on old lease
   - Verify LEASE_INVALID_KID error

5. **Auto-extend flag preservation**:
   - Create lease with autoExtend=true
   - Extend lease
   - Verify returned lease still has autoExtend=true
   - Create lease with autoExtend=false
   - Extend lease (with unlock)
   - Verify returned lease still has autoExtend=false

6. **Multiple extensions**:
   - Create lease
   - Extend 3 times
   - Verify exp keeps moving forward
   - Verify leaseId remains the same

7. **Audit log**:
   - Extend lease
   - Verify audit entry is created with correct details

**Test cases for `createLease` with autoExtend**:

1. **Default autoExtend=true**:
   - Call createLease without autoExtend param
   - Verify lease has autoExtend=true

2. **Explicit autoExtend=true**:
   - Call createLease with autoExtend=true
   - Verify lease has autoExtend=true

3. **Explicit autoExtend=false**:
   - Call createLease with autoExtend=false
   - Verify lease has autoExtend=false

4. **Response includes autoExtend**:
   - Call createLease
   - Verify response includes autoExtend field

## Implementation Order

1. ✅ Create this implementation plan
2. Update lease duration from 24h to 30 days
3. Update storage schema to include `autoExtend`
4. Update RPC validation to include `autoExtend` in createLease and add extendLease
5. Update worker `createLease` to handle `autoExtend` parameter
6. Implement worker `extendLease` handler
7. Update client auth interceptor (decide on approach)
8. Add `extendLease` method to KMSUser
9. Update demo UI to include auto-extend checkbox
10. Write comprehensive tests
11. Manual testing in browser
12. Update documentation

## Security Considerations

### Why Auto-Extend is Safe

1. **No new permissions**: Auto-extend can only extend existing leases, not create new ones
2. **Same scope**: Extended lease has same userId and kid (can't change permissions)
3. **Time-limited**: Each extension is finite (30 days), not infinite
4. **Explicit grant**: User explicitly grants auto-extend permission during initial unlock
5. **Revocable**: User can regenerate VAPID key to invalidate all leases immediately
6. **Key-bound**: If VAPID key changes, all leases (auto-extend or not) become invalid

### Threat Model

**Attack: Malicious parent extends lease indefinitely**
- Mitigation: Each extension is only 30 days, and user can regenerate VAPID key to revoke

**Attack: Parent extends lease after VAPID regeneration**
- Mitigation: Extension checks kid, will fail if VAPID key changed

**Attack: Parent extends someone else's lease**
- Mitigation: Lease is already scoped to userId, extension doesn't change that

**Attack: Parent extends lease with autoExtend=false**
- Mitigation: Worker checks unlock status, will fail if not unlocked

### Comparison to Alternatives

**Alternative 1: Infinite leases**
- ❌ No way to revoke without VAPID regeneration
- ❌ Less granular control

**Alternative 2: Very long leases (1 year)**
- ❌ Same revocation problem
- ✅ But simpler implementation

**Current design (auto-extend with 30-day increments)**:
- ✅ Can be revoked by regenerating VAPID key
- ✅ Time-limited but automatic (best of both worlds)
- ✅ User choice between auto and strict modes

## Migration Path

### Existing Leases

Existing leases created before this change won't have an `autoExtend` field.

**Options**:
1. Default to `false` (strict mode) - safer, but worse UX
2. Default to `true` (auto mode) - better UX, but changes security posture
3. Require re-creation of leases - safest, but annoying

**Recommended**: Default to `false` for existing leases (conservative), but make it easy for users to create new leases with auto-extend enabled.

**Implementation**:
```typescript
// When fetching a lease
const lease = await getLeaseById(leaseId);
const autoExtend = lease.autoExtend ?? false; // Default to strict for old leases
```

### Database Schema

IndexedDB doesn't require schema migrations, but we should:
1. Handle missing `autoExtend` field gracefully (default to false)
2. Update all lease creation to include `autoExtend`
3. Document the change in audit logs

## Open Questions

1. ~~Should `extendLease` require explicit leaseId or auto-detect?~~
   - **Decision**: Explicit leaseId (passed by user)

2. Should we add a "Extend All Valid Leases" bulk operation?
   - **Defer**: Not needed for MVP, can add later if requested

3. Should auto-extend leases have a maximum number of extensions?
   - **Defer**: No limit for now, user can always regenerate VAPID key

4. Should we log each extension in audit log?
   - **Yes**: Important for debugging and security auditing

5. Should the UI show which leases have auto-extend enabled?
   - **Yes**: Add indicator in VAPID key info display

## Success Criteria

1. ✅ Lease duration is 30 days (not 24 hours)
2. ✅ createLease accepts optional `autoExtend` parameter (default: true)
3. ✅ extendLease RPC method works correctly
4. ✅ Auto-extend leases can be extended without re-auth
5. ✅ Strict mode leases require re-auth to extend
6. ✅ UI clearly shows the auto-extend option and implications
7. ✅ All tests pass with 80%+ coverage
8. ✅ Extension is audited in audit log
9. ✅ VAPID key regeneration invalidates auto-extend leases
10. ✅ Manual testing in browser confirms good UX

## Documentation Updates

After implementation, update:
- API documentation for createLease and extendLease
- Architecture docs to explain auto-extend feature
- Security model documentation
- Demo UI usage instructions
