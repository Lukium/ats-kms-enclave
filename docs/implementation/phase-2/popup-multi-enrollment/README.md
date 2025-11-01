# Multi-Enrollment Support for Stateless Popup Flow

**Status**: Planning
**Created**: 2025-11-01
**Target**: Phase 2 - Production KMS

---

## Overview

Re-implement multi-enrollment (add authentication method) functionality using the new stateless popup flow. The previous implementation had the popup detect existing enrollments and handle unlock, but since popups are now stateless, the **iframe must handle unlock before opening the popup**.

### Key Insight

**Old Flow (parent-mediated)**:
```
Parent → Popup (stateful)
  ↓
Popup detects enrollment exists
  ↓
Popup prompts user to unlock with existing auth
  ↓
Popup unwraps MS, gets new auth, re-wraps MS
```

**New Flow (KMS-only popup, stateless)**:
```
Iframe detects enrollment exists
  ↓
Iframe unlocks MS with existing auth (via unlock popup/prompt)
  ↓
Iframe opens stateless setup popup to get NEW auth
  ↓
Iframe receives encrypted new credentials
  ↓
Iframe re-wraps MS with new credentials
```

---

## Current State Analysis

### Existing Code (Already Implemented) ✅

1. **✅ Unlock Functions** (`src/v2/unlock.ts:285-385`):
   - `unlockWithPassphrase(userId, passphrase)`
   - `unlockWithPasskeyPRF(userId, prfOutput)`
   - `unlockWithPasskeyGate(userId)`
   - All return `UnlockResult` with unwrapped MS

2. **✅ Multi-Enrollment Storage** (`docs/architecture/crypto/V2/design/06-multi-enrollment.md`):
   - Enrollment index with metadata
   - Multiple configs encrypting same MS
   - Storage layout: `enrollment:{id}:config`

3. **✅ Stateless Popup Flow** (`src/v2/worker.ts:435-507`):
   - `handleSetupWithPopup()`
   - Generates transport keys
   - Opens popup via client
   - Receives encrypted credentials
   - Decrypts and completes setup

4. **✅ Status Detection** (`src/v2/worker.ts:1913-1927`):
   - `isSetup()` returns `{ isSetup: boolean; methods: string[] }`
   - Already tracks which methods are enrolled

5. **✅ Add Enrollment Implementation** (`src/v2/worker.ts:968-1064`):
   - `handleAddEnrollment()` **fully implemented**
   - Unlocks with existing credentials (lines 989-1011)
   - Gets MS from unlock result
   - Calls setup functions with existing MS (lines 1014-1046)
   - Zeroizes MS (line 1049)
   - **This is the complete multi-enrollment flow!**

### What's Missing (Very Small Changes)

The existing `handleAddEnrollment()` expects **both credentials in the RPC call**:
```typescript
{
  credentials: AuthCredentials,  // existing (for unlock)
  newCredentials: { ... }         // NEW credentials (plaintext!)
}
```

We need to modify it to **get new credentials via popup** instead:
1. **❌ Modify `handleAddEnrollment()`** to open popup for new credentials
2. **❌ Remove `newCredentials` parameter** (get from popup instead)

---

## Architecture

### Flow Diagram

```
┌─────────┐                 ┌────────┐                 ┌───────┐
│ Parent  │                 │ Iframe │                 │ Popup │
│  PWA    │                 │  KMS   │                 │  KMS  │
└─────────┘                 └────────┘                 └───────┘
     │                           │                          │
     │  RPC: setupWithPopup      │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                    [Iframe checks if setup]          │
     │                           │                          │
     │               ┌───────────┴────────────┐             │
     │               │                        │             │
     │        [No enrollment]          [Has enrollment]     │
     │               │                        │             │
     │               │                        │             │
     │       [Direct to setup popup]   [Need to unlock]     │
     │               │                        │             │
     │               │              [Unlock with existing auth]
     │               │                        │             │
     │               │              Option A: Prompt in iframe
     │               │              Option B: Unlock popup │
     │               │                        │             │
     │               │              [MS unwrapped, in memory]
     │               │                        │             │
     │               └────────────┬───────────┘             │
     │                           │                          │
     │             [Open stateless setup popup for NEW auth]│
     │                           │                          │
     │  kms:request-popup        │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  window.open(minimal URL) │                          │
     ├────────────────────────────────────────────────────> │
     │                           │                          │
     │  kms:popup-opened         │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                           │  MessageChannel + params │
     │                           │─────────────────────────>│
     │                           │                          │
     │                           │  encrypted NEW credentials│
     │                           │◄─────────────────────────┤
     │                           │                          │
     │          [Decrypt new credentials]                   │
     │          [Re-wrap MS with new KEK]                   │
     │          [Store new enrollment config]               │
     │                           │                          │
     │  setupComplete            │                          │
     │◄──────────────────────────┤                          │
```

### Decision: How to Unlock?

**Option A: In-iframe Prompt (Simpler, Recommended)**
- Show modal/form in iframe asking for existing passphrase/passkey
- Use existing `unlockWithPassphrase()` / `unlockWithPasskeyPRF()`
- Keeps all crypto operations in iframe (secure)
- No additional popup complexity

**Option B: Unlock Popup (More Complex)**
- Open separate "unlock" popup before "setup" popup
- Same stateless flow as setup
- More consistent UX but adds complexity

**✅ Recommendation: Start with Option A** (in-iframe prompt)

---

## Implementation Steps

### Step 1: Modify `handleAddEnrollment()` to Use Popup

**File**: `src/v2/worker.ts`
**Function**: `handleAddEnrollment()` (lines 968-1064)

**Current signature**:
```typescript
async function handleAddEnrollment(
  params: {
    userId: string;
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    credentials: AuthCredentials;
    newCredentials: unknown;  // ❌ Remove this - get from popup
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }>
```

**New signature**:
```typescript
async function handleAddEnrollment(
  params: {
    userId: string;
    credentials: AuthCredentials;  // For unlocking
    // No newCredentials - will get from popup
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }>
```

**Changes**:
```typescript
async function handleAddEnrollment(
  params: {
    userId: string;
    credentials: AuthCredentials;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { userId, credentials } = params;

  // Step 1: Unlock to get MS (EXISTING CODE - lines 989-1011)
  await withUnlock(credentials, async (mkek, _ms) => {
    await ensureAuditKey(mkek);
    return true;
  });

  let ms: Uint8Array;
  if (credentials.method === 'passphrase') {
    const result = await unlockWithPassphrase(userId, credentials.passphrase);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-prf') {
    const result = await unlockWithPasskeyPRF(userId, credentials.prfOutput);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-gate') {
    const result = await unlockWithPasskeyGate(userId);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else {
    throw new Error('Invalid credentials method');
  }

  // Step 2: Generate transport key and open popup for NEW credentials
  const transport = await generateSetupTransportKey();

  const popupURL = new URL('https://kms.ats.run/');
  popupURL.searchParams.set('mode', 'setup');

  const newCredsPromise = new Promise<{
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    transportKeyId: string;
    userId: string;
    ephemeralPublicKey: string;
    iv: string;
    encryptedCredentials: string;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Add enrollment popup timeout'));
    }, 300000); // 5 minute timeout

    pendingPopupRequests.set(requestId, {
      resolve,
      reject,
      timeout
    });

    self.postMessage({
      type: 'worker:setup-with-popup',
      requestId,
      userId,
      popupURL: popupURL.toString(),
      transportKey: transport.publicKey,
      transportKeyId: transport.keyId,
      appSalt: transport.appSalt,
      hkdfSalt: transport.hkdfSalt,
    });
  });

  const encryptedCreds = await newCredsPromise;

  // Step 3: Decrypt credentials (reuse logic from setupWithEncryptedCredentials)
  const popupPublicKeyBytes = base64urlToArrayBuffer(encryptedCreds.ephemeralPublicKey);
  const popupPublicKey = await crypto.subtle.importKey(
    'raw',
    popupPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: popupPublicKey },
    transport.privateKey,
    256
  );

  const sharedSecretKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits']
  );

  const aesKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('ATS/KMS/setup-transport/v2'),
      hash: 'SHA-256',
    },
    sharedSecretKey,
    256
  );

  const aesKey = await crypto.subtle.importKey(
    'raw',
    aesKeyBits,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const iv = base64urlToArrayBuffer(encryptedCreds.iv);
  const ciphertext = base64urlToArrayBuffer(encryptedCreds.encryptedCredentials);

  const credentialsJSON = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    aesKey,
    ciphertext
  );

  const newCredentials = JSON.parse(new TextDecoder().decode(credentialsJSON));
  const method = encryptedCreds.method;

  // Step 4: Setup new enrollment with existing MS (EXISTING CODE - lines 1014-1046)
  let enrollmentResult;
  if (method === 'passphrase') {
    if (typeof newCredentials.passphrase !== 'string') {
      throw new Error('passphrase must be a string');
    }
    enrollmentResult = await setupPassphrase(userId, newCredentials.passphrase, ms);
  } else if (method === 'passkey-prf') {
    if (!(newCredentials.credentialId instanceof ArrayBuffer)) {
      throw new Error('credentialId must be an ArrayBuffer');
    }
    if (!(newCredentials.prfOutput instanceof ArrayBuffer)) {
      throw new Error('prfOutput must be an ArrayBuffer');
    }
    const rpId = typeof newCredentials.rpId === 'string' ? newCredentials.rpId : '';
    enrollmentResult = await setupPasskeyPRF(
      userId,
      newCredentials.credentialId,
      newCredentials.prfOutput,
      ms,
      rpId
    );
  } else if (method === 'passkey-gate') {
    if (!(newCredentials.credentialId instanceof ArrayBuffer)) {
      throw new Error('credentialId must be an ArrayBuffer');
    }
    const rpId = typeof newCredentials.rpId === 'string' ? newCredentials.rpId : '';
    enrollmentResult = await setupPasskeyGate(userId, newCredentials.credentialId, ms, rpId);
  } else {
    const exhaustive: never = method;
    throw new Error(`Unknown enrollment method: ${String(exhaustive)}`);
  }

  // Zeroize MS (EXISTING CODE - line 1049)
  ms.fill(0);

  if (!enrollmentResult.success) {
    throw new Error(enrollmentResult.error);
  }

  // Delete transport key (one-time use)
  ephemeralTransportKeys.delete(encryptedCreds.transportKeyId);

  await logOperation({
    op: 'add-enrollment',
    kid: '',
    requestId,
    userId: credentials.userId,
    details: { method, action: 'add-enrollment' },
  });

  return { success: true, enrollmentId: `enrollment:${method}:v2` };
}
```

### Step 2: Update RPC Validation

**File**: `src/v2/rpc-validation.ts`
**Function**: `validateAddEnrollment()` (around line 279)

Remove `method` and `newCredentials` validation:

**Before**:
```typescript
export function validateAddEnrollment(params: unknown): {
  userId: string;
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  credentials: AuthCredentials;
  newCredentials: unknown;
} {
  const p = validateParamsObject('addEnrollment', params);
  const method = validateString('addEnrollment', 'method', p.method);

  if (method !== 'passphrase' && method !== 'passkey-prf' && method !== 'passkey-gate') {
    throw new RPCValidationError('addEnrollment', 'method', 'passphrase | passkey-prf | passkey-gate', method);
  }

  return {
    userId: validateString('addEnrollment', 'userId', p.userId),
    method,
    credentials: validateAuthCredentials('addEnrollment', p.credentials),
    newCredentials: p.newCredentials,
  };
}
```

**After**:
```typescript
export function validateAddEnrollment(params: unknown): {
  userId: string;
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('addEnrollment', params);

  return {
    userId: validateString('addEnrollment', 'userId', p.userId),
    credentials: validateAuthCredentials('addEnrollment', p.credentials),
  };
}
```

### Step 3: Update Parent UI

**File**: `example/phase-2/parent.ts`
**Function**: `renderSetupUI()`

Already shows "Add" button when `hasAnyMethod` is true. Change it to call `addEnrollment()` instead of `setupWithPopup()` and pass existing credentials for unlock.

**Change**: Update `renderSetupUI()` to show different buttons for initial setup vs add enrollment.

For **initial setup** (no enrollment): Button calls `setupWithPopup()`
For **add enrollment** (has enrollment): Button calls `addEnrollment()` with unlock credentials

### Step 4: Add Tests

**File**: `tests/v2/worker.test.ts`

```typescript
describe('Multi-enrollment with popup', () => {
  it('should detect existing enrollment and prompt for unlock', async () => {
    // Setup: Initial passphrase enrollment
    await handleMessage(createRequest('setupWithPopup', { userId: 'test@example.com' }));

    // Simulate popup providing passphrase credentials
    // (test helper)

    // Now try to add second enrollment
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });
    const responsePromise = handleMessage(request);

    // Should receive unlock request
    await waitForMessage('worker:request-unlock');

    // Provide unlock credentials
    dispatchMessage({
      type: 'client:unlock-credentials',
      requestId: request.id,
      credentials: {
        method: 'passphrase',
        passphrase: 'test-passphrase-123'
      }
    });

    // Should then request setup popup (for new credentials)
    await waitForMessage('worker:setup-with-popup');

    // Provide new credentials
    dispatchMessage({
      type: 'worker:popup-credentials',
      requestId: request.id,
      credentials: {
        method: 'passkey-prf',
        transportKeyId: 'transport-123',
        userId: 'test@example.com',
        ephemeralPublicKey: '...',
        iv: '...',
        encryptedCredentials: '...'
      }
    });

    const response = await responsePromise;
    expect(response.error).toBeUndefined();

    // Verify two enrollments exist
    const index = await storage.get('enrollment:index');
    expect(index.enrollments).toHaveLength(2);
  });
});
```

---

## Files to Modify

### Core Implementation
1. **`src/v2/worker.ts`**:
   - Modify `handleSetupWithPopup()` to detect existing enrollments
   - Add `handleInitialSetupWithPopup()` (extracted from current logic)
   - Add `handleAddEnrollmentWithPopup()` (new multi-enrollment flow)
   - Add unlock prompt message handlers
   - Add `pendingUnlockPrompts` Map

2. **`src/v2/client.ts`**:
   - Add `worker:request-unlock` message handler
   - Add `showUnlockPrompt()` function
   - Add `showPassphraseUnlock()` function
   - Add `showPasskeyUnlock()` function
   - Handle unlock UI rendering and credential collection

3. **`src/v2/storage.ts` or new `src/v2/enrollment.ts`**:
   - Add `addEnrollmentConfig()` function
   - Add `buildEnrollmentConfig()` helper
   - Add enrollment index management

4. **`src/v2/types.ts`**:
   - Add `UnlockCredentials` type
   - Add message types: `worker:request-unlock`, `client:unlock-credentials`

### Testing
5. **`tests/v2/worker.test.ts`**:
   - Add multi-enrollment popup tests
   - Test unlock prompt flow
   - Test add enrollment with different credential types

### Documentation
6. **`example/phase-2/parent.ts`**:
   - No changes needed (already supports "Add" button)

7. **`README.md`**:
   - Update to document multi-enrollment capability

---

## Complexity Assessment

### Low Complexity (Reuse Existing) ✅
- ✅ **Multi-enrollment logic fully implemented** (`handleAddEnrollment()`)
- ✅ Unlock functions already exist
- ✅ Stateless popup flow already working
- ✅ Parent UI already has "Add" button
- ✅ ECDH decryption logic exists (can reuse from `setupWithEncryptedCredentials`)

### Very Low Complexity (Minimal Changes Needed) 🟢
- 🟢 Remove `newCredentials` parameter from `handleAddEnrollment()`
- 🟢 Add popup opening logic (copy from `handleSetupWithPopup()`)
- 🟢 Add credential decryption (copy from `setupWithEncryptedCredentials()`)
- 🟢 Update RPC validation (remove 2 fields)
- 🟢 Update parent UI to call `addEnrollment()` instead of `setupWithPopup()`

### Estimated Effort (REVISED DOWN)
- **Core Implementation**: 1-2 hours (mostly copy-paste existing code)
- **Testing**: 1-2 hours (similar to existing tests)
- **UI Changes**: 30 minutes (change button handler)
- **Total**: ~3-5 hours (much less than original estimate!)

---

## Security Considerations

### 1. Master Secret Handling
**Risk**: MS in memory during add enrollment flow
**Mitigation**:
- Keep MS in memory only during operation
- Clear MS immediately after re-wrapping
- Use secure memory clearing (fill with random data)

### 2. Unlock Credentials
**Risk**: User provides wrong credentials
**Mitigation**:
- KCV validation on unlock
- Clear error messages
- Limit unlock attempts (future: rate limiting)

### 3. Credential Reuse
**Risk**: User tries to enroll same passkey twice
**Mitigation**:
- Check enrollment index for duplicate credentialIds
- Reject if passkey already enrolled

### 4. Lockout Prevention
**Risk**: User removes all enrollments
**Mitigation**:
- Enforce minimum 1 enrollment (existing logic)
- Warn before removal (future)

---

## Testing Strategy

### Unit Tests
1. **Enrollment Detection**: `setupWithPopup()` correctly branches on `isSetup()`
2. **Unlock Flow**: Unlock prompt resolves with correct credentials
3. **Add Enrollment**: New enrollment config stored with same MS
4. **MS Consistency**: All enrollments decrypt to same MS value

### Integration Tests
1. **Full Add Flow**: Initial setup → add second method → verify both work
2. **Different Method Types**: Passphrase → add passkey, passkey → add passphrase
3. **Unlock with Each Method**: Unlock with passphrase, then add passkey via unlock
4. **Error Handling**: Cancel unlock, wrong passphrase, timeout

### Browser Tests (Playwright)
1. **UI Flow**: Click "Add", see unlock prompt, enter credentials, see setup popup
2. **WebAuthn Integration**: Unlock with passkey, add new passkey
3. **Error States**: Invalid passphrase shows error, retry works

---

## Migration Path

### Phase 1: Core Implementation (This Plan)
- Implement unlock prompt in iframe
- Add multi-enrollment storage
- Update `setupWithPopup()` to handle both flows

### Phase 2: Enhanced UX (Future)
- Better unlock UI (modal, styling)
- Enrollment labels (user-friendly names)
- Remove enrollment functionality
- List enrollments in settings

### Phase 3: Advanced Features (Future)
- Device-specific enrollment hints
- Recovery code generation
- Enrollment usage analytics

---

## Open Questions

1. **Unlock UI Location**: In-iframe modal vs separate popup?
   - **Decision**: Start with in-iframe modal (simpler, more secure)

2. **Enrollment Labels**: Auto-generate or user-provided?
   - **Decision**: Auto-generate initially ("New passphrase", "New passkey"), add user labels later

3. **Unlock Method Selection**: Show all methods or prefer certain order?
   - **Decision**: Show all enrolled methods, no preference

4. **MS Memory Lifetime**: How long to keep MS in memory?
   - **Decision**: Only during add enrollment operation, clear immediately after

---

## Success Criteria

1. ✅ User can add second authentication method via popup
2. ✅ User must unlock with existing method before adding new one
3. ✅ Both methods decrypt to same Master Secret
4. ✅ All tests passing (unit + integration + browser)
5. ✅ No security regressions (MS never exposed)
6. ✅ Code coverage ≥ 80%

---

## References

- **Multi-Enrollment Design**: `docs/architecture/crypto/V2/design/06-multi-enrollment.md`
- **Unlock Functions**: `src/v2/unlock.ts:285-385`
- **Stateless Popup Flow**: `src/v2/worker.ts:435-507`
- **Storage Design**: `docs/architecture/crypto/V2/design/03-storage.md`
