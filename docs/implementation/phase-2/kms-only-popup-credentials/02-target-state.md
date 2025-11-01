# Target State: KMS-Only Popup Flow (Option A+)

## Overview

New implementation where iframe KMS directly manages popup communication, with parent acting only as a "popup opener" with zero visibility into credential exchange.

## Flow Diagram

```
┌─────────────┐                 ┌──────────────┐                 ┌─────────────┐
│   Parent    │                 │    Iframe    │                 │    Popup    │
│     PWA     │                 │     KMS      │                 │     KMS     │
│ localhost   │                 │ kms.ats.run  │                 │ kms.ats.run │
└─────────────┘                 └──────────────┘                 └─────────────┘
      │                                │                                 │
      │ 1. User clicks setup           │                                 │
      │    RPC: setupWithPopup         │                                 │
      │───────────────────────────────>│                                 │
      │                                │                                 │
      │                         2. Generate transport key                │
      │                            (stays in iframe)                     │
      │                                │                                 │
      │                         3. Generate requestId                    │
      │                            (for correlation)                     │
      │                                │                                 │
      │ 4. kms:request-popup           │                                 │
      │    {url, requestId}            │                                 │
      │<───────────────────────────────┤                                 │
      │                                │                                 │
      │ 5. window.open(url)            │                                 │
      │    URL: https://kms.ats.run/?mode=setup                          │
      │    (NO transport params!)      │                                 │
      │────────────────────────────────────────────────────────────────>│
      │                                │                                 │
      │ 6. kms:popup-opened            │                                 │
      │    {requestId}                 │                                 │
      │───────────────────────────────>│                                 │
      │                                │                                 │
      │                                │                          7. Popup ready,
      │                                │                             send kms:popup-ready
      │                                │                                 │
      │                                │ 8. kms:popup-ready              │
      │                                │    {state}                      │
      │                                │<────────────────────────────────┤
      │                                │                                 │
      │                                │ 9. Create MessageChannel        │
      │                                │    Send kms:connect + port2     │
      │                                │    WITH transport params        │
      │                                │────────────────────────────────>│
      │                                │    {transportKey, keyId,        │
      │                                │     appSalt, hkdfSalt}          │
      │                                │                                 │
      │                                │                          10. Collect credentials
      │                                │                              (passphrase/passkey)
      │                                │                                 │
      │                                │                          11. Encrypt with transport key
      │                                │                              (ECDH + AES-GCM)
      │                                │                                 │
      │                                │ 12. kms:setup-credentials       │
      │                                │     (via MessagePort)           │
      │                                │<────────────────────────────────┤
      │                                │                                 │
      │                         13. Decrypt credentials                  │
      │                             (ECDH + AES-GCM)                     │
      │                                │                                 │
      │                         14. Call setup handler                   │
      │                             (setupPassphrase/PRF/Gate)           │
      │                                │                                 │
      │ 15. {success, enrollmentId}    │                                 │
      │<───────────────────────────────┤                                 │
      │                                │                                 │
```

## Key Differences from Current State

### What Parent Does
**Before:**
- ✗ Generates transport key (via iframe RPC)
- ✗ Generates requestId
- ✗ Builds URL with transport params
- ✗ Opens popup
- ✗ Establishes MessageChannel with popup
- ✗ Receives encrypted credentials
- ✗ Forwards credentials to iframe

**After:**
- ✓ Receives popup request from iframe
- ✓ Opens popup (minimal URL only)
- ✓ Notifies iframe popup opened
- **That's it!**

### What Iframe Does
**Before:**
- ✗ Generates transport key (on parent request)
- ✗ Waits for parent to forward credentials
- ✗ Decrypts credentials
- ✗ Processes setup

**After:**
- ✓ Generates transport key (internally)
- ✓ Requests parent to open popup
- ✓ Establishes MessageChannel with popup directly
- ✓ Sends transport params via MessageChannel (not URL)
- ✓ Receives encrypted credentials directly
- ✓ Decrypts credentials
- ✓ Processes setup

### What Popup Does
**Before:**
- ✗ Reads transport params from URL
- ✗ Waits for parent's kms:connect
- ✗ Sends credentials to parent

**After:**
- ✓ Sends kms:popup-ready to iframe (same origin)
- ✓ Receives kms:connect from iframe with transport params
- ✓ Sends credentials to iframe directly

## Security Improvements

### 1. Parent Has Zero Visibility
| Data | Current (Parent Sees) | New (Parent Sees) |
|------|---------------------|------------------|
| Transport public key | ✗ Yes (in URL) | ✓ No |
| Key ID | ✗ Yes (in URL) | ✓ No |
| App salt | ✗ Yes (in URL) | ✓ No |
| HKDF salt | ✗ Yes (in URL) | ✓ No |
| Encrypted credentials | ✗ Yes (via MessageChannel) | ✓ No |
| Setup method | ✗ Yes (in payload) | ✓ No |
| User ID | ✗ Yes (in RPC call) | ✓ Yes (in initial RPC) |

**Net improvement:** Parent only knows user initiated setup. No cryptographic material visible.

### 2. Direct Same-Origin Communication
**Current flow:**
```
Popup (kms.ats.run) ──┐
                      ├─> Parent (localhost) ──> Iframe (kms.ats.run)
                      └─────────────────────────────────^
                           (cross-origin hops)
```

**New flow:**
```
Popup (kms.ats.run) ────────────> Iframe (kms.ats.run)
                    (same-origin, direct)
```

**Benefits:**
- Fewer cross-origin message hops
- Simpler origin validation (popup only accepts `kms.ats.run`)
- Reduced attack surface (parent not in data path)

### 3. Reduced Attack Surface

**Current:**
- Parent could refuse to forward credentials
- Parent could modify encrypted payload
- Parent could intercept MessageChannel setup
- Parent sees metadata (method, timing, success/failure)

**New:**
- Parent can only refuse to open popup (same as before)
- Parent cannot interfere with credential flow
- Parent has no access to MessageChannel
- Parent doesn't see setup outcome (unless iframe reports it)

## Implementation Components

### 1. New RPC Method: setupWithPopup

**File:** `src/v2/kms-user.ts`

```typescript
/**
 * Setup user authentication via popup (iframe-managed flow).
 *
 * Unlike setupWithEncryptedCredentials (parent-mediated), this method
 * allows the iframe to directly manage the popup and credential exchange.
 * Parent only assists with window.open() - all cryptographic operations
 * and data flows bypass the parent entirely.
 *
 * @param params.userId - User ID to setup
 * @returns Promise that resolves when setup completes
 */
async setupWithPopup(params: {
  userId: string;
}): Promise<SetupResult> {
  return this.sendRequest<SetupResult>('setupWithPopup', params);
}
```

### 2. Popup Request Protocol

**Message:** `kms:request-popup`
**Direction:** Iframe → Parent
**Payload:**
```typescript
{
  type: 'kms:request-popup',
  url: string,          // Minimal URL: "https://kms.ats.run/?mode=setup"
  requestId: string,    // For correlation
}
```

**Message:** `kms:popup-opened`
**Direction:** Parent → Iframe
**Payload:**
```typescript
{
  type: 'kms:popup-opened',
  requestId: string,    // Matches request
}
```

**Message:** `kms:popup-blocked`
**Direction:** Parent → Iframe
**Payload:**
```typescript
{
  type: 'kms:popup-blocked',
  requestId: string,    // Matches request
  reason?: string,      // Optional error details
}
```

### 3. Popup-Iframe Handshake

**Message:** `kms:popup-ready`
**Direction:** Popup → Iframe
**Payload:**
```typescript
{
  type: 'kms:popup-ready',
  state?: string,       // Optional state from URL
}
```

**Message:** `kms:connect`
**Direction:** Iframe → Popup
**Payload:**
```typescript
{
  type: 'kms:connect',
  transportKey: string,     // base64url P-256 public key
  keyId: string,            // UUID
  appSalt: string,          // base64url (32 bytes)
  hkdfSalt: string,         // base64url (32 bytes)
  requestId: string,        // For audit logging
}
```
**Transfer:** `[MessagePort]` - port2 transferred to popup

### 4. Credential Response (Same as Before)

**Message:** `kms:setup-credentials`
**Direction:** Popup → Iframe (via MessagePort)
**Payload:**
```typescript
{
  type: 'kms:setup-credentials',
  payload: {
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate',
    transportKeyId: string,
    userId: string,
    ephemeralPublicKey: string,  // Popup's public key
    iv: string,                  // AES-GCM IV
    encryptedCredentials: string // AES-GCM ciphertext
  }
}
```

## File Changes

### New Files
None - all changes in existing files

### Modified Files

#### 1. `src/v2/kms-user.ts`
**Changes:**
- Add `setupWithPopup()` method
- Keep `setupWithEncryptedCredentials()` for backwards compatibility
- Update docs to recommend new method

**Lines affected:** ~50 lines added

#### 2. `src/v2/worker.ts`
**Changes:**
- Add `handleSetupWithPopup()` function
- Add popup request logic
- Add popup handshake handling
- Keep `setupWithEncryptedCredentials()` handler

**Lines affected:** ~150 lines added

#### 3. `src/v2/client.ts`
**Changes:**
- Update stateless popup mode to send `kms:popup-ready`
- Change message validation to only accept `kms.ats.run` origin
- Update connection logic to receive transport params via postMessage

**Lines affected:** ~100 lines modified

#### 4. `src/v2/rpc-validation.ts`
**Changes:**
- Add `validateSetupWithPopup()` function

**Lines affected:** ~15 lines added

#### 5. `example/phase-2/parent.ts`
**Changes:**
- Remove `generateSetupTransportKey()` call
- Remove MessageChannel setup logic
- Remove credential receiving/forwarding
- Add popup request handler
- Simplify to just open popup on iframe request

**Lines affected:** ~150 lines removed, ~50 lines added (net: -100 lines)

#### 6. Tests
**New tests needed:**
- `tests/v2/worker.test.ts` - Test `setupWithPopup` handler
- `tests/v2/client.test.ts` - Test popup handshake
- Integration test for full flow

**Lines affected:** ~200 lines added

### Configuration Files
No changes to build configuration or headers needed.

## Migration Path

### Phase 1: Add New Method (Backwards Compatible)
1. Implement `setupWithPopup()` in parallel
2. Keep old `setupWithEncryptedCredentials()` working
3. Both methods coexist

### Phase 2: Update Example App
1. Change `example/phase-2/parent.ts` to use new method
2. Test thoroughly
3. Keep old code commented for reference

### Phase 3: Deprecation
1. Mark `setupWithEncryptedCredentials()` as deprecated
2. Update documentation to recommend new method
3. Add console warnings when old method used

### Phase 4: Cleanup (Future)
1. Remove deprecated method
2. Remove old test code
3. Update architecture docs

## Testing Strategy

### Unit Tests
- [ ] `validateSetupWithPopup()` parameter validation
- [ ] Popup request message handling
- [ ] Popup handshake logic
- [ ] MessageChannel establishment
- [ ] Credential decryption (same as before)

### Integration Tests
- [ ] Full setup flow with popup
- [ ] Popup blocked scenario
- [ ] Timeout scenarios (popup never responds)
- [ ] Origin validation (reject wrong origins)
- [ ] Concurrent setup attempts
- [ ] Error propagation

### Manual Testing
- [ ] Dev environment (localhost parent + kms.ats.run iframe/popup)
- [ ] Production environment
- [ ] Popup blocker handling
- [ ] Network failures
- [ ] Different browsers (Chrome, Firefox, Safari)
- [ ] Mobile browsers

## Performance Impact

### Latency Changes
**Before:**
```
Parent RPC → Iframe → Parent → Popup → Parent → Iframe
  ~10ms      ~50ms     ~50ms    ~user   ~50ms    ~10ms
Total overhead: ~170ms + user input
```

**After:**
```
Parent RPC → Iframe → Popup → Iframe
  ~10ms      ~50ms     ~user   ~10ms
Total overhead: ~70ms + user input
```

**Improvement:** ~100ms faster (fewer message hops)

### Memory Impact
**Before:**
- Parent: MessagePort (~100 bytes) + pending request (~500 bytes)
- Iframe: Transport key (~200 bytes)
- Popup: MessagePort (~100 bytes)
**Total:** ~900 bytes

**After:**
- Parent: Popup request state (~200 bytes)
- Iframe: Transport key (~200 bytes) + MessagePort (~100 bytes)
- Popup: MessagePort (~100 bytes)
**Total:** ~600 bytes

**Improvement:** ~300 bytes less (parent doesn't store MessagePort)

### Network Impact
**No change** - same number of postMessage calls, just different routing.

## Error Handling

### Popup Blocked
**Before:**
```
Parent: window.open() returns null
Parent: Shows alert to user
Parent: RPC rejects with error
```

**After:**
```
Parent: window.open() returns null
Parent: Sends kms:popup-blocked to iframe
Iframe: Rejects RPC promise
Parent: Catches RPC error, shows alert to user
```

### Popup Closed Early
**Before:**
```
Parent: MessageChannel receives nothing
Parent: Timeout fires (5min)
Parent: RPC rejects
```

**After:**
```
Iframe: MessageChannel receives nothing
Iframe: Timeout fires (5min)
Iframe: RPC rejects
Parent: Catches RPC error
```

### Network Failure
**Both:** Timeout mechanism handles it (no change)

### Concurrent Setups
**Before:**
- Parent could handle multiple concurrent setups
- Each has unique requestId
- Risk of MessagePort confusion

**After:**
- Iframe handles one setup at a time (or uses requestId to correlate)
- Simpler state management
- Less risk of port confusion

## Rollback Plan

If new implementation has issues:

1. **Keep old method available:** Don't delete `setupWithEncryptedCredentials()`
2. **Feature flag:** Add flag to switch between methods
3. **Parent fallback:** Parent can detect if iframe doesn't support new method
4. **Quick revert:** Change example app back to old method
5. **Gradual migration:** Test new method in staging before production

## Success Criteria

- [x] Plan documented
- [ ] Implementation complete
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Manual testing successful
- [ ] Performance meets or exceeds current
- [ ] Security audit passed
- [ ] Example app works
- [ ] Documentation updated
- [ ] No regressions in old flow (if kept for compatibility)
