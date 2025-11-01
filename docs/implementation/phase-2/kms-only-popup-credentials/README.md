# Phase 2: KMS-Only Popup Credential Flow (Option A+)

## Overview

Migration plan to change from parent-mediated popup flow to direct iframe-popup communication, where parent acts only as a "popup opener" with zero visibility into credential exchange.

## Current Flow (Parent-Mediated)

```
┌─────────┐                 ┌────────┐                 ┌───────┐
│ Parent  │────────────────>│ Iframe │                 │ Popup │
│  PWA    │  1. RPC setup   │  KMS   │                 │  KMS  │
└─────────┘                 └────────┘                 └───────┘
     │                           │                          │
     │  2. generateTransport     │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  3. window.open(params)   │                          │
     ├────────────────────────────────────────────────────> │
     │                           │                          │
     │◄─────────────────────────────────────────────────────┤
     │  4. MessageChannel (parent ↔ popup)                  │
     │                           │                          │
     │  5. encrypted credentials │                          │
     │◄─────────────────────────────────────────────────────┤
     │                           │                          │
     │  6. setupWithEncrypted    │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
```

**Security issues:**
- Parent sees transport params in URL
- Parent mediates MessageChannel setup
- Parent receives encrypted credentials (even if can't decrypt)
- Parent could block/interfere with popup communication

## New Flow (KMS-Only, Option A+)

```
┌─────────┐                 ┌────────┐                 ┌───────┐
│ Parent  │                 │ Iframe │                 │ Popup │
│  PWA    │                 │  KMS   │                 │  KMS  │
└─────────┘                 └────────┘                 └───────┘
     │                           │                          │
     │  1. RPC setupRequest      │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │  2. requestPopup(url)     │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  3. window.open(url)      │                          │
     ├────────────────────────────────────────────────────> │
     │                           │                          │
     │  4. popupOpened           │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                           │  5. MessageChannel       │
     │                           │  (iframe ↔ popup)        │
     │                           │◄────────────────────────>│
     │                           │                          │
     │                           │  6. transport params     │
     │                           │─────────────────────────>│
     │                           │                          │
     │                           │  7. encrypted creds      │
     │                           │◄─────────────────────────┤
     │                           │                          │
     │  8. setupComplete(result) │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
```

**Security improvements:**
- Parent only sees minimal URL (`https://kms.ats.run/?mode=setup`)
- No transport params in URL (sent via postMessage after popup opens)
- Direct MessageChannel between iframe and popup (same origin)
- Parent never sees credentials (encrypted or otherwise)
- Popup validates all messages from `kms.ats.run` origin only

## Implementation Plan

### Step 1: Update Parent RPC Method

**File:** `src/v2/kms-user.ts`

Create new method `setupWithPopup()` that requests iframe to handle popup flow:

```typescript
/**
 * Setup user authentication via popup (iframe-managed flow).
 *
 * Parent calls this method, iframe opens popup and handles all credential
 * exchange directly with popup. Parent only assists with window.open().
 *
 * @param params.userId - User ID to setup
 * @returns Promise that resolves when setup completes
 */
async setupWithPopup(params: {
  userId: string;
}): Promise<SetupResult> {
  // Send RPC request to iframe to start popup flow
  return this.sendRequest<SetupResult>('setupWithPopup', params);
}
```

**Changes:**
- Add new RPC method `setupWithPopup`
- Iframe will emit events requesting parent to open popup
- Parent responds with confirmation that popup opened

### Step 2: Implement Iframe-Side Popup Management

**File:** `src/v2/worker.ts`

Add new RPC handler `setupWithPopup`:

```typescript
case 'setupWithPopup':
  result = await handleSetupWithPopup(
    validators.validateSetupWithPopup(params),
    id
  );
  break;
```

Implement `handleSetupWithPopup`:

```typescript
async function handleSetupWithPopup(params: {
  userId: string;
}, requestId: string): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string;
}> {
  // Step 1: Generate transport key (stays in iframe, never sent to parent)
  const transport = await generateSetupTransportKey();

  // Step 2: Request parent to open popup with minimal URL
  const popupURL = 'https://kms.ats.run/?mode=setup'; // No sensitive params
  const popupRequest = {
    type: 'kms:request-popup',
    url: popupURL,
    requestId: requestId,
  };

  // Send to parent via client.ts (which will forward to parent window)
  // Wait for parent to respond with popup opened confirmation

  // Step 3: Establish MessageChannel with popup
  const channel = new MessageChannel();
  const port1 = channel.port1;
  const port2 = channel.port2;

  // Step 4: Send transport params to popup via MessageChannel
  // (NOT via URL, so parent never sees them)

  // Step 5: Wait for encrypted credentials from popup

  // Step 6: Decrypt and process credentials

  // Step 7: Return result to parent
}
```

### Step 3: Update Client to Request Popup from Parent

**File:** `src/v2/client.ts`

Add popup request forwarding in client (iframe context):

```typescript
// In iframe context: Forward popup requests to parent
private forwardPopupRequestToParent(request: {
  type: 'kms:request-popup';
  url: string;
  requestId: string;
}) {
  if (!this.parentOrigin) {
    throw new Error('Parent origin not configured');
  }

  // Forward to parent window
  if (window.parent && window.parent !== window) {
    window.parent.postMessage(request, this.parentOrigin);
  }
}
```

### Step 4: Update Parent to Handle Popup Requests

**File:** `example/phase-2/parent.ts`

Replace current `setupPassphrase()` flow with popup request handler:

```typescript
// Listen for popup requests from iframe
window.addEventListener('message', (event) => {
  if (event.origin !== KMS_ORIGIN) return;

  const message = event.data;

  if (message.type === 'kms:request-popup') {
    // Iframe is requesting parent to open popup
    const { url, requestId } = message;

    console.log('[Parent] Iframe requested popup:', url);

    // Open popup with minimal URL (no sensitive data)
    const popup = window.open(url, 'kms-setup', 'width=500,height=600');

    if (!popup) {
      // Notify iframe that popup was blocked
      kmsIframe.contentWindow?.postMessage({
        type: 'kms:popup-blocked',
        requestId: requestId,
      }, KMS_ORIGIN);
      return;
    }

    // Notify iframe that popup opened successfully
    kmsIframe.contentWindow?.postMessage({
      type: 'kms:popup-opened',
      requestId: requestId,
    }, KMS_ORIGIN);

    console.log('[Parent] Popup opened, iframe will handle the rest');
  }
});
```

**Remove:**
- All MessageChannel setup code in parent
- Transport parameter handling in parent
- Credential receiving/forwarding logic in parent

### Step 5: Update Iframe to Establish Direct MessageChannel

**File:** `src/v2/worker.ts` (continued)

Complete `handleSetupWithPopup` implementation:

```typescript
async function handleSetupWithPopup(params: {
  userId: string;
}, requestId: string): Promise<SetupResult> {
  // ... (from Step 2)

  // Wait for popup opened confirmation from parent
  const popupOpened = await new Promise<boolean>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Popup open timeout'));
    }, 30000); // 30 second timeout

    const handler = (event: MessageEvent) => {
      if (event.data?.requestId !== requestId) return;

      if (event.data.type === 'kms:popup-opened') {
        clearTimeout(timeout);
        window.removeEventListener('message', handler);
        resolve(true);
      } else if (event.data.type === 'kms:popup-blocked') {
        clearTimeout(timeout);
        window.removeEventListener('message', handler);
        reject(new Error('Popup was blocked by browser'));
      }
    };

    window.addEventListener('message', handler);
  });

  // Now establish MessageChannel with popup
  const channel = new MessageChannel();

  // Wait for popup to signal ready
  await waitForPopupReady(popup);

  // Transfer port2 to popup
  popup.postMessage(
    {
      type: 'kms:connect',
      transportKey: transport.publicKey,
      keyId: transport.keyId,
      appSalt: transport.appSalt,
      hkdfSalt: transport.hkdfSalt,
      requestId: requestId,
    },
    'https://kms.ats.run',
    [channel.port2]
  );

  // Wait for credentials on port1
  const credentials = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Credential timeout'));
    }, 300000); // 5 minute timeout

    channel.port1.onmessage = (event) => {
      clearTimeout(timeout);

      if (event.data.type === 'kms:setup-credentials') {
        resolve(event.data.payload);
      } else if (event.data.type === 'kms:error') {
        reject(new Error(event.data.payload));
      }
    };
  });

  // Decrypt and process credentials (existing logic)
  // ...
}
```

**Note:** The iframe needs a reference to the popup window. Since parent opened it, we need parent to pass the window reference:

**Updated Step 4:**

```typescript
// In parent's popup request handler:
if (message.type === 'kms:request-popup') {
  const popup = window.open(url, 'kms-setup', 'width=500,height=600');

  if (!popup) {
    kmsIframe.contentWindow?.postMessage({
      type: 'kms:popup-blocked',
      requestId: requestId,
    }, KMS_ORIGIN);
    return;
  }

  // CRITICAL: Cannot pass window reference via postMessage
  // Instead, store reference and allow iframe to request it
  pendingPopups.set(requestId, popup);

  kmsIframe.contentWindow?.postMessage({
    type: 'kms:popup-opened',
    requestId: requestId,
  }, KMS_ORIGIN);
}
```

**Problem:** Cross-origin iframes cannot receive `Window` references from parent via `postMessage`.

### Step 5 (Revised): Use Popup-Initiated Handshake

Instead of iframe needing popup reference, **popup initiates contact** with iframe:

```typescript
// In popup (client.ts, stateless popup mode):
// Popup detects it's in setup mode
if (this.isStatelessPopup) {
  // Popup initiates handshake with iframe (same origin)
  const parentWindows = [window.opener, window.parent];

  for (const parentWin of parentWindows) {
    if (!parentWin || parentWin === window) continue;

    // Send hello to potential iframe parent
    parentWin.postMessage(
      { type: 'kms:popup-ready', state: this.popupState },
      'https://kms.ats.run' // Only talk to same origin
    );
  }
}
```

**In iframe (worker or client):**

```typescript
// Listen for popup-ready from same-origin popup
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://kms.ats.run') return;

  if (event.data.type === 'kms:popup-ready') {
    // Popup is ready, establish MessageChannel
    const channel = new MessageChannel();

    // Send transport params + port
    event.source.postMessage(
      {
        type: 'kms:connect',
        transportKey: ...,
        keyId: ...,
        // ... transport params
      },
      'https://kms.ats.run',
      [channel.port2]
    );
  }
});
```

### Step 6: Update Popup to Only Accept KMS Origin

**File:** `src/v2/client.ts`

Update popup message handler:

```typescript
// In stateless popup mode
if (this.isStatelessPopup) {
  window.addEventListener('message', (event) => {
    // CRITICAL: Only accept messages from KMS iframe (same origin)
    if (event.origin !== 'https://kms.ats.run') {
      console.warn('[KMS Popup] Rejected message from invalid origin:', event.origin);
      return;
    }

    // Process kms:connect with transport params
    if (event.data.type === 'kms:connect') {
      // Extract transport params
      this.transportPublicKey = event.data.transportKey;
      this.transportKeyId = event.data.keyId;
      // ...

      // Extract MessagePort
      const port = event.ports[0];
      if (!port) {
        console.error('[KMS Popup] No MessagePort received');
        return;
      }

      this.messagePort = port;

      // Now popup can collect credentials and send via port
    }
  });
}
```

### Step 7: Update RPC Validation

**File:** `src/v2/rpc-validation.ts`

Add validator for new method:

```typescript
export function validateSetupWithPopup(params: unknown): {
  userId: string;
} {
  const p = validateParamsObject('setupWithPopup', params);

  return {
    userId: validateString('setupWithPopup', 'userId', p.userId),
  };
}
```

### Step 8: Remove Old Code

**Files to update:**

1. **`example/phase-2/parent.ts`:**
   - Remove `generateSetupTransportKey()` call
   - Remove MessageChannel setup logic
   - Remove credential receiving/forwarding
   - Replace with simple popup request handler

2. **`src/v2/kms-user.ts`:**
   - Keep `setupWithEncryptedCredentials()` for backwards compatibility
   - Add `setupWithPopup()` as new recommended method
   - Update docs to recommend new flow

3. **`src/v2/worker.ts`:**
   - Keep `setupWithEncryptedCredentials()` handler
   - Add `handleSetupWithPopup()`

## Migration Strategy

### Phase 1: Implement New Flow (Parallel)
- Add new `setupWithPopup` RPC method
- Implement iframe popup management
- Add parent popup request handler
- Keep old flow working

### Phase 2: Update Example
- Change `example/phase-2/parent.ts` to use new flow
- Test thoroughly

### Phase 3: Deprecate Old Flow
- Mark `setupWithEncryptedCredentials` as deprecated
- Update documentation
- Eventually remove old flow

## Security Analysis

### Threat: Malicious Parent

**Old flow:**
- Parent sees transport params in URL ❌
- Parent receives encrypted credentials ❌
- Parent could MITM MessageChannel ❌

**New flow:**
- Parent only sees `https://kms.ats.run/?mode=setup` ✅
- Parent never sees transport params (sent via postMessage after popup opens) ✅
- Parent never receives credentials ✅
- Parent cannot access iframe-popup MessageChannel (cross-origin isolation) ✅

### Threat: Malicious Popup

**Both flows:**
- Popup could be compromised (phishing, XSS)
- But popup must be on `kms.ats.run` origin for communication to work
- Browser enforces origin checks on postMessage

**New flow advantage:**
- Popup validates all messages from `kms.ats.run` only
- Rejects messages from parent origin
- Direct communication with iframe reduces attack surface

### Threat: Parent Interference

**Old flow:**
- Parent could refuse to forward credentials ❌
- Parent could modify encrypted payload (would fail decryption, but DOS) ❌

**New flow:**
- Parent could refuse to open popup (same as before)
- Parent cannot interfere with credential flow (bypasses parent entirely) ✅

## Testing Plan

1. **Unit tests:**
   - Test popup request handler in parent
   - Test MessageChannel establishment in iframe
   - Test popup message validation

2. **Integration tests:**
   - Test full setup flow with popup
   - Test popup blocked scenario
   - Test timeout scenarios
   - Test origin validation

3. **Manual tests:**
   - Test in dev environment (localhost parent, kms.ats.run iframe/popup)
   - Test popup blocker handling
   - Test network failures
   - Test concurrent setup attempts

## Open Questions

1. **Popup window reference:** How does iframe get reference to popup if parent opened it?
   - **Solution:** Popup initiates handshake with iframe using `event.source`

2. **State management:** How to track multiple concurrent setup attempts?
   - Use `requestId` to correlate popup requests with responses

3. **Popup blocker handling:** What UX when popup is blocked?
   - Parent detects `window.open()` returned `null`
   - Notify iframe via `kms:popup-blocked` message
   - Iframe rejects promise with error
   - Show user message to allow popups

4. **URL parameters:** Should we include anything in popup URL?
   - Minimal: `?mode=setup` only
   - State/nonce can be sent via postMessage after popup ready

## Success Criteria

- [ ] Parent only sees minimal popup URL
- [ ] Parent never sees transport parameters
- [ ] Parent never receives credentials (encrypted or otherwise)
- [ ] Direct MessageChannel between iframe and popup
- [ ] Popup validates messages from `kms.ats.run` only
- [ ] All tests pass
- [ ] Example app works with new flow
- [ ] Documentation updated
