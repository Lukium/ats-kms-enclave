# Phase 1 Demo: Iframe Isolation - Implementation Plan

**Purpose**: Demonstrate cross-origin isolation between parent PWA and KMS enclave running in a sandboxed iframe on separate ports.

**Status**: Ready for implementation (specification complete)

**Target**: `example/phase-1/iframe-isolation/`

---

## Overview

This demo proves the **core security principle** of the KMS architecture: private keys and secrets are completely isolated from the parent PWA through cross-origin boundaries, postMessage-only communication, and defense-in-depth security layers.

### What This Demo Proves

1. **Cross-origin isolation**: Parent PWA cannot access KMS internals (different ports = different origins)
2. **postMessage-only communication**: All interaction is explicit and auditable
3. **Secrets never touch parent**: Passkey/passphrase setup, key generation, signing all happen in iframe
4. **Parent receives only public outputs**: JWT signatures, public keys - never private keys
5. **Iframe handles crypto validation**: Lock/unlock operations validated entirely within KMS
6. **Disk encryption via memory-only KEK**: Even if OS is compromised, keys cannot be unwrapped without user's passphrase/passkey
7. **Tamper-evident audit log**: Compromised KMS cannot hide malicious operations without detection

---

## Architecture

### Dual-Port Setup

**Development:**
- Parent PWA: `http://localhost:5176`
- KMS Iframe: `http://localhost:5177`

**Production (Future):**
- Parent PWA: `https://allthe.services`
- KMS Iframe: `https://kms.ats.run`

### Why Two Separate Servers?

Different ports create **real origin boundaries**:
- Enables true cross-origin isolation testing
- Allows configuring real CSP headers
- Enables cross-origin postMessage validation
- Demonstrates production security boundaries

### Component Architecture

```
Parent PWA (5176)              KMS Iframe (5177)
┌─────────────────┐            ┌──────────────────┐
│   parent.html   │            │    kms.html      │
│   parent.ts     │◄─────────►│    kms.ts        │
│   (UI + sender) │ postMessage│ (receiver+bridge)│
└─────────────────┘            └────────┬─────────┘
                                        │
                                        ↓
                               ┌──────────────────┐
                               │   src/worker.ts  │
                               │  (crypto ops)    │
                               └──────────────────┘
```

---

## Implementation Approach: Incremental Bottom-Up

### Phase 1: Infrastructure & Communication (Verify Cross-Origin Works)

**Goal**: Establish basic cross-origin communication before adding complexity.

**Tasks**:
1. Create minimal `kms.html` that loads Worker
2. Create minimal `parent.html` that embeds iframe
3. Implement basic postMessage bridge (just `getStatus`)
4. Verify cross-origin communication works
5. Add CSP headers via vite configs
6. Test origin validation

**Success Criteria**:
- Parent can send message to iframe on different port
- Iframe responds with status
- CSP headers prevent unauthorized origins
- DevTools shows postMessage events

### Phase 2: Single Operation End-to-End (Prove Pattern Works)

**Goal**: Implement one complete operation to validate the pattern.

**Tasks**:
1. Implement `setupPassphrase` operation
   - Parent: Button → send postMessage
   - KMS: Receive → call Worker → return response
   - Parent: Display result
2. Add error handling
3. Add timeout protection
4. Add origin validation

**Success Criteria**:
- User can setup passphrase from parent UI
- Passphrase never touches parent (stays in iframe)
- Success/error feedback in parent UI
- Operation logged in audit log

### Phase 3: Complete Operation Set (Build Out Features)

**Goal**: Implement all operations from security-flow demo.

**Tasks**:
1. Setup operations: passphrase, passkey PRF, passkey gate
2. Unlock operations: passphrase, passkey PRF, passkey gate
3. Generate VAPID keypair
4. Sign JWT
5. Lock worker
6. Get status

**Success Criteria**:
- All operations work via postMessage
- Parent receives only public outputs
- All secrets stay in iframe
- Audit log tracks all operations

### Phase 4: Visual Design & Security Indicators (Make It Clear)

**Goal**: Visually demonstrate isolation and security properties.

**Tasks**:
1. Add security indicators (origin display, lock status)
2. Add audit log viewer in iframe
3. Add message flow visualization
4. Style parent vs iframe sections distinctly
5. Add tamper warning banners

**Success Criteria**:
- Clear visual separation between parent and iframe
- Security guarantees visible to user
- Audit log shows all operations with chain integrity
- Tamper detection visible in UI

### Phase 5: Testing & Documentation (Verify Claims)

**Goal**: Prove security guarantees with practical tests.

**Tasks**:
1. Implement Test #1: IndexedDB isolation
2. Implement Test #2: Private key non-extractability
3. Implement Test #3: Lock state enforcement
4. Implement Test #4: Parent cannot bypass lock
5. Implement Test #5: Audit log chain integrity
6. Document how to run each test

**Success Criteria**:
- All 5 tests pass
- User can verify isolation in DevTools
- Audit log tamper detection works
- README test instructions are accurate

---

## File Structure & Implementation Details

### Files to Create

```
example/phase-1/iframe-isolation/
├── README.md           ✅ COMPLETE (specification)
├── parent.html         ⏳ TO IMPLEMENT
├── parent.ts           ⏳ TO IMPLEMENT
├── kms.html           ⏳ TO IMPLEMENT
├── kms.ts             ⏳ TO IMPLEMENT
└── styles.css         ⏳ TO IMPLEMENT
```

---

## File-by-File Implementation Guide

### 1. `kms.html` - KMS Iframe Bootstrap

**Purpose**: Entry point for KMS iframe, loads Worker and main thread bridge.

**Requirements**:
- Minimal HTML structure
- Load `kms.ts` as ES module
- NO inline scripts (CSP compliance)
- Display audit log viewer
- Display lock status indicator

**Key Elements**:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KMS Enclave (Isolated)</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div id="kms-container">
    <h2>KMS Enclave (Isolated)</h2>
    <div id="lock-status">🔒 Locked</div>
    <div id="audit-log-viewer">
      <h3>Audit Log</h3>
      <div id="chain-status">✅ Chain verified</div>
      <div id="audit-entries"></div>
    </div>
  </div>
  <script type="module" src="./kms.ts"></script>
</body>
</html>
```

**Security Considerations**:
- CSP: `script-src 'self'` (no inline scripts)
- CSP: `frame-ancestors http://localhost:5176` (only parent can embed)
- No sensitive data in DOM (audit log is metadata only)

---

### 2. `kms.ts` - postMessage Receiver & Worker Bridge

**Purpose**: Receive postMessage from parent, forward to Worker, return responses.

**Core Logic**:

```typescript
// Import Worker (reuse existing implementation)
import type { RPCRequest, RPCResponse } from '../../src/worker';

// Create Worker instance
const worker = new Worker(new URL('../../src/worker.ts', import.meta.url), {
  type: 'module'
});

// Origin validation
const ALLOWED_PARENT_ORIGIN = 'http://localhost:5176';

// Request tracking
const pendingRequests = new Map<string, {
  resolve: (response: RPCResponse) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}>();

// Listen for messages from parent
window.addEventListener('message', async (event) => {
  // Validate origin
  if (event.origin !== ALLOWED_PARENT_ORIGIN) {
    console.warn('[KMS] Rejected message from unauthorized origin:', event.origin);
    return;
  }

  const request: RPCRequest = event.data;

  // Forward to Worker
  const requestId = crypto.randomUUID();
  const workerRequest = { ...request, id: requestId };

  worker.postMessage(workerRequest);

  // Wait for Worker response (with timeout)
  const response = await waitForWorkerResponse(requestId, 10000);

  // Send response back to parent
  window.parent.postMessage(response, ALLOWED_PARENT_ORIGIN);

  // Update UI (lock status, audit log)
  updateUI(response);
});

// Listen for Worker responses
worker.addEventListener('message', (event) => {
  const response: RPCResponse = event.data;

  // Resolve pending request
  const pending = pendingRequests.get(response.id);
  if (pending) {
    clearTimeout(pending.timeout);
    pending.resolve(response);
    pendingRequests.delete(response.id);
  }
});

// Update UI based on responses
function updateUI(response: RPCResponse) {
  // Update lock status
  if (response.data?.locked !== undefined) {
    const status = response.data.locked ? '🔒 Locked' : '🔓 Unlocked';
    document.getElementById('lock-status')!.textContent = status;
  }

  // Refresh audit log
  refreshAuditLog();
}

// Display audit log
async function refreshAuditLog() {
  // Request audit log from Worker
  const response = await sendToWorker({ method: 'getAuditLog' });

  // Display entries with chain verification
  displayAuditEntries(response.data.entries);
}
```

**Key Responsibilities**:
1. Receive postMessage from parent
2. Validate parent origin
3. Forward to Worker
4. Wait for Worker response (with timeout)
5. Send response back to parent
6. Update iframe UI (lock status, audit log)

**Security Considerations**:
- MUST validate `event.origin` on every message
- Timeout protection (10s max per operation)
- Error handling for Worker failures
- Never leak secrets in postMessage responses

---

### 3. `parent.html` - Parent PWA UI

**Purpose**: User-facing interface with controls and output display.

**Requirements**:
- Embed iframe pointing to `http://localhost:5177`
- Setup controls (passphrase, passkey)
- Operation controls (generate VAPID, sign JWT, lock/unlock)
- Output display (JWT, public key, success/error messages)
- Security indicators

**Key Elements**:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Parent PWA (Untrusted)</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div id="parent-container">
    <h1>Parent PWA (Untrusted)</h1>
    <p class="security-warning">❌ Cannot access KMS internals</p>

    <div class="controls">
      <h2>Setup (Choose One)</h2>
      <button id="setup-passphrase">Setup Passphrase</button>
      <button id="setup-passkey">Setup Passkey</button>

      <h2>Operations</h2>
      <button id="generate-vapid" disabled>Generate VAPID</button>
      <button id="sign-jwt" disabled>Sign JWT</button>
      <button id="lock-kms" disabled>Lock KMS</button>
      <button id="unlock-kms" disabled>Unlock KMS</button>
    </div>

    <div class="output">
      <h2>Received from KMS (Public Only)</h2>
      <div id="output-display"></div>
    </div>
  </div>

  <!-- KMS Iframe (cross-origin) -->
  <iframe
    id="kms-iframe"
    src="http://localhost:5177"
    sandbox="allow-scripts allow-same-origin"
    referrerpolicy="no-referrer"
  ></iframe>

  <script type="module" src="./parent.ts"></script>
</body>
</html>
```

**Security Considerations**:
- iframe `sandbox="allow-scripts allow-same-origin"` (safe due to cross-origin)
- CSP: `frame-src http://localhost:5177` (only allow KMS iframe)
- Display received data only (never access iframe internals)

---

### 4. `parent.ts` - postMessage Sender

**Purpose**: Send requests to KMS iframe, receive and display responses.

**Core Logic**:

```typescript
const iframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
const KMS_ORIGIN = 'http://localhost:5177';

// Wait for iframe to load
iframe.addEventListener('load', () => {
  console.log('[Parent] KMS iframe loaded');
  enableControls();
});

// Send request to KMS
async function sendToKMS(method: string, params?: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();

    // Set up response listener
    const responseHandler = (event: MessageEvent) => {
      if (event.origin !== KMS_ORIGIN) return;

      const response = event.data;
      if (response.id === requestId) {
        window.removeEventListener('message', responseHandler);
        clearTimeout(timeout);

        if (response.error) {
          reject(new Error(response.error.message));
        } else {
          resolve(response.data);
        }
      }
    };

    window.addEventListener('message', responseHandler);

    // Timeout after 10s
    const timeout = setTimeout(() => {
      window.removeEventListener('message', responseHandler);
      reject(new Error('Request timeout'));
    }, 10000);

    // Send request
    iframe.contentWindow!.postMessage(
      { id: requestId, method, params },
      KMS_ORIGIN
    );
  });
}

// Button handlers
document.getElementById('setup-passphrase')!.addEventListener('click', async () => {
  const passphrase = prompt('Enter passphrase:');
  if (!passphrase) return;

  try {
    const result = await sendToKMS('setupPassphrase', { passphrase });
    displayOutput('Setup successful', result);
    enableOperations();
  } catch (error) {
    displayError(error);
  }
});

document.getElementById('generate-vapid')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('generateVAPID');
    displayOutput('VAPID keypair generated', result);
  } catch (error) {
    displayError(error);
  }
});

// ... more handlers for other operations
```

**Key Responsibilities**:
1. Send postMessage to iframe
2. Wait for response (with timeout)
3. Display received data
4. Handle errors
5. Update UI state (enable/disable buttons)

**Security Considerations**:
- MUST validate `event.origin` on responses
- Timeout protection
- Never attempt to access iframe internals directly
- Display only public data received from KMS

---

### 5. `styles.css` - Visual Styling

**Purpose**: Clearly show separation between parent and iframe, add security indicators.

**Key Styles**:
- Parent section: Light background, top of page
- Iframe section: Different background, heavy border, clear label
- Security indicators: Always visible, color-coded
- Audit log: Scrollable, chain visualization
- Tamper warning: Red banner, prominent

**Visual Requirements**:
- Clear separation between parent and iframe
- Origin display for both
- Lock status indicator (color-coded)
- Message flow visualization (optional)
- Security boundaries (dashed line or border)

---

## Reusable Code (Already Implemented)

### From `src/worker.ts`
- ✅ `handleMessage()` - RPC request handling
- ✅ `setupPassphrase()`, `unlockWithPassphrase()`
- ✅ `setupPasskeyPRF()`, `unlockWithPasskeyPRF()`
- ✅ `setupPasskeyGate()`, `unlockWithPasskeyGate()`
- ✅ `generateVAPID()` - VAPID keypair generation
- ✅ `signJWT()` - JWT signing with ES256
- ✅ `lockWorker()` - Clear KEK from memory
- ✅ All audit logging

### From `src/client.ts`
- ✅ WebAuthn passkey setup/unlock flows
- ✅ Browser API integration

### From `src/audit.ts`
- ✅ ES256-signed audit log
- ✅ Hash-chained entries
- ✅ `verifyAuditChain()` - Chain integrity verification
- ✅ `getAuditLog()` - Retrieve entries

### Key Difference: No Direct Worker Access

**Security-flow demo**:
```typescript
// Direct Worker access
const worker = new Worker('./worker.ts');
worker.postMessage(request);
```

**Iframe-isolation demo**:
```typescript
// Parent → iframe → Worker (via postMessage)
iframe.contentWindow.postMessage(request, KMS_ORIGIN);
```

---

## Communication Protocol

**Request Format (Parent → KMS)**:
```typescript
interface Request {
  id: string;          // Request UUID
  method: string;      // Operation name
  params?: any;        // Operation parameters
}
```

**Response Format (KMS → Parent)**:
```typescript
interface Response {
  id: string;          // Matching request ID
  data?: any;          // Operation result
  error?: {            // Or error
    code: string;
    message: string;
  };
}
```

**Supported Methods**:
- `setupPassphrase` - Setup passphrase unlock
- `unlockWithPassphrase` - Unlock with passphrase
- `setupPasskeyPRF` - Setup passkey with PRF
- `unlockWithPasskeyPRF` - Unlock with passkey PRF
- `setupPasskeyGate` - Setup passkey (gate mode)
- `unlockWithPasskeyGate` - Unlock with passkey (gate mode)
- `generateVAPID` - Generate VAPID keypair
- `signJWT` - Sign JWT with VAPID key
- `lockWorker` - Lock worker (clear KEK)
- `getStatus` - Get lock status
- `getAuditLog` - Get audit log entries

---

## CSP Configuration

### Parent PWA (vite.config.phase-1-iframe-isolation-parent.ts)

Already implemented:
```typescript
headers: {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "frame-src http://localhost:5177",  // Only allow KMS iframe
    "connect-src 'self'",
    "style-src 'self' 'unsafe-inline'"  // TODO: Remove unsafe-inline
  ].join('; ')
}
```

### KMS Iframe (vite.config.phase-1-iframe-isolation-kms.ts)

Already implemented:
```typescript
headers: {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "frame-ancestors http://localhost:5176",  // Only parent can embed
    "connect-src 'self'",                     // Zero network access
    "worker-src 'self'",
    "style-src 'self' 'unsafe-inline'"        // TODO: Remove unsafe-inline
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'ALLOW-FROM http://localhost:5176'
}
```

---

## Testing Strategy

### Test #1: IndexedDB Isolation
**What**: Verify parent cannot access KMS IndexedDB
**How**:
1. Open parent DevTools
2. Application → IndexedDB
3. Verify KMS database not visible
4. Open iframe DevTools (right-click iframe → Inspect)
5. Application → IndexedDB
6. Verify KMS database IS visible in iframe context

**Proves**: Cross-origin isolation works at storage level

### Test #2: Private Key Non-Extractability
**What**: Verify keys cannot be exported even in iframe
**How**:
1. Generate VAPID keypair
2. Open iframe DevTools console
3. Try: `crypto.subtle.exportKey('pkcs8', privateKey)`
4. Verify: "Operation not supported" error

**Proves**: WebCrypto non-extractable keys are enforced by browser

### Test #3: Lock State Enforcement
**What**: Verify worker refuses operations when locked
**How**:
1. Generate VAPID keypair (while unlocked)
2. Lock KMS
3. Try to sign JWT
4. Verify: Error "Worker is locked"
5. Unlock with passphrase/passkey
6. Sign JWT again
7. Verify: Signing works

**Proves**: Lock state is enforced by KMS, not parent

### Test #4: Parent Cannot Bypass Lock
**What**: Verify parent cannot override lock state
**How**:
1. Lock KMS from parent UI
2. Modify parent.ts to send signJWT without checking lock state
3. Send message directly via console: `iframe.contentWindow.postMessage({method: 'signJWT', ...}, KMS_ORIGIN)`
4. Verify: Worker refuses operation

**Proves**: KMS enforces lock internally, parent is untrusted

### Test #5: Audit Log Chain Integrity
**What**: Verify tampering is detected
**How**:
1. Perform operations (setup, generate, sign, lock, unlock)
2. View audit log in iframe UI
3. Verify chain: each entry's prevHash matches previous entry's hash
4. Verify signatures: each entry has valid ES256 signature
5. Open iframe DevTools → Application → IndexedDB → audit table
6. Manually modify an entry (e.g., change timestamp)
7. Perform new operation (e.g., sign JWT)
8. Verify: Signature verification fails
9. Check iframe UI: "⚠️ Audit log tamper detected"

**Proves**: Cannot modify audit log without detection

---

## Success Criteria

The demo is complete when:

1. ✅ Parent and KMS run on separate ports (5176, 5177)
2. ✅ Parent can communicate with KMS via postMessage only
3. ✅ All operations work (setup, unlock, generate, sign, lock)
4. ✅ Parent receives only public outputs (JWT, public key)
5. ✅ Secrets never touch parent (passphrase, PRF, KEK, private keys)
6. ✅ Lock/unlock state is enforced by KMS
7. ✅ Audit log viewer shows all operations with chain integrity
8. ✅ All 5 security tests pass
9. ✅ Visual design clearly shows parent/iframe separation
10. ✅ CSP headers are configured correctly

---

## Implementation Checklist

### Phase 1: Infrastructure ⏳
- [ ] Create `kms.html` (minimal structure)
- [ ] Create `parent.html` (iframe embed + minimal UI)
- [ ] Create `kms.ts` (basic postMessage receiver)
- [ ] Create `parent.ts` (basic postMessage sender)
- [ ] Implement `getStatus` operation (test communication)
- [ ] Verify cross-origin communication works
- [ ] Test CSP headers prevent unauthorized origins

### Phase 2: Single Operation ⏳
- [ ] Implement `setupPassphrase` in parent.ts
- [ ] Implement request forwarding in kms.ts
- [ ] Add error handling and timeout protection
- [ ] Add origin validation
- [ ] Display result in parent UI
- [ ] Verify passphrase stays in iframe (not in parent)

### Phase 3: Complete Operations ⏳
- [ ] Implement all setup operations
- [ ] Implement all unlock operations
- [ ] Implement `generateVAPID`
- [ ] Implement `signJWT`
- [ ] Implement `lockWorker`
- [ ] Test all operations end-to-end

### Phase 4: Visual Design ⏳
- [ ] Create `styles.css` with parent/iframe separation
- [ ] Add origin display for both parent and iframe
- [ ] Add lock status indicator (color-coded)
- [ ] Implement audit log viewer in iframe
- [ ] Add chain integrity indicator
- [ ] Add tamper warning banner
- [ ] Style security indicators

### Phase 5: Testing ⏳
- [ ] Document Test #1: IndexedDB isolation
- [ ] Document Test #2: Private key non-extractability
- [ ] Document Test #3: Lock state enforcement
- [ ] Document Test #4: Parent cannot bypass lock
- [ ] Document Test #5: Audit log chain integrity
- [ ] Verify all tests pass
- [ ] Update README with test results

---

## Next Steps

**Start with Phase 1**: Establish basic cross-origin communication before adding complexity. The simplest path forward is:

1. Create minimal HTML files (kms.html, parent.html)
2. Create minimal TypeScript files (kms.ts, parent.ts)
3. Implement one simple operation (getStatus)
4. Verify postMessage communication works across origins
5. Then incrementally add remaining operations

**Estimated Timeline**:
- Phase 1 (Infrastructure): 2-3 hours
- Phase 2 (Single Operation): 1-2 hours
- Phase 3 (Complete Operations): 3-4 hours
- Phase 4 (Visual Design): 2-3 hours
- Phase 5 (Testing): 1-2 hours
- **Total**: ~10-14 hours

---

## References

- Specification: `/example/phase-1/iframe-isolation/README.md`
- Architecture docs: `/docs/architecture/crypto/`
- Existing implementation: `/example/phase-1/security-flow/`
- Worker code: `/src/worker.ts`
- Audit log: `/src/audit.ts`
- Client code: `/src/client.ts`
