# Phase 1: iframe User Authentication Implementation Plan

**Date**: 2025-10-29
**Status**: Planning
**Goal**: Move credential collection from parent PWA into KMS iframe modal

---

## Table of Contents

- [Overview](#overview)
- [Current Architecture Problems](#current-architecture-problems)
- [Target Architecture](#target-architecture)
- [Implementation Steps](#implementation-steps)
- [Testing Plan](#testing-plan)
- [Rollout Strategy](#rollout-strategy)

---

## Overview

This plan implements modal-based authentication within the KMS iframe, eliminating the need for the parent PWA to handle sensitive credentials. This aligns with our security architecture where all authentication material stays within the KMS boundary.

**Key Benefits**:
- ✅ WebAuthn credentials bound to correct origin (`localhost:5174` / `kms.ats.run`)
- ✅ Credentials never traverse parent-iframe boundary
- ✅ Cleaner separation of concerns
- ✅ Better UX with integrated modal
- ✅ Compliant with WebAuthn cross-origin iframe requirements

**Reference Documentation**:
- [Design Doc: WebAuthn in Cross-Origin iframes](../../architecture/crypto/V2/design/14-iframe-user-authentication.md)

---

## Current Architecture Problems

### Current Flow (Parent Collects Credentials)

```
┌─────────────────────────────────────────────────────────────┐
│ parent.ts (localhost:5173)                                  │
│  • prompt('Enter passphrase')          ❌ Parent has access │
│  • navigator.credentials.get()         ❌ Wrong RP binding  │
│  • Sends credentials via postMessage   ❌ Data exposure     │
└────────────────┬────────────────────────────────────────────┘
                 │ postMessage({ credentials })
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ client.ts (localhost:5174)                                  │
│  • Receives credentials                                     │
│  • Forwards to worker                                       │
└────────────────┬────────────────────────────────────────────┘
                 │ postMessage({ credentials })
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ worker.ts (Dedicated Worker)                                │
│  • Performs unlock with credentials                         │
│  • Returns success/failure                                  │
└─────────────────────────────────────────────────────────────┘
```

**Problems**:
1. ❌ **Wrong RP binding**: WebAuthn credentials created in parent context bind to `localhost:5173`, but we want `localhost:5174` (KMS origin)
2. ❌ **Security boundary violation**: Parent has temporary access to authentication credentials
3. ❌ **Unnecessary data flow**: Credentials cross parent→iframe boundary unnecessarily
4. ❌ **Complexity**: Parent must orchestrate WebAuthn ceremonies

---

## Target Architecture

### New Flow (Modal in iframe)

```
┌─────────────────────────────────────────────────────────────┐
│ parent.ts (localhost:5173)                                  │
│  • User clicks "Unlock"                                     │
│  • Sends: { method: 'triggerUnlockUI', userId }             │
│  • No credential handling                                   │
└────────────────┬────────────────────────────────────────────┘
                 │ postMessage({ method: 'triggerUnlockUI' })
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ client.ts (localhost:5174) - MAIN THREAD (has DOM access)   │
│                                                             │
│  1. Shows modal in iframe:                                  │
│     ┌──────────────────────────────────┐                    │
│     │  Unlock KMS                      │                    │
│     │                                  │                    │
│     │  [ Use Face ID / Touch ID]       │  ← WebAuthn here   │
│     │                                  │                    │
│     │  ──────── OR ────────            │                    │
│     │                                  │                    │
│     │  Password: [______________]      │                    │
│     │  [ Unlock with Passphrase]       │                    │
│     └──────────────────────────────────┘                    │
│                                                             │
│  2. User interacts with modal (clicks button)               │
│  3. Navigator.credentials.get() called HERE                 │
│     (bound to localhost:5174 - correct RP)                  │
│  4. Sends credentials to worker                             │
│  5. Hides modal on success/failure                          │
└────────────────┬────────────────────────────────────────────┘
                 │ postMessage({ method: 'unlock', credentials })
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ worker.ts (Dedicated Worker)                                │
│  • Receives credentials from client.ts (not parent!)        │
│  • Performs unlock                                          │
│  • Returns success → client hides modal → notifies parent   │
└─────────────────────────────────────────────────────────────┘
```

**Improvements**:
1. ✅ **Correct RP binding**: WebAuthn bound to `kms.ats.run` (iframe origin)
2. ✅ **Security**: Credentials never leave KMS iframe boundary
3. ✅ **Simpler parent**: Parent just triggers UI, doesn't handle auth
4. ✅ **Better UX**: Modal appears contextually in iframe
5. ✅ **Testable**: Can test WebAuthn in iframe independently

---

## Implementation Steps

### Step 1: Add Permission Policy to iframe Element

**File**: `example/phase-1/full/index.html`

**Before**:
```html
<iframe
  id="kms-iframe"
  src="http://localhost:5174?parentOrigin=http://localhost:5173"
  sandbox="allow-scripts allow-same-origin"
  style="display: none;"
></iframe>
```

**After**:
```html
<iframe
  id="kms-iframe"
  src="http://localhost:5174?parentOrigin=http://localhost:5173"
  allow="publickey-credentials-get"
  sandbox="allow-scripts allow-same-origin"
  style="display: none;"
></iframe>
```

**Why**: Grants iframe permission to use WebAuthn `credentials.get()` API for authentication.

**Note**: We do NOT need `publickey-credentials-create` because enrollment happens in first-party context (direct navigation to kms.html).

---

### Step 2: Add Modal HTML to kms.html

**File**: `example/phase-1/full/kms.html`

**Add before closing `</body>`**:
```html
<!-- Unlock Modal (hidden by default) -->
<div id="unlock-modal" class="kms-modal" style="display: none;">
  <div class="kms-modal-backdrop"></div>
  <div class="kms-modal-content">
    <div class="kms-modal-header">
      <h3>🔐 Unlock KMS</h3>
      <p class="kms-modal-subtitle">Choose your unlock method</p>
    </div>

    <div class="kms-modal-body">
      <!-- WebAuthn Option -->
      <div class="kms-auth-option">
        <button id="kms-webauthn-btn" class="kms-auth-btn kms-primary">
          <span class="kms-auth-icon">🔑</span>
          <span class="kms-auth-label">Use Face ID / Touch ID</span>
        </button>
        <p class="kms-auth-hint">Authenticate with your device biometrics</p>
      </div>

      <!-- Divider -->
      <div class="kms-divider">
        <span>or</span>
      </div>

      <!-- Passphrase Option -->
      <div class="kms-auth-option">
        <label for="kms-passphrase-input" class="kms-input-label">Passphrase</label>
        <input
          type="password"
          id="kms-passphrase-input"
          class="kms-input"
          placeholder="Enter your passphrase"
          autocomplete="off"
        />
        <button id="kms-passphrase-btn" class="kms-auth-btn kms-secondary">
          <span class="kms-auth-icon">🔐</span>
          <span class="kms-auth-label">Unlock with Passphrase</span>
        </button>
      </div>

      <!-- Error Display -->
      <div id="kms-modal-error" class="kms-modal-error" style="display: none;"></div>

      <!-- Loading State -->
      <div id="kms-modal-loading" class="kms-modal-loading" style="display: none;">
        <span class="kms-spinner"></span>
        <span>Unlocking...</span>
      </div>
    </div>
  </div>
</div>
```

---

### Step 3: Add Modal CSS Styles

**File**: `example/phase-1/full/kms.html` (add to `<style>` section)

```css
/* ============================================
   KMS Modal Styles
   ============================================ */

.kms-modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: kms-modal-fade-in 0.2s ease-out;
}

@keyframes kms-modal-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

.kms-modal-backdrop {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.75);
  backdrop-filter: blur(4px);
}

.kms-modal-content {
  position: relative;
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  border: 1px solid #333;
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  width: 90%;
  max-width: 450px;
  padding: 0;
  animation: kms-modal-slide-up 0.3s ease-out;
}

@keyframes kms-modal-slide-up {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.kms-modal-header {
  padding: 2rem 2rem 1rem 2rem;
  border-bottom: 1px solid #333;
}

.kms-modal-header h3 {
  margin: 0 0 0.5rem 0;
  font-size: 1.5rem;
  color: #fff;
  font-weight: 600;
}

.kms-modal-subtitle {
  margin: 0;
  font-size: 0.875rem;
  color: #888;
}

.kms-modal-body {
  padding: 2rem;
}

.kms-auth-option {
  margin-bottom: 1.5rem;
}

.kms-auth-btn {
  width: 100%;
  padding: 1rem;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  transition: all 0.2s ease;
  font-family: inherit;
}

.kms-auth-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.kms-auth-btn:active {
  transform: translateY(0);
}

.kms-auth-btn.kms-primary {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: #fff;
}

.kms-auth-btn.kms-primary:hover {
  background: linear-gradient(135deg, #7a8ff0 0%, #8a5bb2 100%);
}

.kms-auth-btn.kms-secondary {
  background: #2d3748;
  color: #fff;
  border: 1px solid #4a5568;
}

.kms-auth-btn.kms-secondary:hover {
  background: #3d4758;
  border-color: #5a6578;
}

.kms-auth-icon {
  font-size: 1.25rem;
}

.kms-auth-label {
  font-size: 1rem;
}

.kms-auth-hint {
  margin: 0.5rem 0 0 0;
  font-size: 0.8rem;
  color: #888;
  text-align: center;
}

.kms-divider {
  display: flex;
  align-items: center;
  text-align: center;
  margin: 1.5rem 0;
  color: #666;
  font-size: 0.875rem;
}

.kms-divider::before,
.kms-divider::after {
  content: '';
  flex: 1;
  border-bottom: 1px solid #333;
}

.kms-divider span {
  padding: 0 1rem;
}

.kms-input-label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  color: #ccc;
  font-weight: 500;
}

.kms-input {
  width: 100%;
  padding: 0.75rem;
  background: #1a1a2e;
  border: 1px solid #333;
  border-radius: 6px;
  color: #fff;
  font-size: 1rem;
  font-family: inherit;
  margin-bottom: 1rem;
  box-sizing: border-box;
}

.kms-input:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.kms-input::placeholder {
  color: #666;
}

.kms-modal-error {
  padding: 1rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  color: #f87171;
  font-size: 0.875rem;
  margin-top: 1rem;
}

.kms-modal-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 1rem;
  background: rgba(102, 126, 234, 0.1);
  border: 1px solid rgba(102, 126, 234, 0.3);
  border-radius: 6px;
  color: #a5b4fc;
  font-size: 0.875rem;
  margin-top: 1rem;
}

.kms-spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(165, 180, 252, 0.3);
  border-top-color: #a5b4fc;
  border-radius: 50%;
  animation: kms-spin 0.8s linear infinite;
}

@keyframes kms-spin {
  to { transform: rotate(360deg); }
}
```

---

### Step 4: Implement Modal Handling in client.ts

**File**: `src/v2/client.ts`

**Add these interfaces near the top**:
```typescript
/**
 * Pending unlock request (waiting for user interaction)
 */
interface PendingUnlockRequest {
  request: RPCRequest;
  resolve: (result: any) => void;
  reject: (error: Error) => void;
}
```

**Add to KMSClient class**:
```typescript
export class KMSClient {
  private worker: Worker | null = null;
  private parentOrigin: string;
  private workerUrl: string;
  private isInitialized = false;
  private pendingUnlock: PendingUnlockRequest | null = null; // NEW

  // ... existing constructor and init() ...

  /**
   * Handle messages from parent window
   */
  private handleParentMessage(event: MessageEvent): void {
    // Validate origin
    if (event.origin !== this.parentOrigin) {
      console.warn('[KMS Client] Rejected message from invalid origin:', {
        expected: this.parentOrigin,
        received: event.origin,
      });
      return;
    }

    if (!this.isInitialized || !this.worker) {
      console.error('[KMS Client] Received message before initialization');
      return;
    }

    const request = event.data as RPCRequest;

    // NEW: Intercept unlock UI triggers
    if (request.method === 'triggerUnlockUI') {
      this.showUnlockModal(request);
      return; // Don't forward to worker yet
    }

    // Existing: Forward other messages to Worker
    try {
      this.worker.postMessage(event.data);
    } catch (err: any) {
      console.error('[KMS Client] Failed to forward message to Worker:', err);

      if (request?.id) {
        this.sendToParent({
          id: request.id,
          error: `Failed to forward message: ${err.message}`,
        });
      }
    }
  }

  /**
   * Show unlock modal and handle user authentication
   */
  private showUnlockModal(request: RPCRequest): void {
    const modal = document.getElementById('unlock-modal');
    const webauthnBtn = document.getElementById('kms-webauthn-btn');
    const passphraseBtn = document.getElementById('kms-passphrase-btn');
    const passphraseInput = document.getElementById('kms-passphrase-input') as HTMLInputElement;
    const errorEl = document.getElementById('kms-modal-error');
    const loadingEl = document.getElementById('kms-modal-loading');

    if (!modal || !webauthnBtn || !passphraseBtn || !passphraseInput) {
      console.error('[KMS Client] Modal elements not found');
      this.sendToParent({
        id: request.id,
        error: 'Modal UI not available',
      });
      return;
    }

    // Clear previous state
    passphraseInput.value = '';
    if (errorEl) errorEl.style.display = 'none';
    if (loadingEl) loadingEl.style.display = 'none';

    // Show modal
    modal.style.display = 'flex';

    // Handle WebAuthn authentication
    webauthnBtn.onclick = async () => {
      this.handleWebAuthnUnlock(request, modal, errorEl, loadingEl);
    };

    // Handle passphrase authentication
    passphraseBtn.onclick = async () => {
      const passphrase = passphraseInput.value.trim();
      if (!passphrase) {
        this.showError(errorEl, 'Please enter a passphrase');
        return;
      }
      this.handlePassphraseUnlock(request, passphrase, modal, errorEl, loadingEl);
    };

    // Handle Enter key in passphrase input
    passphraseInput.onkeydown = (e) => {
      if (e.key === 'Enter') {
        passphraseBtn.click();
      }
    };

    // Close modal on backdrop click
    const backdrop = modal.querySelector('.kms-modal-backdrop');
    if (backdrop) {
      backdrop.addEventListener('click', () => {
        this.hideModal(modal);
        this.sendToParent({
          id: request.id,
          error: 'User cancelled unlock',
        });
      });
    }
  }

  /**
   * Handle WebAuthn-based unlock
   */
  private async handleWebAuthnUnlock(
    request: RPCRequest,
    modal: HTMLElement,
    errorEl: HTMLElement | null,
    loadingEl: HTMLElement | null
  ): Promise<void> {
    try {
      this.showLoading(loadingEl);
      if (errorEl) errorEl.style.display = 'none';

      // Get stored appSalt (should be in localStorage from enrollment)
      const appSaltStr = localStorage.getItem('kms:appSalt');
      if (!appSaltStr) {
        throw new Error('No WebAuthn enrollment found. Please setup WebAuthn first.');
      }

      const appSalt = new Uint8Array(appSaltStr.split(',').map(n => parseInt(n, 10)));

      console.log('[KMS Client] Calling navigator.credentials.get() in iframe context');

      // Call WebAuthn - this runs in iframe context, bound to localhost:5174
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: 'localhost', // Will be 'kms.ats.run' in production
          userVerification: 'required',
          timeout: 60000,
          extensions: {
            prf: {
              eval: {
                first: appSalt,
              },
            },
          },
        },
      }) as PublicKeyCredential;

      console.log('[KMS Client] WebAuthn authentication successful');

      // Check if PRF extension succeeded
      const prfExt = (credential as any).getClientExtensionResults().prf;
      const prfOutput = prfExt?.results?.first;

      // Build unlock request with credentials
      const unlockRequest: RPCRequest = {
        ...request,
        method: 'unlock',
        params: {
          ...request.params,
          credentials: prfOutput
            ? { method: 'passkey-prf', prfOutput }
            : { method: 'passkey-gate' },
        },
      };

      // Forward to worker
      this.worker!.postMessage(unlockRequest);

      // Wait for worker response (set up one-time listener)
      this.setupUnlockResponseListener(request.id, modal, errorEl, loadingEl);
    } catch (err: any) {
      console.error('[KMS Client] WebAuthn unlock failed:', err);
      this.hideLoading(loadingEl);
      this.showError(errorEl, `WebAuthn failed: ${err.message || 'Unknown error'}`);
    }
  }

  /**
   * Handle passphrase-based unlock
   */
  private async handlePassphraseUnlock(
    request: RPCRequest,
    passphrase: string,
    modal: HTMLElement,
    errorEl: HTMLElement | null,
    loadingEl: HTMLElement | null
  ): Promise<void> {
    try {
      this.showLoading(loadingEl);
      if (errorEl) errorEl.style.display = 'none';

      // Build unlock request with passphrase credentials
      const unlockRequest: RPCRequest = {
        ...request,
        method: 'unlock',
        params: {
          ...request.params,
          credentials: { method: 'passphrase', passphrase },
        },
      };

      // Forward to worker
      this.worker!.postMessage(unlockRequest);

      // Wait for worker response
      this.setupUnlockResponseListener(request.id, modal, errorEl, loadingEl);
    } catch (err: any) {
      console.error('[KMS Client] Passphrase unlock failed:', err);
      this.hideLoading(loadingEl);
      this.showError(errorEl, `Unlock failed: ${err.message || 'Unknown error'}`);
    }
  }

  /**
   * Setup one-time listener for unlock response from worker
   */
  private setupUnlockResponseListener(
    requestId: string,
    modal: HTMLElement,
    errorEl: HTMLElement | null,
    loadingEl: HTMLElement | null
  ): void {
    const handler = (event: MessageEvent) => {
      const response = event.data as RPCResponse;

      // Check if this is the response we're waiting for
      if (response.id === requestId) {
        this.worker!.removeEventListener('message', handler);

        this.hideLoading(loadingEl);

        if (response.error) {
          // Show error in modal
          this.showError(errorEl, `Unlock failed: ${response.error}`);
        } else {
          // Success - hide modal and forward response to parent
          this.hideModal(modal);
          this.sendToParent(response);
        }
      }
    };

    this.worker!.addEventListener('message', handler);
  }

  /**
   * Show error message in modal
   */
  private showError(errorEl: HTMLElement | null, message: string): void {
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }
  }

  /**
   * Show loading indicator
   */
  private showLoading(loadingEl: HTMLElement | null): void {
    if (loadingEl) {
      loadingEl.style.display = 'flex';
    }
  }

  /**
   * Hide loading indicator
   */
  private hideLoading(loadingEl: HTMLElement | null): void {
    if (loadingEl) {
      loadingEl.style.display = 'none';
    }
  }

  /**
   * Hide modal
   */
  private hideModal(modal: HTMLElement): void {
    modal.style.display = 'none';
  }

  // ... rest of existing methods ...
}
```

---

### Step 5: Update parent.ts to Trigger UI

**File**: `example/phase-1/full/parent.ts`

**Replace `getPreferredCredentials()` function** (around line 656):

**Before**:
```typescript
async function getPreferredCredentials(status: { methods: string[] }): Promise<any> {
  const hasPasskey = status.methods.includes('passkey');
  const hasPassphrase = status.methods.includes('passphrase');
  const userId = 'demouser@ats.run';

  // Prefer passkey if available
  if (hasPasskey) {
    const appSalt = localStorage.getItem('kms:appSalt');

    try {
      const assertion = await navigator.credentials.get({
        // ... WebAuthn code in parent ...
      });
      // ... return credentials ...
    } catch (error) {
      // ...
    }
  } else if (hasPassphrase) {
    const passphrase = prompt('Enter your passphrase:');
    if (!passphrase) {
      throw new Error('Passphrase required');
    }
    return { method: 'passphrase', passphrase, userId };
  } else {
    throw new Error('No enrolled authentication methods available');
  }
}
```

**After**:
```typescript
/**
 * Trigger unlock UI in iframe and wait for result
 *
 * This replaces the old credential collection logic. Now we just
 * tell the iframe to show its modal and let it handle authentication.
 */
async function triggerUnlockUI(userId: string): Promise<void> {
  console.log('[Full Demo] Triggering unlock UI in iframe...');

  // Send request to show unlock modal in iframe
  const result = await kmsUser.sendRequest('triggerUnlockUI', { userId });

  console.log('[Full Demo] Unlock completed:', result);

  // Result will contain success/failure from worker
  if (!result.success) {
    throw new Error(result.error || 'Unlock failed');
  }
}
```

**Update `createLease()` function** (around line 752):

**Before**:
```typescript
async function createLease(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  try {
    console.log('[Full Demo] Creating VAPID lease...');

    // Get credentials (prefer passkey)
    const credentials = await getPreferredCredentials(status);

    // For demo, use simple subscription parameters
    const userId = 'demouser@ats.run';
    // ...

    const result = await kmsUser.createLease({
      userId,
      subs,
      ttlHours,
      credentials, // ← Remove this
    });
    // ...
  } catch (error) {
    // ...
  }
}
```

**After**:
```typescript
async function createLease(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  try {
    console.log('[Full Demo] Creating VAPID lease...');

    const userId = 'demouser@ats.run';

    // Trigger unlock UI in iframe (replaces credential collection)
    await triggerUnlockUI(userId);

    // For demo, use simple subscription parameters
    const subs = [
      {
        url: 'https://demo-push-endpoint.example.com/subscription-1',
        aud: 'https://demo-push-endpoint.example.com',
        eid: 'sub-001',
      },
    ];
    const ttlHours = 24;

    console.log('[Full Demo] Calling createLease with:', { userId, subs, ttlHours });
    const result = await kmsUser.createLease({
      userId,
      subs,
      ttlHours,
      // No credentials parameter - unlock already happened via modal
    });
    console.log('[Full Demo] Lease created:', result);

    // ... rest of success handling ...
  } catch (error) {
    console.error('[Full Demo] Lease creation failed:', error);
    alert(`Lease creation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}
```

**Similar updates needed for**:
- `addEnrollmentPassphrase()` - Line ~568
- `addEnrollmentWebAuthn()` - Line ~1017
- `regenerateVAPIDKey()` - Line ~249

**Pattern for all**:
```typescript
// OLD:
const credentials = await getPreferredCredentials(status);
await kmsUser.someOperation({ ...params, credentials });

// NEW:
await triggerUnlockUI('demouser@ats.run');
await kmsUser.someOperation({ ...params }); // No credentials needed
```

---

### Step 6: Update Worker to Handle Unlock Without Explicit Credentials

**File**: `src/v2/worker.ts`

The worker already has unlock context management. We just need to ensure that operations check for an active unlock context instead of requiring credentials in every request.

**Verify these patterns exist**:

```typescript
// In worker.ts - unlock creates context
async function handleUnlock(params: any): Promise<any> {
  const { userId, credentials } = params;

  // Verify credentials and unlock
  // ...

  // Create unlock context (stored in memory)
  const unlockContext = createUnlockContext(masterSecret, userId);

  // Store in active contexts
  activeUnlockContexts.set(userId, unlockContext);

  return { success: true, expiresAt: unlockContext.expiresAt };
}

// In worker.ts - operations check context
async function handleCreateLease(params: any): Promise<any> {
  const { userId } = params;

  // Check for active unlock context
  const unlockContext = activeUnlockContexts.get(userId);
  if (!unlockContext || unlockContext.expiresAt < Date.now()) {
    throw new Error('KMS locked - unlock required');
  }

  // Proceed with operation using unlockContext.masterSecret
  // ...
}
```

This pattern should already exist from the unlock context design. If not, we need to implement it.

---

## Testing Plan

### Phase 1: Local Development Testing

**Test Matrix**:

| Test Case | Browser | Expected Result |
|-----------|---------|-----------------|
| WebAuthn unlock with PRF | Chrome 84+ | ✅ Modal shows, Face ID works, credentials bound to :5174 |
| WebAuthn unlock without PRF | Chrome 84+ | ✅ Modal shows, fallback to Gate works |
| Passphrase unlock | All browsers | ✅ Modal shows, passphrase works |
| Cancel modal | All browsers | ✅ Modal closes, operation cancelled |
| Wrong passphrase | All browsers | ✅ Error shown in modal, stays open |
| WebAuthn cancelled | All browsers | ✅ Error shown in modal, stays open |
| Multiple operations | All browsers | ✅ Modal reappears for each operation |
| Unlock timeout | All browsers | ✅ Error after timeout, requires re-unlock |

### Phase 2: Cross-Browser Testing

- [ ] Chrome 84+ (Windows, macOS)
- [ ] Firefox 118+ (Windows, macOS)
- [ ] Safari 15.5+ (macOS)
- [ ] Edge 84+ (Windows)

### Phase 3: Permission Policy Verification

**Chrome DevTools Check**:
1. Open DevTools (F12)
2. Application tab
3. Frames → `http://localhost:5174`
4. Permissions Policy section
5. Verify: `publickey-credentials-get` in "Allowed Features"

### Phase 4: Origin Binding Verification

**Test that credentials are bound to iframe origin**:
```javascript
// In parent context (localhost:5173)
navigator.credentials.get({...}) // Should show credentials for :5173 (none)

// In iframe context (localhost:5174)
navigator.credentials.get({...}) // Should show credentials for :5174 (our passkey)
```

### Phase 5: Security Testing

- [ ] Verify credentials never appear in parent console logs
- [ ] Verify credentials never in parent memory (heap snapshot)
- [ ] Verify modal only responds to iframe origin messages
- [ ] Verify backdrop prevents accidental parent interaction

---

## Rollout Strategy

### Stage 1: Development (localhost)
- ✅ Implement all changes above
- ✅ Test with both PRF and Gate WebAuthn
- ✅ Test passphrase flow
- ✅ Verify permission policies work

### Stage 2: Staging (*.ats.run domains)
- Update iframe src to `https://kms-staging.ats.run`
- Update parent origin to `https://staging.allthe.services`
- Update rpId to `kms-staging.ats.run`
- Test with production-like origins
- Verify CORS policies
- Verify TLS/HTTPS requirements

### Stage 3: Production
- Update iframe src to `https://kms.ats.run`
- Update parent origin to `https://allthe.services`
- Update rpId to `kms.ats.run`
- Monitor error rates
- Gradual rollout with feature flag
- Rollback plan: Keep old flow as fallback

---

## Success Criteria

### Must Have (MVP)
- ✅ WebAuthn unlock works in iframe with correct RP binding
- ✅ Passphrase unlock works in iframe
- ✅ Modal UI is intuitive and responsive
- ✅ No credentials traverse parent-iframe boundary
- ✅ Works in Chrome, Firefox, Safari (latest versions)

### Should Have (Post-MVP)
- ⏳ Remember device (skip modal for N hours)
- ⏳ Biometric icon shows platform-specific icon (👆 Touch ID, 😀 Face ID, etc.)
- ⏳ Keyboard navigation (Tab, Enter, Escape)
- ⏳ Accessibility (ARIA labels, screen reader support)
- ⏳ Loading states during WebAuthn ceremony
- ⏳ Retry logic for failed authentications

### Nice to Have (Future)
- ⏳ Multiple passkey support (choose which credential)
- ⏳ Passkey management UI (list, remove credentials)
- ⏳ Password strength meter for passphrase
- ⏳ "Forgot passphrase" recovery flow
- ⏳ Session management UI (active unlocks, expire all)

---

## Rollback Plan

If modal implementation fails:

1. **Quick rollback**: Revert to parent-side credential collection
   - Keep old `getPreferredCredentials()` function
   - Remove `triggerUnlockUI` calls
   - Re-add `credentials` parameter to operations
   - Deploy within 5 minutes

2. **Partial rollback**: Feature flag for modal vs old flow
   ```typescript
   const USE_IFRAME_MODAL = localStorage.getItem('kms:useModal') === 'true';
   if (USE_IFRAME_MODAL) {
     await triggerUnlockUI(userId);
   } else {
     const credentials = await getPreferredCredentials(status);
     // ... old flow
   }
   ```

3. **Gradual migration**:
   - 10% users on modal (random)
   - 50% users on modal (if no issues after 24h)
   - 100% users on modal (if no issues after 7 days)

---

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Step 1: Permission Policy | 5 minutes | None |
| Step 2: Modal HTML | 15 minutes | Step 1 |
| Step 3: Modal CSS | 20 minutes | Step 2 |
| Step 4: client.ts logic | 60 minutes | Step 2, 3 |
| Step 5: parent.ts updates | 30 minutes | Step 4 |
| Step 6: Worker verification | 15 minutes | Step 5 |
| Testing (local) | 45 minutes | All steps |
| Testing (cross-browser) | 60 minutes | Testing local |
| Documentation | 30 minutes | All steps |
| **Total** | **~4.5 hours** | - |

---

## Notes

- This is a **breaking change** for existing demo users - they'll need to re-enroll
- Consider adding migration guide for existing credentials
- Document permission policy requirements for integrators
- Add permission policy check to KMSUser init (warn if missing)
- Consider CSP implications for inline styles (if using CSP headers)

---

**Last Updated**: 2025-10-29
**Status**: Ready for Implementation
