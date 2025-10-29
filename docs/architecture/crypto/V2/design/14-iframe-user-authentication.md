# WebAuthn in Cross-Origin iframes (V2)

**Status**: Design Phase
**Version**: V2
**Date**: 2025-10-29
**Priority**: Critical (Required for KMS enclave unlock via platform authenticator)

---

## Table of Contents

- [Overview](#overview)
- [Technical Requirements](#technical-requirements)
- [Browser Support](#browser-support)
- [Implementation Steps](#implementation-steps)
- [Permission Policy Configuration](#permission-policy-configuration)
- [Common Pitfalls and Solutions](#common-pitfalls-and-solutions)
- [Testing and Verification](#testing-and-verification)
- [Security Considerations](#security-considerations)
- [References](#references)

---

## Overview

The KMS enclave (`kms.ats.run`) must support WebAuthn operations (specifically `navigator.credentials.get()`) within a cross-origin iframe context to enable platform authenticator-based unlock from the main PWA (`allthe.services`).

**Critical Context**: WebAuthn is disabled by default in cross-origin iframes due to security policies. Enabling it requires precise configuration of Permission Policies on both the parent page and the iframe source.

**Use Case**: User enrolls with platform authenticator (Face ID, Touch ID, Windows Hello) on `allthe.services` → KMS iframe at `kms.ats.run` must be able to call `navigator.credentials.get()` to verify the user's identity before unlocking master secret operations.

---

## Technical Requirements

### 1. Cross-Origin Context

- **Parent Origin**: `https://allthe.services` (main PWA)
- **iframe Origin**: `https://kms.ats.run` (KMS enclave)
- **Operation**: `navigator.credentials.get({publicKey})` (authentication only)
- **Relying Party ID**: `kms.ats.run`

### 2. WebAuthn Operations Needed

| Operation | Required? | Browser Support Status |
|-----------|-----------|------------------------|
| **Login** (`credentials.get`) | ✅ **Yes** | ✅ Chrome 84+, Firefox 118+, Safari 15.5+ |
| **Registration** (`credentials.create`) | ❌ No | ⚠️ Chrome 123+, Firefox 123+, ❌ Safari (not supported) |

**Important**: We only need `credentials.get()` for unlock operations. Registration happens in first-party context on `kms.ats.run` directly (not in iframe).

---

## Browser Support

### Current Status (October 2025)

| Browser | Cross-Origin `credentials.get()` | Notes |
|---------|----------------------------------|-------|
| Chrome/Edge | ✅ Supported (Chrome 84+) | Full support since July 2020 |
| Firefox | ✅ Supported (Firefox 118+) | Full support since Sept 2023 |
| Safari | ✅ Supported (Safari 15.5+) | Full support since May 2022 |

**Minimum Browser Versions**:
- Chrome/Edge: 84 (July 2020)
- Firefox: 118 (September 2023)
- Safari: 15.5 (May 2022)

All our target browsers support cross-origin WebAuthn authentication.

---

## Implementation Steps

### Step 1: Configure iframe Element (Parent Page)

The parent page (`allthe.services`) must include the `allow` attribute on the iframe element:

```html
<!-- On https://allthe.services (parent PWA) -->
<iframe
  src="https://kms.ats.run"
  allow="publickey-credentials-get"
  sandbox="allow-scripts allow-same-origin"
  title="KMS Enclave"
></iframe>
```

**Key Points**:
- `allow="publickey-credentials-get"` grants permission for WebAuthn authentication
- Do NOT include `publickey-credentials-create` (we don't need registration in iframe)
- `sandbox` attribute is safe because iframe is cross-origin (see design/02-security-decisions.md)

### Step 2: Configure HTTP Response Headers (iframe Source)

The iframe source (`kms.ats.run`) must set the `Permissions-Policy` HTTP header:

```http
Permissions-Policy: publickey-credentials-get=(self "https://allthe.services")
```

**Important**: This header must be sent by the server serving `kms.ats.run`, NOT by the parent page.

**Options**:

1. **Specific Origin** (recommended for production):
   ```http
   Permissions-Policy: publickey-credentials-get=(self "https://allthe.services")
   ```
   Only allows embedding from `allthe.services` (most restrictive).

2. **Wildcard** (for development/testing):
   ```http
   Permissions-Policy: publickey-credentials-get=*
   ```
   Allows any origin to embed (less secure, but useful for local testing).

### Step 3: Alternative - Meta Tag Headers (If Server Config Not Possible)

If you cannot configure server headers, use `<meta>` tags in the iframe's HTML:

```html
<!-- Inside kms.html (served from kms.ats.run) -->
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta
    http-equiv="Permissions-Policy"
    content="publickey-credentials-get=*"
  >
  <!-- Rest of KMS enclave HTML -->
</head>
```

**Note**: Server headers take precedence over meta tags. Meta tags are a fallback.

### Step 4: Require User Activation (Transient Activation)

WebAuthn calls in iframes require **user activation** - the call must be triggered by a user gesture (click, tap, etc.).

```typescript
// Inside iframe (kms.ats.run)
document.getElementById('unlockButton').addEventListener('click', async () => {
  try {
    const publicKeyCredentialRequestOptions = {
      challenge: new Uint8Array(32), // From server
      rpId: 'kms.ats.run',
      userVerification: 'required',
      timeout: 60000,
      allowCredentials: [{
        type: 'public-key',
        id: credentialIdBytes,
        transports: ['internal'] // Platform authenticator
      }]
    };

    const credential = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    });

    // credential contains authenticatorData and signature
    // Send to worker for master secret decryption
  } catch (err) {
    console.error('WebAuthn authentication failed:', err);
    // Handle error (wrong finger, cancelled, timeout, etc.)
  }
});
```

**Critical**: The `credentials.get()` call must be inside an event handler for a user-initiated action.

---

## Permission Policy Configuration

### Understanding Permission Policies

The Permissions-Policy (formerly Feature-Policy) is a two-part system:

1. **Parent grants permission** via `allow` attribute on `<iframe>`
2. **iframe opts in** via `Permissions-Policy` HTTP header

**Both are required**. If either is missing, WebAuthn will be blocked.

### Syntax Differences

**iframe `allow` attribute** (Feature-Policy syntax):
```html
<iframe allow="publickey-credentials-get; publickey-credentials-create"></iframe>
```
Uses **semicolons** to separate features (legacy syntax).

**HTTP `Permissions-Policy` header** (Permissions-Policy syntax):
```http
Permissions-Policy: publickey-credentials-get=*, publickey-credentials-create=*
```
Uses **commas** to separate features (new syntax).

### Why Both Are Needed

```
Parent page (allthe.services)
  ↓ allows="publickey-credentials-get"
  ↓ (grants permission to iframe)
  ↓
iframe (kms.ats.run)
  ↓ Permissions-Policy: publickey-credentials-get=(...)
  ↓ (opts in to use the feature)
  ↓
WebAuthn enabled ✅
```

If parent doesn't grant → iframe can't use (even if it opts in)
If iframe doesn't opt in → feature not enabled (even if parent allows)

---

## Common Pitfalls and Solutions

### Pitfall 1: NotAllowedError - Feature Not Enabled

**Error Message**:
```
NotAllowedError: The 'publickey-credentials-get' feature is not enabled in this document.
Permissions Policy may be used to delegate Web Authentication capabilities to cross-origin child frames.
```

**Cause**: Missing or incorrect Permission Policy configuration.

**Solution**:
1. Verify `allow="publickey-credentials-get"` is on iframe element
2. Verify `Permissions-Policy` header is sent by iframe source
3. Check browser DevTools → Application → Frames → [iframe origin] → Permissions Policy
4. Confirm `publickey-credentials-get` is listed under "Allowed Features"

### Pitfall 2: Safari Cross-Origin Issues

**Error Message**:
```
NotAllowedError: The origin of the document is not the same as its ancestors.
```

**Cause**: This specific error appears when:
- Using Safari with `credentials.create()` in cross-origin iframe (not supported)
- Using third-party cookies in iframe (blocked by Safari's ITP)

**Solution**:
- ✅ For `credentials.get()`: Works in Safari 15.5+ with correct headers
- ❌ For `credentials.create()`: NOT supported in Safari (as of Oct 2025)
- ⚠️ Avoid third-party cookies/localStorage in iframe (Safari blocks these)

**For KMS**: We only use `credentials.get()` in iframe, so Safari should work.

### Pitfall 3: Cross-Origin Frame Access Error

**Error Message**:
```
Blocked a frame with origin "https://kms.ats.run" from accessing a frame with origin "https://ats.run".
Protocols, domains, and ports must match.
```

**Cause**: Attempting to access parent frame's DOM from iframe (or vice versa).

**Solution**: Use `postMessage()` for cross-origin communication (already implemented in our RPC protocol).

### Pitfall 4: Missing User Activation

**Error Message**:
```
NotAllowedError: The operation requires user activation.
```

**Cause**: Calling `credentials.get()` without user gesture (e.g., on page load, in setTimeout).

**Solution**: Only call `credentials.get()` inside click/tap event handlers.

```typescript
// ❌ BAD - No user activation
window.addEventListener('load', async () => {
  const credential = await navigator.credentials.get({...}); // WILL FAIL
});

// ✅ GOOD - User-initiated
button.addEventListener('click', async () => {
  const credential = await navigator.credentials.get({...}); // WILL WORK
});
```

### Pitfall 5: Incorrect rpId

**Error Message**:
```
NotAllowedError: The relying party ID is not a valid domain.
```

**Cause**: `rpId` in request doesn't match iframe's origin domain.

**Solution**: Set `rpId: 'kms.ats.run'` (must match iframe origin, NOT parent origin).

---

## Testing and Verification

### 1. Verify Permissions Policy Is Set

**Chrome DevTools**:
1. Open DevTools (F12)
2. Go to **Application** tab
3. Expand **Frames** in left sidebar
4. Select iframe origin (e.g., `https://kms.ats.run`)
5. Check **Permissions Policy** section
6. Confirm `publickey-credentials-get` is in **Allowed Features**

**Expected**:
```
Allowed Features:
  publickey-credentials-get
```

If not listed → Permission Policy not configured correctly.

### 2. Test WebAuthn Call

```typescript
// Inside iframe - add to developer console
navigator.credentials.get({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: 'kms.ats.run',
    timeout: 60000,
    userVerification: 'required',
    allowCredentials: []
  }
}).then(
  cred => console.log('✅ WebAuthn works!', cred),
  err => console.error('❌ WebAuthn failed:', err)
);
```

**Expected**: Platform authenticator prompt appears (Face ID, Touch ID, etc.)

### 3. Test Across Browsers

Minimum test matrix:
- ✅ Chrome 84+ (Windows, macOS, Android)
- ✅ Firefox 118+ (Windows, macOS, Android)
- ✅ Safari 15.5+ (macOS, iOS)
- ✅ Edge 84+ (Windows)

### 4. Automated Testing

```typescript
// In integration tests
describe('WebAuthn in iframe', () => {
  it('should allow credentials.get() in cross-origin iframe', async () => {
    // Load parent page with iframe
    await page.goto('https://allthe.services');

    // Switch to iframe context
    const iframeElement = await page.waitForSelector('iframe[src*="kms.ats.run"]');
    const iframe = await iframeElement.contentFrame();

    // Trigger unlock button
    await iframe.click('#unlockButton');

    // Verify platform authenticator prompt appears
    // (implementation depends on test framework)
  });
});
```

---

## Security Considerations

### 1. Relying Party ID Binding

- **Credentials are bound to `kms.ats.run`** (the iframe origin)
- Credentials CANNOT be used on `allthe.services` (parent origin)
- This is by design - prevents phishing attacks
- Platform authenticator verifies origin before allowing authentication

### 2. Sandbox Safety

Using `sandbox="allow-scripts allow-same-origin"` is safe because:
- iframe is cross-origin (`kms.ats.run` ≠ `ats.run`)
- Browser enforces origin isolation regardless of sandbox
- `allow-same-origin` needed for:
  - Runtime self-check (`fetch(import.meta.url)`)
  - IndexedDB access
  - WebAuthn API access

See [design/02-security-decisions.md](./02-security-decisions.md) for full rationale.

### 3. Third-Party Context Limitations

**What works**:
- ✅ WebAuthn `credentials.get()` with platform authenticator
- ✅ IndexedDB (for storing credential IDs and wrapped keys)
- ✅ WebCrypto API (for master secret encryption)
- ✅ `postMessage()` communication

**What may not work** (especially in Safari):
- ❌ Third-party cookies
- ❌ `credentials.create()` (registration)
- ⚠️ LocalStorage (use IndexedDB instead)

### 4. Permission Policy Granularity

**Recommended** (production):
```http
Permissions-Policy: publickey-credentials-get=(self "https://allthe.services")
```

Only allows embedding from specific origin.

**Not recommended** (too permissive):
```http
Permissions-Policy: publickey-credentials-get=*
```

Allows any site to embed KMS enclave (potential abuse vector).

### 5. User Verification Requirement

Always set `userVerification: "required"` for unlock operations:

```typescript
{
  publicKey: {
    userVerification: 'required', // ← Forces biometric/PIN
    // ...
  }
}
```

This ensures:
- User is physically present
- Biometric verification happens (Face ID, Touch ID, etc.)
- Cannot be bypassed by malicious scripts

---

## Integration with KMS V2 Architecture

### Unlock Flow with WebAuthn

```
User clicks "Unlock" on allthe.services
  ↓
Parent PWA sends unlock request via postMessage
  ↓
KMS iframe (kms.ats.run) receives message
  ↓
iframe shows "Use Face ID to unlock" button
  ↓
User clicks button (user activation) ←─ REQUIRED
  ↓
iframe calls navigator.credentials.get()
  ↓
Browser shows platform authenticator prompt
  ↓
User authenticates (Face ID, Touch ID, Windows Hello)
  ↓
Credential returned with signature
  ↓
KMS Worker verifies signature
  ↓
Worker decrypts master secret wrapper
  ↓
Master secret available for operations
  ↓
Unlock context created with timer
  ↓
Success response sent to parent PWA
```

### Storage Architecture

**Enrollment (first-party context on kms.ats.run)**:
1. User navigates to `https://kms.ats.run` directly
2. Calls `credentials.create()` (NOT in iframe)
3. Stores credential ID in IndexedDB
4. Wraps master secret with credential public key
5. Stores wrapped master secret in IndexedDB

**Unlock (cross-origin iframe on allthe.services)**:
1. iframe at `kms.ats.run` embedded in `allthe.services`
2. Calls `credentials.get()` with stored credential ID
3. Authenticator returns signature
4. Unwraps master secret using signature verification
5. Master secret available for crypto operations

### RPC Protocol Updates

Add new message type for unlock with WebAuthn:

```typescript
// Parent → iframe
type UnlockWithWebAuthnRequest = {
  type: 'unlockWithWebAuthn';
  requestId: string;
  credentialId: string; // Base64url-encoded
  challenge: string;    // From server
};

// iframe → Parent
type UnlockWithWebAuthnResponse = {
  requestId: string;
  success: true;
  unlockContext: UnlockContext;
} | {
  requestId: string;
  success: false;
  error: 'user_cancelled' | 'timeout' | 'not_allowed' | 'unknown';
  message: string;
};
```

### Worker Implementation

```typescript
// In worker.ts
async function handleUnlockWithWebAuthn(
  credentialId: Uint8Array,
  challenge: Uint8Array
): Promise<UnlockContext> {
  // 1. Prepare WebAuthn request options
  const options: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: 'kms.ats.run',
    timeout: 60000,
    userVerification: 'required',
    allowCredentials: [{
      type: 'public-key',
      id: credentialId,
      transports: ['internal']
    }]
  };

  // 2. NOTE: This call happens in main.ts (main thread), not worker
  //    Worker receives the credential after authentication

  // 3. Verify signature (in worker after receiving credential)
  const signatureValid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    credential.response.signature,
    authenticatorData + clientDataHash
  );

  if (!signatureValid) {
    throw new Error('Invalid WebAuthn signature');
  }

  // 4. Unwrap master secret
  const wrappedMasterSecret = await storage.getWrappedMasterSecret();
  const masterSecret = await unwrapMasterSecret(
    wrappedMasterSecret,
    credential // Use credential as unwrap key
  );

  // 5. Create unlock context
  const unlockContext = createUnlockContext(masterSecret);

  return unlockContext;
}
```

---

## References

### Specifications

- **WebAuthn Level 3**: https://w3c.github.io/webauthn/
  - Cross-origin iframe support: Section 13.4.2
- **Permissions Policy**: https://www.w3.org/TR/permissions-policy-1/
  - publickey-credentials-get: https://w3c.github.io/webauthn/#sctn-permissions-policy

### Browser Implementation Status

- **Chrome**: https://chromestatus.com/feature/5144442672996352
- **Firefox**: https://bugzilla.mozilla.org/show_bug.cgi?id=1460986
- **Safari**: https://webkit.org/blog/11989/webauthn-in-safari-14/

### Community Resources

- **MDN Permissions-Policy**: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
- **WebAuthn Guide**: https://webauthn.guide/
- **FIDO Alliance**: https://fidoalliance.org/specifications/

### Related KMS V2 Design Docs

- [02-security-decisions.md](./02-security-decisions.md) - Sandbox configuration rationale
- [03-unlock-context.md](./03-unlock-context.md) - Unlock context lifecycle
- [04-key-operations.md](./04-key-operations.md) - Master secret encryption
- [06-multi-enrollment.md](./06-multi-enrollment.md) - Multiple authenticator support
- [11-iframe-isolation.md](./11-iframe-isolation.md) - iframe security model

---

## Implementation Checklist

### Phase 1: Development Setup
- [ ] Configure Vite dev server to serve KMS on subdomain (`kms.localhost:5173`)
- [ ] Add `Permissions-Policy` header to dev server config
- [ ] Update iframe element in parent PWA with `allow` attribute
- [ ] Test WebAuthn call in iframe (DevTools console)
- [ ] Verify permission policy in Chrome DevTools

### Phase 2: WebAuthn Integration
- [ ] Implement enrollment flow (first-party context)
- [ ] Store credential ID in IndexedDB
- [ ] Implement unlock RPC message handlers
- [ ] Add WebAuthn call in iframe main thread (with user activation)
- [ ] Pass credential to worker for verification
- [ ] Implement master secret unwrapping with credential

### Phase 3: Production Deployment
- [ ] Configure production server headers for `kms.ats.run`
- [ ] Set restrictive `Permissions-Policy` (only allow `allthe.services`)
- [ ] Add CSP headers for iframe security
- [ ] Test on all target browsers (Chrome, Firefox, Safari, Edge)
- [ ] Test on mobile (iOS Safari, Chrome Android)
- [ ] Document browser version requirements for users

### Phase 4: Error Handling
- [ ] Handle `NotAllowedError` (user cancelled)
- [ ] Handle timeout errors
- [ ] Handle missing credential errors
- [ ] Add user-friendly error messages
- [ ] Implement retry logic (with exponential backoff)
- [ ] Add fallback unlock methods (password, recovery key)

### Phase 5: Testing
- [ ] Unit tests for WebAuthn credential verification
- [ ] Integration tests for iframe unlock flow
- [ ] Cross-browser testing (automated)
- [ ] Mobile browser testing
- [ ] Performance testing (unlock latency)
- [ ] Security audit (permission policy, origin verification)

---

**Last Updated**: 2025-10-29
