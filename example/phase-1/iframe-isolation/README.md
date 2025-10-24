# Phase 1 Demo: Iframe Isolation

## Overview

This demo demonstrates the **core security principle** of the KMS architecture: **cross-origin isolation** between a parent PWA and the KMS enclave running in a sandboxed iframe.

### What This Demo Proves

1. **Parent PWA cannot access KMS internals**: Private keys, IndexedDB, and crypto operations are completely isolated
2. **postMessage-only communication**: Parent and KMS communicate exclusively via message passing
3. **Secrets never touch the parent**: Passkey/passphrase setup, key generation, and signing all happen in the iframe
4. **Parent receives only public outputs**: JWT signatures, public keys - never private keys
5. **Iframe handles all crypto validation**: Lock/unlock operations are validated entirely within the KMS

## Architecture

### Dual-Port Setup (Simulates Production Cross-Origin)

**Development:**
- Parent PWA: `http://localhost:5176`
- KMS Iframe: `http://localhost:5177`

**Production (Future):**
- Parent PWA: `https://allthe.services`
- KMS Iframe: `https://kms.ats.run`

This dual-port setup allows us to configure **real CSP rules** and test **true cross-origin isolation**.

```
┌───────────────────────────────────────────────────────────────┐
│                    Parent Window (PWA)                        │
│                    Origin: localhost:5176                     │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                      UI Controls                        │  │
│  │                                                         │  │
│  │  [Setup Passkey]  [Setup Passphrase]                    │  │
│  │  [Generate VAPID] [Request JWT]                         │  │
│  │  [Lock KMS]       [Unlock KMS]                          │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │            Received from KMS (Public Only)              │  │
│  │                                                         │  │
│  │  JWT signature (base64url)                              │  │
│  │  VAPID public key (ArrayBuffer)                         │  │
│  │  Success/error messages                                 │  │
│  │                                                         │  │
│  │  ❌ Private keys (NEVER accessible)                      │  │
│  │  ❌ Passphrase/PRF output (NEVER accessible)             │  │
│  │  ❌ IndexedDB contents (NEVER accessible)                │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  CSP: frame-src localhost:5177                                │
│  Embeds: <iframe src="http://localhost:5177">                 │
│                                                               │
│              ↓ postMessage (auditable, explicit) ↓            │
└───────────────────────────────────────────────────────────────┘
                                ↓
         Cross-Origin Isolation (Browser-Enforced)
         Different port = Different origin
                                ↓
┌───────────────────────────────────────────────────────────────┐
│                   Sandboxed Iframe (KMS)                      │
│                   Origin: localhost:5177                      │
│             sandbox="allow-scripts allow-same-origin"         │
│                                                               │
│  CSP: frame-ancestors localhost:5176                          │
│  CSP: connect-src 'self'                                      │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    KMS Main Thread                      │  │
│  │                                                         │  │
│  │  - Receive postMessage requests from parent             │  │
│  │  - Validate request origin and structure                │  │
│  │  - Forward to Dedicated Worker                          │  │
│  │  - Return public results to parent                      │  │
│  └─────────────────────────────────────────────────────────┘  │
│                      ↓ Worker boundary ↓                      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                  KMS Worker (Isolated)                  │  │
│  │                                                         │  │
│  │  ┌───────────────────────────────────────────────────┐  │  │
│  │  │        WebCrypto Operations (Sealed)              │  │  │
│  │  │                                                   │  │  │
│  │  │  - Passkey/passphrase setup (gate mode)           │  │  │
│  │  │  - VAPID keypair generation (non-extractable)     │  │  │
│  │  │  - JWT signing (ES256)                            │  │  │
│  │  │  - Lock/unlock state management                   │  │  │
│  │  │  - Key wrapping/unwrapping                        │  │  │
│  │  │                                                   │  │  │
│  │  │  All private keys: extractable: false             │  │  │
│  │  │  Storage: IndexedDB (iframe-local)                │  │  │
│  │  └───────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  Parent PWA CANNOT access:                                    │
│    ❌ Worker memory or state                                   │
│    ❌ IndexedDB (different origin context)                     │
│    ❌ Private keys (non-extractable + worker isolation)        │
│    ❌ Passphrase or PRF outputs                                │
└───────────────────────────────────────────────────────────────┘
```

## Demo Flow

### Phase 1: Setup (Choose One)

**Option A: Setup Passkey**
- User clicks "Setup Passkey" in parent window
- Parent sends `{ type: 'setupPasskey', rpId, rpName }` to iframe
- Iframe forwards to Worker
- Worker invokes WebAuthn API (browser UI appears)
- User creates passkey with device biometrics
- Worker derives KEK from PRF output (or uses gate mode fallback)
- Worker stores passkey config in IndexedDB
- Iframe returns `{ success: true }` to parent
- **Parent never sees**: PRF output, KEK, credential ID details

**Option B: Setup Passphrase**
- User clicks "Setup Passphrase" in parent window
- Parent sends `{ type: 'setupPassphrase' }` to iframe
- Iframe prompts user for passphrase (in iframe context, NOT parent)
- Worker derives KEK using PBKDF2
- Worker stores wrapped passphrase config in IndexedDB
- Iframe returns `{ success: true }` to parent
- **Parent never sees**: Passphrase, KEK, salt, or derivation parameters

### Phase 2: Generate VAPID Keypair

- User clicks "Generate VAPID" in parent window
- Parent sends `{ type: 'generateVAPID' }` to iframe
- Iframe checks if Worker is unlocked (has KEK in memory)
- Worker generates ECDSA P-256 keypair (`extractable: false`)
- Worker wraps private key with KEK (AES-GCM)
- Worker stores wrapped private key in IndexedDB
- Worker exports public key (SPKI format)
- Iframe returns `{ success: true, publicKey: ArrayBuffer }` to parent
- **Parent receives**: Public key only
- **Parent never sees**: Private key, KEK, wrapped key blob

### Phase 3: Sign JWT

- User clicks "Request JWT" in parent window
- Parent sends `{ type: 'signJWT', payload: { aud, exp, sub } }` to iframe
- Iframe forwards request to Worker
- Worker builds JWT header + payload
- Worker retrieves VAPID private key from IndexedDB
- Worker unwraps private key using KEK
- Worker signs JWT using unwrapped private key (ECDSA)
- Worker converts signature from DER to P-1363 format (RFC 7515)
- Worker builds final JWT: `header.payload.signature`
- Iframe returns `{ success: true, jwt: string }` to parent
- **Parent receives**: Signed JWT (can be verified with public key)
- **Parent never sees**: Private key, unwrapping process, KEK

### Phase 4: Lock Worker

- User clicks "Lock KMS" in parent window
- Parent sends `{ type: 'lockWorker' }` to iframe
- Iframe forwards to Worker
- Worker clears KEK from memory (`_wrappingKeyRef = null`)
- Worker clears any session timers
- Iframe returns `{ success: true, locked: true }` to parent
- **After lock**: Worker refuses crypto operations until unlocked
- **Parent never sees**: What was in memory, how lock is implemented

### Phase 5: Unlock Worker

**Passkey Unlock:**
- User clicks "Unlock KMS (Passkey)" in parent window
- Parent sends `{ type: 'unlockWithPasskey', rpId }` to iframe
- Iframe forwards to Worker
- Worker invokes WebAuthn get() (browser UI appears)
- User authenticates with device biometrics
- Browser returns PRF output (or credential for gate mode)
- Worker derives KEK from PRF output
- Worker verifies KEK by attempting to unwrap stored test data
- If successful: Worker stores KEK in memory
- Iframe returns `{ success: true, locked: false }` to parent
- **Parent never sees**: PRF output, KEK, verification process

**Passphrase Unlock:**
- User clicks "Unlock KMS (Passphrase)" in parent window
- Parent sends `{ type: 'unlockWithPassphrase' }` to iframe
- Iframe prompts user for passphrase (in iframe context)
- Worker derives KEK from passphrase using stored salt
- Worker verifies KEK by attempting to unwrap stored test data
- If successful: Worker stores KEK in memory
- Iframe returns `{ success: true, locked: false }` to parent
- **Parent never sees**: Passphrase, KEK, derivation or verification

## Security Guarantees Demonstrated

### 1. Cross-Origin Isolation

Even though the iframe uses `sandbox="allow-same-origin"` (required for IndexedDB), the **parent cannot access iframe internals** because:
- Same-origin policy applies to the iframe's origin, not the parent's origin
- Browser enforces separation at the process/thread level
- No shared memory between parent and iframe
- IndexedDB namespaces are origin-scoped

**Demo Test**: Open browser DevTools in parent window, try to access `iframe.contentWindow.indexedDB` → **Access denied**

### 2. postMessage-Only Communication

All communication between parent and iframe is **explicit and auditable**:
- Every message is visible in DevTools Network/Console
- No ambient authority (no cookies, no localStorage access)
- Origin validation on every message
- Timeout protection (operations fail if iframe doesn't respond)

**Demo Test**: Monitor DevTools Console → see every `postMessage` with full payload

### 3. Private Keys Never Leave Worker

Private keys are marked `extractable: false`:
- Browser's crypto subsystem refuses to export them
- Even compromised KMS code cannot extract keys
- Keys exist only as opaque handles
- Signing happens inside crypto subsystem

**Demo Test**: In Worker scope, try `crypto.subtle.exportKey('pkcs8', privateKey)` → **Operation not supported error**

### 4. Minimal Attack Surface

Parent PWA is **untrusted** by design:
- If parent is compromised, keys remain safe
- Parent can only request specific operations (sign, generate)
- Parent cannot inject arbitrary code into iframe
- Parent cannot bypass lock state

**Demo Test**: Compromise parent by modifying its code → **KMS operations still protected**

## Visual Design

The demo UI is split into two visual sections:

### Parent Window (Top Section)
- **Title**: "Parent PWA (Untrusted)"
- **Controls**: All user interaction buttons
  - Setup section: [Setup Passkey] [Setup Passphrase]
  - Operations: [Generate VAPID] [Request JWT] [Lock KMS] [Unlock KMS]
- **Output**: Display received JWT, public key, success/error messages
- **Security Indicator**: "❌ Cannot access KMS internals" (always visible)

### Iframe (Bottom Section - Visual Border)
- **Title**: "KMS Enclave (Isolated)"
- **Content**: Embedded iframe showing KMS internal state
  - Current lock status: 🔓 Unlocked / 🔒 Locked
  - Operations log: Recent crypto operations
  - Security guarantees: Visual reminders of isolation
- **Visual Separation**: Heavy border, different background color, clear label
- **Security Indicator**: "✅ Private keys never leave this iframe" (always visible)

### Key Visual Elements

1. **Origin display**: Show parent origin (localhost:5176) vs iframe origin
2. **Message flow arrows**: Animate postMessage direction when operations occur
3. **Lock state indicator**: Visual lock icon that changes color (green=unlocked, red=locked)
4. **Operation success/fail**: Color-coded feedback (green/red)
5. **Security boundaries**: Dashed line between parent and iframe sections

## Testing Security Claims

After implementing the demo, users can verify isolation:

### Test 1: IndexedDB Isolation
1. Open parent page DevTools
2. Go to Application → IndexedDB
3. Try to access KMS IndexedDB → **Not visible from parent context**
4. Open iframe DevTools (right-click iframe → Inspect)
5. Go to Application → IndexedDB → **KMS database visible here**

### Test 2: Private Key Non-Extractability
1. Generate VAPID keypair
2. Open iframe DevTools console
3. Try to export private key → **Operation not supported**
4. Signing still works → **Keys exist but cannot be extracted**

### Test 3: Lock State Enforcement
1. Generate VAPID keypair (while unlocked)
2. Lock the KMS
3. Try to sign JWT → **Error: Worker is locked**
4. Unlock with passkey/passphrase → **Signing works again**

### Test 4: Parent Cannot Bypass Lock
1. Lock the KMS from parent UI
2. Modify parent code to send `signJWT` without checking lock state
3. Send message directly → **Worker refuses operation**
4. KMS enforces lock internally, parent cannot override

## Implementation Notes

### File Structure

```
example/phase-1/iframe-isolation/
├── README.md           (this file)
├── parent.html         Parent PWA HTML (loads iframe)
├── parent.ts           Parent PWA logic (postMessage sender)
├── kms.html           KMS iframe HTML (embedded)
├── kms.ts             KMS main thread (postMessage receiver)
└── styles.css         Visual styling (borders, security indicators)
```

### Running the Demo

The demo requires **two separate dev servers** running simultaneously:

```bash
# Terminal 1: Start KMS iframe server (port 5177)
pnpm demo:phase-1-iframe-isolation:kms

# Terminal 2: Start parent PWA server (port 5176)
pnpm demo:phase-1-iframe-isolation:parent

# Then open: http://localhost:5176
```

**Why two servers?**
- Different ports = different origins (simulates production cross-origin setup)
- Allows configuring real CSP headers
- Enables testing true cross-origin postMessage validation
- Demonstrates iframe sandbox restrictions

### CSP Configuration

**Parent PWA (localhost:5176):**
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  frame-src http://localhost:5177;
  connect-src 'self';
  style-src 'self' 'unsafe-inline';
```

**KMS Iframe (localhost:5177):**
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  frame-ancestors http://localhost:5176;
  connect-src 'self';
  worker-src 'self';
  style-src 'self' 'unsafe-inline';
```

**Key CSP Directives:**

| Directive | Purpose | Notes |
|-----------|---------|-------|
| `frame-src` | Parent can only embed KMS from port 5177 | Prevents loading malicious iframes |
| `frame-ancestors` | KMS can only be embedded by parent on 5176 | Prevents clickjacking |
| `connect-src 'self'` | Network requests restricted to same-origin | KMS has zero network access except self-verification |
| `worker-src 'self'` | Workers can only be loaded from same origin | Protects Worker isolation |

### Communication Protocol

**Parent → KMS (Request)**:
```typescript
type Request =
  | { type: 'setupPasskey', rpId: string, rpName: string }
  | { type: 'setupPassphrase' }
  | { type: 'generateVAPID' }
  | { type: 'signJWT', payload: JWTPayload }
  | { type: 'lockWorker' }
  | { type: 'unlockWithPasskey', rpId: string }
  | { type: 'unlockWithPassphrase' }
  | { type: 'getStatus' }
```

**KMS → Parent (Response)**:
```typescript
type Response =
  | { success: true, jwt?: string, publicKey?: ArrayBuffer, locked?: boolean }
  | { success: false, error: string }
```

### Key Differences from security-flow Demo

| Feature | security-flow | iframe-isolation |
|---------|---------------|------------------|
| **Architecture** | Single page, direct Worker access | Parent + iframe, postMessage bridge |
| **Focus** | End-to-end crypto flow | Cross-origin isolation |
| **UI** | Comprehensive testing UI | Minimal, security-focused UI |
| **Security Demo** | Crypto correctness | Isolation boundaries |
| **Parent Access** | Direct Worker reference | No access (postMessage only) |

## Success Criteria

The demo successfully demonstrates iframe isolation when:

1. ✅ User can setup passkey/passphrase without parent seeing secrets
2. ✅ User can generate VAPID keypair, parent receives only public key
3. ✅ User can request JWT signature, parent receives valid JWT
4. ✅ JWT signature verifies with public key (crypto correctness)
5. ✅ Lock/unlock operations work correctly
6. ✅ Parent cannot access KMS IndexedDB (browser DevTools verification)
7. ✅ Parent cannot extract private keys (browser enforces non-extractability)
8. ✅ Parent cannot bypass lock state (KMS enforces internally)
9. ✅ All communication via postMessage is auditable (DevTools Console)
10. ✅ Visual UI clearly shows separation between parent and iframe

## Future Enhancements

After Phase 1, this demo can be extended to show:
- **SRI verification**: Load KMS with Subresource Integrity hash
- **Timeout handling**: Fail requests if iframe doesn't respond
- **Error propagation**: Show how errors are handled across boundary
- **Multiple iframes**: Demonstrate multiple isolated KMS instances
- **Production CSP**: Stricter policies without 'unsafe-inline'
- **HTTPS setup**: Local TLS certificates for testing HTTPS-only features

## References

- [docs/architecture/crypto/README.md](../../../docs/architecture/crypto/README.md) - Complete architecture overview
- [docs/architecture/crypto/design/01-overview-and-architecture.md](../../../docs/architecture/crypto/design/01-overview-and-architecture.md) - Architecture design
- [docs/architecture/crypto/design/05-security-model.md](../../../docs/architecture/crypto/design/05-security-model.md) - Security boundaries and threat model

---

**Note**: This demo runs parent and KMS on separate ports (5176 and 5177) to simulate production cross-origin isolation (allthe.services vs kms.ats.run). The different ports create true origin boundaries, allowing us to test real CSP rules and postMessage origin validation. The security principles demonstrated here translate directly to production with HTTPS and subdomain separation.
