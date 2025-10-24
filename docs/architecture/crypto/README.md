# Browser-Based Verifiable KMS Enclave

---

# ⚠️ CRITICAL: FILE REVERT POLICY ⚠️

**NEVER REVERT ANY FILE USING `git checkout`, `git restore`, OR ANY OTHER METHOD WITHOUT:**

1. **EXPLICIT USER APPROVAL** - User must specifically say "revert file X"
2. **CONFIRMATION** - After approval, ask for confirmation: "Are you sure you want to revert [filename]? This will lose all uncommitted changes."

**WHY THIS IS CRITICAL:**
- Reverting a file can break the entire application by creating API mismatches
- Uncommitted work may represent hours of implementation
- File dependencies are not always obvious (e.g., client.ts ↔ worker.ts ↔ unlock.ts)
- Breaking changes cascade across multiple components

**IF YOU NEED TO UNDO CHANGES:**
- First, understand what changed: `git diff <filename>`
- Ask the user how to proceed
- Consider selective edits rather than full reverts
- If reverting is necessary, get explicit permission FIRST

**THIS RULE APPLIES TO ALL FILES WITHOUT EXCEPTION.**

---

## Overview

This directory documents the browser-based Key Management System (KMS) enclave for AllTheServices PWA. The enclave is a sandboxed, verifiable execution environment for cryptographic operations, designed to provide user-auditable security guarantees.

## Purpose

The KMS enclave serves as a **trustworthy cryptographic foundation** for:
- OS notification push authorization (VAPID keys)
- Secure messaging (Signal protocol, future)
- User authentication (passkey operations, future)
- Any operation requiring user-owned, non-extractable cryptographic keys

## Core Concept

**Traditional approach** (insecure):
```
┌─────────────────────────────────┐
│         Main PWA Code           │
│                                 │
│  - Business logic               │
│  - UI components                │
│  - Crypto operations  !         │
│  - Key storage   !              │
│                                 │
│  Problem: Malicious PWA update  │
│  can steal keys                 │
└─────────────────────────────────┘
```

**KMS enclave approach** (secure):
```
┌─────────────────────────────────┐     ┌─────────────────────────────────┐
│         Main PWA Code           │     │      KMS Enclave (Isolated)     │
│         (ats.run)               │     │      (kms.ats.run)              │
│                                 │     │                                 │
│  - Business logic               │     │  Separate origin                │
│  - UI components                │────▶│  Sandboxed iframe               │
│  - Request signatures           │     │  SRI-verified module            │
│                                 │◀────│  Dedicated Worker               │
│  Receives: signatures only      │     │                                 │
│  Never sees: private keys       │     │  - Key generation               │
│                                 │     │  - Signing/encryption           │
│  Can be compromised without     │     │  - Non-extractable storage      │
│  compromising keys              │     │                                 │
│                                 │     │  User-verifiable code           │
│                                 │     │  Reproducible builds            │
└─────────────────────────────────┘     └─────────────────────────────────┘

<!-- How PWA loads enclave -->
<iframe
  src="https://kms.ats.run/kms.html"
  sandbox="allow-scripts allow-same-origin"
  referrerpolicy="no-referrer"
></iframe>

<!-- Inside kms.html -->
<script type="module"
  src="/artifacts/kms-a3f8b2d1.mjs"
  integrity="sha256-ABCD..."
  crossorigin="anonymous"></script>
```

## Key Features

### 1. Verifiable Execution
- **Content-addressed artifacts**: Files named by hash (`kms-a3f8b2d1.js`)
- **Subresource Integrity**: Browser verifies file hash before execution
- **Reproducible builds**: Anyone can rebuild and verify artifact hash
- **Transparency logs**: Public Sigstore/Rekor record of releases

**User benefit**: Security researchers and advanced users can verify the KMS code matches public source, providing community-audited trust.

### 2. Isolated Execution
- **Separate origin**: KMS served from `kms.ats.run` (cross-origin)
- **Sandboxed iframe**: `sandbox="allow-scripts allow-same-origin"` (safe due to cross-origin)
- **Dedicated Worker**: Further isolation for crypto operations
- **postMessage only**: Parent PWA cannot directly access KMS internals

**User benefit**: Even if main PWA is compromised, keys remain safe in the isolated enclave.

### 3. Non-Extractable Keys
- **WebCrypto API**: `crypto.subtle.generateKey(..., false, ...)` prevents export
- **Browser-enforced**: Keys cannot leave the crypto subsystem
- **IndexedDB storage**: CryptoKey objects stored in encrypted database
- **Handle-only access**: PWA gets key handles, never raw key material

**User benefit**: Keys physically cannot be exfiltrated by application code.

### 4. Defense in Depth
- **CSP hardening**: Content Security Policy blocks unauthorized code
- **SRI verification**: Fails if Service Worker tampers with enclave
- **Runtime self-check**: Enclave validates its own hash at startup
- **Fail-safe defaults**: Errors stop execution rather than degrading security

**User benefit**: Multiple independent security layers protect against various attack vectors.

## Architecture Layers

### Layer 1: Hosting & Delivery
```
kms.ats.run
├── kms-a3f8b2d1.js          (content-addressed)
├── kms-worker-7f4e3a1.js    (content-addressed)
└── manifest.json            (SRI hashes, transparency log reference)
```

**Properties**:
- Static hosting (CDN or object storage)
- Content-addressed URLs (hash in filename)
- Immutable artifacts (never change after publish)
- HTTPS required (enforced by browsers)

### Layer 2: Iframe Sandbox
```html
<!-- Parent PWA loads the enclave HTML -->
<iframe
  src="https://kms.ats.run/kms.html"
  sandbox="allow-scripts allow-same-origin"
  referrerpolicy="no-referrer"
></iframe>

<!-- Inside kms.html, SRI-verified module load: -->
<script type="module"
  src="/artifacts/kms-a3f8b2d1.mjs"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..."
  crossorigin="anonymous"></script>
```

**Restrictions**:
- Cannot access parent origin (cross-origin isolation)
- Cross-origin security enforced by browser (even with allow-same-origin)
- Cannot access parent's cookies/localStorage (different origin)
- Script executes only if SRI hash matches

### Layer 3: Dedicated Worker
```javascript
// Inside sandboxed iframe
const worker = new Worker('/kms-worker-7f4e3a1.js')

worker.postMessage({ type: 'generateVAPID' })
worker.onmessage = (e) => {
  if (e.data.type === 'vapidGenerated') {
    const publicKey = e.data.publicKey  // Safe to share
    // Private key never leaves worker
  }
}
```

**Isolation**:
- No DOM access (cannot be phished)
- Separate thread (performance + security)
- All crypto operations happen here
- Keys stored in worker-local IndexedDB

### Layer 4: WebCrypto API
```javascript
// Inside dedicated worker
const keypair = await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-256'
  },
  false,  // NOT extractable - private key sealed in browser
  ['sign', 'verify']
)

// Store in IndexedDB (encrypted by browser)
await idb.put('vapid_keypair', {
  privateKey: keypair.privateKey,  // CryptoKey (non-extractable)
  publicKey: await crypto.subtle.exportKey('spki', keypair.publicKey)
})
```

**Guarantees**:
- Private keys cannot be exported (browser enforces)
- Signing happens inside crypto subsystem
- Keys stored in browser-encrypted IndexedDB
- Even compromised enclave cannot extract keys

## Communication Protocol

### Parent PWA → KMS Enclave

```javascript
// Main PWA requests signature
kmsIframe.contentWindow.postMessage({
  type: 'signJWT',
  requestId: 'req-123',
  payload: {
    aud: 'https://push.example.com',
    exp: 1705000000,
    relay_id: 'relay-alpha',
    sub: 'mailto:notifications@ats.run'
  }
}, 'https://kms.ats.run')

// KMS enclave responds with signature
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://kms.ats.run') return
  if (event.data.requestId === 'req-123') {
    const jwt = event.data.jwt  // Signed JWT token
    // Send to relay for notification authorization
  }
})
```

**Security properties**:
- PWA never sees private key
- PWA receives signed output only
- Requests are explicit and auditable
- No ambient authority (every request explicit)

### Supported Operations

| Operation | Input | Output | Purpose |
|-----------|-------|--------|---------|
| `generateVAPID` | None | Public key (Base64) | Create per-user VAPID keypair |
| `signJWT` | JWT payload | Signed JWT token | Authorize relay for push |
| `resetVAPID` | None | New public key | Hard revocation (key rotation) |
| `exportPublicKey` | None | Public key (Base64) | Share with push service |

**Future operations** (Signal protocol):
- `generateIdentity` - Create Signal identity key
- `signPreKey` - Sign pre-key bundle
- `x3dhKeyAgreement` - Perform X3DH handshake
- `ratchetEncrypt` - Encrypt message with Double Ratchet
- `ratchetDecrypt` - Decrypt incoming message

## Verifiable Build Pipeline

### Step 1: Reproducible Build
```bash
# Anyone can build from source
git clone https://github.com/alltheservices/kms-enclave
cd kms-enclave
git checkout v1.2.3
make reproducible-build

# Outputs deterministic artifact
ls dist/
# kms-a3f8b2d1.js
# kms-worker-7f4e3a1.js
```

**Requirements**:
- Deterministic compiler (esbuild with fixed options)
- Pinned dependencies (lockfile committed)
- Timestamp normalization (fixed SOURCE_DATE_EPOCH)
- Sorted inputs (consistent file order)

### Step 2: Content Addressing
```bash
# Hash the built artifact
sha384sum dist/kms-a3f8b2d1.js
# a3f8b2d1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0

# Filename includes hash (content-addressed)
# If code changes, hash changes, filename changes
```

### Step 3: Subresource Integrity
```javascript
// Main PWA loads KMS with SRI verification
const kmsIframe = document.createElement('iframe')
kmsIframe.src = 'https://kms.ats.run/kms-a3f8b2d1.js'
kmsIframe.integrity = 'sha384-a3f8b2d1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0'
kmsIframe.crossOrigin = 'anonymous'

// Browser refuses to execute if hash doesn't match
// Protects against:
// - Compromised CDN serving different code
// - Man-in-the-middle attacks
// - Malicious Service Worker tampering
```

### Step 4: Transparency Log
```bash
# Sign release and publish to Sigstore
cosign sign-blob dist/kms-a3f8b2d1.js

# Public Rekor entry created
# https://rekor.sigstore.dev/api/v1/log/entries?logIndex=12345678

# Anyone can verify:
cosign verify-blob \
  --signature kms-a3f8b2d1.js.sig \
  --certificate kms-a3f8b2d1.js.cert \
  kms-a3f8b2d1.js
```

**Guarantees**:
- Immutable public record of all releases
- Timestamp-proven (cannot backdate)
- Certificate transparency (who signed)
- Community-auditable

## Runtime Self-Check

```javascript
// KMS enclave verifies its own hash at startup
async function verifySelf() {
  // Fetch own script
  const response = await fetch(import.meta.url)
  const blob = await response.blob()

  // Compute hash
  const buffer = await blob.arrayBuffer()
  const hashBuffer = await crypto.subtle.digest('SHA-384', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

  // Compare to pinned hash
  const EXPECTED_HASH = 'a3f8b2d1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0'

  if (hashHex !== EXPECTED_HASH) {
    // Hash mismatch - refuse to operate
    throw new Error('KMS integrity check failed - hash mismatch')
  }

  console.log('[KMS] Self-check passed: hash verified')
}

// Run at startup before processing any requests
verifySelf().catch(err => {
  console.error('[KMS] FATAL:', err)
  // Halt all operations
  self.close()
})
```

**Protection**: Even if SRI is bypassed somehow, runtime check catches tampering.

## Threat Model

### Protected Against

✅ **Malicious PWA update**
- PWA code can be compromised without affecting keys
- Isolation prevents PWA from accessing key material
- Keys remain safe even if attacker controls main app

✅ **Supply chain attack**
- Reproducible builds allow independent verification
- SRI ensures loaded code matches verified hash
- Transparency log provides public audit trail

✅ **CDN compromise**
- SRI verification fails if CDN serves wrong file
- Content addressing prevents subtle tampering
- Browser refuses execution on hash mismatch

✅ **Service Worker tampering**
- SRI check happens before execution
- Cannot be bypassed by malicious SW
- Modification breaks hash, fails verification

### NOT Protected Against

❌ **Malicious browser extension**
- Extensions can access all browser data
- Can inject code into any page
- User must only install trusted extensions

❌ **Compromised OS**
- OS-level malware can access all memory
- Can steal keys from browser process
- User must secure their device

❌ **Physical device access**
- Attacker with physical access can extract keys
- Cold boot attacks, memory dumps, etc.
- User must physically protect device

❌ **Browser implementation bugs**
- Sandbox escape vulnerabilities
- WebCrypto API bugs
- Zero-day exploits in browser

### Assumed Trust

This architecture **requires trusting**:
- Browser vendor (Chrome/Firefox/Safari)
- Operating system (Windows/macOS/Linux/Android/iOS)
- Hardware (CPU, memory not compromised)
- User (protects device, doesn't install malware)

This architecture **does NOT require trusting**:
- ATS developers (code is verifiable)
- CDN provider (SRI catches tampering)
- Network operators (HTTPS + SRI)
- Build service (reproducible builds)

## User Verification Flow

### For Advanced Users (Full Verification)

1. **Clone KMS source**:
   ```bash
   git clone https://github.com/alltheservices/kms-enclave
   cd kms-enclave
   git checkout v1.2.3  # Specific release
   ```

2. **Reproducibly build**:
   ```bash
   make reproducible-build
   sha384sum dist/kms-a3f8b2d1.js
   ```

3. **Verify hash matches**:
   - Check hash against pinned value in PWA source
   - Check hash in transparency log entry
   - Confirm hash in loaded iframe (browser DevTools)

4. **Audit source code**:
   - Read KMS implementation (should be ~500 lines)
   - Look for backdoors, key exfiltration, etc.
   - Verify no network requests, no unexplained operations

5. **Check transparency log**:
   ```bash
   cosign verify-blob \
     --signature dist/kms-a3f8b2d1.js.sig \
     --certificate dist/kms-a3f8b2d1.js.cert \
     dist/kms-a3f8b2d1.js
   ```

6. **Make trust decision**: Use KMS or not based on audit results

### For Casual Users (Delegated Trust)

- **SRI verification**: Browser automatically checks hash
- **Transparency log**: Security researchers audit publicly
- **Open source**: Community reviews code for issues
- **Fail-safe**: Errors halt rather than proceeding unsafely

## Design Principles

1. **Simplicity**: KMS code should be simple enough to audit (~500 lines)
2. **Transparency**: All operations logged and auditable
3. **Fail secure**: Errors stop execution, never degrade security
4. **Least privilege**: KMS has minimal capabilities
5. **Defense in depth**: Multiple independent security layers
6. **User empowerment**: Advanced users can verify everything

## Integration with ATS

### OS Notifications
- KMS generates per-user VAPID keypair
- KMS signs JWT delegation tokens for relays
- KMS signs push subscription updates
- **Dependency**: Notifications require KMS to be implemented first

### Secure Messaging (Future)
- KMS generates Signal protocol identity and prekeys
- KMS performs X3DH key agreement with contacts
- KMS encrypts/decrypts messages with Double Ratchet
- **Dependency**: Messaging requires KMS + notification foundation

### Relay Authorization
- KMS signs short-lived (2-hour) JWT tokens
- Relays use JWT to authorize Web Push requests
- KMS can refuse to sign for abusive relays (soft revocation)

## Platform Support

| Platform | Support Level | Notes |
|----------|--------------|-------|
| Chrome Desktop | ✅ Full | All features work |
| Firefox Desktop | ✅ Full | All features work |
| Safari Desktop | ✅ Full | macOS 13+ required |
| Chrome Android | ✅ Full | PWA install required |
| Firefox Android | ✅ Full | PWA install required |
| Safari iOS | ⚠️ Limited | PWA install + iOS 16.4+ |
| Safari iOS (not PWA) | ❌ None | No notifications without install |

## Implementation Phases

### Phase 0: Foundation (This Document)
- Architecture documentation
- Design decisions
- Security model

### Phase 1: Basic KMS (MVP)
- Sandboxed iframe setup
- Dedicated Worker crypto operations
- VAPID keypair generation
- Basic postMessage protocol

### Phase 2: Verifiable Build (Critical)
- Reproducible build pipeline
- Content-addressed artifacts
- SRI verification flow
- Runtime self-check

### Phase 3: Transparency (Production-Ready)
- Sigstore/Rekor integration
- Public release process
- User verification guide
- Security audit

### Phase 4: Signal Protocol (Future)
- Identity key generation
- X3DH key agreement
- Double Ratchet implementation
- Session management

## Documents

- **[current-state.md](./current-state.md)**: Current key management baseline
- **[design.md](./design.md)**: Detailed design of verifiable enclave
- **[target-state.md](./target-state.md)**: Ideal KMS architecture specification
- **[plan.md](./plan.md)**: Implementation roadmap and milestones

## References

- **WebCrypto API**: [W3C Specification](https://www.w3.org/TR/WebCryptoAPI/)
- **Subresource Integrity**: [W3C SRI](https://www.w3.org/TR/SRI/)
- **Reproducible Builds**: [reproducible-builds.org](https://reproducible-builds.org/)
- **Sigstore**: [sigstore.dev](https://sigstore.dev/)
- **Sandboxed Iframes**: [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox)
- **Signal Protocol**: [signal.org/docs](https://signal.org/docs/)

## Next Steps

1. Document current state (what exists now for key management)
2. Complete detailed design (SRI flow, build pipeline, communication protocol)
3. Define target state (ideal KMS with all features)
4. Create implementation plan (phases, milestones, deliverables)
5. Prototype basic KMS (prove concept works)
6. Integrate with OS notifications
