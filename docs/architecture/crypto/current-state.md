# Browser KMS Enclave - Current State

**Date**: 2025-10-22
**Status**: Not Implemented
**Note**: This document establishes the baseline for what exists before KMS implementation

## Overview

As of this document's creation, **no isolated KMS enclave exists** in AllTheServices PWA. All cryptographic operations are performed by the main PWA code without isolation or verifiable execution guarantees.

This document serves as the baseline for understanding what needs to be built.

## Current Behavior

### Key Management
- **No dedicated KMS**: All crypto operations happen in main PWA code
- **No isolation**: Keys (if any) stored in same origin as app
- **No verification**: No way for users to audit crypto code
- **No non-extractable keys**: No use of WebCrypto's non-extractable feature

### User Experience Gaps

1. **No Trust Verification**
   - Users cannot verify crypto code matches public source
   - No way to audit key management implementation
   - Must trust PWA updates won't steal keys (if they existed)

2. **No Isolation Guarantees**
   - Compromised PWA can access all keys
   - No sandboxing of crypto operations
   - Single origin contains all code

3. **No Key Management Infrastructure**
   - No VAPID key generation (required for OS notifications)
   - No Signal protocol keys (required for secure messaging)
   - No relay authorization token signing

## Current Technical Stack

### What We Have (General PWA)
- ✅ **Service Worker**: Registered for PWA offline support
- ✅ **IndexedDB**: Available for encrypted storage
- ✅ **WebCrypto API**: Available but unused for key management
- ✅ **HTTPS**: Required by PWA, enables crypto APIs
- ✅ **Modern Browsers**: Target Chrome/Firefox/Safari with full crypto support

### What We Have (Authentication)
- ✅ **Passkey Support**: Uses WebAuthn for authentication (apps/pwa/src/lib/passkey.ts)
- ✅ **JWT Tokens**: Main-server issues JWT tokens for API access
- ✅ **Secure Storage**: Tokens stored in httpOnly cookies (server-side)

**Note**: Passkeys use browser-managed keys (WebAuthn), which are non-extractable and hardware-backed. This is a good model for what we want with the KMS, but passkeys are limited to authentication challenges and cannot be used for arbitrary signing (VAPID, Signal protocol).

### What We Don't Have (KMS Enclave)
- ❌ **Isolated KMS**: No sandboxed iframe for crypto operations
- ❌ **Dedicated Worker**: No worker thread for key operations
- ❌ **Non-Extractable Keys**: No use of WebCrypto non-extractable feature
- ❌ **VAPID Keys**: No per-user VAPID keypair for notifications
- ✅ **Audit Logging**: Tamper-evident log of key operations (Phase 1 complete - `src/audit.ts`)
- ✅ **Unlock Mechanisms**: Passkey (PRF + gate-only) and passphrase protection (Phase 1 complete - `src/unlock.ts`)
  - Passphrase: PBKDF2(600k) → HKDF → K_wrap
  - Passkey PRF: WebAuthn PRF → HKDF → K_wrap → unwrap KEK
  - Passkey Gate: WebAuthn assertion → 5-minute session with in-memory KEK
- ❌ **Verifiable Build**: No reproducible build pipeline
- ❌ **Content Addressing**: No hash-based artifact naming
- ❌ **SRI Verification**: No subresource integrity checks
- ❌ **Transparency Logs**: No public release audit trail
- ❌ **Signal Protocol Keys**: No identity/prekey infrastructure

## Related Code

### Passkey Authentication (Current)
```typescript
// apps/pwa/src/lib/passkey.ts
export async function registerPasskey(userId: string, userName: string) {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: new Uint8Array(32),
      rp: { name: 'AllTheServices' },
      user: {
        id: Uint8Array.from(userId, c => c.charCodeAt(0)),
        name: userName,
        displayName: userName
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: true,
        userVerification: 'required'
      },
      timeout: 60000,
      attestation: 'direct'
    }
  })

  return credential
}
```

**Current behavior**: Passkey creates non-extractable credential, but it's managed by browser and only usable for WebAuthn challenges, not general-purpose signing.

### Service Worker (Current)
```javascript
// apps/pwa/public/sw.js
// Currently only handles PWA caching, no crypto operations
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('ats-v1').then((cache) => {
      return cache.addAll([
        '/',
        '/index.html',
        '/manifest.json'
        // Static assets
      ])
    })
  )
})

self.addEventListener('fetch', (event) => {
  // Cache-first strategy for static assets
  // Network-first for API calls
})
```

**Current behavior**: Service Worker handles offline caching but does not participate in key management or crypto operations.

### IndexedDB Usage (Current)
```typescript
// apps/pwa/src/lib/db.ts (hypothetical - may not exist)
// Currently no structured IndexedDB usage for key storage
```

**Current behavior**: No existing IndexedDB schema for storing cryptographic keys. This will need to be created.

## Impact of No KMS Enclave

### User Security
- **No Key Isolation**: If we stored keys in PWA, malicious update could steal them
- **No Verifiable Crypto**: Users must trust developers implicitly
- **Single Point of Failure**: Compromised PWA = compromised keys
- **No Defense in Depth**: No isolation layers protecting sensitive operations

### Blocked Features

**OS Notifications** (Cannot implement without KMS):
- No VAPID key generation for Web Push
- No JWT signing for relay authorization
- No push subscription management
- **Blocker**: Must implement KMS before notifications

**Secure Messaging** (Cannot implement without KMS):
- No Signal protocol identity key generation
- No X3DH key agreement capability
- No Double Ratchet encryption/decryption
- **Blocker**: Must implement KMS before messaging

**Advanced Privacy Features** (Future):
- End-to-end encrypted profile data
- Encrypted location sharing
- Private payment authorization
- Zero-knowledge proofs

### Security Posture
- Current authentication (passkeys) is secure (WebAuthn-backed)
- Future features require app-controlled keys (not WebAuthn)
- Without KMS, those keys would be vulnerable to PWA compromise
- Cannot proceed with privacy features until KMS exists

## Baseline Metrics

| Metric | Current Value | Target |
|--------|--------------|--------|
| User-Verifiable Crypto | 0% | 100% (via SRI + reproducible builds) |
| Isolated Key Storage | 0% | 100% (sandbox + non-extractable) |
| Cryptographic Operations | WebAuthn only | WebAuthn + VAPID + Signal |
| Reproducible Builds | None | All KMS artifacts |
| Transparency Log Entries | 0 | All releases |

## Comparison: Passkeys vs. KMS Keys

| Feature | Passkeys (Current) | KMS Keys (Target) |
|---------|-------------------|-------------------|
| **Purpose** | Authentication challenges | General-purpose signing/encryption |
| **Storage** | Browser-managed, hardware-backed | Browser WebCrypto, IndexedDB |
| **Extractability** | Non-extractable ✅ | Non-extractable ✅ |
| **User Control** | Limited (browser UX) | Full (app UX) |
| **Backup** | Platform-dependent (iCloud, etc.) | App-controlled (optional) |
| **Use Cases** | Login only | Notifications, messaging, privacy |
| **Isolation** | OS-level (WebAuthn) | Browser-level (sandbox) |
| **Verifiability** | N/A (platform code) | Verifiable (SRI + reproducible) |

**Key Insight**: Passkeys demonstrate browser support for non-extractable keys but are too limited for our needs. KMS extends this model to general-purpose cryptography with user-verifiable code execution.

## Architectural Gaps

### No Separate Origin for KMS
- Current: All code runs on main PWA origin
- Target: KMS runs on `kms.ats.run` (cross-origin isolation)
- Gap: Need to set up separate subdomain and hosting

### No Sandboxed Execution Environment
- Current: All code has full origin access
- Target: KMS in sandboxed iframe with `sandbox="allow-scripts"`
- Gap: Need to implement iframe-based enclave architecture

### No Reproducible Build Pipeline
- Current: Standard PWA build (non-deterministic)
- Target: Content-addressed artifacts with fixed hashes
- Gap: Need deterministic build toolchain (esbuild with fixed config)

### No Transparency Infrastructure
- Current: No public audit trail of releases
- Target: Sigstore/Rekor entries for all KMS releases
- Gap: Need CI/CD integration with transparency log

### No Communication Protocol
- Current: N/A (no separate KMS)
- Target: postMessage protocol between PWA and KMS enclave
- Gap: Need to design and implement secure message protocol

## WebCrypto API Capabilities (Already Available)

The browser already provides all the primitives we need:

### Available Algorithms
- ✅ **ECDSA P-256**: For VAPID keys (ES256)
- ✅ **Ed25519**: For Signal identity keys and system signatures
- ✅ **X25519**: For Signal Diffie-Hellman (key agreement)
- ✅ **AES-GCM**: For symmetric encryption (Signal messages)
- ✅ **HKDF**: For key derivation (Signal ratchet)
- ✅ **SHA-256/384/512**: For hashing and HMAC

### Non-Extractable Key Support
```javascript
// This works in all modern browsers:
const keypair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,  // extractable = false → private key cannot be exported
  ['sign', 'verify']
)

// Can sign with private key:
const signature = await crypto.subtle.sign(
  { name: 'ECDSA', hash: 'SHA-256' },
  keypair.privateKey,
  data
)

// CANNOT export private key:
await crypto.subtle.exportKey('pkcs8', keypair.privateKey)
// ❌ DOMException: key is not extractable
```

**Availability**: Chrome 37+, Firefox 34+, Safari 11+ (all modern browsers)

### IndexedDB CryptoKey Storage
```javascript
// This works - CryptoKey objects can be stored in IndexedDB:
const db = await idb.open('ats-keys', 1, {
  upgrade(db) {
    db.createObjectStore('keys')
  }
})

// Store non-extractable private key
await db.put('keys', keypair.privateKey, 'vapid_private')

// Retrieve and use (but cannot export)
const privateKey = await db.get('keys', 'vapid_private')
const signature = await crypto.subtle.sign(algo, privateKey, data)  // ✅ Works
const exported = await crypto.subtle.exportKey('pkcs8', privateKey)  // ❌ Fails
```

**Availability**: All modern browsers support storing CryptoKey in IndexedDB

## Browser Support Matrix

| Browser | WebCrypto | Non-Extractable | IndexedDB | Sandbox iframe | Workers |
|---------|-----------|-----------------|-----------|----------------|---------|
| Chrome 120+ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Firefox 120+ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Safari 17+ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Chrome Android | ✅ | ✅ | ✅ | ✅ | ✅ |
| Safari iOS 16.4+ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Conclusion**: All target browsers support the required primitives. No polyfills needed.

## Next Steps

1. **Design Phase**: Define KMS enclave architecture, SRI flow, build pipeline
2. **Target State**: Document ideal KMS with all features and specifications
3. **Implementation Planning**: Break down work into phases (basic KMS → verifiable → production)
4. **Prototype**: Prove sandboxed iframe + WebCrypto works as expected
5. **Integrate**: Use KMS for VAPID keys in OS notifications feature

## References

### Existing ATS Code
- **Passkey Library**: `apps/pwa/src/lib/passkey.ts` (WebAuthn implementation)
- **Service Worker**: `apps/pwa/public/sw.js` (PWA caching)
- **Main-server Auth**: `apps/main-server/internal/auth/` (JWT token issuance)

### Web Standards
- **WebCrypto API**: [W3C Specification](https://www.w3.org/TR/WebCryptoAPI/)
- **IndexedDB**: [W3C Specification](https://www.w3.org/TR/IndexedDB/)
- **WebAuthn**: [W3C Specification](https://www.w3.org/TR/webauthn-2/) (passkeys)
- **Service Workers**: [W3C Specification](https://www.w3.org/TR/service-workers/)

### Security Research
- **Sandboxed Iframes**: [HTML Spec - iframe sandbox](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox)
- **SRI**: [W3C Subresource Integrity](https://www.w3.org/TR/SRI/)
- **Reproducible Builds**: [reproducible-builds.org](https://reproducible-builds.org/)

## Design Questions

Before moving to implementation, we need to answer:

1. **KMS Hosting**: Where should `kms.ats.run` be hosted?
   - Static CDN (Cloudflare, Fastly)?
   - Object storage (S3, R2)?
   - Self-hosted (Nginx)?

2. **Build Pipeline**: What tools for reproducible builds?
   - esbuild (fast, deterministic)?
   - Rollup (mature, well-documented)?
   - Custom (full control)?

3. **Transparency Log**: Which service?
   - Sigstore (official, free)?
   - Custom transparency server (more control)?
   - Git tags only (simple, less verifiable)?

4. **Key Backup**: Should users be able to backup keys?
   - No backup (simple, most secure)?
   - Encrypted backup with passphrase (convenience vs security)?
   - Multi-device sync (complex, highest UX)?

5. **Worker vs. Iframe Only**: Do we need both?
   - Iframe + Worker (maximum isolation)?
   - Iframe only (simpler, still isolated)?
   - Performance vs. security trade-off?

**Recommendation**: These decisions should be made during the design phase based on threat model priorities and implementation complexity.
