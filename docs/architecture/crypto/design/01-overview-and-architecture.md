# Overview and Architecture

## Design Goals

### Primary Goals
1. **Verifiability**: Users (or security researchers on their behalf) can verify KMS code matches public source
2. **Isolation**: Compromised main PWA cannot access cryptographic keys
3. **Non-Extractability**: Private keys physically cannot leave the crypto subsystem
4. **Transparency**: All releases publicly auditable via transparency log
5. **Simplicity**: KMS code simple enough to audit (~500 lines total)

### Secondary Goals
6. **Performance**: Crypto operations complete in <100ms
7. **Reliability**: Graceful degradation if KMS unavailable
8. **Maintainability**: Clear upgrade path for new features
9. **Platform Coverage**: Works on 95%+ of target browsers

### Non-Goals
- Hardware attestation (cannot prove which code runs on device)
- Remote attestation (cannot prove to third party)
- Perfect security (defense in depth, not absolute)
- Backward compatibility (greenfield implementation)

## Critical Concept: Separate Application

**The KMS enclave is a completely separate web application**, not a component of the main PWA:

- **Separate origin**: `https://kms.ats.run` (dedicated subdomain)
- **Separate codebase**: Own repository, own build pipeline, own releases
- **Separate hosting**: Static artifacts only, immutable deploys
- **Minimal API**: Tiny surface area consumed via `postMessage`

This separation provides:
- **Real isolation**: Different origin = browser enforces security boundaries
- **Verifiability**: Small, focused codebase is easier to audit
- **Independent updates**: Enclave can be updated without touching PWA
- **Defense in depth**: Compromised PWA cannot access enclave internals

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Main PWA (allthe.services)                         │
│                          [Separate Application]                        │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Business Logic & UI                         │  │
│  │                                                                  │  │
│  │  - User interface components                                     │  │
│  │  - Application state management                                  │  │
│  │  - API communication                                             │  │
│  │  - Feature logic (maps, broadcasts, etc.)                        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              ↓ postMessage ↓                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              KMS Client Stub (Request/Response)                  │  │
│  │                                                                  │  │
│  │  class KMSClient {                                               │  │
│  │    async version() → Promise<{ hash, commit }>                   │  │
│  │    async generate({ alg, purpose }) → Promise<{ kid }>           │  │
│  │    async publicKey(kid) → Promise<ArrayBuffer>                   │  │
│  │    async sign(kid, bytes) → Promise<ArrayBuffer>                 │  │
│  │    async verify(pub, bytes, sig) → Promise<boolean>              │  │
│  │  }                                                               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              ↓ iframe boundary ↓                       │
└────────────────────────────────────────────────────────────────────────┘

                ↓ Cross-Origin Isolation (Browser-Enforced) ↓

┌────────────────────────────────────────────────────────────────────────┐
│                   KMS Enclave (kms.ats.run)                            │
│                   [Separate Application - Own Repo]                    │
│                                                                        │
│  <iframe src="https://kms.ats.run/kms.html"                            │
│          sandbox="allow-scripts allow-same-origin">                    │
│            Isolation via cross-origin + CSP, not sandbox alone         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    KMS Main Thread (Iframe)                      │  │
│  │                                                                  │  │
│  │  - Receive postMessage requests from parent                      │  │
│  │  - Validate request structure + origin check                     │  │
│  │  - Forward to Dedicated Worker                                   │  │
│  │  - Return signed results to parent                               │  │
│  │  - Runtime self-check (hash verification)                        │  │
│  │  - Expose version endpoint for UI                                │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                           ↓ Worker boundary ↓                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                  KMS Worker (Dedicated Worker)                   │  │
│  │                                                                  │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │            WebCrypto Operations (Isolated)                 │  │  │
│  │  │                                                            │  │  │
│  │  │  - VAPID keypair generation (ECDSA P-256)                  │  │  │
│  │  │  - JWT signing (ES256 algorithm)                           │  │  │
│  │  │  - Signal identity key generation (Ed25519, future)        │  │  │
│  │  │  - X3DH key agreement (Curve25519, future)                 │  │  │
│  │  │  - Double Ratchet crypto (AES-GCM + HKDF, future)          │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  │                                                                  │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │         IndexedDB Key Storage (Non-Extractable)            │  │  │
│  │  │                                                            │  │  │
│  │  │  Database: 'ats-kms'                                       │  │  │
│  │  │  Store: 'keys'                                             │  │  │
│  │  │                                                            │  │  │
│  │  │  - vapid_keypair: { privateKey: CryptoKey (sealed),        │  │  │
│  │  │                     publicKey: Base64,                     │  │  │
│  │  │                     createdAt: timestamp }                 │  │  │
│  │  │                                                            │  │  │
│  │  │  - signal_identity: { privateKey: CryptoKey (sealed),      │  │  │
│  │  │                       publicKey: Base64,                   │  │  │
│  │  │                       createdAt: timestamp } (future)      │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  Security Properties:                                                  │
│  - Cross-origin isolation (cannot access parent cookies/localStorage)  │
│  - Sandboxed (no popups, no navigation, CSP-restricted network)        │
│  - No DOM access in Worker (cannot be phished)                         │
│  - Non-extractable keys (browser enforces, cannot export)              │
│  - SRI-verified code (browser rejects if hash mismatch)                │
└────────────────────────────────────────────────────────────────────────┘
```
