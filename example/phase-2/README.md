# Phase 1 Demo: Complete VAPID & Push Notification System

**Interactive demonstration of the KMS V2 with complete VAPID integration for Web Push notifications**

This demo showcases the entire lifecycle from initial setup through JWT signing, with cross-origin isolation, lease-based authorization, and tamper-evident audit logging.

## Quick Start

```bash
# Terminal 1: Start KMS enclave server
pnpm demo:phase-1:kms
# → http://localhost:5174

# Terminal 2: Start parent PWA server
pnpm demo:phase-1:parent
# → http://localhost:5173

# Open http://localhost:5173 in your browser
```

## Overview

This is a **production-quality demonstration** of a browser-based Key Management System with:

- **Cross-origin isolation** enforced by two separate dev servers
- **VAPID key management** for Web Push notifications
- **Lease-based authorization** for background JWT signing without user authentication
- **Tamper-evident audit log** with cryptographic chain verification
- **WebAuthn integration** with Passkey support (PRF and Gate modes)
- **Push notification** subscription and testing with relay validation
- **Rate-limited quotas** for token issuance and sending

## Architecture

### Two-Server Cross-Origin Setup

The demo runs on **two separate Vite dev servers** to enforce browser-level security isolation:

```
┌─────────────────────────────────────────────────────────────────┐
│               Parent PWA (localhost:5173)                       │
│  ┌─────────────────────┐  ┌──────────────────────────────────┐  │
│  │  LEFT PANE          │  │  RIGHT PANE                      │  │
│  │  - Setup            │  │  - VAPID Public Key              │  │
│  │  - Push Subscribe   │  │  - Active Leases (with status)   │  │
│  │  - Lease Operations │  │  - Complete Audit Log            │  │
│  │  - Test Push        │  │    (persists across refreshes)   │  │
│  │  - VAPID Regenerate │  │  - Chain verification            │  │
│  │  - Reset Demo       │  │  - Expandable entries            │  │
│  └─────────────────────┘  └──────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │ postMessage (cross-origin)
                         │
┌────────────────────────▼────────────────────────────────────────┐
│           KMS Enclave Iframe (localhost:5174)                   │
│  - Authentication modals (passphrase/WebAuthn)                  │
│  - Non-extractable ECDSA P-256 keys                             │
│  - IndexedDB storage (inaccessible to parent)                   │
│  - Dedicated Web Worker for crypto operations                   │
│  - Tamper-evident audit log (KIAK/UAK/LAK signers)              │
└─────────────────────────────────────────────────────────────────┘
```

### Communication Flow

```
Parent PWA (localhost:5173)
  ↓ postMessage (cross-origin, origin-validated)
KMS Client (iframe @ localhost:5174)
  ↓ postMessage (to Worker)
KMS Worker (Dedicated Worker)
  ↓ WebCrypto API + IndexedDB
```

## Key Features

### 🔐 Authentication Methods

1. **Passphrase**
   - PBKDF2 (100,000 iterations) with salt
   - Key Check Value (KCV) verification
   - MKEK derived from passphrase

2. **WebAuthn (PRF Extension)**
   - Deterministic key derivation from PRF output
   - No random Master Secret stored
   - MKEK = PRF output (32 bytes)

3. **WebAuthn (Gate Mode)**
   - Passkey as authentication gate
   - Random Master Secret generated
   - Wrapped with MKEK derived from PRF

**Setup Flow**: Opens KMS in new window (first-party context required for WebAuthn)

### 🔑 VAPID Key Management

- **Automatic generation** during setup (ECDSA P-256)
- **Non-extractable private key** (browser-enforced)
- **Public key export** in raw format (65 bytes, uncompressed) for push subscriptions
- **Regeneration** capability with automatic lease invalidation
- **Key ID (kid)** for version tracking

### 📲 Push Notification System

**Subscription:**
- Service worker registration
- Browser push subscription with VAPID public key
- Subscription stored in IndexedDB with VAPID key association
- Endpoint validation before JWT signing

**Test Flow:**
1. Get active lease for current VAPID key
2. Issue JWT with lease (no unlock required)
3. **Validate JWT** (simulates relay server):
   - Format validation (header.payload.signature)
   - Algorithm check (ES256)
   - Claims validation (exp, aud, sub)
   - Signature verification with VAPID public key
4. Send mock push to service worker
5. Service worker displays notification

### 🎫 Lease System

Time-limited authorization tokens that enable background JWT signing without user authentication.

**Lease Types:**
- **Auto-extendable** - Can extend without re-authentication
- **Non-extendable** - Requires authentication to extend

**Lease Architecture:**
```
Master Secret (MS)
  ↓ HKDF + Lease Salt (random, per-lease)
SessionKEK (unique per lease)
  ↓ wrapKey
VAPID Private Key (wrapped for this lease)
  ↓ stored in lease
```

**Rate Limiting Quotas:**
- Tokens per hour
- Sends per minute (sustained)
- Burst sends (spike allowance)
- Sends per minute per endpoint

**Lease Operations:**
- Create extendable/non-extendable lease
- Extend single lease or batch extend all
- Extend with authentication (for non-extendable)
- Verify lease validity (kid match, expiration check)
- Clear invalid/stale leases

**JWT Signing from Lease:**
- Issue 1-10 JWTs per request
- No unlock required (uses SessionKEK to unwrap VAPID key)
- Automatic endpoint validation
- JWT structure:
  - **aud**: Push service origin (e.g., `https://fcm.googleapis.com`)
  - **sub**: Push endpoint URL
  - **exp**: Expiration (2 minutes from issue)
  - **jti**: Unique identifier

### 📜 Audit Logging

**Tamper-Evident Chain:**
- **First entry**: KIAK initialization (seqNum #1, created automatically)
- **Every operation** logged with:
  - Sequence number (monotonic)
  - Operation type
  - Signer (KIAK, UAK, or LAK)
  - Previous hash (links to prior entry)
  - Chain hash (hash of current entry)
  - Ed25519 signature
  - Timestamp and metadata

**Signer Types:**
- **KIAK** (KMS Instance Audit Key) - System operations (init, reset)
- **UAK** (User Audit Key) - User-authenticated operations (setup, unlock, generateVAPID, createLease)
- **LAK** (Lease Audit Key) - Lease-based operations (signJWT, extendLease without auth)

**Logged Operations:**
```
init, setup, unlock, lock, reset
generateVAPID, regenerateVAPID
signJWT, issueLease, extendLease, revokeLease
setPushSubscription, removePushSubscription
```

**Persistence:**
- Survives page refreshes (loaded from IndexedDB)
- Complete history from KIAK init onwards
- Chain verification on load

## UI Layout

### Left Pane: Operations

**1. Setup Authentication**
- Shows enrolled methods: Passphrase ✓, WebAuthn ✓
- Buttons to add additional methods
- Opens new window on localhost:5174 (first-party for WebAuthn)

**2. Push Notification Operations**
- Subscribe/Unsubscribe to push
- Status display: ✅ Subscribed (endpoint ID, creation time)

**3. VAPID Lease Operations**
- Create extendable/non-extendable lease
- Extend all leases (with/without authentication)
- Verify all leases (kid match, expiration check)
- Clear invalid leases
- Issue JWTs from lease (configurable count 1-10)

**4. Test Push Notification**
- End-to-end test: get lease → issue JWT → validate → send push
- Validates JWT like a relay server would
- Service worker displays notification

**5. VAPID Key Management**
- Regenerate VAPID key button
- **Warning**: Invalidates all existing leases (kid mismatch)

**6. Reset Demo** (bottom, red button)
- Clears all KMS IndexedDB stores
- Reloads page for fresh state
- Next setup creates new KIAK (new audit chain)

### Right Pane: VAPID Key & Audit Log

**VAPID Key Section:**
- **Key ID (kid)**: Version identifier
- **Public Key**: Base64url-encoded (65 bytes, uncompressed EC point)
- **Active Leases**: List with validation status
  - ✅ Valid / ❌ Invalid indicator
  - Kid match check (detects stale leases after regeneration)
  - Expiration time
  - User ID

**Audit Log Section:**
- **Complete history** from KIAD init (seqNum #1)
- **Reverse chronological** order (newest first)
- **Color-coded by signer**:
  - 🟠 KIAK (orange) - System
  - 🔵 UAK (blue) - User authenticated
  - 🟢 LAK (green) - Lease based
- **Displays**: seqNum, signer, timestamp, operation, user, requestId, kid, chainHash, signature
- **Expandable entries**: Click to see full JSON
- **Persists across refreshes**: Loaded from IndexedDB on startup

## Key Workflows

### 1. First-Time Setup

```
1. User clicks "Setup with Passphrase" or "Setup with WebAuthn"
2. New window opens on localhost:5174 (first-party context)
3. User enters passphrase or performs WebAuthn ceremony
4. KMS generates:
   - Master Secret (MS) - random or PRF-derived
   - MKEK - from passphrase/PRF
   - VAPID keypair - ECDSA P-256, non-extractable
5. Audit log entries created:
   - #1: KIAK init (if first time)
   - #2: setup (UAK-signed)
   - #3: generateVAPID (UAK-signed)
6. Window sends completion message to parent
7. Parent displays:
   - Enrolled methods (✓)
   - VAPID public key
   - Empty lease list
```

### 2. Subscribe to Push Notifications

```
1. User clicks "Subscribe to Push"
2. Browser permission prompt (if not granted)
3. Service worker registered
4. Browser creates push subscription with:
   - VAPID public key (from KMS)
   - Endpoint URL (from push service)
5. Subscription stored in KMS IndexedDB
6. Status updates: ✅ Subscribed
   - Endpoint ID displayed
   - Creation timestamp shown
```

### 3. Create Lease & Issue JWTs

```
1. User clicks "Create Extendable Lease" (or Non-extendable)
2. KMS opens modal for authentication:
   - Passphrase input, OR
   - WebAuthn passkey prompt
3. Lease created with:
   - TTL: 30 days (720 hours)
   - SessionKEK: HKDF(MS, lease_salt)
   - VAPID private key wrapped with SessionKEK
   - Rate limit quotas:
     - 100 tokens/hour
     - 10 sends/minute (sustained)
     - 50 burst sends
     - 5 sends/minute/endpoint
4. Lease displayed in right pane with validation status
5. User selects JWT count (1-10) and clicks "Issue JWTs"
6. KMS issues JWTs WITHOUT unlock:
   - Unwraps VAPID private key with SessionKEK
   - Signs JWT with ES256
   - Returns JWTs to parent
7. JWTs displayed with exp, jti
8. Audit log shows LAK-signed entries (lease-based, no unlock)
```

### 4. Send Test Push Notification

```
1. User clicks "Send Test Push Notification"
2. KMS gets active lease for current VAPID key
3. Issues JWT with lease (no unlock)
4. Parent validates JWT:
   - Format: 3 parts (header.payload.signature)
   - Algorithm: ES256
   - Claims: exp (not expired), aud (matches), sub (matches endpoint)
   - Signature: Verifies with VAPID public key
5. If valid:
   - Sends mock push to service worker
   - Service worker displays notification
   - Alert confirms success
6. If invalid:
   - Alert shows validation error
```

### 5. Extend Leases

**Without Authentication (auto-extendable only):**
```
1. User clicks "Extend All Leases"
2. KMS extends auto-extendable leases by 30 days
3. Non-extendable leases skipped
4. Status updated in lease list
5. Audit log: LAK-signed entries (no unlock)
```

**With Authentication (all leases):**
```
1. User clicks "Extend All Leases with Auth"
2. KMS opens modal for authentication
3. User unlocks with passphrase/WebAuthn
4. All leases extended by 30 days (including non-extendable)
5. Status updated in lease list
6. Audit log: UAK-signed entries (user authenticated)
```

### 6. Regenerate VAPID Key

```
1. User clicks "Regenerate VAPID Key"
2. Confirmation warning: "This will invalidate all existing leases"
3. KMS opens modal for authentication
4. User unlocks
5. Old VAPID key deleted
6. New VAPID keypair generated (ECDSA P-256)
7. All leases invalidated (kid mismatch)
8. New public key displayed
9. Lease list shows all as ❌ Invalid (stale kid)
10. Audit log: regenerateVAPID operation (UAK-signed)
```

### 7. Verify Leases

```
1. User clicks "Verify All Leases"
2. KMS checks each lease:
   - Kid matches current VAPID key?
   - Expiration > now?
   - SessionKEK can unwrap VAPID key?
3. Status updated in lease list:
   - ✅ Valid (green)
   - ❌ Invalid (red, with reason)
4. Summary alert shows valid/invalid counts
```

### 8. Clear Invalid Leases

```
1. User clicks "Clear Invalid Leases"
2. KMS removes all invalid leases:
   - Stale kid (after VAPID regeneration)
   - Expired TTL
3. Lease list updates (invalid leases removed)
4. Alert confirms removal count
```

### 9. Reset Demo

```
1. User clicks "Reset Demo" (red button, bottom left)
2. Confirmation prompt: "This will delete all KMS data"
3. User confirms
4. KMS clears all IndexedDB stores:
   - config
   - keys
   - audit
   - leases
   - vapid
   - pushSubscriptions
5. Page reloads (hard refresh recommended)
6. Fresh state:
   - No enrolled methods
   - Empty audit log
   - No VAPID key
   - No leases
7. Next setup creates new KIAK (new audit chain starts at seqNum #1)
```

## Technical Implementation Highlights

### Cross-Origin Isolation

- **Parent**: `http://localhost:5173` (Vite dev server)
- **KMS**: `http://localhost:5174` (separate Vite dev server)
- **CSP headers**:
  - KMS: `frame-ancestors http://localhost:5173` (only allow parent)
  - Parent: `frame-src http://localhost:5174` (only allow KMS iframe)
- **postMessage** with origin validation on both sides
- **Browser enforces**: Parent cannot access KMS IndexedDB

### Non-Extractable Keys

```javascript
// Private key created with extractable: false
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,  // ← Browser enforces: cannot export
  ['sign']
);

// Stored in IndexedDB as CryptoKey object
await idb.put('keys', keyPair.privateKey, 'vapid-private');

// Used via handle only (no raw export possible)
const signature = await crypto.subtle.sign(
  { name: 'ECDSA', hash: 'SHA-256' },
  privateKey,  // ← Handle, not raw bytes
  data
);
```

**Browser enforcement**: Even if KMS code is compromised, private keys cannot be extracted from IndexedDB. They can only be used for their designated operations (signing).

### Session Key Architecture

```
Master Secret (MS) - 32 bytes random
  ↓ stored wrapped with MKEK
  ↓ MKEK = PBKDF2(passphrase) or WebAuthn PRF

Per-Lease Key Derivation:
  MS + lease_salt (random per lease)
    ↓ HKDF-SHA-256
  SessionKEK (32 bytes, unique per lease)
    ↓ AES-GCM wrapKey
  VAPID Private Key (wrapped for this lease)
    ↓ stored in lease object

JWT Signing:
  SessionKEK unwrapKey VAPID Private Key
    ↓ ECDSA sign
  JWT Signature
```

**Security properties**:
- Each lease has unique SessionKEK (derived from random salt)
- SessionKEK never leaves Worker memory
- VAPID key can be used without unwrapping MS (SessionKEK is sufficient)
- Worker restart clears all SessionKEKs (but leases persist in IndexedDB)

### Service Worker Integration

```javascript
// service-worker.js
self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};

  // Display notification
  event.waitUntil(
    self.registration.showNotification(data.title || 'Test Push', {
      body: data.body || 'This is a test notification',
      icon: '/icon.png',
      badge: '/badge.png',
      data: data
    })
  );
});

// Handle mock push from parent (for testing)
self.addEventListener('message', (event) => {
  if (event.data.type === 'MOCK_PUSH') {
    const { title, body } = event.data.payload;
    self.registration.showNotification(title, { body });
  }
});
```

### WebAuthn First-Party Context

WebAuthn requires user gesture in first-party context. The demo handles this by:

1. **Setup/Unlock**: Opens new window on `localhost:5174`
2. **New window UI**:
   - Passphrase input field (for passphrase method)
   - "Use Passkey" button (for WebAuthn method)
3. **User action**: Triggers WebAuthn ceremony in first-party context
4. **Completion**: Window sends postMessage to parent, then closes

This is **required** for WebAuthn API to work. Iframes (even cross-origin) may not have permission for certain WebAuthn operations.

## Security Properties

### What This Protects Against

✅ **Malicious parent PWA updates**
- Parent cannot access KMS IndexedDB (cross-origin isolation)
- Parent cannot extract private keys (non-extractable)
- Parent cannot forge audit log (Ed25519 signatures)

✅ **Compromised CDN or network**
- Leases are time-limited (30 days default)
- Rate limiting prevents abuse
- Audit log records all operations

✅ **Session hijacking**
- Each lease has unique SessionKEK
- SessionKEKs cleared on worker restart
- Leases can be revoked

### What This Does NOT Protect Against

❌ **Malicious browser extensions**
- Extensions run in same process, can access all data

❌ **Compromised OS**
- OS can read all memory and storage

❌ **Physical device access**
- Cold boot attacks, memory dumps, etc.

❌ **Browser implementation bugs**
- Sandbox escapes, crypto bugs, etc.

### Trust Assumptions

**Must trust**:
- Browser vendor (Chrome, Firefox, Safari)
- Operating system
- Hardware (CPU, secure enclave if used)
- User's device security (screen lock, malware protection)

**Do NOT need to trust** (verifiable):
- CDN (integrity checked by browser SRI)
- Network operators (HTTPS + SRI)
- ATS developers (code is open source, auditable)
- Build service (reproducible builds enable verification)

## File Structure

```
example/phase-1/
├── index.html              # Parent PWA entry point
├── kms.html                # KMS iframe with authentication modals
├── parent.ts               # Parent PWA logic (1,520 lines)
├── kms.ts                  # KMS iframe bootstrap (40 lines)
├── push-utils.ts           # Push notification utilities (258 lines)
├── service-worker.js       # Service worker for push events (108 lines)
├── styles.css              # UI styling (993 lines)
│
├── src/                    # Frozen Phase 1 KMS implementation
│   ├── worker.ts           # Main worker orchestrator (1,846 lines)
│   ├── client.ts           # RPC client (iframe ↔ worker) (1,237 lines)
│   ├── kms-user.ts         # High-level API for parent PWA (1,890 lines)
│   ├── unlock.ts           # Authentication logic (458 lines)
│   ├── audit.ts            # Audit logging with KIAK/LAK (614 lines)
│   ├── storage.ts          # IndexedDB operations (649 lines)
│   ├── crypto-utils.ts     # Crypto primitives (415 lines)
│   ├── types.ts            # TypeScript type definitions (50 lines)
│   ├── rpc-validation.ts   # RPC request validation (631 lines)
│   ├── error-utils.ts      # Error formatting (95 lines)
│   ├── storage-types.ts    # Storage type definitions (50 lines)
│   └── webauthn-types.ts   # WebAuthn type definitions (105 lines)
│
├── dist-parent/            # Build output for parent PWA
├── dist-kms/               # Build output for KMS iframe
│
└── README.md               # This file
```

**Total**: ~8,600 lines of production-quality TypeScript implementing a complete KMS with VAPID integration.

## Why This Demo is Special

### Production-Quality Code

This is not a toy demo. It implements:

- **Complete VAPID workflow** from setup to push delivery
- **Industrial-strength crypto** (PBKDF2, ECDSA P-256, HKDF, AES-GCM, Ed25519)
- **Tamper-evident audit log** with chain verification
- **Lease-based authorization** for background operations
- **Rate limiting** to prevent abuse
- **Cross-origin isolation** with browser-enforced boundaries
- **WebAuthn integration** with PRF and Gate modes
- **Push notification** subscription and testing
- **JWT validation** simulating relay server behavior

### Frozen Snapshot

The `src/` directory is a **frozen snapshot** of the KMS V2 implementation as of Phase 1 completion. This means:

- Demo will **not break** when Phase 2 development begins
- Serves as **historical reference** for Phase 1 capabilities
- Can be **independently tested** without worrying about main codebase changes
- **Self-contained** - all dependencies included

### Demonstration Value

This demo shows:

- How **cross-origin isolation** provides security without server-side trust
- How **non-extractable keys** prevent exfiltration even with compromised code
- How **lease-based authorization** enables background operations without user auth
- How **audit logging** provides tamper-evident history
- How **WebAuthn** integrates with browser-based key management
- How **VAPID** enables Web Push without Firebase or third-party services
- How **JWT validation** can be done client-side for testing

Perfect for demos, testing, understanding the architecture, and as a reference implementation for production deployment.

## Troubleshooting

### Demo doesn't start

**Problem**: Servers won't start or ports are in use

**Solution**:
```bash
# Kill existing processes on demo ports
lsof -ti:5173 | xargs kill -9
lsof -ti:5174 | xargs kill -9

# Restart
pnpm demo:phase-1:parent &
pnpm demo:phase-1:kms &
```

### WebAuthn not working

**Problem**: Passkey prompts don't appear

**Causes**:
- Browser doesn't support WebAuthn
- Browser doesn't support PRF extension (use Gate mode instead)
- Not running on localhost (WebAuthn requires secure context)
- Pop-up blocked (check browser settings)

**Solution**:
- Use Chrome 120+ or Firefox 120+
- Enable pop-ups for localhost:5173
- Try Gate mode if PRF mode fails

### Leases become invalid after refresh

**Problem**: All leases show ❌ Invalid after page refresh

**Cause**: Worker restart clears SessionKEKs from memory

**This is EXPECTED**. SessionKEKs are intentionally not persisted. To use leases after refresh:

1. Click "Extend All Leases with Auth"
2. Unlock with passphrase/WebAuthn
3. Leases re-derived, SessionKEKs restored

OR:

1. Create new lease after refresh
2. Old leases still in IndexedDB but not usable (no SessionKEK)

### Push notifications not showing

**Problem**: Test push doesn't display notification

**Checks**:
1. Browser notification permission granted?
2. Service worker registered? (check DevTools → Application → Service Workers)
3. Push subscription active? (check status in UI)
4. JWT validation passed? (check console for validation errors)

**Solution**:
- Grant notification permission when prompted
- Refresh page to re-register service worker
- Re-subscribe to push if subscription lost

### Audit log disappeared

**Problem**: Audit log is empty after page refresh

**Cause**: IndexedDB was cleared (Reset Demo clicked)

**This is PERMANENT**. Reset Demo clears ALL IndexedDB data including audit log.

To recover:
- You can't. Audit log is gone.
- Start fresh: Run setup again (creates new KIAK at seqNum #1)

### VAPID key changed unexpectedly

**Problem**: VAPID public key different after refresh, all leases invalid

**Cause**: Demo was reset or VAPID regenerated

**Check audit log**:
- Look for "regenerateVAPID" operation
- Or "init" operation with new timestamp (demo was reset)

**Solution**:
- If intentional: Create new leases with new key
- If unintentional: You may have clicked "Regenerate VAPID Key" by mistake

## Next Steps

After exploring this demo, you can:

1. **Review the source code** in `src/` to understand implementation
2. **Run the tests** in `/tests/v2/` (from project root: `pnpm test`)
3. **Read the architecture docs** in `/docs/architecture/crypto/`
4. **Try Phase 0 demo** for simpler VAPID-only demo (from project root: `pnpm demo:phase-0`)
5. **Build for production** (see main project README for build instructions)

## Support

For issues or questions:

- Check the **audit log** for error details
- Check **browser console** for error messages
- Review **architecture docs** at `/docs/architecture/crypto/`
- Open issue at https://github.com/Lukium/ats-kms-enclave/issues

---

**Built with security and verifiability in mind** 🔐

This demo represents Phase 1 of the AllTheServices Key Management System, demonstrating browser-based cryptographic operations with cross-origin isolation, non-extractable keys, and tamper-evident audit logging.
