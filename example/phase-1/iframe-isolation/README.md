# Phase 1 Demo: Iframe Isolation

## Overview

This demo demonstrates the **core security principle** of the KMS architecture: **cross-origin isolation** between a parent PWA and the KMS enclave running in a sandboxed iframe.

### What This Demo Proves

1. **Parent PWA cannot access KMS internals**: Private keys, IndexedDB, and crypto operations are completely isolated
2. **postMessage-only communication**: Parent and KMS communicate exclusively via message passing
3. **Secrets never touch the parent**: Passkey/passphrase setup, key generation, and signing all happen in the iframe
4. **Parent receives only public outputs**: JWT signatures, public keys - never private keys
5. **Iframe handles all crypto validation**: Lock/unlock operations are validated entirely within the KMS
6. **Disk encryption via memory-only KEK**: Even if OS is compromised and IndexedDB is dumped, private keys cannot be unwrapped without user's passphrase/passkey
7. **Tamper-evident audit log**: All operations are logged in a cryptographic chain - compromised KMS cannot hide malicious operations without detection

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
│  │  │         Memory (Volatile - Cleared on Lock)       │  │  │
│  │  │                                                   │  │  │
│  │  │  KEK (Key Encryption Key) - NEVER ON DISK         │  │  │
│  │  │    ├─ Derived from passphrase (PBKDF2)            │  │  │
│  │  │    └─ Derived from passkey PRF output             │  │  │
│  │  │                                                   │  │  │
│  │  │  Used to wrap/unwrap private keys                 │  │  │
│  │  │  Cleared from memory when locked                  │  │  │
│  │  └───────────────────────────────────────────────────┘  │  │
│  │                          ↓                              │  │
│  │  ┌───────────────────────────────────────────────────┐  │  │
│  │  │        WebCrypto Operations (Sealed)              │  │  │
│  │  │                                                   │  │  │
│  │  │  - Passkey/passphrase setup (gate mode)           │  │  │
│  │  │  - VAPID keypair generation (non-extractable)     │  │  │
│  │  │  - JWT signing (ES256)                            │  │  │
│  │  │  - Key wrapping with KEK (AES-GCM)                │  │  │
│  │  │  - Key unwrapping with KEK (decrypt + verify)     │  │  │
│  │  │                                                   │  │  │
│  │  │  All private keys: extractable: false             │  │  │
│  │  └───────────────────────────────────────────────────┘  │  │
│  │                          ↓                              │  │
│  │  ┌───────────────────────────────────────────────────┐  │  │
│  │  │    IndexedDB Storage (Security-Appropriate)       │  │  │
│  │  │                                                   │  │  │
│  │  │  Wrapped private keys (AES-GCM encrypted)         │  │  │
│  │  │  Public keys (plaintext - no secrets)             │  │  │
│  │  │  Passkey config (credentialId, salt)              │  │  │
│  │  │  Audit log (ES256 signed, plaintext)              │  │  │
│  │  │  Audit signing key (non-extractable)              │  │  │
│  │  │                                                   │  │  │
│  │  │  ❌ KEK (NEVER STORED - memory only)               │  │  │
│  │  │  ❌ Passphrase (NEVER STORED - derived only)       │  │  │
│  │  │  ❌ PRF output (NEVER STORED - derived only)       │  │  │
│  │  └───────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  Parent PWA CANNOT access:                                    │
│    ❌ Worker memory or state (KEK, unwrapped keys)             │
│    ❌ IndexedDB (different origin context)                     │
│    ❌ Private keys (non-extractable + worker isolation)        │
│    ❌ Passphrase or PRF outputs                                │
│                                                               │
│  Compromised OS with disk access CANNOT:                      │
│    ❌ Unwrap private keys (KEK not on disk)                    │
│    ❌ Read audit log plaintext (encrypted with KEK)            │
│    ❌ Derive KEK (needs passphrase or passkey PRF)             │
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

### 4. Disk Encryption via Memory-Only KEK (Critical Defense Layer)

The KEK (Key Encryption Key) is **NEVER stored on disk** - it only exists in Worker memory:

**KEK Lifecycle:**
1. **Derivation**: KEK is derived from passphrase (PBKDF2) or passkey PRF output during unlock
2. **Memory Storage**: KEK exists only in Worker memory (`_wrappingKeyRef` variable)
3. **Usage**: All private keys are wrapped with KEK before storing in IndexedDB
4. **Lock**: KEK is cleared from memory (`_wrappingKeyRef = null`)
5. **Re-derivation**: User must re-authenticate to derive KEK again

**What This Protects Against:**

| Threat | Protection | Details |
|--------|-----------|---------|
| **Compromised OS (disk access)** | ✅ Protected | Attacker sees wrapped keys in IndexedDB but cannot unwrap without KEK |
| **Cold boot attack** | ✅ Protected | Wrapped keys are useless without KEK from passphrase/passkey |
| **Memory dump (while locked)** | ✅ Protected | KEK is cleared from memory when locked |
| **IndexedDB export** | ✅ Protected | All private keys and audit log are AES-GCM encrypted |
| **Database forensics** | ✅ Protected | Cannot derive KEK from stored data (no KEK on disk) |

**Attack Requirements:**

To unwrap private keys, attacker needs **BOTH**:
- Disk access (to get wrapped keys from IndexedDB)
- **AND** user's passphrase/passkey (to derive KEK)
- **OR** memory access while KMS is unlocked (live memory dump)

**What Gets Encrypted with KEK:**
- ✅ Private keys (wrapped with AES-GCM before IndexedDB storage)
- ✅ Audit log entries (all operations encrypted)
- ✅ Sensitive metadata (key usage stats, timestamps)

**What Is NOT Encrypted:**
- ✅ Public keys (safe to store plaintext)
- ✅ Passkey credential IDs (needed for WebAuthn, not sensitive)
- ✅ Salt values (needed for PBKDF2, not sensitive without passphrase)

**Demo Test**:
1. Setup passkey and generate VAPID keypair
2. Lock the KMS (clears KEK from memory)
3. Open iframe DevTools → Application → IndexedDB
4. Inspect wrapped private key blob → **AES-GCM ciphertext (unreadable)**
5. Try to unwrap without KEK → **Cannot derive KEK without passphrase/passkey**

**Implementation Note**: The security-flow demo already implements this via `unlock.ts` functions (`setupPasskeyPRF`, `unlockWithPasskeyPRF`, etc.). The iframe-isolation demo will use the same Worker code, demonstrating that even with cross-origin isolation, disk encryption provides an additional defense layer.

### 5. Minimal Attack Surface

Parent PWA is **untrusted** by design:
- If parent is compromised, keys remain safe
- Parent can only request specific operations (sign, generate)
- Parent cannot inject arbitrary code into iframe
- Parent cannot bypass lock state

**Demo Test**: Compromise parent by modifying its code → **KMS operations still protected**

### 6. Tamper-Evident Audit Log (Compromise Detection)

The KMS maintains a **cryptographically-signed and hash-chained audit log** that records all operations. This provides tamper detection even if the KMS itself is compromised.

**Signature + Chain Hash Mechanism:**

Every operation in the KMS generates an audit log entry with:
1. **Operation details**: Type, timestamp, parameters, origin, requestId
2. **Previous entry hash** (`prevHash`): SHA-256 hash of the previous log entry
3. **Nonce**: 16 random bytes (prevents replay attacks)
4. **ES256 Signature** (`sig`): ECDSA P-256 signature of the entire entry

This creates a dual-protection system:
```
Entry 1:
  - prevHash: GENESIS (64 zeros)
  - data: {op, timestamp, kid, ...}
  - sig: Sign(data, privateKey)
  - entryHash: SHA-256(data)
        ↓
Entry 2:
  - prevHash: entryHash(Entry 1)   ← Hash chain
  - data: {op, timestamp, kid, ...}
  - sig: Sign(data, privateKey)    ← Signature
  - entryHash: SHA-256(data)
        ↓
Entry 3:
  - prevHash: entryHash(Entry 2)
  - data: {op, timestamp, kid, ...}
  - sig: Sign(data, privateKey)
  - entryHash: SHA-256(data)
        ↓
      ...
```

**Dual Protection:**
- **Hash chain** (prevHash): Prevents reordering, deletion, or insertion of entries
- **ES256 signature** (sig): Prevents forgery - requires non-extractable private key to create valid entry

**Tamper Detection:**

| Scenario | What Happens | Detection |
|----------|--------------|-----------|
| **Compromised KMS forces an operation** | Operation gets logged with valid signature | ✅ User sees unauthorized operation in log |
| **Attacker removes log entry** | Chain hash breaks (next entry's prevHash doesn't match) | ✅ Tamper detected on next operation |
| **Attacker modifies log entry** | Signature verification fails (signed data changed) | ✅ Tamper detected immediately |
| **Attacker forges new entry** | Cannot create valid signature without private key | ✅ Signature verification fails |
| **Attacker recomputes entire chain** | Cannot create valid signatures for recomputed entries | ✅ All signatures fail verification |

**Security Properties:**

1. **Append-only**: Cannot remove past entries without breaking chain
2. **Tamper-evident**: Any modification breaks signature verification
3. **Forgery-resistant**: Cannot create valid entries without audit signing key (non-extractable)
4. **User-auditable**: User can view log and verify chain + signatures
5. **Immediate detection**: Chain and signature validation happens on every operation
6. **Recoverable**: Stored plaintext (not encrypted) for important security reasons

**Why Audit Log is NOT Encrypted (Design Decision):**

The audit log is intentionally stored as plaintext (signed but not encrypted) because:

1. **No Secrets**: Audit log contains only operation metadata (timestamps, operation types, requestIds)
   - Does NOT contain: private keys, KEK, passphrases, JWT payloads, signatures
   - Only records THAT operations occurred, not sensitive data

2. **Integrity Protection**: ES256 signatures provide tamper detection
   - Cannot modify entries without detection (signature verification fails)
   - Cannot forge entries without audit signing key (non-extractable)
   - Signatures provide stronger guarantees than encryption for audit integrity

3. **External Verification**: Anyone with audit public key can verify the log
   - Security researchers can independently verify chain integrity
   - Users can export and verify log outside the KMS
   - Enables third-party auditing without compromising security

4. **Recovery & Forensics**: If user loses passphrase/passkey (KEK lost):
   - Audit log remains accessible (not encrypted with KEK)
   - User can prove what operations occurred (for recovery, insurance claims)
   - Enables post-compromise forensics and investigation

5. **Transparency**: Plaintext audit log supports security-by-design principles
   - Operations are visible and auditable
   - No "hidden" activity that can't be verified
   - Aligns with KMS goal of user-verifiable security

**What IS Encrypted:**
- ✅ Private keys (wrapped with KEK, AES-GCM)
- ✅ Audit signing private key (non-extractable, encrypted by browser)
- ❌ Audit log entries (plaintext by design)

**Attack Scenario - Why Plaintext Audit is Safe:**
- Attacker dumps IndexedDB → sees audit log plaintext → "User signed JWT at timestamp X"
- **No secrets leaked**: Attacker doesn't get private keys, KEK, passphrase, or JWT itself
- **Cannot forge**: Attacker cannot create fake audit entries (needs non-extractable signing key)
- **Cannot hide operations**: Any operations attacker forces will be logged and visible

**What Gets Logged (from src/audit.ts):**
- ✅ **Setup operations** (`setup`): passphrase setup, passkey PRF setup, passkey gate setup
- ✅ **Unlock operations** (`unlock`): passphrase unlock, passkey PRF unlock, passkey gate unlock
- ✅ **VAPID key generation** (`generate_vapid`): P-256 keypair creation
- ✅ **JWT signing** (`sign`): All sign operations including policy violations
- ✅ **Metadata**: timestamp, requestId, origin, clientInfo (user agent, URL), kid (key ID)
- ✅ **Chain data**: prevHash, nonce, signature

**What Is NOT Logged:**
- ❌ Private keys (never logged)
- ❌ KEK or wrapping keys (never logged)
- ❌ Passphrase or PRF outputs (never logged)
- ❌ JWT payloads or signatures (only that signing occurred)
- ❌ User secrets (only operation metadata)

**Audit Log Signing Key:**
- Separate ES256 (ECDSA P-256) keypair for audit log signatures
- Private key is non-extractable, stored in IndexedDB
- Public key is exportable (JWK format) for external verification
- NOT the same key as VAPID keys

**Attack Scenario - Compromised KMS:**

1. **Attacker compromises KMS** (malicious update, browser exploit)
2. **Attacker forces KMS to sign malicious JWT** (e.g., impersonate user)
3. **Operation gets logged with valid signature** (cannot avoid logging)
4. **User checks audit log** (sees unauthorized JWT signing operation)
5. **User detects compromise** (timestamp, requestId, unexpected operation)

**Attack Scenario - Covering Tracks:**

1. **Attacker forces malicious operation** (logged with valid signature)
2. **Attacker tries to remove log entry** (hide evidence)
3. **Chain hash breaks** (next entry's prevHash doesn't match)
4. **Tamper detected on next operation** (chain validation fails)
5. **User sees tamper warning** (immediate visibility)

**Attack Scenario - Forging Audit Entry:**

1. **Attacker wants to create fake audit entry** (make operation look legitimate)
2. **Attacker attempts to sign entry** (needs audit signing private key)
3. **Signing fails** (key is non-extractable, cannot be accessed)
4. **Attacker inserts unsigned/invalid entry** (hoping it won't be verified)
5. **Signature verification fails** (entry has invalid or missing signature)
6. **User sees tamper warning** (invalid signature detected)

**Demo Test**:
1. Generate VAPID keypair and sign JWT (creates audit log entries)
2. View audit log in iframe (shows all operations with signatures and hashes)
3. Verify chain integrity (each entry's prevHash matches previous entry's hash)
4. Verify signatures (each entry has valid ES256 signature from audit signing key)
5. Simulate tamper: manually modify an entry's timestamp in IndexedDB
6. Perform new operation → **Signature verification fails**
7. Check iframe UI → "⚠️ Audit log tamper detected - signature invalid for entry"

**Implementation Note**: The security-flow demo already implements this via the audit log system in `src/audit.ts`. The iframe-isolation demo will expose the audit log viewer in the iframe UI, demonstrating that even if the KMS is compromised, tampering is immediately visible to the user. The audit log uses ES256 (ECDSA P-256) signatures with a separate non-extractable signing key stored in IndexedDB.

**Defense-in-Depth Layer**: This complements the other security properties:
- Cross-origin isolation prevents parent from accessing KMS
- Disk encryption (KEK) prevents OS from reading keys
- **Audit log prevents compromised KMS from hiding malicious operations**

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
  - **Audit log viewer**: Scrollable list of all operations with chain hashes
    - Each entry shows: timestamp, operation type, parameters, result
    - Chain integrity indicator: ✅ Valid / ⚠️ Tampered
    - Visual chain links showing hash connections between entries
  - Security guarantees: Visual reminders of isolation
- **Visual Separation**: Heavy border, different background color, clear label
- **Security Indicators**:
  - "✅ Private keys never leave this iframe" (always visible)
  - "✅ Audit log chain verified" (green) or "⚠️ Tamper detected" (red)

### Key Visual Elements

1. **Origin display**: Show parent origin (localhost:5176) vs iframe origin (localhost:5177)
2. **Message flow arrows**: Animate postMessage direction when operations occur
3. **Lock state indicator**: Visual lock icon that changes color (green=unlocked, red=locked)
4. **Operation success/fail**: Color-coded feedback (green/red)
5. **Security boundaries**: Dashed line between parent and iframe sections
6. **Audit log chain visualization**: Connect entries with visual arrows showing hash dependencies
7. **Tamper warning banner**: Prominent red banner if chain integrity fails

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

### Test 5: Audit Log Chain Integrity
1. Perform several operations (setup, generate VAPID, sign JWT, lock/unlock)
2. View audit log in iframe UI → **See all operations logged**
3. Verify chain: each entry's `prevHash` matches previous entry's hash
4. Open iframe DevTools → Application → IndexedDB → audit log table
5. Manually modify an entry (change timestamp or operation type)
6. Perform a new operation (e.g., sign JWT)
7. **Chain validation fails** → "⚠️ Audit log tamper detected"
8. Check iframe UI → **Tamper warning visible to user**
9. Verify specific entry shows broken chain link

**What This Proves:**
- Cannot hide operations without breaking chain
- Cannot modify past operations without detection
- Tamper detection is immediate and visible
- Even compromised KMS cannot cover its tracks

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

## Phase 6: Integration Tests

The demo now includes comprehensive **automated integration tests** that verify end-to-end functionality with real crypto (no mocks).

### Running Integration Tests

**Prerequisites**: Both parent (5176) and KMS (5177) servers must be running.

**Terminal 1** - Start KMS iframe:
```bash
pnpm demo:phase-1-iframe-isolation:kms
```

**Terminal 2** - Start integration tests:
```bash
pnpm demo:phase-1-iframe-isolation:integration
```

The browser will automatically open to `http://localhost:5178/integration-tests.html` and you can click "Run All Tests" to execute the full test suite.

### Test Coverage

The integration test suite (`integration-tests.ts`) covers:

**Group 1: Setup and Unlock Flows**
- ✅ Passphrase setup and unlock
- ✅ Wrong passphrase handling
- ⏭️ Passkey PRF setup (requires user interaction - manual only)
- ⏭️ Passkey Gate setup (requires user interaction - manual only)

**Group 2: Multi-Enrollment** (Future)
- ⏭️ Multiple auth methods for same master secret

**Group 3: VAPID Key Lifecycle**
- ✅ VAPID keypair generation
- ✅ JWT signing with VAPID key
- ✅ Get public key by kid
- ✅ Error handling for non-existent kid

**Group 4: VAPID Leases** (Phase 5 Feature)
- ✅ Create VAPID lease
- ✅ Issue JWT from lease
- ✅ Lease expiry (short-duration test)
- ✅ Lease revocation

**Group 5: Audit Chain Integrity**
- ✅ Verify audit chain after multiple operations

**Group 6: Error Scenarios**
- ✅ Operations before setup (should fail)
- ✅ Concurrent operations (race conditions)
- ✅ Reset KMS (cleanup)

**Group 7: Performance Benchmarks**
- ✅ VAPID generation timing (< 500ms)
- ✅ JWT signing timing (< 200ms)
- ✅ Passphrase setup timing (includes PBKDF2 calibration)

### Test Architecture

**Key Differences from Unit Tests:**
- ❌ **No mocks** - Uses real KMSUser, KMSClient, Worker, and Storage
- ✅ **Full message flow** - Tests actual postMessage communication across origins
- ✅ **Real crypto** - Uses WebCrypto API, not mocked operations
- ✅ **Cross-origin isolation** - Runs in the actual iframe isolation setup

**Test Framework:**
- Lightweight custom test runner (no external dependencies)
- Visual test results in browser UI
- Each test gets fresh KMS instance (setup → test → teardown)
- Performance timing for benchmarking

### Continuous Integration

Integration tests complement the unit tests (255 tests with 94% coverage):
- **Unit tests**: Fast, focused, mocked dependencies
- **Integration tests**: Slower, end-to-end, real components

Both are critical for ensuring KMS reliability and security.

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
