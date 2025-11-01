# Current State: Parent-Mediated Popup Flow

## Overview

Current implementation where parent PWA mediates all communication between iframe KMS and popup KMS.

## Flow Diagram

```
┌─────────────┐                 ┌──────────────┐                 ┌─────────────┐
│   Parent    │                 │    Iframe    │                 │    Popup    │
│     PWA     │                 │     KMS      │                 │     KMS     │
│ localhost   │                 │ kms.ats.run  │                 │ kms.ats.run │
└─────────────┘                 └──────────────┘                 └─────────────┘
      │                                │                                 │
      │ 1. User clicks setup           │                                 │
      │────────────────────────────────>                                 │
      │                                │                                 │
      │ 2. RPC: generateSetupTransportKey                                │
      │───────────────────────────────>│                                 │
      │                                │                                 │
      │ 3. {publicKey, keyId, salts}   │                                 │
      │<───────────────────────────────┤                                 │
      │                                │                                 │
      │ 4. Generate requestId          │                                 │
      │    (crypto.randomUUID)         │                                 │
      │                                │                                 │
      │ 5. window.open(url + params)   │                                 │
      │────────────────────────────────────────────────────────────────> │
      │    URL contains:               │                                 │
      │    - transportKey              │                                 │
      │    - keyId                     │                                 │
      │    - appSalt                   │                                 │
      │    - hkdfSalt                  │                                 │
      │    - requestId                 │                                 │
      │    - state (CSRF)              │                                 │
      │                                │                                 │
      │                                │                                 │
      │ 6. kms:hello (retry loop)      │                                 │
      │────────────────────────────────────────────────────────────────> │
      │                                │                                 │
      │ 7. kms:ready                   │                                 │
      │<─────────────────────────────────────────────────────────────────┤
      │                                │                                 │
      │ 8. kms:connect (with port2)    │                                 │
      │────────────────────────────────────────────────────────────────> │
      │                                │                                 │
      │ 9. MessageChannel established  │                                 │
      │<───────────────────────────────────────────────────────────────> │
      │                                │                                 │
      │                                │                          10. Collect credentials
      │                                │                              (passphrase/passkey)
      │                                │                                 │
      │                                │                          11. Encrypt with transport key
      │                                │                              (ECDH + AES-GCM)
      │                                │                                 │
      │ 12. kms:setup-credentials      │                                 │
      │    (encrypted payload)         │                                 │
      │<─────────────────────────────────────────────────────────────────┤
      │                                │                                 │
      │ 13. RPC: setupWithEncryptedCredentials                           │
      │    {method, transportKeyId,    │                                 │
      │     ephemeralPublicKey, iv,    │                                 │
      │     encryptedCredentials,      │                                 │
      │     userId, requestId}         │                                 │
      │───────────────────────────────>│                                 │
      │                                │                                 │
      │                         14. Decrypt credentials                  │
      │                             (ECDH + AES-GCM)                     │
      │                                │                                 │
      │                         15. Call setup handler                   │
      │                             (setupPassphrase/PRF/Gate)           │
      │                                │                                 │
      │ 16. {success, enrollmentId}    │                                 │
      │<───────────────────────────────┤                                 │
      │                                │                                 │
```

## Code Locations

### Parent PWA
**File:** `example/phase-2/parent.ts`

**Function:** `setupPassphrase()` (lines 463-653)

Key responsibilities:
- Generate transport key via iframe RPC
- Generate `requestId` for audit logging
- Build popup URL with transport parameters
- Open popup window
- Establish MessageChannel with popup
- Receive encrypted credentials from popup
- Forward credentials to iframe via RPC

### Iframe KMS
**File:** `src/v2/worker.ts`

**Function:** `generateSetupTransportKey()` (lines 194-236)
- Generate ephemeral ECDH keypair (P-256)
- Generate app salt and HKDF salt
- Store private key in memory (Map)
- Return public key + salts to parent

**Function:** `setupWithEncryptedCredentials()` (lines 260-389)
- Retrieve ephemeral transport key
- Perform ECDH with popup's public key
- Derive AES-GCM key via HKDF
- Decrypt credentials
- Call appropriate setup handler
- Delete ephemeral transport key

### Popup KMS
**File:** `src/v2/client.ts`

**Section:** Stateless popup mode (lines 1090-1438)

Key responsibilities:
- Read transport params from URL
- Detect setup method (passphrase/passkey PRF/gate)
- Collect credentials from user
- Generate ephemeral ECDH keypair
- Encrypt credentials with shared secret
- Send to parent via MessageChannel

## Data Flow

### Transport Parameters (Parent → Popup)
Sent via **URL query parameters**:
```
https://kms.ats.run/?mode=setup
  &state=...
  &parentOrigin=http://localhost:5173
  &transportKey=BFn3...     (base64url, 87 chars)
  &keyId=550e8400-...        (UUID)
  &appSalt=kHyG...           (base64url, 43 chars)
  &hkdfSalt=mN2P...          (base64url, 43 chars)
  &requestId=...             (UUID)
```

**Security issue:** Parent sees all transport parameters in URL.

### Encrypted Credentials (Popup → Parent)
Sent via **MessageChannel**:
```typescript
{
  type: 'kms:setup-credentials',
  payload: {
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate',
    transportKeyId: string,
    userId: string,
    ephemeralPublicKey: string,  // Popup's public key (base64url)
    iv: string,                  // AES-GCM IV (base64url)
    encryptedCredentials: string // AES-GCM ciphertext (base64url)
  }
}
```

**Security issue:** Parent receives encrypted credentials even though it can't decrypt them.

### Decryption (Iframe)
Parent forwards to iframe via RPC:
```typescript
await kmsUser.setupWithEncryptedCredentials({
  method: credentials.method,
  transportKeyId: credentials.transportKeyId,
  ephemeralPublicKey: credentials.ephemeralPublicKey,
  iv: credentials.iv,
  encryptedCredentials: credentials.encryptedCredentials,
  userId: credentials.userId,
  requestId: requestId
});
```

## Security Issues

### 1. Parent Visibility
- **Transport params in URL:** Parent sees public key, salts, key ID
- **Encrypted credentials:** Parent receives (but can't decrypt) credentials
- **Metadata leakage:** Parent sees which method user chose (passphrase vs passkey)

### 2. Parent as MITM
- **Message interception:** Parent mediates MessageChannel setup
- **Denial of Service:** Parent could refuse to forward credentials
- **Payload tampering:** Parent could modify encrypted payload (would fail decryption)

### 3. Attack Surface
- **Three-party communication:** Parent ↔ Popup, Parent ↔ Iframe, Popup → Iframe (indirect)
- **Multiple origin checks:** Must validate origins at each hop
- **Complex state management:** Parent tracks popup state, MessagePort, requestId

## Files Modified (Current Implementation)

### Core Implementation
- `src/v2/worker.ts` - Transport key generation, credential decryption
- `src/v2/client.ts` - Popup credential collection, encryption
- `src/v2/kms-user.ts` - RPC interface for parent
- `src/v2/rpc-validation.ts` - Parameter validation

### Example/Demo
- `example/phase-2/parent.ts` - Parent popup orchestration
- `example/vite.config.phase-2.ts` - Dev server config

### Tests
- `tests/v2/worker.test.ts` - Transport key and decryption tests
- (No dedicated popup flow integration tests yet)

## Performance Characteristics

### Latency
- **RPC to iframe:** ~10-50ms (cross-origin postMessage)
- **Popup open:** ~100-500ms (browser popup creation)
- **MessageChannel setup:** ~50-200ms (handshake + port transfer)
- **Credential collection:** User-dependent (2-30 seconds)
- **Encryption:** ~5-20ms (ECDH + AES-GCM)
- **Decryption:** ~5-20ms (ECDH + AES-GCM)

**Total:** ~2-30 seconds (dominated by user input)

### Memory
- **Ephemeral transport key:** ~200 bytes in iframe memory
- **MessagePort:** ~100 bytes in parent and popup
- **Pending request:** ~500 bytes in parent (requestId, resolve/reject, timeout)

**Auto-cleanup:**
- Transport keys deleted after 10 minutes
- MessagePort closed after credentials sent
- Request promises resolved/rejected

## Known Issues

### 1. COOP/COEP Headers
Currently **disabled** for testing. When enabled with `same-origin-allow-popups`:
- Messaging between parent and popup breaks
- Likely due to incompatible browsing context groups
- Need to ensure matching COOP/COEP on both sides
- COEP requires all subresources to have CORS or CORP headers

**Current state:** All COOP/COEP/CORP headers commented out in:
- `placeholders/cf-pages/_headers` (KMS popup)
- `example/vite.config.phase-2.ts` (parent dev server)

### 2. Error Handling
- Popup blocked: Detected, but UX could be improved
- Network failures: Timeout handles it, but no retry
- Concurrent setups: Not tested, may have race conditions

### 3. Browser Compatibility
- Tested on: Chrome/Edge (dev environment)
- Not tested on: Firefox, Safari
- Mobile: Not tested

## Metrics to Preserve

When migrating to new flow, ensure these work equally well or better:

1. **Success rate:** % of setups that complete successfully
2. **User experience:** Time from click to setup complete
3. **Error recovery:** Clear error messages, retry options
4. **Security:** No regression in security properties
5. **Browser support:** Maintain compatibility
