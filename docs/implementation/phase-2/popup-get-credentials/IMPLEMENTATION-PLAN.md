# Phase 2: Stateless Popup Credential Collection - Implementation Plan

## Overview

This plan implements a **stateless popup** approach for WebAuthn/passphrase credential collection during setup. The popup performs WebAuthn ceremonies (first-party context), encrypts only the raw credentials, and sends them to the iframe KMS for all cryptographic operations and storage.

This approach solves multiple problems:
1. **Storage partitioning**: All data stored in iframe's IndexedDB partition
2. **iOS compatibility**: Popup WebAuthn works universally (iframe WebAuthn fails on iOS)
3. **Security**: Parent remains blind to credentials (encrypted channel via ECDH)
4. **Simplicity**: Single code path (no iframe vs popup branches)

---

## Architecture

### Key Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. PARENT → IFRAME KMS: Generate transport parameters           │
│    RPC: generateSetupTransportKey()                             │
│    Response: {                                                  │
│      publicKey: "...",      // Ephemeral ECDH public key       │
│      keyId: "...",          // Transport key identifier         │
│      appSalt: "...",        // 32 bytes for PRF eval.first     │
│      hkdfSalt: "..."        // 32 bytes for HKDF (distinct!)   │
│    }                                                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. PARENT → POPUP: Open with parameters in URL                 │
│    URL: kms.ats.run/?mode=setup&                               │
│         transportKey=<publicKey>&                               │
│         keyId=<keyId>&                                          │
│         appSalt=<appSalt>&                                      │
│         hkdfSalt=<hkdfSalt>&                                    │
│         parentOrigin=<origin>                                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. POPUP KMS: Collect credentials (user chooses method)        │
│                                                                 │
│    Option A: Passphrase                                         │
│    - User enters passphrase                                     │
│    - credentials = {                                            │
│        method: 'passphrase',                                    │
│        passphrase: "...",                                       │
│        userId: "..."                                            │
│      }                                                          │
│                                                                 │
│    Option B: WebAuthn PRF/Gate (auto-detected)                 │
│    - navigator.credentials.create() with PRF extension         │
│    - Use appSalt from URL for eval.first                        │
│    - Check: prf = credential.getClientExtensionResults().prf    │
│                                                                 │
│    Case A: PRF output available immediately (modern)            │
│      - prf.enabled === true AND prf.results.first exists       │
│      - No second auth prompt! ✅                                │
│      - credentials = {                                          │
│          method: 'passkey-prf',                                 │
│          credentialId: rawId,                                   │
│          prfOutput: prf.results.first,                          │
│          rpId: "ats.run",                                       │
│          userId: "..."                                          │
│        }                                                        │
│                                                                 │
│    Case B: PRF enabled but no output yet (legacy)              │
│      - prf.enabled === true BUT prf.results is undefined       │
│      - Call credentials.get() to obtain prfOutput ⚠️           │
│      - Second auth prompt (unavoidable on old platforms)        │
│      - credentials = {                                          │
│          method: 'passkey-prf',                                 │
│          credentialId: rawId,                                   │
│          prfOutput: <from get()>,                               │
│          rpId: "ats.run",                                       │
│          userId: "..."                                          │
│        }                                                        │
│                                                                 │
│    Case C: PRF not supported                                    │
│      - prf.enabled === false or undefined                       │
│      - credentials = {                                          │
│          method: 'passkey-gate',                                │
│          credentialId: rawId,                                   │
│          rpId: "ats.run",                                       │
│          userId: "..."                                          │
│        }                                                        │
│                                                                 │
│    Option C: WebAuthn Gate (future)                            │
│    - navigator.credentials.create() without PRF                 │
│    - credentials = {                                            │
│        method: 'passkey-gate',                                  │
│        credentialId: rawId,                                     │
│        rpId: "ats.run",                                         │
│        userId: "..."                                            │
│      }                                                          │
│                                                                 │
│    NOTE: Popup does NOT store anything in its own IndexedDB    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. POPUP: Encrypt credentials with transport public key        │
│    - Import transport public key (ECDH P-256)                  │
│    - Generate ephemeral keypair for this encryption            │
│    - Derive shared secret (ECDH)                                │
│    - Derive AES-GCM key (HKDF-SHA256)                          │
│    - Encrypt: AES-GCM(JSON.stringify(credentials))             │
│    - Output: {                                                  │
│        ephemeralPublicKey,  // Popup's ephemeral public        │
│        iv,                  // 12 bytes                         │
│        ciphertext,          // credentials + auth tag           │
│      }                                                          │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. POPUP → PARENT: postMessage encrypted credentials           │
│    {                                                            │
│      type: 'kms:setup-credentials',                             │
│      method: 'passphrase' | 'passkey-prf' | 'passkey-gate',    │
│      transportKeyId: '...',                                     │
│      ephemeralPublicKey: '...',  // base64url                  │
│      iv: '...',                  // base64url                  │
│      encryptedCredentials: '...' // base64url (opaque!)        │
│    }                                                            │
│                                                                 │
│    Parent cannot decrypt (doesn't have private key)            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. PARENT → IFRAME KMS: Forward encrypted credentials          │
│    RPC: setupWithEncryptedCredentials({                         │
│      method,                                                    │
│      transportKeyId,                                            │
│      ephemeralPublicKey,                                        │
│      iv,                                                        │
│      encryptedCredentials                                       │
│    })                                                           │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. IFRAME KMS: Decrypt and perform setup                       │
│    - Retrieve ephemeral transport private key by keyId         │
│    - Derive shared secret with popup's ephemeral public key    │
│    - Derive AES-GCM decryption key (HKDF-SHA256)               │
│    - Decrypt credentials                                        │
│    - Parse credentials JSON                                     │
│    - Delete transport keypair (no longer needed)                │
│    - Call EXISTING setup methods in worker:                    │
│      * setupPassphrase({ userId, passphrase })       OR        │
│      * setupPasskeyPRF({ userId, credentialId, prfOutput,      │
│                          appSalt, hkdfSalt })          OR      │
│      * setupPasskeyGate({ userId, credentialId, ... })         │
│    - All normal setup happens in worker.ts (existing code!)    │
│    - Store in iframe's IndexedDB partition                      │
│    - Return { success: true, enrollmentId, vapidKid, ... }     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Critical Design Points

### 1. Two Distinct Salts (Per V2 Design Spec)

**IMPORTANT**: WebAuthn PRF requires **two separate 32-byte salts** per `/docs/architecture/crypto/V2/design/02-master-secret.md`:

1. **`appSalt`**: For WebAuthn PRF `eval.first` input
   - Passed to authenticator
   - Must be same for setup and unlock
   - Generated by iframe, sent to popup in cleartext (NOT secret)

2. **`hkdfSalt`**: For HKDF key derivation from PRF output
   - Distinct from appSalt (different bytes!)
   - Used when deriving KEK from prfOutput
   - Generated by iframe, sent to popup in cleartext (NOT secret)

**Why both can be public:**
- Security comes from `prfOutput` (secret, from authenticator hardware)
- Salts are for domain separation, not confidentiality
- Per RFC 5869: "The salt value is a non-secret random value"

### 2. Popup is Stateless

The popup performs WebAuthn but **stores nothing**:
- ❌ No IndexedDB writes
- ❌ No localStorage writes (except appSalt coordination - see below)
- ✅ Only collects credentials and encrypts them
- ✅ All storage happens in iframe's partition

**Exception for unlock coordination:**
After setup completes, popup may store `appSalt` in its localStorage to support the unlock flow (where popup may be used again for unlock if needed). This is acceptable because appSalt is not secret.

### 3. Parent Remains Blind

Parent sees only encrypted blobs:
- ✅ Cannot decrypt credentials (no private key)
- ✅ Cannot derive KEK (no prfOutput or passphrase)
- ✅ Cannot access Master Secret
- ✅ Zero-knowledge proxy between popup and iframe

### 4. Reuses Existing Setup Logic

Iframe worker.ts already has complete setup implementations:
- `setupPassphrase({ userId, passphrase })`
- `setupPasskeyPRF({ userId, credentialId, prfOutput, appSalt, hkdfSalt })`
- `setupPasskeyGate({ userId, credentialId, ... })`

**No duplication** - popup just collects raw credentials, iframe does all crypto.

### 5. PRF Capability Detection (Critical!)

**IMPORTANT**: The popup must detect whether the authenticator supports PRF or only gate mode:

1. **During `credentials.create()`**:
   - Request PRF extension with `eval: { first: appSalt }`
   - Check response: `credential.getClientExtensionResults().prf`
   - Modern platforms may return PRF output immediately!

2. **Check for PRF output in create() response**:
   - **Modern behavior** (Safari 18+, Chrome with sync): Returns `{ enabled: true, results: { first: ArrayBuffer } }`
   - **Legacy behavior**: Returns `{ enabled: true }` (no results yet)
   - **No PRF support**: Returns `{ enabled: false }` or undefined

3. **Handle three cases**:

   **Case A: PRF output available immediately** (best UX!)
   - `prfExt.enabled === true` AND `prfExt.results?.first` exists
   - Use PRF output directly from `create()`
   - **No second auth prompt needed** ✅
   - Method = `'passkey-prf'`

   **Case B: PRF enabled but no output yet** (legacy)
   - `prfExt.enabled === true` BUT `prfExt.results?.first` is undefined
   - Call `credentials.get()` to obtain PRF output
   - **Second auth prompt required** ⚠️ (unavoidable on older platforms)
   - Method = `'passkey-prf'`

   **Case C: PRF not supported**
   - `prfExt.enabled === false` or undefined
   - Method = `'passkey-gate'`

4. **Send correct method to iframe**:
   - Encrypted credentials must include detected method
   - Iframe calls appropriate setup function based on method

**Why this matters:**
- Not all authenticators support PRF (e.g., older security keys)
- Modern platforms avoid second auth prompt (better UX)
- Gate mode works universally but requires passphrase later
- PRF mode is passwordless but hardware-dependent
- Iframe needs to know which setup method to use

---

## Implementation Steps

### Step 1: Add `generateSetupTransportKey()` to Worker

**File:** `/home/lukium/Dev/ats-kms/src/v2/worker.ts`

**Action:** Add new RPC method to generate ephemeral ECDH keypair and salts

```typescript
/**
 * Generate ephemeral transport keypair and salts for setup flow.
 *
 * SECURITY:
 * - Ephemeral P-256 ECDH keypair (one-time use)
 * - Private key stored in memory (Map), never in IndexedDB
 * - Deleted after successful credential import
 * - Two distinct salts for WebAuthn PRF (appSalt, hkdfSalt)
 *
 * @returns Transport parameters for popup
 */
async function generateSetupTransportKey(): Promise<{
  publicKey: string;      // base64url-encoded P-256 public key (raw format)
  keyId: string;          // UUID v4
  appSalt: string;        // base64url-encoded 32 bytes (for PRF eval.first)
  hkdfSalt: string;       // base64url-encoded 32 bytes (for HKDF)
}> {
  // Generate ephemeral ECDH keypair
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,  // extractable (need to export public key)
    ['deriveBits']
  );

  // Export public key (raw format, 65 bytes uncompressed)
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Generate unique key ID
  const keyId = crypto.randomUUID();

  // Generate two distinct salts for PRF
  const appSalt = crypto.getRandomValues(new Uint8Array(32));
  const hkdfSalt = crypto.getRandomValues(new Uint8Array(32));

  // Store private key in memory (Map<keyId, CryptoKey>)
  ephemeralTransportKeys.set(keyId, {
    privateKey: keypair.privateKey,
    appSalt,
    hkdfSalt,
    createdAt: Date.now()
  });

  // Auto-cleanup after 10 minutes (prevent memory leak)
  setTimeout(() => {
    ephemeralTransportKeys.delete(keyId);
  }, 10 * 60 * 1000);

  return {
    publicKey: base64url.encode(new Uint8Array(publicKeyRaw)),
    keyId,
    appSalt: base64url.encode(appSalt),
    hkdfSalt: base64url.encode(hkdfSalt)
  };
}
```

**Add to worker state:**
```typescript
// At top of worker.ts
const ephemeralTransportKeys = new Map<string, {
  privateKey: CryptoKey;
  appSalt: Uint8Array;
  hkdfSalt: Uint8Array;
  createdAt: number;
}>();
```

**Add to RPC handler:**
```typescript
case 'generateSetupTransportKey':
  result = await generateSetupTransportKey();
  break;
```

---

### Step 2: Add `setupWithEncryptedCredentials()` to Worker

**File:** `/home/lukium/Dev/ats-kms/src/v2/worker.ts`

**Action:** Add RPC method to decrypt credentials and call existing setup methods

```typescript
/**
 * Setup using encrypted credentials from popup.
 *
 * FLOW:
 * 1. Retrieve ephemeral private key by transportKeyId
 * 2. Perform ECDH with popup's ephemeral public key
 * 3. Derive AES-GCM decryption key via HKDF
 * 4. Decrypt credentials
 * 5. Call existing setup method (setupPassphrase, setupPasskeyPRF, etc.)
 * 6. Delete ephemeral transport key
 *
 * @param params.method - Credential method
 * @param params.transportKeyId - Transport key identifier
 * @param params.ephemeralPublicKey - Popup's ephemeral public key (base64url)
 * @param params.iv - AES-GCM IV (base64url)
 * @param params.encryptedCredentials - Encrypted credential JSON (base64url)
 */
async function setupWithEncryptedCredentials(params: {
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  transportKeyId: string;
  ephemeralPublicKey: string;
  iv: string;
  encryptedCredentials: string;
}): Promise<SetupResult> {
  // Step 1: Retrieve ephemeral transport key
  const transport = ephemeralTransportKeys.get(params.transportKeyId);
  if (!transport) {
    throw new Error('Transport key not found or expired');
  }

  try {
    // Step 2: Import popup's ephemeral public key
    const popupPublicKey = await crypto.subtle.importKey(
      'raw',
      base64url.decode(params.ephemeralPublicKey),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Step 3: Derive shared secret (ECDH)
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: popupPublicKey
      },
      transport.privateKey,
      256  // 32 bytes
    );

    // Step 4: Derive AES-GCM key from shared secret (HKDF)
    const sharedSecretKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits']
    );

    const aesKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: new Uint8Array(32), // Zero salt (shared secret already random)
        info: new TextEncoder().encode('ATS/KMS/setup-transport/v2'),
        hash: 'SHA-256'
      },
      sharedSecretKey,
      256
    );

    const aesKey = await crypto.subtle.importKey(
      'raw',
      aesKeyBits,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Step 5: Decrypt credentials
    const iv = base64url.decode(params.iv);
    const ciphertext = base64url.decode(params.encryptedCredentials);

    const credentialsJSON = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      aesKey,
      ciphertext
    );

    const credentials = JSON.parse(new TextDecoder().decode(credentialsJSON));

    // Step 6: Call existing setup methods based on credential type
    let result: SetupResult;

    if (params.method === 'passphrase') {
      // Call existing setupPassphrase
      result = await setupPassphrase({
        userId: credentials.userId,
        passphrase: credentials.passphrase
      });

    } else if (params.method === 'passkey-prf') {
      // Call existing setupPasskeyPRF with BOTH salts
      result = await setupPasskeyPRF({
        userId: credentials.userId,
        credentialId: base64url.decode(credentials.credentialId),
        prfOutput: base64url.decode(credentials.prfOutput),
        rpId: credentials.rpId,
        appSalt: transport.appSalt,      // From transport key generation
        hkdfSalt: transport.hkdfSalt     // From transport key generation
      });

    } else if (params.method === 'passkey-gate') {
      // Call existing setupPasskeyGate
      result = await setupPasskeyGate({
        userId: credentials.userId,
        credentialId: base64url.decode(credentials.credentialId),
        rpId: credentials.rpId
      });

    } else {
      throw new Error(`Unknown method: ${params.method}`);
    }

    // Step 7: Delete ephemeral transport key (no longer needed)
    ephemeralTransportKeys.delete(params.transportKeyId);

    return result;

  } catch (error) {
    // Don't delete key on error (allow retry)
    throw error;
  }
}
```

**Add to RPC handler:**
```typescript
case 'setupWithEncryptedCredentials':
  result = await setupWithEncryptedCredentials(params);
  break;
```

---

### Step 3: Update Existing `setupPasskeyPRF()` to Accept Salts

**File:** `/home/lukium/Dev/ats-kms/src/v2/worker.ts`

**Action:** Modify signature to accept both salts (instead of generating appSalt internally)

**Current signature:**
```typescript
async function setupPasskeyPRF(params: {
  userId: string;
  credentialId: ArrayBuffer;
  prfOutput: ArrayBuffer;
  rpId: string;
}): Promise<SetupResult>
```

**New signature:**
```typescript
async function setupPasskeyPRF(params: {
  userId: string;
  credentialId: ArrayBuffer;
  prfOutput: ArrayBuffer;
  rpId: string;
  appSalt: Uint8Array;      // NEW: 32 bytes (for PRF eval.first)
  hkdfSalt: Uint8Array;     // NEW: 32 bytes (for HKDF)
}): Promise<SetupResult>
```

**Implementation changes:**
```typescript
async function setupPasskeyPRF(params: {
  userId: string;
  credentialId: ArrayBuffer;
  prfOutput: ArrayBuffer;
  rpId: string;
  appSalt: Uint8Array;
  hkdfSalt: Uint8Array;
}): Promise<SetupResult> {
  // Use provided salts instead of generating
  const { userId, credentialId, prfOutput, rpId, appSalt, hkdfSalt } = params;

  // Derive KEK from prfOutput using hkdfSalt
  const kek = await deriveKEKFromPasskeyPRF(
    credentialId,
    rpId,
    prfOutput,
    hkdfSalt  // Use provided hkdfSalt
  );

  // Generate Master Secret
  const ms = generateMasterSecret();

  // Build AAD for MS encryption
  const aad = buildMSEncryptionAAD({
    kmsVersion: 2,
    method: 'passkey-prf',
    algVersion: 1,
    purpose: 'master-secret',
    credentialId
  });

  // Encrypt MS with KEK
  const { ciphertext, iv } = await encryptMasterSecret(
    ms,
    kek,
    new Uint8Array(aad)
  );

  // Build configuration
  const config: PasskeyPRFConfig = {
    kmsVersion: 2,
    algVersion: 1,
    method: 'passkey-prf',
    credentialId,
    rpId,
    kdf: {
      algorithm: 'HKDF-SHA256',
      appSalt: appSalt.buffer,     // Store for unlock
      hkdfSalt: hkdfSalt.buffer,   // Store for unlock
      info: 'ATS/KMS/KEK-wrap/v2'
    },
    encryptedMS: ciphertext,
    msIV: iv,
    msAAD: aad,
    msVersion: 1,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };

  // Store configuration
  const enrollmentId = `enrollment:passkey-prf:v2:${base64url.encode(new Uint8Array(credentialId)).slice(0, 8)}`;
  await storage.put(enrollmentId, config);

  // Generate VAPID keypair
  const vapidResult = await generateVAPIDKeypair(ms);

  // Audit log
  await auditLog({
    op: 'setup',
    method: 'passkey-prf',
    enrollmentId,
    vapidKid: vapidResult.kid,
    timestamp: Date.now()
  });

  return {
    success: true,
    enrollmentId,
    vapidKid: vapidResult.kid,
    method: 'passkey-prf'
  };
}
```

**Update `deriveKEKFromPasskeyPRF()` helper:**
```typescript
async function deriveKEKFromPasskeyPRF(
  credentialId: ArrayBuffer,
  rpId: string,
  prfOutput: ArrayBuffer,  // Already have this from popup
  hkdfSalt: Uint8Array     // Use provided salt
): Promise<CryptoKey> {
  // Import PRF output as HKDF key material
  const prfKey = await crypto.subtle.importKey(
    'raw',
    prfOutput,
    'HKDF',
    false,
    ['deriveBits']
  );

  // Derive KEK using provided hkdfSalt
  const kekBytes = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: hkdfSalt,
      info: new TextEncoder().encode('ATS/KMS/KEK-wrap/v2'),
      hash: 'SHA-256'
    },
    prfKey,
    256
  );

  // Import as AES-GCM key
  const kek = await crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return kek;
}
```

---

### Step 4: Add Encryption Logic to Popup (client.ts)

**File:** `/home/lukium/Dev/ats-kms/src/v2/client.ts`

**Action:** Add encryption helper for popup mode

```typescript
/**
 * Encrypt credentials with transport public key (popup mode).
 *
 * SECURITY:
 * - Ephemeral ECDH keypair per encryption
 * - Shared secret derived via ECDH
 * - AES-GCM encryption with HKDF-derived key
 * - Parent cannot decrypt (doesn't have iframe's private key)
 *
 * @param credentials - Raw credentials (passphrase or PRF output)
 * @param transportPublicKey - Iframe's ephemeral public key (base64url)
 * @returns Encrypted payload for parent
 */
private async encryptCredentials(
  credentials: object,
  transportPublicKey: string
): Promise<{
  ephemeralPublicKey: string;
  iv: string;
  encryptedCredentials: string;
}> {
  // Step 1: Generate ephemeral keypair for this encryption
  const ephemeralKeypair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  // Step 2: Import iframe's transport public key
  const iframePublicKey = await crypto.subtle.importKey(
    'raw',
    base64url.decode(transportPublicKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  // Step 3: Derive shared secret (ECDH)
  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: iframePublicKey
    },
    ephemeralKeypair.privateKey,
    256
  );

  // Step 4: Derive AES-GCM key from shared secret (HKDF)
  const sharedSecretKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits']
  );

  const aesKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('ATS/KMS/setup-transport/v2'),
      hash: 'SHA-256'
    },
    sharedSecretKey,
    256
  );

  const aesKey = await crypto.subtle.importKey(
    'raw',
    aesKeyBits,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Step 5: Encrypt credentials
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(credentials));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    aesKey,
    plaintext
  );

  // Step 6: Export ephemeral public key
  const ephemeralPublicKeyRaw = await crypto.subtle.exportKey(
    'raw',
    ephemeralKeypair.publicKey
  );

  return {
    ephemeralPublicKey: base64url.encode(new Uint8Array(ephemeralPublicKeyRaw)),
    iv: base64url.encode(iv),
    encryptedCredentials: base64url.encode(new Uint8Array(ciphertext))
  };
}
```

---

### Step 5: Update Popup Setup Handlers to Encrypt and Send

**File:** `/home/lukium/Dev/ats-kms/src/v2/client.ts`

**Action:** Modify `handlePassphraseSetup()` and `handleWebAuthnSetup()` for stateless popup mode

**Detect popup mode:**
```typescript
// In client.ts constructor or setup detection
const urlParams = new URLSearchParams(window.location.search);
const transportKey = urlParams.get('transportKey');
const transportKeyId = urlParams.get('keyId');
const appSalt = urlParams.get('appSalt');
const hkdfSalt = urlParams.get('hkdfSalt');
const parentOrigin = urlParams.get('parentOrigin') ?? 'https://allthe.services';

const isStatelessPopup = !!(transportKey && transportKeyId);
```

**Passphrase setup (stateless popup path):**
```typescript
private async handlePassphraseSetup(passphrase: string, confirmPassphrase: string): Promise<void> {
  // ... existing validation ...

  // Check if stateless popup mode
  if (this.isStatelessPopup) {
    try {
      // Encrypt credentials
      const encrypted = await this.encryptCredentials(
        {
          method: 'passphrase',
          userId: this.userId,
          passphrase: passphrase
        },
        this.transportPublicKey!
      );

      // Send to parent
      if (window.opener) {
        (window.opener as Window).postMessage(
          {
            type: 'kms:setup-credentials',
            method: 'passphrase',
            transportKeyId: this.transportKeyId,
            ...encrypted
          },
          this.parentOrigin
        );

        // Show success and close
        this.showSetupSuccess();
        setTimeout(() => window.close(), 2000);
      }
    } catch (error) {
      this.showSetupError(`Setup failed: ${getErrorMessage(error)}`);
    }
  } else {
    // Existing iframe/popup setup logic (call worker directly)
    // ... existing code ...
  }
}
```

**WebAuthn PRF setup (stateless popup path):**
```typescript
private async handleWebAuthnSetup(): Promise<void> {
  // Check if stateless popup mode
  if (this.isStatelessPopup) {
    try {
      this.showSetupLoading();

      // Use appSalt from URL parameters
      const appSalt = base64url.decode(this.appSalt!);

      // Step 1: WebAuthn create ceremony with PRF extension
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: this.rpId, name: 'ATS KMS V2' },
          user: {
            id: new TextEncoder().encode(this.userId),
            name: this.userId,
            displayName: this.userId
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256
            { type: 'public-key', alg: -257 }  // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required'
          },
          extensions: {
            prf: {
              eval: {
                first: appSalt  // Request PRF with provided appSalt
              }
            }
          }
        }
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('No credential returned');
      }

      // Step 2: Check if PRF extension succeeded and if output is available
      // NOTE: Modern platforms return { enabled: true, results: { first: ArrayBuffer } }
      //       Legacy platforms return { enabled: true } (no results yet)
      //       No PRF support returns { enabled: false } or undefined
      const prfExt = getPRFResults(credential);
      const prfEnabled = prfExt?.enabled === true;
      let prfOutput = prfExt?.results?.first;  // May be available immediately!

      // Step 3: Determine if we need to call credentials.get() for PRF output
      let detectedMethod: 'passkey-prf' | 'passkey-gate';

      if (prfEnabled) {
        // PRF is supported by authenticator

        if (prfOutput) {
          // Case A: Modern platform - PRF output available immediately! ✅
          detectedMethod = 'passkey-prf';
          console.log('[Popup] PRF output available from create() (modern platform)');
        } else {
          // Case B: Legacy platform - need to call get() for PRF output ⚠️
          console.log('[Popup] PRF enabled but no output yet, calling get() (legacy platform)');

          const assertion = await navigator.credentials.get({
            publicKey: {
              challenge: crypto.getRandomValues(new Uint8Array(32)),
              timeout: 60000,
              userVerification: 'required',
              extensions: {
                prf: {
                  eval: {
                    first: appSalt  // Same appSalt
                  }
                }
              }
            }
          }) as PublicKeyCredential;

          const assertionPrfExt = getPRFResults(assertion);
          prfOutput = assertionPrfExt?.results?.first;

          if (prfOutput) {
            detectedMethod = 'passkey-prf';
            console.log('[Popup] PRF output obtained from get()');
          } else {
            // PRF enabled but still no output (shouldn't happen, but handle gracefully)
            detectedMethod = 'passkey-gate';
            console.warn('[Popup] PRF enabled but no output from get(), falling back to gate mode');
          }
        }
      } else {
        // Case C: PRF not supported - use gate mode
        detectedMethod = 'passkey-gate';
        console.log('[Popup] PRF not supported by authenticator, using gate mode');
      }

      // Step 4: Build credentials object based on detected method
      const credentials: any = {
        method: detectedMethod,
        userId: this.userId,
        credentialId: base64url.encode(new Uint8Array(credential.rawId)),
        rpId: this.rpId
      };

      // Include prfOutput only if PRF mode
      if (detectedMethod === 'passkey-prf' && prfOutput) {
        credentials.prfOutput = base64url.encode(new Uint8Array(prfOutput));
      }

      // NOTE: appSalt and hkdfSalt NOT included (iframe already has them)

      // Step 5: Encrypt credentials
      const encrypted = await this.encryptCredentials(
        credentials,
        this.transportPublicKey!
      );

      // Step 6: Send to parent with detected method
      if (window.opener) {
        (window.opener as Window).postMessage(
          {
            type: 'kms:setup-credentials',
            method: detectedMethod,  // Critical: tells iframe which setup to use
            transportKeyId: this.transportKeyId,
            ...encrypted
          },
          this.parentOrigin
        );

        // Show success and close
        this.hideSetupLoading();
        this.showSetupSuccess();
        setTimeout(() => window.close(), 2000);
      }
    } catch (error) {
      this.hideSetupLoading();
      this.showSetupError(`WebAuthn setup failed: ${getErrorMessage(error)}`);
    }
  } else {
    // Existing iframe setup logic
    // ... existing code ...
  }
}
```

---

### Step 6: Update Parent to Handle Encrypted Credentials

**File:** `/home/lukium/Dev/ats-kms/example/phase-2/parent.ts`

**Action:** Update `setupPassphrase()` and `setupWebAuthn()` to use new flow

**New setup functions:**
```typescript
/**
 * Setup passphrase authentication using stateless popup.
 */
async function setupPassphrase(): Promise<void> {
  console.log('[Full Demo] Starting passphrase setup with stateless popup...');

  try {
    // Step 1: Get transport parameters from iframe KMS
    const transportParams = await kmsUser.generateSetupTransportKey();
    console.log('[Full Demo] Got transport parameters:', {
      keyId: transportParams.keyId,
      publicKey: transportParams.publicKey.slice(0, 20) + '...'
    });

    // Step 2: Open popup with transport parameters
    const setupURL = new URL(KMS_ORIGIN + '/');
    setupURL.searchParams.set('mode', 'setup');
    setupURL.searchParams.set('transportKey', transportParams.publicKey);
    setupURL.searchParams.set('keyId', transportParams.keyId);
    setupURL.searchParams.set('appSalt', transportParams.appSalt);
    setupURL.searchParams.set('hkdfSalt', transportParams.hkdfSalt);
    setupURL.searchParams.set('parentOrigin', window.location.origin);

    const setupWindow = window.open(
      setupURL.toString(),
      'kms-setup',
      'width=600,height=700,menubar=no,toolbar=no,location=no,status=no'
    );

    if (!setupWindow) {
      alert('Failed to open setup window. Please allow popups for this site.');
      return;
    }

    console.log('[Full Demo] Popup opened, waiting for credentials...');

    // Step 3: Wait for encrypted credentials from popup
    const credentials = await new Promise<{
      method: string;
      transportKeyId: string;
      ephemeralPublicKey: string;
      iv: string;
      encryptedCredentials: string;
    }>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Setup timeout (no credentials received)'));
      }, 5 * 60 * 1000); // 5 minute timeout

      const handler = (event: MessageEvent): void => {
        if (event.origin !== KMS_ORIGIN) return;
        if (event.data?.type === 'kms:setup-credentials') {
          clearTimeout(timeout);
          window.removeEventListener('message', handler);
          resolve(event.data);
        }
      };

      window.addEventListener('message', handler);
    });

    console.log('[Full Demo] Received encrypted credentials, importing to iframe...');

    // Step 4: Forward encrypted credentials to iframe KMS
    const result = await kmsUser.setupWithEncryptedCredentials({
      method: credentials.method as 'passphrase' | 'passkey-prf',
      transportKeyId: credentials.transportKeyId,
      ephemeralPublicKey: credentials.ephemeralPublicKey,
      iv: credentials.iv,
      encryptedCredentials: credentials.encryptedCredentials
    });

    console.log('[Full Demo] Setup completed successfully:', result);

    // Step 5: Update UI
    updateSetupStatus();

  } catch (error) {
    console.error('[Full Demo] Setup failed:', error);
    alert(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Setup WebAuthn authentication using stateless popup.
 */
async function setupWebAuthn(): Promise<void> {
  // Same implementation as setupPassphrase, just different button text
  await setupPassphrase();
}
```

---

### Step 7: Add New RPC Methods to kms-user.ts

**File:** `/home/lukium/Dev/ats-kms/src/v2/kms-user.ts`

**Action:** Add public methods for transport key generation and credential import

```typescript
/**
 * Generate ephemeral transport key and salts for stateless popup setup.
 *
 * @returns Transport parameters to pass to popup
 */
public async generateSetupTransportKey(): Promise<{
  publicKey: string;
  keyId: string;
  appSalt: string;
  hkdfSalt: string;
}> {
  const result = await this.sendRequest<{
    publicKey: string;
    keyId: string;
    appSalt: string;
    hkdfSalt: string;
  }>('generateSetupTransportKey', {});

  return result;
}

/**
 * Import encrypted credentials from stateless popup.
 *
 * @param params - Encrypted credentials and metadata
 * @returns Setup result
 */
public async setupWithEncryptedCredentials(params: {
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  transportKeyId: string;
  ephemeralPublicKey: string;
  iv: string;
  encryptedCredentials: string;
}): Promise<SetupResult> {
  const result = await this.sendRequest<SetupResult>(
    'setupWithEncryptedCredentials',
    params
  );

  return result;
}
```

---

### Step 8: Remove Iframe Setup Code (Cleanup)

**Files to clean up:**
- Remove `showSetupModal()` method from kms-user.ts
- Remove `handleShowSetupRequest()` from client.ts
- Remove `pendingSetupRequest` field from client.ts
- Remove `USE_IFRAME_SETUP` constant from parent.ts
- Remove iframe-specific setup button handlers

**This eliminates:**
- ❌ Iframe modal setup flow
- ❌ Modal timing issues
- ❌ WebAuthn Permissions-Policy headers
- ❌ Dual code paths

---

## Security Analysis

### Threat Model

**Protected Against:**
- ✅ **Parent eavesdropping**: Credentials encrypted with ECDH, parent blind
- ✅ **MITM attacks**: HTTPS + origin validation + authenticated encryption
- ✅ **Credential leakage**: Popup stores nothing persistently
- ✅ **Ciphertext tampering**: AES-GCM authentication tag
- ✅ **Replay attacks**: Ephemeral keys (one-time use)

**NOT Protected Against:**
- ❌ **Compromised parent**: Can intercept encrypted blobs (but can't decrypt)
- ❌ **Malicious popup**: User must verify origin (kms.ats.run)
- ❌ **Phishing**: User responsibility to check URL
- ❌ **Browser bugs**: Crypto implementation flaws

### Cryptographic Properties

**ECDH Key Agreement:**
- Ephemeral P-256 keypairs (NIST recommended curve)
- Perfect forward secrecy (keys deleted after use)
- 128-bit security level

**AES-GCM Encryption:**
- 256-bit keys (derived via HKDF from shared secret)
- 128-bit authentication tag
- Random IV per encryption

**Domain Separation:**
- HKDF info: `'ATS/KMS/setup-transport/v2'`
- Prevents cross-protocol attacks

---

## Testing Plan

### Test 1: Passphrase Setup (Stateless Popup)
1. Click "Setup Passphrase" in parent
2. Verify popup opens with transport parameters in URL
3. Enter passphrase in popup
4. Verify encrypted credentials sent to parent (check console)
5. Verify iframe imports and stores credentials
6. Verify popup closes automatically
7. Check iframe's IndexedDB for stored config
8. Verify unlock works with passphrase

### Test 2: WebAuthn PRF Setup (Stateless Popup)
1. Click "Setup WebAuthn" in parent
2. Verify popup opens with transport parameters in URL
3. Complete WebAuthn ceremony in popup
4. **Verify PRF detection logic works:**
   - Check console for "PRF supported" or "PRF not supported" message
   - Verify correct method detected (passkey-prf or passkey-gate)
   - If PRF supported: verify `credentials.get()` called to obtain prfOutput
   - If PRF not supported: verify gate mode used (no prfOutput)
5. Verify encrypted credentials sent to parent with correct method
6. Verify iframe calls correct setup function (setupPasskeyPRF or setupPasskeyGate)
7. Verify iframe imports and stores credentials
8. Verify popup closes automatically
9. Check iframe's IndexedDB for stored config
10. Verify both salts (appSalt, hkdfSalt) stored correctly for PRF mode
11. Verify unlock works with detected method

### Test 3: iOS Compatibility
1. Test on iOS Safari (expect popup to work)
2. Verify WebAuthn works in popup (first-party context)
3. Verify credentials stored in iframe partition
4. Verify unlock flow works

### Test 4: Storage Partitioning
1. Complete setup via popup
2. Verify credentials in iframe's IndexedDB
3. Verify popup's IndexedDB is empty (stateless)
4. Open standalone `kms.ats.run` in new tab
5. Verify credentials NOT available (different partition)
6. Verify unlock via iframe works correctly

### Test 5: Encryption Security
1. Intercept `kms:setup-credentials` message in console
2. Verify `encryptedCredentials` is base64url blob
3. Attempt to decrypt without private key (should fail)
4. Verify parent code never sees plaintext credentials
5. Verify transport key deleted after import

### Test 6: Error Handling
1. Test popup blocked (user denies popup permission)
2. Test transport key expiration (wait 10+ minutes)
3. Test WebAuthn cancellation
4. Test invalid passphrase format
5. Test network errors during setup
6. Verify graceful error messages

### Test 7: Two Salts Validation
1. Complete WebAuthn PRF setup
2. Check stored config in iframe IndexedDB
3. Verify `kdf.appSalt` exists (32 bytes)
4. Verify `kdf.hkdfSalt` exists (32 bytes)
5. Verify appSalt ≠ hkdfSalt (different values)
6. Perform unlock and verify both salts used correctly

---

## Migration from Existing Code

### Phase 2.1: Remove Iframe Setup Attempt

**Files to modify:**
1. `/docs/implementation/phase-2/iframe-webauthn/` - Archive (keep for reference)
2. `src/v2/client.ts` - Remove `showSetupModal()`, `handleShowSetupRequest()`
3. `src/v2/kms-user.ts` - Remove iframe `showSetupModal()` method
4. `example/phase-2/parent.ts` - Remove `USE_IFRAME_SETUP` flag

### Phase 2.2: Implement Stateless Popup

Follow Steps 1-7 above.

### Phase 2.3: Clean Up

Remove all iframe-specific setup code and documentation.

---

## Files Modified

1. **`/home/lukium/Dev/ats-kms/src/v2/worker.ts`**
   - Add `generateSetupTransportKey()` method
   - Add `setupWithEncryptedCredentials()` method
   - Update `setupPasskeyPRF()` signature (accept salts)
   - Add `ephemeralTransportKeys` Map

2. **`/home/lukium/Dev/ats-kms/src/v2/client.ts`**
   - Add `encryptCredentials()` helper
   - Update `handlePassphraseSetup()` for stateless popup
   - Update `handleWebAuthnSetup()` for stateless popup
   - Add URL parameter parsing for transport params

3. **`/home/lukium/Dev/ats-kms/src/v2/kms-user.ts`**
   - Add `generateSetupTransportKey()` public method
   - Add `setupWithEncryptedCredentials()` public method

4. **`/home/lukium/Dev/ats-kms/example/phase-2/parent.ts`**
   - Update `setupPassphrase()` function
   - Update `setupWebAuthn()` function
   - Add message handler for `kms:setup-credentials`

5. **`/home/lukium/Dev/ats-kms/src/v2/types.ts`** (if needed)
   - Add types for transport parameters
   - Add types for encrypted credential payload

---

## Success Criteria

- ✅ Setup completes successfully via stateless popup
- ✅ Popup stores nothing in IndexedDB (verified via DevTools)
- ✅ All credentials stored in iframe's partition
- ✅ Parent never sees plaintext credentials
- ✅ WebAuthn PRF uses two distinct salts (appSalt, hkdfSalt)
- ✅ **PRF capability detection works correctly**:
  - PRF-capable authenticators → passkey-prf setup
  - Non-PRF authenticators → passkey-gate setup
  - Correct method passed to iframe for setup
- ✅ Unlock works with credentials from stateless popup setup
- ✅ Works on iOS Safari (popup fallback)
- ✅ No iframe reload during flow
- ✅ Proper error handling for all failure modes
- ✅ All existing tests pass
- ✅ New tests added for stateless popup flow

---

## Security Considerations

- Transport keys ephemeral (10-minute lifetime, auto-cleanup)
- ECDH provides perfect forward secrecy
- AES-GCM provides authenticated encryption
- Parent origin validation in postMessage handlers
- Non-extractable keys after import (existing guarantee)
- Storage partitioning ensures isolation
- Two distinct salts per V2 crypto spec

---

## References

- **V2 Crypto Spec**: `/docs/architecture/crypto/V2/design/02-master-secret.md`
- **Two Salt Requirement**: Lines 252-264, 1154-1161 in `02-master-secret.md`
- **ECDH**: RFC 6090, NIST SP 800-56A
- **HKDF**: RFC 5869
- **AES-GCM**: NIST SP 800-38D
- **WebAuthn PRF**: W3C WebAuthn Level 3
- **Storage Partitioning**: [MDN: State Partitioning](https://developer.mozilla.org/en-US/docs/Web/Privacy/State_Partitioning)

---

**Next Steps**: Implement Step 1 (worker.ts transport key generation)
