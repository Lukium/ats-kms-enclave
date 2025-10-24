# Unlock Context (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-01-24

---

## Table of Contents

1. [Overview](#overview)
2. [Unlock Flow](#unlock-flow)
3. [withUnlock Implementation](#withunlock-implementation)
4. [Timing and Duration](#timing-and-duration)
5. [Cleanup Guarantees](#cleanup-guarantees)
6. [Security Properties](#security-properties)
7. [Error Handling](#error-handling)
8. [Usage Examples](#usage-examples)
9. [Testing Strategy](#testing-strategy)

---

## Overview

The unlock context is the **single point of control** for cryptographic operations in KMS V2. All operations requiring access to the Master Secret (MS) must go through `withUnlock`.

### Core Principle

**Per-Operation Authentication**: No persistent unlock state exists. Every operation requiring MS access must authenticate the user.

```
User Authentication → Unlock (milliseconds) → Operation → Cleanup
```

### Key Properties

✅ **Short-lived MS**: Master Secret exists for milliseconds only
✅ **Guaranteed cleanup**: try-finally ensures secrets are zeroed
✅ **Single gate**: All operations funnel through `withUnlock`
✅ **Explicit duration**: Operation must complete within timeout
✅ **Audit trail**: All unlocks are logged with timing

---

## Unlock Flow

The unlock flow has **5 distinct phases**:

```
┌─────────────────────────────────────────────────────────────────┐
│                         UNLOCK FLOW                             │
└─────────────────────────────────────────────────────────────────┘

Phase 1: AUTHENTICATE
  ↓
  User provides credential (passphrase, passkey)
  Derive KEK from credential
  Verify KCV (if password-based)
  [Duration: 150-300ms for passphrase, 1-3s for WebAuthn]

Phase 2: DERIVE MS
  ↓
  Decrypt Master Secret with KEK
  AAD verification (metadata binding)
  [Duration: <10ms]

Phase 3: UNWRAP MKEK
  ↓
  HKDF: MS → MKEK
  Import MKEK as CryptoKey
  [Duration: <5ms]

Phase 4: OPERATE
  ↓
  Execute user-provided operation
  MKEK available for key unwrapping
  MS available for export (if needed)
  [Duration: Variable, typically 10-100ms]

Phase 5: CLEANUP
  ↓
  Zero MS buffer
  Invalidate MKEK handle (GC)
  Log unlock duration
  [Duration: <1ms, ALWAYS EXECUTES]
```

### Phase Details

**Phase 1: AUTHENTICATE**
- User provides credential
- Derive KEK (PBKDF2 150-300ms, or WebAuthn 1-3s)
- Fast password verification via KCV (passphrase only)
- Reject invalid credentials before decryption

**Phase 2: DERIVE MS**
- Decrypt MS with KEK + AAD
- GCM authentication tag verified
- AAD binds decryption to configuration metadata
- Failure here indicates tampering or wrong credential

**Phase 3: UNWRAP MKEK**
- HKDF derives MKEK from MS
- Deterministic salt ensures reproducibility
- MKEK imported as non-extractable CryptoKey
- Ready for application key unwrapping

**Phase 4: OPERATE**
- User-provided operation executes
- MKEK and MS available in closure
- Typical operations: sign JWT, generate key, export backup
- Duration varies (10ms for sign, 100ms for key gen)

**Phase 5: CLEANUP**
- **ALWAYS EXECUTES** (try-finally)
- Zero MS buffer (crypto.getRandomValues overwrite)
- MKEK handle invalidated (JS GC)
- Audit log written with duration
- Guarantees no secrets persist in memory

---

## withUnlock Implementation

### Core Function

```typescript
/**
 * Execute operation with unlocked Master Secret.
 *
 * SECURITY GUARANTEES:
 * 1. MS exists for milliseconds only
 * 2. Cleanup ALWAYS executes (try-finally)
 * 3. All operations audited with timing
 * 4. No persistent unlock state
 *
 * PHASES:
 * 1. Authenticate (derive KEK from credential)
 * 2. Derive MS (decrypt with KEK + AAD)
 * 3. Unwrap MKEK (HKDF from MS)
 * 4. Operate (execute user callback)
 * 5. Cleanup (zero MS, invalidate MKEK, audit)
 *
 * @param credential User credential (passphrase or passkey)
 * @param operation Callback with access to MS and MKEK
 * @param options Unlock options (timeout, method)
 * @returns Operation result
 * @throws Error if authentication fails or operation times out
 */
export async function withUnlock<T>(
  credential: Credential,
  operation: (ctx: UnlockContext) => Promise<T>,
  options: UnlockOptions = {}
): Promise<T> {
  const requestId = crypto.randomUUID();
  const unlockStart = performance.now();

  let ms: Uint8Array | null = null;
  let mkek: CryptoKey | null = null;

  try {
    // Phase 1: AUTHENTICATE
    const config = await loadConfig(credential.method);
    const kek = await deriveKEK(credential, config);

    // Fast password verification (passphrase only)
    if ('kcv' in config) {
      const valid = await verifyKCV(kek, config.kcv);
      if (!valid) {
        throw new Error('Invalid passphrase');
      }
    }

    // Phase 2: DERIVE MS
    ms = await decryptMasterSecret(
      config.encryptedMS,
      kek,
      config.msIV,
      config.msAAD
    );

    // Phase 3: UNWRAP MKEK
    mkek = await deriveMKEK(ms);

    // Phase 4: OPERATE
    const timeout = options.timeout || 10_000;  // 10s default
    const ctx: UnlockContext = {
      ms,
      mkek,
      requestId,
      unlockTime: Date.now()
    };

    const result = await Promise.race([
      operation(ctx),
      timeoutPromise(timeout, 'Operation timed out')
    ]);

    return result;

  } finally {
    // Phase 5: CLEANUP (ALWAYS EXECUTES)
    const lockTime = Date.now();
    const duration = performance.now() - unlockStart;

    // Zero Master Secret
    if (ms) {
      crypto.getRandomValues(ms);  // Overwrite with random
      ms.fill(0);                   // Then zero
      ms = null;
    }

    // Invalidate MKEK (GC will collect)
    mkek = null;

    // Audit unlock
    await audit.log({
      op: 'unlock',
      requestId,
      unlockTime: unlockStart,
      lockTime,
      duration,
      method: credential.method
    });
  }
}
```

### Type Definitions

```typescript
/**
 * Credential types for authentication.
 */
type Credential =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; credentialId: ArrayBuffer }
  | { method: 'passkey-gate'; credentialId: ArrayBuffer; passphrase: string };

/**
 * Unlock context provided to operation callback.
 */
interface UnlockContext {
  ms: Uint8Array;           // Master Secret (32 bytes)
  mkek: CryptoKey;          // Master Key Encryption Key (non-extractable)
  requestId: string;        // UUID for this unlock
  unlockTime: number;       // Unix timestamp (ms)
}

/**
 * Options for withUnlock.
 */
interface UnlockOptions {
  timeout?: number;         // Operation timeout (ms, default 10,000)
  purpose?: string;         // Operation description (for audit)
}
```

### Helper Functions

```typescript
/**
 * Derive KEK from credential.
 */
async function deriveKEK(
  credential: Credential,
  config: PassphraseConfig | PasskeyPRFConfig | PasskeyGateConfig
): Promise<CryptoKey> {
  switch (credential.method) {
    case 'passphrase':
      return deriveKEKFromPassphrase(
        credential.passphrase,
        new Uint8Array(config.kdf.salt),
        config.kdf.iterations
      );

    case 'passkey-prf':
      return deriveKEKFromPasskeyPRF(
        credential.credentialId,
        config.rpId,
        new Uint8Array(config.kdf.appSalt),
        new Uint8Array(config.kdf.hkdfSalt)
      );

    case 'passkey-gate':
      return deriveKEKFromPasskeyGate(
        credential.passphrase,
        credential.credentialId,
        config.encryptedPepper,
        config.kekKdf
      );
  }
}

/**
 * Promise that rejects after timeout.
 */
function timeoutPromise<T>(ms: number, message: string): Promise<T> {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(message)), ms);
  });
}

/**
 * Load configuration for authentication method.
 */
async function loadConfig(
  method: string
): Promise<PassphraseConfig | PasskeyPRFConfig | PasskeyGateConfig> {
  // Load from IndexedDB
  const config = await storage.get(`config:${method}`);
  if (!config) {
    throw new Error(`No configuration found for method: ${method}`);
  }
  return config;
}
```

---

## Timing and Duration

### Expected Durations

| Phase | Typical Duration | Max Duration | Notes |
|-------|------------------|--------------|-------|
| AUTHENTICATE (passphrase) | 150-300ms | 500ms | Calibrated PBKDF2 |
| AUTHENTICATE (passkey) | 1-3s | 10s | WebAuthn user interaction |
| DERIVE MS | <10ms | 50ms | AES-GCM decryption |
| UNWRAP MKEK | <5ms | 20ms | HKDF + key import |
| OPERATE (sign) | 10-50ms | 100ms | ECDSA signature |
| OPERATE (keygen) | 50-100ms | 500ms | P-256 keypair generation |
| CLEANUP | <1ms | 5ms | Memory zeroing + audit |
| **TOTAL (passphrase)** | **200-400ms** | **1s** | |
| **TOTAL (passkey)** | **1-4s** | **15s** | |

### Timeout Configuration

```typescript
// Default timeouts per operation type
const TIMEOUTS = {
  sign: 5_000,        // 5s (includes unlock + sign)
  generateKey: 10_000, // 10s (includes unlock + keygen)
  export: 30_000,      // 30s (includes unlock + export all keys)
  backup: 60_000       // 60s (includes unlock + build bundle)
};

// Usage
await withUnlock(
  credential,
  async (ctx) => {
    // Sign JWT
    return signJWT(payload, ctx.mkek, kid);
  },
  { timeout: TIMEOUTS.sign, purpose: 'vapid:sign' }
);
```

### Performance Monitoring

```typescript
/**
 * Monitor unlock performance.
 */
interface UnlockMetrics {
  authenticateMs: number;  // Phase 1 duration
  deriveMs: number;        // Phase 2 duration
  unwrapMs: number;        // Phase 3 duration
  operateMs: number;       // Phase 4 duration
  cleanupMs: number;       // Phase 5 duration
  totalMs: number;         // End-to-end duration
}

/**
 * Enhanced withUnlock with metrics.
 */
export async function withUnlockMetrics<T>(
  credential: Credential,
  operation: (ctx: UnlockContext) => Promise<T>
): Promise<{ result: T; metrics: UnlockMetrics }> {
  const metrics: UnlockMetrics = {
    authenticateMs: 0,
    deriveMs: 0,
    unwrapMs: 0,
    operateMs: 0,
    cleanupMs: 0,
    totalMs: 0
  };

  const totalStart = performance.now();

  // Track each phase...
  // (implementation similar to withUnlock, but with timing)

  metrics.totalMs = performance.now() - totalStart;

  return { result, metrics };
}
```

---

## Cleanup Guarantees

### Try-Finally Pattern

**CRITICAL**: Cleanup MUST execute even if operation fails.

```typescript
try {
  // Phases 1-4 (authenticate, derive, unwrap, operate)
  // Any of these may throw
} finally {
  // Phase 5 (cleanup)
  // THIS ALWAYS EXECUTES
  // Even if try block throws
  // Even if operation times out
  // Even if user cancels
}
```

### Memory Zeroing

```typescript
/**
 * Securely zero Master Secret buffer.
 *
 * SECURITY:
 * - Overwrites with random first (prevents optimization)
 * - Then zeros (predictable clean state)
 * - Nullifies reference (enables GC)
 *
 * WHY TWO STEPS:
 * - Random overwrite prevents compiler optimization
 * - Zero overwrite ensures clean state for debugging
 */
function zeroMasterSecret(ms: Uint8Array | null): void {
  if (ms) {
    crypto.getRandomValues(ms);  // Step 1: Random overwrite
    ms.fill(0);                   // Step 2: Zero
    ms = null;                    // Step 3: Nullify (GC eligible)
  }
}
```

### MKEK Invalidation

```typescript
/**
 * Invalidate MKEK handle.
 *
 * NOTE: We cannot zero CryptoKey contents (opaque handle).
 * Setting to null makes it GC-eligible, but actual key
 * material lives in browser's crypto subsystem.
 *
 * ASSUMPTION: Browser's crypto subsystem manages key
 * lifecycle securely (best we can do from JavaScript).
 */
function invalidateMKEK(mkek: CryptoKey | null): void {
  mkek = null;  // Remove reference, enable GC
}
```

### Audit Logging

```typescript
/**
 * Audit unlock operation.
 *
 * LOGGED DATA:
 * - Operation type and request ID
 * - Unlock and lock timestamps
 * - Duration (ms)
 * - Authentication method
 * - Success/failure status
 *
 * NOT LOGGED:
 * - Credentials (passphrase, etc.)
 * - Master Secret or MKEK
 * - Application key material
 */
async function auditUnlock(data: {
  op: string;
  requestId: string;
  unlockTime: number;
  lockTime: number;
  duration: number;
  method: string;
  success: boolean;
  error?: string;
}): Promise<void> {
  await audit.log({
    ...data,
    timestamp: Date.now(),
    origin: self.location.origin
  });
}
```

---

## Security Properties

### 1. Short-Lived Secrets

**Property**: Master Secret exists for milliseconds only.

**Enforcement**:
- MS decrypted at start of operation
- MS zeroed in finally block
- No persistent storage of decrypted MS
- No global state holding MS

**Benefit**: Reduces window for memory dumping attacks.

### 2. No Persistent Unlock State

**Property**: Every operation requires authentication.

**Enforcement**:
- No "session" or "unlock token"
- No flag indicating "unlocked state"
- User must re-authenticate for each operation

**Benefit**: Prevents time-of-check-to-time-of-use (TOCTOU) attacks.

### 3. Single Point of Control

**Property**: All MS access goes through `withUnlock`.

**Enforcement**:
- MS never passed to other functions
- No alternative unlock paths
- Operations receive `UnlockContext`, not raw MS

**Benefit**: Easier to audit, no hidden unlock mechanisms.

### 4. Guaranteed Cleanup

**Property**: Cleanup ALWAYS executes.

**Enforcement**:
- try-finally block (JavaScript guarantee)
- Cleanup in finally, not in try
- No early returns that bypass cleanup

**Benefit**: Secrets never accidentally persist.

### 5. Audit Trail

**Property**: All unlocks are logged.

**Enforcement**:
- Audit log written in finally block
- Includes timing and method
- Logs both success and failure

**Benefit**: Detect anomalous unlock patterns (frequency, duration).

---

## Error Handling

### Typed Error Model

**All unlock errors use typed error codes for proper handling and propagation:**

```typescript
/**
 * Typed error codes for unlock operations.
 */
type UnlockErrorCode =
  | 'unlock.denied'             // Authentication failed (wrong passphrase/credential)
  | 'unlock.timeout'            // Operation exceeded timeout
  | 'unlock.method.unknown'     // Unknown unlock method
  | 'config.not.found'          // No config for specified method
  | 'config.corrupted'          // Config exists but invalid/corrupted
  | 'aad.mismatch'              // AAD verification failed
  | 'kcv.invalid'               // Key Check Value mismatch
  | 'attestation.failed'        // Bootloader verification failed
  | 'internal'                  // Unexpected internal error
  ;

/**
 * Structured error for unlock operations.
 */
export class UnlockError extends Error {
  constructor(
    public code: UnlockErrorCode,
    message: string,
    public retryAfterMs?: number,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'UnlockError';
  }
}

/**
 * Build typed error for unlock failures.
 */
function buildUnlockError(
  code: UnlockErrorCode,
  message: string,
  options?: { retryAfterMs?: number; details?: Record<string, unknown> }
): UnlockError {
  return new UnlockError(
    code,
    message,
    options?.retryAfterMs,
    options?.details
  );
}
```

### Authentication Failures

```typescript
// Invalid passphrase
try {
  await withUnlock(
    { method: 'passphrase', passphrase: 'wrong' },
    async (ctx) => { /* ... */ }
  );
} catch (error) {
  if (error instanceof UnlockError && error.code === 'unlock.denied') {
    // Handle authentication failure
    // DO NOT log passphrase
    // DO increment failed attempt counter
    // DO rate-limit authentication attempts

    console.error('Authentication failed:', error.code);
    if (error.retryAfterMs) {
      console.log(`Retry after: ${error.retryAfterMs}ms`);
    }
  }
}
```

### Operation Timeouts

```typescript
// Operation takes too long
try {
  await withUnlock(
    credential,
    async (ctx) => {
      // This takes 15 seconds
      await slowOperation();
    },
    { timeout: 10_000 }
  );
} catch (error) {
  if (error instanceof UnlockError && error.code === 'unlock.timeout') {
    // Cleanup already executed (finally block)
    // MS already zeroed
    // Safe to retry with longer timeout
    console.error('Operation timed out:', error.message);
  }
}
```

### Decryption Failures

```typescript
// AAD mismatch or corrupted ciphertext
try {
  await withUnlock(credential, operation);
} catch (error) {
  if (error instanceof UnlockError && error.code === 'aad.mismatch') {
    // GCM authentication tag verification failed
    // This indicates:
    // 1. Wrong KEK (credential mismatch)
    // 2. Corrupted ciphertext (storage corruption)
    // 3. AAD mismatch (metadata tampering)

    // DO NOT retry (likely tampering)
    // DO log security incident
    // DO alert user

    console.error('AAD verification failed:', error.details);
    await audit.log({
      op: 'unlock.failure',
      error: error.code,
      severity: 'high',
      reason: 'AAD mismatch indicates possible tampering'
    });
  }
}
```

### Error Propagation to PWA

**withUnlock attaches a stable `requestId` for audit correlation:**

```typescript
/**
 * withUnlock wrapper that ensures requestId propagation.
 */
async function withUnlockTracked<T>(
  credential: Credential,
  operation: (ctx: UnlockContext) => Promise<T>,
  options?: UnlockOptions
): Promise<T> {
  const requestId = options?.requestId || crypto.randomUUID();

  try {
    return await withUnlock(credential, operation, { ...options, requestId });
  } catch (error) {
    if (error instanceof UnlockError) {
      // Attach requestId for correlation
      error.details = {
        ...error.details,
        requestId
      };
    }
    throw error;
  }
}
```

### PRF UV Requirement Enforcement

**When using passkey-prf method, UV requirement is enforced:**

```typescript
/**
 * Unlock with Passkey PRF.
 *
 * SECURITY: userVerification: "required" MUST be set.
 * See: [WebAuthn PRF Requirements](./01-primitives.md#13-webauthn-prf-requirements)
 */
async function unlockWithPasskeyPRF(
  credentialId: ArrayBuffer,
  appSalt: Uint8Array
): Promise<CryptoKey> {
  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        rpId: 'kms.ats.run',
        userVerification: 'required',  // CRITICAL: UV required
        extensions: {
          prf: {
            eval: { first: appSalt }
          }
        }
      }
    });

    // Check UV was performed
    if (!assertion.response.userVerificationPerformed) {
      throw buildUnlockError(
        'unlock.denied',
        'User verification was not performed',
        { details: { method: 'passkey-prf', uvRequired: true } }
      );
    }

    // Extract PRF output and derive KEK
    const prfOutput = assertion.getClientExtensionResults().prf?.results?.first;
    if (!prfOutput) {
      throw buildUnlockError(
        'unlock.denied',
        'PRF extension not available',
        { details: { method: 'passkey-prf', prfAvailable: false } }
      );
    }

    return await deriveKEKFromPRF(new Uint8Array(prfOutput));
  } catch (error) {
    if (error instanceof UnlockError) {
      throw error;
    }
    throw buildUnlockError(
      'unlock.denied',
      'Passkey authentication failed',
      { details: { originalError: error.message } }
    );
  }
}
```

---

## Usage Examples

### Example 1: Sign VAPID JWT

```typescript
/**
 * Sign VAPID JWT for push notification.
 */
async function signVAPIDJWT(
  credential: Credential,
  payload: JWTPayload,
  kid: string
): Promise<string> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Load wrapped key
      const keyConfig = await storage.get(`key:${kid}`);

      // Unwrap private key with MKEK
      const privateKey = await unwrapApplicationKey(
        keyConfig.wrappedKey,
        ctx.mkek,  // From unlock context
        keyConfig.iv,
        keyConfig.aad,
        { alg: 'ES256', purpose: 'vapid' }
      );

      // Sign JWT
      const jwt = await signES256JWT(payload, privateKey);

      // Update last used timestamp
      await storage.update(`key:${kid}`, {
        lastUsedAt: Date.now()
      });

      return jwt;
    },
    {
      timeout: TIMEOUTS.sign,
      purpose: 'vapid:sign'
    }
  );
}
```

### Example 2: Generate New Key

```typescript
/**
 * Generate new VAPID keypair.
 */
async function generateVAPIDKeypair(
  credential: Credential
): Promise<{ kid: string; publicKey: ArrayBuffer }> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Generate keypair (temporarily extractable)
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,  // extractable (for wrapping)
        ['sign', 'verify']
      );

      // Export public key
      const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

      // Compute kid
      const kid = await computeJWKThumbprint(keypair.publicKey);

      // Wrap private key with MKEK
      const metadata = {
        kid,
        alg: 'ES256' as const,
        purpose: 'vapid' as const,
        createdAt: Date.now(),
        kmsVersion: 2
      };

      const { wrappedKey, iv, aad } = await wrapApplicationKey(
        keypair.privateKey,
        ctx.mkek,  // From unlock context
        metadata
      );

      // Store wrapped key
      await storage.put(`key:${kid}`, {
        kid,
        kmsVersion: 2,
        wrappedKey,
        iv,
        aad,
        publicKeyRaw,
        alg: 'ES256',
        purpose: 'vapid',
        createdAt: Date.now()
      });

      return { kid, publicKey: publicKeyRaw };
    },
    {
      timeout: TIMEOUTS.generateKey,
      purpose: 'vapid:generate'
    }
  );
}
```

### Example 3: Export Backup Bundle

```typescript
/**
 * Export encrypted backup bundle.
 */
async function exportBackupBundle(
  credential: Credential,
  backupPassword: string
): Promise<BackupBundle> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Derive backup KEK from password
      const backupKEK = await deriveBackupKEK(backupPassword);

      // Export MS (encrypted with backup KEK)
      const encryptedMS = await encryptForBackup(
        ctx.ms,  // From unlock context
        backupKEK
      );

      // Export all wrapped keys
      const wrappedKeys = await storage.getAllKeys();

      // Build backup bundle
      const bundle: BackupBundle = {
        version: 2,
        createdAt: Date.now(),
        encryptedMS,
        wrappedKeys,
        configs: await storage.getAllConfigs()
      };

      return bundle;
    },
    {
      timeout: TIMEOUTS.backup,
      purpose: 'backup:export'
    }
  );
}
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('withUnlock', () => {
  it('should execute operation with MS and MKEK', async () => {
    const result = await withUnlock(
      testCredential,
      async (ctx) => {
        expect(ctx.ms).toBeInstanceOf(Uint8Array);
        expect(ctx.ms.length).toBe(32);
        expect(ctx.mkek).toBeInstanceOf(CryptoKey);
        return 'success';
      }
    );

    expect(result).toBe('success');
  });

  it('should zero MS after operation', async () => {
    let capturedMS: Uint8Array | null = null;

    await withUnlock(
      testCredential,
      async (ctx) => {
        capturedMS = ctx.ms;
        // MS should be non-zero during operation
        expect(capturedMS.some(b => b !== 0)).toBe(true);
      }
    );

    // After operation, captured MS should be zeroed
    expect(capturedMS!.every(b => b === 0)).toBe(true);
  });

  it('should cleanup even if operation throws', async () => {
    let capturedMS: Uint8Array | null = null;

    await expect(
      withUnlock(
        testCredential,
        async (ctx) => {
          capturedMS = ctx.ms;
          throw new Error('Operation failed');
        }
      )
    ).rejects.toThrow('Operation failed');

    // MS should still be zeroed despite error
    expect(capturedMS!.every(b => b === 0)).toBe(true);
  });

  it('should timeout long operations', async () => {
    await expect(
      withUnlock(
        testCredential,
        async (ctx) => {
          await sleep(15_000);  // 15s
        },
        { timeout: 1_000 }  // 1s timeout
      )
    ).rejects.toThrow('Operation timed out');
  });

  it('should audit all unlocks', async () => {
    const auditSpy = vi.spyOn(audit, 'log');

    await withUnlock(
      testCredential,
      async (ctx) => 'success'
    );

    expect(auditSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        op: 'unlock',
        requestId: expect.any(String),
        unlockTime: expect.any(Number),
        lockTime: expect.any(Number),
        duration: expect.any(Number)
      })
    );
  });
});
```

### Integration Tests

```typescript
describe('withUnlock integration', () => {
  it('should unlock → sign → cleanup', async () => {
    // Setup: Generate key
    const { kid } = await generateVAPIDKeypair(testCredential);

    // Sign JWT
    const jwt = await signVAPIDJWT(
      testCredential,
      { aud: 'https://push.example.com', exp: Date.now() + 3600_000 },
      kid
    );

    // Verify JWT signature
    const verified = await verifyJWT(jwt);
    expect(verified.valid).toBe(true);
  });

  it('should handle multiple concurrent unlocks', async () => {
    const results = await Promise.all([
      withUnlock(cred1, op1),
      withUnlock(cred2, op2),
      withUnlock(cred3, op3)
    ]);

    expect(results).toHaveLength(3);
    // Each unlock should be independent
  });
});
```

### Performance Tests

```typescript
describe('withUnlock performance', () => {
  it('should complete passphrase unlock in <500ms', async () => {
    const start = performance.now();

    await withUnlock(
      { method: 'passphrase', passphrase: 'test' },
      async (ctx) => {
        // No-op operation
      }
    );

    const duration = performance.now() - start;
    expect(duration).toBeLessThan(500);
  });

  it('should cleanup in <5ms', async () => {
    let cleanupStart = 0;

    await withUnlock(
      testCredential,
      async (ctx) => {
        cleanupStart = performance.now();
      }
    );

    const cleanupDuration = performance.now() - cleanupStart;
    expect(cleanupDuration).toBeLessThan(5);
  });
});
```

---

## Security Considerations

### Memory Safety

**Challenge**: JavaScript has no manual memory management.
**Mitigation**: Zero buffers, nullify references, rely on GC.
**Limitation**: Cannot guarantee immediate memory release.

### Side-Channel Timing

**Challenge**: Operation duration leaks information.
**Mitigation**: KCV provides fast password check (prevents timing oracle).
**Limitation**: PBKDF2 duration varies by device (acceptable).

### Concurrent Unlocks

**Challenge**: Multiple operations may unlock simultaneously.
**Mitigation**: Each unlock is independent (no shared state).
**Note**: This is SAFE (each operation has own MS copy).

### Timeout Handling

**Challenge**: Timeout may interrupt operation mid-flight.
**Mitigation**: Cleanup in finally (always executes).
**Note**: Operation may be in inconsistent state (caller must handle).

---

## References

- **Secure Coding**: OWASP Secure Coding Practices
- **Memory Zeroing**: CWE-244 (Improper Clearing of Heap Memory)
- **Try-Finally**: JavaScript Language Spec (try-finally guarantees)
- **WebCrypto Cleanup**: W3C Web Cryptography API (key lifecycle)

---

**Next**: [04-key-operations.md](./04-key-operations.md) - VAPID key generation and JWT signing
