# PBKDF2 Calibration (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Overview](#overview)
2. [Why Calibration?](#why-calibration)
3. [Calibration Algorithm](#calibration-algorithm)
4. [Implementation](#implementation)
5. [Platform Detection](#platform-detection)
6. [Recalibration](#recalibration)
7. [Argon2id Alternative](#argon2id-alternative)
8. [Testing Strategy](#testing-strategy)

---

## Overview

PBKDF2 calibration dynamically determines the optimal iteration count for the user's device, targeting **150-300ms** derivation time.

### V2 Improvement

**V1 Problem**: Fixed 600,000 iterations
- Too slow on mobile (~1-2 seconds)
- Too fast on desktop (~50ms, insufficient protection)

**V2 Solution**: Device-specific calibration
- Measures PBKDF2 speed on actual device
- Adjusts iterations to target duration
- Stores calibrated value with configuration

### Target Duration

```typescript
const TARGET_DURATION = {
  min: 150,   // Minimum 150ms (security floor)
  max: 300,   // Maximum 300ms (UX ceiling)
  mid: 220    // Target midpoint
};
```

**Rationale**:
- **Security**: 150ms minimum provides meaningful brute-force resistance
- **UX**: 300ms maximum keeps authentication snappy
- **Balance**: 220ms midpoint balances both concerns

---

## Why Calibration?

### Device Performance Varies

| Device | Fixed 600k iters | Calibrated (220ms target) |
|--------|------------------|---------------------------|
| M2 MacBook Pro | 50ms (too fast!) | 2,640,000 iters → 220ms |
| Intel i5 Desktop | 180ms | 733,333 iters → 220ms |
| iPhone 14 | 420ms (too slow!) | 314,285 iters → 220ms |
| Pixel 6 | 680ms (too slow!) | 194,117 iters → 220ms |
| Budget Android | 1,200ms (unusable!) | 110,000 iters → 220ms |

### Benefits

1. **Consistent UX**: All devices authenticate in ~200ms
2. **Maximized Security**: Fast devices use maximum iterations their CPU allows
3. **Accessible**: Slow devices remain usable
4. **Future-Proof**: As CPUs improve, iterations increase automatically

---

## Calibration Algorithm

### High-Level Flow

```
1. WARM-UP
   ↓
   Run PBKDF2 with small iterations (10k)
   Primes crypto subsystem, caches loaded

2. PROBE
   ↓
   Run PBKDF2 with 100k iterations
   Measure time (e.g., 12ms)

3. SCALE
   ↓
   Extrapolate: (220ms target / 12ms measured) * 100k = 1,833,333 iters
   Round to nearest 5,000: 1,835,000 iters

4. VERIFY
   ↓
   Run PBKDF2 with 1,835,000 iterations
   Measure time (e.g., 218ms)

5. ADJUST (if needed)
   ↓
   If outside 150-300ms range:
     - Recalculate with actual measurement
     - Clamp to [50k, 2M] range
     - Re-verify

6. DONE
   ↓
   Store calibrated iterations with config
```

### Constraints

- **Minimum**: 50,000 iterations (security floor, even on slow devices)
- **Maximum**: 2,000,000 iterations (avoid excessive delays on fast devices)
- **Rounding**: Round to nearest 5,000 (cleaner numbers, negligible impact)

---

## Implementation

### Calibration Function

```typescript
/**
 * Calibrate PBKDF2 iterations for current device.
 *
 * ALGORITHM:
 * 1. Warm-up (10k iters, prime crypto subsystem)
 * 2. Probe (100k iters, measure baseline)
 * 3. Scale (extrapolate to target duration)
 * 4. Verify (measure actual duration)
 * 5. Adjust (if outside target range)
 *
 * TARGET: 150-300ms (midpoint 220ms)
 *
 * @param targetMs Target duration range
 * @returns { iterations, measuredMs }
 */
export async function calibratePBKDF2Iterations(
  targetMs = { min: 150, max: 300, mid: 220 }
): Promise<{
  iterations: number;
  measuredMs: number;
  probeMs: number;
  platformHash: string;
}> {
  // Step 1: WARM-UP
  await timeFor(10_000);

  // Step 2: PROBE
  const probeIters = 100_000;
  const probeMs = await timeFor(probeIters);

  // Step 3: SCALE
  // Extrapolate: (target / measured) * probeIters
  const estimate = Math.round(probeIters * (targetMs.mid / Math.max(1, probeMs)));

  // Round to nearest 5k
  let iterations = clamp(
    round5k(estimate),
    50_000,   // Minimum (security floor)
    2_000_000 // Maximum (avoid excessive delays)
  );

  // Step 4: VERIFY
  let measuredMs = await timeFor(iterations);

  // Step 5: ADJUST (if needed)
  if (measuredMs < targetMs.min || measuredMs > targetMs.max) {
    // Recalculate with actual measurement
    const adjusted = Math.round(iterations * (targetMs.mid / Math.max(1, measuredMs)));

    iterations = clamp(
      round5k(adjusted),
      50_000,
      2_000_000
    );

    // Re-verify
    measuredMs = await timeFor(iterations);
  }

  // Get platform hash for migration detection
  const platformHash = await getCoarsePlatformHash();

  return {
    iterations,
    measuredMs,
    probeMs,
    platformHash
  };
}

/**
 * Time PBKDF2 with given iterations.
 *
 * @param iterations Iteration count
 * @returns Duration in milliseconds (high-resolution)
 */
async function timeFor(iterations: number): Promise<number> {
  // Use deterministic input for consistent timing
  const password = 'calibration-test-password';
  const salt = new Uint8Array(16);  // All zeros (deterministic)

  // Import password
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Measure
  const start = performance.now();

  await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    256
  );

  const end = performance.now();

  return end - start;
}

/**
 * Clamp value to range.
 */
function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/**
 * Round to nearest multiple of 5000.
 */
function round5k(value: number): number {
  return Math.round(value / 5000) * 5000;
}
```

### Helper Functions

```typescript
/**
 * Get coarse platform fingerprint.
 *
 * PURPOSE: Detect device changes (migration)
 * NOT FOR: Unique user identification
 *
 * COMPONENTS:
 * - OS family (Linux, macOS, Windows, Android, iOS)
 * - Browser family (Chrome, Firefox, Safari, Edge)
 * - Rough performance tier (based on calibration result)
 *
 * EXAMPLE: "linux-chrome-fast", "ios-safari-medium"
 *
 * @returns Platform hash string
 */
export async function getCoarsePlatformHash(): Promise<string> {
  const os = getOSFamily();
  const browser = getBrowserFamily();
  const tier = getPerformanceTier();

  return `${os}-${browser}-${tier}`;
}

function getOSFamily(): string {
  const ua = navigator.userAgent.toLowerCase();

  if (ua.includes('android')) return 'android';
  if (ua.includes('iphone') || ua.includes('ipad')) return 'ios';
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('win')) return 'windows';
  if (ua.includes('linux')) return 'linux';

  return 'unknown';
}

function getBrowserFamily(): string {
  const ua = navigator.userAgent.toLowerCase();

  if (ua.includes('firefox')) return 'firefox';
  if (ua.includes('safari') && !ua.includes('chrome')) return 'safari';
  if (ua.includes('edg')) return 'edge';
  if (ua.includes('chrome')) return 'chrome';

  return 'unknown';
}

function getPerformanceTier(): string {
  // Estimate based on deviceMemory and hardwareConcurrency
  const memory = (navigator as any).deviceMemory || 4;
  const cores = navigator.hardwareConcurrency || 4;

  if (memory >= 8 && cores >= 8) return 'fast';
  if (memory >= 4 && cores >= 4) return 'medium';
  return 'slow';
}
```

---

## Platform Detection

### Purpose

Platform hash detects when user switches devices, triggering recalibration.

### Example Scenarios

**Scenario 1: Same Device**
```typescript
// Initial calibration on M2 MacBook
{
  iterations: 2_640_000,
  measuredMs: 220,
  platformHash: "macos-chrome-fast"
}

// User logs in again (same device)
// Platform hash matches → use stored iterations
```

**Scenario 2: Device Migration**
```typescript
// Initial calibration on M2 MacBook
{
  iterations: 2_640_000,
  measuredMs: 220,
  platformHash: "macos-chrome-fast"
}

// User logs in from Pixel 6
// Platform hash: "android-chrome-medium"
// Hash mismatch → trigger recalibration
// New iterations: 194,000 (optimized for Pixel)
```

### Migration Detection

```typescript
/**
 * Check if recalibration needed based on platform change.
 *
 * @param config Passphrase configuration
 * @returns { needed, reason }
 */
export async function shouldRecalibrate(
  config: PassphraseConfig
): Promise<{ needed: boolean; reason?: string }> {
  // Check platform hash
  const currentPlatformHash = await getCoarsePlatformHash();

  if (currentPlatformHash !== config.kdf.platformHash) {
    return {
      needed: true,
      reason: `Platform changed: ${config.kdf.platformHash} → ${currentPlatformHash}`
    };
  }

  // Check age (recalibrate every 90 days)
  const age = Date.now() - config.kdf.lastCalibratedAt;
  const MAX_AGE = 90 * 24 * 60 * 60 * 1000;  // 90 days

  if (age > MAX_AGE) {
    return {
      needed: true,
      reason: `Calibration expired (age: ${Math.floor(age / (24 * 60 * 60 * 1000))} days)`
    };
  }

  return { needed: false };
}
```

---

## Recalibration

### When to Recalibrate

1. **Device Migration**: Platform hash mismatch
2. **Periodic**: Every 90 days (CPUs improve over time)
3. **Manual**: User-initiated (settings)
4. **Performance Degradation**: Measured duration drifts significantly

### Recalibration Flow

```typescript
/**
 * Recalibrate PBKDF2 iterations and re-encrypt MS.
 *
 * FLOW:
 * 1. User authenticates with current credential
 * 2. Decrypt MS with current iterations
 * 3. Run calibration to get new iterations
 * 4. Derive new KEK with new iterations
 * 5. Re-encrypt MS with new KEK
 * 6. Update configuration
 *
 * @param credential Current credential
 * @returns New configuration
 */
export async function recalibrateAndReencrypt(
  credential: Credential & { method: 'passphrase' }
): Promise<PassphraseConfig> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Load current config
      const oldConfig = await storage.get(`enrollment:${credential.enrollmentId}:config`);

      // Run calibration
      const { iterations, measuredMs, platformHash } = await calibratePBKDF2Iterations();

      console.log(`Recalibration complete:
        Old: ${oldConfig.kdf.iterations} iters (${oldConfig.kdf.platformHash})
        New: ${iterations} iters (${platformHash})
        Measured: ${measuredMs}ms
      `);

      // Derive new KEK with new iterations
      const newKEK = await deriveKEKFromPassphrase(
        credential.passphrase,
        new Uint8Array(oldConfig.kdf.salt),  // Keep same salt
        iterations                             // New iteration count
      );

      // Generate new KCV
      const newKCV = await generateKCV(newKEK);

      // Build AAD (unchanged)
      const aad = buildMSEncryptionAAD({
        kmsVersion: 2,
        method: 'passphrase',
        algVersion: 1,
        purpose: 'master-secret'
      });

      // Re-encrypt MS with new KEK
      const { ciphertext, iv } = await encryptMasterSecret(
        ctx.ms,
        newKEK,
        new Uint8Array(aad)
      );

      // Build new configuration
      const newConfig: PassphraseConfig = {
        ...oldConfig,
        kdf: {
          ...oldConfig.kdf,
          iterations,
          lastCalibratedAt: Date.now(),
          platformHash
        },
        kcv: newKCV,
        encryptedMS: ciphertext,
        msIV: iv,
        msVersion: oldConfig.msVersion + 1,  // Increment version
        updatedAt: Date.now()
      };

      // Store updated config
      await storage.put(`enrollment:${credential.enrollmentId}:config`, newConfig);

      // Audit
      await audit.log({
        op: 'recalibrate:pbkdf2',
        kid: credential.enrollmentId,
        requestId: crypto.randomUUID(),
        details: {
          oldIterations: oldConfig.kdf.iterations,
          newIterations: iterations,
          oldPlatform: oldConfig.kdf.platformHash,
          newPlatform: platformHash,
          measuredMs
        }
      }, ctx.mkek);

      return newConfig;
    },
    {
      timeout: 30_000,  // Generous (calibration takes time)
      purpose: 'recalibrate:pbkdf2'
    }
  );
}
```

### Automatic Recalibration Check

```typescript
/**
 * Check and prompt for recalibration on login.
 *
 * FLOW:
 * 1. User enters passphrase
 * 2. Before unlocking, check if recalibration needed
 * 3. If needed, show warning + prompt
 * 4. If user accepts, recalibrate
 * 5. Then proceed with normal unlock
 *
 * @param enrollmentId Enrollment ID
 * @returns { shouldPrompt, reason }
 */
export async function checkRecalibrationOnLogin(
  enrollmentId: string
): Promise<{ shouldPrompt: boolean; reason?: string }> {
  const config = await storage.get(`enrollment:${enrollmentId}:config`);

  if (config.method !== 'passphrase') {
    return { shouldPrompt: false };
  }

  return shouldRecalibrate(config);
}
```

---

## Argon2id Alternative (Future Enhancement)

### Overview

**Status**: Future enhancement (post-MVP)
**Why**: Argon2id is a modern, memory-hard KDF that resists GPU/ASIC attacks better than PBKDF2
**Challenge**: Not built into WebCrypto—requires WASM implementation

### MVP Decision: PBKDF2 Baseline, Argon2id Drop-In Later

**Ship now (MVP)**:
- PBKDF2-HMAC-SHA256 via WebCrypto (universal support)
- Device-calibrated to 150-300ms (documented above)
- Prefer WebAuthn PRF when available (bypasses password KDF entirely)

**Prepare for Argon2id upgrade**:
- Design pluggable KDF architecture (no refactor needed later)
- Forward-compatible config schema
- Clear migration path

### Pluggable KDF Architecture

Design the KMS with an abstract KDF interface so Argon2id can drop in without refactoring:

```typescript
/**
 * KDF parameters (discriminated union).
 */
type KdfParams =
  | {
      name: 'pbkdf2';
      hash: 'SHA-256';
      iterations: number;
      salt: Uint8Array;
    }
  | {
      name: 'argon2id';
      version: '1.3';          // Argon2 version 1.3 (0x13)
      memory: number;          // m: Memory in KB
      iterations: number;      // t: Time cost (passes)
      parallelism: number;     // p: Degree of parallelism
      salt: Uint8Array;        // 16-32 bytes recommended
    };

/**
 * KDF driver interface (strategy pattern).
 */
interface KdfDriver {
  /**
   * Derive KEK from passphrase.
   */
  deriveKEK(passphrase: Uint8Array, params: KdfParams): Promise<CryptoKey>;

  /**
   * Calibrate KDF parameters to target duration.
   */
  calibrate(targetMs: number): Promise<Partial<KdfParams>>;

  /**
   * Check if this KDF is supported on current platform.
   */
  isSupported(): Promise<boolean>;
}

/**
 * KDF driver registry.
 */
const kdfDrivers = {
  pbkdf2: new PBKDF2Driver(),
  argon2id: new Argon2idDriver()  // Added in future release
};

/**
 * Select best available KDF driver.
 */
async function selectKdfDriver(): Promise<KdfDriver> {
  // Priority order:
  // 1. Argon2id (if supported)
  // 2. PBKDF2 (always available)

  if (await kdfDrivers.argon2id.isSupported()) {
    return kdfDrivers.argon2id;
  }

  return kdfDrivers.pbkdf2;  // Fallback
}
```

### Feature Detection Decision Tree

At setup/unlock, select KDF based on capabilities:

```typescript
/**
 * Select authentication method based on available features.
 */
async function selectAuthMethod(): Promise<'webauthn-prf' | 'argon2id' | 'pbkdf2'> {
  // 1. Best: WebAuthn PRF (no password KDF needed)
  if (await isWebAuthnPRFAvailable()) {
    return 'webauthn-prf';
  }

  // 2. Good: Argon2id (if cross-origin isolated + enough RAM)
  if (await canUseArgon2id()) {
    return 'argon2id';
  }

  // 3. Baseline: PBKDF2 (always works)
  return 'pbkdf2';
}

/**
 * Check if Argon2id is viable on current device.
 */
async function canUseArgon2id(): Promise<boolean> {
  // Requirement 1: Cross-origin isolated (for SharedArrayBuffer/threads)
  if (!crossOriginIsolated) {
    return false;  // Can't use threads/SIMD without COOP/COEP
  }

  // Requirement 2: Enough memory for reasonable parameters
  const deviceMemory = (navigator as any).deviceMemory || 4;  // GB
  if (deviceMemory < 2) {
    return false;  // Too constrained for Argon2id
  }

  // Requirement 3: WASM support
  if (typeof WebAssembly === 'undefined') {
    return false;
  }

  return true;
}
```

### Device-Specific Argon2id Parameters

When Argon2id is available, calibrate based on device capabilities:

```typescript
/**
 * Get recommended Argon2id baseline for device.
 */
function getArgon2idBaseline(): { memory: number; iterations: number; parallelism: number } {
  const deviceMemory = (navigator as any).deviceMemory || 4;  // GB
  const hardwareConcurrency = navigator.hardwareConcurrency || 4;

  // Memory (KB)
  let memory: number;
  if (deviceMemory >= 8) {
    memory = 131072;  // 128 MB (desktop)
  } else if (deviceMemory >= 4) {
    memory = 65536;   // 64 MB (laptop, high-end mobile)
  } else if (deviceMemory >= 2) {
    memory = 32768;   // 32 MB (mid-range mobile)
  } else {
    memory = 16384;   // 16 MB (low-end mobile)
  }

  // Parallelism (threads)
  const parallelism = Math.min(Math.max(1, Math.floor(hardwareConcurrency / 2)), 4);

  // Iterations (time cost)
  const iterations = deviceMemory >= 4 ? 3 : 2;

  return { memory, iterations, parallelism };
}

/**
 * Calibrate Argon2id to target duration.
 */
export async function calibrateArgon2id(
  targetMs = { min: 150, max: 300, mid: 220 }
): Promise<{
  memory: number;
  iterations: number;
  parallelism: number;
  measuredMs: number;
}> {
  // Load Argon2 WASM module (in Worker only!)
  const argon2 = await loadArgon2WASM();

  // Start with device-appropriate baseline
  let params = getArgon2idBaseline();

  // Measure baseline
  let measuredMs = await timeArgon2(argon2, params);

  // Adjust iterations to hit target (memory/parallelism stay fixed)
  if (measuredMs < targetMs.min || measuredMs > targetMs.max) {
    const scaleFactor = targetMs.mid / measuredMs;
    params.iterations = Math.max(1, Math.min(10, Math.round(params.iterations * scaleFactor)));

    // Re-measure
    measuredMs = await timeArgon2(argon2, params);
  }

  return { ...params, measuredMs };
}

/**
 * Derive KEK with Argon2id (WASM).
 */
async function deriveKEKWithArgon2id(
  passphrase: string,
  salt: Uint8Array,
  params: { memory: number; iterations: number; parallelism: number }
): Promise<CryptoKey> {
  // Load Argon2 WASM (vetted library, SRI-pinned)
  // Candidates: libsodium.js, argon2-wasm
  const argon2 = await loadArgon2WASM();

  const hash = await argon2.hash({
    pass: new TextEncoder().encode(passphrase),
    salt,
    time: params.iterations,        // t parameter
    mem: params.memory,             // m parameter (KB)
    hashLen: 32,                    // 256-bit output
    parallelism: params.parallelism, // p parameter
    type: argon2.ArgonType.Argon2id, // Argon2id variant
    version: 0x13                   // Argon2 version 1.3
  });

  return crypto.subtle.importKey(
    'raw',
    hash,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
```

### Migration Path: PBKDF2 → Argon2id

When Argon2id becomes available, re-wrap the MS under new KEK:

```typescript
/**
 * Migrate from PBKDF2 to Argon2id.
 *
 * FLOW:
 * 1. User authenticates with current PBKDF2 credential
 * 2. MS available during unlock
 * 3. Calibrate Argon2id parameters
 * 4. Derive new KEK with Argon2id
 * 5. Re-encrypt MS with new KEK
 * 6. Update configuration
 * 7. Keep backup until next successful unlock
 *
 * @param credential Current PBKDF2 credential
 * @returns New Argon2id configuration
 */
export async function migrateToArgon2id(
  credential: Credential & { method: 'passphrase' }
): Promise<PassphraseConfig> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Load current config
      const oldConfig = await storage.get(`enrollment:${credential.enrollmentId}:config`);

      // Calibrate Argon2id
      const argon2Params = await calibrateArgon2id();

      // Derive new KEK with Argon2id
      const newKEK = await deriveKEKWithArgon2id(
        credential.passphrase,
        crypto.getRandomValues(new Uint8Array(32)),  // New salt (32 bytes for Argon2id)
        argon2Params
      );

      // Generate new KCV
      const newKCV = await generateKCV(newKEK);

      // Build new AAD
      const aad = buildMSEncryptionAAD({
        kmsVersion: 2,
        method: 'passphrase',
        algVersion: 2,  // Increment for Argon2id
        purpose: 'master-secret'
      });

      // Re-encrypt MS with Argon2id-derived KEK
      const { ciphertext, iv } = await encryptMasterSecret(
        ctx.ms,
        newKEK,
        new Uint8Array(aad)
      );

      // Build new configuration
      const newConfig: PassphraseConfig = {
        kmsVersion: 2,
        algVersion: 2,  // Argon2id
        method: 'passphrase',
        kdf: {
          algorithm: 'Argon2id',
          version: '1.3',
          memory: argon2Params.memory,
          iterations: argon2Params.iterations,
          parallelism: argon2Params.parallelism,
          salt: argon2Params.salt,
          lastCalibratedAt: Date.now(),
          platformHash: await getCoarsePlatformHash()
        },
        kcv: newKCV,
        encryptedMS: ciphertext,
        msIV: iv,
        msAAD: aad,
        msVersion: oldConfig.msVersion + 1,
        createdAt: oldConfig.createdAt,
        updatedAt: Date.now()
      };

      // Store new config
      await storage.put(`enrollment:${credential.enrollmentId}:config`, newConfig);

      // Keep old config as backup until next successful unlock
      await storage.put(`enrollment:${credential.enrollmentId}:config:backup`, oldConfig);

      // Audit migration
      await audit.log({
        op: 'migrate:argon2id',
        kid: credential.enrollmentId,
        requestId: crypto.randomUUID(),
        details: {
          fromKdf: 'PBKDF2',
          toKdf: 'Argon2id',
          argon2Params: {
            memory: `${argon2Params.memory / 1024} MB`,
            iterations: argon2Params.iterations,
            parallelism: argon2Params.parallelism
          },
          measuredMs: argon2Params.measuredMs
        }
      }, ctx.mkek);

      return newConfig;
    },
    {
      timeout: 30_000,
      purpose: 'migrate:argon2id'
    }
  );
}
```

### WASM Hygiene and Security

**Requirements for Argon2id WASM**:

1. **Worker-Only Execution**
   - NEVER load WASM in main thread (blocks UI)
   - Always run in KMS Worker (already isolated)

2. **Cross-Origin Isolation** (for threads/SIMD)
   - Serve KMS with COOP/COEP headers
   - Unlocks `SharedArrayBuffer` for multi-threaded Argon2
   - Already planned for self-attestation architecture

3. **Vetted Library + SRI**
   - Use established library: `libsodium.js` or `argon2-wasm`
   - Pin SRI hash in HTML: `<script integrity="sha256-..." src="argon2.wasm">`
   - Lock version in package.json

4. **Fallback to PBKDF2**
   - If WASM fails to load → fall back to PBKDF2
   - If calibration exceeds memory → fall back to PBKDF2
   - User never blocked from unlocking

### Configuration Schema (Future)

Forward-compatible config that supports both KDFs:

```typescript
interface PassphraseConfig {
  kmsVersion: 2;
  algVersion: 1 | 2;  // 1=PBKDF2, 2=Argon2id
  method: 'passphrase';

  // KDF parameters (discriminated by algorithm)
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256' | 'Argon2id';
    lastCalibratedAt: number;
    platformHash: string;
  } & (
    | {
        algorithm: 'PBKDF2-HMAC-SHA256';
        iterations: number;
        salt: ArrayBuffer;  // 16 bytes
      }
    | {
        algorithm: 'Argon2id';
        version: '1.3';
        memory: number;      // KB
        iterations: number;  // t parameter
        parallelism: number; // p parameter
        salt: ArrayBuffer;   // 32 bytes
      }
  );

  kcv: ArrayBuffer;
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: number;
  createdAt: number;
  updatedAt: number;
}
```

### Implementation Timeline

**MVP (Ship Now)**:
- ✅ PBKDF2 with calibration (150-300ms)
- ✅ WebAuthn PRF path (preferred)
- ✅ Pluggable KDF architecture (interfaces defined)
- ✅ Forward-compatible config schema

**Post-MVP (Future Enhancement)**:
- ⏳ Argon2id driver implementation
- ⏳ WASM library integration (libsodium.js or argon2-wasm)
- ⏳ Cross-origin isolation deployment (COOP/COEP headers)
- ⏳ Migration UI and tooling
- ⏳ Device capability detection
- ⏳ Fallback logic and error handling

### Why This Design Works

1. **No Refactoring Needed**: KDF driver interface allows drop-in upgrade
2. **Config Forward-Compatible**: Schema supports both KDFs with `algVersion` discriminator
3. **Graceful Degradation**: Falls back to PBKDF2 if Argon2id unavailable
4. **User Never Blocked**: Migration is optional, prompted, never forced
5. **Same Security Properties**: Both KDFs target same duration, same KCV, same encryption flow

---

## Testing Strategy

### Calibration Tests

```typescript
describe('PBKDF2 calibration', () => {
  it('should calibrate to target range', async () => {
    const result = await calibratePBKDF2Iterations();

    // Should be in target range
    expect(result.measuredMs).toBeGreaterThanOrEqual(150);
    expect(result.measuredMs).toBeLessThanOrEqual(300);

    // Iterations should be rounded to 5k
    expect(result.iterations % 5000).toBe(0);

    // Should have platform hash
    expect(result.platformHash).toMatch(/^\w+-\w+-\w+$/);
  });

  it('should respect minimum iterations', async () => {
    const result = await calibratePBKDF2Iterations({
      min: 150,
      max: 300,
      mid: 220
    });

    // Even on very fast devices, minimum is 50k
    expect(result.iterations).toBeGreaterThanOrEqual(50_000);
  });

  it('should respect maximum iterations', async () => {
    const result = await calibratePBKDF2Iterations();

    // Even on very slow devices, maximum is 2M
    expect(result.iterations).toBeLessThanOrEqual(2_000_000);
  });

  it('should detect platform changes', async () => {
    const config = {
      kdf: {
        iterations: 200_000,
        lastCalibratedAt: Date.now(),
        platformHash: 'macos-safari-fast'
      }
    };

    // Simulate different platform
    vi.spyOn(global as any, 'getCoarsePlatformHash')
      .mockResolvedValue('linux-chrome-medium');

    const { needed, reason } = await shouldRecalibrate(config);

    expect(needed).toBe(true);
    expect(reason).toContain('Platform changed');
  });
});
```

### Performance Tests

```typescript
describe('PBKDF2 performance', () => {
  it('should complete calibration in <10s', async () => {
    const start = performance.now();
    await calibratePBKDF2Iterations();
    const duration = performance.now() - start;

    // Calibration includes warm-up, probe, verify, adjust
    // Should complete in reasonable time
    expect(duration).toBeLessThan(10_000);
  });

  it('should produce consistent results', async () => {
    const result1 = await calibratePBKDF2Iterations();
    const result2 = await calibratePBKDF2Iterations();

    // Iterations should be similar (within 10%)
    const diff = Math.abs(result1.iterations - result2.iterations);
    const tolerance = result1.iterations * 0.1;

    expect(diff).toBeLessThan(tolerance);
  });
});
```

---

## References

- **PBKDF2**: RFC 8018, NIST SP 800-132
- **Argon2**: RFC 9106
- **Password Hashing Competition**: https://password-hashing.net/
- **OWASP Password Storage**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

**Next**: [08-security-model.md](./08-security-model.md) - Threat model and security boundaries
