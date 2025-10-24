/**
 * Unlock Manager - Passphrase-based Key Derivation
 *
 * Provides passphrase-based unlock functionality for deriving the wrapping key.
 * Uses PBKDF2 with 600,000 iterations (OWASP recommendation for 2024).
 *
 * @module unlock
 */

import { getMeta, putMeta, deleteMeta, initDB } from './storage.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Result type for setup/unlock operations
 *
 * New architecture: Returns Master Secret (MS) bytes, not CryptoKey
 * Worker derives MKEK from MS using HKDF
 */
export type UnlockResult =
  | { success: true; ms: Uint8Array<ArrayBuffer> } // Master Secret bytes (32 bytes)
  | {
      success: false;
      error:
        | 'INVALID_PASSPHRASE'
        | 'PASSPHRASE_TOO_SHORT'
        | 'ALREADY_SETUP' // Deprecated: use method-specific errors
        | 'PASSPHRASE_ALREADY_SETUP'
        | 'PASSKEY_ALREADY_SETUP'
        | 'NOT_SETUP'
        | 'INCORRECT_PASSPHRASE'
        | 'PASSKEY_NOT_AVAILABLE'
        | 'PASSKEY_CREATION_FAILED'
        | 'PASSKEY_AUTHENTICATION_FAILED'
        | 'PASSKEY_PRF_NOT_SUPPORTED'
        | 'INCORRECT_PASSKEY'
        | 'SESSION_EXPIRED'
        | 'MUST_UNLOCK_FIRST'; // Must be unlocked before adding second unlock method
    };

/**
 * Unlock configuration stored in meta store
 *
 * New architecture: Store encrypted Master Secret (MS) bytes, not wrapped CryptoKeys
 * - MS is random bytes (32 bytes) never stored unencrypted
 * - Each unlock method encrypts the same MS with its own KEK
 * - On unlock: decrypt MS, derive MKEK from MS using HKDF
 * - Adding second method: just encrypt MS with new KEK (no key export needed)
 */
type UnlockPassphraseConfig = {
  method: 'passphrase';
  salt: ArrayBuffer;
  iterations: number;
  encryptedMS: ArrayBuffer; // Master Secret encrypted with passphrase-derived KEK
  msIV: ArrayBuffer; // IV for AES-GCM encryption of MS
  verificationHash: string; // Hash of derived key for verification
};

type UnlockPasskeyPRFConfig = {
  method: 'passkey-prf';
  credentialId: ArrayBuffer;
  appSalt: ArrayBuffer;
  encryptedMS: ArrayBuffer; // Master Secret encrypted with PRF-derived KEK
  msIV: ArrayBuffer; // IV for AES-GCM encryption of MS
};

type UnlockPasskeyGateConfig = {
  method: 'passkey-gate';
  credentialId: ArrayBuffer;
  appSalt: ArrayBuffer;
  encryptedMS: ArrayBuffer; // Master Secret encrypted with gate-derived KEK
  msIV: ArrayBuffer; // IV for AES-GCM encryption of MS
};

// ============================================================================
// Constants
// ============================================================================

const MIN_PASSPHRASE_LENGTH = 8;
const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for 2024
const SALT_LENGTH = 16; // 128 bits
const APP_SALT_LENGTH = 32; // 256 bits
const MS_LENGTH = 32; // Master Secret length (256 bits)
const HKDF_INFO_KEK = 'ATS/KMS/KEK-wrap/v1'; // HKDF purpose label for KEK derivation
const HKDF_INFO_MKEK = 'ATS/KMS/MKEK/v1'; // HKDF purpose label for MKEK derivation from MS

// ============================================================================
// Module State
// ============================================================================

let isInitialized = false;

/**
 * NEW ARCHITECTURE: No persistent unlock state
 *
 * Previously stored _wrappingKeyRef (MKEK) in memory after unlock.
 * New approach: Return MS bytes from unlock functions, worker derives MKEK per operation.
 *
 * Benefits:
 * - Eliminates persistent in-memory keys
 * - Requires authentication per operation
 * - Minimizes key lifetime (milliseconds vs. session duration)
 * - Reduces attack surface for code execution in Worker
 */

/**
 * Initialize the unlock manager
 */
async function ensureInitialized(): Promise<void> {
  if (!isInitialized) {
    await initDB();
    isInitialized = true;
  }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Check if any unlock method is configured
 */
export async function isSetup(): Promise<boolean> {
  await ensureInitialized();
  const passphraseConfig = await getMeta<UnlockPassphraseConfig>('passphraseConfig');
  const passkeyConfig = await getMeta<UnlockPasskeyPRFConfig | UnlockPasskeyGateConfig>('passkeyConfig');
  return passphraseConfig !== undefined || passkeyConfig !== undefined;
}

/**
 * Check if passphrase unlock is configured
 */
export async function isPassphraseSetup(): Promise<boolean> {
  await ensureInitialized();
  const config = await getMeta<UnlockPassphraseConfig>('passphraseConfig');
  return config !== undefined;
}

/**
 * Check if passkey unlock is configured
 */
export async function isPasskeySetup(): Promise<boolean> {
  await ensureInitialized();
  const config = await getMeta<UnlockPasskeyPRFConfig | UnlockPasskeyGateConfig>('passkeyConfig');
  return config !== undefined;
}

/**
 * Setup passphrase-based unlock
 *
 * NEW ARCHITECTURE: Encrypts Master Secret (MS) with passphrase-derived KEK
 *
 * @param passphrase - User's passphrase (min 8 characters)
 * @param existingMS - Optional: MS from another unlock method (for adding second method)
 * @returns Result with MS bytes or error
 */
export async function setupPassphrase(
  passphrase: string,
  existingMS?: Uint8Array<ArrayBuffer>
): Promise<UnlockResult> {
  await ensureInitialized();

  // Validate passphrase
  const validation = validatePassphrase(passphrase);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  // Check if passphrase already setup
  if (await isPassphraseSetup()) {
    return { success: false, error: 'PASSPHRASE_ALREADY_SETUP' };
  }

  // Generate random salt for PBKDF2
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  // Derive KEK from passphrase
  const { key: kek, verificationHash } = await deriveKeyWithVerification(
    passphrase,
    salt,
    PBKDF2_ITERATIONS
  );

  // Get or generate Master Secret (MS)
  const ms = existingMS || crypto.getRandomValues(new Uint8Array(MS_LENGTH));

  // Encrypt MS with KEK (not wrapKey - MS is bytes, not CryptoKey)
  const msIV = crypto.getRandomValues(new Uint8Array(12));
  const encryptedMS = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: msIV },
    kek,
    ms
  );

  // Store unlock configuration
  const config: UnlockPassphraseConfig = {
    method: 'passphrase',
    salt: salt.buffer,
    iterations: PBKDF2_ITERATIONS,
    encryptedMS,
    msIV: msIV.buffer,
    verificationHash,
  };

  await putMeta('passphraseConfig', config);

  return { success: true, ms };
}

/**
 * Unlock with passphrase
 *
 * NEW ARCHITECTURE: Decrypts Master Secret (MS) using passphrase-derived KEK
 *
 * @param passphrase - User's passphrase
 * @returns Result with MS bytes or error
 */
export async function unlockWithPassphrase(
  passphrase: string
): Promise<UnlockResult> {
  await ensureInitialized();

  // Validate passphrase
  const validation = validatePassphrase(passphrase);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  // Check if passphrase is setup
  const config = await getMeta<UnlockPassphraseConfig>('passphraseConfig');
  if (!config) {
    return { success: false, error: 'NOT_SETUP' };
  }

  // Derive KEK from passphrase
  const salt = new Uint8Array(config.salt);
  const { key: kek, verificationHash } = await deriveKeyWithVerification(
    passphrase,
    salt,
    config.iterations
  );

  // Verify passphrase is correct by comparing hash
  if (verificationHash !== config.verificationHash) {
    return { success: false, error: 'INCORRECT_PASSPHRASE' };
  }

  // Decrypt MS with KEK
  try {
    const msIV = new Uint8Array(config.msIV);
    const msBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: msIV },
      kek,
      config.encryptedMS
    );

    const ms = new Uint8Array(msBuffer);

    return { success: true, ms };
  } catch {
    return { success: false, error: 'INCORRECT_PASSPHRASE' };
  }
}

/**
 * Reset unlock configuration
 *
 * WARNING: This will delete the unlock configuration.
 * For testing purposes only.
 */
export async function resetUnlock(): Promise<void> {
  await ensureInitialized();
  await deleteMeta('passphraseConfig');
  await deleteMeta('passkeyConfig');
  // Deprecated: unlockSalt is from old architecture
  await deleteMeta('unlockSalt');
}

/**
 * Setup passkey-based unlock with PRF extension
 *
 * NEW ARCHITECTURE: Encrypts Master Secret (MS) with PRF-derived KEK
 *
 * @param credentialId - Raw credential ID from PublicKeyCredential.rawId
 * @param prfOutput - PRF output from WebAuthn (32 bytes)
 * @param existingMS - Optional: MS from another unlock method (for adding second method)
 * @returns Result with MS bytes or error
 */
export async function setupPasskeyPRF(
  credentialId: ArrayBuffer,
  prfOutput: ArrayBuffer,
  existingMS?: Uint8Array<ArrayBuffer>
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if passkey already setup
  if (await isPasskeySetup()) {
    return { success: false, error: 'PASSKEY_ALREADY_SETUP' };
  }

  /* c8 ignore start - defensive: client.ts always provides valid credentialId from WebAuthn (tested by Playwright) */
  // Validate inputs
  if (credentialId.byteLength === 0) {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
  /* c8 ignore stop */

  if (prfOutput.byteLength !== 32) {
    return { success: false, error: 'PASSKEY_PRF_NOT_SUPPORTED' };
  }

  // Generate random app salt for HKDF
  const appSalt = crypto.getRandomValues(new Uint8Array(APP_SALT_LENGTH));

  try {
    const prfOutputBytes = new Uint8Array(prfOutput);

    // Derive KEK from PRF output using HKDF
    const kek = await hkdfDeriveKey(prfOutputBytes, appSalt, HKDF_INFO_KEK);

    // Get or generate Master Secret (MS)
    const ms = existingMS || crypto.getRandomValues(new Uint8Array(MS_LENGTH));

    // Encrypt MS with KEK
    const msIV = crypto.getRandomValues(new Uint8Array(12));
    const encryptedMS = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: msIV },
      kek,
      ms
    );

    // Store unlock configuration
    await putMeta<UnlockPasskeyPRFConfig>('passkeyConfig', {
      method: 'passkey-prf',
      credentialId: credentialId,
      appSalt: appSalt.buffer,
      encryptedMS,
      msIV: msIV.buffer,
    });

    return { success: true, ms };
    /* c8 ignore start - defensive: crypto operation failures are not testable without mocking crypto subsystem */
  } catch {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
  /* c8 ignore stop */
}

/**
 * Unlock with passkey PRF extension
 *
 * NEW ARCHITECTURE: Decrypts Master Secret (MS) using PRF-derived KEK
 *
 * @param prfOutput - PRF output from WebAuthn (32 bytes)
 * @returns Result with MS bytes or error
 */
export async function unlockWithPasskeyPRF(
  prfOutput: ArrayBuffer
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if passkey is setup
  const config = await getMeta<UnlockPasskeyPRFConfig | UnlockPasskeyGateConfig>('passkeyConfig');
  if (!config || config.method !== 'passkey-prf') {
    return { success: false, error: 'NOT_SETUP' };
  }

  // Validate PRF output
  if (prfOutput.byteLength !== 32) {
    return { success: false, error: 'PASSKEY_PRF_NOT_SUPPORTED' };
  }

  const appSalt = new Uint8Array(config.appSalt);

  try {
    const prfOutputBytes = new Uint8Array(prfOutput);

    // Derive KEK from PRF output using HKDF
    const kek = await hkdfDeriveKey(prfOutputBytes, appSalt, HKDF_INFO_KEK);

    // Decrypt MS with KEK
    try {
      const msIV = new Uint8Array(config.msIV);
      const msBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: msIV },
        kek,
        config.encryptedMS
      );

      const ms = new Uint8Array(msBuffer);

      return { success: true, ms };
    } catch {
      return { success: false, error: 'INCORRECT_PASSKEY' };
    }
  /* c8 ignore start - defensive: WebAuthn failures tested by Playwright */
  } catch {
    return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
  }
  /* c8 ignore stop */
}

/**
 * Setup passkey-based unlock with gate-only mode
 *
 * NEW ARCHITECTURE: Encrypts Master Secret (MS) with gate-derived KEK
 *
 * Fallback mode when PRF is not supported. The passkey gates access;
 * security comes from WebAuthn user verification, not from PRF entropy.
 *
 * @param credentialId - Raw credential ID from PublicKeyCredential.rawId
 * @param existingMS - Optional: MS from another unlock method (for adding second method)
 * @returns Result with MS bytes or error
 */
export async function setupPasskeyGate(
  credentialId: ArrayBuffer,
  existingMS?: Uint8Array<ArrayBuffer>
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if passkey already setup
  if (await isPasskeySetup()) {
    return { success: false, error: 'PASSKEY_ALREADY_SETUP' };
  }

  /* c8 ignore start - defensive: client.ts always provides valid credentialId from WebAuthn (tested by Playwright) */
  // Validate inputs
  if (credentialId.byteLength === 0) {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
  /* c8 ignore stop */

  try {
    // Generate deterministic salt from credential ID
    // In gate-only mode, user verification gates access, not PRF entropy
    const credIdBytes = new Uint8Array(credentialId);
    const saltHash = await crypto.subtle.digest('SHA-256', credIdBytes);
    const appSalt = new Uint8Array(saltHash);

    // Derive KEK from deterministic salt using HKDF
    // This is secure because access is gated by user verification
    const kek = await hkdfDeriveKey(appSalt, appSalt, HKDF_INFO_KEK);

    // Get or generate Master Secret (MS)
    const ms = existingMS || crypto.getRandomValues(new Uint8Array(MS_LENGTH));

    // Encrypt MS with KEK
    const msIV = crypto.getRandomValues(new Uint8Array(12));
    const encryptedMS = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: msIV },
      kek,
      ms
    );

    // Store unlock configuration
    // eslint-disable-next-line no-console
    console.log('[unlock.ts] Storing passkey gate config:', {
      credentialIdLength: credentialId.byteLength,
      credentialIdBytes: new Uint8Array(credentialId).slice(0, 8),
      credentialIdType: Object.prototype.toString.call(credentialId),
    });

    await putMeta<UnlockPasskeyGateConfig>('passkeyConfig', {
      method: 'passkey-gate',
      credentialId: credentialId,
      appSalt: appSalt.buffer,
      encryptedMS,
      msIV: msIV.buffer,
    });

    return { success: true, ms };
    /* c8 ignore start - defensive: crypto operation failures are not testable without mocking crypto subsystem */
  } catch {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
  /* c8 ignore stop */
}

/**
 * Unlock with passkey gate-only mode
 *
 * NEW ARCHITECTURE: Decrypts Master Secret (MS) using gate-derived KEK
 *
 * NOTE: WebAuthn ceremony must be performed by CLIENT (main window context).
 * This function derives the KEK deterministically once authentication succeeds.
 * Security comes from client only calling this after successful WebAuthn.
 *
 * @returns Result with MS bytes or error
 */
export async function unlockWithPasskeyGate(): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if passkey is setup
  const config = await getMeta<UnlockPasskeyPRFConfig | UnlockPasskeyGateConfig>('passkeyConfig');
  if (!config || config.method !== 'passkey-gate') {
    return { success: false, error: 'NOT_SETUP' };
  }

  const appSalt = new Uint8Array(config.appSalt);

  try {
    // Derive KEK deterministically from stored salt
    // Security: This only runs if client successfully authenticated via WebAuthn
    const kek = await hkdfDeriveKey(appSalt, appSalt, HKDF_INFO_KEK);

    // Decrypt MS with KEK
    try {
      const msIV = new Uint8Array(config.msIV);
      const msBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: msIV },
        kek,
        config.encryptedMS
      );

      const ms = new Uint8Array(msBuffer);

      return { success: true, ms };
    } catch {
      return { success: false, error: 'INCORRECT_PASSKEY' };
    }
  /* c8 ignore start - defensive: WebAuthn failures tested by Playwright */
  } catch {
    return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
  }
  /* c8 ignore stop */
}


/**
 * Derive a wrapping key from passphrase using PBKDF2
 *
 * @param passphrase - User's passphrase
 * @param salt - Random salt (16 bytes)
 * @param iterations - PBKDF2 iteration count
 * @returns AES-GCM key for wrapping/unwrapping
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  // Import passphrase as raw key material
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  // Derive AES-GCM key using PBKDF2
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: iterations,
      hash: 'SHA-256',
    },
    passphraseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // non-extractable
    ['encrypt', 'decrypt'] // Changed from wrapKey/unwrapKey for MS encryption
  );

  return key;
}

// ============================================================================
// Internal Utilities
// ============================================================================

/**
 * Validate passphrase format and strength
 */
function validatePassphrase(passphrase: string):
  | { valid: true }
  | {
      valid: false;
      error:
        | 'INVALID_PASSPHRASE'
        | 'PASSPHRASE_TOO_SHORT'
        | 'ALREADY_SETUP'
        | 'NOT_SETUP'
        | 'INCORRECT_PASSPHRASE';
    } {
  // Check type
  if (typeof passphrase !== 'string') {
    return { valid: false, error: 'INVALID_PASSPHRASE' };
  }

  // Check empty
  if (passphrase === '') {
    return { valid: false, error: 'INVALID_PASSPHRASE' };
  }

  // Check minimum length
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    return { valid: false, error: 'PASSPHRASE_TOO_SHORT' };
  }

  return { valid: true };
}

/**
 * Derive key and verification hash from passphrase
 *
 * This uses PBKDF2 to derive bits, then:
 * 1. Imports first 256 bits as AES-GCM key (with wrapKey/unwrapKey usage)
 * 2. Hashes all derived bits for verification
 *
 * @param passphrase - User's passphrase
 * @param salt - Random salt (16 bytes)
 * @param iterations - PBKDF2 iteration count
 * @returns Object with key and verification hash
 */
async function deriveKeyWithVerification(
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<{ key: CryptoKey; verificationHash: string }> {
  // Import passphrase as raw key material
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive 512 bits (64 bytes) from passphrase
  // First 256 bits will be used for AES-GCM key
  // All bits will be hashed for verification
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: iterations,
      hash: 'SHA-256',
    },
    passphraseKey,
    512 // 512 bits = 64 bytes
  );

  // Hash all derived bits for verification
  const hashBuffer = await crypto.subtle.digest('SHA-256', derivedBits);
  const verificationHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Use first 256 bits to create AES-GCM key
  const keyBytes = new Uint8Array(derivedBits.slice(0, 32)); // First 32 bytes = 256 bits

  // Import as AES-GCM key with encrypt/decrypt usage (for MS encryption)
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // non-extractable
    ['encrypt', 'decrypt'] // Changed from wrapKey/unwrapKey for MS encryption
  );

  return { key, verificationHash };
}

/**
 * Derive AES-GCM KEK from PRF output using HKDF
 *
 * This provides cryptographic separation between the PRF output and the
 * final KEK, with purpose labeling via the info parameter.
 *
 * @param prfOutput - Output from WebAuthn PRF extension (32 bytes)
 * @param salt - Application salt for HKDF
 * @param info - Purpose label (e.g., 'ATS/KMS/KEK-wrap/v1')
 * @returns AES-GCM key for encrypting/decrypting MS
 */
async function hkdfDeriveKey(
  prfOutput: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: string
): Promise<CryptoKey> {
  // Import PRF output as key material
  const prfKey = await crypto.subtle.importKey(
    'raw',
    prfOutput,
    'HKDF',
    false,
    ['deriveKey']
  );

  // Derive AES-GCM key using HKDF
  const key = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: salt,
      info: new TextEncoder().encode(info),
      hash: 'SHA-256',
    },
    prfKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // non-extractable
    ['encrypt', 'decrypt'] // Changed from wrapKey/unwrapKey for MS encryption
  );

  return key;
}

// ============================================================================
// MKEK Derivation (for worker.ts)
// ============================================================================

/**
 * Derive Master KEK (MKEK) from Master Secret (MS) using HKDF
 *
 * NEW ARCHITECTURE: Worker calls this after unlocking to derive MKEK from MS
 *
 * The MKEK is used to wrap/unwrap application keys. It is derived deterministically
 * from the MS, so the same MS always produces the same MKEK.
 *
 * @param ms - Master Secret bytes (32 bytes)
 * @param salt - Optional salt for HKDF (default: zero bytes for determinism)
 * @returns Non-extractable AES-GCM key for wrapping/unwrapping
 */
export async function deriveMKEKFromMS(
  ms: Uint8Array<ArrayBuffer>,
  salt?: Uint8Array<ArrayBuffer>
): Promise<CryptoKey> {
  // Use zero salt by default for deterministic derivation
  const hkdfSalt = salt || new Uint8Array(32);

  // Import MS as HKDF key material
  const msKey = await crypto.subtle.importKey(
    'raw',
    ms,
    'HKDF',
    false,
    ['deriveKey']
  );

  // Derive MKEK using HKDF
  const mkek = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: hkdfSalt,
      info: new TextEncoder().encode(HKDF_INFO_MKEK),
      hash: 'SHA-256',
    },
    msKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // non-extractable (never needs to be exported)
    ['wrapKey', 'unwrapKey']
  );

  return mkek;
}

// ============================================================================
// Per-Operation Unlock Pattern
// ============================================================================

/**
 * Authentication credentials for per-operation unlock
 */
export type AuthCredentials =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer }
  | { method: 'passkey-gate' };

/**
 * Result of an operation with unlock timing
 */
export interface UnlockOperationResult<T> {
  result: T;
  unlockTime: number;
  lockTime: number;
  duration: number;
}

/**
 * Execute an operation with momentary unlock
 *
 * This is the SINGLE unlock mechanism all operations must use.
 * Ensures consistent behavior: unlock → operate → lock (cleanup)
 *
 * @param credentials - Authentication credentials
 * @param operation - Function to execute with MKEK
 * @returns Operation result with timing information
 */
export async function withUnlock<T>(
  credentials: AuthCredentials,
  operation: (mkek: CryptoKey) => Promise<T>
): Promise<UnlockOperationResult<T>> {
  const unlockTime = Date.now();
  let ms: Uint8Array<ArrayBuffer> | null = null;

  try {
    // Unlock: Decrypt MS from credentials
    switch (credentials.method) {
      case 'passphrase': {
        const result = await unlockWithPassphrase(credentials.passphrase);
        if (!result.success) {
          throw new Error(result.error || 'Passphrase unlock failed');
        }
        ms = result.ms;
        break;
      }

      case 'passkey-prf': {
        const result = await unlockWithPasskeyPRF(credentials.prfOutput);
        if (!result.success) {
          throw new Error(result.error || 'Passkey PRF unlock failed');
        }
        ms = result.ms;
        break;
      }

      case 'passkey-gate': {
        const result = await unlockWithPasskeyGate();
        if (!result.success) {
          throw new Error(result.error || 'Passkey gate unlock failed');
        }
        ms = result.ms;
        break;
      }

      default:
        throw new Error('Unknown authentication method');
    }

    // Derive MKEK from MS
    const mkek = await deriveMKEKFromMS(ms);

    // Operate: Execute operation with MKEK
    const operationResult = await operation(mkek);

    const lockTime = Date.now();
    const duration = lockTime - unlockTime;

    return {
      result: operationResult,
      unlockTime,
      lockTime,
      duration,
    };
  } finally {
    // Lock: ALWAYS clear MS (guaranteed cleanup)
    if (ms) {
      ms.fill(0);
    }
  }
}
