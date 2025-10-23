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
 */
export type UnlockResult =
  | { success: true; key: CryptoKey }
  | {
      success: false;
      error:
        | 'INVALID_PASSPHRASE'
        | 'PASSPHRASE_TOO_SHORT'
        | 'ALREADY_SETUP'
        | 'NOT_SETUP'
        | 'INCORRECT_PASSPHRASE';
    };

/**
 * Unlock configuration stored in meta store
 */
interface UnlockConfig {
  method: 'passphrase';
  salt: ArrayBuffer;
  iterations: number;
  verificationHash: string; // Hash of derived key for verification
}

// ============================================================================
// Constants
// ============================================================================

const MIN_PASSPHRASE_LENGTH = 8;
const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for 2024
const SALT_LENGTH = 16; // 128 bits

// ============================================================================
// Module State
// ============================================================================

let isInitialized = false;

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
 * Check if unlock is configured
 */
export async function isSetup(): Promise<boolean> {
  await ensureInitialized();
  const config = await getMeta<UnlockConfig>('unlockSalt');
  return config !== undefined;
}

/**
 * Setup passphrase-based unlock
 *
 * This should be called on first use to configure the unlock mechanism.
 *
 * @param passphrase - User's passphrase (min 8 characters)
 * @returns Result with derived wrapping key or error
 */
export async function setupPassphrase(passphrase: string): Promise<UnlockResult> {
  await ensureInitialized();

  // Validate passphrase
  const validation = validatePassphrase(passphrase);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  // Check if already setup
  if (await isSetup()) {
    return { success: false, error: 'ALREADY_SETUP' };
  }

  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  // Derive bits for both key and verification
  const result = await deriveKeyWithVerification(
    passphrase,
    salt,
    PBKDF2_ITERATIONS
  );
  const key = result.key;
  const verificationHash = result.verificationHash;

  // Store unlock configuration
  const config: UnlockConfig = {
    method: 'passphrase',
    salt: salt.buffer,
    iterations: PBKDF2_ITERATIONS,
    verificationHash,
  };

  await putMeta('unlockSalt', config);

  return { success: true, key };
}

/**
 * Unlock with passphrase
 *
 * Derives the wrapping key from the user's passphrase.
 *
 * @param passphrase - User's passphrase
 * @returns Result with derived wrapping key or error
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

  // Check if setup
  const config = await getMeta<UnlockConfig>('unlockSalt');
  if (!config) {
    return { success: false, error: 'NOT_SETUP' };
  }

  // Derive key and verification hash from passphrase
  const salt = new Uint8Array(config.salt);
  const { key, verificationHash } = await deriveKeyWithVerification(
    passphrase,
    salt,
    config.iterations
  );

  // Verify passphrase is correct by comparing hash
  if (verificationHash !== config.verificationHash) {
    return { success: false, error: 'INCORRECT_PASSPHRASE' };
  }

  return { success: true, key };
}

/**
 * Reset unlock configuration
 *
 * WARNING: This will delete the unlock configuration.
 * For testing purposes only.
 */
export async function resetUnlock(): Promise<void> {
  await ensureInitialized();
  await deleteMeta('unlockSalt');
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
    ['wrapKey', 'unwrapKey']
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

  // Import as AES-GCM key with wrapKey/unwrapKey usage
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // non-extractable
    ['wrapKey', 'unwrapKey']
  );

  return { key, verificationHash };
}
