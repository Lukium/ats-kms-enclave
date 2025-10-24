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
        | 'INCORRECT_PASSPHRASE'
        | 'PASSKEY_NOT_AVAILABLE'
        | 'PASSKEY_CREATION_FAILED'
        | 'PASSKEY_AUTHENTICATION_FAILED'
        | 'PASSKEY_PRF_NOT_SUPPORTED'
        | 'INCORRECT_PASSKEY'
        | 'SESSION_EXPIRED';
    };

/**
 * Unlock configuration stored in meta store
 */
type UnlockConfig =
  | {
      method: 'passphrase';
      salt: ArrayBuffer;
      iterations: number;
      verificationHash: string; // Hash of derived key for verification
    }
  | {
      method: 'passkey-prf';
      credentialId: ArrayBuffer;
      appSalt: ArrayBuffer;
      wrappedKEK: ArrayBuffer;
      wrapIV: ArrayBuffer;
    }
  | {
      method: 'passkey-gate';
      credentialId: ArrayBuffer;
      sessionDuration: number;
    };

// ============================================================================
// Constants
// ============================================================================

const MIN_PASSPHRASE_LENGTH = 8;
const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for 2024
const SALT_LENGTH = 16; // 128 bits
const APP_SALT_LENGTH = 32; // 256 bits
const SESSION_DURATION_MS = 5 * 60 * 1000; // 5 minutes
const HKDF_INFO = 'ATS/KMS/KEK-wrap/v1'; // HKDF purpose label

// ============================================================================
// Module State
// ============================================================================

let isInitialized = false;

// Gate session state (only for passkey-gate mode)
let gateSessionKey: CryptoKey | null = null;
let gateSessionExpiry: number | null = null;
let gateSessionTimer: ReturnType<typeof setTimeout> | null = null;

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

  if (config.method !== 'passphrase') {
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
  // Clear gate session if active
  clearGateSession();
}

/**
 * Setup passkey-based unlock with PRF extension
 *
 * This uses the WebAuthn PRF (hmac-secret) extension to derive a deterministic
 * key from the passkey. The derived key is used with HKDF to create a wrapping key
 * that protects the provided KEK.
 *
 * @param rpId - Relying Party ID (domain)
 * @param rpName - Relying Party display name
 * @param kek - Key Encryption Key to wrap (must be extractable)
 * @returns Result with derived wrapping key or error
 */
export async function setupPasskeyPRF(
  rpId: string,
  rpName: string,
  kek: CryptoKey
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if already setup
  if (await isSetup()) {
    return { success: false, error: 'ALREADY_SETUP' };
  }

  // Check WebAuthn availability
  if (
    typeof navigator === 'undefined' ||
    typeof window === 'undefined' ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  ) {
    return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
  }

  // Generate random app salt for HKDF
  const appSalt = crypto.getRandomValues(new Uint8Array(APP_SALT_LENGTH));

  try {
    // Create passkey with PRF extension
    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: rpId, name: rpName },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'kms-user',
          displayName: 'KMS User',
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'required',
        },
        extensions: {
          prf: {},
        },
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { success: false, error: 'PASSKEY_CREATION_FAILED' };
    }

    const clientExtensionResults = credential.getClientExtensionResults();

    // Verify PRF extension is supported
    if (!clientExtensionResults.prf?.enabled) {
      return { success: false, error: 'PASSKEY_PRF_NOT_SUPPORTED' };
    }

    // Derive PRF output (first auth with same passkey)
    const assertionCredential = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: rpId,
        allowCredentials: [
          {
            type: 'public-key',
            id: credential.rawId,
          },
        ],
        userVerification: 'required',
        extensions: {
          prf: {
            eval: {
              first: appSalt,
            },
          },
        },
      },
    })) as PublicKeyCredential | null;

    if (!assertionCredential) {
      return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
    }

    const prfResults = assertionCredential.getClientExtensionResults().prf;

    if (!prfResults?.results?.first) {
      return { success: false, error: 'PASSKEY_PRF_NOT_SUPPORTED' };
    }

    // Derive wrapping key using HKDF
    const prfOutput = new Uint8Array(prfResults.results.first as ArrayBuffer);
    const wrappingKey = await hkdfDeriveKey(prfOutput, appSalt, HKDF_INFO);

    // Wrap the KEK with the derived wrapping key
    const wrapIV = crypto.getRandomValues(new Uint8Array(12));
    const wrappedKEK = await crypto.subtle.wrapKey(
      'raw',
      kek,
      wrappingKey,
      {
        name: 'AES-GCM',
        iv: wrapIV,
      }
    );

    // Store unlock configuration
    const config: UnlockConfig = {
      method: 'passkey-prf',
      credentialId: credential.rawId,
      appSalt: appSalt.buffer,
      wrappedKEK: wrappedKEK,
      wrapIV: wrapIV.buffer,
    };

    await putMeta('unlockSalt', config);

    return { success: true, key: wrappingKey };
  } catch {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
}

/**
 * Unlock with passkey PRF extension
 *
 * Authenticates with the passkey and derives the wrapping key using PRF + HKDF.
 *
 * @param rpId - Relying Party ID (domain)
 * @returns Result with derived wrapping key or error
 */
export async function unlockWithPasskeyPRF(
  rpId: string
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if setup
  const config = await getMeta<UnlockConfig>('unlockSalt');
  if (!config) {
    return { success: false, error: 'NOT_SETUP' };
  }

  if (config.method !== 'passkey-prf') {
    return { success: false, error: 'NOT_SETUP' };
  }

  // Check WebAuthn availability
  if (
    typeof navigator === 'undefined' ||
    typeof window === 'undefined' ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  ) {
    return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
  }

  const appSalt = new Uint8Array(config.appSalt);

  try {
    // Authenticate with passkey and get PRF output
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: rpId,
        allowCredentials: [
          {
            type: 'public-key',
            id: config.credentialId,
          },
        ],
        userVerification: 'required',
        extensions: {
          prf: {
            eval: {
              first: appSalt,
            },
          },
        },
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
    }

    const prfResults = credential.getClientExtensionResults().prf;

    if (!prfResults?.results?.first) {
      return { success: false, error: 'PASSKEY_PRF_NOT_SUPPORTED' };
    }

    // Derive wrapping key using HKDF
    const prfOutput = new Uint8Array(prfResults.results.first as ArrayBuffer);
    const wrappingKey = await hkdfDeriveKey(prfOutput, appSalt, HKDF_INFO);

    // Verify by unwrapping the KEK (if wrapping key is wrong, this will throw)
    try {
      await crypto.subtle.unwrapKey(
        'raw',
        config.wrappedKEK,
        wrappingKey,
        {
          name: 'AES-GCM',
          iv: new Uint8Array(config.wrapIV),
        },
        {
          name: 'AES-GCM',
          length: 256,
        },
        true, // extractable (for re-wrapping if needed)
        ['wrapKey', 'unwrapKey']
      );

      return { success: true, key: wrappingKey };
    } catch {
      return { success: false, error: 'INCORRECT_PASSKEY' };
    }
  } catch {
    return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
  }
}

/**
 * Setup passkey-based unlock with gate-only mode
 *
 * This is a fallback mode for when PRF is not supported. The passkey acts as
 * a gate/authenticator - on successful authentication, we generate a temporary
 * KEK that expires after a fixed duration.
 *
 * @param rpId - Relying Party ID (domain)
 * @param rpName - Relying Party display name
 * @returns Result with temporary KEK or error
 */
export async function setupPasskeyGate(
  rpId: string,
  rpName: string
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if already setup
  if (await isSetup()) {
    return { success: false, error: 'ALREADY_SETUP' };
  }

  // Check WebAuthn availability
  if (
    typeof navigator === 'undefined' ||
    typeof window === 'undefined' ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  ) {
    return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
  }

  try {
    // Create passkey without PRF extension
    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: rpId, name: rpName },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'kms-user',
          displayName: 'KMS User',
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'required',
        },
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { success: false, error: 'PASSKEY_CREATION_FAILED' };
    }

    // Generate temporary KEK for this session
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (required for wrapKey operation)
      ['wrapKey', 'unwrapKey']
    );

    // Store unlock configuration
    const config: UnlockConfig = {
      method: 'passkey-gate',
      credentialId: credential.rawId,
      sessionDuration: SESSION_DURATION_MS,
    };

    await putMeta('unlockSalt', config);

    // Start gate session
    startGateSession(kek, SESSION_DURATION_MS);

    return { success: true, key: kek };
  } catch {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
}

/**
 * Unlock with passkey gate-only mode
 *
 * Authenticates with the passkey and returns a temporary KEK that expires
 * after the configured session duration.
 *
 * @param rpId - Relying Party ID (domain)
 * @returns Result with temporary KEK or error
 */
export async function unlockWithPasskeyGate(
  rpId: string
): Promise<UnlockResult> {
  await ensureInitialized();

  // Check if setup
  const config = await getMeta<UnlockConfig>('unlockSalt');
  if (!config) {
    return { success: false, error: 'NOT_SETUP' };
  }

  if (config.method !== 'passkey-gate') {
    return { success: false, error: 'NOT_SETUP' };
  }

  // Check if session is still active
  if (gateSessionKey && gateSessionExpiry && Date.now() < gateSessionExpiry) {
    return { success: true, key: gateSessionKey };
  }

  // Check WebAuthn availability
  if (
    typeof navigator === 'undefined' ||
    typeof window === 'undefined' ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  ) {
    return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
  }

  try {
    // Authenticate with passkey
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: rpId,
        allowCredentials: [
          {
            type: 'public-key',
            id: config.credentialId,
          },
        ],
        userVerification: 'required',
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
    }

    // Generate new temporary KEK for this session
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (required for wrapKey operation)
      ['wrapKey', 'unwrapKey']
    );

    // Start gate session
    startGateSession(kek, config.sessionDuration);

    return { success: true, key: kek };
  } catch {
    return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
  }
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

/**
 * Derive AES-GCM wrapping key from PRF output using HKDF
 *
 * This provides cryptographic separation between the PRF output and the
 * final wrapping key, with purpose labeling via the info parameter.
 *
 * @param prfOutput - Output from WebAuthn PRF extension (32 bytes)
 * @param salt - Application salt for HKDF
 * @param info - Purpose label (e.g., 'ATS/KMS/KEK-wrap/v1')
 * @returns AES-GCM key for wrapping/unwrapping
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
    ['wrapKey', 'unwrapKey']
  );

  return key;
}

/**
 * Start a gate session with automatic expiry
 *
 * @param kek - Key Encryption Key for this session
 * @param duration - Session duration in milliseconds
 */
function startGateSession(kek: CryptoKey, duration: number): void {
  // Clear any existing session
  clearGateSession();

  // Set new session
  gateSessionKey = kek;
  gateSessionExpiry = Date.now() + duration;

  /* c8 ignore next 4 - Would take 5 minutes to tes */
  // Set timer to clear session on expiry
  gateSessionTimer = setTimeout(() => {
    clearGateSession();
  }, duration);
}

/**
 * Clear the active gate session
 */
function clearGateSession(): void {
  gateSessionKey = null;
  gateSessionExpiry = null;

  if (gateSessionTimer) {
    clearTimeout(gateSessionTimer);
    gateSessionTimer = null;
  }
}
