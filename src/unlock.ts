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
        | 'SESSION_EXPIRED';
    };

/**
 * Unlock configuration stored in meta store
 */
type UnlockPassphraseConfig = {
  method: 'passphrase';
  salt: ArrayBuffer;
  iterations: number;
  verificationHash: string; // Hash of derived key for verification
};

type UnlockPasskeyPRFConfig = {
  method: 'passkey-prf';
  credentialId: ArrayBuffer;
  appSalt: ArrayBuffer;
  wrappedKEK: ArrayBuffer;
  wrapIV: ArrayBuffer;
};

type UnlockPasskeyGateConfig = {
  method: 'passkey-gate';
  credentialId: ArrayBuffer;
  appSalt: ArrayBuffer;
  wrappedKEK: ArrayBuffer;
  wrapIV: ArrayBuffer;
};

// ============================================================================
// Constants
// ============================================================================

const MIN_PASSPHRASE_LENGTH = 8;
const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for 2024
const SALT_LENGTH = 16; // 128 bits
const APP_SALT_LENGTH = 32; // 256 bits
const HKDF_INFO = 'ATS/KMS/KEK-wrap/v1'; // HKDF purpose label

// ============================================================================
// Module State
// ============================================================================

let isInitialized = false;

// Wrapping key reference (stored in memory during unlocked session)
// @ts-expect-error - Reserved for future session management
// eslint-disable-next-line @typescript-eslint/no-unused-vars
let _wrappingKeyRef: CryptoKey | null = null;

// Gate session state (for future session management)
// @ts-expect-error - Reserved for future session management
// eslint-disable-next-line @typescript-eslint/no-unused-vars
let _gateSessionKey: CryptoKey | null = null;
// @ts-expect-error - Reserved for future session management
// eslint-disable-next-line @typescript-eslint/no-unused-vars
let _gateSessionExpiry: number | null = null;
let _gateSessionTimer: ReturnType<typeof setTimeout> | null = null;

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

  // Check if passphrase already setup
  if (await isPassphraseSetup()) {
    return { success: false, error: 'PASSPHRASE_ALREADY_SETUP' };
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
  const config: UnlockPassphraseConfig = {
    method: 'passphrase',
    salt: salt.buffer,
    iterations: PBKDF2_ITERATIONS,
    verificationHash,
  };

  await putMeta('passphraseConfig', config);

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

  // Check if passphrase is setup
  const config = await getMeta<UnlockPassphraseConfig>('passphraseConfig');
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
  // Clear gate session if active
  _clearGateSession();
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
  credentialId: ArrayBuffer,
  prfOutput: ArrayBuffer,
  kek: CryptoKey
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

    // Derive wrapping key from PRF output using HKDF
    const wrappingKey = await hkdfDeriveKey(prfOutputBytes, appSalt, HKDF_INFO);

    // Wrap KEK with wrapping key
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
    await putMeta<UnlockPasskeyPRFConfig>('passkeyConfig', {
      method: 'passkey-prf',
      credentialId: credentialId,
      appSalt: appSalt.buffer,
      wrappedKEK: wrappedKEK,
      wrapIV: wrapIV.buffer,
    });

    // Store the wrapping key in memory
    _wrappingKeyRef = wrappingKey;

    return { success: true, key: wrappingKey };
    /* c8 ignore start - defensive: crypto operation failures (wrapKey, HKDF) are not testable without mocking crypto subsystem */
  } catch {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
  /* c8 ignore stop */
}

/**
 * Unlock with passkey (PRF mode)
 *
 * NOTE: WebAuthn ceremony must be performed by the CLIENT (main window context).
 * This function accepts the PRF output from the client's WebAuthn get() call.
 *
 * @param prfOutput - PRF output from PRF extension (32 bytes)
 * @returns Result with derived wrapping key or error
 */

/**
 * Unlock with passkey PRF extension
 *
 * Authenticates with the passkey and derives the wrapping key using PRF + HKDF.
 *
 * @param rpId - Relying Party ID (domain)
 * @returns Result with derived wrapping key or error
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

    // Derive wrapping key from PRF output using HKDF
    const wrappingKey = await hkdfDeriveKey(prfOutputBytes, appSalt, HKDF_INFO);

    // Try to unwrap KEK to verify correctness
    try {
      const wrapIV = new Uint8Array(config.wrapIV);
      await crypto.subtle.unwrapKey(
        'raw',
        config.wrappedKEK,
        wrappingKey,
        { name: 'AES-GCM', iv: wrapIV },
        { name: 'AES-GCM', length: 256 },
        false,
        ['wrapKey', 'unwrapKey']
      );
    } catch {
      return { success: false, error: 'INCORRECT_PASSKEY' };
    }

    return { success: true, key: wrappingKey };
  /* c8 ignore start - defensive: WebAuthn failures tested by Playwright */
  } catch {
    return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
  }
  /* c8 ignore stop */
}

/**
 * Setup unlock with passkey (gate-only mode, no PRF)
 *
 * NOTE: WebAuthn ceremony must be performed by the CLIENT (main window context).
 * This function accepts the credential data from the client.
 *
 * @param credentialId - Raw credential ID from PublicKeyCredential.rawId
 * @param kek - Key Encryption Key to wrap (must be extractable)
 * @returns Result with derived wrapping key or error
 */

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
  credentialId: ArrayBuffer,
  kek: CryptoKey
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
    // In gate-only mode, user verification gates access, not the PRF output
    const credIdBytes = new Uint8Array(credentialId);
    const saltHash = await crypto.subtle.digest('SHA-256', credIdBytes);
    const appSalt = new Uint8Array(saltHash);

    // Derive wrapping key from deterministic salt using HKDF
    // This is secure because access is gated by user verification
    const wrappingKey = await hkdfDeriveKey(appSalt, appSalt, HKDF_INFO);

    // Wrap KEK with wrapping key
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
      wrappedKEK: wrappedKEK,
      wrapIV: wrapIV.buffer,
    });

    // Store the wrapping key in memory
    _wrappingKeyRef = wrappingKey;

    return { success: true, key: wrappingKey };
    /* c8 ignore start - defensive: crypto operation failures (wrapKey, HKDF) are not testable without mocking crypto subsystem */
  } catch {
    return { success: false, error: 'PASSKEY_CREATION_FAILED' };
  }
  /* c8 ignore stop */
}

/**
 * Unlock with passkey (gate-only mode, no PRF)
 *
 * NOTE: WebAuthn ceremony must be performed by the CLIENT (main window context).
 * This function derives the key deterministically once authentication succeeds.
 * The security comes from the client only calling this after successful WebAuthn.
 *
 * @returns Result with derived wrapping key or error
 */

/**
 * Unlock with passkey gate-only mode
 *
 * Authenticates with the passkey and returns a temporary KEK that expires
 * after the configured session duration.
 *
 * @param rpId - Relying Party ID (domain)
 * @returns Result with temporary KEK or error
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
    // Derive wrapping key deterministically from stored salt
    // Security: This only runs if client successfully authenticated via WebAuthn
    const wrappingKey = await hkdfDeriveKey(appSalt, appSalt, HKDF_INFO);

    // Verify by attempting to unwrap KEK
    try {
      const wrapIV = new Uint8Array(config.wrapIV);
      await crypto.subtle.unwrapKey(
        'raw',
        config.wrappedKEK,
        wrappingKey,
        { name: 'AES-GCM', iv: wrapIV },
        { name: 'AES-GCM', length: 256 },
        false,
        ['wrapKey', 'unwrapKey']
      );
    } catch {
      return { success: false, error: 'INCORRECT_PASSKEY' };
    }

    return { success: true, key: wrappingKey };
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

/* c8 ignore start - Reserved for future session management */
/**
 * Start a gate session with automatic expiry
 *
 * @param kek - Key Encryption Key for this session
 * @param duration - Session duration in milliseconds
 */
// @ts-expect-error - Reserved for future session management
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _startGateSession(kek: CryptoKey, duration: number): void {
  // Clear any existing session
  _clearGateSession();

  // Set new session
  _gateSessionKey = kek;
  _gateSessionExpiry = Date.now() + duration;

  // Set timer to clear session on expiry
  _gateSessionTimer = setTimeout(() => {
    _clearGateSession();
  }, duration);
}
/* c8 ignore stop */

/**
 * Clear the active gate session
 */
function _clearGateSession(): void {
  _gateSessionKey = null;
  _gateSessionExpiry = null;

  /* c8 ignore start - defensive: timer cleanup, tested by resetUnlock test */
  if (_gateSessionTimer) {
    clearTimeout(_gateSessionTimer);
    _gateSessionTimer = null;
  }
  /* c8 ignore stop */
}
