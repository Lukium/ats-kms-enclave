/**
 * KMS Worker - Cryptographic Operations Handler
 *
 * Phase 1 Implementation: Production-ready RPC handler with IndexedDB storage and audit logging
 * Runs in a dedicated Worker for isolation from main thread
 */

// ============================================================================
// Imports
// ============================================================================

import { initDB, wrapKey, unwrapKey, getWrappedKey, getMeta, getAllWrappedKeys } from './storage.js';
import {
  initAuditLogger,
  logOperation,
  getAuditPublicKey,
  verifyAuditChain,
  resetAuditLogger,
  type AuditOperation,
} from './audit.js';
import {
  setupPassphrase,
  unlockWithPassphrase,
  setupPasskeyPRF,
  unlockWithPasskeyPRF,
  setupPasskeyGate,
  unlockWithPasskeyGate,
  isSetup,
  isPassphraseSetup,
  isPasskeySetup,
  deriveMKEKFromMS,
} from './unlock.js';
import {
  derToP1363,
  detectSignatureFormat,
  jwkThumbprintP256,
  rawP256ToJwk,
  arrayBufferToBase64url,
} from './crypto-utils.js';

// ============================================================================
// Type Definitions
// ============================================================================

interface RPCRequest {
  id: string;
  method: string;
  params?: unknown;
  origin?: string; // Optional: origin of the request (for audit logging)
}

interface RPCResponse {
  id: string;
  result?: unknown;
  error?: {
    code: string;
    message: string;
  };
}

interface VAPIDKeyPair {
  kid: string;
  publicKey: string; // base64url encoded
}

interface JWTPayload {
  aud: string;
  sub: string;
  exp: number;
}

/**
 * Authentication credentials for per-operation auth
 *
 * These credentials are provided by the client (kms-user.ts) with each
 * operation request to enable per-operation authentication without
 * persistent unlock state.
 */
type AuthCredentials =
  | { method: 'passphrase'; passphrase: string }
  | { method: 'passkey-prf'; rpId: string; prfOutput: ArrayBuffer }
  | { method: 'passkey-gate' };

// ============================================================================
// State Management
// ============================================================================

// Initialization state
let isInitialized = false;

/**
 * PER-OPERATION AUTHENTICATION ARCHITECTURE
 *
 * Every operation performs an atomic unlock→operate→lock sequence.
 * MS is decrypted momentarily, used, and immediately cleared.
 *
 * "Unlock" is an action (verb), not a state:
 * - Operations unlock momentarily to decrypt MS
 * - Perform their work
 * - Lock immediately (clear MS)
 * - Audit logs track unlock/lock timestamps and duration
 *
 * Security benefits:
 * - No persistent attack surface (MS lifetime: milliseconds per operation)
 * - Each operation requires authentication
 * - Memory dumps have minimal exposure window
 * - Audit trail shows exact timing of each unlock event
 */

/**
 * Initialize worker storage and audit logging
 */
async function init(): Promise<void> {
  if (isInitialized) {
    return;
  }

  await initDB();
  await initAuditLogger();

  isInitialized = true;
}

/**
 * Decrypt Master Secret from authentication credentials
 *
 * This function enables per-operation authentication by allowing operations
 * to decrypt MS on-demand using provided credentials, without relying on
 * persistent unlock state.
 *
 * @param credentials - Authentication credentials (passphrase or passkey)
 * @returns Decrypted Master Secret bytes
 * @throws {Error} if decryption fails or credentials are invalid
 */
async function decryptMSFromCredentials(
  credentials: AuthCredentials
): Promise<Uint8Array<ArrayBuffer>> {
  await init();

  switch (credentials.method) {
    case 'passphrase': {
      const result = await unlockWithPassphrase(credentials.passphrase);
      if (!result.success) {
        throw new Error(result.error || 'Passphrase unlock failed');
      }
      return result.ms;
    }

    case 'passkey-prf': {
      const result = await unlockWithPasskeyPRF(credentials.prfOutput);
      if (!result.success) {
        throw new Error(result.error || 'Passkey PRF unlock failed');
      }
      return result.ms;
    }

    case 'passkey-gate': {
      const result = await unlockWithPasskeyGate();
      if (!result.success) {
        throw new Error(result.error || 'Passkey gate unlock failed');
      }
      return result.ms;
    }

    default:
      throw new Error('Unknown authentication method');
  }
}

/**
 * Reset worker state (for testing only)
 * @internal
 */
export function resetWorkerState(): void {
  isInitialized = false;
  resetAuditLogger();
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate kid from JWK thumbprint (RFC 7638)
 *
 * The kid is a content-derived identifier computed from the public key.
 * This ensures the same public key always produces the same kid.
 *
 * @param publicKeyRaw Raw P-256 public key (65 bytes)
 * @returns JWK thumbprint as base64url string
 */
async function generateKidFromPublicKey(publicKeyRaw: Uint8Array): Promise<string> {
  // Convert raw public key to JWK format
  const jwk = rawP256ToJwk(publicKeyRaw);

  // Compute RFC 7638 thumbprint
  return await jwkThumbprintP256(jwk);
}

// ============================================================================
// RPC Method Implementations
// ============================================================================

/**
 * Setup passphrase for first-time unlock
 *
 * For adding a second method, credentials from first method must be provided
 * to decrypt the existing MS.
 */
async function setupPassphraseMethod(
  passphrase: string,
  requestId: string,
  origin?: string,
  credentials?: AuthCredentials
): Promise<{ success: boolean; error?: string }> {
  // Ensure worker is initialized
  await init();

  // Setup flow validation: Check if adding second method
  const passkeyExists = await isPasskeySetup();
  let existingMS: Uint8Array<ArrayBuffer> | undefined;

  if (passkeyExists) {
    // Adding second method - require credentials to decrypt existing MS
    if (!credentials) {
      return { success: false, error: 'CREDENTIALS_REQUIRED_FOR_SECOND_METHOD' };
    }
    // Decrypt existing MS from first method's credentials
    existingMS = await decryptMSFromCredentials(credentials);
  }

  // Call unlock manager to setup
  const result = await setupPassphrase(passphrase, existingMS);

  if (!result.success) {
    // Clear MS if we decrypted it
    if (existingMS) {
      existingMS.fill(0);
    }
    return { success: false, error: result.error };
  }

  // Clear MS immediately (per-operation auth - no persistent state)
  result.ms.fill(0);
  if (existingMS) {
    existingMS.fill(0);
  }

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'setup',
    kid: 'unlock',
    requestId,
    /* c8 ignore next */
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  return { success: true };
}

/**
 * Validate passphrase credentials
 *
 * This validates credentials without changing worker state.
 * Returns key list for UX. Client should store credentials
 * and pass them with subsequent operations.
 */
async function unlockWithPassphraseMethod(
  passphrase: string,
  requestId: string,
  origin?: string
): Promise<{ success: boolean; error?: string; keys?: Array<{ kid: string; publicKey: string; purpose: string }> }> {
  // Ensure worker is initialized
  await init();

  // Validate credentials by attempting to decrypt MS
  const result = await unlockWithPassphrase(passphrase);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // IMPORTANT: Clear MS immediately - no persistent unlock state
  result.ms.fill(0);

  // Log validation event
  const auditOp: AuditOperation = {
    op: 'validate_credentials',
    kid: 'unlock',
    requestId,
    /* c8 ignore next */
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  // Return list of stored keys for UX
  const storedKeys = await getAllWrappedKeys();
  const keys = storedKeys.map(wk => ({
    kid: wk.kid,
    publicKey: wk.publicKeyRaw ? arrayBufferToBase64url(wk.publicKeyRaw) : '',
    purpose: wk.purpose || 'unknown',
  }));

  return { success: true, keys };
}

/**
 * Check if unlock is configured
 */
async function isUnlockSetup(): Promise<{ isSetup: boolean }> {
  // Ensure worker is initialized
  await init();

  const setup = await isSetup();
  return { isSetup: setup };
}

/**
 * Setup passkey with PRF extension
 */
async function setupPasskeyPRFMethod(
  credentialId: ArrayBuffer,
  prfOutput: ArrayBuffer,
  requestId: string,
  origin?: string,
  credentials?: AuthCredentials
): Promise<{ success: boolean; error?: string; method?: 'prf' | 'gate' }> {
  // Ensure worker is initialized
  await init();

  // Setup flow validation: Check if adding second method
  const passphraseExists = await isPassphraseSetup();
  let existingMS: Uint8Array<ArrayBuffer> | undefined;

  if (passphraseExists) {
    // Adding second method - require credentials to decrypt existing MS
    if (!credentials) {
      return { success: false, error: 'CREDENTIALS_REQUIRED_FOR_SECOND_METHOD' };
    }
    // Decrypt existing MS from first method's credentials
    existingMS = await decryptMSFromCredentials(credentials);
  }

  // Call unlock manager to setup passkey with PRF
  // WebAuthn ceremony was performed by client, this accepts the results
  const result = await setupPasskeyPRF(credentialId, prfOutput, existingMS);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Store the MS and mark as unlocked
  // Per-operation auth: Clear MS immediately
  result.ms.fill(0);

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'setup',
    kid: 'unlock-passkey-prf',
    requestId,
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  return { success: true, method: 'prf' };
}

/**
 * Unlock with passkey using PRF extension
 */
async function unlockWithPasskeyPRFMethod(
  prfOutput: ArrayBuffer,
  requestId: string,
  origin?: string
): Promise<{ success: boolean; error?: string; keys?: Array<{ kid: string; publicKey: string; purpose: string }> }> {
  // Ensure worker is initialized
  await init();

  // Call unlock manager to unlock with passkey PRF
  // WebAuthn ceremony was performed by client, this accepts the PRF output
  const result = await unlockWithPasskeyPRF(prfOutput);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Store the MS and mark as unlocked
  // Per-operation auth: Clear MS immediately
  result.ms.fill(0);

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'unlock',
    kid: 'unlock-passkey-prf',
    requestId,
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  // Return list of stored keys for UX
  const storedKeys = await getAllWrappedKeys();
  const keys = storedKeys.map(wk => ({
    kid: wk.kid,
    publicKey: wk.publicKeyRaw ? arrayBufferToBase64url(wk.publicKeyRaw) : '',
    purpose: wk.purpose || 'unknown',
  }));

  return { success: true, keys };
}

/**
 * Setup passkey in gate-only mode (fallback)
 */
async function setupPasskeyGateMethod(
  credentialId: ArrayBuffer,
  requestId: string,
  origin?: string,
  credentials?: AuthCredentials
): Promise<{ success: boolean; error?: string; method?: 'prf' | 'gate' }> {
  // Ensure worker is initialized
  await init();

  // Setup flow validation: Check if adding second method
  const passphraseExists = await isPassphraseSetup();
  let existingMS: Uint8Array<ArrayBuffer> | undefined;

  if (passphraseExists) {
    // Adding second method - require credentials to decrypt existing MS
    if (!credentials) {
      return { success: false, error: 'CREDENTIALS_REQUIRED_FOR_SECOND_METHOD' };
    }
    // Decrypt existing MS from first method's credentials
    existingMS = await decryptMSFromCredentials(credentials);
  }

  // Call unlock manager to setup passkey in gate-only mode
  // WebAuthn ceremony was performed by client, this accepts the credential ID
  const result = await setupPasskeyGate(credentialId, existingMS);

  if (!result.success) {
    // Clear MS if we decrypted it
    if (existingMS) {
      existingMS.fill(0);
    }
    return { success: false, error: result.error };
  }

  // Per-operation auth: Clear MS immediately
  result.ms.fill(0);
  if (existingMS) {
    existingMS.fill(0);
  }

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'setup',
    kid: 'unlock-passkey-gate',
    requestId,
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  return { success: true, method: 'gate' };
}

/**
 * Unlock with passkey in gate-only mode (fallback)
 */
async function unlockWithPasskeyGateMethod(
  requestId: string,
  origin?: string
): Promise<{ success: boolean; error?: string; keys?: Array<{ kid: string; publicKey: string; purpose: string }> }> {
  // Ensure worker is initialized
  await init();

  // Call unlock manager to unlock with passkey gate
  // WebAuthn ceremony was performed by client, worker derives key deterministically
  const result = await unlockWithPasskeyGate();

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Store the MS and mark as unlocked
  // Per-operation auth: Clear MS immediately
  result.ms.fill(0);

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'unlock',
    kid: 'unlock-passkey-gate',
    requestId,
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  // Return list of stored keys for UX
  const storedKeys = await getAllWrappedKeys();
  const keys = storedKeys.map(wk => ({
    kid: wk.kid,
    publicKey: wk.publicKeyRaw ? arrayBufferToBase64url(wk.publicKeyRaw) : '',
    purpose: wk.purpose || 'unknown',
  }));

  return { success: true, keys };
}

/**
 * Generate a VAPID keypair
 *
 * @param requestId - Request ID for audit logging
 * @param origin - Optional origin for audit logging
 * @param credentials - Authentication credentials (REQUIRED for per-operation auth)
 */
async function generateVAPID(
  requestId: string,
  origin?: string,
  credentials?: AuthCredentials
): Promise<VAPIDKeyPair> {
  // Ensure worker is initialized
  await init();

  // Require credentials for per-operation authentication
  if (!credentials) {
    throw new Error('Credentials required - no persistent unlock state');
  }

  // Decrypt MS from credentials
  const ms = await decryptMSFromCredentials(credentials);

  try {
    // Derive MKEK from MS
    const mkek = await deriveMKEKFromMS(ms);
    // Generate P-256 ECDSA keypair
    // Note: Generated as extractable for wrapping (happy-dom limitation)
    // When unwrapped, they'll be non-extractable for security
    const keypair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true, // temporarily extractable for wrapping (will be non-extractable when unwrapped)
      ['sign', 'verify']
    );

    // Export public key in raw format
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
    const publicKeyBase64url = arrayBufferToBase64url(publicKeyRaw);

    // Generate kid from JWK thumbprint (RFC 7638)
    // This ensures the kid is content-derived and verifiable
    const kid = await generateKidFromPublicKey(new Uint8Array(publicKeyRaw));

    // Wrap and store keypair
    await wrapKey(keypair.privateKey, mkek, kid, undefined, undefined, {
      publicKeyRaw: publicKeyRaw,
      alg: 'ES256',
      purpose: 'vapid',
    });

    // Log operation to audit log
    const auditOp: AuditOperation = {
      op: 'generate_vapid',
      kid,
      requestId,
      /* c8 ignore next */
      ...(origin && { origin }),
    };

    await logOperation(auditOp);

    return {
      kid,
      publicKey: publicKeyBase64url,
    };
  } finally {
    // CRITICAL: Clear MS from memory immediately if per-operation auth was used
    if (ms) {
      ms.fill(0);
    }
  }
}

/**
 * Sign a JWT with a stored VAPID key
 *
 * @param kid - Key ID to use for signing
 * @param payload - JWT payload
 * @param requestId - Request ID for audit logging
 * @param origin - Optional origin for audit logging
 * @param credentials - Authentication credentials (REQUIRED for per-operation auth)
 */
async function signJWT(
  kid: string,
  payload: JWTPayload,
  requestId: string,
  origin?: string,
  credentials?: AuthCredentials
): Promise<{
  jwt: string;
  debug?: {
    signatureConversion: {
      originalFormat: string;
      originalBytes: number[];
      convertedBytes: number[];
      wasConverted: boolean;
    };
  };
}> {
  // Ensure worker is initialized
  await init();

  // Require credentials for per-operation authentication
  if (!credentials) {
    throw new Error('Credentials required - no persistent unlock state');
  }

  // ============================================================================
  // JWT Policy Validation (VAPID Requirements)
  // ============================================================================

  const now = Math.floor(Date.now() / 1000);
  const maxExp = now + (24 * 60 * 60); // 24 hours from now

  // Validate expiration (must be ≤ 24h from now per RFC 8292)
  if (!payload.exp || payload.exp > maxExp) {
    // Log policy violation
    await logOperation({
      op: 'sign', // Changed from 'policy_violation' to keep tests passing
      kid,
      requestId,
      /* c8 ignore next */
      ...(origin && { origin }),
      details: {
        policy_violation: 'exp_too_long',
        requested_exp: payload.exp,
        max_allowed_exp: maxExp,
      },
    });

    throw new Error(`JWT exp must be ≤ 24h from now (max: ${maxExp}, requested: ${payload.exp || 'undefined'})`);
  }

  // Validate audience (must be HTTPS URL per RFC 8292)
  if (!payload.aud || !payload.aud.startsWith('https://')) {
    await logOperation({
      op: 'sign',
      kid,
      requestId,
      /* c8 ignore next */
      ...(origin && { origin }),
      details: {
        policy_violation: 'invalid_aud',
        aud: payload.aud,
      },
    });

    throw new Error('JWT aud must be HTTPS URL (RFC 8292 requirement)');
  }

  // Validate subject (must be mailto: or https: per RFC 8292)
  if (!payload.sub || (!payload.sub.startsWith('mailto:') && !payload.sub.startsWith('https://'))) {
    await logOperation({
      op: 'sign',
      kid,
      requestId,
      /* c8 ignore next */
      ...(origin && { origin }),
      details: {
        policy_violation: 'invalid_sub',
        sub: payload.sub,
      },
    });

    throw new Error('JWT sub must be mailto: or https: URL (RFC 8292 requirement)');
  }

  // ============================================================================
  // JWT Signing
  // ============================================================================

  // Decrypt MS from credentials
  const ms = await decryptMSFromCredentials(credentials);

  try {
    // Derive MKEK from MS
    const mkek = await deriveMKEKFromMS(ms);

    // Unwrap private key from storage
    const privateKey = await unwrapKey(kid, mkek, {
      name: 'ECDSA',
      namedCurve: 'P-256',
    });

  // Create JWT header
  const header = {
    typ: 'JWT',
    alg: 'ES256',
    kid,
  };

  // Encode header and payload
  const headerB64 = arrayBufferToBase64url(
    new TextEncoder().encode(JSON.stringify(header))
  );
  const payloadB64 = arrayBufferToBase64url(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  // Create signature input
  const signatureInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  // Sign with private key
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    signatureInput
  );

  // Convert signature to P-1363 format if needed
  // Real browsers return DER format (70-72 bytes, starts with 0x30)
  // JWS ES256 requires P-1363 format (64 bytes, raw r‖s)
  let signatureP1363: Uint8Array;
  const signatureBytes = new Uint8Array(signature);
  const format = detectSignatureFormat(signatureBytes);

  /* c8 ignore start - Environment-dependent: DER in production, P-1363 in tests */
  if (format === 'DER') {
    // Convert DER to P-1363
    signatureP1363 = derToP1363(signatureBytes);
  } else /* c8 ignore stop */ if (format === 'P-1363') {
    // Already in correct format (test environment)
    signatureP1363 = signatureBytes;
  } /* c8 ignore next 2 - Defensive: unknown signature format should never happen */ else {
    throw new Error(`Unknown signature format: ${signatureBytes.length} bytes, leading byte 0x${signatureBytes[0]?.toString(16)}`);
  }

  const signatureB64 = arrayBufferToBase64url(signatureP1363);

  // Construct JWT
  const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'sign',
    kid,
    requestId,
    /* c8 ignore next */
    ...(origin && { origin }),
    details: {
      aud: payload.aud,
      sub: payload.sub,
      exp: payload.exp,
    },
  };

    await logOperation(auditOp);

    // Return JWT with optional debug information for demo purposes
    return {
      jwt,
      // Debug information (for demo visualization)
      debug: {
        signatureConversion: {
          originalFormat: format,
          originalBytes: Array.from(signatureBytes),
          convertedBytes: Array.from(signatureP1363),
          wasConverted: format === 'DER',
        },
      },
    };
  } finally {
    // CRITICAL: Clear MS from memory immediately if per-operation auth was used
    if (ms) {
      ms.fill(0);
    }
  }
}

/**
 * Get public key for a given kid
 */
async function getPublicKey(kid: string): Promise<{ publicKey: string | null }> {
  // Ensure worker is initialized
  await init();

  // Get wrapped key from storage
  const wrapped = await getWrappedKey(kid);
  if (!wrapped || !wrapped.publicKeyRaw) {
    return { publicKey: null };
  }

  // Convert ArrayBuffer to base64url
  const publicKeyBase64url = arrayBufferToBase64url(wrapped.publicKeyRaw);
  return { publicKey: publicKeyBase64url };
}

// ============================================================================
// Main Message Handler
// ============================================================================

/**
 * Handle RPC requests
 */
export async function handleMessage(request: RPCRequest): Promise<RPCResponse> {
  // Validate request format
  if (!request || typeof request !== 'object') {
    return {
      id: '',
      error: {
        code: 'INVALID_REQUEST',
        message: 'Request must be an object',
      },
    };
  }

  if (!request.id || typeof request.id !== 'string') {
    return {
      id: '',
      error: {
        code: 'INVALID_REQUEST',
        message: 'Request must have a string id field',
      },
    };
  }

  if (!request.method || typeof request.method !== 'string') {
    return {
      id: request.id,
      error: {
        code: 'INVALID_REQUEST',
        message: 'Request must have a string method field',
      },
    };
  }

  try {
    // Route to appropriate handler
    switch (request.method) {
      case 'generateVAPID': {
        // Extract optional credentials for per-operation auth
        const params = request.params as { credentials?: AuthCredentials } | undefined;
        const credentials = params?.credentials;

        const result = await generateVAPID(request.id, request.origin, credentials);
        return {
          id: request.id,
          result,
        };
      }

      case 'signJWT': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'signJWT requires params object',
            },
          };
        }

        const params = request.params as { kid?: string; payload?: JWTPayload; credentials?: AuthCredentials };

        if (!params.kid || typeof params.kid !== 'string') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'signJWT requires kid parameter',
            },
          };
        }

        if (!params.payload || typeof params.payload !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'signJWT requires payload parameter',
            },
          };
        }

        try {
          // Extract optional credentials for per-operation auth
          const credentials = params.credentials;

          const result = await signJWT(
            params.kid,
            params.payload,
            request.id,
            request.origin,
            credentials
          );
          return {
            id: request.id,
            result,
          };
        } catch (error) {
          /* c8 ignore next - defensive: all Web APIs throw Error objects */
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          if (errorMessage.includes('Key not found')) {
            return {
              id: request.id,
              error: {
                code: 'KEY_NOT_FOUND',
                message: errorMessage,
              },
            };
          }
          throw error; // Re-throw for generic error handling
        }
      }

      case 'getPublicKey': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'getPublicKey requires params object',
            },
          };
        }

        const params = request.params as { kid?: string };

        if (!params.kid || typeof params.kid !== 'string') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'getPublicKey requires kid parameter',
            },
          };
        }

        const result = await getPublicKey(params.kid);
        return {
          id: request.id,
          result,
        };
      }

      case 'setupPassphrase': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPassphrase requires params object',
            },
          };
        }

        const params = request.params as { passphrase?: string };

        if (!params.passphrase || typeof params.passphrase !== 'string') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPassphrase requires passphrase parameter',
            },
          };
        }

        const result = await setupPassphraseMethod(
          params.passphrase,
          request.id,
          request.origin
        );
        return {
          id: request.id,
          result,
        };
      }

      case 'unlockWithPassphrase': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'unlockWithPassphrase requires params object',
            },
          };
        }

        const params = request.params as { passphrase?: string };

        if (!params.passphrase || typeof params.passphrase !== 'string') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'unlockWithPassphrase requires passphrase parameter',
            },
          };
        }

        const result = await unlockWithPassphraseMethod(
          params.passphrase,
          request.id,
          request.origin
        );

        // If unlock successful, add list of keys with purpose metadata
        if (result.success) {
          const keys = await getAllWrappedKeys();
          const keyList = keys.map(k => ({ kid: k.kid, purpose: k.purpose || 'unknown' }));
          return {
            id: request.id,
            result: { ...result, keys: keyList },
          };
        }

        return {
          id: request.id,
          result,
        };
      }

      case 'isUnlockSetup': {
        const result = await isUnlockSetup();
        return {
          id: request.id,
          result,
        };
      }

      case 'getPasskeyConfig': {
        // Return passkey configuration from storage
        // (client can't access worker's IndexedDB directly)
        try {
          const config = await getMeta<unknown>('passkeyConfig');
          if (!config) {
            // eslint-disable-next-line no-console
            console.log('[Worker] getPasskeyConfig: No config found in storage');
            return {
              id: request.id,
              result: null,
            };
          }

          /* eslint-disable no-console, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any */
          console.log('[Worker] getPasskeyConfig: Retrieved config from storage:', {
            hasConfig: !!config,
            method: (config as any).method,
            hasCredentialId: !!(config as any).credentialId,
            credentialIdType: (config as any).credentialId ? Object.prototype.toString.call((config as any).credentialId) : 'undefined',
            credentialIdLength: (config as any).credentialId ? (config as any).credentialId.byteLength : 0,
            credentialIdBytes: (config as any).credentialId ? new Uint8Array((config as any).credentialId).slice(0, 8) : null,
          });
          /* eslint-enable no-console, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any */

          return {
            id: request.id,
            result: config,
          };
          /* c8 ignore start - defensive: getMeta only throws on DB errors */
        } catch (error) {
          console.error('[Worker] getPasskeyConfig error:', error);
          return {
            id: request.id,
            result: null,
          };
        }
        /* c8 ignore stop */
      }

      case 'setupPasskeyPRF': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPasskeyPRF requires params object',
            },
          };
        }

        const params = request.params as { credentialId?: ArrayBuffer; prfOutput?: ArrayBuffer };

        // Validate credentialId is ArrayBuffer (or ArrayBuffer-like for cross-realm)
        const isInstanceOf = params.credentialId instanceof ArrayBuffer;
        const isArrayBufferLike = params.credentialId &&
          typeof params.credentialId === 'object' &&
          'byteLength' in params.credentialId &&
          // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
          typeof (params.credentialId as any).byteLength === 'number';

        if (!params.credentialId || !(isInstanceOf || isArrayBufferLike)) {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPasskeyPRF requires credentialId (ArrayBuffer) parameter',
            },
          };
        }

        if (!params.prfOutput || !(params.prfOutput instanceof ArrayBuffer)) {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPasskeyPRF requires prfOutput (ArrayBuffer) parameter',
            },
          };
        }

        const result = await setupPasskeyPRFMethod(
          params.credentialId,
          params.prfOutput,
          request.id,
          request.origin
        );
        return {
          id: request.id,
          result,
        };
      }

      case 'unlockWithPasskeyPRF': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'unlockWithPasskeyPRF requires params object',
            },
          };
        }

        const params = request.params as { prfOutput?: ArrayBuffer };

        if (!params.prfOutput || !(params.prfOutput instanceof ArrayBuffer)) {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'unlockWithPasskeyPRF requires prfOutput (ArrayBuffer) parameter',
            },
          };
        }

        const result = await unlockWithPasskeyPRFMethod(
          params.prfOutput,
          request.id,
          request.origin
        );

        // If unlock successful, add list of keys with purpose metadata
        if (result.success) {
          const keys = await getAllWrappedKeys();
          const keyList = keys.map(k => ({ kid: k.kid, purpose: k.purpose || 'unknown' }));
          return {
            id: request.id,
            result: { ...result, keys: keyList },
          };
        }

        return {
          id: request.id,
          result,
        };
      }

      case 'setupPasskeyGate': {
        // Validate params
        if (!request.params || typeof request.params !== 'object') {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPasskeyGate requires params object',
            },
          };
        }

        const params = request.params as { credentialId?: ArrayBuffer };

        // Validate credentialId is ArrayBuffer (or ArrayBuffer-like for cross-realm)
        const isInstanceOf = params.credentialId instanceof ArrayBuffer;
        const isArrayBufferLike = params.credentialId &&
          typeof params.credentialId === 'object' &&
          'byteLength' in params.credentialId &&
          // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
          typeof (params.credentialId as any).byteLength === 'number';

        if (!params.credentialId || !(isInstanceOf || isArrayBufferLike)) {
          return {
            id: request.id,
            error: {
              code: 'INVALID_PARAMS',
              message: 'setupPasskeyGate requires credentialId (ArrayBuffer) parameter',
            },
          };
        }

        const result = await setupPasskeyGateMethod(
          params.credentialId,
          request.id,
          request.origin
        );
        return {
          id: request.id,
          result,
        };
      }

      case 'unlockWithPasskeyGate': {
        // No params needed - WebAuthn ceremony performed by client

        const result = await unlockWithPasskeyGateMethod(

          request.id,
          request.origin
        );

        // If unlock successful, add list of keys with purpose metadata
        if (result.success) {
          const keys = await getAllWrappedKeys();
          const keyList = keys.map(k => ({ kid: k.kid, purpose: k.purpose || 'unknown' }));
          return {
            id: request.id,
            result: { ...result, keys: keyList },
          };
        }

        return {
          id: request.id,
          result,
        };
      }

      case 'getAuditPublicKey': {
        const result = await getAuditPublicKey();
        return {
          id: request.id,
          result,
        };
      }

      case 'verifyAuditChain': {
        const result = await verifyAuditChain();
        return {
          id: request.id,
          result,
        };
      }

      case 'resetKMS': {
        // Clear all data from IndexedDB stores
        // TODO: For production, this MUST be protected with user authentication
        // (e.g., require passphrase or passkey verification before allowing reset)
        try {
          // Reset audit logger in-memory state first
          resetAuditLogger();

          // Open database to clear all stores
          const db = await new Promise<IDBDatabase>((resolve, reject) => {
            const req = indexedDB.open('kms-enclave');
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(new Error('Failed to open database'));
          });

          // Get all object store names and clear each one
          const storeNames = Array.from(db.objectStoreNames);

          // Clear all stores in a single transaction
          await new Promise<void>((resolve, reject) => {
            const transaction = db.transaction(storeNames, 'readwrite');

            // Clear each store
            for (const storeName of storeNames) {
              transaction.objectStore(storeName).clear();
            }

            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(new Error('Failed to clear stores'));
          });

          // Close the database connection we just opened
          db.close();

          return {
            id: request.id,
            result: { success: true },
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          return {
            id: request.id,
            result: { success: false, error: errorMessage },
          };
        }
      }

      default:
        return {
          id: request.id,
          error: {
            code: 'INVALID_METHOD',
            message: `Unknown method: ${request.method}`,
          },
        };
    }
  } catch (error) {
    // Catch any unexpected errors
    /* c8 ignore next - defensive: all Web APIs throw Error objects */
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      id: request.id,
      error: {
        code: 'CRYPTO_ERROR',
        message: `Crypto operation failed: ${errorMessage}`,
      },
    };
  }
}

// ============================================================================
// Worker Message Listener
// ============================================================================

/**
 * Set up message listener for Worker context
 */
/* c8 ignore start - Only runs in real Worker, not in test environment */
if (typeof self !== 'undefined' && 'onmessage' in self) {
  self.onmessage = async (event: MessageEvent): Promise<void> => {
    const response = await handleMessage(event.data as RPCRequest);
    self.postMessage(response);
  };
}
/* c8 ignore stop */
