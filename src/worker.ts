/**
 * KMS Worker - Cryptographic Operations Handler
 *
 * Phase 1 Implementation: Production-ready RPC handler with IndexedDB storage and audit logging
 * Runs in a dedicated Worker for isolation from main thread
 */

// ============================================================================
// Imports
// ============================================================================

import { initDB, wrapKey, unwrapKey, getWrappedKey } from './storage.js';
import { initAuditLogger, logOperation, type AuditOperation } from './audit.js';
import {
  setupPassphrase,
  unlockWithPassphrase,
  isSetup,
} from './unlock.js';

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

// ============================================================================
// State Management
// ============================================================================

// Initialization state
let isInitialized = false;

// Unlock state (replaces temporary wrapping key)
let wrappingKey: CryptoKey | null = null;
let isUnlocked = false;

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
 * Get the current wrapping key
 * @throws {Error} if worker is not unlocked
 */
function getWrappingKey(): CryptoKey {
  if (!isUnlocked || !wrappingKey) {
    throw new Error('Worker not unlocked');
  }
  return wrappingKey;
}

/**
 * Reset worker state (for testing only)
 * @internal
 */
export function resetWorkerState(): void {
  isInitialized = false;
  wrappingKey = null;
  isUnlocked = false;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert ArrayBuffer to base64url encoding
 */
function arrayBufferToBase64url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a unique key ID
 */
function generateKid(purpose: string): string {
  const timestamp = Date.now();
  const random = crypto.randomUUID().slice(0, 8);
  return `${purpose}-${timestamp}-${random}`;
}

// ============================================================================
// RPC Method Implementations
// ============================================================================

/**
 * Setup passphrase for first-time unlock
 */
async function setupPassphraseMethod(
  passphrase: string,
  requestId: string,
  origin?: string
): Promise<{ success: boolean; error?: string }> {
  // Ensure worker is initialized
  await init();

  // Call unlock manager to setup
  const result = await setupPassphrase(passphrase);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Store the wrapping key and mark as unlocked
  wrappingKey = result.key;
  isUnlocked = true;

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
 * Unlock with passphrase
 */
async function unlockWithPassphraseMethod(
  passphrase: string,
  requestId: string,
  origin?: string
): Promise<{ success: boolean; error?: string }> {
  // Ensure worker is initialized
  await init();

  // Call unlock manager to unlock
  const result = await unlockWithPassphrase(passphrase);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Store the wrapping key and mark as unlocked
  wrappingKey = result.key;
  isUnlocked = true;

  // Log operation to audit log
  const auditOp: AuditOperation = {
    op: 'unlock',
    kid: 'unlock',
    requestId,
    /* c8 ignore next */
    ...(origin && { origin }),
  };
  await logOperation(auditOp);

  return { success: true };
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
 * Generate a VAPID keypair
 */
async function generateVAPID(requestId: string, origin?: string): Promise<VAPIDKeyPair> {
  // Ensure worker is initialized
  await init();

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

  // Generate unique key ID
  const kid = generateKid('vapid');

  // Wrap and store keypair
  await wrapKey(keypair.privateKey, getWrappingKey(), kid, undefined, undefined, {
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
}

/**
 * Sign a JWT with a stored VAPID key
 */
async function signJWT(
  kid: string,
  payload: JWTPayload,
  requestId: string,
  origin?: string
): Promise<{ jwt: string }> {
  // Ensure worker is initialized
  await init();

  // Unwrap private key from storage
  const privateKey = await unwrapKey(kid, getWrappingKey(), {
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

  // Note: happy-dom returns P-1363 format (64 bytes), real browsers return DER (70-72 bytes)
  // For Phase 0, we'll handle both formats
  // In Phase 1, we'll add DER->P-1363 conversion for real browsers
  const signatureB64 = arrayBufferToBase64url(signature);

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
    },
  };

  await logOperation(auditOp);

  return { jwt };
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
        const result = await generateVAPID(request.id, request.origin);
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

        const params = request.params as { kid?: string; payload?: JWTPayload };

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
          const result = await signJWT(
            params.kid,
            params.payload,
            request.id,
            request.origin
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
/* c8 ignore next 7 - only runs in real Worker context, not in tests */
if (typeof self !== 'undefined' && 'onmessage' in self) {
  self.onmessage = async (event: MessageEvent): Promise<void> => {
    const response = await handleMessage(event.data as RPCRequest);
    self.postMessage(response);
  };
}
