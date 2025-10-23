/**
 * KMS Worker - Cryptographic Operations Handler
 *
 * ⚠️ HISTORICAL SNAPSHOT ⚠️
 * This is a copy of the Phase 0 production worker as of commit 8aa5303.
 * Preserved for reference as Phase 1 will modify the production version.
 * See src/worker.ts for the current production implementation.
 *
 * Phase 0 Implementation: Minimal RPC handler for VAPID key generation and JWT signing
 * Runs in a dedicated Worker for isolation from main thread
 */

// ============================================================================
// Type Definitions
// ============================================================================

interface RPCRequest {
  id: string;
  method: string;
  params?: unknown;
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

interface StoredKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyRaw: string; // base64url encoded
}

interface JWTPayload {
  aud: string;
  sub: string;
  exp: number;
}

// ============================================================================
// State Management
// ============================================================================

// In-memory key storage (Phase 0 - will be IndexedDB in Phase 1)
const keyStore = new Map<string, StoredKeyPair>();

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
 * Generate a VAPID keypair
 */
async function generateVAPID(): Promise<VAPIDKeyPair> {
  // Generate P-256 ECDSA keypair
  const keypair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false, // non-extractable private key
    ['sign', 'verify']
  );

  // Export public key in raw format
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
  const publicKeyBase64url = arrayBufferToBase64url(publicKeyRaw);

  // Generate unique key ID
  const kid = generateKid('vapid');

  // Store keypair for later use
  keyStore.set(kid, {
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    publicKeyRaw: publicKeyBase64url,
  });

  return {
    kid,
    publicKey: publicKeyBase64url,
  };
}

/**
 * Sign a JWT with a stored VAPID key
 */
async function signJWT(kid: string, payload: JWTPayload): Promise<{ jwt: string }> {
  // Get keypair from storage
  const stored = keyStore.get(kid);
  if (!stored) {
    throw new Error(`No key found with kid: ${kid}`);
  }

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
    stored.privateKey,
    signatureInput
  );

  // Note: happy-dom returns P-1363 format (64 bytes), real browsers return DER (70-72 bytes)
  // For Phase 0, we'll handle both formats
  // In Phase 1, we'll add DER->P-1363 conversion for real browsers
  const signatureB64 = arrayBufferToBase64url(signature);

  // Construct JWT
  const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;

  return { jwt };
}

/**
 * Get public key for a given kid
 */
function getPublicKey(kid: string): { publicKey: string | null } {
  const stored = keyStore.get(kid);
  if (!stored) {
    return { publicKey: null };
  }
  return { publicKey: stored.publicKeyRaw };
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
        const result = await generateVAPID();
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
          const result = await signJWT(params.kid, params.payload);
          return {
            id: request.id,
            result,
          };
        } catch (error) {
          /* c8 ignore next - defensive: all Web APIs throw Error objects */
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          if (errorMessage.includes('No key found')) {
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

        const result = getPublicKey(params.kid);
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
/* c8 ignore start - only runs in real Worker context, not in tests */
if (typeof self !== 'undefined' && 'onmessage' in self) {
  self.onmessage = async (event: MessageEvent): Promise<void> => {
    const response = await handleMessage(event.data as RPCRequest);
    self.postMessage(response);
  };
}
/* c8 ignore stop */
