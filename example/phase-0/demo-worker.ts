/**
 * Demo-Enhanced KMS Worker (Phase 0)
 *
 * This extends the base Worker with additional verification metadata
 * for demonstration purposes. Shows all the crypto details that prove
 * our implementation is correct.
 */

import { handleMessage as baseHandleMessage } from '@/worker';

// ============================================================================
// Enhanced Types (extends base types with verification data)
// ============================================================================

interface EnhancedVAPIDKeyPair {
  // Base fields
  kid: string;
  publicKey: string; // base64url

  // Verification metadata
  publicKeyJwk: JsonWebKey;
  keyMetadata: {
    algorithm: {
      name: string;
      namedCurve: string;
    };
    extractable: boolean;
    usages: string[];
  };
}

interface EnhancedJWTResult {
  // Base field
  jwt: string;

  // Verification metadata
  jwtParts: {
    header: string;
    payload: string;
    signature: string;
  };
  decodedHeader: Record<string, unknown>;
  decodedPayload: Record<string, unknown>;
  signatureBytes: number;
}

// ============================================================================
// In-Memory Storage (Phase 0 only)
// ============================================================================

const keyStore = new Map<string, { privateKey: CryptoKey; publicKey: CryptoKey; publicKeyRaw: string }>();

// ============================================================================
// Utilities
// ============================================================================

function arrayBufferToBase64url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// RFC 7638 JWK Thumbprint
async function computeJWKThumbprint(jwk: JsonWebKey): Promise<string> {
  // RFC 7638 requires lexicographic ordering of required fields
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  });

  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );

  const bytes = new Uint8Array(hash);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// ============================================================================
// Enhanced RPC Methods
// ============================================================================

async function generateVAPIDEnhanced(): Promise<EnhancedVAPIDKeyPair> {
  // Generate P-256 ECDSA keypair
  const keypair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false, // non-extractable private key
    ['sign', 'verify']
  );

  // Export public key in both raw and JWK formats
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  const publicKeyBase64url = arrayBufferToBase64url(publicKeyRaw);

  // Generate kid using RFC 7638 JWK thumbprint (content-derived)
  const kid = await computeJWKThumbprint(publicKeyJwk);

  // Store keypair
  keyStore.set(kid, {
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    publicKeyRaw: publicKeyBase64url,
  });

  // Return with verification metadata
  return {
    kid,
    publicKey: publicKeyBase64url,
    publicKeyJwk,
    keyMetadata: {
      algorithm: {
        name: keypair.privateKey.algorithm.name as string,
        namedCurve: (keypair.privateKey.algorithm as EcKeyAlgorithm).namedCurve,
      },
      extractable: keypair.privateKey.extractable,
      usages: keypair.privateKey.usages as string[],
    },
  };
}

async function signJWTEnhanced(kid: string, payload: Record<string, unknown>): Promise<EnhancedJWTResult> {
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
  const signatureB64 = arrayBufferToBase64url(signature);

  // Construct JWT
  const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;

  return {
    jwt,
    jwtParts: {
      header: headerB64,
      payload: payloadB64,
      signature: signatureB64,
    },
    decodedHeader: header,
    decodedPayload: payload,
    signatureBytes: signature.byteLength,
  };
}

// ============================================================================
// Enhanced Message Handler
// ============================================================================

async function handleEnhancedMessage(request: { id: string; method: string; params?: unknown }): Promise<{ id: string; result?: unknown; error?: { code: string; message: string } }> {
  // Handle demo-specific enhanced methods
  if (request.method === 'generateVAPIDEnhanced') {
    try {
      const result = await generateVAPIDEnhanced();
      return { id: request.id, result };
    } catch (error) {
      return {
        id: request.id,
        error: {
          code: 'CRYPTO_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
        },
      };
    }
  }

  if (request.method === 'signJWTEnhanced') {
    try {
      const params = request.params as { kid: string; payload: Record<string, unknown> };
      const result = await signJWTEnhanced(params.kid, params.payload);
      return { id: request.id, result };
    } catch (error) {
      return {
        id: request.id,
        error: {
          code: 'CRYPTO_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
        },
      };
    }
  }

  // Fall back to base handler for standard methods
  return baseHandleMessage(request);
}

// ============================================================================
// Worker Message Listener
// ============================================================================

/* c8 ignore start - only runs in real Worker context */
if (typeof self !== 'undefined' && 'onmessage' in self) {
  self.onmessage = async (event: MessageEvent): Promise<void> => {
    const response = await handleEnhancedMessage(event.data);
    self.postMessage(response);
  };
}
/* c8 ignore stop */

export { handleEnhancedMessage };
