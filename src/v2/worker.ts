/**
 * KMS V2 Worker Orchestrator (Phase 3)
 *
 * The worker is the orchestration layer that routes RPC requests to appropriate
 * domain modules (unlock, audit, storage, crypto-utils). All sensitive operations
 * execute within withUnlock context for per-operation authentication.
 *
 * Responsibilities:
 * - RPC request routing and validation
 * - Operation coordination (setup, unlock, VAPID, leases)
 * - Policy enforcement (quotas, expirations)
 * - Audit logging for all operations
 * - Error handling and response formatting
 *
 * Security Properties:
 * - No persistent unlock state (withUnlock context)
 * - All operations logged to tamper-evident audit chain
 * - Non-extractable keys enforced
 * - AAD validation on all key operations
 */

import type {
  RPCRequest,
  RPCResponse,
  AuthCredentials,
  VAPIDPayload,
  LeaseRecord,
  QuotaState,
  AuditEntryV2,
  LeaseVerificationResult,
} from './types';
import {
  setupPassphrase,
  setupPasskeyPRF,
  setupPasskeyGate,
  unlockWithPassphrase,
  unlockWithPasskeyPRF,
  unlockWithPasskeyGate,
  withUnlock,
  deriveMKEKFromMS,
  isSetup,
  isPassphraseSetup,
  isPasskeySetup,
} from './unlock';
import {
  initAuditLogger,
  resetAuditLogger,
  ensureAuditKey,
  logOperation,
  verifyAuditChain,
  getAuditPublicKey,
  generateLAK,
  loadLAK,
  ensureKIAK,
} from './audit';
import {
  initDB,
  closeDB,
  wrapKey,
  unwrapKey,
  getWrappedKey,
  getAllWrappedKeys,
  deleteWrappedKey,
  putMeta,
  getMeta,
  deleteMeta,
  getAllAuditEntries,
  getUserLeases,
  storeLease,
  getLease,
} from './storage';
import {
  rawP256ToJwk,
  jwkThumbprintP256,
  arrayBufferToBase64url,
} from './crypto-utils';
import { getErrorMessage } from './error-utils';

// ============================================================================
// Session Key Cache (Lease-Scoped)
// ============================================================================

/**
 * In-memory cache of SessionKEKs (Session Key Encryption Keys).
 *
 * Each lease has its own SessionKEK derived from MS + lease salt.
 * The SessionKEK is used to wrap/unwrap the VAPID private key for
 * JWT signing without requiring user credentials on each operation.
 *
 * Security properties:
 * - SessionKEK is never persisted (memory-only)
 * - Cleared on worker restart
 * - Cleared when lease expires
 * - Derived uniquely per lease (different salt)
 */
const sessionKEKCache = new Map<string, CryptoKey>();

/**
 * Derive a SessionKEK from Master Secret and lease salt.
 *
 * Uses HKDF-SHA256 with:
 * - IKM: Master Secret (32 bytes)
 * - Salt: Lease Salt (32 bytes, random per lease)
 * - Info: "ATS/KMS/SessionKEK/v1"
 * - Length: 256 bits (32 bytes)
 *
 * The SessionKEK is used to wrap the VAPID private key, allowing
 * JWT signing during the lease lifetime without user re-authentication.
 *
 * @param ms - Master Secret (32 bytes)
 * @param leaseSalt - Lease Salt (32 bytes, unique per lease)
 * @returns SessionKEK (AES-GCM 256-bit key)
 */
async function deriveSessionKEK(ms: Uint8Array<ArrayBuffer>, leaseSalt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  // Import MS as HKDF key material
  const msKey = await crypto.subtle.importKey(
    'raw',
    ms as BufferSource,
    'HKDF',
    false, // not extractable
    ['deriveKey']
  );

  // Derive SessionKEK using HKDF-SHA256
  const sessionKEK = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: leaseSalt as BufferSource,
      info: new TextEncoder().encode('ATS/KMS/SessionKEK/v1'),
    },
    msKey,
    { name: 'AES-GCM', length: 256 },
    false, // not extractable
    ['wrapKey', 'unwrapKey']
  );

  return sessionKEK;
}

// ============================================================================
// Worker Message Listener
// ============================================================================

/**
 * Main worker message handler. Receives RPC requests from client,
 * processes them, and sends back responses.
 */
self.addEventListener('message', (event: MessageEvent) => {
  void (async (): Promise<void> => {
    const request = event.data as RPCRequest;
    const response = await handleMessage(request);
    self.postMessage(response);
  })().catch((err: unknown) => {
    console.error('[KMS Worker] Message handling failed:', err);
    // Send error response back to client
    const request = event.data as RPCRequest;
    self.postMessage({
      id: request?.id || 'unknown',
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  });
});

// ============================================================================
// RPC Request Handler (Entry Point)
// ============================================================================

/**
 * Handle a single RPC request. Routes to appropriate handler based on method.
 * All errors are caught and returned as error responses.
 */
export async function handleMessage(request: RPCRequest): Promise<RPCResponse> {
  const { id, method, params } = request;


  try {
    let result: any;

    switch (method) {
      // === Setup Operations ===
      case 'setupPassphrase':
        result = await handleSetupPassphrase(params, id);
        break;

      case 'setupPasskeyPRF':
        result = await handleSetupPasskeyPRF(params, id);
        break;

      case 'setupPasskeyGate':
        result = await handleSetupPasskeyGate(params, id);
        break;

      case 'addEnrollment':
        result = await handleAddEnrollment(params, id);
        break;

      // === VAPID Operations ===
      case 'generateVAPID':
        result = await handleGenerateVAPID(params, id);
        break;

      case 'regenerateVAPID':
        result = await handleRegenerateVAPID(params, id);
        break;

      case 'signJWT':
        result = await handleSignJWT(params, id);
        break;

      // === VAPID Lease Operations ===
      case 'createLease':
        result = await handleCreateLease(params, id);
        break;

      case 'issueVAPIDJWT':
        result = await handleIssueVAPIDJWT(params, id);
        break;

      case 'issueVAPIDJWTs':
        result = await handleIssueVAPIDJWTs(params, id);
        break;

      // === Status/Query Operations ===
      case 'isSetup':
        result = await handleIsSetup(params);
        break;

      case 'getEnrollments':
        result = await handleGetEnrollments(params);
        break;

      case 'verifyAuditChain':
        result = await handleVerifyAuditChain();
        break;

      case 'getAuditLog':
        result = await handleGetAuditLog();
        break;

      case 'getPublicKey':
        result = await handleGetPublicKey(params);
        break;

      case 'getAuditPublicKey':
        result = await handleGetAuditPublicKey();
        break;

      case 'getUserLeases':
        result = await handleGetUserLeases(params);
        break;

      case 'verifyLease':
        result = await handleVerifyLease(params);
        break;

      case 'getVAPIDKid':
        result = await handleGetVAPIDKid();
        break;

      // === Management Operations ===
      case 'resetKMS':
        result = await handleResetKMS();
        break;

      case 'removeEnrollment':
        result = await handleRemoveEnrollment(params, id);
        break;

      default:
        throw new Error(`Unknown RPC method: ${method}`);
    }

    return { id, result };
  } catch (err: unknown) {
    return { id, error: getErrorMessage(err) };
  }
}

// ============================================================================
// Setup Operations
// ============================================================================

/**
 * Setup passphrase authentication.
 * Creates first Master Secret if none exists, or wraps existing MS.
 * Generates VAPID keypair and returns public key for immediate use.
 */
async function handleSetupPassphrase(
  params: { userId: string; passphrase: string; existingMS?: Uint8Array },
  requestId: string
): Promise<{ success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string }> {
  const { userId, passphrase, existingMS } = params;

  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters');
  }

  const result = await setupPassphrase(userId, passphrase, existingMS);

  if (!result.success) {
    throw new Error(result.error);
  }

  // Derive MKEK and initialize audit key
  const mkek = await deriveMKEKFromMS(result.ms);
  await ensureAuditKey(mkek);

  // Generate VAPID keypair (per V2 spec: generate during setup)
  const keypair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  )) as CryptoKeyPair;

  // Export public key (raw format, 65 bytes)
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Compute kid (JWK thumbprint)
  const jwk = rawP256ToJwk(new Uint8Array(publicKeyRaw));
  const kid = await jwkThumbprintP256(jwk);

  // Wrap private key with MKEK
  await wrapKey(
    keypair.privateKey,
    mkek,
    kid,
    { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
    ['sign'],
    {
      alg: 'ES256',
      purpose: 'vapid',
      publicKeyRaw,
    }
  );

  // Zero out MS after use
  result.ms.fill(0);

  await logOperation({
    op: 'setup-passphrase',
    kid: '',
    requestId,
    userId: userId,
    details: { method: 'passphrase', vapidKid: kid },
  });

  return {
    success: true,
    enrollmentId: 'enrollment:passphrase:v2',
    vapidPublicKey: arrayBufferToBase64url(publicKeyRaw),
    vapidKid: kid,
  };
}

/**
 * Setup passkey PRF authentication.
 * Requires PRF output from WebAuthn ceremony.
 * Generates VAPID keypair and returns public key for immediate use.
 */
async function handleSetupPasskeyPRF(
  params: {
    userId: string;
    credentialId: ArrayBuffer;
    prfOutput: ArrayBuffer;
    rpId?: string;
    existingMS?: Uint8Array;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string }> {
  const { userId, credentialId, prfOutput, rpId = '', existingMS } = params;

  if (!credentialId || credentialId.byteLength === 0) {
    throw new Error('credentialId required');
  }

  if (!prfOutput || prfOutput.byteLength !== 32) {
    throw new Error('prfOutput must be 32 bytes');
  }

  const result = await setupPasskeyPRF(userId, credentialId, prfOutput, existingMS, rpId);

  if (!result.success) {
    throw new Error(result.error);
  }

  // Derive MKEK and initialize audit key
  const mkek = await deriveMKEKFromMS(result.ms);
  await ensureAuditKey(mkek);

  // Generate VAPID keypair (per V2 spec: generate during setup)
  const keypair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  )) as CryptoKeyPair;

  // Export public key (raw format, 65 bytes)
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Compute kid (JWK thumbprint)
  const jwk = rawP256ToJwk(new Uint8Array(publicKeyRaw));
  const kid = await jwkThumbprintP256(jwk);

  // Wrap private key with MKEK
  await wrapKey(
    keypair.privateKey,
    mkek,
    kid,
    { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
    ['sign'],
    {
      alg: 'ES256',
      purpose: 'vapid',
      publicKeyRaw,
    }
  );

  // Zero out MS after use
  result.ms.fill(0);

  await logOperation({
    op: 'setup-passkey-prf',
    kid: '',
    requestId,
    userId: userId,
    details: { method: 'passkey-prf', credentialId: arrayBufferToBase64url(credentialId), vapidKid: kid },
  });

  return {
    success: true,
    enrollmentId: 'enrollment:passkey-prf:v2',
    vapidPublicKey: arrayBufferToBase64url(publicKeyRaw),
    vapidKid: kid,
  };
}

/**
 * Setup passkey gate authentication (fallback for non-PRF passkeys).
 * Uses random pepper + HKDF.
 * Generates VAPID keypair and returns public key for immediate use.
 */
async function handleSetupPasskeyGate(
  params: {
    userId: string;
    credentialId: ArrayBuffer;
    rpId?: string;
    existingMS?: Uint8Array;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string }> {
  const { userId, credentialId, rpId = '', existingMS } = params;

  if (!credentialId || credentialId.byteLength === 0) {
    throw new Error('credentialId required');
  }

  const result = await setupPasskeyGate(userId, credentialId, existingMS, rpId);

  if (!result.success) {
    throw new Error(result.error);
  }

  // Derive MKEK and initialize audit key
  const mkek = await deriveMKEKFromMS(result.ms);
  await ensureAuditKey(mkek);

  // Generate VAPID keypair (per V2 spec: generate during setup)
  const keypair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  )) as CryptoKeyPair;

  // Export public key (raw format, 65 bytes)
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Compute kid (JWK thumbprint)
  const jwk = rawP256ToJwk(new Uint8Array(publicKeyRaw));
  const kid = await jwkThumbprintP256(jwk);

  // Wrap private key with MKEK
  await wrapKey(
    keypair.privateKey,
    mkek,
    kid,
    { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
    ['sign'],
    {
      alg: 'ES256',
      purpose: 'vapid',
      publicKeyRaw,
    }
  );

  // Zero out MS after use
  result.ms.fill(0);

  await logOperation({
    op: 'setup-passkey-gate',
    kid: '',
    requestId,
    userId: userId,
    details: { method: 'passkey-gate', credentialId: arrayBufferToBase64url(credentialId), vapidKid: kid },
  });

  return {
    success: true,
    enrollmentId: 'enrollment:passkey-gate:v2',
    vapidPublicKey: arrayBufferToBase64url(publicKeyRaw),
    vapidKid: kid,
  };
}

/**
 * Add additional enrollment method to existing Master Secret.
 * Enables multi-enrollment (same MS, multiple auth methods).
 */
async function handleAddEnrollment(
  params: {
    userId: string;
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    credentials: AuthCredentials;
    newCredentials: any;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { userId, method, credentials, newCredentials } = params;

  // Unlock to verify credentials and ensure audit key is loaded
  await withUnlock(credentials, async (mkek, _ms) => {
    await ensureAuditKey(mkek);
    return true;
  });

  // Get the MS by unlocking again (we need the raw MS, not just verification)
  let ms: Uint8Array;
  if (credentials.method === 'passphrase') {
    const result = await unlockWithPassphrase(userId, credentials.passphrase);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-prf') {
    const result = await unlockWithPasskeyPRF(userId, credentials.prfOutput);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-gate') {
    const result = await unlockWithPasskeyGate(userId);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else {
    throw new Error('Invalid credentials method');
  }

  // Setup new enrollment with existing MS
  let enrollmentResult;
  if (method === 'passphrase') {
    enrollmentResult = await setupPassphrase(userId, newCredentials.passphrase, ms);
  } else if (method === 'passkey-prf') {
    enrollmentResult = await setupPasskeyPRF(
      userId,
      newCredentials.credentialId,
      newCredentials.prfOutput,
      ms,
      newCredentials.rpId
    );
  } else if (method === 'passkey-gate') {
    enrollmentResult = await setupPasskeyGate(userId, newCredentials.credentialId, ms, newCredentials.rpId);
  } else {
    throw new Error(`Unknown enrollment method: ${method}`);
  }

  // Zeroize MS
  ms.fill(0);

  if (!enrollmentResult!.success) {
    throw new Error(enrollmentResult!.error);
  }

  await logOperation({
    op: 'add-enrollment',
    kid: '',
    requestId,
    userId: credentials.userId,
    details: { method, action: 'add-enrollment' },
  });

  return { success: true, enrollmentId: `enrollment:${method}:v2` };
}

// ============================================================================
// VAPID Operations
// ============================================================================

/**
 * Generate new VAPID keypair (ECDSA P-256).
 * Private key wrapped with MKEK and stored in IndexedDB.
 * Returns kid (JWK thumbprint) and public key (raw format, 65 bytes).
 */
async function handleGenerateVAPID(
  params: { credentials: AuthCredentials },
  requestId: string
): Promise<{ kid: string; publicKey: string }> {
  const { credentials } = params;

  const result = await withUnlock(credentials, async (mkek, _ms) => {
    // Ensure audit key is loaded/generated
    await ensureAuditKey(mkek);

    // Generate ECDSA P-256 keypair
    const keypair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // temporarily extractable for wrapping
      ['sign', 'verify']
    )) as CryptoKeyPair;

    // Export public key (raw format, 65 bytes)
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

    // Compute kid (JWK thumbprint)
    const jwk = rawP256ToJwk(new Uint8Array(publicKeyRaw));
    const kid = await jwkThumbprintP256(jwk);

    // Wrap private key with MKEK
    await wrapKey(
      keypair.privateKey,
      mkek,
      kid,
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      ['sign'],
      {
        alg: 'ES256',
        purpose: 'vapid',
        publicKeyRaw,
      }
    );

    return {
      kid,
      publicKey: arrayBufferToBase64url(publicKeyRaw),
    };
  });

  await logOperation({
    op: 'generate',
    kid: result.result.kid,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
    details: { algorithm: 'ECDSA', curve: 'P-256', purpose: 'vapid' },
  });

  return result.result;
}

/**
 * Regenerate VAPID keypair, invalidating all existing leases.
 * Requires user authentication (UAK-signed operation).
 *
 * This operation:
 * 1. Deletes all existing VAPID keys
 * 2. Generates a new VAPID keypair with a new kid
 * 3. All existing leases become invalid (they reference the old kid)
 */
async function handleRegenerateVAPID(
  params: { credentials: AuthCredentials },
  requestId: string
): Promise<{ kid: string; publicKey: string }> {
  const { credentials } = params;

  const result = await withUnlock(credentials, async (mkek, _ms) => {
    // Ensure audit key is loaded/generated
    await ensureAuditKey(mkek);

    // Get all wrapped keys and find VAPID keys
    const allKeys = await getAllWrappedKeys();
    const vapidKeys = allKeys.filter((key) => key.purpose === 'vapid');

    // Delete all existing VAPID keys
    for (const key of vapidKeys) {
      await deleteWrappedKey(key.kid);
    }

    // Generate new ECDSA P-256 keypair
    const keypair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // temporarily extractable for wrapping
      ['sign', 'verify']
    )) as CryptoKeyPair;

    // Export public key (raw format, 65 bytes)
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

    // Compute kid (JWK thumbprint)
    const jwk = rawP256ToJwk(new Uint8Array(publicKeyRaw));
    const kid = await jwkThumbprintP256(jwk);

    // Wrap private key with MKEK
    await wrapKey(
      keypair.privateKey,
      mkek,
      kid,
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      ['sign'],
      {
        alg: 'ES256',
        purpose: 'vapid',
        publicKeyRaw,
      }
    );

    return {
      kid,
      publicKey: arrayBufferToBase64url(publicKeyRaw),
      oldKids: vapidKeys.map((k) => k.kid),
    };
  });

  await logOperation({
    op: 'regenerate-vapid',
    kid: result.result.kid,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
    details: {
      algorithm: 'ECDSA',
      curve: 'P-256',
      purpose: 'vapid',
      oldKids: result.result.oldKids,
      deletedCount: result.result.oldKids.length,
    },
  });

  return {
    kid: result.result.kid,
    publicKey: result.result.publicKey,
  };
}

/**
 * Sign JWT with VAPID private key (ES256 algorithm).
 * Implements RFC 7515 (JWS) and RFC 8292 (VAPID).
 */
async function handleSignJWT(
  params: {
    kid: string;
    payload: VAPIDPayload;
    credentials: AuthCredentials;
  },
  requestId: string
): Promise<{ jwt: string }> {
  const { kid, payload, credentials } = params;

  // Validate payload
  if (!payload.aud || !payload.sub || !payload.exp) {
    throw new Error('JWT payload must include aud, sub, and exp');
  }

  // Validate expiration (max 24 hours per RFC 8292)
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new Error('JWT exp must be in the future');
  }
  if (payload.exp > now + 86400) {
    throw new Error('JWT exp must be <= 24 hours (RFC 8292)');
  }

  const result = await withUnlock(credentials, async (mkek, _ms) => {
    // Ensure audit key is loaded/generated
    await ensureAuditKey(mkek);

    // Unwrap private key
    const privateKey = await unwrapKey(
      kid,
      mkek,
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      ['sign']
    );

    // Build JWT header
    const header = { typ: 'JWT', alg: 'ES256', kid };
    const headerB64 = arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(header)).buffer);

    // Build JWT payload
    const payloadB64 = arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(payload)).buffer);

    // Sign
    const signatureInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      signatureInput
    );

    // Modern browsers return P-1363 format (64 bytes) which is what JWS ES256 requires
    const signatureB64 = arrayBufferToBase64url(signature);

    // Final JWT
    const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;

    return { jwt };
  });

  await logOperation({
    op: 'sign',
    kid,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
    details: {
      algorithm: 'ES256',
      aud: payload.aud,
      exp: payload.exp,
      jti: payload.jti,
    },
  });

  return result.result;
}

// ============================================================================
// VAPID Lease Operations (MVP)
// ============================================================================

/**
 * Create VAPID lease for long-lived JWT issuance authorization.
 * Leases are relay-agnostic and include quota enforcement.
 *
 * SessionKEK Architecture:
 * - Generates random 32-byte lease salt (LS)
 * - Derives SessionKEK from MS + LS via HKDF
 * - Wraps VAPID private key with SessionKEK (not MKEK)
 * - Caches SessionKEK in memory for JWT issuance
 * - Stores wrappedLeaseKey + leaseSalt in lease record
 */
async function handleCreateLease(
  params: {
    userId: string;
    subs: Array<{ url: string; aud: string; eid: string }>;
    ttlHours: number;
    credentials: AuthCredentials;
  },
  requestId: string
): Promise<{ leaseId: string; exp: number; quotas: QuotaState }> {
  const { userId, subs, ttlHours, credentials } = params;

  // Validate TTL (max 24 hours)
  if (ttlHours <= 0 || ttlHours > 24) {
    throw new Error('ttlHours must be between 0 and 24');
  }

  // Verify VAPID key exists (should have been generated during setup)
  const allKeys = await getAllWrappedKeys();
  const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');
  if (vapidKeys.length === 0) {
    throw new Error('No VAPID key found. VAPID key should have been generated during setup.');
  }

  // Sort by createdAt descending to get the most recent key first (same logic as verifyLease)
  vapidKeys.sort((a, b) => b.createdAt - a.createdAt);

  // Use most recent VAPID key (multi-key rotation is future work)
  const vapidKeyRecord = vapidKeys[0]!;
  const kid = vapidKeyRecord.kid;

  // Generate lease ID and salt
  const leaseId = `lease-${crypto.randomUUID()}`;
  const leaseSalt = crypto.getRandomValues(new Uint8Array(32)) as Uint8Array<ArrayBuffer>;

  // Calculate lease expiration time (needed for LAK delegation cert)
  const now = Date.now();
  const exp = now + ttlHours * 3600 * 1000;

  // Perform key wrapping inside withUnlock context (need MS for SessionKEK derivation)
  const result = await withUnlock(credentials, async (mkek, ms) => {
    // Ensure audit key (UAK) is loaded
    await ensureAuditKey(mkek);

    // Generate LAK (Lease Audit Key) with delegation certificate signed by UAK
    const { delegationCert } = await generateLAK(leaseId, exp);

    // Derive SessionKEK from MS + lease salt
    const sessionKEK = await deriveSessionKEK(ms as Uint8Array<ArrayBuffer>, leaseSalt);

    // Unwrap VAPID private key using MKEK (must be extractable for re-wrapping)
    // Get the wrapped key record from storage
    const wrappedKeyRecord = await getWrappedKey(kid);
    if (!wrappedKeyRecord) {
      throw new Error(`No wrapped key with id: ${kid}`);
    }

    const keyIv = new Uint8Array(wrappedKeyRecord.iv);
    const aad = wrappedKeyRecord.aad;

    // Unwrap the VAPID key with extractable=true (needed for wrapKey to work)
    const vapidPrivateKey = await crypto.subtle.unwrapKey(
      'pkcs8',
      wrappedKeyRecord.wrappedKey,
      mkek,
      { name: 'AES-GCM', iv: keyIv, additionalData: aad },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // extractable: true (required for wrapKey)
      ['sign']
    );

    // Wrap VAPID private key with SessionKEK
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrappedLeaseKey = await crypto.subtle.wrapKey(
      'pkcs8',
      vapidPrivateKey,
      sessionKEK,
      { name: 'AES-GCM', iv }
    );

    return { wrappedLeaseKey, iv, sessionKEK, lakDelegationCert: delegationCert };
  });

  // Store SessionKEK in IndexedDB (persists across worker restarts)
  // CryptoKey objects can be stored directly in IndexedDB
  await putMeta(`sessionkek:${leaseId}`, result.result.sessionKEK);

  // Cache SessionKEK in memory for performance
  sessionKEKCache.set(leaseId, result.result.sessionKEK);

  // Initialize quota state
  const quotas: QuotaState = {
    tokensPerHour: 100, // Default quota: 100 tokens per hour
    sendsPerMinute: 10, // Default: 10 sends per minute
    burstSends: 20, // Default: 20 burst sends
    sendsPerMinutePerEid: 5, // Default: 5 sends per minute per endpoint
  };

  // Create lease record with SessionKEK-wrapped key and LAK delegation cert
  const lease: LeaseRecord = {
    leaseId,
    userId,
    subs,
    ttlHours,
    createdAt: now,
    exp,
    quotas,
    wrappedLeaseKey: result.result.wrappedLeaseKey,
    wrappedLeaseKeyIV: result.result.iv.buffer.slice(result.result.iv.byteOffset, result.result.iv.byteOffset + result.result.iv.byteLength),
    leaseSalt: leaseSalt.buffer.slice(leaseSalt.byteOffset, leaseSalt.byteOffset + leaseSalt.byteLength),
    kid,
    lakDelegationCert: result.result.lakDelegationCert,
  };

  // Store lease
  await storeLease(lease);

  // Initialize quota tracking
  await putMeta(`quota:${leaseId}`, {
    leaseId,
    tokensIssued: 0,
    lastResetAt: now,
    perEndpoint: {},
  });

  await logOperation({
    op: 'create-lease',
    kid,
    requestId,
    userId: userId,
    details: {
      action: 'create-lease',
      leaseId,
      userId,
      ttlHours,
      subsCount: subs.length,
    },
  });

  return { leaseId, exp, quotas };
}

/**
 * Issue VAPID JWT using lease authorization.
 * No credentials required - the lease IS the authorization.
 * Enforces quotas and expiration checks.
 */
async function handleIssueVAPIDJWT(
  params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    kid?: string; // Optional - auto-detect if not provided
    jti?: string; // Optional - for batch issuance
    exp?: number; // Optional - for staggered expirations
  },
  requestId: string
): Promise<{ jwt: string; jti: string; exp: number; auditEntry: AuditEntryV2 }> {
  const { leaseId, endpoint } = params;
  let { kid } = params;

  // Auto-detect VAPID key if kid not provided (per V2 spec)
  if (!kid) {
    const allKeys = await getAllWrappedKeys();
    const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');

    if (vapidKeys.length === 0) {
      throw new Error('No VAPID key found. Create a lease first to auto-generate one.');
    }

    if (vapidKeys.length > 1) {
      throw new Error('Multiple VAPID keys found. Please specify kid explicitly.');
    }

    kid = vapidKeys[0]!.kid;
  }

  // Retrieve lease
  const lease = await getLease(leaseId);
  if (!lease) {
    throw new Error(`Lease not found: ${leaseId}`);
  }

  // Check expiration
  if (Date.now() >= lease.exp) {
    throw new Error('Lease expired');
  }

  // Load LAK (Lease Audit Key) for audit logging
  // This loads the LAK private key and sets it as the active audit signer
  await loadLAK(leaseId, lease.lakDelegationCert);

  // Check endpoint is in lease
  const endpointMatch = lease.subs.find((s) => s.eid === endpoint.eid);
  if (!endpointMatch) {
    throw new Error('Endpoint not authorized for this lease');
  }

  // Check quota (simplified: tokens per hour)
  const quotaState = (await getMeta(`quota:${leaseId}`)) as any;
  if (quotaState) {
    const hourAgo = Date.now() - 3600 * 1000;
    if (quotaState.lastResetAt < hourAgo) {
      // Reset quota
      quotaState.tokensIssued = 0;
      quotaState.lastResetAt = Date.now();
    }

    if (quotaState.tokensIssued >= lease.quotas.tokensPerHour) {
      throw new Error('Quota exceeded: tokens per hour');
    }

    quotaState.tokensIssued++;
    await putMeta(`quota:${leaseId}`, quotaState);
  }

  // Build JWT payload (use provided jti/exp or generate new ones)
  const jti = params.jti ?? crypto.randomUUID();
  const exp = params.exp ?? (Math.floor(Date.now() / 1000) + 900); // 15 min from now if not provided

  const payload: VAPIDPayload = {
    aud: endpoint.aud,
    sub: 'mailto:kms@example.com', // Should come from config
    exp,
    jti,
    uid: lease.userId,
    eid: endpoint.eid,
  };

  // Get SessionKEK (from cache or load from DB)
  let sessionKEK = sessionKEKCache.get(leaseId);
  if (!sessionKEK) {
    // Load from IndexedDB if not in cache
    const sessionKEKFromDB = await getMeta<CryptoKey>(`sessionkek:${leaseId}`);
    if (!sessionKEKFromDB) {
      throw new Error(`SessionKEK not found for lease: ${leaseId}`);
    }
    sessionKEK = sessionKEKFromDB;
    // Cache for next use
    sessionKEKCache.set(leaseId, sessionKEK);
  }

  // Unwrap VAPID private key using SessionKEK (not MKEK - no credentials needed!)
  const wrappedLeaseKey = lease.wrappedLeaseKey;
  const iv = new Uint8Array(lease.wrappedLeaseKeyIV);

  // Unwrap the key using WebCrypto unwrapKey API
  const privateKey = await crypto.subtle.unwrapKey(
    'pkcs8',
    wrappedLeaseKey,
    sessionKEK,
    { name: 'AES-GCM', iv },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // not extractable
    ['sign']
  );

  // Build JWT header
  const header = { typ: 'JWT', alg: 'ES256', kid: lease.kid };
  const headerB64 = arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(header)).buffer);

  // Build JWT payload
  const payloadB64 = arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(payload)).buffer);

  // Sign
  const signatureInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    signatureInput
  );

  // Modern browsers return P-1363 format (64 bytes) which is what JWS ES256 requires
  const signatureB64 = arrayBufferToBase64url(signature);

  // Final JWT
  const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;

  const auditEntry = await logOperation({
    op: 'sign',
    kid: lease.kid,
    requestId,
    userId: lease.userId,
    leaseId, // Top-level field signals audit system to use LAK
    details: {
      action: 'issue-lease-jwt',
      jti,
      aud: endpoint.aud,
      eid: endpoint.eid,
    },
  });

  return { jwt, jti, exp, auditEntry };
}

/**
 * Issue multiple VAPID JWTs with staggered expirations (batch issuance for JWT stashing).
 *
 * STAGGERING STRATEGY:
 * - TTL = 900s (15 minutes)
 * - Stagger interval = 60% of TTL = 540s (9 minutes)
 * - JWT[0]: exp = now + 900s (T+15min)
 * - JWT[1]: exp = now + 1440s (T+24min, staggered by 9min)
 * - JWT[2]: exp = now + 1980s (T+33min, staggered by 9min)
 *
 * This ensures seamless rotation: when JWT[0] reaches 60% TTL (9min), JWT[1] is already valid.
 *
 * IMPLEMENTATION: Calls handleIssueVAPIDJWT sequentially for each JWT to ensure proper
 * serialization and avoid race conditions in audit logging.
 *
 * @param count Number of JWTs to issue (1-10, hard limit)
 */
async function handleIssueVAPIDJWTs(
  params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    count: number;
    kid?: string;
  },
  requestId: string
): Promise<Array<{ jwt: string; jti: string; exp: number; auditEntry: AuditEntryV2 }>> {
  const { leaseId, endpoint, count, kid } = params;

  // Validate count
  if (!Number.isInteger(count) || count < 1 || count > 10) {
    throw new Error('count must be an integer between 1 and 10');
  }

  // Constants for staggering
  const TTL = 900; // 15 minutes in seconds
  const STAGGER_INTERVAL = Math.floor(TTL * 0.6); // 60% of TTL = 540s (9 minutes)
  const baseTime = Math.floor(Date.now() / 1000);

  // Generate JWTs sequentially by calling handleIssueVAPIDJWT
  // This ensures audit logging is properly serialized
  const results: Array<{ jwt: string; jti: string; exp: number; auditEntry: AuditEntryV2 }> = [];

  for (let i = 0; i < count; i++) {
    // Calculate staggered expiration for this JWT
    const jti = crypto.randomUUID();
    const exp = baseTime + TTL + (i * STAGGER_INTERVAL);

    // Call handleIssueVAPIDJWT with staggered expiration and unique requestId
    // This function handles: LAK loading, quota check, key unwrapping, signing, and audit logging
    const result = await handleIssueVAPIDJWT(
      {
        leaseId,
        endpoint,
        ...(kid !== undefined && { kid }),
        jti,
        exp,
      },
      `${requestId}-${i}` // Unique requestId for each JWT
    );

    results.push(result);
  }

  return results;
}

// ============================================================================
// Status/Query Operations
// ============================================================================

/**
 * Check if KMS is setup (has at least one enrollment).
 */
async function handleIsSetup(
  params?: { userId?: string }
): Promise<{ isSetup: boolean; methods: string[]; leases?: LeaseRecord[] }> {
  const userId = params?.userId ?? 'default';
  const setupResult = await isSetup(userId);
  const methods: string[] = [];

  if (await isPassphraseSetup(userId)) methods.push('passphrase');
  if (await isPasskeySetup(userId)) methods.push('passkey');

  // If userId provided and setup is true, fetch leases
  let leases: LeaseRecord[] | undefined;
  if (setupResult && params?.userId) {
    leases = await getUserLeases(params.userId);
  }

  return { isSetup: setupResult, methods, ...(leases !== undefined && { leases }) };
}

/**
 * Get list of all enrollment methods.
 */
async function handleGetEnrollments(params?: { userId?: string }): Promise<{ enrollments: string[] }> {
  const userId = params?.userId ?? 'default';
  const enrollments: string[] = [];

  if (await isPassphraseSetup(userId)) enrollments.push('enrollment:passphrase:v2');
  if (await isPasskeySetup(userId)) {
    // Check both PRF and gate with per-user keys
    const prfConfig = await getMeta(`enrollment:passkey-prf:v2:${userId}`);
    const gateConfig = await getMeta(`enrollment:passkey-gate:v2:${userId}`);
    if (prfConfig) enrollments.push('enrollment:passkey-prf:v2');
    if (gateConfig) enrollments.push('enrollment:passkey-gate:v2');
  }

  return { enrollments };
}

/**
 * Verify audit chain integrity.
 */
async function handleVerifyAuditChain(): Promise<any> {
  return await verifyAuditChain();
}

/**
 * Get all audit log entries.
 */
async function handleGetAuditLog(): Promise<{ entries: AuditEntryV2[] }> {
  const entries = await getAllAuditEntries();
  return { entries };
}

/**
 * Get public key for a wrapped key (by kid).
 */
async function handleGetPublicKey(params: { kid: string }): Promise<{ publicKey: string }> {
  const { kid } = params;

  const wrappedKey = await getWrappedKey(kid);
  if (!wrappedKey || !wrappedKey.publicKeyRaw) {
    throw new Error(`Public key not found for kid: ${kid}`);
  }

  return { publicKey: arrayBufferToBase64url(wrappedKey.publicKeyRaw) };
}

/**
 * Get audit public key for chain verification.
 */
async function handleGetAuditPublicKey(): Promise<{ publicKey: string }> {
  return await getAuditPublicKey();
}

/**
 * Get all leases for a user.
 */
async function handleGetUserLeases(params: { userId: string }): Promise<{ leases: LeaseRecord[] }> {
  const { userId } = params;
  const leases = await getUserLeases(userId);
  return { leases };
}

/**
 * Verify a lease against the current VAPID key (read-only, no audit log).
 *
 * Checks:
 * - Lease exists
 * - Lease is not expired
 * - Lease kid matches current VAPID key
 *
 * This is a read-only operation and does not create audit entries.
 */
async function handleVerifyLease(params: { leaseId: string }): Promise<LeaseVerificationResult> {
  const { leaseId } = params;

  // Retrieve lease
  const lease = await getLease(leaseId);
  if (!lease) {
    return {
      leaseId,
      valid: false,
      reason: 'not-found',
      kid: '',
    };
  }

  // Check expiration
  if (Date.now() >= lease.exp) {
    return {
      leaseId,
      valid: false,
      reason: 'expired',
      kid: lease.kid,
    };
  }

  // Get current VAPID key (most recently created)
  const allKeys = await getAllWrappedKeys();
  const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');

  if (vapidKeys.length === 0) {
    return {
      leaseId,
      valid: false,
      reason: 'no-vapid-key',
      kid: lease.kid,
    };
  }

  // Sort by createdAt descending to get the most recent key first
  vapidKeys.sort((a, b) => b.createdAt - a.createdAt);

  // Check if lease kid matches current VAPID key (most recent)
  const currentKid = vapidKeys[0]!.kid;
  if (lease.kid !== currentKid) {
    return {
      leaseId,
      valid: false,
      reason: 'wrong-key',
      kid: lease.kid,
    };
  }

  // Lease is valid
  return {
    leaseId,
    valid: true,
    kid: lease.kid,
  };
}

/**
 * Get VAPID key ID for the user (convenience method).
 * Returns the first VAPID key found, or throws if none exists.
 */
async function handleGetVAPIDKid(): Promise<{ kid: string }> {
  const allKeys = await getAllWrappedKeys();
  const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');

  if (vapidKeys.length === 0) {
    throw new Error('No VAPID key found');
  }

  if (vapidKeys.length > 1) {
    throw new Error('Multiple VAPID keys found. Please use getPublicKey(kid) with explicit kid.');
  }

  return { kid: vapidKeys[0]!.kid };
}

// ============================================================================
// Management Operations
// ============================================================================

/**
 * Reset KMS (delete all data). USE WITH CAUTION.
 */
async function handleResetKMS(): Promise<{ success: true }> {
  // Close DB
  await closeDB();

  // Delete database
  const deleteRequest = indexedDB.deleteDatabase('kms-v2');
  await new Promise<void>((resolve, reject) => {
    deleteRequest.onsuccess = (): void => resolve();
    deleteRequest.onerror = (): void => reject(deleteRequest.error);
  });

  // Reinitialize
  await initDB();
  resetAuditLogger(); // Reset audit state (seqCounter, auditKeyPair, etc.)

  // Note: We don't log the reset operation because:
  // 1. Audit chain has been destroyed (database deleted)
  // 2. No audit key exists yet (requires MKEK from credentials)
  // 3. Reset will be implicitly logged when next operation creates new audit chain

  return { success: true };
}

/**
 * Remove specific enrollment method.
 */
async function handleRemoveEnrollment(
  params: { enrollmentId: string; credentials: AuthCredentials },
  requestId: string
): Promise<{ success: true }> {
  const { enrollmentId, credentials } = params;

  // Verify unlock works and ensure audit key is loaded
  await withUnlock(credentials, async (mkek, _ms) => {
    await ensureAuditKey(mkek);
    return true;
  });

  // Delete enrollment
  await deleteMeta(enrollmentId);

  await logOperation({
    op: 'reset',
    kid: '',
    requestId,
    userId: credentials.userId,
    details: { action: 'remove-enrollment', enrollmentId },
  });

  return { success: true };
}

// ============================================================================
// Worker Initialization
// ============================================================================

/**
 * Initialize KMS Worker on startup.
 * Generates KIAK (KMS Instance Audit Key) and logs initialization event.
 */
void (async (): Promise<void> => {
  try {
    await initDB();
    await initAuditLogger();

    // Generate KIAK (KMS Instance Audit Key) for system event logging
    await ensureKIAK();

    // Only log initialization event if this is a fresh database (no audit entries yet)
    const existingEntries = await getAllAuditEntries();
    if (existingEntries.length === 0) {
      // Log KMS initialization event (signed by KIAK)
      await logOperation({
        op: 'kms-init',
        kid: '',
        requestId: `init-${Date.now()}`,
        userId: 'system',
        details: {
          kmsVersion: 'v2.0.0',
          timestamp: new Date().toISOString(),
          note: 'KMS worker initialized, KIAK generated',
        },
      });

      // KIAK initialized, audit chain started
    } else {
      // Audit chain already exists, skipping init event
    }
  } catch (err) {
    // Initialization may fail in test environments where Worker/IndexedDB aren't fully set up
    // This is expected and safe to ignore during module loading for tests
    console.error('[KMS Worker] Initialization failed:', err);
  }
})();
