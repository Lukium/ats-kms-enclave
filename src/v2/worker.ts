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
} from './types';
import {
  setupPassphrase,
  setupPasskeyPRF,
  setupPasskeyGate,
  unlockWithPassphrase,
  unlockWithPasskeyPRF,
  unlockWithPasskeyGate,
  withUnlock,
  isSetup,
  isPassphraseSetup,
  isPasskeySetup,
} from './unlock';
import {
  initAuditLogger,
  logOperation,
  verifyAuditChain,
  getAuditPublicKey,
} from './audit';
import {
  initDB,
  closeDB,
  wrapKey,
  unwrapKey,
  getWrappedKey,
  putMeta,
  getMeta,
  deleteMeta,
} from './storage';
import {
  rawP256ToJwk,
  jwkThumbprintP256,
  arrayBufferToBase64url,
} from './crypto-utils';

// ============================================================================
// Worker Message Listener
// ============================================================================

/**
 * Main worker message handler. Receives RPC requests from client,
 * processes them, and sends back responses.
 */
self.addEventListener('message', async (event: MessageEvent) => {
  const request = event.data as RPCRequest;
  const response = await handleMessage(request);
  self.postMessage(response);
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

      // === Status/Query Operations ===
      case 'isSetup':
        result = await handleIsSetup();
        break;

      case 'getEnrollments':
        result = await handleGetEnrollments();
        break;

      case 'verifyAuditChain':
        result = await handleVerifyAuditChain();
        break;

      case 'getPublicKey':
        result = await handleGetPublicKey(params);
        break;

      case 'getAuditPublicKey':
        result = await handleGetAuditPublicKey();
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
  } catch (err: any) {
    return { id, error: err.message ?? String(err) };
  }
}

// ============================================================================
// Setup Operations
// ============================================================================

/**
 * Setup passphrase authentication.
 * Creates first Master Secret if none exists, or wraps existing MS.
 */
async function handleSetupPassphrase(
  params: { passphrase: string; existingMS?: Uint8Array },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { passphrase, existingMS } = params;

  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters');
  }

  const result = await setupPassphrase(passphrase, existingMS);

  if (!result.success) {
    throw new Error(result.error);
  }

  await logOperation({
    op: 'setup',
    kid: '',
    requestId,
    details: { method: 'passphrase' },
  });

  return { success: true, enrollmentId: 'enrollment:passphrase:v2' };
}

/**
 * Setup passkey PRF authentication.
 * Requires PRF output from WebAuthn ceremony.
 */
async function handleSetupPasskeyPRF(
  params: {
    credentialId: ArrayBuffer;
    prfOutput: ArrayBuffer;
    rpId?: string;
    existingMS?: Uint8Array;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { credentialId, prfOutput, rpId = '', existingMS } = params;

  if (!credentialId || credentialId.byteLength === 0) {
    throw new Error('credentialId required');
  }

  if (!prfOutput || prfOutput.byteLength !== 32) {
    throw new Error('prfOutput must be 32 bytes');
  }

  const result = await setupPasskeyPRF(credentialId, prfOutput, existingMS, rpId);

  if (!result.success) {
    throw new Error(result.error);
  }

  await logOperation({
    op: 'setup',
    kid: '',
    requestId,
    details: { method: 'passkey-prf', credentialId: arrayBufferToBase64url(credentialId) },
  });

  return { success: true, enrollmentId: 'enrollment:passkey-prf:v2' };
}

/**
 * Setup passkey gate authentication (fallback for non-PRF passkeys).
 * Uses random pepper + HKDF.
 */
async function handleSetupPasskeyGate(
  params: {
    credentialId: ArrayBuffer;
    rpId?: string;
    existingMS?: Uint8Array;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { credentialId, rpId = '', existingMS } = params;

  if (!credentialId || credentialId.byteLength === 0) {
    throw new Error('credentialId required');
  }

  const result = await setupPasskeyGate(credentialId, existingMS, rpId);

  if (!result.success) {
    throw new Error(result.error);
  }

  await logOperation({
    op: 'setup',
    kid: '',
    requestId,
    details: { method: 'passkey-gate', credentialId: arrayBufferToBase64url(credentialId) },
  });

  return { success: true, enrollmentId: 'enrollment:passkey-gate:v2' };
}

/**
 * Add additional enrollment method to existing Master Secret.
 * Enables multi-enrollment (same MS, multiple auth methods).
 */
async function handleAddEnrollment(
  params: {
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    credentials: AuthCredentials;
    newCredentials: any;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { method, credentials, newCredentials } = params;

  // Unlock to get existing MS
  await withUnlock(credentials, async (_mkek) => {
    // We don't need the MKEK here, just verifying unlock works
    return true;
  });

  // Get the MS by unlocking again (we need the raw MS, not just verification)
  let ms: Uint8Array;
  if (credentials.method === 'passphrase') {
    const result = await unlockWithPassphrase(credentials.passphrase);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-prf') {
    const result = await unlockWithPasskeyPRF(credentials.prfOutput);
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else if (credentials.method === 'passkey-gate') {
    const result = await unlockWithPasskeyGate();
    if (!result.success) throw new Error(result.error);
    ms = result.ms;
  } else {
    throw new Error('Invalid credentials method');
  }

  // Setup new enrollment with existing MS
  let enrollmentResult;
  if (method === 'passphrase') {
    enrollmentResult = await setupPassphrase(newCredentials.passphrase, ms);
  } else if (method === 'passkey-prf') {
    enrollmentResult = await setupPasskeyPRF(
      newCredentials.credentialId,
      newCredentials.prfOutput,
      ms,
      newCredentials.rpId
    );
  } else if (method === 'passkey-gate') {
    enrollmentResult = await setupPasskeyGate(newCredentials.credentialId, ms, newCredentials.rpId);
  } else {
    throw new Error(`Unknown enrollment method: ${method}`);
  }

  // Zeroize MS
  ms.fill(0);

  if (!enrollmentResult!.success) {
    throw new Error(enrollmentResult!.error);
  }

  await logOperation({
    op: 'setup',
    kid: '',
    requestId,
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

  const result = await withUnlock(credentials, async (mkek) => {
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
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
    details: { algorithm: 'ECDSA', curve: 'P-256', purpose: 'vapid' },
  });

  return result.result;
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

  const result = await withUnlock(credentials, async (mkek) => {
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

  // Verify unlock works (policy: must be unlocked to create lease)
  await withUnlock(credentials, async () => true);

  // Generate lease ID
  const leaseId = `lease-${crypto.randomUUID()}`;

  // Initialize quota state
  const quotas: QuotaState = {
    tokensPerHour: 100, // Default quota: 100 tokens per hour
    sendsPerMinute: 10, // Default: 10 sends per minute
    burstSends: 20, // Default: 20 burst sends
    sendsPerMinutePerEid: 5, // Default: 5 sends per minute per endpoint
  };

  // Create lease record
  const now = Date.now();
  const exp = now + ttlHours * 3600 * 1000;

  const lease: LeaseRecord = {
    leaseId,
    userId,
    subs,
    ttlHours,
    createdAt: now,
    exp,
    quotas,
  };

  // Store lease
  await putMeta(`lease:${leaseId}`, lease);

  // Initialize quota tracking
  await putMeta(`quota:${leaseId}`, {
    leaseId,
    tokensIssued: 0,
    lastResetAt: now,
    perEndpoint: {},
  });

  await logOperation({
    op: 'setup',
    kid: '',
    requestId,
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
 * Enforces quotas and expiration checks.
 */
async function handleIssueVAPIDJWT(
  params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    kid: string;
    credentials: AuthCredentials;
  },
  requestId: string
): Promise<{ jwt: string; jti: string; exp: number }> {
  const { leaseId, endpoint, kid, credentials } = params;

  // Retrieve lease
  const lease = (await getMeta(`lease:${leaseId}`)) as LeaseRecord | null;
  if (!lease) {
    throw new Error(`Lease not found: ${leaseId}`);
  }

  // Check expiration
  if (Date.now() >= lease.exp) {
    throw new Error('Lease expired');
  }

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

  // Build JWT payload
  const jti = crypto.randomUUID();
  const exp = Math.floor(Date.now() / 1000) + 900; // 15 min from now

  const payload: VAPIDPayload = {
    aud: endpoint.aud,
    sub: 'mailto:kms@example.com', // Should come from config
    exp,
    jti,
    uid: lease.userId,
    eid: endpoint.eid,
  };

  // Sign JWT
  const result = await handleSignJWT({ kid, payload, credentials }, requestId);

  await logOperation({
    op: 'sign',
    kid,
    requestId,
    details: {
      action: 'issue-lease-jwt',
      leaseId,
      jti,
      aud: endpoint.aud,
      eid: endpoint.eid,
    },
  });

  return { jwt: result.jwt, jti, exp };
}

// ============================================================================
// Status/Query Operations
// ============================================================================

/**
 * Check if KMS is setup (has at least one enrollment).
 */
async function handleIsSetup(): Promise<{ isSetup: boolean; methods: string[] }> {
  const setupResult = await isSetup();
  const methods: string[] = [];

  if (await isPassphraseSetup()) methods.push('passphrase');
  if (await isPasskeySetup()) methods.push('passkey');

  return { isSetup: setupResult, methods };
}

/**
 * Get list of all enrollment methods.
 */
async function handleGetEnrollments(): Promise<{ enrollments: string[] }> {
  const enrollments: string[] = [];

  if (await isPassphraseSetup()) enrollments.push('enrollment:passphrase:v2');
  if (await isPasskeySetup()) {
    // Check both PRF and gate
    const prfConfig = await getMeta('enrollment:passkey-prf:v2');
    const gateConfig = await getMeta('enrollment:passkey-gate:v2');
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
  await initAuditLogger();

  await logOperation({
    op: 'reset',
    kid: '',
    requestId: 'reset',
    details: { action: 'full-reset' },
  });

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

  // Verify unlock works (must be authenticated to remove enrollment)
  await withUnlock(credentials, async () => true);

  // Delete enrollment
  await deleteMeta(enrollmentId);

  await logOperation({
    op: 'reset',
    kid: '',
    requestId,
    details: { action: 'remove-enrollment', enrollmentId },
  });

  return { success: true };
}

// ============================================================================
// Worker Initialization
// ============================================================================

/**
 * Initialize KMS Worker on startup.
 */
(async (): Promise<void> => {
  await initDB();
  await initAuditLogger();
})();
