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
  VerificationResult,
  StoredPushSubscription,
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
  deleteLease,
  setPushSubscription,
  removePushSubscription,
  getPushSubscription,
} from './storage';
import {
  rawP256ToJwk,
  jwkThumbprintP256,
  arrayBufferToBase64url,
  base64urlToArrayBuffer,
} from './crypto-utils';
import { getErrorMessage } from './error-utils';
import * as validators from './rpc-validation';
import { loadRateLimitState } from './storage-types';

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

// ============================================================================
// Ephemeral Transport Keys (Setup Flow)
// ============================================================================

/**
 * In-memory cache of ephemeral ECDH transport keys for stateless popup setup.
 *
 * Each setup flow generates a temporary ECDH keypair for encrypted credential
 * transmission from popup to iframe KMS. The private key is stored here along
 * with the two salts required for WebAuthn PRF setup.
 *
 * Security properties:
 * - Private key never leaves iframe partition
 * - Auto-cleanup after 10 minutes
 * - One-time use (deleted after setupWithEncryptedCredentials)
 * - Parent never sees plaintext credentials
 */
const ephemeralTransportKeys = new Map<
  string,
  {
    privateKey: CryptoKey;
    appSalt: Uint8Array;
    hkdfSalt: Uint8Array;
    createdAt: number;
  }
>();

/**
 * Pending popup setup requests from worker to client.
 *
 * When worker initiates setupWithPopup, it sends message to client (main thread)
 * to handle the entire popup flow. Client responds with encrypted credentials.
 *
 * Map structure:
 * - Key: requestId (UUID)
 * - Value: { resolve, reject, timeout }
 *
 * Auto-cleanup on timeout (5 minutes)
 */
const pendingPopupRequests = new Map<
  string,
  {
    resolve: (value: {
      method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
      transportKeyId: string;
      userId: string;
      ephemeralPublicKey: string;
      iv: string;
      encryptedCredentials: string;
    }) => void;
    reject: (reason: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }
>();

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
// Setup Transport Key Generation
// ============================================================================

/**
 * Generate ephemeral ECDH transport key for stateless popup setup.
 *
 * This method is called by the iframe KMS when initiating a popup-based setup
 * flow. It generates:
 * 1. Ephemeral ECDH P-256 keypair (10-minute lifetime)
 * 2. Two distinct salts for WebAuthn PRF setup (appSalt and hkdfSalt)
 *
 * The public key is sent to the popup (via parent proxy) for credential encryption.
 * The private key stays in iframe partition for later decryption.
 *
 * @returns Transport parameters for popup setup
 */
async function generateSetupTransportKey(): Promise<{
  publicKey: string; // base64url-encoded P-256 public key (raw format, 65 bytes)
  keyId: string; // UUID v4
  appSalt: string; // base64url-encoded 32 bytes (for PRF eval.first)
  hkdfSalt: string; // base64url-encoded 32 bytes (for HKDF derivation)
}> {
  // Generate ephemeral ECDH keypair
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, // extractable (need to export public key)
    ['deriveBits']
  );

  // Export public key (raw format, 65 bytes uncompressed)
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);

  // Generate unique key ID
  const keyId = crypto.randomUUID();

  // Generate two distinct salts for PRF (both are public)
  const appSalt = crypto.getRandomValues(new Uint8Array(32));
  const hkdfSalt = crypto.getRandomValues(new Uint8Array(32));

  // Store private key in memory (Map<keyId, CryptoKey>)
  ephemeralTransportKeys.set(keyId, {
    privateKey: keypair.privateKey,
    appSalt,
    hkdfSalt,
    createdAt: Date.now(),
  });

  // Auto-cleanup after 10 minutes
  setTimeout(() => {
    ephemeralTransportKeys.delete(keyId);
  }, 10 * 60 * 1000);

  return {
    publicKey: arrayBufferToBase64url(publicKeyRaw),
    keyId,
    appSalt: arrayBufferToBase64url(appSalt.buffer),
    hkdfSalt: arrayBufferToBase64url(hkdfSalt.buffer),
  };
}

/**
 * Setup using encrypted credentials from popup.
 *
 * FLOW:
 * 1. Retrieve ephemeral private key by transportKeyId
 * 2. Perform ECDH with popup's ephemeral public key
 * 3. Derive AES-GCM decryption key via HKDF
 * 4. Decrypt credentials
 * 5. Call existing setup method (setupPassphrase, setupPasskeyPRF, etc.)
 * 6. Delete ephemeral transport key (one-time use)
 *
 * This method completes the stateless popup setup flow. The popup encrypts
 * credentials with a shared secret derived via ECDH, and this method decrypts
 * them and forwards to the appropriate setup handler.
 *
 * @param params.method - Credential method ('passphrase', 'passkey-prf', 'passkey-gate')
 * @param params.transportKeyId - Transport key identifier (from generateSetupTransportKey)
 * @param params.ephemeralPublicKey - Popup's ephemeral public key (base64url, 65 bytes raw)
 * @param params.iv - AES-GCM IV (base64url, 12 bytes)
 * @param params.encryptedCredentials - Encrypted credential JSON (base64url)
 * @returns Setup result from the underlying setup method
 */
async function setupWithEncryptedCredentials(params: {
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  transportKeyId: string;
  ephemeralPublicKey: string;
  iv: string;
  encryptedCredentials: string;
  userId: string;
  requestId: string;
}): Promise<{ success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string }> {
  // Step 1: Retrieve ephemeral transport key
  const transport = ephemeralTransportKeys.get(params.transportKeyId);
  if (!transport) {
    throw new Error('Transport key not found or expired');
  }

  // Step 2: Import popup's ephemeral public key
    const popupPublicKeyBytes = base64urlToArrayBuffer(params.ephemeralPublicKey);
    const popupPublicKey = await crypto.subtle.importKey(
      'raw',
      popupPublicKeyBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Step 3: Derive shared secret (ECDH)
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: popupPublicKey,
      },
      transport.privateKey,
      256 // 32 bytes
    );

    // Step 4: Derive AES-GCM key from shared secret (HKDF)
    const sharedSecretKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits']
    );

    const aesKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: new Uint8Array(32), // Zero salt (shared secret already random)
        info: new TextEncoder().encode('ATS/KMS/setup-transport/v2'),
        hash: 'SHA-256',
      },
      sharedSecretKey,
      256
    );

    const aesKey = await crypto.subtle.importKey(
      'raw',
      aesKeyBits,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Step 5: Decrypt credentials
    const iv = base64urlToArrayBuffer(params.iv);
    const ciphertext = base64urlToArrayBuffer(params.encryptedCredentials);

    const credentialsJSON = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      aesKey,
      ciphertext
    );

    const credentials = JSON.parse(new TextDecoder().decode(credentialsJSON)) as
      | { passphrase: string }
      | { credentialId: string; prfOutput: string; rpId?: string }
      | { credentialId: string; rpId?: string };

    // Step 6: Call existing setup methods based on credential type
    let result: { success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string };

    if (params.method === 'passphrase') {
      // Call existing handleSetupPassphrase
      const passphraseCredentials = credentials as { passphrase: string };
      result = await handleSetupPassphrase(
        {
          userId: params.userId,
          passphrase: passphraseCredentials.passphrase,
        },
        params.requestId
      );
    } else if (params.method === 'passkey-prf') {
      // Call existing handleSetupPasskeyPRF with BOTH salts from transport key
      const prfCredentials = credentials as { credentialId: string; prfOutput: string; rpId?: string };
      result = await handleSetupPasskeyPRF(
        {
          userId: params.userId,
          credentialId: base64urlToArrayBuffer(prfCredentials.credentialId),
          prfOutput: base64urlToArrayBuffer(prfCredentials.prfOutput),
          ...(prfCredentials.rpId !== undefined && { rpId: prfCredentials.rpId }),
          appSalt: transport.appSalt,
          hkdfSalt: transport.hkdfSalt,
        },
        params.requestId
      );
    } else if (params.method === 'passkey-gate') {
      // Call existing handleSetupPasskeyGate
      const gateCredentials = credentials as { credentialId: string; rpId?: string };
      result = await handleSetupPasskeyGate(
        {
          userId: params.userId,
          credentialId: base64urlToArrayBuffer(gateCredentials.credentialId),
          ...(gateCredentials.rpId !== undefined && { rpId: gateCredentials.rpId }),
        },
        params.requestId
      );
    } else {
      const exhaustive: never = params.method;
      throw new Error(`Unknown method: ${String(exhaustive)}`);
    }

  // Step 7: Delete ephemeral transport key (one-time use, no longer needed)
  ephemeralTransportKeys.delete(params.transportKeyId);

  return result;
}

/**
 * Setup with popup (iframe-managed flow).
 *
 * This handler orchestrates the entire popup setup flow without parent involvement:
 * 1. Generate transport key (stays in iframe)
 * 2. Request parent to open popup (via client.ts → parent)
 * 3. Wait for popup to signal ready (same-origin postMessage)
 * 4. Establish MessageChannel with popup
 * 5. Send transport params to popup (via MessageChannel)
 * 6. Receive encrypted credentials from popup
 * 7. Decrypt and process credentials
 *
 * @param params.userId - User ID
 * @param requestId - Request ID for audit logging
 * @returns Setup result
 */
async function handleSetupWithPopup(
  params: { userId: string },
  requestId: string
): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string;
}> {
  // Step 1: Generate transport key (stays in iframe, never sent to parent)
  const transport = await generateSetupTransportKey();

  // Step 2: Request parent to open popup with minimal URL
  const popupURL = new URL('https://kms.ats.run/');
  popupURL.searchParams.set('mode', 'setup');
  // Note: No transport params in URL!

  // Step 2: Tell client to open popup and handle the entire popup flow
  // Client will:
  // - Ask parent to open popup
  // - Wait for popup ready signal
  // - Establish MessageChannel with popup
  // - Send transport params to popup
  // - Receive encrypted credentials from popup
  // - Send credentials back to worker
  const credentialsPromise = new Promise<{
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    transportKeyId: string;
    userId: string;
    ephemeralPublicKey: string;
    iv: string;
    encryptedCredentials: string;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Setup with popup timeout'));
    }, 300000); // 5 minute timeout

    // Store resolver
    pendingPopupRequests.set(requestId, {
      resolve,
      reject,
      timeout
    });

    // Send request to client (main thread) with all info needed
    self.postMessage({
      type: 'worker:setup-with-popup',
      requestId,
      userId: params.userId,
      popupURL: popupURL.toString(),
      transportKey: transport.publicKey,
      transportKeyId: transport.keyId,
      appSalt: transport.appSalt,
      hkdfSalt: transport.hkdfSalt,
    });
  });

  // Wait for client to complete entire popup flow and return credentials
  const credentials = await credentialsPromise;

  // Step 3: Decrypt credentials (reuse existing logic)
  const result = await setupWithEncryptedCredentials({
    method: credentials.method,
    transportKeyId: credentials.transportKeyId,
    ephemeralPublicKey: credentials.ephemeralPublicKey,
    iv: credentials.iv,
    encryptedCredentials: credentials.encryptedCredentials,
    userId: credentials.userId,
    requestId: requestId,
  });

  return result;
}

// ============================================================================
// Worker Message Listener
// ============================================================================

/**
 * Main worker message handler. Receives RPC requests and internal messages from client,
 * processes them, and sends back responses.
 */
self.addEventListener('message', (event: MessageEvent) => {
  const message = event.data as RPCRequest | {
    type: string;
    requestId?: string;
    reason?: string;
    credentials?: {
      method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
      transportKeyId: string;
      userId: string;
      ephemeralPublicKey: string;
      iv: string;
      encryptedCredentials: string;
    };
  };

  // Handle internal messages from client (not RPC requests)
  if ('type' in message && message.type === 'worker:popup-credentials') {
    // Client completed popup flow and is sending back encrypted credentials
    const requestId = message.requestId;
    if (requestId && message.credentials) {
      const pending = pendingPopupRequests.get(requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingPopupRequests.delete(requestId);
        pending.resolve(message.credentials);
      }
    }
    return;
  }

  if ('type' in message && message.type === 'worker:popup-error') {
    // Client encountered error during popup flow
    const requestId = message.requestId;
    if (requestId) {
      const pending = pendingPopupRequests.get(requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingPopupRequests.delete(requestId);
        pending.reject(new Error(message.reason || 'Popup setup failed'));
      }
    }
    return;
  }

  // Handle RPC requests
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
    let result: unknown;

    switch (method) {
      // === Setup Operations ===
      case 'generateSetupTransportKey':
        result = await generateSetupTransportKey();
        break;

      case 'setupWithEncryptedCredentials':
        result = await setupWithEncryptedCredentials(validators.validateSetupWithEncryptedCredentials(params));
        break;

      case 'setupWithPopup':
        result = await handleSetupWithPopup(validators.validateSetupWithPopup(params), id);
        break;

      case 'setupPassphrase':
        result = await handleSetupPassphrase(validators.validateSetupPassphrase(params), id);
        break;

      case 'setupPasskeyPRF':
        result = await handleSetupPasskeyPRF(validators.validateSetupPasskeyPRF(params), id);
        break;

      case 'setupPasskeyGate':
        result = await handleSetupPasskeyGate(validators.validateSetupPasskeyGate(params), id);
        break;

      case 'addEnrollment':
        result = await handleAddEnrollment(validators.validateAddEnrollment(params), id);
        break;

      // === VAPID Operations ===
      case 'generateVAPID':
        result = await handleGenerateVAPID(validators.validateGenerateVAPID(params), id);
        break;

      case 'regenerateVAPID':
        result = await handleRegenerateVAPID(validators.validateRegenerateVAPID(params), id);
        break;

      case 'signJWT':
        result = await handleSignJWT(validators.validateSignJWT(params), id);
        break;

      // === VAPID Lease Operations ===
      case 'createLease':
        result = await handleCreateLease(validators.validateCreateLease(params), id);
        break;

      case 'extendLeases':
        result = await handleExtendLeases(validators.validateExtendLeases(params), id);
        break;

      case 'issueVAPIDJWT':
        result = await handleIssueVAPIDJWT(validators.validateIssueVAPIDJWT(params), id);
        break;

      case 'issueVAPIDJWTs':
        result = await handleIssueVAPIDJWTs(validators.validateIssueVAPIDJWTs(params), id);
        break;

      // === Status/Query Operations ===
      case 'isSetup':
        result = await handleIsSetup(validators.validateIsSetup(params));
        break;

      case 'getEnrollments':
        result = await handleGetEnrollments(validators.validateGetEnrollments(params));
        break;

      case 'verifyAuditChain':
        result = await handleVerifyAuditChain();
        break;

      case 'getAuditLog':
        result = await handleGetAuditLog();
        break;

      case 'getPublicKey':
        result = await handleGetPublicKey(validators.validateGetPublicKey(params));
        break;

      case 'getAuditPublicKey':
        result = await handleGetAuditPublicKey();
        break;

      case 'getUserLeases':
        result = await handleGetUserLeases(validators.validateGetUserLeases(params));
        break;

      case 'verifyLease':
        result = await handleVerifyLease(validators.validateVerifyLease(params));
        break;

      case 'getVAPIDKid':
        result = await handleGetVAPIDKid();
        break;

      // === Management Operations ===
      case 'resetKMS':
        result = await handleResetKMS();
        break;

      case 'removeEnrollment':
        result = await handleRemoveEnrollment(validators.validateRemoveEnrollment(params), id);
        break;

      case 'setPushSubscription':
        result = await handleSetPushSubscription(validators.validateSetPushSubscription(params));
        break;

      case 'removePushSubscription':
        result = await handleRemovePushSubscription();
        break;

      case 'getPushSubscription':
        result = await handleGetPushSubscription();
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
  const keypairResult = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  );
  if (!('privateKey' in keypairResult) || !('publicKey' in keypairResult)) {
    throw new Error('Failed to generate ECDSA keypair');
  }
  const keypair = keypairResult;

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
    appSalt?: Uint8Array;
    hkdfSalt?: Uint8Array;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string }> {
  const { userId, credentialId, prfOutput, rpId = '', existingMS, appSalt, hkdfSalt } = params;

  if (!credentialId || credentialId.byteLength === 0) {
    throw new Error('credentialId required');
  }

  if (!prfOutput || prfOutput.byteLength !== 32) {
    throw new Error('prfOutput must be 32 bytes');
  }

  const result = await setupPasskeyPRF(userId, credentialId, prfOutput, existingMS, rpId, appSalt, hkdfSalt);

  if (!result.success) {
    throw new Error(result.error);
  }

  // Derive MKEK and initialize audit key
  const mkek = await deriveMKEKFromMS(result.ms);
  await ensureAuditKey(mkek);

  // Generate VAPID keypair (per V2 spec: generate during setup)
  const keypairResult = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  );
  if (!('privateKey' in keypairResult) || !('publicKey' in keypairResult)) {
    throw new Error('Failed to generate ECDSA keypair');
  }
  const keypair = keypairResult;

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
  const keypairResult = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  );
  if (!('privateKey' in keypairResult) || !('publicKey' in keypairResult)) {
    throw new Error('Failed to generate ECDSA keypair');
  }
  const keypair = keypairResult;

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
    newCredentials: unknown;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { userId, method, credentials, newCredentials } = params;

  // Validate newCredentials structure based on method
  function validateNewCredentials(m: string, creds: unknown): Record<string, unknown> {
    if (typeof creds !== 'object' || creds === null) {
      throw new Error(`newCredentials must be an object for ${m}`);
    }
    return creds as Record<string, unknown>;
  }

  const validatedCreds = validateNewCredentials(method, newCredentials);

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
    if (typeof validatedCreds.passphrase !== 'string') {
      throw new Error('passphrase must be a string');
    }
    enrollmentResult = await setupPassphrase(userId, validatedCreds.passphrase, ms);
  } else if (method === 'passkey-prf') {
    if (!(validatedCreds.credentialId instanceof ArrayBuffer)) {
      throw new Error('credentialId must be an ArrayBuffer');
    }
    if (!(validatedCreds.prfOutput instanceof ArrayBuffer)) {
      throw new Error('prfOutput must be an ArrayBuffer');
    }
    // rpId is optional with default value ''
    const rpId = typeof validatedCreds.rpId === 'string' ? validatedCreds.rpId : '';
    enrollmentResult = await setupPasskeyPRF(
      userId,
      validatedCreds.credentialId,
      validatedCreds.prfOutput,
      ms,
      rpId
    );
  } else if (method === 'passkey-gate') {
    if (!(validatedCreds.credentialId instanceof ArrayBuffer)) {
      throw new Error('credentialId must be an ArrayBuffer');
    }
    // rpId is optional with default value ''
    const rpId = typeof validatedCreds.rpId === 'string' ? validatedCreds.rpId : '';
    enrollmentResult = await setupPasskeyGate(userId, validatedCreds.credentialId, ms, rpId);
  } else {
    const exhaustive: never = method;
    throw new Error(`Unknown enrollment method: ${String(exhaustive)}`);
  }

  // Zeroize MS
  ms.fill(0);

  if (!enrollmentResult.success) {
    throw new Error(enrollmentResult.error);
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
    const keypairResult = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // temporarily extractable for wrapping
      ['sign', 'verify']
    );
    if (!('privateKey' in keypairResult) || !('publicKey' in keypairResult)) {
      throw new Error('Failed to generate ECDSA keypair');
    }
    const keypair = keypairResult;

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
    const keypairResult = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // temporarily extractable for wrapping
      ['sign', 'verify']
    );
    if (!('privateKey' in keypairResult) || !('publicKey' in keypairResult)) {
      throw new Error('Failed to generate ECDSA keypair');
    }
    const keypair = keypairResult;

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
    ttlHours: number;
    credentials: AuthCredentials;
    autoExtend?: boolean;
  },
  requestId: string
): Promise<{ leaseId: string; exp: number; quotas: QuotaState; autoExtend?: boolean }> {
  const { userId, ttlHours, credentials, autoExtend } = params;

  // Validate TTL (max 720 hours / 30 days)
  if (ttlHours <= 0 || ttlHours > 720) {
    throw new Error('ttlHours must be between 0 and 720 (30 days)');
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
  const vapidKeyRecord = vapidKeys[0];
  if (!vapidKeyRecord) {
    throw new Error('VAPID key record not found after filtering');
  }
  const kid = vapidKeyRecord.kid;

  // Generate lease ID and salt
  const leaseId = `lease-${crypto.randomUUID()}`;
  const leaseSalt = crypto.getRandomValues(new Uint8Array(32));

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
  // Note: Push subscription data is stored with VAPID key, not in lease
  const lease: LeaseRecord = {
    leaseId,
    userId,
    ttlHours,
    createdAt: now,
    exp,
    autoExtend: autoExtend ?? true, // Default to true for best UX
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
      autoExtend: lease.autoExtend,
    },
  });

  return { leaseId, exp, quotas, autoExtend: lease.autoExtend ?? true };
}

/**
 * Extend an existing lease.
 *
 * Updates the expiration timestamp to 30 days from now.
 * Preserves the autoExtend flag and all other lease properties.
 *
 * If autoExtend is false on the lease, this operation requires authentication.
 * If autoExtend is true, this can be called without re-authentication.
 */
/**
 * Batch extend multiple leases with smart skipping.
 *
 * Processes an array of lease IDs and extends each one. If requestAuth is false
 * and a lease has autoExtend=false, it will be skipped rather than throwing an error.
 * This allows "Extend All Leases" to work gracefully with mixed lease types.
 */
async function handleExtendLeases(
  params: {
    leaseIds: string[];
    userId: string;
    requestAuth?: boolean;
    credentials?: AuthCredentials;
  },
  requestId: string
): Promise<{
  results: Array<{
    leaseId: string;
    status: 'extended' | 'skipped';
    reason?: string;
    result?: { leaseId: string; exp: number; iat: number; kid: string; autoExtend: boolean };
  }>;
  extended: number;
  skipped: number;
  failed: number;
}> {
  const { leaseIds, credentials, requestAuth } = params;
  const results: Array<{
    leaseId: string;
    status: 'extended' | 'skipped';
    reason?: string;
    result?: { leaseId: string; exp: number; iat: number; kid: string; autoExtend: boolean };
  }> = [];

  let extended = 0;
  let skipped = 0;
  let failed = 0;

  // Validate credentials once if provided (for non-extendable leases)
  let credentialsValid = false;
  if (credentials) {
    try {
      await withUnlock(credentials, async (_mkek, _ms) => {
        credentialsValid = true;
        return Promise.resolve();
      });
    } catch (err: unknown) {
      // If credentials are invalid, mark all non-extendable leases as skipped
      for (const leaseId of leaseIds) {
        const existingLease = await getLease(leaseId);
        if (existingLease && existingLease.autoExtend === false) {
          results.push({
            leaseId,
            status: 'skipped',
            reason: `Authentication failed: ${getErrorMessage(err)}`,
          });
          skipped++;
        }
      }
      if (skipped === leaseIds.length) {
        return { results, extended, skipped, failed };
      }
    }
  }

  // Process each lease
  for (const leaseId of leaseIds) {
    try {
      // Fetch existing lease
      const existingLease = await getLease(leaseId);
      if (!existingLease) {
        results.push({
          leaseId,
          status: 'skipped',
          reason: `Lease not found: ${leaseId}`,
        });
        skipped++;
        continue;
      }

      // Smart skipping: if lease requires auth but none provided, skip it
      if (existingLease.autoExtend === false && !requestAuth) {
        results.push({
          leaseId,
          status: 'skipped',
          reason: 'Lease has autoExtend=false and authentication was not requested',
        });
        skipped++;
        continue;
      }

      // If lease requires auth and requestAuth is true, but credentials are invalid, skip
      if (existingLease.autoExtend === false && requestAuth && !credentialsValid) {
        results.push({
          leaseId,
          status: 'skipped',
          reason: 'Authentication required but credentials not valid',
        });
        skipped++;
        continue;
      }

      // Verify lease is for current VAPID key
      const allKeys = await getAllWrappedKeys();
      const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');
      if (vapidKeys.length === 0) {
        results.push({
          leaseId,
          status: 'skipped',
          reason: 'No VAPID key found',
        });
        skipped++;
        continue;
      }

      vapidKeys.sort((a, b) => b.createdAt - a.createdAt);
      const currentVapidKey = vapidKeys[0];
      const currentKid = currentVapidKey!.kid;

      if (existingLease.kid !== currentKid) {
        results.push({
          leaseId,
          status: 'skipped',
          reason: `Lease is for different VAPID key (lease kid: ${existingLease.kid}, current kid: ${currentKid})`,
        });
        skipped++;
        continue;
      }

      // Extend the lease
      const now = Date.now();
      const newExp = now + 30 * 24 * 60 * 60 * 1000; // 30 days from now

      const updatedLease: LeaseRecord = {
        ...existingLease,
        exp: newExp,
        createdAt: now,
      };

      await storeLease(updatedLease);

      // Log the extension
      await logOperation({
        op: 'extend-lease',
        kid: updatedLease.kid,
        requestId,
        userId: updatedLease.userId,
        details: {
          action: 'extend-lease',
          leaseId: updatedLease.leaseId,
          userId: updatedLease.userId,
          newExp,
          autoExtend: updatedLease.autoExtend,
        },
      });

      results.push({
        leaseId,
        status: 'extended',
        result: {
          leaseId: updatedLease.leaseId,
          exp: updatedLease.exp,
          iat: updatedLease.createdAt,
          kid: updatedLease.kid,
          autoExtend: updatedLease.autoExtend ?? false,
        },
      });
      extended++;
    } catch (err: unknown) {
      results.push({
        leaseId,
        status: 'skipped',
        reason: `Error extending lease: ${getErrorMessage(err)}`,
      });
      failed++;
    }
  }

  return { results, extended, skipped, failed };
}

/**
 * Issue VAPID JWT using lease authorization.
 * No credentials required - the lease IS the authorization.
 * Enforces quotas and expiration checks.
 */
async function handleIssueVAPIDJWT(
  params: {
    leaseId: string;
    kid?: string; // Optional - auto-detect if not provided
    jti?: string; // Optional - for batch issuance
    exp?: number; // Optional - for staggered expirations
  },
  requestId: string
): Promise<{ jwt: string; jti: string; exp: number; auditEntry: AuditEntryV2 }> {
  const { leaseId } = params;
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

    const firstKey = vapidKeys[0];
    if (!firstKey) {
      throw new Error('No VAPID key found after filtering');
    }
    kid = firstKey.kid;
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

  // Check if lease kid matches current VAPID key (same logic as verifyLease)
  // This prevents JWT issuance after VAPID regeneration
  const allKeysForValidation = await getAllWrappedKeys();
  const vapidKeysForValidation = allKeysForValidation.filter((k) => k.purpose === 'vapid');

  if (vapidKeysForValidation.length === 0) {
    throw new Error('No VAPID key available');
  }

  // Sort by createdAt descending to get the most recent key first
  vapidKeysForValidation.sort((a, b) => b.createdAt - a.createdAt);
  const currentKid = vapidKeysForValidation[0]?.kid;

  if (!currentKid) {
    throw new Error('Failed to determine current VAPID key');
  }

  if (lease.kid !== currentKid) {
    throw new Error('Lease invalidated by VAPID key rotation (wrong-key)');
  }

  // Load LAK (Lease Audit Key) for audit logging
  // This loads the LAK private key and sets it as the active audit signer
  await loadLAK(leaseId, lease.lakDelegationCert);

  // Get push subscription from VAPID key (single source of truth)
  const subscription = await getPushSubscription();
  if (!subscription) {
    throw new Error('No push subscription found. Call setPushSubscription() first.');
  }

  // Check quota (simplified: tokens per hour)
  const rawQuotaState = await getMeta(`quota:${leaseId}`);
  const quotaState = loadRateLimitState(rawQuotaState);

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

  // Build JWT payload (use provided jti/exp or generate new ones)
  const jti = params.jti ?? crypto.randomUUID();
  const exp = params.exp ?? (Math.floor(Date.now() / 1000) + 900); // 15 min from now if not provided

  // Extract aud from subscription endpoint (e.g., https://fcm.googleapis.com)
  const endpointUrl = new URL(subscription.endpoint);
  const aud = `${endpointUrl.protocol}//${endpointUrl.host}`;

  const payload: VAPIDPayload = {
    aud,
    sub: 'mailto:kms@example.com', // Should come from config
    exp,
    jti,
    uid: lease.userId,
    eid: subscription.eid,
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
      aud,
      eid: subscription.eid,
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
    count: number;
    kid?: string;
  },
  requestId: string
): Promise<Array<{ jwt: string; jti: string; exp: number; auditEntry: AuditEntryV2 }>> {
  const { leaseId, count, kid } = params;

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
async function handleVerifyAuditChain(): Promise<VerificationResult> {
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
async function handleVerifyLease(params: {
  leaseId: string;
  deleteIfInvalid?: boolean;
}): Promise<LeaseVerificationResult> {
  const { leaseId, deleteIfInvalid = false } = params;

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
    // Delete if requested
    if (deleteIfInvalid) {
      await deleteLease(leaseId);
    }
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
    // Delete if requested (no VAPID key means lease is invalid)
    if (deleteIfInvalid) {
      await deleteLease(leaseId);
    }
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
  const firstKey = vapidKeys[0];
  if (!firstKey) {
    // Delete if requested
    if (deleteIfInvalid) {
      await deleteLease(leaseId);
    }
    return {
      leaseId,
      valid: false,
      reason: 'no-vapid-key',
      kid: lease.kid,
    };
  }
  const currentKid = firstKey.kid;
  if (lease.kid !== currentKid) {
    // Delete if requested (wrong key = stale lease)
    if (deleteIfInvalid) {
      await deleteLease(leaseId);
    }
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

  const firstKey = vapidKeys[0];
  if (!firstKey) {
    throw new Error('No VAPID key found after filtering');
  }

  return { kid: firstKey.kid };
}

// ============================================================================
// Push Subscription Operations
// ============================================================================

/**
 * Set push subscription for the current VAPID key.
 *
 * Stores the subscription data with the VAPID key record. This allows
 * leases and JWTs to automatically include the subscription info without
 * requiring it to be passed on every call.
 *
 * @param params - Validated subscription data
 * @returns Success confirmation
 */
async function handleSetPushSubscription(params: {
  subscription: StoredPushSubscription;
}): Promise<{ success: true }> {
  await setPushSubscription(params.subscription);
  return { success: true };
}

/**
 * Remove push subscription from the current VAPID key.
 *
 * @returns Success confirmation
 */
async function handleRemovePushSubscription(): Promise<{ success: true }> {
  await removePushSubscription();
  return { success: true };
}

/**
 * Get push subscription from the current VAPID key.
 *
 * @returns Subscription data or null if not set
 */
async function handleGetPushSubscription(): Promise<{
  subscription: StoredPushSubscription | null;
}> {
  const subscription = await getPushSubscription();
  return { subscription };
}

// ============================================================================
// Management Operations
// ============================================================================

/**
 * Reset KMS (delete all data). USE WITH CAUTION.
 */
async function handleResetKMS(): Promise<{ success: true }> {
  // Close DB
  closeDB();

  // Delete database
  const deleteRequest = indexedDB.deleteDatabase('kms-v2');
  await new Promise<void>((resolve, reject) => {
    deleteRequest.onsuccess = (): void => resolve();
    deleteRequest.onerror = (): void => reject(new Error(deleteRequest.error?.message ?? 'Failed to delete database'));
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
