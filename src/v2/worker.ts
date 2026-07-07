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
  PasskeyPRFConfigV2,
  PasskeyGateConfigV2,
} from './types';
import {
  setupPassphrase,
  setupPasskeyPRF,
  setupPasskeyGate,
  withUnlock,
  deriveMKEKFromMS,
  deriveMessagingKEK,
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
  clearAllStores,
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
  withSessionLock,
  countUnconsumedOnetimePrekeys,
  getSignalIdentity,
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
import {
  createSignalProtocolStore,
  generateIdentity,
  generateSignedPrekey,
  generateOneTimePrekeys,
  getPublicBundle,
  type PublicPreKeyBundle,
} from './signal';
import {
  generateAccountRoot,
  accountRootToMnemonic,
  mnemonicToAccountRoot,
} from './account-root';
import { storeAccountRoot, loadAccountRoot, hasAccountRoot } from './account-store';
import {
  deriveSelfScope,
  deriveSelfKey,
  encryptSelfMessage,
  decryptSelfMessage,
} from './self-channel';
import { derivePairID, deriveExchangeKey } from './pairing';
import { storeContactSecret, loadContactSecret, listContactPeers } from './contact-store';
import {
  encryptEnvelope,
  serializeBundle,
  parseBundle,
  trialDecryptEnvelope,
  type Envelope,
} from './envelope';
import {
  wrapAccountRootToDevice,
  unwrapAccountRootFromDevice,
  type WrappedAccountRoot,
} from './device-wrap';
import {
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
} from '@lukium/libsignal-protocol-typescript';
import type { DeviceType } from '@lukium/libsignal-protocol-typescript';

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
 * Persistence (IMPORTANT — read before changing): for VAPID leases the
 * SessionKEK is BOTH cached here AND persisted to IndexedDB in `createLease`
 * (see `putMeta('sessionkek:...')`). This is deliberate: push must keep issuing
 * JWTs in the background after a worker restart while the user is away, without
 * forcing a re-unlock. The persisted key is a non-extractable CryptoKey handle
 * (its raw bytes cannot be exported via the JS API), and re-derivation needs the
 * MS, so this is an accepted reliability/security tradeoff for push.
 *
 * NOTE: messaging deliberately does NOT follow this pattern. Messaging is a
 * foreground, user-present activity, so its session KEK is held memory-only
 * (keyed by session id) and never persisted — see the Signal messaging design.
 *
 * Lifecycle:
 * - Derived uniquely per lease (different salt)
 * - Cleared from this cache on worker restart (re-derived/re-loaded on demand)
 * - Cleared when lease expires
 */
const sessionKEKCache = new Map<string, CryptoKey>();

// ============================================================================
// Messaging Capability Sessions (memory-only, per-session id)
// ============================================================================

/**
 * Sliding idle timeout: a messaging session is dropped this long after its last
 * use, so keys leave memory promptly when the user steps away.
 */
const MESSAGING_IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
/**
 * Absolute session cap: one authentication grants at most this much messaging
 * time. After it the PWA must re-authenticate via `openMessaging`. The capability
 * token's `exp` mirrors this value.
 */
const MESSAGING_ABSOLUTE_MAX_MS = 8 * 60 * 60 * 1000; // 8 hours

/**
 * One live messaging session. Created by `openMessaging` after a single unlock,
 * dropped by `closeMessaging` / idle / absolute expiry.
 *
 * SECURITY: `messagingKEK` is the messaging-scoped sub-key (see
 * {@link deriveMessagingKEK}), NOT the master MKEK — a leaked/abused session can
 * only touch Signal blobs, never the VAPID or audit keys. `capPubKey` verifies
 * the capability token the PWA presents on each call; the matching private key is
 * used once at mint time and then discarded (per-session keypair, never stored).
 */
interface MessagingSession {
  messagingKEK: CryptoKey;
  userId: string;
  capPubKey: CryptoKey;
  /** Absolute hard cap (ms epoch). */
  absoluteExp: number;
  /** Sliding idle deadline (ms epoch); refreshed on each authorized call. */
  idleExp: number;
  /**
   * Self-channel content key, derived from the account root at openMessaging and
   * cached memory-only for the session (so routine self-channel seal/open need no
   * extra unlock). Undefined until this device has an account root.
   */
  selfKey?: CryptoKey;
  /** Self-channel address (opaque, non-secret), derived alongside {@link selfKey}. */
  selfScope?: string;
}

/**
 * Memory-only map of live messaging sessions keyed by `sid`. Never persisted to
 * IndexedDB (unlike `sessionKEKCache`): messaging is foreground/user-present, so
 * a worker restart legitimately ends the session and forces a re-unlock.
 */
const messagingSessions = new Map<string, MessagingSession>();

/**
 * Mint an Ed25519 capability token (compact JWS, `alg: EdDSA`) binding a `sid`
 * and the `messaging` scope to an expiry. Signed by the per-session private key;
 * verified later against the session's stored public key.
 */
async function mintCapabilityToken(
  sid: string,
  privateKey: CryptoKey,
  iat: number,
  exp: number
): Promise<string> {
  const header = { typ: 'JWT', alg: 'EdDSA' };
  const payload = { sid, scope: ['messaging'], iat, exp };
  const headerB64 = arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(header)).buffer);
  const payloadB64 = arrayBufferToBase64url(new TextEncoder().encode(JSON.stringify(payload)).buffer);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = await crypto.subtle.sign('Ed25519', privateKey, signingInput);
  return `${headerB64}.${payloadB64}.${arrayBufferToBase64url(signature)}`;
}

/**
 * Authorize a messaging RPC: the call must carry a live `sid` and a valid
 * capability `token`. Enforces (in order) session existence, idle + absolute
 * expiry, token structure, `sid`/scope/`exp` claims, and an Ed25519 signature
 * check against the session's public key. On success it slides the idle deadline
 * and returns the session's messaging-scoped key + user. Throws on any failure
 * (an expired session is evicted first).
 */
async function requireCapability(sid: string, token: string): Promise<MessagingSession> {
  const session = messagingSessions.get(sid);
  if (!session) {
    throw new Error('Messaging session not found (closed, expired, or never opened)');
  }
  const now = Date.now();
  if (now >= session.absoluteExp || now >= session.idleExp) {
    messagingSessions.delete(sid);
    throw new Error('Messaging session expired; re-authenticate with openMessaging');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed capability token');
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  let payload: { sid?: unknown; scope?: unknown; exp?: unknown };
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlToArrayBuffer(payloadB64))) as typeof payload;
  } catch {
    throw new Error('Malformed capability token payload');
  }
  if (payload.sid !== sid) {
    throw new Error('Capability token sid mismatch');
  }
  if (!Array.isArray(payload.scope) || !payload.scope.includes('messaging')) {
    throw new Error('Capability token missing messaging scope');
  }
  if (typeof payload.exp !== 'number' || now / 1000 >= payload.exp) {
    throw new Error('Capability token expired');
  }

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify(
    'Ed25519',
    session.capPubKey,
    base64urlToArrayBuffer(signatureB64),
    signingInput
  );
  if (!valid) {
    throw new Error('Capability token signature invalid');
  }

  // Slide the idle window (absolute cap is untouched).
  session.idleExp = now + MESSAGING_IDLE_TIMEOUT_MS;
  return session;
}

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
 * Pending unlock requests (addEnrollmentWithPopup flow).
 * Maps requestId to promise resolver for unlock credentials.
 *
 * - Key: requestId (UUID)
 * - Value: { resolve, reject, timeout }
 *
 * Auto-cleanup on timeout (5 minutes)
 */
const pendingUnlockRequests = new Map<
  string,
  {
    resolve: (value: AuthCredentials) => void;
    reject: (reason: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }
>();

/**
 * Pending fullSetup requests (multi-step orchestration).
 * Maps requestId to promise resolvers for async operations (push subscription, test notification).
 *
 * - Key: requestId (UUID)
 * - Value: { resolve, reject, timeout, state }
 *
 * Auto-cleanup on timeout (90 seconds for push, 30 seconds for notification)
 */
const pendingFullSetupRequests = new Map<
  string,
  {
    resolve: (value: unknown) => void;
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
}): Promise<{ success: true; enrollmentId: string; vapidPublicKey: string; vapidKid: string; credentials: AuthCredentials }> {
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
    let authCredentials: AuthCredentials;

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

      // Build AuthCredentials for return
      authCredentials = {
        method: 'passphrase',
        passphrase: passphraseCredentials.passphrase,
        userId: params.userId,
      };
    } else if (params.method === 'passkey-prf') {
      // Call existing handleSetupPasskeyPRF with BOTH salts from transport key
      const prfCredentials = credentials as { credentialId: string; prfOutput: string; rpId?: string };
      const prfOutputBuffer = base64urlToArrayBuffer(prfCredentials.prfOutput);
      result = await handleSetupPasskeyPRF(
        {
          userId: params.userId,
          credentialId: base64urlToArrayBuffer(prfCredentials.credentialId),
          prfOutput: prfOutputBuffer,
          ...(prfCredentials.rpId !== undefined && { rpId: prfCredentials.rpId }),
          appSalt: transport.appSalt,
          hkdfSalt: transport.hkdfSalt,
        },
        params.requestId
      );

      // Build AuthCredentials for return
      authCredentials = {
        method: 'passkey-prf',
        prfOutput: prfOutputBuffer,
        userId: params.userId,
      };
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

      // Build AuthCredentials for return
      authCredentials = {
        method: 'passkey-gate',
        userId: params.userId,
      };
    } else {
      const exhaustive: never = params.method;
      throw new Error(`Unknown method: ${String(exhaustive)}`);
    }

  // Step 7: Delete ephemeral transport key (one-time use, no longer needed)
  ephemeralTransportKeys.delete(params.transportKeyId);

  return {
    ...result,
    credentials: authCredentials,
  };
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

/**
 * Complete onboarding flow in a single user action.
 *
 * Orchestrates the entire setup process:
 * 1. User authentication setup (via popup)
 * 2. Web Push subscription (via parent PWA)
 * 3. VAPID lease creation (with autoExtend flag)
 * 4. JWT packet issuance (5 tokens with staggered expirations)
 * 5. Test notification (confirms setup working)
 *
 * @param params.userId - User ID
 * @param params.autoExtend - Whether lease can be auto-extended without re-auth (default: true)
 * @param params.ttlHours - Lease TTL in hours (default: 12, max: 720)
 * @param requestId - Request ID for audit logging
 * @returns Complete setup result with lease, JWTs, and subscription
 */
async function handleFullSetup(
  params: {
    userId: string;
    autoExtend?: boolean;
    ttlHours?: number;
  },
  requestId: string
): Promise<{
  success: true;
  enrollmentId: string;
  vapidPublicKey: string;
  vapidKid: string;
  leaseId: string;
  leaseExp: number;
  autoExtend: boolean;
  jwts: Array<{ jwt: string; jti: string; exp: number }>;
  subscription: StoredPushSubscription;
}> {
  const { userId, autoExtend = true, ttlHours = 12 } = params;

  // Validate TTL
  if (ttlHours <= 0 || ttlHours > 720) {
    throw new Error('ttlHours must be between 0 and 720 (30 days)');
  }

  // STEP 1: Check if already setup
  const setupCheck = await isSetup(userId);
  if (setupCheck) {
    throw new Error('User already has authentication setup. Use addEnrollment to add additional methods.');
  }

  // STEP 2: Setup authentication (via popup)
  // This returns credentials for immediate lease creation (not exposed via RPC)
  // Note: handleSetupWithPopup returns credentials internally, not via RPC
  const setupResult = await handleSetupWithPopup({ userId }, `${requestId}-setup`) as {
    success: true;
    enrollmentId: string;
    vapidPublicKey: string;
    vapidKid: string;
    credentials: AuthCredentials;
  };

  // Extract credentials and VAPID info
  const credentials = setupResult.credentials;
  const vapidPublicKey = setupResult.vapidPublicKey;
  const vapidKid = setupResult.vapidKid;
  const enrollmentId = setupResult.enrollmentId;

  // STEP 3: Request push subscription from parent PWA
  const subscription = await new Promise<StoredPushSubscription>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Push subscription timeout (60s)'));
    }, 60000); // 60 second timeout

    const subRequestId = `${requestId}-push-sub`;

    // Store resolver in pending map
    pendingFullSetupRequests.set(subRequestId, {
      resolve: resolve as (value: unknown) => void,
      reject,
      timeout,
    });

    // Send message to client (main thread) to request push subscription
    self.postMessage({
      type: 'worker:request-push-subscription',
      requestId: subRequestId,
      vapidPublicKey,
      userId,
    });
  });

  // STEP 4: Store push subscription with VAPID key
  await handleSetPushSubscription({ subscription });

  // STEP 5: Create lease with saved credentials
  // No re-authentication needed - we saved credentials from setup
  const leaseResult = await handleCreateLease(
    {
      userId,
      ttlHours,
      credentials,
      autoExtend,
    },
    `${requestId}-lease`
  );

  // STEP 6: Issue packet of 5 JWTs with staggered expirations
  const jwtResults = await handleIssueVAPIDJWTs(
    {
      leaseId: leaseResult.leaseId,
      count: 5,
      kid: vapidKid,
    },
    `${requestId}-jwts`
  );

  // Extract JWTs without audit entries (cleaner return)
  const jwts = jwtResults.map(r => ({
    jwt: r.jwt,
    jti: r.jti,
    exp: r.exp,
  }));

  // STEP 7: Send test notification (best-effort, don't fail if it errors)
  try {
    const testJWT = jwts[0]!;

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Test notification timeout (30s)'));
      }, 30000); // 30 second timeout

      const notifRequestId = `${requestId}-test-notif`;

      // Store resolver
      pendingFullSetupRequests.set(notifRequestId, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timeout,
      });

      // Send message to client to send test notification
      self.postMessage({
        type: 'worker:send-test-notification',
        requestId: notifRequestId,
        jwt: testJWT.jwt,
        subscription,
        vapidPublicKey,
      });
    });
  } catch (err: unknown) {
    // Log warning but don't fail fullSetup
    console.warn('[KMS Worker] Test notification failed (non-fatal):', getErrorMessage(err));
  }

  // STEP 8: Clear credentials from memory (defense in depth)
  if (credentials.method === 'passphrase') {
    // Can't directly zero strings in JS, but reassign to empty
    (credentials as { passphrase: string }).passphrase = '';
  } else if (credentials.method === 'passkey-prf') {
    // Zero PRF output buffer
    new Uint8Array((credentials as { prfOutput: ArrayBuffer }).prfOutput).fill(0);
  }
  // passkey-gate has no sensitive material to clear

  // Log operation
  await logOperation({
    op: 'full-setup',
    kid: vapidKid,
    requestId,
    userId,
    details: {
      action: 'full-setup',
      enrollmentId,
      leaseId: leaseResult.leaseId,
      autoExtend,
      ttlHours,
      jwtCount: jwts.length,
    },
  });

  return {
    success: true,
    enrollmentId,
    vapidPublicKey,
    vapidKid,
    leaseId: leaseResult.leaseId,
    leaseExp: leaseResult.exp,
    autoExtend: leaseResult.autoExtend ?? true,
    jwts,
    subscription,
  };
}

// ============================================================================
// Worker Message Listener
// ============================================================================

/**
 * Main worker message handler. Receives RPC requests and internal messages from client,
 * processes them, and sends back responses.
 */
const handleWorkerMessage = (event: MessageEvent): void => {
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

  if ('type' in message && message.type === 'worker:unlock-credentials') {
    // Client completed unlock modal and is sending back credentials
    const requestId = message.requestId;
    const credentials = (message as { credentials?: AuthCredentials }).credentials;
    if (requestId && credentials) {
      const pending = pendingUnlockRequests.get(requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingUnlockRequests.delete(requestId);
        pending.resolve(credentials);
      }
    }
    return;
  }

  if ('type' in message && message.type === 'worker:unlock-error') {
    // Client encountered error during unlock modal
    const requestId = message.requestId;
    if (requestId) {
      const pending = pendingUnlockRequests.get(requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingUnlockRequests.delete(requestId);
        pending.reject(new Error(message.reason || 'Unlock failed'));
      }
    }
    return;
  }

  // Handle push subscription result from client (fullSetup flow)
  if ('type' in message && message.type === 'worker:push-subscription-result') {
    const data = message as { type: string; requestId?: string; subscription?: StoredPushSubscription; error?: string };
    const requestId = data.requestId;
    const subscription = data.subscription;
    const error = data.error;

    if (requestId) {
      const pending = pendingFullSetupRequests.get(requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingFullSetupRequests.delete(requestId);

        if (subscription) {
          pending.resolve(subscription);
        } else {
          pending.reject(new Error(error || 'Push subscription failed'));
        }
      }
    }
    return;
  }

  // Handle test notification result from client (fullSetup flow)
  if ('type' in message && message.type === 'worker:test-notification-result') {
    const data = message as { type: string; requestId?: string; success?: boolean; error?: string };
    const requestId = data.requestId;
    const success = data.success;
    const error = data.error;

    if (requestId) {
      const pending = pendingFullSetupRequests.get(requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingFullSetupRequests.delete(requestId);

        if (success) {
          pending.resolve(undefined);
        } else {
          pending.reject(new Error(error || 'Test notification failed'));
        }
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
};

// Register the message listener only in a real Worker context. In unit tests
// (node / happy-dom without a Worker global) `self.addEventListener` is absent;
// those tests drive `handleMessage` directly instead.
if (typeof self !== 'undefined' && typeof self.addEventListener === 'function') {
  self.addEventListener('message', handleWorkerMessage);
}

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
      // Legacy RPC methods removed: generateSetupTransportKey, setupWithEncryptedCredentials
      // These are now internal functions used by setupWithPopup

      case 'setupWithPopup': {
        const setupResult = await handleSetupWithPopup(validators.validateSetupWithPopup(params), id) as {
          success: true;
          enrollmentId: string;
          vapidPublicKey: string;
          vapidKid: string;
          credentials: AuthCredentials;
        };
        // Strip credentials from response for security (only used internally by fullSetup)
        result = {
          success: setupResult.success,
          enrollmentId: setupResult.enrollmentId,
          vapidPublicKey: setupResult.vapidPublicKey,
          vapidKid: setupResult.vapidKid,
        };
        break;
      }

      case 'fullSetup':
        result = await handleFullSetup(validators.validateFullSetup(params), id);
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

      case 'addEnrollmentWithPopup':
        result = await handleAddEnrollmentWithPopup(validators.validateAddEnrollmentWithPopup(params), id);
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

      case 'getPasskeyUnlockParams':
        result = await handleGetPasskeyUnlockParams(validators.validateGetPasskeyUnlockParams(params));
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

      // === Signal Messaging Operations ===
      case 'setupMessaging':
        result = await handleSetupMessaging(validators.validateSetupMessaging(params), id);
        break;

      case 'getMessagingBundle':
        result = await handleGetMessagingBundle(validators.validateGetMessagingBundle(params));
        break;

      case 'getPrekeyCount':
        result = await handleGetPrekeyCount(validators.validateGetPrekeyCount(params));
        break;

      case 'openMessaging':
        result = await handleOpenMessaging(validators.validateOpenMessaging(params), id);
        break;

      case 'closeMessaging':
        result = await handleCloseMessaging(validators.validateCloseMessaging(params), id);
        break;

      case 'rotatePrekeys':
        result = await handleRotatePrekeys(validators.validateRotatePrekeys(params), id);
        break;

      // === Fan-out Bundle Operations (secure-messaging §8/§12) ===
      case 'buildBundle':
        result = await handleBuildBundle(validators.validateBuildBundle(params), id);
        break;

      case 'openBundle':
        result = await handleOpenBundle(validators.validateOpenBundle(params), id);
        break;

      // === Account Root Operations (secure-messaging §18) ===
      case 'setupAccountRoot':
        result = await handleSetupAccountRoot(validators.validateSetupAccountRoot(params), id);
        break;

      case 'importAccountRootFromMnemonic':
        result = await handleImportAccountRootFromMnemonic(
          validators.validateImportAccountRootFromMnemonic(params),
          id
        );
        break;

      case 'importWrappedAccountRoot':
        result = await handleImportWrappedAccountRoot(
          validators.validateImportWrappedAccountRoot(params),
          id
        );
        break;

      case 'wrapAccountRootForDevice':
        result = await handleWrapAccountRootForDevice(
          validators.validateWrapAccountRootForDevice(params),
          id
        );
        break;

      case 'hasAccountRoot':
        result = await handleHasAccountRoot(validators.validateHasAccountRoot(params));
        break;

      // === Self-channel Operations (secure-messaging §18.2) ===
      case 'getSelfScope':
        result = await handleGetSelfScope(validators.validateGetSelfScope(params));
        break;

      case 'sealSelfMessage':
        result = await handleSealSelfMessage(validators.validateSealSelfMessage(params), id);
        break;

      case 'openSelfMessage':
        result = await handleOpenSelfMessage(validators.validateOpenSelfMessage(params), id);
        break;

      // === Pairing / Contact Operations (secure-messaging §5/§6) ===
      case 'setContactSecret':
        result = await handleSetContactSecret(validators.validateSetContactSecret(params), id);
        break;

      case 'getContactPairID':
        result = await handleGetContactPairID(validators.validateGetContactPairID(params));
        break;

      case 'listContacts':
        result = await handleListContacts(validators.validateListContacts(params));
        break;

      case 'sealDeviceExchange':
        result = await handleSealDeviceExchange(validators.validateSealDeviceExchange(params), id);
        break;

      case 'openDeviceExchange':
        result = await handleOpenDeviceExchange(validators.validateOpenDeviceExchange(params), id);
        break;

      case 'sealContactAnnouncement':
        result = await handleSealContactAnnouncement(
          validators.validateSealContactAnnouncement(params),
          id
        );
        break;

      case 'applyContactAnnouncement':
        result = await handleApplyContactAnnouncement(
          validators.validateApplyContactAnnouncement(params),
          id
        );
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
    credentials: AuthCredentials;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { userId, credentials } = params;

  // Unlock ONCE to verify credentials, ensure audit key, and get MS
  // (Similar pattern to createLease - do everything in a single withUnlock call)
  const unlockResult = await withUnlock(credentials, async (_mkek, masterSecret) => {
    // Ensure audit key is loaded (required for multi-enrollment)
    await ensureAuditKey(_mkek);
    // Return the MS for use outside withUnlock
    return masterSecret;
  });
  const ms = unlockResult.result;

  // Step 2: Generate transport key (stays in iframe, never sent to parent)
  const transport = await generateSetupTransportKey();

  // Step 3: Request parent to open popup with minimal URL
  const popupURL = new URL('https://kms.ats.run/');
  popupURL.searchParams.set('mode', 'setup');

  // Step 4: Tell client to open popup and handle the entire popup flow
  const credentialsPromise = new Promise<{
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    transportKeyId: string;
    userId: string;
    ephemeralPublicKey: string;
    iv: string;
    encryptedCredentials: string;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.error('[Worker] Popup timeout after 5 minutes');
      reject(new Error('Add enrollment popup timeout'));
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
  const newCredentialsEncrypted = await credentialsPromise;

  // Step 5: Decrypt credentials (copy from setupWithEncryptedCredentials)
  const transportKey = ephemeralTransportKeys.get(newCredentialsEncrypted.transportKeyId);
  if (!transportKey) {
    throw new Error('Transport key not found or expired');
  }

  const popupPublicKeyBytes = base64urlToArrayBuffer(newCredentialsEncrypted.ephemeralPublicKey);
  const popupPublicKey = await crypto.subtle.importKey(
    'raw',
    popupPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: popupPublicKey,
    },
    transportKey.privateKey,
    256
  );

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
      salt: new Uint8Array(32),
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

  const iv = base64urlToArrayBuffer(newCredentialsEncrypted.iv);
  const ciphertext = base64urlToArrayBuffer(newCredentialsEncrypted.encryptedCredentials);

  const credentialsJSON = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128,
    },
    aesKey,
    ciphertext
  );

  const decryptedCredentials = JSON.parse(new TextDecoder().decode(credentialsJSON)) as
    | { passphrase: string }
    | { credentialId: string; prfOutput: string; rpId?: string }
    | { credentialId: string; rpId?: string };

  // Delete ephemeral transport key (one-time use)
  ephemeralTransportKeys.delete(newCredentialsEncrypted.transportKeyId);

  // Step 5: Setup new enrollment with existing MS based on decrypted credential type
  const method = newCredentialsEncrypted.method;
  let enrollmentResult;

  if (method === 'passphrase') {
    const passphraseCredentials = decryptedCredentials as { passphrase: string };
    enrollmentResult = await setupPassphrase(userId, passphraseCredentials.passphrase, ms);
  } else if (method === 'passkey-prf') {
    const prfCredentials = decryptedCredentials as { credentialId: string; prfOutput: string; rpId?: string };
    const rpId = prfCredentials.rpId || '';
    enrollmentResult = await setupPasskeyPRF(
      userId,
      base64urlToArrayBuffer(prfCredentials.credentialId),
      base64urlToArrayBuffer(prfCredentials.prfOutput),
      ms,
      rpId
    );
  } else if (method === 'passkey-gate') {
    const gateCredentials = decryptedCredentials as { credentialId: string; rpId?: string };
    const rpId = gateCredentials.rpId || '';
    enrollmentResult = await setupPasskeyGate(userId, base64urlToArrayBuffer(gateCredentials.credentialId), ms, rpId);
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

/**
 * Add additional enrollment method with popup flow (reversed order).
 * Opens popup FIRST to collect new credentials (preserves user gesture),
 * then shows unlock modal to get existing credentials.
 * Enables multi-enrollment (same MS, multiple auth methods).
 */
async function handleAddEnrollmentWithPopup(
  params: {
    userId: string;
  },
  requestId: string
): Promise<{ success: true; enrollmentId: string }> {
  const { userId } = params;

  // Step 1: Generate transport key (stays in iframe, never sent to parent)
  const transport = await generateSetupTransportKey();

  // Step 2: Request popup to collect NEW credentials (user gesture preserved)
  const popupURL = new URL('https://kms.ats.run/');
  popupURL.searchParams.set('mode', 'setup');

  const newCredentialsEncrypted = await new Promise<{
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
    transportKeyId: string;
    userId: string;
    ephemeralPublicKey: string;
    iv: string;
    encryptedCredentials: string;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.error('[Worker] Popup timeout after 5 minutes');
      reject(new Error('Add enrollment popup timeout'));
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
      userId,
      popupURL: popupURL.toString(),
      transportKey: transport.publicKey,
      transportKeyId: transport.keyId,
      appSalt: transport.appSalt,
      hkdfSalt: transport.hkdfSalt,
    });
  });

  // Step 3: Decrypt new credentials
  const transportKey = ephemeralTransportKeys.get(newCredentialsEncrypted.transportKeyId);
  if (!transportKey) {
    throw new Error('Transport key not found or expired');
  }

  const popupPublicKeyBytes = base64urlToArrayBuffer(newCredentialsEncrypted.ephemeralPublicKey);
  const popupPublicKey = await crypto.subtle.importKey(
    'raw',
    popupPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: popupPublicKey,
    },
    transportKey.privateKey,
    256
  );

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
      salt: new Uint8Array(32),
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

  const iv = base64urlToArrayBuffer(newCredentialsEncrypted.iv);
  const ciphertext = base64urlToArrayBuffer(newCredentialsEncrypted.encryptedCredentials);

  const credentialsJSON = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128,
    },
    aesKey,
    ciphertext
  );

  const newCredentials = JSON.parse(new TextDecoder().decode(credentialsJSON)) as
    | { passphrase: string }
    | { credentialId: string; prfOutput: string; rpId?: string }
    | { credentialId: string; rpId?: string };

  // Delete ephemeral transport key (one-time use)
  ephemeralTransportKeys.delete(newCredentialsEncrypted.transportKeyId);

  // Step 4: Now request unlock modal to get EXISTING credentials
  const unlockCredentials = await new Promise<AuthCredentials>((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.error('[Worker] Unlock timeout after 5 minutes');
      reject(new Error('Unlock modal timeout'));
    }, 300000); // 5 minute timeout

    // Store resolver
    pendingUnlockRequests.set(requestId, {
      resolve,
      reject,
      timeout
    });

    // Send message to client to show unlock modal
    self.postMessage({
      type: 'worker:request-unlock',
      requestId,
      userId,
    });
  });

  // Step 5: Unlock with existing credentials to get MS
  const unlockResult = await withUnlock(unlockCredentials, async (_mkek, masterSecret) => {
    // Ensure audit key is loaded (required for multi-enrollment)
    await ensureAuditKey(_mkek);
    // CRITICAL: Copy the MS before withUnlock zeroizes it
    // The original MS will be zeroized in withUnlock's finally block
    const msCopy = new Uint8Array(masterSecret);
    return msCopy;
  });
  const ms = unlockResult.result;

  // Step 6: Setup new enrollment with existing MS based on new credential type
  // Wrap in try/finally to ensure MS copy is always zeroized (defense-in-depth)
  const method = newCredentialsEncrypted.method;
  try {
    let enrollmentResult;

    if (method === 'passphrase') {
      const passphraseCredentials = newCredentials as { passphrase: string };
      enrollmentResult = await setupPassphrase(userId, passphraseCredentials.passphrase, ms);
    } else if (method === 'passkey-prf') {
      const prfCredentials = newCredentials as { credentialId: string; prfOutput: string; rpId?: string };
      const rpId = prfCredentials.rpId || '';
      enrollmentResult = await setupPasskeyPRF(
        userId,
        base64urlToArrayBuffer(prfCredentials.credentialId),
        base64urlToArrayBuffer(prfCredentials.prfOutput),
        ms,
        rpId
      );
    } else if (method === 'passkey-gate') {
      const gateCredentials = newCredentials as { credentialId: string; rpId?: string };
      const rpId = gateCredentials.rpId || '';
      enrollmentResult = await setupPasskeyGate(userId, base64urlToArrayBuffer(gateCredentials.credentialId), ms, rpId);
    } else {
      const exhaustive: never = method;
      throw new Error(`Unknown enrollment method: ${String(exhaustive)}`);
    }

    if (!enrollmentResult.success) {
      throw new Error(enrollmentResult.error);
    }
  } finally {
    // CRITICAL: Always zeroize MS copy (defense-in-depth)
    ms.fill(0);
  }

  await logOperation({
    op: 'add-enrollment-with-popup',
    kid: '',
    requestId,
    userId,
    details: { method, action: 'add-enrollment-with-popup' },
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

  // Store SessionKEK in IndexedDB so background push JWT issuance survives a
  // worker restart without forcing a re-unlock (see the sessionKEKCache doc
  // comment for the rationale + security tradeoff). Stored as a non-extractable
  // CryptoKey handle; raw bytes are not exportable via the JS API.
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
    sub: 'mailto:admin@allthe.services',
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
 * - TTL = 6000s (100 minutes)
 * - Stagger interval = 60% of TTL = 3600s (60 minutes)
 * - JWT[0]: exp = now + 6000s (T+100min)
 * - JWT[1]: exp = now + 9600s (T+160min, staggered by 60min)
 * - JWT[2]: exp = now + 13200s (T+220min, staggered by 60min)
 *
 * This ensures seamless rotation: when JWT[0] reaches 60% TTL (60min), JWT[1] is already valid.
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
  const TTL = 6000; // 100 minutes in seconds
  const STAGGER_INTERVAL = Math.floor(TTL * 0.6); // 60% of TTL = 3600s (60 minutes)
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
 * Resolve the parameters the top-level popup needs to run a WebAuthn unlock
 * ceremony for a user's passkey enrollment.
 *
 * SECURITY / CORRECTNESS: the authoritative PRF `appSalt` lives ONLY in the
 * worker's IndexedDB (`PasskeyPRFConfigV2.kdf.appSalt`). The iframe used to read
 * `localStorage['kms:appSalt']` and fabricate a random salt when absent — which
 * produced a wrong PRF output and a failed unlock (BUG-008). This RPC is the
 * single source of truth for the salt, the stored credentialId (for
 * `allowCredentials`), and the rpId.
 *
 * Prefers PRF when both PRF and gate enrollments exist.
 */
async function handleGetPasskeyUnlockParams(params?: { userId?: string }): Promise<{
  method: 'passkey-prf' | 'passkey-gate';
  appSalt?: string;
  credentialId?: string;
  rpId?: string;
}> {
  const userId = params?.userId ?? 'default';

  const prfConfig = await getMeta<PasskeyPRFConfigV2>(`enrollment:passkey-prf:v2:${userId}`);
  if (prfConfig) {
    return {
      method: 'passkey-prf',
      appSalt: arrayBufferToBase64url(prfConfig.kdf.appSalt),
      ...(prfConfig.credentialId
        ? { credentialId: arrayBufferToBase64url(prfConfig.credentialId) }
        : {}),
      rpId: prfConfig.rpId,
    };
  }

  const gateConfig = await getMeta<PasskeyGateConfigV2>(`enrollment:passkey-gate:v2:${userId}`);
  if (gateConfig) {
    return {
      method: 'passkey-gate',
      ...(gateConfig.credentialId
        ? { credentialId: arrayBufferToBase64url(gateConfig.credentialId) }
        : {}),
      rpId: gateConfig.rpId,
    };
  }

  throw new Error('No passkey enrollment found for this user');
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
// Signal Messaging Operations (Phase 2)
// ============================================================================

/**
 * Provision a user's Signal identity, signed prekey, and one-time prekeys (one
 * full unlock), and return the public bundle for upload to the directory server.
 * Idempotent on the identity; intended to run once at messaging onboarding.
 */
async function handleSetupMessaging(
  params: {
    credentials: AuthCredentials;
    signedPreKeyId: number;
    oneTimePrekeyCount: number;
  },
  requestId: string
): Promise<{ bundle: PublicPreKeyBundle }> {
  const { credentials, signedPreKeyId, oneTimePrekeyCount } = params;

  const result = await withUnlock(credentials, async (mkek, ms) => {
    await ensureAuditKey(mkek);
    const messagingKEK = await deriveMessagingKEK(ms);
    await generateIdentity(credentials.userId, messagingKEK);
    await generateSignedPrekey(credentials.userId, messagingKEK, signedPreKeyId);
    await generateOneTimePrekeys(credentials.userId, messagingKEK, 1, oneTimePrekeyCount);
    return getPublicBundle(credentials.userId);
  });

  await logOperation({
    op: 'messaging.setup',
    kid: `messaging:${credentials.userId}`,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
    details: { signedPreKeyId, oneTimePrekeyCount },
  });

  return { bundle: result.result };
}

/**
 * Return a user's public prekey bundle. Public bytes only — no unlock required.
 */
async function handleGetMessagingBundle(params: {
  userId: string;
}): Promise<{ bundle: PublicPreKeyBundle }> {
  return { bundle: await getPublicBundle(params.userId) };
}

/**
 * Return the count of unconsumed one-time prekeys (for low-count top-up polling).
 * Public/count read — no unlock required.
 */
async function handleGetPrekeyCount(params: { userId: string }): Promise<{ count: number }> {
  return { count: await countUnconsumedOnetimePrekeys(params.userId) };
}

/**
 * Open a messaging session: one unlock, derive the messaging-scoped KEK, mint a
 * per-session Ed25519 capability token, and cache the session in memory. The
 * master MKEK is NOT retained — only the messaging KEK lives on past this call.
 */
async function handleOpenMessaging(
  params: { credentials: AuthCredentials },
  requestId: string
): Promise<{ sid: string; token: string; exp: number }> {
  const { credentials } = params;
  const sid = crypto.randomUUID();

  const result = await withUnlock(credentials, async (mkek, ms) => {
    await ensureAuditKey(mkek);

    // Messaging must be provisioned first (setupMessaging).
    const identity = await getSignalIdentity(credentials.userId);
    if (!identity) {
      throw new Error('Messaging not set up for this user; call setupMessaging first');
    }

    const messagingKEK = await deriveMessagingKEK(ms);

    // If this device has an account root, derive the self-channel key + address
    // now (the master MKEK is in hand) and cache them memory-only for the
    // session, so self-channel seal/open need no further unlock.
    let selfKey: CryptoKey | undefined;
    let selfScope: string | undefined;
    const accountRoot = await loadAccountRoot(credentials.userId, mkek);
    if (accountRoot) {
      selfKey = await deriveSelfKey(accountRoot);
      selfScope = await deriveSelfScope(accountRoot);
      accountRoot.fill(0);
    }

    const capKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);

    const nowMs = Date.now();
    const iat = Math.floor(nowMs / 1000);
    const exp = iat + Math.floor(MESSAGING_ABSOLUTE_MAX_MS / 1000);
    const token = await mintCapabilityToken(sid, capKeyPair.privateKey, iat, exp);

    const session: MessagingSession = {
      messagingKEK,
      userId: credentials.userId,
      capPubKey: capKeyPair.publicKey,
      absoluteExp: nowMs + MESSAGING_ABSOLUTE_MAX_MS,
      idleExp: nowMs + MESSAGING_IDLE_TIMEOUT_MS,
    };
    if (selfKey && selfScope) {
      session.selfKey = selfKey;
      session.selfScope = selfScope;
    }
    messagingSessions.set(sid, session);

    return { token, exp };
  });

  await logOperation({
    op: 'messaging.open',
    kid: `messaging:${credentials.userId}`,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
    details: { sid },
  });

  return { sid, token: result.result.token, exp: result.result.exp };
}

/**
 * Close a messaging session: drop its keys from memory and audit. Requires a
 * valid capability so a session can only be closed by its holder.
 */
async function handleCloseMessaging(
  params: { sid: string; token: string },
  requestId: string
): Promise<{ closed: true }> {
  const { sid, token } = params;
  const { userId } = await requireCapability(sid, token);
  messagingSessions.delete(sid);

  await logOperation({
    op: 'messaging.close',
    kid: `messaging:${userId}`,
    requestId,
    userId,
    details: { sid },
  });

  return { closed: true };
}

/**
 * Rotate the signed prekey and top up one-time prekeys, returning the refreshed
 * public bundle for re-upload. Runs under a live session (uses the messaging KEK).
 */
async function handleRotatePrekeys(
  params: {
    sid: string;
    token: string;
    signedPreKeyId: number;
    startKeyId: number;
    count: number;
  },
  requestId: string
): Promise<{ bundle: PublicPreKeyBundle }> {
  const { sid, token, signedPreKeyId, startKeyId, count } = params;
  const { messagingKEK, userId } = await requireCapability(sid, token);

  await generateSignedPrekey(userId, messagingKEK, signedPreKeyId);
  await generateOneTimePrekeys(userId, messagingKEK, startKeyId, count);
  const bundle = await getPublicBundle(userId);

  await logOperation({
    op: 'messaging.rotate',
    kid: `messaging:${userId}`,
    requestId,
    userId,
    details: { signedPreKeyId, startKeyId, count },
  });

  return { bundle };
}

// ============================================================================
// Fan-out Bundle Operations (secure-messaging §8/§12) — messaging capability
// ============================================================================

/**
 * Build one opaque fan-out bundle for a logical message: encrypt the plaintext
 * once per recipient device session (establishing a session from `deviceBundle`
 * on the first message to a device), then shuffle + serialize. The caller
 * composes the recipient set (a contact's devices + the account's own other
 * devices); this handler only ciphers and packs — no addressing/routing logic.
 */
async function handleBuildBundle(
  params: {
    sid: string;
    token: string;
    recipients: Array<{ peerName: string; peerDeviceId: number; deviceBundle?: DeviceType }>;
    plaintext: ArrayBuffer;
  },
  requestId: string
): Promise<{ bundle: ArrayBuffer }> {
  const { sid, token, recipients, plaintext } = params;
  const { messagingKEK, userId } = await requireCapability(sid, token);

  const envelopes: Envelope[] = [];
  for (const recipient of recipients) {
    const address = new SignalProtocolAddress(recipient.peerName, recipient.peerDeviceId);
    const peerAddress = address.toString();
    const envelope = await withSessionLock(userId, peerAddress, async () => {
      const store = createSignalProtocolStore(userId, messagingKEK);
      const existing = await store.loadSession(peerAddress);
      if (!existing) {
        if (!recipient.deviceBundle) {
          throw new Error(`No existing session with ${peerAddress}; deviceBundle is required`);
        }
        await new SessionBuilder(store, address).processPreKey(recipient.deviceBundle);
      }
      return encryptEnvelope(new SessionCipher(store, address), plaintext);
    });
    envelopes.push(envelope);
  }

  const bundle = serializeBundle(envelopes);

  await logOperation({
    op: 'messaging.bundle.build',
    kid: `messaging:${userId}`,
    requestId,
    userId,
    details: { recipients: recipients.length },
  });

  return { bundle: u8ToArrayBuffer(bundle) };
}

/**
 * Open a fan-out bundle: trial-decrypt each envelope against each candidate
 * sender-device session, returning the first plaintext that authenticates (or
 * null if none is addressed to this device). A failed trial mutates no persisted
 * state (fork MAC isolation). Each attempt runs under the per-peer session lock.
 */
async function handleOpenBundle(
  params: {
    sid: string;
    token: string;
    senders: Array<{ peerName: string; peerDeviceId: number }>;
    bundle: ArrayBuffer;
  },
  requestId: string
): Promise<{ plaintext: ArrayBuffer | null }> {
  const { sid, token, senders, bundle } = params;
  const { messagingKEK, userId } = await requireCapability(sid, token);

  const envelopes = parseBundle(bundle);
  for (const envelope of envelopes) {
    for (const sender of senders) {
      const address = new SignalProtocolAddress(sender.peerName, sender.peerDeviceId);
      const peerAddress = address.toString();
      const plaintext = await withSessionLock(userId, peerAddress, async () => {
        const store = createSignalProtocolStore(userId, messagingKEK);
        return trialDecryptEnvelope(new SessionCipher(store, address), envelope);
      });
      if (plaintext !== null) {
        await logOperation({
          op: 'messaging.bundle.open',
          kid: `messaging:${userId}`,
          requestId,
          userId,
          details: { sender: peerAddress, envelopes: envelopes.length },
        });
        return { plaintext: u8ToArrayBuffer(plaintext) };
      }
    }
  }

  await logOperation({
    op: 'messaging.bundle.open',
    kid: `messaging:${userId}`,
    requestId,
    userId,
    details: { matched: false, envelopes: envelopes.length },
  });

  return { plaintext: null };
}

// ============================================================================
// Account Root Operations (secure-messaging §18) — full unlock required
// ============================================================================

/**
 * Generate a fresh account root on this (first) device, persist it wrapped under
 * the master MKEK, and return the 12-word recovery phrase for one-time display.
 * Guarded: fails if an account root already exists, so a regenerate can't orphan
 * the account's self-channel state.
 */
async function handleSetupAccountRoot(
  params: { credentials: AuthCredentials },
  requestId: string
): Promise<{ mnemonic: string }> {
  const { credentials } = params;

  const result = await withUnlock(credentials, async (mkek) => {
    await ensureAuditKey(mkek);
    if (await hasAccountRoot(credentials.userId)) {
      throw new Error('Account root already exists for this user');
    }
    const accountRoot = generateAccountRoot();
    const mnemonic = await accountRootToMnemonic(accountRoot);
    await storeAccountRoot(credentials.userId, accountRoot, mkek);
    accountRoot.fill(0);
    return { mnemonic };
  });

  await logOperation({
    op: 'messaging.accountRoot.setup',
    kid: `messaging:${credentials.userId}`,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
  });

  return result.result;
}

/**
 * Restore an account root from its 12-word recovery phrase and persist it
 * (overwrites any existing record — recovery is deliberate).
 */
async function handleImportAccountRootFromMnemonic(
  params: { credentials: AuthCredentials; mnemonic: string },
  requestId: string
): Promise<{ ok: true }> {
  const { credentials, mnemonic } = params;

  const result = await withUnlock(credentials, async (mkek) => {
    await ensureAuditKey(mkek);
    const accountRoot = await mnemonicToAccountRoot(mnemonic);
    await storeAccountRoot(credentials.userId, accountRoot, mkek);
    accountRoot.fill(0);
  });

  await logOperation({
    op: 'messaging.accountRoot.importPhrase',
    kid: `messaging:${credentials.userId}`,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
  });

  return { ok: true };
}

/**
 * Auto-onboard: unseal an account root that an existing device wrapped to THIS
 * device's X25519 identity public key, then persist it. Requires this device's
 * Signal identity to exist (its private key does the unseal).
 */
async function handleImportWrappedAccountRoot(
  params: { credentials: AuthCredentials; wrapped: WrappedAccountRoot },
  requestId: string
): Promise<{ ok: true }> {
  const { credentials, wrapped } = params;

  const result = await withUnlock(credentials, async (mkek, ms) => {
    await ensureAuditKey(mkek);
    const messagingKEK = await deriveMessagingKEK(ms);
    const store = createSignalProtocolStore(credentials.userId, messagingKEK);
    const identity = await store.getIdentityKeyPair();
    if (!identity) {
      throw new Error('Messaging not set up for this user; call setupMessaging first');
    }
    const accountRoot = await unwrapAccountRootFromDevice(
      wrapped,
      new Uint8Array(identity.privKey)
    );
    await storeAccountRoot(credentials.userId, accountRoot, mkek);
    accountRoot.fill(0);
  });

  await logOperation({
    op: 'messaging.accountRoot.importWrapped',
    kid: `messaging:${credentials.userId}`,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
  });

  return { ok: true };
}

/**
 * Seal this device's account root to another device's X25519 identity public
 * key (from the self-keyserver) so it can be carried to that device via
 * main-server, which cannot read it.
 */
async function handleWrapAccountRootForDevice(
  params: { credentials: AuthCredentials; recipientIdentityPubKey: ArrayBuffer },
  requestId: string
): Promise<{ wrapped: WrappedAccountRoot }> {
  const { credentials, recipientIdentityPubKey } = params;

  const result = await withUnlock(credentials, async (mkek) => {
    await ensureAuditKey(mkek);
    const accountRoot = await loadAccountRoot(credentials.userId, mkek);
    if (!accountRoot) {
      throw new Error('No account root on this device');
    }
    const wrapped = await wrapAccountRootToDevice(
      accountRoot,
      new Uint8Array(recipientIdentityPubKey)
    );
    accountRoot.fill(0);
    return { wrapped };
  });

  await logOperation({
    op: 'messaging.accountRoot.wrapForDevice',
    kid: `messaging:${credentials.userId}`,
    requestId,
    userId: credentials.userId,
    unlockTime: result.unlockTime,
    lockTime: result.lockTime,
    duration: result.duration,
  });

  return result.result;
}

/**
 * Whether this device already holds an account root. Presence check only — no
 * unlock, reads no secret bytes.
 */
async function handleHasAccountRoot(params: { userId: string }): Promise<{ present: boolean }> {
  return { present: await hasAccountRoot(params.userId) };
}

// ============================================================================
// Self-channel Operations (secure-messaging §18.2) — messaging capability
// ============================================================================

/** Copy a Uint8Array into a fresh, standalone ArrayBuffer (for RPC responses). */
function u8ToArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
}

/** Small helper: the self-channel key/scope cached on the session, or throw. */
function requireSelfChannel(session: MessagingSession): { selfKey: CryptoKey; selfScope: string } {
  if (!session.selfKey || !session.selfScope) {
    throw new Error('No account root on this device; set up or import one first');
  }
  return { selfKey: session.selfKey, selfScope: session.selfScope };
}

/**
 * Return the account's self-channel address `selfScope` (opaque, non-secret).
 * The transport forms the scope key `self:<selfScope>`.
 */
async function handleGetSelfScope(params: {
  sid: string;
  token: string;
}): Promise<{ selfScope: string }> {
  const session = await requireCapability(params.sid, params.token);
  return { selfScope: requireSelfChannel(session).selfScope };
}

/**
 * Encrypt a self-channel payload (a contact-add announcement or a snapshot) under
 * the account's symmetric self-key. `context` domain-separates payload kinds.
 */
async function handleSealSelfMessage(
  params: { sid: string; token: string; payload: ArrayBuffer; context: string },
  requestId: string
): Promise<{ ciphertext: ArrayBuffer }> {
  const session = await requireCapability(params.sid, params.token);
  const { selfKey } = requireSelfChannel(session);
  const out = await encryptSelfMessage(selfKey, params.payload, params.context);

  await logOperation({
    op: 'messaging.self.seal',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { context: params.context, bytes: params.payload.byteLength },
  });

  return { ciphertext: u8ToArrayBuffer(out) };
}

/**
 * Decrypt a self-channel payload produced by {@link handleSealSelfMessage}.
 * `context` must match the value used at seal time.
 */
async function handleOpenSelfMessage(
  params: { sid: string; token: string; ciphertext: ArrayBuffer; context: string },
  requestId: string
): Promise<{ payload: ArrayBuffer }> {
  const session = await requireCapability(params.sid, params.token);
  const { selfKey } = requireSelfChannel(session);
  const out = await decryptSelfMessage(selfKey, params.ciphertext, params.context);

  await logOperation({
    op: 'messaging.self.open',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { context: params.context },
  });

  return { payload: u8ToArrayBuffer(out) };
}

// ============================================================================
// Pairing / Contact Operations (secure-messaging §5/§6) — messaging capability
// ============================================================================

/** Context labels domain-separating the two pairing-secret-keyed AEAD payloads. */
const DEVICE_EXCHANGE_CONTEXT = 'device-exchange';
const CONTACT_ANNOUNCEMENT_CONTEXT = 'contact-announcement';

/** Serialize a self-channel contact announcement ({peerUserId, secret}). */
function encodeContactAnnouncement(peerUserId: string, secret: Uint8Array): Uint8Array {
  const obj = { peerUserId, secret: arrayBufferToBase64url(u8ToArrayBuffer(secret)) };
  return new TextEncoder().encode(JSON.stringify(obj));
}

function decodeContactAnnouncement(bytes: Uint8Array): { peerUserId: string; secret: Uint8Array } {
  const obj = JSON.parse(new TextDecoder().decode(bytes)) as { peerUserId?: unknown; secret?: unknown };
  if (typeof obj.peerUserId !== 'string' || typeof obj.secret !== 'string') {
    throw new Error('Malformed contact announcement');
  }
  return { peerUserId: obj.peerUserId, secret: new Uint8Array(base64urlToArrayBuffer(obj.secret)) };
}

/** Load a contact's pairing secret or throw a clear error. */
async function requireContactSecret(
  userId: string,
  peerUserId: string,
  messagingKEK: CryptoKey
): Promise<Uint8Array> {
  const secret = await loadContactSecret(userId, peerUserId, messagingKEK);
  if (!secret) {
    throw new Error(`No pairing secret for contact ${peerUserId}`);
  }
  return secret;
}

/**
 * Store a contact's pairing secret (from a QR / word-pair, supplied by the PWA at
 * pairing time) and return the derived pairID. Overwrites any existing record.
 */
async function handleSetContactSecret(
  params: { sid: string; token: string; peerUserId: string; secret: ArrayBuffer },
  requestId: string
): Promise<{ pairID: string }> {
  const session = await requireCapability(params.sid, params.token);
  const secret = new Uint8Array(params.secret);
  await storeContactSecret(session.userId, params.peerUserId, secret, session.messagingKEK);
  const pairID = await derivePairID(secret, session.userId, params.peerUserId);

  await logOperation({
    op: 'messaging.contact.set',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { peer: params.peerUserId },
  });

  return { pairID };
}

/** Derive the pairID for an existing contact (to subscribe to its pair-topic). */
async function handleGetContactPairID(params: {
  sid: string;
  token: string;
  peerUserId: string;
}): Promise<{ pairID: string }> {
  const session = await requireCapability(params.sid, params.token);
  const secret = await requireContactSecret(session.userId, params.peerUserId, session.messagingKEK);
  return { pairID: await derivePairID(secret, session.userId, params.peerUserId) };
}

/** List every contact's {peerUserId, pairID} — for subscribing all pair-topics on connect. */
async function handleListContacts(params: {
  sid: string;
  token: string;
}): Promise<{ contacts: Array<{ peerUserId: string; pairID: string }> }> {
  const session = await requireCapability(params.sid, params.token);
  const peers = await listContactPeers(session.userId);
  const contacts: Array<{ peerUserId: string; pairID: string }> = [];
  for (const peerUserId of peers) {
    const secret = await loadContactSecret(session.userId, peerUserId, session.messagingKEK);
    if (secret) {
      contacts.push({ peerUserId, pairID: await derivePairID(secret, session.userId, peerUserId) });
    }
  }
  return { contacts };
}

/**
 * AEAD-seal a device-key-exchange payload (this account's device bundle) under
 * the contact's pairing-secret-derived key, so the peer can authenticate + read
 * it over the pair-topic (§6).
 */
async function handleSealDeviceExchange(
  params: { sid: string; token: string; peerUserId: string; payload: ArrayBuffer },
  requestId: string
): Promise<{ ciphertext: ArrayBuffer }> {
  const session = await requireCapability(params.sid, params.token);
  const secret = await requireContactSecret(session.userId, params.peerUserId, session.messagingKEK);
  const key = await deriveExchangeKey(secret);
  const out = await encryptSelfMessage(key, params.payload, DEVICE_EXCHANGE_CONTEXT);

  await logOperation({
    op: 'messaging.contact.sealExchange',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { peer: params.peerUserId },
  });

  return { ciphertext: u8ToArrayBuffer(out) };
}

/** Open a device-key-exchange payload a contact sealed for us over the pair-topic. */
async function handleOpenDeviceExchange(
  params: { sid: string; token: string; peerUserId: string; ciphertext: ArrayBuffer },
  requestId: string
): Promise<{ payload: ArrayBuffer }> {
  const session = await requireCapability(params.sid, params.token);
  const secret = await requireContactSecret(session.userId, params.peerUserId, session.messagingKEK);
  const key = await deriveExchangeKey(secret);
  const out = await decryptSelfMessage(key, params.ciphertext, DEVICE_EXCHANGE_CONTEXT);

  await logOperation({
    op: 'messaging.contact.openExchange',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { peer: params.peerUserId },
  });

  return { payload: u8ToArrayBuffer(out) };
}

/**
 * Seal a contact for propagation to the account's OTHER devices over the
 * self-channel: read the stored pairing secret and seal {peerUserId, secret}
 * under the account self-key. The PWA publishes the opaque result to the
 * self-channel; only this account's enclaves can open it.
 */
async function handleSealContactAnnouncement(
  params: { sid: string; token: string; peerUserId: string },
  requestId: string
): Promise<{ ciphertext: ArrayBuffer }> {
  const session = await requireCapability(params.sid, params.token);
  const { selfKey } = requireSelfChannel(session);
  const secret = await requireContactSecret(session.userId, params.peerUserId, session.messagingKEK);
  const payload = encodeContactAnnouncement(params.peerUserId, secret);
  const out = await encryptSelfMessage(selfKey, payload, CONTACT_ANNOUNCEMENT_CONTEXT);

  await logOperation({
    op: 'messaging.contact.announce',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { peer: params.peerUserId },
  });

  return { ciphertext: u8ToArrayBuffer(out) };
}

/**
 * Apply a self-channel contact announcement from another of the account's
 * devices: open it under the self-key, store the pairing secret locally, and
 * return {peerUserId, pairID} so the PWA can subscribe to the new pair-topic.
 */
async function handleApplyContactAnnouncement(
  params: { sid: string; token: string; ciphertext: ArrayBuffer },
  requestId: string
): Promise<{ peerUserId: string; pairID: string }> {
  const session = await requireCapability(params.sid, params.token);
  const { selfKey } = requireSelfChannel(session);
  const bytes = await decryptSelfMessage(selfKey, params.ciphertext, CONTACT_ANNOUNCEMENT_CONTEXT);
  const { peerUserId, secret } = decodeContactAnnouncement(bytes);
  await storeContactSecret(session.userId, peerUserId, secret, session.messagingKEK);
  const pairID = await derivePairID(secret, session.userId, peerUserId);

  await logOperation({
    op: 'messaging.contact.applyAnnounce',
    kid: `messaging:${session.userId}`,
    requestId,
    userId: session.userId,
    details: { peer: peerUserId },
  });

  return { peerUserId, pairID };
}

// ============================================================================
// Management Operations
// ============================================================================

/**
 * Reset KMS (delete all data). USE WITH CAUTION.
 */
async function handleResetKMS(): Promise<{ success: true }> {
  // Wipe all user data by CLEARING every object store on the open connection, rather than
  // deleting the whole database.
  //
  // Why not indexedDB.deleteDatabase('kms-v2')? It requires exclusive access: if ANY other
  // context still holds kms-v2 open — a second app tab, or the fullSetup popup's own enclave
  // worker — the delete fires `onblocked` and never completes. The previous implementation
  // awaited that delete with no `onblocked` handler, so the reset hung forever and left the
  // database wedged; every subsequent isSetup/fullSetup `open()` then queued behind the stuck
  // delete and also hung. In the app that surfaced as a dead setup ceremony ("No active popup
  // window reference", because the worker never emitted worker:setup-with-popup). Clearing the
  // stores runs in an ordinary readwrite transaction that cannot be blocked by other
  // connections, wiping all data while keeping the current v4 schema.
  await clearAllStores();

  // Reset in-memory audit state (seqCounter, auditKeyPair, etc.) so the next operation starts
  // a fresh audit chain. We don't log the reset itself: the audit chain has just been wiped and
  // no audit key exists yet (it requires the MKEK from credentials); the reset is implicitly
  // recorded when the next operation creates a new chain.
  resetAuditLogger();

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
