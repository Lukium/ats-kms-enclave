/**
 * KMS V2 Type Definitions
 *
 * This file centralises all TypeScript interfaces and type aliases used
 * throughout the KMS v2 implementation. Keeping a single source of truth
 * for types makes it easy to audit the system for correctness and ensures
 * modules remain loosely coupled via well‑defined interfaces. Where
 * possible, structures mirror the schemas described in the `TARGET.md`
 * document and accompanying design specifications.
 */

/* ------------------------------------------------------------------
 * Authentication credentials
 *
 * Users may authenticate to the KMS using one of three methods: a
 * passphrase, a WebAuthn PRF output or a gate‑only passkey. The
 * discriminated union defined below captures these possibilities and
 * ensures callers can pattern match on the `method` property.
 */

/**
 * Authentication credentials for KMS operations.
 *
 * Discriminated union supporting three authentication methods:
 * - **Passphrase**: User-provided password (PBKDF2-derived KEK)
 * - **Passkey PRF**: WebAuthn PRF extension output (deterministic key derivation)
 * - **Passkey Gate**: WebAuthn credential as authentication gate (random MS)
 *
 * @example
 * ```typescript
 * // Passphrase authentication
 * const creds: AuthCredentials = {
 *   method: 'passphrase',
 *   passphrase: 'my-secure-password',
 *   userId: 'user@example.com',
 * };
 *
 * // Passkey PRF authentication
 * const creds: AuthCredentials = {
 *   method: 'passkey-prf',
 *   prfOutput: prfOutputBuffer,
 *   userId: 'user@example.com',
 * };
 *
 * // Passkey Gate authentication
 * const creds: AuthCredentials = {
 *   method: 'passkey-gate',
 *   userId: 'user@example.com',
 * };
 * ```
 */
export type AuthCredentials =
  | { method: 'passphrase'; passphrase: string; userId: string }
  | { method: 'passkey-prf'; prfOutput: ArrayBuffer; userId: string }
  | { method: 'passkey-gate'; userId: string };

/* ------------------------------------------------------------------
 * Configuration schemas
 *
 * Each enrolled credential stores a configuration object under a
 * deterministic key in the database. The properties mirror the fields
 * described in the design documents, including algorithm versions,
 * KDF parameters and encrypted master secret material. Where arrays
 * appear, the type is ArrayBuffer to emphasise binary data. Fields
 * such as `kmsVersion` and `algVersion` ensure forward and backwards
 * compatibility during migrations.
 */

export interface PassphraseConfigV2 {
  kmsVersion: 2;
  algVersion: number;
  method: 'passphrase';
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    iterations: number;
    salt: ArrayBuffer;
    lastCalibratedAt: number;
    platformHash: string;
  };
  kcv: ArrayBuffer;
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: number;
  createdAt: number;
  updatedAt: number;
}

export interface PasskeyPRFConfigV2 {
  kmsVersion: 2;
  algVersion: number;
  method: 'passkey-prf';
  credentialId: ArrayBuffer;
  rpId: string;
  kdf: {
    algorithm: 'HKDF-SHA256';
    appSalt: ArrayBuffer;
    hkdfSalt: ArrayBuffer;
    info: string;
  };
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: number;
  createdAt: number;
  updatedAt: number;
}

export interface PasskeyGateConfigV2 {
  kmsVersion: 2;
  algVersion: number;
  method: 'passkey-gate';
  credentialId: ArrayBuffer;
  rpId: string;
  pepperWrapped: ArrayBuffer;
  // no PRF output; gate method relies on pepper + passphrase
  encryptedMS: ArrayBuffer;
  msIV: ArrayBuffer;
  msAAD: ArrayBuffer;
  msVersion: number;
  createdAt: number;
  updatedAt: number;
}

export type EnrollmentConfigV2 =
  | PassphraseConfigV2
  | PasskeyPRFConfigV2
  | PasskeyGateConfigV2;

/* ------------------------------------------------------------------
 * Push Notification Subscription
 *
 * Stores the push subscription data returned by PushManager.subscribe().
 * This is stored with the VAPID key record, as subscriptions are tied
 * to the VAPID key lifecycle (regenerating VAPID key invalidates subs).
 */

/**
 * Web Push subscription data stored with VAPID key.
 *
 * Represents a push notification subscription returned by `PushManager.subscribe()`.
 * The subscription establishes a 1:1 relationship with the VAPID key - each VAPID
 * key can have exactly one subscription. Stored on the `WrappedKey.subscription` field.
 *
 * **Storage:** Stored with VAPID key, NOT in lease records. All leases for a VAPID
 * key use the same subscription (single source of truth).
 *
 * **Lifecycle:** Lost when VAPID key is regenerated. Must call `setPushSubscription()`
 * again after `regenerateVAPID()`.
 *
 * **Security:** Endpoints are validated against a whitelist of known push services:
 * FCM, APNs, Mozilla Push, Windows Push Notification Services.
 *
 * @example
 * ```typescript
 * // Browser push subscription converted to StoredPushSubscription
 * const registration = await navigator.serviceWorker.ready;
 * const pushSub = await registration.pushManager.subscribe({
 *   userVisibleOnly: true,
 *   applicationServerKey: vapidPublicKey,
 * });
 *
 * const storedSub: StoredPushSubscription = {
 *   endpoint: pushSub.endpoint,
 *   expirationTime: pushSub.expirationTime,
 *   keys: {
 *     p256dh: arrayBufferToBase64url(pushSub.getKey('p256dh')),
 *     auth: arrayBufferToBase64url(pushSub.getKey('auth')),
 *   },
 *   eid: 'my-laptop-chrome',
 *   createdAt: Date.now(),
 * };
 * ```
 */
export interface StoredPushSubscription {
  /** Push service endpoint URL (must be HTTPS and whitelisted: FCM/APNs/Mozilla/WNS) */
  endpoint: string;
  /** When subscription expires in milliseconds (null = no expiry) */
  expirationTime: number | null;
  /** Client encryption keys for push message encryption */
  keys: {
    /** Client public key (base64url-encoded, 65 bytes decoded) */
    p256dh: string;
    /** Authentication secret (base64url-encoded, 16 bytes decoded) */
    auth: string;
  };
  /** Endpoint ID - user-defined label for this device/browser (e.g., "laptop-chrome") */
  eid: string;
  /** Creation timestamp in milliseconds */
  createdAt: number;
}

/* ------------------------------------------------------------------
 * Wrapped keys and metadata
 *
 * Application keys (e.g. VAPID signing keys) are wrapped under the
 * master key encryption key (MKEK) and stored with associated
 * metadata. The `WrappedKey` type captures both the ciphertext and
 * the required associated data for safe unwrapping. Additional
 * metadata such as the algorithm and purpose are recorded for audit
 * and to aid proper key usage.
 */

/**
 * Wrapped application key stored in IndexedDB.
 *
 * Application keys (e.g., VAPID signing keys) are encrypted with the Master Key
 * Encryption Key (MKEK) derived from the Master Secret. The wrapped key is stored
 * with metadata and optional push subscription data.
 *
 * **Encryption:**
 * - Algorithm: AES-GCM
 * - KEK: MKEK (derived from Master Secret via HKDF)
 * - AAD: Binds metadata to ciphertext (prevents swapping attacks)
 *
 * **Storage:**
 * - Location: IndexedDB `wrappedKeys` object store
 * - Key path: `kid` (Key ID - JWK thumbprint)
 * - Indexed by: `purpose` for efficient queries
 *
 * **Push Subscription:**
 * - VAPID keys can have an optional `subscription` field
 * - Establishes 1:1 relationship between VAPID key and push subscription
 * - Lost when VAPID key is regenerated
 *
 * @example
 * ```typescript
 * const wrappedVapidKey: WrappedKey = {
 *   kid: 'vapid-key-123',
 *   kmsVersion: 2,
 *   wrappedKey: ArrayBuffer, // Encrypted VAPID private key
 *   iv: ArrayBuffer,         // AES-GCM IV
 *   aad: ArrayBuffer,        // Additional Authenticated Data
 *   publicKeyRaw: ArrayBuffer, // P-256 public key (65 bytes, uncompressed)
 *   alg: 'ES256',
 *   purpose: 'vapid',
 *   createdAt: Date.now(),
 *   lastUsedAt: Date.now(),
 *   subscription: { ... },   // Optional push subscription
 * };
 * ```
 */
export interface WrappedKey {
  /** Key ID (JWK thumbprint) - unique identifier */
  kid: string;
  /** KMS version (currently 2) */
  kmsVersion: number;
  /** Encrypted private key (AES-GCM ciphertext) */
  wrappedKey: ArrayBuffer;
  /** Initialization vector for AES-GCM encryption */
  iv: ArrayBuffer;
  /** Additional Authenticated Data (binds metadata to ciphertext) */
  aad: ArrayBuffer;
  /** Public key in raw format (optional, for asymmetric keys like VAPID) */
  publicKeyRaw?: ArrayBuffer;
  /** Algorithm (e.g., "ES256" for ECDSA P-256, "Ed25519" for audit keys) */
  alg: string;
  /** Key purpose (e.g., "vapid", "audit-user", "audit-lease") */
  purpose: string;
  /** Creation timestamp in milliseconds */
  createdAt: number;
  /** Last usage timestamp in milliseconds (optional) */
  lastUsedAt?: number;
  /** Optional push subscription for VAPID keys (1:1 relationship) */
  subscription?: StoredPushSubscription;
}

export interface KeyMetadata {
  publicKeyRaw?: ArrayBuffer;
  alg: string;
  purpose: string;
}

/* ------------------------------------------------------------------
 * Audit types
 *
 * The audit log records every sensitive operation performed by the
 * KMS worker. Each entry in the chain is signed and hashes the
 * previous entry to provide tamper evidence. Verification results
 * communicate how many entries have been verified and collate
 * errors encountered during the process.
 */

export interface AuditOperation {
  op: string;
  kid: string;
  requestId: string;
  userId: string;
  origin?: string;
  leaseId?: string; // If present, audit entry will be signed with LAK instead of UAK
  details?: Record<string, unknown>;
  unlockTime?: number;
  lockTime?: number;
  duration?: number;
}

/**
 * Audit delegation certificate
 *
 * Authorizes a signing key (LAK or KIAK) to sign audit entries.
 * Signed by UAK to create chain of trust back to user's Master Secret.
 */
export interface AuditDelegationCert {
  type: 'audit-delegation';
  version: 1;
  signerKind: 'LAK' | 'KIAK';
  leaseId?: string; // Present for LAK, absent for KIAK
  instanceId?: string; // Present for KIAK, absent for LAK
  delegatePub: string; // base64url Ed25519 public key
  scope: string[]; // e.g., ["vapid.issue", "lease.expire"] or ["system.*"]
  notBefore: number; // Unix timestamp (ms)
  notAfter: number | null; // Unix timestamp (ms), null = no expiration
  codeHash: string; // KMS code hash at delegation time
  manifestHash: string; // KMS manifest hash
  kmsVersion: string; // e.g., "v2.0.0"
  sig: string; // base64url signature by UAK
}

/**
 * V2 audit entry with delegation support
 *
 * Entries can be signed by three types of keys:
 * - UAK: User Audit Key (user-authenticated operations)
 * - LAK: Lease Audit Key (lease-scoped background operations)
 * - KIAK: KMS Instance Audit Key (system events)
 */
export interface AuditEntryV2 {
  kmsVersion: 2;
  seqNum: number;
  timestamp: number;
  op: string;
  kid: string;
  requestId: string;
  userId: string;
  origin?: string;
  leaseId?: string; // Present if operation is lease-related
  unlockTime?: number;
  lockTime?: number;
  duration?: number;
  details?: Record<string, unknown>;
  previousHash: string;
  chainHash: string;

  // Delegation support
  signer: 'UAK' | 'LAK' | 'KIAK';
  signerId: string; // base64url(SHA-256(publicKey))
  cert?: AuditDelegationCert; // Present for LAK entries, optional for others

  // Signature
  sig: string; // base64url Ed25519 signature over chainHash
  sigNew?: string; // For rotation entries: second signature from new key
}

export interface VerificationResult {
  valid: boolean;
  verified: number;
  errors: string[];
}

/* ------------------------------------------------------------------
 * Unlock operation result
 *
 * Each operation executed under an unlocked context returns its
 * result along with timing information. The timings help with
 * auditing and debugging by recording precisely when the context
 * was opened and closed.
 */

export interface UnlockOperationResult<T> {
  result: T;
  unlockTime: number;
  lockTime: number;
  duration: number;
}

/* ------------------------------------------------------------------
 * RPC Request/Response types
 *
 * The worker orchestrator exposes a message based API. Requests
 * include a method name and parameters; responses include either
 * a result or an error string. Additional fields such as `id` and
 * `kmsVersion` facilitate correlation on the client side.
 */

export interface RPCRequest<TParams = unknown> {
  id: string;
  method: string;
  params: TParams;
}

export interface RPCResponse<TResult = unknown> {
  id: string;
  result?: TResult;
  error?: string | { code: string; message: string };
}

// Example enumerated method names. Implementations may extend this list.
export type RPCMethod =
  | 'setupPassphrase'
  | 'setupPasskey'
  | 'setupPasskeyPRF'
  | 'setupPasskeyGate'
  // Legacy methods removed: generateSetupTransportKey, setupWithEncryptedCredentials
  | 'setupWithPopup'
  | 'unlockWithPassphrase'
  | 'unlockWithPasskey'
  | 'addEnrollment'
  | 'removeEnrollment'
  | 'getEnrollments'
  | 'generateVAPID'
  | 'regenerateVAPID'
  | 'signJWT'
  | 'getPublicKey'
  | 'getVAPIDKid'
  | 'createLease'
  | 'extendLeases'
  | 'issueVAPIDJWT'
  | 'issueVAPIDJWTs'
  | 'getUserLeases'
  | 'verifyLease'
  | 'getAuditLog'
  | 'verifyAuditChain'
  | 'getAuditPublicKey'
  | 'isSetup'
  | 'resetKMS'
  | 'setPushSubscription'
  | 'removePushSubscription'
  | 'getPushSubscription';

/* ------------------------------------------------------------------
 * VAPID lease and quota types (MVP)
 *
 * The VAPID lease model grants a client the right to mint short
 * lived JWTs. Quotas constrain the issuance rate to prevent abuse.
 */

/**
 * VAPID lease record for credential-free JWT issuance.
 *
 * A lease allows issuing VAPID JWTs without re-authentication by wrapping the VAPID
 * private key with a session-specific KEK (SessionKEK) derived from the Master Secret.
 * The wrapped key is stored in worker memory, enabling JWT signing until lease expiration.
 *
 * **Security Model:**
 * - SessionKEK derived from: MS + random leaseSalt via HKDF
 * - VAPID private key wrapped with SessionKEK (not MKEK)
 * - Wrapped key stored in memory only (not IndexedDB)
 * - Lease invalidated when VAPID key regenerated (kid mismatch)
 *
 * **Push Subscription:**
 * - Subscription data is NOT stored in lease
 * - Worker reads subscription from VAPID key's `subscription` field
 * - All leases for a VAPID key share the same subscription
 *
 * **Quotas:**
 * - 100 tokens per hour (global)
 * - 10 sends per minute (burst: 20)
 * - 5 sends per minute per endpoint ID
 *
 * @example
 * ```typescript
 * // Lease stored in worker memory after createLease()
 * const lease: LeaseRecord = {
 *   leaseId: 'lease-abc-123',
 *   userId: 'user@example.com',
 *   ttlHours: 12,
 *   createdAt: Date.now(),
 *   exp: Date.now() + (12 * 60 * 60 * 1000),
 *   quotas: {
 *     tokensPerHour: 100,
 *     sendsPerMinute: 10,
 *     burstSends: 20,
 *     sendsPerMinutePerEid: 5,
 *   },
 *   wrappedLeaseKey: ArrayBuffer, // VAPID private key wrapped with SessionKEK
 *   wrappedLeaseKeyIV: ArrayBuffer,
 *   leaseSalt: ArrayBuffer, // Used to derive SessionKEK
 *   kid: 'vapid-key-id',
 *   lakDelegationCert: { ... }, // LAK authorization
 * };
 * ```
 */
export interface LeaseRecord {
  /** Unique lease identifier (format: "lease-{uuid}") */
  leaseId: string;
  /** User ID associated with this lease */
  userId: string;
  // Note: Push subscription data is stored with VAPID key, not in lease
  // Worker reads subscription from VAPID key when creating lease/issuing JWTs
  /** Lease time-to-live in hours (max 720 hours / 30 days) */
  ttlHours: number;
  /** Creation timestamp in milliseconds */
  createdAt: number;
  /** Expiration timestamp in milliseconds */
  exp: number;
  /** Whether the lease can be auto-extended without re-authentication (default: false for backward compatibility) */
  autoExtend?: boolean;
  /** Rate limit quotas for this lease */
  quotas: QuotaState;
  // SessionKEK-wrapped VAPID key (allows JWT signing without user credentials)
  /** VAPID private key wrapped with SessionKEK (AES-GCM) */
  wrappedLeaseKey: ArrayBuffer;
  /** IV used for AES-GCM encryption of wrappedLeaseKey */
  wrappedLeaseKeyIV: ArrayBuffer;
  /** Random salt used to derive SessionKEK from Master Secret via HKDF */
  leaseSalt: ArrayBuffer;
  /** Key ID (JWK thumbprint) of the VAPID keypair */
  kid: string;
  // LAK (Lease Audit Key) delegation certificate (authorizes LAK to sign audit entries)
  /** LAK delegation certificate authorizing this lease to sign audit entries */
  lakDelegationCert: AuditDelegationCert;
}

/**
 * Rate limit quotas enforced by the KMS worker for lease operations.
 *
 * Quotas prevent abuse by limiting JWT issuance rates. Enforced in worker
 * memory using token bucket and sliding window algorithms.
 *
 * **Default Limits:**
 * - `tokensPerHour`: 100 (global rate limit)
 * - `sendsPerMinute`: 10 (burst: 20)
 * - `sendsPerMinutePerEid`: 5 (per-endpoint limit)
 */
export interface QuotaState {
  /** Maximum tokens that can be issued per hour (global limit) */
  tokensPerHour: number;
  /** Maximum push sends per minute (sustained rate) */
  sendsPerMinute: number;
  /** Maximum burst sends (allows short bursts above sustained rate) */
  burstSends: number;
  /** Maximum sends per minute per endpoint ID (prevents single endpoint abuse) */
  sendsPerMinutePerEid: number;
}

/**
 * Result of lease verification check.
 *
 * Returned by `verifyLease()` to indicate whether a lease is valid.
 * A lease is valid if:
 * 1. It exists in storage
 * 2. It has not expired (`exp > Date.now()`)
 * 3. Its `kid` matches the current VAPID key
 *
 * @example
 * ```typescript
 * const result: LeaseVerificationResult = {
 *   leaseId: 'lease-abc-123',
 *   valid: false,
 *   reason: 'expired',
 *   kid: 'old-vapid-key-id',
 * };
 *
 * // Possible reasons: 'expired', 'wrong-key', 'not-found'
 * ```
 */
export interface LeaseVerificationResult {
  /** Lease ID being verified (echoed from input) */
  leaseId: string;
  /** Whether the lease is valid */
  valid: boolean;
  /** Reason for invalidity if `valid: false` ("expired" | "wrong-key" | "not-found") */
  reason?: string;
  /** Key ID from the lease */
  kid: string;
}

/**
 * VAPID JWT payload structure (RFC 8292 compliant).
 *
 * The JWT payload for VAPID (Voluntary Application Server Identification)
 * authentication with push services. Conforms to RFC 8292 requirements.
 *
 * **Required Claims:**
 * - `aud`: Push service origin (e.g., "https://fcm.googleapis.com")
 * - `exp`: Expiration timestamp (max 24 hours from issuance)
 * - `sub`: Subject (typically "mailto:admin@example.com" or origin URL)
 * - `jti`: JWT ID (unique identifier to prevent replay)
 *
 * **Additional claims** can be included via index signature.
 *
 * @example
 * ```typescript
 * const payload: VAPIDPayload = {
 *   aud: 'https://fcm.googleapis.com',
 *   exp: Date.now() + (15 * 60 * 1000), // 15 minutes
 *   sub: 'mailto:admin@ats.run',
 *   jti: crypto.randomUUID(),
 * };
 * ```
 */
export interface VAPIDPayload {
  /** Audience - push service origin (e.g., "https://fcm.googleapis.com") */
  aud: string;
  /** Expiration time in seconds since epoch */
  exp: number;
  /** Subject - typically "mailto:admin@example.com" or origin URL */
  sub: string;
  /** JWT ID - unique identifier for this token */
  jti: string;
  /** Additional custom claims */
  [claim: string]: unknown;
}

/* ------------------------------------------------------------------
 * AAD configuration types
 *
 * Additional Authenticated Data (AAD) for AES-GCM operations binds
 * metadata to ciphertext to prevent swapping or replay attacks.
 */

export interface MSAADConfig {
  kmsVersion: number;
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  algVersion: number;
  purpose: string;
  credentialId?: ArrayBuffer;
}

export interface KeyWrapAADConfig {
  kmsVersion: number;
  kid: string;
  alg: string;
  purpose: string;
  createdAt: number;
  keyType: string;
}

/* ------------------------------------------------------------------
 * Unlock result type
 *
 * Returned by unlock functions to indicate success or failure.
 * On success, returns decrypted Master Secret bytes.
 */

export type UnlockResult =
  | { success: true; ms: Uint8Array }
  | { success: false; error: string };
