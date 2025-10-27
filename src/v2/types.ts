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
 * Wrapped keys and metadata
 *
 * Application keys (e.g. VAPID signing keys) are wrapped under the
 * master key encryption key (MKEK) and stored with associated
 * metadata. The `WrappedKey` type captures both the ciphertext and
 * the required associated data for safe unwrapping. Additional
 * metadata such as the algorithm and purpose are recorded for audit
 * and to aid proper key usage.
 */

export interface WrappedKey {
  kid: string;
  kmsVersion: number;
  wrappedKey: ArrayBuffer;
  iv: ArrayBuffer;
  aad: ArrayBuffer;
  publicKeyRaw?: ArrayBuffer;
  alg: string;
  purpose: string;
  createdAt: number;
  lastUsedAt?: number;
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

export interface RPCRequest {
  id: string;
  method: string;
  params: any;
}

export interface RPCResponse {
  id: string;
  result?: any;
  error?: string | { code: string; message: string };
}

// Example enumerated method names. Implementations may extend this list.
export type RPCMethod =
  | 'setupPassphrase'
  | 'setupPasskey'
  | 'unlockWithPassphrase'
  | 'unlockWithPasskey'
  | 'generateVAPID'
  | 'signJWT'
  | 'getPublicKey'
  | 'getAuditLog'
  | string;

/* ------------------------------------------------------------------
 * VAPID lease and quota types (MVP)
 *
 * The VAPID lease model grants a client the right to mint short
 * lived JWTs. Quotas constrain the issuance rate to prevent abuse.
 */

export interface LeaseRecord {
  leaseId: string;
  userId: string;
  subs: Array<{
    url: string;
    aud: string;
    eid: string;
  }>;
  ttlHours: number;
  createdAt: number;
  exp: number;
  quotas: QuotaState;
  // SessionKEK-wrapped VAPID key (allows JWT signing without user credentials)
  wrappedLeaseKey: ArrayBuffer; // VAPID private key wrapped with SessionKEK
  wrappedLeaseKeyIV: ArrayBuffer; // IV used for AES-GCM encryption of wrappedLeaseKey
  leaseSalt: ArrayBuffer; // Random salt used to derive SessionKEK from MS
  kid: string; // Key ID (JWK thumbprint) of the VAPID keypair
  // LAK (Lease Audit Key) delegation certificate (authorizes LAK to sign audit entries)
  lakDelegationCert: AuditDelegationCert;
}

export interface QuotaState {
  tokensPerHour: number;
  sendsPerMinute: number;
  burstSends: number;
  sendsPerMinutePerEid: number;
}

export interface LeaseVerificationResult {
  leaseId: string;
  valid: boolean;
  reason?: string;
  kid: string;
}

export interface VAPIDPayload {
  aud: string;
  exp: number;
  sub: string;
  jti: string;
  [claim: string]: any;
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
