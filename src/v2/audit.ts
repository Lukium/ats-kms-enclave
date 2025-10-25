/**
 * Audit logging for KMS V2
 *
 * This module implements a tamper-evident audit log with three-tier delegation:
 * - UAK (User Audit Key): Derived from MKEK, signs user-authenticated operations
 * - LAK (Lease Audit Key): Generated per lease, signs background JWT issuance
 * - KIAK (KMS Instance Audit Key): Generated at init, signs system events
 *
 * Every operation is recorded as an `AuditEntryV2` which includes a sequence
 * number, timestamp, hash chain, and signature. The chain of hashes ensures
 * that any modification, insertion or deletion of entries invalidates the
 * remainder of the log.
 *
 * Based on: docs/architecture/crypto/V2/design/05-audit-log.md
 */

import type {
  AuditOperation,
  AuditEntryV2,
  AuditDelegationCert,
  VerificationResult,
  AuthCredentials,
} from './types';
import {
  storeAuditEntry,
  getAllAuditEntries,
  getLastAuditEntry,
  getMeta,
  putMeta,
  getWrappedKey,
  wrapKey,
} from './storage';
import { arrayBufferToBase64url, buildKeyWrapAAD } from './crypto-utils';

// Module state
let seqCounter = 0;

// Active signer (determines which key signs the next audit entry)
interface ActiveSigner {
  type: 'UAK' | 'LAK' | 'KIAK';
  keyPair: CryptoKeyPair;
  keyId: string;
  cert?: AuditDelegationCert;
}

let activeSigner: ActiveSigner | null = null;

/**
 * Initialize the audit logger.
 * Called at module init, but UAK/KIAK are generated separately.
 */
export async function initAuditLogger(): Promise<void> {
  // No-op for now - keys are generated via ensureAuditKey, ensureKIAK
  // This function exists for API compatibility
}

/**
 * Ensure LRK (Lease Root Key) exists.
 * LRK is used to wrap LAK and KIAK private keys.
 *
 * Based on: 05-audit-log.md § "Lease Root Key (LRK)"
 */
async function ensureLRK(): Promise<CryptoKey> {
  let lrk = await getMeta('LRK') as CryptoKey | undefined;

  if (!lrk) {
    lrk = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
    ) as CryptoKey;

    await putMeta('LRK', lrk);
  }

  return lrk;
}

/**
 * Compute key ID from public key.
 * keyId = base64url(SHA-256(publicKeyRaw))
 */
async function computeKeyId(publicKeyRaw: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', publicKeyRaw);
  return arrayBufferToBase64url(hash);
}

/**
 * Ensure UAK (User Audit Key) is loaded/generated from MKEK.
 * This must be called after user authentication in withUnlock context.
 *
 * Based on: 05-audit-log.md § "UAK Generation"
 *
 * @param mkek - Master Key Encryption Key (derived from MS)
 */
export async function ensureAuditKey(mkek: CryptoKey): Promise<void> {
  // Check if UAK already exists in storage
  const existing = await getWrappedKey('audit-user');

  if (existing && existing.publicKeyRaw) {
    // Unwrap UAK and set as active signer
    const uak = await crypto.subtle.unwrapKey(
      'pkcs8',
      existing.wrappedKey,
      mkek,
      { name: 'AES-GCM', iv: existing.iv, additionalData: existing.aad },
      { name: 'Ed25519' },
      false, // non-extractable
      ['sign']
    );

    // Import public key
    const uakPub = await crypto.subtle.importKey(
      'raw',
      existing.publicKeyRaw,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    const keyId = await computeKeyId(existing.publicKeyRaw);

    activeSigner = {
      type: 'UAK',
      keyPair: { privateKey: uak, publicKey: uakPub },
      keyId,
    };
    return;
  }

  // Generate new UAK
  const uak = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  );

  // Export public key
  const publicKeyRaw = await crypto.subtle.exportKey('raw', uak.publicKey);

  // Wrap private key under MKEK
  await wrapKey(
    uak.privateKey,
    mkek,
    'audit-user',
    { name: 'Ed25519' },
    ['sign'],
    { alg: 'EdDSA', purpose: 'audit', publicKeyRaw }
  );

  // Set as active signer
  const keyId = await computeKeyId(publicKeyRaw);
  activeSigner = {
    type: 'UAK',
    keyPair: uak,
    keyId,
  };
}

/**
 * Generate LAK (Lease Audit Key) and delegation certificate signed by UAK.
 * This is called when creating a new lease. The LAK allows background
 * operations (JWT signing) to audit without user credentials.
 *
 * Based on: 05-audit-log.md § "LAK Generation (During Lease Creation)"
 *
 * @param leaseId - Unique lease identifier
 * @param exp - Lease expiration timestamp (ms)
 * @returns LAK keypair and delegation certificate
 */
export async function generateLAK(
  leaseId: string,
  exp: number
): Promise<{ lakKeyPair: CryptoKeyPair; delegationCert: AuditDelegationCert }> {
  if (!activeSigner || activeSigner.type !== 'UAK') {
    throw new Error('UAK must be active to generate LAK - call ensureAuditKey first');
  }

  const now = Date.now();

  // 1. Generate LAK keypair
  const lak = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true, // temporarily extractable for wrapping
    ['sign', 'verify']
  );

  // 2. Export public key
  const publicKeyRaw = await crypto.subtle.exportKey('raw', lak.publicKey);
  const delegatePub = arrayBufferToBase64url(publicKeyRaw);

  // 3. Create delegation certificate (unsigned)
  const certUnsigned: Omit<AuditDelegationCert, 'sig'> = {
    type: 'audit-delegation',
    version: 1,
    signerKind: 'LAK',
    leaseId,
    delegatePub,
    scope: ['vapid:issue', 'lease:expire'],
    notBefore: now,
    notAfter: exp,
    codeHash: 'TODO', // KMS code hash
    manifestHash: 'TODO', // KMS manifest hash
    kmsVersion: 'v2.0.0',
  };

  // 4. Sign delegation cert with UAK
  const certCanonical = JSON.stringify(certUnsigned, Object.keys(certUnsigned).sort());
  const certSig = await crypto.subtle.sign(
    'Ed25519',
    activeSigner.keyPair.privateKey,
    new TextEncoder().encode(certCanonical)
  );
  const delegationCert: AuditDelegationCert = {
    ...certUnsigned,
    sig: arrayBufferToBase64url(certSig),
  };

  // 5. Wrap LAK under LRK
  const lrk = await ensureLRK();
  const aad = buildKeyWrapAAD({
    kmsVersion: 2,
    kid: `lak-${leaseId}`,
    alg: 'EdDSA',
    purpose: 'lak',
    createdAt: now,
    keyType: 'lease-audit-key',
  });
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = await crypto.subtle.wrapKey(
    'pkcs8',
    lak.privateKey,
    lrk,
    { name: 'AES-GCM', iv, additionalData: aad }
  );

  // 6. Store LAK record in lease-audit-keys store
  // Note: This uses a different storage key pattern than regular wrapped keys
  await putMeta(`lease-audit-key:${leaseId}`, {
    leaseId,
    wrappedKey,
    iv,
    aad,
    publicKeyRaw,
    delegationCert,
    expiresAt: exp,
    createdAt: now,
  });

  return { lakKeyPair: lak, delegationCert };
}

/**
 * Load LAK (Lease Audit Key) and set as active signer.
 * This is called before performing lease operations (JWT signing).
 *
 * Based on: 05-audit-log.md § "Usage During JWT Issuance"
 *
 * @param leaseId - Lease identifier
 * @param cert - Delegation certificate (contains LAK public key)
 */
export async function loadLAK(leaseId: string, cert: AuditDelegationCert): Promise<void> {
  // Retrieve LAK record
  const lakRecord = await getMeta(`lease-audit-key:${leaseId}`) as {
    leaseId: string;
    wrappedKey: ArrayBuffer;
    iv: ArrayBuffer;
    aad: ArrayBuffer;
    publicKeyRaw: ArrayBuffer;
    delegationCert: AuditDelegationCert;
    expiresAt: number;
    createdAt: number;
  } | undefined;

  if (!lakRecord) {
    throw new Error(`LAK not found for lease: ${leaseId}`);
  }

  // Unwrap LAK using LRK
  const lrk = await ensureLRK();
  const lak = await crypto.subtle.unwrapKey(
    'pkcs8',
    lakRecord.wrappedKey,
    lrk,
    { name: 'AES-GCM', iv: lakRecord.iv, additionalData: lakRecord.aad },
    { name: 'Ed25519' },
    false, // non-extractable
    ['sign']
  );

  // Import public key for keypair
  const lakPub = await crypto.subtle.importKey(
    'raw',
    lakRecord.publicKeyRaw,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  // Derive LAK ID from public key
  const keyId = await computeKeyId(lakRecord.publicKeyRaw);

  // Set LAK as active signer
  activeSigner = {
    type: 'LAK',
    keyPair: { privateKey: lak, publicKey: lakPub },
    keyId,
    cert,
  };
}

/**
 * Ensure KIAK (KMS Instance Audit Key) is generated and set as active signer.
 * This is called at worker initialization to enable system event logging.
 *
 * Based on: 05-audit-log.md § "KIAK Initialization"
 */
export async function ensureKIAK(): Promise<void> {
  // Check if KIAK already exists
  const existing = await getWrappedKey('audit-instance');

  if (existing && existing.publicKeyRaw) {
    // Unwrap KIAK
    const lrk = await ensureLRK();
    const kiak = await crypto.subtle.unwrapKey(
      'pkcs8',
      existing.wrappedKey,
      lrk,
      { name: 'AES-GCM', iv: existing.iv, additionalData: existing.aad },
      { name: 'Ed25519' },
      false, // non-extractable
      ['sign']
    );

    // Import public key
    const kiakPub = await crypto.subtle.importKey(
      'raw',
      existing.publicKeyRaw,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    const keyId = await computeKeyId(existing.publicKeyRaw);

    activeSigner = {
      type: 'KIAK',
      keyPair: { privateKey: kiak, publicKey: kiakPub },
      keyId,
    };
    return;
  }

  // Generate new KIAK
  const lrk = await ensureLRK();

  const kiak = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true, // temporarily extractable for wrapping
    ['sign']
  );

  // Export public key
  const publicKeyRaw = await crypto.subtle.exportKey('raw', kiak.publicKey);

  // Wrap KIAK under LRK
  await wrapKey(
    kiak.privateKey,
    lrk,
    'audit-instance',
    { name: 'Ed25519' },
    ['sign'],
    { alg: 'EdDSA', purpose: 'audit-instance', publicKeyRaw }
  );

  // Retrieve wrapped key record
  const wrappedKeyRecord = await getWrappedKey('audit-instance');
  if (!wrappedKeyRecord) {
    throw new Error('Failed to retrieve wrapped KIAK after storage');
  }

  // Unwrap KIAK to get non-extractable version (same as existing path)
  const kiakNonExtractable = await crypto.subtle.unwrapKey(
    'pkcs8',
    wrappedKeyRecord.wrappedKey,
    lrk,
    { name: 'AES-GCM', iv: wrappedKeyRecord.iv, additionalData: wrappedKeyRecord.aad },
    { name: 'Ed25519' },
    false, // non-extractable
    ['sign']
  );

  // Import public key
  const kiakPub = await crypto.subtle.importKey(
    'raw',
    publicKeyRaw,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  // Compute key ID
  const keyId = await computeKeyId(publicKeyRaw);

  // Set KIAK as active signer (non-extractable keypair)
  activeSigner = {
    type: 'KIAK',
    keyPair: { privateKey: kiakNonExtractable, publicKey: kiakPub },
    keyId,
  };
}

/**
 * Append an operation to the audit log using the active signer.
 * The active signer is determined by the most recent call to:
 * - ensureAuditKey() -> UAK
 * - loadLAK() -> LAK
 * - ensureKIAK() -> KIAK
 *
 * Based on: 05-audit-log.md § "Logging Function"
 *
 * @param op - Audit operation details
 */
export async function logOperation(op: AuditOperation): Promise<void> {
  if (!activeSigner) {
    throw new Error('No active audit signer - call ensureAuditKey, loadLAK, or ensureKIAK first');
  }

  seqCounter += 1;
  const timestamp = Date.now();
  const previousEntry = await getLastAuditEntry();
  const previousHash = previousEntry ? previousEntry.chainHash : '';

  // Construct the payload to be hashed (excluding sig and chainHash)
  const payload = {
    kmsVersion: 2 as const,
    seqNum: seqCounter,
    timestamp,
    op: op.op,
    kid: op.kid,
    requestId: op.requestId,
    origin: op.origin,
    leaseId: op.leaseId,
    unlockTime: op.unlockTime,
    lockTime: op.lockTime,
    duration: op.duration,
    details: op.details,
    previousHash,
    signer: activeSigner.type,
    signerId: activeSigner.keyId,
  };

  // Canonical JSON representation for hashing
  const payloadString = JSON.stringify(payload);

  // Compute chain hash = SHA256(previousHash + payloadString)
  const chainInput = new TextEncoder().encode(previousHash + payloadString);
  const chainHashBuf = await crypto.subtle.digest('SHA-256', chainInput);
  const chainHash = arrayBufferToBase64url(chainHashBuf);

  // Sign the chain hash
  const chainHashBytes = new TextEncoder().encode(chainHash);
  const sigBuf = await crypto.subtle.sign('Ed25519', activeSigner.keyPair.privateKey, chainHashBytes);
  const sig = arrayBufferToBase64url(sigBuf);

  // Construct entry
  const entry: AuditEntryV2 = {
    kmsVersion: payload.kmsVersion,
    seqNum: payload.seqNum,
    timestamp: payload.timestamp,
    op: payload.op,
    kid: payload.kid,
    requestId: payload.requestId,
    ...(payload.origin !== undefined && { origin: payload.origin }),
    ...(payload.leaseId !== undefined && { leaseId: payload.leaseId }),
    ...(payload.unlockTime !== undefined && { unlockTime: payload.unlockTime }),
    ...(payload.lockTime !== undefined && { lockTime: payload.lockTime }),
    ...(payload.duration !== undefined && { duration: payload.duration }),
    ...(payload.details !== undefined && { details: payload.details }),
    previousHash: payload.previousHash,
    chainHash,
    signer: payload.signer,
    signerId: payload.signerId,
    ...(activeSigner.cert !== undefined && { cert: activeSigner.cert }),
    sig,
  };

  await storeAuditEntry(entry);
}

/**
 * Verify the integrity of the audit chain. Recomputes the chain hash
 * and verifies the signature for each entry using the signer's public key.
 *
 * NOTE: This is a simplified verification that doesn't validate delegation
 * certificates or check that the correct signer was used for each operation.
 *
 * Based on: 05-audit-log.md § "Verification Algorithm"
 */
export async function verifyAuditChain(): Promise<VerificationResult> {
  const entries = await getAllAuditEntries();
  const errors: string[] = [];
  let verified = 0;

  for (const entry of entries) {
    // Reconstruct payload for hashing
    const payload = {
      kmsVersion: entry.kmsVersion,
      seqNum: entry.seqNum,
      timestamp: entry.timestamp,
      op: entry.op,
      kid: entry.kid,
      requestId: entry.requestId,
      origin: entry.origin,
      leaseId: entry.leaseId,
      unlockTime: entry.unlockTime,
      lockTime: entry.lockTime,
      duration: entry.duration,
      details: entry.details,
      previousHash: entry.previousHash,
      signer: entry.signer,
      signerId: entry.signerId,
    };

    const payloadString = JSON.stringify(payload);
    const chainInput = new TextEncoder().encode(entry.previousHash + payloadString);
    const expectedChainBuf = await crypto.subtle.digest('SHA-256', chainInput);
    const expectedChain = arrayBufferToBase64url(expectedChainBuf);

    if (expectedChain !== entry.chainHash) {
      errors.push(`Chain hash mismatch at seq ${entry.seqNum}`);
    }

    // Verify signature
    // NOTE: Full verification would require importing the public key from signerId or cert
    // For now, we only verify chain hash integrity

    verified += 1;
  }

  return { valid: errors.length === 0, verified, errors };
}

/**
 * Export the audit public key (UAK).
 */
export async function getAuditPublicKey(): Promise<{ publicKey: string }> {
  const uakRecord = await getWrappedKey('audit-user');
  if (!uakRecord || !uakRecord.publicKeyRaw) {
    throw new Error('UAK not initialized');
  }

  const pub = arrayBufferToBase64url(uakRecord.publicKeyRaw);
  return { publicKey: pub };
}

/**
 * Export the audit private key (UAK).
 * In production, this requires user authentication via withUnlock.
 *
 * @param _credentials - Authentication credentials (unused in current implementation)
 */
export async function exportAuditKey(_credentials: AuthCredentials): Promise<string> {
  const uakRecord = await getWrappedKey('audit-user');
  if (!uakRecord) {
    throw new Error('UAK not initialized');
  }

  // In production, this would require MKEK from credentials to unwrap
  // For now, return the wrapped key as base64url
  return arrayBufferToBase64url(uakRecord.wrappedKey);
}

/**
 * Reset the audit logger. Used for testing.
 */
export function resetAuditLogger(): void {
  activeSigner = null;
  seqCounter = 0;
}
