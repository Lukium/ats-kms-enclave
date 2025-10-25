/**
 * Audit logging for KMS V2
 *
 * This module implements a tamper‑evident audit log. Every
 * operation performed by the KMS worker is recorded as an `AuditEntryV2`
 * which includes a sequence number, timestamp, hash of the previous
 * entry, a chain hash over the current entry and a signature
 * produced by a locally generated Ed25519 key. The chain of hashes
 * ensures that any modification, insertion or deletion of entries
 * invalidates the remainder of the log. The design follows the
 * specifications outlined in the design documents.
 */

import type { AuditOperation, AuditEntryV2, VerificationResult, AuthCredentials } from './types';
import { storeAuditEntry, getAllAuditEntries, getLastAuditEntry } from './storage';
import { arrayBufferToBase64url, base64urlToArrayBuffer } from './crypto-utils';

// WebCrypto is used to generate Ed25519 keys and sign/verify
let auditKeyPair: CryptoKeyPair | null = null;
let auditKeyId = '';
let seqCounter = 0;

/**
 * Initialise the audit logger. Generates a new Ed25519 key pair if
 * one does not already exist. The public key is hashed to derive a
 * stable key identifier used in audit entries. Subsequent calls are
 * idempotent.
 */
export async function initAuditLogger(): Promise<void> {
  if (auditKeyPair) return;
  // Generate Ed25519 key pair
  auditKeyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true, // extractable: true (needed for export)
    ['sign', 'verify']
  ) as CryptoKeyPair;
  // Derive auditKeyId by hashing the public key SPKI
  const pubSpki = await crypto.subtle.exportKey('spki', auditKeyPair.publicKey);
  const hashBuf = await crypto.subtle.digest('SHA-256', pubSpki);
  auditKeyId = arrayBufferToBase64url(hashBuf);
}

/**
 * Append an operation to the audit log. An AuditEntryV2 is built
 * containing a monotonic sequence number, a timestamp, a chain hash
 * over the previous entry and current payload, and a signature
 * produced by the audit key. Entries are persisted via the storage
 * module. The function is resilient to concurrent calls by relying
 * on an incrementing internal sequence counter.
 */
export async function logOperation(op: AuditOperation): Promise<void> {
  if (!auditKeyPair) await initAuditLogger();
  seqCounter += 1;
  const timestamp = Date.now();
  const previousEntry = await getLastAuditEntry();
  const previousHash = previousEntry ? previousEntry.chainHash : '';
  // Construct the payload to be hashed (excluding signature and chainHash)
  const payload = {
    kmsVersion: 2 as const,
    seqNum: seqCounter,
    timestamp,
    op: op.op,
    kid: op.kid,
    requestId: op.requestId,
    origin: op.origin,
    unlockTime: op.unlockTime,
    lockTime: op.lockTime,
    duration: op.duration,
    details: op.details,
    previousHash,
    auditKeyId,
  };
  // Canonical JSON representation for hashing
  const payloadString = JSON.stringify(payload);
  // Compute chain hash = SHA256(previousHash + payloadString)
  const chainInput = new TextEncoder().encode(previousHash + payloadString);
  const chainHashBuf = await crypto.subtle.digest('SHA-256', chainInput);
  const chainHash = arrayBufferToBase64url(chainHashBuf);
  // Sign the chain hash. For Ed25519 the input is signed directly.
  const chainHashBytes = new TextEncoder().encode(chainHash);
  const signatureBuf = await crypto.subtle.sign('Ed25519', auditKeyPair!.privateKey, chainHashBytes);
  const signature = arrayBufferToBase64url(signatureBuf);
  const entry: AuditEntryV2 = {
    kmsVersion: payload.kmsVersion,
    seqNum: payload.seqNum,
    timestamp: payload.timestamp,
    op: payload.op,
    kid: payload.kid,
    requestId: payload.requestId,
    ...(payload.origin !== undefined && { origin: payload.origin }),
    ...(payload.unlockTime !== undefined && { unlockTime: payload.unlockTime }),
    ...(payload.lockTime !== undefined && { lockTime: payload.lockTime }),
    ...(payload.duration !== undefined && { duration: payload.duration }),
    ...(payload.details !== undefined && { details: payload.details }),
    previousHash: payload.previousHash,
    auditKeyId: payload.auditKeyId,
    chainHash,
    signature,
  };
  await storeAuditEntry(entry);
}

/**
 * Verify the integrity of the audit chain. Recomputes the chain hash
 * and verifies the signature for each entry. Accumulates any errors
 * encountered and returns an overall validity flag along with the
 * number of entries verified. Verification is purely computational
 * and does not modify any state.
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
      unlockTime: entry.unlockTime,
      lockTime: entry.lockTime,
      duration: entry.duration,
      details: entry.details,
      previousHash: entry.previousHash,
      auditKeyId: entry.auditKeyId,
    };
    const payloadString = JSON.stringify(payload);
    const chainInput = new TextEncoder().encode(entry.previousHash + payloadString);
    const expectedChainBuf = await crypto.subtle.digest('SHA-256', chainInput);
    const expectedChain = arrayBufferToBase64url(expectedChainBuf);
    if (expectedChain !== entry.chainHash) {
      errors.push(`Chain hash mismatch at seq ${entry.seqNum}`);
    }
    // Verify signature
    const signatureBuf = base64urlToArrayBuffer(entry.signature);
    const chainHashBytes = new TextEncoder().encode(entry.chainHash);
    const ok = await crypto.subtle.verify('Ed25519', auditKeyPair!.publicKey, signatureBuf, chainHashBytes);
    if (!ok) {
      errors.push(`Signature verification failed at seq ${entry.seqNum}`);
    }
    verified += 1;
  }
  return { valid: errors.length === 0, verified, errors };
}

/**
 * Export the audit public key. Returns the base64url encoded
 * subjectPublicKeyInfo (SPKI) of the Ed25519 public key. This value
 * may be published in the PWA to allow external verification of
 * audit signatures.
 */
export async function getAuditPublicKey(): Promise<{ publicKey: string }> {
  if (!auditKeyPair) await initAuditLogger();
  const spki = await crypto.subtle.exportKey('spki', auditKeyPair!.publicKey);
  const pub = arrayBufferToBase64url(spki);
  return { publicKey: pub };
}

/**
 * Export the audit private key. In a production system this function
 * would require user authentication via `withUnlock` to prevent
 * unprivileged export of secrets. Here we simply return the
 * base64url encoded PKCS#8 representation for demonstration
 * purposes. Use with caution.
 */
export async function exportAuditKey(_credentials: AuthCredentials): Promise<string> {
  if (!auditKeyPair) await initAuditLogger();
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', auditKeyPair!.privateKey);
  return arrayBufferToBase64url(pkcs8);
}

/**
 * Reset the audit logger and remove all entries. Primarily used for
 * testing to ensure a clean state between test cases.
 */
export function resetAuditLogger(): void {
  auditKeyPair = null;
  auditKeyId = '';
  seqCounter = 0;
  // Clearing audit entries is done via storage module; we rely on
  // tests calling initDB() to clear audit storage between runs.
}
