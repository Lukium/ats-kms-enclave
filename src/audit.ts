/**
 * Audit Logger with Hash-Chained Entries
 *
 * Provides tamper-evident audit logging with:
 * - ES256 (ECDSA P-256) signatures for each entry
 * - Hash-chained entries (each entry references previous entry's hash)
 * - Verification of chain integrity
 * - Integration with IndexedDB storage
 *
 * Security Properties:
 * - Entries cannot be modified without breaking the chain
 * - Entries cannot be reordered without breaking the chain
 * - Entries cannot be deleted from middle without breaking the chain
 * - Signing key is non-extractable CryptoKey (stored in IndexedDB)
 * - Public key is exportable for independent verification
 *
 * @module src/audit
 */

import {
  putAuditEntry,
  getAllAuditEntries,
  getTailAuditEntries,
  putMeta,
  getMeta,
  type AuditEntry,
} from './storage.js';

// ============================================================
// Types
// ============================================================

/**
 * Audit operation data (input for logging)
 */
export interface AuditOperation {
  op: 'setup' | 'unlock' | 'unwrap' | 'sign' | 'reset' | 'export_attempt' | 'generate_vapid';
  kid: string;
  requestId: string;
  origin?: string;
  clientInfo?: { ua: string; url: string };
  details?: Record<string, unknown>;
}

/**
 * Audit log entry (same as AuditEntry from storage)
 */
export type AuditLogEntry = AuditEntry;

/**
 * Chain verification result
 */
export interface ChainVerificationResult {
  valid: boolean;
  verified: number;
  errors: string[];
}

// ============================================================
// Module State
// ============================================================

let privateKey: CryptoKey | null = null;
let publicKey: CryptoKey | null = null;
let lastHash: string | null = null;

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// ============================================================
// Initialization
// ============================================================

/**
 * Initialize audit logger
 *
 * Generates or retrieves the ES256 signing keypair used for audit entries.
 * - Private key is stored as non-extractable CryptoKey in IndexedDB
 * - Public key is stored as JWK in IndexedDB for external verification
 * Safe to call multiple times (idempotent).
 */
export async function initAuditLogger(): Promise<void> {
  // Always load from storage to ensure we're using the correct keypair for this database instance
  // (Workers may share module state but have different IndexedDB instances)
  const storedPrivateKey = await getMeta<CryptoKey>('auditSigningKey');
  const storedPublicKeyJwk = await getMeta<JsonWebKey>('auditPublicKey');

  if (storedPrivateKey && storedPublicKeyJwk) {
    // Use existing keypair
    privateKey = storedPrivateKey;
    publicKey = await crypto.subtle.importKey(
      'jwk',
      storedPublicKeyJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
  } else {
    // Generate new ES256 keypair
    const keypair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false, // private key non-extractable
      ['sign', 'verify']
    );

    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;

    // Export and store public key JWK for external verification
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', publicKey);

    // Store both keys in IndexedDB
    await putMeta('auditSigningKey', privateKey);
    await putMeta('auditPublicKey', publicKeyJwk);
  }

  // Load last hash from existing chain
  const entries = await getTailAuditEntries(1);
  if (entries.length > 0) {
    lastHash = await computeEntryHash(entries[0]!);
  }
}

/**
 * Reset audit logger state (for testing)
 */
export function resetAuditLogger(): void {
  privateKey = null;
  publicKey = null;
  lastHash = null;
}

// ============================================================
// Entry Creation
// ============================================================

/**
 * Log an operation to the audit trail
 *
 * Creates a signed, hash-chained audit entry and stores it.
 *
 * @param data - Operation data to log
 * @throws Error if audit logger not initialized
 */
export async function logOperation(data: AuditOperation): Promise<void> {
  if (!privateKey) {
    throw new Error('Audit logger not initialized');
  }

  const timestamp = new Date().toISOString();
  const nonce = generateNonce();
  const prevHash = lastHash || GENESIS_HASH;

  // Create unsigned entry
  const unsignedEntry: Omit<AuditEntry, 'sig'> = {
    version: 1,
    timestamp,
    op: data.op,
    kid: data.kid,
    requestId: data.requestId,
    origin: data.origin || 'unknown',
    clientInfo: data.clientInfo || { ua: 'unknown', url: 'unknown' },
    prevHash,
    nonce,
    ...(data.details && { details: data.details }),
  };

  // Sign the entry
  const sig = await signEntry(unsignedEntry, privateKey);

  // Create final entry
  const entry: AuditEntry = {
    ...unsignedEntry,
    sig,
  };

  // Store entry
  await putAuditEntry(entry);

  // Update last hash
  lastHash = await computeEntryHash(entry);
}

// ============================================================
// Chain Verification
// ============================================================

/**
 * Verify the integrity of the entire audit chain
 *
 * Checks:
 * - Each entry has a valid signature
 * - Each entry's prevHash correctly references the previous entry
 * - Chain is unbroken from genesis to latest entry
 *
 * @returns Verification result with error details
 */
export async function verifyAuditChain(): Promise<ChainVerificationResult> {
  // Load public key from storage (for independent verification)
  const publicKeyJwk = await getMeta<JsonWebKey>('auditPublicKey');
  /* c8 ignore next 3 - defensive: audit logger always initialized before verification */
  if (!publicKeyJwk) {
    throw new Error('Audit public key not found - audit logger may not be initialized');
  }

  const verificationKey = await crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  const entries = await getAllAuditEntries();
  const errors: string[] = [];
  let verified = 0;

  if (entries.length === 0) {
    return { valid: true, verified: 0, errors: [] };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;

    // Verify signature
    const validSig = await verifyEntrySignature(entry, verificationKey);
    if (!validSig) {
      errors.push(`Entry ${i}: Invalid signature (requestId=${entry.requestId})`);
      continue;
    }

    // Verify chain link
    /* c8 ignore next 6 */
    if (entry.prevHash !== expectedPrevHash) {
      errors.push(
        `Entry ${i}: Chain broken (expected prevHash=${expectedPrevHash}, got=${entry.prevHash})`
      );
      continue;
    }

    verified++;
    expectedPrevHash = await computeEntryHash(entry);
  }

  return {
    valid: errors.length === 0,
    verified,
    errors,
  };
}

// ============================================================
// Log Retrieval
// ============================================================

/**
 * Retrieve audit log entries
 *
 * @param limit - Optional limit (returns last N entries if specified)
 * @returns Audit entries in chronological order
 */
export async function getAuditLog(limit?: number): Promise<AuditLogEntry[]> {
  if (limit !== undefined) {
    const entries = await getTailAuditEntries(limit);
    return entries.reverse(); // Reverse to chronological order
  }

  return await getAllAuditEntries();
}

/**
 * Get the audit log public key for external verification
 *
 * This public key can be used by anyone to independently verify the audit chain.
 * The key is exported in JWK format for easy use with standard crypto libraries.
 *
 * @returns Public key in JWK format, or null if audit logger not initialized
 */
export async function getAuditPublicKey(): Promise<JsonWebKey | null> {
  return (await getMeta<JsonWebKey>('auditPublicKey')) || null;
}

// ============================================================
// Cryptographic Utilities
// ============================================================

/**
 * Generate a random nonce
 */
function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return arrayBufferToHex(bytes.buffer);
}

/**
 * Compute entry hash (for chain linking)
 *
 * Hash includes all fields except signature
 */
async function computeEntryHash(entry: AuditEntry): Promise<string> {
  const data = JSON.stringify({
    version: entry.version,
    timestamp: entry.timestamp,
    op: entry.op,
    kid: entry.kid,
    requestId: entry.requestId,
    origin: entry.origin,
    clientInfo: entry.clientInfo,
    prevHash: entry.prevHash,
    nonce: entry.nonce,
    /* c8 ignore next */
    ...(entry.details && { details: entry.details }),
  });

  const buffer = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return arrayBufferToHex(hashBuffer);
}

/**
 * Sign an audit entry with ES256 (ECDSA P-256)
 */
async function signEntry(
  entry: Omit<AuditEntry, 'sig'>,
  key: CryptoKey
): Promise<string> {
  const data = JSON.stringify({
    version: entry.version,
    timestamp: entry.timestamp,
    op: entry.op,
    kid: entry.kid,
    requestId: entry.requestId,
    origin: entry.origin,
    clientInfo: entry.clientInfo,
    prevHash: entry.prevHash,
    nonce: entry.nonce,
    /* c8 ignore next */
    ...(entry.details && { details: entry.details }),
  });

  const buffer = new TextEncoder().encode(data);
  const sigBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    buffer
  );
  return arrayBufferToHex(sigBuffer);
}

/**
 * Verify an audit entry signature using ES256 (ECDSA P-256)
 */
async function verifyEntrySignature(
  entry: AuditEntry,
  key: CryptoKey
): Promise<boolean> {
  const data = JSON.stringify({
    version: entry.version,
    timestamp: entry.timestamp,
    op: entry.op,
    kid: entry.kid,
    requestId: entry.requestId,
    origin: entry.origin,
    clientInfo: entry.clientInfo,
    prevHash: entry.prevHash,
    nonce: entry.nonce,
    /* c8 ignore next */
    ...(entry.details && { details: entry.details }),
  });

  const buffer = new TextEncoder().encode(data);
  const sigBuffer = hexToArrayBuffer(entry.sig);

  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sigBuffer,
      buffer
    );
  } /* c8 ignore next 2 */ catch {
    return false;
  }
}

/**
 * Convert ArrayBuffer to hex string
 */
function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to ArrayBuffer
 */
function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}
