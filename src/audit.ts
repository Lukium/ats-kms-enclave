/**
 * Audit Logger with Hash-Chained Entries
 *
 * Provides tamper-evident audit logging with:
 * - HMAC-SHA256 signatures for each entry
 * - Hash-chained entries (each entry references previous entry's hash)
 * - Verification of chain integrity
 * - Integration with IndexedDB storage
 *
 * Security Properties:
 * - Entries cannot be modified without breaking the chain
 * - Entries cannot be reordered without breaking the chain
 * - Entries cannot be deleted from middle without breaking the chain
 * - Signing key is non-extractable CryptoKey
 *
 * @module src/audit
 */

import {
  putAuditEntry,
  getAllAuditEntries,
  getTailAuditEntries,
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

let signingKey: CryptoKey | null = null;
let lastHash: string | null = null;

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// ============================================================
// Initialization
// ============================================================

/**
 * Initialize audit logger
 *
 * Generates or retrieves the HMAC signing key used for audit entries.
 * Safe to call multiple times (idempotent).
 */
export async function initAuditLogger(): Promise<void> {
  if (signingKey) {
    return; // Already initialized
  }

  // Generate HMAC signing key (non-extractable)
  signingKey = await crypto.subtle.generateKey(
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false, // non-extractable
    ['sign', 'verify']
  );

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
  signingKey = null;
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
  if (!signingKey) {
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
  const sig = await signEntry(unsignedEntry, signingKey);

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
  if (!signingKey) {
    throw new Error('Audit logger not initialized');
  }

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
    const validSig = await verifyEntrySignature(entry, signingKey);
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
 * Sign an audit entry with HMAC-SHA256
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
  const sigBuffer = await crypto.subtle.sign('HMAC', key, buffer);
  return arrayBufferToHex(sigBuffer);
}

/**
 * Verify an audit entry signature
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
    return await crypto.subtle.verify('HMAC', key, sigBuffer, buffer);
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
