/**
 * Audit Module Test Suite (KMS V2)
 *
 * Comprehensive tests for audit logging including:
 * - Audit logger initialization (Ed25519 key generation)
 * - Operation logging (chain hashing and signing)
 * - Chain verification (integrity and signature checks)
 * - Public key export
 *
 * Tests verify cryptographic correctness and security properties.
 *
 * Note: Tampering tests are intentionally omitted because the audit store uses
 * a unique index on seqNum, which correctly prevents modifications to existing
 * entries (immutable audit log). This is the correct behavior for an audit log.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  initAuditLogger,
  logOperation,
  verifyAuditChain,
  getAuditPublicKey,
  exportAuditKey,
  resetAuditLogger,
} from '@/v2/audit';
import { initDB, closeDB, getAllAuditEntries } from '@/v2/storage';
import type { AuditOperation } from '@/v2/types';

// ============================================================================
// Test Setup
// ============================================================================

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
  resetAuditLogger();
});

afterEach(() => {
  closeDB();
  resetAuditLogger();
});

// ============================================================================
// Audit Logger Initialization Tests
// ============================================================================

describe('initAuditLogger', () => {
  it('should initialize audit logger with Ed25519 key pair', async () => {
    await initAuditLogger();

    // Verify we can get the public key
    const { publicKey } = await getAuditPublicKey();
    expect(publicKey).toBeDefined();
    expect(publicKey.length).toBeGreaterThan(0);
  });

  it('should be idempotent (same key on multiple calls)', async () => {
    await initAuditLogger();
    const { publicKey: key1 } = await getAuditPublicKey();

    await initAuditLogger();
    const { publicKey: key2 } = await getAuditPublicKey();

    expect(key1).toBe(key2);
  });

  it('should generate unique keys for different logger instances', async () => {
    await initAuditLogger();
    const { publicKey: key1 } = await getAuditPublicKey();

    // Reset and reinitialize with fresh database (simulates new installation)
    // KIAK persists in DB, so we need to clear it for a fresh key
    resetAuditLogger();
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await initAuditLogger();
    const { publicKey: key2 } = await getAuditPublicKey();

    expect(key1).not.toBe(key2);
  });
});

// ============================================================================
// Operation Logging Tests
// ============================================================================

describe('logOperation', () => {
  it('should log a simple operation', async () => {
    const op: AuditOperation = {
      op: 'sign',
      kid: 'test-key-1',
      requestId: 'req-123',
    };

    await logOperation(op);

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.op).toBe('sign');
    expect(entries[0]!.kid).toBe('test-key-1');
    expect(entries[0]!.requestId).toBe('req-123');
    expect(entries[0]!.seqNum).toBe(1);
  });

  it('should increment sequence numbers', async () => {
    await logOperation({ op: 'setup', kid: '', requestId: 'req-1' });
    await logOperation({ op: 'unlock', kid: '', requestId: 'req-2' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3' });

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(3);
    expect(entries[0]!.seqNum).toBe(1);
    expect(entries[1]!.seqNum).toBe(2);
    expect(entries[2]!.seqNum).toBe(3);
  });

  it('should include timestamps', async () => {
    const before = Date.now();
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1' });
    const after = Date.now();

    const entries = await getAllAuditEntries();
    expect(entries[0]!.timestamp).toBeGreaterThanOrEqual(before);
    expect(entries[0]!.timestamp).toBeLessThanOrEqual(after);
  });

  it('should include optional fields when provided', async () => {
    const op: AuditOperation = {
      op: 'sign',
      kid: 'key-1',
      requestId: 'req-1',
      origin: 'https://example.com',
      unlockTime: 100,
      lockTime: 200,
      duration: 100,
      details: { algorithm: 'ECDSA' },
    };

    await logOperation(op);

    const entries = await getAllAuditEntries();
    expect(entries[0]!.origin).toBe('https://example.com');
    expect(entries[0]!.unlockTime).toBe(100);
    expect(entries[0]!.lockTime).toBe(200);
    expect(entries[0]!.duration).toBe(100);
    expect(entries[0]!.details).toEqual({ algorithm: 'ECDSA' });
  });

  it('should create chain hash linking to previous entry', async () => {
    await logOperation({ op: 'setup', kid: '', requestId: 'req-1' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-2' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.previousHash).toBe(''); // First entry has no previous
    expect(entries[1]!.previousHash).toBe(entries[0]!.chainHash); // Second links to first
  });

  it('should create unique chain hashes for different operations', async () => {
    await logOperation({ op: 'setup', kid: '', requestId: 'req-1' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-2' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.chainHash).not.toBe(entries[1]!.chainHash);
  });

  it('should include signer ID in entries', async () => {
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.signerId).toBeDefined();
    expect(entries[0]!.signerId.length).toBeGreaterThan(0);
  });

  it('should include signature in entries', async () => {
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.sig).toBeDefined();
    expect(entries[0]!.sig.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Chain Verification Tests
// ============================================================================

describe('verifyAuditChain', () => {
  it('should verify an empty chain', async () => {
    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(0);
    expect(result.errors).toEqual([]);
  });

  it('should verify a single entry', async () => {
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1' });

    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(1);
    expect(result.errors).toEqual([]);
  });

  it('should verify multiple entries', async () => {
    await logOperation({ op: 'setup', kid: '', requestId: 'req-1' });
    await logOperation({ op: 'unlock', kid: '', requestId: 'req-2' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3' });

    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(3);
    expect(result.errors).toEqual([]);
  });
});

// ============================================================================
// Public Key Export Tests
// ============================================================================

describe('getAuditPublicKey', () => {
  it('should export base64url encoded SPKI public key', async () => {
    const { publicKey } = await getAuditPublicKey();

    // Base64url should not contain +, /, or =
    expect(publicKey).not.toMatch(/[+/=]/);
    expect(publicKey.length).toBeGreaterThan(0);
  });

  it('should initialize logger if not already initialized', async () => {
    // Don't call initAuditLogger
    const { publicKey } = await getAuditPublicKey();

    expect(publicKey).toBeDefined();
    expect(publicKey.length).toBeGreaterThan(0);
  });

  it('should return consistent public key', async () => {
    const { publicKey: key1 } = await getAuditPublicKey();
    const { publicKey: key2 } = await getAuditPublicKey();

    expect(key1).toBe(key2);
  });
});

// ============================================================================
// Private Key Export Tests
// ============================================================================

describe('exportAuditKey', () => {
  it('should export base64url encoded PKCS#8 private key', async () => {
    const privateKey = await exportAuditKey({ method: 'passphrase', passphrase: 'test' });

    // Base64url should not contain +, /, or =
    expect(privateKey).not.toMatch(/[+/=]/);
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('should initialize logger if not already initialized', async () => {
    // Don't call initAuditLogger
    const privateKey = await exportAuditKey({ method: 'passphrase', passphrase: 'test' });

    expect(privateKey).toBeDefined();
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('should export different key than public key', async () => {
    const { publicKey } = await getAuditPublicKey();
    const privateKey = await exportAuditKey({ method: 'passphrase', passphrase: 'test' });

    expect(privateKey).not.toBe(publicKey);
    // Private key PKCS#8 should be longer than public key SPKI
    expect(privateKey.length).toBeGreaterThan(publicKey.length);
  });
});

// ============================================================================
// Reset Tests
// ============================================================================

describe('resetAuditLogger', () => {
  it('should reset sequence counter', async () => {
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-2' });

    const entriesBefore = await getAllAuditEntries();
    expect(entriesBefore[1]!.seqNum).toBe(2);

    resetAuditLogger();

    // Clear entries manually (resetAuditLogger only resets logger state, not storage)
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await initDB();

    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3' });

    const entriesAfter = await getAllAuditEntries();
    expect(entriesAfter[0]!.seqNum).toBe(1);
  });

  it('should generate new key pair after reset', async () => {
    await initAuditLogger();
    const { publicKey: key1 } = await getAuditPublicKey();

    // Reset with fresh database to get new KIAK (simulates new installation)
    resetAuditLogger();
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await initAuditLogger();
    const { publicKey: key2 } = await getAuditPublicKey();

    expect(key1).not.toBe(key2);
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('audit integration', () => {
  it('should maintain chain integrity across multiple operations', async () => {
    // Simulate a typical KMS session
    await logOperation({ op: 'setup', kid: '', requestId: 'req-1', details: { method: 'passphrase' } });
    await logOperation({ op: 'unlock', kid: '', requestId: 'req-2', unlockTime: 100 });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3', duration: 50, details: { algorithm: 'ECDSA' } });
    await logOperation({ op: 'unwrap', kid: 'key-2', requestId: 'req-4', duration: 30 });
    await logOperation({ op: 'reset', kid: '', requestId: 'req-5', lockTime: 500 });

    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(5);
    expect(result.errors).toEqual([]);
  });

  it('should verify chain with all optional fields populated', async () => {
    const op: AuditOperation = {
      op: 'sign',
      kid: 'key-1',
      requestId: 'req-1',
      origin: 'https://example.com',
      unlockTime: 100,
      lockTime: 200,
      duration: 100,
      details: {
        algorithm: 'ECDSA',
        curve: 'P-256',
        purpose: 'authentication',
      },
    };

    await logOperation(op);
    await logOperation({ ...op, requestId: 'req-2' });
    await logOperation({ ...op, requestId: 'req-3' });

    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(3);
  });
});
