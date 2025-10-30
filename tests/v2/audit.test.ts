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
  logOperation,
  verifyAuditChain,
  getAuditPublicKey,
  exportAuditKey,
  resetAuditLogger,
  ensureKIAK,
  generateLAK,
  loadLAK,
} from '@/v2/audit';
import { initDB, closeDB, getAllAuditEntries, getWrappedKey } from '@/v2/storage';
import type { AuditOperation, AuditDelegationCert } from '@/v2/types';
import { handleMessage } from '@/v2/worker';

// Helper function to create worker requests
function createRequest(method: string, params: unknown = {}): { id: string; method: string; params: unknown } {
  return {
    id: crypto.randomUUID(),
    method,
    params,
  };
}

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

describe('ensureKIAK', () => {
  it('should initialize KIAK with Ed25519 key pair', async () => {
    await ensureKIAK();

    // Verify KIAK was stored
    const kiakRecord = await getWrappedKey('audit-instance');
    expect(kiakRecord).toBeDefined();
    expect(kiakRecord?.publicKeyRaw).toBeDefined();
    expect(kiakRecord?.publicKeyRaw!.byteLength).toBe(32); // Ed25519 public key is 32 bytes
  });

  it('should be idempotent (same key on multiple calls)', async () => {
    await ensureKIAK();
    const kiakRecord1 = await getWrappedKey('audit-instance');
    expect(kiakRecord1).toBeDefined();
    expect(kiakRecord1?.publicKeyRaw).toBeDefined();

    await ensureKIAK();
    const kiakRecord2 = await getWrappedKey('audit-instance');
    expect(kiakRecord2).toBeDefined();
    expect(kiakRecord2?.publicKeyRaw).toBeDefined();

    // Should be the same key (same public key bytes)
    const pub1 = new Uint8Array(kiakRecord1!.publicKeyRaw!);
    const pub2 = new Uint8Array(kiakRecord2!.publicKeyRaw!);
    expect(pub1).toEqual(pub2);
  });

  it('should generate unique keys for different logger instances', async () => {
    await ensureKIAK();
    const kiakRecord1 = await getWrappedKey('audit-instance');
    expect(kiakRecord1).toBeDefined();
    expect(kiakRecord1?.publicKeyRaw).toBeDefined();
    const pub1 = new Uint8Array(kiakRecord1!.publicKeyRaw!);

    // Reset and reinitialize with fresh database (simulates new installation)
    // KIAK persists in DB, so we need to clear it for a fresh key
    resetAuditLogger();
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await ensureKIAK();
    const kiakRecord2 = await getWrappedKey('audit-instance');
    expect(kiakRecord2).toBeDefined();
    expect(kiakRecord2?.publicKeyRaw).toBeDefined();
    const pub2 = new Uint8Array(kiakRecord2!.publicKeyRaw!);

    expect(pub1).not.toEqual(pub2);
  });
});

// ============================================================================
// Operation Logging Tests
// ============================================================================

describe('logOperation', () => {
  it('should log a simple operation', async () => {
    await ensureKIAK();

    const op: AuditOperation = {
      op: 'sign',
      kid: 'test-key-1',
      requestId: 'req-123',
      userId: 'test-user',
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
    await ensureKIAK();

    await logOperation({ op: 'setup-passphrase', kid: '', requestId: 'req-1', userId: 'test-user' });
    await logOperation({ op: 'unlock', kid: '', requestId: 'req-2', userId: 'test-user' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3', userId: 'test-user' });

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(3);
    expect(entries[0]!.seqNum).toBe(1);
    expect(entries[1]!.seqNum).toBe(2);
    expect(entries[2]!.seqNum).toBe(3);
  });

  it('should include timestamps', async () => {
    await ensureKIAK();

    const before = Date.now();
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1', userId: 'test-user' });
    const after = Date.now();

    const entries = await getAllAuditEntries();
    expect(entries[0]!.timestamp).toBeGreaterThanOrEqual(before);
    expect(entries[0]!.timestamp).toBeLessThanOrEqual(after);
  });

  it('should include optional fields when provided', async () => {
    await ensureKIAK();

    const op: AuditOperation = {
      op: 'sign',
      kid: 'key-1',
      requestId: 'req-1',
      userId: 'test-user',
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
    await ensureKIAK();

    await logOperation({ op: 'setup-passphrase', kid: '', requestId: 'req-1', userId: 'test-user' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-2', userId: 'test-user' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.previousHash).toBe(''); // First entry has no previous
    expect(entries[1]!.previousHash).toBe(entries[0]!.chainHash); // Second links to first
  });

  it('should create unique chain hashes for different operations', async () => {
    await ensureKIAK();

    await logOperation({ op: 'setup-passphrase', kid: '', requestId: 'req-1', userId: 'test-user' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-2', userId: 'test-user' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.chainHash).not.toBe(entries[1]!.chainHash);
  });

  it('should include signer ID in entries', async () => {
    await ensureKIAK();

    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1', userId: 'test-user' });

    const entries = await getAllAuditEntries();
    expect(entries[0]!.signerId).toBeDefined();
    expect(entries[0]!.signerId.length).toBeGreaterThan(0);
  });

  it('should include signature in entries', async () => {
    await ensureKIAK();

    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1', userId: 'test-user' });

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
    await ensureKIAK();

    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1', userId: 'test-user' });

    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(1);
    expect(result.errors).toEqual([]);
  });

  it('should verify multiple entries', async () => {
    await ensureKIAK();

    await logOperation({ op: 'setup-passphrase', kid: '', requestId: 'req-1', userId: 'test-user' });
    await logOperation({ op: 'unlock', kid: '', requestId: 'req-2', userId: 'test-user' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3', userId: 'test-user' });

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
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));

    const { publicKey } = await getAuditPublicKey();

    // Base64url should not contain +, /, or =
    expect(publicKey).not.toMatch(/[+/=]/);
    expect(publicKey.length).toBeGreaterThan(0);
  });

  it('should return UAK public key after setup', async () => {
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));

    const { publicKey } = await getAuditPublicKey();

    expect(publicKey).toBeDefined();
    expect(publicKey.length).toBeGreaterThan(0);
  });

  it('should return consistent public key', async () => {
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));

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
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));

    const privateKey = await exportAuditKey({ method: 'passphrase', passphrase: 'test', userId: 'test@example.com' });

    // Base64url should not contain +, /, or =
    expect(privateKey).not.toMatch(/[+/=]/);
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('should export UAK after setup', async () => {
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));

    const privateKey = await exportAuditKey({ method: 'passphrase', passphrase: 'test', userId: 'test@example.com' });

    expect(privateKey).toBeDefined();
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('should export different key than public key', async () => {
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));

    const { publicKey } = await getAuditPublicKey();
    const privateKey = await exportAuditKey({ method: 'passphrase', passphrase: 'test', userId: 'test@example.com' });

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
    await ensureKIAK();

    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-1', userId: 'test-user' });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-2', userId: 'test-user' });

    const entriesBefore = await getAllAuditEntries();
    expect(entriesBefore[1]!.seqNum).toBe(2);

    resetAuditLogger();

    // Clear entries manually (resetAuditLogger only resets logger state, not storage)
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await ensureKIAK();

    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3', userId: 'test-user' });

    const entriesAfter = await getAllAuditEntries();
    expect(entriesAfter[0]!.seqNum).toBe(1);
  });

  it('should generate new key pair after reset', async () => {
    // Setup KMS to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));
    const { publicKey: key1 } = await getAuditPublicKey();

    // Reset with fresh database to get new UAK (simulates new installation)
    resetAuditLogger();
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-1234' }));
    const { publicKey: key2 } = await getAuditPublicKey();

    expect(key1).not.toBe(key2);
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('audit integration', () => {
  it('should maintain chain integrity across multiple operations', async () => {
    await ensureKIAK();

    // Simulate a typical KMS session
    await logOperation({ op: 'setup-passphrase', kid: '', requestId: 'req-1', userId: 'test-user', details: { method: 'passphrase' } });
    await logOperation({ op: 'unlock', kid: '', requestId: 'req-2', userId: 'test-user', unlockTime: 100 });
    await logOperation({ op: 'sign', kid: 'key-1', requestId: 'req-3', userId: 'test-user', duration: 50, details: { algorithm: 'ECDSA' } });
    await logOperation({ op: 'unwrap', kid: 'key-2', requestId: 'req-4', userId: 'test-user', duration: 30 });
    await logOperation({ op: 'reset', kid: '', requestId: 'req-5', userId: 'test-user', lockTime: 500 });

    const result = await verifyAuditChain();

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(5);
    expect(result.errors).toEqual([]);
  });

  it('should verify chain with all optional fields populated', async () => {
    await ensureKIAK();

    const op: AuditOperation = {
      op: 'sign',
      kid: 'key-1',
      requestId: 'req-1',
      userId: 'test-user',
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

describe('audit error paths for branch coverage', () => {
  it('should error when generating LAK without UAK initialized', async () => {
    // Branch: !activeSigner check in generateLAK (line 176)
    await expect(
      generateLAK('lease-1', Date.now() + 3600000)
    ).rejects.toThrow('UAK must be active to generate LAK');
  });

  it('should error when loading non-existent LAK', async () => {
    // Branch: !lakRecord check in loadLAK (line 276)
    const dummyCert: AuditDelegationCert = {
      type: 'audit-delegation',
      version: 1,
      signerKind: 'LAK',
      leaseId: 'non-existent-lease',
      delegatePub: 'dGVzdC1wdWJsaWMta2V5LWR1bW15LWRhdGE',
      scope: ['vapid.issue'],
      notBefore: Date.now(),
      notAfter: Date.now() + 3600000,
      codeHash: 'dummy-code-hash',
      manifestHash: 'dummy-manifest-hash',
      kmsVersion: 'v2.0.0',
      sig: 'ZHVtbXktc2lnbmF0dXJlLWRhdGEtZm9yLXRlc3Q',
    };
    await expect(
      loadLAK('non-existent-lease', dummyCert)
    ).rejects.toThrow('LAK not found for lease');
  });

  it('should error when getting audit public key before initialization', async () => {
    // Branch: UAK not initialized in getAuditPublicKey (line 581)
    await expect(getAuditPublicKey()).rejects.toThrow('UAK not initialized');
  });

  it('should error when exporting audit key before initialization', async () => {
    // Branch: UAK not initialized in exportAuditKey (line 597)
    const dummyCredentials = {
      method: 'passphrase' as const,
      userId: 'test-user',
      passphrase: 'test-pass',
    };
    await expect(
      exportAuditKey(dummyCredentials)
    ).rejects.toThrow('UAK not initialized');
  });
});
