/**
 * Unit tests for Audit Logger
 *
 * Tests all audit logging operations including:
 * - Signing key generation and management
 * - Hash-chained audit entry creation
 * - HMAC-SHA256 signature generation and verification
 * - Audit chain integrity validation
 * - Integration with storage layer
 *
 * @module tests/unit/audit.test
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  initAuditLogger,
  logOperation,
  verifyAuditChain,
  getAuditLog,
  getAuditPublicKey,
  resetAuditLogger,
  type AuditOperation,
  type AuditLogEntry,
} from '../../src/audit.js';
import { initDB, closeDB, getAllAuditEntries } from '../../src/storage.js';

// ============================================================
// Audit Logger Initialization Tests
// ============================================================

describe('Audit Logger - Initialization', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });

  afterEach(() => {
    resetAuditLogger();
    closeDB();
  });

  it('should initialize audit logger successfully', async () => {
    await expect(initAuditLogger()).resolves.toBeUndefined();
  });

  it('should handle multiple init calls', async () => {
    await initAuditLogger();
    await expect(initAuditLogger()).resolves.toBeUndefined();
  });

  it('should generate signing key on first init', async () => {
    await initAuditLogger();
    // Verify by logging an operation (which requires signing key)
    await expect(
      logOperation({
        op: 'setup',
        kid: 'test-key',
        requestId: 'req-1',
        origin: 'https://ats.run',
        clientInfo: { ua: 'Test', url: 'https://ats.run' },
      })
    ).resolves.toBeUndefined();
  });
});

// ============================================================
// Audit Entry Creation Tests
// ============================================================

describe('Audit Logger - Entry Creation', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await initAuditLogger();
  });

  afterEach(() => {
    resetAuditLogger();
    closeDB();
  });

  const createOperationData = (overrides?: Partial<AuditOperation>): AuditOperation => ({
    op: 'setup',
    kid: 'test-key',
    requestId: 'req-1',
    origin: 'https://ats.run',
    clientInfo: { ua: 'Test', url: 'https://ats.run' },
    ...overrides,
  });

  it('should log first operation with genesis prevHash', async () => {
    await logOperation(createOperationData());

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.prevHash).toBe(
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
  });

  it('should log operation with all required fields', async () => {
    const opData = createOperationData();
    await logOperation(opData);

    const entries = await getAllAuditEntries();
    const entry = entries[0];

    expect(entry).toBeDefined();
    expect(entry?.version).toBe(1);
    expect(entry?.op).toBe('setup');
    expect(entry?.kid).toBe('test-key');
    expect(entry?.requestId).toBe('req-1');
    expect(entry?.origin).toBe('https://ats.run');
    expect(entry?.clientInfo).toEqual({ ua: 'Test', url: 'https://ats.run' });
    expect(entry?.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(entry?.nonce).toBeTruthy();
    expect(entry?.sig).toBeTruthy();
  });

  it('should create unique nonces for each entry', async () => {
    await logOperation(createOperationData({ requestId: 'req-1' }));
    await logOperation(createOperationData({ requestId: 'req-2' }));

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(2);
    expect(entries[0]?.nonce).not.toBe(entries[1]?.nonce);
  });

  it('should chain entries with prevHash', async () => {
    await logOperation(createOperationData({ requestId: 'req-1' }));
    await logOperation(createOperationData({ requestId: 'req-2' }));

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(2);

    // Second entry's prevHash should reference first entry
    expect(entries[1]?.prevHash).not.toBe(
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
    expect(entries[1]?.prevHash).toBeTruthy();
  });

  it('should log operation with optional details', async () => {
    await logOperation(
      createOperationData({
        details: { algorithm: 'ES256', keySize: 256 },
      })
    );

    const entries = await getAllAuditEntries();
    expect(entries[0]?.details).toEqual({ algorithm: 'ES256', keySize: 256 });
  });

  it('should support all operation types', async () => {
    const operations: Array<AuditLogEntry['op']> = [
      'setup',
      'unlock',
      'unwrap',
      'sign',
      'reset',
      'export_attempt',
    ];

    for (const op of operations) {
      await logOperation(createOperationData({ op, requestId: `req-${op}` }));
    }

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(6);
    expect(entries.map((e) => e.op)).toEqual(operations);
  });
});

// ============================================================
// Audit Chain Verification Tests
// ============================================================

describe('Audit Logger - Chain Verification', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await initAuditLogger();
  });

  afterEach(() => {
    resetAuditLogger();
    closeDB();
  });

  const createOperationData = (overrides?: Partial<AuditOperation>): AuditOperation => ({
    op: 'setup',
    kid: 'test-key',
    requestId: 'req-1',
    origin: 'https://ats.run',
    clientInfo: { ua: 'Test', url: 'https://ats.run' },
    ...overrides,
  });

  it('should verify valid single-entry chain', async () => {
    await logOperation(createOperationData());

    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.verified).toBe(1);
    expect(result.errors).toEqual([]);
  });

  it('should verify valid multi-entry chain', async () => {
    for (let i = 0; i < 5; i++) {
      await logOperation(createOperationData({ requestId: `req-${i}` }));
    }

    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.verified).toBe(5);
    expect(result.errors).toEqual([]);
  });

  it('should detect empty chain', async () => {
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.verified).toBe(0);
    expect(result.errors).toEqual([]);
  });

  it('should detect invalid signature', async () => {
    await logOperation(createOperationData());

    // Manually corrupt signature in storage
    const entries = await getAllAuditEntries();
    const corrupted = { ...entries[0]!, sig: 'invalid-signature' };

    // We'll need putAuditEntry to test corruption
    const { putAuditEntry } = await import('../../src/storage.js');
    await putAuditEntry(corrupted);

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Invalid signature');
  });

  it('should detect broken chain link', async () => {
    await logOperation(createOperationData({ requestId: 'req-1' }));
    await logOperation(createOperationData({ requestId: 'req-2' }));
    await logOperation(createOperationData({ requestId: 'req-3' }));

    // Corrupt prevHash of third entry which makes signature invalid
    // This is the expected behavior - tampering is detected via invalid signature
    const entries = await getAllAuditEntries();
    const corrupted = { ...entries[2]!, prevHash: 'invalid-hash' };
    const { putAuditEntry } = await import('../../src/storage.js');
    await putAuditEntry(corrupted);

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    // When prevHash is tampered, signature becomes invalid (prevHash is signed)
    expect(result.errors[0]).toContain('Invalid signature');
  });
});

// ============================================================
// Audit Log Retrieval Tests
// ============================================================

describe('Audit Logger - Log Retrieval', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    await initAuditLogger();
  });

  afterEach(() => {
    resetAuditLogger();
    closeDB();
  });

  const createOperationData = (overrides?: Partial<AuditOperation>): AuditOperation => ({
    op: 'setup',
    kid: 'test-key',
    requestId: 'req-1',
    origin: 'https://ats.run',
    clientInfo: { ua: 'Test', url: 'https://ats.run' },
    ...overrides,
  });

  it('should retrieve empty log', async () => {
    const log = await getAuditLog();
    expect(log).toEqual([]);
  });

  it('should retrieve all entries in chronological order', async () => {
    await logOperation(createOperationData({ requestId: 'req-1' }));
    await logOperation(createOperationData({ requestId: 'req-2' }));
    await logOperation(createOperationData({ requestId: 'req-3' }));

    const log = await getAuditLog();
    expect(log).toHaveLength(3);
    expect(log[0]?.requestId).toBe('req-1');
    expect(log[1]?.requestId).toBe('req-2');
    expect(log[2]?.requestId).toBe('req-3');
  });

  it('should retrieve last N entries', async () => {
    for (let i = 0; i < 10; i++) {
      await logOperation(createOperationData({ requestId: `req-${i}` }));
      // Small delay to ensure unique timestamps
      await new Promise((resolve) => setTimeout(resolve, 2));
    }

    const log = await getAuditLog(3);
    expect(log).toHaveLength(3);
    expect(log[0]?.requestId).toBe('req-7');
    expect(log[1]?.requestId).toBe('req-8');
    expect(log[2]?.requestId).toBe('req-9');
  });
});

// ============================================================
// Error Handling Tests
// ============================================================

describe('Audit Logger - Error Handling', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });

  afterEach(() => {
    resetAuditLogger();
    closeDB();
  });

  it('should reject logging before initialization', async () => {
    await expect(
      logOperation({
        op: 'setup',
        kid: 'test-key',
        requestId: 'req-1',
        origin: 'https://ats.run',
        clientInfo: { ua: 'Test', url: 'https://ats.run' },
      })
    ).rejects.toThrow('Audit logger not initialized');
  });

  it('should handle verification after reset', async () => {
    await initAuditLogger();
    await logOperation({
      op: 'setup',
      kid: 'test-key',
      requestId: 'req-1',
      origin: 'https://ats.run',
      clientInfo: { ua: 'Test', url: 'https://ats.run' },
    });

    resetAuditLogger();

    // Verification should still work (uses public key from storage)
    // This enables independent verification without private key
    const result = await verifyAuditChain();
    expect(result.valid).toBe(true);
    expect(result.verified).toBe(1);

    // But logging should fail without private key
    await expect(
      logOperation({
        op: 'generate_vapid',
        kid: 'test-key-2',
        requestId: 'req-2',
        origin: 'https://ats.run',
        clientInfo: { ua: 'Test', url: 'https://ats.run' },
      })
    ).rejects.toThrow('Audit logger not initialized');
  });

  it('should handle malformed signature during verification', async () => {
    await initAuditLogger();
    await logOperation({
      op: 'setup',
      kid: 'test-key',
      requestId: 'req-1',
      origin: 'https://ats.run',
      clientInfo: { ua: 'Test', url: 'https://ats.run' },
    });

    // Corrupt signature with invalid hex
    const entries = await getAllAuditEntries();
    const corrupted = { ...entries[0]!, sig: 'not-valid-hex' };

    const { putAuditEntry } = await import('../../src/storage.js');
    await putAuditEntry(corrupted);

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Invalid signature');
  });

  it('should initialize with existing audit entries', async () => {
    // Create some entries
    await initDB();
    await initAuditLogger();
    await logOperation({
      op: 'setup',
      kid: 'test-key',
      requestId: 'req-1',
      origin: 'https://ats.run',
      clientInfo: { ua: 'Test', url: 'https://ats.run' },
    });

    // Reset and reinitialize
    resetAuditLogger();
    closeDB();

    // Reinitialize with existing entries
    globalThis.indexedDB = new IDBFactory();
    await initDB();

    // Put the entry back
    const entry = {
      version: 1 as const,
      timestamp: new Date().toISOString(),
      op: 'setup' as const,
      kid: 'test-key',
      requestId: 'req-1',
      origin: 'https://ats.run',
      clientInfo: { ua: 'Test', url: 'https://ats.run' },
      prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
      nonce: 'test-nonce',
      sig: 'test-sig',
    };

    const { putAuditEntry } = await import('../../src/storage.js');
    await putAuditEntry(entry);

    // Init should load last hash
    await expect(initAuditLogger()).resolves.toBeUndefined();
  });
});

// ============================================================
// Audit Public Key Tests
// ============================================================

describe('Audit Logger - Public Key Export', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
    resetAuditLogger();
  });

  afterEach(() => {
    closeDB();
  });

  it('should return audit public key after initialization', async () => {
    await initAuditLogger();
    const publicKey = await getAuditPublicKey();

    expect(publicKey).toBeTruthy();
    expect(publicKey).toHaveProperty('kty');
    expect(publicKey).toHaveProperty('crv');
    expect(publicKey!.kty).toBe('EC');
    expect(publicKey!.crv).toBe('P-256');
  });

  it('should return null if audit logger not initialized', async () => {
    const publicKey = await getAuditPublicKey();
    expect(publicKey).toBeNull();
  });

  it('should return same public key on multiple calls', async () => {
    await initAuditLogger();
    const publicKey1 = await getAuditPublicKey();
    const publicKey2 = await getAuditPublicKey();

    expect(publicKey1).toEqual(publicKey2);
  });
});
