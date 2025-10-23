/**
 * Unit tests for IndexedDB Storage Layer
 *
 * Tests all storage operations including:
 * - Database initialization
 * - Keys store CRUD operations
 * - Audit store operations and pruning
 * - Meta store operations
 * - Error handling
 *
 * @module tests/unit/storage.test
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  initDB,
  closeDB,
  putWrappedKey,
  getWrappedKey,
  deleteWrappedKey,
  getAllWrappedKeys,
  putAuditEntry,
  getAllAuditEntries,
  getTailAuditEntries,
  pruneAuditEntries,
  putMeta,
  getMeta,
  deleteMeta,
  getAllMeta,
  wrapKey,
  unwrapKey,
  type WrappedKey,
  type WrapParams,
  type AuditEntry,
} from '../../src/storage.js';

// ============================================================
// Database Initialization Tests
// ============================================================

describe('Storage - Database Initialization', () => {
  beforeEach(() => {
    // Create fresh IndexedDB instance for test isolation
    globalThis.indexedDB = new IDBFactory();
  });

  afterEach(() => {
    closeDB();
  });

  it('should initialize database successfully', async () => {
    await expect(initDB()).resolves.toBeUndefined();
  });

  it('should create three object stores', async () => {
    await initDB();
    await expect(getAllWrappedKeys()).resolves.toEqual([]);
    await expect(getAllAuditEntries()).resolves.toEqual([]);
    await expect(getAllMeta()).resolves.toEqual([]);
  });

  it('should handle multiple init calls', async () => {
    await initDB();
    await expect(initDB()).resolves.toBeUndefined();
  });

  it('should auto-initialize on first operation', async () => {
    // Don't call initDB()
    await expect(getAllWrappedKeys()).resolves.toEqual([]);
  });
});

// ============================================================
// Keys Store Tests
// ============================================================

describe('Storage - Keys Store', () => {
  beforeEach(async () => {
    // Create fresh IndexedDB instance for test isolation
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });

  afterEach(() => {
    closeDB();
  });

  const createWrapParams = (): WrapParams => ({
    alg: 'AES-GCM',
    keySize: 256,
    salt: new Uint8Array([1, 2, 3, 4]).buffer,
    iv: new Uint8Array([5, 6, 7, 8]).buffer,
    iterations: 600000,
  });

  it('should store a wrapped key', async () => {
    const key: WrappedKey = {
      kid: 'test-key-1',
      wrappedKey: new Uint8Array([9, 10, 11, 12]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T12:00:00.000Z',
    };

    await expect(putWrappedKey(key)).resolves.toBeUndefined();
  });

  it('should retrieve a stored key', async () => {
    const key: WrappedKey = {
      kid: 'test-key-2',
      wrappedKey: new Uint8Array([9, 10, 11, 12]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T12:00:00.000Z',
    };

    await putWrappedKey(key);
    const retrieved = await getWrappedKey('test-key-2');

    expect(retrieved).toBeDefined();
    expect(retrieved?.kid).toBe('test-key-2');
    expect(retrieved?.wrappedAt).toBe('2025-10-23T12:00:00.000Z');
    expect(new Uint8Array(retrieved!.wrappedKey)).toEqual(
      new Uint8Array([9, 10, 11, 12])
    );
  });

  it('should return undefined for non-existent key', async () => {
    const retrieved = await getWrappedKey('non-existent');
    expect(retrieved).toBeUndefined();
  });

  it('should overwrite existing key', async () => {
    const key1: WrappedKey = {
      kid: 'test-key-3',
      wrappedKey: new Uint8Array([1, 1, 1, 1]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T12:00:00.000Z',
    };

    const key2: WrappedKey = {
      kid: 'test-key-3',
      wrappedKey: new Uint8Array([2, 2, 2, 2]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T13:00:00.000Z',
    };

    await putWrappedKey(key1);
    await putWrappedKey(key2);

    const retrieved = await getWrappedKey('test-key-3');
    expect(new Uint8Array(retrieved!.wrappedKey)).toEqual(
      new Uint8Array([2, 2, 2, 2])
    );
  });

  it('should delete a key', async () => {
    const key: WrappedKey = {
      kid: 'test-key-4',
      wrappedKey: new Uint8Array([9, 10, 11, 12]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T12:00:00.000Z',
    };

    await putWrappedKey(key);
    await deleteWrappedKey('test-key-4');

    const retrieved = await getWrappedKey('test-key-4');
    expect(retrieved).toBeUndefined();
  });

  it('should get all keys', async () => {
    const key1: WrappedKey = {
      kid: 'key-a',
      wrappedKey: new Uint8Array([1]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T12:00:00.000Z',
    };

    const key2: WrappedKey = {
      kid: 'key-b',
      wrappedKey: new Uint8Array([2]).buffer,
      wrapParams: createWrapParams(),
      wrappedAt: '2025-10-23T13:00:00.000Z',
    };

    await putWrappedKey(key1);
    await putWrappedKey(key2);

    const all = await getAllWrappedKeys();
    expect(all).toHaveLength(2);
    expect(all.map((k) => k.kid).sort()).toEqual(['key-a', 'key-b']);
  });
});

// ============================================================
// Audit Store Tests
// ============================================================

describe('Storage - Audit Store', () => {
  beforeEach(async () => {
    // Create fresh IndexedDB instance for test isolation
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });

  afterEach(() => {
    closeDB();
  });

  const createAuditEntry = (overrides: Partial<AuditEntry> = {}): AuditEntry => ({
    version: 1,
    timestamp: '2025-10-23T12:00:00.000Z',
    op: 'setup',
    kid: 'test-key',
    requestId: 'req-1',
    origin: 'https://ats.run',
    clientInfo: { ua: 'Test', url: 'https://ats.run' },
    prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
    nonce: 'nonce-1',
    sig: 'sig-1',
    ...overrides,
  });

  it('should store an audit entry', async () => {
    const entry = createAuditEntry();
    await expect(putAuditEntry(entry)).resolves.toBeUndefined();
  });

  it('should retrieve all audit entries', async () => {
    const entry1 = createAuditEntry();
    const entry2 = createAuditEntry({
      timestamp: '2025-10-23T13:00:00.000Z',
      op: 'unlock',
    });

    await putAuditEntry(entry1);
    await putAuditEntry(entry2);

    const all = await getAllAuditEntries();
    expect(all).toHaveLength(2);
    expect(all.map((e) => e.op)).toContain('setup');
    expect(all.map((e) => e.op)).toContain('unlock');
  });

  it('should get last N entries (newest first)', async () => {
    for (let i = 0; i < 10; i++) {
      const entry = createAuditEntry({
        timestamp: `2025-10-23T${String(i).padStart(2, '0')}:00:00.000Z`,
        requestId: `req-${i}`,
      });
      await putAuditEntry(entry);
    }

    const tail = await getTailAuditEntries(3);
    expect(tail).toHaveLength(3);
    expect(tail[0]?.timestamp).toBe('2025-10-23T09:00:00.000Z');
    expect(tail[1]?.timestamp).toBe('2025-10-23T08:00:00.000Z');
    expect(tail[2]?.timestamp).toBe('2025-10-23T07:00:00.000Z');
  });

  it('should prune old entries (keep last N)', async () => {
    // Create 10 entries with old timestamps (> 1000 days ago)
    for (let i = 0; i < 10; i++) {
      const date = new Date('2022-01-01T00:00:00.000Z');
      date.setDate(date.getDate() + i);
      const entry = createAuditEntry({
        timestamp: date.toISOString(),
        requestId: `req-${i}`,
      });
      await putAuditEntry(entry);
    }

    // Keep last 5, prune anything older than 1000 days (all entries should be old)
    const deleted = await pruneAuditEntries(5, 1000);
    expect(deleted).toBe(5);

    const remaining = await getAllAuditEntries();
    expect(remaining).toHaveLength(5);
  });

  it('should not prune if count <= keepCount', async () => {
    for (let i = 0; i < 3; i++) {
      const entry = createAuditEntry({
        timestamp: `2025-10-23T${String(i).padStart(2, '0')}:00:00.000Z`,
        requestId: `req-${i}`,
      });
      await putAuditEntry(entry);
    }

    const deleted = await pruneAuditEntries(5, 30);
    expect(deleted).toBe(0);

    const remaining = await getAllAuditEntries();
    expect(remaining).toHaveLength(3);
  });
});

// ============================================================
// Meta Store Tests
// ============================================================

// ============================================================
// Error Handling Tests
// ============================================================

describe('Storage - Error Handling', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });

  afterEach(() => {
    closeDB();
  });

  it('should handle database reinitialization gracefully', async () => {
    // Close DB and verify it reinitializes automatically
    closeDB();
    // getDB() will reinitialize on next operation
    await expect(getWrappedKey('test')).resolves.toBeUndefined();
  });

  it('should handle database reinitialization after close', async () => {
    closeDB();
    // Should auto-reinitialize
    await expect(getAllWrappedKeys()).resolves.toEqual([]);
  });
});

// ============================================================
// Meta Store Tests
// ============================================================

describe('Storage - Meta Store', () => {
  beforeEach(async () => {
    // Create fresh IndexedDB instance for test isolation
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });

  afterEach(() => {
    closeDB();
  });

  it('should store meta value (string)', async () => {
    await expect(putMeta('unlockMethod', 'passkey')).resolves.toBeUndefined();
  });

  it('should store meta value (ArrayBuffer)', async () => {
    const salt = new Uint8Array([1, 2, 3, 4]).buffer;
    await expect(putMeta('unlockSalt', salt)).resolves.toBeUndefined();
  });

  it('should retrieve meta value', async () => {
    await putMeta('unlockMethod', 'passphrase');
    const retrieved = await getMeta<string>('unlockMethod');
    expect(retrieved).toBe('passphrase');
  });

  it('should return undefined for non-existent key', async () => {
    const retrieved = await getMeta('chainHead');
    expect(retrieved).toBeUndefined();
  });

  it('should overwrite existing meta value', async () => {
    await putMeta('chainHead', 'hash1');
    await putMeta('chainHead', 'hash2');
    const retrieved = await getMeta<string>('chainHead');
    expect(retrieved).toBe('hash2');
  });

  it('should delete meta value', async () => {
    await putMeta('chainHead', 'hash');
    await deleteMeta('chainHead');
    const retrieved = await getMeta('chainHead');
    expect(retrieved).toBeUndefined();
  });

  it('should get all meta entries', async () => {
    await putMeta('unlockMethod', 'passkey');
    await putMeta('chainHead', 'hash123');

    const all = await getAllMeta();
    expect(all).toHaveLength(2);
    expect(all.map((m) => m.key).sort()).toEqual(['chainHead', 'unlockMethod']);
  });
});

// ============================================================
// Key Wrapping Tests
// ============================================================

describe('Storage - Key Wrapping', () => {
  let testUnwrapKey: CryptoKey;

  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();

    // Generate a test unwrap key (AES-GCM 256-bit)
    testUnwrapKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['wrapKey', 'unwrapKey']
    );
  });

  afterEach(() => {
    closeDB();
  });

  it('should wrap and store a key', async () => {
    // Generate a test key to wrap (ECDSA P-256)
    const keypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // extractable for testing
      ['sign', 'verify']
    );

    const kid = 'test-key-1';
    const salt = crypto.getRandomValues(new Uint8Array(16));

    await wrapKey(keypair.privateKey, testUnwrapKey, kid, salt, 600000);

    // Verify key was stored
    const stored = await getWrappedKey(kid);
    expect(stored).toBeDefined();
    expect(stored?.kid).toBe(kid);
    expect(stored?.wrappedKey).toBeInstanceOf(ArrayBuffer);
    expect(stored?.wrapParams.alg).toBe('AES-GCM');
    expect(stored?.wrapParams.keySize).toBe(256);
    expect(stored?.wrapParams.iterations).toBe(600000);
    expect(stored?.wrappedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('should generate unique IV for each wrap', async () => {
    const keypair1 = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const keypair2 = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const salt = crypto.getRandomValues(new Uint8Array(16));
    await wrapKey(keypair1.privateKey, testUnwrapKey, 'key1', salt, 600000);
    await wrapKey(keypair2.privateKey, testUnwrapKey, 'key2', salt, 600000);

    const stored1 = await getWrappedKey('key1');
    const stored2 = await getWrappedKey('key2');

    // Compare as byte arrays, not ArrayBuffers
    const iv1 = new Uint8Array(stored1!.wrapParams.iv);
    const iv2 = new Uint8Array(stored2!.wrapParams.iv);
    expect(Array.from(iv1)).not.toEqual(Array.from(iv2));
  });

  it('should wrap key without salt and iterations (optional params)', async () => {
    const keypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const kid = 'test-key-no-salt';

    // Call wrapKey without salt/iterations
    await wrapKey(keypair.privateKey, testUnwrapKey, kid);

    // Verify key was stored with default values
    const stored = await getWrappedKey(kid);
    expect(stored).toBeDefined();
    expect(stored?.kid).toBe(kid);
    expect(stored?.wrapParams.iterations).toBe(0);
    expect(stored?.wrapParams.salt.byteLength).toBe(0);
  });

  it('should unwrap a wrapped key', async () => {
    // Generate and wrap a key
    const originalKeypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const kid = 'test-key-2';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await wrapKey(originalKeypair.privateKey, testUnwrapKey, kid, salt, 600000);

    // Unwrap the key
    const unwrapped = await unwrapKey(kid, testUnwrapKey, {
      name: 'ECDSA',
      namedCurve: 'P-256',
    });

    // Verify unwrapped key can be used for signing
    expect(unwrapped).toBeDefined();
    expect(unwrapped.type).toBe('private');
    expect(unwrapped.algorithm.name).toBe('ECDSA');

    // Test that unwrapped key can sign
    const data = new TextEncoder().encode('test message');
    await expect(
      crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, unwrapped, data)
    ).resolves.toBeInstanceOf(ArrayBuffer);
  });

  it('should unwrap key as non-extractable', async () => {
    const originalKeypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const kid = 'test-key-3';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await wrapKey(originalKeypair.privateKey, testUnwrapKey, kid, salt, 600000);

    const unwrapped = await unwrapKey(kid, testUnwrapKey, {
      name: 'ECDSA',
      namedCurve: 'P-256',
    });

    // Verify key is non-extractable
    expect(unwrapped.extractable).toBe(false);

    // Attempt to export should fail
    await expect(crypto.subtle.exportKey('pkcs8', unwrapped)).rejects.toThrow();
  });

  it('should throw error when unwrapping non-existent key', async () => {
    await expect(
      unwrapKey('non-existent-key', testUnwrapKey, {
        name: 'ECDSA',
        namedCurve: 'P-256',
      })
    ).rejects.toThrow('Key not found: non-existent-key');
  });

  it('should throw error when unwrapping with wrong key', async () => {
    // Generate and wrap a key
    const originalKeypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const kid = 'test-key-4';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await wrapKey(originalKeypair.privateKey, testUnwrapKey, kid, salt, 600000);

    // Generate a different unwrap key
    const wrongUnwrapKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['wrapKey', 'unwrapKey']
    );

    // Attempt to unwrap with wrong key should fail
    await expect(
      unwrapKey(kid, wrongUnwrapKey, {
        name: 'ECDSA',
        namedCurve: 'P-256',
      })
    ).rejects.toThrow();
  });

  it('should preserve wrap parameters', async () => {
    const keypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const kid = 'test-key-5';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iterations = 600000;

    await wrapKey(keypair.privateKey, testUnwrapKey, kid, salt, iterations);

    const stored = await getWrappedKey(kid);
    expect(stored?.wrapParams.salt).toEqual(salt.buffer);
    expect(stored?.wrapParams.iterations).toBe(iterations);
    expect(stored?.wrapParams.iv).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(stored!.wrapParams.iv).length).toBe(12);
  });

  it('should handle different key algorithms', async () => {
    // Test with Ed25519 (for future Signal Protocol support)
    // Note: Ed25519 support may vary by browser
    try {
      const keypair = await crypto.subtle.generateKey('Ed25519', true, [
        'sign',
        'verify',
      ]);

      const kid = 'test-ed25519-key';
      const salt = crypto.getRandomValues(new Uint8Array(16));
      await wrapKey(keypair.privateKey, testUnwrapKey, kid, salt, 600000);

      const unwrapped = await unwrapKey(kid, testUnwrapKey, 'Ed25519');

      expect(unwrapped.algorithm.name).toBe('Ed25519');
      expect(unwrapped.type).toBe('private');
    } catch (error) {
      // Ed25519 not supported in this environment, skip test
      if (
        error instanceof Error &&
        (error.message.includes('Unrecognized') ||
          error.message.includes('not supported'))
      ) {
        expect(true).toBe(true); // Test passes if algorithm not supported
      } else {
        throw error;
      }
    }
  });

  it('should handle wrap/unwrap round-trip correctly', async () => {
    // Generate test data
    const testMessage = 'Test message for signing';
    const testData = new TextEncoder().encode(testMessage);

    // Generate original keypair
    const originalKeypair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    // Sign with original key
    const originalSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      originalKeypair.privateKey,
      testData
    );

    // Wrap and unwrap
    const kid = 'test-key-6';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await wrapKey(originalKeypair.privateKey, testUnwrapKey, kid, salt, 600000);
    const unwrapped = await unwrapKey(kid, testUnwrapKey, {
      name: 'ECDSA',
      namedCurve: 'P-256',
    });

    // Sign with unwrapped key
    const unwrappedSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      unwrapped,
      testData
    );

    // Verify both signatures are valid with original public key
    const isOriginalValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      originalKeypair.publicKey,
      originalSignature,
      testData
    );
    const isUnwrappedValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      originalKeypair.publicKey,
      unwrappedSignature,
      testData
    );

    expect(isOriginalValid).toBe(true);
    expect(isUnwrappedValid).toBe(true);
  });
});
