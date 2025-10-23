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
