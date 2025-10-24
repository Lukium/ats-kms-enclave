/**
 * Storage Layer Test Suite (KMS V2)
 *
 * Comprehensive tests for IndexedDB storage operations including:
 * - Database initialization and object store creation
 * - Key wrapping and unwrapping operations
 * - Metadata storage and retrieval
 * - Audit log storage and ordering
 * - VAPID lease management
 *
 * Uses fake-indexeddb to simulate IndexedDB in Node.js test environment.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  initDB,
  closeDB,
  wrapKey,
  unwrapKey,
  getWrappedKey,
  getAllWrappedKeys,
  deleteWrappedKey,
  getMeta,
  putMeta,
  deleteMeta,
  getAllMeta,
  storeAuditEntry,
  getAllAuditEntries,
  getLastAuditEntry,
  storeLease,
  getLease,
  getUserLeases,
  deleteLease,
  deleteExpiredLeases,
} from '@/v2/storage';
import type { AuditEntryV2, LeaseRecord } from '@/v2/types';

// ============================================================================
// Test Setup
// ============================================================================

beforeEach(async () => {
  // Setup fake IndexedDB
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});

afterEach(() => {
  closeDB();
});

// ============================================================================
// Database Initialization Tests
// ============================================================================

describe('initDB', () => {
  it('should initialize database successfully', async () => {
    // Database already initialized in beforeEach
    // Just verify it doesn't throw
    await initDB();
  });

  it('should create all required object stores', async () => {
    // Verify stores exist by attempting to use them
    await expect(putMeta('test', 'value')).resolves.not.toThrow();
    await expect(getAllAuditEntries()).resolves.toBeDefined();
    await expect(getAllWrappedKeys()).resolves.toBeDefined();
  });

  it('should be idempotent (safe to call multiple times)', async () => {
    await initDB();
    await initDB();
    await initDB();
    // Should not throw
  });
});

// ============================================================================
// Key Storage Tests
// ============================================================================

describe('wrapKey and unwrapKey', () => {
  let wrappingKey: CryptoKey;

  beforeEach(async () => {
    // Generate a wrapping key (MKEK)
    wrappingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['encrypt', 'decrypt']
    );
  });

  it('should wrap and unwrap a key successfully', async () => {
    // Generate a key to wrap
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // extractable for testing
      ['sign', 'verify']
    );

    // Export public key for metadata
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

    // Wrap the private key
    await wrapKey(
      keyPair.privateKey,
      wrappingKey,
      'test-key-1',
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign'],
      {
        alg: 'ECDSA',
        purpose: 'test',
        publicKeyRaw,
      }
    );

    // Unwrap the key
    const unwrapped = await unwrapKey(
      'test-key-1',
      wrappingKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign']
    );

    expect(unwrapped).toBeDefined();
    expect(unwrapped.type).toBe('private');
    expect(unwrapped.algorithm.name).toBe('ECDSA');
  });

  it('should store wrapped key metadata correctly', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

    await wrapKey(
      keyPair.privateKey,
      wrappingKey,
      'vapid-1',
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign'],
      {
        alg: 'ES256',
        purpose: 'vapid',
        publicKeyRaw,
      }
    );

    const record = await getWrappedKey('vapid-1');
    expect(record).not.toBeNull();
    expect(record!.kid).toBe('vapid-1');
    expect(record!.alg).toBe('ES256');
    expect(record!.purpose).toBe('vapid');
    expect(record!.kmsVersion).toBe(2);
    expect(record!.createdAt).toBeGreaterThan(0);
    expect(record!.publicKeyRaw).toBeDefined();
  });

  it('should fail to unwrap with wrong wrapping key', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      keyPair.privateKey,
      wrappingKey,
      'test-key',
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign'],
      { alg: 'ECDSA', purpose: 'test' }
    );

    // Generate a different wrapping key
    const wrongKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Should fail to unwrap
    await expect(
      unwrapKey(
        'test-key',
        wrongKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        ['sign']
      )
    ).rejects.toThrow();
  });

  it('should throw when unwrapping non-existent key', async () => {
    await expect(
      unwrapKey(
        'non-existent',
        wrappingKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        ['sign']
      )
    ).rejects.toThrow('No wrapped key with id: non-existent');
  });
});

describe('getWrappedKey', () => {
  it('should return null for non-existent key', async () => {
    const result = await getWrappedKey('non-existent');
    expect(result).toBeNull();
  });

  it('should retrieve wrapped key without unwrapping', async () => {
    const wrappingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      keyPair.privateKey,
      wrappingKey,
      'test-key',
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign'],
      { alg: 'ECDSA', purpose: 'test' }
    );

    const record = await getWrappedKey('test-key');
    expect(record).not.toBeNull();
    expect(record!.kid).toBe('test-key');
    expect(record!.wrappedKey).toBeInstanceOf(ArrayBuffer);
  });
});

describe('getAllWrappedKeys', () => {
  it('should return empty array when no keys stored', async () => {
    const keys = await getAllWrappedKeys();
    expect(keys).toEqual([]);
  });

  it('should return all wrapped keys', async () => {
    const wrappingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Store multiple keys
    for (let i = 1; i <= 3; i++) {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );

      await wrapKey(
        keyPair.privateKey,
        wrappingKey,
        `key-${i}`,
        { name: 'ECDSA', namedCurve: 'P-256' },
        ['sign'],
        { alg: 'ECDSA', purpose: 'test' }
      );
    }

    const keys = await getAllWrappedKeys();
    expect(keys).toHaveLength(3);
    expect(keys.map(k => k.kid)).toEqual(['key-1', 'key-2', 'key-3']);
  });
});

describe('deleteWrappedKey', () => {
  it('should delete wrapped key', async () => {
    const wrappingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      keyPair.privateKey,
      wrappingKey,
      'to-delete',
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign'],
      { alg: 'ECDSA', purpose: 'test' }
    );

    // Verify key exists
    let record = await getWrappedKey('to-delete');
    expect(record).not.toBeNull();

    // Delete key
    await deleteWrappedKey('to-delete');

    // Verify key is gone
    record = await getWrappedKey('to-delete');
    expect(record).toBeNull();
  });

  it('should not throw when deleting non-existent key', async () => {
    await expect(deleteWrappedKey('non-existent')).resolves.not.toThrow();
  });
});

// ============================================================================
// Metadata Storage Tests
// ============================================================================

describe('putMeta and getMeta', () => {
  it('should store and retrieve metadata', async () => {
    await putMeta('test-key', 'test-value');
    const value = await getMeta<string>('test-key');
    expect(value).toBe('test-value');
  });

  it('should return null for non-existent key', async () => {
    const value = await getMeta('non-existent');
    expect(value).toBeNull();
  });

  it('should store complex objects', async () => {
    const obj = {
      foo: 'bar',
      nested: {
        a: 1,
        b: [2, 3, 4],
      },
    };

    await putMeta('complex', obj);
    const retrieved = await getMeta<typeof obj>('complex');
    expect(retrieved).toEqual(obj);
  });

  it('should overwrite existing value', async () => {
    await putMeta('key', 'value1');
    await putMeta('key', 'value2');

    const value = await getMeta<string>('key');
    expect(value).toBe('value2');
  });
});

describe('deleteMeta', () => {
  it('should delete metadata entry', async () => {
    await putMeta('to-delete', 'value');

    // Verify exists
    let value = await getMeta('to-delete');
    expect(value).not.toBeNull();

    // Delete
    await deleteMeta('to-delete');

    // Verify deleted
    value = await getMeta('to-delete');
    expect(value).toBeNull();
  });

  it('should not throw when deleting non-existent key', async () => {
    await expect(deleteMeta('non-existent')).resolves.not.toThrow();
  });
});

describe('getAllMeta', () => {
  it('should return empty array when no metadata', async () => {
    const entries = await getAllMeta();
    expect(entries).toEqual([]);
  });

  it('should return all metadata entries', async () => {
    await putMeta('key1', 'value1');
    await putMeta('key2', 'value2');
    await putMeta('key3', 'value3');

    const entries = await getAllMeta();
    expect(entries).toHaveLength(3);

    const keys = entries.map(e => e.key);
    expect(keys).toContain('key1');
    expect(keys).toContain('key2');
    expect(keys).toContain('key3');
  });
});

// ============================================================================
// Audit Log Tests
// ============================================================================

describe('storeAuditEntry and getAllAuditEntries', () => {
  it('should store and retrieve audit entries', async () => {
    const entry: AuditEntryV2 = {
      kmsVersion: 2,
      seqNum: 1,
      timestamp: Date.now(),
      op: 'setupPassphrase',
      kid: '',
      requestId: 'req-1',
      previousHash: '',
      chainHash: 'hash1',
      signature: 'sig1',
      auditKeyId: 'audit-key-1',
    };

    await storeAuditEntry(entry);

    const entries = await getAllAuditEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual(entry);
  });

  it('should maintain sequence order', async () => {
    // Store entries out of order by seqNum
    const entries: AuditEntryV2[] = [
      {
        kmsVersion: 2,
        seqNum: 3,
        timestamp: Date.now(),
        op: 'operation3',
        kid: '',
        requestId: 'req-3',
        previousHash: '',
        chainHash: 'hash3',
        signature: 'sig3',
        auditKeyId: 'audit-key',
      },
      {
        kmsVersion: 2,
        seqNum: 1,
        timestamp: Date.now(),
        op: 'operation1',
        kid: '',
        requestId: 'req-1',
        previousHash: '',
        chainHash: 'hash1',
        signature: 'sig1',
        auditKeyId: 'audit-key',
      },
      {
        kmsVersion: 2,
        seqNum: 2,
        timestamp: Date.now(),
        op: 'operation2',
        kid: '',
        requestId: 'req-2',
        previousHash: '',
        chainHash: 'hash2',
        signature: 'sig2',
        auditKeyId: 'audit-key',
      },
    ];

    for (const entry of entries) {
      await storeAuditEntry(entry);
    }

    const retrieved = await getAllAuditEntries();
    expect(retrieved).toHaveLength(3);

    // Should be sorted by seqNum
    expect(retrieved[0].seqNum).toBe(1);
    expect(retrieved[1].seqNum).toBe(2);
    expect(retrieved[2].seqNum).toBe(3);
  });
});

describe('getLastAuditEntry', () => {
  it('should return null when no entries', async () => {
    const last = await getLastAuditEntry();
    expect(last).toBeNull();
  });

  it('should return last entry by sequence number', async () => {
    const entries: AuditEntryV2[] = [
      {
        kmsVersion: 2,
        seqNum: 1,
        timestamp: Date.now(),
        op: 'op1',
        kid: '',
        requestId: 'req-1',
        previousHash: '',
        chainHash: 'hash1',
        signature: 'sig1',
        auditKeyId: 'audit-key',
      },
      {
        kmsVersion: 2,
        seqNum: 2,
        timestamp: Date.now(),
        op: 'op2',
        kid: '',
        requestId: 'req-2',
        previousHash: 'hash1',
        chainHash: 'hash2',
        signature: 'sig2',
        auditKeyId: 'audit-key',
      },
    ];

    for (const entry of entries) {
      await storeAuditEntry(entry);
    }

    const last = await getLastAuditEntry();
    expect(last).not.toBeNull();
    expect(last!.seqNum).toBe(2);
    expect(last!.op).toBe('op2');
  });
});

// ============================================================================
// Lease Storage Tests
// ============================================================================

describe('storeLease and getLease', () => {
  it('should store and retrieve lease', async () => {
    const lease: LeaseRecord = {
      leaseId: 'lease-1',
      userId: 'user-1',
      subs: [
        {
          url: 'https://example.com/push',
          aud: 'https://example.com',
          eid: 'endpoint-1',
        },
      ],
      ttlHours: 8,
      createdAt: Date.now(),
      exp: Date.now() + 8 * 60 * 60 * 1000,
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
    };

    await storeLease(lease);

    const retrieved = await getLease('lease-1');
    expect(retrieved).toEqual(lease);
  });

  it('should return null for non-existent lease', async () => {
    const lease = await getLease('non-existent');
    expect(lease).toBeNull();
  });
});

describe('getUserLeases', () => {
  it('should return empty array when user has no leases', async () => {
    const leases = await getUserLeases('user-1');
    expect(leases).toEqual([]);
  });

  it('should return all leases for a user', async () => {
    const now = Date.now();
    const leases: LeaseRecord[] = [
      {
        leaseId: 'lease-1',
        userId: 'user-1',
        subs: [],
        ttlHours: 8,
        createdAt: now,
        exp: now + 8 * 60 * 60 * 1000,
        quotas: {
          tokensPerHour: 100,
          sendsPerMinute: 10,
          burstSends: 50,
          sendsPerMinutePerEid: 5,
        },
      },
      {
        leaseId: 'lease-2',
        userId: 'user-1',
        subs: [],
        ttlHours: 8,
        createdAt: now,
        exp: now + 8 * 60 * 60 * 1000,
        quotas: {
          tokensPerHour: 100,
          sendsPerMinute: 10,
          burstSends: 50,
          sendsPerMinutePerEid: 5,
        },
      },
      {
        leaseId: 'lease-3',
        userId: 'user-2',
        subs: [],
        ttlHours: 8,
        createdAt: now,
        exp: now + 8 * 60 * 60 * 1000,
        quotas: {
          tokensPerHour: 100,
          sendsPerMinute: 10,
          burstSends: 50,
          sendsPerMinutePerEid: 5,
        },
      },
    ];

    for (const lease of leases) {
      await storeLease(lease);
    }

    const user1Leases = await getUserLeases('user-1');
    expect(user1Leases).toHaveLength(2);
    expect(user1Leases.map(l => l.leaseId)).toEqual(['lease-1', 'lease-2']);

    const user2Leases = await getUserLeases('user-2');
    expect(user2Leases).toHaveLength(1);
    expect(user2Leases[0].leaseId).toBe('lease-3');
  });
});

describe('deleteLease', () => {
  it('should delete lease', async () => {
    const lease: LeaseRecord = {
      leaseId: 'to-delete',
      userId: 'user-1',
      subs: [],
      ttlHours: 8,
      createdAt: Date.now(),
      exp: Date.now() + 8 * 60 * 60 * 1000,
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
    };

    await storeLease(lease);

    // Verify exists
    let retrieved = await getLease('to-delete');
    expect(retrieved).not.toBeNull();

    // Delete
    await deleteLease('to-delete');

    // Verify deleted
    retrieved = await getLease('to-delete');
    expect(retrieved).toBeNull();
  });

  it('should not throw when deleting non-existent lease', async () => {
    await expect(deleteLease('non-existent')).resolves.not.toThrow();
  });
});

describe('deleteExpiredLeases', () => {
  it('should return 0 when no expired leases', async () => {
    const now = Date.now();
    const lease: LeaseRecord = {
      leaseId: 'valid-lease',
      userId: 'user-1',
      subs: [],
      ttlHours: 8,
      createdAt: now,
      exp: now + 8 * 60 * 60 * 1000, // Future expiration
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
    };

    await storeLease(lease);

    const deleted = await deleteExpiredLeases();
    expect(deleted).toBe(0);

    // Lease should still exist
    const retrieved = await getLease('valid-lease');
    expect(retrieved).not.toBeNull();
  });

  it('should delete expired leases and return count', async () => {
    const now = Date.now();
    const expiredLease1: LeaseRecord = {
      leaseId: 'expired-1',
      userId: 'user-1',
      subs: [],
      ttlHours: 8,
      createdAt: now - 10 * 60 * 60 * 1000,
      exp: now - 2 * 60 * 60 * 1000, // Expired 2 hours ago
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
    };

    const expiredLease2: LeaseRecord = {
      leaseId: 'expired-2',
      userId: 'user-1',
      subs: [],
      ttlHours: 8,
      createdAt: now - 10 * 60 * 60 * 1000,
      exp: now - 1 * 60 * 60 * 1000, // Expired 1 hour ago
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
    };

    const validLease: LeaseRecord = {
      leaseId: 'valid',
      userId: 'user-1',
      subs: [],
      ttlHours: 8,
      createdAt: now,
      exp: now + 8 * 60 * 60 * 1000, // Future
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
    };

    await storeLease(expiredLease1);
    await storeLease(expiredLease2);
    await storeLease(validLease);

    const deleted = await deleteExpiredLeases();
    expect(deleted).toBe(2);

    // Expired leases should be gone
    expect(await getLease('expired-1')).toBeNull();
    expect(await getLease('expired-2')).toBeNull();

    // Valid lease should remain
    expect(await getLease('valid')).not.toBeNull();
  });
});
