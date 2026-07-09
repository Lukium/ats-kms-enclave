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
  clearAllStores,
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
  DB_NAME,
  DB_VERSION,
  migrateDatabase,
  wrapBlob,
  unwrapBlob,
  getSignalIdentity,
  putSignalIdentity,
  getSignalSignedPrekey,
  getSignalSignedPrekeys,
  putSignalSignedPrekey,
  getSignalOnetimePrekey,
  getSignalOnetimePrekeys,
  putSignalOnetimePrekeys,
  countUnconsumedOnetimePrekeys,
  getSignalSession,
  putSignalSession,
  deleteSignalSession,
  withSessionLock,
  getSignalTrustedIdentity,
  putSignalTrustedIdentity,
  getMessagingAccount,
  putMessagingAccount,
  deleteMessagingAccount,
  getMessagingContact,
  getMessagingContacts,
  putMessagingContact,
  deleteMessagingContact,
} from '@/v2/storage';
import type {
  AuditEntryV2,
  LeaseRecord,
  AuditDelegationCert,
  SignalOnetimePrekeyRecord,
} from '@/v2/types';

// ============================================================================
// Test Helpers
// ============================================================================

// Dummy LAK delegation certificate for testing
const DUMMY_LAK_CERT: AuditDelegationCert = {
  type: 'audit-delegation',
  version: 1,
  signerKind: 'LAK',
  leaseId: 'test-lease',
  delegatePub: 'test-pub-key',
  scope: ['vapid:issue'],
  notBefore: Date.now(),
  notAfter: Date.now() + 8 * 60 * 60 * 1000,
  codeHash: 'test-code-hash',
  manifestHash: 'test-manifest-hash',
  kmsVersion: 'v2.0.0',
  sig: 'test-signature',
};

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
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      true, // extractable for testing
      ['sign', 'verify']
    );

    // Export public key for metadata
    const publicKeyRaw = await crypto.subtle.exportKey('raw', (keyPair as CryptoKeyPair).publicKey);

    // Wrap the private key
    await wrapKey(
      (keyPair as CryptoKeyPair).privateKey,
      wrappingKey,
      'test-key-1',
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      ['sign']
    );

    expect(unwrapped).toBeDefined();
    expect(unwrapped.type).toBe('private');
    expect(unwrapped.algorithm.name).toBe('ECDSA');
  });

  it('should store wrapped key metadata correctly', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      true,
      ['sign', 'verify']
    );

    const publicKeyRaw = await crypto.subtle.exportKey('raw', (keyPair as CryptoKeyPair).publicKey);

    await wrapKey(
      (keyPair as CryptoKeyPair).privateKey,
      wrappingKey,
      'vapid-1',
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      (keyPair as CryptoKeyPair).privateKey,
      wrappingKey,
      'test-key',
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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
        { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
        ['sign']
      )
    ).rejects.toThrow();
  });

  it('should throw when unwrapping non-existent key', async () => {
    await expect(
      unwrapKey(
        'non-existent',
        wrappingKey,
        { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      (keyPair as CryptoKeyPair).privateKey,
      wrappingKey,
      'test-key',
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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
        { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
        true,
        ['sign', 'verify']
      );

      await wrapKey(
        (keyPair as CryptoKeyPair).privateKey,
        wrappingKey,
        `key-${i}`,
        { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      (keyPair as CryptoKeyPair).privateKey,
      wrappingKey,
      'to-delete',
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
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

describe('clearAllStores', () => {
  it('clears object stores but keeps the schema and connection usable', async () => {
    // Seed data (one store is enough — clearAllStores clears every store in one transaction).
    await putMeta('k1', 'v1');
    await putMeta('k2', 'v2');
    await putSignalIdentity({
      userId: 'u1',
    } as unknown as Parameters<typeof putSignalIdentity>[0]);
    expect((await getAllMeta()).length).toBeGreaterThanOrEqual(2);
    expect(await getSignalIdentity('u1')).not.toBeNull();

    // Clear everything.
    await clearAllStores();

    // Stores are empty across the board…
    expect(await getAllMeta()).toEqual([]);
    expect(await getSignalIdentity('u1')).toBeNull();

    // …and the connection is still open/usable (schema intact, no deleteDatabase teardown
    // that could wedge it): writing again works immediately.
    await putMeta('after-clear', 'ok');
    expect(await getAllMeta()).toHaveLength(1);
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
      userId: 'test-user',
      previousHash: '',
      chainHash: 'hash1',
      signer: 'UAK' as const,
      sig: 'sig1',
      signerId: 'audit-key-1',
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
        userId: 'test-user',
        previousHash: '',
        chainHash: 'hash3',
        signer: 'UAK' as const,
        sig: 'sig3',
        signerId: 'audit-key',
      },
      {
        kmsVersion: 2,
        seqNum: 1,
        timestamp: Date.now(),
        op: 'operation1',
        kid: '',
        requestId: 'req-1',
        userId: 'test-user',
        previousHash: '',
        chainHash: 'hash1',
        signer: 'UAK' as const,
        sig: 'sig1',
        signerId: 'audit-key',
      },
      {
        kmsVersion: 2,
        seqNum: 2,
        timestamp: Date.now(),
        op: 'operation2',
        kid: '',
        requestId: 'req-2',
        userId: 'test-user',
        previousHash: '',
        chainHash: 'hash2',
        signer: 'UAK' as const,
        sig: 'sig2',
        signerId: 'audit-key',
      },
    ];

    for (const entry of entries) {
      await storeAuditEntry(entry);
    }

    const retrieved = await getAllAuditEntries();
    expect(retrieved).toHaveLength(3);

    // Should be sorted by seqNum
    expect(retrieved[0]!.seqNum).toBe(1);
    expect(retrieved[1]!.seqNum).toBe(2);
    expect(retrieved[2]!.seqNum).toBe(3);
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
        userId: 'test-user',
        previousHash: '',
        chainHash: 'hash1',
        signer: 'UAK' as const,
        sig: 'sig1',
        signerId: 'audit-key',
      },
      {
        kmsVersion: 2,
        seqNum: 2,
        timestamp: Date.now(),
        op: 'op2',
        kid: '',
        requestId: 'req-2',
        userId: 'test-user',
        previousHash: 'hash1',
        chainHash: 'hash2',
        signer: 'UAK' as const,
        sig: 'sig2',
        signerId: 'audit-key',
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
      ttlHours: 8,
      createdAt: Date.now(),
      exp: Date.now() + 8 * 60 * 60 * 1000,
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
      wrappedLeaseKey: new ArrayBuffer(32),
      wrappedLeaseKeyIV: new ArrayBuffer(12),
      leaseSalt: new ArrayBuffer(32),
      kid: 'test-kid-1',
      lakDelegationCert: DUMMY_LAK_CERT,
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
        ttlHours: 8,
        createdAt: now,
        exp: now + 8 * 60 * 60 * 1000,
        quotas: {
          tokensPerHour: 100,
          sendsPerMinute: 10,
          burstSends: 50,
          sendsPerMinutePerEid: 5,
        },
        wrappedLeaseKey: new ArrayBuffer(32),
        wrappedLeaseKeyIV: new ArrayBuffer(12),
        leaseSalt: new ArrayBuffer(32),
        kid: 'test-kid',
        lakDelegationCert: DUMMY_LAK_CERT,
      },
      {
        leaseId: 'lease-2',
        userId: 'user-1',
        ttlHours: 8,
        createdAt: Date.now(),
        exp: Date.now() + 8 * 60 * 60 * 1000,
        quotas: {
          tokensPerHour: 100,
          sendsPerMinute: 10,
          burstSends: 50,
          sendsPerMinutePerEid: 5,
        },
        wrappedLeaseKey: new ArrayBuffer(32),
        wrappedLeaseKeyIV: new ArrayBuffer(12),
        leaseSalt: new ArrayBuffer(32),
        kid: 'test-kid-1',
        lakDelegationCert: DUMMY_LAK_CERT,
      },
    ];

    // Store all leases
    for (const lease of leases) {
      await storeLease(lease);
    }

    // Verify all leases are retrieved for user-1
    const userLeases = await getUserLeases('user-1');
    expect(userLeases).toHaveLength(2);
    expect(userLeases.map(l => l.leaseId).sort()).toEqual(['lease-1', 'lease-2']);
  });

  it('should not throw when deleting non-existent lease', async () => {
    await expect(deleteLease('non-existent')).resolves.not.toThrow();
  });
});

describe('deleteExpiredLeases', () => {
  it('should delete only expired leases', async () => {
    const now = Date.now();
    const expiredLease1: LeaseRecord = {
      leaseId: 'expired-1',
      userId: 'user-1',
      ttlHours: 8,
      createdAt: now - 10 * 60 * 60 * 1000,
      exp: now - 2 * 60 * 60 * 1000, // Expired 2 hours ago
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
      wrappedLeaseKey: new ArrayBuffer(32),
      wrappedLeaseKeyIV: new ArrayBuffer(12),
      leaseSalt: new ArrayBuffer(32),
      kid: 'test-kid',
      lakDelegationCert: DUMMY_LAK_CERT,
    };

    const expiredLease2: LeaseRecord = {
      leaseId: 'expired-2',
      userId: 'user-1',
      ttlHours: 8,
      createdAt: now - 5 * 60 * 60 * 1000,
      exp: now - 1 * 60 * 60 * 1000, // Expired 1 hour ago
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
      wrappedLeaseKey: new ArrayBuffer(32),
      wrappedLeaseKeyIV: new ArrayBuffer(12),
      leaseSalt: new ArrayBuffer(32),
      kid: 'test-kid',
      lakDelegationCert: DUMMY_LAK_CERT,
    };

    const validLease: LeaseRecord = {
      leaseId: 'valid',
      userId: 'user-1',
      ttlHours: 8,
      createdAt: now,
      exp: now + 8 * 60 * 60 * 1000, // Future
      quotas: {
        tokensPerHour: 100,
        sendsPerMinute: 10,
        burstSends: 50,
        sendsPerMinutePerEid: 5,
      },
      wrappedLeaseKey: new ArrayBuffer(32),
      wrappedLeaseKeyIV: new ArrayBuffer(12),
      leaseSalt: new ArrayBuffer(32),
      kid: 'test-kid',
      lakDelegationCert: DUMMY_LAK_CERT,
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

describe('wrapKey edge cases for branch coverage', () => {
  let wrappingKey: CryptoKey;

  beforeEach(async () => {
    wrappingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  });

  it('should handle wrapping an AES secret key (non-private key)', async () => {
    // Branch: key.type !== 'private' → use 'raw' format instead of 'pkcs8'
    const secretKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['encrypt', 'decrypt']
    );

    await wrapKey(
      secretKey,
      wrappingKey,
      'secret-key-1',
      { name: 'AES-GCM', length: 256 } as AlgorithmIdentifier,
      ['encrypt', 'decrypt'],
      { alg: 'AES-GCM', purpose: 'test-secret' }
    );

    const unwrapped = await unwrapKey(
      'secret-key-1',
      wrappingKey,
      { name: 'AES-GCM', length: 256 } as AlgorithmIdentifier,
      ['encrypt', 'decrypt']
    );

    expect(unwrapped).toBeDefined();
    expect(unwrapped.type).toBe('secret');
    expect(unwrapped.algorithm.name).toBe('AES-GCM');
  });

  it('should handle unwrapping with algorithm as object (not string)', async () => {
    // Branch: Algorithm object format detection in unwrapKey
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      (keyPair as CryptoKeyPair).privateKey,
      wrappingKey,
      'ecdsa-key-1',
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      ['sign'],
      { alg: 'ES256', purpose: 'test' }
    );

    // Unwrap with algorithm as object (not string)
    const unwrapped = await unwrapKey(
      'ecdsa-key-1',
      wrappingKey,
      { name: 'ECDSA', namedCurve: 'P-256' } as AlgorithmIdentifier,
      ['sign']
    );

    expect(unwrapped).toBeDefined();
    expect(unwrapped.type).toBe('private');
  });

  it('should handle unwrapping RSA key with object algorithm', async () => {
    // Branch: RSA algorithm handling in unwrapKey
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );

    await wrapKey(
      keyPair.privateKey,
      wrappingKey,
      'rsa-key-1',
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      } as AlgorithmIdentifier,
      ['sign'],
      { alg: 'PS256', purpose: 'test-rsa' }
    );

    const unwrapped = await unwrapKey(
      'rsa-key-1',
      wrappingKey,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      } as AlgorithmIdentifier,
      ['sign']
    );

    expect(unwrapped).toBeDefined();
    expect(unwrapped.type).toBe('private');
    expect(unwrapped.algorithm.name).toBe('RSA-PSS');
  });
});

// Import loadRateLimitState for testing
import { loadRateLimitState } from '../../src/v2/storage-types.js';

describe('loadRateLimitState', () => {
  it('should return valid state when input is valid', () => {
    const validState = {
      tokensIssued: 5,
      lastResetAt: Date.now(),
    };
    const result = loadRateLimitState(validState);
    expect(result).toEqual(validState);
  });

  it('should return default state when input is invalid', () => {
    const invalidState = { invalid: true };
    const result = loadRateLimitState(invalidState);
    expect(result).toMatchObject({
      tokensIssued: 0,
      lastResetAt: expect.any(Number),
    });
  });

  it('should return default state when input is null', () => {
    const result = loadRateLimitState(null);
    expect(result).toMatchObject({
      tokensIssued: 0,
      lastResetAt: expect.any(Number),
    });
  });

  it('should return default state when input is undefined', () => {
    const result = loadRateLimitState(undefined);
    expect(result).toMatchObject({
      tokensIssued: 0,
      lastResetAt: expect.any(Number),
    });
  });
});

// ============================================================================
// Schema Migration Tests (v1 -> v2)
// ============================================================================

describe('schema migration', () => {
  // Build a realistic v1 database (pre-Signal) containing a VAPID key, using
  // the production migration logic, then close it. The next initDB() upgrades.
  async function createV1DatabaseWithVapidKey(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const req = globalThis.indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = (): void => {
        migrateDatabase(req.result, 0, 1); // v1 stores only — no Signal stores
      };
      req.onsuccess = (): void => {
        const db = req.result;
        const tx = db.transaction('keys', 'readwrite');
        tx.objectStore('keys').put({
          kid: 'vapid-existing',
          kmsVersion: 2,
          wrappedKey: new ArrayBuffer(8),
          iv: new ArrayBuffer(12),
          aad: new ArrayBuffer(4),
          alg: 'ES256',
          purpose: 'vapid',
          createdAt: 1000,
        });
        tx.oncomplete = (): void => {
          db.close();
          resolve();
        };
        tx.onerror = (): void => reject(tx.error ?? new Error('seed tx failed'));
      };
      req.onerror = (): void => reject(req.error ?? new Error('open v1 failed'));
    });
  }

  it('DB_VERSION is 5', () => {
    expect(DB_VERSION).toBe(5);
  });

  it('a v1 database has no Signal stores', async () => {
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await createV1DatabaseWithVapidKey();

    const names = await new Promise<DOMStringList>((resolve, reject) => {
      const req = globalThis.indexedDB.open(DB_NAME, 1);
      req.onsuccess = (): void => {
        const names = req.result.objectStoreNames;
        req.result.close();
        resolve(names);
      };
      req.onerror = (): void => reject(req.error ?? new Error('open failed'));
    });
    expect(names.contains('keys')).toBe(true);
    expect(names.contains('signal-identity')).toBe(false);
  });

  it('upgrading v1 -> v2 preserves existing VAPID data and adds Signal stores', async () => {
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await createV1DatabaseWithVapidKey();

    // initDB() opens at DB_VERSION (2): runs only the v2 migration step.
    await initDB();

    // Existing VAPID key survived the upgrade.
    const vapid = await getWrappedKey('vapid-existing');
    expect(vapid).not.toBeNull();
    expect(vapid?.purpose).toBe('vapid');

    // New Signal stores are present and usable.
    await putSignalIdentity({
      userId: 'alice',
      registrationId: 42,
      wrappedIdentity: { ciphertext: new ArrayBuffer(8), iv: new ArrayBuffer(12), aad: new ArrayBuffer(4) },
      identityPubKey: new ArrayBuffer(33),
      identitySigningPubKey: new ArrayBuffer(32),
      createdAt: 2000,
    });
    expect((await getSignalIdentity('alice'))?.registrationId).toBe(42);
  });

  // Build a realistic v2 database (VAPID + a Signal identity) via the production
  // migration logic, then close it so the next initDB() upgrades v2 -> v3.
  async function createV2DatabaseWithSignalIdentity(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const req = globalThis.indexedDB.open(DB_NAME, 2);
      req.onupgradeneeded = (event): void => {
        migrateDatabase(req.result, event.oldVersion, 2); // v1 + v2 stores, no v3
      };
      req.onsuccess = (): void => {
        const db = req.result;
        const tx = db.transaction(['keys', 'signal-identity'], 'readwrite');
        tx.objectStore('keys').put({
          kid: 'vapid-existing',
          kmsVersion: 2,
          wrappedKey: new ArrayBuffer(8),
          iv: new ArrayBuffer(12),
          aad: new ArrayBuffer(4),
          alg: 'ES256',
          purpose: 'vapid',
          createdAt: 1000,
        });
        tx.objectStore('signal-identity').put({
          userId: 'alice',
          registrationId: 7,
          wrappedIdentity: { ciphertext: new ArrayBuffer(8), iv: new ArrayBuffer(12), aad: new ArrayBuffer(4) },
          identityPubKey: new ArrayBuffer(33),
          identitySigningPubKey: new ArrayBuffer(32),
          createdAt: 2000,
        });
        tx.oncomplete = (): void => {
          db.close();
          resolve();
        };
        tx.onerror = (): void => reject(tx.error ?? new Error('seed tx failed'));
      };
      req.onerror = (): void => reject(req.error ?? new Error('open v2 failed'));
    });
  }

  it('a v2 database has no messaging-account store', async () => {
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await createV2DatabaseWithSignalIdentity();

    const names = await new Promise<DOMStringList>((resolve, reject) => {
      const req = globalThis.indexedDB.open(DB_NAME, 2);
      req.onsuccess = (): void => {
        const n = req.result.objectStoreNames;
        req.result.close();
        resolve(n);
      };
      req.onerror = (): void => reject(req.error ?? new Error('open failed'));
    });
    expect(names.contains('signal-identity')).toBe(true);
    expect(names.contains('messaging-account')).toBe(false);
  });

  it('upgrading v2 -> v3 preserves Signal data and adds the account store', async () => {
    closeDB();
    globalThis.indexedDB = new IDBFactory();
    await createV2DatabaseWithSignalIdentity();

    // initDB() opens at DB_VERSION (3): runs only the v3 migration step.
    await initDB();

    // v2 data survived.
    expect((await getWrappedKey('vapid-existing'))?.purpose).toBe('vapid');
    expect((await getSignalIdentity('alice'))?.registrationId).toBe(7);

    // The new account store is present and usable.
    await putMessagingAccount({
      userId: 'alice',
      wrappedAccountRoot: { ciphertext: new ArrayBuffer(32), iv: new ArrayBuffer(12), aad: new ArrayBuffer(4) },
      createdAt: 3000,
    });
    expect((await getMessagingAccount('alice'))?.createdAt).toBe(3000);
  });
});

describe('messaging-account store', () => {
  it('put / get / delete round-trip; missing user is null', async () => {
    expect(await getMessagingAccount('nobody')).toBeNull();

    await putMessagingAccount({
      userId: 'bob',
      wrappedAccountRoot: { ciphertext: new ArrayBuffer(32), iv: new ArrayBuffer(12), aad: new ArrayBuffer(4) },
      createdAt: 4242,
    });
    const rec = await getMessagingAccount('bob');
    expect(rec?.userId).toBe('bob');
    expect(rec?.wrappedAccountRoot.ciphertext.byteLength).toBe(32);

    await deleteMessagingAccount('bob');
    expect(await getMessagingAccount('bob')).toBeNull();
  });
});

describe('messaging-contact store', () => {
  const blob = (): { ciphertext: ArrayBuffer; iv: ArrayBuffer; aad: ArrayBuffer } => ({
    ciphertext: new ArrayBuffer(32),
    iv: new ArrayBuffer(12),
    aad: new ArrayBuffer(4),
  });

  it('put / get / delete round-trip keyed by (user, peer)', async () => {
    expect(await getMessagingContact('alice', 'bob')).toBeNull();

    await putMessagingContact({ userId: 'alice', peerUserId: 'bob', wrappedSecret: blob(), createdAt: 1 });
    expect((await getMessagingContact('alice', 'bob'))?.peerUserId).toBe('bob');

    await deleteMessagingContact('alice', 'bob');
    expect(await getMessagingContact('alice', 'bob')).toBeNull();
  });

  it('lists all contacts for a user via the by-userId index', async () => {
    await putMessagingContact({ userId: 'alice', peerUserId: 'bob', wrappedSecret: blob(), createdAt: 1 });
    await putMessagingContact({ userId: 'alice', peerUserId: 'carol', wrappedSecret: blob(), createdAt: 2 });
    await putMessagingContact({ userId: 'dave', peerUserId: 'bob', wrappedSecret: blob(), createdAt: 3 });
    const peers = (await getMessagingContacts('alice')).map((r) => r.peerUserId).sort();
    expect(peers).toEqual(['bob', 'carol']);
  });
});

// ============================================================================
// wrapBlob / unwrapBlob Tests
// ============================================================================

describe('wrapBlob and unwrapBlob', () => {
  let mkek: CryptoKey;

  beforeEach(async () => {
    mkek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
  });

  it('round-trips arbitrary bytes', async () => {
    const plaintext = new TextEncoder().encode('ratchet-state-bytes').buffer;
    const aad = new TextEncoder().encode('{"type":"signal-session"}').buffer;

    const blob = await wrapBlob(plaintext, mkek, aad);
    expect(blob.iv.byteLength).toBe(12);

    const out = await unwrapBlob(blob, mkek);
    expect(new TextDecoder().decode(out)).toBe('ratchet-state-bytes');
  });

  it('fails to decrypt when the expected AAD does not match (context binding)', async () => {
    const plaintext = new TextEncoder().encode('secret').buffer;
    const aadAlice = new TextEncoder().encode('{"peer":"alice"}').buffer;
    const aadBob = new TextEncoder().encode('{"peer":"bob"}').buffer;

    const blob = await wrapBlob(plaintext, mkek, aadAlice);

    // Verifying against a different context's AAD must fail the GCM tag.
    await expect(unwrapBlob(blob, mkek, aadBob)).rejects.toThrow();
    // Verifying against the correct AAD succeeds.
    await expect(unwrapBlob(blob, mkek, aadAlice)).resolves.toBeInstanceOf(ArrayBuffer);
  });

  it('fails to decrypt under a different wrapping key', async () => {
    const blob = await wrapBlob(new ArrayBuffer(16), mkek, new ArrayBuffer(0));
    const otherKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
    await expect(unwrapBlob(blob, otherKey)).rejects.toThrow();
  });
});

// ============================================================================
// Signal Store CRUD Tests
// ============================================================================

describe('Signal messaging stores', () => {
  const blob = (): { ciphertext: ArrayBuffer; iv: ArrayBuffer; aad: ArrayBuffer } => ({
    ciphertext: new ArrayBuffer(16),
    iv: new ArrayBuffer(12),
    aad: new ArrayBuffer(4),
  });

  it('stores and retrieves identity by userId', async () => {
    await putSignalIdentity({
      userId: 'alice',
      registrationId: 7,
      wrappedIdentity: blob(),
      identityPubKey: new ArrayBuffer(33),
      identitySigningPubKey: new ArrayBuffer(32),
      createdAt: 1,
    });
    expect((await getSignalIdentity('alice'))?.registrationId).toBe(7);
    expect(await getSignalIdentity('nobody')).toBeNull();
  });

  it('isolates records by userId via compound keys', async () => {
    await putSignalSignedPrekey({
      userId: 'alice',
      keyId: 1,
      wrappedKeyPair: blob(),
      signedPubKey: new ArrayBuffer(33),
      signature: new ArrayBuffer(64),
      createdAt: 1,
      expiresAt: 2,
    });
    await putSignalSignedPrekey({
      userId: 'bob',
      keyId: 1, // same keyId, different user — must not collide
      wrappedKeyPair: blob(),
      signedPubKey: new ArrayBuffer(33),
      signature: new ArrayBuffer(64),
      createdAt: 1,
      expiresAt: 2,
    });

    expect(await getSignalSignedPrekey('alice', 1)).not.toBeNull();
    expect(await getSignalSignedPrekey('bob', 1)).not.toBeNull();
    expect(await getSignalSignedPrekeys('alice')).toHaveLength(1);
    expect(await getSignalSignedPrekeys('bob')).toHaveLength(1);
  });

  it('batches one-time prekeys and counts unconsumed', async () => {
    const records: SignalOnetimePrekeyRecord[] = Array.from({ length: 5 }, (_, i) => ({
      userId: 'alice',
      keyId: i,
      wrappedKeyPair: blob(),
      pubKey: new ArrayBuffer(33),
      consumed: i < 2, // first two already consumed
      createdAt: 1,
    }));
    await putSignalOnetimePrekeys(records);

    expect(await getSignalOnetimePrekeys('alice')).toHaveLength(5);
    expect(await countUnconsumedOnetimePrekeys('alice')).toBe(3);

    // Mark one more consumed.
    const pk = await getSignalOnetimePrekey('alice', 2);
    expect(pk).not.toBeNull();
    await putSignalOnetimePrekeys([{ ...pk!, consumed: true }]);
    expect(await countUnconsumedOnetimePrekeys('alice')).toBe(2);
  });

  it('stores, retrieves and deletes per-peer sessions', async () => {
    await putSignalSession({
      userId: 'alice',
      peerAddress: 'bob.1',
      wrappedSession: blob(),
      updatedAt: 10,
      messageCount: 0,
    });
    expect((await getSignalSession('alice', 'bob.1'))?.messageCount).toBe(0);

    await putSignalSession({
      userId: 'alice',
      peerAddress: 'bob.1',
      wrappedSession: blob(),
      updatedAt: 20,
      messageCount: 3,
    });
    expect((await getSignalSession('alice', 'bob.1'))?.messageCount).toBe(3);

    await deleteSignalSession('alice', 'bob.1');
    expect(await getSignalSession('alice', 'bob.1')).toBeNull();
  });

  it('stores TOFU trusted identities per peer', async () => {
    await putSignalTrustedIdentity({
      userId: 'alice',
      peerAddress: 'bob.1',
      identityPubKey: new ArrayBuffer(33),
      firstSeenAt: 1,
      updatedAt: 1,
    });
    expect(await getSignalTrustedIdentity('alice', 'bob.1')).not.toBeNull();
    expect(await getSignalTrustedIdentity('alice', 'carol.1')).toBeNull();
  });
});

describe('withSessionLock', () => {
  // A read-modify-write that loses updates without serialization: read the
  // session's messageCount, yield, then write count+1.
  async function unsafeIncrement(userId: string, peer: string): Promise<void> {
    const session = await getSignalSession(userId, peer);
    const count = session?.messageCount ?? 0;
    await new Promise((r) => setTimeout(r, 1)); // force interleaving window
    await putSignalSession({
      userId,
      peerAddress: peer,
      wrappedSession: { ciphertext: new ArrayBuffer(8), iv: new ArrayBuffer(12), aad: new ArrayBuffer(4) },
      updatedAt: 0,
      messageCount: count + 1,
    });
  }

  it('serializes concurrent operations on the same peer (no lost updates)', async () => {
    await Promise.all(
      Array.from({ length: 5 }, () => withSessionLock('alice', 'bob.1', () => unsafeIncrement('alice', 'bob.1')))
    );
    expect((await getSignalSession('alice', 'bob.1'))?.messageCount).toBe(5);
  });

  it('allows different peers to proceed concurrently', async () => {
    const order: string[] = [];
    await Promise.all([
      withSessionLock('alice', 'bob.1', async () => {
        await new Promise((r) => setTimeout(r, 5));
        order.push('bob');
      }),
      withSessionLock('alice', 'carol.1', async () => {
        order.push('carol'); // no contention with bob -> runs without waiting
      }),
    ]);
    // Carol (different peer) completed without waiting for Bob's 5ms hold.
    expect(order[0]).toBe('carol');
  });

  it('keeps a peer chain alive after an operation throws', async () => {
    await expect(
      withSessionLock('alice', 'bob.1', () => Promise.reject(new Error('boom')))
    ).rejects.toThrow('boom');
    // Subsequent op on the same peer still runs.
    const result = await withSessionLock('alice', 'bob.1', () => Promise.resolve('ok'));
    expect(result).toBe('ok');
  });
});
