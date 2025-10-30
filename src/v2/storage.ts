/**
 * IndexedDB Storage Layer for KMS V2
 *
 * Manages persistent storage for the KMS V2 implementation using IndexedDB.
 * Provides four object stores:
 * - config: Enrollment configurations (passphrase, passkey-prf, passkey-gate)
 * - keys: Wrapped application keys (VAPID, Signal, etc.)
 * - leases: VAPID lease records
 * - audit: Tamper-evident audit log entries
 *
 * All operations are asynchronous and return Promises. The module automatically
 * initializes the database on first use with lazy loading via getDB().
 */

import type { WrappedKey, KeyMetadata, AuditEntryV2, LeaseRecord } from './types';
import { buildKeyWrapAAD } from './crypto-utils';

// ============================================================================
// Database Configuration
// ============================================================================

export const DB_NAME = 'kms-v2';
const DB_VERSION = 1;

// Database instance (lazy initialized)
let db: IDBDatabase | null = null;

// ============================================================================
// Database Initialization
// ============================================================================

/**
 * Initialize IndexedDB database with required object stores.
 *
 * Creates four object stores:
 * - config: Enrollment configurations keyed by method (passphrase, passkey-prf, etc.)
 * - keys: Wrapped application keys keyed by kid
 * - leases: VAPID leases keyed by leaseId
 * - audit: Audit log with auto-increment key and indexes
 *
 * This function is idempotent and safe to call multiple times.
 */
export async function initDB(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error('Failed to open IndexedDB'));
    };

    request.onsuccess = (): void => {
      db = request.result;
      resolve();
    };

    request.onupgradeneeded = (event): void => {
      const database = (event.target as IDBOpenDBRequest).result;

      // Config store: enrollment configurations
      if (!database.objectStoreNames.contains('config')) {
        database.createObjectStore('config', { keyPath: 'method' });
      }

      // Keys store: wrapped application keys
      if (!database.objectStoreNames.contains('keys')) {
        const keyStore = database.createObjectStore('keys', { keyPath: 'kid' });
        keyStore.createIndex('by-purpose', 'purpose', { unique: false });
        keyStore.createIndex('by-createdAt', 'createdAt', { unique: false });
      }

      // Leases store: VAPID lease records
      if (!database.objectStoreNames.contains('leases')) {
        const leaseStore = database.createObjectStore('leases', { keyPath: 'leaseId' });
        leaseStore.createIndex('by-userId', 'userId', { unique: false });
        leaseStore.createIndex('by-exp', 'exp', { unique: false });
      }

      // Audit store: tamper-evident audit log
      if (!database.objectStoreNames.contains('audit')) {
        const auditStore = database.createObjectStore('audit', {
          autoIncrement: true,
        });
        auditStore.createIndex('by-seqNum', 'seqNum', { unique: true });
        auditStore.createIndex('by-timestamp', 'timestamp', { unique: false });
        auditStore.createIndex('by-op', 'op', { unique: false });
        auditStore.createIndex('by-kid', 'kid', { unique: false });
      }

      // Meta store: miscellaneous metadata (audit key, sequence counters, etc.)
      if (!database.objectStoreNames.contains('meta')) {
        database.createObjectStore('meta', { keyPath: 'key' });
      }
    };
  });
}

/**
 * Get database instance with lazy initialization.
 * Automatically calls initDB() if database not yet opened.
 */
async function getDB(): Promise<IDBDatabase> {
  if (!db) {
    await initDB();
  }
  /* c8 ignore next 3 */
  if (!db) {
    throw new Error('Database not initialized');
  }
  return db;
}

/**
 * Close the database connection.
 * Primarily used for cleanup in tests.
 */
export function closeDB(): void {
  if (db) {
    db.close();
    db = null;
  }
}

// ============================================================================
// Generic Storage Operations
// ============================================================================

/**
 * Generic get operation for any object store.
 */
async function get<T>(
  storeName: string,
  key: string | IDBKeyRange
): Promise<T | undefined> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readonly');
    const store = transaction.objectStore(storeName);
    const request = store.get(key);

    request.onsuccess = (): void => {
      resolve(request.result as T | undefined);
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error(`Failed to get from ${storeName}`));
    };
  });
}

/**
 * Generic put operation for any object store.
 */
async function put<T>(storeName: string, value: T): Promise<void> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = store.put(value);

    request.onsuccess = (): void => {
      resolve();
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error(`Failed to put to ${storeName}`));
    };
  });
}

/**
 * Generic delete operation for any object store.
 */
async function del(storeName: string, key: string | IDBKeyRange): Promise<void> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = store.delete(key);

    request.onsuccess = (): void => {
      resolve();
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error(`Failed to delete from ${storeName}`));
    };
  });
}

/**
 * Generic getAll operation for any object store.
 */
async function getAll<T>(storeName: string): Promise<T[]> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readonly');
    const store = transaction.objectStore(storeName);
    const request = store.getAll();

    request.onsuccess = (): void => {
      resolve(request.result as T[]);
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error(`Failed to getAll from ${storeName}`));
    };
  });
}

// ============================================================================
// Key Storage Operations
// ============================================================================

/**
 * Wrap (encrypt) a CryptoKey and persist it to IndexedDB.
 *
 * Exports the key as raw bytes, encrypts with AES-GCM under the wrapping key,
 * and stores the result with associated metadata. AAD binds the kid and
 * metadata to the ciphertext to prevent context swapping.
 *
 * @param key - The CryptoKey to wrap (must be extractable)
 * @param wrappingKey - The MKEK used to encrypt the key
 * @param kid - Unique key identifier
 * @param algorithm - Algorithm identifier for unwrapping
 * @param usages - Key usages for unwrapping
 * @param metadata - Key metadata (algorithm, purpose, public key)
 */
export async function wrapKey(
  key: CryptoKey,
  wrappingKey: CryptoKey,
  kid: string,
  _algorithm: AlgorithmIdentifier = key.algorithm,
  usages: KeyUsage[] = key.usages,
  metadata: KeyMetadata = { alg: 'unknown', purpose: 'unknown' }
): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const createdAt = Date.now();
  const aad = buildKeyWrapAAD({
    kmsVersion: 2,
    kid,
    alg: metadata.alg,
    purpose: metadata.purpose,
    createdAt,
    keyType: Array.isArray(usages) ? usages.join(',') : String(usages),
  });

  // Export key in appropriate format (pkcs8 for asymmetric, raw for symmetric)
  const format = key.type === 'private' ? 'pkcs8' : 'raw';
  const exportedKey = await crypto.subtle.exportKey(format, key);

  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    wrappingKey,
    exportedKey
  );

  // Build storage record
  const record: WrappedKey = {
    kid,
    kmsVersion: 2,
    wrappedKey: ciphertext,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
    aad,
    ...(metadata.publicKeyRaw !== undefined && { publicKeyRaw: metadata.publicKeyRaw }),
    alg: metadata.alg,
    purpose: metadata.purpose,
    createdAt,
  };

  // Persist to keys object store
  await put('keys', record);
}

/**
 * Unwrap (decrypt) a previously stored key.
 *
 * Retrieves the wrapped key record from IndexedDB, decrypts using the
 * wrapping key, and imports as a CryptoKey with specified algorithm and usages.
 *
 * @param kid - Key identifier
 * @param wrappingKey - The MKEK used to decrypt the key
 * @param algorithm - Algorithm for imported key
 * @param usages - Key usages for imported key
 * @returns Decrypted CryptoKey
 * @throws Error if key not found or decryption fails
 */
export async function unwrapKey(
  kid: string,
  wrappingKey: CryptoKey,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[] = []
): Promise<CryptoKey> {
  const record = await get<WrappedKey>('keys', kid);
  if (!record) {
    throw new Error(`No wrapped key with id: ${kid}`);
  }

  const iv = new Uint8Array(record.iv);
  const aad = record.aad;

  // Decrypt the wrapped key
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    wrappingKey,
    record.wrappedKey
  );

  // Determine import format based on algorithm
  // Asymmetric algorithms (ECDSA, ECDH, Ed25519, RSA-*) use pkcs8 for private keys
  // Symmetric algorithms (AES-*) use raw
  const algName = typeof algorithm === 'string' ? algorithm : (algorithm as { name: string }).name;
  const isAsymmetric = algName === 'ECDSA' || algName === 'ECDH' || algName === 'Ed25519' || algName.startsWith('RSA');
  const format = isAsymmetric ? 'pkcs8' : 'raw';

  // Import the key
  const key = await crypto.subtle.importKey(
    format,
    decrypted,
    algorithm,
    false, // extractable
    usages
  );

  return key;
}

/**
 * Retrieve wrapped key record without unwrapping.
 *
 * @param kid - Key identifier
 * @returns WrappedKey record or null if not found
 */
export async function getWrappedKey(kid: string): Promise<WrappedKey | null> {
  const record = await get<WrappedKey>('keys', kid);
  return record ?? null;
}

/**
 * Retrieve all wrapped key records.
 *
 * @returns Array of all WrappedKey records
 */
export async function getAllWrappedKeys(): Promise<WrappedKey[]> {
  return getAll<WrappedKey>('keys');
}

/**
 * Delete a wrapped key record.
 *
 * @param kid - Key identifier to delete
 */
export async function deleteWrappedKey(kid: string): Promise<void> {
  await del('keys', kid);
}

// ============================================================================
// Metadata Storage Operations
// ============================================================================

/**
 * Get metadata value from meta store.
 *
 * @param key - Metadata key
 * @returns Value or null if not found
 */
export async function getMeta<T>(key: string): Promise<T | null> {
  const record = await get<{ key: string; value: T }>('meta', key);
  return record ? record.value : null;
}

/**
 * Put metadata value to meta store.
 *
 * @param key - Metadata key
 * @param value - Value to store
 */
export async function putMeta(key: string, value: unknown): Promise<void> {
  await put('meta', { key, value });
}

/**
 * Delete metadata entry.
 *
 * @param key - Metadata key to delete
 */
export async function deleteMeta(key: string): Promise<void> {
  await del('meta', key);
}

/**
 * Get all metadata entries.
 *
 * @returns Array of {key, value} pairs
 */
export async function getAllMeta(): Promise<Array<{ key: string; value: unknown }>> {
  const records = await getAll<{ key: string; value: unknown }>('meta');
  return records;
}

// ============================================================================
// Audit Log Storage Operations
// ============================================================================

/**
 * Append audit entry to the audit log.
 *
 * Entries are always appended with auto-increment keys to preserve order.
 * The seqNum field provides logical ordering independent of storage keys.
 *
 * @param entry - Audit entry to store
 */
export async function storeAuditEntry(entry: AuditEntryV2): Promise<void> {
  await put('audit', entry);
}

/**
 * Retrieve all audit entries in sequence number order.
 *
 * @returns Array of audit entries sorted by seqNum
 */
export async function getAllAuditEntries(): Promise<AuditEntryV2[]> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction('audit', 'readonly');
    const store = transaction.objectStore('audit');
    const index = store.index('by-seqNum');
    const request = index.getAll();

    request.onsuccess = (): void => {
      resolve(request.result as AuditEntryV2[]);
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error('Failed to get audit entries'));
    };
  });
}

/**
 * Retrieve the last audit entry by sequence number.
 *
 * @returns Most recent audit entry or null if log is empty
 */
export async function getLastAuditEntry(): Promise<AuditEntryV2 | null> {
  const entries = await getAllAuditEntries();
  return entries.length > 0 ? entries[entries.length - 1]! : null;
}

// ============================================================================
// Lease Storage Operations
// ============================================================================

/**
 * Store a VAPID lease record.
 *
 * @param lease - Lease record to store
 */
export async function storeLease(lease: LeaseRecord): Promise<void> {
  await put('leases', lease);
}

/**
 * Retrieve a lease by ID.
 *
 * @param leaseId - Lease identifier
 * @returns Lease record or null if not found
 */
export async function getLease(leaseId: string): Promise<LeaseRecord | null> {
  const record = await get<LeaseRecord>('leases', leaseId);
  return record ?? null;
}

/**
 * Get all leases for a user.
 *
 * @param userId - User identifier
 * @returns Array of lease records for the user
 */
export async function getUserLeases(userId: string): Promise<LeaseRecord[]> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction('leases', 'readonly');
    const store = transaction.objectStore('leases');
    const index = store.index('by-userId');
    const request = index.getAll(userId);

    request.onsuccess = (): void => {
      resolve(request.result as LeaseRecord[]);
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error('Failed to get user leases'));
    };
  });
}

/**
 * Delete a lease.
 *
 * @param leaseId - Lease identifier to delete
 */
export async function deleteLease(leaseId: string): Promise<void> {
  await del('leases', leaseId);
}

/**
 * Delete all expired leases.
 *
 * @returns Number of leases deleted
 */
export async function deleteExpiredLeases(): Promise<number> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction('leases', 'readwrite');
    const store = transaction.objectStore('leases');
    const index = store.index('by-exp');
    const now = Date.now();

    // Get all leases with exp < now
    const range = IDBKeyRange.upperBound(now);
    const request = index.openCursor(range);
    let deleted = 0;

    request.onsuccess = (event): void => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
      if (cursor) {
        cursor.delete();
        deleted++;
        cursor.continue();
      } else {
        resolve(deleted);
      }
    };

    /* c8 ignore next 3 */
    request.onerror = (): void => {
      reject(new Error('Failed to delete expired leases'));
    };
  });
}
