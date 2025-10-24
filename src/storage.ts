/**
 * IndexedDB Storage Layer for KMS Enclave
 *
 * Manages three object stores:
 * - keys: Wrapped key storage
 * - audit: Audit log entries (hash-chained, signed)
 * - meta: Metadata (audit signing key, chain head, unlock config)
 *
 * @module storage
 */

/**
 * Wrapped key storage interface
 */
export interface WrappedKey {
  kid: string;
  wrappedKey: ArrayBuffer;
  wrapParams: WrapParams;
  wrappedAt: string; // ISO timestamp
  publicKeyRaw?: ArrayBuffer; // Optional: raw public key bytes (for asymmetric keys)
  alg?: string; // Optional: algorithm identifier (e.g., 'ES256')
  purpose?: string; // Optional: key purpose (e.g., 'vapid', 'signal')
}

/**
 * Key wrapping parameters
 */
export interface WrapParams {
  alg: 'AES-GCM';
  keySize: 256;
  salt: ArrayBufferLike;
  iv: ArrayBufferLike;
  iterations: number;
}

/**
 * Audit log entry interface
 */
export interface AuditEntry {
  version: 1;
  timestamp: string; // ISO timestamp
  op: 'setup' | 'unlock' | 'unwrap' | 'sign' | 'reset' | 'export_attempt' | 'generate_vapid';
  kid: string;
  requestId: string;
  origin: string;
  clientInfo: {
    ua: string;
    url: string;
  };
  prevHash: string;
  nonce: string;
  details?: Record<string, unknown>;
  sig: string;
}

/**
 * Meta store keys
 */
export type MetaKey =
  | 'auditSigningKey'
  | 'auditPublicKey'
  | 'chainHead'
  | 'unlockMethod'
  | 'unlockSalt' // Deprecated: use passphraseConfig or passkeyConfig
  | 'passphraseConfig'
  | 'passkeyConfig';

/**
 * Database name and version
 */
export const DB_NAME = 'kms-enclave';
const DB_VERSION = 1;

/**
 * IndexedDB database instance
 */
let db: IDBDatabase | null = null;

/**
 * Initialize the IndexedDB database
 *
 * Creates three object stores:
 * - keys (keyPath: kid)
 * - audit (autoIncrement: true, with indexes)
 * - meta (keyPath: key)
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

      // Create keys object store
      if (!database.objectStoreNames.contains('keys')) {
        database.createObjectStore('keys', { keyPath: 'kid' });
      }

      // Create audit object store with indexes
      if (!database.objectStoreNames.contains('audit')) {
        const auditStore = database.createObjectStore('audit', {
          autoIncrement: true,
        });
        auditStore.createIndex('by-kid', 'kid', { unique: false });
        auditStore.createIndex('by-op', 'op', { unique: false });
        auditStore.createIndex('by-timestamp', 'timestamp', { unique: false });
      }

      // Create meta object store
      if (!database.objectStoreNames.contains('meta')) {
        database.createObjectStore('meta', { keyPath: 'key' });
      }
    };
  });
}

/**
 * Get database instance (lazy initialization)
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
 * Close the database connection
 */
export function closeDB(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Generic get operation
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
 * Generic put operation
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
 * Generic delete operation
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
 * Generic getAll operation
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

// ============================================================
// Keys Object Store Operations
// ============================================================

/**
 * Store a wrapped key
 */
export async function putWrappedKey(wrappedKey: WrappedKey): Promise<void> {
  await put('keys', wrappedKey);
}

/**
 * Get a wrapped key by kid
 */
export async function getWrappedKey(
  kid: string
): Promise<WrappedKey | undefined> {
  return await get<WrappedKey>('keys', kid);
}

/**
 * Delete a wrapped key
 */
export async function deleteWrappedKey(kid: string): Promise<void> {
  await del('keys', kid);
}

/**
 * Get all wrapped keys
 */
export async function getAllWrappedKeys(): Promise<WrappedKey[]> {
  return await getAll<WrappedKey>('keys');
}

// ============================================================
// Audit Object Store Operations
// ============================================================

/**
 * Append an audit entry
 */
export async function putAuditEntry(entry: AuditEntry): Promise<void> {
  await put('audit', entry);
}

/**
 * Get all audit entries (sorted by timestamp)
 */
export async function getAllAuditEntries(): Promise<AuditEntry[]> {
  return await getAll<AuditEntry>('audit');
}

/**
 * Get last N audit entries (newest first)
 */
export async function getTailAuditEntries(n: number): Promise<AuditEntry[]> {
  const all = await getAllAuditEntries();
  // Sort by timestamp descending (newest first)
  all.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  return all.slice(0, n);
}

/**
 * Delete old audit entries (keep last N or last D days)
 */
export async function pruneAuditEntries(
  keepCount: number,
  keepDays: number
): Promise<number> {
  const all = await getAllAuditEntries();

  if (all.length <= keepCount) {
    return 0; // Nothing to prune
  }

  // Sort by timestamp descending
  all.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  // Calculate cutoff date
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - keepDays);
  const cutoffISO = cutoffDate.toISOString();

  // Keep entries that are:
  // 1. In the last N entries, OR
  // 2. Newer than D days
  const toDelete: IDBValidKey[] = [];
  for (let i = 0; i < all.length; i++) {
    const entry = all[i];
    if (entry && i >= keepCount && entry.timestamp < cutoffISO) {
      // Need to get the key for this entry using cursor
      toDelete.push(i); // Store index for now, will map to keys
    }
  }

  /* c8 ignore next 3 */
  if (toDelete.length === 0) {
    return 0;
  }

  // Delete old entries using cursor to get keys
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction('audit', 'readwrite');
    const store = transaction.objectStore('audit');
    const index = store.index('by-timestamp');
    const keys: IDBValidKey[] = [];
    let cursorIndex = 0;

    const cursorRequest = index.openCursor();

    cursorRequest.onsuccess = (event): void => {
      const cursor = (event.target as IDBRequest).result as IDBCursorWithValue | null;

      if (cursor) {
        // Check if this index should be deleted
        if (toDelete.includes(cursorIndex)) {
          keys.push(cursor.primaryKey);
        }
        cursorIndex++;
        cursor.continue();
      } else {
        // Done collecting keys, now delete them
        keys.forEach((key) => {
          store.delete(key);
        });
      }
    };

    transaction.oncomplete = (): void => {
      resolve(keys.length);
    };

    /* c8 ignore next 3 */
    transaction.onerror = (): void => {
      reject(new Error('Failed to prune audit entries'));
    };
  });
}

// ============================================================
// Meta Object Store Operations
// ============================================================

/**
 * Put a meta value
 */
export async function putMeta<T>(key: MetaKey, value: T): Promise<void> {
  await put('meta', { key, value });
}

/**
 * Get a meta value
 */
export async function getMeta<T>(key: MetaKey): Promise<T | undefined> {
  const result = await get<{ key: MetaKey; value: T }>('meta', key);
  return result?.value;
}

/**
 * Delete a meta value
 */
export async function deleteMeta(key: MetaKey): Promise<void> {
  await del('meta', key);
}

/**
 * Get all meta entries
 */
export async function getAllMeta(): Promise<
  Array<{ key: MetaKey; value: unknown }>
> {
  return await getAll<{ key: MetaKey; value: unknown }>('meta');
}

// ============================================================================
// Key Wrapping Operations
// ============================================================================

/**
 * Wrap a CryptoKey with AES-GCM and store it
 *
 * @param key - The CryptoKey to wrap (e.g., ECDSA private key)
 * @param unwrapKey - The AES-GCM key used for wrapping
 * @param kid - Key identifier
 * @param salt - Optional: Salt used in key derivation (16 bytes) - for metadata only
 * @param iterations - Optional: PBKDF2 iterations - for metadata only
 */
export async function wrapKey(
  key: CryptoKey,
  unwrapKey: CryptoKey,
  kid: string,
  salt?: Uint8Array,
  iterations?: number,
  options?: {
    publicKeyRaw?: ArrayBuffer; // Already exported public key bytes
    alg?: string;
    purpose?: string;
  }
): Promise<void> {
  // Generate random IV (12 bytes for AES-GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Wrap the key using AES-GCM
  // Use 'pkcs8' format for private keys (cannot use 'raw' for ECDSA/RSA keys)
  const wrappedKeyBytes = await crypto.subtle.wrapKey(
    'pkcs8',
    key,
    unwrapKey,
    { name: 'AES-GCM', iv }
  );

  // Create wrapped key object
  const wrapped: WrappedKey = {
    kid,
    wrappedKey: wrappedKeyBytes,
    wrapParams: {
      alg: 'AES-GCM',
      keySize: 256,
      salt: salt ? salt.buffer : new ArrayBuffer(0),
      iv: iv.buffer,
      iterations: iterations ?? 0,
    },
    wrappedAt: new Date().toISOString(),
    ...(options?.publicKeyRaw && { publicKeyRaw: options.publicKeyRaw }),
    ...(options?.alg && { alg: options.alg }),
    ...(options?.purpose && { purpose: options.purpose }),
  };

  // Store in IndexedDB
  await putWrappedKey(wrapped);
}

/**
 * Unwrap a stored key
 *
 * @param kid - Key identifier
 * @param unwrapKey - The AES-GCM key used for unwrapping
 * @param algorithm - The algorithm of the unwrapped key (e.g., { name: 'ECDSA', namedCurve: 'P-256' })
 * @returns The unwrapped CryptoKey (non-extractable)
 */
export async function unwrapKey(
  kid: string,
  unwrapKey: CryptoKey,
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm
): Promise<CryptoKey> {
  // Retrieve wrapped key from storage
  const wrapped = await getWrappedKey(kid);
  if (!wrapped) {
    throw new Error(`Key not found: ${kid}`);
  }

  // Unwrap the key using AES-GCM
  // Use 'pkcs8' format for private keys (matches wrapKey format)
  const key = await crypto.subtle.unwrapKey(
    'pkcs8',
    wrapped.wrappedKey,
    unwrapKey,
    { name: 'AES-GCM', iv: wrapped.wrapParams.iv as ArrayBuffer },
    algorithm,
    false, // non-extractable
    ['sign'] // usage
  );

  return key;
}
