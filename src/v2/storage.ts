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

import type {
  WrappedKey,
  KeyMetadata,
  AuditEntryV2,
  LeaseRecord,
  StoredPushSubscription,
  WrappedBlob,
  SignalIdentityRecord,
  SignalSignedPrekeyRecord,
  SignalOnetimePrekeyRecord,
  SignalSessionRecord,
  SignalTrustedIdentityRecord,
  MessagingAccountRecord,
  MessagingContactRecord,
  MessagingInviteRecord,
} from './types';
import { buildKeyWrapAAD } from './crypto-utils';

// ============================================================================
// Database Configuration
// ============================================================================

export const DB_NAME = 'kms-v2';
/**
 * Current schema version. v2 added the Signal messaging stores; v3 the per-device
 * account-root store; v4 the per-contact pairing-secret store (secure-messaging
 * §5). Every increment must add a numbered entry to {@link MIGRATIONS}.
 */
export const DB_VERSION = 5;

/** Names of the Signal messaging object stores (added in v2). */
export type SignalStoreName =
  | 'signal-identity'
  | 'signal-signed-prekey'
  | 'signal-onetime-prekey'
  | 'signal-session'
  | 'signal-trusted-identity';

/**
 * Ordered schema migrations keyed by the version they upgrade the database TO.
 * Each runs inside the single `versionchange` transaction. Migrations are
 * create-if-absent so they are safe to re-run, and {@link migrateDatabase}
 * applies only those strictly greater than the database's existing version —
 * so an existing v1 database (real users with VAPID/push data) only runs the
 * v2 step and keeps all prior data.
 */
const MIGRATIONS: Record<number, (db: IDBDatabase) => void> = {
  // v1: original VAPID/push + audit schema.
  1: (database) => {
    if (!database.objectStoreNames.contains('config')) {
      database.createObjectStore('config', { keyPath: 'method' });
    }
    if (!database.objectStoreNames.contains('keys')) {
      const keyStore = database.createObjectStore('keys', { keyPath: 'kid' });
      keyStore.createIndex('by-purpose', 'purpose', { unique: false });
      keyStore.createIndex('by-createdAt', 'createdAt', { unique: false });
    }
    if (!database.objectStoreNames.contains('leases')) {
      const leaseStore = database.createObjectStore('leases', { keyPath: 'leaseId' });
      leaseStore.createIndex('by-userId', 'userId', { unique: false });
      leaseStore.createIndex('by-exp', 'exp', { unique: false });
    }
    if (!database.objectStoreNames.contains('audit')) {
      const auditStore = database.createObjectStore('audit', { autoIncrement: true });
      auditStore.createIndex('by-seqNum', 'seqNum', { unique: true });
      auditStore.createIndex('by-timestamp', 'timestamp', { unique: false });
      auditStore.createIndex('by-op', 'op', { unique: false });
      auditStore.createIndex('by-kid', 'kid', { unique: false });
    }
    if (!database.objectStoreNames.contains('meta')) {
      database.createObjectStore('meta', { keyPath: 'key' });
    }
  },
  // v2: Signal messaging stores. Compound keys scope every record to a user so
  // the single-user-per-origin assumption is no longer baked into queries.
  // NOTE: `consumed` is intentionally NOT indexed (IndexedDB keys cannot be
  // boolean); unconsumed prekeys are filtered in code over the `by-userId` set.
  2: (database) => {
    if (!database.objectStoreNames.contains('signal-identity')) {
      database.createObjectStore('signal-identity', { keyPath: 'userId' });
    }
    if (!database.objectStoreNames.contains('signal-signed-prekey')) {
      const store = database.createObjectStore('signal-signed-prekey', {
        keyPath: ['userId', 'keyId'],
      });
      store.createIndex('by-userId', 'userId', { unique: false });
    }
    if (!database.objectStoreNames.contains('signal-onetime-prekey')) {
      const store = database.createObjectStore('signal-onetime-prekey', {
        keyPath: ['userId', 'keyId'],
      });
      store.createIndex('by-userId', 'userId', { unique: false });
    }
    if (!database.objectStoreNames.contains('signal-session')) {
      const store = database.createObjectStore('signal-session', {
        keyPath: ['userId', 'peerAddress'],
      });
      store.createIndex('by-userId', 'userId', { unique: false });
    }
    if (!database.objectStoreNames.contains('signal-trusted-identity')) {
      const store = database.createObjectStore('signal-trusted-identity', {
        keyPath: ['userId', 'peerAddress'],
      });
      store.createIndex('by-userId', 'userId', { unique: false });
    }
  },
  // v3: per-device account-root store (secure-messaging §18). One MKEK-wrapped
  // accountRoot per user; additive, leaves all v2 Signal data untouched.
  3: (database) => {
    if (!database.objectStoreNames.contains('messaging-account')) {
      database.createObjectStore('messaging-account', { keyPath: 'userId' });
    }
  },
  // v4: per-contact pairing-secret store (secure-messaging §5). Compound key
  // scopes each secret to (userId, peerUserId); additive.
  4: (database) => {
    if (!database.objectStoreNames.contains('messaging-contact')) {
      const store = database.createObjectStore('messaging-contact', {
        keyPath: ['userId', 'peerUserId'],
      });
      store.createIndex('by-userId', 'userId', { unique: false });
    }
  },
  // v5: armed Connect invites (rooms-and-trust §3.2/§3.3). The room secret is
  // wrapped under the messagingKEK so an armed invite survives the app closing —
  // a link the peer opens LATER must still land. Keyed by inviteId, indexed by
  // userId; additive, leaves all prior data untouched.
  5: (database) => {
    if (!database.objectStoreNames.contains('messaging-invite')) {
      const store = database.createObjectStore('messaging-invite', { keyPath: 'inviteId' });
      store.createIndex('by-userId', 'userId', { unique: false });
    }
  },
};

/**
 * Apply every migration whose target version is in (oldVersion, newVersion].
 * Exported so tests can construct a realistic prior-version database.
 */
export function migrateDatabase(
  database: IDBDatabase,
  oldVersion: number,
  newVersion: number
): void {
  for (let v = oldVersion + 1; v <= newVersion; v++) {
    MIGRATIONS[v]?.(database);
  }
}

// Database instance (lazy initialized)
let db: IDBDatabase | null = null;

// ============================================================================
// Database Initialization
// ============================================================================

/**
 * Initialize IndexedDB database, applying any pending schema migrations.
 *
 * Object stores (see {@link MIGRATIONS}):
 * - v1: `config`, `keys`, `leases`, `audit`, `meta`
 * - v2: `signal-identity`, `signal-signed-prekey`, `signal-onetime-prekey`,
 *       `signal-session`, `signal-trusted-identity`
 * - v3: `messaging-account`
 * - v4: `messaging-contact`
 * - v5: `messaging-invite`
 *
 * This function is idempotent and safe to call multiple times. Upgrading an
 * existing database only runs the newer migrations and preserves prior data.
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
      // Apply only the migrations newer than the database's current version,
      // so existing v1 data (VAPID keys, leases, audit log) is preserved.
      migrateDatabase(database, event.oldVersion, DB_VERSION);
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

/**
 * Clear every record from all object stores WITHOUT deleting the database.
 *
 * Used by KMS reset. Unlike `indexedDB.deleteDatabase()`, clearing stores runs in an
 * ordinary readwrite transaction on the already-open connection, so it can NEVER be
 * blocked by another open connection to `kms-v2` (a second app tab, or the fullSetup
 * popup's own enclave worker). `deleteDatabase()` fires `onblocked` in that situation
 * and, if the reset awaits it, hangs forever — leaving the database wedged so every
 * subsequent `open()` (isSetup / fullSetup) queues behind the stuck delete and also
 * hangs. That is the "reset → No active popup window reference" bug. Clearing the stores
 * wipes all user data (keys, leases, enrollments, audit chain, signal/messaging state)
 * while keeping the current v4 schema, which is exactly what a reset needs.
 */
export async function clearAllStores(): Promise<void> {
  const database = await getDB();
  const storeNames = Array.from(database.objectStoreNames);
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeNames, 'readwrite');
    transaction.oncomplete = (): void => resolve();
    /* c8 ignore next 6 */
    transaction.onerror = (): void => {
      reject(new Error(`Failed to clear stores: ${transaction.error?.message ?? 'unknown'}`));
    };
    transaction.onabort = (): void => {
      reject(new Error(`Clear-stores transaction aborted: ${transaction.error?.message ?? 'unknown'}`));
    };
    for (const name of storeNames) {
      transaction.objectStore(name).clear();
    }
  });
}

// ============================================================================
// Generic Storage Operations
// ============================================================================

/**
 * Generic get operation for any object store.
 */
async function get<T>(
  storeName: string,
  key: IDBValidKey | IDBKeyRange
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
async function del(storeName: string, key: IDBValidKey | IDBKeyRange): Promise<void> {
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
  const algName = typeof algorithm === 'string' ? algorithm : (algorithm).name;
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
// Signal Messaging Storage (Phase 6)
// ============================================================================

/**
 * Encrypt arbitrary BYTES into an MKEK-wrapped blob.
 *
 * Unlike {@link wrapKey} (which wraps a CryptoKey), this wraps opaque secret
 * bytes — Signal private keys and serialised Double Ratchet state, which must
 * remain readable to advance the ratchet. The supplied `aad` binds the blob to
 * its context (e.g. {type,userId,peerAddress}); decryption requires the same
 * AAD, so a blob cannot be transplanted into another context.
 *
 * @param plaintext - Secret bytes to encrypt
 * @param wrappingKey - The MKEK (AES-GCM)
 * @param aad - Context-binding Additional Authenticated Data
 */
export async function wrapBlob(
  plaintext: ArrayBuffer | Uint8Array,
  wrappingKey: CryptoKey,
  aad: ArrayBuffer
): Promise<WrappedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    wrappingKey,
    plaintext as BufferSource
  );
  return {
    ciphertext,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
    aad,
  };
}

/**
 * Decrypt an MKEK-wrapped blob back to bytes.
 *
 * Verification uses `expectedAad` when provided (the caller should recompute it
 * from the record's context so a swapped blob fails the GCM tag), otherwise the
 * AAD stored alongside the blob.
 *
 * @throws if the wrapping key or AAD is wrong (AES-GCM authentication failure)
 */
export async function unwrapBlob(
  blob: WrappedBlob,
  wrappingKey: CryptoKey,
  expectedAad?: ArrayBuffer
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(blob.iv), additionalData: expectedAad ?? blob.aad },
    wrappingKey,
    blob.ciphertext
  );
}

/**
 * Generic indexed query over a store (e.g. all records for a given userId).
 */
async function getAllByIndex<T>(
  storeName: SignalStoreName | 'messaging-contact' | 'messaging-invite',
  indexName: string,
  query: IDBValidKey | IDBKeyRange
): Promise<T[]> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readonly');
    const request = transaction.objectStore(storeName).index(indexName).getAll(query);
    request.onsuccess = (): void => resolve(request.result as T[]);
    /* c8 ignore next 3 */
    request.onerror = (): void => reject(new Error(`Failed to query ${storeName}.${indexName}`));
  });
}

// -- Identity (one per user) --------------------------------------------------

export async function getSignalIdentity(userId: string): Promise<SignalIdentityRecord | null> {
  return (await get<SignalIdentityRecord>('signal-identity', userId)) ?? null;
}

export async function putSignalIdentity(record: SignalIdentityRecord): Promise<void> {
  await put('signal-identity', record);
}

// -- Signed prekeys -----------------------------------------------------------

export async function getSignalSignedPrekey(
  userId: string,
  keyId: number
): Promise<SignalSignedPrekeyRecord | null> {
  return (await get<SignalSignedPrekeyRecord>('signal-signed-prekey', [userId, keyId])) ?? null;
}

export async function getSignalSignedPrekeys(
  userId: string
): Promise<SignalSignedPrekeyRecord[]> {
  return getAllByIndex<SignalSignedPrekeyRecord>('signal-signed-prekey', 'by-userId', userId);
}

export async function putSignalSignedPrekey(record: SignalSignedPrekeyRecord): Promise<void> {
  await put('signal-signed-prekey', record);
}

export async function deleteSignalSignedPrekey(userId: string, keyId: number): Promise<void> {
  await del('signal-signed-prekey', [userId, keyId]);
}

// -- One-time prekeys ---------------------------------------------------------

export async function getSignalOnetimePrekey(
  userId: string,
  keyId: number
): Promise<SignalOnetimePrekeyRecord | null> {
  return (await get<SignalOnetimePrekeyRecord>('signal-onetime-prekey', [userId, keyId])) ?? null;
}

/** All one-time prekeys for a user (consumed and unconsumed). */
export async function getSignalOnetimePrekeys(
  userId: string
): Promise<SignalOnetimePrekeyRecord[]> {
  return getAllByIndex<SignalOnetimePrekeyRecord>('signal-onetime-prekey', 'by-userId', userId);
}

/** Count unconsumed one-time prekeys for a user (drives top-up). */
export async function countUnconsumedOnetimePrekeys(userId: string): Promise<number> {
  const all = await getSignalOnetimePrekeys(userId);
  return all.filter((pk) => !pk.consumed).length;
}

export async function putSignalOnetimePrekey(record: SignalOnetimePrekeyRecord): Promise<void> {
  await put('signal-onetime-prekey', record);
}

/** Persist a batch of one-time prekeys in a single transaction. */
export async function putSignalOnetimePrekeys(
  records: SignalOnetimePrekeyRecord[]
): Promise<void> {
  const database = await getDB();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction('signal-onetime-prekey', 'readwrite');
    const store = transaction.objectStore('signal-onetime-prekey');
    for (const record of records) {
      store.put(record);
    }
    transaction.oncomplete = (): void => resolve();
    /* c8 ignore next 3 */
    transaction.onerror = (): void =>
      reject(transaction.error ?? new Error('Failed to store one-time prekeys'));
  });
}

// -- Sessions (per-peer Double Ratchet state) ---------------------------------

/**
 * Per-(user,peer) serialization gate for ratchet operations.
 *
 * A Double Ratchet advance is a read-modify-write: unwrap session -> cipher ->
 * rewrap -> put. Those steps span multiple async ticks, so two concurrent
 * messages to the SAME peer could read the same session, both advance from it,
 * and the second write would clobber the first — silently corrupting the
 * ratchet. {@link withSessionLock} serialises operations per peer (different
 * peers still run concurrently). This complements — it does not duplicate — the
 * crypto library's internal session lock, which only covers the cipher step,
 * not our unwrap/rewrap storage steps.
 */
const sessionLocks = new Map<string, Promise<unknown>>();

export function withSessionLock<T>(
  userId: string,
  peerAddress: string,
  fn: () => Promise<T>
): Promise<T> {
  const key = `${userId} ${peerAddress}`;
  const prev = sessionLocks.get(key) ?? Promise.resolve();
  const result = prev.then(() => fn());
  // Tail must never reject, or a failed op would wedge the peer's chain.
  const tail = result.catch(() => undefined);
  sessionLocks.set(key, tail);
  // Drop the entry once this is the last queued op, to bound map growth.
  void tail.then(() => {
    if (sessionLocks.get(key) === tail) {
      sessionLocks.delete(key);
    }
  });
  return result;
}

export async function getSignalSession(
  userId: string,
  peerAddress: string
): Promise<SignalSessionRecord | null> {
  return (await get<SignalSessionRecord>('signal-session', [userId, peerAddress])) ?? null;
}

export async function getSignalSessions(userId: string): Promise<SignalSessionRecord[]> {
  return getAllByIndex<SignalSessionRecord>('signal-session', 'by-userId', userId);
}

export async function putSignalSession(record: SignalSessionRecord): Promise<void> {
  await put('signal-session', record);
}

export async function deleteSignalSession(userId: string, peerAddress: string): Promise<void> {
  await del('signal-session', [userId, peerAddress]);
}

// -- Trusted peer identities (TOFU) -------------------------------------------

export async function getSignalTrustedIdentity(
  userId: string,
  peerAddress: string
): Promise<SignalTrustedIdentityRecord | null> {
  return (
    (await get<SignalTrustedIdentityRecord>('signal-trusted-identity', [userId, peerAddress])) ??
    null
  );
}

export async function putSignalTrustedIdentity(
  record: SignalTrustedIdentityRecord
): Promise<void> {
  await put('signal-trusted-identity', record);
}

// -- Account root (secure-messaging §18; one per user) ------------------------

export async function getMessagingAccount(
  userId: string
): Promise<MessagingAccountRecord | null> {
  return (await get<MessagingAccountRecord>('messaging-account', userId)) ?? null;
}

export async function putMessagingAccount(record: MessagingAccountRecord): Promise<void> {
  await put('messaging-account', record);
}

export async function deleteMessagingAccount(userId: string): Promise<void> {
  await del('messaging-account', userId);
}

// -- Contact pairing secrets (secure-messaging §5; one per [user, peer]) ------

export async function getMessagingContact(
  userId: string,
  peerUserId: string
): Promise<MessagingContactRecord | null> {
  return (await get<MessagingContactRecord>('messaging-contact', [userId, peerUserId])) ?? null;
}

export async function getMessagingContacts(userId: string): Promise<MessagingContactRecord[]> {
  return getAllByIndex<MessagingContactRecord>('messaging-contact', 'by-userId', userId);
}

export async function putMessagingContact(record: MessagingContactRecord): Promise<void> {
  await put('messaging-contact', record);
}

export async function deleteMessagingContact(userId: string, peerUserId: string): Promise<void> {
  await del('messaging-contact', [userId, peerUserId]);
}

// ============================================================================
// Messaging Invite Storage Operations (rooms-and-trust §3.2/§3.3)
// ============================================================================

export async function getMessagingInvite(inviteId: string): Promise<MessagingInviteRecord | null> {
  return (await get<MessagingInviteRecord>('messaging-invite', inviteId)) ?? null;
}

export async function getMessagingInvites(userId: string): Promise<MessagingInviteRecord[]> {
  return getAllByIndex<MessagingInviteRecord>('messaging-invite', 'by-userId', userId);
}

export async function putMessagingInvite(record: MessagingInviteRecord): Promise<void> {
  await put('messaging-invite', record);
}

export async function deleteMessagingInvite(inviteId: string): Promise<void> {
  await del('messaging-invite', inviteId);
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

// ============================================================================
// Push Subscription Storage Operations
// ============================================================================

/**
 * Set push subscription for the current VAPID key.
 *
 * This updates the subscription field of the VAPID key record. There can only
 * be one VAPID key (enforced by getVAPIDKid logic), and only one subscription
 * per VAPID key.
 *
 * @param subscription - Push subscription data from PushManager.subscribe()
 * @throws Error if no VAPID key found or multiple VAPID keys exist
 */
export async function setPushSubscription(subscription: StoredPushSubscription): Promise<void> {
  // Get all keys and find the VAPID key
  const allKeys = await getAllWrappedKeys();
  const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');

  if (vapidKeys.length === 0) {
    throw new Error('No VAPID key found. Generate a VAPID key first.');
  }

  if (vapidKeys.length > 1) {
    throw new Error('Multiple VAPID keys found. Cannot determine which to update.');
  }

  const vapidKey = vapidKeys[0];
  if (!vapidKey) {
    throw new Error('No VAPID key found after filtering');
  }

  // Update the VAPID key record with the subscription
  const updatedKey: WrappedKey = {
    ...vapidKey,
    subscription,
  };

  // Write back to database
  await put('keys', updatedKey);
}

/**
 * Remove push subscription from the current VAPID key.
 *
 * @throws Error if no VAPID key found or multiple VAPID keys exist
 */
export async function removePushSubscription(): Promise<void> {
  // Get all keys and find the VAPID key
  const allKeys = await getAllWrappedKeys();
  const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');

  if (vapidKeys.length === 0) {
    throw new Error('No VAPID key found');
  }

  if (vapidKeys.length > 1) {
    throw new Error('Multiple VAPID keys found. Cannot determine which to update.');
  }

  const vapidKey = vapidKeys[0];
  if (!vapidKey) {
    throw new Error('No VAPID key found after filtering');
  }

  // Remove the subscription field (don't set to undefined, delete it)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { subscription: _, ...updatedKey } = vapidKey;

  // Write back to database
  await put('keys', updatedKey);
}

/**
 * Get push subscription from the current VAPID key.
 *
 * @returns Push subscription or null if not set
 * @throws Error if no VAPID key found or multiple VAPID keys exist
 */
export async function getPushSubscription(): Promise<StoredPushSubscription | null> {
  // Get all keys and find the VAPID key
  const allKeys = await getAllWrappedKeys();
  const vapidKeys = allKeys.filter((k) => k.purpose === 'vapid');

  if (vapidKeys.length === 0) {
    throw new Error('No VAPID key found');
  }

  if (vapidKeys.length > 1) {
    throw new Error('Multiple VAPID keys found. Cannot determine which to read.');
  }

  const vapidKey = vapidKeys[0];
  if (!vapidKey) {
    throw new Error('No VAPID key found after filtering');
  }

  return vapidKey.subscription ?? null;
}
