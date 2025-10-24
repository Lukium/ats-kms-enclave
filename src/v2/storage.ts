/**
 * In‑memory storage abstraction for the KMS V2 implementation.
 *
 * The design documents specify that the KMS should persist keys,
 * configuration metadata and audit entries in IndexedDB. Because
 * IndexedDB is unavailable in a Node.js environment the functions
 * herein provide a simplified in‑memory alternative. When compiled
 * for the browser these functions can be replaced with true
 * IndexedDB implementations. Until then, the API exposed here
 * mirrors the intended asynchronous nature of IndexedDB operations.
 */

import type { WrappedKey, KeyMetadata, AuditEntryV2 } from './types';
import { buildKeyWrapAAD } from './crypto-utils';

// Internal storage structures. When running in a browser these would
// correspond to IndexedDB object stores. Here they are simple maps.
const wrappedKeys: Map<string, WrappedKey> = new Map();
const metaStore: Map<string, any> = new Map();
const auditEntries: AuditEntryV2[] = [];

let dbInitialised = false;

/**
 * Initialise the storage. In this in‑memory implementation there is
 * nothing to set up beyond clearing the current maps. In a browser
 * context this would create object stores and version the database.
 */
export async function initDB(): Promise<void> {
  if (!dbInitialised) {
    wrappedKeys.clear();
    metaStore.clear();
    auditEntries.length = 0;
    dbInitialised = true;
  }
}

/**
 * Wrap (encrypt) a CryptoKey and persist it. The key is exported as
 * raw bytes and encrypted using AES‑GCM under the provided wrapping
 * key. Associated data is derived from the provided metadata to bind
 * the ciphertext to its context. The resulting record is stored in
 * memory keyed by `kid`.
 */
export async function wrapKey(
  key: CryptoKey,
  wrappingKey: CryptoKey,
  kid: string,
  algorithm: AlgorithmIdentifier = key.algorithm,
  usages: KeyUsage[] = key.usages,
  metadata: KeyMetadata = { alg: 'unknown', purpose: 'unknown' }
): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = buildKeyWrapAAD({
    kmsVersion: 2,
    kid,
    alg: metadata.alg,
    purpose: metadata.purpose,
    createdAt: Date.now(),
    keyType: Array.isArray(usages) ? usages.join(',') : String(usages),
  });
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    wrappingKey,
    rawKey
  );
  const record: WrappedKey = {
    kid,
    kmsVersion: 2,
    wrappedKey: ciphertext,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
    aad,
    publicKeyRaw: metadata.publicKeyRaw,
    alg: metadata.alg,
    purpose: metadata.purpose,
    createdAt: Date.now(),
  };
  wrappedKeys.set(kid, record);
}

/**
 * Unwrap (decrypt) a previously stored key. Retrieves the record
 * associated with `kid`, decrypts the wrapped key using the provided
 * wrapping key and imports the resulting raw bytes into a CryptoKey
 * of the requested algorithm and usages.
 */
export async function unwrapKey(
  kid: string,
  wrappingKey: CryptoKey,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[] = []
): Promise<CryptoKey> {
  const record = wrappedKeys.get(kid);
  if (!record) {
    throw new Error(`No wrapped key with id: ${kid}`);
  }
  const iv = new Uint8Array(record.iv);
  const aad = record.aad;
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    wrappingKey,
    record.wrappedKey
  );
  const raw = new Uint8Array(decrypted);
  const key = await crypto.subtle.importKey('raw', raw, algorithm, false, usages);
  return key;
}

/**
 * Retrieve the wrapped key record for a given `kid`. Returns null if
 * none exists. The record is returned as stored; callers should not
 * modify the returned object directly.
 */
export async function getWrappedKey(kid: string): Promise<WrappedKey | null> {
  return wrappedKeys.get(kid) ?? null;
}

/**
 * Retrieve all wrapped key records. Returns a shallow copy of the
 * values in the internal map to prevent accidental mutation.
 */
export async function getAllWrappedKeys(): Promise<WrappedKey[]> {
  return Array.from(wrappedKeys.values());
}

/**
 * Fetch metadata stored under the specified key. Returns null if no
 * entry exists. Metadata entries are untyped; callers should cast
 * appropriately.
 */
export async function getMeta<T>(key: string): Promise<T | null> {
  return (metaStore.has(key) ? (metaStore.get(key) as T) : null);
}

/**
 * Persist a metadata value under the specified key. Any existing
 * value is overwritten.
 */
export async function putMeta(key: string, value: unknown): Promise<void> {
  metaStore.set(key, value);
}

/**
 * Delete a metadata entry. Has no effect if the key does not exist.
 */
export async function deleteMeta(key: string): Promise<void> {
  metaStore.delete(key);
}

/**
 * Retrieve all metadata entries as an array of { key, value } pairs.
 */
export async function getAllMeta(): Promise<Array<{ key: string; value: unknown }>> {
  return Array.from(metaStore.entries()).map(([k, v]) => ({ key: k, value: v }));
}

/**
 * Append an audit entry to storage. Audit entries are always
 * appended to the end of the array to preserve order.
 */
export async function storeAuditEntry(entry: AuditEntryV2): Promise<void> {
  auditEntries.push(entry);
}

/**
 * Retrieve all audit entries. Returns a shallow copy of the array.
 */
export async function getAllAuditEntries(): Promise<AuditEntryV2[]> {
  return auditEntries.slice();
}

/**
 * Retrieve the last audit entry or null if none exist.
 */
export async function getLastAuditEntry(): Promise<AuditEntryV2 | null> {
  return auditEntries.length > 0 ? auditEntries[auditEntries.length - 1] : null;
}
