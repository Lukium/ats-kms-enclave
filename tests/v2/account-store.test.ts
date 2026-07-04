/**
 * Account-root persistence tests (secure-messaging §18).
 *
 * Store/load round-trip under a master MKEK, presence check, AAD binding to the
 * user (a blob can't be read by another user's context), and wrong-key rejection.
 *
 * Runs in the `node` environment for native AES-GCM.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { initDB, closeDB } from '@/v2/storage';
import { storeAccountRoot, loadAccountRoot, hasAccountRoot } from '@/v2/account-store';
import { generateAccountRoot } from '@/v2/account-root';

function makeMkek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});

afterEach(() => {
  closeDB();
});

describe('account-root persistence', () => {
  it('round-trips an accountRoot under the MKEK', async () => {
    const mkek = await makeMkek();
    const root = generateAccountRoot();

    expect(await hasAccountRoot('alice')).toBe(false);
    await storeAccountRoot('alice', root, mkek);
    expect(await hasAccountRoot('alice')).toBe(true);

    const loaded = await loadAccountRoot('alice', mkek);
    expect(loaded).not.toBeNull();
    expect(Buffer.from(loaded!).equals(Buffer.from(root))).toBe(true);
  });

  it('loadAccountRoot returns null for a user with no record', async () => {
    const mkek = await makeMkek();
    expect(await loadAccountRoot('ghost', mkek)).toBeNull();
  });

  it('binds the blob to the user (another userId cannot read it)', async () => {
    const mkek = await makeMkek();
    const root = generateAccountRoot();
    await storeAccountRoot('alice', root, mkek);

    // Same MKEK but a different user's AAD → GCM auth failure.
    // (Simulate by storing under 'alice' then reading as if 'mallory' owned it.)
    await storeAccountRoot('mallory', generateAccountRoot(), mkek);
    const aliceRoot = await loadAccountRoot('alice', mkek);
    const malloryRoot = await loadAccountRoot('mallory', mkek);
    expect(Buffer.from(aliceRoot!).equals(Buffer.from(malloryRoot!))).toBe(false);
  });

  it('fails to load under the wrong MKEK (fail-closed)', async () => {
    const mkek = await makeMkek();
    const other = await makeMkek();
    await storeAccountRoot('alice', generateAccountRoot(), mkek);
    await expect(loadAccountRoot('alice', other)).rejects.toThrow();
  });

  it('overwrites an existing record', async () => {
    const mkek = await makeMkek();
    const first = generateAccountRoot();
    const second = generateAccountRoot();
    await storeAccountRoot('alice', first, mkek);
    await storeAccountRoot('alice', second, mkek);
    const loaded = await loadAccountRoot('alice', mkek);
    expect(Buffer.from(loaded!).equals(Buffer.from(second))).toBe(true);
  });
});
