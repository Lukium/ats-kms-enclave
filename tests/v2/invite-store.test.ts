/**
 * Armed-invite persistence tests (rooms-and-trust §3.2/§3.3).
 *
 * An invite's room secret round-trips wrapped under a messagingKEK with per-
 * (userId, inviteId) AAD binding, so it survives the app closing and a late join
 * still lands. Fail-closed on the wrong key or a foreign owner; metadata is
 * readable without touching secrets.
 *
 * Runs in the `node` environment for native AES-GCM + fake-indexeddb.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { initDB, closeDB, deleteMessagingInvite, getMessagingInvite } from '@/v2/storage';
import { storeInvite, loadInvite, listInviteMeta } from '@/v2/invite-store';

const ALICE = 'aaaaaaaa-0000-0000-0000-000000000001';
const BOB = 'bbbbbbbb-0000-0000-0000-000000000002';

function makeKek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function secret(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});
afterEach(() => closeDB());

describe('storeInvite / loadInvite', () => {
  it('round-trips the secret + metadata under a messagingKEK', async () => {
    const kek = await makeKek();
    expect(await loadInvite(ALICE, 'inv-1', kek)).toBeNull();

    await storeInvite(
      { userId: ALICE, inviteId: 'inv-1', secret: secret(0x11), scope: 'scope-1', type: 'connect-1:1', expiresAt: 9_999, singleUse: true },
      kek
    );
    const loaded = await loadInvite(ALICE, 'inv-1', kek);
    expect(loaded).not.toBeNull();
    expect(Array.from(loaded!.secret)).toEqual(Array.from(secret(0x11)));
    expect(loaded!.meta).toEqual({
      inviteId: 'inv-1',
      scope: 'scope-1',
      type: 'connect-1:1',
      expiresAt: 9_999,
      singleUse: true,
      createdAt: expect.any(Number),
    });
  });

  it('returns null for an unknown invite or a foreign owner (scoped to the minter)', async () => {
    const kek = await makeKek();
    await storeInvite({ userId: ALICE, inviteId: 'inv-1', secret: secret(0x11), scope: 's', type: 'room' }, kek);
    expect(await loadInvite(ALICE, 'nope', kek)).toBeNull();
    expect(await loadInvite(BOB, 'inv-1', kek)).toBeNull(); // record.userId !== BOB
  });

  it('fails closed under the wrong messagingKEK', async () => {
    const kek = await makeKek();
    const other = await makeKek();
    await storeInvite({ userId: ALICE, inviteId: 'inv-1', secret: secret(0x11), scope: 's', type: 'room' }, kek);
    await expect(loadInvite(ALICE, 'inv-1', other)).rejects.toThrow();
  });

  it('omits absent optional metadata (room invite)', async () => {
    const kek = await makeKek();
    await storeInvite({ userId: ALICE, inviteId: 'inv-2', secret: secret(0x22), scope: 's2', type: 'room' }, kek);
    const meta = (await loadInvite(ALICE, 'inv-2', kek))!.meta;
    expect(meta.expiresAt).toBeUndefined();
    expect(meta.singleUse).toBeUndefined();
  });
});

describe('listInviteMeta', () => {
  it('returns public metadata for the user only, reading no secrets', async () => {
    const kek = await makeKek();
    await storeInvite({ userId: ALICE, inviteId: 'a1', secret: secret(0x11), scope: 's-a1', type: 'connect-1:1', expiresAt: 1 }, kek);
    await storeInvite({ userId: ALICE, inviteId: 'a2', secret: secret(0x22), scope: 's-a2', type: 'room' }, kek);
    await storeInvite({ userId: BOB, inviteId: 'b1', secret: secret(0x33), scope: 's-b1', type: 'room' }, kek);

    const metas = await listInviteMeta(ALICE);
    expect(metas.map((m) => m.inviteId).sort()).toEqual(['a1', 'a2']);
    expect(metas.find((m) => m.inviteId === 'a1')!.scope).toBe('s-a1');
    // Public metadata carries no secret material.
    expect(JSON.stringify(metas)).not.toContain('wrappedSecret');
  });
});

describe('deleteMessagingInvite', () => {
  it('forgets an armed invite (forgetInvite path)', async () => {
    const kek = await makeKek();
    await storeInvite({ userId: ALICE, inviteId: 'inv-1', secret: secret(0x11), scope: 's', type: 'room' }, kek);
    expect(await getMessagingInvite('inv-1')).not.toBeNull();
    await deleteMessagingInvite('inv-1');
    expect(await getMessagingInvite('inv-1')).toBeNull();
    expect(await loadInvite(ALICE, 'inv-1', kek)).toBeNull();
  });
});
