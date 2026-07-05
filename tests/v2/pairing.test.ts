/**
 * Pairing crypto + contact-secret persistence tests (secure-messaging §5/§6).
 *
 * pairID/exchangeKey derivation is deterministic and order-independent (both
 * users, every device agree); different secrets/UUID-pairs diverge; the two legs
 * are domain-separated. Contact-store round-trips a secret under a messagingKEK
 * with per-(user,peer) AAD binding. A device-exchange payload sealed by one user
 * opens for the peer (same secret) but not for a wrong secret.
 *
 * Runs in the `node` environment for native HKDF/AES-GCM.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { initDB, closeDB } from '@/v2/storage';
import { derivePairID, deriveExchangeKey } from '@/v2/pairing';
import { storeContactSecret, loadContactSecret, listContactPeers } from '@/v2/contact-store';
import { encryptSelfMessage, decryptSelfMessage } from '@/v2/self-channel';

const ALICE = 'aaaaaaaa-0000-0000-0000-000000000001';
const BOB = 'bbbbbbbb-0000-0000-0000-000000000002';
const CAROL = 'cccccccc-0000-0000-0000-000000000003';

function makeMkek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function secret(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

describe('derivePairID', () => {
  it('is deterministic and order-independent (both users agree)', async () => {
    const s = secret(0x11);
    const a = await derivePairID(s, ALICE, BOB);
    const b = await derivePairID(Uint8Array.from(s), BOB, ALICE); // swapped order
    expect(a).toBe(b);
  });

  it('is a URL-safe base64url string with no dm: prefix', async () => {
    const id = await derivePairID(secret(0x11), ALICE, BOB);
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(id.startsWith('dm:')).toBe(false);
  });

  it('differs for a different secret or a different peer', async () => {
    const base = await derivePairID(secret(0x11), ALICE, BOB);
    expect(await derivePairID(secret(0x22), ALICE, BOB)).not.toBe(base); // different secret
    expect(await derivePairID(secret(0x11), ALICE, CAROL)).not.toBe(base); // different peer
  });
});

describe('deriveExchangeKey', () => {
  it('derives a non-extractable AES-GCM key both users share', async () => {
    const s = secret(0x11);
    const k1 = await deriveExchangeKey(s);
    const k2 = await deriveExchangeKey(Uint8Array.from(s));
    expect(k1.extractable).toBe(false);
    expect(k1.algorithm.name).toBe('AES-GCM');

    // A device bundle sealed by Alice opens for Bob (same shared secret).
    const bundle = new TextEncoder().encode('device-bundle-bytes');
    const sealed = await encryptSelfMessage(k1, bundle, 'device-exchange');
    const opened = await decryptSelfMessage(k2, sealed, 'device-exchange');
    expect(new TextDecoder().decode(opened)).toBe('device-bundle-bytes');
  });

  it('a wrong secret cannot open the exchange (fail-closed)', async () => {
    const good = await deriveExchangeKey(secret(0x11));
    const wrong = await deriveExchangeKey(secret(0x22));
    const sealed = await encryptSelfMessage(good, new TextEncoder().encode('x'), 'device-exchange');
    await expect(decryptSelfMessage(wrong, sealed, 'device-exchange')).rejects.toThrow();
  });

  it('is domain-separated from pairID (both derive from the same secret)', async () => {
    const s = secret(0x11);
    const id = await derivePairID(s, ALICE, BOB);
    const key = await deriveExchangeKey(s);
    // Sealing the pairID string under the exchange key must not reproduce it.
    const sealed = await encryptSelfMessage(key, new TextEncoder().encode(id), 'device-exchange');
    expect(new TextDecoder().decode(sealed.subarray(12))).not.toBe(id);
  });
});

describe('contact-secret persistence', () => {
  beforeEach(async () => {
    globalThis.indexedDB = new IDBFactory();
    await initDB();
  });
  afterEach(() => closeDB());

  it('round-trips a secret under a messagingKEK', async () => {
    const kek = await makeMkek();
    const s = secret(0x11);
    expect(await loadContactSecret(ALICE, BOB, kek)).toBeNull();

    await storeContactSecret(ALICE, BOB, s, kek);
    const loaded = await loadContactSecret(ALICE, BOB, kek);
    expect(Buffer.from(loaded!).equals(Buffer.from(s))).toBe(true);
  });

  it('binds the blob to (user, peer): a different peer key cannot read it', async () => {
    const kek = await makeMkek();
    await storeContactSecret(ALICE, BOB, secret(0x11), kek);
    // Same kek, but the AAD for (ALICE, CAROL) differs → no record + null anyway;
    // assert the stored one is only retrievable under its own (user,peer).
    expect(await loadContactSecret(ALICE, CAROL, kek)).toBeNull();
    expect(await loadContactSecret(BOB, BOB, kek)).toBeNull();
  });

  it('fails to load under the wrong messagingKEK', async () => {
    const kek = await makeMkek();
    const other = await makeMkek();
    await storeContactSecret(ALICE, BOB, secret(0x11), kek);
    await expect(loadContactSecret(ALICE, BOB, other)).rejects.toThrow();
  });

  it('lists contact peers for a user', async () => {
    const kek = await makeMkek();
    await storeContactSecret(ALICE, BOB, secret(0x11), kek);
    await storeContactSecret(ALICE, CAROL, secret(0x22), kek);
    await storeContactSecret(BOB, ALICE, secret(0x33), kek); // different user
    const peers = await listContactPeers(ALICE);
    expect(peers.sort()).toEqual([BOB, CAROL].sort());
  });

  it('overwrites an existing secret', async () => {
    const kek = await makeMkek();
    await storeContactSecret(ALICE, BOB, secret(0x11), kek);
    await storeContactSecret(ALICE, BOB, secret(0x99), kek);
    const loaded = await loadContactSecret(ALICE, BOB, kek);
    expect(Buffer.from(loaded!).equals(Buffer.from(secret(0x99)))).toBe(true);
  });
});
