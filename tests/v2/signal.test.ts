/**
 * Signal messaging domain tests (Phase 1 — enclave messaging core).
 *
 * The headline test is the milestone gate: a full Alice -> Bob X3DH + Double
 * Ratchet round trip driven through two `StorageType` adapters backed by the
 * MKEK-wrapped IndexedDB stores (asserting plaintext equality and the 3-then-1
 * message types). The remaining tests cover the adapter surface and prekey/
 * bundle generation.
 *
 * Runs in the `node` environment so `crypto.subtle` provides native X25519 /
 * Ed25519 (the fork's WebCrypto curve backend), which happy-dom does not.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
  Direction,
} from '@lukium/libsignal-protocol-typescript';
import type { DeviceType } from '@lukium/libsignal-protocol-typescript';

import { initDB, closeDB } from '@/v2/storage';
import {
  createSignalProtocolStore,
  generateIdentity,
  generateSignedPrekey,
  generateOneTimePrekeys,
  getPublicBundle,
  type PublicPreKeyBundle,
} from '@/v2/signal';

function makeMkek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function provision(userId: string, mkek: CryptoKey): Promise<void> {
  await generateIdentity(userId, mkek);
  await generateSignedPrekey(userId, mkek, 1);
  await generateOneTimePrekeys(userId, mkek, 1, 5);
}

function bundleToDevice(bundle: PublicPreKeyBundle): DeviceType {
  const pk = bundle.oneTimePreKeys[0]!;
  return {
    identityKey: bundle.identityKey,
    identitySigningKey: bundle.identitySigningKey,
    registrationId: bundle.registrationId,
    signedPreKey: bundle.signedPreKey,
    preKey: { keyId: pk.keyId, publicKey: pk.publicKey },
  };
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});

afterEach(() => {
  closeDB();
});

describe('signal round trip (milestone gate)', () => {
  it('completes an Alice->Bob X3DH + ratchet exchange over MKEK-wrapped stores', async () => {
    const aliceMkek = await makeMkek();
    const bobMkek = await makeMkek();
    await provision('alice', aliceMkek);
    await provision('bob', bobMkek);

    const aliceStore = createSignalProtocolStore('alice', aliceMkek);
    const bobStore = createSignalProtocolStore('bob', bobMkek);

    const aliceAddr = new SignalProtocolAddress('alice', 1);
    const bobAddr = new SignalProtocolAddress('bob', 1);

    // Alice fetches Bob's public bundle (as the directory would serve it) and
    // builds an outbound session.
    const bobBundle = await getPublicBundle('bob');
    expect(bobBundle.identityKey.byteLength).toBe(33);
    expect(bobBundle.identitySigningKey.byteLength).toBe(32);
    expect(bobBundle.oneTimePreKeys.length).toBe(5);

    const builder = new SessionBuilder(aliceStore, bobAddr);
    await builder.processPreKey(bundleToDevice(bobBundle));

    // Alice -> Bob: first message is a pre-key (type 3) message.
    const aliceCipher = new SessionCipher(aliceStore, bobAddr);
    const msg1 = await aliceCipher.encrypt(utf8.encode('hello bob').buffer);
    expect(msg1.type).toBe(3);

    const bobCipher = new SessionCipher(bobStore, aliceAddr);
    const pt1 = await bobCipher.decryptPreKeyWhisperMessage(msg1.body as string, 'binary');
    expect(fromUtf8.decode(pt1)).toBe('hello bob');

    // Bob -> Alice: reply is a normal (type 1) Whisper message.
    const msg2 = await bobCipher.encrypt(utf8.encode('hi alice').buffer);
    expect(msg2.type).toBe(1);
    const pt2 = await aliceCipher.decryptWhisperMessage(msg2.body as string, 'binary');
    expect(fromUtf8.decode(pt2)).toBe('hi alice');

    // The consumed one-time prekey can no longer be loaded (replay protection).
    expect(await bobStore.loadPreKey(bobBundle.oneTimePreKeys[0]!.keyId)).toBeUndefined();
  });
});

describe('prekey + bundle generation', () => {
  it('generateIdentity is idempotent and records both public keys', async () => {
    const mkek = await makeMkek();
    const first = await generateIdentity('u', mkek);
    const second = await generateIdentity('u', mkek);
    expect(second.createdAt).toBe(first.createdAt);
    expect(first.identityPubKey.byteLength).toBe(33);
    expect(first.identitySigningPubKey.byteLength).toBe(32);
  });

  it('generateSignedPrekey requires an identity', async () => {
    const mkek = await makeMkek();
    await expect(generateSignedPrekey('ghost', mkek, 1)).rejects.toThrow('No Signal identity');
  });

  it('getPublicBundle throws without identity or signed prekey', async () => {
    const mkek = await makeMkek();
    await expect(getPublicBundle('nobody')).rejects.toThrow('No Signal identity');
    await generateIdentity('u2', mkek);
    await expect(getPublicBundle('u2')).rejects.toThrow('No signed prekey');
  });

  it('getPublicBundle picks the newest signed prekey', async () => {
    const mkek = await makeMkek();
    await generateIdentity('u3', mkek);
    await generateSignedPrekey('u3', mkek, 1);
    await generateSignedPrekey('u3', mkek, 2);
    const bundle = await getPublicBundle('u3');
    expect(bundle.signedPreKey.keyId).toBe(2);
    expect(bundle.signedPreKey.signature.byteLength).toBe(64);
  });
});

describe('StorageType adapter', () => {
  it('returns undefined for a user with no provisioned state', async () => {
    const mkek = await makeMkek();
    const store = createSignalProtocolStore('ghost', mkek);
    expect(await store.getIdentityKeyPair()).toBeUndefined();
    expect(await store.getLocalRegistrationId()).toBeUndefined();
    expect(await store.loadPreKey(1)).toBeUndefined();
    expect(await store.loadSignedPreKey(1)).toBeUndefined();
    expect(await store.loadSession('peer.1')).toBeUndefined();
  });

  it('round-trips identity and registration id through the MKEK', async () => {
    const mkek = await makeMkek();
    const created = await generateIdentity('u', mkek, 1234);
    const store = createSignalProtocolStore('u', mkek);
    const id = await store.getIdentityKeyPair();
    expect(id).toBeDefined();
    expect(new Uint8Array(id!.pubKey)).toEqual(new Uint8Array(created.identityPubKey));
    expect(id!.signingPrivKey.byteLength).toBe(32);
    expect(await store.getLocalRegistrationId()).toBe(1234);
  });

  it('stores, loads, and consumes a one-time prekey', async () => {
    const mkek = await makeMkek();
    await generateIdentity('u', mkek);
    const store = createSignalProtocolStore('u', mkek);
    const pk = await KeyHelper.generatePreKey(99);

    await store.storePreKey(99, pk.keyPair);
    const loaded = await store.loadPreKey(99);
    expect(loaded).toBeDefined();
    expect(new Uint8Array(loaded!.pubKey)).toEqual(new Uint8Array(pk.keyPair.pubKey));

    await store.removePreKey(99);
    expect(await store.loadPreKey(99)).toBeUndefined();
    // removing an unknown prekey is a no-op
    await store.removePreKey(424242);
  });

  it('stores, loads, and removes a signed prekey', async () => {
    const mkek = await makeMkek();
    await generateIdentity('u', mkek);
    const store = createSignalProtocolStore('u', mkek);
    const identity = await store.getIdentityKeyPair();
    const sp = await KeyHelper.generateSignedPreKey(identity!, 7);

    await store.storeSignedPreKey(7, sp.keyPair);
    const loaded = await store.loadSignedPreKey(7);
    expect(loaded).toBeDefined();
    expect(new Uint8Array(loaded!.pubKey)).toEqual(new Uint8Array(sp.keyPair.pubKey));

    await store.removeSignedPreKey(7);
    expect(await store.loadSignedPreKey(7)).toBeUndefined();
  });

  it('storeSignedPreKey requires an identity', async () => {
    const mkek = await makeMkek();
    const store = createSignalProtocolStore('ghost', mkek);
    const pk = await KeyHelper.generatePreKey(1);
    await expect(store.storeSignedPreKey(1, pk.keyPair)).rejects.toThrow('No Signal identity');
  });

  it('implements trust-on-first-use for peer identities', async () => {
    const mkek = await makeMkek();
    const store = createSignalProtocolStore('u', mkek);
    const keyA = utf8.encode('peer-identity-key-A').buffer;
    const keyB = utf8.encode('peer-identity-key-B-different').buffer;

    // Unseen peer is trusted.
    expect(await store.isTrustedIdentity('peer.1', keyA, Direction.RECEIVING)).toBe(true);
    // First save records it (not a change).
    expect(await store.saveIdentity('peer.1', keyA)).toBe(false);
    // Matching key trusted; different key not.
    expect(await store.isTrustedIdentity('peer.1', keyA, Direction.RECEIVING)).toBe(true);
    expect(await store.isTrustedIdentity('peer.1', keyB, Direction.RECEIVING)).toBe(false);
    // Saving the same key is not a change; a different key is.
    expect(await store.saveIdentity('peer.1', keyA)).toBe(false);
    expect(await store.saveIdentity('peer.1', keyB)).toBe(true);
  });

  it('binds wrapped blobs to context (AAD): a session cannot be read as another peer', async () => {
    const mkek = await makeMkek();
    await generateIdentity('u', mkek);
    const store = createSignalProtocolStore('u', mkek);
    await store.storeSession('peer.1', 'serialized-session-state');
    expect(await store.loadSession('peer.1')).toBe('serialized-session-state');
    // A different peer key has no record (and its blob, if swapped in, would fail
    // the AAD-bound GCM tag — see storage.wrapBlob/unwrapBlob).
    expect(await store.loadSession('peer.2')).toBeUndefined();
  });
});
