/**
 * Worker messaging RPC tests (Phase 2 — enclave messaging surface).
 *
 * Exit-criteria test: open a session over the RPC boundary and encrypt/decrypt a
 * message that a second party (the `signal.ts` library acting as a separate
 * enclave) decrypts, plus a type-1 reply decrypted back through the RPC surface.
 * Also covers the capability/session model: minting, signature/sid checks,
 * close, and idle + absolute expiry.
 *
 * Runs in the `node` environment so `crypto.subtle` provides native X25519 /
 * Ed25519 (the fork's curve backend + the Ed25519 capability token).
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { SessionCipher, SignalProtocolAddress } from '@lukium/libsignal-protocol-typescript';
import type { DeviceType } from '@lukium/libsignal-protocol-typescript';

import { handleMessage } from '@/v2/worker';
import type { RPCRequest, RPCResponse } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';
import {
  createSignalProtocolStore,
  generateIdentity,
  generateSignedPrekey,
  generateOneTimePrekeys,
  getPublicBundle,
  type PublicPreKeyBundle,
} from '@/v2/signal';
import { buildFanoutBundle, openFanoutBundle } from '@/v2/envelope';

const ALICE_PASS = 'correct-horse-battery-staple';
const aliceCreds = { method: 'passphrase' as const, userId: 'alice', passphrase: ALICE_PASS };
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

function createRequest(method: string, params: unknown = {}): RPCRequest {
  return { id: `req-${method}-${Math.random().toString(36).slice(2)}`, method, params };
}

function getResult<T>(response: RPCResponse): T {
  return response.result as T;
}

function makeMkek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
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

/** Enroll alice (passphrase) and provision her messaging keys via the RPC surface. */
async function setupAlice(): Promise<PublicPreKeyBundle> {
  const enroll = await handleMessage(
    createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })
  );
  expect(enroll.error).toBeUndefined();
  const res = await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds }));
  expect(res.error).toBeUndefined();
  return getResult<{ bundle: PublicPreKeyBundle }>(res).bundle;
}

/** Provision a "bob" enclave directly through the library (separate party). */
async function provisionBobViaLibrary(): Promise<{ kek: CryptoKey; bundle: PublicPreKeyBundle }> {
  const kek = await makeMkek();
  await generateIdentity('bob', kek);
  await generateSignedPrekey('bob', kek, 1);
  await generateOneTimePrekeys('bob', kek, 1, 5);
  return { kek, bundle: await getPublicBundle('bob') };
}

async function openAlice(): Promise<{ sid: string; token: string; exp: number }> {
  const res = await handleMessage(createRequest('openMessaging', { credentials: aliceCreds }));
  expect(res.error).toBeUndefined();
  return getResult<{ sid: string; token: string; exp: number }>(res);
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
  resetAuditLogger();
});

afterEach(() => {
  vi.useRealTimers();
  closeDB();
  resetAuditLogger();
});

describe('setupMessaging / getMessagingBundle / getPrekeyCount', () => {
  it('provisions an identity + prekeys and serves the public bundle', async () => {
    const bundle = await setupAlice();
    expect(bundle.identityKey.byteLength).toBe(33);
    expect(bundle.identitySigningKey.byteLength).toBe(32);
    expect(bundle.oneTimePreKeys.length).toBe(20);

    const fetched = getResult<{ bundle: PublicPreKeyBundle }>(
      await handleMessage(createRequest('getMessagingBundle', { userId: 'alice' }))
    );
    expect(fetched.bundle.signedPreKey.keyId).toBe(bundle.signedPreKey.keyId);

    const count = getResult<{ count: number }>(
      await handleMessage(createRequest('getPrekeyCount', { userId: 'alice' }))
    );
    expect(count.count).toBe(20);
  });

  it('honors a custom one-time prekey count', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS }));
    await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds, oneTimePrekeyCount: 3 }));
    const count = getResult<{ count: number }>(
      await handleMessage(createRequest('getPrekeyCount', { userId: 'alice' }))
    );
    expect(count.count).toBe(3);
  });

  it('rejects setup with wrong credentials', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS }));
    const res = await handleMessage(
      createRequest('setupMessaging', {
        credentials: { method: 'passphrase', userId: 'alice', passphrase: 'wrong' },
      })
    );
    expect(res.error).toBeDefined();
  });
});

describe('openMessaging', () => {
  it('mints a capability token with an ~8h expiry', async () => {
    await setupAlice();
    const before = Math.floor(Date.now() / 1000);
    const open = await openAlice();
    expect(open.sid).toMatch(/[0-9a-f-]{36}/);
    expect(open.token.split('.')).toHaveLength(3);
    // exp is ~8h out (allow scheduling slack).
    expect(open.exp).toBeGreaterThan(before + 8 * 3600 - 60);
    expect(open.exp).toBeLessThanOrEqual(before + 8 * 3600 + 5);
  });

  it('refuses to open before messaging is set up', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS }));
    const res = await handleMessage(createRequest('openMessaging', { credentials: aliceCreds }));
    expect(res.error).toMatch(/not set up/i);
  });

  it('rejects open with wrong credentials', async () => {
    await setupAlice();
    const res = await handleMessage(
      createRequest('openMessaging', {
        credentials: { method: 'passphrase', userId: 'alice', passphrase: 'wrong' },
      })
    );
    expect(res.error).toBeDefined();
  });
});

describe('buildBundle/openBundle round trip (exit criteria)', () => {
  it('builds a bundle over RPC a library peer opens, and opens the reply over RPC', async () => {
    await setupAlice();
    const bob = await provisionBobViaLibrary();
    const open = await openAlice();

    // Alice -> Bob: buildBundle establishes the session and produces one opaque
    // bundle (a single type-3 envelope for bob).
    const buildRes = await handleMessage(
      createRequest('buildBundle', {
        sid: open.sid,
        token: open.token,
        recipients: [{ peerName: 'bob', peerDeviceId: 1, deviceBundle: bundleToDevice(bob.bundle) }],
        plaintext: utf8.encode('hello bob').buffer,
      })
    );
    expect(buildRes.error).toBeUndefined();
    const { bundle } = getResult<{ bundle: ArrayBuffer }>(buildRes);

    // Bob (library, separate enclave) opens his envelope.
    const bobStore = createSignalProtocolStore('bob', bob.kek);
    const aliceAddr = new SignalProtocolAddress('alice', 1);
    const bobCipher = new SessionCipher(bobStore, aliceAddr);
    const pt1 = await openFanoutBundle([bobCipher], bundle);
    expect(fromUtf8.decode(new Uint8Array(pt1!))).toBe('hello bob');

    // Bob's one-time prekey was consumed (replay protection).
    expect(await bobStore.loadPreKey(bob.bundle.oneTimePreKeys[0]!.keyId)).toBeUndefined();

    // Bob -> Alice: reply bundle; Alice opens it over RPC via trial decryption.
    const replyBundle = await buildFanoutBundle([bobCipher], utf8.encode('hi alice'));
    const openRes = await handleMessage(
      createRequest('openBundle', {
        sid: open.sid,
        token: open.token,
        senders: [{ peerName: 'bob', peerDeviceId: 1 }],
        bundle: replyBundle.buffer.slice(0),
      })
    );
    expect(openRes.error).toBeUndefined();
    const { plaintext } = getResult<{ plaintext: ArrayBuffer | null }>(openRes);
    expect(fromUtf8.decode(new Uint8Array(plaintext!))).toBe('hi alice');
  });

  it('refuses to build to an unknown peer without a device bundle', async () => {
    await setupAlice();
    const open = await openAlice();
    const res = await handleMessage(
      createRequest('buildBundle', {
        sid: open.sid,
        token: open.token,
        recipients: [{ peerName: 'stranger' }],
        plaintext: utf8.encode('hi').buffer,
      })
    );
    expect(res.error).toMatch(/deviceBundle is required/i);
  });
});

describe('capability enforcement', () => {
  async function encryptAttempt(sid: string, token: string): Promise<RPCResponse> {
    return handleMessage(
      createRequest('buildBundle', {
        sid,
        token,
        recipients: [{ peerName: 'bob' }],
        plaintext: utf8.encode('hi').buffer,
      })
    );
  }

  it('rejects a tampered token signature', async () => {
    await setupAlice();
    const open = await openAlice();
    const parts = open.token.split('.');
    const sig = parts[2]!;
    parts[2] = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const res = await encryptAttempt(open.sid, parts.join('.'));
    expect(res.error).toBeDefined();
    expect(res.error).toMatch(/token|signature/i);
  });

  it('rejects a malformed token', async () => {
    await setupAlice();
    const open = await openAlice();
    const res = await encryptAttempt(open.sid, 'not-a-jwt');
    expect(res.error).toMatch(/malformed/i);
  });

  it('rejects an unknown session id', async () => {
    await setupAlice();
    const open = await openAlice();
    const res = await encryptAttempt('00000000-0000-0000-0000-000000000000', open.token);
    expect(res.error).toMatch(/not found/i);
  });

  it('closeMessaging drops the session', async () => {
    await setupAlice();
    const open = await openAlice();
    const closed = await handleMessage(
      createRequest('closeMessaging', { sid: open.sid, token: open.token })
    );
    expect(getResult<{ closed: boolean }>(closed).closed).toBe(true);
    const res = await encryptAttempt(open.sid, open.token);
    expect(res.error).toMatch(/not found/i);
  });

  it('drops the session after the absolute cap', async () => {
    await setupAlice();
    const open = await openAlice();
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 8 * 60 * 60 * 1000 + 1000);
    const res = await encryptAttempt(open.sid, open.token);
    expect(res.error).toMatch(/expired/i);
  });

  it('drops the session after the idle timeout', async () => {
    await setupAlice();
    const open = await openAlice();
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 16 * 60 * 1000);
    const res = await encryptAttempt(open.sid, open.token);
    expect(res.error).toMatch(/expired/i);
  });
});

describe('rotatePrekeys', () => {
  it('tops up one-time prekeys and returns a refreshed bundle', async () => {
    await setupAlice();
    const open = await openAlice();
    const res = await handleMessage(
      createRequest('rotatePrekeys', {
        sid: open.sid,
        token: open.token,
        signedPreKeyId: 2,
        startKeyId: 100,
        count: 5,
      })
    );
    expect(res.error).toBeUndefined();
    const { bundle } = getResult<{ bundle: PublicPreKeyBundle }>(res);
    expect(bundle.signedPreKey.keyId).toBe(2);
    // 20 initial + 5 new unconsumed one-time prekeys.
    const count = getResult<{ count: number }>(
      await handleMessage(createRequest('getPrekeyCount', { userId: 'alice' }))
    );
    expect(count.count).toBe(25);
  });
});
