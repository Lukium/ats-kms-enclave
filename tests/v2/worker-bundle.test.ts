/**
 * Worker fan-out bundle RPC tests (secure-messaging §8/§12).
 *
 * The RPC surface is single-enrolled (alice); other devices are modeled directly
 * through the library. Covers alice BUILDING a bundle that library recipients
 * decrypt, and alice OPENING a bundle a library sender built (trial decryption +
 * inbound session establishment), plus the null / missing-bundle paths.
 *
 * Runs in the `node` environment for native X25519/Ed25519.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { SessionBuilder, SessionCipher, SignalProtocolAddress } from '@lukium/libsignal-protocol-typescript';
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
function getResult<T>(r: RPCResponse): T {
  return r.result as T;
}
function expectOk(r: RPCResponse): RPCResponse {
  expect(r.error).toBeUndefined();
  return r;
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

/** A library-modeled device (its own KMS identity). */
interface LibDevice {
  id: string;
  store: ReturnType<typeof createSignalProtocolStore>;
  addr: SignalProtocolAddress;
  bundle: PublicPreKeyBundle;
}
async function makeLibDevice(id: string, startKeyId: number): Promise<LibDevice> {
  const mkek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  await generateIdentity(id, mkek);
  await generateSignedPrekey(id, mkek, 1);
  await generateOneTimePrekeys(id, mkek, startKeyId, 5);
  return {
    id,
    store: createSignalProtocolStore(id, mkek),
    addr: new SignalProtocolAddress(id, 1),
    bundle: await getPublicBundle(id),
  };
}

/** Enroll alice + provision messaging via RPC; return her bundle + open session. */
async function setupAndOpenAlice(): Promise<{ sid: string; token: string; bundle: PublicPreKeyBundle }> {
  expectOk(await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })));
  const setup = expectOk(await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds })));
  const bundle = getResult<{ bundle: PublicPreKeyBundle }>(setup).bundle;
  const open = expectOk(await handleMessage(createRequest('openMessaging', { credentials: aliceCreds })));
  const { sid, token } = getResult<{ sid: string; token: string }>(open);
  return { sid, token, bundle };
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
  resetAuditLogger();
});

afterEach(() => {
  closeDB();
});

describe('buildBundle (alice sends)', () => {
  it('builds one bundle each recipient device decrypts', async () => {
    const { sid, token } = await setupAndOpenAlice();
    const b1 = await makeLibDevice('b1', 300);
    const b2 = await makeLibDevice('b2', 400);
    const c1 = await makeLibDevice('c1', 500); // not a recipient

    const res = expectOk(
      await handleMessage(
        createRequest('buildBundle', {
          sid,
          token,
          recipients: [
            { peerName: 'b1', deviceBundle: bundleToDevice(b1.bundle) },
            { peerName: 'b2', deviceBundle: bundleToDevice(b2.bundle) },
          ],
          plaintext: utf8.encode('hi devices').buffer,
        })
      )
    );
    const { bundle } = getResult<{ bundle: ArrayBuffer }>(res);

    // Each recipient opens with its session to alice; a non-recipient gets null.
    const fromAlice = (d: LibDevice): SessionCipher =>
      new SessionCipher(d.store, new SignalProtocolAddress('alice', 1));
    expect(fromUtf8.decode((await openFanoutBundle([fromAlice(b1)], bundle))!)).toBe('hi devices');
    expect(fromUtf8.decode((await openFanoutBundle([fromAlice(b2)], bundle))!)).toBe('hi devices');
    expect(await openFanoutBundle([fromAlice(c1)], bundle)).toBeNull();
  });

  it('errors when a new peer is given without a deviceBundle', async () => {
    const { sid, token } = await setupAndOpenAlice();
    const res = await handleMessage(
      createRequest('buildBundle', {
        sid,
        token,
        recipients: [{ peerName: 'stranger' }],
        plaintext: utf8.encode('x').buffer,
      })
    );
    expect(res.error).toMatch(/deviceBundle is required/);
  });
});

describe('openBundle (alice receives)', () => {
  it('opens the envelope addressed to alice via trial decryption', async () => {
    const { sid, token, bundle: aliceBundle } = await setupAndOpenAlice();

    // A library sender S fans out to alice + a decoy device.
    const s = await makeLibDevice('s', 600);
    const decoy = await makeLibDevice('decoy', 700);
    const aliceAddr = new SignalProtocolAddress('alice', 1);
    await new SessionBuilder(s.store, aliceAddr).processPreKey(bundleToDevice(aliceBundle));
    await new SessionBuilder(s.store, decoy.addr).processPreKey(bundleToDevice(decoy.bundle));
    const sToAlice = new SessionCipher(s.store, aliceAddr);
    const sToDecoy = new SessionCipher(s.store, decoy.addr);
    const bundle = await buildFanoutBundle([sToAlice, sToDecoy], utf8.encode('hello alice'));

    const res = expectOk(
      await handleMessage(
        createRequest('openBundle', { sid, token, senders: [{ peerName: 's' }], bundle })
      )
    );
    const { plaintext } = getResult<{ plaintext: ArrayBuffer | null }>(res);
    expect(plaintext).not.toBeNull();
    expect(fromUtf8.decode(plaintext!)).toBe('hello alice');
  });

  it('returns null when no envelope is addressed to this device', async () => {
    const { sid, token } = await setupAndOpenAlice();
    // A sender fans out to two OTHER devices only (nothing for alice).
    const s = await makeLibDevice('s', 600);
    const x = await makeLibDevice('x', 700);
    const y = await makeLibDevice('y', 800);
    await new SessionBuilder(s.store, x.addr).processPreKey(bundleToDevice(x.bundle));
    await new SessionBuilder(s.store, y.addr).processPreKey(bundleToDevice(y.bundle));
    const bundle = await buildFanoutBundle(
      [new SessionCipher(s.store, x.addr), new SessionCipher(s.store, y.addr)],
      utf8.encode('not for alice')
    );

    const res = expectOk(
      await handleMessage(
        createRequest('openBundle', { sid, token, senders: [{ peerName: 's' }], bundle })
      )
    );
    expect(getResult<{ plaintext: ArrayBuffer | null }>(res).plaintext).toBeNull();
  });

  it('round-trips alice -> library recipient -> reply -> alice opens', async () => {
    const { sid, token } = await setupAndOpenAlice();
    const bob = await makeLibDevice('bob', 900);

    // alice -> bob (PreKey).
    const built = expectOk(
      await handleMessage(
        createRequest('buildBundle', {
          sid,
          token,
          recipients: [{ peerName: 'bob', deviceBundle: bundleToDevice(bob.bundle) }],
          plaintext: utf8.encode('ping').buffer,
        })
      )
    );
    const bundle1 = getResult<{ bundle: ArrayBuffer }>(built).bundle;

    const bobFromAlice = new SessionCipher(bob.store, new SignalProtocolAddress('alice', 1));
    expect(fromUtf8.decode((await openFanoutBundle([bobFromAlice], bundle1))!)).toBe('ping');

    // bob -> alice reply (Whisper, session established on bob's side).
    const reply = await buildFanoutBundle([bobFromAlice], utf8.encode('pong'));
    const res = expectOk(
      await handleMessage(
        createRequest('openBundle', { sid, token, senders: [{ peerName: 'bob' }], bundle: reply })
      )
    );
    expect(fromUtf8.decode(getResult<{ plaintext: ArrayBuffer | null }>(res).plaintext!)).toBe('pong');
  });
});
