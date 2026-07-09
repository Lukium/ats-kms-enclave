/**
 * Worker master-identity RPC tests (rooms-and-trust §2/§4).
 *
 * Drives getIdentityCard / getDeviceCert / verifyContactDevice over the RPC
 * boundary. Value checks close against the recovery phrase: decode it to the
 * account root test-side, derive the expected master public keys, and confirm the
 * RPC agrees — and that this device's certificate verifies under the account
 * master. verifyContactDevice is exercised with a peer simulated entirely
 * test-side (a second root), covering the valid / foreign-master / tampered cases.
 *
 * Runs in the `node` environment for native Ed25519/X25519 + HKDF.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { handleMessage } from '@/v2/worker';
import type { RPCRequest, RPCResponse } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';
import { mnemonicToAccountRoot } from '@/v2/account-root';
import { arrayBufferToBase64url } from '@/v2/crypto-utils';
import {
  masterSigningPublicRaw,
  masterEncryptionPublicRaw,
  signDeviceCert,
  verifyDeviceCert,
} from '@/v2/master-identity';

const ALICE_PASS = 'correct-horse-battery-staple';
const aliceCreds = { method: 'passphrase' as const, userId: 'alice', passphrase: ALICE_PASS };

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
/** Copy a Uint8Array into a fresh, exactly-sized ArrayBuffer. */
function toAb(u: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u.byteLength);
  new Uint8Array(b).set(u);
  return b;
}

/** Enroll alice + provision messaging; return an open session (sid/token). */
async function setupAndOpen(withRoot: boolean): Promise<{ sid: string; token: string; mnemonic?: string }> {
  expectOk(await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })));
  expectOk(await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds })));
  let mnemonic: string | undefined;
  if (withRoot) {
    const r = expectOk(await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds })));
    mnemonic = getResult<{ mnemonic: string }>(r).mnemonic;
  }
  const open = expectOk(await handleMessage(createRequest('openMessaging', { credentials: aliceCreds })));
  const { sid, token } = getResult<{ sid: string; token: string }>(open);
  return mnemonic ? { sid, token, mnemonic } : { sid, token };
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
  resetAuditLogger();
});

afterEach(() => {
  closeDB();
});

describe('getIdentityCard', () => {
  it('returns the master public keys derived from the account root', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true);
    const root = await mnemonicToAccountRoot(mnemonic!);
    const expMsk = arrayBufferToBase64url(toAb(await masterSigningPublicRaw(root)));
    const expMek = arrayBufferToBase64url(toAb(await masterEncryptionPublicRaw(root)));

    const res = expectOk(await handleMessage(createRequest('getIdentityCard', { sid, token })));
    const card = getResult<{ uid: string; msk: string; mek: string }>(res);
    expect(card.uid).toBe('alice');
    expect(card.msk).toBe(expMsk);
    expect(card.mek).toBe(expMek);
    // The two legs are independent — the identity card is not a single key twice.
    expect(card.msk).not.toBe(card.mek);
  });

  it('errors when the session has no account root', async () => {
    const { sid, token } = await setupAndOpen(false);
    const res = await handleMessage(createRequest('getIdentityCard', { sid, token }));
    expect(res.error).toMatch(/No account root/);
  });
});

describe('getDeviceCert', () => {
  it('returns a cert that verifies against the account master over this device keys', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true);
    const root = await mnemonicToAccountRoot(mnemonic!);
    const msk = await masterSigningPublicRaw(root);

    const res = expectOk(await handleMessage(createRequest('getDeviceCert', { sid, token })));
    const { deviceCert, identityKey, identitySigningKey } = getResult<{
      deviceCert: ArrayBuffer;
      identityKey: ArrayBuffer;
      identitySigningKey: ArrayBuffer;
    }>(res);

    expect(deviceCert.byteLength).toBe(64);
    const ok = await verifyDeviceCert(
      msk,
      { identityKey: new Uint8Array(identityKey), identitySigningKey: new Uint8Array(identitySigningKey) },
      new Uint8Array(deviceCert)
    );
    expect(ok).toBe(true);
    // A foreign master must NOT verify this device.
    const foreign = await masterSigningPublicRaw(new Uint8Array(16).fill(0xcc));
    expect(
      await verifyDeviceCert(
        foreign,
        { identityKey: new Uint8Array(identityKey), identitySigningKey: new Uint8Array(identitySigningKey) },
        new Uint8Array(deviceCert)
      )
    ).toBe(false);
  });

  it('errors when the session has no account root', async () => {
    const { sid, token } = await setupAndOpen(false);
    const res = await handleMessage(createRequest('getDeviceCert', { sid, token }));
    expect(res.error).toMatch(/No account root/);
  });
});

describe('verifyContactDevice', () => {
  it('accepts a peer device certified by its own master and rejects a foreign master or tamper', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true);
    const aliceRoot = await mnemonicToAccountRoot(mnemonic!);
    const aliceMsk = await masterSigningPublicRaw(aliceRoot);

    // Simulate a peer (bob) entirely test-side: a distinct root, master key, and a
    // device cert over bob's device keys.
    const bobRoot = new Uint8Array(16).fill(0xb2);
    const bobMsk = await masterSigningPublicRaw(bobRoot);
    const identityKey = new Uint8Array(33).fill(0x09);
    const identitySigningKey = new Uint8Array(32).fill(0x04);
    const cert = await signDeviceCert(bobRoot, { identityKey, identitySigningKey });

    // Valid: bob's device verifies under bob's master.
    const good = expectOk(
      await handleMessage(
        createRequest('verifyContactDevice', {
          sid,
          token,
          masterSigningPub: toAb(bobMsk),
          identityKey: toAb(identityKey),
          identitySigningKey: toAb(identitySigningKey),
          cert: toAb(cert),
        })
      )
    );
    expect(getResult<{ valid: boolean }>(good).valid).toBe(true);

    // Foreign master (alice's) must not verify bob's device → impersonation caught.
    const wrongMaster = expectOk(
      await handleMessage(
        createRequest('verifyContactDevice', {
          sid,
          token,
          masterSigningPub: toAb(aliceMsk),
          identityKey: toAb(identityKey),
          identitySigningKey: toAb(identitySigningKey),
          cert: toAb(cert),
        })
      )
    );
    expect(getResult<{ valid: boolean }>(wrongMaster).valid).toBe(false);

    // Tampered signature → invalid.
    const bad = new Uint8Array(cert);
    bad[0] = ((bad[0] ?? 0) ^ 0xff) & 0xff;
    const tampered = expectOk(
      await handleMessage(
        createRequest('verifyContactDevice', {
          sid,
          token,
          masterSigningPub: toAb(bobMsk),
          identityKey: toAb(identityKey),
          identitySigningKey: toAb(identitySigningKey),
          cert: toAb(bad),
        })
      )
    );
    expect(getResult<{ valid: boolean }>(tampered).valid).toBe(false);
  });

  it('rejects an unauthenticated call (no session)', async () => {
    const res = await handleMessage(
      createRequest('verifyContactDevice', {
        sid: 'nope',
        token: 'nope',
        masterSigningPub: new Uint8Array(32),
        identityKey: new Uint8Array(32),
        identitySigningKey: new Uint8Array(32),
        cert: new Uint8Array(64),
      })
    );
    expect(res.error).toBeDefined();
  });
});
