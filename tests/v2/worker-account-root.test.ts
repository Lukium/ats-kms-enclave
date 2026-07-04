/**
 * Worker account-root RPC tests (secure-messaging §18).
 *
 * Drives the account-root lifecycle over the RPC boundary (handleMessage):
 * setup + guard, presence, recovery-phrase import, auto-onboard via a
 * device-wrapped blob, and re-sealing for another device. Value correctness is
 * closed end-to-end by re-wrapping the stored root to a throwaway key and
 * unsealing it test-side.
 *
 * Runs in the `node` environment for native X25519/Ed25519.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { KeyHelper } from '@lukium/libsignal-protocol-typescript';

import { handleMessage } from '@/v2/worker';
import type { RPCRequest, RPCResponse } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';
import { type PublicPreKeyBundle } from '@/v2/signal';
import { generateAccountRoot, accountRootToMnemonic } from '@/v2/account-root';
import { wrapAccountRootToDevice, unwrapAccountRootFromDevice } from '@/v2/device-wrap';

const ALICE_PASS = 'correct-horse-battery-staple';
const aliceCreds = { method: 'passphrase' as const, userId: 'alice', passphrase: ALICE_PASS };

function createRequest(method: string, params: unknown = {}): RPCRequest {
  return { id: `req-${method}-${Math.random().toString(36).slice(2)}`, method, params };
}

function getResult<T>(response: RPCResponse): T {
  return response.result as T;
}

/** Enroll alice (passphrase) + provision her Signal identity via the RPC surface. */
async function setupAlice(): Promise<PublicPreKeyBundle> {
  const enroll = await handleMessage(
    createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })
  );
  expect(enroll.error).toBeUndefined();
  const res = await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds }));
  expect(res.error).toBeUndefined();
  return getResult<{ bundle: PublicPreKeyBundle }>(res).bundle;
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
  resetAuditLogger();
});

afterEach(() => {
  closeDB();
});

describe('setupAccountRoot', () => {
  it('generates a 12-word phrase, flips presence, and guards re-setup', async () => {
    await setupAlice();

    expect(getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    ).present).toBe(false);

    const res = await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds }));
    expect(res.error).toBeUndefined();
    const { mnemonic } = getResult<{ mnemonic: string }>(res);
    expect(mnemonic.split(' ')).toHaveLength(12);

    expect(getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    ).present).toBe(true);

    // Second setup must fail — regenerate would orphan self-channel state.
    const again = await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds }));
    expect(again.error).toMatch(/already exists/);
  });

  it('requires a valid unlock (no enrollment → error)', async () => {
    // No setupPassphrase for alice → withUnlock fails.
    const res = await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds }));
    expect(res.error).toBeDefined();
  });
});

describe('hasAccountRoot', () => {
  it('is false for an unknown user', async () => {
    const res = await handleMessage(createRequest('hasAccountRoot', { userId: 'nobody' }));
    expect(getResult<{ present: boolean }>(res).present).toBe(false);
  });
});

describe('importAccountRootFromMnemonic', () => {
  it('restores from a valid phrase', async () => {
    await setupAlice();
    const mnemonic = await accountRootToMnemonic(generateAccountRoot());
    const res = await handleMessage(
      createRequest('importAccountRootFromMnemonic', { credentials: aliceCreds, mnemonic })
    );
    expect(res.error).toBeUndefined();
    expect(getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    ).present).toBe(true);
  });

  it('rejects a bad-checksum phrase', async () => {
    await setupAlice();
    const bad = new Array(12).fill('abandon').join(' '); // checksum fails
    const res = await handleMessage(
      createRequest('importAccountRootFromMnemonic', { credentials: aliceCreds, mnemonic: bad })
    );
    expect(res.error).toMatch(/checksum/);
  });
});

describe('importWrappedAccountRoot + wrapAccountRootForDevice', () => {
  it('auto-onboards a device-wrapped root and preserves its value end-to-end', async () => {
    const bundle = await setupAlice();

    // Simulate an existing device sealing a known root to alice's identity key.
    const root = generateAccountRoot();
    const wrapped = await wrapAccountRootToDevice(root, new Uint8Array(bundle.identityKey));

    const imp = await handleMessage(
      createRequest('importWrappedAccountRoot', { credentials: aliceCreds, wrapped })
    );
    expect(imp.error).toBeUndefined();
    expect(getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    ).present).toBe(true);

    // Close the value loop: re-seal the stored root to a throwaway key and unseal
    // it test-side — it must equal the root that was imported.
    const throwaway = await KeyHelper.generateIdentityKeyPair();
    const res = await handleMessage(
      createRequest('wrapAccountRootForDevice', {
        credentials: aliceCreds,
        recipientIdentityPubKey: throwaway.pubKey,
      })
    );
    expect(res.error).toBeUndefined();
    const { wrapped: reWrapped } = getResult<{ wrapped: Parameters<typeof unwrapAccountRootFromDevice>[0] }>(res);
    const recovered = await unwrapAccountRootFromDevice(reWrapped, new Uint8Array(throwaway.privKey));
    expect(Buffer.from(recovered).equals(Buffer.from(root))).toBe(true);
  });

  it('importWrappedAccountRoot requires this device to have a messaging identity', async () => {
    // Enroll alice but do NOT setupMessaging → no identity to unseal with.
    await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS }));
    const throwaway = await KeyHelper.generateIdentityKeyPair();
    const wrapped = await wrapAccountRootToDevice(
      generateAccountRoot(),
      new Uint8Array(throwaway.pubKey)
    );
    const res = await handleMessage(
      createRequest('importWrappedAccountRoot', { credentials: aliceCreds, wrapped })
    );
    expect(res.error).toMatch(/not set up/);
  });

  it('wrapAccountRootForDevice fails when this device has no root', async () => {
    const bundle = await setupAlice();
    const res = await handleMessage(
      createRequest('wrapAccountRootForDevice', {
        credentials: aliceCreds,
        recipientIdentityPubKey: bundle.identityKey,
      })
    );
    expect(res.error).toMatch(/No account root/);
  });
});
