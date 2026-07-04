/**
 * Worker self-channel RPC tests (secure-messaging §18.2).
 *
 * Drives getSelfScope / sealSelfMessage / openSelfMessage over the RPC boundary,
 * and verifies openMessaging caches the self-key/scope so no extra unlock is
 * needed. Value checks are closed against the recovery phrase: decode it to the
 * root test-side, derive the expected scope/key, and confirm the RPC agrees and
 * that a sealed payload is readable by any device holding the same root.
 *
 * Runs in the `node` environment for native HKDF/AES-GCM + Ed25519 tokens.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { handleMessage } from '@/v2/worker';
import type { RPCRequest, RPCResponse } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';
import { mnemonicToAccountRoot } from '@/v2/account-root';
import {
  deriveSelfScope,
  deriveSelfKey,
  encryptSelfMessage,
  decryptSelfMessage,
} from '@/v2/self-channel';

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

describe('getSelfScope', () => {
  it('returns the scope derived from the account root', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true);
    const root = await mnemonicToAccountRoot(mnemonic!);
    const expected = await deriveSelfScope(root);

    const res = expectOk(await handleMessage(createRequest('getSelfScope', { sid, token })));
    expect(getResult<{ selfScope: string }>(res).selfScope).toBe(expected);
  });

  it('errors when the session has no account root', async () => {
    const { sid, token } = await setupAndOpen(false);
    const res = await handleMessage(createRequest('getSelfScope', { sid, token }));
    expect(res.error).toMatch(/No account root/);
  });

  it('a session opened BEFORE the root existed has no self-channel', async () => {
    // Open first (no root), then set up the root: the already-open session did
    // not cache a self-key, so a re-open is required to use the self-channel.
    const { sid, token } = await setupAndOpen(false);
    expectOk(await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds })));
    const stale = await handleMessage(createRequest('getSelfScope', { sid, token }));
    expect(stale.error).toMatch(/No account root/);

    const reopen = expectOk(await handleMessage(createRequest('openMessaging', { credentials: aliceCreds })));
    const fresh = getResult<{ sid: string; token: string }>(reopen);
    expectOk(await handleMessage(createRequest('getSelfScope', fresh)));
  });
});

describe('sealSelfMessage / openSelfMessage', () => {
  it('round-trips a payload through the RPC surface', async () => {
    const { sid, token } = await setupAndOpen(true);
    const payload = utf8.encode('contact-add: bob=word-pair').buffer;

    const sealed = expectOk(
      await handleMessage(createRequest('sealSelfMessage', { sid, token, payload, context: 'announcement' }))
    );
    const { ciphertext } = getResult<{ ciphertext: ArrayBuffer }>(sealed);

    const opened = expectOk(
      await handleMessage(createRequest('openSelfMessage', { sid, token, ciphertext, context: 'announcement' }))
    );
    const { payload: out } = getResult<{ payload: ArrayBuffer }>(opened);
    expect(fromUtf8.decode(out)).toBe('contact-add: bob=word-pair');
  });

  it('a payload sealed via RPC is readable by any device holding the same root', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true);
    const root = await mnemonicToAccountRoot(mnemonic!);

    const sealed = expectOk(
      await handleMessage(
        createRequest('sealSelfMessage', {
          sid,
          token,
          payload: utf8.encode('snapshot-state').buffer,
          context: 'snapshot',
        })
      )
    );
    const { ciphertext } = getResult<{ ciphertext: ArrayBuffer }>(sealed);

    // Another device derives the same self-key from the shared root and decrypts.
    const selfKey = await deriveSelfKey(root);
    const plain = await decryptSelfMessage(selfKey, ciphertext, 'snapshot');
    expect(fromUtf8.decode(plain)).toBe('snapshot-state');
  });

  it('opens a payload sealed by another device (test-side) with the same root', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true);
    const root = await mnemonicToAccountRoot(mnemonic!);
    const selfKey = await deriveSelfKey(root);
    const ct = await encryptSelfMessage(selfKey, utf8.encode('from-other-device'), 'announcement');

    const opened = expectOk(
      await handleMessage(
        createRequest('openSelfMessage', { sid, token, ciphertext: ct.buffer.slice(0), context: 'announcement' })
      )
    );
    expect(fromUtf8.decode(getResult<{ payload: ArrayBuffer }>(opened).payload)).toBe('from-other-device');
  });

  it('binds context: sealing as snapshot does not open as announcement', async () => {
    const { sid, token } = await setupAndOpen(true);
    const sealed = expectOk(
      await handleMessage(
        createRequest('sealSelfMessage', { sid, token, payload: utf8.encode('x').buffer, context: 'snapshot' })
      )
    );
    const { ciphertext } = getResult<{ ciphertext: ArrayBuffer }>(sealed);
    const res = await handleMessage(
      createRequest('openSelfMessage', { sid, token, ciphertext, context: 'announcement' })
    );
    expect(res.error).toBeDefined();
  });

  it('sealSelfMessage errors without an account root', async () => {
    const { sid, token } = await setupAndOpen(false);
    const res = await handleMessage(
      createRequest('sealSelfMessage', { sid, token, payload: utf8.encode('x').buffer })
    );
    expect(res.error).toMatch(/No account root/);
  });
});
