/**
 * provisionMessaging — single-unlock setup (BUG-011) + in-enclave recovery-phrase
 * backup ceremony (BUG-007).
 *
 * Runs in happy-dom (the default env) rather than node, because it needs BOTH the
 * worker↔client message plumbing (self.postMessage / self.dispatchEvent, used to
 * drive the mnemonic-confirm handshake) AND native Ed25519/X25519 (happy-dom
 * delegates crypto.subtle to Node, which provides them). The mint path pauses on
 * `worker:show-mnemonic` until the client replies `worker:mnemonic-confirmed` /
 * `worker:mnemonic-cancelled`; the account root is persisted ONLY after confirm.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { handleMessage } from '@/v2/worker';
import type { RPCRequest, RPCResponse } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';

const ALICE_PASS = 'correct-horse-battery-staple-1';
const aliceCreds = { method: 'passphrase' as const, userId: 'alice', passphrase: ALICE_PASS };

function createRequest(method: string, params: unknown = {}): RPCRequest {
  return { id: `req-${method}-${Math.random().toString(36).slice(2)}`, method, params };
}
function getResult<T>(response: RPCResponse): T {
  return response.result as T;
}

async function enrollAlice(): Promise<void> {
  const res = await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS }));
  expect(res.error).toBeUndefined();
}

interface ShownMnemonic {
  type: string;
  requestId: string;
  mnemonic: string;
}

/**
 * Call provisionMessaging and, when `action` is set, drive the mnemonic-confirm
 * handshake: wait for the worker's `worker:show-mnemonic`, then dispatch the
 * confirm/cancel reply. Returns the RPC response and the shown-mnemonic message
 * (if any).
 */
async function provision(
  params: Record<string, unknown>,
  action: 'confirm' | 'cancel' | 'none'
): Promise<{ response: RPCResponse; shown: ShownMnemonic | undefined }> {
  const postSpy = vi.spyOn(self, 'postMessage');
  const req = createRequest('provisionMessaging', { credentials: aliceCreds, ...params });
  const responsePromise = handleMessage(req);

  let shown: ShownMnemonic | undefined;
  if (action !== 'none') {
    for (let i = 0; i < 200 && !shown; i++) {
      await new Promise((r) => setTimeout(r, 5));
      shown = postSpy.mock.calls
        .map((c) => c[0] as ShownMnemonic)
        .find((m) => m?.type === 'worker:show-mnemonic');
    }
    self.dispatchEvent(
      new MessageEvent('message', {
        data: {
          type: action === 'confirm' ? 'worker:mnemonic-confirmed' : 'worker:mnemonic-cancelled',
          requestId: req.id,
        },
      })
    );
  }

  const response = await responsePromise;
  postSpy.mockRestore();
  return { response, shown };
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

describe('provisionMessaging — mint + confirm (BUG-007/BUG-011)', () => {
  it('shows the phrase, confirms, persists the root, and returns NO mnemonic', async () => {
    await enrollAlice();
    const { response, shown } = await provision({}, 'confirm');
    expect(response.error).toBeUndefined();

    // The phrase was shown in-enclave (worker:show-mnemonic), a valid 12-word BIP39.
    expect(shown?.type).toBe('worker:show-mnemonic');
    expect(shown!.mnemonic.trim().split(/\s+/)).toHaveLength(12);

    // The result NEVER carries the mnemonic back to the PWA.
    const out = getResult<Record<string, unknown>>(response);
    expect(out).not.toHaveProperty('mnemonic');
    expect(out.sid).toMatch(/[0-9a-f-]{36}/);
    expect((out.bundle as { oneTimePreKeys: unknown[] }).oneTimePreKeys).toHaveLength(20);

    // Root persisted ONLY after confirm; the session's self-channel is wired.
    const hasRoot = getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    );
    expect(hasRoot.present).toBe(true);
    const selfScope = await handleMessage(
      createRequest('getSelfScope', { sid: out.sid as string, token: out.token as string })
    );
    expect(selfScope.error).toBeUndefined();
  });

  it('cancelling the backup persists nothing and errors', async () => {
    await enrollAlice();
    const { response } = await provision({}, 'cancel');

    expect(response.error).toBeDefined();
    // No orphaned account root — the whole setup aborts.
    const hasRoot = getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    );
    expect(hasRoot.present).toBe(false);
  });

  it('honors a custom one-time prekey count on the mint path', async () => {
    await enrollAlice();
    const { response } = await provision({ oneTimePrekeyCount: 3 }, 'confirm');
    expect(response.error).toBeUndefined();
    const count = getResult<{ count: number }>(
      await handleMessage(createRequest('getPrekeyCount', { userId: 'alice' }))
    );
    expect(count.count).toBe(3);
  });

  it('with an existing root: no ceremony, opens the session directly', async () => {
    await enrollAlice();
    // Pre-mint a root out-of-band, then provision — no worker:show-mnemonic expected.
    expect((await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds }))).error).toBeUndefined();

    const { response, shown } = await provision({}, 'none');
    expect(response.error).toBeUndefined();
    expect(shown).toBeUndefined();
    const out = getResult<{ sid: string; token: string }>(response);
    const selfScope = await handleMessage(createRequest('getSelfScope', { sid: out.sid, token: out.token }));
    expect(selfScope.error).toBeUndefined();
  });

  it('rejects wrong credentials before any ceremony or persistence', async () => {
    await enrollAlice();
    const postSpy = vi.spyOn(self, 'postMessage');
    const res = await handleMessage(
      createRequest('provisionMessaging', {
        credentials: { method: 'passphrase', userId: 'alice', passphrase: 'wrong' },
      })
    );
    expect(res.error).toBeDefined();
    // Unlock failed → no mnemonic ceremony was started.
    expect(postSpy.mock.calls.map((c) => c[0] as { type?: string }).find((m) => m?.type === 'worker:show-mnemonic')).toBeUndefined();
    postSpy.mockRestore();
    const hasRoot = getResult<{ present: boolean }>(
      await handleMessage(createRequest('hasAccountRoot', { userId: 'alice' }))
    );
    expect(hasRoot.present).toBe(false);
  });
});
