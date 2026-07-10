/**
 * Connect invite ceremony RPC tests (rooms-and-trust §3.2/§3.4).
 *
 * Drives mint / accept / openInviteJoin / approveInviteJoin / forget / list over
 * the RPC boundary. mint + accept pause on a popup handshake (worker:show-invite /
 * worker:collect-invite); this file drives that handshake exactly like the
 * mnemonic ceremony test. The OTHER party is simulated test-side with the invite
 * crypto primitives, so a single enclave account exercises the whole flow.
 *
 * The core security property under test: the room secret is generated + parsed in
 * the enclave and NEVER appears in an RPC result — only opaque blobs (to the
 * popup) and public identity (scope / card / fingerprint) come back.
 *
 * Runs in happy-dom (default env) for self.postMessage plumbing + native crypto.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

import { handleMessage } from '@/v2/worker';
import type { RPCRequest, RPCResponse } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';
import { arrayBufferToBase64url } from '@/v2/crypto-utils';
import { deriveScope, deriveExchangeKey } from '@/v2/pairing';
import { encryptSelfMessage, decryptSelfMessage } from '@/v2/self-channel';
import { masterSigningPublicRaw, masterEncryptionPublicRaw, identityFingerprint } from '@/v2/master-identity';
import {
  buildConnectInvite,
  encodeInvite,
  decodeInvite,
  encodeAnnouncement,
  decodeAnnouncement,
  roomSecretFromB64url,
  type InviteCard,
} from '@/v2/invite';

vi.setConfig({ testTimeout: 30000 });

const DEVICE_EXCHANGE_CONTEXT = 'device-exchange';
const ALICE_PASS = 'correct-horse-battery-staple-2';
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
function toAb(u: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u.byteLength);
  new Uint8Array(b).set(u);
  return b;
}

/** Build a simulated party's identity card from a raw root (any 16+ bytes). */
async function cardFor(uid: string, root: Uint8Array, name?: string): Promise<InviteCard> {
  const msk = arrayBufferToBase64url(toAb(await masterSigningPublicRaw(root)));
  const mek = arrayBufferToBase64url(toAb(await masterEncryptionPublicRaw(root)));
  return name ? { uid, name, msk, mek } : { uid, msk, mek };
}

/** Enroll alice + provision an open messaging session WITH an account root. */
async function setupAndOpen(): Promise<{ sid: string; token: string }> {
  expectOk(await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })));
  expectOk(await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds })));
  expectOk(await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds })));
  const open = expectOk(await handleMessage(createRequest('openMessaging', { credentials: aliceCreds })));
  const { sid, token } = getResult<{ sid: string; token: string }>(open);
  return { sid, token };
}

/** A minimal view of the postMessage spy: its recorded call argument lists. */
type PostSpy = { mock: { calls: ReadonlyArray<readonly unknown[]> } };

/** Wait for a worker→client ceremony message of `type`, or undefined if none in time. */
async function waitForCeremony(
  spy: PostSpy,
  type: string,
  settled: () => boolean
): Promise<{ type: string; requestId: string; blob?: string } | undefined> {
  let msg: { type: string; requestId: string; blob?: string } | undefined;
  for (let i = 0; i < 1500 && !msg && !settled(); i++) {
    await new Promise((r) => setTimeout(r, 10));
    msg = spy.mock.calls.map((c) => c[0] as { type: string; requestId: string; blob?: string }).find((m) => m?.type === type);
  }
  return msg;
}

/** Call mintInvite and drive the show-invite handshake; capture the displayed blob. */
async function driveMint(
  sid: string,
  token: string,
  extra: Record<string, unknown> = {},
  action: 'shown' | 'cancelled' = 'shown'
): Promise<{ response: RPCResponse; blob: string | undefined }> {
  const spy = vi.spyOn(self, 'postMessage');
  const req = createRequest('mintInvite', { sid, token, ...extra });
  const p = handleMessage(req);
  let done = false;
  void p.finally(() => (done = true));
  const shown = await waitForCeremony(spy, 'worker:show-invite', () => done);
  if (shown && !done) {
    self.dispatchEvent(
      new MessageEvent('message', {
        data: {
          type: action === 'shown' ? 'worker:invite-shown' : 'worker:invite-show-cancelled',
          requestId: req.id,
        },
      })
    );
  }
  const response = await p;
  spy.mockRestore();
  return { response, blob: shown?.blob };
}

/** Call acceptInvite and drive the collect handshake, supplying `blob`. */
async function driveAccept(sid: string, token: string, blob: string): Promise<RPCResponse> {
  const spy = vi.spyOn(self, 'postMessage');
  const req = createRequest('acceptInvite', { sid, token });
  const p = handleMessage(req);
  let done = false;
  void p.finally(() => (done = true));
  const collect = await waitForCeremony(spy, 'worker:collect-invite', () => done);
  if (collect && !done) {
    self.dispatchEvent(new MessageEvent('message', { data: { type: 'worker:invite-blob', requestId: req.id, blob } }));
  }
  const response = await p;
  spy.mockRestore();
  return response;
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

describe('mintInvite', () => {
  it('arms an invite, shows the blob in the popup, and returns only public data', async () => {
    const { sid, token } = await setupAndOpen();
    const { response, blob } = await driveMint(sid, token, { nameHint: 'Alice', ttlMs: 60_000 });
    expectOk(response);
    const out = getResult<{ inviteId: string; scope: string }>(response);

    // The RPC result carries NO secret and NO blob — only inviteId + scope.
    expect(out.inviteId).toMatch(/[0-9a-f-]{36}/);
    expect(JSON.stringify(out)).not.toContain(blob!.slice(0, 24));
    expect(out).not.toHaveProperty('secret');

    // The blob went to the popup and encodes this account's card + a secret whose
    // scope matches what the PWA was told to subscribe on.
    const payload = decodeInvite(blob!);
    expect(payload.card.uid).toBe('alice');
    expect(payload.card.name).toBe('Alice');
    expect(payload.single).toBe(true);
    expect(await deriveScope(roomSecretFromB64url(payload.s))).toBe(out.scope);

    // It's persisted (survives close) and listable as public metadata.
    const list = getResult<{ invites: Array<{ inviteId: string; scope: string }> }>(
      expectOk(await handleMessage(createRequest('listInvites', { sid, token })))
    );
    expect(list.invites.map((i) => i.inviteId)).toContain(out.inviteId);
  });

  it('a cancelled display leaves no armed invite behind', async () => {
    const { sid, token } = await setupAndOpen();
    const { response } = await driveMint(sid, token, {}, 'cancelled');
    expect(response.error).toBeDefined();
    const list = getResult<{ invites: unknown[] }>(
      expectOk(await handleMessage(createRequest('listInvites', { sid, token })))
    );
    expect(list.invites).toHaveLength(0);
  });

  it('errors without an account root (no master identity)', async () => {
    // Open a session without a root: setupMessaging + openMessaging, no setupAccountRoot.
    expectOk(await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })));
    expectOk(await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds })));
    const open = expectOk(await handleMessage(createRequest('openMessaging', { credentials: aliceCreds })));
    const { sid, token } = getResult<{ sid: string; token: string }>(open);
    const { response } = await driveMint(sid, token);
    expect(response.error).toMatch(/No account root/);
  });
});

describe('acceptInvite', () => {
  it('confirms + stores the shared secret and seals our announcement for the minter', async () => {
    const { sid, token } = await setupAndOpen();

    // Simulate a minter (distinct account) and their invite blob.
    const minterRoot = new Uint8Array(16).fill(0x51);
    const minter = await cardFor('minter-uid', minterRoot, 'Minter');
    const secret = new Uint8Array(32).fill(0x77);
    const blob = encodeInvite(buildConnectInvite(minter, secret, { singleUse: true }));

    const response = await driveAccept(sid, token, blob);
    const out = getResult<{ scope: string; peer: { uid: string; fingerprint: string }; announcement: ArrayBuffer }>(
      expectOk(response)
    );

    // Public peer identity comes back with the right fingerprint; scope is derived.
    expect(out.peer.uid).toBe('minter-uid');
    expect(out.peer.fingerprint).toBe(
      await identityFingerprint(await masterSigningPublicRaw(minterRoot), await masterEncryptionPublicRaw(minterRoot))
    );
    expect(out.scope).toBe(await deriveScope(secret));

    // The sealed announcement (opaque to the PWA) decrypts under the shared secret
    // to OUR identity card — that's how the minter learns who joined.
    const key = await deriveExchangeKey(secret);
    const annBytes = await decryptSelfMessage(key, out.announcement, DEVICE_EXCHANGE_CONTEXT);
    expect(decodeAnnouncement(annBytes).uid).toBe('alice');

    // The shared secret is now stored as a contact (scope derivable in-session).
    const cs = getResult<{ scope: string }>(
      expectOk(await handleMessage(createRequest('getContactScope', { sid, token, peerUserId: 'minter-uid' })))
    );
    expect(cs.scope).toBe(out.scope);
  });

  it('rejects an expired invite', async () => {
    const { sid, token } = await setupAndOpen();
    const minter = await cardFor('minter-uid', new Uint8Array(16).fill(0x51));
    const secret = new Uint8Array(32).fill(0x77);
    const blob = encodeInvite(buildConnectInvite(minter, secret, { expiresAt: 1, singleUse: true }));
    const response = await driveAccept(sid, token, blob);
    expect(response.error).toMatch(/expired/);
  });
});

describe('openInviteJoin / approveInviteJoin', () => {
  it('opens a join, surfaces the joiner, and binds them on approval (single-use consumes)', async () => {
    const { sid, token } = await setupAndOpen();
    const { response, blob } = await driveMint(sid, token, { nameHint: 'Alice' });
    const { inviteId, scope } = getResult<{ inviteId: string; scope: string }>(expectOk(response));

    // The joiner (Bob) — simulated — seals HIS announcement under the invite secret.
    const secret = roomSecretFromB64url(decodeInvite(blob!).s);
    const bobRoot = new Uint8Array(16).fill(0x62);
    const bob = await cardFor('bob-uid', bobRoot, 'Bob');
    const key = await deriveExchangeKey(secret);
    const sealed = await encryptSelfMessage(key, encodeAnnouncement(bob), DEVICE_EXCHANGE_CONTEXT);

    // Alice opens the join → sees Bob's public identity + an approvalId, nothing committed yet.
    const opened = getResult<{ peer: { uid: string; name?: string; fingerprint: string }; approvalId: string }>(
      expectOk(await handleMessage(createRequest('openInviteJoin', { sid, token, inviteId, ciphertext: toAb(sealed) })))
    );
    expect(opened.peer.uid).toBe('bob-uid');
    expect(opened.peer.name).toBe('Bob');
    expect(opened.peer.fingerprint).toBe(
      await identityFingerprint(await masterSigningPublicRaw(bobRoot), await masterEncryptionPublicRaw(bobRoot))
    );
    expect(typeof opened.approvalId).toBe('string');

    // Approve BY approvalId → the enclave binds the uid it opened (bob-uid), returns it,
    // and consumes the single-use invite. The caller never supplies the uid.
    const approved = getResult<{ scope: string; peerUserId: string }>(
      expectOk(await handleMessage(createRequest('approveInviteJoin', { sid, token, approvalId: opened.approvalId })))
    );
    expect(approved.scope).toBe(scope);
    expect(approved.peerUserId).toBe('bob-uid');

    const cs = getResult<{ scope: string }>(
      expectOk(await handleMessage(createRequest('getContactScope', { sid, token, peerUserId: 'bob-uid' })))
    );
    expect(cs.scope).toBe(scope);

    const list = getResult<{ invites: unknown[] }>(
      expectOk(await handleMessage(createRequest('listInvites', { sid, token })))
    );
    expect(list.invites).toHaveLength(0); // consumed

    // Replaying the same approvalId fails — the approval was consumed.
    const replay = await handleMessage(createRequest('approveInviteJoin', { sid, token, approvalId: opened.approvalId }));
    expect(replay.error).toMatch(/No such pending approval/);
  });

  it('approveInviteJoin errors for an unknown approvalId', async () => {
    const { sid, token } = await setupAndOpen();
    const res = await handleMessage(
      createRequest('approveInviteJoin', { sid, token, approvalId: 'no-such-approval' })
    );
    expect(res.error).toMatch(/No such pending approval/);
  });

  it('openInviteJoin errors for an unknown invite', async () => {
    const { sid, token } = await setupAndOpen();
    const res = await handleMessage(
      createRequest('openInviteJoin', { sid, token, inviteId: 'nope', ciphertext: new Uint8Array(48).fill(1).buffer })
    );
    expect(res.error).toMatch(/No such armed invite/);
  });
});

describe('forgetInvite', () => {
  it('drops an armed invite', async () => {
    const { sid, token } = await setupAndOpen();
    const { response } = await driveMint(sid, token);
    const { inviteId } = getResult<{ inviteId: string }>(expectOk(response));

    expectOk(await handleMessage(createRequest('forgetInvite', { sid, token, inviteId })));
    const list = getResult<{ invites: unknown[] }>(
      expectOk(await handleMessage(createRequest('listInvites', { sid, token })))
    );
    expect(list.invites).toHaveLength(0);
  });
});
