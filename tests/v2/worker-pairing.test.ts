/**
 * Worker pairing / contact RPC tests (secure-messaging §5/§6).
 *
 * Drives set/get/list contact secrets, the device-key exchange (seal for a peer
 * / open what a peer sealed), and the self-channel contact announcement
 * (propagate a stored secret to the account's other devices). Value checks are
 * closed test-side by deriving pairID/exchangeKey/selfKey from the raw secret /
 * recovery phrase and confirming the enclave agrees.
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
import { arrayBufferToBase64url } from '@/v2/crypto-utils';
import { mnemonicToAccountRoot } from '@/v2/account-root';
import { derivePairID, deriveExchangeKey } from '@/v2/pairing';
import { deriveSelfKey, encryptSelfMessage, decryptSelfMessage } from '@/v2/self-channel';

const ALICE_PASS = 'correct-horse-battery-staple';
const aliceCreds = { method: 'passphrase' as const, userId: 'alice', passphrase: ALICE_PASS };
const BOB = 'bbbbbbbb-0000-0000-0000-000000000002';
const CAROL = 'cccccccc-0000-0000-0000-000000000003';
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
function secretBuf(fill: number): ArrayBuffer {
  return new Uint8Array(32).fill(fill).buffer;
}

/** Enroll + provision + open a session. If `withRoot`, also set up an account root. */
async function setupAndOpen(withRoot = false): Promise<{ sid: string; token: string; mnemonic?: string }> {
  expectOk(await handleMessage(createRequest('setupPassphrase', { userId: 'alice', passphrase: ALICE_PASS })))
  expectOk(await handleMessage(createRequest('setupMessaging', { credentials: aliceCreds })))
  let mnemonic: string | undefined
  if (withRoot) {
    mnemonic = getResult<{ mnemonic: string }>(
      expectOk(await handleMessage(createRequest('setupAccountRoot', { credentials: aliceCreds })))
    ).mnemonic
  }
  const open = expectOk(await handleMessage(createRequest('openMessaging', { credentials: aliceCreds })))
  const { sid, token } = getResult<{ sid: string; token: string }>(open)
  return mnemonic ? { sid, token, mnemonic } : { sid, token }
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory()
  await initDB()
  resetAuditLogger()
})
afterEach(() => closeDB())

describe('setContactSecret / getContactPairID / listContacts', () => {
  it('stores a secret and derives the expected pairID', async () => {
    const { sid, token } = await setupAndOpen()
    const secret = secretBuf(0x11)

    const set = expectOk(
      await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: BOB, secret }))
    )
    const { pairID } = getResult<{ pairID: string }>(set)
    const expected = await derivePairID(new Uint8Array(secret), 'alice', BOB)
    expect(pairID).toBe(expected)

    // getContactPairID returns the same value.
    const got = expectOk(
      await handleMessage(createRequest('getContactPairID', { sid, token, peerUserId: BOB }))
    )
    expect(getResult<{ pairID: string }>(got).pairID).toBe(expected)
  })

  it('getContactPairID errors for an unknown contact', async () => {
    const { sid, token } = await setupAndOpen()
    const res = await handleMessage(createRequest('getContactPairID', { sid, token, peerUserId: BOB }))
    expect(res.error).toMatch(/No pairing secret/)
  })

  it('listContacts returns every contact with its pairID', async () => {
    const { sid, token } = await setupAndOpen()
    await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: BOB, secret: secretBuf(0x11) }))
    await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: CAROL, secret: secretBuf(0x22) }))

    const res = expectOk(await handleMessage(createRequest('listContacts', { sid, token })))
    const { contacts } = getResult<{ contacts: Array<{ peerUserId: string; pairID: string }> }>(res)
    expect(contacts.map((c) => c.peerUserId).sort()).toEqual([BOB, CAROL].sort())
    const bob = contacts.find((c) => c.peerUserId === BOB)!
    expect(bob.pairID).toBe(await derivePairID(new Uint8Array(secretBuf(0x11)), 'alice', BOB))
  })
})

describe('device-key exchange', () => {
  it('sealDeviceExchange output opens for a peer holding the same secret', async () => {
    const { sid, token } = await setupAndOpen()
    const secret = secretBuf(0x11)
    await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: BOB, secret }))

    const sealed = expectOk(
      await handleMessage(
        createRequest('sealDeviceExchange', { sid, token, peerUserId: BOB, payload: utf8.encode('alice-devices').buffer })
      )
    )
    const { ciphertext } = getResult<{ ciphertext: ArrayBuffer }>(sealed)

    // The peer (Bob) derives the same exchange key from the shared secret.
    const key = await deriveExchangeKey(new Uint8Array(secret))
    const opened = await decryptSelfMessage(key, ciphertext, 'device-exchange')
    expect(fromUtf8.decode(opened)).toBe('alice-devices')
  })

  it('openDeviceExchange opens what a peer sealed', async () => {
    const { sid, token } = await setupAndOpen()
    const secret = secretBuf(0x11)
    await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: BOB, secret }))

    const key = await deriveExchangeKey(new Uint8Array(secret))
    const ct = await encryptSelfMessage(key, utf8.encode('bob-devices'), 'device-exchange')

    const res = expectOk(
      await handleMessage(
        createRequest('openDeviceExchange', { sid, token, peerUserId: BOB, ciphertext: ct.buffer.slice(0) })
      )
    )
    expect(fromUtf8.decode(getResult<{ payload: ArrayBuffer }>(res).payload)).toBe('bob-devices')
  })

  it('sealDeviceExchange errors without a contact secret', async () => {
    const { sid, token } = await setupAndOpen()
    const res = await handleMessage(
      createRequest('sealDeviceExchange', { sid, token, peerUserId: BOB, payload: utf8.encode('x').buffer })
    )
    expect(res.error).toMatch(/No pairing secret/)
  })
})

describe('contact announcement (self-channel sync)', () => {
  it('seals a stored contact for the account, readable by any device with the root', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true)
    const secret = secretBuf(0x11)
    await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: BOB, secret }))

    const sealed = expectOk(
      await handleMessage(createRequest('sealContactAnnouncement', { sid, token, peerUserId: BOB }))
    )
    const { ciphertext } = getResult<{ ciphertext: ArrayBuffer }>(sealed)

    // Another device with the same accountRoot opens it and recovers {peer, secret}.
    const selfKey = await deriveSelfKey(await mnemonicToAccountRoot(mnemonic!))
    const bytes = await decryptSelfMessage(selfKey, ciphertext, 'contact-announcement')
    const obj = JSON.parse(fromUtf8.decode(bytes)) as { peerUserId: string; secret: string }
    expect(obj.peerUserId).toBe(BOB)
    expect(obj.secret).toBe(arrayBufferToBase64url(secret))
  })

  it('applyContactAnnouncement stores a contact announced by another device', async () => {
    const { sid, token, mnemonic } = await setupAndOpen(true)
    const carolSecret = secretBuf(0x22)

    // Another device seals an announcement for Carol under the shared self-key.
    const selfKey = await deriveSelfKey(await mnemonicToAccountRoot(mnemonic!))
    const payload = utf8.encode(
      JSON.stringify({ peerUserId: CAROL, secret: arrayBufferToBase64url(carolSecret) })
    )
    const ct = await encryptSelfMessage(selfKey, payload, 'contact-announcement')

    const res = expectOk(
      await handleMessage(
        createRequest('applyContactAnnouncement', { sid, token, ciphertext: ct.buffer.slice(0) })
      )
    )
    const applied = getResult<{ peerUserId: string; pairID: string }>(res)
    expect(applied.peerUserId).toBe(CAROL)
    expect(applied.pairID).toBe(await derivePairID(new Uint8Array(carolSecret), 'alice', CAROL))

    // The secret is now stored locally — getContactPairID agrees.
    const got = expectOk(
      await handleMessage(createRequest('getContactPairID', { sid, token, peerUserId: CAROL }))
    )
    expect(getResult<{ pairID: string }>(got).pairID).toBe(applied.pairID)
  })

  it('sealContactAnnouncement errors without an account root (no self-key)', async () => {
    const { sid, token } = await setupAndOpen(false)
    await handleMessage(createRequest('setContactSecret', { sid, token, peerUserId: BOB, secret: secretBuf(0x11) }))
    const res = await handleMessage(createRequest('sealContactAnnouncement', { sid, token, peerUserId: BOB }))
    expect(res.error).toMatch(/No account root/)
  })
})
