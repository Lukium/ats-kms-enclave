/**
 * Per-device envelope + fan-out bundle tests (secure-messaging §8/§12).
 *
 * Headline: a real multi-device fan-out over the fork. Sender A1 encrypts one
 * message to three recipient devices (B1, B2, A2); each recipient opens the ONE
 * opaque bundle by trial decryption and recovers the plaintext, while a device
 * not addressed gets null. Critically, a failed trial (wrong envelope) leaves
 * the recipient's session intact — a subsequent legit message still decrypts and
 * no one-time prekey is burned (fork MAC isolation).
 *
 * Runs in the `node` environment for native X25519/Ed25519.
 */

// @vitest-environment node

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
} from '@lukium/libsignal-protocol-typescript';
import type { DeviceType } from '@lukium/libsignal-protocol-typescript';

import { initDB, closeDB, countUnconsumedOnetimePrekeys } from '@/v2/storage';
import {
  createSignalProtocolStore,
  generateIdentity,
  generateSignedPrekey,
  generateOneTimePrekeys,
  getPublicBundle,
  type PublicPreKeyBundle,
} from '@/v2/signal';
import {
  encryptEnvelope,
  serializeBundle,
  parseBundle,
  buildFanoutBundle,
  trialDecryptEnvelope,
  openFanoutBundle,
  ENVELOPE_TYPE_PREKEY,
  ENVELOPE_TYPE_WHISPER,
  type Envelope,
} from '@/v2/envelope';

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

function makeMkek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** A single device: its own KMS identity (store + mkek), provisioned with keys. */
interface Device {
  id: string;
  store: ReturnType<typeof createSignalProtocolStore>;
  addr: SignalProtocolAddress;
}

async function makeDevice(id: string, startKeyId: number): Promise<Device> {
  const mkek = await makeMkek();
  await generateIdentity(id, mkek);
  await generateSignedPrekey(id, mkek, 1);
  await generateOneTimePrekeys(id, mkek, startKeyId, 5);
  return { id, store: createSignalProtocolStore(id, mkek), addr: new SignalProtocolAddress(id, 1) };
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

/** Establish an outbound session from `sender` to `recipient` and return the cipher. */
async function outboundCipher(sender: Device, recipient: Device): Promise<SessionCipher> {
  const bundle = await getPublicBundle(recipient.id);
  const builder = new SessionBuilder(sender.store, recipient.addr);
  await builder.processPreKey(bundleToDevice(bundle));
  return new SessionCipher(sender.store, recipient.addr);
}

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});

afterEach(() => {
  closeDB();
});

describe('serializeBundle / parseBundle', () => {
  it('round-trips envelopes (bytes preserved, tag reserved)', () => {
    const envelopes: Envelope[] = [
      { type: ENVELOPE_TYPE_PREKEY, body: new Uint8Array([1, 2, 3]) },
      { type: ENVELOPE_TYPE_WHISPER, body: new Uint8Array([9, 8, 7, 6]) },
    ];
    const parsed = parseBundle(serializeBundle(envelopes));
    expect(parsed).toHaveLength(2);
    // Order may be shuffled; match by body content.
    const bodies = parsed.map((e) => Array.from(e.body).join(','));
    expect(bodies).toContain('1,2,3');
    expect(bodies).toContain('9,8,7,6');
    for (const e of parsed) expect(e.tag).toBeUndefined();
  });

  it('preserves a reserved tag when present', () => {
    const parsed = parseBundle(
      serializeBundle([{ type: 1, body: new Uint8Array([0]), tag: new Uint8Array([42, 43]) }])
    );
    expect(Array.from(parsed[0]!.tag!)).toEqual([42, 43]);
  });

  it('handles an empty bundle', () => {
    expect(parseBundle(serializeBundle([]))).toEqual([]);
  });

  it('rejects a malformed / truncated bundle', () => {
    expect(() => parseBundle(new Uint8Array([1]))).toThrow(/too short/);
    const good = serializeBundle([{ type: 1, body: new Uint8Array([1, 2, 3, 4]) }]);
    expect(() => parseBundle(good.subarray(0, good.length - 2))).toThrow(/Malformed|invalid body/);
  });

  it('rejects an unsupported version', () => {
    const good = serializeBundle([{ type: 1, body: new Uint8Array([1]) }]);
    const bad = good.slice();
    bad[0] = 9;
    expect(() => parseBundle(bad)).toThrow(/version/);
  });
});

describe('multi-device fan-out (milestone)', () => {
  it('each addressed device opens the one opaque bundle; an unaddressed one gets null', async () => {
    // Alice devices A1 (sender), A2 (own other device); Bob devices B1, B2.
    // A third-party device C1 shares no session with A1.
    const a1 = await makeDevice('a1', 100);
    const a2 = await makeDevice('a2', 200);
    const b1 = await makeDevice('b1', 300);
    const b2 = await makeDevice('b2', 400);
    const c1 = await makeDevice('c1', 500);

    // A1 establishes outbound sessions to every recipient device.
    const toA2 = await outboundCipher(a1, a2);
    const toB1 = await outboundCipher(a1, b1);
    const toB2 = await outboundCipher(a1, b2);

    const plaintext = utf8.encode('lunch at noon?');
    const bundle = await buildFanoutBundle([toA2, toB1, toB2], plaintext);

    // Bundle is opaque: three envelopes, all PreKey (first message), shuffled.
    const parsed = parseBundle(bundle);
    expect(parsed).toHaveLength(3);
    for (const e of parsed) expect(e.type).toBe(ENVELOPE_TYPE_PREKEY);

    // Each recipient opens with its session to the sender A1.
    const a1AddrFrom = (d: Device): SessionCipher => new SessionCipher(d.store, a1.addr);
    expect(fromUtf8.decode((await openFanoutBundle([a1AddrFrom(b1)], bundle))!)).toBe('lunch at noon?');
    expect(fromUtf8.decode((await openFanoutBundle([a1AddrFrom(b2)], bundle))!)).toBe('lunch at noon?');
    expect(fromUtf8.decode((await openFanoutBundle([a1AddrFrom(a2)], bundle))!)).toBe('lunch at noon?');

    // C1 has no session with A1 → null.
    expect(await openFanoutBundle([a1AddrFrom(c1)], bundle)).toBeNull();
  });

  it('a failed trial burns no prekey and leaves the device able to receive', async () => {
    const a1 = await makeDevice('a1', 100);
    const b1 = await makeDevice('b1', 300);
    const b2 = await makeDevice('b2', 400);

    // A bundle addressed ONLY to B2 — none of it is for B1.
    const toB2 = await outboundCipher(a1, b2);
    const onlyForB2 = await buildFanoutBundle([toB2], utf8.encode('not for b1'));

    const b1FromA1 = new SessionCipher(b1.store, a1.addr);
    expect(await countUnconsumedOnetimePrekeys('b1')).toBe(5);

    // B1 trial-decrypts B2's PreKey envelope and fails — must not consume a prekey.
    expect(await openFanoutBundle([b1FromA1], onlyForB2)).toBeNull();
    expect(await countUnconsumedOnetimePrekeys('b1')).toBe(5);

    // A legit message to B1 afterwards still works (and consumes exactly one OTK).
    const toB1 = await outboundCipher(a1, b1);
    const forB1 = await buildFanoutBundle([toB1], utf8.encode('for b1'));
    expect(fromUtf8.decode((await openFanoutBundle([b1FromA1], forB1))!)).toBe('for b1');
    expect(await countUnconsumedOnetimePrekeys('b1')).toBe(4);
  });

  it('trialDecryptEnvelope returns null for an unknown envelope type', async () => {
    const a1 = await makeDevice('a1', 100);
    const b1 = await makeDevice('b1', 300);
    const cipher = new SessionCipher(b1.store, a1.addr);
    const plaintext = await trialDecryptEnvelope(cipher, { type: 7, body: new Uint8Array([1, 2]) });
    expect(plaintext).toBeNull();
  });
});

describe('encryptEnvelope', () => {
  it('produces a PreKey envelope until the peer replies, then Whisper', async () => {
    const a1 = await makeDevice('a1', 100);
    const b1 = await makeDevice('b1', 300);
    const toB1 = await outboundCipher(a1, b1);

    // First A1->B1 message is a PreKey (type 3) message.
    const first = await encryptEnvelope(toB1, utf8.encode('one'));
    expect(first.type).toBe(ENVELOPE_TYPE_PREKEY);

    // B1 receives it (establishing its inbound session) and replies (Whisper).
    const b1FromA1 = new SessionCipher(b1.store, a1.addr);
    await trialDecryptEnvelope(b1FromA1, first);
    const reply = await encryptEnvelope(b1FromA1, utf8.encode('reply'));
    expect(reply.type).toBe(ENVELOPE_TYPE_WHISPER);

    // A1 processes the reply, clearing its pending-prekey state; the next
    // A1->B1 message is now a Whisper (type 1) message.
    await trialDecryptEnvelope(toB1, reply);
    const second = await encryptEnvelope(toB1, utf8.encode('two'));
    expect(second.type).toBe(ENVELOPE_TYPE_WHISPER);
  });
});
