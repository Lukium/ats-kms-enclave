/**
 * Connect invite crypto tests (rooms-and-trust §3.2/§3.3).
 *
 * The room secret is generated in the enclave and round-trips through an opaque
 * blob; decode tolerates a link/fragment wrapper; malformed or wrong-version
 * blobs are rejected before any invite is honored.
 */

import { describe, it, expect } from 'vitest';
import {
  generateRoomSecret,
  roomSecretToB64url,
  roomSecretFromB64url,
  encodeInvite,
  decodeInvite,
  buildConnectInvite,
  isInviteExpired,
  encodeAnnouncement,
  decodeAnnouncement,
  type InviteCard,
} from '@/v2/invite';

// Real cards carry 32-byte Ed25519 (msk) / X25519 (mek) public keys, base64url.
const MSK = roomSecretToB64url(new Uint8Array(32).fill(1));
const MEK = roomSecretToB64url(new Uint8Array(32).fill(2));
const card: InviteCard = { uid: 'alice-uuid', name: 'Alice', msk: MSK, mek: MEK };

describe('generateRoomSecret', () => {
  it('is 32 random bytes, distinct per call, and round-trips through base64url', () => {
    const a = generateRoomSecret();
    const b = generateRoomSecret();
    expect(a).toHaveLength(32);
    expect(Array.from(a)).not.toEqual(Array.from(b));
    const back = roomSecretFromB64url(roomSecretToB64url(a));
    expect(Array.from(back)).toEqual(Array.from(a));
  });
});

describe('encodeInvite / decodeInvite', () => {
  it('round-trips a connect-1:1 payload including secret + policy', () => {
    const secret = generateRoomSecret();
    const payload = buildConnectInvite(card, secret, { expiresAt: 1_000, singleUse: true });
    const blob = encodeInvite(payload);
    expect(blob).toMatch(/^[A-Za-z0-9_-]+$/);

    const out = decodeInvite(blob);
    expect(out).toEqual(payload);
    expect(roomSecretFromB64url(out.s)).toEqual(secret);
    expect(out.t).toBe('connect-1:1');
    expect(out.single).toBe(true);
  });

  it('omits absent optional fields (name / exp / single)', () => {
    const payload = buildConnectInvite({ uid: 'u', msk: MSK, mek: MEK }, generateRoomSecret());
    const out = decodeInvite(encodeInvite(payload));
    expect(out.card.name).toBeUndefined();
    expect(out.exp).toBeUndefined();
    expect(out.single).toBeUndefined();
  });

  it('tolerates a surrounding link / `c=` fragment / bare token', () => {
    const blob = encodeInvite(buildConnectInvite(card, generateRoomSecret()));
    expect(decodeInvite(`https://ats.run/connect#c=${blob}`).card.uid).toBe('alice-uuid');
    expect(decodeInvite(`#${blob}`).card.uid).toBe('alice-uuid');
    expect(decodeInvite(blob).card.uid).toBe('alice-uuid');
  });
});

describe('decodeInvite rejects bad input', () => {
  it('throws on non-base64 / non-JSON / empty', () => {
    expect(() => decodeInvite('%%%')).toThrow(/Invalid invite/);
    expect(() => decodeInvite('Zm9v')).toThrow(/Invalid invite/); // "foo" — valid b64url, not JSON
    expect(() => decodeInvite('')).toThrow(/Invalid invite/);
  });

  it('throws on wrong version, bad type, or missing card fields', () => {
    const b64 = (o: unknown): string => {
      const bytes = new TextEncoder().encode(JSON.stringify(o));
      // inline base64url so the test does not depend on the module under test
      let bin = '';
      for (const byte of bytes) bin += String.fromCharCode(byte);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    expect(() => decodeInvite(b64({ v: 2, t: 'connect-1:1', card, s: 'x' }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(b64({ v: 1, t: 'nope', card, s: 'x' }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(b64({ v: 1, t: 'room', card: { uid: 'u' }, s: 'x' }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(b64({ v: 1, t: 'room', card, s: '' }))).toThrow(/Invalid invite/);
  });
});

describe('decodeInvite hardens against malformed input', () => {
  // Inline base64url so these tests do not depend on the module's encoder.
  const toBlob = (o: unknown): string => {
    const bytes = new TextEncoder().encode(JSON.stringify(o));
    let bin = '';
    for (const byte of bytes) bin += String.fromCharCode(byte);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const secret = roomSecretToB64url(generateRoomSecret());
  const base = { v: 1, t: 'connect-1:1', card, s: secret };

  it('rejects an over-long blob before decoding', () => {
    expect(() => decodeInvite('a'.repeat(4097))).toThrow(/Invalid invite/);
  });

  it('requires the room secret to be exactly 32 bytes', () => {
    expect(() => decodeInvite(toBlob({ ...base, s: roomSecretToB64url(new Uint8Array(16)) }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(toBlob({ ...base, s: roomSecretToB64url(new Uint8Array(31)) }))).toThrow(/Invalid invite/);
  });

  it('requires msk and mek to be exactly 32 bytes', () => {
    const shortKey = roomSecretToB64url(new Uint8Array(16));
    expect(() => decodeInvite(toBlob({ ...base, card: { ...card, msk: shortKey } }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(toBlob({ ...base, card: { ...card, mek: shortKey } }))).toThrow(/Invalid invite/);
  });

  it('bounds the uid and name lengths', () => {
    expect(() => decodeInvite(toBlob({ ...base, card: { ...card, uid: 'u'.repeat(129) } }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(toBlob({ ...base, card: { ...card, name: 'n'.repeat(129) } }))).toThrow(/Invalid invite/);
  });

  it('requires a sane expiry (positive safe integer, not absurdly far future)', () => {
    expect(() => decodeInvite(toBlob({ ...base, exp: -1 }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(toBlob({ ...base, exp: 1.5 }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(toBlob({ ...base, exp: 5_000_000_000_000 }))).toThrow(/Invalid invite/); // > year 2100
    expect(decodeInvite(toBlob({ ...base, exp: 1_000 })).exp).toBe(1_000);
  });

  it('rejects unknown fields on the payload or the card', () => {
    expect(() => decodeInvite(toBlob({ ...base, evil: 1 }))).toThrow(/Invalid invite/);
    expect(() => decodeInvite(toBlob({ ...base, card: { ...card, evil: 1 } }))).toThrow(/Invalid invite/);
  });
});

describe('encodeInvite rejects an invalid payload', () => {
  it('throws rather than mint a malformed invite', () => {
    // @ts-expect-error — deliberately invalid type at the call site
    expect(() => encodeInvite({ v: 1, t: 'bad', card, s: 'x' })).toThrow(/Invalid invite/);
  });
});

describe('encodeAnnouncement / decodeAnnouncement', () => {
  it('round-trips the joiner identity card (no secret, no device keys)', () => {
    const bytes = encodeAnnouncement(card);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(decodeAnnouncement(bytes)).toEqual(card);
    // The announcement is identity-only — it must not carry a room secret.
    expect(new TextDecoder().decode(bytes)).not.toContain('"s"');
  });

  it('rejects a malformed card or a non-announcement blob', () => {
    // @ts-expect-error — missing msk/mek
    expect(() => encodeAnnouncement({ uid: 'u' })).toThrow(/Invalid announcement/);
    expect(() => decodeAnnouncement(new TextEncoder().encode('not json'))).toThrow(/Invalid announcement/);
    // an invite blob decoded as an announcement (wrong kind) is rejected
    const inviteJson = new TextEncoder().encode(
      JSON.stringify({ v: 1, t: 'connect-1:1', card, s: 'x' })
    );
    expect(() => decodeAnnouncement(inviteJson)).toThrow(/Invalid announcement/);
  });
});

describe('isInviteExpired', () => {
  it('respects exp; treats a missing exp as never-expiring', () => {
    const withExp = buildConnectInvite(card, generateRoomSecret(), { expiresAt: 1_000 });
    expect(isInviteExpired(withExp, 999)).toBe(false);
    expect(isInviteExpired(withExp, 1_000)).toBe(true);
    const noExp = buildConnectInvite(card, generateRoomSecret());
    expect(isInviteExpired(noExp, Number.MAX_SAFE_INTEGER)).toBe(false);
  });
});
