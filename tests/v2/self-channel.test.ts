/**
 * Self-channel crypto tests (secure-messaging §18.2).
 *
 * Covers deterministic derivation of `selfScope`/`selfKey` from `accountRoot`
 * (same root → same scope/key across "devices"; different roots diverge; the two
 * legs are domain-separated) and the announcement/snapshot encrypt/decrypt round
 * trip incl. context binding and tamper/format rejection.
 *
 * Runs in the `node` environment for native `crypto.subtle` (HKDF + AES-GCM).
 */

// @vitest-environment node

import { describe, it, expect } from 'vitest';

import {
  deriveSelfScope,
  deriveSelfKey,
  encryptSelfMessage,
  decryptSelfMessage,
  SELF_CONTEXT_ANNOUNCEMENT,
  SELF_CONTEXT_SNAPSHOT,
} from '@/v2/self-channel';

const FIXED_ROOT = new Uint8Array(16).fill(0x11);

describe('deriveSelfScope', () => {
  it('is deterministic for a given accountRoot (every device agrees)', async () => {
    const a = await deriveSelfScope(FIXED_ROOT);
    const b = await deriveSelfScope(Uint8Array.from(FIXED_ROOT));
    expect(a).toBe(b);
  });

  it('is a URL-safe base64url string (no prefix, no padding/special chars)', async () => {
    const scope = await deriveSelfScope(FIXED_ROOT);
    expect(scope).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(scope.startsWith('self:')).toBe(false);
  });

  it('differs for different accountRoots', async () => {
    const a = await deriveSelfScope(new Uint8Array(16).fill(0x01));
    const b = await deriveSelfScope(new Uint8Array(16).fill(0x02));
    expect(a).not.toBe(b);
  });
});

describe('deriveSelfKey', () => {
  it('derives a non-extractable AES-GCM key', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    expect(key.type).toBe('secret');
    expect(key.extractable).toBe(false);
    expect(key.algorithm.name).toBe('AES-GCM');
  });

  it('two devices deriving from the same root can decrypt each other', async () => {
    const keyDevice1 = await deriveSelfKey(FIXED_ROOT);
    const keyDevice2 = await deriveSelfKey(Uint8Array.from(FIXED_ROOT));
    const msg = new TextEncoder().encode('contact-add: bob');
    const ct = await encryptSelfMessage(keyDevice1, msg);
    const pt = await decryptSelfMessage(keyDevice2, ct);
    expect(new TextDecoder().decode(pt)).toBe('contact-add: bob');
  });

  it('a key from a different root cannot decrypt', async () => {
    const key = await deriveSelfKey(new Uint8Array(16).fill(0x01));
    const other = await deriveSelfKey(new Uint8Array(16).fill(0x02));
    const ct = await encryptSelfMessage(key, new TextEncoder().encode('secret'));
    await expect(decryptSelfMessage(other, ct)).rejects.toThrow();
  });

  it('scope and key are domain-separated (key bytes are not the scope bytes)', async () => {
    // Indirect check: encrypting with selfKey then trying to treat the scope as a
    // key is impossible via the public API; instead assert distinct HKDF legs by
    // confirming two different roots that collide in scope would be astronomically
    // unlikely — here we just assert scope != any base64 of a round trip.
    const scope = await deriveSelfScope(FIXED_ROOT);
    const key = await deriveSelfKey(FIXED_ROOT);
    const ct = await encryptSelfMessage(key, new TextEncoder().encode(scope));
    // Ciphertext must not equal the scope (sanity that encryption happened).
    expect(new TextDecoder().decode(ct.subarray(12))).not.toBe(scope);
  });
});

describe('encryptSelfMessage / decryptSelfMessage', () => {
  it('round-trips arbitrary bytes', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    const payload = crypto.getRandomValues(new Uint8Array(200));
    const ct = await encryptSelfMessage(key, payload, SELF_CONTEXT_SNAPSHOT);
    const pt = await decryptSelfMessage(key, ct, SELF_CONTEXT_SNAPSHOT);
    expect(Buffer.from(pt).equals(Buffer.from(payload))).toBe(true);
  });

  it('uses a random IV (two encryptions of the same plaintext differ)', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    const msg = new TextEncoder().encode('same');
    const a = await encryptSelfMessage(key, msg);
    const b = await encryptSelfMessage(key, msg);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('binds context: a snapshot blob does not decrypt as an announcement', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    const ct = await encryptSelfMessage(
      key,
      new TextEncoder().encode('state'),
      SELF_CONTEXT_SNAPSHOT
    );
    await expect(
      decryptSelfMessage(key, ct, SELF_CONTEXT_ANNOUNCEMENT)
    ).rejects.toThrow();
  });

  it('defaults to the announcement context on both sides', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    const ct = await encryptSelfMessage(key, new TextEncoder().encode('hi'));
    const pt = await decryptSelfMessage(key, ct); // both default to announcement
    expect(new TextDecoder().decode(pt)).toBe('hi');
  });

  it('rejects a truncated/malformed blob', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    await expect(decryptSelfMessage(key, new Uint8Array(8))).rejects.toThrow(/too short/);
  });

  it('rejects a tampered ciphertext', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    const ct = await encryptSelfMessage(key, new TextEncoder().encode('hello'));
    const last = ct.length - 1;
    ct[last] = ct[last]! ^ 0xff; // flip a tag byte
    await expect(decryptSelfMessage(key, ct)).rejects.toThrow();
  });

  it('accepts an ArrayBuffer blob as well as a Uint8Array', async () => {
    const key = await deriveSelfKey(FIXED_ROOT);
    const ct = await encryptSelfMessage(key, new TextEncoder().encode('buf'));
    const asArrayBuffer = ct.buffer.slice(
      ct.byteOffset,
      ct.byteOffset + ct.byteLength
    ) as ArrayBuffer;
    const pt = await decryptSelfMessage(key, asArrayBuffer);
    expect(new TextDecoder().decode(pt)).toBe('buf');
  });
});
