/**
 * accountRoot device-wrap tests (secure-messaging §18.1).
 *
 * The headline test seals an accountRoot to a REAL fork-generated identity key
 * (33-byte 0x05-prefixed public) and unseals it with that identity's 32-byte
 * private scalar — proving byte-compatibility with the keyserver bundle format.
 * Plus: raw-32 public input, cross-device rejection, tamper rejection, and the
 * malformed-input surface.
 *
 * Runs in the `node` environment for native `crypto.subtle` X25519.
 */

// @vitest-environment node

import { describe, it, expect } from 'vitest';
import { KeyHelper } from '@lukium/libsignal-protocol-typescript';

import { generateAccountRoot } from '@/v2/account-root';
import {
  wrapAccountRootToDevice,
  unwrapAccountRootFromDevice,
} from '@/v2/device-wrap';

/** Generate a fork identity and return {pub33, priv32} as Uint8Arrays. */
async function forkIdentity(): Promise<{ pub: Uint8Array; priv: Uint8Array }> {
  const id = await KeyHelper.generateIdentityKeyPair();
  return { pub: new Uint8Array(id.pubKey), priv: new Uint8Array(id.privKey) };
}

describe('wrapAccountRootToDevice / unwrapAccountRootFromDevice', () => {
  it('round-trips against a real fork identity key (33-byte 0x05-prefixed pub)', async () => {
    const { pub, priv } = await forkIdentity();
    expect(pub.length).toBe(33);
    expect(pub[0]).toBe(0x05);
    const accountRoot = generateAccountRoot();

    const wrapped = await wrapAccountRootToDevice(accountRoot, pub);
    const recovered = await unwrapAccountRootFromDevice(wrapped, priv);

    expect(Buffer.from(recovered).equals(Buffer.from(accountRoot))).toBe(true);
  });

  it('accepts a 32-byte raw public key (prefix stripped equivalent)', async () => {
    const { pub, priv } = await forkIdentity();
    const raw = pub.subarray(1); // drop 0x05
    const accountRoot = generateAccountRoot();
    const wrapped = await wrapAccountRootToDevice(accountRoot, raw);
    const recovered = await unwrapAccountRootFromDevice(wrapped, priv);
    expect(Buffer.from(recovered).equals(Buffer.from(accountRoot))).toBe(true);
  });

  it('uses a fresh ephemeral key each wrap (two seals differ)', async () => {
    const { pub } = await forkIdentity();
    const accountRoot = generateAccountRoot();
    const a = await wrapAccountRootToDevice(accountRoot, pub);
    const b = await wrapAccountRootToDevice(accountRoot, pub);
    expect(Buffer.from(new Uint8Array(a.ephemeralPubKey)).equals(Buffer.from(new Uint8Array(b.ephemeralPubKey)))).toBe(
      false
    );
    expect(Buffer.from(new Uint8Array(a.ciphertext)).equals(Buffer.from(new Uint8Array(b.ciphertext)))).toBe(false);
  });

  it('produces a 32-byte ephemeral public and 12-byte iv', async () => {
    const { pub } = await forkIdentity();
    const wrapped = await wrapAccountRootToDevice(generateAccountRoot(), pub);
    expect(wrapped.ephemeralPubKey.byteLength).toBe(32);
    expect(wrapped.iv.byteLength).toBe(12);
    expect(wrapped.ciphertext.byteLength).toBe(16 + 16); // accountRoot + GCM tag
  });

  it('a different device cannot unseal (fail-closed)', async () => {
    const alice = await forkIdentity();
    const bob = await forkIdentity();
    const wrapped = await wrapAccountRootToDevice(generateAccountRoot(), alice.pub);
    await expect(unwrapAccountRootFromDevice(wrapped, bob.priv)).rejects.toThrow();
  });

  it('rejects a tampered ciphertext', async () => {
    const { pub, priv } = await forkIdentity();
    const wrapped = await wrapAccountRootToDevice(generateAccountRoot(), pub);
    const ct = new Uint8Array(wrapped.ciphertext);
    ct[ct.length - 1] = ct[ct.length - 1]! ^ 0xff;
    const tampered = { ...wrapped, ciphertext: ct.buffer.slice(0) as ArrayBuffer };
    await expect(unwrapAccountRootFromDevice(tampered, priv)).rejects.toThrow();
  });

  it('rejects a tampered ephemeral public key', async () => {
    const { pub, priv } = await forkIdentity();
    const wrapped = await wrapAccountRootToDevice(generateAccountRoot(), pub);
    const eph = new Uint8Array(wrapped.ephemeralPubKey);
    eph[0] = eph[0]! ^ 0xff;
    const tampered = { ...wrapped, ephemeralPubKey: eph.buffer.slice(0) as ArrayBuffer };
    await expect(unwrapAccountRootFromDevice(tampered, priv)).rejects.toThrow();
  });
});

describe('input validation', () => {
  it('rejects a non-16-byte accountRoot', async () => {
    const { pub } = await forkIdentity();
    await expect(wrapAccountRootToDevice(new Uint8Array(32), pub)).rejects.toThrow(/accountRoot must be 16 bytes/);
  });

  it('rejects a malformed public key length', async () => {
    await expect(
      wrapAccountRootToDevice(generateAccountRoot(), new Uint8Array(20))
    ).rejects.toThrow(/Invalid X25519 public key length/);
  });

  it('rejects a 33-byte public with a wrong prefix byte', async () => {
    const bad = new Uint8Array(33);
    bad[0] = 0x04;
    await expect(wrapAccountRootToDevice(generateAccountRoot(), bad)).rejects.toThrow(
      /Invalid X25519 public key length/
    );
  });

  it('rejects a non-32-byte private key on unwrap', async () => {
    const { pub } = await forkIdentity();
    const wrapped = await wrapAccountRootToDevice(generateAccountRoot(), pub);
    await expect(unwrapAccountRootFromDevice(wrapped, new Uint8Array(16))).rejects.toThrow(
      /Invalid X25519 private key length/
    );
  });
});
