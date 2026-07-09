/**
 * Master identity crypto (rooms-and-trust §2): deterministic account-root-derived
 * sign+encrypt keys, device certificates (continuity), and the fingerprint.
 */

import { describe, it, expect } from 'vitest';
import {
  deriveMasterSigningKey,
  deriveMasterEncryptionKey,
  masterSigningPublicRaw,
  masterEncryptionPublicRaw,
  signDeviceCert,
  verifyDeviceCert,
  identityFingerprint,
  type DeviceIdentityKeys,
} from '@/v2/master-identity';

const rootA = new Uint8Array(16).fill(0xa1);
const rootB = new Uint8Array(16).fill(0xb2);

/** A device's public identity keys — arbitrary bytes for cert tests (the cert just signs over them). */
function device(seed: number): DeviceIdentityKeys {
  return {
    identityKey: new Uint8Array(33).fill(seed),
    identitySigningKey: new Uint8Array(32).fill(seed ^ 0xff),
  };
}

describe('master-identity: derivation', () => {
  it('is deterministic per accountRoot and distinct across roots (identity survives restore)', async () => {
    const sA1 = await masterSigningPublicRaw(rootA);
    const sA2 = await masterSigningPublicRaw(new Uint8Array(rootA)); // "restore": same bytes, fresh array
    const sB = await masterSigningPublicRaw(rootB);
    expect(sA1).toHaveLength(32);
    expect(Array.from(sA2)).toEqual(Array.from(sA1)); // same root → same identity
    expect(Array.from(sB)).not.toEqual(Array.from(sA1));

    const eA1 = await masterEncryptionPublicRaw(rootA);
    const eA2 = await masterEncryptionPublicRaw(rootA);
    const eB = await masterEncryptionPublicRaw(rootB);
    expect(eA1).toHaveLength(32);
    expect(Array.from(eA2)).toEqual(Array.from(eA1));
    expect(Array.from(eB)).not.toEqual(Array.from(eA1));

    // The two master keys are independent legs — sign pub != enc pub.
    expect(Array.from(sA1)).not.toEqual(Array.from(eA1));
  });

  it('yields usable private handles (sign / deriveBits)', async () => {
    const sign = await deriveMasterSigningKey(rootA);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, sign, new Uint8Array([1, 2, 3]));
    expect(sig.byteLength).toBe(64);

    const enc = await deriveMasterEncryptionKey(rootA);
    const peer = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
    const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: peer.publicKey }, enc, 256);
    expect(bits.byteLength).toBe(32);
  });
});

describe('master-identity: device certificates (continuity §2.2)', () => {
  it('a cert verifies against the account master and rejects a foreign master', async () => {
    const d = device(7);
    const cert = await signDeviceCert(rootA, d);
    expect(cert.byteLength).toBe(64);
    expect(await verifyDeviceCert(await masterSigningPublicRaw(rootA), d, cert)).toBe(true);
    expect(await verifyDeviceCert(await masterSigningPublicRaw(rootB), d, cert)).toBe(false);
  });

  it('rejects tampered device keys or a tampered signature', async () => {
    const d = device(7);
    const cert = await signDeviceCert(rootA, d);
    const msk = await masterSigningPublicRaw(rootA);
    expect(await verifyDeviceCert(msk, device(8), cert)).toBe(false); // different keys
    const bad = new Uint8Array(cert);
    bad[0] ^= 0xff;
    expect(await verifyDeviceCert(msk, d, bad)).toBe(false); // flipped signature byte
  });

  it('rotation is seamless: a NEW device certified by the SAME master verifies; a foreign cert does not', async () => {
    const msk = await masterSigningPublicRaw(rootA);
    const d1 = device(1);
    const d2 = device(2); // e.g. a reinstall → new device keys
    expect(await verifyDeviceCert(msk, d1, await signDeviceCert(rootA, d1))).toBe(true);
    expect(await verifyDeviceCert(msk, d2, await signDeviceCert(rootA, d2))).toBe(true);
    // Same device keys, but certified by a DIFFERENT account → impersonation caught.
    expect(await verifyDeviceCert(msk, d2, await signDeviceCert(rootB, d2))).toBe(false);
  });
});

describe('master-identity: fingerprint (§4 safety numbers)', () => {
  it('is stable per identity and distinct across identities', async () => {
    const fp = (r: Uint8Array): Promise<string> =>
      Promise.all([masterSigningPublicRaw(r), masterEncryptionPublicRaw(r)]).then(([s, e]) =>
        identityFingerprint(s, e)
      );
    const fpA1 = await fp(rootA);
    const fpA2 = await fp(rootA);
    const fpB = await fp(rootB);
    expect(fpA1).toBe(fpA2);
    expect(fpA1).not.toBe(fpB);
    expect(fpA1.length).toBeGreaterThan(0);
  });
});
