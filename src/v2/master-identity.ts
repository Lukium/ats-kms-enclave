/**
 * Master identity crypto (secure-messaging `rooms-and-trust.md` §2).
 *
 * The account's stable cryptographic identity is TWO keypairs derived
 * deterministically from the {@link ./account-root.ts | accountRoot} — like the
 * self-channel keys — so every device of an account reconstructs the same
 * identity independently, and it survives device loss / recovery-phrase restore
 * (only a *fresh* account root is a new identity). Only the public halves ever
 * leave the enclave.
 *
 *  - **master signing key (Ed25519)** — certifies this account's per-device
 *    identity keys (continuity across rotation, §2.2) and is the fingerprint
 *    compared during out-of-band verification (§4). A contact who holds the
 *    master signing *public* key can verify any device the account presents,
 *    including a brand-new one after a reinstall, without re-scanning.
 *  - **master encryption key (X25519)** — lets a peer *seal* an invite/secret to
 *    the account (§3.2 sealed Connect), openable by any device (all hold the
 *    accountRoot → the private half).
 *
 * Private keys are non-extractable WebCrypto handles derived on demand; raw
 * public keys are exported for the identity card. Deterministic derivation uses
 * the same PKCS#8-from-seed technique as {@link ./device-wrap.ts} (WebCrypto
 * `generateKey` is random, so a seeded keypair must be imported, not generated).
 */

import { arrayBufferToBase64url, base64urlToArrayBuffer, deriveDeterministicSalt } from './crypto-utils';

// ============================================================================
// Constants
// ============================================================================

/** Raw scalar/seed size for both curves (bytes). */
const KEY_BYTES = 32;

/**
 * Fixed PKCS#8 DER prefixes for a bare 32-byte private key. Ed25519 = OID
 * 1.3.101.112 (…2b 65 70…); X25519 = OID 1.3.101.110 (…2b 65 6e…) — they differ
 * only in that final OID byte. Matches the fork's / device-wrap's conventions.
 */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/** AAD/version tag bound into a device certificate; bump if the binding changes. */
const DEVICE_CERT_VERSION = 'device-cert/1';

/** Public identity keys of a single device, as certified/verified below. */
export interface DeviceIdentityKeys {
  /** X25519 DH identity public key (32-byte raw or 33-byte 0x05-prefixed). */
  identityKey: Uint8Array;
  /** Ed25519 identity signing public key (32-byte raw). */
  identitySigningKey: Uint8Array;
}

// ============================================================================
// Derivation
// ============================================================================

/** Import the accountRoot as HKDF input keying material. */
async function importAccountRootIKM(accountRoot: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', u8ToArrayBuffer(accountRoot), 'HKDF', false, ['deriveBits']);
}

/** HKDF 32 bytes of private seed from the accountRoot under a distinct salt+info. */
async function deriveSeed(accountRoot: Uint8Array, saltLabel: string, infoLabel: string): Promise<Uint8Array> {
  const salt = await deriveDeterministicSalt(saltLabel);
  const info = new TextEncoder().encode(infoLabel);
  const ikm = await importAccountRootIKM(accountRoot);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, ikm, KEY_BYTES * 8);
  return new Uint8Array(bits);
}

/** Wrap a 32-byte raw private key in its PKCS#8 DER envelope. */
function toPkcs8(prefix: Uint8Array, raw: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(prefix.length + KEY_BYTES);
  out.set(prefix, 0);
  out.set(raw, prefix.length);
  return out.buffer;
}

/** Copy a Uint8Array's contents into a fresh, exactly-sized ArrayBuffer. */
function u8ToArrayBuffer(u: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u.byteLength);
  new Uint8Array(b).set(u);
  return b;
}

/** Export the raw 32-byte public key from a freshly-imported (extractable) private key. */
async function rawPublicFromSeed(
  prefix: Uint8Array,
  seed: Uint8Array,
  name: 'Ed25519' | 'X25519'
): Promise<Uint8Array> {
  const usages: KeyUsage[] = name === 'Ed25519' ? ['sign'] : ['deriveBits'];
  const priv = await crypto.subtle.importKey('pkcs8', toPkcs8(prefix, seed), { name }, true, usages);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  return new Uint8Array(base64urlToArrayBuffer(jwk.x ?? ''));
}

/**
 * The account's master **signing** private key (Ed25519), non-extractable.
 * Deterministic from `accountRoot`; used to sign device certificates.
 */
export async function deriveMasterSigningKey(accountRoot: Uint8Array): Promise<CryptoKey> {
  const seed = await deriveSeed(accountRoot, 'ATS/KMS/master/sign/salt/v1', 'ATS/KMS/master/sign/v1');
  try {
    return await crypto.subtle.importKey('pkcs8', toPkcs8(ED25519_PKCS8_PREFIX, seed), { name: 'Ed25519' }, false, ['sign']);
  } finally {
    seed.fill(0);
  }
}

/**
 * The account's master **encryption** private key (X25519), non-extractable.
 * Deterministic from `accountRoot`; used to open invites sealed to this account.
 */
export async function deriveMasterEncryptionKey(accountRoot: Uint8Array): Promise<CryptoKey> {
  const seed = await deriveSeed(accountRoot, 'ATS/KMS/master/enc/salt/v1', 'ATS/KMS/master/enc/v1');
  try {
    return await crypto.subtle.importKey('pkcs8', toPkcs8(X25519_PKCS8_PREFIX, seed), { name: 'X25519' }, false, ['deriveBits']);
  } finally {
    seed.fill(0);
  }
}

/** Raw 32-byte Ed25519 master signing public key (for the identity card §2.3). */
export async function masterSigningPublicRaw(accountRoot: Uint8Array): Promise<Uint8Array> {
  const seed = await deriveSeed(accountRoot, 'ATS/KMS/master/sign/salt/v1', 'ATS/KMS/master/sign/v1');
  try {
    return await rawPublicFromSeed(ED25519_PKCS8_PREFIX, seed, 'Ed25519');
  } finally {
    seed.fill(0);
  }
}

/** Raw 32-byte X25519 master encryption public key (for the identity card §2.3). */
export async function masterEncryptionPublicRaw(accountRoot: Uint8Array): Promise<Uint8Array> {
  const seed = await deriveSeed(accountRoot, 'ATS/KMS/master/enc/salt/v1', 'ATS/KMS/master/enc/v1');
  try {
    return await rawPublicFromSeed(X25519_PKCS8_PREFIX, seed, 'X25519');
  } finally {
    seed.fill(0);
  }
}

// ============================================================================
// Device certificates (continuity, §2.2)
// ============================================================================

/**
 * Canonical bytes a device certificate signs over: a version tag + the device's
 * two public identity keys. Deterministic (sorted keys) so both signer and
 * verifier reconstruct the identical payload.
 */
function deviceCertPayload(keys: DeviceIdentityKeys): ArrayBuffer {
  const fields = {
    v: DEVICE_CERT_VERSION,
    ik: arrayBufferToBase64url(u8ToArrayBuffer(keys.identityKey)),
    isk: arrayBufferToBase64url(u8ToArrayBuffer(keys.identitySigningKey)),
  };
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  return u8ToArrayBuffer(new TextEncoder().encode(canonical));
}

/**
 * Sign a device certificate: `Ed25519(master_sign_priv, "these device keys are
 * mine")`. A contact holding the master signing public key can then verify this
 * device — and any future rotated device — belongs to the same identity (§2.2).
 */
export async function signDeviceCert(accountRoot: Uint8Array, keys: DeviceIdentityKeys): Promise<Uint8Array> {
  const signKey = await deriveMasterSigningKey(accountRoot);
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, signKey, deviceCertPayload(keys));
  return new Uint8Array(sig);
}

/**
 * Verify a device certificate against a master signing public key. `true` iff
 * `cert` is a valid signature by that master over exactly these device keys —
 * i.e. the device provably belongs to that identity. Fails closed on any error.
 */
export async function verifyDeviceCert(
  masterSigningPubRaw: Uint8Array,
  keys: DeviceIdentityKeys,
  cert: Uint8Array
): Promise<boolean> {
  try {
    const pub = await crypto.subtle.importKey('raw', u8ToArrayBuffer(masterSigningPubRaw), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, pub, u8ToArrayBuffer(cert), deviceCertPayload(keys));
  } catch {
    return false;
  }
}

// ============================================================================
// Fingerprint (safety numbers, §4 — verification UX is roadmap)
// ============================================================================

/**
 * A stable fingerprint of an identity = SHA-256 over both master public keys,
 * base64url. Two people comparing fingerprints out-of-band is the safety-number
 * check that flips a contact Unverified→Verified (§4). Rendering it as
 * words/emoji/number for display is a follow-up; this is the canonical value.
 */
export async function identityFingerprint(
  masterSigningPubRaw: Uint8Array,
  masterEncryptionPubRaw: Uint8Array
): Promise<string> {
  const buf = new Uint8Array(masterSigningPubRaw.length + masterEncryptionPubRaw.length);
  buf.set(masterSigningPubRaw, 0);
  buf.set(masterEncryptionPubRaw, masterSigningPubRaw.length);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return arrayBufferToBase64url(hash);
}
