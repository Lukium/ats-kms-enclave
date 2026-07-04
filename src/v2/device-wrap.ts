/**
 * Wrap `accountRoot` to a device public key for auto-onboarding (§18.1).
 *
 * When a new device joins an account, an existing device seals the shared
 * `accountRoot` to the new device's self-only-keyserver public key (its X25519
 * DH identity key). The sealed blob is carried via main-server, which cannot
 * read it (server-blind bootstrap). The recipient device unseals it with its
 * identity private key and now shares the account's self-channel keys.
 *
 * Construction is an ECIES-style seal over X25519 (matching the fork's WebCrypto
 * curve convention exactly — 32-byte raw scalars, 0x05-prefixed public keys):
 *
 *   1. Sender generates an ephemeral X25519 keypair.
 *   2. shared = X25519(ephemeralPriv, recipientPub).
 *   3. AES-GCM key = HKDF(shared, info = label || ephemeralPub || recipientPub),
 *      binding both parties' keys into the derivation (thwarts key-reuse /
 *      unknown-key-share).
 *   4. Encrypt `accountRoot`; ship { ephemeralPub, iv, ciphertext }.
 *
 * The recipient recomputes the same shared secret with its private key and its
 * own public (derived from that private), so a blob sealed to a different device
 * fails to authenticate (fail-closed).
 *
 * Residual trust (§18.1): main-server runs the keyserver, so it could substitute
 * a device pubkey before the wrap (keyserver MITM). Mitigated out-of-band by the
 * optional device-fingerprint verification and the recovery phrase; not this
 * module's concern.
 */

import { deriveDeterministicSalt } from './crypto-utils';
import { ACCOUNT_ROOT_BYTES } from './account-root';
import type { WrappedAccountRoot } from './types';

// ============================================================================
// Constants
// ============================================================================

/** DJB type byte prefixing a serialized curve25519 public key (fork convention). */
const DJB_TYPE = 0x05;

/** Raw X25519 key length in bytes (public and private). */
const X25519_KEY_BYTES = 32;

/** AES-GCM IV length in bytes. */
const IV_BYTES = 12;

/** HKDF label / GCM AAD domain-separation string for this seal. */
const WRAP_LABEL = 'ATS/KMS/accountRoot-wrap/v1';

/**
 * Fixed PKCS#8 DER prefix for a bare 32-byte X25519 private key (OID
 * 1.3.101.110). Identical to the fork's backend so byte conventions match.
 */
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

// `WrappedAccountRoot` now lives in ./types (a fork/storage-free module the PWA
// vendors) so the vendored kms-user client can reference it without pulling in
// this crypto module. Re-exported here for enclave-side consumers.
export type { WrappedAccountRoot };

// ============================================================================
// X25519 helpers (WebCrypto, byte-compatible with the fork's curve backend)
// ============================================================================

/**
 * Strip the 0x05 DJB type prefix from a serialized curve25519 public key. The
 * keyserver publishes 33-byte (0x05-prefixed) identity keys; WebCrypto X25519
 * wants the 32-byte raw form. A 32-byte input is passed through.
 */
function toRawPublic(pub: Uint8Array): Uint8Array {
  if (pub.length === X25519_KEY_BYTES) {
    return pub;
  }
  if (pub.length === X25519_KEY_BYTES + 1 && pub[0] === DJB_TYPE) {
    return pub.subarray(1);
  }
  throw new Error(
    `Invalid X25519 public key length: ${pub.length} (expected 32, or 33 with 0x05 prefix)`
  );
}

/** Import a 32-byte raw X25519 private scalar as a WebCrypto key. */
async function importPrivate(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== X25519_KEY_BYTES) {
    throw new Error(`Invalid X25519 private key length: ${raw.length} (expected 32)`);
  }
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + X25519_KEY_BYTES);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(raw, X25519_PKCS8_PREFIX.length);
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
}

/** Import a 32-byte raw X25519 public key as a WebCrypto key. */
async function importPublic(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new Uint8Array(raw), { name: 'X25519' }, false, []);
}

/** X25519 shared secret (32 bytes) between a private key and a peer public key. */
async function sharedSecret(priv: CryptoKey, peerPubRaw: Uint8Array): Promise<ArrayBuffer> {
  const pub = await importPublic(peerPubRaw);
  return crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
}

/** Recover the 32-byte raw public key for a raw X25519 private scalar. */
async function publicFromPrivate(rawPriv: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + X25519_KEY_BYTES);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(rawPriv, X25519_PKCS8_PREFIX.length);
  // Extractable so we can read the JWK `x` member (the public coordinate).
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, [
    'deriveBits',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const b64 = (jwk.x ?? '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Derive the AES-GCM seal key from the X25519 shared secret, binding the label
 * and both parties' public keys into the HKDF `info`.
 */
async function deriveSealKey(
  shared: ArrayBuffer,
  ephemeralPubRaw: Uint8Array,
  recipientPubRaw: Uint8Array
): Promise<CryptoKey> {
  const label = new TextEncoder().encode(WRAP_LABEL);
  const info = new Uint8Array(label.length + ephemeralPubRaw.length + recipientPubRaw.length);
  info.set(label, 0);
  info.set(ephemeralPubRaw, label.length);
  info.set(recipientPubRaw, label.length + ephemeralPubRaw.length);
  const salt = await deriveDeterministicSalt('ATS/KMS/accountRoot-wrap/salt/v1');
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ============================================================================
// Wrap / unwrap
// ============================================================================

/**
 * Seal `accountRoot` to a recipient device's X25519 identity public key.
 *
 * @param accountRoot the 16-byte account root to seal.
 * @param recipientIdentityPubKey the recipient's DH identity public key, either
 *   32-byte raw or 33-byte 0x05-prefixed (as published by the keyserver).
 * @throws if `accountRoot` is not 16 bytes or the public key is malformed.
 */
export async function wrapAccountRootToDevice(
  accountRoot: Uint8Array,
  recipientIdentityPubKey: Uint8Array
): Promise<WrappedAccountRoot> {
  if (accountRoot.length !== ACCOUNT_ROOT_BYTES) {
    throw new Error(`accountRoot must be ${ACCOUNT_ROOT_BYTES} bytes, got ${accountRoot.length}`);
  }
  const recipientPubRaw = toRawPublic(recipientIdentityPubKey);

  const ephemeral = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const ephemeralPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));

  const shared = await sharedSecret(ephemeral.privateKey, recipientPubRaw);
  const sealKey = await deriveSealKey(shared, ephemeralPubRaw, recipientPubRaw);

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(WRAP_LABEL) },
    sealKey,
    new Uint8Array(accountRoot)
  );

  return {
    ephemeralPubKey: ephemeralPubRaw.buffer.slice(
      ephemeralPubRaw.byteOffset,
      ephemeralPubRaw.byteOffset + ephemeralPubRaw.byteLength
    ),
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
    ciphertext,
  };
}

/**
 * Unseal an `accountRoot` sealed by {@link wrapAccountRootToDevice}, using the
 * recipient device's X25519 identity private key.
 *
 * @param wrapped the sealed blob.
 * @param recipientIdentityPrivKey the recipient's 32-byte raw DH identity
 *   private scalar (from its unwrapped Signal identity record).
 * @throws if the private key is malformed, or the blob was not sealed to this
 *   device (AES-GCM authentication failure — fail-closed).
 */
export async function unwrapAccountRootFromDevice(
  wrapped: WrappedAccountRoot,
  recipientIdentityPrivKey: Uint8Array
): Promise<Uint8Array> {
  const rawPriv =
    recipientIdentityPrivKey instanceof Uint8Array
      ? recipientIdentityPrivKey
      : new Uint8Array(recipientIdentityPrivKey);
  if (rawPriv.length !== X25519_KEY_BYTES) {
    throw new Error(`Invalid X25519 private key length: ${rawPriv.length} (expected 32)`);
  }
  const ephemeralPubRaw = new Uint8Array(wrapped.ephemeralPubKey);
  const recipientPubRaw = await publicFromPrivate(rawPriv);

  const priv = await importPrivate(rawPriv);
  const shared = await sharedSecret(priv, ephemeralPubRaw);
  const sealKey = await deriveSealKey(shared, ephemeralPubRaw, recipientPubRaw);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(wrapped.iv), additionalData: new TextEncoder().encode(WRAP_LABEL) },
    sealKey,
    wrapped.ciphertext
  );
  return new Uint8Array(plaintext);
}
