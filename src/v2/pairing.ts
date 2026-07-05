/**
 * Pairing / contact crypto (secure-messaging §5/§6).
 *
 * When two users add each other they agree on a shared **pairing secret** out of
 * band (a QR-carried high-entropy value, or a lower-entropy word-pair fallback).
 * That secret is enclave-held contact state (see contact-store.ts) and drives two
 * derivations, both computed here and both deterministic on either side / every
 * device (same secret + same UUID pair → same output):
 *
 *  - `pairID = KDF(secret, sort(userA, userB))` — the opaque DM routing address.
 *    The transport forms the scope key `dm:<pairID>`; a party without the secret
 *    (a relay/observer) cannot compute or locate it.
 *  - `exchangeKey = KDF(secret, "dke")` — a symmetric AES-GCM key that AEAD-seals
 *    the device-key exchange (§6), so a contact's published device bundle is both
 *    authenticated (defeats injection/MITM by anyone who learns the pairID) and
 *    confidential. Both users derive the same key from the shared secret.
 */

import { deriveDeterministicSalt, arrayBufferToBase64url } from './crypto-utils';

/** Field separator for the canonical UUID-pair KDF info (not a UUID character). */
const PAIR_SEPARATOR = '\x1f';

/** Import a pairing secret as HKDF input keying material. */
async function importSecretIKM(secret: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ]);
}

/**
 * Derive the opaque DM routing address `pairID` from the pairing secret and the
 * two account UUIDs. Order-independent: the UUIDs are sorted first, so both users
 * compute the same value regardless of who initiated. Returned as base64url of 32
 * derived bytes (the transport places it after the `dm:` topic prefix).
 */
export async function derivePairID(
  secret: Uint8Array,
  userA: string,
  userB: string
): Promise<string> {
  const info = new TextEncoder().encode([userA, userB].sort().join(PAIR_SEPARATOR));
  const salt = await deriveDeterministicSalt('ATS/KMS/pair/id/salt/v1');
  const ikm = await importSecretIKM(secret);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    256
  );
  return arrayBufferToBase64url(bits);
}

/**
 * Derive the device-key-exchange AEAD key from the pairing secret. A SEPARATE
 * HKDF leg from {@link derivePairID} (distinct salt + info). Non-extractable
 * AES-GCM; both users derive the same key to seal/open each other's device
 * bundles over the pair-topic.
 */
export async function deriveExchangeKey(secret: Uint8Array): Promise<CryptoKey> {
  const info = new TextEncoder().encode('ATS/KMS/pair/dke/v1');
  const salt = await deriveDeterministicSalt('ATS/KMS/pair/dke/salt/v1');
  const ikm = await importSecretIKM(secret);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
