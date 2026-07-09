/**
 * Channel / contact crypto (secure-messaging §5/§6, rooms-and-trust §3.1).
 *
 * A conversation is a **scope seeded by a shared secret** agreed out of band (a
 * QR-carried high-entropy value, or a lower-entropy word-pair fallback). That
 * secret is enclave-held state (see contact-store.ts) and drives two derivations,
 * both computed here and both deterministic for anyone who holds the secret —
 * whether a 1:1 pair or a room of N (same secret → same output):
 *
 *  - `scope = KDF(secret)` — the opaque routing address, decoupled from any
 *    user.id (rooms-and-trust §3.1: identity ≠ channel). The transport forms the
 *    topic key from it; a party without the secret (a relay/observer) cannot
 *    compute or locate it. Generic from the start so the room/group path and 1:1
 *    fall out of one primitive.
 *  - `exchangeKey = KDF(secret, "dke")` — a symmetric AES-GCM key that AEAD-seals
 *    the device-key exchange (§6), so a published device bundle is both
 *    authenticated (defeats injection/MITM by anyone who learns the scope) and
 *    confidential. Everyone derives the same key from the shared secret.
 */

import { deriveDeterministicSalt, arrayBufferToBase64url } from './crypto-utils';

/** Import a shared secret as HKDF input keying material. */
async function importSecretIKM(secret: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ]);
}

/**
 * Derive the opaque channel/room **scope** from the shared secret alone
 * (rooms-and-trust §3.1: `scope = HKDF(room_secret)`), NOT bound to any user.id.
 * Everyone who holds the secret — a 1:1 pair or a room of N — derives the same
 * scope; a party without it (a relay/observer) cannot compute or locate it.
 * Returned as base64url of 32 derived bytes (the transport places it after the
 * topic prefix). Replaces the old two-party `derivePairID(secret, userA, userB)`.
 */
export async function deriveScope(secret: Uint8Array): Promise<string> {
  const info = new TextEncoder().encode('ATS/KMS/scope/id/v1');
  const salt = await deriveDeterministicSalt('ATS/KMS/scope/id/salt/v1');
  const ikm = await importSecretIKM(secret);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    256
  );
  return arrayBufferToBase64url(bits);
}

/**
 * Derive the device-key-exchange AEAD key from the shared secret. A SEPARATE
 * HKDF leg from {@link deriveScope} (distinct salt + info). Non-extractable
 * AES-GCM; everyone derives the same key to seal/open each other's device
 * bundles over the channel topic.
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
