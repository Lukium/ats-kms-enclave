/**
 * Contact pairing-secret persistence (secure-messaging §5).
 *
 * Wraps each per-contact pairing secret under the device's messagingKEK (session
 * tier — so scopes derive within an open messaging session without a fresh
 * unlock), binding it by AAD to (userId, peerUserId). The plaintext secret is
 * shared with the peer out-of-band and synced across the account's own devices
 * via the self-channel; each device wraps its own copy under its own messagingKEK.
 *
 * These run off a live messaging capability (the messagingKEK the session holds),
 * never a full unlock — pairing/routing is routine foreground activity.
 */

import {
  wrapBlob,
  unwrapBlob,
  getMessagingContact,
  getMessagingContacts,
  putMessagingContact,
} from './storage';

/** AAD schema version for a contact-secret blob; bump if the binding changes. */
const CONTACT_SECRET_AAD_VERSION = 'contact-secret/1';

/**
 * Deterministic AAD binding a wrapped pairing secret to (userId, peerUserId), so
 * a blob cannot be transplanted to another contact or user (GCM tag fails if the
 * recomputed AAD differs).
 */
function contactSecretAAD(userId: string, peerUserId: string): ArrayBuffer {
  const fields = { v: CONTACT_SECRET_AAD_VERSION, type: 'contact-secret', userId, peerUserId };
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  const bytes = new TextEncoder().encode(canonical);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Encrypt and persist a contact's pairing secret under the messagingKEK.
 * Overwrites any existing record for that (userId, peerUserId).
 */
export async function storeContactSecret(
  userId: string,
  peerUserId: string,
  secret: Uint8Array,
  messagingKEK: CryptoKey
): Promise<void> {
  const wrapped = await wrapBlob(secret, messagingKEK, contactSecretAAD(userId, peerUserId));
  await putMessagingContact({
    userId,
    peerUserId,
    wrappedSecret: wrapped,
    createdAt: Date.now(),
  });
}

/**
 * Load and decrypt a contact's pairing secret, or `null` if this device has none
 * for that peer. Fail-closed on the wrong key/AAD.
 */
export async function loadContactSecret(
  userId: string,
  peerUserId: string,
  messagingKEK: CryptoKey
): Promise<Uint8Array | null> {
  const record = await getMessagingContact(userId, peerUserId);
  if (!record) {
    return null;
  }
  const bytes = await unwrapBlob(
    record.wrappedSecret,
    messagingKEK,
    contactSecretAAD(userId, peerUserId)
  );
  return new Uint8Array(bytes);
}

/**
 * List the peer user ids this device holds a contact secret for (public field;
 * reads no secret bytes). Used to derive/subscribe every pair-topic on connect.
 */
export async function listContactPeers(userId: string): Promise<string[]> {
  const records = await getMessagingContacts(userId);
  return records.map((r) => r.peerUserId);
}
