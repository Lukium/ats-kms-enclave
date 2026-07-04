/**
 * Self-channel crypto (secure-messaging §18.2).
 *
 * The self-channel is a server-blind, per-account channel on the relay mesh that
 * every device of an account subscribes to, used to sync secret contact/channel
 * state (contact-add announcements + a keep-latest snapshot) across a user's
 * devices. Both its address and its content key are derived deterministically
 * from the shared {@link ../account-root.ts | accountRoot}, so every device
 * computes them independently with no discovery bootstrap:
 *
 *  - `selfScope = KDF(accountRoot, "self")` — the opaque channel address. The
 *    relay transport forms the scope key `self:<selfScope>` (mirrors
 *    `dm:<pairID>`); relays route by it and never learn what it means.
 *  - `selfKey = KDF(accountRoot, "key")` — a symmetric AES-GCM key that encrypts
 *    announcements and the snapshot. Because it is symmetric (derived, not
 *    exchanged), self-sync content does NOT depend on keyserver pubkey
 *    authenticity: a malicious main-server that runs the keyserver still cannot
 *    read or forge self-channel content (§18.2).
 *
 * Payloads travel as one opaque buffer the relay forwards verbatim (base64 on
 * the wire, see the PWA's encoding.ts). The framing here is `iv(12) || GCM
 * ciphertext(+tag)`, with AAD binding a version + a caller context label so an
 * announcement blob cannot be reinterpreted as a snapshot (or vice versa).
 */

import { arrayBufferToBase64url, deriveDeterministicSalt } from './crypto-utils';

// ============================================================================
// Constants
// ============================================================================

/** AES-GCM IV length in bytes. */
const IV_BYTES = 12;

/** AAD schema version for self-channel messages; bump if the binding changes. */
const SELF_MSG_AAD_VERSION = 'self-msg/1';

/**
 * Default context label for {@link encryptSelfMessage} / {@link decryptSelfMessage}.
 * Callers should pass a specific label (e.g. `'announcement'`, `'snapshot'`) to
 * domain-separate the two self-channel payload kinds.
 */
export const SELF_CONTEXT_ANNOUNCEMENT = 'announcement';
export const SELF_CONTEXT_SNAPSHOT = 'snapshot';

// ============================================================================
// Derivation
// ============================================================================

/**
 * Import an `accountRoot` as HKDF input keying material.
 */
async function importAccountRootIKM(accountRoot: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', accountRoot as BufferSource, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ]);
}

/**
 * Derive the account's self-channel address `selfScope` from `accountRoot`.
 *
 * Deterministic across every device of the account. Returned as a base64url
 * string of 32 derived bytes — an opaque identifier the relay transport places
 * after the `self:` topic prefix. Does NOT include the prefix (mirrors how
 * `pairID` excludes the `dm:` prefix).
 */
export async function deriveSelfScope(accountRoot: Uint8Array): Promise<string> {
  const salt = await deriveDeterministicSalt('ATS/KMS/self/scope/salt/v1');
  const info = new TextEncoder().encode('ATS/KMS/self/scope/v1');
  const ikm = await importAccountRootIKM(accountRoot);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    256
  );
  return arrayBufferToBase64url(bits);
}

/**
 * Derive the account's self-channel content key `selfKey` from `accountRoot`.
 *
 * A non-extractable AES-GCM key (a handle, not bytes) that every device derives
 * independently to encrypt/decrypt self-channel announcements and the snapshot.
 * A SEPARATE HKDF leg from {@link deriveSelfScope} (distinct salt + info).
 */
export async function deriveSelfKey(accountRoot: Uint8Array): Promise<CryptoKey> {
  const salt = await deriveDeterministicSalt('ATS/KMS/self/key/salt/v1');
  const info = new TextEncoder().encode('ATS/KMS/self/key/v1');
  const ikm = await importAccountRootIKM(accountRoot);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ============================================================================
// AAD
// ============================================================================

/**
 * Build deterministic AAD binding a self-channel message to its schema version
 * and caller context, so a blob cannot be reinterpreted across contexts (the
 * GCM tag fails if the recomputed AAD differs).
 */
function selfMsgAAD(context: string): ArrayBuffer {
  const fields = { v: SELF_MSG_AAD_VERSION, context };
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  const bytes = new TextEncoder().encode(canonical);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

// ============================================================================
// Message encrypt / decrypt
// ============================================================================

/**
 * Encrypt a self-channel payload under `selfKey`.
 *
 * Returns a single opaque buffer `iv(12) || GCM ciphertext(+tag)` the relay
 * forwards verbatim. `context` domain-separates payload kinds (e.g.
 * {@link SELF_CONTEXT_ANNOUNCEMENT} vs {@link SELF_CONTEXT_SNAPSHOT}); the same
 * label must be supplied to decrypt.
 */
export async function encryptSelfMessage(
  selfKey: CryptoKey,
  plaintext: ArrayBuffer | Uint8Array,
  context: string = SELF_CONTEXT_ANNOUNCEMENT
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: selfMsgAAD(context) },
    selfKey,
    plaintext as BufferSource
  );
  const out = new Uint8Array(IV_BYTES + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), IV_BYTES);
  return out;
}

/**
 * Decrypt a self-channel payload produced by {@link encryptSelfMessage}.
 *
 * @param context must match the label used at encryption time.
 * @throws if the buffer is malformed, or the key/context/ciphertext do not
 *   authenticate (AES-GCM tag failure).
 */
export async function decryptSelfMessage(
  selfKey: CryptoKey,
  blob: ArrayBuffer | Uint8Array,
  context: string = SELF_CONTEXT_ANNOUNCEMENT
): Promise<Uint8Array> {
  const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
  if (bytes.length <= IV_BYTES) {
    throw new Error('Malformed self-channel message: too short');
  }
  // Copy into fresh ArrayBuffer-backed views (subarray preserves the source's
  // ArrayBufferLike, which does not satisfy WebCrypto's BufferSource).
  const iv = new Uint8Array(bytes.subarray(0, IV_BYTES));
  const ciphertext = new Uint8Array(bytes.subarray(IV_BYTES));
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: selfMsgAAD(context) },
    selfKey,
    ciphertext
  );
  return new Uint8Array(plaintext);
}
