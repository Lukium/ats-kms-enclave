/**
 * Per-device envelope + fan-out bundle (secure-messaging §8/§12).
 *
 * A logical message is delivered as a set of per-device envelopes — one Signal
 * ciphertext per recipient device (including the sender's own other devices, so
 * history converges). The §12-resolved wire format bundles them into ONE opaque
 * payload the relay forwards verbatim, so no per-device structure leaks on the
 * wire, and recipients find their envelope by **trial decryption** rather than a
 * cleartext device tag.
 *
 * Trial decryption is safe here because of the fork's clone-verify-commit MAC
 * isolation: a decrypt attempt against the wrong session advances the ratchet on
 * a throwaway clone and only commits after `verifyMAC`, and (verified in the
 * fork's `decryptPreKeyWhisperMessage`) a failed PreKey attempt removes no
 * one-time prekey and stores no session — so a non-matching envelope leaves the
 * recipient's state untouched.
 *
 * The envelope reserves an optional `tag` field (§12) for a future rotating
 * per-envelope transport tag (groups); it is unused today and always absent from
 * bundles this module produces. Envelope order within a bundle is shuffled so
 * position leaks nothing about which device an envelope targets.
 *
 * Serialization is a compact length-prefixed binary framing (opaque to relays):
 *   bundle   = version(1) || count(u16 BE) || envelope*
 *   envelope = type(1) || tagLen(1) || tag(tagLen) || bodyLen(u32 BE) || body
 */

import { SessionCipher } from '@lukium/libsignal-protocol-typescript';

// ============================================================================
// Constants & types
// ============================================================================

/** Whisper (normal Double Ratchet) message — an established session. */
export const ENVELOPE_TYPE_WHISPER = 1;
/** PreKey (X3DH bootstrap) message — the first message to a device. */
export const ENVELOPE_TYPE_PREKEY = 3;

/** Bundle framing version. */
const BUNDLE_VERSION = 1;

/** Guards against absurd allocations when parsing untrusted bundles. */
const MAX_ENVELOPES = 4096;
const MAX_BODY_BYTES = 1 << 20; // 1 MiB per envelope

/**
 * One recipient device's copy of a message: a Signal ciphertext plus its type.
 * `tag` is a reserved rotating per-envelope transport tag (§12), unused today.
 */
export interface Envelope {
  /** {@link ENVELOPE_TYPE_WHISPER} (1) or {@link ENVELOPE_TYPE_PREKEY} (3). */
  type: number;
  /** Signal ciphertext bytes (the fork's binary-string body, decoded to bytes). */
  body: Uint8Array;
  /** Reserved optional rotating tag for future group transport; absent today. */
  tag?: Uint8Array;
}

// ============================================================================
// binary-string <-> bytes (the fork emits/consumes latin1 binary strings)
// ============================================================================

function binaryStringToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i) & 0xff;
  }
  return out;
}

function bytesToBinaryString(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) {
    s += String.fromCharCode(b[i]!);
  }
  return s;
}

function toArrayBuffer(data: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (data instanceof Uint8Array) {
    // Copy into a fresh ArrayBuffer-backed view (a subarray/view over an
    // ArrayBufferLike does not satisfy the ArrayBuffer return type).
    return new Uint8Array(data).buffer;
  }
  return data;
}

// ============================================================================
// Producer
// ============================================================================

/**
 * Encrypt `plaintext` for one recipient device via its established
 * {@link SessionCipher}, yielding a single {@link Envelope}. The first message
 * to a device is a PreKey (type 3) message; subsequent ones are Whisper (type 1).
 */
export async function encryptEnvelope(
  cipher: SessionCipher,
  plaintext: ArrayBuffer | Uint8Array
): Promise<Envelope> {
  const msg = await cipher.encrypt(toArrayBuffer(plaintext));
  return { type: msg.type, body: binaryStringToBytes(msg.body as string) };
}

/**
 * Serialize (and shuffle) a set of envelopes into one opaque bundle buffer.
 * Shuffling hides any positional correlation to a target device.
 */
export function serializeBundle(envelopes: Envelope[]): Uint8Array {
  if (envelopes.length > MAX_ENVELOPES) {
    throw new Error(`Too many envelopes: ${envelopes.length} (max ${MAX_ENVELOPES})`);
  }
  const shuffled = shuffle(envelopes);
  let total = 1 + 2; // version + count
  for (const env of shuffled) {
    const tagLen = env.tag?.length ?? 0;
    if (tagLen > 0xff) {
      throw new Error(`Envelope tag too long: ${tagLen} (max 255)`);
    }
    total += 1 + 1 + tagLen + 4 + env.body.length;
  }
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  out[off++] = BUNDLE_VERSION;
  view.setUint16(off, shuffled.length, false);
  off += 2;
  for (const env of shuffled) {
    out[off++] = env.type;
    const tag = env.tag ?? new Uint8Array(0);
    out[off++] = tag.length;
    out.set(tag, off);
    off += tag.length;
    view.setUint32(off, env.body.length, false);
    off += 4;
    out.set(env.body, off);
    off += env.body.length;
  }
  return out;
}

/**
 * Convenience producer: encrypt `plaintext` once per recipient device session,
 * then serialize into one shuffled opaque bundle.
 */
export async function buildFanoutBundle(
  ciphers: SessionCipher[],
  plaintext: ArrayBuffer | Uint8Array
): Promise<Uint8Array> {
  const envelopes = await Promise.all(ciphers.map((c) => encryptEnvelope(c, plaintext)));
  return serializeBundle(envelopes);
}

// ============================================================================
// Consumer
// ============================================================================

/**
 * Parse an opaque bundle back to its envelopes, with hard bounds so a malformed
 * or hostile buffer cannot force a huge allocation.
 *
 * @throws if the version, count, or any length field is invalid/out of bounds.
 */
export function parseBundle(bundle: ArrayBuffer | Uint8Array): Envelope[] {
  const bytes = bundle instanceof Uint8Array ? bundle : new Uint8Array(bundle);
  if (bytes.length < 3) {
    throw new Error('Malformed bundle: too short');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 0;
  const version = bytes[off++];
  if (version !== BUNDLE_VERSION) {
    throw new Error(`Unsupported bundle version: ${version}`);
  }
  const count = view.getUint16(off, false);
  off += 2;
  if (count > MAX_ENVELOPES) {
    throw new Error(`Too many envelopes: ${count} (max ${MAX_ENVELOPES})`);
  }
  const envelopes: Envelope[] = [];
  for (let i = 0; i < count; i++) {
    if (off + 2 > bytes.length) {
      throw new Error('Malformed bundle: truncated envelope header');
    }
    const type = bytes[off++]!;
    const tagLen = bytes[off++]!;
    if (off + tagLen + 4 > bytes.length) {
      throw new Error('Malformed bundle: truncated envelope');
    }
    const tag = tagLen > 0 ? bytes.slice(off, off + tagLen) : undefined;
    off += tagLen;
    const bodyLen = view.getUint32(off, false);
    off += 4;
    if (bodyLen > MAX_BODY_BYTES || off + bodyLen > bytes.length) {
      throw new Error('Malformed bundle: invalid body length');
    }
    const body = bytes.slice(off, off + bodyLen);
    off += bodyLen;
    envelopes.push(tag ? { type, body, tag } : { type, body });
  }
  return envelopes;
}

/**
 * Attempt to decrypt one envelope with one recipient session. Returns the
 * plaintext bytes on success, or `null` if this envelope is not for this session
 * (any decrypt failure). Safe to call speculatively: a failed attempt does not
 * mutate persisted session/prekey state (fork MAC isolation).
 */
export async function trialDecryptEnvelope(
  cipher: SessionCipher,
  envelope: Envelope
): Promise<Uint8Array | null> {
  const body = bytesToBinaryString(envelope.body);
  try {
    let plaintext: ArrayBuffer;
    if (envelope.type === ENVELOPE_TYPE_PREKEY) {
      plaintext = await cipher.decryptPreKeyWhisperMessage(body, 'binary');
    } else if (envelope.type === ENVELOPE_TYPE_WHISPER) {
      plaintext = await cipher.decryptWhisperMessage(body, 'binary');
    } else {
      return null;
    }
    return new Uint8Array(plaintext);
  } catch {
    return null;
  }
}

/**
 * Open a fan-out bundle: trial-decrypt each envelope against each candidate
 * sender-device session, returning the first plaintext that authenticates, or
 * `null` if none is addressed to any of the given sessions.
 *
 * `ciphers` are the recipient's sessions with the plausible senders on this
 * scope (on a pair-topic, the recipient's sessions with each of the peer's
 * devices, since any could be the sender).
 */
export async function openFanoutBundle(
  ciphers: SessionCipher[],
  bundle: ArrayBuffer | Uint8Array
): Promise<Uint8Array | null> {
  const envelopes = parseBundle(bundle);
  for (const envelope of envelopes) {
    for (const cipher of ciphers) {
      const plaintext = await trialDecryptEnvelope(cipher, envelope);
      if (plaintext !== null) {
        return plaintext;
      }
    }
  }
  return null;
}

// ============================================================================
// Internal
// ============================================================================

/** Fisher-Yates shuffle using the CSPRNG; returns a new array (input untouched). */
function shuffle<T>(items: T[]): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const r = crypto.getRandomValues(new Uint32Array(1))[0]!;
    const j = r % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}
