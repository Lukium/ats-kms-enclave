/**
 * Connect invites (rooms-and-trust §3.2/§3.3).
 *
 * An invite carries the minter's identity card (rooms §2.3) plus a `room_secret`
 * to a recipient, delivered over a trusted external channel (open Connect / TOFU)
 * or in person. Everything here is ENCLAVE-SIDE: the room secret is generated,
 * encoded, and parsed inside the enclave and NEVER crosses to the PWA. The PWA
 * only ever sees the opaque blob (rendered/scanned in the enclave popup, like the
 * BUG-007 mnemonic ceremony) plus public data — scope, identity card, fingerprint.
 *
 * The blob is a compact, self-describing token (versioned JSON → base64url) so the
 * popup can render it as a link or QR and the peer's popup can parse it back.
 */

import { arrayBufferToBase64url, base64urlToArrayBuffer } from './crypto-utils';
import type { InviteType } from './types';

/** Invite lifecycle type (rooms §3.3): a single-use 1:1, or a reusable room. */
export type { InviteType };

/** Raw room-secret size (bytes). */
const ROOM_SECRET_BYTES = 32;

/** Ed25519 (msk) / X25519 (mek) master public key size (bytes). */
const MASTER_KEY_BYTES = 32;

/** Current invite blob version; bump on any wire-format change. */
const INVITE_VERSION = 1;

/**
 * Hardening bounds for UNTRUSTED invite/announcement input (rooms §3.4). A blob
 * is pasted/scanned by the user, so it must be validated defensively before any
 * invite is honored: cap the raw size, require the crypto fields to decode to
 * their exact byte lengths, bound the human-supplied strings, and reject
 * unknown/out-of-range fields.
 */
/** Cap the raw blob before base64 decoding (a well-formed invite is ~600 chars). */
const MAX_INVITE_BLOB_CHARS = 4096;
/** Upper bounds on the human-supplied card fields (defense in depth). */
const MAX_UID_CHARS = 128;
const MAX_NAME_CHARS = 128;
/** Reject absurd expiries: a positive safe integer no later than year 2100 (ms epoch). */
const MAX_EXP_MS = 4_102_444_800_000;

/** The minter's identity card as carried in an invite (rooms §2.3). Public keys only. */
export interface InviteCard {
  uid: string;
  /** Display-name hint (forgeable — never the crypto identity). */
  name?: string;
  /** Master signing public key (Ed25519), base64url. */
  msk: string;
  /** Master encryption public key (X25519), base64url. */
  mek: string;
}

/** The decoded contents of an invite blob. */
export interface InvitePayload {
  v: number;
  t: InviteType;
  card: InviteCard;
  /** Room secret, base64url. Enclave-only — never handed to the PWA. */
  s: string;
  /** Absolute expiry (ms epoch), for `connect-1:1`. */
  exp?: number;
  /** Single-use flag, for `connect-1:1`. */
  single?: boolean;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Copy a Uint8Array into a fresh, exactly-sized ArrayBuffer (never SharedArrayBuffer). */
function u8ToArrayBuffer(u: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u.byteLength);
  new Uint8Array(b).set(u);
  return b;
}

/** A fresh 32-byte room secret. Generated in the enclave; never leaves it in the clear. */
export function generateRoomSecret(): Uint8Array {
  const b = new Uint8Array(ROOM_SECRET_BYTES);
  crypto.getRandomValues(b);
  return b;
}

/** Encode raw secret bytes to the base64url form carried inside a blob. */
export function roomSecretToB64url(secret: Uint8Array): string {
  return arrayBufferToBase64url(u8ToArrayBuffer(secret));
}

/** Decode the base64url room secret from a payload back to raw bytes. */
export function roomSecretFromB64url(s: string): Uint8Array {
  return new Uint8Array(base64urlToArrayBuffer(s));
}

/**
 * Encode an invite payload to an opaque base64url blob (the popup renders it as a
 * link/QR). Validates the shape so a malformed invite can never be minted.
 */
export function encodeInvite(payload: InvitePayload): string {
  assertValidPayload(payload);
  const json = JSON.stringify(payload);
  return arrayBufferToBase64url(u8ToArrayBuffer(encoder.encode(json)));
}

/**
 * Decode an invite blob (tolerant of a surrounding link/`#…` fragment) back to its
 * payload. Throws on anything that isn't a well-formed, current-version invite.
 */
export function decodeInvite(blob: string): InvitePayload {
  // Cap the untrusted input before any decoding so a huge paste/scan can't force
  // a large base64 + JSON parse.
  if (typeof blob !== 'string' || blob.length > MAX_INVITE_BLOB_CHARS) {
    throw new Error('Invalid invite');
  }
  const token = extractToken(blob);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(base64urlToArrayBuffer(token)));
  } catch {
    throw new Error('Invalid invite');
  }
  assertValidPayload(parsed);
  return parsed;
}

/** Build the minter's `connect-1:1` invite payload from a card + secret + policy. */
export function buildConnectInvite(
  card: InviteCard,
  secret: Uint8Array,
  opts: { expiresAt?: number; singleUse?: boolean } = {}
): InvitePayload {
  const payload: InvitePayload = {
    v: INVITE_VERSION,
    t: 'connect-1:1',
    card,
    s: roomSecretToB64url(secret),
  };
  if (opts.expiresAt !== undefined) payload.exp = opts.expiresAt;
  if (opts.singleUse !== undefined) payload.single = opts.singleUse;
  return payload;
}

/** Whether a `connect-1:1` invite has passed its expiry at time `now` (ms). */
export function isInviteExpired(payload: InvitePayload, now: number): boolean {
  return typeof payload.exp === 'number' && now >= payload.exp;
}

/** Tag distinguishing a Connect join-announcement from an invite blob. */
const ANNOUNCEMENT_KIND = 'connect-ann';

/**
 * Encode a Connect **join announcement** — the joiner's identity card only
 * (rooms §3.4). It travels sealed under the room secret's exchange key so the
 * minter learns WHO is joining (+ their fingerprint) and can mutually confirm.
 * Device keys + certificate exchange over the existing device-exchange flow AFTER
 * approval — not stuffed in here. Returns raw bytes for the caller to seal.
 */
export function encodeAnnouncement(card: InviteCard): Uint8Array {
  if (!isValidCard(card)) throw new Error('Invalid announcement');
  return encoder.encode(JSON.stringify({ v: INVITE_VERSION, k: ANNOUNCEMENT_KIND, card }));
}

/** Decode a Connect join announcement back to the joiner's identity card. */
export function decodeAnnouncement(bytes: Uint8Array): InviteCard {
  let parsed: { v?: number; k?: string; card?: InviteCard } | null;
  try {
    parsed = JSON.parse(decoder.decode(bytes)) as { v?: number; k?: string; card?: InviteCard };
  } catch {
    throw new Error('Invalid announcement');
  }
  if (!parsed || parsed.v !== INVITE_VERSION || parsed.k !== ANNOUNCEMENT_KIND || !isValidCard(parsed.card)) {
    throw new Error('Invalid announcement');
  }
  return parsed.card;
}

// ----------------------------------------------------------------------------
// Internals
// ----------------------------------------------------------------------------

/** Pull the bare base64url token from a link, a `#…` fragment, or the token itself. */
function extractToken(input: string): string {
  const trimmed = input.trim();
  const hash = trimmed.indexOf('#');
  const frag = hash >= 0 ? trimmed.slice(hash + 1) : trimmed;
  const eq = frag.indexOf('=');
  return eq >= 0 ? frag.slice(eq + 1) : frag;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

/** Whether `s` is a base64url string that decodes to EXACTLY `bytes` bytes. */
function isB64urlOfLength(s: unknown, bytes: number): boolean {
  if (typeof s !== 'string' || s.length === 0) return false;
  try {
    return base64urlToArrayBuffer(s).byteLength === bytes;
  } catch {
    return false;
  }
}

/** Whether `o` is a plain object whose keys are all within `allowed` (reject extras). */
function hasOnlyKeys(o: object, allowed: readonly string[]): boolean {
  return Object.keys(o).every((k) => allowed.includes(k));
}

const CARD_KEYS = ['uid', 'name', 'msk', 'mek'] as const;
const PAYLOAD_KEYS = ['v', 't', 'card', 's', 'exp', 'single'] as const;

/**
 * Whether `c` is a valid identity card: a plain object with ONLY the card keys, a
 * bounded non-empty uid, an optional bounded name hint, and msk/mek that decode to
 * exactly 32 bytes (Ed25519 / X25519 public keys).
 */
function isValidCard(c: unknown): c is InviteCard {
  if (!c || typeof c !== 'object' || Array.isArray(c) || !hasOnlyKeys(c, CARD_KEYS)) {
    return false;
  }
  const card = c as Partial<InviteCard>;
  if (!isNonEmptyString(card.uid) || card.uid.length > MAX_UID_CHARS) return false;
  if (card.name !== undefined && (typeof card.name !== 'string' || card.name.length > MAX_NAME_CHARS)) {
    return false;
  }
  return isB64urlOfLength(card.msk, MASTER_KEY_BYTES) && isB64urlOfLength(card.mek, MASTER_KEY_BYTES);
}

/**
 * Throw unless `p` is a valid current-version invite payload: a plain object with
 * ONLY the payload keys, a 32-byte room secret, a valid card, and (when present) a
 * bounded safe-integer expiry + boolean single-use flag.
 */
function assertValidPayload(p: unknown): asserts p is InvitePayload {
  if (!p || typeof p !== 'object' || Array.isArray(p) || !hasOnlyKeys(p, PAYLOAD_KEYS)) {
    throw new Error('Invalid invite');
  }
  const o = p as Partial<InvitePayload>;
  if (
    o.v !== INVITE_VERSION ||
    (o.t !== 'connect-1:1' && o.t !== 'room') ||
    !isB64urlOfLength(o.s, ROOM_SECRET_BYTES) ||
    !isValidCard(o.card)
  ) {
    throw new Error('Invalid invite');
  }
  if (o.exp !== undefined && (!Number.isSafeInteger(o.exp) || o.exp <= 0 || o.exp > MAX_EXP_MS)) {
    throw new Error('Invalid invite');
  }
  if (o.single !== undefined && typeof o.single !== 'boolean') throw new Error('Invalid invite');
}
