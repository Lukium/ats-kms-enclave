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

/** Invite lifecycle type (rooms §3.3): a single-use 1:1, or a reusable room. */
export type InviteType = 'connect-1:1' | 'room';

/** Raw room-secret size (bytes). */
const ROOM_SECRET_BYTES = 32;

/** Current invite blob version; bump on any wire-format change. */
const INVITE_VERSION = 1;

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

/** Throw unless `p` is a structurally-valid current-version invite payload. */
function assertValidPayload(p: unknown): asserts p is InvitePayload {
  const o = p as Partial<InvitePayload> | null;
  if (
    !o ||
    o.v !== INVITE_VERSION ||
    (o.t !== 'connect-1:1' && o.t !== 'room') ||
    !isNonEmptyString(o.s) ||
    !o.card ||
    !isNonEmptyString(o.card.uid) ||
    !isNonEmptyString(o.card.msk) ||
    !isNonEmptyString(o.card.mek)
  ) {
    throw new Error('Invalid invite');
  }
  if (o.card.name !== undefined && typeof o.card.name !== 'string') throw new Error('Invalid invite');
  if (o.exp !== undefined && typeof o.exp !== 'number') throw new Error('Invalid invite');
  if (o.single !== undefined && typeof o.single !== 'boolean') throw new Error('Invalid invite');
}
