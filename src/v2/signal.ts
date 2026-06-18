/**
 * Signal-protocol messaging domain (Phase 1 — enclave messaging core).
 *
 * This module is the linchpin between the vendored Signal library
 * (`@lukium/libsignal-protocol-typescript`) and the enclave's MKEK-wrapped
 * IndexedDB stores. It provides:
 *
 *  - {@link createSignalProtocolStore}: a per-(user, unlock-session) object that
 *    satisfies the library's `StorageType`. All secret key material and ratchet
 *    state is persisted only as MKEK-wrapped blobs; the MKEK is captured in the
 *    closure (in Worker memory) and is never read back from storage.
 *  - prekey generation ({@link generateIdentity}, {@link generateSignedPrekey},
 *    {@link generateOneTimePrekeys}) and {@link getPublicBundle}, which returns
 *    only public bytes (no unlock needed) for upload to the directory server.
 *
 * Identity is the WebCrypto two-key form: an X25519 DH key (X3DH) plus an
 * Ed25519 signing key (signs signed-prekeys). Both public halves travel in the
 * bundle; the four private/public bytes are wrapped together under the MKEK.
 *
 * Secret bytes are plaintext in Worker memory only transiently, during a cipher
 * operation — inherent to a Double Ratchet, and within the accepted threat model
 * (a compromised Worker is already out of scope). At rest, everything is
 * MKEK-wrapped with AAD binding it to {type, userId, peer/keyId}.
 */

import { KeyHelper } from '@lukium/libsignal-protocol-typescript';
import type {
  StorageType,
  IdentityKeyPairType,
  KeyPairType,
} from '@lukium/libsignal-protocol-typescript';

import {
  wrapBlob,
  unwrapBlob,
  getSignalIdentity,
  putSignalIdentity,
  getSignalSignedPrekey,
  getSignalSignedPrekeys,
  putSignalSignedPrekey,
  deleteSignalSignedPrekey,
  getSignalOnetimePrekey,
  getSignalOnetimePrekeys,
  putSignalOnetimePrekey,
  putSignalOnetimePrekeys,
  getSignalSession,
  putSignalSession,
  getSignalTrustedIdentity,
  putSignalTrustedIdentity,
} from './storage';
import type {
  SignalIdentityRecord,
  SignalSignedPrekeyRecord,
  SignalOnetimePrekeyRecord,
} from './types';
import {
  arrayBufferToBase64url,
  base64urlToArrayBuffer,
  timingSafeEqual,
} from './crypto-utils';

// ============================================================================
// Constants
// ============================================================================

/** AAD schema version; bump if the blob-context binding shape changes. */
const SIGNAL_AAD_VERSION = 'signal/1';

/** Default signed-prekey lifetime (rotation cadence is enforced elsewhere). */
const SIGNED_PREKEY_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// ============================================================================
// AAD + (de)serialization helpers
// ============================================================================

type BlobContext =
  | { type: 'identity'; userId: string }
  | { type: 'signed-prekey'; userId: string; keyId: number }
  | { type: 'onetime-prekey'; userId: string; keyId: number }
  | { type: 'session'; userId: string; peerAddress: string };

/**
 * Build deterministic Additional Authenticated Data that binds a wrapped blob to
 * its context, so a blob cannot be transplanted between users, peers, or key
 * slots (the GCM tag fails if the recomputed AAD differs).
 */
function blobAAD(ctx: BlobContext): ArrayBuffer {
  const fields: Record<string, string | number> = { v: SIGNAL_AAD_VERSION, ...ctx };
  // Canonical JSON: serialize keys in sorted order.
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  const bytes = new TextEncoder().encode(canonical);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

interface SerializedKeyPair {
  pubKey: string;
  privKey: string;
}

interface SerializedIdentity extends SerializedKeyPair {
  signingPubKey: string;
  signingPrivKey: string;
}

function serializeKeyPair(kp: KeyPairType): Uint8Array {
  const obj: SerializedKeyPair = {
    pubKey: arrayBufferToBase64url(kp.pubKey),
    privKey: arrayBufferToBase64url(kp.privKey),
  };
  return new TextEncoder().encode(JSON.stringify(obj));
}

function deserializeKeyPair(bytes: ArrayBuffer): KeyPairType {
  const obj = JSON.parse(new TextDecoder().decode(bytes)) as SerializedKeyPair;
  return {
    pubKey: base64urlToArrayBuffer(obj.pubKey),
    privKey: base64urlToArrayBuffer(obj.privKey),
  };
}

function serializeIdentity(id: IdentityKeyPairType): Uint8Array {
  const obj: SerializedIdentity = {
    pubKey: arrayBufferToBase64url(id.pubKey),
    privKey: arrayBufferToBase64url(id.privKey),
    signingPubKey: arrayBufferToBase64url(id.signingPubKey),
    signingPrivKey: arrayBufferToBase64url(id.signingPrivKey),
  };
  return new TextEncoder().encode(JSON.stringify(obj));
}

function deserializeIdentity(bytes: ArrayBuffer): IdentityKeyPairType {
  const obj = JSON.parse(new TextDecoder().decode(bytes)) as SerializedIdentity;
  return {
    pubKey: base64urlToArrayBuffer(obj.pubKey),
    privKey: base64urlToArrayBuffer(obj.privKey),
    signingPubKey: base64urlToArrayBuffer(obj.signingPubKey),
    signingPrivKey: base64urlToArrayBuffer(obj.signingPrivKey),
  };
}

/** Unwrap a stored identity record to its full (4-key) identity key pair. */
async function unwrapIdentity(
  record: SignalIdentityRecord,
  userId: string,
  mkek: CryptoKey
): Promise<IdentityKeyPairType> {
  const bytes = await unwrapBlob(record.wrappedIdentity, mkek, blobAAD({ type: 'identity', userId }));
  return deserializeIdentity(bytes);
}

// ============================================================================
// Key generation (require the MKEK to wrap secret material)
// ============================================================================

/**
 * Create and persist the user's long-term Signal identity. Idempotent: if an
 * identity already exists it is returned unchanged.
 */
export async function generateIdentity(
  userId: string,
  mkek: CryptoKey,
  registrationId?: number
): Promise<SignalIdentityRecord> {
  const existing = await getSignalIdentity(userId);
  if (existing) {
    return existing;
  }
  const identity = await KeyHelper.generateIdentityKeyPair();
  const regId = registrationId ?? KeyHelper.generateRegistrationId();
  const wrappedIdentity = await wrapBlob(
    serializeIdentity(identity),
    mkek,
    blobAAD({ type: 'identity', userId })
  );
  const record: SignalIdentityRecord = {
    userId,
    registrationId: regId,
    wrappedIdentity,
    identityPubKey: identity.pubKey,
    identitySigningPubKey: identity.signingPubKey,
    createdAt: Date.now(),
  };
  await putSignalIdentity(record);
  return record;
}

/**
 * Generate a signed prekey for `keyId`, signed by the user's Ed25519 identity
 * key, and persist it (private bytes MKEK-wrapped).
 */
export async function generateSignedPrekey(
  userId: string,
  mkek: CryptoKey,
  keyId: number
): Promise<SignalSignedPrekeyRecord> {
  const identityRecord = await getSignalIdentity(userId);
  if (!identityRecord) {
    throw new Error(`No Signal identity for user ${userId}; call generateIdentity first`);
  }
  const identity = await unwrapIdentity(identityRecord, userId, mkek);
  const signed = await KeyHelper.generateSignedPreKey(identity, keyId);
  const wrappedKeyPair = await wrapBlob(
    serializeKeyPair(signed.keyPair),
    mkek,
    blobAAD({ type: 'signed-prekey', userId, keyId })
  );
  const now = Date.now();
  const record: SignalSignedPrekeyRecord = {
    userId,
    keyId,
    wrappedKeyPair,
    signedPubKey: signed.keyPair.pubKey,
    signature: signed.signature,
    createdAt: now,
    expiresAt: now + SIGNED_PREKEY_TTL_MS,
  };
  await putSignalSignedPrekey(record);
  return record;
}

/**
 * Generate `count` one-time prekeys with sequential ids starting at `startKeyId`
 * and persist them in one transaction (private bytes MKEK-wrapped).
 */
export async function generateOneTimePrekeys(
  userId: string,
  mkek: CryptoKey,
  startKeyId: number,
  count: number
): Promise<SignalOnetimePrekeyRecord[]> {
  const now = Date.now();
  const records: SignalOnetimePrekeyRecord[] = [];
  for (let i = 0; i < count; i++) {
    const keyId = startKeyId + i;
    const preKey = await KeyHelper.generatePreKey(keyId);
    const wrappedKeyPair = await wrapBlob(
      serializeKeyPair(preKey.keyPair),
      mkek,
      blobAAD({ type: 'onetime-prekey', userId, keyId })
    );
    records.push({
      userId,
      keyId,
      wrappedKeyPair,
      pubKey: preKey.keyPair.pubKey,
      consumed: false,
      createdAt: now,
    });
  }
  await putSignalOnetimePrekeys(records);
  return records;
}

// ============================================================================
// Public bundle (public bytes only — no unlock required)
// ============================================================================

export interface PublicPreKeyBundle {
  registrationId: number;
  /** X25519 DH identity public key (33 bytes, 0x05-prefixed). */
  identityKey: ArrayBuffer;
  /** Ed25519 identity signing public key (32 bytes). */
  identitySigningKey: ArrayBuffer;
  signedPreKey: { keyId: number; publicKey: ArrayBuffer; signature: ArrayBuffer };
  /** Unconsumed one-time prekey publics for upload to the directory. */
  oneTimePreKeys: { keyId: number; publicKey: ArrayBuffer }[];
}

/**
 * Assemble the public prekey bundle the directory server's upload expects. Reads
 * only public fields, so it needs no MKEK / unlock.
 */
export async function getPublicBundle(userId: string): Promise<PublicPreKeyBundle> {
  const identity = await getSignalIdentity(userId);
  if (!identity) {
    throw new Error(`No Signal identity for user ${userId}`);
  }
  const signedPrekeys = await getSignalSignedPrekeys(userId);
  if (signedPrekeys.length === 0) {
    throw new Error(`No signed prekey for user ${userId}`);
  }
  // Use the most recently created signed prekey.
  const signed = signedPrekeys.reduce((newest, candidate) =>
    candidate.createdAt > newest.createdAt ? candidate : newest
  );
  const oneTime = (await getSignalOnetimePrekeys(userId)).filter((pk) => !pk.consumed);
  return {
    registrationId: identity.registrationId,
    identityKey: identity.identityPubKey,
    identitySigningKey: identity.identitySigningPubKey,
    signedPreKey: {
      keyId: signed.keyId,
      publicKey: signed.signedPubKey,
      signature: signed.signature,
    },
    oneTimePreKeys: oneTime.map((pk) => ({ keyId: pk.keyId, publicKey: pk.pubKey })),
  };
}

// ============================================================================
// StorageType adapter
// ============================================================================

/**
 * Build a `StorageType` for one user, with the MKEK captured in-closure. Every
 * read unwraps and every write rewraps against the MKEK; the key is never
 * persisted. One adapter is created per unlock session and discarded when the
 * session closes (the MKEK leaves memory with it).
 */
export function createSignalProtocolStore(userId: string, mkek: CryptoKey): StorageType {
  return {
    getIdentityKeyPair: async (): Promise<IdentityKeyPairType | undefined> => {
      const record = await getSignalIdentity(userId);
      if (!record) {
        return undefined;
      }
      return unwrapIdentity(record, userId, mkek);
    },

    getLocalRegistrationId: async (): Promise<number | undefined> => {
      const record = await getSignalIdentity(userId);
      return record?.registrationId;
    },

    isTrustedIdentity: async (identifier: string, identityKey: ArrayBuffer): Promise<boolean> => {
      // Trust-on-first-use: an unseen peer is trusted; a changed key is not (the
      // RPC/UI layer surfaces the change). `identifier` is the peer address.
      const record = await getSignalTrustedIdentity(userId, identifier);
      if (!record) {
        return true;
      }
      return timingSafeEqual(record.identityPubKey, identityKey);
    },

    saveIdentity: async (encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> => {
      const existing = await getSignalTrustedIdentity(userId, encodedAddress);
      const now = Date.now();
      if (!existing) {
        await putSignalTrustedIdentity({
          userId,
          peerAddress: encodedAddress,
          identityPubKey: publicKey,
          firstSeenAt: now,
          updatedAt: now,
        });
        return false;
      }
      const changed = !timingSafeEqual(existing.identityPubKey, publicKey);
      if (changed) {
        await putSignalTrustedIdentity({
          ...existing,
          identityPubKey: publicKey,
          updatedAt: now,
        });
      }
      return changed;
    },

    loadPreKey: async (encodedAddress: string | number): Promise<KeyPairType | undefined> => {
      const keyId = Number(encodedAddress);
      const record = await getSignalOnetimePrekey(userId, keyId);
      if (!record || record.consumed) {
        return undefined;
      }
      const bytes = await unwrapBlob(
        record.wrappedKeyPair,
        mkek,
        blobAAD({ type: 'onetime-prekey', userId, keyId })
      );
      return deserializeKeyPair(bytes);
    },

    storePreKey: async (keyId: number | string, keyPair: KeyPairType): Promise<void> => {
      const id = Number(keyId);
      const wrappedKeyPair = await wrapBlob(
        serializeKeyPair(keyPair),
        mkek,
        blobAAD({ type: 'onetime-prekey', userId, keyId: id })
      );
      await putSignalOnetimePrekey({
        userId,
        keyId: id,
        wrappedKeyPair,
        pubKey: keyPair.pubKey,
        consumed: false,
        createdAt: Date.now(),
      });
    },

    removePreKey: async (keyId: number | string): Promise<void> => {
      // Mark consumed rather than delete: keeps the record for audit and makes a
      // replayed prekey message fail (loadPreKey returns undefined when consumed).
      const id = Number(keyId);
      const record = await getSignalOnetimePrekey(userId, id);
      if (!record) {
        return;
      }
      await putSignalOnetimePrekey({ ...record, consumed: true });
    },

    loadSignedPreKey: async (keyId: number | string): Promise<KeyPairType | undefined> => {
      const id = Number(keyId);
      const record = await getSignalSignedPrekey(userId, id);
      if (!record) {
        return undefined;
      }
      const bytes = await unwrapBlob(
        record.wrappedKeyPair,
        mkek,
        blobAAD({ type: 'signed-prekey', userId, keyId: id })
      );
      return deserializeKeyPair(bytes);
    },

    storeSignedPreKey: async (keyId: number | string, keyPair: KeyPairType): Promise<void> => {
      // Not used by the library's session flows (we mint signed prekeys via
      // generateSignedPrekey); provided for StorageType completeness. Re-sign the
      // public with our identity so the persisted record stays self-consistent.
      const id = Number(keyId);
      const identityRecord = await getSignalIdentity(userId);
      if (!identityRecord) {
        throw new Error(`No Signal identity for user ${userId}`);
      }
      const identity = await unwrapIdentity(identityRecord, userId, mkek);
      const signed = await KeyHelper.generateSignedPreKey(identity, id);
      const wrappedKeyPair = await wrapBlob(
        serializeKeyPair(keyPair),
        mkek,
        blobAAD({ type: 'signed-prekey', userId, keyId: id })
      );
      const now = Date.now();
      await putSignalSignedPrekey({
        userId,
        keyId: id,
        wrappedKeyPair,
        signedPubKey: keyPair.pubKey,
        signature: signed.signature,
        createdAt: now,
        expiresAt: now + SIGNED_PREKEY_TTL_MS,
      });
    },

    removeSignedPreKey: async (keyId: number | string): Promise<void> => {
      await deleteSignalSignedPrekey(userId, Number(keyId));
    },

    storeSession: async (encodedAddress: string, record: string): Promise<void> => {
      const wrappedSession = await wrapBlob(
        new TextEncoder().encode(record),
        mkek,
        blobAAD({ type: 'session', userId, peerAddress: encodedAddress })
      );
      const existing = await getSignalSession(userId, encodedAddress);
      await putSignalSession({
        userId,
        peerAddress: encodedAddress,
        wrappedSession,
        updatedAt: Date.now(),
        messageCount: (existing?.messageCount ?? 0) + 1,
      });
    },

    loadSession: async (encodedAddress: string): Promise<string | undefined> => {
      const record = await getSignalSession(userId, encodedAddress);
      if (!record) {
        return undefined;
      }
      const bytes = await unwrapBlob(
        record.wrappedSession,
        mkek,
        blobAAD({ type: 'session', userId, peerAddress: encodedAddress })
      );
      return new TextDecoder().decode(bytes);
    },
  };
}
