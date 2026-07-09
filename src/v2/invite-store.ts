/**
 * Armed Connect-invite persistence (rooms-and-trust §3.2/§3.3).
 *
 * When a user mints an invite, its room secret is wrapped under the device's
 * messagingKEK and persisted (bound by AAD to (userId, inviteId)) so the invite
 * SURVIVES the app closing — the whole point of a link the peer opens later. On
 * reopen the enclave reloads it and the PWA re-subscribes to `scope`, so a late
 * join still lands. The plaintext secret never leaves the enclave; the PWA only
 * ever learns the (non-secret) `scope` + public lifecycle fields.
 *
 * These run off a live messaging capability (the session's messagingKEK), never a
 * full unlock — minting/receiving is routine foreground activity.
 */

import { wrapBlob, unwrapBlob, getMessagingInvite, getMessagingInvites, putMessagingInvite } from './storage';
import type { InviteType, InviteMeta, MessagingInviteRecord } from './types';

export type { InviteMeta };

/** AAD schema version for a wrapped invite secret; bump if the binding changes. */
const INVITE_SECRET_AAD_VERSION = 'invite-secret/1';

/**
 * Deterministic AAD binding a wrapped invite secret to (userId, inviteId), so a
 * blob cannot be transplanted to another invite or user (GCM tag fails if the
 * recomputed AAD differs).
 */
function inviteSecretAAD(userId: string, inviteId: string): ArrayBuffer {
  const fields = { v: INVITE_SECRET_AAD_VERSION, type: 'invite-secret', userId, inviteId };
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  const bytes = new TextEncoder().encode(canonical);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/** The public metadata view of a stored record (no secret bytes). */
function toMeta(r: MessagingInviteRecord): InviteMeta {
  const meta: InviteMeta = {
    inviteId: r.inviteId,
    scope: r.scope,
    type: r.type,
    createdAt: r.createdAt,
  };
  if (r.expiresAt !== undefined) meta.expiresAt = r.expiresAt;
  if (r.singleUse !== undefined) meta.singleUse = r.singleUse;
  return meta;
}

/** Wrap and persist an armed invite's room secret + public metadata. */
export async function storeInvite(
  params: {
    userId: string;
    inviteId: string;
    secret: Uint8Array;
    scope: string;
    type: InviteType;
    expiresAt?: number;
    singleUse?: boolean;
  },
  messagingKEK: CryptoKey
): Promise<void> {
  const wrapped = await wrapBlob(
    params.secret,
    messagingKEK,
    inviteSecretAAD(params.userId, params.inviteId)
  );
  const record: MessagingInviteRecord = {
    inviteId: params.inviteId,
    userId: params.userId,
    wrappedSecret: wrapped,
    scope: params.scope,
    type: params.type,
    createdAt: Date.now(),
  };
  if (params.expiresAt !== undefined) record.expiresAt = params.expiresAt;
  if (params.singleUse !== undefined) record.singleUse = params.singleUse;
  await putMessagingInvite(record);
}

/**
 * Load and decrypt an armed invite's secret (+ metadata), or `null` if this device
 * has no such invite for `userId`. Fail-closed on the wrong key/AAD or a foreign
 * owner (an invite is scoped to the user who minted it).
 */
export async function loadInvite(
  userId: string,
  inviteId: string,
  messagingKEK: CryptoKey
): Promise<{ secret: Uint8Array; meta: InviteMeta } | null> {
  const record = await getMessagingInvite(inviteId);
  if (!record || record.userId !== userId) {
    return null;
  }
  const bytes = await unwrapBlob(record.wrappedSecret, messagingKEK, inviteSecretAAD(userId, inviteId));
  return { secret: new Uint8Array(bytes), meta: toMeta(record) };
}

/** List the public metadata of every armed invite this user holds (no secrets read). */
export async function listInviteMeta(userId: string): Promise<InviteMeta[]> {
  const records = await getMessagingInvites(userId);
  return records.map(toMeta);
}
