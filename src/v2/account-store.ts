/**
 * Account-root persistence (secure-messaging §18).
 *
 * Wraps the 16-byte `accountRoot` under the device's MASTER MKEK (the top key
 * tier — not the messaging sub-KEK), binding it to the user via AAD, and stores
 * it in the `messaging-account` object store. The plaintext value is shared
 * across the account's devices, but each device wraps its own copy under its own
 * MKEK, so the stored blob differs per device even though the value does not.
 *
 * Because it lives under the master MKEK, reads/writes here happen inside a full
 * `withUnlock` (setup / import / add-device / open-messaging), never off a bare
 * messaging capability — consistent with keeping the recovery master secret in
 * the top trust tier.
 */

import { wrapBlob, unwrapBlob, getMessagingAccount, putMessagingAccount } from './storage';

/** AAD schema version for the account-root blob; bump if the binding changes. */
const ACCOUNT_ROOT_AAD_VERSION = 'account-root/1';

/**
 * Deterministic AAD binding the wrapped accountRoot to its owner, so a blob
 * cannot be transplanted to another user (the GCM tag fails if the recomputed
 * AAD differs).
 */
function accountRootAAD(userId: string): ArrayBuffer {
  const fields = { v: ACCOUNT_ROOT_AAD_VERSION, type: 'account-root', userId };
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  const bytes = new TextEncoder().encode(canonical);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Encrypt and persist the account root for `userId` under the master MKEK.
 * Overwrites any existing record (setup guards against that at the RPC layer).
 */
export async function storeAccountRoot(
  userId: string,
  accountRoot: Uint8Array,
  mkek: CryptoKey
): Promise<void> {
  const wrapped = await wrapBlob(accountRoot, mkek, accountRootAAD(userId));
  await putMessagingAccount({ userId, wrappedAccountRoot: wrapped, createdAt: Date.now() });
}

/**
 * Load and decrypt the account root for `userId`, or `null` if this device has
 * none yet. Requires the master MKEK (fail-closed if the wrong key/AAD).
 */
export async function loadAccountRoot(
  userId: string,
  mkek: CryptoKey
): Promise<Uint8Array | null> {
  const record = await getMessagingAccount(userId);
  if (!record) {
    return null;
  }
  const bytes = await unwrapBlob(record.wrappedAccountRoot, mkek, accountRootAAD(userId));
  return new Uint8Array(bytes);
}

/**
 * Whether this device already holds an account root (no unlock needed — a
 * presence check that reads no secret bytes).
 */
export async function hasAccountRoot(userId: string): Promise<boolean> {
  return (await getMessagingAccount(userId)) !== null;
}
