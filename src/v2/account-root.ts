/**
 * Account root & recovery-phrase domain (secure-messaging §18).
 *
 * A per-account `accountRoot` is 128 bits of entropy, born once on the first
 * device and shown to the user once as a 12-word BIP-39 recovery phrase. It is
 * the seed from which the server-blind self-channel (`selfScope`/`selfKey`) is
 * derived (see {@link ./account-root.ts} follow-on functions) and which is
 * wrapped to other devices for auto-onboarding.
 *
 * This module implements the pure `accountRoot` <-> mnemonic mapping:
 *  - {@link generateAccountRoot}: 128 bits of CSPRNG entropy.
 *  - {@link entropyToMnemonic} / {@link mnemonicToEntropy}: the general BIP-39
 *    encode/decode (128–256-bit entropy, checksummed), verified against the
 *    canonical Trezor test vectors.
 *  - {@link accountRootToMnemonic} / {@link mnemonicToAccountRoot}: the
 *    account-facing 128-bit-pinned wrappers.
 *
 * A generated 128-bit phrase is NOT brute-forceable (unlike a human passphrase),
 * so the phrase is a MITM-free recovery path per §18.1.
 */

import { BIP39_WORDLIST } from './bip39-wordlist';

// ============================================================================
// Constants
// ============================================================================

/** `accountRoot` size in bytes (128 bits) — a 12-word BIP-39 phrase. */
export const ACCOUNT_ROOT_BYTES = 16;

/** Number of words in the account recovery phrase (128-bit entropy → 12 words). */
export const ACCOUNT_ROOT_WORDS = 12;

/** Bits per BIP-39 word (each word encodes an 11-bit index into the wordlist). */
const BITS_PER_WORD = 11;

/** Valid BIP-39 entropy sizes in bytes (128, 160, 192, 224, 256 bits). */
const VALID_ENTROPY_BYTES: readonly number[] = [16, 20, 24, 28, 32];

// ============================================================================
// accountRoot generation
// ============================================================================

/**
 * Generate a fresh 128-bit `accountRoot` from the platform CSPRNG.
 *
 * Born once per account on the first device; the caller is responsible for
 * showing the derived recovery phrase to the user exactly once and never
 * persisting the raw bytes unwrapped.
 */
export function generateAccountRoot(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(ACCOUNT_ROOT_BYTES));
}

// ============================================================================
// Bit helpers
// ============================================================================

/**
 * Expand bytes to a big-endian bit string ('0'/'1' chars, MSB first). Used to
 * regroup entropy+checksum into 11-bit word indices; string bit-twiddling keeps
 * the mapping obvious and side-channel concerns are irrelevant (the phrase is
 * shown to the user anyway).
 */
function bytesToBits(bytes: Uint8Array): string {
  let bits = '';
  for (const byte of bytes) {
    bits += byte.toString(2).padStart(8, '0');
  }
  return bits;
}

/** Pack a big-endian bit string (length a multiple of 8) into bytes. */
function bitsToBytes(bits: string): Uint8Array {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return out;
}

/**
 * Compute the BIP-39 checksum bits: the first `entropyBytes / 4` bits of
 * SHA-256(entropy), as a big-endian bit string.
 */
async function checksumBits(entropy: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy as BufferSource));
  const checksumLength = entropy.length / 4; // ENT/32 bits
  return bytesToBits(digest).slice(0, checksumLength);
}

// ============================================================================
// BIP-39 encode / decode (general)
// ============================================================================

/**
 * Encode entropy as a BIP-39 mnemonic phrase (space-joined lowercase words).
 *
 * @param entropy 16/20/24/28/32 bytes (128–256 bits, 32-bit steps).
 * @throws if the entropy length is not a valid BIP-39 size.
 */
export async function entropyToMnemonic(entropy: Uint8Array): Promise<string> {
  if (!VALID_ENTROPY_BYTES.includes(entropy.length)) {
    throw new Error(
      `Invalid BIP-39 entropy length: ${entropy.length} bytes (expected one of ${VALID_ENTROPY_BYTES.join(', ')})`
    );
  }
  const bits = bytesToBits(entropy) + (await checksumBits(entropy));
  const words: string[] = [];
  for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
    const index = parseInt(bits.slice(i, i + BITS_PER_WORD), 2);
    words.push(BIP39_WORDLIST[index]!);
  }
  return words.join(' ');
}

/**
 * Decode a BIP-39 mnemonic phrase back to its entropy, verifying the checksum.
 *
 * Input is normalised (trimmed, collapsed whitespace, lowercased). Each word
 * must be in the English wordlist and the trailing checksum bits must match
 * SHA-256(entropy); otherwise the phrase is rejected.
 *
 * @throws if the word count is invalid, a word is unknown, or the checksum fails.
 */
export async function mnemonicToEntropy(mnemonic: string): Promise<Uint8Array> {
  const words = mnemonic.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const validWordCounts = VALID_ENTROPY_BYTES.map((b) => ((b * 8) / 32) * 3); // 12,15,18,21,24
  if (!validWordCounts.includes(words.length)) {
    throw new Error(
      `Invalid BIP-39 word count: ${words.length} (expected one of ${validWordCounts.join(', ')})`
    );
  }
  let bits = '';
  for (const word of words) {
    const index = BIP39_WORDLIST.indexOf(word);
    if (index === -1) {
      throw new Error(`Invalid BIP-39 word: "${word}" is not in the wordlist`);
    }
    bits += index.toString(2).padStart(BITS_PER_WORD, '0');
  }
  // Split into entropy (multiple of 8 bits) + checksum (the remainder).
  const entropyBits = Math.floor(bits.length / 33) * 32;
  const entropy = bitsToBytes(bits.slice(0, entropyBits));
  const providedChecksum = bits.slice(entropyBits);
  const expectedChecksum = await checksumBits(entropy);
  if (providedChecksum !== expectedChecksum) {
    throw new Error('Invalid BIP-39 mnemonic: checksum mismatch');
  }
  return entropy;
}

// ============================================================================
// Account-facing wrappers (128-bit pinned)
// ============================================================================

/**
 * Render a 128-bit `accountRoot` as its 12-word recovery phrase.
 *
 * @throws if `accountRoot` is not exactly {@link ACCOUNT_ROOT_BYTES} bytes.
 */
export async function accountRootToMnemonic(accountRoot: Uint8Array): Promise<string> {
  if (accountRoot.length !== ACCOUNT_ROOT_BYTES) {
    throw new Error(
      `accountRoot must be ${ACCOUNT_ROOT_BYTES} bytes, got ${accountRoot.length}`
    );
  }
  return entropyToMnemonic(accountRoot);
}

/**
 * Reconstruct a 128-bit `accountRoot` from its 12-word recovery phrase.
 *
 * @throws if the phrase is not 12 words or does not decode to a 128-bit value.
 */
export async function mnemonicToAccountRoot(mnemonic: string): Promise<Uint8Array> {
  const entropy = await mnemonicToEntropy(mnemonic);
  if (entropy.length !== ACCOUNT_ROOT_BYTES) {
    throw new Error(
      `Recovery phrase must decode to a ${ACCOUNT_ROOT_BYTES}-byte accountRoot, got ${entropy.length} bytes`
    );
  }
  return entropy;
}
