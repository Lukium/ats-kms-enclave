/**
 * Account root & recovery-phrase tests (secure-messaging §18).
 *
 * BIP-39 encode/decode is checked against the canonical Trezor English test
 * vectors (all-zero, 0x7f, 0x80, 0xff at 128 bits, plus a 256-bit vector) so a
 * corrupted or reordered wordlist fails loudly, plus roundtrips and the full
 * error surface for the account-facing 128-bit wrappers.
 *
 * Runs in the `node` environment for native `crypto.subtle` (SHA-256 checksum
 * + CSPRNG), matching the other v2 crypto suites.
 */

// @vitest-environment node

import { describe, it, expect } from 'vitest';

import {
  ACCOUNT_ROOT_BYTES,
  ACCOUNT_ROOT_WORDS,
  generateAccountRoot,
  entropyToMnemonic,
  mnemonicToEntropy,
  accountRootToMnemonic,
  mnemonicToAccountRoot,
} from '@/v2/account-root';

/** Build a Uint8Array of `length` bytes all set to `value`. */
function filled(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Canonical BIP-39 English test vectors (Trezor python-mnemonic vectors.json).
const VECTORS: Array<{ entropy: Uint8Array; mnemonic: string }> = [
  {
    entropy: filled(16, 0x00),
    mnemonic:
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  },
  {
    entropy: filled(16, 0x7f),
    mnemonic:
      'legal winner thank year wave sausage worth useful legal winner thank yellow',
  },
  {
    entropy: filled(16, 0x80),
    mnemonic:
      'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
  },
  {
    entropy: filled(16, 0xff),
    mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  },
  {
    // 256-bit entropy → 24 words.
    entropy: filled(32, 0x00),
    mnemonic:
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art',
  },
  {
    // A non-uniform 128-bit vector (Trezor vectors.json).
    entropy: hexToBytes('9e885d952ad362caeb4efe34a8e91bd2'),
    mnemonic:
      'ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic',
  },
];

describe('generateAccountRoot', () => {
  it('returns 128 bits (16 bytes)', () => {
    const root = generateAccountRoot();
    expect(root).toBeInstanceOf(Uint8Array);
    expect(root.length).toBe(ACCOUNT_ROOT_BYTES);
    expect(ACCOUNT_ROOT_BYTES).toBe(16);
  });

  it('is not all-zero and differs across calls (CSPRNG)', () => {
    const a = generateAccountRoot();
    const b = generateAccountRoot();
    expect(a.some((byte) => byte !== 0)).toBe(true);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe('entropyToMnemonic / mnemonicToEntropy — canonical vectors', () => {
  for (const { entropy, mnemonic } of VECTORS) {
    it(`encodes ${entropy.length}-byte entropy to the expected phrase`, async () => {
      expect(await entropyToMnemonic(entropy)).toBe(mnemonic);
    });

    it(`decodes the phrase back to ${entropy.length}-byte entropy`, async () => {
      const decoded = await mnemonicToEntropy(mnemonic);
      expect(Buffer.from(decoded).equals(Buffer.from(entropy))).toBe(true);
    });
  }
});

describe('entropyToMnemonic — errors', () => {
  it('rejects an invalid entropy length', async () => {
    await expect(entropyToMnemonic(new Uint8Array(15))).rejects.toThrow(/entropy length/);
  });
});

describe('mnemonicToEntropy — errors & normalisation', () => {
  it('normalises whitespace and case', async () => {
    const decoded = await mnemonicToEntropy(
      '  ABANDON   abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ABOUT '
    );
    expect(Buffer.from(decoded).equals(Buffer.from(filled(16, 0x00)))).toBe(true);
  });

  it('rejects an invalid word count', async () => {
    await expect(mnemonicToEntropy('abandon abandon abandon')).rejects.toThrow(/word count/);
  });

  it('rejects an unknown word', async () => {
    const bad =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword';
    await expect(mnemonicToEntropy(bad)).rejects.toThrow(/not in the wordlist/);
  });

  it('rejects a checksum mismatch', async () => {
    // Valid words, wrong last word → checksum fails (0x00*16 needs "about").
    const bad =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    await expect(mnemonicToEntropy(bad)).rejects.toThrow(/checksum/);
  });
});

describe('roundtrip', () => {
  it('generate → mnemonic → entropy is identity', async () => {
    for (let i = 0; i < 20; i++) {
      const root = generateAccountRoot();
      const phrase = await accountRootToMnemonic(root);
      expect(phrase.split(' ')).toHaveLength(ACCOUNT_ROOT_WORDS);
      const recovered = await mnemonicToAccountRoot(phrase);
      expect(Buffer.from(recovered).equals(Buffer.from(root))).toBe(true);
    }
  });
});

describe('accountRootToMnemonic / mnemonicToAccountRoot — 128-bit pinning', () => {
  it('accountRootToMnemonic rejects a non-16-byte root', async () => {
    await expect(accountRootToMnemonic(new Uint8Array(32))).rejects.toThrow(/must be 16 bytes/);
  });

  it('mnemonicToAccountRoot rejects a valid but 256-bit (24-word) phrase', async () => {
    const phrase24 = await entropyToMnemonic(filled(32, 0x00));
    await expect(mnemonicToAccountRoot(phrase24)).rejects.toThrow(/must decode to a 16-byte/);
  });

  it('accountRootToMnemonic produces a 12-word phrase', async () => {
    const phrase = await accountRootToMnemonic(filled(16, 0x00));
    expect(phrase.split(' ')).toHaveLength(12);
  });
});
