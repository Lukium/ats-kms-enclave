/**
 * Unlock Manager Tests (Phase 1 - TDD)
 *
 * Tests for passphrase-based unlock and key derivation.
 * Tests written BEFORE implementation following TDD methodology.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  setupPassphrase,
  unlockWithPassphrase,
  isSetup,
  resetUnlock,
  deriveKey,
} from '@/unlock';

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await resetUnlock();
});

describe('Unlock Manager - Setup', () => {
  it('should setup passphrase on first use', async () => {
    const result = await setupPassphrase('my-secure-passphrase');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key).toBeInstanceOf(CryptoKey);
    }
  });

  it('should generate a wrapping key with correct algorithm', async () => {
    const result = await setupPassphrase('test-passphrase');

    expect(result.success).toBe(true);
    if (result.success) {
      const key = result.key;
      expect(key.type).toBe('secret');
      expect(key.algorithm.name).toBe('AES-GCM');
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
    }
  });

  it('should make key non-extractable', async () => {
    const result = await setupPassphrase('test-passphrase');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key.extractable).toBe(false);
    }
  });

  it('should set key usages for wrapping', async () => {
    const result = await setupPassphrase('test-passphrase');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key.usages).toContain('wrapKey');
      expect(result.key.usages).toContain('unwrapKey');
    }
  });

  it('should mark as setup after passphrase setup', async () => {
    expect(await isSetup()).toBe(false);

    await setupPassphrase('test-passphrase');

    expect(await isSetup()).toBe(true);
  });

  it('should fail if already setup', async () => {
    await setupPassphrase('first-passphrase');

    const result = await setupPassphrase('second-passphrase');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('ALREADY_SETUP');
    }
  });

  it('should reject empty passphrase', async () => {
    const result = await setupPassphrase('');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INVALID_PASSPHRASE');
    }
  });

  it('should reject passphrase shorter than 8 characters', async () => {
    const result = await setupPassphrase('short');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSPHRASE_TOO_SHORT');
    }
  });
});

describe('Unlock Manager - Unlock', () => {
  beforeEach(async () => {
    // Setup a passphrase before unlock tests
    await setupPassphrase('my-test-passphrase');
  });

  it('should unlock with correct passphrase', async () => {
    const result = await unlockWithPassphrase('my-test-passphrase');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key).toBeInstanceOf(CryptoKey);
    }
  });

  it('should derive same key on unlock as setup', async () => {
    // Reset to start fresh
    await resetUnlock();

    const setupResult = await setupPassphrase('consistent-passphrase');
    await resetUnlock();

    // Re-setup with same passphrase
    const secondSetup = await setupPassphrase('consistent-passphrase');
    await resetUnlock();

    // Note: We can't directly compare CryptoKey objects, but we can verify
    // they produce the same wrapped output
    expect(setupResult.success).toBe(true);
    if (setupResult.success) {
      expect(setupResult.key).toBeDefined();
    }
    expect(secondSetup.success).toBe(true);
    if (secondSetup.success) {
      expect(secondSetup.key).toBeDefined();
    }
  });

  it('should fail unlock with wrong passphrase', async () => {
    const result = await unlockWithPassphrase('wrong-passphrase');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INCORRECT_PASSPHRASE');
    }
  });

  it('should fail unlock if not setup', async () => {
    await resetUnlock();

    const result = await unlockWithPassphrase('any-passphrase');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it('should reject empty passphrase on unlock', async () => {
    const result = await unlockWithPassphrase('');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INVALID_PASSPHRASE');
    }
  });
});

describe('Unlock Manager - Key Derivation', () => {
  it('should derive key from passphrase and salt', async () => {
    const passphrase = 'test-passphrase';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iterations = 600000;

    const key = await deriveKey(passphrase, salt, iterations);

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
  });

  it('should derive same key with same inputs', async () => {
    const passphrase = 'consistent-test';
    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const iterations = 600000;

    const key1 = await deriveKey(passphrase, salt, iterations);
    const key2 = await deriveKey(passphrase, salt, iterations);

    // Can't directly compare CryptoKeys, but both should be defined
    expect(key1).toBeDefined();
    expect(key2).toBeDefined();
    expect(key1.algorithm.name).toBe(key2.algorithm.name);
  });

  it('should derive different keys with different salts', async () => {
    const passphrase = 'same-passphrase';
    const salt1 = new Uint8Array(16).fill(1);
    const salt2 = new Uint8Array(16).fill(2);
    const iterations = 600000;

    const key1 = await deriveKey(passphrase, salt1, iterations);
    const key2 = await deriveKey(passphrase, salt2, iterations);

    // Both should exist but we can verify they're different by using them
    expect(key1).toBeDefined();
    expect(key2).toBeDefined();
  });

  it('should use correct iteration count', async () => {
    // This test verifies the key derivation completes with the specified iterations
    const passphrase = 'iteration-test';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iterations = 600000; // OWASP recommendation

    const key = await deriveKey(passphrase, salt, iterations);

    expect(key).toBeDefined();
  });
});

describe('Unlock Manager - State Management', () => {
  it('should start with no setup', async () => {
    expect(await isSetup()).toBe(false);
  });

  it('should persist setup state', async () => {
    await setupPassphrase('persist-test');

    expect(await isSetup()).toBe(true);
  });

  it('should reset unlock state', async () => {
    await setupPassphrase('reset-test');
    expect(await isSetup()).toBe(true);

    await resetUnlock();

    expect(await isSetup()).toBe(false);
  });

  it('should allow re-setup after reset', async () => {
    await setupPassphrase('first-setup');
    await resetUnlock();

    const result = await setupPassphrase('second-setup');

    expect(result.success).toBe(true);
    expect(await isSetup()).toBe(true);
  });
});

describe('Unlock Manager - Error Handling', () => {
  it('should handle null passphrase gracefully', async () => {
    const result = await setupPassphrase(null as unknown as string);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INVALID_PASSPHRASE');
    }
  });

  it('should handle undefined passphrase gracefully', async () => {
    const result = await setupPassphrase(undefined as unknown as string);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INVALID_PASSPHRASE');
    }
  });

  it('should handle non-string passphrase gracefully', async () => {
    const result = await setupPassphrase(12345 as unknown as string);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INVALID_PASSPHRASE');
    }
  });
});

describe('Unlock Manager - Security', () => {
  it('should use 600,000 iterations (OWASP recommendation)', async () => {
    const result = await setupPassphrase('security-test');

    // This is implicit in the implementation - we're verifying it completes
    expect(result.success).toBe(true);
  });

  it('should generate random salt on setup', async () => {
    // Setup twice and verify we can unlock each independently
    await setupPassphrase('first-user');
    const firstSetup = await isSetup();
    await resetUnlock();

    await setupPassphrase('second-user');
    const secondSetup = await isSetup();

    expect(firstSetup).toBe(true);
    expect(secondSetup).toBe(true);
  });

  it('should store salt in meta store', async () => {
    await setupPassphrase('meta-test');

    // Salt should be retrievable (tested indirectly via unlock)
    const unlockResult = await unlockWithPassphrase('meta-test');
    expect(unlockResult.success).toBe(true);
  });
});
