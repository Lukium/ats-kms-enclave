/**
 * Unlock Module Test Suite (KMS V2)
 *
 * Comprehensive tests for unlock context management including:
 * - Passphrase setup and unlock (PBKDF2-based)
 * - Passkey PRF setup and unlock (HKDF-based)
 * - Passkey gate setup and unlock (pepper-based fallback)
 * - Multi-enrollment (multiple auth methods for same MS)
 * - MKEK derivation from MS
 * - withUnlock context (per-operation authentication)
 * - MS zeroization and timing tracking
 * - Helper functions (isSetup, isPassphraseSetup, isPasskeySetup)
 *
 * Tests verify cryptographic correctness, error handling, and security properties.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  setupPassphrase,
  unlockWithPassphrase,
  setupPasskeyPRF,
  unlockWithPasskeyPRF,
  setupPasskeyGate,
  unlockWithPasskeyGate,
  deriveMKEKFromMS,
  withUnlock,
  isSetup,
  isPassphraseSetup,
  isPasskeySetup,
} from '@/v2/unlock';
import { initDB, closeDB } from '@/v2/storage';

// ============================================================================
// Test Setup
// ============================================================================

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});

afterEach(() => {
  closeDB();
});

// ============================================================================
// Passphrase Tests
// ============================================================================

describe('setupPassphrase', () => {
  it('should setup passphrase and return MS', async () => {
    const result = await setupPassphrase('my-secure-passphrase-123');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.ms).toBeInstanceOf(Uint8Array);
      expect(result.ms.length).toBe(32); // 256 bits
    }
  });

  it('should use existing MS if provided', async () => {
    const existingMS = new Uint8Array(32);
    crypto.getRandomValues(existingMS);

    const result = await setupPassphrase('passphrase', existingMS);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.ms).toEqual(existingMS);
    }
  });

  it('should store config in storage', async () => {
    await setupPassphrase('test-passphrase');

    // Verify config exists by attempting unlock
    const unlockResult = await unlockWithPassphrase('test-passphrase');
    expect(unlockResult.success).toBe(true);
  });

  it('should calibrate PBKDF2 iterations', async () => {
    const result = await setupPassphrase('passphrase');
    expect(result.success).toBe(true);
    // Iterations should be reasonable (50k-2M range)
    // We can't directly check iterations without exposing internal state,
    // but we can verify that unlock works (which proves correct derivation)
  });
});

describe('unlockWithPassphrase', () => {
  it('should unlock with correct passphrase', async () => {
    const setupResult = await setupPassphrase('correct-passphrase');
    expect(setupResult.success).toBe(true);

    const unlockResult = await unlockWithPassphrase('correct-passphrase');
    expect(unlockResult.success).toBe(true);

    if (setupResult.success && unlockResult.success) {
      expect(unlockResult.ms).toEqual(setupResult.ms);
    }
  });

  it('should fail with incorrect passphrase (KCV check)', async () => {
    await setupPassphrase('correct-passphrase');

    const result = await unlockWithPassphrase('wrong-passphrase');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('Invalid passphrase');
    }
  });

  it('should fail when passphrase not set up', async () => {
    const result = await unlockWithPassphrase('any-passphrase');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('Passphrase not set up');
    }
  });

  it('should return same MS on multiple unlocks', async () => {
    const setupResult = await setupPassphrase('passphrase');
    expect(setupResult.success).toBe(true);

    const unlock1 = await unlockWithPassphrase('passphrase');
    const unlock2 = await unlockWithPassphrase('passphrase');

    expect(unlock1.success).toBe(true);
    expect(unlock2.success).toBe(true);

    if (unlock1.success && unlock2.success) {
      expect(unlock1.ms).toEqual(unlock2.ms);
    }
  });
});

// ============================================================================
// Passkey PRF Tests
// ============================================================================

describe('setupPasskeyPRF', () => {
  it('should setup passkey PRF and return MS', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const result = await setupPasskeyPRF(credentialId, prfOutput);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.ms).toBeInstanceOf(Uint8Array);
      expect(result.ms.length).toBe(32);
    }
  });

  it('should use existing MS if provided', async () => {
    const existingMS = new Uint8Array(32);
    crypto.getRandomValues(existingMS);

    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const result = await setupPasskeyPRF(credentialId, prfOutput, existingMS);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.ms).toEqual(existingMS);
    }
  });

  it('should store config with RP ID', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    await setupPasskeyPRF(credentialId, prfOutput, undefined, 'example.com');

    // Verify by unlocking
    const unlockResult = await unlockWithPasskeyPRF(prfOutput);
    expect(unlockResult.success).toBe(true);
  });
});

describe('unlockWithPasskeyPRF', () => {
  it('should unlock with correct PRF output', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const setupResult = await setupPasskeyPRF(credentialId, prfOutput);
    expect(setupResult.success).toBe(true);

    const unlockResult = await unlockWithPasskeyPRF(prfOutput);
    expect(unlockResult.success).toBe(true);

    if (setupResult.success && unlockResult.success) {
      expect(unlockResult.ms).toEqual(setupResult.ms);
    }
  });

  it('should fail with incorrect PRF output', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const correctPRF = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const wrongPRF = crypto.getRandomValues(new Uint8Array(32)).buffer;

    await setupPasskeyPRF(credentialId, correctPRF);

    const result = await unlockWithPasskeyPRF(wrongPRF);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('Decryption failed');
    }
  });

  it('should fail when passkey PRF not set up', async () => {
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const result = await unlockWithPasskeyPRF(prfOutput);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('Passkey not set up');
    }
  });
});

// ============================================================================
// Passkey Gate Tests
// ============================================================================

describe('setupPasskeyGate', () => {
  it('should setup passkey gate and return MS', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;

    const result = await setupPasskeyGate(credentialId);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.ms).toBeInstanceOf(Uint8Array);
      expect(result.ms.length).toBe(32);
    }
  });

  it('should use existing MS if provided', async () => {
    const existingMS = new Uint8Array(32);
    crypto.getRandomValues(existingMS);

    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;

    const result = await setupPasskeyGate(credentialId, existingMS);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.ms).toEqual(existingMS);
    }
  });

  it('should store config with RP ID', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;

    await setupPasskeyGate(credentialId, undefined, 'example.com');

    // Verify by unlocking
    const unlockResult = await unlockWithPasskeyGate();
    expect(unlockResult.success).toBe(true);
  });
});

describe('unlockWithPasskeyGate', () => {
  it('should unlock successfully', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;

    const setupResult = await setupPasskeyGate(credentialId);
    expect(setupResult.success).toBe(true);

    const unlockResult = await unlockWithPasskeyGate();
    expect(unlockResult.success).toBe(true);

    if (setupResult.success && unlockResult.success) {
      expect(unlockResult.ms).toEqual(setupResult.ms);
    }
  });

  it('should fail when passkey gate not set up', async () => {
    const result = await unlockWithPasskeyGate();
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('Passkey gate not set up');
    }
  });

  it('should return same MS on multiple unlocks', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;
    await setupPasskeyGate(credentialId);

    const unlock1 = await unlockWithPasskeyGate();
    const unlock2 = await unlockWithPasskeyGate();

    expect(unlock1.success).toBe(true);
    expect(unlock2.success).toBe(true);

    if (unlock1.success && unlock2.success) {
      expect(unlock1.ms).toEqual(unlock2.ms);
    }
  });
});

// ============================================================================
// Multi-Enrollment Tests
// ============================================================================

describe('multi-enrollment', () => {
  it('should support passphrase + passkey PRF with same MS', async () => {
    // Setup passphrase first
    const passphraseResult = await setupPassphrase('passphrase');
    expect(passphraseResult.success).toBe(true);

    if (!passphraseResult.success) return;

    // Setup passkey PRF with same MS
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const prfResult = await setupPasskeyPRF(credentialId, prfOutput, passphraseResult.ms);

    expect(prfResult.success).toBe(true);

    // Both methods should unlock to same MS
    const passphraseUnlock = await unlockWithPassphrase('passphrase');
    const prfUnlock = await unlockWithPasskeyPRF(prfOutput);

    expect(passphraseUnlock.success).toBe(true);
    expect(prfUnlock.success).toBe(true);

    if (passphraseUnlock.success && prfUnlock.success) {
      expect(passphraseUnlock.ms).toEqual(prfUnlock.ms);
      expect(passphraseUnlock.ms).toEqual(passphraseResult.ms);
    }
  });

  it('should support all three methods with same MS', async () => {
    // Generate shared MS
    const sharedMS = new Uint8Array(32);
    crypto.getRandomValues(sharedMS);

    // Setup all three methods
    await setupPassphrase('passphrase', sharedMS);

    const credId1 = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credId1, prfOutput, sharedMS);

    const credId2 = new Uint8Array([5, 6, 7, 8]).buffer;
    await setupPasskeyGate(credId2, sharedMS);

    // All should unlock to same MS
    const unlock1 = await unlockWithPassphrase('passphrase');
    const unlock2 = await unlockWithPasskeyPRF(prfOutput);
    const unlock3 = await unlockWithPasskeyGate();

    expect(unlock1.success && unlock2.success && unlock3.success).toBe(true);

    if (unlock1.success && unlock2.success && unlock3.success) {
      expect(unlock1.ms).toEqual(sharedMS);
      expect(unlock2.ms).toEqual(sharedMS);
      expect(unlock3.ms).toEqual(sharedMS);
    }
  });
});

// ============================================================================
// MKEK Derivation Tests
// ============================================================================

describe('deriveMKEKFromMS', () => {
  it('should derive non-extractable MKEK from MS', async () => {
    const ms = new Uint8Array(32);
    crypto.getRandomValues(ms);

    const mkek = await deriveMKEKFromMS(ms);

    // Check CryptoKey properties (no instanceof check for Node 18 compatibility)
    expect(mkek.type).toBe('secret');
    expect(mkek.algorithm.name).toBe('AES-GCM');
    expect((mkek.algorithm as AesKeyAlgorithm).length).toBe(256);
    expect(mkek.extractable).toBe(false);
    expect(mkek.usages).toContain('encrypt');
    expect(mkek.usages).toContain('decrypt');
  });

  it('should derive same MKEK for same MS', async () => {
    const ms = new Uint8Array(32);
    crypto.getRandomValues(ms);

    const mkek1 = await deriveMKEKFromMS(ms);
    const mkek2 = await deriveMKEKFromMS(ms);

    // Can't compare CryptoKey objects directly, but can test they encrypt/decrypt same
    const testData = new Uint8Array([1, 2, 3, 4]);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      mkek1,
      testData
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      mkek2,
      encrypted
    );

    expect(new Uint8Array(decrypted)).toEqual(testData);
  });

  it('should derive different MKEKs for different MSs', async () => {
    const ms1 = new Uint8Array(32);
    const ms2 = new Uint8Array(32);
    crypto.getRandomValues(ms1);
    crypto.getRandomValues(ms2);

    const mkek1 = await deriveMKEKFromMS(ms1);
    const mkek2 = await deriveMKEKFromMS(ms2);

    // Encrypt with mkek1, should fail to decrypt with mkek2
    const testData = new Uint8Array([1, 2, 3, 4]);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      mkek1,
      testData
    );

    await expect(
      crypto.subtle.decrypt({ name: 'AES-GCM', iv }, mkek2, encrypted)
    ).rejects.toThrow();
  });
});

// ============================================================================
// withUnlock Context Tests
// ============================================================================

describe('withUnlock', () => {
  it('should execute operation with MKEK (passphrase)', async () => {
    await setupPassphrase('passphrase');

    let operationCalled = false;
    let receivedMkek: CryptoKey | null = null;

    const result = await withUnlock(
      { method: 'passphrase', passphrase: 'passphrase' },
      async (mkek) => {
        operationCalled = true;
        receivedMkek = mkek;
        return 'success';
      }
    );

    expect(operationCalled).toBe(true);
    expect(receivedMkek).not.toBeNull();
    expect(receivedMkek!.algorithm.name).toBe('AES-GCM');
    expect(result.result).toBe('success');
  });

  it('should track timing information', async () => {
    await setupPassphrase('passphrase');

    const result = await withUnlock(
      { method: 'passphrase', passphrase: 'passphrase' },
      async () => {
        // Simulate some work
        await new Promise(resolve => setTimeout(resolve, 10));
        return 'done';
      }
    );

    expect(result.unlockTime).toBeGreaterThan(0);
    expect(result.lockTime).toBeGreaterThan(result.unlockTime);
    expect(result.duration).toBeGreaterThanOrEqual(10);
    expect(result.duration).toBe(result.lockTime - result.unlockTime);
  });

  it('should zeroize MS after operation', async () => {
    await setupPassphrase('passphrase');

    // We can't directly observe MS zeroization, but we can verify the operation completes
    const result = await withUnlock(
      { method: 'passphrase', passphrase: 'passphrase' },
      async (mkek) => {
        // Operation uses mkek
        const testData = new Uint8Array([1, 2, 3]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mkek, testData);
      }
    );

    expect(result.result).toBeInstanceOf(ArrayBuffer);
  });

  it('should work with passkey PRF credentials', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credentialId, prfOutput);

    const result = await withUnlock(
      { method: 'passkey-prf', prfOutput },
      async (mkek) => {
        expect(mkek.algorithm.name).toBe('AES-GCM');
        return 'prf-success';
      }
    );

    expect(result.result).toBe('prf-success');
  });

  it('should work with passkey gate credentials', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;
    await setupPasskeyGate(credentialId);

    const result = await withUnlock(
      { method: 'passkey-gate' },
      async (mkek) => {
        expect(mkek.algorithm.name).toBe('AES-GCM');
        return 'gate-success';
      }
    );

    expect(result.result).toBe('gate-success');
  });

  it('should propagate operation errors', async () => {
    await setupPassphrase('passphrase');

    await expect(
      withUnlock(
        { method: 'passphrase', passphrase: 'passphrase' },
        async () => {
          throw new Error('Operation failed');
        }
      )
    ).rejects.toThrow('Operation failed');
  });

  it('should fail with incorrect credentials', async () => {
    await setupPassphrase('correct');

    await expect(
      withUnlock(
        { method: 'passphrase', passphrase: 'wrong' },
        async () => 'should not reach here'
      )
    ).rejects.toThrow();
  });
});

// ============================================================================
// Helper Function Tests
// ============================================================================

describe('isSetup', () => {
  it('should return false when no enrollment exists', async () => {
    expect(await isSetup()).toBe(false);
  });

  it('should return true when passphrase is set up', async () => {
    await setupPassphrase('passphrase');
    expect(await isSetup()).toBe(true);
  });

  it('should return true when passkey PRF is set up', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credentialId, prfOutput);

    expect(await isSetup()).toBe(true);
  });

  it('should return true when passkey gate is set up', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;
    await setupPasskeyGate(credentialId);

    expect(await isSetup()).toBe(true);
  });

  it('should return true when multiple methods are set up', async () => {
    const sharedMS = new Uint8Array(32);
    crypto.getRandomValues(sharedMS);

    await setupPassphrase('passphrase', sharedMS);

    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credentialId, prfOutput, sharedMS);

    expect(await isSetup()).toBe(true);
  });
});

describe('isPassphraseSetup', () => {
  it('should return false when not set up', async () => {
    expect(await isPassphraseSetup()).toBe(false);
  });

  it('should return true when passphrase is set up', async () => {
    await setupPassphrase('passphrase');
    expect(await isPassphraseSetup()).toBe(true);
  });

  it('should return false when only passkey is set up', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credentialId, prfOutput);

    expect(await isPassphraseSetup()).toBe(false);
  });
});

describe('isPasskeySetup', () => {
  it('should return false when not set up', async () => {
    expect(await isPasskeySetup()).toBe(false);
  });

  it('should return true when passkey PRF is set up', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credentialId, prfOutput);

    expect(await isPasskeySetup()).toBe(true);
  });

  it('should return true when passkey gate is set up', async () => {
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;
    await setupPasskeyGate(credentialId);

    expect(await isPasskeySetup()).toBe(true);
  });

  it('should return false when only passphrase is set up', async () => {
    await setupPassphrase('passphrase');
    expect(await isPasskeySetup()).toBe(false);
  });

  it('should return true when both PRF and gate are set up', async () => {
    const sharedMS = new Uint8Array(32);
    crypto.getRandomValues(sharedMS);

    const credId1 = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await setupPasskeyPRF(credId1, prfOutput, sharedMS);

    const credId2 = new Uint8Array([5, 6, 7, 8]).buffer;
    await setupPasskeyGate(credId2, sharedMS);

    expect(await isPasskeySetup()).toBe(true);
  });
});
