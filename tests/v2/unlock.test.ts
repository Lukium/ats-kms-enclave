/**
 * @file unlock.test.ts
 * @description Tests for unlock.ts error paths and edge cases
 * Focuses on uncovered branches to improve coverage
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  setupPassphrase,
  setupPasskeyPRF,
  setupPasskeyGate,
  unlockWithPassphrase,
  unlockWithPasskeyPRF,
  unlockWithPasskeyGate,
  withUnlock,
} from '@/v2/unlock';
import { initDB } from '@/v2/storage';
import type { AuthCredentials } from '@/v2/types';

// Setup fake IndexedDB before each test
beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
});

describe('unlock.ts error paths', () => {

  describe('unlockWithPasskeyPRF', () => {
    it('should return error when passkey PRF not set up', async () => {
      // Branch #11: !config check (line 298)
      const result = await unlockWithPasskeyPRF('user-not-setup', new ArrayBuffer(32));
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe('Passkey not set up');
      }
    });

    it('should return error when decryption fails with wrong PRF output', async () => {
      // Branch #12: catch block for decryption failure (line 316)
      const prfOutput1 = crypto.getRandomValues(new Uint8Array(32)).buffer;
      const prfOutput2 = crypto.getRandomValues(new Uint8Array(32)).buffer;
      const credentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;

      // Setup with first PRF output
      await setupPasskeyPRF('user-prf-test', credentialId, prfOutput1);

      // Try to unlock with different PRF output (wrong key)
      const result = await unlockWithPasskeyPRF('user-prf-test', prfOutput2);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe('Decryption failed');
      }
    });
  });

  describe('unlockWithPassphrase', () => {
    it('should return error when decryption fails with wrong passphrase', async () => {
      // Branch #10: catch block for decryption failure (line 286)
      await setupPassphrase('user-pass-test', 'correct-password');

      // Try to unlock with wrong passphrase
      const result = await unlockWithPassphrase('user-pass-test', 'wrong-password');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe('Invalid passphrase');
      }
    });
  });

  describe('withUnlock', () => {
    it('should throw error for unknown credential method', async () => {
      // Branch #13: default case in switch (line 436)
      const invalidCredentials = {
        method: 'invalid-method',
        userId: 'test-user',
      } as unknown as AuthCredentials;

      await expect(
        withUnlock(invalidCredentials, async () => {
          return 'should not reach here';
        })
      ).rejects.toThrow('Unknown credential method');
    });

    it('should throw error when unlock fails (wrong passphrase)', async () => {
      // Branch #14: !unlockResult.success check (line 438-439)
      await setupPassphrase('user-unlock-fail', 'correct-password');

      const wrongCredentials: AuthCredentials = {
        method: 'passphrase',
        userId: 'user-unlock-fail',
        passphrase: 'wrong-password',
      };

      await expect(
        withUnlock(wrongCredentials, async () => {
          return 'should not reach here';
        })
      ).rejects.toThrow('Invalid passphrase');
    });

    it('should successfully unlock with passkey-gate method', async () => {
      // Branch #15: case 'passkey-gate' in switch (line 432-433)
      const credentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;
      await setupPasskeyGate('user-gate-test', credentialId);

      const credentials: AuthCredentials = {
        method: 'passkey-gate',
        userId: 'user-gate-test',
      };

      const result = await withUnlock(credentials, async (mkek, ms) => {
        // Verify we got valid MKEK and MS
        expect(mkek).toBeDefined();
        expect(mkek).toBeInstanceOf(CryptoKey);
        expect(ms).toBeInstanceOf(Uint8Array);
        expect(ms.byteLength).toBe(32);
        return 'success';
      });

      expect(result.result).toBe('success');
      expect(result.unlockTime).toBeDefined();
      expect(result.lockTime).toBeDefined();
      expect(result.duration).toBeGreaterThanOrEqual(0);
    });

    it('should zeroize MS even when operation throws error', async () => {
      // Verify finally block always runs
      await setupPassphrase('user-cleanup-test', 'test-password');

      const credentials: AuthCredentials = {
        method: 'passphrase',
        userId: 'user-cleanup-test',
        passphrase: 'test-password',
      };

      let capturedMS: Uint8Array | null = null;

      await expect(
        withUnlock(credentials, async (_mkek, ms) => {
          // Capture MS reference
          capturedMS = ms;
          // Verify MS is not yet zeroized
          expect(ms.some((byte) => byte !== 0)).toBe(true);
          // Throw error to test cleanup
          throw new Error('Intentional error');
        })
      ).rejects.toThrow('Intentional error');

      // Verify MS was zeroized despite error
      expect(capturedMS).not.toBeNull();
      expect(capturedMS!.every((byte: number) => byte === 0)).toBe(true);
    });
  });

  describe('unlockWithPasskeyGate', () => {
    it('should successfully unlock with passkey gate', async () => {
      const credentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;
      await setupPasskeyGate('user-gate-unlock', credentialId);

      const result = await unlockWithPasskeyGate('user-gate-unlock');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.ms).toBeInstanceOf(Uint8Array);
        expect(result.ms.byteLength).toBe(32);
      }
    });

    it('should return error when passkey gate not set up', async () => {
      const result = await unlockWithPasskeyGate('user-no-gate');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBe('Passkey gate not set up');
      }
    });
  });

  describe('integration: multiple unlock methods', () => {
    it('should allow multiple enrollment methods for same user', async () => {
      const userId = 'multi-method-user';

      // Setup all three methods independently
      await setupPassphrase(userId, 'test-pass');

      const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
      const credId1 = crypto.getRandomValues(new Uint8Array(16)).buffer;
      await setupPasskeyPRF(userId, credId1, prfOutput);

      const credId2 = crypto.getRandomValues(new Uint8Array(16)).buffer;
      await setupPasskeyGate(userId, credId2);

      // Verify all three methods can unlock successfully (with their own MS)
      const result1 = await unlockWithPassphrase(userId, 'test-pass');
      expect(result1.success).toBe(true);
      if (result1.success) {
        expect(result1.ms).toBeInstanceOf(Uint8Array);
        expect(result1.ms.byteLength).toBe(32);
      }

      const result2 = await unlockWithPasskeyPRF(userId, prfOutput);
      expect(result2.success).toBe(true);
      if (result2.success) {
        expect(result2.ms).toBeInstanceOf(Uint8Array);
        expect(result2.ms.byteLength).toBe(32);
      }

      const result3 = await unlockWithPasskeyGate(userId);
      expect(result3.success).toBe(true);
      if (result3.success) {
        expect(result3.ms).toBeInstanceOf(Uint8Array);
        expect(result3.ms.byteLength).toBe(32);
      }
    });
  });
});
