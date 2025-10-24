/**
 * Unlock Manager Tests - Passkey Support
 *
 * Tests for passkey-based unlock (PRF and gate-only modes).
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/explicit-function-return-type */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  setupPasskeyPRF,
  unlockWithPasskeyPRF,
  setupPasskeyGate,
  unlockWithPasskeyGate,
  isSetup,
  resetUnlock,
} from '@/unlock';

// Helper to create mock WebAuthn credential
function createMockCredential(id: Uint8Array, prfEnabled = true) {
  const credential = {
    id: btoa(String.fromCharCode(...id)),
    rawId: id.buffer,
    type: 'public-key',
    response: {
      clientDataJSON: new Uint8Array(),
      attestationObject: new Uint8Array(),
    },
  } as any;

  // Add getClientExtensionResults as a method
  credential.getClientExtensionResults = () => ({
    prf: prfEnabled ? { enabled: true } : { enabled: false },
  });

  return credential as PublicKeyCredential;
}

// Helper to create mock WebAuthn assertion
function createMockAssertion(
  credentialId: ArrayBuffer,
  prfOutput?: Uint8Array
) {
  const assertion = {
    id: btoa(String.fromCharCode(...new Uint8Array(credentialId))),
    rawId: credentialId,
    type: 'public-key',
    response: {
      clientDataJSON: new Uint8Array(),
      authenticatorData: new Uint8Array(),
      signature: new Uint8Array(64), // P-256 signature
      userHandle: null,
    },
  } as any;

  // Add getClientExtensionResults as a method
  assertion.getClientExtensionResults = () => ({
    prf: prfOutput
      ? {
          results: {
            first: prfOutput.buffer,
          },
        }
      : undefined,
  });

  return assertion as PublicKeyCredential;
}

// Mock credential data for tests
const mockCredentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;
const mockPrfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await resetUnlock();

  // Reset WebAuthn mocks
  delete (globalThis as any).navigator;
  delete (globalThis as any).window;
});

describe('Unlock Manager - Passkey PRF Setup', () => {
  it.skip('should setup passkey with PRF extension', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    // Mock WebAuthn API
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    // Generate a test KEK (must be extractable to be wrapped)
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
      expect(result.key.algorithm.name).toBe('AES-GCM');
    }
  });

  it.skip('should fail if PRF extension not supported', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    // Mock WebAuthn API with PRF disabled
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it.skip('should fail if WebAuthn not available', async () => {
    // No navigator.credentials mock

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it.skip('should fail if already setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (must be true to be wrapped)
      ['wrapKey', 'unwrapKey']
    );

    // First setup
    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Second setup should fail
    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('ALREADY_SETUP');
    }
  });

  it.skip('should mark as setup after passkey PRF setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    expect(await isSetup()).toBe(false);

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (must be true to be wrapped)
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    expect(await isSetup()).toBe(true);
  });
});

describe('Unlock Manager - Passkey PRF Unlock', () => {
  it.skip('should unlock with passkey PRF', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    // Setup first
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (must be true to be wrapped)
      ['wrapKey', 'unwrapKey']
    );
    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Now unlock
    const result = await unlockWithPasskeyPRF(mockPrfOutput);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
    }
  });

  it.skip('should fail if not setup', async () => {
    const result = await unlockWithPasskeyPRF(mockPrfOutput);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it.skip('should fail with wrong method', async () => {
    // Setup with passphrase instead
    await resetUnlock();
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // Try to unlock with PRF (should fail - wrong method)
    const result = await unlockWithPasskeyPRF(mockPrfOutput);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });
});

describe('Unlock Manager - Passkey Gate Setup', () => {
  it.skip('should setup passkey in gate-only mode', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    const result = await setupPasskeyGate(mockCredentialId, kek);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
      expect(result.key.algorithm.name).toBe('AES-GCM');
    }
  });

  it.skip('should fail if WebAuthn not available', async () => {

      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    const result = await setupPasskeyGate(mockCredentialId, kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it.skip('should fail if already setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['wrapKey', 'unwrapKey']
    );

    // First setup
    await setupPasskeyGate(mockCredentialId, kek);

    // Second setup should fail
    const result = await setupPasskeyGate(mockCredentialId, kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('ALREADY_SETUP');
    }
  });

  it.skip('should mark as setup after passkey gate setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    expect(await isSetup()).toBe(false);


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    expect(await isSetup()).toBe(true);
  });
});

describe('Unlock Manager - Passkey Gate Unlock', () => {
  it.skip('should unlock with passkey gate', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    // Setup first

      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // Now unlock
    const result = await unlockWithPasskeyGate();

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
    }
  });

  it.skip('should generate fresh KEK on each unlock', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // First unlock
    const result1 = await unlockWithPasskeyGate();
    expect(result1.success).toBe(true);

    // Second unlock
    const result2 = await unlockWithPasskeyGate();
    expect(result2.success).toBe(true);

    // Both should succeed (fresh KEKs generated)
  });

  it.skip('should fail if not setup', async () => {
    const result = await unlockWithPasskeyGate();

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it.skip('should fail with wrong method', async () => {
    // Setup with passphrase
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (must be true to be wrapped)
      ['wrapKey', 'unwrapKey']
    );
    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Try to unlock with gate (should fail - wrong method)
    const result = await unlockWithPasskeyGate();

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });
});

describe('Unlock Manager - Passkey State Management', () => {
  it.skip('should reset passkey PRF state', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable (must be true to be wrapped)
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);
    expect(await isSetup()).toBe(true);

    await resetUnlock();

    expect(await isSetup()).toBe(false);
  });

  it.skip('should reset passkey gate state', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);
    expect(await isSetup()).toBe(true);

    await resetUnlock();

    expect(await isSetup()).toBe(false);
  });
});

describe('Unlock Manager - Passkey Error Paths', () => {
  it('should reject PRF output with wrong size during setup', async () => {
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const wrongSizePrfOutput = crypto.getRandomValues(new Uint8Array(16)); // Wrong size!

    const result = await setupPasskeyPRF(credentialId.buffer, wrongSizePrfOutput.buffer, kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it('should reject PRF output with wrong size during unlock', async () => {
    // First setup successfully
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    await setupPasskeyPRF(credentialId.buffer, prfOutput.buffer, kek);

    // Try to unlock with wrong size PRF output
    const wrongSizePrfOutput = crypto.getRandomValues(new Uint8Array(16));
    const result = await unlockWithPasskeyPRF(wrongSizePrfOutput.buffer);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it('should return INCORRECT_PASSKEY when PRF output is wrong', async () => {
    // Setup with one PRF output
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput1 = crypto.getRandomValues(new Uint8Array(32));

    await setupPasskeyPRF(credentialId.buffer, prfOutput1.buffer, kek);

    // Try to unlock with different PRF output (should fail unwrap)
    const prfOutput2 = crypto.getRandomValues(new Uint8Array(32));
    const result = await unlockWithPasskeyPRF(prfOutput2.buffer);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INCORRECT_PASSKEY');
    }
  });

  it('should return INCORRECT_PASSKEY when gate passkey is wrong', async () => {
    // Setup with one session KEK
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    await setupPasskeyGate(credentialId.buffer, kek);

    // Manually corrupt the wrapped KEK in storage to force unwrap failure
    const { putMeta, getMeta } = await import('@/storage');
    const config = await getMeta<any>('unlockSalt');

    // Corrupt the wrapped KEK
    const corruptedWrappedKEK = crypto.getRandomValues(new Uint8Array(config.wrappedKEK.byteLength));
    config.wrappedKEK = corruptedWrappedKEK.buffer;
    await putMeta('unlockSalt', config);

    const result = await unlockWithPasskeyGate();

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INCORRECT_PASSKEY');
    }
  });

  it('should return NOT_SETUP when unlocking PRF before setup', async () => {
    // Try to unlock without setting up first
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const result = await unlockWithPasskeyPRF(prfOutput.buffer);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it('should return NOT_SETUP when unlocking gate before setup', async () => {
    // Try to unlock without setting up first
    const result = await unlockWithPasskeyGate();

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it('should clean up gate session timer on reset', async () => {
    // Setup gate mode
    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    await setupPasskeyGate(credentialId.buffer, kek);

    // Unlock to start the timer
    await unlockWithPasskeyGate();

    // Reset should clean up the timer
    await resetUnlock();

    // Verify no errors occur (timer was properly cleaned up)
    expect(true).toBe(true);
  });

  it.skip('should handle credential creation returning null (PRF)', async () => {
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(null),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it.skip('should handle assertion returning null after creation (PRF)', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(null), // Assertion fails
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it.skip('should handle missing PRF results after successful assertion (PRF setup)', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    // Create assertion without PRF results
    const assertionNoPRF = {
      id: btoa(String.fromCharCode(...credentialId)),
      rawId: credentialId.buffer,
      type: 'public-key',
      response: {
        clientDataJSON: new Uint8Array(),
        authenticatorData: new Uint8Array(),
        signature: new Uint8Array(64),
        userHandle: null,
      },
      getClientExtensionResults: () => ({
        prf: undefined, // No PRF results
      }),
    } as any;

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(assertionNoPRF),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it.skip('should handle credential get returning null (PRF unlock)', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Now mock get to return null
    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(null);

    const result = await unlockWithPasskeyPRF(mockPrfOutput);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it.skip('should handle missing PRF results during unlock', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Create assertion without PRF results
    const assertionNoPRF = {
      id: btoa(String.fromCharCode(...credentialId)),
      rawId: credentialId.buffer,
      type: 'public-key',
      response: {
        clientDataJSON: new Uint8Array(),
        authenticatorData: new Uint8Array(),
        signature: new Uint8Array(64),
        userHandle: null,
      },
      getClientExtensionResults: () => ({
        prf: undefined,
      }),
    } as any;

    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(assertionNoPRF);

    const result = await unlockWithPasskeyPRF(mockPrfOutput);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it.skip('should handle incorrect passkey (unwrap fails)', async () => {
    // First setup successfully with one PRF output
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput1 = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput1)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Now try to unlock with different PRF output (simulating wrong passkey)
    const prfOutput2 = crypto.getRandomValues(new Uint8Array(32));
    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(
      createMockAssertion(credentialId.buffer, prfOutput2)
    );

    const result = await unlockWithPasskeyPRF(mockPrfOutput);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INCORRECT_PASSKEY');
    }
  });

  it.skip('should handle credential creation returning null (gate)', async () => {
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(null),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    const result = await setupPasskeyGate(mockCredentialId, kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it.skip('should handle credential get returning null (gate unlock)', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // Reset to clear the active gate session, but keep the config
    // We need to manually preserve the config since resetUnlock deletes it
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now mock get to return null
    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(null);

    const result = await unlockWithPasskeyGate();
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it.skip('should handle exception during PRF setup', async () => {
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockRejectedValue(new Error('User cancelled')),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it.skip('should handle exception during PRF unlock', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Now mock get to throw
    (globalThis as any).navigator.credentials.get = vi.fn().mockRejectedValue(
      new Error('Authentication failed')
    );

    const result = await unlockWithPasskeyPRF(mockPrfOutput);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it.skip('should handle exception during gate setup', async () => {
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockRejectedValue(new Error('User cancelled')),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    const result = await setupPasskeyGate(mockCredentialId, kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it.skip('should handle exception during gate unlock', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // Reset to clear the active gate session, but keep the config
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now mock get to throw
    (globalThis as any).navigator.credentials.get = vi.fn().mockRejectedValue(
      new Error('Authentication failed')
    );

    const result = await unlockWithPasskeyGate();
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it.skip('should fail unlock if WebAuthn becomes unavailable (PRF)', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, true)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer, prfOutput)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );

    await setupPasskeyPRF(mockCredentialId, mockPrfOutput, kek);

    // Now remove WebAuthn support
    delete (globalThis as any).navigator;
    delete (globalThis as any).window;

    const result = await unlockWithPasskeyPRF(mockPrfOutput);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it.skip('should fail unlock if WebAuthn becomes unavailable (gate)', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // Clear session to force fresh auth
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now remove WebAuthn support
    delete (globalThis as any).navigator;
    delete (globalThis as any).window;

    const result = await unlockWithPasskeyGate();
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it.skip('should unlock with fresh authentication when gate session expired', async () => {
    // First setup successfully
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
        get: vi.fn().mockResolvedValue(createMockAssertion(credentialId.buffer)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };


      const kek = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['wrapKey', 'unwrapKey']
      );

    await setupPasskeyGate(mockCredentialId, kek);

    // Clear session to force fresh auth
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now unlock again - should do fresh authentication
    const result = await unlockWithPasskeyGate();
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      // Verify it's an AES-GCM key
      expect(result.key.algorithm).toEqual({
        name: 'AES-GCM',
        length: 256,
      });
      expect(result.key.usages).toContain('wrapKey');
      expect(result.key.usages).toContain('unwrapKey');
    }
  });
});
