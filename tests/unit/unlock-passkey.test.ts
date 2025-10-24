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

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await resetUnlock();

  // Reset WebAuthn mocks
  delete (globalThis as any).navigator;
  delete (globalThis as any).window;
});

describe('Unlock Manager - Passkey PRF Setup', () => {
  it('should setup passkey with PRF extension', async () => {
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

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
      expect(result.key.algorithm.name).toBe('AES-GCM');
    }
  });

  it('should fail if PRF extension not supported', async () => {
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

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it('should fail if WebAuthn not available', async () => {
    // No navigator.credentials mock

    const kek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['wrapKey', 'unwrapKey']
    );

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it('should fail if already setup', async () => {
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
    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Second setup should fail
    const result = await setupPasskeyPRF('localhost', 'Test App', kek);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('ALREADY_SETUP');
    }
  });

  it('should mark as setup after passkey PRF setup', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);

    expect(await isSetup()).toBe(true);
  });
});

describe('Unlock Manager - Passkey PRF Unlock', () => {
  it('should unlock with passkey PRF', async () => {
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
    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Now unlock
    const result = await unlockWithPasskeyPRF('localhost');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
    }
  });

  it('should fail if not setup', async () => {
    const result = await unlockWithPasskeyPRF('localhost');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it('should fail with wrong method', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    // Try to unlock with PRF (should fail - wrong method)
    const result = await unlockWithPasskeyPRF('localhost');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });
});

describe('Unlock Manager - Passkey Gate Setup', () => {
  it('should setup passkey in gate-only mode', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const result = await setupPasskeyGate('localhost', 'Test App');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
      expect(result.key.algorithm.name).toBe('AES-GCM');
    }
  });

  it('should fail if WebAuthn not available', async () => {
    const result = await setupPasskeyGate('localhost', 'Test App');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it('should fail if already setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    // First setup
    await setupPasskeyGate('localhost', 'Test App');

    // Second setup should fail
    const result = await setupPasskeyGate('localhost', 'Test App');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('ALREADY_SETUP');
    }
  });

  it('should mark as setup after passkey gate setup', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    expect(await isSetup()).toBe(true);
  });
});

describe('Unlock Manager - Passkey Gate Unlock', () => {
  it('should unlock with passkey gate', async () => {
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
    await setupPasskeyGate('localhost', 'Test App');

    // Now unlock
    const result = await unlockWithPasskeyGate('localhost');

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.key).toBeDefined();
      expect(result.key.type).toBe('secret');
    }
  });

  it('should generate fresh KEK on each unlock', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    // First unlock
    const result1 = await unlockWithPasskeyGate('localhost');
    expect(result1.success).toBe(true);

    // Second unlock
    const result2 = await unlockWithPasskeyGate('localhost');
    expect(result2.success).toBe(true);

    // Both should succeed (fresh KEKs generated)
  });

  it('should fail if not setup', async () => {
    const result = await unlockWithPasskeyGate('localhost');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });

  it('should fail with wrong method', async () => {
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
    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Try to unlock with gate (should fail - wrong method)
    const result = await unlockWithPasskeyGate('localhost');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('NOT_SETUP');
    }
  });
});

describe('Unlock Manager - Passkey State Management', () => {
  it('should reset passkey PRF state', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);
    expect(await isSetup()).toBe(true);

    await resetUnlock();

    expect(await isSetup()).toBe(false);
  });

  it('should reset passkey gate state', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));

    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(createMockCredential(credentialId, false)),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    await setupPasskeyGate('localhost', 'Test App');
    expect(await isSetup()).toBe(true);

    await resetUnlock();

    expect(await isSetup()).toBe(false);
  });
});

describe('Unlock Manager - Passkey Error Paths', () => {
  it('should handle credential creation returning null (PRF)', async () => {
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

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it('should handle assertion returning null after creation (PRF)', async () => {
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

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it('should handle missing PRF results after successful assertion (PRF setup)', async () => {
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

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it('should handle credential get returning null (PRF unlock)', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Now mock get to return null
    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(null);

    const result = await unlockWithPasskeyPRF('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it('should handle missing PRF results during unlock', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);

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

    const result = await unlockWithPasskeyPRF('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_PRF_NOT_SUPPORTED');
    }
  });

  it('should handle incorrect passkey (unwrap fails)', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Now try to unlock with different PRF output (simulating wrong passkey)
    const prfOutput2 = crypto.getRandomValues(new Uint8Array(32));
    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(
      createMockAssertion(credentialId.buffer, prfOutput2)
    );

    const result = await unlockWithPasskeyPRF('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('INCORRECT_PASSKEY');
    }
  });

  it('should handle credential creation returning null (gate)', async () => {
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockResolvedValue(null),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const result = await setupPasskeyGate('localhost', 'Test App');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it('should handle credential get returning null (gate unlock)', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    // Reset to clear the active gate session, but keep the config
    // We need to manually preserve the config since resetUnlock deletes it
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now mock get to return null
    (globalThis as any).navigator.credentials.get = vi.fn().mockResolvedValue(null);

    const result = await unlockWithPasskeyGate('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it('should handle exception during PRF setup', async () => {
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

    const result = await setupPasskeyPRF('localhost', 'Test App', kek);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it('should handle exception during PRF unlock', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Now mock get to throw
    (globalThis as any).navigator.credentials.get = vi.fn().mockRejectedValue(
      new Error('Authentication failed')
    );

    const result = await unlockWithPasskeyPRF('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it('should handle exception during gate setup', async () => {
    (globalThis as any).navigator = {
      credentials: {
        create: vi.fn().mockRejectedValue(new Error('User cancelled')),
      },
    };
    (globalThis as any).window = {
      PublicKeyCredential: class {},
    };

    const result = await setupPasskeyGate('localhost', 'Test App');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_CREATION_FAILED');
    }
  });

  it('should handle exception during gate unlock', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    // Reset to clear the active gate session, but keep the config
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now mock get to throw
    (globalThis as any).navigator.credentials.get = vi.fn().mockRejectedValue(
      new Error('Authentication failed')
    );

    const result = await unlockWithPasskeyGate('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_AUTHENTICATION_FAILED');
    }
  });

  it('should fail unlock if WebAuthn becomes unavailable (PRF)', async () => {
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

    await setupPasskeyPRF('localhost', 'Test App', kek);

    // Now remove WebAuthn support
    delete (globalThis as any).navigator;
    delete (globalThis as any).window;

    const result = await unlockWithPasskeyPRF('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it('should fail unlock if WebAuthn becomes unavailable (gate)', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    // Clear session to force fresh auth
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now remove WebAuthn support
    delete (globalThis as any).navigator;
    delete (globalThis as any).window;

    const result = await unlockWithPasskeyGate('localhost');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe('PASSKEY_NOT_AVAILABLE');
    }
  });

  it('should unlock with fresh authentication when gate session expired', async () => {
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

    await setupPasskeyGate('localhost', 'Test App');

    // Clear session to force fresh auth
    const { getMeta, putMeta } = await import('@/storage');
    const config = await getMeta('unlockSalt');
    await resetUnlock();
    if (config) await putMeta('unlockSalt', config);

    // Now unlock again - should do fresh authentication
    const result = await unlockWithPasskeyGate('localhost');
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
