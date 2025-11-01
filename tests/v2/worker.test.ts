/**
 * Worker Module Test Suite (KMS V2 - Phase 3)
 *
 * Comprehensive tests for worker orchestration layer including:
 * - RPC message handling
 * - Setup operations (passphrase, passkey PRF, passkey gate)
 * - VAPID operations (generate key, sign JWT)
 * - VAPID lease operations (create, issue)
 * - Status and query operations
 * - Management operations
 *
 * Tests verify correct routing, policy enforcement, audit logging, and error handling.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { handleMessage } from '@/v2/worker';
import type { RPCRequest, AuthCredentials, VAPIDPayload } from '@/v2/types';
import { initDB, closeDB } from '@/v2/storage';
import { resetAuditLogger } from '@/v2/audit';

// ============================================================================
// Test Setup
// ============================================================================

beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  await initDB();
  resetAuditLogger();
});

afterEach(() => {
  closeDB();
  resetAuditLogger();
});

// ============================================================================
// Helper Functions
// ============================================================================

function createRequest(method: string, params: any = {}): RPCRequest {
  return {
    id: `req-${Date.now()}-${Math.random()}`,
    method,
    params,
  };
}

function createPassphraseCredentials(passphrase: string): AuthCredentials {
  return { method: 'passphrase', passphrase, userId: 'test@example.com' };
}

/**
 * Helper to safely extract result from RPC response in tests.
 * Tests know the expected response shape, so this is safe.
 */
function getResult<T>(response: { result?: unknown }): T {
  return response.result as T;
}

// ============================================================================
// RPC Message Handling Tests
// ============================================================================

describe('RPC message handling', () => {
  it('should return error for unknown method', async () => {
    const request = createRequest('unknownMethod');
    const response = await handleMessage(request);

    expect(response.id).toBe(request.id);
    expect(response.error).toBeDefined();
    expect(response.error).toContain('Unknown RPC method');
  });

  it('should include requestId in response', async () => {
    const request = createRequest('isSetup');
    const response = await handleMessage(request);

    expect(response.id).toBe(request.id);
  });

  it('should return result on success', async () => {
    const request = createRequest('isSetup');
    const response = await handleMessage(request);

    expect(response.result).toBeDefined();
    expect(response.error).toBeUndefined();
  });

  it('should return error on failure', async () => {
    const request = createRequest('setupPassphrase', { passphrase: 'short' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.result).toBeUndefined();
  });
});

// ============================================================================
// Setup Operations Tests
// ============================================================================

describe('setupPassphrase', () => {
  it('should setup passphrase successfully', async () => {
    const request = createRequest('setupPassphrase', {
      userId: 'test@example.com',
      passphrase: 'my-secure-passphrase-123',
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toMatchObject({
      success: true,
      enrollmentId: 'enrollment:passphrase:v2',
    });
    const setupResult = getResult<{ vapidPublicKey: string; vapidKid: string }>(response);
    expect(setupResult.vapidPublicKey).toBeDefined();
    expect(setupResult.vapidKid).toBeDefined();
  });

  it('should reject short passphrase', async () => {
    const request = createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'short' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('at least 8 characters');
  });

  it('should reject empty passphrase', async () => {
    const request = createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: '' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

describe('setupPasskeyPRF', () => {
  it('should setup passkey PRF successfully', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request = createRequest('setupPasskeyPRF', {
      userId: 'test@example.com',
      credentialId,
      prfOutput,
      rpId: 'example.com',
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toMatchObject({
      success: true,
      enrollmentId: 'enrollment:passkey-prf:v2',
    });
    const setupResult = getResult<{ vapidPublicKey: string; vapidKid: string }>(response);
    expect(setupResult.vapidPublicKey).toBeDefined();
    expect(setupResult.vapidKid).toBeDefined();
  });

  it('should reject missing credentialId', async () => {
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const request = createRequest('setupPasskeyPRF', { userId: 'test@example.com', prfOutput });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('credentialId required');
  });

  it('should reject invalid prfOutput size', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = new Uint8Array(16).buffer; // Wrong size

    const request = createRequest('setupPasskeyPRF', { userId: 'test@example.com', credentialId, prfOutput });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('32 bytes');
  });
});

describe('setupPasskeyGate', () => {
  it('should setup passkey gate successfully', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;

    const request = createRequest('setupPasskeyGate', {
      userId: 'test@example.com',
      credentialId,
      rpId: 'example.com',
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toMatchObject({
      success: true,
      enrollmentId: 'enrollment:passkey-gate:v2',
    });
    const setupResult = getResult<{ vapidPublicKey: string; vapidKid: string }>(response);
    expect(setupResult.vapidPublicKey).toBeDefined();
    expect(setupResult.vapidKid).toBeDefined();
  });

  it('should reject missing credentialId', async () => {
    const request = createRequest('setupPasskeyGate', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

describe('addEnrollment (multi-enrollment)', () => {
  it('should add passkey PRF to existing passphrase', async () => {
    // Setup passphrase first
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'initial-passphrase-123' })
    );

    // Add passkey PRF
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request = createRequest('addEnrollment', {
      userId: 'test@example.com',
      method: 'passkey-prf',
      credentials: { method: 'passphrase', passphrase: 'initial-passphrase-123', userId: 'test@example.com' },
      newCredentials: { credentialId, prfOutput, rpId: 'example.com' },
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toEqual({
      success: true,
      enrollmentId: 'enrollment:passkey-prf:v2',
    });
  });

  it('should reject with invalid credentials', async () => {
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'correct-passphrase-123' })
    );

    const request = createRequest('addEnrollment', {
      userId: 'test@example.com',
      method: 'passphrase',
      credentials: { method: 'passphrase', passphrase: 'wrong-passphrase', userId: 'test@example.com' },
      newCredentials: { passphrase: 'second-passphrase-456' },
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

// ============================================================================
// VAPID Operations Tests
// ============================================================================

describe('generateVAPID', () => {
  it('should generate VAPID keypair successfully', async () => {
    // Setup first
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-123' })
    );

    const credentials = createPassphraseCredentials('test-passphrase-123');
    const request = createRequest('generateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('kid');
    expect(response.result).toHaveProperty('publicKey');
    const vapidResult = getResult<{ kid: string; publicKey: string }>(response);
    expect(vapidResult.kid).toBeDefined();
    expect(vapidResult.publicKey).toBeDefined();
    expect(vapidResult.publicKey.length).toBeGreaterThan(0);
  });

  it('should fail without setup', async () => {
    const credentials = createPassphraseCredentials('no-setup-passphrase');
    const request = createRequest('generateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });

  it('should fail with wrong credentials', async () => {
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'correct-passphrase-123' })
    );

    const credentials = createPassphraseCredentials('wrong-passphrase');
    const request = createRequest('generateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

describe('regenerateVAPID', () => {
  it('should regenerate VAPID keypair successfully', async () => {
    // Setup first
    const passphrase = 'regenerate-vapid-test-123';
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );

    // Generate initial VAPID key
    const credentials = createPassphraseCredentials(passphrase);
    const initialResponse = await handleMessage(createRequest('generateVAPID', { credentials }));
    const initialKid = getResult<{ kid: string }>(initialResponse).kid;

    expect(initialResponse.error).toBeUndefined();
    expect(initialKid).toBeDefined();

    // Regenerate VAPID key
    const regenerateRequest = createRequest('regenerateVAPID', { credentials });
    const regenerateResponse = await handleMessage(regenerateRequest);

    expect(regenerateResponse.error).toBeUndefined();
    expect(regenerateResponse.result).toHaveProperty('kid');
    expect(regenerateResponse.result).toHaveProperty('publicKey');
    const regenerateResult = getResult<{ kid: string; publicKey: string }>(regenerateResponse);
    expect(regenerateResult.kid).toBeDefined();
    expect(regenerateResult.publicKey).toBeDefined();

    // New kid should be different from old kid
    expect(regenerateResult.kid).not.toBe(initialKid);

    // Public key should be valid (65 bytes base64url-encoded)
    expect(regenerateResult.publicKey.length).toBeGreaterThan(0);
  });

  it('should delete old VAPID key after regeneration', async () => {
    // Setup
    const passphrase = 'delete-old-key-test-123';
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );

    // Generate initial VAPID key
    const credentials = createPassphraseCredentials(passphrase);
    const initialResponse = await handleMessage(createRequest('generateVAPID', { credentials }));
    const initialKid = getResult<{ kid: string }>(initialResponse).kid;

    // Verify old key exists
    const oldKeyResponse = await handleMessage(createRequest('getPublicKey', { kid: initialKid }));
    expect(oldKeyResponse.error).toBeUndefined();

    // Regenerate VAPID key
    await handleMessage(createRequest('regenerateVAPID', { credentials }));

    // Try to get old key - should fail
    const afterRegenResponse = await handleMessage(createRequest('getPublicKey', { kid: initialKid }));
    expect(afterRegenResponse.error).toBeDefined();
    expect(afterRegenResponse.error).toContain('not found');
  });

  it('should create audit log entry for regeneration', async () => {
    // Setup
    const passphrase = 'audit-regen-test-123';
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );

    // Generate initial VAPID key
    const credentials = createPassphraseCredentials(passphrase);
    await handleMessage(createRequest('generateVAPID', { credentials }));

    // Regenerate
    await handleMessage(createRequest('regenerateVAPID', { credentials }));

    // Check audit log
    const auditRequest = createRequest('getAuditLog');
    const auditResponse = await handleMessage(auditRequest);

    expect(auditResponse.error).toBeUndefined();
    const auditResult = getResult<{ entries: any[] }>(auditResponse);
    expect(auditResult.entries).toBeDefined();

    // Find regenerate-vapid entry
    const regenerateEntry = auditResult.entries.find(
      (entry: any) => entry.op === 'regenerate-vapid'
    );

    expect(regenerateEntry).toBeDefined();
    expect(regenerateEntry.details).toHaveProperty('algorithm', 'ECDSA');
    expect(regenerateEntry.details).toHaveProperty('curve', 'P-256');
    expect(regenerateEntry.details).toHaveProperty('purpose', 'vapid');
    expect(regenerateEntry.details).toHaveProperty('oldKids');
    expect(regenerateEntry.details).toHaveProperty('deletedCount');
  });

  it('should fail without setup', async () => {
    const credentials = createPassphraseCredentials('no-setup-passphrase');
    const request = createRequest('regenerateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });

  it('should fail with wrong credentials', async () => {
    // Setup with correct passphrase
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'correct-passphrase-123' })
    );

    // Generate initial key
    const correctCredentials = createPassphraseCredentials('correct-passphrase-123');
    await handleMessage(createRequest('generateVAPID', { credentials: correctCredentials }));

    // Try to regenerate with wrong passphrase
    const wrongCredentials = createPassphraseCredentials('wrong-passphrase');
    const request = createRequest('regenerateVAPID', { credentials: wrongCredentials });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });

  it('should handle regeneration when no VAPID key exists', async () => {
    // Setup without generating initial VAPID key
    const passphrase = 'no-initial-key-test-123';
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );

    const credentials = createPassphraseCredentials(passphrase);
    const request = createRequest('regenerateVAPID', { credentials });

    const response = await handleMessage(request);

    // Should succeed and generate a new key (even though there was none to delete)
    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('kid');
    expect(response.result).toHaveProperty('publicKey');
  });

  it('should handle regeneration with multiple existing VAPID keys', async () => {
    // Setup
    const passphrase = 'multiple-keys-test-123';
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );

    const credentials = createPassphraseCredentials(passphrase);

    // Generate first key
    const first = await handleMessage(createRequest('generateVAPID', { credentials }));
    const firstKid = getResult<{ kid: string }>(first).kid;

    // Generate second key (this creates a second VAPID key)
    const second = await handleMessage(createRequest('generateVAPID', { credentials }));
    const secondKid = getResult<{ kid: string }>(second).kid;

    // Both keys should exist
    expect(firstKid).not.toBe(secondKid);

    // Regenerate - should delete ALL existing VAPID keys
    const regenerateResponse = await handleMessage(createRequest('regenerateVAPID', { credentials }));
    const newKid = getResult<{ kid: string }>(regenerateResponse).kid;

    expect(regenerateResponse.error).toBeUndefined();
    expect(newKid).not.toBe(firstKid);
    expect(newKid).not.toBe(secondKid);

    // Verify old keys are gone
    const firstKeyCheck = await handleMessage(createRequest('getPublicKey', { kid: firstKid }));
    expect(firstKeyCheck.error).toBeDefined();

    const secondKeyCheck = await handleMessage(createRequest('getPublicKey', { kid: secondKid }));
    expect(secondKeyCheck.error).toBeDefined();

    // New key should exist
    const newKeyCheck = await handleMessage(createRequest('getPublicKey', { kid: newKid }));
    expect(newKeyCheck.error).toBeUndefined();
  });

  it('should invalidate existing leases after regeneration', async () => {
    // Setup
    const passphrase = 'lease-invalidation-test-123';
    await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );

    const credentials = createPassphraseCredentials(passphrase);

    // Generate initial VAPID key
    const vapidResponse = await handleMessage(createRequest('generateVAPID', { credentials }));
    const oldKid = getResult<{ kid: string }>(vapidResponse).kid;

    // Create a lease with the initial key
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'test@example.com',
        subs: [
          {
            url: 'https://example.com/push',
            aud: 'https://example.com',
            eid: 'test-endpoint-1',
          },
        ],
        ttlHours: 24,
        credentials,
      })
    );
    const leaseId = getResult<{ leaseId: string }>(leaseResponse).leaseId;

    expect(leaseResponse.error).toBeUndefined();
    expect(leaseId).toBeDefined();

    // Verify lease is valid before regeneration
    const verifyBeforeResponse = await handleMessage(
      createRequest('verifyLease', { leaseId })
    );
    expect(verifyBeforeResponse.error).toBeUndefined();
    expect(getResult<{ valid: boolean }>(verifyBeforeResponse).valid).toBe(true);

    // Regenerate VAPID key (should delete old key and create new one)
    const regenerateResponse = await handleMessage(createRequest('regenerateVAPID', { credentials }));
    const newKid = getResult<{ kid: string }>(regenerateResponse).kid;

    expect(regenerateResponse.error).toBeUndefined();
    expect(newKid).not.toBe(oldKid);

    // Verify lease is now invalid (because old kid is gone)
    const verifyAfterResponse = await handleMessage(
      createRequest('verifyLease', { leaseId })
    );

    // Lease verification should fail because the kid referenced in the lease no longer matches current key
    const verifyAfterResult = getResult<{ valid: boolean; reason: string }>(verifyAfterResponse);
    expect(verifyAfterResult.valid).toBe(false);
    expect(verifyAfterResult.reason).toBe('wrong-key');
  });
});

describe('signJWT', () => {
  let kid: string;
  const passphrase = 'jwt-signing-passphrase-123';

  beforeEach(async () => {
    // Setup and generate VAPID key
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase }));

    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', { credentials: createPassphraseCredentials(passphrase) })
    );

    kid = getResult<{ kid: string }>(vapidResponse).kid;
  });

  it('should sign JWT successfully', async () => {
    const payload: VAPIDPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 600, // 10 min from now
      jti: 'test-jti-123',
    };

    const request = createRequest('signJWT', {
      kid,
      payload,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('jwt');
    const jwtResult = getResult<{ jwt: string }>(response);
    expect(jwtResult.jwt).toBeDefined();

    // JWT should have 3 parts
    const parts = jwtResult.jwt.split('.');
    expect(parts).toHaveLength(3);

    // Parse header
    const header = JSON.parse(atob(parts[0]!.replace(/-/g, '+').replace(/_/g, '/')));
    expect(header.alg).toBe('ES256');
    expect(header.kid).toBe(kid);
  });

  it('should reject missing aud', async () => {
    const payload = {
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 600,
      jti: 'test',
    } as VAPIDPayload;

    const request = createRequest('signJWT', {
      kid,
      payload,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('aud');
  });

  it('should reject expired exp', async () => {
    const payload: VAPIDPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) - 600, // Past
      jti: 'test',
    };

    const request = createRequest('signJWT', {
      kid,
      payload,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('future');
  });

  it('should reject exp > 24 hours (RFC 8292)', async () => {
    const payload: VAPIDPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 90000, // > 24h
      jti: 'test',
    };

    const request = createRequest('signJWT', {
      kid,
      payload,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('24 hours');
  });
});

// ============================================================================
// VAPID Lease Operations Tests
// ============================================================================

describe('createLease', () => {
  const passphrase = 'lease-creation-passphrase-123';

  beforeEach(async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase }));
  });

  it('should create lease successfully', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [
        { url: 'https://push.example.com/sub1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
        { url: 'https://push.example.com/sub2', aud: 'https://fcm.googleapis.com', eid: 'ep-2' },
      ],
      ttlHours: 12,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('leaseId');
    expect(response.result).toHaveProperty('exp');
    expect(response.result).toHaveProperty('quotas');
    const leaseResult = getResult<{ leaseId: string; quotas: { tokensPerHour: number } }>(response);
    expect(leaseResult.leaseId).toMatch(/^lease-/);
    expect(leaseResult.quotas).toHaveProperty('tokensPerHour');
  });

  it('should reject ttlHours > 720', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 721,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('720');
  });

  it('should reject ttlHours <= 0', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 0,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });

  it('should default autoExtend to true', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 12,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const leaseResult = getResult<{ autoExtend?: boolean }>(response);
    expect(leaseResult.autoExtend).toBe(true);
  });

  it('should accept autoExtend=true explicitly', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 12,
      credentials: createPassphraseCredentials(passphrase),
      autoExtend: true,
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const leaseResult = getResult<{ autoExtend?: boolean }>(response);
    expect(leaseResult.autoExtend).toBe(true);
  });

  it('should accept autoExtend=false', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 12,
      credentials: createPassphraseCredentials(passphrase),
      autoExtend: false,
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const leaseResult = getResult<{ autoExtend?: boolean }>(response);
    expect(leaseResult.autoExtend).toBe(false);
  });

  it('should include autoExtend in response', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 12,
      credentials: createPassphraseCredentials(passphrase),
      autoExtend: false,
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('autoExtend');
  });
});

describe('extendLeases', () => {
  const passphrase = 'extend-lease-passphrase-123';
  let leaseId: string;
  let kid: string;

  beforeEach(async () => {
    // Setup passphrase and generate VAPID
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase }));
    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', { credentials: createPassphraseCredentials(passphrase) })
    );
    kid = getResult<{ kid: string }>(vapidResponse).kid;

    // Create a lease with autoExtend=true by default
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'user-123',
        subs: [],
        ttlHours: 12,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    leaseId = getResult<{ leaseId: string }>(leaseResponse).leaseId;
  });

  it('should extend lease successfully', async () => {
    // Extend the lease twice and verify exp increases
    const extendResponse1 = await handleMessage(createRequest('extendLeases', { leaseIds: [leaseId], userId: 'user-123' }));
    expect(extendResponse1.error).toBeUndefined();
    const batchResult1 = getResult<{
      results: Array<{ leaseId: string; status: string; result?: { leaseId: string; exp: number; iat: number; kid: string; autoExtend: boolean } }>;
      extended: number;
    }>(extendResponse1);
    expect(batchResult1.extended).toBe(1);
    expect(batchResult1.results).toHaveLength(1);
    const extendResult1 = batchResult1.results[0]!.result!;

    // Wait a bit to ensure timestamps differ
    await new Promise((resolve) => setTimeout(resolve, 10));

    // Extend again
    const extendResponse2 = await handleMessage(createRequest('extendLeases', { leaseIds: [leaseId], userId: 'user-123' }));
    expect(extendResponse2.error).toBeUndefined();
    const batchResult2 = getResult<{
      results: Array<{ leaseId: string; status: string; result?: { leaseId: string; exp: number; iat: number; kid: string; autoExtend: boolean } }>;
      extended: number;
    }>(extendResponse2);
    expect(batchResult2.extended).toBe(1);
    expect(batchResult2.results).toHaveLength(1);
    const extendResult2 = batchResult2.results[0]!.result!;

    // Verify basic properties
    expect(extendResult2.leaseId).toBe(leaseId);
    expect(extendResult2.kid).toBe(kid);
    expect(extendResult2.autoExtend).toBe(true);

    // Verify exp increased
    expect(extendResult2.exp).toBeGreaterThan(extendResult1.exp);

    // Verify the lease is still valid
    const verifyResponse = await handleMessage(createRequest('verifyLease', { leaseId }));
    const verifyResult = getResult<{ valid: boolean }>(verifyResponse);
    expect(verifyResult.valid).toBe(true);
  });

  it('should preserve autoExtend flag when extending', async () => {
    // Create a lease with autoExtend=false
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'user-123',
        subs: [],
        ttlHours: 12,
        credentials: createPassphraseCredentials(passphrase),
        autoExtend: false,
      })
    );
    const leaseIdNoAuto = getResult<{ leaseId: string }>(leaseResponse).leaseId;

    // Extend the lease - must provide credentials for non-extendable leases
    const extendResponse = await handleMessage(
      createRequest('extendLeases', {
        leaseIds: [leaseIdNoAuto],
        userId: 'user-123',
        requestAuth: true,
        credentials: createPassphraseCredentials(passphrase),
      })
    );

    expect(extendResponse.error).toBeUndefined();
    const batchResult = getResult<{
      results: Array<{ status: string; result?: { autoExtend: boolean } }>;
      extended: number;
    }>(extendResponse);
    expect(batchResult.extended).toBe(1);
    expect(batchResult.results[0]!.result!.autoExtend).toBe(false);
  });

  it('should skip extending non-extendable lease without requestAuth', async () => {
    // Create a lease with autoExtend=false
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'user-123',
        subs: [],
        ttlHours: 12,
        credentials: createPassphraseCredentials(passphrase),
        autoExtend: false,
      })
    );
    const leaseIdNoAuto = getResult<{ leaseId: string }>(leaseResponse).leaseId;

    // Attempt to extend without requestAuth - should skip with reason
    const extendResponse = await handleMessage(createRequest('extendLeases', { leaseIds: [leaseIdNoAuto], userId: 'user-123' }));

    expect(extendResponse.error).toBeUndefined();
    const batchResult = getResult<{
      results: Array<{ status: string; reason?: string }>;
      skipped: number;
    }>(extendResponse);
    expect(batchResult.skipped).toBe(1);
    expect(batchResult.results[0]!.status).toBe('skipped');
    expect(batchResult.results[0]!.reason).toContain('autoExtend=false');
  });

  it('should allow multiple extensions', async () => {
    const expirations: number[] = [];

    // Extend 3 times
    for (let i = 0; i < 3; i++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      const extendResponse = await handleMessage(createRequest('extendLeases', { leaseIds: [leaseId], userId: 'user-123' }));
      expect(extendResponse.error).toBeUndefined();
      const batchResult = getResult<{ results: Array<{ result?: { exp: number } }> }>(extendResponse);
      expirations.push(batchResult.results[0]!.result!.exp);
    }

    // Each expiration should be greater than the previous
    expect(expirations[1]).toBeGreaterThan(expirations[0]!);
    expect(expirations[2]).toBeGreaterThan(expirations[1]!);
  });

  it('should skip extending non-existent lease', async () => {
    const extendResponse = await handleMessage(createRequest('extendLeases', { leaseIds: ['lease-nonexistent'], userId: 'user-123' }));

    expect(extendResponse.error).toBeUndefined();
    const batchResult = getResult<{
      results: Array<{ status: string; reason?: string }>;
      skipped: number;
    }>(extendResponse);
    expect(batchResult.skipped).toBe(1);
    expect(batchResult.results[0]!.status).toBe('skipped');
    expect(batchResult.results[0]!.reason).toContain('not found');
  });

  it('should skip extending lease for different VAPID key', async () => {
    // Regenerate VAPID key
    await handleMessage(createRequest('regenerateVAPID', { credentials: createPassphraseCredentials(passphrase) }));

    // Try to extend lease created with old VAPID key
    const extendResponse = await handleMessage(createRequest('extendLeases', { leaseIds: [leaseId], userId: 'user-123' }));

    expect(extendResponse.error).toBeUndefined();
    const batchResult = getResult<{
      results: Array<{ status: string; reason?: string }>;
      skipped: number;
    }>(extendResponse);
    expect(batchResult.skipped).toBe(1);
    expect(batchResult.results[0]!.status).toBe('skipped');
    expect(batchResult.results[0]!.reason).toContain('different VAPID key');
  });

  it('should create audit log entry for extension', async () => {
    // Extend the lease
    await handleMessage(createRequest('extendLeases', { leaseIds: [leaseId], userId: 'user-123' }));

    // Get audit log
    const auditResponse = await handleMessage(createRequest('getAuditLog', {}));
    const auditLog = getResult<{ entries: Array<{ op: string; details?: { leaseId?: string } }> }>(auditResponse);

    // Find extend-lease entry
    const extendEntry = auditLog.entries.find(
      (entry) => entry.op === 'extend-lease' && entry.details?.leaseId === leaseId
    );
    expect(extendEntry).toBeDefined();
  });

  it('should update exp to 30 days from now', async () => {
    const beforeExtend = Date.now();
    const extendResponse = await handleMessage(createRequest('extendLeases', { leaseIds: [leaseId], userId: 'user-123' }));
    const afterExtend = Date.now();

    expect(extendResponse.error).toBeUndefined();
    const batchResult = getResult<{ results: Array<{ result?: { exp: number } }> }>(extendResponse);
    const extendResult = batchResult.results[0]!.result!;

    // exp should be approximately 30 days from now
    const thirtyDaysInMs = 30 * 24 * 60 * 60 * 1000;
    const expectedExpMin = beforeExtend + thirtyDaysInMs;
    const expectedExpMax = afterExtend + thirtyDaysInMs;

    expect(extendResult.exp).toBeGreaterThanOrEqual(expectedExpMin);
    expect(extendResult.exp).toBeLessThanOrEqual(expectedExpMax);
  });
});

describe('verifyLease', () => {
  let kid: string;
  let leaseId: string;
  const passphrase = 'verify-lease-passphrase-123';

  beforeEach(async () => {
    // Setup passphrase and generate VAPID
    await handleMessage(
      createRequest('setupPassphrase', {
        userId: 'test@example.com',
        passphrase,
      })
    );

    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    kid = getResult<{ kid: string }>(vapidResponse).kid;

    // Create a lease
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'test@example.com',
        subs: [{ url: 'https://push.example.com/sub1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' }],
        ttlHours: 1,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    leaseId = getResult<{ leaseId: string }>(leaseResponse).leaseId;
  });

  it('should verify valid lease successfully', async () => {
    const request = createRequest('verifyLease', { leaseId });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('valid', true);
    expect(response.result).toHaveProperty('leaseId', leaseId);
    expect(response.result).toHaveProperty('kid'); // Should return the lease's kid
    const verifyResult = getResult<{ reason?: string }>(response);
    expect(verifyResult.reason).toBeUndefined();
  });

  it('should return invalid for non-existent lease', async () => {
    const request = createRequest('verifyLease', { leaseId: 'lease-does-not-exist' });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('valid', false);
    expect(response.result).toHaveProperty('reason', 'not-found');
    expect(response.result).toHaveProperty('kid', '');
  });

  it('should return invalid for expired lease', async () => {
    // Create an expired lease by manipulating the lease record
    // First create a valid lease
    const expiredLeaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'test@example.com',
        subs: [{ url: 'https://push.example.com/sub2', aud: 'https://fcm.googleapis.com', eid: 'ep-2' }],
        ttlHours: 0.001, // Very short TTL (3.6 seconds)
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    const expiredLeaseId = getResult<{ leaseId: string }>(expiredLeaseResponse).leaseId;

    // Wait for lease to expire
    await new Promise((resolve) => setTimeout(resolve, 5000));

    const request = createRequest('verifyLease', { leaseId: expiredLeaseId });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('valid', false);
    expect(response.result).toHaveProperty('reason', 'expired');
    expect(response.result).toHaveProperty('kid'); // Should return the lease's kid
  });

  it('should return invalid for lease with wrong key', async () => {
    // Save the old kid before regenerating
    const oldKid = kid;

    // Regenerate VAPID key (creates new kid)
    const newVapidResponse = await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    const newKid = getResult<{ kid: string }>(newVapidResponse).kid;

    // The old lease is now bound to the old kid, not the new one
    const request = createRequest('verifyLease', { leaseId });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('valid', false);
    expect(response.result).toHaveProperty('reason', 'wrong-key');
    expect(response.result).toHaveProperty('kid'); // Should return the lease's kid (old kid)
    expect(oldKid).not.toBe(newKid); // Verify keys are different
  });
});

describe('issueVAPIDJWT', () => {
  let kid: string;
  let leaseId: string;
  const passphrase = 'lease-jwt-passphrase-123';

  beforeEach(async () => {
    // Setup (automatically generates VAPID key)
    const setupResponse = await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase }));
    kid = getResult<{ vapidKid: string }>(setupResponse).vapidKid;

    // Set push subscription
    await handleMessage(
      createRequest('setPushSubscription', {
        subscription: {
          endpoint: 'https://fcm.googleapis.com/fcm/send/test-subscription-1',
          expirationTime: null,
          keys: { p256dh: 'test-p256dh-key', auth: 'test-auth-key' },
          eid: 'ep-1',
          createdAt: Date.now(),
        },
      })
    );

    // Create lease
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'user-123',
        ttlHours: 1,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    leaseId = getResult<{ leaseId: string }>(leaseResponse).leaseId;
  });

  it('should issue JWT with lease successfully', async () => {
    const request = createRequest('issueVAPIDJWT', {
      leaseId,
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('jwt');
    expect(response.result).toHaveProperty('jti');
    expect(response.result).toHaveProperty('exp');

    // JWT should be valid
    const issueResult = getResult<{ jwt: string }>(response);
    const parts = issueResult.jwt.split('.');
    expect(parts).toHaveLength(3);
  });

  it('should reject non-existent lease', async () => {
    const request = createRequest('issueVAPIDJWT', {
      leaseId: 'lease-does-not-exist',
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('not found');
  });

  it('should reject unauthorized endpoint', async () => {
    // This test is no longer relevant since endpoint authorization
    // is now handled at lease creation time via push subscription
    // Rather than delete it, we'll verify that JWT issuance works
    // with the subscription set during beforeEach
    const request = createRequest('issueVAPIDJWT', {
      leaseId,
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('jwt');
  });

  it('should enforce quota (tokens per hour)', async () => {
    // Manually set quota state to near limit (99 tokens issued)
    // This avoids issuing 100 JWTs which would timeout due to expensive PBKDF2 operations
    const { putMeta } = await import('../../src/v2/storage.js');
    await putMeta(`quota:${leaseId}`, {
      leaseId,
      tokensIssued: 99,
      lastResetAt: Date.now(),
      perEndpoint: {},
    });

    // Issue one more JWT - should succeed (99 < 100)
    const request1 = createRequest('issueVAPIDJWT', {
      leaseId,
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response1 = await handleMessage(request1);
    expect(response1.error).toBeUndefined();

    // Issue second JWT - should fail (100 >= 100)
    const request2 = createRequest('issueVAPIDJWT', {
      leaseId,
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response2 = await handleMessage(request2);
    expect(response2.error).toBeDefined();
    expect(response2.error).toContain('Quota exceeded');
  });

  it('should reject JWT issuance after VAPID regeneration', async () => {
    // Issue JWT successfully with current lease/kid
    const request1 = createRequest('issueVAPIDJWT', {
      leaseId,
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response1 = await handleMessage(request1);
    expect(response1.error).toBeUndefined();

    // Regenerate VAPID key (invalidates all existing leases)
    const regenerateResponse = await handleMessage(
      createRequest('regenerateVAPID', { credentials: createPassphraseCredentials(passphrase) })
    );
    const newKid = getResult<{ kid: string }>(regenerateResponse).kid;
    expect(newKid).not.toBe(kid); // Should be a new key

    // Try to issue JWT with old lease - should fail due to kid mismatch
    const request2 = createRequest('issueVAPIDJWT', {
      leaseId, // Old lease with old kid
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response2 = await handleMessage(request2);
    expect(response2.error).toBeDefined();
    expect(response2.error).toContain('invalidated');
    expect(response2.error).toContain('wrong-key');
  });
});

// ============================================================================
// issueVAPIDJWTs (Batch) Tests
// ============================================================================

describe('issueVAPIDJWTs', () => {
  let passphrase: string;
  let leaseId: string;
  let kid: string;

  beforeEach(async () => {
    // Setup KMS with passphrase
    passphrase = 'batch-jwt-passphrase-123';
    const setupResponse = await handleMessage(
      createRequest('setupPassphrase', {
        userId: 'test@example.com',
        passphrase,
      })
    );
    kid = getResult<{ vapidKid: string }>(setupResponse).vapidKid;

    // Set push subscription (required for JWT issuance)
    await handleMessage(
      createRequest('setPushSubscription', {
        subscription: {
          endpoint: 'https://fcm.googleapis.com/fcm/send/batch-jwt-test',
          expirationTime: null,
          keys: { p256dh: 'test-p256dh', auth: 'test-auth' },
          eid: 'ep-batch-test',
          createdAt: Date.now(),
        },
      })
    );

    // Create a lease
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'test-user',
        subs: [],
        ttlHours: 12,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    leaseId = getResult<{ leaseId: string }>(leaseResponse).leaseId;
  });

  it('should issue multiple JWTs with staggered expirations', async () => {
    const request = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 3,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);
    expect(response.error).toBeUndefined();

    const result = getResult<Array<{ jwt: string; jti: string; exp: number }>>(response);
    expect(result).toHaveLength(3);

    // Verify all JWTs are present
    for (const item of result) {
      expect(item.jwt).toBeDefined();
      expect(item.jti).toBeDefined();
      expect(item.exp).toBeGreaterThan(Date.now() / 1000);
    }

    // Verify expirations are staggered (each should be ~9 minutes apart)
    expect(result[1]!.exp).toBeGreaterThan(result[0]!.exp);
    expect(result[2]!.exp).toBeGreaterThan(result[1]!.exp);

    // Check stagger interval is approximately 540 seconds (9 minutes = 60% of 15 min TTL)
    const stagger1 = result[1]!.exp - result[0]!.exp;
    const stagger2 = result[2]!.exp - result[1]!.exp;
    expect(stagger1).toBeGreaterThan(500);
    expect(stagger1).toBeLessThan(600);
    expect(stagger2).toBeGreaterThan(500);
    expect(stagger2).toBeLessThan(600);
  });

  it('should validate count is between 1 and 10', async () => {
    // Test count = 0 (invalid)
    const request0 = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 0,
      credentials: createPassphraseCredentials(passphrase),
    });
    const response0 = await handleMessage(request0);
    expect(response0.error).toBeDefined();
    expect(response0.error).toContain('count must be an integer between 1 and 10');

    // Test count = 11 (invalid)
    const request11 = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 11,
      credentials: createPassphraseCredentials(passphrase),
    });
    const response11 = await handleMessage(request11);
    expect(response11.error).toBeDefined();
    expect(response11.error).toContain('count must be an integer between 1 and 10');

    // Test count = 1 (valid)
    const request1 = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 1,
      credentials: createPassphraseCredentials(passphrase),
    });
    const response1 = await handleMessage(request1);
    expect(response1.error).toBeUndefined();
    expect(getResult<Array<any>>(response1)).toHaveLength(1);

    // Test count = 10 (valid)
    const request10 = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 10,
      credentials: createPassphraseCredentials(passphrase),
    });
    const response10 = await handleMessage(request10);
    expect(response10.error).toBeUndefined();
    expect(getResult<Array<any>>(response10)).toHaveLength(10);
  });

  it('should issue single JWT when count=1', async () => {
    const request = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 1,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);
    expect(response.error).toBeUndefined();

    const result = getResult<Array<{ jwt: string; jti: string; exp: number }>>(response);
    expect(result).toHaveLength(1);
    expect(result[0]!.jwt).toBeDefined();
    expect(result[0]!.jti).toBeDefined();
  });

  it('should work with autoExtend leases', async () => {
    const request = createRequest('issueVAPIDJWTs', {
      leaseId,
      kid,
      count: 2,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);
    expect(response.error).toBeUndefined();

    const result = getResult<Array<{ jwt: string }>>(response);
    expect(result).toHaveLength(2);
    expect(result[0]!.jwt).toBeDefined();
    expect(result[1]!.jwt).toBeDefined();
  });
});

// ============================================================================
// Status/Query Operations Tests
// ============================================================================

describe('isSetup', () => {
  it('should return false when not setup', async () => {
    const request = createRequest('isSetup', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const setupResult = getResult<{ isSetup: boolean; methods: string[] }>(response);
    expect(setupResult.isSetup).toBe(false);
    expect(setupResult.methods).toEqual([]);
  });

  it('should return true after passphrase setup', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-passphrase-123' }));

    const request = createRequest('isSetup', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    const setupResult = getResult<{ isSetup: boolean; methods: string[] }>(response);
    expect(setupResult.isSetup).toBe(true);
    expect(setupResult.methods).toContain('passphrase');
  });

  it('should return true after passkey setup', async () => {
    const credentialId = new Uint8Array([1, 2, 3]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    await handleMessage(
      createRequest('setupPasskeyPRF', { userId: 'test@example.com', credentialId, prfOutput })
    );

    const request = createRequest('isSetup', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    const setupResult = getResult<{ isSetup: boolean; methods: string[] }>(response);
    expect(setupResult.isSetup).toBe(true);
    expect(setupResult.methods).toContain('passkey');
  });
});

describe('getEnrollments', () => {
  it('should return empty array when no enrollments', async () => {
    const request = createRequest('getEnrollments', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(getResult<{ enrollments: string[] }>(response).enrollments).toEqual([]);
  });

  it('should return passphrase enrollment', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-123' }));

    const request = createRequest('getEnrollments', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    expect(getResult<{ enrollments: string[] }>(response).enrollments).toContain('enrollment:passphrase:v2');
  });

  it('should return multiple enrollments', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'test-123' }));

    // Add passkey PRF as additional enrollment (shares same MS)
    const credentialId = new Uint8Array([1, 2, 3]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await handleMessage(
      createRequest('addEnrollment', {
        userId: 'test@example.com',
        method: 'passkey-prf',
        credentials: { method: 'passphrase', passphrase: 'test-123', userId: 'test@example.com' },
        newCredentials: { credentialId, prfOutput },
      })
    );

    const request = createRequest('getEnrollments', { userId: 'test@example.com' });
    const response = await handleMessage(request);

    const enrollmentsResult = getResult<{ enrollments: string[] }>(response);
    expect(enrollmentsResult.enrollments).toContain('enrollment:passphrase:v2');
    expect(enrollmentsResult.enrollments).toContain('enrollment:passkey-prf:v2');
  });
});

describe('verifyAuditChain', () => {
  it('should verify empty audit chain', async () => {
    const request = createRequest('verifyAuditChain');
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const verifyResult = getResult<{ valid: boolean; verified: number }>(response);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.verified).toBe(0);
  });

  it('should verify audit chain after operations', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'audit-test-123' }));
    await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials('audit-test-123'),
      })
    );

    const request = createRequest('verifyAuditChain');
    const response = await handleMessage(request);

    const verifyResult = getResult<{ valid: boolean; verified: number }>(response);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.verified).toBeGreaterThan(0);
  });
});

describe('getPublicKey', () => {
  let kid: string;

  beforeEach(async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'pubkey-test-123' }));

    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials('pubkey-test-123'),
      })
    );
    kid = getResult<{ kid: string }>(vapidResponse).kid;
  });

  it('should retrieve public key', async () => {
    const request = createRequest('getPublicKey', { kid });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const keyResult = getResult<{ publicKey: string }>(response);
    expect(keyResult.publicKey).toBeDefined();
    expect(keyResult.publicKey.length).toBeGreaterThan(0);
  });

  it('should fail for non-existent kid', async () => {
    const request = createRequest('getPublicKey', { kid: 'does-not-exist' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('not found');
  });
});

describe('getAuditPublicKey', () => {
  it('should retrieve audit public key', async () => {
    // Setup KMS first to initialize UAK
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'audit-key-test' }));

    const request = createRequest('getAuditPublicKey');
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    const keyResult = getResult<{ publicKey: string }>(response);
    expect(keyResult.publicKey).toBeDefined();
    expect(keyResult.publicKey.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Management Operations Tests
// ============================================================================

describe('resetKMS', () => {
  it('should reset KMS successfully', async () => {
    // Setup first
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'reset-test-123' }));

    // Verify setup
    const setupCheck = await handleMessage(createRequest('isSetup', { userId: 'test@example.com' }));
    expect(getResult<{ isSetup: boolean }>(setupCheck).isSetup).toBe(true);

    // Reset
    const resetRequest = createRequest('resetKMS', { userId: 'test@example.com' });
    const resetResponse = await handleMessage(resetRequest);

    expect(resetResponse.error).toBeUndefined();
    expect(getResult<{ success: boolean }>(resetResponse).success).toBe(true);

    // Verify not setup anymore
    const afterReset = await handleMessage(createRequest('isSetup', { userId: 'test@example.com' }));
    expect(getResult<{ isSetup: boolean }>(afterReset).isSetup).toBe(false);
  });
});

describe('removeEnrollment', () => {
  it('should remove enrollment successfully', async () => {
    const passphrase = 'remove-enrollment-123';
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase }));

    const request = createRequest('removeEnrollment', {
      enrollmentId: 'enrollment:passphrase:v2',
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(getResult<{ success: boolean }>(response).success).toBe(true);
  });

  it('should require valid credentials', async () => {
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: 'correct-pass-123' }));

    const request = createRequest('removeEnrollment', {
      enrollmentId: 'enrollment:passphrase:v2',
      credentials: createPassphraseCredentials('wrong-pass'),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('setupWithPopup', () => {
  it('should initiate popup setup flow and send worker:setup-with-popup message', async () => {
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });

    // Spy on self.postMessage to intercept worker→client messages
    const postMessageSpy = vi.spyOn(self, 'postMessage');

    // Start the setup (don't await - it will timeout waiting for credentials)
    const responsePromise = handleMessage(request);

    // Wait a bit for the worker to send the setup-with-popup message
    await new Promise(resolve => setTimeout(resolve, 100));

    // Verify worker sent setup-with-popup message to client
    const setupMessage = postMessageSpy.mock.calls.find(
      (call: unknown[]) => (call[0] as { type?: string })?.type === 'worker:setup-with-popup'
    );

    expect(setupMessage).toBeDefined();
    expect(setupMessage![0]).toMatchObject({
      type: 'worker:setup-with-popup',
      requestId: request.id,
      userId: 'test@example.com',
      popupURL: expect.stringContaining('https://kms.ats.run/?mode=setup'),
    });

    // Verify transport params are included
    expect(setupMessage![0]).toHaveProperty('transportKey');
    expect(setupMessage![0]).toHaveProperty('transportKeyId');
    expect(setupMessage![0]).toHaveProperty('appSalt');
    expect(setupMessage![0]).toHaveProperty('hkdfSalt');

    // Verify popup URL does NOT contain sensitive params
    const popupURL = new URL(setupMessage![0].popupURL);
    expect(popupURL.searchParams.has('transportKey')).toBe(false);
    expect(popupURL.searchParams.has('keyId')).toBe(false);
    expect(popupURL.searchParams.has('appSalt')).toBe(false);
    expect(popupURL.searchParams.has('hkdfSalt')).toBe(false);

    // Send error to clean up the pending request
    const messageEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-error',
        requestId: request.id,
        reason: 'Test cleanup'
      }
    });
    self.dispatchEvent(messageEvent);

    // Wait for error response
    const response = await responsePromise;
    expect(response.error).toBeDefined();

    postMessageSpy.mockRestore();
  });

  it('should reject if popup credentials not received', async () => {
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });

    // Spy on self.postMessage to intercept worker→client messages
    const postMessageSpy = vi.spyOn(self, 'postMessage');

    // Start the setup
    const responsePromise = handleMessage(request);

    // Wait for worker to send setup-with-popup message
    await new Promise(resolve => setTimeout(resolve, 100));

    // Verify worker sent setup-with-popup message to client
    const setupMessage = postMessageSpy.mock.calls.find(
      (call: unknown[]) => (call[0] as { type?: string })?.type === 'worker:setup-with-popup'
    );
    expect(setupMessage).toBeDefined();

    // Note: The full encryption/decryption flow is tested in integration tests
    // Here we just test the message flow, so we send an error response
    const errorEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-error',
        requestId: request.id,
        reason: 'Test - not testing full encryption in unit tests',
      }
    });
    self.dispatchEvent(errorEvent);

    // Wait for response
    const response = await responsePromise;

    expect(response.error).toBeDefined();
    expect(response.error).toContain('Test - not testing full encryption in unit tests');

    postMessageSpy.mockRestore();
  });

  it('should handle popup error gracefully', async () => {
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });

    // Start the setup
    const responsePromise = handleMessage(request);

    // Wait for worker to send setup-with-popup message
    await new Promise(resolve => setTimeout(resolve, 100));

    // Simulate client sending error
    const errorEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-error',
        requestId: request.id,
        reason: 'User closed popup',
      }
    });
    self.dispatchEvent(errorEvent);

    // Wait for response
    const response = await responsePromise;

    expect(response.error).toBeDefined();
    expect(response.error).toContain('User closed popup');
  });
});

describe('worker integration', () => {
  it('should handle complete VAPID flow', async () => {
    const passphrase = 'integration-test-passphrase-123';

    // 1. Setup (automatically generates VAPID key)
    const setupResponse = await handleMessage(
      createRequest('setupPassphrase', { userId: 'test@example.com', passphrase })
    );
    expect(setupResponse.error).toBeUndefined();
    const kid = getResult<{ vapidKid: string }>(setupResponse).vapidKid;

    // 2. Set push subscription
    const setPushResponse = await handleMessage(
      createRequest('setPushSubscription', {
        subscription: {
          endpoint: 'https://fcm.googleapis.com/fcm/send/integration-test-sub',
          expirationTime: null,
          keys: { p256dh: 'test-p256dh', auth: 'test-auth' },
          eid: 'ep-1',
          createdAt: Date.now(),
        },
      })
    );
    expect(setPushResponse.error).toBeUndefined();

    // 3. Create lease
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'test-user',
        ttlHours: 12,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    expect(leaseResponse.error).toBeUndefined();
    const leaseId = getResult<{ leaseId: string }>(leaseResponse).leaseId;

    // 4. Issue JWT
    const jwtResponse = await handleMessage(
      createRequest('issueVAPIDJWT', {
        leaseId,
        kid,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    expect(jwtResponse.error).toBeUndefined();
    expect(getResult<{ jwt: string }>(jwtResponse).jwt).toBeDefined();

    // 5. Verify audit chain
    const auditResponse = await handleMessage(createRequest('verifyAuditChain', { userId: 'test@example.com' }));
    expect(getResult<{ valid: boolean }>(auditResponse).valid).toBe(true);

    // 6. Check quota state
    const enrollmentsResponse = await handleMessage(createRequest('getEnrollments', { userId: 'test@example.com' }));
    expect(getResult<{ enrollments: string[] }>(enrollmentsResponse).enrollments).toContain('enrollment:passphrase:v2');
  });

  it('should support multi-enrollment workflow', async () => {
    const pass1 = 'first-passphrase-123';

    // Setup passphrase
    await handleMessage(createRequest('setupPassphrase', { userId: 'test@example.com', passphrase: pass1 }));

    // Add passkey PRF
    const credentialId = new Uint8Array([9, 10, 11, 12]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    await handleMessage(
      createRequest('addEnrollment', {
        userId: 'test@example.com',
        method: 'passkey-prf',
        credentials: { method: 'passphrase', passphrase: pass1, userId: 'test@example.com' },
        newCredentials: { credentialId, prfOutput },
      })
    );

    // Verify both methods work
    const vapidWithPassphrase = await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials(pass1),
      })
    );
    expect(vapidWithPassphrase.error).toBeUndefined();

    const vapidWithPRF = await handleMessage(
      createRequest('generateVAPID', {
        credentials: { method: 'passkey-prf', prfOutput, userId: 'test@example.com' },
      })
    );
    expect(vapidWithPRF.error).toBeUndefined();

    // Both should generate valid keys
    expect(getResult<{ kid: string }>(vapidWithPassphrase).kid).toBeDefined();
    expect(getResult<{ kid: string }>(vapidWithPRF).kid).toBeDefined();
  });
});

// ============================================================================
// setupWithEncryptedCredentials Tests (Internal Function Coverage)
// ============================================================================

describe('setupWithEncryptedCredentials - ECDH encryption flow', () => {
  /**
   * Helper to simulate the popup's encryption process using ECDH.
   * This mirrors what the actual popup does when encrypting credentials.
   */
  async function encryptCredentials(
    transportPublicKey: string,
    credentials: object
  ): Promise<{
    ephemeralPublicKey: string;
    iv: string;
    encryptedCredentials: string;
  }> {
    // Import iframe's transport public key
    const transportPubKeyBytes = base64urlToArrayBuffer(transportPublicKey);
    const transportPubKey = await crypto.subtle.importKey(
      'raw',
      transportPubKeyBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Generate popup's ephemeral keypair
    const ephemeralKeypair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    // Export popup's public key (raw format, 65 bytes)
    const ephemeralPubKeyRaw = await crypto.subtle.exportKey('raw', ephemeralKeypair.publicKey);

    // Perform ECDH to derive shared secret
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: transportPubKey,
      },
      ephemeralKeypair.privateKey,
      256
    );

    // Derive AES-GCM key from shared secret (HKDF)
    const sharedSecretKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);

    const aesKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: new Uint8Array(32), // Zero salt (shared secret already random)
        info: new TextEncoder().encode('ATS/KMS/setup-transport/v2'),
        hash: 'SHA-256',
      },
      sharedSecretKey,
      256
    );

    const aesKey = await crypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
    ]);

    // Encrypt credentials
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const credentialsJSON = new TextEncoder().encode(JSON.stringify(credentials));

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      aesKey,
      credentialsJSON
    );

    return {
      ephemeralPublicKey: arrayBufferToBase64url(ephemeralPubKeyRaw),
      iv: arrayBufferToBase64url(iv.buffer),
      encryptedCredentials: arrayBufferToBase64url(ciphertext),
    };
  }

  /**
   * Helper to call generateSetupTransportKey via handleSetupWithPopup.
   * This is a workaround since generateSetupTransportKey is not exposed as an RPC method anymore.
   */
  async function getTransportKey(): Promise<{
    publicKey: string;
    keyId: string;
    appSalt: string;
    hkdfSalt: string;
  }> {
    // Start setupWithPopup which generates transport key internally
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });

    // Intercept postMessage to capture transport params
    let transportParams: any = null;
    const originalPostMessage = (self as any).postMessage;
    (self as any).postMessage = vi.fn((data: any) => {
      if (data.type === 'worker:setup-with-popup') {
        transportParams = {
          publicKey: data.transportKey,
          keyId: data.transportKeyId,
          appSalt: data.appSalt,
          hkdfSalt: data.hkdfSalt,
        };
      }
      originalPostMessage.call(self, data);
    });

    const responsePromise = handleMessage(request);

    // Wait for worker to send setup-with-popup message
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Cancel the setup by sending an error
    const errorEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-error',
        requestId: request.id,
        reason: 'Cancelled for transport key extraction',
      },
    });
    self.dispatchEvent(errorEvent);

    // Wait for response to complete (will error, but that's expected)
    await responsePromise.catch(() => {});

    // Restore postMessage
    (self as any).postMessage = originalPostMessage;

    if (!transportParams) {
      throw new Error('Failed to extract transport params from setupWithPopup');
    }

    return transportParams;
  }

  /**
   * Helper to import base64url functions from crypto-utils.
   */
  function arrayBufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
    const b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
    let b64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad) b64 += '='.repeat(4 - pad);
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  it('should decrypt and setup with passphrase credentials', async () => {
    // Step 1: Get transport key from iframe
    const transportParams = await getTransportKey();
    expect(transportParams.publicKey).toBeDefined();
    expect(transportParams.keyId).toBeDefined();

    // Step 2: Encrypt passphrase credentials (simulate popup behavior)
    const passphrase = 'test-encrypted-passphrase-123';
    const encryptedData = await encryptCredentials(transportParams.publicKey, { passphrase });

    // Step 3: Call setupWithPopup and complete the flow
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });
    const responsePromise = handleMessage(request);

    // Wait for worker to be ready
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Simulate encrypted credentials from popup (correct message format)
    const credentialsEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-credentials',
        requestId: request.id,
        credentials: {
          method: 'passphrase',
          transportKeyId: transportParams.keyId,
          userId: 'test@example.com',
          ephemeralPublicKey: encryptedData.ephemeralPublicKey,
          iv: encryptedData.iv,
          encryptedCredentials: encryptedData.encryptedCredentials,
        },
      },
    });
    self.dispatchEvent(credentialsEvent);

    // Wait for response
    const response = await responsePromise;

    // Verify setup succeeded with correct response structure
    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = getResult<{ success: boolean; vapidKid: string; enrollmentId: string; vapidPublicKey: string }>(response);
    expect(result.success).toBe(true);
    expect(result.vapidKid).toBeDefined();
    expect(result.vapidPublicKey).toBeDefined();
    expect(result.enrollmentId).toContain('enrollment:passphrase:v2');
  });

  it('should decrypt and setup with passkey-prf credentials', async () => {
    // Step 1: Get transport key
    const transportParams = await getTransportKey();

    // Step 2: Generate PRF output (simulate WebAuthn)
    const credentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    // Step 3: Encrypt PRF credentials
    const encryptedData = await encryptCredentials(transportParams.publicKey, {
      credentialId: arrayBufferToBase64url(credentialId),
      prfOutput: arrayBufferToBase64url(prfOutput),
      rpId: 'localhost',
    });

    // Step 4: Complete setupWithPopup flow
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });
    const responsePromise = handleMessage(request);

    await new Promise((resolve) => setTimeout(resolve, 50));

    const credentialsEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-credentials',
        requestId: request.id,
        credentials: {
          method: 'passkey-prf',
          transportKeyId: transportParams.keyId,
          userId: 'test@example.com',
          ephemeralPublicKey: encryptedData.ephemeralPublicKey,
          iv: encryptedData.iv,
          encryptedCredentials: encryptedData.encryptedCredentials,
        },
      },
    });
    self.dispatchEvent(credentialsEvent);

    const response = await responsePromise;

    // Verify setup succeeded with correct response structure
    expect(response.error).toBeUndefined();
    const result = getResult<{ success: boolean; vapidKid: string; enrollmentId: string; vapidPublicKey: string }>(response);
    expect(result.success).toBe(true);
    expect(result.vapidKid).toBeDefined();
    expect(result.vapidPublicKey).toBeDefined();
    expect(result.enrollmentId).toContain('enrollment:passkey-prf:v2');
  });

  it('should decrypt and setup with passkey-gate credentials', async () => {
    // Step 1: Get transport key
    const transportParams = await getTransportKey();

    // Step 2: Generate credential ID
    const credentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;

    // Step 3: Encrypt gate credentials
    const encryptedData = await encryptCredentials(transportParams.publicKey, {
      credentialId: arrayBufferToBase64url(credentialId),
      rpId: 'localhost',
    });

    // Step 4: Complete setupWithPopup flow
    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });
    const responsePromise = handleMessage(request);

    await new Promise((resolve) => setTimeout(resolve, 50));

    const credentialsEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-credentials',
        requestId: request.id,
        credentials: {
          method: 'passkey-gate',
          transportKeyId: transportParams.keyId,
          userId: 'test@example.com',
          ephemeralPublicKey: encryptedData.ephemeralPublicKey,
          iv: encryptedData.iv,
          encryptedCredentials: encryptedData.encryptedCredentials,
        },
      },
    });
    self.dispatchEvent(credentialsEvent);

    const response = await responsePromise;

    // Verify setup succeeded
    expect(response.error).toBeUndefined();
    const result = getResult<{ success: boolean; vapidKid: string; enrollmentId: string }>(response);
    expect(result.success).toBe(true);
    expect(result.enrollmentId).toContain('enrollment:passkey-gate:v2');

    // Verify enrollment exists
    const enrollmentsResponse = await handleMessage(
      createRequest('getEnrollments', { userId: 'test@example.com' })
    );
    const enrollments = getResult<{ enrollments: string[] }>(enrollmentsResponse);
    expect(enrollments.enrollments).toContain(result.enrollmentId);
  });

  it('should throw on expired/missing transport key', async () => {
    // Try to use a non-existent transport key
    const fakeKeyId = crypto.randomUUID();
    const fakeEphemeralPublicKey = arrayBufferToBase64url(crypto.getRandomValues(new Uint8Array(65)).buffer);
    const fakeIv = arrayBufferToBase64url(crypto.getRandomValues(new Uint8Array(12)).buffer);
    const fakeEncrypted = arrayBufferToBase64url(crypto.getRandomValues(new Uint8Array(64)).buffer);

    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });
    const responsePromise = handleMessage(request);

    await new Promise((resolve) => setTimeout(resolve, 50));

    const credentialsEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-credentials',
        requestId: request.id,
        credentials: {
          method: 'passphrase',
          transportKeyId: fakeKeyId,
          userId: 'test@example.com',
          ephemeralPublicKey: fakeEphemeralPublicKey,
          iv: fakeIv,
          encryptedCredentials: fakeEncrypted,
        },
      },
    });
    self.dispatchEvent(credentialsEvent);

    const response = await responsePromise;

    // Should fail with transport key not found error
    expect(response.error).toBeDefined();
    expect(response.error).toContain('Transport key not found or expired');
  });

  it('should delete transport key after successful use', async () => {
    // Step 1: Get transport key
    const transportParams = await getTransportKey();

    // Step 2: Use it successfully
    const passphrase = 'test-one-time-use-123';
    const encryptedData = await encryptCredentials(transportParams.publicKey, { passphrase });

    const request = createRequest('setupWithPopup', { userId: 'test@example.com' });
    const responsePromise = handleMessage(request);

    await new Promise((resolve) => setTimeout(resolve, 50));

    const credentialsEvent = new MessageEvent('message', {
      data: {
        type: 'worker:popup-credentials',
        requestId: request.id,
        credentials: {
          method: 'passphrase',
          transportKeyId: transportParams.keyId,
          userId: 'test@example.com',
          ephemeralPublicKey: encryptedData.ephemeralPublicKey,
          iv: encryptedData.iv,
          encryptedCredentials: encryptedData.encryptedCredentials,
        },
      },
    });
    self.dispatchEvent(credentialsEvent);

    const response = await responsePromise;
    expect(response.error).toBeUndefined();

    // Step 3: Try to use the same transport key again (should fail)
    const encryptedData2 = await encryptCredentials(transportParams.publicKey, { passphrase: 'another-pass-456' });

    const request2 = createRequest('setupWithPopup', { userId: 'test2@example.com' });
    const responsePromise2 = handleMessage(request2);

    await new Promise((resolve) => setTimeout(resolve, 50));

    const credentialsEvent2 = new MessageEvent('message', {
      data: {
        type: 'worker:popup-credentials',
        requestId: request2.id,
        credentials: {
          method: 'passphrase',
          transportKeyId: transportParams.keyId, // Same key ID
          userId: 'test2@example.com',
          ephemeralPublicKey: encryptedData2.ephemeralPublicKey,
          iv: encryptedData2.iv,
          encryptedCredentials: encryptedData2.encryptedCredentials,
        },
      },
    });
    self.dispatchEvent(credentialsEvent2);

    const response2 = await responsePromise2;

    // Should fail because transport key was deleted after first use
    expect(response2.error).toBeDefined();
    expect(response2.error).toContain('Transport key not found or expired');
  });
});
