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

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
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
  return { method: 'passphrase', passphrase };
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
      passphrase: 'my-secure-passphrase-123',
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toMatchObject({
      success: true,
      enrollmentId: 'enrollment:passphrase:v2',
    });
    expect(response.result.vapidPublicKey).toBeDefined();
    expect(response.result.vapidKid).toBeDefined();
  });

  it('should reject short passphrase', async () => {
    const request = createRequest('setupPassphrase', { passphrase: 'short' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('at least 8 characters');
  });

  it('should reject empty passphrase', async () => {
    const request = createRequest('setupPassphrase', { passphrase: '' });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

describe('setupPasskeyPRF', () => {
  it('should setup passkey PRF successfully', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request = createRequest('setupPasskeyPRF', {
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
    expect(response.result.vapidPublicKey).toBeDefined();
    expect(response.result.vapidKid).toBeDefined();
  });

  it('should reject missing credentialId', async () => {
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const request = createRequest('setupPasskeyPRF', { prfOutput });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('credentialId required');
  });

  it('should reject invalid prfOutput size', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;
    const prfOutput = new Uint8Array(16).buffer; // Wrong size

    const request = createRequest('setupPasskeyPRF', { credentialId, prfOutput });
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('32 bytes');
  });
});

describe('setupPasskeyGate', () => {
  it('should setup passkey gate successfully', async () => {
    const credentialId = new Uint8Array([1, 2, 3, 4]).buffer;

    const request = createRequest('setupPasskeyGate', {
      credentialId,
      rpId: 'example.com',
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toMatchObject({
      success: true,
      enrollmentId: 'enrollment:passkey-gate:v2',
    });
    expect(response.result.vapidPublicKey).toBeDefined();
    expect(response.result.vapidKid).toBeDefined();
  });

  it('should reject missing credentialId', async () => {
    const request = createRequest('setupPasskeyGate', {});
    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

describe('addEnrollment (multi-enrollment)', () => {
  it('should add passkey PRF to existing passphrase', async () => {
    // Setup passphrase first
    await handleMessage(
      createRequest('setupPassphrase', { passphrase: 'initial-passphrase-123' })
    );

    // Add passkey PRF
    const credentialId = new Uint8Array([5, 6, 7, 8]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request = createRequest('addEnrollment', {
      method: 'passkey-prf',
      credentials: { method: 'passphrase', passphrase: 'initial-passphrase-123' },
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
      createRequest('setupPassphrase', { passphrase: 'correct-passphrase-123' })
    );

    const request = createRequest('addEnrollment', {
      method: 'passphrase',
      credentials: { method: 'passphrase', passphrase: 'wrong-passphrase' },
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
      createRequest('setupPassphrase', { passphrase: 'test-passphrase-123' })
    );

    const credentials = createPassphraseCredentials('test-passphrase-123');
    const request = createRequest('generateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('kid');
    expect(response.result).toHaveProperty('publicKey');
    expect(response.result.kid).toBeDefined();
    expect(response.result.publicKey).toBeDefined();
    expect(response.result.publicKey.length).toBeGreaterThan(0);
  });

  it('should fail without setup', async () => {
    const credentials = createPassphraseCredentials('no-setup-passphrase');
    const request = createRequest('generateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });

  it('should fail with wrong credentials', async () => {
    await handleMessage(
      createRequest('setupPassphrase', { passphrase: 'correct-passphrase-123' })
    );

    const credentials = createPassphraseCredentials('wrong-passphrase');
    const request = createRequest('generateVAPID', { credentials });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
  });
});

describe('signJWT', () => {
  let kid: string;
  const passphrase = 'jwt-signing-passphrase-123';

  beforeEach(async () => {
    // Setup and generate VAPID key
    await handleMessage(createRequest('setupPassphrase', { passphrase }));

    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', { credentials: createPassphraseCredentials(passphrase) })
    );

    kid = vapidResponse.result!.kid;
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
    expect(response.result.jwt).toBeDefined();

    // JWT should have 3 parts
    const parts = response.result.jwt.split('.');
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
    await handleMessage(createRequest('setupPassphrase', { passphrase }));
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
    expect(response.result.leaseId).toMatch(/^lease-/);
    expect(response.result.quotas).toHaveProperty('tokensPerHour');
  });

  it('should reject ttlHours > 24', async () => {
    const request = createRequest('createLease', {
      userId: 'user-123',
      subs: [],
      ttlHours: 25,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('24');
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
});

describe('issueVAPIDJWT', () => {
  let kid: string;
  let leaseId: string;
  const passphrase = 'lease-jwt-passphrase-123';

  beforeEach(async () => {
    // Setup
    await handleMessage(createRequest('setupPassphrase', { passphrase }));

    // Generate VAPID key
    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', { credentials: createPassphraseCredentials(passphrase) })
    );
    kid = vapidResponse.result!.kid;

    // Create lease
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'user-123',
        subs: [
          { url: 'https://push.example.com/sub1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
        ],
        ttlHours: 1,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    leaseId = leaseResponse.result!.leaseId;
  });

  it('should issue JWT with lease successfully', async () => {
    const request = createRequest('issueVAPIDJWT', {
      leaseId,
      endpoint: { url: 'https://push.example.com/sub1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result).toHaveProperty('jwt');
    expect(response.result).toHaveProperty('jti');
    expect(response.result).toHaveProperty('exp');

    // JWT should be valid
    const parts = response.result.jwt.split('.');
    expect(parts).toHaveLength(3);
  });

  it('should reject non-existent lease', async () => {
    const request = createRequest('issueVAPIDJWT', {
      leaseId: 'lease-does-not-exist',
      endpoint: { url: '', aud: '', eid: 'ep-1' },
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('not found');
  });

  it('should reject unauthorized endpoint', async () => {
    const request = createRequest('issueVAPIDJWT', {
      leaseId,
      endpoint: { url: '', aud: '', eid: 'ep-999' }, // Not in lease
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeDefined();
    expect(response.error).toContain('not authorized');
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
      endpoint: { url: 'https://push.example.com/sub1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response1 = await handleMessage(request1);
    expect(response1.error).toBeUndefined();

    // Issue second JWT - should fail (100 >= 100)
    const request2 = createRequest('issueVAPIDJWT', {
      leaseId,
      endpoint: { url: 'https://push.example.com/sub1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
      kid,
      credentials: createPassphraseCredentials(passphrase),
    });

    const response2 = await handleMessage(request2);
    expect(response2.error).toBeDefined();
    expect(response2.error).toContain('Quota exceeded');
  });
});

// ============================================================================
// Status/Query Operations Tests
// ============================================================================

describe('isSetup', () => {
  it('should return false when not setup', async () => {
    const request = createRequest('isSetup');
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result.isSetup).toBe(false);
    expect(response.result.methods).toEqual([]);
  });

  it('should return true after passphrase setup', async () => {
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'test-passphrase-123' }));

    const request = createRequest('isSetup');
    const response = await handleMessage(request);

    expect(response.result.isSetup).toBe(true);
    expect(response.result.methods).toContain('passphrase');
  });

  it('should return true after passkey setup', async () => {
    const credentialId = new Uint8Array([1, 2, 3]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    await handleMessage(
      createRequest('setupPasskeyPRF', { credentialId, prfOutput })
    );

    const request = createRequest('isSetup');
    const response = await handleMessage(request);

    expect(response.result.isSetup).toBe(true);
    expect(response.result.methods).toContain('passkey');
  });
});

describe('getEnrollments', () => {
  it('should return empty array when no enrollments', async () => {
    const request = createRequest('getEnrollments');
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result.enrollments).toEqual([]);
  });

  it('should return passphrase enrollment', async () => {
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'test-123' }));

    const request = createRequest('getEnrollments');
    const response = await handleMessage(request);

    expect(response.result.enrollments).toContain('enrollment:passphrase:v2');
  });

  it('should return multiple enrollments', async () => {
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'test-123' }));

    const credentialId = new Uint8Array([1, 2, 3]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
    await handleMessage(
      createRequest('setupPasskeyPRF', { credentialId, prfOutput })
    );

    const request = createRequest('getEnrollments');
    const response = await handleMessage(request);

    expect(response.result.enrollments).toContain('enrollment:passphrase:v2');
    expect(response.result.enrollments).toContain('enrollment:passkey-prf:v2');
  });
});

describe('verifyAuditChain', () => {
  it('should verify empty audit chain', async () => {
    const request = createRequest('verifyAuditChain');
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result.valid).toBe(true);
    expect(response.result.verified).toBe(0);
  });

  it('should verify audit chain after operations', async () => {
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'audit-test-123' }));
    await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials('audit-test-123'),
      })
    );

    const request = createRequest('verifyAuditChain');
    const response = await handleMessage(request);

    expect(response.result.valid).toBe(true);
    expect(response.result.verified).toBeGreaterThan(0);
  });
});

describe('getPublicKey', () => {
  let kid: string;

  beforeEach(async () => {
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'pubkey-test-123' }));

    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials('pubkey-test-123'),
      })
    );
    kid = vapidResponse.result!.kid;
  });

  it('should retrieve public key', async () => {
    const request = createRequest('getPublicKey', { kid });
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result.publicKey).toBeDefined();
    expect(response.result.publicKey.length).toBeGreaterThan(0);
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
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'audit-key-test' }));

    const request = createRequest('getAuditPublicKey');
    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result.publicKey).toBeDefined();
    expect(response.result.publicKey.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Management Operations Tests
// ============================================================================

describe('resetKMS', () => {
  it('should reset KMS successfully', async () => {
    // Setup first
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'reset-test-123' }));

    // Verify setup
    const setupCheck = await handleMessage(createRequest('isSetup'));
    expect(setupCheck.result.isSetup).toBe(true);

    // Reset
    const resetRequest = createRequest('resetKMS');
    const resetResponse = await handleMessage(resetRequest);

    expect(resetResponse.error).toBeUndefined();
    expect(resetResponse.result.success).toBe(true);

    // Verify not setup anymore
    const afterReset = await handleMessage(createRequest('isSetup'));
    expect(afterReset.result.isSetup).toBe(false);
  });
});

describe('removeEnrollment', () => {
  it('should remove enrollment successfully', async () => {
    const passphrase = 'remove-enrollment-123';
    await handleMessage(createRequest('setupPassphrase', { passphrase }));

    const request = createRequest('removeEnrollment', {
      enrollmentId: 'enrollment:passphrase:v2',
      credentials: createPassphraseCredentials(passphrase),
    });

    const response = await handleMessage(request);

    expect(response.error).toBeUndefined();
    expect(response.result.success).toBe(true);
  });

  it('should require valid credentials', async () => {
    await handleMessage(createRequest('setupPassphrase', { passphrase: 'correct-pass-123' }));

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

describe('worker integration', () => {
  it('should handle complete VAPID flow', async () => {
    const passphrase = 'integration-test-passphrase-123';

    // 1. Setup
    const setupResponse = await handleMessage(
      createRequest('setupPassphrase', { passphrase })
    );
    expect(setupResponse.error).toBeUndefined();

    // 2. Generate VAPID key
    const vapidResponse = await handleMessage(
      createRequest('generateVAPID', {
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    expect(vapidResponse.error).toBeUndefined();
    const kid = vapidResponse.result!.kid;

    // 3. Create lease
    const leaseResponse = await handleMessage(
      createRequest('createLease', {
        userId: 'test-user',
        subs: [{ url: 'https://push.example.com/sub', aud: 'https://fcm.googleapis.com', eid: 'ep-1' }],
        ttlHours: 12,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    expect(leaseResponse.error).toBeUndefined();
    const leaseId = leaseResponse.result!.leaseId;

    // 4. Issue JWT
    const jwtResponse = await handleMessage(
      createRequest('issueVAPIDJWT', {
        leaseId,
        endpoint: { url: 'https://push.example.com/sub', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
        kid,
        credentials: createPassphraseCredentials(passphrase),
      })
    );
    expect(jwtResponse.error).toBeUndefined();
    expect(jwtResponse.result.jwt).toBeDefined();

    // 5. Verify audit chain
    const auditResponse = await handleMessage(createRequest('verifyAuditChain'));
    expect(auditResponse.result.valid).toBe(true);

    // 6. Check quota state
    const enrollmentsResponse = await handleMessage(createRequest('getEnrollments'));
    expect(enrollmentsResponse.result.enrollments).toContain('enrollment:passphrase:v2');
  });

  it('should support multi-enrollment workflow', async () => {
    const pass1 = 'first-passphrase-123';

    // Setup passphrase
    await handleMessage(createRequest('setupPassphrase', { passphrase: pass1 }));

    // Add passkey PRF
    const credentialId = new Uint8Array([9, 10, 11, 12]).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    await handleMessage(
      createRequest('addEnrollment', {
        method: 'passkey-prf',
        credentials: { method: 'passphrase', passphrase: pass1 },
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
        credentials: { method: 'passkey-prf', prfOutput },
      })
    );
    expect(vapidWithPRF.error).toBeUndefined();

    // Both should generate valid keys
    expect(vapidWithPassphrase.result.kid).toBeDefined();
    expect(vapidWithPRF.result.kid).toBeDefined();
  });
});
