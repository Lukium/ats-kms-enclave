/**
 * Worker RPC Handler Tests (Phase 0 - TDD RED)
 *
 * These tests define the expected behavior of the Worker message handler
 * that processes RPC requests and executes crypto operations.
 *
 * Tests written BEFORE implementation following TDD methodology.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable no-console */

import { describe, it, expect, beforeEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { handleMessage, resetWorkerState } from '@/worker';

// Initialize IndexedDB and unlock worker before each test
beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();

  // Setup passphrase to unlock the worker for crypto operations
  await handleMessage({
    id: 'setup-test',
    method: 'setupPassphrase',
    params: { passphrase: 'test-passphrase-12345' },
  });
});

// Type definitions for our RPC protocol
interface RPCRequest {
  id: string;
  method: string;
  params?: unknown;
  origin?: string;
}

interface RPCResponse {
  id: string;
  result?: unknown;
  error?: {
    code: string;
    message: string;
  };
}

interface VAPIDKeyPair {
  kid: string;
  publicKey: string; // base64url encoded
}

interface JWTPayload {
  aud: string;
  sub: string;
  exp: number;
}

describe('Worker RPC Handler - Message Processing', () => {
  describe('handleMessage', () => {
    it('should be defined as a function', () => {
      // The handleMessage function will be the main entry point
      expect(typeof handleMessage).toBe('function');
    });

    it('should return a promise', () => {
      const request: RPCRequest = {
        id: 'test-001',
        method: 'generateVAPID',
      };

      const result = handleMessage(request);
      expect(result).toBeInstanceOf(Promise);
    });

    it('should handle generateVAPID method', async () => {
      const request: RPCRequest = {
        id: 'req-001',
        method: 'generateVAPID',
      };

      const response = await handleMessage(request) as RPCResponse;

      expect(response.id).toBe(request.id);
      expect(response.result).toBeDefined();
      expect(response.error).toBeUndefined();
    });

    it('should return error for unknown method', async () => {
      const request: RPCRequest = {
        id: 'req-002',
        method: 'unknownMethod',
      };

      const response = await handleMessage(request) as RPCResponse;

      expect(response.id).toBe(request.id);
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('INVALID_METHOD');
      expect(response.result).toBeUndefined();
    });

    it('should handle null request', async () => {
      const response = await handleMessage(null as unknown as RPCRequest) as RPCResponse;

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('INVALID_REQUEST');
      expect(response.error?.message).toContain('must be an object');
    });

    it('should handle non-object request', async () => {
      const response = await handleMessage('invalid' as unknown as RPCRequest) as RPCResponse;

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('INVALID_REQUEST');
      expect(response.error?.message).toContain('must be an object');
    });

    it('should handle invalid request format', async () => {
      const invalidRequest = {
        // Missing id field
        method: 'generateVAPID',
      };

      const response = await handleMessage(invalidRequest as RPCRequest) as RPCResponse;

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('INVALID_REQUEST');
    });

    it('should handle missing method field', async () => {
      const invalidRequest = {
        id: 'req-003',
        // Missing method field
      };

      const response = await handleMessage(invalidRequest as RPCRequest) as RPCResponse;

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('INVALID_REQUEST');
    });
  });
});

describe('Worker RPC Handler - generateVAPID', () => {
  it('should generate a VAPID keypair', async () => {
    const request: RPCRequest = {
      id: 'req-100',
      method: 'generateVAPID',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe('req-100');
    expect(response.result).toBeDefined();

    const result = response.result as VAPIDKeyPair;
    expect(result.kid).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(typeof result.kid).toBe('string');
    expect(typeof result.publicKey).toBe('string');
  });

  it('should generate unique key IDs', async () => {
    const request1: RPCRequest = {
      id: 'req-101',
      method: 'generateVAPID',
    };

    const request2: RPCRequest = {
      id: 'req-102',
      method: 'generateVAPID',
    };

    const response1 = await handleMessage(request1) as RPCResponse;
    const response2 = await handleMessage(request2) as RPCResponse;

    const result1 = response1.result as VAPIDKeyPair;
    const result2 = response2.result as VAPIDKeyPair;

    expect(result1.kid).not.toBe(result2.kid);
  });

  it('should generate kid as JWK thumbprint (RFC 7638)', async () => {
    const request: RPCRequest = {
      id: 'req-103',
      method: 'generateVAPID',
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as VAPIDKeyPair;

    // JWK thumbprint is base64url-encoded SHA-256 hash (43 characters)
    expect(result.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Should NOT have the old timestamp format
    expect(result.kid.startsWith('vapid-')).toBe(false);
  });

  it('should generate base64url-encoded public key', async () => {
    const request: RPCRequest = {
      id: 'req-104',
      method: 'generateVAPID',
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as VAPIDKeyPair;

    // base64url should only contain these characters
    expect(result.publicKey).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.publicKey.length).toBeGreaterThan(0);
  });

  it('should store keypair for later use', async () => {
    const generateRequest: RPCRequest = {
      id: 'req-105',
      method: 'generateVAPID',
    };

    const generateResponse = await handleMessage(generateRequest) as RPCResponse;
    const result = generateResponse.result as VAPIDKeyPair;

    // Try to get the public key back
    const getRequest: RPCRequest = {
      id: 'req-106',
      method: 'getPublicKey',
      params: { kid: result.kid },
    };

    const getResponse = await handleMessage(getRequest) as RPCResponse;
    const getResult = getResponse.result as { publicKey: string };

    expect(getResult.publicKey).toBe(result.publicKey);
  });
});

describe('Worker RPC Handler - signJWT', () => {
  let kid: string;

  beforeEach(async () => {
    // Generate a key to use for signing tests
    const request: RPCRequest = {
      id: 'setup-001',
      method: 'generateVAPID',
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as VAPIDKeyPair;
    kid = result.kid;
  });

  it('should require params with kid and payload', async () => {
    const request: RPCRequest = {
      id: 'req-200',
      method: 'signJWT',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });

  it('should require kid parameter', async () => {
    const request: RPCRequest = {
      id: 'req-201',
      method: 'signJWT',
      params: {
        // Missing kid
        payload: { aud: 'test', sub: 'test', exp: 123 },
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });

  it('should require payload parameter', async () => {
    const request: RPCRequest = {
      id: 'req-202',
      method: 'signJWT',
      params: {
        kid: 'test-kid',
        // Missing payload
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });

  it('should sign JWT with valid kid', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const request: RPCRequest = {
      id: 'req-203',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();

    const result = response.result as { jwt: string };
    expect(result.jwt).toBeDefined();
    expect(typeof result.jwt).toBe('string');
  });

  it('should return JWT with three parts (header.payload.signature)', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const request: RPCRequest = {
      id: 'req-204',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as { jwt: string };

    const parts = result.jwt.split('.');
    expect(parts).toHaveLength(3);
  });

  it('should successfully sign JWT without origin parameter', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const request: RPCRequest = {
      id: 'req-205a',
      method: 'signJWT',
      params: { kid, payload },
      // Explicitly no origin to cover branch
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as { jwt: string };

    expect(result).toBeDefined();
    expect(result.jwt).toBeDefined();
    expect(typeof result.jwt).toBe('string');
  });

  it('should return error for non-existent kid', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const request: RPCRequest = {
      id: 'req-205',
      method: 'signJWT',
      params: { kid: 'non-existent-key', payload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('KEY_NOT_FOUND');
  });

  it('should include kid in JWT header', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const request: RPCRequest = {
      id: 'req-206',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as { jwt: string };

    // Decode JWT header
    const parts = result.jwt.split('.');
    expect(parts).toHaveLength(3);

    const headerB64 = parts[0];
    expect(headerB64).toBeDefined();

    const headerJson = atob(headerB64!.replace(/-/g, '+').replace(/_/g, '/'));
    const header = JSON.parse(headerJson) as { typ: string; alg: string; kid: string };

    expect(header.kid).toBe(kid);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');
  });

  // JWT Policy Validation Tests (RFC 8292)
  it('should reject JWT with exp > 24h', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + (25 * 60 * 60), // 25 hours (exceeds 24h limit)
    };

    const request: RPCRequest = {
      id: 'req-207',
      method: 'signJWT',
      params: { kid, payload },
      // Explicitly no origin to cover validation branch without origin
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toContain('JWT exp must be ≤ 24h from now');
  });

  it('should reject JWT with missing exp', async () => {
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      // Missing exp
    } as JWTPayload;

    const request: RPCRequest = {
      id: 'req-208',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toContain('JWT exp must be ≤ 24h from now');
  });

  it('should reject JWT with non-HTTPS aud', async () => {
    const payload: JWTPayload = {
      aud: 'http://insecure.example.com', // HTTP instead of HTTPS
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const request: RPCRequest = {
      id: 'req-209',
      method: 'signJWT',
      params: { kid, payload },
      // Explicitly no origin to cover validation branch without origin
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toContain('JWT aud must be HTTPS URL');
  });

  it('should reject JWT with missing aud', async () => {
    const payload = {
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600,
      // Missing aud
    } as JWTPayload;

    const request: RPCRequest = {
      id: 'req-210',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toContain('JWT aud must be HTTPS URL');
  });

  it('should reject JWT with invalid sub format', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'invalid-format', // Must be mailto: or https:
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const request: RPCRequest = {
      id: 'req-211',
      method: 'signJWT',
      params: { kid, payload },
      // Explicitly no origin - to cover branch where origin is undefined
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toContain('JWT sub must be mailto: or https: URL');
  });

  it('should reject JWT with missing sub', async () => {
    const payload = {
      aud: 'https://fcm.googleapis.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
      // Missing sub
    } as JWTPayload;

    const request: RPCRequest = {
      id: 'req-212',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toContain('JWT sub must be mailto: or https: URL');
  });

  it('should accept JWT with https: sub (alternative to mailto:)', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'https://ats.run/contact', // https: is also valid
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const request: RPCRequest = {
      id: 'req-213',
      method: 'signJWT',
      params: { kid, payload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { jwt: string };
    expect(result.jwt).toBeDefined();
  });
});

describe('Worker RPC Handler - getPublicKey', () => {
  it('should require params with kid', async () => {
    const request: RPCRequest = {
      id: 'req-300',
      method: 'getPublicKey',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });

  it('should return publicKey for valid kid', async () => {
    // First generate a key
    const generateRequest: RPCRequest = {
      id: 'req-301',
      method: 'generateVAPID',
    };

    const generateResponse = await handleMessage(generateRequest) as RPCResponse;
    const generateResult = generateResponse.result as VAPIDKeyPair;

    // Now get the public key
    const getRequest: RPCRequest = {
      id: 'req-302',
      method: 'getPublicKey',
      params: { kid: generateResult.kid },
    };

    const getResponse = await handleMessage(getRequest) as RPCResponse;
    const getResult = getResponse.result as { publicKey: string };

    expect(getResult.publicKey).toBe(generateResult.publicKey);
  });

  it('should return null for non-existent kid', async () => {
    const request: RPCRequest = {
      id: 'req-303',
      method: 'getPublicKey',
      params: { kid: 'non-existent-key' },
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as { publicKey: string | null };

    expect(result.publicKey).toBeNull();
  });

  it('should require kid parameter in params', async () => {
    const request: RPCRequest = {
      id: 'req-304',
      method: 'getPublicKey',
      params: {
        // params exists but kid is missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('kid');
  });

  it('should reject non-string kid parameter', async () => {
    const request: RPCRequest = {
      id: 'req-305',
      method: 'getPublicKey',
      params: {
        kid: 123, // Invalid type
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });
});

describe('Worker RPC Handler - Error Handling', () => {
  it('should handle circular reference in JWT payload', async () => {
    // First generate a key
    const generateRequest: RPCRequest = {
      id: 'req-400',
      method: 'generateVAPID',
    };

    const generateResponse = await handleMessage(generateRequest) as RPCResponse;
    const generateResult = generateResponse.result as VAPIDKeyPair;

    // Create a payload with circular reference (will cause JSON.stringify to fail)
    const circularPayload: Record<string, unknown> = {
      aud: 'https://test.com',
      sub: 'mailto:test@test.com',
      exp: 123456,
    };
    circularPayload.self = circularPayload; // Circular reference

    const request: RPCRequest = {
      id: 'req-401',
      method: 'signJWT',
      params: { kid: generateResult.kid, payload: circularPayload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('CRYPTO_ERROR');
    expect(response.error?.message).toContain('Crypto operation failed');
  });

  it('should preserve request ID in error responses', async () => {
    const requestId = 'req-402-unique-id';
    const request: RPCRequest = {
      id: requestId,
      method: 'unknownMethod',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe(requestId);
  });

  it('should include helpful error messages', async () => {
    const request: RPCRequest = {
      id: 'req-403',
      method: 'unknownMethod',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.message).toBeDefined();
    expect(response.error?.message.length).toBeGreaterThan(0);
    expect(response.error?.message).toContain('unknownMethod');
  });

  it('should preserve request ID even in generic error handler', async () => {
    // Generate a key first
    const generateRequest: RPCRequest = {
      id: 'req-404',
      method: 'generateVAPID',
    };

    const generateResponse = await handleMessage(generateRequest) as RPCResponse;
    const generateResult = generateResponse.result as VAPIDKeyPair;

    // Create a payload with circular reference
    const circularPayload: Record<string, unknown> = {
      aud: 'https://test.com',
      sub: 'mailto:test@test.com',
      exp: 123456,
    };
    circularPayload.self = circularPayload;

    const request: RPCRequest = {
      id: 'req-405-error-id',
      method: 'signJWT',
      params: { kid: generateResult.kid, payload: circularPayload },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe('req-405-error-id');
    expect(response.error).toBeDefined();
  });
});

describe('Worker RPC Handler - Unlock Error Paths', () => {
  // No beforeEach setup - test error paths in clean state

  beforeEach(() => {
    globalThis.indexedDB = new IDBFactory();
  });

  it('should return error result for setupPassphrase with too-short passphrase', async () => {
    const request: RPCRequest = {
      id: 'req-600',
      method: 'setupPassphrase',
      params: {
        passphrase: 'short', // Too short
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean; error?: string };
    expect(result.success).toBe(false);
    expect(result.error).toBe('PASSPHRASE_TOO_SHORT');
  });

  it('should return success:false for unlockWithPassphrase with wrong passphrase', async () => {
    // Setup first with a known passphrase
    const setupResponse = await handleMessage({
      id: 'req-600a',
      method: 'setupPassphrase',
      params: { passphrase: 'correct-passphrase-12345' },
    });

    // Verify setup succeeded or already setup
    const setupResult = setupResponse.result as { success: boolean; error?: string };
    if (!setupResult.success && setupResult.error !== 'ALREADY_SETUP') {
      throw new Error(`Setup failed: ${setupResult.error}`);
    }

    // Then try to unlock with wrong passphrase
    const request: RPCRequest = {
      id: 'req-601',
      method: 'unlockWithPassphrase',
      params: {
        passphrase: 'wrong-passphrase-12345',
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean; error?: string };
    expect(result.success).toBe(false);
    expect(result.error).toBe('INCORRECT_PASSPHRASE');
  });

  it('should return error when attempting crypto operations without unlock', async () => {
    // Reset worker state to simulate uninitialized worker
    resetWorkerState();

    // Try to generate VAPID without unlocking
    const request: RPCRequest = {
      id: 'req-602',
      method: 'generateVAPID',
    };

    const response = await handleMessage(request) as RPCResponse;

    // Should get a CRYPTO_ERROR
    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('CRYPTO_ERROR');
    expect(response.error?.message).toContain('Worker not unlocked');
  });
});

describe('Worker RPC Handler - Unlock Methods', () => {
  it('should handle isUnlockSetup method', async () => {
    const request: RPCRequest = {
      id: 'req-500',
      method: 'isUnlockSetup',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe('req-500');
    expect(response.result).toBeDefined();
    expect(response.error).toBeUndefined();

    const result = response.result as { isSetup: boolean };
    expect(typeof result.isSetup).toBe('boolean');
  });

  it('should handle origin parameter in setupPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-500b',
      method: 'setupPassphrase',
      params: { passphrase: 'test-origin-pass-12345' },
      origin: 'https://test.example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe('req-500b');
    expect(response.result).toBeDefined();
  });

  it('should handle origin parameter in unlockWithPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-500c',
      method: 'unlockWithPassphrase',
      params: { passphrase: 'test-passphrase-12345' },
      origin: 'https://test.example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe('req-500c');
    expect(response.result).toBeDefined();
  });

  it('should handle origin parameter in generateVAPID', async () => {
    const request: RPCRequest = {
      id: 'req-500d',
      method: 'generateVAPID',
      origin: 'https://test.example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.id).toBe('req-500d');
    expect(response.result).toBeDefined();

    const result = response.result as VAPIDKeyPair;
    expect(result.kid).toBeDefined();
  });

  it('should return isSetup: true after setupPassphrase', async () => {
    // First check before setup
    const checkBefore: RPCRequest = {
      id: 'req-501a',
      method: 'isUnlockSetup',
    };
    const beforeResponse = await handleMessage(checkBefore) as RPCResponse;
    const beforeResult = beforeResponse.result as { isSetup: boolean };
    expect(beforeResult.isSetup).toBe(true); // Already set up in beforeEach

    // The beforeEach already set up passphrase, so isSetup should be true
  });

  it('should require params for setupPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-502',
      method: 'setupPassphrase',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('params');
  });

  it('should require passphrase parameter for setupPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-503',
      method: 'setupPassphrase',
      params: {
        // params exists but passphrase is missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('passphrase');
  });

  it('should require params for unlockWithPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-504',
      method: 'unlockWithPassphrase',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('params');
  });

  it('should require passphrase parameter for unlockWithPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-505',
      method: 'unlockWithPassphrase',
      params: {
        // params exists but passphrase is missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('passphrase');
  });

  it('should reject non-string passphrase for setupPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-506',
      method: 'setupPassphrase',
      params: {
        passphrase: 12345, // Invalid type
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });

  it('should reject non-string passphrase for unlockWithPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-507',
      method: 'unlockWithPassphrase',
      params: {
        passphrase: 12345, // Invalid type
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
  });

  it('should return error for setupPassphrase with short passphrase', async () => {
    const request: RPCRequest = {
      id: 'req-508',
      method: 'setupPassphrase',
      params: {
        passphrase: 'short', // Too short
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean; error?: string };
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should return error for unlockWithPassphrase with incorrect passphrase', async () => {
    const request: RPCRequest = {
      id: 'req-509',
      method: 'unlockWithPassphrase',
      params: {
        passphrase: 'wrong-passphrase-12345', // Incorrect
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean; error?: string };
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

describe('Worker RPC Handler - Passkey Methods', () => {
  // Mock credential data for passkey tests
  const mockCredentialId = crypto.getRandomValues(new Uint8Array(16)).buffer;
  const mockPrfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

  beforeEach(async () => {
    // Initialize IndexedDB for passkey tests
    globalThis.indexedDB = new IDBFactory();
  });

  // setupPasskeyPRF tests
  it('should require params for setupPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-600',
      method: 'setupPasskeyPRF',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('params');
  });

  it('should require credentialId parameter for setupPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-601',
      method: 'setupPasskeyPRF',
      params: {
        prfOutput: mockPrfOutput,
        // credentialId missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('credentialId');
  });

  it('should require prfOutput parameter for setupPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-602',
      method: 'setupPasskeyPRF',
      params: {
        credentialId: mockCredentialId,
        // prfOutput missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('prfOutput');
  });

  it('should reject non-ArrayBuffer credentialId for setupPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-603',
      method: 'setupPasskeyPRF',
      params: {
        credentialId: 'not-an-arraybuffer',
        prfOutput: mockPrfOutput,
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('credentialId');
  });

  it('should reject non-ArrayBuffer prfOutput for setupPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-604',
      method: 'setupPasskeyPRF',
      params: {
        credentialId: mockCredentialId,
        prfOutput: 'not-an-arraybuffer',
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('prfOutput');
  });

  // unlockWithPasskeyPRF tests
  it('should require params for unlockWithPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-605',
      method: 'unlockWithPasskeyPRF',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('params');
  });

  it('should require prfOutput parameter for unlockWithPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-606',
      method: 'unlockWithPasskeyPRF',
      params: {
        // prfOutput missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('prfOutput');
  });

  it('should reject non-ArrayBuffer prfOutput for unlockWithPasskeyPRF', async () => {
    const request: RPCRequest = {
      id: 'req-607',
      method: 'unlockWithPasskeyPRF',
      params: {
        prfOutput: 'not-an-arraybuffer',
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('prfOutput');
  });

  it('should fail unlock when passkey PRF not setup', async () => {
    // Reset to fresh state without passkey setup (only passphrase from global beforeEach)
    const request: RPCRequest = {
      id: 'req-607a',
      method: 'unlockWithPasskeyPRF',
      params: {
        prfOutput: new ArrayBuffer(32),
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.result).toBeDefined();
    expect((response.result as any).success).toBe(false);
    expect((response.result as any).error).toBeDefined();
  });

  // setupPasskeyGate tests
  it('should require params for setupPasskeyGate', async () => {
    const request: RPCRequest = {
      id: 'req-608',
      method: 'setupPasskeyGate',
      // Missing params
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('params');
  });

  it('should require credentialId parameter for setupPasskeyGate', async () => {
    const request: RPCRequest = {
      id: 'req-609',
      method: 'setupPasskeyGate',
      params: {
        // credentialId missing
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('credentialId');
  });

  it('should reject non-ArrayBuffer credentialId for setupPasskeyGate', async () => {
    const request: RPCRequest = {
      id: 'req-610',
      method: 'setupPasskeyGate',
      params: {
        credentialId: 'not-an-arraybuffer',
      },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe('INVALID_PARAMS');
    expect(response.error?.message).toContain('credentialId');
  });

  // unlockWithPasskeyGate tests
  it('should fail unlock when passkey gate not setup', async () => {
    // Reset to fresh state without passkey setup (only passphrase from global beforeEach)
    const request: RPCRequest = {
      id: 'req-610a',
      method: 'unlockWithPasskeyGate',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.result).toBeDefined();
    expect((response.result as any).success).toBe(false);
    expect((response.result as any).error).toBeDefined();
  });
});

describe('Worker RPC Handler - getPasskeyConfig', () => {
  // Note: Global beforeEach sets up passphrase, so unlockSalt will have passphrase config

  it('should return null when no unlock method configured', async () => {
    // Reset and create fresh DB
    resetWorkerState();
    globalThis.indexedDB = new IDBFactory();

    // Initialize DB by calling initDB directly
    const { initDB } = await import('@/storage');
    await initDB();

    const request: RPCRequest = {
      id: 'req-get-config-empty',
      method: 'getPasskeyConfig',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeNull();
  });

  it('should return unlock config (passphrase from global setup)', async () => {
    // The global beforeEach sets up passphrase, so config should exist
    const request: RPCRequest = {
      id: 'req-get-config-1',
      method: 'getPasskeyConfig',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    expect((response.result as any).method).toBe('passphrase'); // From global beforeEach
  });

  it('should return config when passkey PRF is setup', async () => {
    // Reset worker for fresh test (remove passphrase setup)
    resetWorkerState();
    globalThis.indexedDB = new IDBFactory();

    // Setup passkey PRF
    const setupRequest: RPCRequest = {
      id: 'req-setup-prf',
      method: 'setupPasskeyPRF',
      params: {
        credentialId: new ArrayBuffer(32),
        prfOutput: new ArrayBuffer(32),
      },
    };
    await handleMessage(setupRequest);

    // Now get the config
    const request: RPCRequest = {
      id: 'req-get-config-2',
      method: 'getPasskeyConfig',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    expect((response.result as any).method).toBe('passkey-prf');
    expect((response.result as any).credentialId).toBeDefined();
    expect((response.result as any).appSalt).toBeDefined();
  });

  it('should return config when passkey gate is setup', async () => {
    // Reset worker for fresh test (remove passphrase setup)
    resetWorkerState();
    globalThis.indexedDB = new IDBFactory();

    // Setup passkey gate
    const setupRequest: RPCRequest = {
      id: 'req-setup-gate',
      method: 'setupPasskeyGate',
      params: {
        credentialId: new ArrayBuffer(32),
      },
    };
    await handleMessage(setupRequest);

    // Now get the config
    const request: RPCRequest = {
      id: 'req-get-config-3',
      method: 'getPasskeyConfig',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    expect((response.result as any).method).toBe('passkey-gate');
    expect((response.result as any).credentialId).toBeDefined();
  });
});

describe('Worker RPC Handler - Audit Operations', () => {
  beforeEach(async () => {
    // Reset worker state and reinitialize
    // (Global beforeEach already created fresh IDB and called setupPassphrase,
    // but we need to ensure audit logger is properly initialized for these tests)
    resetWorkerState();

    // Reinitialize by calling setupPassphrase again
    await handleMessage({
      id: 'audit-setup',
      method: 'setupPassphrase',
      params: { passphrase: 'test-passphrase-12345' },
    });
  });

  it('should get audit public key', async () => {
    const request: RPCRequest = {
      id: 'req-audit-1',
      method: 'getAuditPublicKey',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeTruthy();
    const publicKey = response.result as JsonWebKey;
    expect(publicKey.kty).toBe('EC');
    expect(publicKey.crv).toBe('P-256');
  });

  it('should verify audit chain', async () => {
    // Generate some audit entries
    const setupRequest: RPCRequest = {
      id: 'req-setup',
      method: 'setupPassphrase',
      params: { passphrase: 'test-pass-12345' },
    };
    await handleMessage(setupRequest);

    const vapidRequest: RPCRequest = {
      id: 'req-vapid',
      method: 'generateVAPID',
    };
    await handleMessage(vapidRequest);

    // Verify the chain
    const request: RPCRequest = {
      id: 'req-audit-2',
      method: 'verifyAuditChain',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeTruthy();
    const result = response.result as { valid: boolean; verified: number; errors: string[] };
    expect(result.valid).toBe(true);
    expect(result.verified).toBeGreaterThan(0);
    expect(result.errors).toEqual([]);
  });

  it('should verify audit chain after initialization', async () => {
    // Note: beforeEach calls setupPassphrase, which creates at least one audit entry
    const request: RPCRequest = {
      id: 'req-audit-3',
      method: 'verifyAuditChain',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeTruthy();
    const result = response.result as { valid: boolean; verified: number; errors: string[] };
    expect(result.valid).toBe(true);
    expect(result.verified).toBeGreaterThanOrEqual(1); // At least the setup entry
    expect(result.errors).toEqual([]);
  });
});

describe('Worker RPC Handler - Passkey Success Paths', () => {
  beforeEach(async () => {
    // Reset worker state for fresh passkey tests
    resetWorkerState();
    globalThis.indexedDB = new IDBFactory();
  });

  it('should successfully setup passkey with PRF', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request: RPCRequest = {
      id: 'req-passkey-prf-setup',
      method: 'setupPasskeyPRF',
      params: { credentialId, prfOutput },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should successfully unlock with passkey PRF', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    // First setup
    await handleMessage({
      id: 'setup',
      method: 'setupPasskeyPRF',
      params: { credentialId, prfOutput },
    });

    // Then unlock
    const request: RPCRequest = {
      id: 'req-passkey-prf-unlock',
      method: 'unlockWithPasskeyPRF',
      params: { prfOutput },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should successfully setup passkey in gate mode', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request: RPCRequest = {
      id: 'req-passkey-gate-setup',
      method: 'setupPasskeyGate',
      params: { credentialId },
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should successfully unlock with passkey gate', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;

    // First setup
    await handleMessage({
      id: 'setup',
      method: 'setupPasskeyGate',
      params: { credentialId },
    });

    // Then unlock
    const request: RPCRequest = {
      id: 'req-passkey-gate-unlock',
      method: 'unlockWithPasskeyGate',
      params: {},
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should handle origin parameter in setupPassphrase', async () => {
    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'setupPassphrase',
      params: { passphrase: 'test-pass-12345' },
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should handle origin parameter in unlockWithPassphrase', async () => {
    // Setup first
    await handleMessage({
      id: 'setup',
      method: 'setupPassphrase',
      params: { passphrase: 'test-pass-12345' },
    });

    // Unlock with origin
    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'unlockWithPassphrase',
      params: { passphrase: 'test-pass-12345' },
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should handle origin parameter in generateVAPID', async () => {
    // Setup first
    await handleMessage({
      id: 'setup',
      method: 'setupPassphrase',
      params: { passphrase: 'test-pass-12345' },
    });

    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'generateVAPID',
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
  });

  it('should handle origin parameter in passkey PRF setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'setupPasskeyPRF',
      params: { credentialId, prfOutput },
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean; error?: string };
    if (!result.success) {
      console.log('Setup failed with error:', result.error);
    }
    expect(result.success).toBe(true);
  });

  it('should handle origin parameter in passkey PRF unlock', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;

    // Setup first
    await handleMessage({
      id: 'setup',
      method: 'setupPasskeyPRF',
      params: { credentialId, prfOutput },
    });

    // Unlock with origin
    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'unlockWithPasskeyPRF',
      params: { prfOutput },
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should handle origin parameter in passkey gate setup', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;

    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'setupPasskeyGate',
      params: { credentialId },
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });

  it('should handle origin parameter in passkey gate unlock', async () => {
    const credentialId = crypto.getRandomValues(new Uint8Array(32)).buffer;

    // Setup first
    await handleMessage({
      id: 'setup',
      method: 'setupPasskeyGate',
      params: { credentialId },
    });

    // Unlock with origin
    const request: RPCRequest = {
      id: 'req-with-origin',
      method: 'unlockWithPasskeyGate',
      params: {},
      origin: 'https://example.com',
    };

    const response = await handleMessage(request) as RPCResponse;

    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    const result = response.result as { success: boolean };
    expect(result.success).toBe(true);
  });
});
