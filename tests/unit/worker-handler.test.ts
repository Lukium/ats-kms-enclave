/**
 * Worker RPC Handler Tests (Phase 0 - TDD RED)
 *
 * These tests define the expected behavior of the Worker message handler
 * that processes RPC requests and executes crypto operations.
 *
 * Tests written BEFORE implementation following TDD methodology.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { handleMessage } from '@/worker';

// Initialize IndexedDB before each test
beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
});

// Type definitions for our RPC protocol
interface RPCRequest {
  id: string;
  method: string;
  params?: unknown;
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

  it('should generate kid with vapid prefix', async () => {
    const request: RPCRequest = {
      id: 'req-103',
      method: 'generateVAPID',
    };

    const response = await handleMessage(request) as RPCResponse;
    const result = response.result as VAPIDKeyPair;

    expect(result.kid.startsWith('vapid-')).toBe(true);
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
