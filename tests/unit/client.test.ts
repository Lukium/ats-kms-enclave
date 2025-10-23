/**
 * Client RPC Bridge Tests (Phase 0 - TDD RED)
 *
 * These tests define the expected behavior of the client-side RPC bridge
 * that communicates with the Worker via postMessage.
 *
 * Tests written BEFORE implementation following TDD methodology.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { KMSClient } from '@/client';

// Type definitions for our API
interface JWTPayload {
  aud: string;
  sub: string;
  exp: number;
}

describe('Client RPC Bridge - Initialization', () => {
  let client: KMSClient;

  afterEach(() => {
    if (client) {
      client.destroy();
    }
  });

  it('should be defined as a class', () => {
    expect(typeof KMSClient).toBe('function');
  });

  it('should create a new instance', () => {
    client = new KMSClient();
    expect(client).toBeInstanceOf(KMSClient);
  });

  it('should initialize without errors', () => {
    expect(() => {
      client = new KMSClient();
    }).not.toThrow();
  });
});

describe('Client RPC Bridge - Worker Management', () => {
  let client: KMSClient;

  beforeEach(() => {
    client = new KMSClient();
  });

  afterEach(() => {
    client.destroy();
  });

  it('should create a Worker instance internally', () => {
    // Worker should be created during initialization
    // We can't directly test the private worker property,
    // but we can test that methods work (which requires a worker)
    expect(client).toBeDefined();
  });

  it('should clean up worker on destroy', () => {
    // Call destroy and verify no errors
    expect(() => {
      client.destroy();
    }).not.toThrow();
  });

  it('should not allow operations after destroy', async () => {
    client.destroy();

    await expect(async () => {
      await client.generateVAPID();
    }).rejects.toThrow('Client has been destroyed');
  });
});

describe('Client RPC Bridge - generateVAPID', () => {
  let client: KMSClient;

  beforeEach(() => {
    client = new KMSClient();
  });

  afterEach(() => {
    client.destroy();
  });

  it('should have generateVAPID method', () => {
    expect(typeof client.generateVAPID).toBe('function');
  });

  it('should return a promise', () => {
    const result = client.generateVAPID();
    expect(result).toBeInstanceOf(Promise);
  });

  it('should generate VAPID keypair', async () => {
    const result = await client.generateVAPID();

    expect(result).toBeDefined();
    expect(result.kid).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(typeof result.kid).toBe('string');
    expect(typeof result.publicKey).toBe('string');
  });

  it('should generate unique kids', async () => {
    const result1 = await client.generateVAPID();
    const result2 = await client.generateVAPID();

    expect(result1.kid).not.toBe(result2.kid);
  });

  it('should have kid with vapid prefix', async () => {
    const result = await client.generateVAPID();
    expect(result.kid.startsWith('vapid-')).toBe(true);
  });
});

describe('Client RPC Bridge - signJWT', () => {
  let client: KMSClient;
  let kid: string;

  beforeEach(async () => {
    client = new KMSClient();
    const result = await client.generateVAPID();
    kid = result.kid;
  });

  afterEach(() => {
    client.destroy();
  });

  it('should have signJWT method', () => {
    expect(typeof client.signJWT).toBe('function');
  });

  it('should return a promise', () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const result = client.signJWT(kid, payload);
    expect(result).toBeInstanceOf(Promise);
  });

  it('should sign JWT with valid kid', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const result = await client.signJWT(kid, payload);

    expect(result).toBeDefined();
    expect(result.jwt).toBeDefined();
    expect(typeof result.jwt).toBe('string');
  });

  it('should return JWT with three parts', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const result = await client.signJWT(kid, payload);
    const parts = result.jwt.split('.');

    expect(parts).toHaveLength(3);
  });

  it('should reject with non-existent kid', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    await expect(async () => {
      await client.signJWT('non-existent-kid', payload);
    }).rejects.toThrow();
  });
});

describe('Client RPC Bridge - getPublicKey', () => {
  let client: KMSClient;
  let kid: string;
  let publicKey: string;

  beforeEach(async () => {
    client = new KMSClient();
    const result = await client.generateVAPID();
    kid = result.kid;
    publicKey = result.publicKey;
  });

  afterEach(() => {
    client.destroy();
  });

  it('should have getPublicKey method', () => {
    expect(typeof client.getPublicKey).toBe('function');
  });

  it('should return a promise', () => {
    const result = client.getPublicKey(kid);
    expect(result).toBeInstanceOf(Promise);
  });

  it('should retrieve public key for valid kid', async () => {
    const result = await client.getPublicKey(kid);

    expect(result).toBeDefined();
    expect(result.publicKey).toBe(publicKey);
  });

  it('should return null for non-existent kid', async () => {
    const result = await client.getPublicKey('non-existent-kid');
    expect(result.publicKey).toBeNull();
  });
});

describe('Client RPC Bridge - Error Handling', () => {
  let client: KMSClient;

  beforeEach(() => {
    client = new KMSClient();
  });

  afterEach(() => {
    client.destroy();
  });

  it('should handle worker errors gracefully', async () => {
    // Try to sign with non-existent key
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    await expect(async () => {
      await client.signJWT('invalid-kid', payload);
    }).rejects.toThrow();
  });

  it('should include error message from worker', async () => {
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    try {
      await client.signJWT('non-existent-key', payload);
      expect.fail('Should have thrown an error');
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      if (error instanceof Error) {
        expect(error.message).toContain('No key found');
      }
    }
  });
});

describe('Client RPC Bridge - Request Correlation', () => {
  let client: KMSClient;

  beforeEach(() => {
    client = new KMSClient();
  });

  afterEach(() => {
    client.destroy();
  });

  it('should handle multiple concurrent requests', async () => {
    // Send multiple requests in parallel
    const promises = [
      client.generateVAPID(),
      client.generateVAPID(),
      client.generateVAPID(),
    ];

    const results = await Promise.all(promises);

    // All should succeed and have unique kids
    expect(results).toHaveLength(3);
    expect(results[0]?.kid).not.toBe(results[1]?.kid);
    expect(results[1]?.kid).not.toBe(results[2]?.kid);
    expect(results[0]?.kid).not.toBe(results[2]?.kid);
  });

  it('should handle mixed concurrent operations', async () => {
    // Generate a key first
    const vapid = await client.generateVAPID();

    // Then do mixed operations
    const payload: JWTPayload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const promises = [
      client.generateVAPID(),
      client.signJWT(vapid.kid, payload),
      client.getPublicKey(vapid.kid),
    ];

    const results = await Promise.all(promises);

    expect(results).toHaveLength(3);
    expect(results[0]).toHaveProperty('kid');
    expect(results[1]).toHaveProperty('jwt');
    expect(results[2]).toHaveProperty('publicKey');
  });
});
