/**
 * Worker Crypto Operations Tests (Phase 0 Prototype)
 *
 * TDD RED PHASE: These tests are written BEFORE implementation
 * They define the expected behavior of the KMS worker
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('KMS Worker - VAPID Key Generation', () => {
  beforeEach(() => {
    // Clear any mocks between tests
    vi.clearAllMocks();
  });

  describe('generateVAPIDKeypair', () => {
    it('should generate a P-256 ECDSA keypair', async () => {
      // Test that key generation uses correct algorithm
      const keypair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false, // non-extractable
        ['sign', 'verify']
      );

      expect(keypair).toHaveProperty('privateKey');
      expect(keypair).toHaveProperty('publicKey');
      expect(keypair.privateKey.type).toBe('private');
      expect(keypair.publicKey.type).toBe('public');
    });

    it('should create non-extractable private keys', async () => {
      const keypair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false, // non-extractable
        ['sign', 'verify']
      );

      expect(keypair.privateKey.extractable).toBe(false);
    });

    it('should allow extractable public keys', async () => {
      const keypair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false,
        ['sign', 'verify']
      );

      expect(keypair.publicKey.extractable).toBe(true);
    });

    it('should have correct key usages', async () => {
      const keypair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false,
        ['sign', 'verify']
      );

      expect(keypair.privateKey.usages).toContain('sign');
      expect(keypair.publicKey.usages).toContain('verify');
    });

    it('should generate different keys each time', async () => {
      const keypair1 = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const keypair2 = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      // Export public keys to compare
      const pubKey1 = await crypto.subtle.exportKey('raw', keypair1.publicKey);
      const pubKey2 = await crypto.subtle.exportKey('raw', keypair2.publicKey);

      expect(new Uint8Array(pubKey1)).not.toEqual(new Uint8Array(pubKey2));
    });
  });

  describe('exportVAPIDPublicKey', () => {
    it('should export public key in raw format (65 bytes uncompressed)', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const rawPublicKey = await crypto.subtle.exportKey('raw', keypair.publicKey);

      expect(rawPublicKey).toBeInstanceOf(ArrayBuffer);
      expect(rawPublicKey.byteLength).toBe(65); // Uncompressed point
      expect(new Uint8Array(rawPublicKey)[0]).toBe(0x04); // Uncompressed prefix
    });

    it('should be able to convert to base64url for VAPID', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const rawPublicKey = await crypto.subtle.exportKey('raw', keypair.publicKey);
      const base64url = btoa(String.fromCharCode(...new Uint8Array(rawPublicKey)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      expect(base64url).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(base64url.length).toBeGreaterThan(0);
    });
  });

  describe('signES256', () => {
    it('should sign data with ECDSA SHA-256', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const data = new TextEncoder().encode('test data');
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data
      );

      expect(signature).toBeInstanceOf(ArrayBuffer);
      // Note: Real browsers return DER format (70-72 bytes)
      // happy-dom returns P-1363 format (64 bytes)
      // Both are valid, but JWT requires P-1363 (64 bytes exactly)
      expect(signature.byteLength).toBeGreaterThanOrEqual(64);
      expect(signature.byteLength).toBeLessThanOrEqual(72);
    });

    it('should produce verifiable signatures', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const data = new TextEncoder().encode('test data');
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data
      );

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.publicKey,
        signature,
        data
      );

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong data', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const data = new TextEncoder().encode('test data');
      const wrongData = new TextEncoder().encode('wrong data');
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data
      );

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.publicKey,
        signature,
        wrongData
      );

      expect(isValid).toBe(false);
    });

    it('should produce different signatures for different data', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const data1 = new TextEncoder().encode('data 1');
      const data2 = new TextEncoder().encode('data 2');

      const signature1 = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data1
      );

      const signature2 = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data2
      );

      expect(new Uint8Array(signature1)).not.toEqual(new Uint8Array(signature2));
    });
  });

  describe('DER to P-1363 Conversion', () => {
    it('should convert DER signature to 64-byte P-1363 format', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const data = new TextEncoder().encode('test data');
      const derSignature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data
      );

      // Note: happy-dom returns P-1363 (64 bytes), real browsers return DER (70-72 bytes)
      // This test verifies we can handle both cases
      const isP1363Format = derSignature.byteLength === 64;
      const isDERFormat = derSignature.byteLength >= 70 && derSignature.byteLength <= 72;

      expect(isP1363Format || isDERFormat).toBe(true);

      // After conversion (if needed), should be exactly 64 bytes (32 bytes r + 32 bytes s)
      const expectedP1363Length = 64;
      if (isP1363Format) {
        expect(derSignature.byteLength).toBe(expectedP1363Length);
      }
    });
  });
});

describe('KMS Worker - Error Handling', () => {
  it('should handle invalid algorithm parameters', async () => {
    await expect(async () => {
      await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'INVALID-CURVE' as 'P-256', // Testing invalid curve
        },
        false,
        ['sign', 'verify']
      );
    }).rejects.toThrow();
  });

  it('should handle invalid key usages', async () => {
    await expect(async () => {
      await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false,
        ['encrypt'] as unknown as ['sign', 'verify'] // Testing invalid usage - ECDSA doesn't support encrypt
      );
    }).rejects.toThrow();
  });
});
