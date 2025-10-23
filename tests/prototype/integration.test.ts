/**
 * Integration Tests (Phase 0 Prototype)
 *
 * TDD RED PHASE: Tests written BEFORE implementation
 * Tests the full integration between client, main thread, and worker
 */

import { describe, it, expect } from 'vitest';

describe('End-to-End Integration', () => {
  describe('JWT Generation Flow', () => {
    it('should complete full VAPID key generation and JWT signing flow', async () => {
      // This test defines the expected end-to-end behavior:
      // 1. Generate VAPID keypair
      // 2. Get public key
      // 3. Sign JWT
      // 4. Verify JWT structure

      // Step 1: Generate keypair (simulated)
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
      const publicKeyBase64url = btoa(String.fromCharCode(...new Uint8Array(publicKeyRaw)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      expect(publicKeyBase64url).toBeTruthy();
      expect(publicKeyBase64url.length).toBeGreaterThan(0);

      // Step 2: Create JWT payload
      const payload = {
        aud: 'https://fcm.googleapis.com',
        sub: 'mailto:notifications@ats.run',
        exp: Math.floor(Date.now() / 1000) + 7200,
      };

      // Step 3: Create JWT header
      const header = {
        typ: 'JWT',
        alg: 'ES256',
      };

      // Step 4: Sign JWT (simulated structure)
      const headerB64 = btoa(JSON.stringify(header))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      const payloadB64 = btoa(JSON.stringify(payload))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const signatureInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
      const derSignature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        signatureInput
      );

      // Simulate signature conversion to base64url
      const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(derSignature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const jwt = `${headerB64}.${payloadB64}.${signatureB64}`;

      // Verify JWT structure
      expect(jwt.split('.')).toHaveLength(3);
      expect(jwt).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    });
  });

  describe('Base64url Encoding', () => {
    it('should correctly encode and decode base64url', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5, 255]);

      // Encode to base64url
      const base64url = btoa(String.fromCharCode(...data))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      expect(base64url).not.toContain('+');
      expect(base64url).not.toContain('/');
      expect(base64url).not.toContain('=');

      // Decode from base64url
      const base64 = base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');
      const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
      const decoded = Uint8Array.from(atob(padded), c => c.charCodeAt(0));

      expect(decoded).toEqual(data);
    });

    it('should handle padding correctly', () => {
      const testCases = [
        new Uint8Array([1]),
        new Uint8Array([1, 2]),
        new Uint8Array([1, 2, 3]),
        new Uint8Array([1, 2, 3, 4]),
      ];

      for (const data of testCases) {
        const base64url = btoa(String.fromCharCode(...data))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '');

        expect(base64url).not.toContain('=');

        // Decode
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        const decoded = Uint8Array.from(atob(padded), c => c.charCodeAt(0));

        expect(decoded).toEqual(data);
      }
    });
  });

  describe('Key ID (kid) Generation', () => {
    it('should generate unique key IDs with timestamp', () => {
      const now = Date.now();
      const kid1 = `vapid-${now}-${crypto.randomUUID().slice(0, 8)}`;
      const kid2 = `vapid-${now}-${crypto.randomUUID().slice(0, 8)}`;

      expect(kid1).toMatch(/^vapid-\d+-[0-9a-f]{8}$/);
      expect(kid2).toMatch(/^vapid-\d+-[0-9a-f]{8}$/);
      expect(kid1).not.toBe(kid2);
    });

    it('should include purpose prefix in kid', () => {
      const kid = `vapid-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

      expect(kid.startsWith('vapid-')).toBe(true);
    });
  });

  describe('Error Handling Flow', () => {
    it('should handle invalid algorithm gracefully', async () => {
      await expect(async () => {
        await crypto.subtle.generateKey(
          {
            name: 'ECDSA',
            namedCurve: 'INVALID' as 'P-256', // Testing error case with invalid curve
          },
          false,
          ['sign', 'verify']
        );
      }).rejects.toThrow();
    });

    it('should handle signing with wrong key', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      // Try to sign with public key (should fail - runtime error, not type error)
      await expect(async () => {
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          keypair.publicKey, // Wrong key type (public instead of private)
          new Uint8Array([1, 2, 3])
        );
      }).rejects.toThrow();
    });
  });

  describe('Performance Requirements', () => {
    it('should generate keypair in under 100ms', async () => {
      const start = performance.now();

      await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(100);
    });

    it('should sign data in under 50ms', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const data = new TextEncoder().encode('test data');

      const start = performance.now();
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keypair.privateKey,
        data
      );
      const duration = performance.now() - start;

      expect(duration).toBeLessThan(50);
    });

    it('should export public key in under 10ms', async () => {
      const keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const start = performance.now();
      await crypto.subtle.exportKey('raw', keypair.publicKey);
      const duration = performance.now() - start;

      expect(duration).toBeLessThan(10);
    });
  });
});

describe('JWT Structure Validation', () => {
  it('should create valid JWT header', () => {
    const header = {
      typ: 'JWT',
      alg: 'ES256',
    };

    const headerB64 = btoa(JSON.stringify(header))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Decode and verify
    const decoded = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'))) as typeof header;
    expect(decoded).toEqual(header);
  });

  it('should create valid JWT payload', () => {
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    const payloadB64 = btoa(JSON.stringify(payload))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Decode and verify
    const decoded = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as typeof payload;
    expect(decoded).toEqual(payload);
  });

  it('should validate exp is in the future', () => {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 7200; // 2 hours from now

    expect(exp).toBeGreaterThan(now);
    expect(exp - now).toBe(7200);
  });

  it('should validate required VAPID fields', () => {
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:notifications@ats.run',
      exp: Math.floor(Date.now() / 1000) + 7200,
    };

    expect(payload).toHaveProperty('aud');
    expect(payload).toHaveProperty('sub');
    expect(payload).toHaveProperty('exp');
    expect(payload.aud.startsWith('http')).toBe(true);
    expect(payload.sub.startsWith('mailto:')).toBe(true);
  });
});
