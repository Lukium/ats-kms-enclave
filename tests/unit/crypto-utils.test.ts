/**
 * Unit tests for crypto-utils module
 *
 * Tests DER/P-1363 conversion, JWK thumbprints, and key format conversion
 */

import { describe, it, expect } from 'vitest';
import {
  derToP1363,
  p1363ToDer,
  detectSignatureFormat,
  jwkThumbprintP256,
  rawP256ToJwk,
  jwkToRawP256,
  arrayBufferToBase64url,
  base64urlToArrayBuffer,
} from '../../src/crypto-utils.js';

describe('DER ↔ P-1363 Signature Conversion', () => {
  // Test data: Valid P-1363 signature (64 bytes)
  const validP1363 = new Uint8Array(64).fill(0xAB);
  validP1363[0] = 0x7F; // Not 0x30 (to distinguish from DER)

  // Test data: Valid DER signature (70 bytes)
  // DER format: 0x30 [total-length] 0x02 [r-length] [r-value] 0x02 [s-length] [s-value]
  const validDER70 = new Uint8Array([
    0x30, 0x44, // SEQUENCE, length 68
    0x02, 0x20, // INTEGER, length 32 (r)
    ...(new Array(32).fill(0xAB) as number[]),
    0x02, 0x20, // INTEGER, length 32 (s)
    ...(new Array(32).fill(0xCD) as number[]),
  ]);

  // Test data: DER signature with padding (72 bytes) - high bit set requiring 0x00 prefix
  const validDER72 = new Uint8Array([
    0x30, 0x46, // SEQUENCE, length 70
    0x02, 0x21, // INTEGER, length 33 (r with padding)
    0x00, // Padding byte
    ...(new Array(32).fill(0xFF) as number[]), // High bit set
    0x02, 0x21, // INTEGER, length 33 (s with padding)
    0x00, // Padding byte
    ...(new Array(32).fill(0x80) as number[]), // High bit set
  ]);

  describe('derToP1363', () => {
    it('should convert 70-byte DER to 64-byte P-1363', () => {
      const result = derToP1363(validDER70);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64);
      expect(result[0]).toBe(0xAB); // First byte of r
      expect(result[32]).toBe(0xCD); // First byte of s
    });

    it('should convert 72-byte DER (with padding) to 64-byte P-1363', () => {
      const result = derToP1363(validDER72);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64);
      // Should strip the 0x00 padding bytes
      expect(result[0]).toBe(0xFF); // First byte of r (after stripping 0x00)
      expect(result[32]).toBe(0x80); // First byte of s (after stripping 0x00)
    });

    it('should throw on invalid DER (wrong leading byte)', () => {
      const invalidDER = new Uint8Array([0x31, 0x44, ...(new Array(68).fill(0) as number[])]);

      expect(() => derToP1363(invalidDER)).toThrow('Invalid DER signature: must start with 0x30');
    });

    it('should throw on invalid DER (length mismatch)', () => {
      const invalidDER = new Uint8Array([
        0x30, 0x50, // Claims length 80 but array is shorter
        ...(new Array(68).fill(0) as number[]),
      ]);

      expect(() => derToP1363(invalidDER)).toThrow('Invalid DER signature: length mismatch');
    });

    it('should throw on invalid DER (r not INTEGER)', () => {
      const invalidDER = new Uint8Array([
        0x30, 0x44,
        0x03, 0x20, // Wrong tag (0x03 instead of 0x02)
        ...(new Array(66).fill(0) as number[]),
      ]);

      expect(() => derToP1363(invalidDER)).toThrow('Invalid DER signature: r value must start with 0x02');
    });

    it('should throw on invalid DER (s not INTEGER)', () => {
      const invalidDER = new Uint8Array([
        0x30, 0x44,
        0x02, 0x20, ...(new Array(32).fill(0) as number[]),
        0x03, 0x20, // Wrong tag for s
        ...(new Array(32).fill(0) as number[]),
      ]);

      expect(() => derToP1363(invalidDER)).toThrow('Invalid DER signature: s value must start with 0x02');
    });

    it('should pad r to 32 bytes when r is shorter', () => {
      // DER with short r value (only 31 bytes, with leading zero stripped)
      const shortRDER = new Uint8Array([
        0x30, 0x43, // SEQUENCE, length 67
        0x02, 0x1F, // INTEGER, length 31 (short r)
        ...(new Array(31).fill(0x01) as number[]), // 31 bytes (will be < 32 after processing)
        0x02, 0x20, // INTEGER, length 32 (normal s)
        ...(new Array(32).fill(0xCD) as number[]),
      ]);

      const result = derToP1363(shortRDER);
      expect(result.length).toBe(64);
      // First byte should be 0 (padding), then 0x01
      expect(result[0]).toBe(0x00); // Padding
      expect(result[1]).toBe(0x01); // First byte of actual r value
      expect(result[32]).toBe(0xCD); // First byte of s
    });

    it('should pad s to 32 bytes when s is shorter', () => {
      // DER with short s value (only 31 bytes)
      const shortSDER = new Uint8Array([
        0x30, 0x43, // SEQUENCE, length 67
        0x02, 0x20, // INTEGER, length 32 (normal r)
        ...(new Array(32).fill(0xAB) as number[]),
        0x02, 0x1F, // INTEGER, length 31 (short s)
        ...(new Array(31).fill(0x02) as number[]), // 31 bytes
      ]);

      const result = derToP1363(shortSDER);
      expect(result.length).toBe(64);
      expect(result[0]).toBe(0xAB); // First byte of r
      // s should be padded: first byte is 0 (padding), then 0x02
      expect(result[32]).toBe(0x00); // Padding
      expect(result[33]).toBe(0x02); // First byte of actual s value
    });

    it('should pad both r and s when both are shorter', () => {
      // DER with both r and s being short (31 bytes each)
      const shortBothDER = new Uint8Array([
        0x30, 0x42, // SEQUENCE, length 66
        0x02, 0x1F, // INTEGER, length 31 (short r)
        ...(new Array(31).fill(0x03) as number[]),
        0x02, 0x1F, // INTEGER, length 31 (short s)
        ...(new Array(31).fill(0x04) as number[]),
      ]);

      const result = derToP1363(shortBothDER);
      expect(result.length).toBe(64);
      // r should be padded
      expect(result[0]).toBe(0x00); // Padding
      expect(result[1]).toBe(0x03); // First byte of actual r
      // s should be padded
      expect(result[32]).toBe(0x00); // Padding
      expect(result[33]).toBe(0x04); // First byte of actual s
    });
  });

  describe('p1363ToDer', () => {
    it('should convert 64-byte P-1363 to DER', () => {
      const result = p1363ToDer(validP1363);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result[0]).toBe(0x30); // SEQUENCE
      expect(result.length).toBeGreaterThanOrEqual(70);
      expect(result.length).toBeLessThanOrEqual(72);
    });

    it('should add padding when high bit is set', () => {
      const p1363WithHighBit = new Uint8Array(64);
      p1363WithHighBit.fill(0xFF); // All bytes have high bit set

      const result = p1363ToDer(p1363WithHighBit);

      // Should be 72 bytes due to padding
      expect(result.length).toBe(72);
      expect(result[0]).toBe(0x30); // SEQUENCE
      expect(result[1]).toBe(70); // Total length
      expect(result[2]).toBe(0x02); // INTEGER tag for r
      expect(result[3]).toBe(33); // Length of r (32 + 1 padding)
      expect(result[4]).toBe(0x00); // Padding byte
    });

    it('should round-trip correctly (P-1363 → DER → P-1363)', () => {
      const der = p1363ToDer(validP1363);
      const roundtrip = derToP1363(der);

      expect(roundtrip).toEqual(validP1363);
    });

    it('should round-trip correctly (DER → P-1363 → DER)', () => {
      const p1363 = derToP1363(validDER70);
      const roundtrip = p1363ToDer(p1363);

      // Lengths might differ due to padding, but conversion should be valid
      expect(roundtrip[0]).toBe(0x30);
      expect(derToP1363(roundtrip)).toEqual(p1363);
    });

    it('should throw on invalid length', () => {
      const invalid = new Uint8Array(63); // Wrong length

      expect(() => p1363ToDer(invalid)).toThrow('Invalid P-1363 signature: must be 64 bytes');
    });
  });

  describe('detectSignatureFormat', () => {
    it('should detect P-1363 format (64 bytes, not starting with 0x30)', () => {
      const format = detectSignatureFormat(validP1363);
      expect(format).toBe('P-1363');
    });

    it('should detect DER format (70 bytes, starting with 0x30)', () => {
      const format = detectSignatureFormat(validDER70);
      expect(format).toBe('DER');
    });

    it('should detect DER format (72 bytes, starting with 0x30)', () => {
      const format = detectSignatureFormat(validDER72);
      expect(format).toBe('DER');
    });

    it('should detect DER format (71 bytes)', () => {
      const der71 = new Uint8Array([
        0x30, 0x45,
        0x02, 0x21, 0x00, ...(new Array(32).fill(0xAB) as number[]),
        0x02, 0x20, ...(new Array(32).fill(0xCD) as number[]),
      ]);
      const format = detectSignatureFormat(der71);
      expect(format).toBe('DER');
    });

    it('should return UNKNOWN for invalid format (wrong length)', () => {
      const invalid = new Uint8Array(65);
      const format = detectSignatureFormat(invalid);
      expect(format).toBe('UNKNOWN');
    });

    it('should return UNKNOWN for 64 bytes starting with 0x30', () => {
      const ambiguous = new Uint8Array(64);
      ambiguous[0] = 0x30;
      const format = detectSignatureFormat(ambiguous);
      expect(format).toBe('UNKNOWN');
    });
  });
});

describe('JWK Thumbprint (RFC 7638)', () => {
  // Test JWK from RFC 7638 example (different curve, but same structure)
  const testJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
    y: 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
  };

  describe('jwkThumbprintP256', () => {
    it('should compute JWK thumbprint', async () => {
      const thumbprint = await jwkThumbprintP256(testJwk);

      expect(thumbprint).toBeTruthy();
      expect(typeof thumbprint).toBe('string');
      // Base64url-encoded SHA-256 hash should be 43 characters
      expect(thumbprint.length).toBe(43);
      expect(thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    it('should be deterministic (same input = same output)', async () => {
      const thumbprint1 = await jwkThumbprintP256(testJwk);
      const thumbprint2 = await jwkThumbprintP256(testJwk);

      expect(thumbprint1).toBe(thumbprint2);
    });

    it('should produce different thumbprints for different keys', async () => {
      const jwk1 = { ...testJwk };
      const jwk2 = {
        ...testJwk,
        x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      };

      const thumbprint1 = await jwkThumbprintP256(jwk1);
      const thumbprint2 = await jwkThumbprintP256(jwk2);

      expect(thumbprint1).not.toBe(thumbprint2);
    });

    it('should be order-independent (fields can be in any order)', async () => {
      const jwk1 = { kty: 'EC', crv: 'P-256', x: testJwk.x, y: testJwk.y };
      const jwk2 = { y: testJwk.y, x: testJwk.x, crv: 'P-256', kty: 'EC' };

      const thumbprint1 = await jwkThumbprintP256(jwk1);
      const thumbprint2 = await jwkThumbprintP256(jwk2);

      // RFC 7638 specifies canonical ordering, so these should match
      expect(thumbprint1).toBe(thumbprint2);
    });
  });
});

describe('Raw ↔ JWK Conversion', () => {
  // Valid raw P-256 public key (65 bytes: 0x04 || x (32 bytes) || y (32 bytes))
  const validRawKey = new Uint8Array(65);
  validRawKey[0] = 0x04; // Uncompressed point indicator
  for (let i = 1; i < 33; i++) validRawKey[i] = 0xAA; // x coordinate
  for (let i = 33; i < 65; i++) validRawKey[i] = 0xBB; // y coordinate

  describe('rawP256ToJwk', () => {
    it('should convert raw P-256 to JWK', () => {
      const jwk = rawP256ToJwk(validRawKey);

      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeTruthy();
      expect(jwk.y).toBeTruthy();
      // Base64url of 32 bytes should be 43 characters
      expect(jwk.x.length).toBe(43);
      expect(jwk.y.length).toBe(43);
    });

    it('should throw on invalid length', () => {
      const invalid = new Uint8Array(64); // Wrong length

      expect(() => rawP256ToJwk(invalid)).toThrow('Invalid raw P-256 public key: must be 65 bytes');
    });

    it('should throw on invalid leading byte', () => {
      const invalid = new Uint8Array(65);
      invalid[0] = 0x03; // Wrong leading byte

      expect(() => rawP256ToJwk(invalid)).toThrow('Invalid raw P-256 public key: must start with 0x04');
    });
  });

  describe('jwkToRawP256', () => {
    const validJwk = rawP256ToJwk(validRawKey);

    it('should convert JWK to raw P-256', () => {
      const raw = jwkToRawP256(validJwk);

      expect(raw).toBeInstanceOf(Uint8Array);
      expect(raw.length).toBe(65);
      expect(raw[0]).toBe(0x04); // Uncompressed point
    });

    it('should round-trip correctly (raw → JWK → raw)', () => {
      const jwk = rawP256ToJwk(validRawKey);
      const roundtrip = jwkToRawP256(jwk);

      expect(roundtrip).toEqual(validRawKey);
    });

    it('should throw on invalid key type', () => {
      const invalid = { ...validJwk, kty: 'RSA' };

      expect(() => jwkToRawP256(invalid)).toThrow('JWK must be EC P-256');
    });

    it('should throw on invalid curve', () => {
      const invalid = { ...validJwk, crv: 'P-384' };

      expect(() => jwkToRawP256(invalid)).toThrow('JWK must be EC P-256');
    });

    it('should throw on invalid coordinate length', () => {
      const invalid = {
        kty: 'EC',
        crv: 'P-256',
        x: 'AA', // Too short
        y: validJwk.y,
      };

      expect(() => jwkToRawP256(invalid)).toThrow('Invalid JWK: x and y must be 32 bytes each');
    });
  });
});

describe('Base64url Utilities', () => {
  const testData = new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"
  const testB64url = 'SGVsbG8'; // "Hello" in base64url

  describe('arrayBufferToBase64url', () => {
    it('should encode Uint8Array to base64url', () => {
      const result = arrayBufferToBase64url(testData);

      expect(result).toBe(testB64url);
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
      expect(result).not.toContain('=');
    });

    it('should encode ArrayBuffer to base64url', () => {
      const result = arrayBufferToBase64url(testData.buffer);

      expect(result).toBe(testB64url);
    });

    it('should handle empty data', () => {
      const result = arrayBufferToBase64url(new Uint8Array(0));
      expect(result).toBe('');
    });

    it('should use URL-safe characters', () => {
      // Data that would produce + and / in standard base64
      const data = new Uint8Array([0xFB, 0xFF, 0xBF]);
      const result = arrayBufferToBase64url(data);

      expect(result).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
      expect(result).not.toContain('=');
    });
  });

  describe('base64urlToArrayBuffer', () => {
    it('should decode base64url to ArrayBuffer', () => {
      const result = base64urlToArrayBuffer(testB64url);
      const bytes = new Uint8Array(result);

      expect(bytes).toEqual(testData);
    });

    it('should handle empty string', () => {
      const result = base64urlToArrayBuffer('');
      expect(result.byteLength).toBe(0);
    });

    it('should handle padding correctly (add missing padding)', () => {
      // Base64url without padding
      const withoutPadding = 'SGVsbG8'; // "Hello" (no padding needed)
      const result1 = base64urlToArrayBuffer(withoutPadding);
      expect(new Uint8Array(result1)).toEqual(testData);

      // Data that needs padding
      const needsPadding = 'YQ'; // "a" in base64url (would be "YQ==" in base64)
      const result2 = base64urlToArrayBuffer(needsPadding);
      expect(new Uint8Array(result2)).toEqual(new Uint8Array([0x61])); // 'a'
    });

    it('should round-trip correctly', () => {
      const original = new Uint8Array(32);
      for (let i = 0; i < 32; i++) original[i] = i;

      const encoded = arrayBufferToBase64url(original);
      const decoded = new Uint8Array(base64urlToArrayBuffer(encoded));

      expect(decoded).toEqual(original);
    });

    it('should handle URL-safe characters (convert - to + and _ to /)', () => {
      const b64url = '-_-_'; // URL-safe version of "+/+/"
      const result = base64urlToArrayBuffer(b64url);

      // Should decode without errors
      expect(result).toBeInstanceOf(ArrayBuffer);
    });
  });

  describe('Round-trip encoding', () => {
    it('should round-trip various data sizes', () => {
      for (const size of [0, 1, 15, 16, 31, 32, 63, 64, 100]) {
        const original = new Uint8Array(size);
        for (let i = 0; i < size; i++) original[i] = (i * 7) % 256;

        const encoded = arrayBufferToBase64url(original);
        const decoded = new Uint8Array(base64urlToArrayBuffer(encoded));

        expect(decoded).toEqual(original);
      }
    });

    it('should round-trip binary data', () => {
      const binary = new Uint8Array(256);
      for (let i = 0; i < 256; i++) binary[i] = i;

      const encoded = arrayBufferToBase64url(binary);
      const decoded = new Uint8Array(base64urlToArrayBuffer(encoded));

      expect(decoded).toEqual(binary);
    });
  });
});

describe('Integration: Full cryptographic workflow', () => {
  it('should handle complete key generation and thumbprint workflow', async () => {
    // Simulate generating a P-256 key (using Web Crypto API)
    const keypair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    );

    // Export public key in raw format
    const rawPublicKey = await crypto.subtle.exportKey('raw', keypair.publicKey);
    const rawBytes = new Uint8Array(rawPublicKey);

    // Convert to JWK
    const jwk = rawP256ToJwk(rawBytes);

    // Compute thumbprint
    const thumbprint = await jwkThumbprintP256(jwk);

    // Verify thumbprint format
    expect(thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // Round-trip conversion
    const reconstructedRaw = jwkToRawP256(jwk);
    expect(reconstructedRaw).toEqual(rawBytes);
  });

  it('should handle complete signature conversion workflow', async () => {
    // Generate a signature (this will be in implementation-specific format)
    const keypair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['sign']
    );

    const data = new TextEncoder().encode('test data');
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keypair.privateKey,
      data
    );

    const sigBytes = new Uint8Array(signature);
    const format = detectSignatureFormat(sigBytes);

    // Depending on environment (happy-dom vs real browser), format will vary
    if (format === 'DER') {
      // Convert to P-1363
      const p1363 = derToP1363(sigBytes);
      expect(p1363.length).toBe(64);

      // Convert back to DER
      const der = p1363ToDer(p1363);
      expect(der[0]).toBe(0x30);

      // Round-trip should work
      expect(derToP1363(der)).toEqual(p1363);
    } else if (format === 'P-1363') {
      // Already correct format
      expect(sigBytes.length).toBe(64);

      // Can convert to DER and back
      const der = p1363ToDer(sigBytes);
      const roundtrip = derToP1363(der);
      expect(roundtrip).toEqual(sigBytes);
    }
  });
});
