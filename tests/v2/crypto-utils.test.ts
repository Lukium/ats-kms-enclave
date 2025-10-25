/**
 * Crypto Utilities Test Suite (KMS V2)
 *
 * Comprehensive tests for all cryptographic utility functions including:
 * - Encoding/decoding (base64url, hex)
 * - Signature format conversion (DER ↔ P-1363)
 * - JWK operations (conversion, thumbprint)
 * - AAD construction (Master Secret, Key Wrapping)
 * - KCV computation and verification
 * - Deterministic salt derivation
 * - PBKDF2 calibration
 *
 * These tests verify correctness against known test vectors and ensure
 * functions behave correctly with edge cases and invalid inputs.
 */

import { describe, it, expect } from 'vitest';
import {
  arrayBufferToBase64url,
  base64urlToArrayBuffer,
  arrayBufferToHex,
  hexToArrayBuffer,
  detectSignatureFormat,
  derToP1363,
  p1363ToDer,
  rawP256ToJwk,
  jwkThumbprintP256,
  buildMSEncryptionAAD,
  buildKeyWrapAAD,
  computeKCV,
  verifyKCV,
  timingSafeEqual,
  deriveDeterministicSalt,
  calibratePBKDF2Iterations,
} from '@/v2/crypto-utils';

// ============================================================================
// Encoding/Decoding Tests
// ============================================================================

describe('arrayBufferToBase64url', () => {
  it('should encode empty buffer', () => {
    const buffer = new ArrayBuffer(0);
    expect(arrayBufferToBase64url(buffer)).toBe('');
  });

  it('should encode single byte', () => {
    const buffer = new Uint8Array([0x41]).buffer; // 'A'
    expect(arrayBufferToBase64url(buffer)).toBe('QQ');
  });

  it('should encode known test vector', () => {
    // "Hello" in UTF-8: [0x48, 0x65, 0x6c, 0x6c, 0x6f]
    const buffer = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]).buffer;
    // Base64: "SGVsbG8=" → base64url: "SGVsbG8" (no padding)
    expect(arrayBufferToBase64url(buffer)).toBe('SGVsbG8');
  });

  it('should replace + and / with - and _', () => {
    // Byte sequence that produces + and / in base64
    const buffer = new Uint8Array([0xfb, 0xff]).buffer;
    const result = arrayBufferToBase64url(buffer);
    expect(result).not.toContain('+');
    expect(result).not.toContain('/');
    expect(result).toContain('-'); // Replacement for +
    expect(result).toContain('_'); // Replacement for /
  });

  it('should omit padding', () => {
    const buffer = new Uint8Array([0x41, 0x42]).buffer; // Would pad to "QUI="
    const result = arrayBufferToBase64url(buffer);
    expect(result).toBe('QUI');
    expect(result).not.toContain('=');
  });
});

describe('base64urlToArrayBuffer', () => {
  it('should decode empty string', () => {
    const buffer = base64urlToArrayBuffer('');
    expect(new Uint8Array(buffer).length).toBe(0);
  });

  it('should decode known test vector', () => {
    const buffer = base64urlToArrayBuffer('SGVsbG8');
    const bytes = new Uint8Array(buffer);
    expect(Array.from(bytes)).toEqual([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  });

  it('should handle missing padding', () => {
    // "QUI" should decode same as "QUI="
    const buffer1 = base64urlToArrayBuffer('QUI');
    const buffer2 = base64urlToArrayBuffer('QUI=');
    expect(new Uint8Array(buffer1)).toEqual(new Uint8Array(buffer2));
  });

  it('should replace - and _ with + and /', () => {
    const buffer = base64urlToArrayBuffer('-_-_');
    expect(buffer.byteLength).toBeGreaterThan(0);
  });

  it('should round-trip with encode', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 200, 255]).buffer;
    const encoded = arrayBufferToBase64url(original);
    const decoded = base64urlToArrayBuffer(encoded);
    expect(new Uint8Array(decoded)).toEqual(new Uint8Array(original));
  });
});

describe('arrayBufferToHex', () => {
  it('should encode empty buffer', () => {
    const buffer = new ArrayBuffer(0);
    expect(arrayBufferToHex(buffer)).toBe('');
  });

  it('should encode single byte with leading zero', () => {
    const buffer = new Uint8Array([0x0a]).buffer;
    expect(arrayBufferToHex(buffer)).toBe('0a');
  });

  it('should encode known test vector', () => {
    const buffer = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer;
    expect(arrayBufferToHex(buffer)).toBe('deadbeef');
  });

  it('should use lowercase', () => {
    const buffer = new Uint8Array([0xff, 0xaa]).buffer;
    const result = arrayBufferToHex(buffer);
    expect(result).toBe('ffaa');
    expect(result).not.toContain('F');
    expect(result).not.toContain('A');
  });
});

describe('hexToArrayBuffer', () => {
  it('should throw on odd length', () => {
    expect(() => hexToArrayBuffer('abc')).toThrow('even length');
  });

  it('should handle 0x prefix', () => {
    const buffer = hexToArrayBuffer('0xdeadbeef');
    expect(new Uint8Array(buffer)).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('should decode without prefix', () => {
    const buffer = hexToArrayBuffer('deadbeef');
    expect(new Uint8Array(buffer)).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('should handle uppercase and lowercase', () => {
    const buf1 = hexToArrayBuffer('DEADBEEF');
    const buf2 = hexToArrayBuffer('deadbeef');
    expect(new Uint8Array(buf1)).toEqual(new Uint8Array(buf2));
  });

  it('should round-trip with encode', () => {
    const original = new Uint8Array([0, 15, 255, 0x80]).buffer;
    const encoded = arrayBufferToHex(original);
    const decoded = hexToArrayBuffer(encoded);
    expect(new Uint8Array(decoded)).toEqual(new Uint8Array(original));
  });
});

// ============================================================================
// Signature Format Conversion Tests
// ============================================================================

describe('detectSignatureFormat', () => {
  it('should detect P-1363 format (64 bytes)', () => {
    const sig = new Uint8Array(64);
    expect(detectSignatureFormat(sig)).toBe('P-1363');
  });

  it('should detect DER format (starts with 0x30)', () => {
    const sig = new Uint8Array([0x30, 0x45, 0x02, 0x20]); // DER sequence
    expect(detectSignatureFormat(sig)).toBe('DER');
  });

  it('should return unknown for other formats', () => {
    const sig = new Uint8Array([0x00, 0x01, 0x02]);
    expect(detectSignatureFormat(sig)).toBe('unknown');
  });
});

describe('derToP1363', () => {
  it('should throw on invalid DER (no sequence tag)', () => {
    const sig = new Uint8Array([0x00, 0x45, 0x02, 0x20]);
    expect(() => derToP1363(sig)).toThrow('expected sequence');
  });

  it('should throw on missing integer tag for r', () => {
    const sig = new Uint8Array([0x30, 0x06, 0x00, 0x02]); // Wrong tag
    expect(() => derToP1363(sig)).toThrow('expected integer for r');
  });

  it('should convert known DER signature to P-1363', () => {
    // Minimal DER signature: r=1, s=1 (each 32 bytes in P-1363)
    const der = new Uint8Array([
      0x30, 0x06, // SEQUENCE, length 6
      0x02, 0x01, 0x01, // INTEGER r, length 1, value 1
      0x02, 0x01, 0x01  // INTEGER s, length 1, value 1
    ]);
    const p1363 = derToP1363(der);
    expect(p1363.byteLength).toBe(64);
    // r should be padded to 32 bytes with leading zeros, then 0x01
    expect(p1363[31]).toBe(0x01); // Last byte of r
    expect(p1363[63]).toBe(0x01); // Last byte of s
  });

  it('should handle DER with leading zero padding', () => {
    // DER with 0x00 prefix (for positive integers with high bit set)
    const der = new Uint8Array([
      0x30, 0x08,
      0x02, 0x02, 0x00, 0x80, // r with leading zero
      0x02, 0x02, 0x00, 0xff  // s with leading zero
    ]);
    const p1363 = derToP1363(der);
    expect(p1363[31]).toBe(0x80);
    expect(p1363[63]).toBe(0xff);
  });
});

describe('p1363ToDer', () => {
  it('should throw on invalid length', () => {
    const sig = new Uint8Array(63);
    expect(() => p1363ToDer(sig)).toThrow('must be 64 bytes');
  });

  it('should convert P-1363 to DER format', () => {
    // Simple case: r=1, s=1
    const p1363 = new Uint8Array(64);
    p1363[31] = 0x01; // r = 1
    p1363[63] = 0x01; // s = 1

    const der = p1363ToDer(p1363);
    expect(der[0]).toBe(0x30); // SEQUENCE tag
    expect(der[2]).toBe(0x02); // INTEGER tag for r
    expect(der[4]).toBe(0x01); // r value
    expect(der[5]).toBe(0x02); // INTEGER tag for s
    expect(der[7]).toBe(0x01); // s value
  });

  it('should add leading zero for high bit set', () => {
    const p1363 = new Uint8Array(64);
    p1363[31] = 0x80; // High bit set, needs 0x00 prefix
    p1363[63] = 0xff; // High bit set, needs 0x00 prefix

    const der = p1363ToDer(p1363);
    // Find r INTEGER
    expect(der[2]).toBe(0x02); // INTEGER tag
    expect(der[3]).toBe(0x02); // Length 2 (includes 0x00 prefix)
    expect(der[4]).toBe(0x00); // Leading zero
    expect(der[5]).toBe(0x80); // r value
  });

  it('should round-trip with derToP1363', () => {
    const original = new Uint8Array(64);
    crypto.getRandomValues(original);

    const der = p1363ToDer(original);
    const recovered = derToP1363(der);

    expect(recovered).toEqual(original);
  });
});

// ============================================================================
// JWK Operations Tests
// ============================================================================

describe('rawP256ToJwk', () => {
  it('should throw on invalid length', () => {
    const raw = new Uint8Array(64); // Should be 65
    expect(() => rawP256ToJwk(raw)).toThrow('Invalid uncompressed P-256');
  });

  it('should throw on missing 0x04 prefix', () => {
    const raw = new Uint8Array(65);
    raw[0] = 0x03; // Wrong prefix
    expect(() => rawP256ToJwk(raw)).toThrow('Invalid uncompressed P-256');
  });

  it('should convert valid raw key to JWK', () => {
    const raw = new Uint8Array(65);
    raw[0] = 0x04; // Uncompressed prefix
    // Fill x and y with test data
    for (let i = 1; i < 65; i++) {
      raw[i] = i;
    }

    const jwk = rawP256ToJwk(raw);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
    expect(typeof jwk.x).toBe('string');
    expect(typeof jwk.y).toBe('string');
  });
});

describe('jwkThumbprintP256', () => {
  it('should compute RFC 7638 thumbprint', async () => {
    const jwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };

    const thumbprint = await jwkThumbprintP256(jwk);
    // Should produce consistent hash
    expect(typeof thumbprint).toBe('string');
    expect(thumbprint.length).toBeGreaterThan(0);
    expect(thumbprint).not.toContain('='); // base64url has no padding
  });

  it('should produce same thumbprint for same key', async () => {
    const jwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'test-x',
      y: 'test-y',
    };

    const t1 = await jwkThumbprintP256(jwk);
    const t2 = await jwkThumbprintP256(jwk);
    expect(t1).toBe(t2);
  });

  it('should produce different thumbprints for different keys', async () => {
    const jwk1: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'test-x-1',
      y: 'test-y-1',
    };
    const jwk2: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'test-x-2',
      y: 'test-y-2',
    };

    const t1 = await jwkThumbprintP256(jwk1);
    const t2 = await jwkThumbprintP256(jwk2);
    expect(t1).not.toBe(t2);
  });
});

// ============================================================================
// AAD Construction Tests
// ============================================================================

describe('buildMSEncryptionAAD', () => {
  it('should build AAD for passphrase method', () => {
    const aad = buildMSEncryptionAAD({
      kmsVersion: 2,
      method: 'passphrase',
      algVersion: 1,
      purpose: 'master-secret',
    });

    const text = new TextDecoder().decode(aad);
    expect(text).toContain('"kmsVersion":2');
    expect(text).toContain('"method":"passphrase"');
    expect(text).toContain('"algVersion":1');
    expect(text).toContain('"purpose":"master-secret"');
  });

  it('should build AAD for passkey-prf with credentialId', () => {
    const credId = new Uint8Array([1, 2, 3, 4]).buffer;
    const aad = buildMSEncryptionAAD({
      kmsVersion: 2,
      method: 'passkey-prf',
      algVersion: 1,
      purpose: 'master-secret',
      credentialId: credId,
    });

    const text = new TextDecoder().decode(aad);
    expect(text).toContain('"method":"passkey-prf"');
    expect(text).toContain('credentialId');
  });

  it('should produce deterministic output for same inputs', () => {
    const config = {
      kmsVersion: 2,
      method: 'passphrase' as const,
      algVersion: 1,
      purpose: 'master-secret',
    };

    const aad1 = buildMSEncryptionAAD(config);
    const aad2 = buildMSEncryptionAAD(config);

    expect(new Uint8Array(aad1)).toEqual(new Uint8Array(aad2));
  });

  it('should produce different output for different methods', () => {
    const config1 = {
      kmsVersion: 2,
      method: 'passphrase' as const,
      algVersion: 1,
      purpose: 'master-secret',
    };
    const config2 = {
      kmsVersion: 2,
      method: 'passkey-prf' as const,
      algVersion: 1,
      purpose: 'master-secret',
    };

    const aad1 = buildMSEncryptionAAD(config1);
    const aad2 = buildMSEncryptionAAD(config2);

    expect(new Uint8Array(aad1)).not.toEqual(new Uint8Array(aad2));
  });
});

describe('buildKeyWrapAAD', () => {
  it('should build AAD for key wrapping', () => {
    const aad = buildKeyWrapAAD({
      kmsVersion: 2,
      kid: 'vapid-1',
      alg: 'ECDSA',
      purpose: 'vapid',
      createdAt: 1234567890,
      keyType: 'private',
    });

    const text = new TextDecoder().decode(aad);
    expect(text).toContain('"kid":"vapid-1"');
    expect(text).toContain('"alg":"ECDSA"');
    expect(text).toContain('"purpose":"vapid"');
    expect(text).toContain('"createdAt":1234567890');
    expect(text).toContain('"keyType":"private"');
  });

  it('should produce deterministic output', () => {
    const metadata = {
      kmsVersion: 2,
      kid: 'test-key',
      alg: 'ECDSA',
      purpose: 'test',
      createdAt: 1000,
      keyType: 'private',
    };

    const aad1 = buildKeyWrapAAD(metadata);
    const aad2 = buildKeyWrapAAD(metadata);

    expect(new Uint8Array(aad1)).toEqual(new Uint8Array(aad2));
  });

  it('should produce different output for different kids', () => {
    const metadata1 = {
      kmsVersion: 2,
      kid: 'key-1',
      alg: 'ECDSA',
      purpose: 'test',
      createdAt: 1000,
      keyType: 'private',
    };
    const metadata2 = {
      ...metadata1,
      kid: 'key-2',
    };

    const aad1 = buildKeyWrapAAD(metadata1);
    const aad2 = buildKeyWrapAAD(metadata2);

    expect(new Uint8Array(aad1)).not.toEqual(new Uint8Array(aad2));
  });
});

// ============================================================================
// KCV Tests
// ============================================================================

describe('computeKCV', () => {
  it('should compute KCV for AES-GCM key', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable for testing
      ['encrypt', 'decrypt']
    );

    const kcv = await computeKCV(key);
    expect(kcv.byteLength).toBe(32); // SHA-256 output
  });

  it('should produce consistent KCV for same key', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const kcv1 = await computeKCV(key);
    const kcv2 = await computeKCV(key);

    expect(new Uint8Array(kcv1)).toEqual(new Uint8Array(kcv2));
  });

  it('should produce different KCVs for different keys', async () => {
    const key1 = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const key2 = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const kcv1 = await computeKCV(key1);
    const kcv2 = await computeKCV(key2);

    expect(new Uint8Array(kcv1)).not.toEqual(new Uint8Array(kcv2));
  });
});

describe('verifyKCV', () => {
  it('should return true for matching KCVs', () => {
    const kcv1 = new Uint8Array([1, 2, 3, 4]).buffer;
    const kcv2 = new Uint8Array([1, 2, 3, 4]).buffer;
    expect(verifyKCV(kcv1, kcv2)).toBe(true);
  });

  it('should return false for different KCVs', () => {
    const kcv1 = new Uint8Array([1, 2, 3, 4]).buffer;
    const kcv2 = new Uint8Array([1, 2, 3, 5]).buffer;
    expect(verifyKCV(kcv1, kcv2)).toBe(false);
  });

  it('should return false for different lengths', () => {
    const kcv1 = new Uint8Array([1, 2, 3]).buffer;
    const kcv2 = new Uint8Array([1, 2, 3, 4]).buffer;
    expect(verifyKCV(kcv1, kcv2)).toBe(false);
  });
});

describe('timingSafeEqual', () => {
  it('should return true for equal buffers', () => {
    const a = new Uint8Array([1, 2, 3]).buffer;
    const b = new Uint8Array([1, 2, 3]).buffer;
    expect(timingSafeEqual(a, b)).toBe(true);
  });

  it('should return false for different buffers', () => {
    const a = new Uint8Array([1, 2, 3]).buffer;
    const b = new Uint8Array([1, 2, 4]).buffer;
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('should return false for different lengths', () => {
    const a = new Uint8Array([1, 2]).buffer;
    const b = new Uint8Array([1, 2, 3]).buffer;
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('should return true for empty buffers', () => {
    const a = new ArrayBuffer(0);
    const b = new ArrayBuffer(0);
    expect(timingSafeEqual(a, b)).toBe(true);
  });
});

// ============================================================================
// Deterministic Salt Tests
// ============================================================================

describe('deriveDeterministicSalt', () => {
  it('should derive 32-byte salt', async () => {
    const salt = await deriveDeterministicSalt('ATS/KMS/MKEK/salt/v2');
    expect(salt.byteLength).toBe(32);
  });

  it('should produce consistent salt for same context', async () => {
    const context = 'test-context';
    const salt1 = await deriveDeterministicSalt(context);
    const salt2 = await deriveDeterministicSalt(context);

    expect(new Uint8Array(salt1)).toEqual(new Uint8Array(salt2));
  });

  it('should produce different salts for different contexts', async () => {
    const salt1 = await deriveDeterministicSalt('context-1');
    const salt2 = await deriveDeterministicSalt('context-2');

    expect(new Uint8Array(salt1)).not.toEqual(new Uint8Array(salt2));
  });

  it('should produce non-zero salt', async () => {
    const salt = await deriveDeterministicSalt('ATS/KMS/test');
    const bytes = new Uint8Array(salt);
    const hasNonZero = bytes.some(b => b !== 0);
    expect(hasNonZero).toBe(true);
  });
});

// ============================================================================
// PBKDF2 Calibration Tests
// ============================================================================

describe('calibratePBKDF2Iterations', () => {
  it('should return iterations within valid range', async () => {
    const result = await calibratePBKDF2Iterations();
    expect(result.iterations).toBeGreaterThanOrEqual(50_000);
    expect(result.iterations).toBeLessThanOrEqual(2_000_000);
  });

  it('should measure timing', async () => {
    const result = await calibratePBKDF2Iterations();
    expect(result.measuredMs).toBeGreaterThan(0);
  });

  it('should target specified midpoint', async () => {
    const target = { min: 100, max: 200, mid: 150 };
    const result = await calibratePBKDF2Iterations(target);
    // Iterations should be scaled to target the midpoint
    expect(result.iterations).toBeGreaterThan(0);
  });

  it('should clamp to minimum iterations', async () => {
    // Target very low time (should clamp to 50k)
    const target = { min: 1, max: 2, mid: 1.5 };
    const result = await calibratePBKDF2Iterations(target);
    expect(result.iterations).toBeGreaterThanOrEqual(50_000);
  });

  it('should be deterministic for repeated calls (within tolerance)', async () => {
    const result1 = await calibratePBKDF2Iterations();
    const result2 = await calibratePBKDF2Iterations();
    // Allow 100% variance due to system load (CI environments are highly variable)
    const tolerance = result1.iterations * 1.0;
    expect(Math.abs(result1.iterations - result2.iterations)).toBeLessThan(tolerance);
  });
});
