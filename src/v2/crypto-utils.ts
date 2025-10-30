/**
 * Crypto utilities for KMS V2
 *
 * This module implements a suite of helper functions used across the
 * KMS worker. The functions cover encoding/decoding operations,
 * signature format conversions, construction of authenticated data
 * (AAD) for AES‑GCM operations, computation of key check values
 * (KCVs), derivation of deterministic salts, PBKDF2 calibration
 * routines and platform fingerprinting. All functions are pure and
 * return new data structures without side effects. Any use of the
 * WebCrypto API is encapsulated here to isolate cryptographic
 * operations from higher‑level business logic.
 */

// Browser-compatible imports (TextEncoder and performance are globals)
import type { MSAADConfig, KeyWrapAADConfig } from './types';

// -- Encoding helpers ----------------------------------------------------

/**
 * Convert an ArrayBuffer into a base64url encoded string. Base64url
 * encoding differs from standard base64 in that it replaces `+` and
 * `/` with `-` and `_` respectively and omits padding. This function
 * performs the necessary substitutions on top of Node's Buffer API.
 */
export function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  // Convert to base64 using browser-compatible approach
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Decode a base64url string into an ArrayBuffer. The input is first
 * padded to a multiple of four characters then the URL safe
 * substitutions are undone. The Buffer API is used to perform the
 * base64 decoding.
 */
export function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
  // Add padding
  let b64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad) b64 += '='.repeat(4 - pad);
  // Decode base64 using browser-compatible approach
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert an ArrayBuffer into a hexadecimal string. Each byte is
 * rendered as two lowercase hex digits. Hex encoding is useful for
 * debugging and logging as it is compact and human readable.
 */
export function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decode a hexadecimal string into an ArrayBuffer. The string may
 * optionally include a leading `0x` prefix. An error is thrown if
 * the string has an odd length or contains invalid hex characters.
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = clean.substr(i * 2, 2);
    bytes[i] = parseInt(byte, 16);
  }
  return bytes.buffer;
}

// -- Signature format conversions ----------------------------------------

/**
 * Detect the format of an ECDSA signature. The P‑1363 format is a
 * simple concatenation of the `r` and `s` values each padded to 32
 * bytes. DER encoding uses ASN.1 SEQUENCE and INTEGER types. The
 * function inspects the first byte to see if it looks like an ASN.1
 * SEQUENCE (0x30). Returns 'DER', 'P-1363' or 'unknown'.
 */
export function detectSignatureFormat(signature: Uint8Array): 'DER' | 'P-1363' | 'unknown' {
  if (signature.byteLength === 64) return 'P-1363';
  if (signature[0] === 0x30) return 'DER';
  return 'unknown';
}

/**
 * Convert a DER encoded ECDSA signature into the P‑1363 format.
 * DER uses ASN.1 sequences of integers; this function parses the
 * lengths and extracts the `r` and `s` components, padding them to
 * 32 bytes each. No validation of the integer values is performed.
 */
export function derToP1363(signature: Uint8Array): Uint8Array {
  // Minimal ASN.1 DER parser for ECDSA signatures
  let offset = 0;
  if (signature[offset++] !== 0x30) {
    throw new Error('Invalid DER signature: expected sequence');
  }
  offset++; // Skip sequence length byte
  // Read r
  if (signature[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected integer for r');
  }
  const rLength = signature[offset++];
  if (rLength === undefined) {
    throw new Error('Invalid DER signature: missing r length');
  }
  let rBytes = signature.slice(offset, offset + rLength);
  offset += rLength;
  // Remove leading zero padding
  if (rBytes[0] === 0x00) rBytes = rBytes.slice(1);
  // Read s
  if (signature[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected integer for s');
  }
  const sLength = signature[offset++];
  if (sLength === undefined) {
    throw new Error('Invalid DER signature: missing s length');
  }
  let sBytes = signature.slice(offset, offset + sLength);
  // Remove leading zero padding
  if (sBytes[0] === 0x00) sBytes = sBytes.slice(1);
  // Pad r and s to 32 bytes
  const rPad = new Uint8Array(32);
  const sPad = new Uint8Array(32);
  rPad.set(rBytes, 32 - rBytes.length);
  sPad.set(sBytes, 32 - sBytes.length);
  const result = new Uint8Array(64);
  result.set(rPad, 0);
  result.set(sPad, 32);
  return result;
}

/**
 * Convert a P‑1363 formatted ECDSA signature into DER encoding. The
 * input is assumed to be exactly 64 bytes containing the big endian
 * `r` and `s` values. The function strips any leading zeros when
 * encoding to DER to avoid negative integers. It returns a DER
 * encoded ASN.1 SEQUENCE of two INTEGERs.
 */
export function p1363ToDer(signature: Uint8Array): Uint8Array {
  if (signature.byteLength !== 64) {
    throw new Error('P-1363 signature must be 64 bytes');
  }
  const r = signature.slice(0, 32);
  const s = signature.slice(32);
  // Remove leading zeros
  let rTrim = r;
  let sTrim = s;
  while (rTrim.length > 0 && rTrim[0] === 0x00) rTrim = rTrim.slice(1);
  while (sTrim.length > 0 && sTrim[0] === 0x00) sTrim = sTrim.slice(1);
  // Ensure positive integers by prepending 0x00 if high bit is set
  if (rTrim.length > 0 && rTrim[0]! & 0x80) {
    const newRTrim = new Uint8Array(rTrim.length + 1);
    newRTrim[0] = 0x00;
    newRTrim.set(rTrim, 1);
    rTrim = newRTrim;
  }
  if (sTrim.length > 0 && sTrim[0]! & 0x80) {
    const newSTrim = new Uint8Array(sTrim.length + 1);
    newSTrim[0] = 0x00;
    newSTrim.set(sTrim, 1);
    sTrim = newSTrim;
  }
  const seqLength = 2 + rTrim.length + 2 + sTrim.length;
  const result = new Uint8Array(2 + seqLength);
  let idx = 0;
  result[idx++] = 0x30;
  result[idx++] = seqLength;
  // r
  result[idx++] = 0x02;
  result[idx++] = rTrim.length;
  result.set(rTrim, idx);
  idx += rTrim.length;
  // s
  result[idx++] = 0x02;
  result[idx++] = sTrim.length;
  result.set(sTrim, idx);
  return result;
}

/**
 * Convert a raw P‑256 public key into a JWK object. The input is the
 * uncompressed 65‑byte form starting with 0x04 followed by the x and
 * y coordinates. The returned JWK conforms to RFC 7517 with EC
 * parameters appropriate for P‑256.
 */
export function rawP256ToJwk(rawPublicKey: Uint8Array): JsonWebKey {
  if (rawPublicKey.length !== 65 || rawPublicKey[0] !== 0x04) {
    throw new Error('Invalid uncompressed P-256 public key');
  }
  const x = arrayBufferToBase64url(rawPublicKey.slice(1, 33).buffer);
  const y = arrayBufferToBase64url(rawPublicKey.slice(33).buffer);
  return {
    kty: 'EC',
    crv: 'P-256',
    x,
    y,
  };
}

/**
 * Compute the RFC 7638 JWK thumbprint of a P‑256 JWK. The thumbprint
 * is the SHA‑256 hash of the UTF‑8 encoded canonical JSON form of the
 * JWK with keys sorted as ["crv","kty","x","y"]. The result is
 * returned as a base64url string.
 */
export async function jwkThumbprintP256(jwk: JsonWebKey): Promise<string> {
  const obj = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
  const canonical = JSON.stringify(obj);
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );
  return arrayBufferToBase64url(digest);
}

// -- AAD construction ----------------------------------------------------

/**
 * Canonically serialise a JSON object by sorting keys lexicographically
 * and using `JSON.stringify`. This helper is used by AAD builders to
 * ensure deterministic encoding regardless of property order.
 */
function canonicalise(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const entries = keys.map((k) => [k, obj[k]]);
  return '{' + entries.map(([k, v]) => `"${String(k)}":${JSON.stringify(v)}`).join(',') + '}';
}

/**
 * Build the Additional Authenticated Data (AAD) for master secret
 * encryption. V2 uses AAD to bind metadata to the ciphertext to
 * prevent swapping or replay attacks. The configuration object is
 * canonicalised and encoded as UTF‑8 bytes.
 */
export function buildMSEncryptionAAD(config: MSAADConfig): ArrayBuffer {
  const obj: Record<string, unknown> = {
    kmsVersion: config.kmsVersion,
    method: config.method,
    algVersion: config.algVersion,
    purpose: config.purpose,
  };
  if (config.credentialId) {
    // Represent credential ID as base64url for canonical JSON
    obj.credentialId = arrayBufferToBase64url(config.credentialId);
  }
  const canonical = canonicalise(obj);
  return new TextEncoder().encode(canonical).buffer;
}

/**
 * Build the AAD for key wrapping operations. Metadata about the key
 * (kid, algorithm, purpose, creation time and key type) is
 * canonicalised and encoded. Binding this data as AAD prevents
 * substitution of wrapped keys between contexts.
 */
export function buildKeyWrapAAD(metadata: KeyWrapAADConfig): ArrayBuffer {
  const obj: Record<string, unknown> = {
    kmsVersion: metadata.kmsVersion,
    kid: metadata.kid,
    alg: metadata.alg,
    purpose: metadata.purpose,
    createdAt: metadata.createdAt,
    keyType: metadata.keyType,
  };
  const canonical = canonicalise(obj);
  return new TextEncoder().encode(canonical).buffer;
}

// -- Key Check Value (KCV) ----------------------------------------------

/**
 * Compute a Key Check Value over an AES‑GCM wrapping key. The KCV is
 * defined as HMAC‑SHA256(key, label) where the key material is the
 * raw AES key bytes and the label is the constant string
 * "ATS/KMS/KCV/v2". The returned ArrayBuffer is 32 bytes long.
 */
export async function computeKCV(kek: CryptoKey): Promise<ArrayBuffer> {
  // Export raw key material
  const keyBytes = await crypto.subtle.exportKey('raw', kek);
  // Import as HMAC key
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const data = new TextEncoder().encode('ATS/KMS/KCV/v2');
  const mac = await crypto.subtle.sign('HMAC', hmacKey, data);
  return mac;
}

/**
 * Compare two KCV values in constant time. Returns true if the
 * computed value matches the stored value and false otherwise.
 */
export function verifyKCV(computed: ArrayBuffer, stored: ArrayBuffer): boolean {
  return timingSafeEqual(computed, stored);
}

/**
 * Constant‑time comparison of two ArrayBuffers. Performs a bitwise
 * accumulation over all bytes to ensure the time taken depends only
 * on the length of the buffers. Buffers of different lengths always
 * return false.
 */
export function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const arrA = new Uint8Array(a);
  const arrB = new Uint8Array(b);
  if (arrA.length !== arrB.length) return false;
  let result = 0;
  for (let i = 0; i < arrA.length; i++) {
    result |= arrA[i]! ^ arrB[i]!;
  }
  return result === 0;
}

// -- Deterministic salts --------------------------------------------------

/**
 * Derive a deterministic 32‑byte salt for HKDF based on a context
 * string. Uses SHA‑256 over the UTF‑8 encoding of the context. The
 * salt output is suitable for use directly as the `salt` parameter
 * in HKDF operations.
 */
export async function deriveDeterministicSalt(context: string): Promise<ArrayBuffer> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(context));
  return digest;
}

// -- PBKDF2 calibration ---------------------------------------------------

/**
 * Calibrate the number of PBKDF2 iterations to achieve a target
 * derivation time window on the current platform. The algorithm
 * measures the time taken for 100k iterations of PBKDF2 and scales
 * accordingly to hit the desired midpoint between min and max. The
 * returned object includes both the recommended iteration count and
 * the measured duration for the probe run.
 */
export async function calibratePBKDF2Iterations(
  targetMs: { min: number; max: number; mid: number } = { min: 150, max: 300, mid: 220 }
): Promise<{ iterations: number; measuredMs: number }> {
  // Setup a dummy password and salt
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('calibration'),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const probeIterations = 100_000;
  const start = performance.now();
  // Derive 256 bits to approximate AES key size
  await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations: probeIterations,
    },
    passwordKey,
    256
  );
  const end = performance.now();
  const measuredMs = end - start;
  // Estimate iterations to target mid point
  let iterations = Math.round((probeIterations * targetMs.mid) / measuredMs);
  // Clamp iterations between 50k and 2M as per design
  iterations = Math.min(Math.max(iterations, 50_000), 2_000_000);
  return { iterations, measuredMs };
}

// -- Platform fingerprint -------------------------------------------------

/**
 * Generate a coarse platform fingerprint by hashing a selection of
 * environmental variables. In a browser context this might include
 * the user agent and hardware concurrency; in Node we fall back to
 * process.platform and process.arch. The resulting hash is returned
 * as a base64url string suitable for storage in the KMS config.
 */
export async function getPlatformHash(): Promise<string> {
  const concurrency = typeof navigator !== 'undefined' && 'hardwareConcurrency' in navigator
    ? String((navigator as Navigator & { hardwareConcurrency?: number }).hardwareConcurrency ?? '')
    : '';
  const info = typeof navigator !== 'undefined'
    ? [navigator.userAgent, navigator.platform, concurrency].join('|')
    : [process.platform, process.arch, process.version].join('|');
  const data = new TextEncoder().encode(info);
  // Use WebCrypto subtle.digest which works in both browser and Node.js
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToBase64url(hashBuffer);
}
