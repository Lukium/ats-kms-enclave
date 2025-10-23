/**
 * Cryptographic Utility Functions
 *
 * Provides low-level crypto operations:
 * - DER ↔ P-1363 signature format conversion
 * - JWK thumbprint computation (RFC 7638)
 * - Key format conversions
 *
 * @module src/crypto-utils
 */

// ============================================================================
// DER ↔ P-1363 Signature Conversion
// ============================================================================

/**
 * Convert DER-encoded ECDSA signature to P-1363 format
 *
 * DER format: 0x30 [length] 0x02 [r-length] [r] 0x02 [s-length] [s]
 * P-1363 format: [r (32 bytes)] [s (32 bytes)]
 *
 * @param derSignature DER-encoded signature (typically 70-72 bytes)
 * @returns P-1363 signature (always 64 bytes for P-256)
 * @throws {Error} if signature is not valid DER format
 */
export function derToP1363(derSignature: Uint8Array): Uint8Array {
  // DER format validation
  if (derSignature[0] !== 0x30) {
    throw new Error('Invalid DER signature: must start with 0x30 (SEQUENCE)');
  }

  const totalLength = derSignature[1]!;
  if (totalLength + 2 !== derSignature.length) {
    throw new Error(`Invalid DER signature: length mismatch (expected ${totalLength + 2}, got ${derSignature.length})`);
  }

  // Parse r value
  let offset = 2;
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: r value must start with 0x02 (INTEGER)');
  }
  offset++;

  const rLength = derSignature[offset]!;
  offset++;

  let r = derSignature.slice(offset, offset + rLength);
  offset += rLength;

  // Remove leading zeros from r (DER includes them for sign bit, P-1363 doesn't)
  while (r.length > 32 && r[0] === 0x00) {
    r = r.slice(1);
  }

  // Pad r to 32 bytes if needed (shouldn't happen, but be defensive)
  if (r.length < 32) {
    const padded = new Uint8Array(32);
    padded.set(r, 32 - r.length);
    r = padded;
  }

  // Parse s value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: s value must start with 0x02 (INTEGER)');
  }
  offset++;

  const sLength = derSignature[offset]!;
  offset++;

  let s = derSignature.slice(offset, offset + sLength);

  // Remove leading zeros from s
  while (s.length > 32 && s[0] === 0x00) {
    s = s.slice(1);
  }

  // Pad s to 32 bytes if needed
  if (s.length < 32) {
    const padded = new Uint8Array(32);
    padded.set(s, 32 - s.length);
    s = padded;
  }

  // Concatenate r and s (P-1363 format)
  const p1363 = new Uint8Array(64);
  p1363.set(r, 0);
  p1363.set(s, 32);

  return p1363;
}

/**
 * Convert P-1363 signature to DER format
 *
 * @param p1363Signature P-1363 signature (64 bytes for P-256)
 * @returns DER-encoded signature (70-72 bytes)
 * @throws {Error} if signature is not 64 bytes
 */
export function p1363ToDer(p1363Signature: Uint8Array): Uint8Array {
  if (p1363Signature.length !== 64) {
    throw new Error(`Invalid P-1363 signature: must be 64 bytes (got ${p1363Signature.length})`);
  }

  let r = p1363Signature.slice(0, 32);
  let s = p1363Signature.slice(32, 64);

  // Add leading 0x00 if high bit is set (DER requirement for positive integers)
  if (r[0]! & 0x80) {
    const padded = new Uint8Array(r.length + 1);
    padded[0] = 0x00;
    padded.set(r, 1);
    r = padded;
  }

  if (s[0]! & 0x80) {
    const padded = new Uint8Array(s.length + 1);
    padded[0] = 0x00;
    padded.set(s, 1);
    s = padded;
  }

  // Build DER structure
  const derLength = 2 + r.length + 2 + s.length;
  const der = new Uint8Array(2 + derLength);

  let offset = 0;
  der[offset++] = 0x30; // SEQUENCE
  der[offset++] = derLength;

  // r value
  der[offset++] = 0x02; // INTEGER
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;

  // s value
  der[offset++] = 0x02; // INTEGER
  der[offset++] = s.length;
  der.set(s, offset);

  return der;
}

/**
 * Detect signature format (DER or P-1363)
 *
 * @param signature Signature bytes
 * @returns 'DER' if DER format, 'P-1363' if P-1363 format, 'UNKNOWN' if neither
 */
export function detectSignatureFormat(signature: Uint8Array): 'DER' | 'P-1363' | 'UNKNOWN' {
  // P-1363 is always 64 bytes and doesn't start with 0x30
  if (signature.length === 64 && signature[0] !== 0x30) {
    return 'P-1363';
  }

  // DER starts with 0x30 and is typically 70-72 bytes
  if (signature[0] === 0x30 && signature.length >= 70 && signature.length <= 72) {
    return 'DER';
  }

  return 'UNKNOWN';
}

// ============================================================================
// JWK Thumbprint (RFC 7638)
// ============================================================================

/**
 * Compute JWK Thumbprint for an EC P-256 key (RFC 7638)
 *
 * The thumbprint is a content-derived identifier for a JWK.
 * It's the base64url encoding of SHA-256(canonical JSON representation).
 *
 * For EC keys, the canonical form is:
 * {"crv":"P-256","kty":"EC","x":"...","y":"..."}
 * (alphabetically ordered, no whitespace)
 *
 * @param jwk JWK representation of public key
 * @returns Base64url-encoded thumbprint
 */
export async function jwkThumbprintP256(jwk: {
  kty: string;
  crv: string;
  x: string;
  y: string;
}): Promise<string> {
  // RFC 7638: Required members in lexicographic order
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });

  // Hash the canonical representation
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );

  // Return base64url encoding
  return arrayBufferToBase64url(hash);
}

/**
 * Convert raw P-256 public key to JWK format
 *
 * Raw format: 0x04 || x (32 bytes) || y (32 bytes)
 * JWK format: { kty: "EC", crv: "P-256", x: "...", y: "..." }
 *
 * @param rawPublicKey Raw public key bytes (65 bytes)
 * @returns JWK representation
 * @throws {Error} if key is not valid raw P-256 format
 */
export function rawP256ToJwk(rawPublicKey: Uint8Array): {
  kty: string;
  crv: string;
  x: string;
  y: string;
} {
  if (rawPublicKey.length !== 65) {
    throw new Error(`Invalid raw P-256 public key: must be 65 bytes (got ${rawPublicKey.length})`);
  }

  if (rawPublicKey[0] !== 0x04) {
    throw new Error('Invalid raw P-256 public key: must start with 0x04 (uncompressed)');
  }

  const x = rawPublicKey.slice(1, 33);
  const y = rawPublicKey.slice(33, 65);

  return {
    kty: 'EC',
    crv: 'P-256',
    x: arrayBufferToBase64url(x),
    y: arrayBufferToBase64url(y),
  };
}

/**
 * Convert JWK to raw P-256 public key format
 *
 * @param jwk JWK representation
 * @returns Raw public key bytes (65 bytes)
 * @throws {Error} if JWK is not valid P-256
 */
export function jwkToRawP256(jwk: {
  kty: string;
  crv: string;
  x: string;
  y: string;
}): Uint8Array {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('JWK must be EC P-256');
  }

  const x = base64urlToArrayBuffer(jwk.x);
  const y = base64urlToArrayBuffer(jwk.y);

  if (x.byteLength !== 32 || y.byteLength !== 32) {
    throw new Error('Invalid JWK: x and y must be 32 bytes each');
  }

  const raw = new Uint8Array(65);
  raw[0] = 0x04; // Uncompressed point
  raw.set(new Uint8Array(x), 1);
  raw.set(new Uint8Array(y), 33);

  return raw;
}

// ============================================================================
// Base64url Utilities
// ============================================================================

/**
 * Convert ArrayBuffer to base64url string
 */
export function arrayBufferToBase64url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Convert base64url string to ArrayBuffer
 */
export function base64urlToArrayBuffer(b64url: string): ArrayBuffer {
  // Convert base64url to base64
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');

  // Pad with '=' if needed
  const padLen = (4 - (b64.length % 4)) % 4;
  const padded = b64 + '='.repeat(padLen);

  // Decode base64
  const binary = atob(padded);

  // Convert to ArrayBuffer
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}
