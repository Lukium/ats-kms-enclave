/**
 * Verification utilities for KMS demo
 *
 * These functions verify that crypto operations match specifications:
 * - VAPID public keys are in correct format (65 bytes, uncompressed P-256)
 * - JWT signatures are in P-1363 format (not DER)
 * - Key identifiers are RFC 7638 thumbprints
 */

// ============================================================================
// Base64url helpers
// ============================================================================

export function b64uToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64u(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// ============================================================================
// Public Key Verification
// ============================================================================

export interface PublicKeyVerification {
  ok: boolean;
  length: number;
  leadingByte: string;
  reason?: string;
}

/**
 * Verify public key is raw uncompressed P-256 (65 bytes, starts with 0x04)
 *
 * Why this matters: PushManager.subscribe() requires the raw uncompressed
 * P-256 point (65 bytes). SPKI or JWK formats will fail.
 */
export function verifyRawP256(pubRaw: Uint8Array): PublicKeyVerification {
  const length = pubRaw.length;
  const leadingByte = `0x${pubRaw[0]?.toString(16).padStart(2, '0') || '00'}`;

  if (length !== 65) {
    return {
      ok: false,
      length,
      leadingByte,
      reason: `Expected 65 bytes, got ${length}`
    };
  }

  if (pubRaw[0] !== 0x04) {
    return {
      ok: false,
      length,
      leadingByte,
      reason: `Expected leading 0x04 (uncompressed), got ${leadingByte}`
    };
  }

  return { ok: true, length, leadingByte };
}

// ============================================================================
// JWT Verification
// ============================================================================

export interface JWTVerification {
  ok: boolean;
  sigLength?: number;
  sigLeadingByte?: string;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  reason?: string;
}

/**
 * Extract JWS parts and verify P-1363 signature format (64 bytes, not DER)
 *
 * Why this matters: WebCrypto returns DER-encoded signatures, but JWS ES256
 * requires P-1363 format (raw r‖s). A 64-byte signature proves conversion.
 */
export function verifyJwtEs256Compact(jwt: string): JWTVerification {
  const parts = jwt.split('.');

  if (parts.length !== 3) {
    return { ok: false, reason: 'Not a compact JWS (expected 3 parts)' };
  }

  const [h, p, s] = parts;

  try {
    const header = JSON.parse(new TextDecoder().decode(b64uToBytes(h!)));
    const payload = JSON.parse(new TextDecoder().decode(b64uToBytes(p!)));
    const sig = b64uToBytes(s!);

    const sigLength = sig.length;
    const sigLeadingByte = `0x${sig[0]?.toString(16).padStart(2, '0') || '00'}`;

    // P-1363 must be exactly 64 bytes; DER usually starts with 0x30 and is 70-72 bytes
    if (sigLength !== 64) {
      return {
        ok: false,
        sigLength,
        sigLeadingByte,
        header,
        payload,
        reason: `Signature not 64 bytes (got ${sigLength}, likely DER format)`
      };
    }

    if (sig[0] === 0x30) {
      return {
        ok: false,
        sigLength,
        sigLeadingByte,
        header,
        payload,
        reason: 'Signature looks like DER (starts with 0x30)'
      };
    }

    return {
      ok: true,
      sigLength,
      sigLeadingByte,
      header,
      payload
    };
  } catch (error) {
    return {
      ok: false,
      reason: `Failed to decode JWT: ${error instanceof Error ? error.message : 'unknown error'}`
    };
  }
}

// ============================================================================
// JWT Payload Verification
// ============================================================================

// Note: JWK thumbprint computation is in src/crypto-utils.ts (not duplicated here)

export interface JWTPayloadVerification {
  ok: boolean;
  aud?: string;
  sub?: string;
  exp?: number;
  expRelative?: string;
  reason?: string;
}

/**
 * Verify JWT payload has required VAPID fields with correct constraints
 *
 * Why this matters: VAPID requires short-lived tokens (≤24h) and correct
 * audience. Relays and push services reject tokens that violate this.
 */
export function verifyVAPIDPayload(payload: Record<string, unknown>): JWTPayloadVerification {
  const { aud, sub, exp } = payload;

  if (typeof aud !== 'string') {
    return { ok: false, reason: 'Missing or invalid "aud" field' };
  }

  if (typeof sub !== 'string' || !sub.startsWith('mailto:')) {
    return { ok: false, aud, sub: sub as string, reason: '"sub" must start with mailto:' };
  }

  if (typeof exp !== 'number') {
    return { ok: false, aud, sub, reason: 'Missing or invalid "exp" field' };
  }

  const now = Math.floor(Date.now() / 1000);
  const ttl = exp - now;

  if (ttl > 86400) {
    return {
      ok: false,
      aud,
      sub,
      exp,
      expRelative: `${Math.floor(ttl / 3600)}h`,
      reason: 'Token lifetime exceeds 24 hours'
    };
  }

  if (ttl < 0) {
    return {
      ok: false,
      aud,
      sub,
      exp,
      expRelative: 'expired',
      reason: 'Token has expired'
    };
  }

  return {
    ok: true,
    aud,
    sub,
    exp,
    expRelative: `${Math.floor(ttl / 60)}min`
  };
}
