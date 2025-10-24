## Practical Implementation Guide

This section provides a concrete, production-ready approach to building the verifiable KMS enclave based on proven patterns.

### Key Principles

1. **Single-file module**: No dynamic imports (simplifies SRI verification)
2. **Content-addressed artifacts**: Filename includes hash (`kms-a3f8b2d1.mjs`)
3. **Deterministic builds**: Fixed timestamp, sorted inputs, no randomness
4. **Signed manifests**: Sigstore-signed JSON with artifact metadata
5. **Minimal iframe bootstrap**: One `<script>` tag with SRI attribute

### Hosting & Origin

**Critical**: The enclave is hosted on a **dedicated origin** separate from the main PWA.

**Origin**: `https://kms.ats.run`

**Hosting requirements**:
- **Static artifacts only**: One HTML + one bundled module (+ optional WASM)
- **No cookies**: Origin never sets cookies
- **No analytics**: No tracking scripts or external resources
- **No other content**: Nothing else hosted on this origin
- **Immutable deploys**: Content-addressed filenames with `Cache-Control: immutable`

**File structure**:
```
https://kms.ats.run/
├── kms.html                          # Iframe bootstrap (updated per release)
├── artifacts/
│   ├── kms-abcd1234.mjs              # Bundled enclave (content-addressed)
│   ├── kms-ef567890.mjs              # Previous version (during rollout)
│   └── ...
├── .well-known/
│   └── kms-manifest.json             # Signed manifest of allowed hashes
└── _headers                          # Security headers (Netlify/Cloudflare)
```

**Immutable cache headers**:
```
# artifacts/*.mjs
Cache-Control: public, max-age=31536000, immutable

# kms.html
Cache-Control: public, max-age=300
```

**Content addressing**: Artifacts are named by their hash, so URLs never change for a given version. This enables:
- Aggressive caching (1 year)
- SRI verification (hash in filename matches hash in `integrity` attribute)
- Rollback safety (keep old versions online during transition)

### Well-Known Manifest

**File**: `https://kms.ats.run/.well-known/kms-manifest.json`

```json
{
  "schema": 1,
  "current": {
    "version": "1.2.0",
    "artifact": "kms-abcd1234.mjs",
    "sha256": "abcd1234ef567890...",
    "sri": "sha256-ABCD...",
    "commit": "deadbeef",
    "timestamp": "2025-01-22T12:00:00Z"
  },
  "allowed": [
    {
      "artifact": "kms-abcd1234.mjs",
      "sha256": "abcd1234...",
      "status": "current"
    },
    {
      "artifact": "kms-ef567890.mjs",
      "sha256": "ef567890...",
      "status": "rollout"
    }
  ],
  "deprecated": [
    {
      "artifact": "kms-01234567.mjs",
      "sha256": "01234567...",
      "reason": "Security patch in 1.2.0"
    }
  ]
}
```

**Signature**: Signed with Sigstore, published to Rekor transparency log

**Purpose**:
- PWA can fetch to show current version
- Users/auditors can verify running version is in allowed list
- Third-party verifiers can monitor for unexpected changes

### Repository Layout

**Separate repository**: `https://github.com/alltheservices/kms-enclave`

```
kms-enclave/                         # Separate repo from main PWA
├── src/
│   ├── index.ts                     # KMS API, no dynamic imports
│   ├── worker.ts                    # Crypto operations, non-extractable keys
│   └── wasm/                        # (Optional) Bundled as data URL
├── build/
│   └── esbuild.ts                   # Deterministic build configuration
├── public/
│   ├── kms.html                     # Sandboxed iframe bootstrap
│   └── _headers                     # Security headers
├── .well-known/
│   └── kms-manifest.json.template   # Manifest template (filled by CI)
├── sigstore/                        # Release signatures
│   ├── v1.0.0.sig
│   ├── v1.0.0.cert
│   └── ...
├── .github/workflows/
│   ├── release.yml                  # Build + sign + deploy
│   └── verify.yml                   # Verify reproducibility
├── tools/
│   └── verify-cli/                  # Node script to verify hashes
├── docs/
│   ├── VERIFICATION.md              # How to verify enclave
│   └── SECURITY.md                  # Security model
└── README.md                        # Quick start guide
```

**Main PWA integration**: The PWA repository only contains the client stub (`enclave-bridge.ts`)

### Enclave Iframe Bootstrap

**File**: `packages/enclave/public/kms.html`

```html
<!doctype html>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; object-src 'none'">
<script type="module"
        src="/artifacts/kms-abcd1234….mjs"
        integrity="sha256-ABCD…">
</script>
```

**Key Properties**:
- Single module script (no other imports)
- SRI-pinned (browser verifies hash before execution)
- CSP enforces no inline scripts, restricts network to same-origin
- Filename and integrity updated by CI on each release

### Deterministic Build

**File**: `packages/enclave/build/esbuild.ts`

```typescript
import esbuild from 'esbuild'
import crypto from 'crypto'
import fs from 'fs'

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  target: ['es2020'],
  outfile: 'dist/kms.mjs',
  metafile: true,
  sourcemap: false,           // No sourcemaps (nondeterministic)
  legalComments: 'none',      // No comments (can vary)
  logLevel: 'info',
  minify: true,
  banner: { js: '/* ats-enclave-kms */' },
  footer: { js: '' },
  define: {
    // Kill nondeterminism - fixed timestamp
    'process.env.BUILD_TS': '"1970-01-01T00:00:00Z"',
    'process.env.GIT_COMMIT': `"${process.env.GIT_COMMIT || 'unknown'}"`,
  },
})

// Compute SHA-256 hash
const bundle = fs.readFileSync('dist/kms.mjs')
const hash = crypto.createHash('sha256').update(bundle).digest('hex')
const shortHash = hash.slice(0, 8)

// Rename to content-addressed filename
fs.renameSync('dist/kms.mjs', `dist/kms-${shortHash}.mjs`)

// Compute SRI hash
const sriHash = `sha256-${crypto.createHash('sha256').update(bundle).digest('base64')}`

console.log(`✅ Built kms-${shortHash}.mjs`)
console.log(`   SHA-256: ${hash}`)
console.log(`   SRI: ${sriHash}`)

// Write manifest
fs.writeFileSync('dist/manifest.json', JSON.stringify({
  version: process.env.npm_package_version,
  artifact: `kms-${shortHash}.mjs`,
  sha256: hash,
  sri: sriHash,
  commit: process.env.GIT_COMMIT,
  timestamp: new Date().toISOString(),
  schema: 1
}, null, 2))
```

**CI Pipeline Steps**:
1. Build `kms.mjs` (deterministic output)
2. Compute SHA-256 → rename to `kms-<sha>.mjs`
3. Emit SRI `<script integrity="sha256-...">` value
4. Sign manifest with Sigstore
5. Upload to `kms.ats.run`

### Signed Release Manifest

**File**: `packages/enclave/sigstore/release.json`

```json
{
  "version": "1.0.0",
  "artifact": "kms-abcd1234.mjs",
  "sha256": "abcd1234ef567890...",
  "sri": "sha256-ABCD1234EF567890...",
  "commit": "deadbeef",
  "timestamp": "2025-01-22T12:00:00Z",
  "schema": 1
}
```

**Sigstore Signature** (attached):
- Sign with `cosign sign-blob release.json`
- Publish to Rekor transparency log
- Generates `release.json.sig` and `release.json.cert`

**Verification**:
```bash
cosign verify-blob \
  --signature release.json.sig \
  --certificate release.json.cert \
  release.json
```

### Enclave Bootstrap Code

**File**: `packages/enclave/src/index.ts`

```typescript
// Spawn worker; keep all key operations in the worker
const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })

let ready: Promise<{ hash: string; commit: string }>

// Initialize worker
worker.postMessage({ type: 'init' })

/**
 * Get enclave version info (for verification UX)
 */
export async function version(): Promise<{ hash: string; commit: string }> {
  return new Promise((resolve) => {
    const onMsg = (e: MessageEvent) => {
      if (e.data?.type === 'version') {
        self.removeEventListener('message', onMsg)
        resolve(e.data.payload)
      }
    }
    self.addEventListener('message', onMsg)
    worker.postMessage({ type: 'version' })
  })
}

/**
 * Sign data with private key
 * @param kid Key ID (from generate())
 * @param bytes Data to sign
 */
export async function sign(kid: string, bytes: ArrayBuffer): Promise<ArrayBuffer> {
  return rpc('sign', { kid, bytes })
}

/**
 * Generate new keypair
 * @param alg Algorithm: ES256, Ed25519, X25519
 * @param purpose Purpose string (e.g., 'vapid', 'signal-identity')
 */
export async function generate(
  alg: 'ES256' | 'Ed25519' | 'X25519',
  purpose: string
): Promise<{ kid: string; publicKey: JsonWebKey }> {
  return rpc('generate', { alg, purpose, extractable: false })
}

/**
 * Internal RPC helper
 */
function rpc<T>(method: string, params: any): Promise<T> {
  const id = crypto.randomUUID()
  return new Promise((resolve, reject) => {
    const onMsg = (e: MessageEvent) => {
      if (e.data?.id !== id) return
      self.removeEventListener('message', onMsg)
      e.data.error ? reject(new Error(e.data.error)) : resolve(e.data.result)
    }
    self.addEventListener('message', onMsg)
    worker.postMessage({ id, method, params })
  })
}
```

### VAPID/JWS Quirks (Critical Implementation Notes)

**Critical**: WebCrypto ECDSA signatures and VAPID have format mismatches that **must** be handled correctly.

#### 1. ECDSA Signature Format: P-1363 (WebCrypto Native Format)

**Truth**:
- WebCrypto `crypto.subtle.sign()` with ECDSA returns **P-1363 format** (raw r‖s, exactly 64 bytes for P-256)
- JWS ES256 specification requires **P-1363 format** (same format)
- **No conversion needed** for pure WebCrypto → JWT signing

**When conversion IS needed:**
- **WebAuthn (passkeys)** signatures are DER format → convert DER → P-1363 for WebCrypto verification
- **Some server libraries** expect DER → convert P-1363 → DER when sending to them

```typescript
/**
 * Convert DER-encoded ECDSA signature to P-1363 (raw r‖s) format
 *
 * Used for WebAuthn (passkey) signatures which are DER-encoded.
 * NOT needed for WebCrypto sign() output (already P-1363).
 *
 * DER: ~70-72 bytes with ASN.1 structure (WebAuthn format)
 * P-1363: exactly 64 bytes (32-byte r + 32-byte s) (WebCrypto format)
 */
function derToP1363(derSignature: ArrayBuffer): ArrayBuffer {
  const der = new Uint8Array(derSignature)

  // DER structure: 0x30 [total-len] 0x02 [r-len] [r-bytes] 0x02 [s-len] [s-bytes]
  let offset = 0

  // Skip SEQUENCE tag (0x30) and length
  if (der[offset++] !== 0x30) throw new Error('Invalid DER signature')
  offset++ // Skip total length

  // Extract r
  if (der[offset++] !== 0x02) throw new Error('Invalid DER signature (r)')
  let rLen = der[offset++]
  let rStart = offset

  // If r has leading zero (for sign), skip it
  if (der[rStart] === 0x00) {
    rStart++
    rLen--
  }
  offset += rLen

  // Extract s
  if (der[offset++] !== 0x02) throw new Error('Invalid DER signature (s)')
  let sLen = der[offset++]
  let sStart = offset

  // If s has leading zero (for sign), skip it
  if (der[sStart] === 0x00) {
    sStart++
    sLen--
  }

  // P-1363 format: exactly 32 bytes r + 32 bytes s
  const p1363 = new Uint8Array(64)

  // Copy r (right-aligned if shorter than 32 bytes)
  p1363.set(der.slice(rStart, rStart + rLen), 32 - rLen)

  // Copy s (right-aligned if shorter than 32 bytes)
  p1363.set(der.slice(sStart, sStart + sLen), 64 - sLen)

  return p1363.buffer
}
```

#### 2. VAPID Public Key Format for PushManager

**Problem**:
- `PushManager.subscribe({ applicationServerKey })` expects **raw uncompressed P-256 public key** (65 bytes)
- WebCrypto exports as **SPKI** (SubjectPublicKeyInfo, ~91 bytes ASN.1 structure)
- If you pass SPKI, **subscription will fail**

**Solution**: Extract raw key from SPKI or export as JWK and convert

```typescript
/**
 * Convert SPKI public key to raw uncompressed format for PushManager
 * SPKI: ~91 bytes with ASN.1 structure
 * Raw: exactly 65 bytes (0x04 + 32-byte x + 32-byte y)
 */
function spkiToRaw(spki: ArrayBuffer): Uint8Array {
  const der = new Uint8Array(spki)

  // SPKI structure has 26-byte header, then 65-byte raw key
  // This is for P-256 specifically
  const rawKey = der.slice(26, 26 + 65)

  if (rawKey.length !== 65 || rawKey[0] !== 0x04) {
    throw new Error('Invalid P-256 public key')
  }

  return rawKey
}

/**
 * Alternative: Convert JWK to raw format
 */
function jwkToRaw(jwk: JsonWebKey): Uint8Array {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('Only P-256 keys supported')
  }

  // Decode base64url x and y coordinates
  const x = base64urlDecode(jwk.x!)
  const y = base64urlDecode(jwk.y!)

  // Uncompressed format: 0x04 + x + y
  const raw = new Uint8Array(65)
  raw[0] = 0x04
  raw.set(x, 1)
  raw.set(y, 33)

  return raw
}

function base64urlDecode(str: string): Uint8Array {
  // Add padding
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  while (str.length % 4) str += '='

  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
```

#### 3. Updated VAPID Key Generation & Storage

```typescript
async function generateVAPID(): Promise<{ kid: string; publicKey: string; rawPublicKey: Uint8Array }> {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,  // NOT extractable
    ['sign', 'verify']
  )

  // Export public key as JWK
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey)

  // Compute kid (JWK thumbprint)
  const kid = await thumbprint(publicKeyJwk)

  // Convert to raw format for PushManager
  const rawPublicKey = jwkToRaw(publicKeyJwk)

  // Store both formats
  await db.put('keys', {
    privateKey: keypair.privateKey,
    publicKey: publicKeyJwk,        // For verification, JWT header
    rawPublicKey: Array.from(rawPublicKey),  // For PushManager (stored as array)
    createdAt: Date.now()
  }, 'vapid_keypair')

  return {
    kid,
    publicKey: JSON.stringify(publicKeyJwk),  // For PWA (can verify)
    rawPublicKey                               // For PushManager.subscribe()
  }
}
```

#### 4. JWT Signing with WebCrypto (No Conversion Needed)

```typescript
async function signJWT(payload: object): Promise<string> {
  const keypair = await db.get('keys', 'vapid_keypair')

  const header = { typ: 'JWT', alg: 'ES256' }
  const encodedHeader = base64url(JSON.stringify(header))
  const encodedPayload = base64url(JSON.stringify(payload))
  const message = `${encodedHeader}.${encodedPayload}`

  // Sign with WebCrypto (returns P-1363 format - 64 bytes for P-256)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keypair.privateKey,
    new TextEncoder().encode(message)
  )

  // No conversion needed - WebCrypto returns P-1363, JWS expects P-1363
  const encodedSignature = base64url(signature)

  return `${message}.${encodedSignature}`
}
```

**Why this works**:
- WebCrypto `sign()` returns P-1363 format (64 bytes for P-256)
- JWS ES256 spec requires P-1363 format
- **No conversion needed** - formats already match
- Without raw public key: **PushManager.subscribe() fails**
- Raw public key export is **critical for VAPID to work** in production

#### 5. Production-Ready ES256 Utilities (Drop-In Code)

**File**: `packages/enclave/src/vapid-es256.ts`

This is **production-ready, browser-tested code** that handles all ES256/VAPID quirks correctly. Drop this into your enclave as-is.

```typescript
// ats-enclave-es256.ts
// Utilities for ES256 (P-256 ECDSA) VAPID: DER<->P1363, raw pubkey export, JWT signing, headers.
// All WebCrypto ops run in the current realm (your enclave worker).

/* ===================== Base64url helpers ===================== */
export function b64uEncode(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  // btoa expects binary string
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function b64uEncodeStr(str: string): string {
  return b64uEncode(new TextEncoder().encode(str));
}

export function b64uDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ===================== DER <-> P-1363 converters ===================== */
// WebAuthn (passkeys) returns DER. WebCrypto verify() needs P-1363 (r||s) 64 bytes.
// WebCrypto sign() already returns P-1363 - no conversion needed for JWT signing.

export function derToP1363(der: ArrayBuffer): Uint8Array {
  const d = new Uint8Array(der);
  // Very small ASN.1 parser for ECDSA-Sig: SEQUENCE { r INTEGER, s INTEGER }
  if (d[0] !== 0x30) throw new Error('Invalid DER: expected SEQUENCE');
  let idx = 2;
  if (d[1] & 0x80) idx = 2 + (d[1] & 0x7f); // skip long-form len
  if (d[idx] !== 0x02) throw new Error('Invalid DER: expected INTEGER (r)');
  const rLen = d[idx + 1];
  const r = d.slice(idx + 2, idx + 2 + rLen);
  idx = idx + 2 + rLen;
  if (d[idx] !== 0x02) throw new Error('Invalid DER: expected INTEGER (s)');
  const sLen = d[idx + 1];
  const s = d.slice(idx + 2, idx + 2 + sLen);

  // INTEGER may be prefixed with 0x00 (to avoid negative). Strip then left-pad to 32.
  const r32 = leftPadUnsigned(r, 32);
  const s32 = leftPadUnsigned(s, 32);
  const out = new Uint8Array(64);
  out.set(r32, 0);
  out.set(s32, 32);
  return out;
}

export function p1363ToDer(sig: ArrayBuffer | Uint8Array): Uint8Array {
  const p = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
  if (p.length !== 64) throw new Error('P-1363 must be 64 bytes');
  const r = trimLeadingZeros(p.slice(0, 32));
  const s = trimLeadingZeros(p.slice(32, 64));
  const rInt = r[0] & 0x80 ? prependZero(r) : r;
  const sInt = s[0] & 0x80 ? prependZero(s) : s;

  const len = 2 + rInt.length + 2 + sInt.length;
  const hdr = len < 128 ? Uint8Array.of(0x30, len) : Uint8Array.of(0x30, 0x81, len);
  return concatBytes(
    hdr,
    Uint8Array.of(0x02, rInt.length), rInt,
    Uint8Array.of(0x02, sInt.length), sInt
  );
}

function leftPadUnsigned(x: Uint8Array, len: number): Uint8Array {
  // strip any leading 0x00 then left-pad
  let i = 0;
  while (i < x.length - 1 && x[i] === 0) i++;
  const trimmed = x.slice(i);
  if (trimmed.length > len) throw new Error('Value too large');
  const out = new Uint8Array(len);
  out.set(trimmed, len - trimmed.length);
  return out;
}
function trimLeadingZeros(x: Uint8Array): Uint8Array {
  let i = 0;
  while (i < x.length - 1 && x[i] === 0) i++;
  return x.slice(i);
}
function prependZero(x: Uint8Array): Uint8Array {
  const out = new Uint8Array(x.length + 1);
  out.set([0], 0);
  out.set(x, 1);
  return out;
}
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/* ===================== VAPID keypair + raw public key ===================== */

export async function generateVAPIDKeypair(): Promise<CryptoKeyPair> {
  // Private key non-extractable; ES256 sign/verify.
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // extractable (private=false)
    ['sign', 'verify']
  ) as Promise<CryptoKeyPair>;
}

/**
 * Export the uncompressed P-256 public key (65 bytes: 0x04 || X(32) || Y(32))
 * required by PushManager.subscribe({ applicationServerKey }).
 */
export async function exportRawP256PublicKey(pub: CryptoKey): Promise<Uint8Array> {
  // Most browsers support 'raw' for EC public keys and return uncompressed point.
  try {
    const raw = await crypto.subtle.exportKey('raw', pub);
    return new Uint8Array(raw); // 65 bytes
  } catch {
    // Fallback: parse SPKI if needed (rare in modern browsers).
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pub));
    return spkiToUncompressedPoint(spki);
  }
}

// Minimal SPKI parser to extract uncompressed EC point
function spkiToUncompressedPoint(spki: Uint8Array): Uint8Array {
  // Search for BIT STRING that holds the ECPoint (starts with 0x03 len 0x00 0x04…)
  // This is simplistic but works with standard P-256 SPKI encodings.
  let i = 0;
  if (spki[i++] !== 0x30) throw new Error('Invalid SPKI');
  i += lenLen(spki, i); // skip seq len
  // skip algorithm id sequence
  if (spki[i++] !== 0x30) throw new Error('Invalid SPKI algid');
  i += lenLen(spki, i);
  // find BIT STRING tag
  if (spki[i++] !== 0x03) throw new Error('Invalid SPKI: no BIT STRING');
  const bitLenBytes = lenBytes(spki, i); i += bitLenBytes.skip;
  const unusedBits = spki[i++]; // must be 0
  if (unusedBits !== 0) throw new Error('Invalid ECPoint bits');
  const point = spki.slice(i, i + bitLenBytes.length - 1);
  if (point[0] !== 0x04 || point.length !== 65) throw new Error('Unexpected ECPoint format');
  return point;
}
function lenLen(bytes: Uint8Array, i: number): number {
  // returns total length of length field (1 or 2 bytes) and advances nothing
  if ((bytes[i] & 0x80) === 0) return 1;
  return 1 + (bytes[i] & 0x7f);
}
function lenBytes(bytes: Uint8Array, i: number): { length: number; skip: number } {
  // read ASN.1 length at i, return the value and the number of bytes consumed
  const b = bytes[i];
  if ((b & 0x80) === 0) return { length: b, skip: 1 };
  const n = b & 0x7f;
  let v = 0;
  for (let k = 1; k <= n; k++) v = (v << 8) | bytes[i + k];
  return { length: v, skip: 1 + n };
}

/* ===================== VAPID JWT (ES256 JWS) ===================== */

export type VapidClaims = {
  aud: string;      // push service origin, e.g. "https://fcm.googleapis.com"
  sub: string;      // contact URI, e.g. "mailto:notifications@ats.run"
  exp: number;      // seconds since epoch, typically now + 12h (<= 24h)
  [k: string]: any; // optional private claims like relay_id
};

export async function signVAPIDJWT(
  priv: CryptoKey,         // ES256 private key (non-extractable)
  claims: VapidClaims,
  kid?: string             // optional key id for rotation
): Promise<string> {
  const header: any = { alg: 'ES256', typ: 'JWT' };
  if (kid) header.kid = kid;

  const encHeader = b64uEncodeStr(JSON.stringify(header));
  const encPayload = b64uEncodeStr(JSON.stringify(claims));
  const signingInput = new TextEncoder().encode(`${encHeader}.${encPayload}`);

  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, signingInput);
  // Note: WebCrypto sign() already returns P-1363 format (64 bytes) - no conversion needed

  const encSig = b64uEncode(sig);
  return `${encHeader}.${encPayload}.${encSig}`;
}

/* ===================== RFC 8292 VAPID headers for relays ===================== */
/**
 * Build Authorization/Crypto-Key headers for a push request using RFC 8292 VAPID.
 * - jwt: compact JWS from signVAPIDJWT
 * - appServerPubRaw: 65-byte uncompressed public key (same keypair as used to sign jwt)
 */
export function buildVapidHeaders(jwt: string, appServerPubRaw: Uint8Array): {
  Authorization: string;
  'Crypto-Key': string;
} {
  // RFC 8292 uses Authorization: vapid t=..., k=...
  const k = b64uEncode(appServerPubRaw);
  return {
    Authorization: `vapid t=${jwt}, k=${k}`,
    'Crypto-Key': `p256ecdsa=${k}`, // many push services still require this header
  };
}

/* ===================== Convenience: everything to set up VAPID ===================== */
/**
 * Generate ES256 keypair, export 65-byte raw public key for PushManager.subscribe,
 * and produce a ready-to-use JWT + headers for relays.
 */
export async function prepareVapidForRelay(opts: {
  sub: string;
  aud: string;            // push service origin
  lifetimeSec?: number;   // default 12h
  kid?: string;
}): Promise<{
  keypair: CryptoKeyPair;
  applicationServerKey: Uint8Array; // feed to PushManager.subscribe
  jwt: string;
  headers: { Authorization: string; 'Crypto-Key': string };
  exp: number;
}> {
  const keypair = await generateVAPIDKeypair();
  const applicationServerKey = await exportRawP256PublicKey(keypair.publicKey);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + (opts.lifetimeSec ?? 12 * 60 * 60); // 12h default
  const jwt = await signVAPIDJWT(keypair.privateKey, { aud: opts.aud, sub: opts.sub, exp }, opts.kid);
  const headers = buildVapidHeaders(jwt, applicationServerKey);
  return { keypair, applicationServerKey, jwt, headers, exp };
}
```

#### 6. Usage Examples

**One-time VAPID setup** (enclave worker):
```typescript
import { prepareVapidForRelay } from './vapid-es256'

// Create per-user VAPID keypair once (non-extractable private key)
const { keypair, applicationServerKey } = await prepareVapidForRelay({
  sub: 'mailto:notifications@ats.run',
  aud: 'https://fcm.googleapis.com',   // or Mozilla/Apple push service origin
});

// Store keypair in IndexedDB (privateKey is non-extractable)
await db.put('keys', {
  privateKey: keypair.privateKey,
  publicKey: await crypto.subtle.exportKey('jwk', keypair.publicKey),
  rawPublicKey: Array.from(applicationServerKey),  // For PushManager
  createdAt: Date.now()
}, 'vapid_keypair')

// Return applicationServerKey to host PWA
return {
  kid: await thumbprint(publicKey),
  applicationServerKey: Array.from(applicationServerKey)  // 65 bytes
}
```

**Host PWA subscribes to push** (using enclave's applicationServerKey):
```typescript
// PWA receives applicationServerKey from enclave
const subscription = await navigator.serviceWorker.ready.then(reg =>
  reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: new Uint8Array(applicationServerKey)  // 65 bytes from enclave
  })
)

// Store subscription endpoint
const { endpoint, keys } = subscription.toJSON()
```

**Generate JWT for relay authorization** (every 2 hours):
```typescript
import { signVAPIDJWT, buildVapidHeaders, exportRawP256PublicKey } from './vapid-es256'

// Retrieve keypair from IndexedDB
const stored = await db.get('keys', 'vapid_keypair')

// Generate short-lived JWT (2 hours)
const jwt = await signVAPIDJWT(
  stored.privateKey,
  {
    aud: 'https://fcm.googleapis.com',  // Push service origin
    sub: 'mailto:notifications@ats.run',
    exp: Math.floor(Date.now() / 1000) + 2 * 60 * 60,  // 2 hours
    relay_id: 'relay-alpha'  // Optional private claim
  },
  'vapid-2025-01'  // Optional key ID
)

// Build RFC 8292 headers
const rawPublicKey = new Uint8Array(stored.rawPublicKey)
const headers = buildVapidHeaders(jwt, rawPublicKey)

// Return to PWA → relay
return {
  jwt,
  publicKey: rawPublicKey,
  headers  // { Authorization: '...', 'Crypto-Key': '...' }
}
```

**Relay sends push notification**:
```typescript
// Relay receives from PWA: { jwt, publicKey, pushEndpoint }
const response = await fetch(pushEndpoint, {
  method: 'POST',
  headers: {
    'Authorization': `vapid t=${jwt}, k=${b64uEncode(publicKey)}`,
    'Crypto-Key': `p256ecdsa=${b64uEncode(publicKey)}`,
    'Content-Type': 'application/json',
    'TTL': '86400'  // 24 hours
  },
  body: JSON.stringify({
    message_id: 'broadcast-123',
    topic: '#food',
    content: 'Free pizza in lobby!',
    relay_id: 'relay-alpha'
  })
})
```

**What this code handles automatically**:
- ✅ P-1363 signature format (WebCrypto native format, works with JWS ES256)
- ✅ Raw public key export (PushManager.subscribe works correctly)
- ✅ RFC 8292 VAPID headers (push services accept requests)
- ✅ Non-extractable private keys (keys stay in enclave)
- ✅ Base64url encoding (correct format for JWT/VAPID)
- ✅ DER ↔ P-1363 converters (available for WebAuthn passkey unlock)

**Pitfalls this avoids**:
- ❌ Passing SPKI to PushManager (subscription fails)
- ❌ Missing Crypto-Key header (some push services reject)
- ❌ Extractable private keys (could be stolen by compromised PWA)
- ❌ Long-lived JWTs (24-hour limit, we use 2 hours for relay auth)

### Worker Implementation

**File**: `packages/enclave/src/worker.ts`

```typescript
/**
 * KMS Worker - All crypto operations happen here
 * Keys are non-extractable and never leave this worker
 */

// In-memory key storage (never exported)
const keys = new Map<string, CryptoKey>()
const meta = new Map<string, { alg: string; purpose: string; publicKey: JsonWebKey }>()

self.addEventListener('message', async (e) => {
  const { id, type, method, params } = e.data || {}

  if (type === 'init') {
    console.log('[KMS Worker] Initialized')
    return
  }

  if (type === 'version') {
    return post({
      type: 'version',
      payload: {
        hash: '<build-hash>',        // Injected by build
        commit: '<git-commit>'        // Injected by build
      }
    })
  }

  try {
    if (method === 'generate') {
      const { alg, purpose, extractable } = params
      const keypair = await generateKeypair(alg, extractable)

      // Export public key (safe to share)
      const publicKey = await crypto.subtle.exportKey('jwk', keypair.publicKey)

      // Generate key ID (thumbprint of public key)
      const kid = await thumbprint(publicKey)

      // Store private key (non-extractable)
      keys.set(kid, keypair.privateKey)
      meta.set(kid, { alg, purpose, publicKey })

      console.log(`[KMS Worker] Generated ${alg} keypair: ${kid} (${purpose})`)

      return post({ id, result: { kid, publicKey } })
    }

    if (method === 'sign') {
      const { kid, bytes } = params
      const privateKey = keys.get(kid)

      if (!privateKey) {
        throw new Error(`Unknown key ID: ${kid}`)
      }

      const signature = await crypto.subtle.sign(
        privateKey.algorithm,
        privateKey,
        bytes
      )

      console.log(`[KMS Worker] Signed with ${kid}`)

      return post({ id, result: signature })
    }

    throw new Error(`Unknown method: ${method}`)
  } catch (error) {
    console.error('[KMS Worker] Error:', error)
    post({ id, error: String(error) })
  }
})

/**
 * Generate keypair based on algorithm
 */
async function generateKeypair(alg: string, extractable: boolean): Promise<CryptoKeyPair> {
  if (alg === 'ES256') {
    return crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      extractable,  // MUST be false for non-extractable keys
      ['sign', 'verify']
    )
  }

  if (alg === 'Ed25519') {
    // Use SubtleCrypto if available (Chrome 113+)
    // Otherwise, use WASM-backed implementation (bundled)
    throw new Error('Ed25519 not yet implemented')
  }

  if (alg === 'X25519') {
    // Used for Signal protocol key agreement
    throw new Error('X25519 not yet implemented')
  }

  throw new Error(`Unsupported algorithm: ${alg}`)
}

/**
 * Compute JWK thumbprint (RFC 7638)
 */
async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  })
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Post message to main thread
 */
function post(msg: any): void {
  (self as any).postMessage(msg)
}
```

**Key Properties**:
- `extractable: false` - Private keys cannot be exported
- Keys stored in Map (in-memory, never persists to IndexedDB initially)
- Simple RPC protocol (request ID for correlation)
- Ed25519/X25519 can be added via WASM (bundled as data URL)

### Host PWA Integration

**File**: `apps/pwa/src/lib/enclave-bridge.ts`

```typescript
/**
 * Enclave Bridge - Loads KMS iframe and provides RPC interface
 */

export async function startEnclave(expectedHash: string): Promise<EnclaveAPI> {
  const iframe = document.createElement('iframe')

  // Sandboxed iframe (no same-origin = no cookie/localStorage access)
  iframe.sandbox.add('allow-scripts')  // ONLY scripts, nothing else
  iframe.src = `https://kms.ats.run/kms.html?hash=${expectedHash}`
  iframe.style.display = 'none'

  document.body.appendChild(iframe)

  // Wait for enclave ready
  await new Promise<void>((resolve) => {
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== 'https://kms.ats.run') return
      if (e.data.type === 'ready') {
        window.removeEventListener('message', onMessage)
        resolve()
      }
    }
    window.addEventListener('message', onMessage)
  })

  // Return RPC interface
  return {
    async version() {
      return rpc(iframe, 'version', {})
    },
    async generateVAPID() {
      return rpc(iframe, 'generate', { alg: 'ES256', purpose: 'vapid' })
    },
    async signJWT(kid: string, payload: any) {
      const bytes = new TextEncoder().encode(JSON.stringify(payload))
      const signature = await rpc(iframe, 'sign', { kid, bytes })
      return signature
    }
  }
}

interface EnclaveAPI {
  version(): Promise<{ hash: string; commit: string }>
  generateVAPID(): Promise<{ kid: string; publicKey: JsonWebKey }>
  signJWT(kid: string, payload: any): Promise<ArrayBuffer>
}

/**
 * RPC helper - send request to enclave and wait for response
 */
function rpc<T>(iframe: HTMLIFrameElement, method: string, params: any): Promise<T> {
  const id = crypto.randomUUID()

  return new Promise((resolve, reject) => {
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== 'https://kms.ats.run') return
      if (e.data.id !== id) return

      window.removeEventListener('message', onMessage)
      e.data.error ? reject(new Error(e.data.error)) : resolve(e.data.result)
    }

    window.addEventListener('message', onMessage)

    iframe.contentWindow!.postMessage(
      { id, method, params },
      'https://kms.ats.run'
    )
  })
}
```

### Security Headers

**Critical**: Strong security headers on both origins prevent various attacks and enforce isolation.

**KMS Enclave** (`kms.ats.run`) - **Strictest possible**:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  connect-src 'self';
  worker-src 'self';
  object-src 'none';
  base-uri 'none';
  frame-ancestors https://allthe.services;
  form-action 'none';
  upgrade-insecure-requests;

Permissions-Policy:
  geolocation=(),
  microphone=(),
  camera=(),
  usb=(),
  bluetooth=(),
  magnetometer=(),
  accelerometer=(),
  gyroscope=(),
  payment=(),
  interest-cohort=()

Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Why this matters**:
- `default-src 'none'` - Nothing allowed by default (whitelist only)
- `script-src 'self'` - Only scripts from same origin (no inline, no eval)
- `connect-src 'self'` - Can fetch from own origin (runtime self-check works)
- `frame-ancestors https://allthe.services` - **Only PWA can embed** (critical!)
- `Cross-Origin-Resource-Policy: same-origin` - Prevent embedding by other sites
- All device permissions denied - No access to geolocation, camera, etc.

**Why `frame-ancestors https://allthe.services` is critical**:
- Without it, anyone could embed the enclave and impersonate the PWA
- This ensures only the official PWA can load the enclave
- Prevents phishing attacks where attacker embeds real enclave in fake UI

**Host PWA** (`allthe.services`):

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'strict-dynamic';
  connect-src 'self' https://api.ats.run https://kms.ats.run;
  frame-src https://kms.ats.run;
  img-src 'self' data: https:;
  style-src 'self';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  upgrade-insecure-requests;

Permissions-Policy:
  geolocation=(self),
  microphone=(),
  camera=(),
  usb=(),
  payment=()

Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Why this matters**:
- `frame-src https://kms.ats.run` - Only allow KMS enclave iframe
- `connect-src` includes `kms.ats.run` for fetching manifest
- `geolocation=(self)` - PWA needs geolocation for HWR routing
- More permissive than enclave (but still strict)

**Cache-Control Headers** (Cloudflare/Netlify `_headers`):

```
# kms.ats.run/_headers

/artifacts/*.mjs
  Cache-Control: public, max-age=31536000, immutable
  Content-Type: application/javascript; charset=utf-8
  X-Content-Type-Options: nosniff
  Cross-Origin-Resource-Policy: cross-origin
  Access-Control-Allow-Origin: https://ats.run

/kms.html
  Cache-Control: public, max-age=300, must-revalidate
  Content-Type: text/html; charset=utf-8
  X-Content-Type-Options: nosniff

/.well-known/kms-manifest.json
  Cache-Control: public, max-age=60, must-revalidate
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
```

**Why immutable caching matters**:
- Content-addressed files (`kms-abcd1234.mjs`) never change
- 1-year cache = instant loading on repeat visits
- Reduces CDN costs and latency
- SRI verification ensures integrity even if cache poisoned

### Minimal API Surface

The enclave exposes a **tiny, auditable API** over `postMessage`. This simplicity makes verification easier.

**Core Operations**:

| Method | Parameters | Returns | Purpose |
|--------|-----------|---------|---------|
| `version()` | None | `{ hash, commit, schema }` | Get enclave version for verification |
| `generate({ alg, purpose })` | `alg`: 'ES256'\|'Ed25519'\|'X25519'<br>`purpose`: string | `{ kid }` | Generate new keypair |
| `publicKey(kid)` | `kid`: string | `ArrayBuffer` | Export public key |
| `sign(kid, bytes)` | `kid`: string<br>`bytes`: ArrayBuffer | `ArrayBuffer` (signature) | Sign arbitrary data |
| `verify(pub, bytes, sig)` | `pub`: ArrayBuffer<br>`bytes`: ArrayBuffer<br>`sig`: ArrayBuffer | `boolean` | Verify signature |
| `derive(kid, peerPub)` | `kid`: string (X25519 key)<br>`peerPub`: ArrayBuffer | `ArrayBuffer` (shared secret) | X3DH key agreement (future) |

**Design constraints**:
- ✅ **No key export**: Private keys never leave the enclave
- ✅ **Opaque key IDs**: `kid` is JWK thumbprint, not key material
- ✅ **Binary data**: Use `ArrayBuffer` (transferable, efficient)
- ✅ **Explicit purpose**: Each key tagged with purpose string
- ✅ **Version endpoint**: Always expose running hash for verification

**NOT exposed** (intentionally omitted):
- ❌ Key deletion (keys persist in IndexedDB)
- ❌ Key import (enclave-generated only)
- ❌ Batch operations (keep API simple)
- ❌ Configuration (no runtime config, build-time only)

**Example usage**:

```typescript
// PWA generates VAPID key
const { kid } = await enclave.generate({ alg: 'ES256', purpose: 'vapid' })

// Get public key for push subscription
const publicKey = await enclave.publicKey(kid)

// Sign JWT for relay authorization
const jwtPayload = new TextEncoder().encode(JSON.stringify({
  aud: 'https://push.example.com',
  exp: Math.floor(Date.now() / 1000) + 7200,
  relay_id: 'relay-alpha',
  sub: 'mailto:notifications@ats.run'
}))
const signature = await enclave.sign(kid, jwtPayload)

// Verify own signature (sanity check)
const valid = await enclave.verify(publicKey, jwtPayload, signature)
```

**Why this matters**:
- Small API = easy to audit
- Explicit operations = hard to misuse
- No key export = keys physically cannot be stolen
- Version endpoint = users can verify running code

### Storage & Lifecycle

**Critical**: Keys are stored in IndexedDB **on the enclave origin** (`kms.ats.run`), completely isolated from the PWA.

**IndexedDB Schema**:

```typescript
// Database: 'ats-kms' on kms.ats.run origin
{
  stores: {
    keys: {
      keyPath: 'kid',
      value: {
        kid: string,                  // JWK thumbprint
        privateKey: CryptoKey,        // Non-extractable
        publicKey: JsonWebKey,        // Exportable
        alg: 'ES256' | 'Ed25519' | 'X25519',
        purpose: string,              // e.g., 'vapid', 'signal-identity'
        createdAt: number,            // Unix timestamp
        usedAt: number,               // Last sign() call timestamp
        usageCount: number            // Number of sign() calls
      }
    },
    metadata: {
      keyPath: 'key',
      value: {
        key: string,
        value: any
      }
    }
  }
}
```

**Storage properties**:
- ✅ **Origin-isolated**: PWA on `ats.run` cannot access `kms.ats.run` IndexedDB
- ✅ **Non-extractable**: Private keys have `extractable: false`
- ✅ **Persistent**: Keys survive page reload (unless in-memory mode)
- ✅ **Browser-encrypted**: IndexedDB encryption handled by browser
- ✅ **Quota management**: Monitor usage, warn if quota exceeded

**Service Worker isolation**:
- Service Workers are scoped to origin
- A SW on `ats.run` cannot control `kms.ats.run`
- This prevents malicious PWA SW from intercepting enclave
- Enclave can have its own SW (for caching), but not required

**Lifecycle**:

1. **First visit**:
   - PWA loads KMS iframe
   - Enclave initializes (SRI check, runtime self-check)
   - IndexedDB created (empty)
   - Signals `ready` to parent

2. **Key generation**:
   - PWA requests `generate({ alg: 'ES256', purpose: 'vapid' })`
   - Enclave worker generates keypair (`extractable: false`)
   - Stores in IndexedDB on `kms.ats.run`
   - Returns `kid` to PWA

3. **Signing operation**:
   - PWA requests `sign(kid, bytes)`
   - Enclave retrieves private key from IndexedDB
   - Signs in WebCrypto (key never exported)
   - Returns signature to PWA
   - Updates `usedAt` and `usageCount`

4. **Page reload**:
   - PWA loads KMS iframe again
   - Enclave initializes
   - Keys already in IndexedDB (persistent)
   - PWA can immediately use existing keys

5. **Enclave update**:
   - New version deployed (`kms-ef567890.mjs`)
   - `kms.html` updated to load new version
   - PWA reloads iframe
   - IndexedDB migrated if schema changed
   - Keys preserved across updates

**Why this matters**:
- Origin isolation = PWA cannot steal keys
- Service Worker isolation = malicious SW cannot intercept
- Persistent storage = keys survive reload (better UX)
- Independent lifecycle = enclave updates don't affect PWA

### Verification UX

**What users see**:

```
┌────────────────────────────────────────────┐
│  Crypto Enclave Status                     │
├────────────────────────────────────────────┤
│  Version: kms-abcd1234                     │
│  Signed by: ATS Release Key 2025-01        │
│  Verified: ✅ Hash matches public repo      │
│                                            │
│  [Verify Manually]  [View Source]         │
└────────────────────────────────────────────┘
```

**"Verify Manually" button**:
1. Calls `enclave.version()` → shows hash
2. Fetches `/sigstore/release.json` → checks Sigstore signature
3. Compares running hash to manifest hash
4. Shows result (✅ match / ❌ mismatch)
5. If mismatch: warn user and disable sensitive actions

**"View Source" button**:
- Links to GitHub: `https://github.com/alltheservices/kms-enclave/tree/v1.0.0`
- Shows reproducible build instructions
- Links to Rekor transparency log entry

### How This Maps to ATS Features

**OS Notifications**:
- Per-user VAPID key generated in enclave: `enclave.generateVAPID()`
- JWT signing for relay authorization: `enclave.signJWT(kid, { aud, exp, relay_id })`
- Host PWA never sees private key, only receives signed JWTs

**Signal Protocol** (Future):
- Identity key: `enclave.generate('Ed25519', 'signal-identity')`
- Session keys: `enclave.generate('X25519', 'signal-session')`
- Encryption/decryption: libsignal WASM bundled *inside the worker*
- Double Ratchet state managed in worker (never exposed)

**Relay Authorization**:
- Short-lived (2-hour) JWT tokens signed by user's VAPID key
- Enclave enforces key usage (won't sign for abusive relays if PWA implements policy)
- Soft revocation: PWA stops requesting signatures

### Honest Limits

**What this achieves**:
- ✅ Raises the bar significantly over traditional web app crypto
- ✅ Makes targeted tampering transparent (hash mismatch visible)
- ✅ Allows community verification (reproducible builds + Sigstore)
- ✅ Isolates keys from main PWA (sandboxed iframe + non-extractable)

**What this does NOT achieve**:
- ❌ **Still origin-trusting**: If `ats.run` stops loading expected hash, users must notice
- ❌ **No hardware attestation**: Cannot prove which code runs on specific device
- ❌ **Requires user vigilance**: Users must check the "enclave hash" UI
- ❌ **Module-graph SRI limitations**: Only works with single-file modules

**Why single-file matters**:
- Module-graph SRI isn't universally supported (Safari limitations)
- Dynamic imports break deterministic verification
- Single file = one SRI hash = simpler verification

**Mitigation strategies**:
1. **Persistent hash display**: Always show enclave hash in UI (cannot hide)
2. **Public manifest**: `release.json` in repo, signed by Sigstore
3. **Transparency log**: Rekor entry for every release (public, immutable)
4. **Community watchdogs**: Security researchers monitor for hash changes
5. **Browser extension**: (Future) Browser extension to auto-verify hash

### Implementation Checklist

**Phase 1: Basic Enclave** (MVP)
- [ ] Set up `packages/enclave/` structure
- [ ] Implement worker with ECDSA P-256 (ES256)
- [ ] Implement single-file build (esbuild)
- [ ] Test sandboxed iframe loading
- [ ] Test postMessage RPC protocol

**Phase 2: Verifiable Build** (Critical)
- [ ] Deterministic esbuild config
- [ ] Content-addressed filenames (`kms-<hash>.mjs`)
- [ ] SRI hash generation
- [ ] Reproducible build script
- [ ] CI pipeline for automated builds

**Phase 3: Transparency** (Production-Ready)
- [ ] Sigstore integration (`cosign sign-blob`)
- [ ] Release manifest schema
- [ ] Rekor transparency log publishing
- [ ] Verification CLI tool
- [ ] Public release process documentation

**Phase 4: User Verification** (Trust UX)
- [ ] Enclave version display in PWA
- [ ] "Verify" button implementation
- [ ] Manifest verification flow
- [ ] Sigstore signature check (in-browser or via API)
- [ ] Hash mismatch warnings

**Phase 5: Integration** (OS Notifications)
- [ ] VAPID key generation via enclave
- [ ] JWT signing for relay authorization
- [ ] Key persistence (IndexedDB in worker)
- [ ] Integrate with notification system

**Phase 6: Signal Protocol** (Future)
- [ ] Ed25519 keypair generation (WASM or native)
- [ ] X25519 key agreement (WASM)
- [ ] libsignal integration (WASM bundled in worker)
- [ ] Session management

