# ATS KMS Enclave - Phase 0 Demo

This is an **enhanced progressive verification demo** that proves the KMS implementation is correct by showing explicit, verifiable proofs at each stage.

## What Makes This Demo Different

Instead of just showing "✓ Success", this demo displays:
- **Numeric proofs** (byte counts, flag values, hash lengths)
- **Progressive verification** (cards fill in as you complete each stage)
- **Educational explanations** ("Why this matters" for each check)
- **Full values** (complete keys, JWTs, thumbprints with lengths)

## How to Run

```bash
# Start the demo server
pnpm demo

# Or specifically for Phase 0
pnpm demo:phase-0

# The demo will open at: http://localhost:5173
```

## Progressive Stages

You can either run each stage individually or click "Run Full Demo" to execute all stages at once.

### Stage 1: Generate VAPID Keypair 🔑

**What it does:**
- Generates P-256 ECDSA keypair with `extractable: false`
- Exports public key in raw format (65 bytes)
- Computes RFC 7638 JWK thumbprint as key ID
- Displays full public key with length

**Verification cards populated:**
- ✅ **Public Key Verification**
  - Format: 65 bytes (uncompressed P-256 point)
  - Leading byte: 0x04 (proves uncompressed format)
  - Full base64url value displayed

- ✅ **Key Properties Verification**
  - Algorithm: ECDSA
  - Curve: P-256
  - Extractable: false (private key cannot be exported)
  - Usages: sign, verify
  - JWK Thumbprint: Full RFC 7638 hash

- ⏳ **JWT Verification** (pending - need to sign JWT)

### Stage 2: Sign JWT Token 🎫

**What it does:**
- Signs a VAPID-compliant JWT with the generated key
- Sets audience to `https://fcm.googleapis.com`
- Sets 1-hour expiry (within 24h VAPID requirement)
- Displays JWT parts (header, payload, signature) with lengths

**Verification cards now complete:**
- ✅ **JWT Verification**
  - Algorithm: ES256
  - Kid matches JWK thumbprint (content-derived)
  - Signature: 64 bytes (P-1363 format, not DER)
  - Leading byte: not 0x30 (proves not DER encoding)
  - Token lifetime: within 24h requirement

### Run Full Demo ▶️

Executes both stages sequentially with a brief visual pause between stages so you can watch the cards populate progressively.

## Verification Checks Explained

### 🔑 Public Key Verification

**Format: 65 bytes**
- *Why:* `PushManager.subscribe()` requires exactly 65 bytes
- *Failure:* Using SPKI (91 bytes) or JWK format will cause subscription to fail

**Leading byte: 0x04**
- *Why:* Indicates uncompressed point format
- *Failure:* Compressed format (0x02/0x03) is not supported by all push services

**Base64url encoding**
- *Why:* Standard encoding for web APIs and JSON
- *Shows:* Full encoded value with character count

### 🎫 JWT Signature Verification

**Algorithm: ES256**
- *Why:* VAPID spec requires ECDSA with P-256 and SHA-256
- *Failure:* Other algorithms (RS256, HS256) will be rejected

**Kid matches JWK thumbprint**
- *Why:* RFC 7638 thumbprint is content-derived from public key
- *Benefit:* Auditable, deterministic, prevents kid collisions
- *Shows:* Full thumbprint value (not truncated)

**Signature: 64 bytes (P-1363)**
- *Why:* JWS ES256 requires raw r‖s format (32 + 32 bytes)
- *Problem:* WebCrypto returns DER encoding (~70-72 bytes)
- *Solution:* We convert DER → P-1363 before base64url encoding
- *Failure:* JWT validators will reject DER-encoded signatures

**Leading byte: not 0x30**
- *Why:* DER encoding always starts with 0x30
- *Proves:* Our signature is in P-1363 format, not DER

**Token lifetime: ≤24h**
- *Why:* VAPID spec requires tokens expire within 24 hours
- *Shows:* Relative time (e.g., "60min remaining")
- *Failure:* Push services reject tokens with longer lifetimes

### 🔐 Key Properties Verification

**Algorithm: ECDSA**
- *Why:* Required for VAPID ES256 signatures
- *Shows:* Actual algorithm name from CryptoKey

**Curve: P-256**
- *Why:* Also called secp256r1, required for ES256
- *Alternative:* P-384 or P-521 would fail VAPID validation

**Extractable: false**
- *Why:* Browser refuses to export the private key
- *Security:* Even if host app is compromised, key cannot be stolen
- *Shows:* Actual `extractable` flag from CryptoKey

**Usages: sign, verify**
- *Why:* Key must be allowed to perform signing operations
- *Shows:* Actual usage array from CryptoKey

**JWK Thumbprint (RFC 7638)**
- *Why:* Content-derived identifier, not random
- *Benefit:* Deterministic, auditable, collision-resistant
- *Shows:* Full SHA-256 hash in base64url (43 chars)

## Output Section

Below the verification cards, the demo displays detailed output for each completed stage:

**VAPID Keypair:**
- Kid with length
- Full public key (base64url) with character and byte counts
- Expandable JWK representation (shows x, y coordinates)

**JWT Token:**
- Full JWT with length
- Separate header, payload, signature with lengths
- Expandable decoded header (shows alg, typ, kid)
- Expandable decoded payload (shows aud, sub, exp)

## Files

- **`index.html`** - Progressive demo page with three control buttons
- **`demo.ts`** - Progressive demo logic with stage management
- **`demo-worker.ts`** - Enhanced worker that returns verification metadata
- **`verify.ts`** - Verification utilities (format checkers, JWK thumbprints)
- **`README.md`** - This file

## Visual States

The verification cards use three visual states:

- **✅ Pass** (green) - Check completed successfully
- **❌ Fail** (red) - Check failed (shows reason)
- **⏳ Pending** (gray) - Check waiting for data (shows what's needed)

This makes it immediately clear which checks are complete and which are awaiting action.

## Architecture Decisions

### Why RFC 7638 Thumbprints?

The demo uses RFC 7638 JWK thumbprints as key IDs instead of random/timestamp-based IDs:

**Benefits:**
- Content-derived from public key (deterministic)
- Anyone can verify kid matches the public key
- No collision risk (cryptographic hash)
- Enables key rotation without ambiguity

**Computation:**
```typescript
// Canonical JSON of required JWK fields
const canonical = JSON.stringify({
  crv: jwk.crv,  // "P-256"
  kty: jwk.kty,  // "EC"
  x: jwk.x,      // base64url x-coordinate
  y: jwk.y       // base64url y-coordinate
});

// SHA-256 hash, base64url encoded
const kid = base64url(sha256(canonical));
```

### Why Separate Demo Worker?

The production `worker.ts` returns minimal data for security. The demo's `demo-worker.ts` extends it to return verification metadata:

- JWK representation of keys
- Algorithm and property details
- Decoded JWT parts
- Signature byte counts

This keeps demo-specific code isolated while showing all the proofs users need.

## Development

The demo uses Vite for hot-reloading during development:

```bash
# Start dev server
pnpm demo

# Build for production
pnpm demo:build

# The output goes to example/phase-0/dist/
```

## Acceptance Criteria

When you run the demo and click "Run Full Demo", you should see:

1. **All three verification cards populate progressively**
2. **All checks show green ✅**
3. **Full values displayed** (not truncated with "...")
4. **Numeric proofs visible** (65 bytes, 64 bytes, false, 43 chars)
5. **Output section shows detailed data** with expandable sections
6. **No console errors**

If any check shows ❌ or the reason isn't clear, the implementation has a bug that needs fixing.

## Next Steps (Future Phases)

This Phase 0 demo proves the crypto operations work correctly. Future phases will add:

- **Phase 1:** IndexedDB storage (persistent keys)
- **Phase 2:** Verifiable builds (deterministic artifacts)
- **Phase 3:** Transparency logs (Sigstore/Rekor)
- **Phase 4:** User verification UX (hash display in PWA)
- **Phase 5:** Integration with main PWA (real push notifications)
- **Phase 6:** Signal Protocol (E2EE messaging)

Each phase will extend this demo to show additional verification proofs.
