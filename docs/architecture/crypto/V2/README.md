# KMS Architecture V2

**Status**: Design Phase
**Date**: 2025-10-24
**Supersedes**: V1 Architecture (`docs/architecture/crypto/`)

---

## What's New in V2

V2 addresses critical security gaps identified in the V1 architecture through community security review. This version maintains V1's strong foundational principles while adding production-hardened cryptographic practices.

### Key Improvements

1. **Calibrated KDF**: Device-specific PBKDF2 iteration counts targeting 150-300ms (or Argon2id via WASM)
2. **Proper Metadata Binding**: AES-GCM AAD for all encryptions prevents ciphertext replay/swapping
3. **Standard Key Check Value (KCV)**: Replaces custom verification hash with `HMAC(KEK, "ATS/KCV/v1")`
4. **Deterministic Salt Management**: Non-zero, versioned salts for HKDF operations
5. **Hardened Audit Log**: Non-extractable signing keys, sequence numbers, periodic anchors
6. **Multi-Enrollment Support**: Single MS wrapped by multiple credentials (passphrase + N passkeys)
7. **Explicit Versioning**: All configs include `kmsVersion`, `algVersion`, and algorithm parameters
8. **Key Rotation Paths**: Clear procedures for re-encrypting MS under new methods
9. **Backup/Export Strategy**: Secure JSON bundle format for cross-device sync
10. **PBKDF2 Calibration**: On-device tuning and adaptive adjustment over time

### What Stayed Strong from V1

✅ Per-operation authentication (no persistent unlock state)
✅ Master Secret (MS) encryption pattern
✅ Single unlock gate (`withUnlock`) with guaranteed cleanup
✅ Non-extractable CryptoKeys
✅ Cross-origin isolation and sandboxed worker
✅ Content-derived key identifiers (JWK thumbprint)
✅ Tamper-evident audit chain

---

## Implementation Priority

### Current Focus: VAPID Leases for User-Run Relays (MVP)

The **primary use case** for KMS V2 is providing secure VAPID JWT signing for user-run relay servers:

- Production-ready KMS with VAPID keypair management
- Lease-based authorization model (8-12h leases, 10-15min JWTs)
- Relay-agnostic design for seamless failover
- Quota enforcement and abuse prevention
- Full auditability (every JWT issuance logged)

See **[12-vapid-leases.md](./design/12-vapid-leases.md)** for complete specifications.

### Future Enhancements (Post-MVP)

After the VAPID MVP is production-ready and stable, the following enhancements are planned:

1. **Signal Protocol Integration** ([10-signal-protocol.md](./design/10-signal-protocol.md))
   - End-to-end encrypted messaging
   - Ed25519 identity keys and X25519 key agreement
   - Double Ratchet with forward secrecy

2. **Argon2id KDF Option** (see [07-calibration.md](./design/07-calibration.md))
   - Memory-hard KDF via WASM
   - Better resistance to GPU/ASIC attacks

3. **Hardware Security Module Integration**
   - TPM integration (if browser APIs available)
   - Enhanced WebAuthn PRF usage

4. **Cloud-Based Backup Sync**
   - Automatic cross-device synchronization
   - End-to-end encrypted backup bundles

---

## V1 → V2 Migration

### Breaking Changes

1. **Config Schema**: All configs now include `kmsVersion: 2`, `algVersion`, and expanded metadata
2. **Encryption Format**: `encryptedMS` now includes AAD; old ciphertexts cannot be decrypted
3. **Verification Method**: KCV replaces custom verification hash
4. **HKDF Salts**: MKEK derivation uses deterministic non-zero salt
5. **Audit Log**: New fields (`seqNum`, `kmsVersion`, `keyId` reference instead of embedded pubkey)

### Migration Path

**Users must reset and re-setup** (one-time, breaking change):

1. **Export V1 Data** (optional backup):
   - Export public keys and audit logs for archival
   - No way to migrate wrapped keys (MS derivation changed)

2. **Reset KMS**: Clear all V1 data

3. **Setup V2**:
   - Run PBKDF2 calibration
   - Setup passphrase with calibrated iterations
   - Setup additional methods (passkeys)
   - Regenerate application keys

**Rationale**: Security improvements require fundamental changes to encrypted data structures. Clean break ensures no hybrid V1/V2 state bugs.

---

## Documentation Structure

### Core Documents

- **[README.md](./README.md)** (this file): V2 overview and migration guide
- **[crypto-spec.md](./crypto-spec.md)**: Complete cryptographic specification with diagrams
- **[security-improvements.md](./security-improvements.md)**: Detailed rationale for each V2 change
- **[implementation-checklist.md](./implementation-checklist.md)**: Step-by-step implementation guide

### Design Components (`design/`)

V2 design docs are reorganized for clarity:

- **[01-primitives.md](./design/01-primitives.md)**: Crypto primitives (PBKDF2, HKDF, AES-GCM, ECDSA, Ed25519)
- **[02-master-secret.md](./design/02-master-secret.md)**: MS generation, KEK derivation, encryption with AAD
- **[03-unlock-context.md](./design/03-unlock-context.md)**: `withUnlock` implementation, timing, cleanup
- **[04-key-operations.md](./design/04-key-operations.md)**: VAPID generation, JWT signing, key wrapping
- **[05-audit-log.md](./design/05-audit-log.md)**: Hardened audit with sequence numbers and anchors
- **[06-multi-enrollment.md](./design/06-multi-enrollment.md)**: Multiple credentials wrapping same MS
- **[07-calibration.md](./design/07-calibration.md)**: PBKDF2/Argon2id calibration algorithm
- **[08-security-model.md](./design/08-security-model.md)**: Threat model, attack surfaces, mitigations
- **[09-backup-export.md](./design/09-backup-export.md)**: Backup bundle format and sync strategy
- **[10-signal-protocol.md](./design/10-signal-protocol.md)**: **FUTURE** - Signal Protocol integration with capability tokens
- **[11-iframe-isolation.md](./design/11-iframe-isolation.md)**: Iframe isolation, CSP headers, verifiable enclave, SRI
- **[12-vapid-leases.md](./design/12-vapid-leases.md)**: **PRIMARY MVP USE CASE** - VAPID leases for user-run relays

---

## Quick Reference

### V2 Crypto Stack

```
User Authentication
    ↓
Passphrase → PBKDF2-SHA256 (calibrated iters, 150-300ms) → KEK
Passkey PRF → HKDF-SHA256 → KEK
    ↓
KEK + AES-256-GCM (with AAD) → encryptedMS
    ↓
MS + HKDF-SHA256 (deterministic salt) → MKEK
    ↓
MKEK + AES-GCM (with AAD) → wrapped application keys
    ↓
Application Keys (ECDSA P-256 for VAPID, Ed25519 for audit)
```

### V2 Configuration Schema

```typescript
// Passphrase Config (V2)
{
  kmsVersion: 2,
  algVersion: 1,
  method: 'passphrase',

  // KDF params (stored for migration/recalibration)
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256',
    iterations: number,        // Calibrated per device
    salt: ArrayBuffer,         // 16 bytes random
    lastCalibratedAt: number,  // Timestamp
    platformHash: string       // Coarse device fingerprint
  },

  // Key Check Value (replaces verificationHash)
  kcv: ArrayBuffer,            // HMAC(KEK, "ATS/KCV/v1")

  // Encrypted Master Secret
  encryptedMS: ArrayBuffer,    // 32-byte MS + 16-byte tag
  msIV: ArrayBuffer,           // 12 bytes (AES-GCM IV)
  msAAD: ArrayBuffer,          // AAD for metadata binding
  msVersion: 1,                // Re-encryption tracking

  createdAt: number,
  updatedAt: number
}

// Passkey PRF Config (V2)
{
  kmsVersion: 2,
  algVersion: 1,
  method: 'passkey-prf',

  // WebAuthn credential
  credentialId: ArrayBuffer,
  rpId: string,

  // HKDF params
  kdf: {
    algorithm: 'HKDF-SHA256',
    appSalt: ArrayBuffer,      // 32 bytes (for PRF eval.first)
    hkdfSalt: ArrayBuffer,     // 32 bytes (for HKDF, distinct from appSalt)
    info: 'ATS/KMS/KEK-wrap/v2'
  },

  // Encrypted MS (same structure as passphrase)
  encryptedMS: ArrayBuffer,
  msIV: ArrayBuffer,
  msAAD: ArrayBuffer,
  msVersion: 1,

  createdAt: number,
  updatedAt: number
}

// Wrapped Key (V2)
{
  kid: string,                 // JWK thumbprint
  kmsVersion: 2,

  // Wrapped key data
  wrappedKey: ArrayBuffer,
  iv: ArrayBuffer,
  aad: ArrayBuffer,            // AAD = {kid, alg, purpose, createdAt, kmsVersion}

  // Public key and metadata
  publicKeyRaw: ArrayBuffer,
  alg: 'ES256' | 'EdDSA',
  purpose: 'vapid' | 'audit' | 'identity',

  createdAt: number,
  lastUsedAt?: number
}

// Audit Entry (V2)
{
  kmsVersion: 2,
  seqNum: number,              // Monotonic sequence (truncation detection)
  timestamp: number,

  // Operation
  op: string,
  kid: string,
  requestId: string,
  origin?: string,

  // Unlock timing
  unlockTime: number,
  lockTime: number,
  duration: number,

  // Details
  details?: Record<string, unknown>,

  // Chain integrity
  previousHash: string,
  chainHash: string,

  // Signature
  signature: string,           // Ed25519 signature of chainHash
  auditKeyId: string           // Reference to audit key (not embedded pubkey)
}
```

### Security Properties (V2)

| Property | V1 | V2 | Notes |
|----------|----|----|-------|
| MS lifetime | ✅ Milliseconds | ✅ Milliseconds | Same |
| Non-extractable keys | ✅ Yes | ✅ Yes | Same |
| Per-operation auth | ✅ Yes | ✅ Yes | Same |
| Metadata binding | ❌ No AAD | ✅ AAD everywhere | **New** |
| KDF calibration | ❌ Fixed | ✅ Device-specific | **New** |
| Password verification | ⚠️ Custom | ✅ Standard KCV | **Improved** |
| HKDF salt | ⚠️ All zeros | ✅ Deterministic | **Improved** |
| Audit truncation | ❌ Vulnerable | ✅ Sequence numbers | **Fixed** |
| Audit key extractable | ⚠️ Yes | ✅ No (with export) | **Improved** |
| Multi-enrollment | ❌ No | ✅ N credentials | **New** |
| Backup/export | ❌ No | ✅ Secure bundle | **New** |
| Config versioning | ⚠️ Implicit | ✅ Explicit | **New** |

---

## Implementation Status

- [ ] V2 Design Documentation (this directory)
- [ ] V2 Cryptographic Specification
- [ ] V2 Implementation Checklist
- [ ] PBKDF2 Calibration Algorithm
- [ ] Updated `unlock.ts` with V2 primitives
- [ ] Updated `worker.ts` with V2 operations
- [ ] Updated storage schemas
- [ ] Migration tooling (V1 → V2)
- [ ] Updated tests for V2
- [ ] Browser compatibility testing

---

## References

### Standards

- **PBKDF2**: NIST SP 800-132, RFC 8018
- **HKDF**: RFC 5869
- **AES-GCM**: NIST SP 800-38D
- **ECDSA**: FIPS 186-4, SEC 1
- **Ed25519**: RFC 8032
- **WebAuthn**: W3C WebAuthn Level 2
- **JWS/JWT**: RFC 7515, RFC 7519
- **VAPID**: RFC 8292
- **JWK Thumbprint**: RFC 7638

### Security Resources

- OWASP Key Management Cheat Sheet
- Web Crypto API Best Practices
- WebAuthn PRF Extension
- Argon2 RFC 9106

---

## Contributing

When updating V2 docs:

1. **Precision**: Include exact byte sizes, algorithm names, and parameter values
2. **Rationale**: Explain *why* each choice was made (security, compatibility, performance)
3. **Examples**: Provide TypeScript snippets for complex operations
4. **Cross-references**: Link related sections (e.g., AAD usage in multiple places)
5. **Versioning**: Mark any future changes clearly with version bumps

---

## License

Same as parent project: MIT

---

**Next Steps**: Read [crypto-spec.md](./crypto-spec.md) for the complete cryptographic specification.
