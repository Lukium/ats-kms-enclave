# Security Model (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-01-24

---

## Table of Contents

1. [Overview](#overview)
2. [Security Boundaries](#security-boundaries)
3. [Threat Model](#threat-model)
4. [Attack Surfaces](#attack-surfaces)
5. [Mitigations](#mitigations)
6. [Trust Assumptions](#trust-assumptions)
7. [Security Properties](#security-properties)
8. [Limitations](#limitations)

---

## Overview

KMS V2 uses **defense in depth** with 5 independent security layers. Compromising one layer doesn't compromise the entire system.

### Design Principle

**Zero Trust Architecture**: Every boundary enforces security independently. No single point of failure.

---

## Security Boundaries

### 5-Layer Defense

```
┌────────────────────────────────────────────────────────────┐
│ LAYER 1: Browser Origin Isolation                          │
│                                                            │
│   kms.ats.run (iframe)  !=  allthe.services (parent)       │
│   → Browser enforces cross-origin policy (SOP)             │
│   → Parent CANNOT access iframe DOM, storage, memory       │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│ LAYER 2: Sandboxed Iframe                                  │
│                                                            │
│   <iframe sandbox="allow-scripts allow-same-origin">       │
│   → Restricts capabilities (no forms, popups, etc.)        │
│   → allow-same-origin safe due to cross-origin isolation   │
│   → CSP headers: default-src 'none'                        │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│ LAYER 3: Dedicated Worker                                  │
│                                                            │
│   Crypto operations run in worker (off-main-thread)        │
│   → No DOM access (no phishing vector)                     │
│   → Isolated from main iframe (separate execution)         │
│   → Message passing only (structured clone)                │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│ LAYER 4: Non-Extractable CryptoKeys                        │
│                                                            │
│   All keys generated with extractable=false                │
│   → Browser crypto subsystem prevents export               │
│   → Even compromised KMS code cannot extract keys          │
│   → Keys used via opaque handles only                      │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│ LAYER 5: Short-Lived Master Secret                         │
│                                                            │
│   MS exists for milliseconds only (per-operation auth)     │
│   → Decrypted on demand during withUnlock                  │
│   → Zeroed in finally block (guaranteed cleanup)           │
│   → No persistent unlock state                             │
└────────────────────────────────────────────────────────────┘
```

### Boundary Explanations

**Layer 1: Origin Isolation**
- **Enforced by**: Browser (Same-Origin Policy)
- **Protects**: All iframe internals from parent PWA
- **Bypassed by**: Browser bugs (rare), extensions (not in scope)

**Layer 2: Sandbox**
- **Enforced by**: Browser sandbox implementation
- **Protects**: Restricts iframe capabilities (no forms, popups, top-level navigation)
- **Note**: `allow-same-origin` safe because Layer 1 already provides isolation

**Layer 3: Worker**
- **Enforced by**: Browser worker execution model
- **Protects**: Crypto operations from DOM manipulation
- **Benefit**: No phishing vector (worker has no DOM access)

**Layer 4: Non-Extractable Keys**
- **Enforced by**: WebCrypto API implementation
- **Protects**: Application keys from extraction
- **Limitation**: Browser must implement correctly (trust assumption)

**Layer 5: Short-Lived MS**
- **Enforced by**: Application code (`withUnlock` pattern)
- **Protects**: Reduces memory dumping window
- **Benefit**: No persistent unlock state (every operation requires auth)

---

## Threat Model

### Threat Categories

1. **Network Attacks** (TLS, HTTPS, CDN compromise)
2. **Supply Chain Attacks** (malicious dependencies, build compromise)
3. **Code Injection** (XSS, CSP bypass)
4. **Phishing** (fake origin, typosquatting)
5. **Memory Dumping** (cold boot, memory dumps)
6. **Side Channels** (timing, cache, spectre)
7. **Brute Force** (offline password cracking)
8. **Physical Access** (device theft, screen capture)

### What's Protected

✅ **Scenario 1: Malicious PWA Update**
- **Attack**: Parent PWA compromised (malicious update)
- **Protection**: Layer 1 (origin isolation) prevents PWA from accessing KMS internals
- **Result**: Keys remain safe

✅ **Scenario 2: XSS in Parent PWA**
- **Attack**: Attacker injects script into parent PWA
- **Protection**: Layer 1 (SOP) + Layer 2 (sandbox) prevent cross-origin access
- **Result**: Keys remain safe

✅ **Scenario 3: Compromised CDN**
- **Attack**: CDN serves malicious `kms.mjs`
- **Protection**: SRI verification (browser rejects hash mismatch)
- **Protection**: Self-attestation (KMS verifies own code at runtime)
- **Result**: Browser blocks execution OR KMS detects mismatch and locks down

✅ **Scenario 4: Memory Snapshot (Unlocked State)**
- **Attack**: Attacker captures memory dump during unlock
- **Protection**: Layer 5 (MS exists for milliseconds only)
- **Protection**: Cleanup (MS zeroed after operation)
- **Result**: Small time window (~200ms), reduced risk

✅ **Scenario 5: Offline Brute Force**
- **Attack**: Attacker steals encrypted MS, attempts to crack passphrase
- **Protection**: Calibrated PBKDF2 (150-300ms per attempt)
- **Protection**: Strong password requirements
- **Result**: Millions of years for strong passwords

✅ **Scenario 6: Key Extraction via XSS in KMS**
- **Attack**: Attacker compromises KMS code, tries to export keys
- **Protection**: Layer 4 (non-extractable keys)
- **Result**: WebCrypto API refuses export (browser enforced)

### What's NOT Protected

❌ **Scenario A: Browser Extension with Full Access**
- **Attack**: Malicious extension with permissions to read all content
- **Protection**: None (extensions are outside security model)
- **Mitigation**: User education, browser warnings

❌ **Scenario B: Compromised OS (Kernel-Level)**
- **Attack**: Rootkit or compromised OS
- **Protection**: None (OS is trusted computing base)
- **Mitigation**: Hardware security modules (future), secure boot

❌ **Scenario C: Physical Device Access (Unlocked)**
- **Attack**: Attacker physically accesses unlocked device
- **Protection**: None (user authentication assumed valid)
- **Mitigation**: Reauthentication timeouts, screen lock

❌ **Scenario D: Phishing (User Enters Passphrase on Fake Site)**
- **Attack**: User enters passphrase on attacker-controlled site
- **Protection**: None (user responsibility)
- **Mitigation**: WebAuthn (origin-bound), user education

❌ **Scenario E: Browser Implementation Bugs**
- **Attack**: WebCrypto API bug allows key extraction
- **Protection**: None (browser is trusted)
- **Mitigation**: Browser updates, vendor audits

---

## Attack Surfaces

### 1. Network Layer

**Surface**: HTTPS connection to `kms.ats.run`

**Attacks**:
- Man-in-the-middle (MITM)
- Certificate authority compromise
- DNS hijacking

**Mitigations**:
- HTTPS with HSTS (HTTP Strict Transport Security)
- SRI (Subresource Integrity) on `<script>` tags
- Certificate Transparency monitoring
- Self-attestation (runtime integrity check)

### 2. Code Delivery

**Surface**: JavaScript artifacts served from CDN

**Attacks**:
- CDN compromise (malicious artifact)
- Build process compromise
- Supply chain attack (malicious dependency)

**Mitigations**:
- Reproducible builds (deterministic artifacts)
- SRI verification (browser enforces hash)
- Sigstore signatures (transparency log)
- Self-attestation (KMS verifies own code)

### 3. Browser Environment

**Surface**: Browser execution environment

**Attacks**:
- XSS in parent PWA
- Malicious browser extensions
- Browser bugs (sandbox escape)

**Mitigations**:
- Origin isolation (SOP)
- Sandboxed iframe
- CSP headers (strict policy)
- Minimal code surface (~500 lines target)

### 4. Storage Layer

**Surface**: IndexedDB (encrypted configs and wrapped keys)

**Attacks**:
- Ciphertext tampering
- Ciphertext swapping (replay attacks)
- Log truncation

**Mitigations**:
- AES-GCM authentication tags
- AAD (Additional Authenticated Data)
- Sequence numbers in audit log
- Tamper-evident audit chain

### 5. Cryptographic Layer

**Surface**: Cryptographic operations (PBKDF2, AES-GCM, ECDSA, Ed25519)

**Attacks**:
- Weak passwords (brute force)
- Side-channel attacks (timing, cache)
- Algorithm vulnerabilities

**Mitigations**:
- Calibrated PBKDF2 (150-300ms per attempt)
- Standard algorithms (NIST, RFC)
- Constant-time operations (KCV verification)
- WebCrypto API (browser-provided implementations)

### 6. User Interface

**Surface**: Parent PWA UI that initiates KMS operations

**Attacks**:
- Phishing (fake UI)
- Clickjacking
- Social engineering

**Mitigations**:
- Origin verification (check `window.location.origin`)
- Visual indicators (lock icon, origin display)
- User education
- WebAuthn (origin-bound, resistant to phishing)

### 7. WebAuthn PRF Security

**Surface**: WebAuthn PRF-based key derivation

**Attacks**:
- Downgrade to gate-only mode (weaker security)
- Bypassing user verification
- Authenticator compromise

**Mitigations**:
- **CRITICAL**: `userVerification: "required"` MUST be enforced for all PRF operations
- See [WebAuthn PRF Requirements](./01-primitives.md#13-webauthn-prf-requirements)
- Gate-only mode strictly rate-limited and flagged in telemetry
- UV performance check: Verify `assertion.response.userVerificationPerformed === true`
- Platform authenticator preferred (device-bound, harder to compromise)

**PRF vs Gate-Only Comparison**:

| Property | PRF Mode | Gate-Only Mode |
|----------|----------|----------------|
| User Verification | Required | Required |
| Key Derivation | PRF output (32 bytes entropy) | Passphrase + encrypted pepper |
| Security Level | High (hardware-backed) | Medium (password-based) |
| Rate Limiting | Standard (50 attempts/hour) | Strict (20 attempts/hour) |
| Telemetry Flag | `gateOnlyMode: false` | `gateOnlyMode: true` |
| UI Indicator | Normal | "Enhanced security unavailable" |

---

## Mitigations

### Cryptographic Mitigations

| Threat | Mitigation | Layer |
|--------|------------|-------|
| Weak passwords | Calibrated PBKDF2 (150-300ms) | Crypto |
| Brute force | High iteration count (50k-2M) | Crypto |
| Ciphertext tampering | AES-GCM authentication tag | Crypto |
| Replay attacks | AAD with metadata binding | Crypto |
| Key extraction | Non-extractable CryptoKeys | Browser |
| Memory dumping | Short-lived MS (milliseconds) | Application |

### Architectural Mitigations

| Threat | Mitigation | Layer |
|--------|------------|-------|
| Malicious PWA | Origin isolation (SOP) | Browser |
| XSS in parent | Sandboxed iframe | Browser |
| DOM manipulation | Dedicated Worker | Application |
| Phishing | WebAuthn origin binding | Protocol |
| CDN compromise | SRI + self-attestation | Build + Runtime |
| Log tampering | Ed25519 signatures | Crypto |
| Log truncation | Sequence numbers | Application |

### Operational Mitigations

| Threat | Mitigation | Layer |
|--------|------------|-------|
| Supply chain | Reproducible builds | Build |
| Build compromise | Sigstore transparency | Build |
| Version confusion | Explicit versioning | Application |
| Configuration errors | Schema validation | Application |
| Audit tampering | Tamper-evident chain | Application |

---

## Trust Assumptions

### What We Must Trust

1. **Browser Vendor**
   - Correct implementation of Same-Origin Policy
   - Correct implementation of sandbox
   - Correct implementation of WebCrypto API
   - Timely security updates

2. **Operating System**
   - Memory isolation between processes
   - No kernel-level malware
   - Secure storage for IndexedDB
   - Entropy sources for CSPRNG

3. **Hardware**
   - CPU implements instructions correctly
   - Hardware RNG provides entropy
   - No hardware backdoors

4. **User**
   - Chooses strong passphrase
   - Verifies origin before entering credentials
   - Keeps device secure (screen lock, encryption)
   - Updates browser regularly

5. **DNS and PKI**
   - DNS returns correct IP for `kms.ats.run`
   - Certificate authorities issue certs correctly
   - TLS protects traffic

### What We DON'T Trust

❌ **Parent PWA**: Could be compromised by malicious update
❌ **CDN**: Could serve malicious artifacts (mitigated by SRI)
❌ **Network**: Could be monitored or manipulated (mitigated by HTTPS)
❌ **Build Service**: Could be compromised (mitigated by reproducible builds)
❌ **Developers**: Could push malicious code (mitigated by community verification)

---

## Security Properties

### Confidentiality

**Property**: Private keys never leave KMS boundary in plaintext.

**Enforcement**:
- Layer 4: Non-extractable CryptoKeys
- Layer 5: MS encrypted at rest, decrypted only during `withUnlock`
- Application: All keys wrapped with MKEK + AAD

**Exceptions**:
- Explicit backup ceremony (audit:export) with user confirmation
- During unlock window (~200ms) MS exists in memory

### Integrity

**Property**: All stored data is tamper-evident.

**Enforcement**:
- AES-GCM authentication tags (config, wrapped keys)
- AAD binds ciphertext to metadata
- Audit log chain with Ed25519 signatures
- Sequence numbers detect truncation

**Verification**:
- On load: Verify GCM tags
- Periodically: Verify audit chain
- On demand: Full consistency check

### Authenticity

**Property**: Operations are attributable to authenticated user.

**Enforcement**:
- Per-operation authentication (no persistent unlock)
- Audit log with timestamps and requestId
- Ed25519 signatures on audit entries
- Non-repudiation (audit key non-extractable)

**Limitations**:
- Cannot prove user identity (only that authentication succeeded)
- Cannot prevent user from sharing credentials

### Availability

**Property**: User can always access keys with valid credentials.

**Enforcement**:
- Multi-enrollment (multiple credentials → same MS)
- Backup/export mechanism (encrypted backup bundles)
- Self-contained (no external dependencies for crypto ops)

**Risks**:
- Last credential lost → permanent lockout
- Backup password forgotten → backup useless
- Browser storage cleared → data loss (if no backup)

---

## Limitations

### 1. JavaScript Memory Safety

**Limitation**: JavaScript cannot guarantee memory isolation.

**Impact**: MS exists in memory during unlock (~200ms).

**Mitigation**:
- Minimize duration
- Zero buffer after use
- Accept residual risk

### 2. Browser as Trusted Computing Base

**Limitation**: Must trust browser implementation.

**Impact**: Browser bugs could defeat all protections.

**Mitigation**:
- Use standard APIs (audited by vendors)
- Encourage browser updates
- Monitor for browser CVEs

### 3. No Hardware Security Module

**Limitation**: Keys stored in software (IndexedDB).

**Impact**: OS-level compromise defeats all protections.

**Mitigation**:
- Future: WebAuthn PRF for hardware-backed keys
- Future: TPM integration (if APIs available)
- Accept limitation for web-based KMS

### 4. User Education Required

**Limitation**: Cannot prevent user from entering passphrase on phishing site.

**Impact**: Credentials leaked to attacker.

**Mitigation**:
- WebAuthn (origin-bound, resists phishing)
- Visual indicators (origin display)
- User education (verify URL)
- Accept residual risk

### 5. Browser Extensions Outside Security Model

**Limitation**: Extensions can read all page content.

**Impact**: Extension could extract MS during unlock.

**Mitigation**:
- User education (only install trusted extensions)
- Browser warnings for sensitive permissions
- Accept limitation (unavoidable in web context)

### 6. Background Execution Constraints

**Limitation**: Mobile platforms (iOS, Android) suspend JavaScript execution in background.

**Impact**: KMS cannot mint tokens while PWA is suspended.

**Environmental Constraints**:

**iOS Specific**:
- Background execution extremely limited (5-30 seconds)
- Service Worker may be terminated after ~30 seconds inactive
- Push notifications wake app but execution limited
- WebAuthn may not work in background (platform-dependent)

**Android Specific**:
- Background execution more lenient but still limited
- Doze mode aggressively suspends apps after inactivity
- Service Worker may be kept alive longer
- WebAuthn generally works in background

**Mitigation Strategy**:

```typescript
/**
 * Background token stashing strategy.
 *
 * PWA maintains pre-minted token stashes sized for ~1 hour operation:
 * - Active relay: 6-8 overlapping tokens
 * - Standby relay: 2-3 tokens
 * - Total coverage: ~60-120 minutes offline
 *
 * Lifecycle hooks:
 * - visibilitychange: Top up stash before backgrounding
 * - focus: Prune expired and refresh on resume
 * - pageshow: Full refresh after page restore
 */
document.addEventListener('visibilitychange', async () => {
  if (document.hidden) {
    // Going to background - pre-mint stash
    console.log('Backgrounding: topping up token stash');
    await topUpStash(activeRelay, target = 8);
    await topUpStash(standbyRelay, target = 3);
  } else {
    // Returning to foreground - refresh
    console.log('Foregrounded: refreshing tokens');
    pruneExpiredTokens();
    await topUpStash(activeRelay, target = 6);
    await topUpStash(standbyRelay, target = 3);
  }
});

/**
 * Handle suspended state (PWA suspended >1.5 hours).
 *
 * If stash expires while suspended:
 * - Relay queues notifications until tokens available
 * - On resume: request fresh tokens from KMS
 * - User may see brief delay in notification delivery
 */
async function handleSuspendedState() {
  const stash = getActiveStash();
  const allExpired = stash.every(t => t.exp < Date.now());

  if (allExpired) {
    console.warn('All tokens expired during suspension - requesting fresh');
    await requestFreshTokens(activeRelay, count = 6);
  }
}
```

**Stash Sizing**:
- **Active relay**: 6-8 tokens (10-15min each) = 60-120 minutes coverage
- **Standby relay**: 2-3 tokens = 20-45 minutes coverage
- **Renewal trigger**: 60% of JWT TTL (~6-9 minutes)
- **Background top-up**: On `visibilitychange` (going background)
- **Foreground refresh**: On `visibilitychange` (coming foreground)

**Reality Check**:
- If PWA suspended >1.5 hours, all tokens expire
- On resume: KMS must mint fresh tokens (requires unlock if MS expired)
- Brief notification delay acceptable (user was away)

---

## Security Properties Summary

| Property | V1 | V2 | Improvement |
|----------|----|----|-------------|
| Origin isolation | ✅ Yes | ✅ Yes | Same |
| Sandbox | ✅ Yes | ✅ Yes | Same |
| Worker isolation | ✅ Yes | ✅ Yes | Same |
| Non-extractable keys | ✅ Yes | ✅ Yes | Same |
| Short-lived MS | ✅ Yes | ✅ Yes | Same |
| AAD everywhere | ❌ No | ✅ Yes | **NEW** |
| Sequence numbers | ❌ No | ✅ Yes | **NEW** |
| Non-extractable audit key | ⚠️ Extractable | ✅ Non-extractable | **Improved** |
| Multi-enrollment | ❌ No | ✅ Yes | **NEW** |
| Calibrated PBKDF2 | ❌ Fixed | ✅ Adaptive | **Improved** |
| Standard KCV | ⚠️ Custom | ✅ Standard | **Improved** |
| Deterministic HKDF salt | ❌ All zeros | ✅ Deterministic | **Improved** |

---

## References

- **OWASP Top 10**: Web Application Security Risks
- **NIST SP 800-53**: Security and Privacy Controls
- **Same-Origin Policy**: RFC 6454
- **Content Security Policy**: W3C CSP Level 3
- **Web Crypto API**: W3C Web Cryptography API
- **WebAuthn Security**: W3C WebAuthn Level 2 Security Considerations

---

**Next**: [09-backup-export.md](./09-backup-export.md) - Backup bundles and cross-device sync
