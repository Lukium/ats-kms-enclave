# Security Model and Threat Analysis

## Security Boundaries

### Boundary 1: Parent PWA ↔ KMS Iframe

**Enforcement**: Browser same-origin policy + sandbox attribute

**Protection**:
- KMS cannot access parent's cookies, localStorage, IndexedDB (different origin)
- KMS cannot navigate parent window
- KMS cannot access parent DOM
- Network requests restricted to same-origin (CSP `connect-src 'self'`)

**Communication**: postMessage only (explicit, auditable)

**Threat**: Malicious PWA trying to steal keys
**Defense**: Cross-origin isolation prevents access even with `allow-same-origin`

### Boundary 2: KMS Iframe ↔ KMS Worker

**Enforcement**: Worker API + no shared memory

**Protection**:
- Worker has no DOM access (cannot be phished)
- Worker runs in separate thread (perf + security)
- No shared memory between iframe and worker

**Communication**: postMessage only

**Threat**: Phishing attack on KMS iframe
**Defense**: Worker has no UI, cannot be tricked into revealing keys

### Boundary 3: KMS Worker ↔ WebCrypto

**Enforcement**: Browser crypto subsystem

**Protection**:
- Private keys marked non-extractable (browser enforces)
- Signing happens inside crypto subsystem
- Keys never exposed to JavaScript

**Communication**: WebCrypto API

**Threat**: Compromised KMS trying to export keys
**Defense**: Browser refuses to export non-extractable keys

### Boundary 4: Code Integrity (SRI)

**Enforcement**: Browser SRI verification

**Protection**:
- Browser computes SHA-384 of loaded script
- Rejects execution if hash doesn't match `integrity` attribute
- Protects against CDN compromise, MITM, malicious SW

**Communication**: N/A (load-time check)

**Threat**: Attacker serving malicious KMS code
**Defense**: Browser refuses to execute code with wrong hash

## Threat Model

### Threats We Defend Against

| Threat | Defense | Effectiveness |
|--------|---------|---------------|
| Malicious PWA update | Cross-origin isolation | High (cannot access KMS) |
| CDN compromise | SRI verification | High (wrong hash rejected) |
| Supply chain attack | Reproducible builds + transparency log | Medium (requires user verification) |
| MITM attack | HTTPS + SRI | High (cannot tamper) |
| Malicious Service Worker | SRI check before execution | High (cannot bypass) |
| Phishing KMS iframe | Worker isolation (no DOM) | High (cannot display UI) |
| Key exfiltration | Non-extractable WebCrypto | High (browser enforces) |

### Threats We Don't Defend Against

| Threat | Why Not Defended | Mitigation |
|--------|------------------|------------|
| Malicious browser extension | Extensions have full browser access | User must only install trusted extensions |
| Compromised OS | OS can access all memory | User must secure their device |
| Physical device access | Attacker has full control | User must physically protect device |
| Browser implementation bug | Cannot control browser code | Keep browser updated, report bugs |
| Sandbox escape 0-day | Zero-day vulnerabilities unknown | Defense in depth, monitoring |

### Assumed Trust

We assume:
- ✅ Browser vendor (Chrome/Firefox/Safari) is not malicious
- ✅ Operating system is not compromised
- ✅ Hardware is not backdoored
- ✅ User protects their device physically

We do NOT assume:
- ❌ CDN provider is trustworthy (SRI protects)
- ❌ Network operator is trustworthy (HTTPS + SRI protects)
- ❌ ATS developers are trustworthy (reproducible builds allow verification)
- ❌ Build service is trustworthy (reproducible builds eliminate trust)

## Open Design Questions

### 1. KMS Hosting Location

**Options**:
- **CDN** (Cloudflare, Fastly): Fast, reliable, potential single point of failure
- **Object Storage** (S3, R2): Simple, cheap, requires CDN for performance
- **Self-Hosted** (Nginx): Full control, more operational overhead
- **IPFS**: Decentralized, slow, limited browser support

**Recommendation**: Start with CDN (Cloudflare R2 + CDN), evaluate decentralized options later.

### 2. Key Backup Strategy

**Options**:
- **No Backup** (device-only): Most secure, lose keys if device lost
- **Encrypted Backup** (passphrase): Convenience, passphrase is weak point
- **Multi-Device Sync** (E2EE): Best UX, most complex to implement
- **Recovery Code** (one-time): Simple, good middle ground

**Recommendation**: Start with no backup (device-only), add recovery code in future.

### 3. Worker vs. Iframe-Only

**Options**:
- **Iframe + Worker**: Maximum isolation (no DOM access in crypto code)
- **Iframe Only**: Simpler, still isolated from parent
- **Performance**: Worker adds ~10ms latency per operation

**Recommendation**: Use Worker for maximum security (defense in depth).

### 4. Transparency Log Service

**Options**:
- **Sigstore** (official): Free, widely adopted, good tooling
- **Custom Server**: More control, operational overhead
- **Git Tags Only**: Simple, less verifiable

**Recommendation**: Use Sigstore (official) for credibility and tooling.

### 5. SRI Update Process

**Options**:
- **Manual Update**: Developer updates SRI hash in PWA code
- **Automated PR**: CI creates PR with new hash
- **Dynamic Loading**: PWA fetches current hash from manifest (less secure)

**Recommendation**: Automated PR for traceability and review.

## Performance Considerations

### Latency Budget

| Operation | Target | Acceptable | Notes |
|-----------|--------|------------|-------|
| KMS Initialization | <500ms | <1s | One-time at page load |
| Generate VAPID | <100ms | <500ms | One-time per device |
| Sign JWT | <50ms | <200ms | Frequent (every 2 hours per relay) |
| Reset VAPID | <100ms | <500ms | Rare (abuse only) |

### Optimization Strategies

1. **Lazy Initialization**: Don't load KMS until needed
2. **Request Batching**: Sign multiple JWTs in one roundtrip
3. **Worker Pool**: Multiple workers for parallel operations (if needed)
4. **Caching**: Cache public key export (doesn't change)
