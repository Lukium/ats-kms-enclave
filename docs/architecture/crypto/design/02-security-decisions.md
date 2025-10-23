# Critical Security Decisions

## Sandbox: `allow-scripts allow-same-origin`

**Important**: The iframe sandbox includes `allow-same-origin` despite the common advice against it.

**Why this is safe**:
- Enclave is on **different origin** (`kms.ats.run` ≠ `allthe.services`)
- Browser's same-origin policy still enforces isolation
- CSP + cross-origin = defense in depth

**Why this is necessary**:
- Without `allow-same-origin`, iframe has **opaque origin** (`"null"`)
- Opaque origin breaks runtime self-check (`fetch(import.meta.url)` blocked by CSP)
- IndexedDB can be unreliable under opaque origins
- CSP `connect-src 'self'` doesn't work (`'self'` = `null` ≠ `kms.ats.run`)

**Isolation layers**:
1. **Cross-origin**: `kms.ats.run` ≠ `allthe.services` (browser enforces)
2. **CSP**: Enclave has `frame-ancestors https://allthe.services` (only PWA can embed)
3. **No external network**: Only same-origin requests for self-verification
4. **Non-extractable keys**: WebCrypto enforces at crypto subsystem level

**What parent PWA CANNOT do** (despite `allow-same-origin`):
- ❌ Access enclave's IndexedDB (different origin)
- ❌ Access enclave's localStorage (different origin)
- ❌ Access enclave's cookies (different origin)
- ❌ Call enclave's functions directly (different origin)
- ✅ Only communicate via postMessage (explicit, auditable)

## SRI: Only on Script Tags, Not Iframes

**Important**: Subresource Integrity (SRI) does NOT work on `<iframe>` elements.

**Wrong approach** (doesn't work):
```typescript
iframe.setAttribute('integrity', 'sha256-...')  // ❌ No-op, browsers ignore
```

**Correct approach** (SRI inside kms.html):
```html
<!-- kms.html loaded by iframe -->
<script type="module"
        src="/artifacts/kms-abcd1234.mjs"
        integrity="sha256-ABCD..."
        crossorigin="anonymous">
</script>
```

**Why this matters**:
- SRI verification happens when browser loads the module script
- If artifact is tampered, browser refuses to execute
- Protects against CDN compromise, MITM, malicious SW

**Verification chain**:
1. PWA loads `kms.html` (no SRI possible on iframe)
2. `kms.html` loads `kms-abcd1234.mjs` with SRI attribute
3. Browser verifies hash before executing
4. Runtime self-check provides additional verification
