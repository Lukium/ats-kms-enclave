# Fail-Secure Verification System

**Status:** Design Phase (extends existing self-attestation with runtime enforcement)

## Overview

This document extends the [self-attestation design](./design.md) with a **fail-secure verification mechanism** that allows the KMS enclave to automatically verify its own integrity at runtime and enter a safe lockdown mode if verification fails.

Instead of relying solely on browser SRI (which can fail silently or be bypassed), the KMS actively verifies its deployment against multiple independent sources and refuses to operate if verification fails.

## The Problem

Current self-attestation (design.md) provides:
- ✅ Random verification runs (~3×/day)
- ✅ Public evidence in GitHub Actions
- ✅ SRI verification in browser

But it has gaps:
- ❌ **Delayed detection**: Compromise only detected when next verification runs (up to several hours)
- ❌ **Passive response**: Users see failed workflow but KMS keeps running
- ❌ **No self-awareness**: KMS cannot check its own integrity
- ❌ **Single point of failure**: GitHub Actions downtime = no verification

## The Solution: Fail-Secure Verification

Add runtime verification to the KMS enclave itself:

1. **Machine-readable badge** - Verifier publishes signed `badge.json` with current status
2. **Boot-time verification** - KMS checks badge on startup before accepting operations
3. **Quorum-based decisions** - Require 2-of-3 sources to agree before declaring compromise
4. **Fail-secure mode** - Lock operations but provide clear incident response UI
5. **Operational guardrails** - Sliding window tolerance, backoff, caching

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GitHub Actions                                │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  KMS Verifier Workflow                                         │ │
│  │                                                                 │ │
│  │  1. Rebuild from source                                        │ │
│  │  2. Fetch live artifact                                        │ │
│  │  3. Compare hashes                                             │ │
│  │  4. Verify Sigstore bundle                                     │ │
│  │  5. Generate badge.json ←───────────────┐                      │ │
│  │  6. Sign with Sigstore                  │ NEW                  │ │
│  │  7. Publish as release asset            │                      │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ badge.json + bundle
                                   ↓
                    ┌──────────────────────────────────┐
                    │  GitHub Releases / CDN           │
                    │                                  │
                    │  - badge.json (signed)           │
                    │  - badge.json.bundle (Sigstore)  │
                    │  - Updated every ~3x/day         │
                    └──────────────────────────────────┘
                                   │
                                   │ fetch on startup
                                   ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    KMS Enclave (kms.ats.run)                         │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Boot Sequence                                                 │ │
│  │                                                                 │ │
│  │  1. Load kms.mjs (SRI verified)                                │ │
│  │  2. Fetch badge.json ←───────────────────┐                     │ │
│  │  3. Verify Sigstore signature            │ NEW                 │ │
│  │  4. Check freshness (expires_at)         │                     │ │
│  │  5. Compare bundle_sha256 with self      │                     │ │
│  │  6. Fetch latest Sigstore bundle ────────┤                     │ │
│  │  7. Quorum check (2 of 3 sources)        │                     │ │
│  │  8. Decision: operate vs fail-secure ────┘                     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  If quorum PASS:                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Normal Operation                                              │ │
│  │  - Accept RPC requests                                         │ │
│  │  - Perform crypto operations                                   │ │
│  │  - Show status: "✅ Verified (last: 2h ago)"                   │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  If quorum FAIL:                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Fail-Secure Mode                                              │ │
│  │  - Reject all crypto operations                                │ │
│  │  - Render incident response UI                                 │ │
│  │  - Show evidence: expected vs observed hashes                  │ │
│  │  - Show verification runs, Rekor entries                       │ │
│  │  - Provide manual override (verification only, no keys)        │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Component 1: Machine-Readable Badge

### Badge Schema

**File:** `badge.json`

```json
{
  "schema": "ats-kms/badge/v1",
  "verifier_commit": "abc123def456",
  "release_tag": "v1.0.1",
  "bundle_sha256": "7f8a9b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e",
  "sri": "sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU=",
  "rekor_entry": "24296fb24b8ad77a12345678",
  "result": "PASS",
  "generated_at": "2025-10-23T14:23:42Z",
  "expires_at": "2025-10-23T20:23:42Z",
  "evidence_url": "https://github.com/Lukium/ats-kms-enclave/actions/runs/1234567890"
}
```

**Field descriptions:**

- `schema`: Version identifier (allows future schema changes)
- `verifier_commit`: Exact commit SHA of verifier code used
- `release_tag`: Git tag being verified
- `bundle_sha256`: SHA-256 of kms-*.mjs artifact
- `sri`: SRI hash (sha256-base64 format)
- `rekor_entry`: Rekor transparency log entry UUID
- `result`: "PASS" or "FAIL"
- `generated_at`: Timestamp when badge was created
- `expires_at`: Expiration time (4-6 hours after generation)
- `evidence_url`: Link to workflow run with full evidence

### Badge Generation (in kms-verify.yml)

Add this step after comparison succeeds:

```yaml
- name: Generate verification badge
  id: badge
  run: |
    # Compute expiration (6 hours from now)
    EXPIRES_AT=$(date -u -d '+6 hours' +"%Y-%m-%dT%H:%M:%SZ")

    cat > badge.json << EOF
    {
      "schema": "ats-kms/badge/v1",
      "verifier_commit": "${{ github.sha }}",
      "release_tag": "${{ env.RELEASE_TAG }}",
      "bundle_sha256": "${{ steps.local-hashes.outputs.sha256 }}",
      "sri": "${{ steps.local-hashes.outputs.sri }}",
      "rekor_entry": "${{ steps.sigstore.outputs.rekor_id }}",
      "result": "${{ steps.compare.outputs.result }}",
      "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
      "expires_at": "$EXPIRES_AT",
      "evidence_url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
    }
    EOF

    echo "Badge generated:"
    cat badge.json | jq .

- name: Sign badge with Sigstore
  run: |
    # Sign the badge (creates badge.json.bundle)
    cosign sign-blob \
      --bundle badge.json.bundle \
      --yes \
      badge.json

    echo "Badge signed, bundle created"

- name: Upload badge as release asset
  env:
    GH_TOKEN: ${{ github.token }}
  run: |
    # Upload to GitHub release (overwrites previous)
    gh release upload "${{ env.RELEASE_TAG }}" \
      --repo ${{ github.repository }} \
      --clobber \
      badge.json \
      badge.json.bundle

    echo "✅ Badge uploaded to release ${{ env.RELEASE_TAG }}"

- name: Upload badge as artifact
  uses: actions/upload-artifact@v4
  with:
    name: verification-badge
    path: |
      badge.json
      badge.json.bundle
    retention-days: 90
```

### Badge Properties

**Signed:**
- Sigstore bundle proves badge came from GitHub Actions
- Certificate contains workflow identity
- Cannot be forged without compromising GitHub

**Replay-safe:**
- `expires_at` prevents old badges from being reused
- Short TTL (4-6 hours) forces fresh verification
- `generated_at` provides timestamp proof

**Content-addressed:**
- `bundle_sha256` ties badge to specific artifact
- KMS can verify it's checking the right version
- Prevents hash confusion attacks

**Independently verifiable:**
- `rekor_entry` allows external verification
- `evidence_url` links to full workflow run
- `verifier_commit` allows code audit

## Component 2: Verify the Verifier

### Pinned Verifier Identity

The KMS trusts badges signed by a specific GitHub Actions workflow:

**Trusted OIDC identity:**
```
Issuer: https://token.actions.githubusercontent.com
Subject: https://github.com/Lukium/ats-kms-enclave/.github/workflows/kms-verify.yml@refs/heads/main
```

This identity is **hardcoded** in the KMS source code and can only change with a source code update (which would be visible in Git).

### Badge Verification Algorithm

**File:** `src/verify-badge.ts`

```typescript
/**
 * Verifies a verification badge from the KMS verifier workflow.
 *
 * Returns true if badge is valid, false otherwise.
 */
export async function verifyBadge(
  badgeJson: string,
  bundleData: ArrayBuffer
): Promise<{ valid: boolean; reason?: string }> {
  let badge: Badge;

  try {
    badge = JSON.parse(badgeJson);
  } catch (err) {
    return { valid: false, reason: 'Invalid JSON' };
  }

  // 1. Check schema version
  if (badge.schema !== 'ats-kms/badge/v1') {
    return { valid: false, reason: `Unknown schema: ${badge.schema}` };
  }

  // 2. Check expiration
  const now = Date.now();
  const expiresAt = new Date(badge.expires_at).getTime();

  if (now > expiresAt) {
    return { valid: false, reason: `Expired at ${badge.expires_at}` };
  }

  // 3. Verify Sigstore bundle
  const sigstoreValid = await verifySigstoreBundle(
    badgeJson,
    bundleData,
    {
      // Pin the verifier workflow identity
      expectedIssuer: 'https://token.actions.githubusercontent.com',
      expectedSubjectRegex: /^https:\/\/github\.com\/Lukium\/ats-kms-enclave\/.github\/workflows\/kms-verify\.yml@/
    }
  );

  if (!sigstoreValid) {
    return { valid: false, reason: 'Sigstore verification failed' };
  }

  // 4. Check bundle hash matches current artifact
  const currentHash = await computeSelfHash();

  if (badge.bundle_sha256 !== currentHash) {
    return { valid: false, reason: `Hash mismatch: badge=${badge.bundle_sha256}, self=${currentHash}` };
  }

  // All checks passed
  return { valid: true };
}

/**
 * Computes SHA-256 hash of the currently running KMS artifact.
 */
async function computeSelfHash(): Promise<string> {
  // Fetch self (import.meta.url points to current script)
  const response = await fetch(import.meta.url);
  const arrayBuffer = await response.arrayBuffer();

  // Compute SHA-256
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);

  // Convert to hex
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifies a Sigstore bundle (simplified - use @sigstore/bundle in production).
 */
async function verifySigstoreBundle(
  payload: string,
  bundleData: ArrayBuffer,
  options: {
    expectedIssuer: string;
    expectedSubjectRegex: RegExp;
  }
): Promise<boolean> {
  // Parse bundle
  const bundleJson = JSON.parse(new TextDecoder().decode(bundleData));

  // Extract certificate from bundle
  const cert = parseCertificate(bundleJson.verificationMaterial.certificate);

  // Verify certificate extensions contain expected OIDC identity
  const issuer = cert.extensions.issuer;
  const subject = cert.extensions.subject;

  if (issuer !== options.expectedIssuer) {
    return false;
  }

  if (!options.expectedSubjectRegex.test(subject)) {
    return false;
  }

  // Verify signature
  const signature = bundleJson.messageSignature.signature;
  const publicKey = extractPublicKeyFromCert(cert);

  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    base64Decode(signature),
    new TextEncoder().encode(payload)
  );

  return valid;
}

interface Badge {
  schema: string;
  verifier_commit: string;
  release_tag: string;
  bundle_sha256: string;
  sri: string;
  rekor_entry: string;
  result: 'PASS' | 'FAIL';
  generated_at: string;
  expires_at: string;
  evidence_url: string;
}
```

## Component 3: Two Independent Truth Sources (Quorum)

Don't rely on `badge.json` alone - require 2 of 3 sources to agree:

### Truth Sources

1. **Latest badge.json** (signed, from GitHub release)
2. **Latest Sigstore bundle** for current release (download directly from GitHub)
3. **Attestations manifest** (optional, future: content-addressed manifest with expected hashes)

### Quorum Algorithm

```typescript
/**
 * Boot-time verification using quorum of sources.
 */
export async function bootVerification(): Promise<{
  decision: 'OPERATE' | 'FAIL_SECURE';
  evidence: VerificationEvidence;
}> {
  const currentHash = await computeSelfHash();
  const currentVersion = extractVersionFromUrl(import.meta.url);

  const sources: SourceResult[] = [];

  // Source 1: badge.json
  try {
    const badge = await fetchAndVerifyBadge(currentVersion);
    sources.push({
      name: 'badge.json',
      pass: badge.valid && badge.data.result === 'PASS' && badge.data.bundle_sha256 === currentHash,
      evidence: badge
    });
  } catch (err) {
    sources.push({
      name: 'badge.json',
      pass: false,
      error: err.message
    });
  }

  // Source 2: Sigstore bundle
  try {
    const bundle = await fetchAndVerifySigstoreBundle(currentVersion, currentHash);
    sources.push({
      name: 'sigstore-bundle',
      pass: bundle.valid,
      evidence: bundle
    });
  } catch (err) {
    sources.push({
      name: 'sigstore-bundle',
      pass: false,
      error: err.message
    });
  }

  // Source 3: Attestations manifest (future)
  // For now, always fails (not implemented)
  sources.push({
    name: 'attestations-manifest',
    pass: false,
    error: 'Not implemented'
  });

  // Quorum: require 2 of 3 to pass
  const passCount = sources.filter(s => s.pass).length;

  const decision = passCount >= 2 ? 'OPERATE' : 'FAIL_SECURE';

  return {
    decision,
    evidence: {
      currentHash,
      currentVersion,
      sources,
      quorum: { required: 2, passed: passCount },
      timestamp: new Date().toISOString()
    }
  };
}

async function fetchAndVerifyBadge(version: string): Promise<any> {
  // Fetch badge.json from GitHub release
  const badgeUrl = `https://github.com/Lukium/ats-kms-enclave/releases/download/${version}/badge.json`;
  const bundleUrl = `https://github.com/Lukium/ats-kms-enclave/releases/download/${version}/badge.json.bundle`;

  const badgeResponse = await fetch(badgeUrl);
  const badgeJson = await badgeResponse.text();

  const bundleResponse = await fetch(bundleUrl);
  const bundleData = await bundleResponse.arrayBuffer();

  // Verify badge
  const verification = await verifyBadge(badgeJson, bundleData);

  return {
    valid: verification.valid,
    data: JSON.parse(badgeJson),
    reason: verification.reason
  };
}

async function fetchAndVerifySigstoreBundle(version: string, expectedHash: string): Promise<any> {
  // Fetch Sigstore bundle for artifact
  const bundleUrl = `https://github.com/Lukium/ats-kms-enclave/releases/download/${version}/kms-${version}-${expectedHash.slice(0, 8)}.mjs.bundle`;

  const response = await fetch(bundleUrl);
  const bundleData = await response.arrayBuffer();

  // Parse and verify
  const bundleJson = JSON.parse(new TextDecoder().decode(bundleData));

  // Verify the bundle's message digest matches our hash
  const digest = bundleJson.messageSignature.messageDigest.digest;
  const digestHex = Array.from(base64Decode(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  if (digestHex !== expectedHash) {
    return { valid: false, reason: 'Hash mismatch in bundle' };
  }

  // Verify signature
  const sigstoreValid = await verifySigstoreBundle(
    /* artifact data would be here */,
    bundleData,
    {
      expectedIssuer: 'https://token.actions.githubusercontent.com',
      expectedSubjectRegex: /^https:\/\/github\.com\/Lukium\/ats-kms-enclave\/.github\/workflows\/release\.yml@/
    }
  );

  return { valid: sigstoreValid };
}

interface SourceResult {
  name: string;
  pass: boolean;
  evidence?: any;
  error?: string;
}

interface VerificationEvidence {
  currentHash: string;
  currentVersion: string;
  sources: SourceResult[];
  quorum: { required: number; passed: number };
  timestamp: string;
}
```

### Why Quorum?

**Prevents single point of failure:**
- GitHub downtime won't brick the KMS (1 source can fail)
- CDN issues won't trigger false positive (need 2 to fail)
- Sigstore Rekor downtime tolerated

**Requires coordinated compromise:**
- Attacker must compromise 2 of 3 systems
- badge.json + Sigstore bundle both need to be faked
- Much harder than compromising just GitHub Actions

**Graceful degradation:**
- If 1 source fails temporarily, KMS still operates
- User sees warning: "1 of 3 verification sources unavailable"
- Operations continue normally

## Component 4: Fail-Secure Mode

When quorum fails (< 2 of 3 sources pass), enter **fail-secure mode**.

### What Fail-Secure Means

**NOT "brick mode":**
- ❌ Don't make KMS unusable
- ❌ Don't delete keys
- ❌ Don't prevent recovery

**Instead:**
- ✅ **Lock the gate** - refuse all crypto operations
- ✅ **Clear UI** - explain what happened and why
- ✅ **Show evidence** - expected vs observed hashes, verification runs
- ✅ **Provide guidance** - what to check, who to contact
- ✅ **Manual override** - allow viewing verification info only (no key access)

### Fail-Secure UI

```typescript
/**
 * Render fail-secure incident response screen.
 */
function renderFailSecureMode(evidence: VerificationEvidence) {
  const ui = `
    <div class="fail-secure-screen">
      <div class="header">
        <h1>🚨 KMS Integrity Verification Failed</h1>
        <p class="subtitle">Crypto operations are locked for your protection</p>
      </div>

      <div class="status">
        <h2>Verification Status</h2>
        <p>Expected: 2 of 3 sources to pass</p>
        <p>Actual: ${evidence.quorum.passed} of ${evidence.quorum.required} passed</p>
      </div>

      <div class="sources">
        <h2>Source Details</h2>
        ${evidence.sources.map(source => `
          <div class="source ${source.pass ? 'pass' : 'fail'}">
            <h3>${source.pass ? '✅' : '❌'} ${source.name}</h3>
            ${source.error ? `<p class="error">Error: ${source.error}</p>` : ''}
            ${source.evidence ? `<pre>${JSON.stringify(source.evidence, null, 2)}</pre>` : ''}
          </div>
        `).join('')}
      </div>

      <div class="evidence">
        <h2>Current Deployment</h2>
        <table>
          <tr>
            <th>Version:</th>
            <td>${evidence.currentVersion}</td>
          </tr>
          <tr>
            <th>Hash:</th>
            <td><code>${evidence.currentHash}</code></td>
          </tr>
          <tr>
            <th>Checked at:</th>
            <td>${evidence.timestamp}</td>
          </tr>
        </table>
      </div>

      <div class="actions">
        <h2>What This Means</h2>
        <p>The deployed KMS artifact could not be verified against trusted sources. This could indicate:</p>
        <ul>
          <li>CDN compromise or misconfiguration</li>
          <li>GitHub infrastructure downtime (if all sources failed)</li>
          <li>Network issues preventing verification</li>
          <li>In rare cases, an actual security incident</li>
        </ul>

        <h3>Your Keys Are Safe</h3>
        <p>
          All crypto operations are locked. Your keys cannot be accessed, even by
          a compromised KMS, because they are stored as non-extractable CryptoKeys
          in IndexedDB.
        </p>

        <h3>What You Should Do</h3>
        <ol>
          <li>
            <strong>Check verification runs:</strong>
            <a href="${getLatestVerificationRunUrl()}" target="_blank">
              View recent KMS verifications on GitHub
            </a>
          </li>
          <li>
            <strong>Check service status:</strong>
            Are GitHub Actions or Sigstore experiencing outages?
          </li>
          <li>
            <strong>Try again later:</strong>
            Reload this page in 10-15 minutes. If this was a temporary issue,
            verification should pass.
          </li>
          <li>
            <strong>Contact security team:</strong>
            If the issue persists for more than 6 hours, email
            <a href="mailto:security@ats.run">security@ats.run</a>
            with the evidence shown above.
          </li>
        </ol>
      </div>

      <div class="manual-override">
        <h3>Advanced: Manual Verification</h3>
        <p>Security researchers can verify the deployment independently:</p>
        <pre><code>git clone https://github.com/Lukium/ats-kms-enclave.git
cd ats-kms-enclave
node tools/verify-kms.js --release ${evidence.currentVersion}</code></pre>

        <button onclick="showRawEvidence()">
          Show Raw Evidence JSON
        </button>
      </div>
    </div>
  `;

  document.body.innerHTML = ui;
}
```

### RPC Rejection

When in fail-secure mode, all RPC requests are rejected:

```typescript
/**
 * Main RPC handler (in worker.ts)
 */
async function handleMessage(request: RPCRequest): Promise<RPCResponse> {
  // Check if in fail-secure mode
  if (bootStatus.decision === 'FAIL_SECURE') {
    return {
      requestId: request.id,
      error: 'KMS_LOCKED',
      details: {
        reason: 'Integrity verification failed',
        quorum: bootStatus.evidence.quorum,
        timestamp: bootStatus.evidence.timestamp,
        evidence_url: getEvidenceUrl()
      }
    };
  }

  // Normal operation...
  switch (request.method) {
    case 'generateVAPID':
      return await handleGenerateVAPID(request);
    // ... other methods
  }
}
```

## Component 5: Operational Guardrails

### Sliding Window Tolerance

Don't fail on a single bad verification run - use a sliding window:

```typescript
/**
 * Checks if verification has been consistently failing.
 */
async function checkSlidingWindow(): Promise<{
  shouldFail: boolean;
  reason?: string;
}> {
  // Fetch last N verification runs from GitHub API
  const runs = await fetchRecentVerificationRuns(count = 10);

  // Check for fresh PASS within last 6 hours
  const sixHoursAgo = Date.now() - (6 * 60 * 60 * 1000);
  const recentPass = runs.find(run =>
    run.result === 'PASS' &&
    new Date(run.timestamp).getTime() > sixHoursAgo
  );

  if (recentPass) {
    return { shouldFail: false };
  }

  // No fresh PASS - check pattern
  const recentRuns = runs.filter(run =>
    new Date(run.timestamp).getTime() > sixHoursAgo
  );

  if (recentRuns.length === 0) {
    return {
      shouldFail: true,
      reason: 'No verification runs in last 6 hours'
    };
  }

  const allFailed = recentRuns.every(run => run.result === 'FAIL');

  if (allFailed) {
    return {
      shouldFail: true,
      reason: `All ${recentRuns.length} runs failed in last 6 hours`
    };
  }

  // Mixed results - don't fail yet
  return { shouldFail: false };
}
```

### Backoff and Caching

Don't hammer GitHub API on every page load:

```typescript
/**
 * Cached verification status.
 */
let cachedVerification: {
  status: VerificationEvidence;
  fetchedAt: number;
} | null = null;

const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Boot verification with caching.
 */
export async function bootVerificationCached(): Promise<{
  decision: 'OPERATE' | 'FAIL_SECURE';
  evidence: VerificationEvidence;
}> {
  const now = Date.now();

  // Use cached result if fresh
  if (cachedVerification && (now - cachedVerification.fetchedAt) < CACHE_TTL) {
    return {
      decision: cachedVerification.status.quorum.passed >= 2 ? 'OPERATE' : 'FAIL_SECURE',
      evidence: cachedVerification.status
    };
  }

  // Fetch fresh verification
  try {
    const result = await bootVerification();

    // Cache the result
    cachedVerification = {
      status: result.evidence,
      fetchedAt: now
    };

    return result;
  } catch (err) {
    // If fetch fails and we have a cached PASS, use it
    if (cachedVerification && cachedVerification.status.quorum.passed >= 2) {
      console.warn('Verification fetch failed, using cached PASS', err);
      return {
        decision: 'OPERATE',
        evidence: {
          ...cachedVerification.status,
          warning: 'Using cached verification (fetch failed)'
        }
      };
    }

    // No cached PASS - fail secure
    throw err;
  }
}
```

### Exponential Backoff

If verification keeps failing, back off:

```typescript
let failureCount = 0;
let nextRetryAt = 0;

async function bootWithBackoff(): Promise<BootResult> {
  const now = Date.now();

  // Check if we should retry yet
  if (now < nextRetryAt) {
    const waitSec = Math.round((nextRetryAt - now) / 1000);
    throw new Error(`Verification on backoff, retry in ${waitSec}s`);
  }

  try {
    const result = await bootVerificationCached();

    if (result.decision === 'OPERATE') {
      // Success - reset backoff
      failureCount = 0;
      nextRetryAt = 0;
    } else {
      // Failed - increase backoff
      failureCount++;
      const backoffMs = Math.min(
        1000 * Math.pow(2, failureCount), // Exponential: 2s, 4s, 8s, ...
        5 * 60 * 1000 // Max 5 minutes
      );
      nextRetryAt = now + backoffMs;
    }

    return result;
  } catch (err) {
    failureCount++;
    const backoffMs = Math.min(
      1000 * Math.pow(2, failureCount),
      5 * 60 * 1000
    );
    nextRetryAt = now + backoffMs;
    throw err;
  }
}
```

### Status Surface in PWA

Show verification status in the main PWA settings:

```typescript
/**
 * Display verification status in PWA settings page.
 */
async function displayVerificationStatus() {
  const iframe = document.querySelector('iframe#kms');

  // Request status from KMS
  const status = await sendRPCToKMS(iframe, {
    method: 'getVerificationStatus'
  });

  const statusHtml = `
    <div class="verification-status">
      <h3>KMS Verification Status</h3>

      ${status.decision === 'OPERATE' ? `
        <div class="status-ok">
          <p>✅ Verified</p>
          <p class="timestamp">Last check: ${formatTimestamp(status.evidence.timestamp)}</p>
          <p class="quorum">${status.evidence.quorum.passed} of ${status.evidence.quorum.required} sources passed</p>
        </div>
      ` : `
        <div class="status-fail">
          <p>🚨 Verification Failed</p>
          <p class="timestamp">Checked: ${formatTimestamp(status.evidence.timestamp)}</p>
          <p class="quorum">${status.evidence.quorum.passed} of ${status.evidence.quorum.required} sources passed</p>
          <a href="#" onclick="showVerificationDetails()">View Details</a>
        </div>
      `}

      <div class="source-summary">
        ${status.evidence.sources.map(s => `
          <div class="source ${s.pass ? 'pass' : 'fail'}">
            ${s.pass ? '✅' : '❌'} ${s.name}
          </div>
        `).join('')}
      </div>

      <p class="links">
        <a href="${getLatestVerificationRunUrl()}" target="_blank">
          View verification runs on GitHub →
        </a>
      </p>
    </div>
  `;

  document.querySelector('#kms-status').innerHTML = statusHtml;
}
```

## Integration with Existing Workflows

### Changes to kms-verify.yml

Add badge generation step (shown in Component 1):

```yaml
# After comparison succeeds, generate badge
- name: Generate verification badge
  # ... (see Component 1)

- name: Sign badge with Sigstore
  # ... (see Component 1)

- name: Upload badge as release asset
  # ... (see Component 1)
```

**Delta:** +3 steps, ~30 lines of YAML

### Changes to KMS Boot Sequence

**File:** `src/main.ts`

```typescript
// On KMS iframe load

async function init() {
  console.log('🔐 KMS Enclave starting...');

  // 1. Run boot verification
  let bootResult: BootResult;
  try {
    bootResult = await bootWithBackoff();
  } catch (err) {
    console.error('Boot verification failed:', err);
    renderFailSecureMode({
      currentHash: 'unknown',
      currentVersion: extractVersionFromUrl(import.meta.url),
      sources: [],
      quorum: { required: 2, passed: 0 },
      timestamp: new Date().toISOString(),
      error: err.message
    });
    return; // Stop here - don't initialize worker
  }

  // 2. Check decision
  if (bootResult.decision === 'FAIL_SECURE') {
    console.warn('Boot verification: FAIL_SECURE mode');
    renderFailSecureMode(bootResult.evidence);
    return; // Stop here
  }

  // 3. Normal operation
  console.log('✅ Boot verification: OPERATE');
  console.log('Quorum:', bootResult.evidence.quorum);

  // Continue with normal KMS initialization
  await initWorker();
  await initRPC();

  console.log('🔐 KMS Enclave ready');
}

init();
```

**Delta:** +25 lines

### Changes to Worker

**File:** `src/worker.ts`

```typescript
// Add verification status method

async function handleGetVerificationStatus(request: RPCRequest): Promise<RPCResponse> {
  return {
    requestId: request.id,
    data: {
      decision: bootStatus.decision,
      evidence: bootStatus.evidence
    }
  };
}

// Add check in all operation handlers

async function handleGenerateVAPID(request: RPCRequest): Promise<RPCResponse> {
  // Check fail-secure
  if (bootStatus.decision === 'FAIL_SECURE') {
    return {
      requestId: request.id,
      error: 'KMS_LOCKED',
      details: {
        reason: 'Integrity verification failed',
        quorum: bootStatus.evidence.quorum
      }
    };
  }

  // Normal operation...
}
```

**Delta:** +15 lines per method (6 methods) = ~90 lines

### Total Code Delta

- `src/verify-badge.ts`: ~300 lines (new file)
- `src/main.ts`: +25 lines
- `src/worker.ts`: +90 lines
- `.github/workflows/kms-verify.yml`: +30 lines
- UI templates: ~200 lines (new)

**Total:** ~645 lines of new code

**Well within target** (<500 lines for core, ~1000 for all infrastructure)

## Security Analysis

### What This Prevents

✅ **Delayed compromise detection**
- Old: Compromise detected hours later when verification runs
- New: Detected on next KMS load (within minutes)

✅ **Passive failure mode**
- Old: Verification fails, but KMS keeps running
- New: KMS locks itself and shows incident UI

✅ **Single point of failure**
- Old: GitHub Actions downtime = no verification
- New: Quorum tolerates 1 source failing

✅ **Silent SRI failures**
- Old: If SRI fails, just see browser error
- New: KMS actively checks and explains

### What This Doesn't Prevent

❌ **Source code compromise**
- If malicious code is merged to Git, badge will verify it
- Defense: Code review, community audits

❌ **Coordinated infrastructure compromise**
- If attacker compromises GitHub + Sigstore + CDN simultaneously
- Defense: Extremely difficult to coordinate, low probability

❌ **GitHub Actions OIDC compromise**
- If GitHub's OIDC token issuance is compromised
- Defense: Trust GitHub's security (same as before)

### Trust Assumptions

**Must trust:**
1. GitHub Actions (workflow execution)
2. Sigstore/Rekor (transparency log)
3. Browser (WebCrypto, fetch API)

**New trust requirements:**
- None! Same trust assumptions as existing design

**Reduced trust:**
- Don't need to trust that GitHub Actions will always be available (quorum tolerates failures)

## Implementation Phases

### Phase 4.5: Badge Generation (Week 1)

- [ ] Add badge generation step to `kms-verify.yml`
- [ ] Add Sigstore signing for badge
- [ ] Upload badge to GitHub releases
- [ ] Test badge format and signing

**Deliverable:** Every verification run produces signed `badge.json`

### Phase 4.6: Badge Verification (Week 2)

- [ ] Create `src/verify-badge.ts`
- [ ] Implement Sigstore bundle verification
- [ ] Implement self-hash computation
- [ ] Test badge verification logic

**Deliverable:** KMS can verify badges locally

### Phase 4.7: Quorum Logic (Week 3)

- [ ] Implement `bootVerification()` with quorum
- [ ] Add 3 source checks (badge, bundle, manifest stub)
- [ ] Add sliding window check
- [ ] Test quorum decision making

**Deliverable:** Boot verification decides OPERATE vs FAIL_SECURE

### Phase 4.8: Fail-Secure Mode (Week 4)

- [ ] Create fail-secure UI templates
- [ ] Render incident response screen
- [ ] Add RPC rejection in worker
- [ ] Test fail-secure UX

**Deliverable:** Clear, helpful fail-secure mode

### Phase 4.9: Operational Guardrails (Week 5)

- [ ] Add caching (5-minute TTL)
- [ ] Add exponential backoff
- [ ] Add status display in PWA settings
- [ ] Test cache behavior and backoff

**Deliverable:** Production-ready verification with resilience

### Phase 4.10: Testing and Rollout (Week 6)

- [ ] E2E tests for all quorum scenarios
- [ ] Test with real GitHub releases
- [ ] Test fail-secure mode (inject bad badge)
- [ ] Document for users
- [ ] Gradual rollout (canary → full)

**Deliverable:** Fail-secure verification in production

## Operational Runbook

### Normal Operation

**Expected behavior:**
- KMS loads in <2 seconds
- Badge fetched and cached
- Quorum: 2/3 or 3/3 PASS
- All RPC operations work

**Monitoring:**
- Check verification runs daily (should be ~3 per day)
- Check badge freshness (should be <6 hours old)
- Check PWA status UI (should show ✅)

### Incident: Single Source Fails

**Symptom:** Quorum passes (2/3) but one source failed

**Action:**
1. Check which source failed
2. Check if it's a known outage (GitHub, Sigstore)
3. If persistent >24h, investigate root cause
4. Fix or wait for external service recovery

**User impact:** None (KMS operates normally)

### Incident: Quorum Fails (Fail-Secure Triggered)

**Symptom:** KMS shows fail-secure screen, operations locked

**Action:**
1. Check recent verification runs - are they failing?
2. Check GitHub Actions status - is it down?
3. Check Sigstore/Rekor - is it accessible?
4. Check CDN - is it serving correct file?
5. If all sources show hash mismatch → **SECURITY INCIDENT**

**User impact:** Cannot use KMS, keys are safe

**Resolution:**
- If transient (GitHub down): Wait for recovery, users reload
- If CDN issue: Fix deployment, trigger manual verification
- If security incident: Follow incident response plan

### Incident: Security Incident (Hash Mismatch)

**Symptom:** Multiple sources report hash mismatch, verification fails consistently

**Action (URGENT):**
1. **Confirm the issue:**
   - Run manual verification: `node tools/verify-kms.js`
   - Check if local build matches live CDN

2. **Isolate:**
   - Do NOT deploy new version (preserve evidence)
   - Capture logs, hashes, timestamps

3. **Investigate:**
   - Who last deployed to CDN?
   - Were any release workflows run?
   - Check CDN access logs
   - Check GitHub audit logs

4. **Communicate:**
   - Post incident notice in PWA
   - Email security@ats.run
   - Notify user base if widespread

5. **Remediate:**
   - Identify root cause
   - Fix vulnerability
   - Redeploy correct artifact
   - Run verification

6. **Post-mortem:**
   - Document incident timeline
   - Identify what allowed compromise
   - Add additional controls
   - Update runbook

**User impact:** KMS locked until resolution

## Success Criteria

✅ **Badge generation works**
- Every verification run creates signed `badge.json`
- Badge uploaded to GitHub releases
- Badge signature verifies correctly

✅ **Boot verification works**
- KMS fetches and verifies badge on startup
- Quorum logic makes correct decisions
- Caching and backoff work correctly

✅ **Fail-secure mode is clear**
- Users understand what happened
- Evidence is visible and actionable
- Manual override works for verification

✅ **No false positives**
- Normal operation: 99.9%+ quorum pass rate
- GitHub downtime doesn't brick KMS
- Transient network issues handled gracefully

✅ **Real incidents are caught**
- Hash mismatch triggers fail-secure
- Users see incident UI within 5 minutes of load
- Evidence collection works

✅ **Performance is acceptable**
- Boot verification: <2 seconds
- Cache hit: <100ms
- Cache miss: <2 seconds
- No impact on RPC operation latency

## Related Documentation

- [Self-Attestation README](./README.md) - Overview of self-attestation system
- [Design](./design.md) - Core verifier workflows (extended by this doc)
- [Target State](./target-state.md) - Ideal end state (now includes fail-secure)
- [Plan](./plan.md) - Implementation roadmap (add Phases 4.5-4.10)

## Future Enhancements

### Attestations Manifest (Source #3)

Create a signed manifest with expected hashes:

```json
{
  "schema": "ats-kms/attestations/v1",
  "releases": [
    {
      "tag": "v1.0.0",
      "bundle_sha256": "3a5b9f2e...",
      "sri": "sha256-OlvH...",
      "released_at": "2025-10-20T10:00:00Z",
      "rekor_entry": "abc123..."
    },
    {
      "tag": "v1.0.1",
      "bundle_sha256": "7f8a9b0c...",
      "sri": "sha256-f4OxZX...",
      "released_at": "2025-10-23T12:00:00Z",
      "rekor_entry": "def456..."
    }
  ],
  "signed_at": "2025-10-23T14:00:00Z"
}
```

Host this at a separate, immutable location (e.g., IPFS, Arweave) and sign it.

**Benefit:** Third independent source not controlled by GitHub

### Client-Side Rebuild Verification

Allow advanced users to trigger a client-side rebuild in WebAssembly:

```typescript
// Build KMS from source in browser (using esbuild WASM)
const localBuild = await buildInBrowser(sourceCode);
const localHash = await computeHash(localBuild);

if (localHash !== currentHash) {
  alert('⚠️ Local build does not match deployed artifact!');
}
```

**Benefit:** Ultimate verification - build it yourself

**Challenge:** Large WebAssembly runtime, slow build times

### Distributed Verifier Network

Allow community members to run verifiers and publish results:

```
Verifier #1 (GitHub Actions): ✅ PASS
Verifier #2 (Community - Alice):  ✅ PASS
Verifier #3 (Community - Bob):    ✅ PASS
Verifier #4 (Community - Carol):  ✅ PASS
```

Aggregate results and display in PWA.

**Benefit:** Even less reliance on GitHub infrastructure

**Challenge:** Coordination, aggregation, handling disagreements
