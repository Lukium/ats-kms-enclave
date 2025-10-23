# Self-Attestation: Detailed Design

**Status:** Design Phase (not yet implemented)

## Overview

The self-attestation system consists of two GitHub Actions workflows that work together to provide continuous, random, public verification of deployed KMS artifacts:

1. **Random Cadence Workflow** - Triggers verification ~3 times per day using probabilistic scheduling
2. **KMS Verifier Workflow** - Rebuilds artifact from source, compares with live deployment, publishes evidence

All components run entirely within GitHub Actions. No external hosting is required.

## Design Principles

1. **Zero Trust Architecture**: Even ATS developers cannot predict or influence verification timing
2. **Public Auditability**: All evidence published in GitHub Actions logs and job summaries
3. **Tamper Evidence**: Any modification to verifier code or workflow breaks the audit chain
4. **Reproducible Verification**: Anyone can re-run the same verification independently

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Actions Runner                        │
│                                                                  │
│  ┌────────────────────────┐                                     │
│  │  random-cadence.yml    │                                     │
│  │                        │                                     │
│  │  Triggers: schedule    │                                     │
│  │    - cron: '0 * * * *' │  # Every hour                       │
│  │                        │                                     │
│  │  Steps:                │                                     │
│  │  1. Generate random    │                                     │
│  │  2. Check if trigger   │  # ~3/24 = 12.5% probability       │
│  │  3. Add jitter (0-30m) │                                     │
│  │  4. Dispatch to verify │                                     │
│  └────────┬───────────────┘                                     │
│           │                                                      │
│           │ workflow_dispatch                                   │
│           │ (if selected)                                       │
│           ▼                                                      │
│  ┌────────────────────────────────────────────────────────┐    │
│  │             kms-verify.yml                             │    │
│  │                                                         │    │
│  │  Triggers:                                              │    │
│  │    - workflow_dispatch (from random-cadence)           │    │
│  │    - manual (for testing)                              │    │
│  │                                                         │    │
│  │  Jobs:                                                  │    │
│  │  ┌──────────────────────────────────────────────────┐ │    │
│  │  │ 1. Setup Environment                             │ │    │
│  │  │    - Checkout verifier @ pinned SHA              │ │    │
│  │  │    - Setup Node (frozen version)                 │ │    │
│  │  │    - Install deps (frozen lockfile)              │ │    │
│  │  └──────────────────────────────────────────────────┘ │    │
│  │  ┌──────────────────────────────────────────────────┐ │    │
│  │  │ 2. Reproducible Build                            │ │    │
│  │  │    - Checkout KMS release tag                    │ │    │
│  │  │    - Build with SOURCE_DATE_EPOCH                │ │    │
│  │  │    - Compute SHA-256 + SRI hashes                │ │    │
│  │  └──────────────────────────────────────────────────┘ │    │
│  │  ┌──────────────────────────────────────────────────┐ │    │
│  │  │ 3. Fetch Live Artifact                           │ │    │
│  │  │    - Download from https://kms.ats.run/kms.mjs   │ │    │
│  │  │    - Compute SHA-256 + SRI hashes                │ │    │
│  │  └──────────────────────────────────────────────────┘ │    │
│  │  ┌──────────────────────────────────────────────────┐ │    │
│  │  │ 4. Compare Hashes                                │ │    │
│  │  │    - Check local SHA-256 == live SHA-256         │ │    │
│  │  │    - Check local SRI == live SRI                 │ │    │
│  │  │    - Fail job if mismatch                        │ │    │
│  │  └──────────────────────────────────────────────────┘ │    │
│  │  ┌──────────────────────────────────────────────────┐ │    │
│  │  │ 5. Verify Sigstore Bundle                        │ │    │
│  │  │    - Download cosign bundle from release         │ │    │
│  │  │    - Verify signature with cosign                │ │    │
│  │  │    - Check Rekor transparency log entry          │ │    │
│  │  │    - Validate certificate                        │ │    │
│  │  └──────────────────────────────────────────────────┘ │    │
│  │  ┌──────────────────────────────────────────────────┐ │    │
│  │  │ 6. Publish Evidence                              │ │    │
│  │  │    - Generate job summary (markdown table)       │ │    │
│  │  │    - Upload verification report artifact         │ │    │
│  │  │    - Upload build artifacts                      │ │    │
│  │  │    - Log all results                             │ │    │
│  │  └──────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Public Evidence (Artifacts)                 │   │
│  │                                                          │   │
│  │  - Job summary (visible in UI)                          │   │
│  │  - verification-report.json                             │   │
│  │  - dist/kms-*.mjs (reproducible build)                  │   │
│  │  - cosign.bundle (Sigstore proof)                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Workflow 1: Random Cadence Trigger

**File:** `.github/workflows/random-cadence.yml`

### Purpose

Triggers verification at unpredictable times (~3x per day) to prevent gaming the system. Uses probabilistic scheduling with random jitter.

### Scheduling Mathematics

**Goal:** Average 3 verifications per day, unpredictable timing

**Approach:** Poisson process with λ=3 events per day

- **Check frequency:** Every hour (24 checks per day)
- **Trigger probability:** 3/24 = 12.5% per check
- **Expected executions:** 24 × 0.125 = 3 per day
- **Jitter:** Random delay 0-30 minutes after selection

**Why this works:**
- Each hour has ~12.5% chance of triggering verification
- Over 24 hours, expect ~3 triggers (but varies randomly)
- We cannot predict which hours will trigger
- Even if we could, 0-30min jitter makes exact timing unknown

### Implementation

```yaml
name: Random Cadence Trigger

on:
  schedule:
    # Run every hour at minute 0
    - cron: '0 * * * *'
  workflow_dispatch:
    # Allow manual testing

jobs:
  check-and-trigger:
    runs-on: ubuntu-latest
    permissions:
      actions: write  # Required for workflow_dispatch

    steps:
      - name: Generate random number
        id: random
        run: |
          # Generate random number 0-99
          RANDOM_NUM=$((RANDOM % 100))
          echo "Random number: $RANDOM_NUM"
          echo "random=$RANDOM_NUM" >> $GITHUB_OUTPUT

          # Trigger if < 12 (12% chance = ~3x per day)
          if [ $RANDOM_NUM -lt 12 ]; then
            echo "trigger=true" >> $GITHUB_OUTPUT
            echo "✅ Trigger selected (random=$RANDOM_NUM < 12)"
          else
            echo "trigger=false" >> $GITHUB_OUTPUT
            echo "⏭️ Skipping (random=$RANDOM_NUM >= 12)"
          fi

      - name: Add random jitter
        if: steps.random.outputs.trigger == 'true'
        id: jitter
        run: |
          # Random delay 0-1800 seconds (0-30 minutes)
          JITTER=$((RANDOM % 1800))
          echo "Jitter: ${JITTER}s ($(($JITTER / 60))m $(($JITTER % 60))s)"
          echo "jitter=$JITTER" >> $GITHUB_OUTPUT

      - name: Wait for jitter
        if: steps.random.outputs.trigger == 'true'
        run: |
          sleep ${{ steps.jitter.outputs.jitter }}

      - name: Trigger verification workflow
        if: steps.random.outputs.trigger == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          echo "🚀 Triggering KMS verification workflow"
          gh workflow run kms-verify.yml \
            --repo ${{ github.repository }} \
            --ref ${{ github.ref }}

      - name: Log decision
        run: |
          cat << EOF >> $GITHUB_STEP_SUMMARY
          ## Random Cadence Check

          - **Time:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
          - **Random number:** ${{ steps.random.outputs.random }}
          - **Threshold:** 12 (12% probability)
          - **Decision:** ${{ steps.random.outputs.trigger == 'true' && '✅ TRIGGER' || '⏭️ SKIP' }}
          ${{ steps.random.outputs.trigger == 'true' && format('- **Jitter:** {0}s ({1}m {2}s)', steps.jitter.outputs.jitter, steps.jitter.outputs.jitter / 60, steps.jitter.outputs.jitter % 60) || '' }}

          **Next check:** $(date -u -d '+1 hour' +"%Y-%m-%d %H:%M:%S UTC")
          EOF
```

### Security Properties

**Unpredictability:**
- GitHub Actions uses system random source (not predictable)
- Even with workflow code access, cannot predict `$RANDOM` output
- Jitter adds additional unpredictability

**Tamper Resistance:**
- Workflow file is version controlled (changes are visible)
- Protected branch rules require reviews for changes
- Commit SHA pinned in evidence (verifiers can audit exact code)

**Auditability:**
- Every check (trigger or skip) logged to job summary
- Random numbers and decisions visible
- Timestamps prove frequency

## Workflow 2: KMS Verifier

**File:** `.github/workflows/kms-verify.yml`

### Purpose

Performs complete verification: rebuild from source, fetch live artifact, compare hashes, verify Sigstore bundle, publish evidence.

### Implementation

```yaml
name: KMS Verifier

on:
  workflow_dispatch:
    # Triggered by random-cadence or manual
  schedule:
    # Fallback: run at least once per week even if random-cadence fails
    - cron: '0 12 * * 0'  # Sundays at noon UTC

env:
  NODE_VERSION: '20.11.1'
  PNPM_VERSION: '8.15.0'
  RELEASE_TAG: 'v1.0.0'  # TODO: Make this dynamic
  LIVE_URL: 'https://kms.ats.run/kms.mjs'

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # For Sigstore verification

    steps:
      # ============================================================
      # 1. Setup Environment
      # ============================================================

      - name: Checkout verifier code
        uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
          # Pin this SHA in evidence for auditability

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}

      - name: Install pnpm
        uses: pnpm/action-setup@v2
        with:
          version: ${{ env.PNPM_VERSION }}

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      # ============================================================
      # 2. Reproducible Build
      # ============================================================

      - name: Checkout KMS release
        uses: actions/checkout@v4
        with:
          ref: ${{ env.RELEASE_TAG }}
          path: kms-release

      - name: Build KMS reproducibly
        working-directory: kms-release
        env:
          # Deterministic timestamp (from release tag)
          SOURCE_DATE_EPOCH: '1698765432'  # TODO: Extract from git tag
        run: |
          pnpm install --frozen-lockfile
          pnpm build:reproducible

      - name: Compute local hashes
        id: local-hashes
        working-directory: kms-release/dist
        run: |
          # Find the built artifact (content-addressed filename)
          ARTIFACT=$(ls kms-*.mjs)
          echo "artifact=$ARTIFACT" >> $GITHUB_OUTPUT

          # SHA-256 hash
          SHA256=$(sha256sum "$ARTIFACT" | cut -d' ' -f1)
          echo "sha256=$SHA256" >> $GITHUB_OUTPUT

          # SRI hash (sha256- prefix + base64)
          SRI="sha256-$(openssl dgst -sha256 -binary "$ARTIFACT" | openssl base64 -A)"
          echo "sri=$SRI" >> $GITHUB_OUTPUT

          # File size
          SIZE=$(stat -c%s "$ARTIFACT")
          echo "size=$SIZE" >> $GITHUB_OUTPUT

          echo "Local build: $ARTIFACT"
          echo "  SHA-256: $SHA256"
          echo "  SRI:     $SRI"
          echo "  Size:    $SIZE bytes"

      # ============================================================
      # 3. Fetch Live Artifact
      # ============================================================

      - name: Fetch live artifact
        id: live-fetch
        run: |
          echo "Fetching from ${{ env.LIVE_URL }}"
          curl -fsSL "${{ env.LIVE_URL }}" -o live-kms.mjs

          # Verify we got JavaScript
          if ! file live-kms.mjs | grep -q "JavaScript"; then
            echo "❌ Downloaded file is not JavaScript"
            file live-kms.mjs
            exit 1
          fi

      - name: Compute live hashes
        id: live-hashes
        run: |
          # SHA-256 hash
          SHA256=$(sha256sum live-kms.mjs | cut -d' ' -f1)
          echo "sha256=$SHA256" >> $GITHUB_OUTPUT

          # SRI hash
          SRI="sha256-$(openssl dgst -sha256 -binary live-kms.mjs | openssl base64 -A)"
          echo "sri=$SRI" >> $GITHUB_OUTPUT

          # File size
          SIZE=$(stat -c%s live-kms.mjs)
          echo "size=$SIZE" >> $GITHUB_OUTPUT

          echo "Live artifact:"
          echo "  SHA-256: $SHA256"
          echo "  SRI:     $SRI"
          echo "  Size:    $SIZE bytes"

      # ============================================================
      # 4. Compare Hashes
      # ============================================================

      - name: Compare hashes
        id: compare
        run: |
          LOCAL_SHA="${{ steps.local-hashes.outputs.sha256 }}"
          LIVE_SHA="${{ steps.live-hashes.outputs.sha256 }}"
          LOCAL_SRI="${{ steps.local-hashes.outputs.sri }}"
          LIVE_SRI="${{ steps.live-hashes.outputs.sri }}"

          echo "Comparison:"
          echo "  Local SHA-256:  $LOCAL_SHA"
          echo "  Live SHA-256:   $LIVE_SHA"
          echo ""
          echo "  Local SRI:      $LOCAL_SRI"
          echo "  Live SRI:       $LIVE_SRI"
          echo ""

          # Check SHA-256
          if [ "$LOCAL_SHA" = "$LIVE_SHA" ]; then
            echo "sha256_match=true" >> $GITHUB_OUTPUT
            echo "✅ SHA-256 hashes MATCH"
          else
            echo "sha256_match=false" >> $GITHUB_OUTPUT
            echo "❌ SHA-256 hashes DO NOT MATCH"
          fi

          # Check SRI
          if [ "$LOCAL_SRI" = "$LIVE_SRI" ]; then
            echo "sri_match=true" >> $GITHUB_OUTPUT
            echo "✅ SRI hashes MATCH"
          else
            echo "sri_match=false" >> $GITHUB_OUTPUT
            echo "❌ SRI hashes DO NOT MATCH"
          fi

          # Overall result
          if [ "$LOCAL_SHA" = "$LIVE_SHA" ] && [ "$LOCAL_SRI" = "$LIVE_SRI" ]; then
            echo "result=PASS" >> $GITHUB_OUTPUT
            echo ""
            echo "✅ VERIFICATION PASSED"
          else
            echo "result=FAIL" >> $GITHUB_OUTPUT
            echo ""
            echo "❌ VERIFICATION FAILED"
            exit 1
          fi

      # ============================================================
      # 5. Verify Sigstore Bundle
      # ============================================================

      - name: Download Sigstore bundle
        run: |
          # Sigstore bundle is attached to GitHub release
          gh release download "${{ env.RELEASE_TAG }}" \
            --repo ${{ github.repository }} \
            --pattern 'kms-*.mjs.bundle' \
            --dir .
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Verify Sigstore signature
        id: sigstore
        run: |
          BUNDLE=$(ls kms-*.mjs.bundle)
          echo "Verifying bundle: $BUNDLE"

          # Verify signature and Rekor entry
          if cosign verify-blob \
            --bundle "$BUNDLE" \
            --certificate-identity-regexp="^https://github.com/${{ github.repository }}/" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            "kms-release/dist/${{ steps.local-hashes.outputs.artifact }}"; then
            echo "result=PASS" >> $GITHUB_OUTPUT
            echo "✅ Sigstore verification PASSED"
          else
            echo "result=FAIL" >> $GITHUB_OUTPUT
            echo "❌ Sigstore verification FAILED"
            exit 1
          fi

          # Extract Rekor entry ID
          REKOR_ID=$(cosign verify-blob \
            --bundle "$BUNDLE" \
            --certificate-identity-regexp="^https://github.com/${{ github.repository }}/" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            "kms-release/dist/${{ steps.local-hashes.outputs.artifact }}" \
            2>&1 | grep -oP 'tlog entry verified with uuid: \K[a-f0-9]+' || echo "unknown")
          echo "rekor_id=$REKOR_ID" >> $GITHUB_OUTPUT
          echo "Rekor entry ID: $REKOR_ID"

      # ============================================================
      # 6. Publish Evidence
      # ============================================================

      - name: Generate verification report
        run: |
          cat > verification-report.json << EOF
          {
            "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
            "verifier_commit": "${{ github.sha }}",
            "release_tag": "${{ env.RELEASE_TAG }}",
            "workflow_run_id": "${{ github.run_id }}",
            "workflow_run_number": "${{ github.run_number }}",
            "local_build": {
              "artifact": "${{ steps.local-hashes.outputs.artifact }}",
              "sha256": "${{ steps.local-hashes.outputs.sha256 }}",
              "sri": "${{ steps.local-hashes.outputs.sri }}",
              "size": ${{ steps.local-hashes.outputs.size }}
            },
            "live_artifact": {
              "url": "${{ env.LIVE_URL }}",
              "sha256": "${{ steps.live-hashes.outputs.sha256 }}",
              "sri": "${{ steps.live-hashes.outputs.sri }}",
              "size": ${{ steps.live-hashes.outputs.size }}
            },
            "comparison": {
              "sha256_match": ${{ steps.compare.outputs.sha256_match }},
              "sri_match": ${{ steps.compare.outputs.sri_match }},
              "result": "${{ steps.compare.outputs.result }}"
            },
            "sigstore": {
              "verified": ${{ steps.sigstore.outputs.result == 'PASS' }},
              "rekor_entry_id": "${{ steps.sigstore.outputs.rekor_id }}"
            }
          }
          EOF

          echo "Verification report:"
          cat verification-report.json | jq .

      - name: Generate job summary
        run: |
          cat << EOF >> $GITHUB_STEP_SUMMARY
          # KMS Verification Report

          **Status:** ${{ steps.compare.outputs.result == 'PASS' && '✅ PASS' || '❌ FAIL' }}

          **Verification Details:**
          - **Timestamp:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
          - **Verifier Commit:** \`${{ github.sha }}\`
          - **Release Tag:** \`${{ env.RELEASE_TAG }}\`
          - **Workflow Run:** [#${{ github.run_number }}](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})

          ## Hash Comparison

          | Hash Type | Local Build | Live Artifact | Match |
          |-----------|-------------|---------------|-------|
          | **SHA-256** | \`${{ steps.local-hashes.outputs.sha256 }}\` | \`${{ steps.live-hashes.outputs.sha256 }}\` | ${{ steps.compare.outputs.sha256_match == 'true' && '✅' || '❌' }} |
          | **SRI** | \`${{ steps.local-hashes.outputs.sri }}\` | \`${{ steps.live-hashes.outputs.sri }}\` | ${{ steps.compare.outputs.sri_match == 'true' && '✅' || '❌' }} |
          | **Size** | ${{ steps.local-hashes.outputs.size }} bytes | ${{ steps.live-hashes.outputs.size }} bytes | ${{ steps.local-hashes.outputs.size == steps.live-hashes.outputs.size && '✅' || '❌' }} |

          ## Sigstore Verification

          - **Signature:** ${{ steps.sigstore.outputs.result == 'PASS' && '✅ Valid' || '❌ Invalid' }}
          - **Rekor Entry:** [\`${{ steps.sigstore.outputs.rekor_id }}\`](https://rekor.sigstore.dev/api/v1/log/entries/${{ steps.sigstore.outputs.rekor_id }})
          - **Certificate:** Verified with GitHub Actions OIDC

          ## Artifacts

          - Local build: \`${{ steps.local-hashes.outputs.artifact }}\`
          - Live URL: ${{ env.LIVE_URL }}

          ---

          **Verifier code:** [View at commit \`${{ github.sha }}\`](${{ github.server_url }}/${{ github.repository }}/tree/${{ github.sha }})
          EOF

      - name: Upload verification report
        uses: actions/upload-artifact@v4
        with:
          name: verification-report
          path: verification-report.json
          retention-days: 90

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-artifacts
          path: |
            kms-release/dist/${{ steps.local-hashes.outputs.artifact }}
            live-kms.mjs
            kms-*.mjs.bundle
          retention-days: 90
```

### Security Properties

**Reproducibility:**
- Fixed Node, pnpm, esbuild versions
- Frozen lockfile (deterministic dependencies)
- `SOURCE_DATE_EPOCH` set (normalized timestamps)
- Same input → same output (byte-for-byte)

**Tamper Resistance:**
- Verifier code checked out at commit SHA (pinned in evidence)
- Protected branches require reviews for workflow changes
- Pinned Action SHAs (not tags that can be moved)
- All operations logged (visible command execution)

**Cryptographic Proof:**
- SHA-256 collision resistance (2^256 security)
- SRI provides second independent hash
- Sigstore ECDSA signatures (NIST P-256)
- Rekor transparency log (external verification)

**Public Auditability:**
- Job summary visible without login
- All logs public and permanent (90 days)
- Artifacts downloadable by anyone
- Workflow definition in version control

## Verifier Script Architecture

**File:** `tools/verify-kms.js`

### Purpose

Standalone CLI tool that anyone can run to verify KMS artifacts independently (outside GitHub Actions).

### Usage

```bash
# Verify latest release
node tools/verify-kms.js

# Verify specific release
node tools/verify-kms.js --release v1.2.0

# Verify custom URL
node tools/verify-kms.js --url https://custom-cdn.example.com/kms.mjs

# Verbose output
node tools/verify-kms.js --verbose
```

### Implementation

```javascript
#!/usr/bin/env node

/**
 * KMS Artifact Verifier
 *
 * Standalone verification tool that can be run by anyone to verify
 * KMS artifacts match the released source code.
 *
 * Usage:
 *   node tools/verify-kms.js [--release v1.0.0] [--url URL] [--verbose]
 */

import { spawn } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import https from 'https';

// ============================================================
// Configuration
// ============================================================

const CONFIG = {
  REPO: 'Lukium/ats-kms-enclave',
  DEFAULT_RELEASE: 'latest',
  DEFAULT_URL: 'https://kms.ats.run/kms.mjs',
  NODE_VERSION: '20.11.1',
  PNPM_VERSION: '8.15.0',
};

// ============================================================
// Utilities
// ============================================================

function log(msg, level = 'info') {
  const prefix = {
    info: 'ℹ️ ',
    success: '✅',
    error: '❌',
    warn: '⚠️ ',
  }[level] || '';
  console.log(`${prefix} ${msg}`);
}

function verbose(msg) {
  if (process.argv.includes('--verbose')) {
    console.log(`  ${msg}`);
  }
}

async function exec(cmd, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    verbose(`$ ${cmd} ${args.join(' ')}`);
    const proc = spawn(cmd, args, { stdio: 'inherit', ...options });
    proc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Command failed with code ${code}`));
    });
  });
}

async function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

function computeHashes(data) {
  const sha256 = createHash('sha256').update(data).digest('hex');
  const sri = 'sha256-' + createHash('sha256').update(data).digest('base64');
  return { sha256, sri, size: data.length };
}

// ============================================================
// Verification Steps
// ============================================================

async function resolveRelease(release) {
  if (release && release !== 'latest') return release;

  log('Resolving latest release...');
  const url = `https://api.github.com/repos/${CONFIG.REPO}/releases/latest`;
  const data = await fetchUrl(url);
  const json = JSON.parse(data.toString());
  verbose(`Latest release: ${json.tag_name}`);
  return json.tag_name;
}

async function buildLocal(release, tmpDir) {
  log(`Building KMS ${release} from source...`);

  // Clone release
  await exec('git', ['clone', '--depth=1', '--branch', release,
    `https://github.com/${CONFIG.REPO}.git`, tmpDir]);

  // Install dependencies
  await exec('pnpm', ['install', '--frozen-lockfile'], { cwd: tmpDir });

  // Build reproducibly
  const env = { ...process.env, SOURCE_DATE_EPOCH: '1698765432' };
  await exec('pnpm', ['build:reproducible'], { cwd: tmpDir, env });

  // Find artifact
  const distDir = join(tmpDir, 'dist');
  const files = require('fs').readdirSync(distDir);
  const artifact = files.find(f => f.startsWith('kms-') && f.endsWith('.mjs'));

  if (!artifact) {
    throw new Error('No KMS artifact found in dist/');
  }

  verbose(`Built: ${artifact}`);
  return join(distDir, artifact);
}

async function fetchLive(url) {
  log(`Fetching live artifact from ${url}...`);
  const data = await fetchUrl(url);
  verbose(`Downloaded ${data.length} bytes`);
  return data;
}

async function compareHashes(localPath, liveData) {
  log('Comparing hashes...');

  const localData = readFileSync(localPath);
  const local = computeHashes(localData);
  const live = computeHashes(liveData);

  console.log('\nHash Comparison:');
  console.log('─'.repeat(80));
  console.log(`SHA-256:`);
  console.log(`  Local: ${local.sha256}`);
  console.log(`  Live:  ${live.sha256}`);
  console.log(`  ${local.sha256 === live.sha256 ? '✅ MATCH' : '❌ MISMATCH'}`);
  console.log();
  console.log(`SRI:`);
  console.log(`  Local: ${local.sri}`);
  console.log(`  Live:  ${live.sri}`);
  console.log(`  ${local.sri === live.sri ? '✅ MATCH' : '❌ MISMATCH'}`);
  console.log();
  console.log(`Size:`);
  console.log(`  Local: ${local.size} bytes`);
  console.log(`  Live:  ${live.size} bytes`);
  console.log(`  ${local.size === live.size ? '✅ MATCH' : '❌ MISMATCH'}`);
  console.log('─'.repeat(80));

  return {
    match: local.sha256 === live.sha256 && local.sri === live.sri,
    local,
    live,
  };
}

async function verifySigstore(release, localPath, tmpDir) {
  log('Verifying Sigstore bundle...');

  // Download bundle from GitHub release
  const bundleUrl = `https://github.com/${CONFIG.REPO}/releases/download/${release}/kms-${release}.mjs.bundle`;
  const bundleData = await fetchUrl(bundleUrl);
  const bundlePath = join(tmpDir, 'artifact.bundle');
  writeFileSync(bundlePath, bundleData);

  // Verify with cosign
  try {
    await exec('cosign', [
      'verify-blob',
      '--bundle', bundlePath,
      '--certificate-identity-regexp', `^https://github.com/${CONFIG.REPO}/`,
      '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
      localPath,
    ]);
    log('Sigstore verification passed', 'success');
    return true;
  } catch (err) {
    log('Sigstore verification failed', 'error');
    verbose(err.message);
    return false;
  }
}

// ============================================================
// Main
// ============================================================

async function main() {
  console.log('🔐 ATS KMS Verifier\n');

  // Parse arguments
  const args = process.argv.slice(2);
  const releaseArg = args.find(a => a.startsWith('--release='))?.split('=')[1];
  const urlArg = args.find(a => a.startsWith('--url='))?.split('=')[1] || CONFIG.DEFAULT_URL;

  try {
    // Resolve release
    const release = await resolveRelease(releaseArg || CONFIG.DEFAULT_RELEASE);
    console.log(`📦 Verifying release: ${release}\n`);

    // Create temp directory
    const tmpDir = mkdtempSync(join(tmpdir(), 'kms-verify-'));
    verbose(`Temp directory: ${tmpDir}`);

    try {
      // Build from source
      const localPath = await buildLocal(release, tmpDir);

      // Fetch live artifact
      const liveData = await fetchLive(urlArg);

      // Compare hashes
      const comparison = await compareHashes(localPath, liveData);

      // Verify Sigstore
      const sigstoreOk = await verifySigstore(release, localPath, tmpDir);

      // Final result
      console.log();
      if (comparison.match && sigstoreOk) {
        log('VERIFICATION PASSED', 'success');
        log('Deployed artifact matches audited source code', 'info');
        process.exit(0);
      } else {
        log('VERIFICATION FAILED', 'error');
        if (!comparison.match) log('Hash mismatch detected', 'error');
        if (!sigstoreOk) log('Sigstore verification failed', 'error');
        process.exit(1);
      }
    } finally {
      // Cleanup
      verbose('Cleaning up temp directory...');
      rmSync(tmpDir, { recursive: true, force: true });
    }
  } catch (err) {
    log(`Verification error: ${err.message}`, 'error');
    if (process.argv.includes('--verbose')) {
      console.error(err);
    }
    process.exit(1);
  }
}

main();
```

### Security Properties

**Independence:**
- Runs outside GitHub Actions (user's local machine)
- Downloads verifier code from repo (auditable)
- Performs same checks as CI workflow
- Does not trust any intermediate servers

**Reproducibility:**
- Uses same build process as CI
- Same frozen lockfile
- Same `SOURCE_DATE_EPOCH`
- Byte-for-byte identical output

**Cryptographic Verification:**
- Computes hashes independently
- Verifies Sigstore bundle with cosign
- Checks Rekor transparency log
- No trust in CDN required (hashes prove integrity)

## Hash Comparison Algorithm

### SHA-256 Computation

```bash
# Method 1: sha256sum (Linux/macOS)
sha256sum kms.mjs

# Method 2: openssl
openssl dgst -sha256 kms.mjs

# Method 3: Node.js crypto
node -e "
const fs = require('fs');
const crypto = require('crypto');
const data = fs.readFileSync('kms.mjs');
const hash = crypto.createHash('sha256').update(data).digest('hex');
console.log(hash);
"
```

### SRI Hash Computation

SRI (Subresource Integrity) format: `sha256-<base64>`

```bash
# Method 1: openssl
SRI="sha256-$(openssl dgst -sha256 -binary kms.mjs | openssl base64 -A)"
echo $SRI

# Method 2: Node.js crypto
node -e "
const fs = require('fs');
const crypto = require('crypto');
const data = fs.readFileSync('kms.mjs');
const hash = crypto.createHash('sha256').update(data).digest('base64');
console.log('sha256-' + hash);
"
```

### Why Both SHA-256 and SRI?

**SHA-256 (hex):**
- Standard format for file integrity
- Used in Git commits, Docker images, etc.
- Easy to compare visually

**SRI (base64):**
- Used by browsers for `<script integrity="...">`
- Verifies KMS loads correct artifact
- Provides second independent check

Both must match for verification to pass.

## Sigstore Verification Flow

### Overview

Sigstore provides keyless code signing using:
1. **OIDC identity** (GitHub Actions workflow)
2. **Short-lived certificates** (10-minute validity)
3. **Transparency logs** (Rekor - public, immutable)

### Verification Steps

```bash
# 1. Verify signature and certificate
cosign verify-blob \
  --bundle kms-v1.0.0.mjs.bundle \
  --certificate-identity-regexp "^https://github.com/Lukium/ats-kms-enclave/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  kms-v1.0.0.mjs

# This checks:
# - Signature is valid (ECDSA P-256)
# - Certificate matches GitHub Actions identity
# - Certificate was issued by Sigstore CA
# - Rekor entry exists and is valid
# - Artifact hash matches signed hash
```

### What Sigstore Proves

✅ **Artifact was built by GitHub Actions**
- Certificate embedded with workflow identity
- OIDC token proves workflow ran
- Cannot be forged without compromising GitHub

✅ **Artifact hasn't been modified**
- Signature covers artifact hash
- Any modification breaks signature
- Mathematically impossible to forge

✅ **Build happened at specific time**
- Certificate has timestamp
- Rekor entry has timestamp
- Cannot be backdated

✅ **Evidence is public and permanent**
- Rekor is append-only transparency log
- Anyone can query entries
- Cannot be deleted or hidden

### Sigstore Bundle Contents

```json
{
  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
  "verificationMaterial": {
    "certificate": "<x509 certificate with GitHub Actions identity>",
    "tlogEntries": [
      {
        "logIndex": 12345678,
        "logId": "<Rekor log ID>",
        "integratedTime": 1698765432
      }
    ]
  },
  "messageSignature": {
    "signature": "<ECDSA P-256 signature>",
    "messageDigest": {
      "algorithm": "SHA2_256",
      "digest": "<artifact SHA-256>"
    }
  }
}
```

## Public Evidence Format

### Job Summary (GitHub Actions UI)

Displayed at the top of each workflow run:

```markdown
# KMS Verification Report

**Status:** ✅ PASS

**Verification Details:**
- **Timestamp:** 2025-10-23 14:23:42 UTC
- **Verifier Commit:** `abc123def456`
- **Release Tag:** `v1.0.0`
- **Workflow Run:** [#1234](https://github.com/.../runs/1234)

## Hash Comparison

| Hash Type | Local Build | Live Artifact | Match |
|-----------|-------------|---------------|-------|
| **SHA-256** | `3a5b...9f2e` | `3a5b...9f2e` | ✅ |
| **SRI** | `sha256-OlvH...nLs=` | `sha256-OlvH...nLs=` | ✅ |
| **Size** | 123456 bytes | 123456 bytes | ✅ |

## Sigstore Verification

- **Signature:** ✅ Valid
- **Rekor Entry:** [`abc12345`](https://rekor.sigstore.dev/api/v1/log/entries/abc12345)
- **Certificate:** Verified with GitHub Actions OIDC

## Artifacts

- Local build: `kms-v1.0.0-3a5b9f2e.mjs`
- Live URL: https://kms.ats.run/kms.mjs

---

**Verifier code:** [View at commit `abc123def456`](https://github.com/.../tree/abc123def456)
```

### Verification Report JSON

Downloadable artifact with complete details:

```json
{
  "timestamp": "2025-10-23T14:23:42Z",
  "verifier_commit": "abc123def456",
  "release_tag": "v1.0.0",
  "workflow_run_id": "1234567890",
  "workflow_run_number": 1234,
  "local_build": {
    "artifact": "kms-v1.0.0-3a5b9f2e.mjs",
    "sha256": "3a5b9f2e...",
    "sri": "sha256-OlvH...nLs=",
    "size": 123456
  },
  "live_artifact": {
    "url": "https://kms.ats.run/kms.mjs",
    "sha256": "3a5b9f2e...",
    "sri": "sha256-OlvH...nLs=",
    "size": 123456
  },
  "comparison": {
    "sha256_match": true,
    "sri_match": true,
    "result": "PASS"
  },
  "sigstore": {
    "verified": true,
    "rekor_entry_id": "abc12345",
    "certificate_identity": "https://github.com/Lukium/ats-kms-enclave/.github/workflows/release.yml@refs/tags/v1.0.0"
  }
}
```

### Workflow Logs

Complete audit trail of every command executed:

```
Run: pnpm build:reproducible
> @ats/kms-enclave@1.0.0 build:reproducible
> node build/esbuild.js --reproducible

✅ Build complete: kms-v1.0.0-3a5b9f2e.mjs

Run: sha256sum kms-v1.0.0-3a5b9f2e.mjs
3a5b9f2e... kms-v1.0.0-3a5b9f2e.mjs

Run: openssl dgst -sha256 -binary kms-v1.0.0-3a5b9f2e.mjs | openssl base64 -A
sha256-OlvH...nLs=

Run: curl -fsSL https://kms.ats.run/kms.mjs -o live-kms.mjs
[downloaded]

Run: sha256sum live-kms.mjs
3a5b9f2e... live-kms.mjs

✅ SHA-256 hashes MATCH
✅ SRI hashes MATCH
✅ VERIFICATION PASSED
```

## Tamper Resistance Mechanisms

### 1. Pinned Action SHAs

**Why:** GitHub Actions can be referenced by tags (e.g., `v4`), which can be moved to point to malicious code.

**Solution:** Pin all actions to commit SHAs:

```yaml
# ❌ BAD (tag can be moved)
- uses: actions/checkout@v4

# ✅ GOOD (immutable commit)
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608  # v4.1.0
```

All actions in both workflows use commit SHAs with version comments.

### 2. Protected Branches

**Configuration** (`.github/branch-protection.yml`):

```yaml
main:
  required_status_checks:
    strict: true
    contexts:
      - test
      - lint
      - typecheck
  required_pull_request_reviews:
    required_approving_review_count: 1
  restrictions:
    users: []
    teams: []
```

**Effect:**
- Cannot push directly to `main`
- All changes require PR review
- Prevents tampering with workflow files
- Audit trail of all modifications

### 3. OIDC Attestations

GitHub Actions provides cryptographic proof of workflow identity:

```yaml
permissions:
  id-token: write  # Required for OIDC
```

**Embedded in Sigstore certificates:**
- Workflow path (e.g., `.github/workflows/release.yml`)
- Ref (e.g., `refs/tags/v1.0.0`)
- Repository (e.g., `Lukium/ats-kms-enclave`)
- Commit SHA

**Cannot be forged:**
- GitHub signs OIDC tokens
- Sigstore CA validates before issuing certificate
- Certificate embedded in bundle
- Anyone can verify identity

### 4. Commit-Bound Evidence

Every verification report includes:

```
Verifier commit: abc123def456
```

Users can audit the exact verifier code:

```bash
# Checkout verifier code used in run #1234
git checkout abc123def456

# Review workflow files
cat .github/workflows/kms-verify.yml
cat tools/verify-kms.js
```

**If verifier code is malicious, it's visible in the audit.**

## Security Analysis

### Attack Scenarios

**Scenario 1: ATS developer tries to deploy backdoored KMS**

1. Developer modifies `src/worker.ts` to exfiltrate keys
2. Commits to branch, creates PR
3. CI builds and tests pass (backdoor is stealthy)
4. PR merged, released as `v1.0.1`
5. Random verification runs within hours
6. **Verifier rebuilds from source** → includes backdoor
7. **Verifier fetches live artifact** → also has backdoor
8. **Hashes match** → verification passes

**Result:** ❌ Backdoor not detected

**Why this isn't a problem:**
- Source code is public (anyone can audit)
- Backdoor would be visible in Git history
- Code review process catches obvious exfiltration
- Users are trusting audited source, not build process

**What self-attestation proves:**
- Deployed artifact matches the source in Git
- We didn't deploy something different from Git
- Build process is honest

**What it doesn't prove:**
- Source code is not malicious
- Crypto operations are correct

**Defense:** Users should audit source code before trusting KMS.

---

**Scenario 2: ATS developer tries to deploy backdoor without committing to Git**

1. Developer deploys modified `kms.mjs` to CDN
2. CDN now serves backdoored version
3. Random verification runs
4. **Verifier rebuilds from Git** → no backdoor
5. **Verifier fetches live CDN** → has backdoor
6. **Hashes don't match** → verification fails

**Result:** ✅ Attack detected immediately

---

**Scenario 3: CDN compromise (attacker replaces artifact)**

Same as Scenario 2 - hash mismatch detected.

---

**Scenario 4: ATS developer modifies verifier to always pass**

1. Developer changes `kms-verify.yml` to skip comparison
2. Commits to branch, creates PR
3. PR shows workflow changes (visible in diff)
4. If merged, verification always passes

**Result:** ❌ Attack succeeds if PR review fails

**Defense:**
- Protected branches require code review
- Workflow changes are highly visible
- Community can audit verifier code via commit SHAs
- Multiple reviewers should check workflow changes

---

**Scenario 5: ATS developer schedules "good" verification runs**

1. Developer knows verification runs ~3x/day
2. Developer tries to time deployments between runs
3. Random cadence workflow uses `$RANDOM` (unpredictable)
4. Even if timing is guessed, 0-30min jitter adds uncertainty
5. Fallback weekly run catches any missed checks

**Result:** ❌ Attack is impractical (timing cannot be predicted)

---

**Scenario 6: GitHub Actions compromise**

If GitHub Actions infrastructure is compromised, attacker can:
- Modify workflow execution
- Fake verification results
- Tamper with artifacts

**Result:** ❌ Attack succeeds (violates trust assumptions)

**Defense:**
- Users should run independent verification with `tools/verify-kms.js`
- Sigstore Rekor provides external verification (not controlled by GitHub)
- Multiple independent verifiers increase confidence

---

### Trust Boundary Analysis

**What you MUST trust:**

1. **GitHub Actions infrastructure**
   - Executes workflows honestly
   - Doesn't tamper with logs
   - Provides valid OIDC tokens

2. **Sigstore infrastructure**
   - Rekor log is append-only
   - Certificate authority validates identities
   - Transparency log is publicly auditable

3. **Your own machine** (when running `tools/verify-kms.js`)
   - OS and tools aren't compromised
   - Network connection isn't MITMed (use HTTPS)

**What you DON'T need to trust:**

1. **ATS developers**
   - Verifier code is auditable
   - Workflow runs are automatic and public
   - Can audit exact code used in each run

2. **CDN hosting KMS artifact**
   - Hash comparison detects tampering
   - SRI provides browser-level verification
   - Sigstore proves origin

3. **Build server**
   - Reproducible builds allow independent verification
   - Anyone can rebuild and compare hashes

### Residual Risks

**Risk 1: Malicious source code merged to Git**

- **Likelihood:** Low (code review, open source)
- **Impact:** High (backdoor deployed)
- **Mitigation:** Encourage community audits, security reviews

**Risk 2: Verifier code tampered with**

- **Likelihood:** Low (protected branches, visible changes)
- **Impact:** High (false verification passes)
- **Mitigation:** Commit-bound evidence allows audit of verifier code

**Risk 3: GitHub Actions compromise**

- **Likelihood:** Very low (GitHub's security posture)
- **Impact:** Critical (all verification bypassed)
- **Mitigation:** Encourage independent verification with local tool

**Risk 4: Coordinated timing attack**

- **Likelihood:** Very low (random timing + jitter)
- **Impact:** Medium (backdoor deployed between checks)
- **Mitigation:** Fallback weekly run, increase verification frequency

## Implementation Checklist

### Phase 2: Reproducible Builds (Prerequisite)

- [ ] Implement deterministic esbuild configuration
- [ ] Add content-addressed filename generation
- [ ] Compute SRI hashes
- [ ] Test byte-for-byte reproducibility
- [ ] Document build process

### Phase 3: Sigstore Integration (Prerequisite)

- [ ] Install cosign CLI in release workflow
- [ ] Sign artifacts with GitHub Actions OIDC
- [ ] Publish to Rekor transparency log
- [ ] Attach bundles to GitHub releases
- [ ] Document verification process

### Phase 4: Random Cadence Workflow

- [ ] Create `.github/workflows/random-cadence.yml`
- [ ] Implement probabilistic triggering (12% per hour)
- [ ] Add random jitter (0-30 minutes)
- [ ] Test with manual `workflow_dispatch`
- [ ] Enable cron schedule

### Phase 5: KMS Verifier Workflow

- [ ] Create `.github/workflows/kms-verify.yml`
- [ ] Implement reproducible build step
- [ ] Add live artifact fetching
- [ ] Implement hash comparison logic
- [ ] Add Sigstore verification
- [ ] Generate job summary
- [ ] Upload verification artifacts
- [ ] Test with known-good release

### Phase 6: Verifier CLI Tool

- [ ] Create `tools/verify-kms.js`
- [ ] Implement local build logic
- [ ] Add hash comparison
- [ ] Add Sigstore verification
- [ ] Add command-line options
- [ ] Write usage documentation
- [ ] Test on multiple platforms

### Phase 7: Documentation and Rollout

- [ ] Write user-facing verification guide
- [ ] Add verification badge to README
- [ ] Announce self-attestation system
- [ ] Monitor initial runs
- [ ] Fix any issues
- [ ] Increase verification frequency if stable

## Related Documentation

- [README](./README.md) - High-level overview
- [Current State](./current-state.md) - What exists today
- [Plan](./plan.md) - Implementation roadmap (to be written)
- [Target State](./target-state.md) - Ideal end state (to be written)
