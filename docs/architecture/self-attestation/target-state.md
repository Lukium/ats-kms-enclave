# Self-Attestation: Target State

**Status:** Design Phase (describes ideal end state, not yet implemented)

## Overview

This document describes the **ideal end state** of the self-attestation system when fully implemented and operational. This is what users will experience and what the system will look like when all phases are complete.

## User Experience

### For Security Researchers and Auditors

**Discovery:**
1. Researcher visits `https://github.com/Lukium/ats-kms-enclave`
2. Sees badge in README: [![Verification Status](badge.svg)](workflow-link)
3. Clicks badge → lands on GitHub Actions verification workflow page
4. Sees recent verification runs, all passing ✅

**Inspection:**
1. Clicks on most recent verification run
2. Sees job summary with hash comparison table
3. Sees all hashes match ✅
4. Sees Sigstore verification passed ✅
5. Sees link to exact verifier code commit used

**Audit:**
1. Clicks verifier code commit link
2. Reviews `.github/workflows/kms-verify.yml`
3. Reviews `tools/verify-kms.js`
4. Verifies workflow does what it claims (rebuild, fetch, compare)
5. Checks for backdoors or tampering (none found)

**Independent Verification:**
1. Clones repository
2. Runs `node tools/verify-kms.js`
3. Waits 2-3 minutes
4. Sees output: "✅ VERIFICATION PASSED"
5. Gains confidence that deployed artifact matches source

**Rekor Audit:**
1. Visits [https://rekor.sigstore.dev/](https://rekor.sigstore.dev/)
2. Searches for `Lukium/ats-kms-enclave`
3. Sees list of all releases with timestamps
4. Verifies release signatures
5. Confirms GitHub Actions was the signer

**Result:**
- ✅ **High confidence** that KMS artifact is trustworthy
- ✅ **No need to trust ATS developers** - math proves correctness
- ✅ **Can verify independently** - don't rely on GitHub Actions
- ✅ **Public evidence** - can share findings with others

---

### For End Users (PWA Visitors)

**Initial visit:**
1. User visits `https://ats.run`
2. PWA loads, includes KMS iframe from `https://kms.ats.run`
3. Browser loads `kms.html` with SRI verification
4. `<script type="module" integrity="sha256-..." src="kms-v1.0.0-3a5b9f2e.mjs">`
5. Browser verifies hash matches before executing code
6. If hash mismatch → browser refuses to load script
7. User sees error: "KMS failed integrity check"

**Settings page:**
1. User opens PWA settings
2. Sees "Security" section
3. Sees "KMS Version: v1.0.0 (hash: 3a5b9f2e)"
4. Sees link: "Verify this build"
5. Clicks link → opens verification guide

**Verification guide (in PWA):**
```
Your KMS is running version v1.0.0 (hash: 3a5b9f2e)

To verify this build matches audited source code:

1. Visit the verification page:
   https://github.com/Lukium/ats-kms-enclave/actions/workflows/kms-verify.yml

2. Look for recent runs that show:
   Live artifact: sha256-3a5b9f2e...
   Result: ✅ PASS

3. Or run verification yourself:
   git clone https://github.com/Lukium/ats-kms-enclave.git
   cd ats-kms-enclave
   node tools/verify-kms.js --release v1.0.0

If verification passes, you can trust that:
✅ The KMS code matches the public source code
✅ ATS developers cannot access your keys
✅ The build process was honest and reproducible
```

**Hash mismatch (security breach):**
1. User visits PWA
2. Browser loads KMS iframe
3. SRI check fails (hash doesn't match)
4. Browser refuses to execute KMS script
5. PWA shows error modal:
   ```
   🚨 Security Warning 🚨

   KMS failed integrity check!

   The KMS artifact does not match the expected hash.
   This could indicate:
   - CDN compromise
   - Man-in-the-middle attack
   - Server misconfiguration

   Your keys are safe (they cannot be accessed), but
   you should not create new keys until this is resolved.

   Expected: sha256-3a5b9f2e...
   Received: sha256-8d9e1f2a...

   Contact support: security@ats.run
   ```

**Result:**
- ✅ **Browser enforces integrity** (SRI verification)
- ✅ **User can verify hash** (displayed in settings)
- ✅ **Clear error messages** (if integrity fails)
- ✅ **Fail-secure** (PWA refuses to load compromised KMS)

---

### For ATS Developers

**Release process:**
1. Developer creates release PR
2. PR includes version bump and changelog
3. CI runs all tests, builds reproducibly
4. PR reviewed and merged
5. Developer creates Git tag: `git tag v1.0.1`
6. Developer pushes tag: `git push origin v1.0.1`

**Automatic release workflow:**
```
Trigger: Git tag pushed
  ↓
Build reproducibly with SOURCE_DATE_EPOCH
  ↓
Generate content-addressed filename: kms-v1.0.1-7f8a9b0c.mjs
  ↓
Compute SHA-256 and SRI hashes
  ↓
Sign with Sigstore (GitHub Actions OIDC identity)
  ↓
Publish to Rekor transparency log
  ↓
Create GitHub Release with:
  - kms-v1.0.1-7f8a9b0c.mjs
  - kms-v1.0.1-7f8a9b0c.mjs.bundle (Sigstore)
  - kms.html (with updated SRI)
  ↓
Deploy to CDN (kms.ats.run):
  - /kms.mjs → kms-v1.0.1-7f8a9b0c.mjs (symlink or redirect)
  - /kms.html (with SRI integrity attribute)
```

**Automatic verification (random):**
```
Random cadence workflow runs every hour
  ↓
12% chance → triggers verification
  ↓
Random jitter (0-30 minutes)
  ↓
KMS verifier workflow runs:
  1. Rebuild from v1.0.1 source
  2. Fetch from https://kms.ats.run/kms.mjs
  3. Compare hashes
  4. Verify Sigstore bundle
  5. Publish evidence
  ↓
Job summary shows: ✅ PASS
  ↓
Verification report artifact uploaded
```

**Monitoring dashboard:**
1. Developer visits GitHub Actions page
2. Sees recent verification runs (3-4 per day)
3. All showing ✅ PASS
4. Clicks on a run to see details
5. Sees hash comparison table (all matches)
6. Sees Rekor entry link

**If verification fails:**
1. Developer receives GitHub notification (workflow failed)
2. Checks job summary → ❌ FAIL
3. Sees hash mismatch:
   ```
   SHA-256:
     Local:  7f8a9b0c...
     Live:   8d9e1f2a... ❌ MISMATCH
   ```
4. Investigates cause:
   - Was CDN updated with wrong file?
   - Was artifact tampered with?
   - Is there a caching issue?
5. Fixes issue (redeploy correct artifact)
6. Manually triggers verification to confirm fix

**Result:**
- ✅ **Automated release process** (no manual signing)
- ✅ **Continuous monitoring** (3-4x/day verification)
- ✅ **Immediate alerts** (if verification fails)
- ✅ **Public evidence** (builds trust with users)

---

## System Architecture (Fully Operational)

### Repository Structure

```
ats-kms-enclave/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                      ✅ Test/lint/typecheck/build
│   │   ├── release.yml                 ✅ Reproducible build + Sigstore
│   │   ├── random-cadence.yml          ✅ Triggers ~3x/day
│   │   └── kms-verify.yml              ✅ Verification workflow
│   └── branch-protection.yml           ✅ Protected main branch
├── src/
│   ├── main.ts                         ✅ Enclave main thread
│   ├── worker.ts                       ✅ Crypto operations
│   └── storage.ts                      ✅ IndexedDB persistence
├── public/
│   └── kms.html                        ✅ Iframe bootstrap with SRI
├── build/
│   ├── esbuild.js                      ✅ Deterministic build
│   └── content-address.ts              ✅ Hash-based filenames
├── tools/
│   └── verify-kms.js                   ✅ CLI verification tool
├── docs/
│   ├── architecture/
│   │   ├── crypto/                     ✅ Crypto architecture
│   │   └── self-attestation/           ✅ This documentation
│   ├── verification-guide.md           ✅ User guide
│   └── release-process.md              ✅ Release checklist
├── tests/
│   ├── unit/                           ✅ 100% coverage
│   ├── integration/                    ✅ E2E RPC tests
│   └── e2e/                            ✅ Browser tests
└── README.md                           ✅ With verification badge
```

### GitHub Actions Workflows

**CI Workflow** (`.github/workflows/ci.yml`)
- Runs on every push and PR
- Tests (100% coverage required)
- Linting (ESLint)
- Type checking (TypeScript)
- Reproducible build (uploads artifact)

**Release Workflow** (`.github/workflows/release.yml`)
- Triggers on Git tag push
- Builds reproducibly with `SOURCE_DATE_EPOCH`
- Generates content-addressed filename
- Computes SRI hash
- Signs with Sigstore/cosign
- Publishes to Rekor transparency log
- Creates GitHub Release with:
  - `kms-v{version}-{hash}.mjs`
  - `kms-v{version}-{hash}.mjs.bundle`
  - `kms.html` (with SRI)

**Random Cadence Workflow** (`.github/workflows/random-cadence.yml`)
- Runs every hour via cron
- 12% probability triggers verification (~3x/day)
- Random jitter (0-30 minutes)
- Dispatches to `kms-verify.yml`

**Verifier Workflow** (`.github/workflows/kms-verify.yml`)
- Rebuilds from tagged release
- Fetches live artifact from CDN
- Compares SHA-256 and SRI hashes
- Verifies Sigstore bundle
- Publishes job summary and artifacts
- Fails if hashes don't match

### CDN Deployment

**File structure:**
```
https://kms.ats.run/
├── kms.mjs                            → symlink to latest version
├── kms.html                           → iframe bootstrap
├── kms-v1.0.0-3a5b9f2e.mjs           → immutable (v1.0.0)
├── kms-v1.0.1-7f8a9b0c.mjs           → immutable (v1.0.1)
└── ...                                → (old versions kept for audit)
```

**kms.html:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>ATS KMS Enclave</title>
</head>
<body>
  <!-- SRI verification -->
  <script type="module"
    integrity="sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU="
    src="/kms-v1.0.1-7f8a9b0c.mjs">
  </script>
</body>
</html>
```

**Deployment process:**
1. Release workflow uploads artifacts to CDN
2. Old versions kept (immutable, content-addressed)
3. `kms.mjs` symlink updated to latest version
4. `kms.html` updated with new SRI hash
5. CDN cache invalidated (force refresh)

### Verification Evidence

**Job Summary** (visible in GitHub Actions UI):

```markdown
# KMS Verification Report

**Status:** ✅ PASS

**Verification Details:**
- **Timestamp:** 2025-10-23 14:23:42 UTC
- **Verifier Commit:** [`abc123d`](commit-link)
- **Release Tag:** `v1.0.1`
- **Workflow Run:** [#1234](run-link)

## Hash Comparison

| Hash Type | Local Build | Live Artifact | Match |
|-----------|-------------|---------------|-------|
| **SHA-256** | `7f8a9b0c...` | `7f8a9b0c...` | ✅ |
| **SRI** | `sha256-f4OxZX...` | `sha256-f4OxZX...` | ✅ |
| **Size** | 123456 bytes | 123456 bytes | ✅ |

## Sigstore Verification

- **Signature:** ✅ Valid
- **Rekor Entry:** [`12345678`](rekor-link)
- **Certificate:** Verified with GitHub Actions OIDC
- **Identity:** `https://github.com/Lukium/ats-kms-enclave/.github/workflows/release.yml@refs/tags/v1.0.1`

## Artifacts

- Local build: `kms-v1.0.1-7f8a9b0c.mjs`
- Live URL: https://kms.ats.run/kms.mjs

---

**Verifier code:** [View at commit `abc123d`](commit-link)
```

**Downloadable Artifacts:**
- `verification-report.json` - Structured JSON with all data
- `dist/kms-v1.0.1-7f8a9b0c.mjs` - Reproducible build output
- `live-kms.mjs` - Downloaded live artifact (for comparison)
- `kms-v1.0.1-7f8a9b0c.mjs.bundle` - Sigstore bundle

**Workflow Logs:**
- Complete audit trail of every command executed
- Shows build output, hash computation, comparison results
- Visible to anyone (public repository)

### Independent Verification

**CLI Tool** (`tools/verify-kms.js`):

```bash
$ node tools/verify-kms.js
🔐 ATS KMS Verifier

📦 Verifying release: v1.0.1

ℹ️  Building KMS v1.0.1 from source...
ℹ️  Fetching live artifact from https://kms.ats.run/kms.mjs...
ℹ️  Comparing hashes...

Hash Comparison:
────────────────────────────────────────────────────────────────
SHA-256:
  Local: 7f8a9b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e
  Live:  7f8a9b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e
  ✅ MATCH

SRI:
  Local: sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU=
  Live:  sha256-f4OxZX/x/FO5LcGBSKHWXfwtSxCeq6d2kqbUqZ5K6fU=
  ✅ MATCH

Size:
  Local: 123456 bytes
  Live:  123456 bytes
  ✅ MATCH
────────────────────────────────────────────────────────────────

ℹ️  Verifying Sigstore bundle...
✅ Sigstore verification passed

✅ VERIFICATION PASSED
ℹ️  Deployed artifact matches audited source code
```

**Usage:**
```bash
# Verify latest release
node tools/verify-kms.js

# Verify specific release
node tools/verify-kms.js --release v1.0.0

# Verify custom URL
node tools/verify-kms.js --url https://staging.kms.ats.run/kms.mjs

# Verbose output (show all commands)
node tools/verify-kms.js --verbose
```

## Security Properties (Fully Realized)

### What Self-Attestation Proves

✅ **Deployed artifact matches audited source code**
- Reproducible build from tagged release
- Hash comparison proves byte-for-byte match
- No hidden changes between Git and production

✅ **Build process is honest**
- GitHub Actions builds from public source
- Workflow definition is version-controlled
- Verifier code is auditable

✅ **Artifact hasn't been tampered with**
- SRI hash verified by browser on every load
- Random verification catches tampering
- Sigstore signature proves origin

✅ **ATS developers cannot deploy backdoors**
- Backdoor would be visible in Git
- Verification would detect hash mismatch
- Community can audit source code

✅ **CDN compromise is detected**
- If CDN serves different file, hashes won't match
- Verification fails immediately
- Users protected by SRI (browser refuses to load)

### What Self-Attestation Does NOT Prove

❌ **Source code is not malicious**
- Malicious code in Git would pass verification
- Users must still audit source code
- Self-attestation proves deployment matches source, not that source is safe

❌ **Browser implementation is secure**
- Assumes WebCrypto implementation is correct
- Assumes SRI implementation works
- Assumes browser sandbox is enforced

❌ **Keys are safe from browser extensions**
- Extensions can access page content
- Non-extractable keys help but not perfect
- Users should use dedicated browser profile

❌ **GitHub Actions is trustworthy**
- Must trust GitHub's infrastructure
- Must trust OIDC token issuance
- Can mitigate with independent CLI verification

### Trust Boundaries

**Must Trust:**
1. **Browser vendor** - WebCrypto, SRI, sandboxing work correctly
2. **GitHub Actions** - Workflows execute honestly, logs are real
3. **Sigstore/Rekor** - Transparency log is append-only, CA validates identities
4. **Git** - Commit history is tamper-evident
5. **Mathematics** - SHA-256 collision resistance, ECDSA signature security

**Do NOT Need to Trust:**
1. **ATS developers** - Verifier code is auditable, runs automatically
2. **CDN** - Hash comparison detects tampering, SRI enforces integrity
3. **Build server** - Reproducible builds allow independent verification
4. **Network** - HTTPS + SRI protect against MITM

### Defense in Depth Layers

**Layer 1: SRI (Browser Enforcement)**
- Browser verifies hash before executing code
- Catches any modification (CDN, MITM, etc.)
- Immediate protection on every page load

**Layer 2: Random Verification (Continuous)**
- Verifies deployed artifact ~3x per day
- Catches tampering within hours
- Public evidence builds trust

**Layer 3: Sigstore (External Proof)**
- Rekor transparency log (not controlled by ATS)
- Certificate transparency (public audit)
- Cryptographic proof of origin

**Layer 4: Reproducible Builds (Independent Verification)**
- Anyone can rebuild and verify
- No special access required
- CLI tool makes it easy

**Layer 5: Source Code Transparency (Community Audit)**
- Open source (anyone can review)
- Git history (tamper-evident)
- Protected branches (reviewed changes only)

## Operational Metrics

### Verification Frequency

**Target:** ~3 verifications per day

**Actual:**
- Random cadence: 24 checks/day × 12% = ~3 triggers/day
- Variance: 1-6 verifications per day (Poisson distribution)
- Fallback: 1 verification per week (if random fails)

**Yearly:** ~1,095 verifications (3 × 365)

### Verification Success Rate

**Target:** >99% pass rate

**Expected failures:**
- False positives: <0.1% (build non-determinism edge cases)
- True positives: 0% (no actual tampering expected)
- Network errors: <0.5% (CDN downtime, GitHub API limits)

**If pass rate drops below 95%:**
- Investigate immediately
- Check for systematic issue (CDN caching, build non-determinism)
- Disable random cadence if necessary
- Fix underlying issue before re-enabling

### Verification Run Time

**Target:** <10 minutes per run

**Breakdown:**
- Setup (checkout, install deps): ~2 minutes
- Build from source: ~1 minute
- Fetch live artifact: ~5 seconds
- Hash comparison: <1 second
- Sigstore verification: ~10 seconds
- Upload artifacts: ~30 seconds

**Total:** ~4 minutes (well under target)

### GitHub Actions Usage

**Monthly:**
- Random cadence checks: 720 runs (24/day × 30 days)
- Verification runs: ~90 runs (3/day × 30 days)
- CI runs: ~100 runs (varies by commit frequency)
- Release runs: ~2-4 runs (varies by release cadence)

**Total:** ~912 workflow runs/month

**GitHub Actions limits:**
- Free tier: 2,000 minutes/month
- Our usage: ~912 runs × 5 min = 4,560 minutes/month
- **Need paid tier or optimizations**

**Optimizations:**
- Cache dependencies (reduce install time)
- Use smaller runners (if available)
- Reduce verification frequency to 2x/day if needed

### Artifact Storage

**Per release:**
- `kms-v{version}-{hash}.mjs` - ~120 KB
- `kms-v{version}-{hash}.mjs.bundle` - ~10 KB
- `kms.html` - ~2 KB

**Total per release:** ~132 KB

**Yearly:** ~12 releases/year × 132 KB = 1.6 MB

**GitHub Release limits:**
- Per file: 2 GB (we're at 120 KB, plenty of room)
- Per release: Unlimited files
- **No concerns with storage**

### Verification Artifacts

**Per verification run:**
- `verification-report.json` - ~2 KB
- Build artifacts - ~120 KB
- Live artifact - ~120 KB
- Sigstore bundle - ~10 KB

**Total per run:** ~252 KB

**Monthly:** ~90 runs × 252 KB = 22 MB

**GitHub Actions artifact retention:**
- Default: 90 days
- Our usage: ~90 runs × 252 KB × 3 months = 66 MB
- **No concerns with storage**

## User-Facing Documentation

### README Badge

```markdown
# ATS KMS Enclave

[![CI](ci-badge)](ci-link)
[![Coverage](coverage-badge)](codecov-link)
[![Verification](verification-badge)](verification-link)

Browser-based verifiable Key Management System (KMS) enclave for AllTheServices.

## Security

This KMS uses **continuous self-attestation** to prove deployed artifacts match audited source code:

✅ **Verified ~3x per day** by independent GitHub Actions workflow
✅ **Reproducible builds** - anyone can rebuild and verify hashes
✅ **Sigstore signing** - cryptographic proof in Rekor transparency log
✅ **Browser SRI enforcement** - hash verified on every page load

**Latest verification:** [View workflow runs →](verification-link)

**Verify yourself:**
```bash
git clone https://github.com/Lukium/ats-kms-enclave.git
cd ats-kms-enclave
node tools/verify-kms.js
```

[Learn more about our self-attestation system →](docs/architecture/self-attestation/README.md)
```

### Verification Guide (for users)

**File:** `docs/verification-guide.md`

**Contents:**
- What is self-attestation and why it matters
- How to interpret verification runs
- How to run manual verification
- What to do if verification fails
- FAQ about trust model and security

### Settings Page (in PWA)

**UI mockup:**

```
┌─────────────────────────────────────────────────────────────┐
│ Settings                                                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ 🔐 Security                                                 │
│                                                             │
│ KMS Version: v1.0.1                                         │
│ Build Hash: 7f8a9b0c...                                     │
│                                                             │
│ [Verify This Build]                                         │
│                                                             │
│ Latest Verification:                                        │
│ ✅ Passed (2025-10-23 14:23 UTC)                            │
│                                                             │
│ [View All Verifications]                                    │
│                                                             │
│ What does this mean?                                        │
│ The KMS code has been independently verified to match      │
│ the audited source code. Your keys are protected by        │
│ browser isolation and cannot be accessed by ATS servers.   │
│                                                             │
│ [Learn More About KMS Security →]                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**When user clicks "Verify This Build":**
- Opens modal with verification instructions
- Shows expected hash
- Links to GitHub Actions verification runs
- Links to manual verification guide

**When user clicks "View All Verifications":**
- Opens GitHub Actions workflow page in new tab
- Filters to show only `kms-verify.yml` runs
- User can see all recent verification runs

## Future Enhancements

### Phase 8: Blockchain Anchoring (Optional)

**Idea:** Publish verification evidence to a blockchain for permanent, decentralized proof.

**Implementation:**
- Post verification hashes to Ethereum (expensive)
- Post to Polygon/Arbitrum (cheaper)
- Or post to IPFS + Filecoin (permanent storage)

**Benefits:**
- Evidence survives even if GitHub disappears
- Fully decentralized verification
- Timestamped proof (blockchain blocks)

**Costs:**
- Gas fees for blockchain transactions
- Additional complexity
- May not be worth it (Rekor already provides transparency)

**Decision:** Deferred to Phase 8, evaluate after Phase 7 success.

---

### Phase 9: Multi-Party Verification

**Idea:** Multiple independent parties run verification, publish results.

**Implementation:**
- Community members volunteer to run verifiers
- Each publishes results to own platform
- Aggregate results into dashboard

**Benefits:**
- Even less trust in GitHub Actions
- Distributed verification
- Community involvement

**Challenges:**
- Coordinating multiple verifiers
- Aggregating results
- What if verifiers disagree?

**Decision:** Deferred to Phase 9, evaluate community interest.

---

### Phase 10: Real-Time Verification

**Idea:** Verify on every PWA page load (client-side).

**Implementation:**
- PWA checks hash on startup
- Compares with known-good hash (from API)
- Displays result to user

**Benefits:**
- Immediate feedback
- No reliance on GitHub Actions schedule
- User sees verification status in UI

**Challenges:**
- Where does "known-good hash" come from? (trust problem)
- Cannot do full rebuild in browser
- May give false sense of security

**Decision:** Deferred to Phase 10, research trust model.

---

## Success Criteria (Fully Operational)

### Technical Success

✅ **Reproducible builds work**
- Two independent builds produce identical artifacts
- Tested on multiple machines and OSes
- CI builds match local builds

✅ **Sigstore integration works**
- All releases signed with GitHub Actions identity
- Rekor entries created successfully
- Manual verification with cosign passes

✅ **Random verification runs ~3x/day**
- Cron schedule active and working
- Probabilistic triggering averages 3/day
- Jitter applied correctly

✅ **Verifications pass consistently**
- >99% pass rate
- <1% false positives
- No false negatives

✅ **Independent verification works**
- CLI tool runs on multiple platforms
- Produces same results as CI workflow
- User-friendly output

✅ **Evidence is public and accessible**
- Job summaries visible in GitHub UI
- Artifacts downloadable
- Logs readable and complete

---

### User Trust Success

✅ **Security researchers endorse system**
- No major flaws discovered in audits
- Positive reviews from crypto community
- Trust in self-attestation model

✅ **Users understand verification**
- User guide is clear
- Settings page is informative
- Verification concept makes sense

✅ **Community participates**
- Independent verifications run by community
- Results shared publicly
- No discrepancies found

✅ **No verification failures**
- If failure occurs, investigated immediately
- Cause identified and documented
- Fix deployed and verified

---

### Business Success

✅ **Differentiation from competitors**
- Only KMS with continuous self-attestation
- Marketing point for security-conscious users
- Builds brand trust

✅ **User confidence increases**
- Survey results show higher trust
- User retention improves
- Security concerns decrease

✅ **Operational overhead is manageable**
- Verification runs automatically
- No manual intervention needed
- Monitoring alerts work correctly

✅ **Cost is acceptable**
- GitHub Actions usage within budget
- CDN costs minimal
- No significant overhead

---

## Related Documentation

- [README](./README.md) - High-level overview
- [Current State](./current-state.md) - What exists today (Phase 0)
- [Design](./design.md) - Detailed technical design
- [Plan](./plan.md) - Implementation roadmap and timeline

---

## Appendix: Example Verification Run

**URL:** `https://github.com/Lukium/ats-kms-enclave/actions/runs/1234567890`

**Status:** ✅ Passed

**Triggered by:** Random cadence (12% probability, +17min jitter)

**Duration:** 3m 42s

**Job Summary:**

```markdown
# KMS Verification Report

**Status:** ✅ PASS

**Verification Details:**
- **Timestamp:** 2025-10-23 14:23:42 UTC
- **Verifier Commit:** [`abc123d`](https://github.com/Lukium/ats-kms-enclave/tree/abc123d)
- **Release Tag:** `v1.0.1`
- **Workflow Run:** [#1234](https://github.com/Lukium/ats-kms-enclave/actions/runs/1234567890)

## Hash Comparison

| Hash Type | Local Build | Live Artifact | Match |
|-----------|-------------|---------------|-------|
| **SHA-256** | `7f8a9b0c3d4e5f6a...` | `7f8a9b0c3d4e5f6a...` | ✅ |
| **SRI** | `sha256-f4OxZX/x/FO...` | `sha256-f4OxZX/x/FO...` | ✅ |
| **Size** | 123456 bytes | 123456 bytes | ✅ |

## Sigstore Verification

- **Signature:** ✅ Valid
- **Rekor Entry:** [`12345678`](https://rekor.sigstore.dev/api/v1/log/entries/12345678)
- **Certificate:** Verified with GitHub Actions OIDC
- **Identity:** `https://github.com/Lukium/ats-kms-enclave/.github/workflows/release.yml@refs/tags/v1.0.1`

## Artifacts

- Local build: `kms-v1.0.1-7f8a9b0c.mjs`
- Live URL: https://kms.ats.run/kms.mjs

---

**Verifier code:** [View at commit `abc123d`](https://github.com/Lukium/ats-kms-enclave/tree/abc123d)

**How to verify independently:**
```bash
git clone https://github.com/Lukium/ats-kms-enclave.git
cd ats-kms-enclave
node tools/verify-kms.js --release v1.0.1
```
```

**Artifacts:**
1. `verification-report.json` (2.1 KB)
2. `build-artifacts/kms-v1.0.1-7f8a9b0c.mjs` (123 KB)
3. `build-artifacts/live-kms.mjs` (123 KB)
4. `build-artifacts/kms-v1.0.1-7f8a9b0c.mjs.bundle` (9.8 KB)

**Logs excerpt:**
```
Run: pnpm build:reproducible
✅ Build complete: kms-v1.0.1-7f8a9b0c.mjs

Run: sha256sum kms-v1.0.1-7f8a9b0c.mjs
7f8a9b0c3d4e5f6a7b8c9d0e1f2a3b4c... kms-v1.0.1-7f8a9b0c.mjs

Run: curl -fsSL https://kms.ats.run/kms.mjs -o live-kms.mjs
[downloaded 123456 bytes]

Run: sha256sum live-kms.mjs
7f8a9b0c3d4e5f6a7b8c9d0e1f2a3b4c... live-kms.mjs

✅ SHA-256 hashes MATCH
✅ SRI hashes MATCH
✅ Sigstore verification PASSED
✅ VERIFICATION PASSED
```

This is what success looks like when the self-attestation system is fully operational.
