# Self-Attestation: Implementation Plan

**Status:** Design Phase (not yet started)

## Overview

This document outlines the phased implementation plan for the self-attestation system. The system cannot be implemented immediately - it requires prerequisite work on reproducible builds and Sigstore integration.

## Prerequisites

Self-attestation **requires** these foundation pieces to work:

1. **Reproducible builds** (Phase 2) - Without deterministic builds, verification is meaningless
2. **Sigstore integration** (Phase 3) - Provides external transparency log proof
3. **Content-addressed artifacts** (Phase 2) - Hash-based filenames for immutability

**Current status:** Phase 0 (in-memory prototype). Prerequisites are Phase 2-3.

## Implementation Phases

### Phase 1: Production Enclave (Not Self-Attestation)

**Timeline:** 1-2 weeks
**Dependencies:** Phase 0 complete
**Blockers:** None

**Scope:**
- Production-ready KMS enclave code (~500 lines)
- IndexedDB storage for non-extractable keys
- VAPID keypair generation and JWT signing
- PostMessage RPC protocol
- Comprehensive test coverage

**Deliverables:**
- `src/main.ts` - Enclave main thread
- `src/worker.ts` - Dedicated Worker with crypto operations
- `src/storage.ts` - IndexedDB key storage
- `public/kms.html` - Iframe bootstrap
- Tests with 100% coverage

**NOT included:**
- Self-attestation (prerequisites not met)
- Verifiable builds (comes in Phase 2)
- Sigstore (comes in Phase 3)

---

### Phase 2: Reproducible Builds (Self-Attestation Prerequisite)

**Timeline:** 1 week
**Dependencies:** Phase 1 complete
**Blockers:** None

**Scope:**
- Deterministic esbuild configuration
- Content-addressed artifact filenames
- SRI hash computation
- Build reproducibility verification
- Documentation

**Deliverables:**

1. **Deterministic build script** (`build/esbuild.js`)
   - Fixed esbuild version (pinned in lockfile)
   - Deterministic plugin ordering
   - Consistent source map generation
   - Timestamp normalization via `SOURCE_DATE_EPOCH`

2. **Content addressing** (`build/content-address.ts`)
   - Compute SHA-256 hash of artifact
   - Generate filename: `kms-v{version}-{hash}.mjs`
   - Update `kms.html` with hashed filename
   - Compute SRI hash for `<script integrity="...">`

3. **Build script** (`pnpm build:reproducible`)
   ```bash
   # Set deterministic timestamp
   export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

   # Build with frozen versions
   pnpm install --frozen-lockfile
   node build/esbuild.js --reproducible

   # Generate content-addressed filename
   node build/content-address.ts

   # Output: dist/kms-v1.0.0-3a5b9f2e.mjs
   #         dist/kms.html (with SRI)
   ```

4. **Verification test**
   ```bash
   # Build twice, compare byte-for-byte
   pnpm build:reproducible
   mv dist/kms-*.mjs build1.mjs

   rm -rf dist node_modules
   pnpm install --frozen-lockfile
   pnpm build:reproducible
   mv dist/kms-*.mjs build2.mjs

   diff build1.mjs build2.mjs  # Should be identical
   ```

5. **CI job** (`.github/workflows/ci.yml`)
   ```yaml
   reproducible-build:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@<SHA>
       - uses: actions/setup-node@<SHA>
       - uses: pnpm/action-setup@<SHA>
       - run: pnpm install --frozen-lockfile
       - run: pnpm build:reproducible
       - uses: actions/upload-artifact@<SHA>
         with:
           name: kms-artifact
           path: dist/kms-*.mjs
   ```

**Acceptance Criteria:**
- [ ] Two independent builds produce identical artifacts (SHA-256 match)
- [ ] Content-addressed filenames include version and hash
- [ ] SRI hashes computed and embedded in `kms.html`
- [ ] CI uploads reproducible build artifacts
- [ ] Documentation explains build process

**Estimated Effort:** 3-5 days

---

### Phase 3: Sigstore Integration (Self-Attestation Prerequisite)

**Timeline:** 3-4 days
**Dependencies:** Phase 2 complete (reproducible builds)
**Blockers:** None

**Scope:**
- Sign artifacts with Sigstore/cosign
- Publish to Rekor transparency log
- Attach bundles to GitHub releases
- Document verification process

**Deliverables:**

1. **Release workflow** (`.github/workflows/release.yml`)
   ```yaml
   name: Release

   on:
     push:
       tags:
         - 'v*'

   permissions:
     contents: write
     id-token: write  # Required for Sigstore OIDC

   jobs:
     release:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@<SHA>
         - uses: actions/setup-node@<SHA>
         - uses: pnpm/action-setup@<SHA>

         # Build reproducibly
         - run: pnpm install --frozen-lockfile
         - run: pnpm build:reproducible

         # Install cosign
         - uses: sigstore/cosign-installer@<SHA>

         # Sign artifact
         - name: Sign with Sigstore
           env:
             COSIGN_EXPERIMENTAL: 1
           run: |
             ARTIFACT=$(ls dist/kms-*.mjs)

             # Sign and create bundle
             cosign sign-blob \
               --bundle ${ARTIFACT}.bundle \
               --yes \
               ${ARTIFACT}

             # Verify it worked
             cosign verify-blob \
               --bundle ${ARTIFACT}.bundle \
               --certificate-identity-regexp "^https://github.com/${{ github.repository }}/" \
               --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
               ${ARTIFACT}

         # Create GitHub release
         - name: Create release
           env:
             GH_TOKEN: ${{ github.token }}
           run: |
             ARTIFACT=$(ls dist/kms-*.mjs)

             gh release create ${{ github.ref_name }} \
               --title "Release ${{ github.ref_name }}" \
               --notes "Reproducible build with Sigstore attestation" \
               ${ARTIFACT} \
               ${ARTIFACT}.bundle
   ```

2. **Verification documentation** (`docs/verification.md`)
   - How to verify Sigstore signatures
   - How to check Rekor transparency log
   - Example verification commands
   - Expected output

3. **Test release**
   - Tag `v0.1.0-alpha` for testing
   - Verify signing works
   - Check Rekor entry
   - Download and verify bundle

**Acceptance Criteria:**
- [ ] Artifacts signed with GitHub Actions OIDC identity
- [ ] Sigstore bundles attached to releases
- [ ] Rekor transparency log entries created
- [ ] Manual verification works with cosign
- [ ] Documentation explains verification process

**Estimated Effort:** 2-3 days

---

### Phase 4: Random Cadence Workflow (First Self-Attestation Component)

**Timeline:** 1 day
**Dependencies:** Phase 2-3 complete (reproducible builds + Sigstore)
**Blockers:** None

**Scope:**
- Create workflow that triggers verification randomly
- Implement probabilistic scheduling
- Add random jitter
- Test triggering mechanism

**Deliverables:**

1. **Random cadence workflow** (`.github/workflows/random-cadence.yml`)
   - See [design.md](./design.md#workflow-1-random-cadence-trigger) for full implementation
   - Runs hourly via cron
   - 12% probability per check (~3x per day)
   - 0-30 minute random jitter
   - Triggers `kms-verify.yml` via `workflow_dispatch`

2. **Testing**
   ```bash
   # Manual trigger to test
   gh workflow run random-cadence.yml

   # Check job summary shows decision
   gh run view --log

   # Should see either:
   # "✅ TRIGGER (random=8 < 12)" → verification triggered
   # "⏭️ SKIP (random=67 >= 12)" → skipped this hour
   ```

3. **Enable cron schedule**
   - Initially: manual testing only
   - After validation: enable `schedule: cron: '0 * * * *'`

**Acceptance Criteria:**
- [ ] Workflow runs hourly via cron
- [ ] Probabilistic triggering works (test with manual runs)
- [ ] Jitter adds 0-30 minutes delay
- [ ] `workflow_dispatch` successfully triggers verifier
- [ ] Job summary logs decision and random numbers

**Estimated Effort:** 1 day (mostly testing)

---

### Phase 5: KMS Verifier Workflow (Core Self-Attestation)

**Timeline:** 3 days
**Dependencies:** Phase 2-4 complete
**Blockers:** Must have at least one release with Sigstore bundle

**Scope:**
- Implement complete verification workflow
- Reproducible rebuild from source
- Live artifact fetching
- Hash comparison
- Sigstore verification
- Public evidence publishing

**Deliverables:**

1. **Verifier workflow** (`.github/workflows/kms-verify.yml`)
   - See [design.md](./design.md#workflow-2-kms-verifier) for full implementation
   - Rebuilds KMS from tagged release
   - Fetches live artifact from production URL
   - Compares SHA-256 and SRI hashes
   - Verifies Sigstore bundle
   - Publishes job summary and artifacts

2. **Evidence artifacts**
   - `verification-report.json` - Structured verification results
   - `dist/kms-*.mjs` - Reproducible build output
   - `live-kms.mjs` - Downloaded live artifact
   - `kms-*.mjs.bundle` - Sigstore bundle

3. **Job summary template**
   - Markdown table with hash comparison
   - Links to Rekor transparency log
   - Links to verifier code commit
   - Pass/fail indicators

4. **Testing**
   ```bash
   # Trigger manually against known-good release
   gh workflow run kms-verify.yml

   # Check output
   gh run view --log

   # Download artifacts
   gh run download <run-id>

   # Verify report
   cat verification-report.json | jq .
   ```

**Acceptance Criteria:**
- [ ] Workflow rebuilds artifact reproducibly
- [ ] Hash comparison correctly identifies matches/mismatches
- [ ] Sigstore verification checks Rekor log
- [ ] Job summary displays all evidence
- [ ] Artifacts uploaded and downloadable
- [ ] Workflow fails if hashes don't match

**Estimated Effort:** 2-3 days

---

### Phase 6: Verifier CLI Tool (Independent Verification)

**Timeline:** 3 days
**Dependencies:** Phase 5 complete (verifier workflow working)
**Blockers:** None

**Scope:**
- Standalone tool for manual verification
- Can be run by anyone, anywhere
- No GitHub Actions required
- Reproduces same checks as CI

**Deliverables:**

1. **Verifier script** (`tools/verify-kms.js`)
   - See [design.md](./design.md#verifier-script-architecture) for full implementation
   - Clones release from GitHub
   - Builds reproducibly
   - Fetches live artifact
   - Compares hashes
   - Verifies Sigstore bundle

2. **Usage documentation** (`docs/verification.md`)
   ```markdown
   # Manual Verification

   Anyone can verify KMS artifacts independently:

   ## Prerequisites

   - Node.js 20.11.1+
   - pnpm 8.15.0+
   - cosign (Sigstore CLI)
   - Git

   ## Run Verifier

   ```bash
   # Verify latest release
   node tools/verify-kms.js

   # Verify specific release
   node tools/verify-kms.js --release v1.0.0

   # Verbose output
   node tools/verify-kms.js --verbose
   ```

   ## Expected Output

   ```
   🔐 ATS KMS Verifier

   📦 Verifying release: v1.0.0

   ℹ️  Building KMS v1.0.0 from source...
   ℹ️  Fetching live artifact from https://kms.ats.run/kms.mjs...
   ℹ️  Comparing hashes...

   Hash Comparison:
   ─────────────────────────────────────
   SHA-256:
     Local: 3a5b9f2e...
     Live:  3a5b9f2e...
     ✅ MATCH

   SRI:
     Local: sha256-OlvH...nLs=
     Live:  sha256-OlvH...nLs=
     ✅ MATCH

   Size:
     Local: 123456 bytes
     Live:  123456 bytes
     ✅ MATCH
   ─────────────────────────────────────

   ℹ️  Verifying Sigstore bundle...
   ✅ Sigstore verification passed

   ✅ VERIFICATION PASSED
   ℹ️  Deployed artifact matches audited source code
   ```
   ```

3. **Testing**
   ```bash
   # Test against known-good release
   node tools/verify-kms.js --release v1.0.0

   # Test against tampered artifact (should fail)
   # Modify live artifact, run verifier, expect failure
   ```

**Acceptance Criteria:**
- [ ] Tool runs on Linux, macOS, Windows
- [ ] Clones and builds release successfully
- [ ] Fetches live artifact
- [ ] Computes and compares hashes correctly
- [ ] Verifies Sigstore bundle
- [ ] Clear pass/fail output
- [ ] Helpful error messages

**Estimated Effort:** 2-3 days

---

### Phase 7: Documentation and Rollout

**Timeline:** 2 days
**Dependencies:** Phase 4-6 complete (all workflows working)
**Blockers:** None

**Scope:**
- User-facing documentation
- Announcement and education
- Monitoring and refinement

**Deliverables:**

1. **README badge**
   ```markdown
   # ATS KMS Enclave

   [![Verification Status](https://github.com/Lukium/ats-kms-enclave/actions/workflows/kms-verify.yml/badge.svg)](https://github.com/Lukium/ats-kms-enclave/actions/workflows/kms-verify.yml)

   **Self-Attestation:** This repository uses [continuous random verification](docs/architecture/self-attestation/README.md) to prove deployed artifacts match audited source code.
   ```

2. **User guide** (`docs/verification-guide.md`)
   - What self-attestation is
   - Why it matters
   - How to interpret verification runs
   - How to run manual verification
   - What to do if verification fails

3. **Announcement**
   - Blog post or GitHub discussion
   - Explain self-attestation system
   - Invite community to audit verifier code
   - Encourage independent verification

4. **Monitoring**
   - Check first ~10 verification runs
   - Ensure they pass consistently
   - Fix any issues discovered
   - Adjust verification frequency if needed

**Acceptance Criteria:**
- [ ] README updated with verification badge
- [ ] User guide published
- [ ] Announcement posted
- [ ] First 10 verification runs pass
- [ ] No false positives or negatives

**Estimated Effort:** 1-2 days

---

## Phase Dependencies

```
Phase 0: Prototype (DONE)
    │
    ├─→ Phase 1: Production Enclave (1-2 weeks)
    │       │
    │       └─→ Phase 2: Reproducible Builds (1 week) ← PREREQUISITE
    │               │
    │               └─→ Phase 3: Sigstore (3-4 days) ← PREREQUISITE
    │                       │
    │                       ├─→ Phase 4: Random Cadence (1 day)
    │                       │       │
    │                       │       └─→ Phase 5: Verifier Workflow (3 days)
    │                       │               │
    │                       │               └─→ Phase 6: Verifier CLI (3 days)
    │                       │                       │
    │                       │                       └─→ Phase 7: Rollout (2 days)
    │                       │
    │                       └─→ [Can start Phase 4-7 in parallel after Phase 3]
```

**Critical Path:**
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6 → Phase 7

**Total Timeline:**
- Phase 1: 1-2 weeks
- Phase 2: 1 week
- Phase 3: 3-4 days
- Phase 4-6: Can be done in parallel (~1 week total)
- Phase 7: 2 days

**Estimated Total: 4-5 weeks from Phase 0 completion to full self-attestation rollout**

## Timeline Estimates

### Optimistic (Everything Goes Smoothly)

| Phase | Duration | Start | End |
|-------|----------|-------|-----|
| Phase 1 | 1 week | Week 1 | Week 1 |
| Phase 2 | 5 days | Week 2 | Week 2 |
| Phase 3 | 3 days | Week 3 | Week 3 |
| Phase 4 | 1 day | Week 3 | Week 3 |
| Phase 5 | 2 days | Week 3 | Week 3 |
| Phase 6 | 2 days | Week 4 | Week 4 |
| Phase 7 | 1 day | Week 4 | Week 4 |

**Total: 4 weeks**

### Realistic (Some Debugging, Documentation Time)

| Phase | Duration | Start | End |
|-------|----------|-------|-----|
| Phase 1 | 2 weeks | Week 1 | Week 2 |
| Phase 2 | 1 week | Week 3 | Week 3 |
| Phase 3 | 4 days | Week 4 | Week 4 |
| Phase 4 | 1 day | Week 4 | Week 4 |
| Phase 5 | 3 days | Week 5 | Week 5 |
| Phase 6 | 3 days | Week 5 | Week 5 |
| Phase 7 | 2 days | Week 5 | Week 5 |

**Total: 5 weeks**

### Pessimistic (Multiple Issues, Learning Curve)

| Phase | Duration | Start | End |
|-------|----------|-------|-----|
| Phase 1 | 3 weeks | Week 1 | Week 3 |
| Phase 2 | 1.5 weeks | Week 4 | Week 5 |
| Phase 3 | 1 week | Week 6 | Week 6 |
| Phase 4 | 2 days | Week 7 | Week 7 |
| Phase 5 | 1 week | Week 7 | Week 7 |
| Phase 6 | 1 week | Week 8 | Week 8 |
| Phase 7 | 3 days | Week 8 | Week 8 |

**Total: 8 weeks**

## Resource Requirements

### Infrastructure

**Required:**
- ✅ GitHub repository (already have)
- ✅ GitHub Actions (already using)
- ❌ GitHub Pages or CDN for hosting KMS artifact (need to set up)
- ❌ Sigstore account (free, automatic via GitHub OIDC)

**Optional:**
- Codecov (already using for test coverage)
- Dependabot (for dependency updates)

### Tools and Dependencies

**Development:**
- ✅ Node.js 20.11.1
- ✅ pnpm 8.15.0
- ✅ esbuild 0.19.11
- ✅ TypeScript 5.3.3

**New dependencies needed:**
- ❌ cosign (Sigstore CLI) - installed in CI only
- ❌ rekor-cli (optional) - for manual transparency log queries

**All code-level dependencies already in place** - no new npm packages needed.

### Skills and Knowledge

**Already have:**
- ✅ TypeScript/JavaScript
- ✅ GitHub Actions workflows
- ✅ Cryptographic concepts
- ✅ Testing and CI/CD

**Need to learn:**
- ❌ Reproducible builds (deterministic compilation)
- ❌ Sigstore/cosign (keyless signing)
- ❌ Rekor transparency log (how it works)
- ❌ Content addressing (hash-based filenames)

**Learning resources:**
- [Reproducible Builds Documentation](https://reproducible-builds.org/)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Cosign GitHub Actions](https://github.com/sigstore/cosign-installer)
- [esbuild Determinism Guide](https://esbuild.github.io/)

### Time Investment

**Development time (writing code):**
- Phase 1: 40-80 hours
- Phase 2: 24-32 hours
- Phase 3: 16-24 hours
- Phase 4: 8 hours
- Phase 5: 16-24 hours
- Phase 6: 16-24 hours
- Phase 7: 8-16 hours

**Total development: 128-208 hours (16-26 days)**

**Documentation time:**
- Architecture docs (already done): 8 hours
- User-facing docs: 8-12 hours
- Code comments and inline docs: 4-8 hours

**Total documentation: 20-28 hours (2.5-3.5 days)**

**Testing and debugging:**
- Unit tests: 24-32 hours
- Integration tests: 16-24 hours
- E2E verification tests: 8-16 hours
- Debugging issues: 16-32 hours

**Total testing: 64-104 hours (8-13 days)**

**Grand total: 212-340 hours (27-42 days of work)**

With a single developer working full-time (8 hours/day), this is **5-8 weeks of calendar time**.

## Risk Assessment

### Risk 1: Reproducible Builds Not Truly Deterministic

**Likelihood:** Medium
**Impact:** Critical (verification will fail randomly)

**Causes:**
- esbuild non-determinism
- Dependency version drift
- System-dependent paths in bundle
- Timestamp leakage

**Mitigation:**
- Test reproducibility extensively in Phase 2
- Use fixed `SOURCE_DATE_EPOCH`
- Pin all dependency versions
- Test on multiple machines/OSes
- Document any known sources of non-determinism

**Contingency:**
- If cannot achieve byte-for-byte reproducibility, document differences
- Compare logical equivalence (AST) instead of byte matching
- Use fuzzy hash comparison (ssdeep) for near-matches

---

### Risk 2: Sigstore/Rekor Availability Issues

**Likelihood:** Low
**Impact:** Medium (verification blocked but not broken)

**Causes:**
- Rekor transparency log downtime
- Sigstore CA issues
- Network connectivity problems

**Mitigation:**
- Cache Sigstore bundles in GitHub releases
- Verification can use cached bundles
- Rekor queries are optional (nice-to-have)
- Document fallback verification without Rekor

**Contingency:**
- If Sigstore is down, verification can still compare hashes
- Sigstore adds defense in depth, but hash comparison is primary

---

### Risk 3: GitHub Actions Rate Limits

**Likelihood:** Low
**Impact:** Low (just slows verification frequency)

**Causes:**
- Too many workflow runs
- API rate limits hit

**Mitigation:**
- Limit random cadence to ~3x/day (well below limits)
- Use `workflow_dispatch` instead of API calls
- Monitor workflow run counts

**Contingency:**
- Reduce verification frequency temporarily
- Add longer jitter delays
- Split workflows across multiple repos if needed

---

### Risk 4: False Positives (Verification Fails When It Shouldn't)

**Likelihood:** Medium (during initial rollout)
**Impact:** High (erodes trust in system)

**Causes:**
- Build non-determinism
- CDN caching issues
- Network errors fetching artifact
- Timezone/timestamp issues

**Mitigation:**
- Extensive testing before rollout (Phase 7)
- Manual verification runs first
- Monitor first 10+ automatic runs
- Add retry logic for network errors
- Document expected failure modes

**Contingency:**
- Disable automatic verification temporarily
- Fix underlying issue
- Re-enable with manual testing
- Add better error messages

---

### Risk 5: Verifier Code Malicious

**Likelihood:** Low (code review catches this)
**Impact:** Critical (undermines entire system)

**Causes:**
- Malicious PR merged
- Developer account compromised
- Supply chain attack on dependencies

**Mitigation:**
- Protected branches (require code review)
- Commit-bound evidence (auditors can check exact code)
- Minimal dependencies (small attack surface)
- Community audits of verifier code

**Contingency:**
- If discovered, publish incident report
- Roll back to last known-good verifier
- Increase review requirements
- Add GPG signing requirement for verifier changes

---

### Risk 6: Learning Curve for Reproducible Builds

**Likelihood:** High
**Impact:** Medium (delays Phase 2)

**Causes:**
- esbuild internals complex
- Reproducibility hard to debug
- Non-obvious sources of non-determinism

**Mitigation:**
- Allocate extra time for Phase 2 (1 week → 1.5 weeks)
- Study existing reproducible build projects
- Start with simple determinism tests
- Document findings for future maintainers

**Contingency:**
- If Phase 2 takes longer, delay subsequent phases
- Consider consulting reproducible builds community
- Use simpler bundler if esbuild too difficult (rollup, swc)

---

## Success Criteria

### Phase 2 Success (Reproducible Builds)

✅ **Two independent builds produce identical artifacts**
- Run build twice on same machine → SHA-256 match
- Run build on different machines → SHA-256 match
- Run build on different OSes → SHA-256 match

✅ **Content-addressed filenames work**
- Filename includes hash: `kms-v1.0.0-3a5b9f2e.mjs`
- Hash in filename matches actual file hash
- SRI hash computed and embedded in `kms.html`

✅ **CI produces reproducible artifacts**
- CI build matches local build
- Multiple CI runs produce identical artifacts

---

### Phase 3 Success (Sigstore)

✅ **Artifacts signed with GitHub Actions identity**
- Sigstore bundle created
- Certificate includes workflow path
- OIDC token validated

✅ **Rekor transparency log entry created**
- Entry visible at rekor.sigstore.dev
- Entry includes artifact hash
- Entry timestamp matches release

✅ **Manual verification works**
```bash
cosign verify-blob \
  --bundle kms-v1.0.0.mjs.bundle \
  --certificate-identity-regexp "..." \
  --certificate-oidc-issuer "..." \
  kms-v1.0.0.mjs
# Output: Verified OK
```

---

### Phase 4 Success (Random Cadence)

✅ **Workflow runs hourly**
- Cron schedule active
- Check job runs every hour
- Job summary shows decision

✅ **Probabilistic triggering works**
- Over 24 checks, ~3 trigger verification
- Random numbers logged
- Jitter applied (0-30 minutes)

✅ **Verifier workflow triggered**
- `workflow_dispatch` sent successfully
- Verifier workflow starts within jitter period

---

### Phase 5 Success (Verifier Workflow)

✅ **Reproducible rebuild works**
- Checks out tagged release
- Builds successfully
- Artifact filename matches expected pattern

✅ **Hash comparison accurate**
- SHA-256 computed correctly
- SRI computed correctly
- Comparison logic works

✅ **Job summary informative**
- Shows hash comparison table
- Links to Rekor entry
- Links to verifier code commit
- Clear pass/fail indicator

✅ **Verification fails when it should**
- Test with modified artifact → fails
- Test with wrong tag → fails
- Test with invalid Sigstore bundle → fails

---

### Phase 6 Success (Verifier CLI)

✅ **Tool runs on multiple platforms**
- Linux (Ubuntu, Debian)
- macOS (Intel and Apple Silicon)
- Windows (WSL)

✅ **Verification matches CI**
- Same release tag
- Same hash results
- Same pass/fail decision

✅ **User-friendly output**
- Clear progress indicators
- Readable hash comparison
- Helpful error messages

---

### Phase 7 Success (Rollout)

✅ **Documentation complete**
- README badge added
- User guide published
- Verification examples provided

✅ **First 10 runs pass**
- No false positives
- No false negatives
- Evidence published correctly

✅ **Community awareness**
- Announcement posted
- Feedback collected
- No major concerns raised

---

## Rollback Plan

If self-attestation causes issues:

### Immediate Rollback (Phase 4-7)

**Disable random cadence:**
```yaml
# .github/workflows/random-cadence.yml
on:
  # schedule:  # Commented out
  #   - cron: '0 * * * *'
  workflow_dispatch:  # Keep manual trigger for testing
```

**Impact:**
- Stops automatic verification
- Manual verification still available
- No code changes needed
- Can re-enable after fixing issue

### Partial Rollback (Phase 5-6)

**Keep reproducible builds and Sigstore (Phase 2-3)**
**Remove verification workflows (Phase 4-5)**

**Reason:**
- Reproducible builds still valuable
- Sigstore still provides transparency
- Just removes automatic verification
- Users can still verify manually

### Full Rollback (Phase 2-7)

**Remove all self-attestation components**

**Files to remove:**
- `.github/workflows/random-cadence.yml`
- `.github/workflows/kms-verify.yml`
- `tools/verify-kms.js`
- `docs/architecture/self-attestation/` (or mark as "Deprecated")

**Files to keep:**
- Reproducible build script (still useful)
- Sigstore signing (still useful)

**Reason:**
- Self-attestation fundamentally flawed or unnecessary
- Too complex to maintain
- False positives causing confusion

**Impact:**
- Back to traditional trust model (trust developers)
- Sigstore still provides some transparency
- Reproducible builds still allow manual verification

---

## Monitoring and Maintenance

### During Rollout (Phase 7)

**Monitor:**
- First 10 verification runs (watch for failures)
- Job execution time (should be <10 minutes)
- Artifact upload success rate
- User feedback (GitHub discussions, issues)

**Metrics to track:**
- Verification pass rate (target: >99%)
- Average run time (target: <10 minutes)
- False positive rate (target: 0%)
- False negative rate (target: 0%)

### Ongoing (Post-Rollout)

**Weekly checks:**
- Review failed verification runs (investigate causes)
- Check Rekor log entries (ensure publishing works)
- Monitor workflow run counts (ensure cron working)

**Monthly reviews:**
- Analyze verification frequency (should average ~90/month)
- Review verifier code for maintenance needs
- Update dependencies if needed
- Check for Sigstore/GitHub Actions changes

**Quarterly audits:**
- Community review of verifier code
- Security assessment of workflow
- Performance optimization
- Documentation updates

---

## Next Steps

1. **Complete Phase 0** (current work)
   - Merge Phase 0 demo PR
   - Document Phase 0 baseline

2. **Plan Phase 1** (production enclave)
   - Design IndexedDB schema
   - Plan component architecture
   - Write test plan

3. **Begin Phase 2** (reproducible builds)
   - Research esbuild determinism
   - Prototype content addressing
   - Test local reproducibility

4. **When Phase 2 complete, start Phase 3** (Sigstore)
   - Set up release workflow
   - Test signing locally
   - Create first signed release

5. **After Phase 3, begin Phase 4-6 in parallel**
   - Random cadence workflow
   - Verifier workflow
   - Verifier CLI tool

6. **Finish with Phase 7** (rollout)
   - Documentation
   - Announcement
   - Monitoring

**Estimated start date for self-attestation work:** 3-4 weeks from now (after Phase 1-2 complete)

**Estimated completion date:** 8-10 weeks from now (realistic timeline)

## Related Documentation

- [README](./README.md) - High-level overview
- [Current State](./current-state.md) - What exists today
- [Design](./design.md) - Detailed technical design
- [Target State](./target-state.md) - Ideal end state (to be written)
