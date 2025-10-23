# Self-Attestation: Current State

**As of:** Phase 0 completion (commit 8f3387a)
**Status:** Not yet implemented

## What Exists Today

### Phase 0 Baseline

Currently, the KMS enclave has:

✅ **Reproducible build foundation**
- Deterministic esbuild configuration planned (Phase 2)
- Content-addressed filenames design documented
- SRI hash computation design ready

✅ **Testing infrastructure**
- 100% test coverage enforced
- CI runs on every commit
- Tests pass on Node 18.x and 20.x

✅ **Demo verification**
- Interactive demo shows crypto correctness
- Visual proofs of byte counts, formats, algorithms
- Educational explanations for each check

### What's Missing

❌ **No self-attestation system**
- No random verification workflow
- No reproducible build artifacts
- No Sigstore integration
- No public verification evidence

❌ **No deterministic builds**
- Build script creates placeholder only
- No content-addressed filenames yet
- No SRI hash computation
- No timestamp normalization

❌ **No transparency logs**
- No Sigstore/cosign integration
- No Rekor transparency log entries
- No certificate transparency

❌ **No verification infrastructure**
- No verifier script
- No live artifact fetching
- No hash comparison logic
- No public evidence publishing

## Current Verification Process

**Today:**
1. User reads source code
2. User trusts our build process
3. User trusts deployed artifact matches source
4. User trusts we didn't backdoor it

**Problem:** Requires trusting ATS developers

## What Users Can't Verify Today

Users have no way to:

- ❌ Verify deployed artifact matches audited source
- ❌ Check if artifact was modified after release
- ❌ See independent verification evidence
- ❌ Audit the build process reproducibility
- ❌ Confirm Sigstore transparency log entries

## CI Status

Current CI (`.github/workflows/ci.yml`):

```yaml
jobs:
  test:
    - Run tests with coverage (enforces 100%)
    - Upload coverage to Codecov

  lint:
    - Run ESLint

  typecheck:
    - Run TypeScript compiler

  build:
    - Run build script (creates placeholder)
    - Upload build artifacts (placeholder only)

  reproducible-build:
    - Not yet implemented
    - Placeholder job exists but does nothing
```

**Gap:** No verification workflow at all

## Repository Structure

```
ats-kms/
├── .github/workflows/
│   ├── ci.yml                    # ✅ Exists (test/lint/typecheck)
│   ├── random-cadence.yml        # ❌ Missing (Phase 3)
│   └── kms-verify.yml            # ❌ Missing (Phase 4)
├── tools/
│   ├── verify-kms.js             # ❌ Missing (Phase 4)
│   └── release/                  # ❌ Missing (Phase 2)
│       ├── sign.sh               # Sigstore signing
│       └── publish.sh            # Transparency log
├── build/
│   └── esbuild.js                # ✅ Exists (placeholder only)
└── docs/architecture/
    └── self-attestation/         # ✅ New (design docs)
```

## Dependencies Status

### Installed

✅ **Build tools:**
- `esbuild@0.19.11` - bundler (used for demo, not production yet)
- `vite@7.1.12` - dev server (demo only)
- `typescript@5.3.3` - type checking

✅ **Testing:**
- `vitest@1.1.1` - test runner
- `@vitest/coverage-v8@1.1.1` - coverage
- `happy-dom@12.10.3` - DOM simulation

### Missing

❌ **Signing/verification:**
- `cosign` - Sigstore signing tool (will use CLI, not npm)
- `rekor-cli` - Rekor transparency log CLI (optional)

❌ **Build reproducibility:**
- Deterministic esbuild config (code exists, not used)
- SHA-256 hashing utilities (native crypto.subtle)
- SRI computation (will implement in Phase 2)

## Blockers for Self-Attestation

### Must Complete First

1. **Phase 1: Reproducible Builds**
   - Implement deterministic esbuild configuration
   - Add content-addressed filenames
   - Compute SRI hashes
   - Verify byte-for-byte reproducibility

2. **Phase 2: Sigstore Integration**
   - Install cosign CLI
   - Implement signing workflow
   - Publish to Rekor transparency log
   - Store bundles as release assets

### Then Can Implement

3. **Phase 3: Random Cadence**
   - Create `random-cadence.yml` workflow
   - Implement probabilistic thinning
   - Add random jitter
   - Test trigger mechanism

4. **Phase 4: Verifier**
   - Implement `tools/verify-kms.js`
   - Add reproducible rebuild logic
   - Fetch live artifact
   - Compare hashes
   - Verify Sigstore bundle
   - Publish evidence

## Timeline

```
Current: Phase 0 (In-memory prototype)
  │
  ├─ No self-attestation
  ├─ Placeholder build script
  └─ Design docs written

Next: Phase 1 (Basic enclave)
  │
  ├─ Production-ready enclave code
  ├─ IndexedDB storage
  └─ Still no self-attestation

Then: Phase 2 (Verifiable builds)
  │
  ├─ Deterministic builds ← REQUIRED
  ├─ Content-addressed artifacts
  ├─ SRI hashes
  └─ Reproducibility verified

Then: Phase 3 (Transparency)
  │
  ├─ Sigstore integration ← REQUIRED
  ├─ Rekor transparency log
  └─ Release process with signing

Finally: Phase 4-6 (Self-attestation)
  │
  ├─ Random cadence workflow
  ├─ Verifier implementation
  ├─ Public evidence
  └─ User-facing UI
```

## Next Steps

To enable self-attestation:

1. **Merge Phase 0 changes** (current PR)
2. **Complete Phase 1** (production enclave with IndexedDB)
3. **Implement Phase 2** (reproducible builds)
4. **Implement Phase 3** (Sigstore/Rekor)
5. **Build self-attestation** (Phase 4+)

Estimated timeline: Phase 2-3 prerequisite work = 2-3 weeks, then self-attestation implementation = 1 week.

## Resources Needed

### Infrastructure

- ✅ GitHub Actions (already using)
- ✅ GitHub Pages or CDN (for hosting)
- ❌ Sigstore account (free, OIDC-based)
- ❌ Rekor transparency log (free, public)

### Skills

- ✅ TypeScript/JavaScript
- ✅ GitHub Actions workflows
- ✅ Cryptographic concepts
- ❌ Sigstore/cosign expertise (can learn)
- ❌ Reproducible builds expertise (can learn)

### Time

- Reproducible builds: ~1 week
- Sigstore integration: ~3 days
- Random cadence workflow: ~1 day
- Verifier implementation: ~3 days
- Documentation and testing: ~2 days

**Total: ~2-3 weeks** for full self-attestation

## Summary

**Current state:** No self-attestation exists. We have design docs and a placeholder build script, but users must trust our build process.

**Blockers:** Need reproducible builds (Phase 2) and Sigstore integration (Phase 3) before self-attestation can work.

**Path forward:** Complete Phase 1-3 prerequisite work, then implement random cadence verification workflow with public evidence publishing.
