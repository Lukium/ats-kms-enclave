# Self-Attestation System

**Status:** Design Phase (not yet implemented)

## Overview

The self-attestation system is a **continuous, random, public verification mechanism** that proves the KMS enclave deployed at `kms.ats.run` matches the audited source code and hasn't been tampered with.

Instead of asking users to trust our build process, we provide **transparent, verifiable proof** that anyone can inspect.

## The Trust Problem

Users need to trust:
1. The KMS code we deploy matches the audited source
2. Our build process is reproducible and deterministic
3. We haven't backdoored the deployed artifact
4. The artifact hasn't been modified after release

**Traditional approach:** "Trust us, we're careful"
**Our approach:** "Don't trust, verify—here's the public evidence"

## How It Works

### 1. Random Verification Schedule (~3x/day)

- GitHub Actions runs **every hour** via cron
- Probabilistic thinning: only executes ~3 times per day
- **Random timing** (up to 30min jitter) prevents gaming
- We can't predict when verification will run

### 2. Public Verifier Workflow

When selected, the verifier:
1. **Checks out a pinned commit** of verifier code (tamper-evident)
2. **Rebuilds the KMS** from the released tag (deterministic build)
3. **Fetches live artifact** from `https://kms.ats.run`
4. **Compares hashes** (SHA-256 + SRI)
5. **Verifies Sigstore bundle** (transparency log proof)
6. **Publishes results** to workflow run (public, permanent)

### 3. Public Evidence

Everything is visible in GitHub Actions:
- **Workflow run logs** - every command executed
- **Job summary** - pass/fail with hash comparison table
- **Artifacts** - full verification report, hashes, Sigstore bundles
- **Commit SHA** - exact verifier code used (auditable)

### 4. Tamper Resistance

- **Pinned Action SHAs** - no tag/version swapping
- **Protected branches** - verifier code requires reviews
- **OIDC attestations** - cryptographically bound to workflow identity
- **Commit-bound evidence** - verification tied to exact commit

## What Users See

Anyone can visit our Actions page and see:

```
✅ KMS Verification (Run #1234) - 2025-10-23 14:23 UTC
   Verifier commit: abc123def
   Released tag: v1.2.0

   Hash Comparison:
   Local build:  sha256-Jmn8pQ7...
   Live artifact: sha256-Jmn8pQ7... ✅ MATCH

   Sigstore: ✅ Verified in Rekor transparency log

   Result: ✅ PASS
```

They can:
1. **Inspect the verifier code** at commit `abc123def`
2. **See the workflow definition** (no hidden steps)
3. **Verify runs happen randomly** (unpredictable timing)
4. **Check the hash comparison** (exact match proof)
5. **Verify Sigstore signature** (external transparency log)

## Trust Model

### What You Must Trust

1. **GitHub Actions infrastructure** - execution environment
2. **GitHub's audit logs** - run records aren't falsified
3. **Sigstore/Rekor** - transparency log (optional, adds defense in depth)

### What You DON'T Need to Trust

1. ❌ **ATS developers** - code is auditable, runs are automatic
2. ❌ **Our build server** - verification rebuilds from source
3. ❌ **Our CDN** - we fetch from it and verify hashes
4. ❌ **Our honesty** - the math proves correctness

## Key Benefits

1. **Continuous verification** - not just at release, but ongoing
2. **Random timing** - can't prepare a "good" artifact before checks
3. **Public evidence** - anyone can audit the results
4. **Zero trust** - cryptographic proof, not promises
5. **Tamper-evident** - any modification breaks the chain

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     GitHub Actions                          │
│                                                             │
│  ┌──────────────────┐          ┌────────────────────────┐ │
│  │ Random Cadence   │          │   KMS Verifier         │ │
│  │ (hourly cron)    │─trigger→ │   (reproducible build) │ │
│  │                  │          │                        │ │
│  │ • Probabilistic  │          │ 1. Checkout v1.2.0     │ │
│  │   thinning (~3/d)│          │ 2. Build deterministic │ │
│  │ • Random jitter  │          │ 3. Compute SHA + SRI   │ │
│  │ • Public trigger │          │ 4. Fetch live artifact │ │
│  └──────────────────┘          │ 5. Compare hashes      │ │
│                                │ 6. Verify Sigstore     │ │
│                                │ 7. Publish evidence    │ │
│                                └────────────────────────┘ │
│                                           │                │
│                                           ▼                │
│                                ┌─────────────────────┐    │
│                                │ Public Evidence      │    │
│                                │                      │    │
│                                │ • Workflow logs      │    │
│                                │ • Job summary        │    │
│                                │ • Artifacts          │    │
│                                │ • Commit SHA         │    │
│                                └─────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
                              ┌──────────────────────────┐
                              │  External Verification   │
                              │                          │
                              │  • Sigstore/Rekor        │
                              │  • Certificate Trans.    │
                              │  • (future) Blockchain   │
                              └──────────────────────────┘
```

## Example Workflow Run

```yaml
Workflow: KMS Verifier
Run #1234
Started: 2025-10-23 14:23:42 UTC
Trigger: Random cadence
Commit: abc123def456 (verifier code)

Steps:
  ✅ Checkout verifier @ abc123def
  ✅ Setup Node 20.11.1
  ✅ Install dependencies (frozen lockfile)
  ✅ Checkout KMS release v1.2.0
  ✅ Build reproducibly (esbuild 0.19.11, SOURCE_DATE_EPOCH=1698765432)
  ✅ Compute hashes
     - Local:  sha256-Jmn8pQ7YQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5f
     - Remote: sha256-Jmn8pQ7YQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5f
     - Match: ✅
  ✅ Verify Sigstore bundle
     - Signature valid: ✅
     - Rekor entry: 12345678 (verified)
     - Certificate: CN=kms.ats.run (valid)
  ✅ Publish summary

Result: ✅ VERIFICATION PASSED

Artifacts:
  - verifier.json (full report)
  - dist/kms-*.mjs (reproducible build)
  - cosign.bundle (Sigstore proof)
```

## Security Properties

### Randomness

- **Poisson process** - `λ=3/day`, checked hourly
- **Jitter** - up to 30min random delay
- **Unpredictable** - we can't know when it runs
- **Prevents gaming** - can't prepare a "good" artifact

### Tamper Evidence

- **Pinned Actions** - all GitHub Actions use commit SHAs
- **Protected branches** - verifier code requires approval
- **Signed commits** - GPG/SSH signing required
- **OIDC binding** - attestations tied to workflow identity

### Reproducibility

- **Deterministic builds** - same input → same output
- **Pinned versions** - Node, pnpm, esbuild versions frozen
- **Timestamp normalization** - `SOURCE_DATE_EPOCH` set
- **Sorted inputs** - consistent file ordering

### Public Auditability

- **Open source verifier** - anyone can read the code
- **Public runs** - all workflow executions visible
- **Permanent logs** - GitHub retains for 90 days
- **Downloadable artifacts** - full evidence bundles

## Implementation Status

- [ ] Phase 1: Reproducible builds (deterministic artifacts)
- [ ] Phase 2: Sigstore integration (transparency logs)
- [ ] Phase 3: Random cadence workflow (probabilistic scheduling)
- [ ] Phase 4: Verifier implementation (comparison logic)
- [ ] Phase 5: Public evidence UI (user-facing display)
- [ ] Phase 6: Attestation publishing (OIDC-bound proofs)

## Related Documentation

- [Current State](./current-state.md) - What exists today
- [Design](./design.md) - Detailed technical design
- [Target State](./target-state.md) - Ideal end state
- [Plan](./plan.md) - Implementation roadmap

## References

- [Reproducible Builds](https://reproducible-builds.org/)
- [Sigstore](https://www.sigstore.dev/)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Certificate Transparency](https://certificate.transparency.dev/)
