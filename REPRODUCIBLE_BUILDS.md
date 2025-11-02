# Reproducible Build Verification

This document explains how to independently verify that the KMS enclave deployed at https://kms.ats.run matches the published source code.

## Quick Verification

```bash
# Clone the repository
git clone https://github.com/Lukium/ats-kms-enclave.git
cd ats-kms-enclave

# Checkout the specific commit you want to verify
git checkout <commit-hash>

# Use the correct Node.js version
nvm use 20

# Install dependencies with locked versions
pnpm install --frozen-lockfile

# Build reproducibly
pnpm build:reproducible

# Compute worker hash
sha256sum dist/kms-worker.*.js

# Compare with deployed hash at:
# https://kms.ats.run/.well-known/kms-manifest.json
```

## Build Environment

For reproducibility, use the exact same environment as CI:

- **Node.js:** 20.x (any patch version should work)
- **pnpm:** 8.x
- **OS:** Linux (Ubuntu recommended, but macOS/Windows should also work)
- **Dependencies:** Locked via `pnpm-lock.yaml`

## How Reproducibility Works

1. **SOURCE_DATE_EPOCH:** Automatically set from git commit timestamp
   - Same commit → same timestamp → deterministic build
   - See `package.json`: `build:reproducible`

2. **Locked Dependencies:** `pnpm-lock.yaml` ensures exact versions
   - npm/yarn may produce different lock files
   - Always use `pnpm install --frozen-lockfile`

3. **Content-Addressed Artifacts:** Filenames include SHA-256 hash
   - Example: `kms-worker.d5333940.js`
   - Hash is first 8 chars of full SHA-256

## Verification Process

### Step 1: Get Deployed Hash

```bash
curl -s https://kms.ats.run/.well-known/kms-manifest.json | jq -r '.current.sha256'
```

### Step 2: Build Locally

```bash
git checkout <commit-from-manifest>
pnpm install --frozen-lockfile
pnpm build:reproducible
sha256sum dist/kms-worker.*.js | cut -d' ' -f1
```

### Step 3: Compare

If the hashes match, you've verified:
- ✅ Deployed code matches source
- ✅ Build is deterministic
- ✅ No tampering in deployment pipeline

## CI/CD Pipeline

Official builds run in GitHub Actions:
- **Workflow:** `.github/workflows/deploy.yml`
- **Environment:** Ubuntu latest, Node 20.x, pnpm 8
- **Logs:** Publicly auditable at https://github.com/Lukium/ats-kms-enclave/actions

## Verification Reports

Automated verification runs 4 times per day:
- **Reports:** https://github.com/Lukium/ats-kms-enclave/tree/attestation
- **Verifier Code:** https://github.com/Lukium/ats-kms-enclave/tree/verifier
- **Badge:** ![Verification Status](https://github.com/Lukium/ats-kms-enclave/blob/attestation/verification-badge.svg)

## Troubleshooting

### Different Hash on First Build

**Symptom:** First local build produces different hash than deployed

**Likely Causes:**
1. Wrong git commit - verify with `git rev-parse HEAD`
2. Modified files - check `git status` for uncommitted changes
3. Different Node version - verify with `node --version`
4. Wrong pnpm version - verify with `pnpm --version`

### Different Hash on Rebuild

**Symptom:** Building twice locally produces different hashes

**This should never happen.** If it does:
1. Check for non-deterministic code (timestamps, random values, etc.)
2. Open an issue - reproducibility is critical

### CI Build Works, Local Build Fails

**Likely Causes:**
1. Platform-specific path separators (Windows vs Unix)
2. File encoding differences (CRLF vs LF)
3. Missing build dependencies

## Security Considerations

**Trust Model:**

You must trust:
- ✅ Git commit hashes (SHA-1 collision resistant)
- ✅ GitHub as code host
- ✅ Your own build environment

You do NOT need to trust:
- ❌ CI/CD pipeline (you can rebuild yourself)
- ❌ Cloudflare Pages (SRI verifies deployed artifacts)
- ❌ Developer's machine (reproducible builds prove no tampering)

## Questions?

- GitHub Issues: https://github.com/Lukium/ats-kms-enclave/issues
- Architecture Docs: `docs/architecture/crypto/`
