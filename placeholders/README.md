# Placeholder Files for Cloudflare Pages Deployment

**Status:** Temporary infrastructure testing files
**Phase:** Pre-Phase 2 (infrastructure setup)
**Will be replaced by:** Production artifacts from reproducible build pipeline

## Purpose

These placeholder files enable early infrastructure testing and validation of the Cloudflare Pages deployment before Phase 2 implementation is complete. They allow you to:

1. **Test Cloudflare Pages deployment** - Verify custom domain, SSL, and routing
2. **Validate security headers** - Ensure CSP, COOP, COEP headers are correctly applied
3. **Test manifest serving** - Verify `.well-known/kms-manifest.json` is accessible
4. **Verify Sigstore directory** - Ensure `/sigstore/*` directory is publicly accessible
5. **End-to-end infrastructure check** - Confirm all components work before shipping real code

## Files

### `kms.html`
Minimal HTML placeholder that will be replaced by the real enclave iframe in Phase 2.

### `.well-known/kms-manifest.json`
Placeholder manifest with dummy values. In Phase 2, this will contain:
- Real artifact hashes (SHA-384)
- SRI values for script integrity
- Version numbers
- Commit references
- Allowed/deprecated version lists

### `_headers`
**Production-ready security headers** (not a placeholder - these are final):
- Content Security Policy (CSP) - Strict isolation
- Cross-Origin policies (COOP, COEP, CORP)
- Permissions Policy - Disable unnecessary browser features
- Cache-Control directives per file type

### `sigstore/` (empty directory)
Will contain Sigstore/Rekor transparency log attestations in Phase 2.
Uses `.gitkeep` to preserve directory in version control.

## Directory Structure

```
placeholders/
├── README.md              (this file)
└── cf-pages/              (deploy this directory to Cloudflare Pages)
    ├── kms.html           (placeholder iframe entry point)
    ├── _headers           (security headers - production ready)
    ├── .well-known/
    │   └── kms-manifest.json  (placeholder manifest)
    └── sigstore/
        └── .gitkeep       (preserve directory)
```

## Deployment Instructions

### Upload to Cloudflare Pages

From your Cloudflare Pages project (`kms.ats.run`):

1. **Via Dashboard (initial test):**
   - Go to Pages → Your Project → Upload Assets
   - Upload contents of `placeholders/cf-pages/` directory
   - Verify deployment succeeds

2. **Via Wrangler CLI (recommended):**
   ```bash
   cd placeholders/cf-pages/
   wrangler pages deploy . --project-name=your-kms-project
   ```

3. **Verify deployment:**
   - Visit `https://kms.ats.run/kms.html` → Should see placeholder page
   - Visit `https://kms.ats.run/.well-known/kms-manifest.json` → Should return JSON
   - Check response headers → Security headers should be present

### Security Header Validation

Use browser DevTools or `curl -I` to verify headers:

```bash
# Check kms.html headers
curl -I https://kms.ats.run/kms.html

# Should include:
# Content-Security-Policy: default-src 'none'; script-src 'self'; ...
# Cross-Origin-Opener-Policy: same-origin
# Cross-Origin-Embedder-Policy: require-corp
# etc.

# Check manifest headers
curl -I https://kms.ats.run/.well-known/kms-manifest.json

# Should include:
# Content-Type: application/json; charset=utf-8
# Access-Control-Allow-Origin: *
```

## What Happens in Phase 2

These placeholders will be replaced by:

1. **Real `kms.html`** - Bootstrap iframe with SRI-verified script tags
2. **Real manifest** - Actual artifact hashes, version numbers, commit SHAs
3. **Real artifacts** - Content-addressed bundles (e.g., `kms-abc123.mjs`)
4. **Sigstore attestations** - Cryptographic signatures and transparency log entries

The `_headers` file will remain largely the same (production-ready now).

## Important Notes

- ⚠️ **DO NOT use these placeholders in production PWA** - They contain no real security
- ⚠️ **DO NOT modify `_headers`** without security review - These are production settings
- ✅ **DO test infrastructure thoroughly** - Catch deployment issues early
- ✅ **DO verify CORS and CSP** - Ensure they don't break legitimate use

## Related Documentation

- [Phase 2 Plan](../docs/architecture/crypto/plan.md#phase-2-verifiable-build) - Reproducible build implementation
- [Build Pipeline Design](../docs/architecture/crypto/design/04-build-pipeline.md) - Content-addressed artifacts
- [Security Headers](../docs/architecture/crypto/design/02-security-decisions.md) - CSP/COOP/COEP rationale

## Cleanup

After Phase 2 is complete and production artifacts are deployed:

```bash
# Remove placeholder directory (entire placeholders/ folder)
git rm -r placeholders/
git commit -m "chore: Remove placeholders after Phase 2 deployment"
```

The `_headers` file should be migrated to your production deployment location before cleanup.
