# KMS Enclave Verifier Branch

⚠️ **THIS BRANCH CONTAINS ONLY VERIFICATION CODE** ⚠️

This is the **verifier branch** - it contains only the code needed to verify the deployed KMS enclave at `kms.ats.run`.

## Purpose

This branch is designed to be:
- **Minimal**: Only verification code, no main project code
- **Auditable**: Easy to review and trust
- **Frozen**: Once audited, this branch should rarely change
- **Independent**: Runs verification checks independently from main codebase

## Structure

```
verifier/
├── verify-deployment.ts    # Main orchestrator
├── verify-headers.ts        # Security headers validation
├── generate-badge.ts        # Badge generation
├── generate-report.ts       # Report generation
├── README.md               # Verifier documentation
└── .github/workflows/
    └── verify.yml          # Verification workflow
```

## How It Works

1. **Triggered by**: `repository_dispatch` from main branch (every minute, 1/360 probability)
2. **Runs**: All verification checks against live deployment
3. **Outputs**: Badge and report to `attestation` branch

## Verification Checks

- ✅ Manifest fetch and integrity
- ✅ Worker hash matches deployed version
- ✅ SRI (Subresource Integrity) hashes
- ✅ Security headers (CSP, Permissions-Policy, etc.)
- ✅ Allowed version list
- ⏭️  Rekor/GitHub attestations (Phase 2.2)

## Trust Model

**To trust this verifier:**
1. Review the TypeScript files in `verifier/` directory
2. Review the workflow in `verifier/.github/workflows/verify.yml`
3. Verify no other code exists in this branch
4. Check that it only makes requests to `kms.ats.run`
5. Confirm it writes results only to `attestation` branch

Once you trust this commit, you can verify immutability:
```bash
git rev-parse verifier  # Note the commit hash
# Later, verify nothing changed:
git diff <commit-hash> verifier
```

## Reports

All verification reports are written to the **`attestation` branch**:
- `README.md` - Latest verification report
- `verification-badge.svg` - Status badge
- `verification-badge.json` - Machine-readable metadata

## Deployment

This branch does **not** trigger Cloudflare Pages deployments. Only the `main` branch deploys to production.

## Links

- **Attestation Branch**: https://github.com/Lukium/ats-kms-enclave/tree/attestation
- **Main Repository**: https://github.com/Lukium/ats-kms-enclave
- **KMS Deployment**: https://kms.ats.run
