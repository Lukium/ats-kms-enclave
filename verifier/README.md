# KMS Enclave Verifier

**Independent verification system for kms.ats.run deployment**

⚠️ **THIS BRANCH IS FROZEN FOR AUDITABILITY** ⚠️

This branch contains only the verification code. Once audited and trusted, **this branch should never change**. All verification reports are written to the `attestation` branch.

## 🔍 Purpose

Automatically verify that the deployed KMS enclave at `kms.ats.run` matches:
- Published manifest hashes
- SRI (Subresource Integrity) specifications
- Security header requirements
- Allowed version list

## 📁 Files (Complete List)

```
verifier/
├── verify-deployment.ts       # Main orchestrator
├── verify-headers.ts           # Security headers validation
├── generate-badge.ts           # Badge and report generation
├── generate-report.ts          # Detailed markdown report
├── .github/workflows/verify.yml # GitHub Actions workflow
└── README.md                   # This file
```

**That's it.** No other files. Easy to audit.

## 🔒 Trust Model

1. **Audit this commit** - Review the 4 TypeScript files above
2. **Verify they do what they claim** - Check logic, no backdoors
3. **Trust this commit forever** - Code never changes
4. **Check attestation branch** - For latest verification reports

## ✅ What Gets Verified

### 1. Manifest Fetch
- Fetches `/.well-known/kms-manifest.json`
- Validates JSON structure

### 2. Worker Hash
- Downloads deployed worker JS
- Computes SHA-256 hash
- Compares with manifest

### 3. SRI Hashes
- Verifies client JS SHA-384 hash
- Verifies CSS SHA-384 hash
- Compares with manifest

### 4. Security Headers
- Content-Security-Policy (CSP)
- Permissions-Policy
- X-Content-Type-Options
- Referrer-Policy
- COOP/COEP absence (iframe compatibility)

### 5. Allowed List
- Current hash in manifest.allowed array

### 6. Rekor Attestation (Phase 2.2)
- Hook ready, not yet implemented

## 🚀 How It Works

1. **Trigger**: Main branch cron runs every minute with 1/360 probability
2. **Dispatch**: Sends `repository_dispatch` to this branch
3. **Workflow**: `.github/workflows/verify.yml` runs verification
4. **Report**: Writes results to `attestation` branch
5. **Badge**: Updates badge SVG in `attestation` branch

## 📊 Verification Reports

All reports are written to the **`attestation` branch**:
- `README.md` - Latest verification report
- `verification-badge.svg` - Current status badge
- `verification-badge.json` - Machine-readable metadata
- `history/` - Timestamped historical reports

## 🔐 Security Properties

- **Randomized timing** - Unpredictable ~4x/day
- **1-minute attack window** - Fast detection
- **Independent verification** - Separate from main codebase
- **Public auditability** - GitHub Actions logs
- **Immutable code** - This branch frozen after audit

## 📝 Code Audit Checklist

When auditing this verifier:

- [ ] Read `verify-deployment.ts` - Main logic correct?
- [ ] Read `verify-headers.ts` - Header checks complete?
- [ ] Read `generate-badge.ts` - Badge generation safe?
- [ ] Read `generate-report.ts` - Report generation safe?
- [ ] Read `.github/workflows/verify.yml` - Workflow secure?
- [ ] No other files in `verifier/` directory?
- [ ] No network calls except to kms.ats.run?
- [ ] No secret extraction or data exfiltration?
- [ ] Reports written to `attestation` branch only?

## 🎯 Audit This Commit

**This commit should be the last one on the verifier branch.**

Once you audit and trust this commit, you can verify immutability:

```bash
# Get current commit
git rev-parse verifier
# abc123...

# Later, verify nothing changed
git diff abc123 verifier
# Should show: no changes
```

If anything changed, **re-audit**.

## 📌 Links

- **Verification Reports**: https://github.com/lukium/ats-kms/tree/attestation
- **Latest Badge**: https://raw.githubusercontent.com/lukium/ats-kms/attestation/verification-badge.svg
- **Main Repo**: https://github.com/lukium/ats-kms

---

**After this commit, the verifier branch should be frozen.**
