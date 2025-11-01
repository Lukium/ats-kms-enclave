# Safe Point: Before KMS-Only Popup Implementation

## Purpose

This document marks the safe commit point before implementing the KMS-only popup credential flow (Option A+). If implementation causes issues, revert to this commit.

## Safe Commit

**Full Hash:** `97078fe8bf3da21671729a3d53f1a209732139eb`
**Short Hash:** `97078fe`
**Date:** 2025-11-01 05:26:32 -0400
**Author:** Lukium <mrlukium@outlook.com>

**Commit Message:**
```
docs: Add implementation plan for KMS-only popup credential flow
```

## How to Revert

If implementation breaks the codebase and you need to go back:

```bash
# Option 1: Hard reset (WARNING: Loses all uncommitted changes)
git reset --hard 97078fe

# Option 2: Create new branch from safe point
git checkout -b fix-from-safe-point 97078fe

# Option 3: Revert specific files (safer)
git checkout 97078fe -- <file-path>
```

## Current State Summary

### Working Features
- ✅ Phase 2 stateless popup credential collection (parent-mediated)
- ✅ ECDH transport key generation in iframe
- ✅ Encrypted credential exchange (popup → parent → iframe)
- ✅ All three setup methods: passphrase, passkey-prf, passkey-gate
- ✅ RequestId audit logging flow
- ✅ All tests passing (401 tests)
- ✅ Code coverage: 80.07%
- ✅ TypeScript: No errors
- ✅ ESLint: No errors

### Current Architecture
```
┌─────────┐                 ┌────────┐                 ┌───────┐
│ Parent  │────────────────>│ Iframe │                 │ Popup │
│  PWA    │  RPC: setup     │  KMS   │                 │  KMS  │
└─────────┘                 └────────┘                 └───────┘
     │                           │                          │
     │  generateTransportKey     │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  window.open(params)      │                          │
     ├────────────────────────────────────────────────────> │
     │                           │                          │
     │◄─────────────────────────────────────────────────────┤
     │  MessageChannel (parent ↔ popup)                     │
     │                           │                          │
     │  encrypted credentials    │                          │
     │◄─────────────────────────────────────────────────────┤
     │                           │                          │
     │  setupWithEncrypted       │                          │
     ├──────────────────────────>│                          │
```

**Security Issue:** Parent sees transport params in URL and receives encrypted credentials.

### Implementation Plan Status
- ✅ Plan documented (README.md, 01-current-state.md, 02-target-state.md, 03-implementation-steps.md)
- ⏳ Implementation not started
- 14 steps planned (~17 hours estimated)

### Key Files in Current State

**Core Implementation:**
- `src/v2/worker.ts` - generateSetupTransportKey(), setupWithEncryptedCredentials()
- `src/v2/client.ts` - Stateless popup mode (lines 1090-1438)
- `src/v2/kms-user.ts` - setupWithEncryptedCredentials() RPC method
- `src/v2/rpc-validation.ts` - validateSetupWithEncryptedCredentials()
- `example/phase-2/parent.ts` - setupPassphrase() (lines 463-653)

**Tests:**
- All passing (401 tests)
- Coverage: 80.07% lines, 81.59% branches, 83.05% functions

## What Will Change

### Target Architecture
```
┌─────────┐                 ┌────────┐                 ┌───────┐
│ Parent  │                 │ Iframe │                 │ Popup │
│  PWA    │                 │  KMS   │                 │  KMS  │
└─────────┘                 └────────┘                 └───────┘
     │                           │                          │
     │  RPC: setupWithPopup      │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │  kms:request-popup        │                          │
     │◄──────────────────────────┤                          │
     │                           │                          │
     │  window.open(minimal URL) │                          │
     ├────────────────────────────────────────────────────> │
     │                           │                          │
     │  kms:popup-opened         │                          │
     ├──────────────────────────>│                          │
     │                           │                          │
     │                           │  kms:popup-ready         │
     │                           │◄─────────────────────────┤
     │                           │                          │
     │                           │  MessageChannel + params │
     │                           │─────────────────────────>│
     │                           │                          │
     │                           │  encrypted credentials   │
     │                           │◄─────────────────────────┤
     │                           │                          │
     │  setupComplete            │                          │
     │◄──────────────────────────┤                          │
```

**Security Improvement:** Parent only opens popup, never sees cryptographic material.

### Files That Will Be Modified
1. `src/v2/types.ts` - Add 'setupWithPopup' to RPCMethod type
2. `src/v2/rpc-validation.ts` - Add validateSetupWithPopup()
3. `src/v2/kms-user.ts` - Add setupWithPopup() method
4. `src/v2/worker.ts` - Add handleSetupWithPopup() handler
5. `src/v2/client.ts` - Add worker-parent message forwarding, popup handshake
6. `example/phase-2/parent.ts` - Replace current flow with popup request handler
7. Tests - Add new test coverage

## Verification Before Implementation

Run these commands to verify current state:

```bash
# All tests should pass
pnpm test

# Coverage should be 80.07%
pnpm test:coverage

# No TypeScript errors
pnpm typecheck

# No linting errors
pnpm lint

# Or run all checks
make pre-commit
```

## Post-Implementation Rollback Checklist

If you need to rollback, verify these still work:
- [ ] `pnpm test` - All 401 tests pass
- [ ] `pnpm test:coverage` - Coverage ≥ 80%
- [ ] `pnpm typecheck` - No TypeScript errors
- [ ] `pnpm lint` - No ESLint errors
- [ ] `pnpm demo:phase-2:parent` - Parent demo starts
- [ ] `pnpm demo:phase-2:kms` - KMS demo starts
- [ ] Manual test: Setup with passphrase works
- [ ] Manual test: Setup with passkey PRF works
- [ ] Manual test: Setup with passkey gate works

## Notes

- This safe point includes the full implementation plan
- Current implementation is stable and tested
- New implementation maintains backwards compatibility
- Old `setupWithEncryptedCredentials` will be kept as deprecated method
- Migration can be gradual

## Created

**Date:** 2025-11-01
**Purpose:** Safe rollback point before implementing KMS-only popup flow
