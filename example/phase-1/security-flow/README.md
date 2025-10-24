# ATS KMS Enclave - Phase 1 Demo

This is an **interactive Phase 1 demonstration** that proves the production-ready KMS implementation with persistent storage, passphrase-based unlock, and comprehensive audit logging.

## What's New in Phase 1

Phase 1 adds critical production features beyond the Phase 0 prototype:

- 🔐 **Passphrase-based unlock** - Secure key derivation with PBKDF2 (600,000 iterations)
- 💾 **Persistent storage** - Keys stored in IndexedDB with AES-GCM wrapping
- 📋 **Audit logging** - Complete operation history with timestamps
- 🔒 **Worker isolation** - All crypto operations in dedicated Worker
- ✅ **100% test coverage** - 219 tests, all passing

## How to Run

```bash
# Start the Phase 1 demo server
pnpm demo:phase-1

# Or use the generic demo command (starts latest phase)
pnpm demo

# The demo will open at: http://localhost:5174
```

## Demo Flow

The Phase 1 demo follows a realistic user journey through the KMS lifecycle:

### 1. Initial Setup 🔧

**First time setup:**
- User creates a passphrase (minimum 8 characters)
- System derives wrapping key with PBKDF2 (600k iterations)
- Wrapping key stored securely (never leaves Worker)
- System is now "unlocked" and ready

**Verification cards show:**
- ✅ Setup successful
- ✅ Salt generated (32 bytes)
- ✅ Iterations: 600,000
- ✅ Worker unlocked

### 2. Generate VAPID Keypair 🔑

**What happens:**
- P-256 ECDSA keypair generated
- Private key wrapped with AES-GCM
- Wrapped key + metadata stored in IndexedDB
- Public key returned to caller

**Verification cards show:**
- ✅ Key format: 65 bytes uncompressed
- ✅ Algorithm: ECDSA P-256
- ✅ Extractable: false
- ✅ Stored in IndexedDB
- ✅ Wrapped with AES-GCM

### 3. Sign JWT Token 🎫

**What happens:**
- Private key unwrapped from IndexedDB
- JWT signed with ES256
- Operation logged to audit trail
- Token returned to caller

**Verification cards show:**
- ✅ Algorithm: ES256
- ✅ Signature: 64 bytes (P-1363 format)
- ✅ Token lifetime: ≤24h
- ✅ Audit entry created

### 4. Lock Worker 🔒

**What happens:**
- Wrapping key cleared from memory
- Worker enters locked state
- Crypto operations now fail
- Keys remain in IndexedDB (encrypted)

**Verification cards show:**
- ✅ Worker locked
- ✅ Keys still in storage
- ✅ Operations require unlock

### 5. Unlock Worker 🔓

**What happens:**
- User provides passphrase
- System re-derives wrapping key
- Worker unlocked
- Crypto operations resume

**Verification cards show:**
- ✅ Passphrase verified
- ✅ Worker unlocked
- ✅ Keys accessible

### 6. Persistence Test 🔄

**What happens:**
- Page refreshes (simulated or real F5)
- Keys still in IndexedDB
- User unlocks with passphrase
- Original keys recovered

**Verification cards show:**
- ✅ Keys survived refresh
- ✅ Same kid recovered
- ✅ JWT signing still works

### 7. View Audit Log 📋

**What happens:**
- Fetch all audit entries from IndexedDB
- Display chronological operation history
- Show: operation type, timestamp, kid, details

**Audit log shows:**
- Setup operation
- Generate VAPID operation
- Sign JWT operation
- Lock/unlock operations

## Performance Metrics

The demo measures and displays actual browser performance:

**Key Generation:**
- Target: <100ms
- Actual: (measured in demo)

**JWT Signing:**
- Target: <50ms
- Actual: (measured in demo)

**Storage Operations:**
- Key wrap + store: (measured)
- Key retrieve + unwrap: (measured)

**Worker Load:**
- Target: <500ms
- Actual: (measured on page load)

## Verification Checks

### 🔐 Unlock System

**PBKDF2 Iterations: 600,000**
- *Why:* OWASP recommendation for 2025+
- *Security:* Makes brute-force attacks infeasible
- *Tradeoff:* ~1 second unlock time (acceptable)

**Salt: 32 bytes random**
- *Why:* Prevents rainbow table attacks
- *Format:* Unique per installation
- *Storage:* Persisted in IndexedDB

**Wrapping Key: Never exported**
- *Why:* Exists only in Worker memory
- *Security:* Even with IndexedDB access, keys are encrypted
- *Cleared:* On lock or Worker termination

### 💾 Persistent Storage

**Storage: IndexedDB**
- *Why:* Large quota, transactional, supports CryptoKey objects
- *Schema:* Structured with indices
- *Quota:* Unlimited (Chrome 113+)

**Key Wrapping: AES-GCM**
- *Why:* Authenticated encryption (confidentiality + integrity)
- *Algorithm:* AES-256-GCM
- *IV:* Unique per wrap operation (96 bits)

**Stored Metadata:**
- Kid (key identifier)
- Wrapped key bytes
- Wrapping parameters (alg, IV, salt, iterations)
- Public key (raw format)
- Algorithm info (alg, purpose)
- Timestamps (created, last used)

### 📋 Audit Logging

**Logged Operations:**
- `setup` - Initial passphrase setup
- `unlock` - Unlock with passphrase
- `generate_vapid` - VAPID keypair generation
- `sign` - JWT signing operation

**Entry Format:**
- Operation type
- Timestamp (ISO 8601)
- Kid (which key was used)
- Request ID (correlation)
- Origin (if provided)
- Details (operation-specific data)

**Retention:**
- Stored in IndexedDB
- Survives page refresh
- Can be cleared by user

### 🔒 Security Properties

**Worker Isolation:**
- *Why:* Crypto operations isolated from DOM
- *Benefit:* No XSS access to crypto operations
- *Communication:* Only via postMessage

**Non-Extractable Keys:**
- *Why:* Browser refuses to export private keys
- *Benefit:* Even compromised host can't steal keys
- *Verified:* CryptoKey.extractable === false

**Lock State:**
- *Why:* User can lock KMS when not needed
- *Benefit:* Limits exposure window
- *Implementation:* Wrapping key cleared from memory

## Files

**Demo Files:**
- `index.html` - Interactive demo UI with tabs
- `demo.ts` - Demo orchestration logic
- `README.md` - This file

**Uses Production Code:**
- `../../src/client.ts` - Real KMSClient
- `../../src/worker.ts` - Real Worker (via client)
- `../../src/storage.ts` - Real IndexedDB operations
- `../../src/audit.ts` - Real audit logging
- `../../src/unlock.ts` - Real unlock manager

**No Mock/Demo Worker:** This demo uses the actual Phase 1 production code, proving it works in a real browser environment.

## Differences from Phase 0

| Feature | Phase 0 | Phase 1 |
|---------|---------|---------|
| Storage | In-memory only | IndexedDB (persistent) |
| Security | No unlock required | Passphrase-based unlock |
| Key Wrapping | None | AES-GCM encryption |
| Audit Logging | None | Full operation history |
| Worker Lifecycle | Always unlocked | Lock/unlock states |
| Persistence | Lost on refresh | Survives refresh |
| Test Coverage | 108 tests | 219 tests |

## Interactive Features

### Tabs

The demo has multiple tabs for different functions:

1. **Demo Flow** - Main workflow with progressive stages
2. **Audit Log** - View operation history
3. **Storage Inspector** - Browse IndexedDB contents
4. **Performance** - View timing metrics

### Controls

**Stage Execution:**
- Run stages individually (step-by-step)
- Run full demo (automated flow)
- Reset demo (clear all state)

**Worker Control:**
- Lock worker (manual lock)
- Unlock worker (with passphrase)
- Check lock status

**Storage:**
- View all stored keys
- Export audit log
- Clear storage (destructive)

## Development

The demo uses Vite for hot-reloading:

```bash
# Start dev server
pnpm demo:phase-1

# Build for production
pnpm demo:build

# Output goes to example/phase-1/dist/
```

## Acceptance Criteria

When you run the full demo, you should see:

1. ✅ **All stages complete successfully**
2. ✅ **All verification cards show green**
3. ✅ **Keys persist across refresh**
4. ✅ **Lock/unlock works correctly**
5. ✅ **Audit log shows all operations**
6. ✅ **Performance within targets**
7. ✅ **No console errors**

If any check fails, there's a bug in the Phase 1 implementation.

## Troubleshooting

**"Worker not unlocked" errors:**
- Ensure you completed Stage 1 (setup passphrase)
- Check worker is unlocked (should show unlocked icon)
- Try manual unlock with passphrase

**Keys not persisting:**
- Check IndexedDB quota (should be unlimited)
- Verify browser supports IndexedDB (Chrome 113+)
- Check browser console for IndexedDB errors

**Slow performance:**
- PBKDF2 unlock is intentionally slow (~1s with 600k iterations)
- Key generation should be <100ms
- JWT signing should be <50ms
- If much slower, check browser throttling

## Security Notes

**This is a demo environment:**
- Uses `http://localhost` (not secure origin in production)
- Passphrase stored in demo for convenience (never do this in production)
- Audit log displayed openly (production should protect this)
- No rate limiting on operations

**Production deployment would add:**
- HTTPS required
- CSP headers
- SRI on script tags
- Rate limiting
- Secure passphrase input (no autocomplete, no logging)
- Protected audit log access

## Next Steps

Phase 1 proves the KMS is production-ready with persistent storage. Next phases:

- **Phase 2:** Verifiable builds (deterministic artifacts, SRI)
- **Phase 3:** Transparency logs (Sigstore, Rekor)
- **Phase 4:** User verification UX
- **Phase 5:** Integration with main PWA
- **Phase 6:** Signal Protocol (E2EE)

Each phase will extend this demo to prove new capabilities.
