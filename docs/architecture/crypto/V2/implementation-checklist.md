# V2 Implementation Checklist

**Version**: 2.0
**Date**: 2025-01-24

This document provides a step-by-step implementation guide for all V2 security improvements.

---

## Prerequisites

- ✅ V1 architecture documentation review
- ✅ V2 crypto-spec.md understanding
- ✅ V2 security-improvements.md review
- [ ] Test environment setup
- [ ] Browser compatibility matrix confirmed

---

## Phase 1: Core Primitives (Foundation)

### 1.1. PBKDF2 Calibration Module

**Location**: `src/calibration.ts` (new file)

**Tasks**:

- [ ] Create `calibratePBKDF2Iterations()` function
  - [ ] Warm-up run (10k iterations)
  - [ ] Probe run (100k iterations, measure time)
  - [ ] Scale to target (150-300ms)
  - [ ] Clamp (50k - 2M iterations)
  - [ ] Verify measurement
  - [ ] Return `{ iterations, measuredMs }`

- [ ] Create calibration state management
  - [ ] `CalibrationState` interface
  - [ ] EMA (exponential moving average) tracking
  - [ ] Platform hash computation
  - [ ] Persistence to IndexedDB

- [ ] Create recalibration logic
  - [ ] Opportunistic adjustment (±10% based on EMA)
  - [ ] Periodic full recalibration (30 days)
  - [ ] Platform change detection

- [ ] Add tests
  - [ ] Unit tests for calibration algorithm
  - [ ] Mock performance.now() for determinism
  - [ ] Test clamp boundaries
  - [ ] Test recalibration triggers

**Acceptance Criteria**:
- Calibration completes in <5 seconds
- Result is consistently 150-300ms on test device
- Recalibration logic doesn't run too frequently
- All tests pass

---

### 1.2. Key Check Value (KCV) Utilities

**Location**: `src/crypto-utils.ts` (update existing)

**Tasks**:

- [ ] Create `computeKCV()` function
  ```typescript
  async function computeKCV(kek: CryptoKey): Promise<ArrayBuffer>
  ```
  - [ ] Import KEK for HMAC
  - [ ] Compute HMAC-SHA256(KEK, "ATS/KMS/KCV/v2")
  - [ ] Return 32-byte KCV

- [ ] Create `verifyKCV()` function
  ```typescript
  function verifyKCV(computed: ArrayBuffer, stored: ArrayBuffer): boolean
  ```
  - [ ] Implement constant-time comparison
  - [ ] Return boolean

- [ ] Create `timingSafeEqual()` helper
  - [ ] XOR-based comparison
  - [ ] Test against timing attack vectors

- [ ] Add tests
  - [ ] KCV determinism (same KEK → same KCV)
  - [ ] KCV uniqueness (different KEK → different KCV)
  - [ ] Constant-time verification
  - [ ] Edge cases (wrong length, null buffers)

**Acceptance Criteria**:
- KCV is deterministic
- Verification is constant-time (no early exit)
- All tests pass

---

### 1.3. AAD Construction Utilities

**Location**: `src/crypto-utils.ts` (update existing)

**Tasks**:

- [ ] Create `buildMSEncryptionAAD()` function
  ```typescript
  function buildMSEncryptionAAD(config: {
    kmsVersion: number;
    method: string;
    algVersion: number;
    credentialId?: ArrayBuffer;
  }): ArrayBuffer
  ```
  - [ ] Canonical JSON serialization
  - [ ] Base64url encode credentialId if present
  - [ ] UTF-8 encode result

- [ ] Create `buildKeyWrapAAD()` function
  ```typescript
  function buildKeyWrapAAD(metadata: {
    kmsVersion: number;
    kid: string;
    alg: string;
    purpose: string;
    createdAt: number;
  }): ArrayBuffer
  ```
  - [ ] Canonical JSON with sorted keys
  - [ ] UTF-8 encode result

- [ ] Add tests
  - [ ] AAD determinism (same input → same AAD)
  - [ ] AAD uniqueness (different input → different AAD)
  - [ ] JSON canonicalization (key ordering)
  - [ ] Binary output validation

**Acceptance Criteria**:
- AAD is deterministic
- JSON is properly canonicalized
- All tests pass

---

### 1.4. Deterministic Salt Generation

**Location**: `src/crypto-utils.ts` (update existing)

**Tasks**:

- [ ] Create `deriveDeterministicSalt()` function
  ```typescript
  async function deriveDeterministicSalt(context: string): Promise<ArrayBuffer>
  ```
  - [ ] SHA-256 hash of context string
  - [ ] Return 32-byte salt

- [ ] Define salt contexts as constants
  ```typescript
  const MKEK_SALT_CONTEXT = 'ATS/KMS/MKEK/salt/v2';
  const KEK_WRAP_SALT_CONTEXT = 'ATS/KMS/KEK-wrap/salt/v2';
  // ... others
  ```

- [ ] Add tests
  - [ ] Salt determinism
  - [ ] Salt uniqueness per context
  - [ ] Salt length (32 bytes)

**Acceptance Criteria**:
- Salts are deterministic per context
- Different contexts produce different salts
- All tests pass

---

## Phase 2: Storage Schema Updates

### 2.1. Update Config Types

**Location**: `src/storage.ts` (update existing)

**Tasks**:

- [ ] Define V2 config interfaces
  - [ ] `PassphraseConfigV2` with all new fields
  - [ ] `PasskeyPrfConfigV2` with separate hkdfSalt
  - [ ] `PasskeyGateConfigV2` with pepper
  - [ ] `WrappedKeyConfigV2` with AAD

- [ ] Add version detection
  ```typescript
  function detectConfigVersion(config: unknown): number
  ```

- [ ] Update `getMeta()` to handle versioning
  - [ ] Check kmsVersion field
  - [ ] Throw on V1 detection (require reset)
  - [ ] Return typed V2 config

- [ ] Add migration utilities (for future)
  ```typescript
  async function migrateConfigV2ToV3(config: ConfigV2): Promise<ConfigV3>
  ```

**Acceptance Criteria**:
- All V2 types defined
- Version detection works correctly
- getMeta() throws on V1 configs

---

### 2.2. Update Audit Entry Schema

**Location**: `src/audit.ts` (update existing)

**Tasks**:

- [ ] Define `AuditEntryV2` interface
  - [ ] Add `kmsVersion: 2`
  - [ ] Add `seqNum: number`
  - [ ] Replace `publicKey` with `auditKeyId`
  - [ ] Keep all timing fields

- [ ] Create audit key storage
  ```typescript
  interface AuditKeyConfig {
    keyId: string;
    publicKey: ArrayBuffer;
    privateKeyWrapped: ArrayBuffer;
    iv: ArrayBuffer;
    createdAt: number;
  }
  ```

- [ ] Update sequence counter persistence
  - [ ] Store `nextSeqNum` in meta
  - [ ] Atomic increment on each log operation

**Acceptance Criteria**:
- New audit schema defined
- Sequence counter persisted correctly
- Audit key stored separately

---

## Phase 3: Unlock Module Updates

### 3.1. Update `unlock.ts` for V2

**Location**: `src/unlock.ts` (major update)

**Tasks**:

- [ ] Update `setupPassphrase()` for V2
  - [ ] Run calibration if first time
  - [ ] Use calibrated iterations
  - [ ] Compute KCV after KEK derivation
  - [ ] Build MS encryption AAD
  - [ ] Encrypt MS with AAD
  - [ ] Store V2 config with all new fields

- [ ] Update `unlockWithPassphrase()` for V2
  - [ ] Load V2 config
  - [ ] Derive KEK with stored iterations
  - [ ] Verify KCV before decrypt
  - [ ] Decrypt MS with AAD verification
  - [ ] Return MS

- [ ] Update `setupPasskeyPRF()` for V2
  - [ ] Generate separate hkdfSalt
  - [ ] Build MS encryption AAD (include credentialId)
  - [ ] Encrypt MS with AAD
  - [ ] Store V2 config

- [ ] Update `unlockWithPasskeyPRF()` for V2
  - [ ] Use hkdfSalt (not appSalt) for HKDF
  - [ ] Decrypt MS with AAD verification

- [ ] Implement `setupPasskeyGate()` with pepper
  - [ ] Generate random pepper
  - [ ] Derive gate KEK from credentialId
  - [ ] Encrypt pepper with gate KEK + AAD
  - [ ] Derive MS KEK from (passphrase || pepper)
  - [ ] Encrypt MS with AAD
  - [ ] Store V2 config

- [ ] Implement `unlockWithPasskeyGate()` with pepper
  - [ ] Derive gate KEK
  - [ ] Decrypt pepper
  - [ ] Derive MS KEK from (passphrase || pepper)
  - [ ] Decrypt MS with AAD
  - [ ] Clear pepper

- [ ] Update `deriveMKEKFromMS()` for V2
  - [ ] Use deterministic non-zero salt
  - [ ] Update info string to v2

- [ ] Update `withUnlock()` signature
  - [ ] Return `UnlockOperationResult<T>` with timing
  - [ ] Ensure guaranteed MS cleanup in finally

**Acceptance Criteria**:
- All setup methods create V2 configs
- All unlock methods verify AAD
- KCV verification works
- PBKDF2 uses calibrated iterations
- Passkey gate uses pepper
- MKEK uses deterministic salt
- withUnlock() returns timing data

---

### 3.2. Add Multi-Enrollment Support

**Location**: `src/unlock.ts` (new functions)

**Tasks**:

- [ ] Create `addEnrollment()` function
  ```typescript
  async function addEnrollment(
    newMethod: 'passphrase' | 'passkey-prf' | 'passkey-gate',
    newMethodParams: unknown,
    existingCredentials: AuthCredentials
  ): Promise<{ success: boolean }>
  ```
  - [ ] Unlock with existing credentials to get MS
  - [ ] Setup new method with existing MS
  - [ ] Clear MS after setup

- [ ] Create `removeEnrollment()` function
  ```typescript
  async function removeEnrollment(
    methodToRemove: string,
    authCredentials: AuthCredentials
  ): Promise<{ success: boolean }>
  ```
  - [ ] Verify auth with different method
  - [ ] Delete config for removed method

- [ ] Create `listEnrollments()` function
  - [ ] Query all *Config keys in meta store
  - [ ] Return array of methods

**Acceptance Criteria**:
- Can add second method without unlocking first
- Can remove method with auth from another
- Cannot remove last method
- All enrollments decrypt to same MS

---

## Phase 4: Worker Updates

### 4.1. Update `worker.ts` for Per-Operation Auth

**Location**: `src/worker.ts` (update existing)

**Tasks**:

- [ ] Update `generateVAPID()` to use withUnlock
  - [ ] Require credentials parameter
  - [ ] Call `withUnlock(credentials, async (mkek) => {...})`
  - [ ] Log duration from unlock result
  - [ ] Ensure MS is cleared

- [ ] Update `signJWT()` to use withUnlock
  - [ ] Require credentials parameter
  - [ ] Unwrap key inside withUnlock
  - [ ] Log duration

- [ ] Update all setup methods
  - [ ] `setupPassphraseMethod()` for V2
  - [ ] `setupPasskeyPRFMethod()` for V2
  - [ ] `setupPasskeyGateMethod()` for V2 with credentials

- [ ] Update RPC handlers
  - [ ] Extract credentials from params
  - [ ] Pass to operation functions
  - [ ] Handle missing credentials error

**Acceptance Criteria**:
- All operations use withUnlock()
- MS is never stored in worker state
- Timing is logged to audit
- Credentials are required for all crypto ops

---

### 4.2. Update Key Wrapping/Unwrapping

**Location**: `src/storage.ts` (update existing)

**Tasks**:

- [ ] Update `wrapKey()` to use AAD
  - [ ] Build AAD from key metadata
  - [ ] Pass additionalData to wrapKey()
  - [ ] Store AAD with wrapped key

- [ ] Update `unwrapKey()` to use AAD
  - [ ] Load AAD from storage
  - [ ] Pass additionalData to unwrapKey()
  - [ ] Verify AAD integrity

- [ ] Update wrapped key storage schema
  - [ ] Add `kmsVersion: 2`
  - [ ] Add `aad: ArrayBuffer`
  - [ ] Add `lastUsedAt?: number`

**Acceptance Criteria**:
- All keys wrapped with AAD
- AAD verification on unwrap
- Cannot swap wrapped keys (AAD prevents)

---

## Phase 5: Audit Log Hardening

### 5.1. Non-Extractable Audit Key

**Location**: `src/audit.ts` (major update)

**Tasks**:

- [ ] Update `initAuditLogger()` for V2
  - [ ] Generate Ed25519 key with `extractable: false`
  - [ ] Compute `keyId = SHA256(publicKey)`
  - [ ] Store `AuditKeyConfig` in meta

- [ ] Create `exportAuditKey()` function
  - [ ] Require authentication (credentials parameter)
  - [ ] Use withUnlock for auth
  - [ ] Generate temporary extractable key
  - [ ] Export as JWK
  - [ ] Return for backup

- [ ] Update `logOperation()` for sequence numbers
  - [ ] Load and increment `nextSeqNum`
  - [ ] Add `seqNum` to entry
  - [ ] Store `auditKeyId` instead of embedded pubkey
  - [ ] Persist updated sequence counter

**Acceptance Criteria**:
- Audit key is non-extractable by default
- Explicit export requires auth
- Sequence numbers are monotonic
- keyId reference instead of embedded pubkey

---

### 5.2. Audit Chain Verification

**Location**: `src/audit.ts` (update existing)

**Tasks**:

- [ ] Update `verifyAuditChain()` for V2
  - [ ] Load audit key config once (by keyId)
  - [ ] Check sequence number continuity
  - [ ] Verify chain hashes
  - [ ] Verify Ed25519 signatures
  - [ ] Return detailed errors

- [ ] Add anchor support (optional)
  - [ ] Create `AuditAnchor` interface
  - [ ] Implement `anchorChainHash()` function
  - [ ] Store anchors in separate store
  - [ ] Verify anchors in chain verification

**Acceptance Criteria**:
- Verification detects sequence gaps
- Verification detects chain tampering
- Anchors prevent truncation (if implemented)

---

## Phase 6: Client Updates

### 6.1. Update `kms-user.ts` for V2

**Location**: `src/kms-user.ts` (update existing)

**Tasks**:

- [ ] Update method signatures to include credentials
  - [ ] `generateVAPID(credentials?: AuthCredentials)`
  - [ ] `signJWT(kid, payload, credentials?: AuthCredentials)`

- [ ] Add credential storage (optional)
  - [ ] Store credentials in memory after unlock
  - [ ] Auto-pass credentials to operations
  - [ ] Clear on lock/timeout

- [ ] Update unlock methods
  - [ ] Return credential object for subsequent ops
  - [ ] Validate credentials format

**Acceptance Criteria**:
- Client can pass credentials to operations
- Unlock returns credentials for reuse
- Credentials are cleared appropriately

---

## Phase 7: Testing

### 7.1. Unit Tests

**Tasks**:

- [ ] Test calibration algorithm
  - [ ] Mock performance.now()
  - [ ] Test scaling logic
  - [ ] Test clamping
  - [ ] Test recalibration triggers

- [ ] Test KCV
  - [ ] Determinism
  - [ ] Constant-time comparison
  - [ ] Edge cases

- [ ] Test AAD construction
  - [ ] Determinism
  - [ ] JSON canonicalization
  - [ ] Binary output

- [ ] Test MS encryption with AAD
  - [ ] Successful encrypt/decrypt
  - [ ] AAD mismatch fails
  - [ ] IV reuse detection

- [ ] Test MKEK derivation
  - [ ] Deterministic salt
  - [ ] Same MS → same MKEK
  - [ ] Different MS → different MKEK

- [ ] Test key wrapping with AAD
  - [ ] Successful wrap/unwrap
  - [ ] AAD mismatch fails
  - [ ] Cannot swap wrapped keys

- [ ] Test multi-enrollment
  - [ ] Add second method
  - [ ] Both methods unlock to same MS
  - [ ] Remove method

- [ ] Test audit sequence numbers
  - [ ] Monotonic increment
  - [ ] Gap detection
  - [ ] Truncation detection

**Acceptance Criteria**:
- All unit tests pass
- 100% code coverage maintained
- Edge cases covered

---

### 7.2. Integration Tests

**Tasks**:

- [ ] Test full setup + unlock flow (V2)
  - [ ] Calibration runs
  - [ ] KCV verification works
  - [ ] AAD verified on decrypt

- [ ] Test per-operation auth
  - [ ] generateVAPID requires credentials
  - [ ] signJWT requires credentials
  - [ ] No persistent unlock state

- [ ] Test multi-enrollment scenarios
  - [ ] Setup passphrase, add passkey
  - [ ] Setup passkey, add passphrase
  - [ ] Unlock with either method

- [ ] Test V1 config detection
  - [ ] Loading V1 config throws error
  - [ ] Reset required message

- [ ] Test audit chain integrity
  - [ ] Sequence numbers continuous
  - [ ] Chain hashes valid
  - [ ] Signatures valid

**Acceptance Criteria**:
- All integration tests pass
- Realistic user scenarios work
- Error handling is correct

---

### 7.3. Browser Compatibility Tests

**Tasks**:

- [ ] Test calibration on different devices
  - [ ] Desktop (fast CPU)
  - [ ] Mobile (slow CPU)
  - [ ] Results in 150-300ms range

- [ ] Test WebAuthn PRF
  - [ ] Chrome/Edge (PRF supported)
  - [ ] Safari (may need gate-only)
  - [ ] Firefox (check PRF support)

- [ ] Test performance targets
  - [ ] Setup passphrase: 150-300ms
  - [ ] Unlock passphrase: 150-300ms
  - [ ] Generate VAPID: <100ms
  - [ ] Sign JWT: <50ms

**Acceptance Criteria**:
- Works on all target browsers
- Performance targets met
- Graceful degradation (PRF → gate)

---

## Phase 8: Documentation Updates

### 8.1. Update Implementation Docs

**Tasks**:

- [ ] Update CLAUDE.md for V2
  - [ ] Reference V2 docs
  - [ ] Update config schema examples
  - [ ] Add V2 migration notes

- [ ] Create V2 migration guide
  - [ ] Export V1 data (if possible)
  - [ ] Reset procedure
  - [ ] V2 setup procedure

- [ ] Update README with V2 status

**Acceptance Criteria**:
- All docs reference V2
- Migration path clear
- Breaking changes documented

---

### 8.2. Update Design Docs

**Tasks**:

- [ ] Mark V1 docs as deprecated
  - [ ] Add banner to V1 docs
  - [ ] Link to V2 equivalents

- [ ] Create V2 design component docs
  - [ ] 01-primitives.md
  - [ ] 02-master-secret.md
  - [ ] 03-unlock-context.md
  - [ ] 04-key-operations.md
  - [ ] 05-audit-log.md
  - [ ] 06-multi-enrollment.md
  - [ ] 07-calibration.md
  - [ ] 08-security-model.md
  - [ ] 09-backup-export.md

**Acceptance Criteria**:
- V2 docs complete and accurate
- V1 docs clearly deprecated
- Design components match implementation

---

## Phase 9: Migration & Deployment

### 9.1. V1 → V2 Migration

**Tasks**:

- [ ] Create migration detection
  - [ ] Check kmsVersion on load
  - [ ] Show migration prompt if V1 detected

- [ ] Create reset procedure
  - [ ] Clear all V1 configs
  - [ ] Clear wrapped keys
  - [ ] Preserve audit log (optional)

- [ ] Create V2 setup wizard
  - [ ] Run calibration
  - [ ] Setup first method
  - [ ] Offer to setup second method
  - [ ] Generate initial keys

**Acceptance Criteria**:
- Migration prompt clear
- Reset is safe (no data corruption)
- Setup wizard guides user

---

### 9.2. Deployment Checklist

**Tasks**:

- [ ] Run full test suite
  - [ ] Unit tests pass
  - [ ] Integration tests pass
  - [ ] Browser compat tests pass

- [ ] Security review
  - [ ] All V2 improvements implemented
  - [ ] No V1 code paths remain
  - [ ] AAD everywhere
  - [ ] KCV for password verification
  - [ ] Calibrated PBKDF2
  - [ ] Non-extractable audit key
  - [ ] Sequence numbers in audit

- [ ] Performance validation
  - [ ] Calibration targets met
  - [ ] Operation latency acceptable
  - [ ] No memory leaks

- [ ] Documentation complete
  - [ ] V2 docs published
  - [ ] Migration guide available
  - [ ] Breaking changes documented

**Acceptance Criteria**:
- All tests pass
- Security checklist complete
- Performance targets met
- Docs complete

---

## Success Criteria

### Must Have (MVP)

- ✅ PBKDF2 calibration working (150-300ms)
- ✅ AAD on all AES-GCM operations
- ✅ KCV for password verification
- ✅ Deterministic HKDF salts
- ✅ Audit sequence numbers
- ✅ Non-extractable audit key
- ✅ Multi-enrollment support
- ✅ Per-operation authentication
- ✅ All tests passing (100% coverage)

### Should Have

- ✅ Enhanced passkey gate (pepper)
- ✅ Explicit versioning everywhere
- ✅ V1 migration detection
- ✅ Recalibration logic
- ✅ Audit chain verification

### Nice to Have (Optional)

- ⏸️ Argon2id support (WASM)
- ⏸️ Audit anchors (external)
- ⏸️ Export ceremonies (backup)
- ⏸️ Multi-device sync

---

## Timeline Estimate

| Phase | Estimated Time | Priority |
|-------|----------------|----------|
| Phase 1: Core Primitives | 2-3 days | Critical |
| Phase 2: Storage Schema | 1 day | Critical |
| Phase 3: Unlock Module | 3-4 days | Critical |
| Phase 4: Worker Updates | 2-3 days | Critical |
| Phase 5: Audit Hardening | 2 days | Critical |
| Phase 6: Client Updates | 1 day | High |
| Phase 7: Testing | 3-4 days | Critical |
| Phase 8: Documentation | 1-2 days | High |
| Phase 9: Migration | 1-2 days | High |

**Total**: 16-22 days (3-4 weeks)

---

## Current Status

- [x] V2 architecture documentation
- [x] V2 cryptographic specification
- [x] V2 security improvements analysis
- [x] V2 implementation checklist (this document)
- [ ] Phase 1: Core Primitives
- [ ] Phase 2: Storage Schema
- [ ] Phase 3: Unlock Module
- [ ] Phase 4: Worker Updates
- [ ] Phase 5: Audit Hardening
- [ ] Phase 6: Client Updates
- [ ] Phase 7: Testing
- [ ] Phase 8: Documentation
- [ ] Phase 9: Migration

---

**Next**: Begin Phase 1 implementation (Core Primitives).

**Questions**: Review with team before starting implementation.
