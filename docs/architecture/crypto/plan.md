# Browser KMS Enclave - Implementation Plan

**Status**: 🚧 STUB - Awaiting Target State
**Dependencies**: target-state.md (incomplete)

## Purpose

This document defines the phased implementation roadmap for the verifiable KMS enclave, breaking down the work into manageable milestones with clear deliverables and success criteria.

## Development Methodology: Test-Driven Development (TDD)

**CRITICAL**: This project MUST follow strict Test-Driven Development practices with **100% code coverage** from the very beginning.

### TDD Requirements

**Every feature, from Phase 0 onwards, must**:
1. **Write tests first** - Before writing any production code
2. **Red-Green-Refactor** - Follow the TDD cycle:
   - Write a failing test (RED)
   - Write minimal code to pass (GREEN)
   - Refactor while keeping tests green (REFACTOR)
3. **100% coverage** - No exceptions, no compromises
4. **Test all paths** - Success paths, error paths, edge cases
5. **No untested code** - Code without tests must not be merged

### Why 100% Coverage is Critical

For a security-critical cryptographic system:
- **Cryptographic correctness** - Every crypto operation must be verified
- **Error handling** - All failure modes must be tested
- **Security guarantees** - Isolation boundaries must be validated
- **Regression prevention** - Changes cannot break existing guarantees
- **Auditability** - Tests serve as executable documentation

### TDD Applies To

- ✅ Crypto operations (key generation, signing, verification)
- ✅ RPC protocol (message handling, serialization)
- ✅ Error handling (all error paths)
- ✅ Browser API interactions (WebCrypto, IndexedDB, postMessage)
- ✅ Build scripts (determinism, hash generation)
- ✅ Verification tools (hash checking, signature validation)

### Measurement and Enforcement

**Coverage tooling**:
- Use `c8` or similar for coverage measurement
- Set coverage thresholds in `package.json`:
  ```json
  {
    "c8": {
      "all": true,
      "lines": 100,
      "functions": 100,
      "branches": 100,
      "statements": 100
    }
  }
  ```

**CI/CD enforcement**:
- Coverage checks run on every commit
- PRs cannot be merged if coverage drops below 100%
- Build fails if any code is untested

**Code review**:
- Tests reviewed before implementation code
- Test quality is as important as implementation quality
- Reviewers verify TDD process was followed

## Dependencies

This document depends on:
- ✅ [current-state.md](./current-state.md) - Completed (no KMS exists)
- ✅ [design.md](./design.md) - Completed (practical implementation guide)
- ✅ [target-state.md](./target-state.md) - Stub complete, ready for expansion

## Scope

Once target-state.md is complete, this document will define:

### Implementation Phases

**Phase 0: Prototype** (Proof of Concept - TDD from start)
- **Tests first**: Write test suite before implementation
- Minimal enclave (iframe + worker)
- VAPID key generation
- Basic postMessage RPC
- Validate assumptions
- **100% test coverage required**

**Phase 1: Basic Enclave** (MVP - TDD)
- **Tests first**: Comprehensive test suite before production code
- Production-ready enclave code
- ECDSA P-256 (ES256) support
- Single-file module build
- IndexedDB key storage
- Error handling
- **100% test coverage enforced in CI**

**Phase 2: Verifiable Build** (Critical)
- Deterministic esbuild pipeline
- Content-addressed artifacts
- SRI hash generation
- Reproducible build script
- CI/CD automation

**Phase 3: Transparency** (Production-Ready)
- Sigstore integration
- Release manifest schema
- Rekor transparency log
- Verification CLI tool
- Public release process

**Phase 4: User Verification** (Trust UX)
- Enclave version display
- "Verify" button in PWA
- Manual verification guide
- Hash mismatch warnings
- Source code linking

**Phase 5: OS Notifications Integration**
- VAPID key generation via enclave
- JWT signing for relay authorization
- Push subscription management
- Integration with notification system

**Phase 6: Signal Protocol** (Future)
- Ed25519 keypair generation
- X25519 key agreement
- libsignal WASM integration
- Session management

### Deliverables Per Phase

**Phase 0: Prototype**
- [ ] `tests/prototype/` - Test suite written FIRST
  - [ ] Worker crypto operation tests
  - [ ] RPC protocol tests
  - [ ] Browser API interaction tests
- [ ] `src/prototype/` - Minimal implementation (written after tests)
- [ ] Coverage report showing 100%

**Phase 1: Basic Enclave**
- [ ] **Tests written FIRST**:
  - [ ] `tests/unit/worker.test.ts` - All crypto operations
  - [ ] `tests/unit/main.test.ts` - RPC message handling
  - [ ] `tests/unit/storage.test.ts` - IndexedDB operations
  - [ ] `tests/integration/rpc.test.ts` - End-to-end RPC
  - [ ] `tests/integration/browser-apis.test.ts` - WebCrypto, IndexedDB
- [ ] **Production code** (written after tests):
  - [ ] `packages/enclave/src/index.ts` (enclave main)
  - [ ] `packages/enclave/src/worker.ts` (crypto worker)
  - [ ] `packages/enclave/src/storage.ts` (IndexedDB key storage)
  - [ ] `packages/enclave/build/esbuild.ts` (build script)
  - [ ] `packages/enclave/public/kms.html` (iframe bootstrap)
  - [ ] `apps/pwa/src/lib/enclave-bridge.ts` (host integration)
- [ ] Coverage report: 100% (lines, branches, functions, statements)

**Phase 2: Verifiable Build**
- [ ] Deterministic build configuration
- [ ] Content-addressing script
- [ ] SRI hash generation
- [ ] Reproducible build documentation
- [ ] CI workflow (`.github/workflows/enclave-release.yml`)

**Phase 3: Transparency**
- [ ] Sigstore signing script
- [ ] Release manifest schema
- [ ] Rekor log publishing
- [ ] Verification CLI tool (`tools/verify-cli/`)
- [ ] Public release checklist

**Phase 4: User Verification**
- [ ] Enclave status component (React)
- [ ] Manual verification flow
- [ ] Hash comparison logic
- [ ] Error/warning UI
- [ ] User documentation

**Phase 5: OS Notifications Integration**
- [ ] Update notification system to use enclave
- [ ] VAPID key migration (if existing keys)
- [ ] JWT token generation
- [ ] Relay authorization flow
- [ ] End-to-end tests

### Success Criteria

**Phase 0: Prototype**
- ✅ All tests written before implementation
- ✅ 100% code coverage (lines, branches, functions, statements)
- ✅ All tests passing
- ✅ Basic crypto operations validated in browser
- ✅ TDD process documented

**Phase 1: Basic Enclave**
- ✅ All tests written before implementation code
- ✅ **100% code coverage** (lines, branches, functions, statements) - NO EXCEPTIONS
- ✅ All unit tests passing
- ✅ All integration tests passing
- ✅ Enclave loads in sandboxed iframe (<500ms)
- ✅ VAPID keypair generation works (<100ms)
- ✅ JWT signing works (<50ms)
- ✅ Keys verified as non-extractable
- ✅ Coverage enforced in CI pipeline

**Phase 2: Verifiable Build**
- ✅ Two independent builds produce identical output (byte-for-byte)
- ✅ SRI verification blocks tampered files
- ✅ Content-addressed filename matches computed hash
- ✅ CI pipeline runs successfully
- ✅ Build time <60 seconds

**Phase 3: Transparency**
- ✅ Release manifest signed with Sigstore
- ✅ Rekor entry created for release
- ✅ Verification CLI validates signature
- ✅ Public documentation published
- ✅ First release successfully deployed

**Phase 4: User Verification**
- ✅ Enclave hash displayed in PWA
- ✅ "Verify" button checks manifest
- ✅ Hash mismatch triggers warning
- ✅ User can view source code link
- ✅ Verification guide published

**Phase 5: OS Notifications Integration**
- ✅ Notifications use enclave for VAPID keys
- ✅ JWT delegation works end-to-end
- ✅ Relay authorization successful
- ✅ No security regressions
- ✅ Performance targets met

### Testing Strategy

**CRITICAL**: All testing follows strict TDD principles with 100% coverage requirement.

#### Test-Driven Development Process

**For every feature**:
1. **Write failing test** - Define expected behavior through tests
2. **Run test** - Verify it fails (RED)
3. **Write minimal code** - Just enough to pass the test
4. **Run test** - Verify it passes (GREEN)
5. **Refactor** - Improve code while keeping tests green
6. **Verify coverage** - Ensure 100% coverage maintained

#### Unit Tests (Test First, Always)

**Crypto Operations** (All must have 100% coverage):
- Key generation (ECDSA P-256, Ed25519, X25519)
- Signing operations (JWT, arbitrary data)
- Signature verification
- Key export/import (where applicable)
- DER ↔ P-1363 conversion
- Raw public key extraction
- JWK thumbprint calculation

**RPC Protocol**:
- Message serialization/deserialization
- Request/response pairing
- Timeout handling
- Error propagation
- Origin validation

**Error Handling** (Critical - must test all paths):
- Invalid input handling
- Browser API failures (WebCrypto, IndexedDB)
- Timeout scenarios
- Memory/quota limits
- Concurrent operation handling

**Storage**:
- IndexedDB operations
- Key persistence and retrieval
- Non-extractable key verification
- Storage quota handling

#### Integration Tests (Test First)

**Cross-Component Communication**:
- Enclave ↔ host PWA communication (postMessage)
- Main thread ↔ Worker communication
- IndexedDB persistence across sessions
- SRI verification (with tampered files)

**Browser API Integration**:
- WebCrypto operations in worker context
- IndexedDB in worker context
- postMessage across origins
- Sandbox isolation verification

**Multi-Browser Compatibility**:
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Chrome Android
- Safari iOS

#### End-to-End Tests

**Complete Workflows**:
- Full enclave initialization flow
- VAPID key generation → JWT signing → relay authorization
- Key rotation scenarios
- Error recovery flows
- Verification UX (manual verification button)

**Performance Benchmarks**:
- Enclave initialization time
- Key generation time
- Signing operation time
- RPC roundtrip latency

#### Build and Release Tests

**Determinism Verification**:
- Multiple builds produce identical output
- Content-addressed filenames match computed hash
- SRI hash correctness
- Timestamp normalization

**Signature Verification**:
- Sigstore signature validation
- Rekor transparency log integration
- Manifest schema validation

#### Test Quality Requirements

**All tests must**:
- Be written BEFORE implementation code
- Test one thing clearly
- Have descriptive names explaining what is tested
- Include both success and failure cases
- Test boundary conditions
- Verify error messages
- Run in isolation (no shared state)
- Complete in <100ms (unit tests)
- Be deterministic (no flaky tests)

**Coverage Requirements**:
- **100% line coverage** - Every line executed
- **100% branch coverage** - Every conditional path tested
- **100% function coverage** - Every function called
- **100% statement coverage** - Every statement executed
- **No exemptions** - No `/* istanbul ignore */` allowed

#### Manual Testing

**Cross-browser validation**:
- Chrome, Firefox, Safari (desktop)
- Chrome Android, Safari iOS (mobile PWA)

**Security validation**:
- Reproducible build verification
- Sigstore signature verification
- Hash mismatch behavior
- Sandbox isolation manual testing

#### CI/CD Test Automation

**Every commit must**:
- Run full test suite
- Generate coverage report
- Fail if coverage < 100%
- Fail if any test fails
- Block merge if tests don't pass

**Coverage reporting**:
- Display coverage in PR comments
- Track coverage trends over time
- Alert on coverage decreases
- Require maintainer override for any coverage drop

### Rollout Strategy

**Phase 1: Development** (Internal Only)
- Deploy to dev environment
- Test with development PWA
- Validate all functionality
- Measure performance

**Phase 2: Staging** (Limited Testing)
- Deploy to staging environment
- Beta testers validate enclave
- Community review of source code
- Security audit (if budget allows)

**Phase 3: Production** (Gradual Rollout)
- Feature flag: `USE_VERIFIABLE_KMS=true`
- Rollout to 1% of users
- Monitor for errors and performance issues
- Gradually increase to 100%

**Phase 4: Mandatory** (Full Adoption)
- Remove feature flag
- All users use verifiable KMS
- Deprecate legacy key management (if any)

### Risks & Mitigation

**Technical Risks**

| Risk | Impact | Mitigation |
|------|--------|------------|
| Browser compatibility issues | High | Extensive testing, graceful degradation |
| SRI breaks on some CDNs | Medium | Test with multiple CDN providers |
| Reproducible build fails | High | Validate early, fix nondeterminism sources |
| IndexedDB quota exceeded | Low | Monitor usage, implement cleanup |

**Security Risks**

| Risk | Impact | Mitigation |
|------|--------|------------|
| User ignores hash mismatch | High | Persistent warnings, disable sensitive actions |
| Compromised build pipeline | Critical | Sigstore transparency, multiple verifiers |
| Service Worker bypass SRI | Medium | Runtime self-check, CSP hardening |
| Browser sandbox escape | Critical | Defense in depth, keep browser updated |

**UX Risks**

| Risk | Impact | Mitigation |
|------|--------|------------|
| Users don't understand verification | Medium | Clear documentation, simple UX |
| Verification flow too complex | Low | Streamline UX, provide one-click verification |
| Performance degradation | Medium | Optimize worker communication, measure latency |

### Timeline (Estimated)

- **Phase 0: Prototype**: 1 week
- **Phase 1: Basic Enclave**: 2 weeks
- **Phase 2: Verifiable Build**: 1 week
- **Phase 3: Transparency**: 1 week
- **Phase 4: User Verification**: 1 week
- **Phase 5: OS Notifications Integration**: 2 weeks
- **Phase 6: Signal Protocol**: 4 weeks (future)

**Total (Phases 0-5)**: ~8 weeks

**Note**: Timeline assumes single developer, full-time. Adjust for team size and availability.

### Dependencies

**External Dependencies**:
- Sigstore/cosign (for signing)
- Rekor transparency log (public service)
- esbuild (deterministic builds)
- Browser support (Chrome 113+, Firefox 120+, Safari 17+)

**Testing Dependencies**:
- Vitest or similar (test runner with 100% coverage support)
- c8 or nyc (coverage measurement)
- Playwright or Puppeteer (browser automation for e2e tests)
- happy-dom or jsdom (DOM mocking for unit tests)
- msw (Mock Service Worker for network mocking)

**Internal Dependencies**:
- OS Notifications system (consumes enclave)
- Main PWA infrastructure (hosts iframe)
- CI/CD pipeline (GitHub Actions with coverage enforcement)
- Hosting infrastructure (for `kms.ats.run`)

### Monitoring & Metrics

**Test Coverage Metrics** (CRITICAL):
- Line coverage (must be 100%)
- Branch coverage (must be 100%)
- Function coverage (must be 100%)
- Statement coverage (must be 100%)
- Coverage trend over time
- Uncovered code alerts

**Test Quality Metrics**:
- Test execution time (target <5s for unit tests)
- Test failure rate (target 0%)
- Flaky test detection
- Test-to-code ratio
- Test review time

**Performance Metrics**:
- Enclave initialization time (p50, p95, p99)
- Key generation time (VAPID, Signal identity)
- Signing operation time (JWT, arbitrary data)
- RPC roundtrip latency

**Reliability Metrics**:
- Enclave load success rate
- SRI verification pass rate
- Key generation failure rate
- RPC timeout rate

**Security Metrics**:
- Hash mismatch detection rate
- Manual verification usage
- Sigstore verification success rate
- Reported security issues

**User Metrics**:
- Enclave adoption rate (% of users)
- Verification button click rate
- Hash mismatch warnings shown
- Source code link clicks

### Documentation Requirements

**Developer Documentation**:
- [ ] Enclave architecture overview
- [ ] TDD workflow guide
- [ ] Test writing guidelines
- [ ] Reproducible build guide
- [ ] Release process checklist
- [ ] Security considerations
- [ ] API reference

**Test Documentation**:
- [ ] Test structure and organization
- [ ] How to write tests first (TDD examples)
- [ ] Coverage requirements and enforcement
- [ ] Running tests locally
- [ ] CI/CD test pipeline
- [ ] Debugging failed tests
- [ ] Test quality standards

**User Documentation**:
- [ ] What is the KMS enclave?
- [ ] How to verify enclave integrity
- [ ] What to do if hash mismatch occurs
- [ ] FAQ (common questions)
- [ ] Troubleshooting guide

**Security Documentation**:
- [ ] Threat model
- [ ] Security guarantees and limitations
- [ ] Incident response plan
- [ ] Responsible disclosure policy
- [ ] Security audit reports (if available)

## Next Steps

1. **Set up testing infrastructure**: Configure test runner, coverage tools, CI enforcement
2. **Complete target-state.md**: Define ideal KMS with all features
3. **Write tests for Phase 0**: Create test suite for prototype (TDD)
4. **Prototype**: Build minimal enclave (Phase 0) - tests first!
5. **Validate assumptions**: Test browser compatibility, performance
6. **Finalize plan**: Adjust timeline based on prototype learnings
7. **Begin Phase 1**: Implement production-ready enclave (TDD from start)

## Related Documents

- [current-state.md](./current-state.md) - Current key management baseline
- [design.md](./design.md) - Detailed design and practical guide
- [target-state.md](./target-state.md) - Ideal KMS architecture (must complete first)
- [../../os-notifications/plan.md](../../os-notifications/plan.md) - Reference for structure
