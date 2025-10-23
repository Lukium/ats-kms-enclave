# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains the **browser-based verifiable Key Management System (KMS) enclave** for AllTheServices (ATS). The KMS enclave is a sandboxed, verifiable execution environment for cryptographic operations, designed to provide user-auditable security guarantees.

**Current Status**: Architecture design phase complete, implementation not yet started.

## What This Repository Will Contain

This will be a **standalone web application** that:
- Runs in a sandboxed cross-origin iframe (`kms.ats.run`)
- Manages non-extractable cryptographic keys using WebCrypto API
- Provides cryptographic services to the main PWA via postMessage
- Uses reproducible builds with content-addressed artifacts
- Enables community verification through Subresource Integrity (SRI) and transparency logs

## Core Architecture Principles

### 1. Separate Application Design
The KMS enclave is NOT a component of the main PWA—it's a completely separate application:
- **Different origin**: `kms.ats.run` vs `ats.run` (browser-enforced isolation)
- **Minimal codebase**: Target ~500 lines (simple enough to audit)
- **Static hosting**: Immutable, content-addressed artifacts
- **Zero network access**: Only same-origin requests for self-verification

### 2. Defense in Depth Security
Multiple independent security layers:
1. **Cross-origin isolation**: Browser prevents parent PWA from accessing enclave internals
2. **Sandboxed iframe**: `sandbox="allow-scripts allow-same-origin"` (safe due to cross-origin)
3. **Dedicated Worker**: Crypto operations isolated from DOM, no phishing vector
4. **Non-extractable keys**: WebCrypto `extractable: false` enforced by browser
5. **SRI verification**: Browser validates hash before executing code
6. **Runtime self-check**: Enclave verifies its own integrity at startup
7. **Reproducible builds**: Community can verify artifacts match source

### 3. Verifiability First
Every design decision prioritizes user auditability:
- Content-addressed filenames (hash in filename)
- Deterministic builds (anyone can rebuild and verify)
- Transparency logs (Sigstore/Rekor for public record)
- Simple codebase (small enough for security researchers to audit)

## Architecture Documentation

**All architectural decisions are documented in `docs/architecture/crypto/`:**

### Core Documents

- **[README.md](docs/architecture/crypto/README.md)**: Complete overview, security model, design principles (~530 lines)
- **[current-state.md](docs/architecture/crypto/current-state.md)**: Baseline (no implementation exists yet)
- **[design.md](docs/architecture/crypto/design.md)**: Design index with links to all components (now concise!)
- **[target-state.md](docs/architecture/crypto/target-state.md)**: Ideal end state specification
- **[plan.md](docs/architecture/crypto/plan.md)**: Implementation phases and roadmap

### Detailed Design Components (`docs/architecture/crypto/design/`)

The detailed design has been broken down into focused, readable components:

- **[01-overview-and-architecture.md](docs/architecture/crypto/design/01-overview-and-architecture.md)**: Design goals, architecture diagram, security properties
- **[02-security-decisions.md](docs/architecture/crypto/design/02-security-decisions.md)**: Critical security rationale (sandbox, SRI)
- **[03-component-design.md](docs/architecture/crypto/design/03-component-design.md)**: Complete TypeScript implementations for all 3 components
- **[04-build-pipeline.md](docs/architecture/crypto/design/04-build-pipeline.md)**: Reproducible builds, Sigstore integration
- **[05-security-model.md](docs/architecture/crypto/design/05-security-model.md)**: Security boundaries, threat model, design questions
- **[06-implementation-guide.md](docs/architecture/crypto/design/06-implementation-guide.md)**: ⚠️ **CRITICAL** - Production-ready guide with VAPID/JWT solutions
- **[README.md](docs/architecture/crypto/design/README.md)**: Index with quick reference and implementation warnings

**Read these documents before implementing features or making architectural decisions.**

### Quick Navigation

**For understanding the system**:
1. Start with [crypto/README.md](docs/architecture/crypto/README.md)
2. Read [design/01-overview-and-architecture.md](docs/architecture/crypto/design/01-overview-and-architecture.md)
3. Review [design/05-security-model.md](docs/architecture/crypto/design/05-security-model.md)

**For implementation**:
1. Study [design/03-component-design.md](docs/architecture/crypto/design/03-component-design.md)
2. **Must read**: [design/06-implementation-guide.md](docs/architecture/crypto/design/06-implementation-guide.md)
3. Follow [design/04-build-pipeline.md](docs/architecture/crypto/design/04-build-pipeline.md)

## Critical Implementation Warnings ⚠️

**Before implementing, read [design/06-implementation-guide.md](docs/architecture/crypto/design/06-implementation-guide.md)** - it contains critical solutions to common pitfalls:

### 1. ECDSA Signature Format (CRITICAL for JWT)
- **Problem**: WebCrypto returns DER-encoded signatures (~70-72 bytes), but JWS ES256 requires P-1363 format (exactly 64 bytes)
- **Impact**: If you base64url-encode DER directly, **JWT validation will fail**
- **Solution**: Must convert DER → P-1363 before building JWT (conversion code provided in implementation guide)

### 2. VAPID Public Key Format (CRITICAL for Push)
- **Problem**: `PushManager.subscribe()` expects 65-byte uncompressed raw format, WebCrypto exports SPKI (~91 bytes)
- **Impact**: If you pass SPKI, **push subscription will fail**
- **Solution**: Must extract/convert to raw format (conversion code provided in implementation guide)

### 3. Production-Ready Utilities
The implementation guide ([design/06-implementation-guide.md](docs/architecture/crypto/design/06-implementation-guide.md)) includes:
- **Drop-in ES256 utilities** (~500 lines of tested code)
- DER ↔ P-1363 converters
- Raw public key exporters
- Complete VAPID JWT signing
- RFC 8292 VAPID header builders

**These are production-ready and should be used as-is** - they handle all the edge cases.

## Key Design Decisions (from Architecture Docs)

### Sandbox Configuration
- Uses `sandbox="allow-scripts allow-same-origin"` despite common warnings against `allow-same-origin`
- **Safe** because enclave is on different origin (browser enforces isolation)
- **Necessary** for runtime self-check (`fetch(import.meta.url)`) and reliable IndexedDB
- Details in [design/02-security-decisions.md](docs/architecture/crypto/design/02-security-decisions.md)

### SRI Verification Flow
- SRI does **not** work on `<iframe>` elements (browsers ignore it)
- SRI is applied to `<script type="module">` tags inside `kms.html`
- Runtime self-check provides additional verification layer
- Details in [design/02-security-decisions.md](docs/architecture/crypto/design/02-security-decisions.md)

### Non-Extractable Keys
- Keys generated with `extractable: false` parameter in WebCrypto
- Browser enforces at crypto subsystem level - **cannot be exported even by compromised enclave**
- Stored in IndexedDB as CryptoKey objects, used via handles only
- Implementation in [design/03-component-design.md](docs/architecture/crypto/design/03-component-design.md)

## Repository Structure (Planned)

```
ats-kms/
├── docs/architecture/crypto/     # Architecture documentation (exists)
├── src/
│   ├── main.ts                   # Enclave main thread (iframe)
│   ├── worker.ts                 # Dedicated Worker (crypto operations)
│   └── storage.ts                # IndexedDB key storage
├── public/
│   └── kms.html                  # Iframe bootstrap with SRI
├── build/
│   ├── esbuild.config.ts         # Deterministic build configuration
│   └── content-address.ts        # Hash-based filename generation
├── tools/
│   ├── verify-cli/               # CLI tool for manual verification
│   └── release/                  # Sigstore signing scripts
└── tests/
    ├── unit/                     # Crypto operation tests
    ├── integration/              # PostMessage protocol tests
    └── e2e/                      # Browser compatibility tests
```

## Development Commands

### Pre-Commit Requirements (MANDATORY)

**CRITICAL**: Before ANY commit, all quality checks MUST pass without errors.

**Recommended: Use the Makefile**
```bash
make pre-commit   # Runs test, typecheck, and lint in sequence
```

**Or run manually**:
```bash
pnpm test         # All tests must pass
pnpm typecheck    # TypeScript must compile without errors
pnpm lint         # ESLint must pass without errors
```

**Commit workflow**:
1. Write/modify code following TDD
2. Run `make pre-commit`
3. Fix any errors
4. Only then attempt `git commit`

**Never skip these checks**. They prevent broken code from entering version control and ensure consistent quality.

**Makefile targets**:
```bash
make help         # Show all available commands
make install      # Install dependencies
make test         # Run tests only
make typecheck    # Type check only
make lint         # Lint only
make pre-commit   # Run all checks (recommended)
make clean        # Remove generated files
```

### Testing
```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run tests with coverage report
pnpm test:coverage

# Run tests with UI
pnpm test:ui
```

### Type Checking and Linting
```bash
# Type check without emitting files
pnpm typecheck

# Lint all TypeScript files
pnpm lint
```

### Building (To Be Implemented)
```bash
# Development build (not reproducible)
pnpm build:dev

# Reproducible build (deterministic output)
pnpm build:reproducible
```

## Commit Guidelines

### Commit Message Format

**Write comprehensive, well-structured commit messages.**

```
<type>: <short summary> (50 chars or less)

<detailed description explaining what and why>

- Key change 1
- Key change 2
- Key change 3

<optional footer>
```

**Types**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`

### File Grouping Rules

**Group together** (single commit):
- ✅ Test file + implementation file for same feature
- ✅ Multiple files that together implement one feature
- ✅ Configuration + code that uses it
- ✅ Documentation + code it documents

**Keep separate** (different commits):
- ❌ Two unrelated bug fixes
- ❌ New feature + refactoring of old code
- ❌ Multiple independent features

### Atomic Commits

- Each commit = one complete, working change
- All tests must pass at every commit
- Should be revertable cleanly
- Makes code review and git bisect easier

### Example Good Commit

```
feat: Add VAPID key generation to KMS worker

Implement P-256 ECDSA key generation with non-extractable private keys
for VAPID authentication. This is Phase 0 of the KMS implementation.

- Add generateVAPIDKeypair() function in worker.ts
- Add comprehensive tests for key generation and signing
- Add RPC protocol tests for key generation method
- Document DER vs P-1363 signature format differences

Tests include verification of:
- Non-extractable private keys
- Correct algorithm parameters (P-256, ES256)
- Signature generation and verification
- Performance requirements (<100ms key gen)

Phase 0 deliverable: Proof of concept for browser crypto operations
```

**See [plan.md](docs/architecture/crypto/plan.md#commit-message-guidelines) for full guidelines.**

## Implementation Phases

### Phase 0: Prototype (Current: Not Started)
- Minimal enclave (iframe + worker)
- VAPID key generation proof-of-concept
- Validate browser compatibility assumptions

### Phase 1: Basic Enclave
- Production-ready enclave code (~500 lines)
- VAPID keypair generation (ECDSA P-256)
- JWT signing for relay authorization
- IndexedDB storage for non-extractable keys
- PostMessage RPC protocol

### Phase 2: Verifiable Build
- Deterministic esbuild configuration
- Content-addressed artifact generation
- SRI hash computation
- Reproducible build documentation

### Phase 3: Transparency
- Sigstore/cosign integration
- Rekor transparency log publishing
- Verification CLI tool
- Public release process

### Phase 4: User Verification UX
- Enclave version/hash display in PWA
- Manual verification guide
- Hash mismatch warnings

### Phase 5: OS Notifications Integration
- Integration with main ATS PWA
- VAPID key generation for Web Push
- JWT token signing for relay authorization

### Phase 6: Signal Protocol (Future)
- Ed25519 identity keys
- X25519 key agreement
- Double Ratchet implementation

## Critical Implementation Guidelines

### Security Principles
1. **Fail secure**: Errors must halt execution, never degrade security
2. **Minimal privileges**: KMS has zero network access except self-verification
3. **Explicit over implicit**: All operations require explicit requests
4. **Auditability**: Log all operations for debugging (no sensitive data)

### Code Style
1. **Simplicity**: Target ~500 lines total - favor clarity over cleverness
2. **No dependencies**: Minimal external libraries (reduces audit surface)
3. **TypeScript strict mode**: Catch errors at compile time
4. **Comprehensive tests**: >95% coverage for crypto operations

### Build Requirements
1. **Deterministic**: Same source → same artifact (byte-for-byte)
2. **Pinned dependencies**: Lockfile committed, no version ranges
3. **Timestamp normalization**: Fixed `SOURCE_DATE_EPOCH`
4. **Sorted inputs**: Consistent file ordering

## Communication Protocol

The enclave exposes a minimal API via postMessage:

```typescript
// Main PWA → KMS Enclave
type Request =
  | { type: 'generateVAPID' }
  | { type: 'signJWT', payload: JWTPayload }
  | { type: 'resetVAPID' }
  | { type: 'exportPublicKey' }

// KMS Enclave → Main PWA
type Response =
  | { requestId: string, data: any }
  | { requestId: string, error: string }
```

All communication is:
- Explicit (no ambient authority)
- Origin-checked (verify sender/receiver)
- Timeout-protected (fail after 10s)
- Auditable (logged for debugging)

## Browser Compatibility

**Target browsers** (all support required WebCrypto primitives):
- Chrome/Edge 120+
- Firefox 120+
- Safari 17+ (macOS 13+)
- Chrome Android (PWA)
- Safari iOS 16.4+ (PWA)

**Required APIs**:
- WebCrypto (ECDSA P-256, Ed25519, X25519, AES-GCM, HKDF)
- IndexedDB (CryptoKey storage)
- Web Workers (Dedicated Worker)
- Sandboxed iframes with cross-origin isolation
- Subresource Integrity (SRI)

## Threat Model

### Protected Against
✅ Malicious PWA updates (isolation prevents key access)
✅ Supply chain attacks (reproducible builds + SRI)
✅ CDN compromise (SRI verification)
✅ Service Worker tampering (SRI + runtime self-check)

### NOT Protected Against
❌ Malicious browser extensions (can access all data)
❌ Compromised OS (memory access)
❌ Physical device access (cold boot, memory dumps)
❌ Browser implementation bugs (sandbox escapes)

### Trust Assumptions
**Must trust**: Browser vendor, OS, hardware, user device security

**Do NOT need to trust**: ATS developers (code is verifiable), CDN (SRI catches tampering), network (HTTPS + SRI), build service (reproducible)

## Common Development Workflows

### Adding a New Crypto Operation
1. Review [design/03-component-design.md](docs/architecture/crypto/design/03-component-design.md) for component structure
2. Check [design/06-implementation-guide.md](docs/architecture/crypto/design/06-implementation-guide.md) for patterns and utilities
3. Add operation to worker.ts (crypto implementation)
4. Add RPC handler to main.ts (message routing)
5. Update types in protocol definition
6. Add unit tests (crypto correctness)
7. Add integration tests (end-to-end flow)
8. Update documentation

### Making Architectural Changes
1. Propose change in architecture docs first
2. Review relevant design component:
   - Security changes → [design/02-security-decisions.md](docs/architecture/crypto/design/02-security-decisions.md)
   - Component changes → [design/03-component-design.md](docs/architecture/crypto/design/03-component-design.md)
   - Build changes → [design/04-build-pipeline.md](docs/architecture/crypto/design/04-build-pipeline.md)
   - Security model → [design/05-security-model.md](docs/architecture/crypto/design/05-security-model.md)
3. Validate against security principles (verifiability, isolation, fail-secure)
4. Update affected design documents
5. Get security review if changing isolation boundaries
6. Implement with tests
7. Update CLAUDE.md if workflow changes

### Preparing a Release
1. Follow [design/04-build-pipeline.md](docs/architecture/crypto/design/04-build-pipeline.md) build process
2. Run reproducible build
3. Verify build determinism (compare with CI)
4. Generate content-addressed filenames
5. Compute SRI hashes
6. Sign with Sigstore/cosign
7. Publish to Rekor transparency log
8. Deploy immutable artifacts
9. Update verification documentation

### Reading Large Design Files
The implementation guide is ~1440 lines. When reading:
```bash
# Read specific sections using offset/limit
Read file_path="docs/architecture/crypto/design/06-implementation-guide.md" offset=1 limit=200

# Or search for specific topics
Grep pattern="DER.*P-1363" path="docs/architecture/crypto/design/" output_mode="content"
```

## Important: Read Architecture Docs First

Before implementing any feature or making design decisions:

**High-level understanding**:
1. **[crypto/README.md](docs/architecture/crypto/README.md)** - Overview and security model
2. **[design/01-overview-and-architecture.md](docs/architecture/crypto/design/01-overview-and-architecture.md)** - Goals and architecture
3. **[design/05-security-model.md](docs/architecture/crypto/design/05-security-model.md)** - Threat model and boundaries

**Implementation details**:
1. **[design/03-component-design.md](docs/architecture/crypto/design/03-component-design.md)** - Component structure
2. **[design/06-implementation-guide.md](docs/architecture/crypto/design/06-implementation-guide.md)** - ⚠️ MUST READ before coding
3. **[design/04-build-pipeline.md](docs/architecture/crypto/design/04-build-pipeline.md)** - Build and release process

**Planning**:
1. **[plan.md](docs/architecture/crypto/plan.md)** - Implementation phases and roadmap

The architecture documents are the source of truth. When in doubt, refer to them rather than making assumptions.
