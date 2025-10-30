# AllTheServices KMS Enclave

**Browser-based verifiable Key Management System (KMS) enclave for AllTheServices**

[![Status](https://img.shields.io/badge/status-design%20phase-yellow)](docs/architecture/crypto/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

This repository contains a sandboxed, verifiable execution environment for cryptographic operations in the AllTheServices Progressive Web App. The KMS enclave provides user-auditable security guarantees through cross-origin isolation, Subresource Integrity (SRI), and reproducible builds.

**Key Features**:
- 🔒 **Cross-origin isolation** - Runs at `kms.ats.run`, separate from main PWA
- 🔐 **Non-extractable keys** - WebCrypto keys cannot be exported
- ✅ **Reproducible builds** - Anyone can verify artifacts match source
- 📝 **Transparency logs** - All releases published to Sigstore/Rekor
- 🔍 **User-auditable** - Simple codebase (~500 lines target)
- 🧪 **80%+ test coverage** - Strict TDD from day one

## Current Status

**Phase 0: Prototype** ✅ **COMPLETE**

- ✅ 108 tests passing (100% coverage)
- ✅ Worker-based RPC handler
- ✅ Client-side bridge implementation
- ✅ VAPID key generation
- ✅ ES256 JWT signing
- ✅ Interactive demo

**[Try the demo →](example/phase-0/README.md)** `make demo-phase-0`

See [docs/architecture/crypto/plan.md](docs/architecture/crypto/plan.md) for the implementation roadmap.


### Test Coverage & Statistics

<!-- AUTO-GENERATED: Do not edit manually -->
*Last updated: 2025-10-30 18:43:17 UTC*

**Test Results:**
- Test Files: 9 passed (9)
- Tests: 389 passed (389)
- Duration: 22.83s

**Coverage Report:**
```
File                │ Lines   │ % Stmts │ % Branch │ % Funcs │ % Lines │ Uncovered
────────────────────────────────────────────────────────────────────────────────────────────────────
All files           │ 11684   │   83.81│    84.81 │   85.71│   83.81 │
 v2/audit.ts        │ 614     │   99.18│    96.15 │     100│   99.18 │ 5 lines
 v2/client.ts       │ 1225    │   36.71│    83.78 │   66.66│   36.71 │ 593 lines
 v2/crypto-utils.ts │ 415     │   95.65│    95.45 │   94.44│   95.65 │ 18 lines
 v2/error-utils.ts  │ 95      │     100│      100 │     100│     100 │ 
 v2/kms-user.ts     │ 862     │   87.34│    72.22 │   67.74│   87.34 │ 109 lines
 v2/rpc-validation.ts│ 541     │   94.81│    89.09 │   94.11│   94.81 │ 28 lines
 v2/storage-types.ts│ 50      │   87.75│    50.00 │     100│   87.75 │ 6 lines
 v2/storage.ts      │ 649     │   93.95│    88.60 │   97.72│   93.95 │ 37 lines
 v2/unlock.ts       │ 458     │   99.12│    93.02 │     100│   99.12 │ 4 lines
 v2/webauthn-types.ts│ 105     │   93.26│    18.18 │   66.66│   93.26 │ 7 lines
 v2/worker.ts       │ 1629    │   86.85│    78.77 │   79.31│   86.85 │ 214 lines
```
<!-- END AUTO-GENERATED -->

## Documentation

### Quick Start

- **[CLAUDE.md](CLAUDE.md)** - Guidance for AI assistants working with this codebase
- **[docs/architecture/crypto/README.md](docs/architecture/crypto/README.md)** - Architecture overview
- **[docs/architecture/crypto/design/](docs/architecture/crypto/design/)** - Detailed design components
- **[docs/architecture/crypto/DOMAINS.md](docs/architecture/crypto/DOMAINS.md)** - Domain architecture
- **[docs/architecture/crypto/plan.md](docs/architecture/crypto/plan.md)** - Implementation plan

### Architecture Components

The design has been broken down into focused documents:

1. **[Overview and Architecture](docs/architecture/crypto/design/01-overview-and-architecture.md)** - Goals, principles, architecture diagram
2. **[Security Decisions](docs/architecture/crypto/design/02-security-decisions.md)** - Critical security rationale
3. **[Component Design](docs/architecture/crypto/design/03-component-design.md)** - Complete TypeScript implementations
4. **[Build Pipeline](docs/architecture/crypto/design/04-build-pipeline.md)** - Reproducible builds, Sigstore
5. **[Security Model](docs/architecture/crypto/design/05-security-model.md)** - Threat model, boundaries
6. **[Implementation Guide](docs/architecture/crypto/design/06-implementation-guide.md)** - Production-ready guide with VAPID/JWT solutions

## Security Model

### What This Provides

✅ **Isolated key management** - Keys cannot be accessed by compromised PWA
✅ **Verifiable integrity** - Users can verify code matches published source
✅ **Transparent releases** - All builds logged publicly (Sigstore/Rekor)
✅ **Defense in depth** - Multiple independent security layers

### What This Requires

🔒 **Trust in**: Browser vendor, OS, hardware, user device security

⚖️ **Verification replaces blind trust in**: CDN, network operators, ATS developers, and build services — each release can be independently verified via SRI, reproducible builds, and transparency logs.

### Threat Model

**Defends against**:
- Malicious PWA updates
- CDN compromise
- Supply chain attacks
- MITM attacks
- Service Worker tampering

**Does NOT defend against**:
- Malicious browser extensions
- Compromised OS
- Physical device access
- Browser implementation bugs

See [Security Model](docs/architecture/crypto/design/05-security-model.md) for details.

### Web Enclave vs. Native OS Applications

Traditional native applications depend on **blind trust in the developer and app store** — users cannot independently verify that the compiled binary they run matches the published source. Even hardware-backed key storage (e.g., Secure Enclave, TPM) provides little assurance if an update is malicious or compromised.

Our approach takes a different path:

**Web-based verifiable architecture**:
- Built entirely with web technologies, loaded from a dedicated origin (`kms.ats.run`)
- Every release is **publicly logged**, **reproducible**, and **hash-verifiable** in the browser
- Verification can be automated (e.g., via GitHub Actions) to confirm running code matches public release
- **Single codebase** works across all platforms with modern browsers

**The tradeoff**: While native applications can leverage stronger OS-level isolation primitives, our model achieves **stronger global trust** through verifiability, transparency, and platform neutrality. In practice, this can yield a *higher trust ceiling* — not because the code is unbreakable, but because **it's impossible to hide a break**.

This positions the KMS enclave as a forward-looking trust model: **shifting trust from authority to transparency**.

## Development

### Test-Driven Development (TDD)

**CRITICAL**: This project follows strict TDD with **80% minimum code coverage** requirement.

- ✅ Tests written FIRST, before implementation
- ✅ 80% minimum line, branch, function, and statement coverage
- ✅ No exceptions, no compromises
- ✅ CI blocks merges if coverage < 80%

See [Implementation Plan](docs/architecture/crypto/plan.md) for full TDD requirements.

### Prerequisites

- Node.js 18+ (for build tools)
- pnpm (package manager)
- Modern browser (Chrome 120+, Firefox 120+, or Safari 17+)

### Getting Started

```bash
# Install dependencies
make install
# or: pnpm install

# Before committing (MANDATORY)
make pre-commit

# Run tests
make test
# or: pnpm test

# Type check
make typecheck
# or: pnpm typecheck

# Lint
make lint
# or: pnpm lint

# See all available commands
make help
```

### Try the Demo

See the Phase 0 prototype in action:

```bash
# Run interactive demo in browser
make demo-phase-0
# or: make demo (alias to latest phase)
# or: pnpm demo:phase-0
```

This opens an interactive demo at `http://localhost:5173` that demonstrates:
- VAPID keypair generation
- JWT token signing
- Public key retrieval
- Complete workflow validation

See [example/phase-0/README.md](example/phase-0/README.md) for more details.

### Development Workflow

1. Write tests first (TDD)
2. Implement code to pass tests
3. Run `make pre-commit` before committing
4. Fix any errors
5. Commit only when all checks pass

## Repository Structure

```
ats-kms/
├── docs/architecture/crypto/  # Architecture documentation (complete)
│   ├── README.md              # Overview
│   ├── design/                # Detailed design components
│   ├── DOMAINS.md             # Domain architecture
│   ├── plan.md                # Implementation roadmap
│   ├── current-state.md       # Baseline (no implementation yet)
│   └── target-state.md        # Ideal end state
├── src/                       # Source code (to be implemented)
├── tests/                     # Test suite (to be implemented)
├── build/                     # Build configuration (to be implemented)
├── tools/                     # Verification CLI (to be implemented)
├── CLAUDE.md                  # AI assistant guidance
└── README.md                  # This file
```

## Contributing

This is a security-critical project. All contributions must:

1. **Follow TDD** - Write tests first, achieve 80%+ coverage
2. **Maintain verifiability** - Keep codebase simple and auditable
3. **Document decisions** - Update architecture docs when needed
4. **Pass CI checks** - All tests, coverage, and linting must pass

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Verification

### For Users

When the enclave is deployed, you can verify its integrity:

1. Check the enclave version in the PWA UI
2. Click "Verify" to compare hash against published manifest
3. Manually verify via CLI: `npx @ats/verify-kms <hash>`

See [Verification Guide](docs/architecture/crypto/design/06-implementation-guide.md#verification-ux) for details.

### For Developers

Verify reproducible builds:

```bash
# Clone repository
git clone https://github.com/Lukium/ats-kms-enclave
cd ats-kms-enclave

# Checkout specific version
git checkout v1.0.0

# Build reproducibly
pnpm build:reproducible

# Compare hash with published artifacts
pnpm verify:build
```

## License

MIT License - See [LICENSE](LICENSE) for details.

This project is designed to be auditable and verifiable by the community. The permissive license encourages security review and independent verification.

## Security

### Reporting Security Issues

**Do not** open public issues for security vulnerabilities.

Email security concerns to: `security@ats.run`

We will respond within 48 hours and work with you to address the issue.

### Security Audits

- [ ] Independent security audit (planned post-implementation)
- [ ] Community security review (ongoing)
- [ ] Reproducible build verification (automated)

## Related Projects

- **[AllTheServices PWA](https://allthe.services)** - Main platform (private repository)
- **Relay Infrastructure** - Distributed relay nodes (private repository)

## Status and Roadmap

**Phase 0: Prototype** ✅ **COMPLETE** (2025-10-23)
- 109 tests passing (100% coverage)
- VAPID key generation and JWT signing
- Interactive demo with progressive verification
- Worker-based RPC protocol

**Phase 1: Production Enclave** 🚧 **READY TO BEGIN**
- [Readiness Report](docs/PHASE1_READINESS.md) - All prerequisites met
- Production-ready enclave with IndexedDB
- Audit logging with tamper-evident chain
- Passkey/passphrase unlock mechanisms
- Estimated timeline: 2-3 weeks

See [plan.md](docs/architecture/crypto/plan.md) for complete roadmap.

## Development Approach

This project is substantially implemented with **AI assistance** (Anthropic's Claude Code and OpenAI's Codex) while being **human-guided and reviewed**. This approach offers several advantages for a security-critical project:

### Why AI-Assisted Development Works Here

✅ **Comprehensive documentation** - Extensive architecture design before implementation
✅ **Test-driven from start** - 80%+ coverage requirement catches issues early
✅ **Consistent patterns** - AI follows architectural decisions precisely
✅ **Thorough consideration** - AI explores edge cases systematically
✅ **Human oversight** - All decisions, reviews, and architecture by humans

### Human-Only Responsibilities

Humans have final authority over:
- 🧠 **Architecture decisions** - All security model and design choices
- 📝 **Design documentation** - Comprehensive docs written first
- 🎯 **Requirements** - What to build and why
- ✅ **Final approval** - All merges require human sign-off

### Shared Responsibilities

Both human and AI collaborate on:
- 🔍 **Code review** - AI reviews implementation, humans review everything before merge
- 🛡️ **Security validation** - AI checks against threat model, humans validate guarantees
- 🧪 **Test design** - AI writes comprehensive tests, humans verify completeness
- 📋 **Quality assurance** - Continuous validation by both parties

### AI-Primary Contributions

AI leads on (with human review):
- ⚙️ **Implementation** - Writing code that follows architecture
- 🧪 **Test coverage** - Comprehensive test suites with 80%+ coverage
- 📚 **Documentation** - Detailed inline comments and guides
- 🔄 **Consistency** - Following patterns across codebase
- 🐛 **Edge cases** - Identifying and handling error paths

### Verification

This approach maintains verifiability:
- Code is open source and auditable
- Reproducible builds enable verification
- Comprehensive tests serve as executable specification
- Human review ensures security guarantees
- Architecture thoroughly documented

**The result**: Well-documented, thoroughly-tested, security-focused code with human accountability.

---

**Built with security and verifiability in mind** 🔐
