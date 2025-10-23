# Design Components

This directory contains the detailed design documentation for the KMS enclave, broken down into focused components for easier navigation and maintenance.

## Component Files

### [01-overview-and-architecture.md](./01-overview-and-architecture.md)
**Design goals and high-level architecture**
- Primary, secondary, and non-goals
- Separate application concept
- Architecture diagram with all layers
- Security properties overview

### [02-security-decisions.md](./02-security-decisions.md)
**Critical security design decisions**
- Sandbox configuration (`allow-scripts allow-same-origin` rationale)
- SRI verification approach (why it doesn't work on iframes)
- Isolation layers and verification chain

### [03-component-design.md](./03-component-design.md)
**Component implementations with code**
- KMS Client Stub (Main PWA)
- KMS Enclave Main Thread (Iframe)
- KMS Worker (Crypto Operations)
- Complete TypeScript implementations with IndexedDB schema

### [04-build-pipeline.md](./04-build-pipeline.md)
**Reproducible builds and release process**
- Deterministic esbuild configuration
- Reproducible build scripts
- Transparency log integration (Sigstore/Rekor)
- Content-addressed artifact generation

### [05-security-model.md](./05-security-model.md)
**Security boundaries and threat analysis**
- Four security boundaries (PWA↔Iframe, Iframe↔Worker, Worker↔WebCrypto, Code Integrity)
- Threat model (what we defend against vs. what we don't)
- Assumed trust requirements
- Open design questions (hosting, backups, transparency service, etc.)
- Performance considerations and optimization strategies

### [06-implementation-guide.md](./06-implementation-guide.md)
**Comprehensive production-ready implementation guide** (~1440 lines)
- Key principles and hosting requirements
- Well-known manifest schema
- Repository layout
- Deterministic build setup
- **VAPID/JWS critical implementation notes**:
  - DER to P-1363 signature conversion (critical for JWT)
  - Raw public key format for PushManager
  - Production-ready ES256 utilities (drop-in code)
  - Complete usage examples
- Worker implementation
- Host PWA integration
- Security headers (CSP, CORS, Permissions-Policy)
- Integration with ATS features
- Implementation checklist

## How to Use This Documentation

### For Understanding the System
1. Start with [01-overview-and-architecture.md](./01-overview-and-architecture.md) to understand goals and structure
2. Read [02-security-decisions.md](./02-security-decisions.md) for critical security rationale
3. Review [05-security-model.md](./05-security-model.md) for threat analysis

### For Implementation
1. Read [03-component-design.md](./03-component-design.md) for component structure
2. Follow [06-implementation-guide.md](./06-implementation-guide.md) for step-by-step guidance
3. Use [04-build-pipeline.md](./04-build-pipeline.md) for reproducible builds

### Key Implementation Warnings

**From implementation-guide.md** - Critical issues that will break production:

1. **ECDSA Signature Format**: WebCrypto returns DER-encoded signatures, but JWS ES256 requires P-1363 format. **Must convert** or JWT validation fails.

2. **VAPID Public Key Format**: PushManager.subscribe() requires 65-byte uncompressed raw format, NOT SPKI. **Must convert** or subscription fails.

3. **Sandbox Configuration**: Using `allow-same-origin` is **safe** because enclave is on different origin. This is necessary for runtime self-check.

4. **SRI on Iframes**: SRI attribute on `<iframe>` tags **does not work**. Must apply SRI to `<script>` tags inside kms.html.

## Quick Reference

**Architecture**:
- Main PWA: `allthe.services` (contains business logic)
- KMS Enclave: `kms.ats.run` (separate origin, sandboxed)
- Communication: postMessage only (explicit, auditable)

**Security Layers**:
1. Cross-origin isolation (browser enforces)
2. Sandboxed iframe
3. Dedicated Worker (no DOM access)
4. Non-extractable WebCrypto keys
5. SRI verification
6. Runtime self-check

**Build Process**:
1. Deterministic esbuild
2. Content-addressed filenames (`kms-<hash>.mjs`)
3. SRI hash generation
4. Sigstore signing
5. Rekor transparency log

**Key Operations**:
- Generate VAPID keypair
- Sign JWT for relay authorization
- Reset VAPID (hard revocation)
- Export public key

## File Size Summary

- 01-overview-and-architecture.md: ~125 lines (architecture diagrams)
- 02-security-decisions.md: ~65 lines (critical decisions)
- 03-component-design.md: ~510 lines (complete component code)
- 04-build-pipeline.md: ~175 lines (build scripts)
- 05-security-model.md: ~185 lines (threat model + design questions)
- 06-implementation-guide.md: ~1440 lines (production guide + VAPID utilities)

**Total**: ~2500 lines of detailed design documentation
