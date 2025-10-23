# Browser KMS Enclave - Design

**Status**: 🚧 In Progress
**Last Updated**: 2025-01-22

## Purpose

This document defines the detailed design of the verifiable Key Management System (KMS) enclave for AllTheServices PWA, including:
- Sandboxed execution architecture
- Subresource Integrity (SRI) verification flow
- Reproducible build pipeline
- Transparency log integration
- Communication protocol
- Security boundaries and threat model

## Document Organization

This design has been broken down into focused component documents for easier navigation and maintenance. **See the [design/](./design/) directory** for all detailed design documentation.

## Design Components

### [01. Overview and Architecture](./design/01-overview-and-architecture.md)
- Design goals (primary, secondary, and non-goals)
- Separate application concept
- Complete architecture diagram
- Security properties overview

### [02. Security Decisions](./design/02-security-decisions.md)
- Sandbox configuration rationale
- SRI verification approach
- Why `allow-same-origin` is safe with cross-origin
- Verification chain

### [03. Component Design](./design/03-component-design.md)
- KMS Client Stub (Main PWA) - complete TypeScript implementation
- KMS Enclave Main Thread (Iframe) - complete TypeScript implementation
- KMS Worker (Crypto Operations) - complete TypeScript implementation
- IndexedDB schema and storage

### [04. Build Pipeline](./design/04-build-pipeline.md)
- Deterministic esbuild configuration
- Reproducible build scripts
- Content-addressed artifacts
- Transparency log integration (Sigstore/Rekor)

### [05. Security Model](./design/05-security-model.md)
- Security boundaries (4 layers)
- Threat model analysis
- Assumed trust requirements
- Open design questions
- Performance considerations

### [06. Implementation Guide](./design/06-implementation-guide.md) ⚠️ **CRITICAL**
Comprehensive production-ready implementation guide (~1440 lines) including:
- Key principles and hosting requirements
- Well-known manifest schema
- Repository layout
- **VAPID/JWS critical implementation notes**:
  - DER to P-1363 signature conversion (required for JWT)
  - Raw public key format for PushManager
  - Production-ready ES256 utilities (drop-in code)
- Worker implementation
- Host PWA integration
- Security headers (CSP, CORS, Permissions-Policy)
- Implementation checklist

## Quick Start

### For Understanding
1. Read [Overview and Architecture](./design/01-overview-and-architecture.md)
2. Review [Security Decisions](./design/02-security-decisions.md)
3. Study [Security Model](./design/05-security-model.md)

### For Implementation
1. Study [Component Design](./design/03-component-design.md)
2. Follow [Implementation Guide](./design/06-implementation-guide.md) step-by-step
3. Set up [Build Pipeline](./design/04-build-pipeline.md)

### Critical Implementation Warnings

**Read [Implementation Guide](./design/06-implementation-guide.md) carefully** - it contains critical information about:

1. **ECDSA Signature Format**: WebCrypto returns DER, JWS ES256 needs P-1363. **Must convert or JWT fails**.
2. **VAPID Public Key Format**: PushManager needs 65-byte raw format, NOT SPKI. **Must convert or subscription fails**.
3. **Sandbox Safety**: `allow-same-origin` is safe because enclave is cross-origin. Required for self-check.
4. **SRI Limitation**: SRI on `<iframe>` doesn't work. Must use SRI on `<script>` tags inside kms.html.

## Architecture at a Glance

```
Main PWA (allthe.services)
     ↓ postMessage
KMS Iframe (kms.ats.run) [sandboxed, cross-origin]
     ↓ postMessage
KMS Worker [no DOM, crypto operations]
     ↓ WebCrypto API
Non-Extractable Keys [browser-enforced]
```

**Security Layers**:
1. Cross-origin isolation
2. Sandboxed iframe
3. Dedicated Worker
4. Non-extractable keys
5. SRI verification
6. Runtime self-check

## Next Steps

1. **Complete Target State**: Define ideal KMS with all features and flows
2. **Implementation Plan**: Break down into phases (basic → verifiable → production)
3. **Prototype**: Build minimal working enclave with single-file module
4. **Build Pipeline**: Set up reproducible builds with CI
5. **Integrate**: Use KMS for VAPID keys in OS notifications

## References

- **WebCrypto Non-Extractable Keys**: [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#extractable)
- **Subresource Integrity**: [W3C SRI Specification](https://www.w3.org/TR/SRI/)
- **Reproducible Builds**: [Best Practices Guide](https://reproducible-builds.org/docs/)
- **Sigstore**: [Getting Started](https://docs.sigstore.dev/cosign/sign/)
- **Sandboxed Iframes**: [HTML Standard](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox)
- **JWK Thumbprint**: [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)
- **VAPID**: [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292.html)
- **JWS ES256**: [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)

## Related Documents

- [README.md](./README.md) - KMS enclave overview
- [current-state.md](./current-state.md) - Current baseline (no implementation)
- [target-state.md](./target-state.md) - Ideal end state
- [plan.md](./plan.md) - Implementation roadmap
- [design-full.md](./design-full.md) - Original full design document (backup)
