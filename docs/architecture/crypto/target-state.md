# Browser KMS Enclave - Target State

**Status**: 🚧 STUB - Awaiting Design Completion
**Dependencies**: design.md (complete)

## Purpose

This document will define the ideal state of the verifiable KMS enclave, including:
- Complete user flows and scenarios
- Technical specifications for all components
- Success criteria and metrics
- Platform compatibility matrix
- Security guarantees and limitations

## Scope

Once design.md is fully validated, this document will define:

### User Flows
- Initial enclave setup and key generation
- Daily usage (signing operations)
- Verification flow (manual hash checking)
- Key rotation and recovery
- Abuse detection and revocation

### Technical Specifications
- Complete API surface area
- Storage schema (IndexedDB)
- Communication protocol (postMessage)
- Error handling and retry logic
- Performance requirements

### Integration Points
- OS Notifications (VAPID keys, JWT signing)
- Signal Protocol (identity/session keys, encryption)
- Relay Authorization (token generation)
- Main PWA (enclave bridge API)

### Security Model
- Threat model (what we protect against)
- Trust assumptions (what we require)
- Isolation boundaries (iframe, worker, WebCrypto)
- Verification guarantees (SRI, reproducible builds, Sigstore)

## Expected Structure

Following the pattern from [os-notifications/target-state.md](../../os-notifications/target-state.md):

### 1. Architecture Principles
- User sovereignty (owns keys, controls access)
- Relay autonomy (relays can't steal keys)
- Verifiability (community can audit)
- Defense in depth (multiple security layers)

### 2. Key Management
- VAPID keypair (ES256, per-user)
- Signal identity key (Ed25519, long-term)
- Signal session keys (X25519, ephemeral)
- Key ID system (JWK thumbprints)

### 3. Cryptographic Operations
- Sign JWT (for relay authorization)
- Sign arbitrary data (for challenges)
- Encrypt/decrypt (Signal protocol)
- Key agreement (X3DH)

### 4. Storage & Persistence
- Non-extractable CryptoKey storage (IndexedDB)
- Metadata storage (key purpose, creation time)
- Operation logs (audit trail)
- Backup strategy (optional encrypted backup)

### 5. Verification System
- Runtime self-check (enclave hash verification)
- Manifest verification (Sigstore signature check)
- User-facing verification UX
- Community watchdog infrastructure

### 6. Performance Requirements
- Enclave initialization: <500ms
- Key generation: <100ms (VAPID), <200ms (Signal)
- Signing operation: <50ms
- Hash verification: <100ms

### 7. Platform Support
- Chrome/Edge Desktop: Full support
- Firefox Desktop: Full support
- Safari Desktop: Full support (macOS 13+)
- Chrome Android: Full support (PWA)
- Safari iOS: Full support (PWA, iOS 16.4+)

### 8. Success Criteria

**Phase 1: Basic Enclave**
- [ ] Enclave loads successfully in sandboxed iframe
- [ ] VAPID keypair generation works
- [ ] JWT signing works
- [ ] Keys are non-extractable (verified via API)

**Phase 2: Verifiable Build**
- [ ] Reproducible build produces identical output
- [ ] Content-addressed artifacts deployed
- [ ] SRI verification blocks tampered code
- [ ] CI pipeline automates release process

**Phase 3: Production**
- [ ] Sigstore signatures on all releases
- [ ] User verification UX shows hash
- [ ] Manual verification instructions available
- [ ] Performance targets met

**Phase 4: Integration**
- [ ] OS notifications use enclave for VAPID
- [ ] JWT delegation works end-to-end
- [ ] No security regressions from integration

## Open Questions

Before completing target-state, we need to decide:

1. **Key Persistence**: IndexedDB or in-memory only?
   - IndexedDB: Keys survive page refresh (better UX)
   - In-memory: Keys lost on reload (better security)
   - Hybrid: Option to persist with user consent?

2. **Key Backup**: Allow encrypted backup or not?
   - No backup: Most secure, lose keys if device lost
   - Encrypted backup: Convenience, passphrase is weak point
   - Recovery code: Middle ground (one-time seed phrase)

3. **Multi-Device**: Support same keys on multiple devices?
   - Single device: Simpler, more secure
   - Multi-device sync: Better UX, more complex
   - Import/export: Manual transfer (middle ground)

4. **Signal Protocol Scope**: Which parts in enclave?
   - Identity key only: Simpler, less isolation
   - All keys: Maximum isolation, more complex
   - Session keys ephemeral: Hybrid approach

5. **Verification Automation**: How much automation?
   - Manual only: User runs verification script
   - Semi-automated: "Verify" button in UI
   - Fully automated: Background checks + alerts
   - Browser extension: Auto-verify on load

## Next Steps

1. **Validate Design**: Review design.md with security experts
2. **Prototype**: Build minimal enclave to test assumptions
3. **Complete Target State**: Fill in all sections above
4. **Define Success Metrics**: Specific, measurable criteria
5. **Create Implementation Plan**: Break into phases

## Related Documents

- [current-state.md](./current-state.md) - Baseline (no KMS exists)
- [design.md](./design.md) - Detailed design (complete)
- [plan.md](./plan.md) - Implementation roadmap (awaiting target-state)
- [../../os-notifications/target-state.md](../../os-notifications/target-state.md) - Reference for structure
