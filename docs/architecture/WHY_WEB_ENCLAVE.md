# Why a Verifiable Web Enclave?

**The Strategic Case for Web-Based Key Management**

## Overview

While hardware-backed key storage (TPM, Secure Enclave, Titan M) provides strong physical tamper resistance, our verifiable web KMS offers a fundamentally different — and in many contexts, **superior** — trust model based on **systemic transparency** rather than opaque hardware trust.

This document explains when and why a verifiable web enclave is the better choice.

---

## The Core Difference

### Traditional Native Apps with Hardware Enclaves

**Trust model:**
- Trust the OS vendor (Apple, Google, Microsoft)
- Trust proprietary hardware firmware (closed-source)
- Trust binary attestation mechanisms (notarization, code signing)
- Trust app store review processes
- **No independent verification possible**

**Strengths:**
- Strong physical tamper resistance
- Hardware-rooted attestation
- Protection against device forensics

**Weaknesses:**
- Opaque, proprietary implementations
- No public auditability
- Platform-specific fragmentation
- Vendor lock-in
- Slow update cycles (app store approval)

### Verifiable Web KMS

**Trust model:**
- Trust the browser runtime (open-source: Chromium, Gecko, WebKit)
- Trust mathematical proofs (SRI hashes, signatures)
- Trust public transparency logs (Sigstore/Rekor)
- Trust reproducible builds (anyone can rebuild and verify)
- **Full independent verification possible**

**Strengths:**
- Globally verifiable integrity
- Cross-platform consistency
- Open-source transparency
- Rapid updates with proof-of-integrity
- No vendor lock-in

**Weaknesses:**
- No protection against physical device compromise
- Depends on browser security (but browsers are highly audited)
- Newer trust model (less familiar to users)

---

## When Web Enclave is Superior

### 1. Publicly Verifiable, Auditable Environments ✅

**Use cases:**
- NGOs and human rights organizations
- Journalists and whistleblower platforms
- Open-source security utilities
- Election integrity systems
- Public health data management
- Academic research platforms

**Why web wins:**
- Native apps depend on binary attestation (Apple notarization, Microsoft signing) that **the public cannot independently verify**
- Our web KMS offers **reproducible builds + SRI + Sigstore + public GitHub Actions proofs** that are **provably transparent**
- Anyone can:
  - Clone the repository
  - Rebuild the artifact byte-for-byte
  - Verify the hash matches deployed version
  - Audit the transparency log entries
  - Review the entire codebase

**Result:** ✅ **Preferred when institutional or community trust matters more than vendor hardware trust**

**Real-world impact:**
A journalist using a native app must trust that Apple's notarization process caught all backdoors. With our KMS, the journalist's security team can independently verify the deployed code matches the audited source.

---

### 2. Cross-Platform Reach ✅

**Use cases:**
- Consumer apps across all devices (iOS, Android, desktop, web)
- Enterprise applications with diverse device fleets
- Educational platforms
- Kiosk and embedded browser environments
- Chromebooks and Linux desktops

**Why web wins:**
- Hardware KMS code must be **rewritten per platform**:
  - iOS: Secure Enclave API
  - Android: Android Keystore
  - Windows: Cryptographic Next Generation (CNG) / TPM
  - macOS: Keychain + Secure Enclave
  - Linux: Varies (TPM, gpg-agent, kernel keyrings)
- Web KMS: **one verified JavaScript module, identical behavior everywhere**
- Testing complexity: Native = N platforms × M configurations; Web = browser matrix only
- Consistency guarantees: Native varies subtly per platform; Web is deterministic

**Result:** ✅ **Preferred when consistency and reach trump per-platform depth**

**Real-world impact:**
A healthcare app needs identical security guarantees on patient iPads, nurse Android tablets, and doctor workstations. One web KMS instead of three native implementations reduces attack surface and audit complexity.

---

### 3. Open-Source / Auditable Ecosystems ✅

**Use cases:**
- Verifiable identity systems
- Cryptocurrency wallets
- Community security tools
- Privacy-focused messaging
- Decentralized applications

**Why web wins:**
- You can **read and reproduce** the enclave's code
- Secure Enclave/TPM firmware is **closed and proprietary** — no one can audit it
- Security researchers can review every line of code
- Community can propose and verify fixes
- No reliance on vendor security-through-obscurity

**Result:** ✅ **Preferred when transparency and community auditing matter**

**Real-world impact:**
A cryptocurrency wallet can prove to users that the key management code matches the GitHub repository. Users don't need to trust the developer — they can verify the math.

---

### 4. Fast Iteration and Patchability ✅

**Use cases:**
- Zero-day vulnerability mitigation
- Cryptographic algorithm updates
- Key-handling bug fixes
- Feature additions
- Security improvements

**Why web wins:**
- Native enclave apps rely on:
  - App store review (days to weeks)
  - User updates (many users delay)
  - OS update cycles (for system-level fixes)
  - Some users stay on old versions indefinitely
- Web KMS can:
  - Redeploy instantly under same origin
  - Users get updates on next page load
  - Transparency-logged proofs of each version
  - No app store approval gatekeeping

**Result:** ✅ **Preferred when agility is critical**

**Real-world impact:**
When a vulnerability is discovered, you can patch and deploy within hours with cryptographic proof of the fix. Compare to native: weeks for app store approval, then weeks/months for user adoption.

---

### 5. Reduced Central Authority Dependence ✅

**Use cases:**
- Regions or organizations that distrust OS vendors
- Sovereign applications
- Privacy-focused services
- Decentralized systems
- Open governance projects

**Why web wins:**
- Hardware roots (TPM, Secure Enclave) ultimately trust **Apple/Microsoft/Google firmware keys**
- Web model trusts the **browser runtime only**, whose code is:
  - Open-source (Chromium, Gecko, WebKit)
  - Cross-audited by security community
  - Forkable (Brave, Vivaldi, Edge all use Chromium)
  - No single vendor control point

**Result:** ✅ **Preferred when you want to minimize dependence on a single hardware vendor**

**Real-world impact:**
A government agency concerned about foreign hardware backdoors can audit the open-source browser stack but cannot audit proprietary Secure Enclave firmware.

---

### 6. User Privacy and Control ✅

**Use cases:**
- End-to-end encrypted messaging
- Personal health data management
- Private document storage
- Zero-knowledge applications
- Self-sovereign identity

**Why web wins:**
- Native hardware enclaves may:
  - Share attestations with vendor servers
  - Require OS-level accounts (Apple ID, Google account)
  - Include telemetry and analytics
  - Be subject to government access requests
- Web KMS:
  - Never leaves browser sandbox
  - No vendor telemetry
  - No account requirements
  - Transparent audit logs (user-controlled)
  - Origin-isolated (no cross-site tracking)

**Result:** ✅ **Preferred when privacy and local autonomy matter**

**Real-world impact:**
A user's therapy notes encrypted with web KMS keys never touch vendor servers and require no cloud account. The user controls the entire chain of custody.

---

### 7. Auditable Compliance & Reproducibility ✅

**Use cases:**
- Regulated sectors (finance, healthcare, government)
- Compliance-heavy industries
- Public sector applications
- Contractual verification requirements
- Insurance and audit requirements

**Why web wins:**
- Regulators and auditors can:
  - Reproduce builds independently
  - Verify deployed hashes match releases
  - Review transparency log entries
  - Audit complete source code
  - Run automated verification tools
- With hardware enclaves, regulators must:
  - Trust manufacturer certifications
  - Accept opaque attestation chains
  - Rely on vendor documentation
  - Cannot independently verify firmware

**Result:** ✅ **Preferred where compliance = verifiable reproducibility**

**Real-world impact:**
A financial auditor can run `make verify-build` and cryptographically prove the deployed KMS matches the audited source. No trust required beyond mathematics.

---

### 8. Developer and Ecosystem Neutrality ✅

**Use cases:**
- Open federation protocols
- Third-party integrations
- Multi-vendor ecosystems
- Standards-based applications
- Long-term maintainability

**Why web wins:**
- Native enclaves lock you to vendor SDKs:
  - Apple's Security framework
  - Google's SafetyNet
  - Microsoft's CNG
  - Each with different APIs and guarantees
- Web KMS is:
  - Origin-based (standard URL security model)
  - Standards-compliant (postMessage, WebCrypto, WebAuthn)
  - Vendor-neutral (works across all browsers)
  - Longevity-focused (standards evolve, but slowly)

**Result:** ✅ **Preferred when neutrality and longevity matter**

**Real-world impact:**
A 10-year-old web app can still use modern KMS without platform rewrites. Native apps must rewrite for each OS major version and maintain 5+ platform-specific codebases.

---

## When Hardware Enclave Still Wins

To be candid, hardware enclaves are stronger when:

### Physical Device Security is Primary Threat

✅ **Hardware wins if:**
- Device theft is expected (lost phones, stolen laptops)
- Forensic attacks are realistic threat model
- Cold boot attacks are concern
- Hardware implants are threat
- Physical access to device is adversary's goal

**Why:** Hardware enclaves provide tamper-resistant storage that survives device compromise

### Enterprise MDM Control

✅ **Hardware wins if:**
- You control the OS stack (corporate MDM)
- Can enforce device policies
- Need hardware-rooted attestation for compliance
- Centralized key escrow is required

**Why:** Full device control enables hardware-backed guarantees

### High-Value Hardware-Rooted Secrets

✅ **Hardware wins if:**
- FIDO security keys (U2F, WebAuthn authenticator)
- Payment card credentials (Apple Pay, Google Pay)
- Hardware attestation required by external party
- HSM-level security needed

**Why:** Some protocols explicitly require hardware attestation

---

## Hybrid Approach: Best of Both Worlds

**You don't have to choose exclusively.**

Our web KMS can leverage hardware when available:

```typescript
// When generating keys, prefer hardware backing if available
const keypair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,  // non-extractable
  ['sign', 'verify']
);

// Browser may store in hardware if available
// But we maintain same verification and audit model
```

**Benefits:**
- Hardware backing when available (iOS Secure Enclave, Android Keystore)
- Consistent API and audit trail across all platforms
- Graceful degradation (software-backed keys when hardware unavailable)
- Same reproducible build and verification model
- User sees same security dashboard regardless

**Result:** Hardware depth + web transparency

---

## Framing the Value Proposition

### For Users

> **Traditional key management:** "Trust us, we use secure hardware."
>
> **Verifiable web KMS:** "Don't trust us — verify the math. Here's how."

### For Developers

> **Traditional approach:** Maintain 5+ platform-specific implementations, each with proprietary APIs, none verifiable.
>
> **Web KMS:** One implementation, reproducible builds, public verification, works everywhere.

### For Regulators/Auditors

> **Traditional attestation:** "The vendor says it's secure."
>
> **Verifiable web KMS:** "We rebuilt it independently and verified the hash. Here's the proof."

### For the Industry

> **Old model:** Security through obscurity and vendor trust.
>
> **New model:** Security through transparency and mathematical proof.

---

## Summary: When to Choose Web Enclave

| Criterion | Hardware Enclave | Web Enclave |
|-----------|-----------------|-------------|
| **Public verifiability** | ❌ Opaque | ✅ Transparent |
| **Cross-platform consistency** | ❌ Fragmented | ✅ Unified |
| **Open-source auditability** | ❌ Proprietary | ✅ Open |
| **Rapid patching** | ❌ Slow (app stores) | ✅ Instant |
| **Vendor neutrality** | ❌ Locked-in | ✅ Neutral |
| **User privacy** | ⚠️ Vendor-dependent | ✅ Local-only |
| **Compliance reproducibility** | ❌ Trust-based | ✅ Math-based |
| **Physical tamper resistance** | ✅ Strong | ❌ Browser-dependent |
| **Device theft protection** | ✅ Strong | ⚠️ Session-based |
| **Hardware attestation** | ✅ Native | ⚠️ Optional hybrid |

**Choose web enclave when:**
- ✅ Verifiability, transparency, and auditability are requirements
- ✅ Cross-platform consistency matters more than per-platform depth
- ✅ Open-source and community auditing are values
- ✅ Rapid updates and agility are critical
- ✅ Vendor neutrality and longevity matter
- ✅ User privacy and local control are priorities
- ✅ Compliance requires reproducible verification

**Choose hardware enclave when:**
- 🔒 Physical device security is primary threat
- 🔒 You control device fleet via MDM
- 🔒 Hardware attestation is external requirement

**Choose hybrid approach when:**
- 🌟 You want hardware backing **and** verifiable transparency

---

## Conclusion

The verifiable web enclave isn't trying to beat hardware enclaves at physical tamper resistance. Instead, it offers a **fundamentally different and often superior trust model** based on:

1. **Systemic transparency** over opaque hardware
2. **Mathematical proof** over vendor attestation
3. **Public verifiability** over trust-me security
4. **Cross-platform consistency** over fragmented APIs
5. **Community auditability** over proprietary secrets

**In the domains where provable integrity and ecosystem trust matter — journalism, NGOs, open-source crypto, privacy-focused services, regulated compliance — this design isn't just competitive; it's genuinely best-in-class.**

When you care more about **"Can I verify this is secure?"** than **"Can I survive device theft?"**, the web enclave model is **strictly superior**.

---

**Related Documentation:**
- [Architecture Overview](./crypto/README.md)
- [Security Model](./crypto/design/05-security-model.md)
- [Threat Model](./crypto/design/05-security-model.md#threat-model)
- [Target State](./crypto/target-state.md)
