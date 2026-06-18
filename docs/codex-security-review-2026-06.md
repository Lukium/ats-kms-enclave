# Codex Security Review — KMS Enclave (parked for later)

> **Status: PARKED — review only, NOT yet actioned.** Captured 2026-06-18 after
> Phase 2 (messaging RPC surface) landed. None of the findings below have been
> implemented or triaged yet. This document exists so we can come back to it
> deliberately; do not treat any item here as done or in-progress.

## Why this is parked with a caveat

When we revisit this, remember the historical constraint: at one point we could
**not** run the KMS at "maximum" security because of how browsers handled the KMS
**iframe / cross-origin postMessage** path — to our knowledge at the time, the
current (somewhat convoluted) auth/handshake shape was the only arrangement that
made the whole system actually work end-to-end across browsers. So before adopting
any of the hardening below, we need to re-check whether:

- these findings **overlap or collide** with the iframe/browser constraints that
  forced the current design, and
- **browser handling has improved** since then such that a cleaner handshake
  (e.g. `MessageChannel` after a validated handshake, HTTP-header CSP with
  `frame-ancestors`, SRI-pinned bootstrap) is now viable where it previously
  wasn't.

In other words: this is not a "just do it" list. Each item needs to be validated
against real cross-browser iframe behavior before we change anything.

---

## Reviewer summary

> I reviewed the KMS concept against the V2 docs and the actual `src/v2`
> implementation. Short version: the architecture is strong for the constraints,
> and the direction is right. The main remaining work is not "more fortress"; it
> is making sure the security claims match the exact browser reality.

---

## Pre-Release Fixes

### 1. Passkey gate mode is not cryptographic at-rest protection

`setupPasskeyGate` (`src/v2/unlock.ts:179`) stores the pepper directly as
`pepperWrapped`, and `unlockWithPasskeyGate` (`src/v2/unlock.ts:313`) can decrypt
from that stored value. The WebAuthn ceremony happens in the UI path, but the
stored data itself is enough for KMS-origin code to unlock.

**Recommendation:** treat non-PRF passkeys as a UX gate only, not as a standalone
encryption method. For release, either disable standalone passkey-gate, require
passphrase + WebAuthn gate together, or label it clearly as lower-security
convenience. The secure default should be passkey PRF where available, passphrase
fallback, and gate-only as an additional consent step.

### 2. Deployed bootstrap does not enforce the integrity story in the docs

`public/kms.html:6` uses a meta CSP and loads `/client.js` without SRI at
`public/kms.html:12`. Also, `frame-ancestors` must be enforced by HTTP CSP
headers; it is not reliable as a meta CSP directive.

**Recommendation:** generate `kms.html` with an SRI-pinned, content-addressed
script, and enforce CSP via server headers. Keep the visible meta CSP for
auditability if desired, but do not count on it for `frame-ancestors`.

### 3. Do not trust `parentOrigin` from the URL as the authority

`kms-user.ts:216` passes `parentOrigin` into the iframe URL, and `client.ts:2195`
accepts it with a default. If HTTP `frame-ancestors` is missing or wrong, a
hostile embedder could pass its own origin and talk to the KMS.

**Recommendation:** maintain an internal allowlist in the KMS build, reject any
`parentOrigin` not in that allowlist, bind the accepted `event.source`, and move
to a `MessageChannel` after a validated handshake.

### 4. `resetKMS` is unauthenticated destructive behavior

`worker.ts:1115` routes `resetKMS`, and `handleResetKMS` (`worker.ts:2888`)
deletes the database without authentication. That may be acceptable for dev, but
not for production.

**Recommendation:** require a fresh KMS-origin confirmation and authentication, or
compile this method out of production builds.

> Note: line numbers above are from the reviewer's snapshot and may have drifted
> (Phase 2 added code to `worker.ts`). Re-grep before acting.

---

## Architecture Advice

The biggest conceptual point: key isolation prevents the parent PWA from
*extracting* secrets, but it does not prevent the parent PWA from *asking* the KMS
to do authorized work. So the best security/UX lever is an **operation policy
matrix**, not more prompts everywhere.

Define each operation by: fresh auth required, KMS-local confirmation required,
allowed under lease/session, max TTL, max count/quota, and audit severity.
Suggested defaults:

- **Fresh auth + KMS confirmation:** export/backup, reset, add/remove enrollment,
  regenerate VAPID, long-lived lease creation.
- **Fresh auth, no scary confirmation:** open messaging session, create normal
  VAPID lease.
- **Lease/session allowed:** issue short VAPID JWTs, encrypt/decrypt foreground
  messages.
- **Read-only:** public bundle, public key, setup status.

The VAPID lease model is a good UX/security compromise. The messaging
capability-session work also looks directionally good: scoped messaging KEK,
memory-only session, idle timeout, absolute cap — exactly the kind of "not fortress
at UX cost" tradeoff that fits the goal.

**Strongest product recommendation:** make the KMS-origin UI the place where
credentials and high-risk confirmations happen, but keep it lightweight and rare.
For ordinary use, users should mostly see passkey/biometric unlock, short
lease/session status, and a calm "recent security activity" view rather than
constant prompts.

---

## Our follow-up notes (to fill in when we triage)

- [ ] Re-validate each Pre-Release Fix against the iframe/cross-origin browser
      constraints that drove the current auth design (see "Why this is parked").
- [ ] Confirm whether HTTP-header CSP + `frame-ancestors` + `MessageChannel`
      handshake is viable in current target browsers.
- [ ] Cross-check finding #4 (`resetKMS`) — decide dev-only vs. authenticated.
- [ ] Map our existing operations onto the proposed policy matrix; note where the
      messaging capability-session model already satisfies it.
