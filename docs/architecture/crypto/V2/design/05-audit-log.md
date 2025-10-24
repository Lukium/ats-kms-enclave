# Audit Log (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-01-24

---

## Table of Contents

1. [Overview](#overview)
2. [Audit Entry Schema](#audit-entry-schema)
3. [Chain Integrity](#chain-integrity)
4. [Sequence Numbers](#sequence-numbers)
5. [Ed25519 Signatures](#ed25519-signatures)
6. [Periodic Anchors](#periodic-anchors)
7. [Audit Key Management](#audit-key-management)
8. [Verification](#verification)
9. [Implementation](#implementation)
10. [Security Analysis](#security-analysis)

---

## Overview

The audit log is a **tamper-evident record** of all cryptographic operations in KMS V2. Each entry is cryptographically signed and chained to previous entries.

### V2 Improvements

1. **Sequence Numbers**: Monotonic counter detects truncation attacks
2. **Non-Extractable Audit Keys**: Ed25519 keys stored as non-extractable
3. **Enhanced Chain**: SHA-256 hash of previous entry's `chainHash`
4. **Periodic Anchors**: Checkpoint entries every N operations
5. **Key Reference**: `auditKeyId` instead of embedding public key

### Security Properties

✅ **Tamper-evident**: Any modification breaks chain
✅ **Truncation-resistant**: Sequence numbers detect log truncation
✅ **Replay-resistant**: Each entry has unique timestamp + requestId
✅ **Verifiable**: Ed25519 signatures can be verified externally
✅ **Non-repudiable**: Audit key cannot be extracted (with backup ceremony)

---

## Audit Entry Schema

### V2 Entry Structure

```typescript
interface AuditEntry {
  // Version and identification
  kmsVersion: 2;
  seqNum: number;              // Monotonic sequence (0, 1, 2, ...)
  timestamp: number;           // Unix timestamp (ms)

  // Operation details
  op: string;                  // Operation type (e.g., "vapid:sign")
  kid: string;                 // Key ID involved (if applicable)
  requestId: string;           // UUID for this operation
  origin?: string;             // Origin of request (if available)

  // Unlock timing
  unlockTime: number;          // Unlock start (ms since epoch)
  lockTime: number;            // Unlock end (ms since epoch)
  duration: number;            // Duration (ms, high-resolution)

  // Additional context
  details?: Record<string, unknown>;  // Operation-specific data
  jti?: string;                // JWT Token ID (for VAPID issuance, anti-replay tracking)

  // Chain integrity
  previousHash: string;        // SHA-256 of previous entry's chainHash (base64url)
  chainHash: string;           // SHA-256 of this entry's canonical form (base64url)

  // Signature
  signature: string;           // Ed25519 signature of chainHash (base64url)
  auditKeyId: string;          // Reference to audit key (kid)
}
```

### Operation Types

```typescript
// Operation type examples
type AuditOperation =
  | 'unlock'                   // Generic unlock (if no specific op)
  | 'vapid:generate'           // Generate VAPID keypair
  | 'vapid:sign'               // Sign VAPID JWT
  | 'vapid:issue'              // Issue VAPID JWT (V2 lease-based)
  | 'vapid:export'             // Export VAPID public key
  | 'audit:generate'           // Generate audit keypair
  | 'audit:export'             // Export audit public key (for backup)
  | 'enrollment:add'           // Add new credential
  | 'enrollment:remove'        // Remove credential
  | 'backup:export'            // Export backup bundle
  | 'backup:import'            // Import backup bundle
  | 'recalibrate:pbkdf2'       // Recalibrate PBKDF2 iterations
  | 'anchor'                   // Periodic anchor entry
  ;
```

### VAPID Issuance with `jti` Field

**For VAPID JWT issuance operations (`vapid:issue`), the `jti` field is MANDATORY:**

```typescript
/**
 * VAPID issuance audit entry (V2).
 *
 * ANTI-REPLAY PROTECTION:
 * - KMS records every jti it issues
 * - KMS MUST NOT re-issue a token with the same jti within TTL window
 * - This prevents broker replay attacks
 * - Audit entries include jti for tracking and correlation
 */
interface VAPIDIssuanceAuditEntry extends AuditEntry {
  op: 'vapid:issue';
  jti: string;               // REQUIRED: Unique token ID (UUID v4)
  details: {
    jti: string;             // Also in details for consistency
    aud: string;             // Audience (push service origin)
    exp: number;             // Token expiration (Unix ms)
    leaseId: string;         // Lease this token was issued for
    endpoint: string;        // Subscription endpoint fingerprint (eid)
  };
}
```

**Anti-Replay Enforcement:**

```typescript
/**
 * Check if jti was already issued (anti-replay).
 *
 * KMS maintains a rolling blacklist of jti values issued in the last TTL window.
 * Prevents re-issuance of the same jti within the token's validity period.
 *
 * @param jti JWT Token ID to check
 * @param ttlMs Token TTL in milliseconds
 * @returns true if jti is safe to use (not recently issued)
 */
async function checkJTINotReissued(jti: string, ttlMs: number): Promise<boolean> {
  // Query audit log for recent jti usage
  const recentEntries = await audit.getRecentByOp('vapid:issue', Date.now() - ttlMs);

  for (const entry of recentEntries) {
    if (entry.jti === jti) {
      // This jti was issued recently - reject
      return false;
    }
  }

  return true;
}
```

**Audit Query for Verification:**

Verification endpoints can reject tokens if they appear in the audit log with suspicious patterns:

```typescript
/**
 * Verify jti is not in revoked list (emergency mode).
 *
 * Optional: KMS can maintain a rolling blacklist of jti values
 * from revoked leases for emergency revocation (last N minutes).
 */
async function isJTIRevoked(jti: string): Promise<boolean> {
  const revokedLeases = await storage.get('revoked-leases');

  for (const lease of revokedLeases) {
    const leaseJTIs = await audit.getByLeaseId(lease.leaseId, lease.revokedAt - 600_000);
    if (leaseJTIs.some(entry => entry.jti === jti)) {
      return true;
    }
  }

  return false;
}
```

### Example Entry

```json
{
  "kmsVersion": 2,
  "seqNum": 42,
  "timestamp": 1704067200000,
  "op": "vapid:sign",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "origin": "https://allthe.services",
  "unlockTime": 1704067200100,
  "lockTime": 1704067200350,
  "duration": 250,
  "details": {
    "jti": "9c7d330b-5b7a-4d3c-9c4b-7f8a9b0c1d2e"
  },
  "previousHash": "pQ7YQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5fGhIj",
  "chainHash": "zQz4FxS2kL9mN3pR6tU8vW1xY2zA3bC4dE5fGhIjKlM",
  "signature": "A3bC4dE5fGhIjKlMnOpQrStUvWxYzA1bC2dE3fGhIjKlMnOpQrStUvWxYzA1b...",
  "auditKeyId": "abc123def456..."
}
```

---

## Chain Integrity

### Chain Structure

```
Entry 0 (genesis)
  ↓
  chainHash₀ = SHA256(canonical(entry₀))
  ↓
Entry 1
  previousHash₁ = chainHash₀
  chainHash₁ = SHA256(canonical(entry₁))
  ↓
Entry 2
  previousHash₂ = chainHash₁
  chainHash₂ = SHA256(canonical(entry₂))
  ↓
...
```

### Canonical Form

To ensure consistent hashing, entries are serialized in **canonical JSON** with sorted keys:

```typescript
/**
 * Build canonical form of audit entry for hashing.
 *
 * CANONICAL JSON:
 * - All keys sorted alphabetically
 * - No whitespace
 * - Deterministic serialization
 *
 * INCLUDED FIELDS:
 * - All fields except signature (signature covers chainHash)
 *
 * @param entry Audit entry (without signature)
 * @returns Canonical JSON string
 */
function canonicalizeAuditEntry(entry: Omit<AuditEntry, 'signature'>): string {
  // Build object with sorted keys
  const canonical = {
    auditKeyId: entry.auditKeyId,
    chainHash: entry.chainHash,
    details: entry.details || null,
    duration: entry.duration,
    kid: entry.kid,
    kmsVersion: entry.kmsVersion,
    lockTime: entry.lockTime,
    op: entry.op,
    origin: entry.origin || null,
    previousHash: entry.previousHash,
    requestId: entry.requestId,
    seqNum: entry.seqNum,
    timestamp: entry.timestamp,
    unlockTime: entry.unlockTime
  };

  // Stringify with sorted keys (Object.keys returns sorted array)
  return JSON.stringify(canonical, Object.keys(canonical).sort());
}
```

### Chain Hash Computation

```typescript
/**
 * Compute chain hash for audit entry.
 *
 * ALGORITHM:
 * 1. Canonicalize entry (sorted JSON)
 * 2. SHA-256 hash
 * 3. Base64url encode
 *
 * @param entry Audit entry (partial, before chainHash computed)
 * @returns Base64url-encoded SHA-256 hash
 */
async function computeChainHash(
  entry: Omit<AuditEntry, 'chainHash' | 'signature'>
): Promise<string> {
  // Canonical JSON
  const canonical = canonicalizeAuditEntry({
    ...entry,
    chainHash: ''  // Placeholder (will be replaced)
  });

  // SHA-256 hash
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );

  // Base64url encode
  return base64url.encode(new Uint8Array(hash));
}
```

### Previous Hash Lookup

```typescript
/**
 * Get previousHash for new audit entry.
 *
 * CASES:
 * - Genesis entry (seqNum=0): previousHash = "0" (no previous)
 * - Subsequent entries: previousHash = chainHash of seqNum-1
 *
 * @param seqNum Sequence number of new entry
 * @returns previousHash value
 */
async function getPreviousHash(seqNum: number): Promise<string> {
  if (seqNum === 0) {
    return '0';  // Genesis entry
  }

  // Load previous entry
  const prevEntry = await audit.getBySeqNum(seqNum - 1);
  if (!prevEntry) {
    throw new Error(`Missing previous audit entry: seqNum=${seqNum - 1}`);
  }

  return prevEntry.chainHash;
}
```

---

## Sequence Numbers

### V2 IMPROVEMENT: Truncation Detection

**V1 Problem**: Attacker could truncate audit log (delete recent entries) without detection.
**V2 Solution**: Monotonic sequence numbers. Missing seqNum indicates truncation.

### Sequence Tracking

```typescript
/**
 * Audit log state (stored separately from entries).
 */
interface AuditState {
  nextSeqNum: number;          // Next sequence number to assign
  totalEntries: number;        // Total entries written (sanity check)
  lastTimestamp: number;       // Last entry timestamp (ordering check)
  lastChainHash: string;       // Last entry chainHash (quick access)
  lastAnchor: number;          // Sequence number of last anchor
}

/**
 * Get next sequence number and increment.
 */
async function getNextSeqNum(): Promise<number> {
  const state = await storage.get('audit:state') || {
    nextSeqNum: 0,
    totalEntries: 0,
    lastTimestamp: 0,
    lastChainHash: '0',
    lastAnchor: 0
  };

  const seqNum = state.nextSeqNum;

  // Increment for next entry
  await storage.put('audit:state', {
    ...state,
    nextSeqNum: seqNum + 1
  });

  return seqNum;
}
```

### Verification Check

```typescript
/**
 * Verify audit log sequence is complete (no gaps).
 *
 * CHECKS:
 * 1. Sequence numbers are consecutive (0, 1, 2, ...)
 * 2. Total count matches nextSeqNum
 * 3. No duplicate sequence numbers
 *
 * @returns { valid, gaps, duplicates }
 */
async function verifySequence(): Promise<{
  valid: boolean;
  gaps: number[];
  duplicates: number[];
}> {
  const entries = await audit.getAll();
  const state = await storage.get('audit:state');

  // Extract sequence numbers
  const seqNums = entries.map(e => e.seqNum).sort((a, b) => a - b);

  // Check for gaps
  const gaps: number[] = [];
  for (let i = 0; i < state.nextSeqNum; i++) {
    if (!seqNums.includes(i)) {
      gaps.push(i);
    }
  }

  // Check for duplicates
  const seen = new Set<number>();
  const duplicates: number[] = [];
  for (const seqNum of seqNums) {
    if (seen.has(seqNum)) {
      duplicates.push(seqNum);
    }
    seen.add(seqNum);
  }

  return {
    valid: gaps.length === 0 && duplicates.length === 0,
    gaps,
    duplicates
  };
}
```

---

## Ed25519 Signatures

### Signing Flow

```
withUnlock → Unwrap Audit Key → Sign chainHash → Attach Signature
```

### Implementation

```typescript
/**
 * Sign audit entry with Ed25519 audit key.
 *
 * WHAT IS SIGNED: The chainHash (32-byte SHA-256)
 * WHY: chainHash already commits to all entry fields
 *
 * @param entry Audit entry (with chainHash computed)
 * @param auditKeyId Audit key identifier
 * @param mkek Master Key Encryption Key (from unlock context)
 * @returns Ed25519 signature (64 bytes, base64url-encoded)
 */
async function signAuditEntry(
  entry: Omit<AuditEntry, 'signature'>,
  auditKeyId: string,
  mkek: CryptoKey
): Promise<string> {
  // Load audit key configuration
  const keyConfig = await storage.get(`key:${auditKeyId}`);
  if (!keyConfig || keyConfig.purpose !== 'audit') {
    throw new Error(`Audit key not found: ${auditKeyId}`);
  }

  // Unwrap audit private key
  const auditKey = await unwrapApplicationKey(
    keyConfig.wrappedKey,
    mkek,
    keyConfig.iv,
    keyConfig.aad,
    { alg: 'EdDSA', purpose: 'audit' }
  );

  // Sign chainHash
  const signature = await crypto.subtle.sign(
    'Ed25519',
    auditKey,
    base64url.decode(entry.chainHash)  // Sign raw hash bytes
  );

  // Base64url encode signature
  return base64url.encode(new Uint8Array(signature));
}
```

### Verification

```typescript
/**
 * Verify audit entry signature.
 *
 * @param entry Complete audit entry (including signature)
 * @param auditPublicKey Audit public key (raw Ed25519, 32 bytes)
 * @returns true if signature valid
 */
async function verifyAuditSignature(
  entry: AuditEntry,
  auditPublicKey: ArrayBuffer
): Promise<boolean> {
  // Import public key
  const publicKey = await crypto.subtle.importKey(
    'raw',
    auditPublicKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  // Verify signature
  const valid = await crypto.subtle.verify(
    'Ed25519',
    publicKey,
    base64url.decode(entry.signature),
    base64url.decode(entry.chainHash)
  );

  return valid;
}
```

---

## Periodic Anchors

### Purpose

**Anchors** are special audit entries that serve as checkpoints:
- Summarize recent activity
- Reference external verification (e.g., timestamp from transparency log)
- Detect rollback attacks (attacker replaces recent entries)

### Anchor Frequency

```typescript
const ANCHOR_FREQUENCY = 100;  // Every 100 operations

/**
 * Check if anchor should be inserted.
 */
function shouldInsertAnchor(seqNum: number): boolean {
  return seqNum > 0 && seqNum % ANCHOR_FREQUENCY === 0;
}
```

### Anchor Entry

```typescript
interface AnchorEntry extends AuditEntry {
  op: 'anchor';
  details: {
    anchorType: 'periodic';
    sinceSeqNum: number;        // Start of range (last anchor)
    untilSeqNum: number;        // End of range (this anchor)
    operationCount: number;     // Number of ops since last anchor
    keyOperations: {            // Summary by key
      [kid: string]: number;    // Count per key
    };
    externalTimestamp?: string; // RFC 3161 timestamp (future)
    rekorEntry?: string;        // Rekor transparency log entry (future)
  };
}

/**
 * Create periodic anchor entry.
 */
async function createAnchor(
  seqNum: number,
  previousHash: string
): Promise<AnchorEntry> {
  const state = await storage.get('audit:state');

  // Compute summary statistics
  const recentEntries = await audit.getRange(state.lastAnchor + 1, seqNum - 1);
  const keyOperations: Record<string, number> = {};

  for (const entry of recentEntries) {
    if (entry.kid) {
      keyOperations[entry.kid] = (keyOperations[entry.kid] || 0) + 1;
    }
  }

  const anchor: Omit<AnchorEntry, 'chainHash' | 'signature'> = {
    kmsVersion: 2,
    seqNum,
    timestamp: Date.now(),
    op: 'anchor',
    kid: '',
    requestId: crypto.randomUUID(),
    unlockTime: 0,
    lockTime: 0,
    duration: 0,
    details: {
      anchorType: 'periodic',
      sinceSeqNum: state.lastAnchor,
      untilSeqNum: seqNum,
      operationCount: recentEntries.length,
      keyOperations
    },
    previousHash,
    auditKeyId: await audit.getCurrentKeyId()
  };

  // Compute chainHash
  const chainHash = await computeChainHash(anchor);

  return { ...anchor, chainHash, signature: '' };
}
```

---

## Audit Key Management

### V2 IMPROVEMENT: Non-Extractable Keys

**V1 Problem**: Audit key was extractable (could be exported and used to forge entries).
**V2 Solution**: Non-extractable with explicit backup ceremony.

### Backup Ceremony

```typescript
/**
 * Export audit key for backup (one-time ceremony).
 *
 * SECURITY:
 * - Requires explicit user action (not automatic)
 * - User must confirm understanding of risks
 * - Backup should be encrypted and stored securely
 * - Original key remains non-extractable in KMS
 *
 * FLOW:
 * 1. User initiates backup ceremony
 * 2. withUnlock (authenticate user)
 * 3. Temporarily make audit key extractable
 * 4. Export as JWK
 * 5. Encrypt with backup password
 * 6. Return encrypted backup
 * 7. Re-wrap key as non-extractable
 *
 * @param credential User credential
 * @param backupPassword Strong password for backup encryption
 * @returns Encrypted backup bundle
 */
export async function exportAuditKeyBackup(
  credential: Credential,
  backupPassword: string
): Promise<{
  encryptedKey: ArrayBuffer;
  iv: ArrayBuffer;
  salt: ArrayBuffer;
}> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Load current audit key
      const auditKeyId = await audit.getCurrentKeyId();
      const keyConfig = await storage.get(`key:${auditKeyId}`);

      // Unwrap (temporarily accessible)
      const auditKey = await unwrapApplicationKey(
        keyConfig.wrappedKey,
        ctx.mkek,
        keyConfig.iv,
        keyConfig.aad,
        { alg: 'EdDSA', purpose: 'audit' }
      );

      // Export as JWK (requires re-wrapping with extractable=true)
      // This is the ONE TIME we make audit key extractable
      const jwk = await crypto.subtle.exportKey('jwk', auditKey);

      // Derive backup KEK from password
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const backupKEK = await deriveBackupKEK(backupPassword, salt, 600_000);

      // Encrypt JWK
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedKey = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        backupKEK,
        new TextEncoder().encode(JSON.stringify(jwk))
      );

      // Audit this sensitive operation
      await audit.log({
        op: 'audit:export',
        kid: auditKeyId,
        requestId: crypto.randomUUID(),
        details: {
          warning: 'Audit key exported for backup'
        }
      });

      return {
        encryptedKey,
        iv: iv.buffer,
        salt: salt.buffer
      };
    },
    {
      timeout: 10_000,
      purpose: 'audit:backup'
    }
  );
}
```

### Key Rotation

```typescript
/**
 * Rotate audit key (generate new, keep old for verification).
 *
 * FLOW:
 * 1. Generate new Ed25519 keypair
 * 2. Sign "key rotation" entry with OLD key
 * 3. Sign next entry with NEW key
 * 4. Store both keys (old for verification, new for signing)
 *
 * @param credential User credential
 * @returns New audit key ID
 */
export async function rotateAuditKey(
  credential: Credential
): Promise<string> {
  return withUnlock(
    credential,
    async (ctx) => {
      const oldKeyId = await audit.getCurrentKeyId();

      // Generate new keypair
      const { kid: newKeyId } = await generateAuditKeypair(credential);

      // Sign rotation entry with OLD key
      await audit.log({
        op: 'audit:rotate',
        kid: oldKeyId,
        requestId: crypto.randomUUID(),
        details: {
          oldKeyId,
          newKeyId,
          reason: 'periodic-rotation'
        }
      });

      // Update current key ID
      await storage.put('audit:currentKeyId', newKeyId);

      return newKeyId;
    },
    {
      timeout: 10_000,
      purpose: 'audit:rotate'
    }
  );
}
```

---

## Verification

### Complete Chain Verification

```typescript
/**
 * Verify entire audit log chain.
 *
 * CHECKS:
 * 1. Sequence numbers are complete (no gaps)
 * 2. Chain hashes link correctly (previousHash = chainHash[n-1])
 * 3. All signatures valid
 * 4. Timestamps are monotonic
 *
 * @returns { valid, errors }
 */
export async function verifyAuditChain(): Promise<{
  valid: boolean;
  errors: string[];
}> {
  const errors: string[] = [];

  // Check 1: Sequence complete
  const seqCheck = await verifySequence();
  if (!seqCheck.valid) {
    errors.push(`Sequence gaps: ${seqCheck.gaps.join(', ')}`);
    errors.push(`Sequence duplicates: ${seqCheck.duplicates.join(', ')}`);
  }

  // Load all entries
  const entries = await audit.getAll();
  entries.sort((a, b) => a.seqNum - b.seqNum);

  // Check 2: Chain links
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].previousHash !== entries[i - 1].chainHash) {
      errors.push(`Chain break at seqNum ${entries[i].seqNum}: ` +
        `previousHash=${entries[i].previousHash} but ` +
        `expected=${entries[i - 1].chainHash}`);
    }
  }

  // Check 3: Signatures
  const auditKeys = await audit.getAllPublicKeys();
  for (const entry of entries) {
    const publicKey = auditKeys[entry.auditKeyId];
    if (!publicKey) {
      errors.push(`Missing audit public key: ${entry.auditKeyId}`);
      continue;
    }

    const valid = await verifyAuditSignature(entry, publicKey);
    if (!valid) {
      errors.push(`Invalid signature at seqNum ${entry.seqNum}`);
    }
  }

  // Check 4: Timestamp ordering
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].timestamp < entries[i - 1].timestamp) {
      errors.push(`Timestamp not monotonic at seqNum ${entries[i].seqNum}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
```

---

## Implementation

### Logging Function

```typescript
/**
 * Log operation to audit trail.
 *
 * FLOW:
 * 1. Get next sequence number
 * 2. Get previousHash
 * 3. Build entry (without chainHash/signature)
 * 4. Compute chainHash
 * 5. Sign chainHash
 * 6. Store entry
 * 7. Check if anchor needed
 *
 * @param data Operation data
 * @param mkek Master Key Encryption Key (from unlock context, if available)
 */
export async function logAudit(
  data: {
    op: string;
    kid?: string;
    requestId: string;
    unlockTime?: number;
    lockTime?: number;
    duration?: number;
    details?: Record<string, unknown>;
  },
  mkek?: CryptoKey
): Promise<void> {
  // Get sequence number
  const seqNum = await getNextSeqNum();

  // Get previousHash
  const previousHash = await getPreviousHash(seqNum);

  // Get audit key ID
  const auditKeyId = await audit.getCurrentKeyId();

  // Build entry (partial)
  const partial: Omit<AuditEntry, 'chainHash' | 'signature'> = {
    kmsVersion: 2,
    seqNum,
    timestamp: Date.now(),
    op: data.op,
    kid: data.kid || '',
    requestId: data.requestId,
    origin: self.location?.origin,
    unlockTime: data.unlockTime || 0,
    lockTime: data.lockTime || 0,
    duration: data.duration || 0,
    details: data.details,
    previousHash,
    auditKeyId
  };

  // Compute chainHash
  const chainHash = await computeChainHash(partial);

  // Sign (if MKEK available, otherwise queue for signing)
  let signature = '';
  if (mkek) {
    signature = await signAuditEntry({ ...partial, chainHash }, auditKeyId, mkek);
  } else {
    // Queue for signing on next unlock
    // (Some operations like setup don't have unlock context)
    signature = 'UNSIGNED';
  }

  // Complete entry
  const entry: AuditEntry = {
    ...partial,
    chainHash,
    signature
  };

  // Store
  await storage.put(`audit:${seqNum}`, entry);

  // Update state
  const state = await storage.get('audit:state');
  await storage.put('audit:state', {
    ...state,
    totalEntries: state.totalEntries + 1,
    lastTimestamp: entry.timestamp,
    lastChainHash: chainHash
  });

  // Check if anchor needed
  if (shouldInsertAnchor(seqNum)) {
    await insertAnchor();
  }
}
```

---

## Security Analysis

### Threat Model

**Protected Against**:
- ✅ **Entry modification**: Signature verification fails
- ✅ **Entry deletion**: Chain break (previousHash mismatch)
- ✅ **Log truncation**: Sequence number gaps detected
- ✅ **Replay attacks**: Unique requestId + timestamp
- ✅ **Forgery (without key)**: Ed25519 signature required

**NOT Protected Against**:
- ❌ **Forgery (with key)**: If attacker gets audit private key, can forge
- ❌ **Rollback (with key)**: Attacker could regenerate chain from checkpoint
- ❌ **Complete deletion**: If entire log deleted, no evidence remains

### Mitigation for Key Compromise

1. **Non-Extractable**: Audit key cannot be exported from KMS
2. **Backup Ceremony**: Explicit user action required
3. **Periodic Rotation**: Rotate audit key every 90 days
4. **External Anchors**: Timestamp anchors to external transparency logs (future)

### Periodic Anchors Defense

**Attack**: Attacker gets audit key, replaces last N entries
**Defense**: Anchors published to external transparency log (Rekor, Certificate Transparency)
**Verification**: User can verify anchor matches external record

---

## References

- **Ed25519**: RFC 8032
- **Tamper-Evident Logging**: Schneier, "Applied Cryptography"
- **Audit Trails**: NIST SP 800-92
- **Transparency Logs**: Rekor, Certificate Transparency

---

**Next**: [06-multi-enrollment.md](./06-multi-enrollment.md) - Multiple credentials wrapping same MS
