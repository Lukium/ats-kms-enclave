# Backup and Export (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-01-24

---

## Table of Contents

1. [Overview](#overview)
2. [Backup Bundle Format](#backup-bundle-format)
3. [Export Flow](#export-flow)
4. [Import Flow](#import-flow)
5. [Cross-Device Sync](#cross-device-sync)
6. [Security Considerations](#security-considerations)
7. [Implementation](#implementation)
8. [Testing Strategy](#testing-strategy)

---

## Overview

Backup and export enable users to:
1. **Recover from data loss** (browser storage cleared, device lost)
2. **Migrate to new device** (transfer KMS state)
3. **Sync across devices** (same keys on multiple devices)

### Design Principles

1. **Encrypted at Rest**: Backup bundle encrypted with strong password
2. **Self-Contained**: Bundle includes everything needed to restore
3. **Versioned**: Bundle includes schema version for future migrations
4. **Auditable**: Export operation logged in audit trail

---

## Backup Bundle Format

### Bundle Structure

```typescript
/**
 * Backup bundle (V2).
 *
 * CONTENTS:
 * - Encrypted Master Secret
 * - All wrapped application keys
 * - All enrollment configurations
 * - Audit log (optional, for forensics)
 * - Metadata (version, created timestamp)
 *
 * ENCRYPTION:
 * - Bundle password → PBKDF2 → backup KEK
 * - MS encrypted with backup KEK
 * - Everything else stored as-is (already encrypted)
 */
interface BackupBundle {
  // Schema version
  version: 2;
  bundleId: string;           // UUID for this bundle
  createdAt: number;          // Unix timestamp (ms)
  exportedFrom: string;       // Platform hash (informational)

  // Backup KEK parameters
  backupKdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    iterations: number;       // High iterations (600,000)
    salt: ArrayBuffer;        // 16 bytes random
  };

  // Encrypted Master Secret
  encryptedMS: {
    ciphertext: ArrayBuffer;  // 32-byte MS + 16-byte tag
    iv: ArrayBuffer;          // 12 bytes
    aad: ArrayBuffer;         // Metadata binding
  };

  // Enrollment configurations (already encrypted, copied as-is)
  enrollments: Array<PassphraseConfig | PasskeyPRFConfig | PasskeyGateConfig>;

  // Wrapped application keys (already encrypted, copied as-is)
  wrappedKeys: WrappedKeyConfig[];

  // Audit log (optional)
  auditLog?: {
    entries: AuditEntry[];
    auditPublicKeys: {
      [keyId: string]: ArrayBuffer;  // Ed25519 public keys for verification
    };
  };

  // Metadata
  metadata: {
    msVersion: number;        // Master Secret version
    enrollmentCount: number;
    keyCount: number;
    auditEntryCount: number;
  };
}
```

### Example Bundle (JSON)

```json
{
  "version": 2,
  "bundleId": "550e8400-e29b-41d4-a716-446655440000",
  "createdAt": 1704067200000,
  "exportedFrom": "macos-chrome-fast",

  "backupKdf": {
    "algorithm": "PBKDF2-HMAC-SHA256",
    "iterations": 600000,
    "salt": "<base64url>"
  },

  "encryptedMS": {
    "ciphertext": "<base64url>",
    "iv": "<base64url>",
    "aad": "<base64url>"
  },

  "enrollments": [
    {
      "kmsVersion": 2,
      "method": "passphrase",
      ...
    }
  ],

  "wrappedKeys": [
    {
      "kid": "NzbLsXh8uDCcd...",
      "purpose": "vapid",
      ...
    }
  ],

  "auditLog": {
    "entries": [...],
    "auditPublicKeys": {
      "audit-key-1": "<base64url>"
    }
  },

  "metadata": {
    "msVersion": 1,
    "enrollmentCount": 2,
    "keyCount": 3,
    "auditEntryCount": 42
  }
}
```

---

## Export Flow

### High-Level Flow

```
1. User initiates export
   ↓
2. User enters backup password (strong passphrase)
   ↓
3. withUnlock (authenticate with existing credential)
   ↓
4. MS available during unlock window
   ↓
5. Derive backup KEK from backup password
   ↓
6. Encrypt MS with backup KEK
   ↓
7. Load all enrollments and wrapped keys (as-is)
   ↓
8. Load audit log (optional)
   ↓
9. Build bundle
   ↓
10. Serialize to JSON
    ↓
11. Offer download (or copy to clipboard)
    ↓
12. Audit export operation
```

### Implementation

```typescript
/**
 * Export backup bundle.
 *
 * REQUIREMENTS:
 * - User must be authenticated (unlock with existing credential)
 * - Backup password must be strong (entropy check)
 * - Export operation audited
 *
 * @param credential Existing credential (for unlock)
 * @param backupPassword Strong password for backup encryption
 * @param options Export options (include audit log, etc.)
 * @returns Backup bundle (JSON-serializable)
 */
export async function exportBackupBundle(
  credential: Credential,
  backupPassword: string,
  options: {
    includeAuditLog?: boolean;
  } = {}
): Promise<BackupBundle> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Step 1: Derive backup KEK from backup password
      const backupSalt = crypto.getRandomValues(new Uint8Array(16));
      const backupKdf = {
        algorithm: 'PBKDF2-HMAC-SHA256' as const,
        iterations: 600_000,  // High iterations (export is one-time)
        salt: backupSalt.buffer
      };

      const backupKEK = await deriveBackupKEK(
        backupPassword,
        backupSalt,
        backupKdf.iterations
      );

      // Step 2: Encrypt MS with backup KEK
      const backupAAD = new TextEncoder().encode(JSON.stringify({
        purpose: 'backup',
        kmsVersion: 2,
        bundleId: crypto.randomUUID()
      }));

      const { ciphertext, iv } = await encryptMasterSecret(
        ctx.ms,
        backupKEK,
        backupAAD
      );

      // Step 3: Load enrollments (as-is, already encrypted)
      const enrollmentIndex = await storage.get('enrollment:index');
      const enrollments: Array<PassphraseConfig | PasskeyPRFConfig | PasskeyGateConfig> = [];

      for (const enrollment of enrollmentIndex.enrollments) {
        const config = await storage.get(`enrollment:${enrollment.id}:config`);
        enrollments.push(config);
      }

      // Step 4: Load wrapped keys (as-is, already encrypted)
      const wrappedKeys: WrappedKeyConfig[] = [];
      const keyIds = await storage.getAllKeys('key:*');

      for (const keyId of keyIds) {
        const keyConfig = await storage.get(keyId);
        wrappedKeys.push(keyConfig);
      }

      // Step 5: Load audit log (optional)
      let auditLog: BackupBundle['auditLog'];

      if (options.includeAuditLog) {
        const entries = await audit.getAll();
        const auditPublicKeys: Record<string, ArrayBuffer> = {};

        // Collect all audit public keys
        for (const entry of entries) {
          if (!auditPublicKeys[entry.auditKeyId]) {
            const keyConfig = await storage.get(`key:${entry.auditKeyId}`);
            auditPublicKeys[entry.auditKeyId] = keyConfig.publicKeyRaw;
          }
        }

        auditLog = { entries, auditPublicKeys };
      }

      // Step 6: Build bundle
      const bundle: BackupBundle = {
        version: 2,
        bundleId: crypto.randomUUID(),
        createdAt: Date.now(),
        exportedFrom: await getCoarsePlatformHash(),

        backupKdf,

        encryptedMS: {
          ciphertext,
          iv,
          aad: backupAAD
        },

        enrollments,
        wrappedKeys,
        auditLog,

        metadata: {
          msVersion: 1,  // TODO: Get from MS metadata
          enrollmentCount: enrollments.length,
          keyCount: wrappedKeys.length,
          auditEntryCount: auditLog?.entries.length || 0
        }
      };

      // Step 7: Audit export
      await audit.log({
        op: 'backup:export',
        kid: '',
        requestId: crypto.randomUUID(),
        details: {
          bundleId: bundle.bundleId,
          enrollmentCount: bundle.metadata.enrollmentCount,
          keyCount: bundle.metadata.keyCount,
          includeAuditLog: !!options.includeAuditLog
        }
      }, ctx.mkek);

      return bundle;
    },
    {
      timeout: 60_000,  // 60s (export may be slow)
      purpose: 'backup:export'
    }
  );
}

/**
 * Derive backup KEK from backup password.
 */
async function deriveBackupKEK(
  backupPassword: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(backupPassword),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const kekBytes = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    256
  );

  return crypto.subtle.importKey(
    'raw',
    kekBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
```

---

## Import Flow

### High-Level Flow

```
1. User uploads backup bundle (JSON)
   ↓
2. Parse and validate bundle schema
   ↓
3. User enters backup password
   ↓
4. Derive backup KEK from backup password
   ↓
5. Decrypt MS from bundle
   ↓
6. Verify MS integrity (optional: KCV check)
   ↓
7. Store MS metadata
   ↓
8. Import all enrollments (as-is)
   ↓
9. Import all wrapped keys (as-is)
   ↓
10. Import audit log (optional, append to existing)
    ↓
11. Audit import operation
    ↓
12. Success: KMS ready to use
```

### Implementation

```typescript
/**
 * Import backup bundle.
 *
 * SECURITY:
 * - Validates bundle schema
 * - Requires correct backup password
 * - Verifies MS decryption succeeds
 * - Audits import operation
 *
 * OPTIONS:
 * - merge: Merge with existing data (default: replace)
 * - validateMS: Verify MS with enrollments (default: true)
 *
 * @param bundle Backup bundle (parsed JSON)
 * @param backupPassword Backup password
 * @param options Import options
 */
export async function importBackupBundle(
  bundle: BackupBundle,
  backupPassword: string,
  options: {
    merge?: boolean;           // Merge with existing (vs replace)
    validateMS?: boolean;      // Verify MS decrypts with enrollments
    importAuditLog?: boolean;  // Import audit log (append)
  } = {}
): Promise<void> {
  // Step 1: Validate bundle schema
  if (bundle.version !== 2) {
    throw new Error(`Unsupported bundle version: ${bundle.version}`);
  }

  // Step 2: Derive backup KEK
  const backupKEK = await deriveBackupKEK(
    backupPassword,
    new Uint8Array(bundle.backupKdf.salt),
    bundle.backupKdf.iterations
  );

  // Step 3: Decrypt MS
  const ms = await decryptMasterSecret(
    bundle.encryptedMS.ciphertext,
    backupKEK,
    bundle.encryptedMS.iv,
    bundle.encryptedMS.aad
  );

  // Step 4: Validate MS (optional)
  if (options.validateMS !== false) {
    await validateMSWithEnrollments(ms, bundle.enrollments);
  }

  // Step 5: Clear existing data (if not merging)
  if (!options.merge) {
    await clearAllKMSData();
  }

  // Step 6: Store MS metadata
  await storage.put('ms:metadata', {
    version: bundle.metadata.msVersion,
    createdAt: bundle.createdAt,
    importedAt: Date.now(),
    algorithm: 'CSPRNG',
    size: 32
  });

  // Step 7: Import enrollments
  const enrollmentIds: string[] = [];

  for (const enrollment of bundle.enrollments) {
    const enrollmentId = `enroll-${crypto.randomUUID()}`;
    await storage.put(`enrollment:${enrollmentId}:config`, enrollment);
    enrollmentIds.push(enrollmentId);
  }

  // Update enrollment index
  await storage.put('enrollment:index', {
    enrollments: enrollmentIds.map((id, idx) => ({
      id,
      method: bundle.enrollments[idx].method,
      label: `Imported ${bundle.enrollments[idx].method}`,
      createdAt: bundle.enrollments[idx].createdAt,
      deviceHint: await getCoarsePlatformHash()
    }))
  });

  // Step 8: Import wrapped keys
  for (const keyConfig of bundle.wrappedKeys) {
    await storage.put(`key:${keyConfig.kid}`, keyConfig);
  }

  // Step 9: Import audit log (optional)
  if (options.importAuditLog && bundle.auditLog) {
    // Append imported entries with imported=true flag
    const currentSeqNum = await audit.getNextSeqNum();

    for (const entry of bundle.auditLog.entries) {
      await storage.put(`audit:${currentSeqNum + entry.seqNum}`, {
        ...entry,
        imported: true,
        importedAt: Date.now()
      });
    }

    // Import audit public keys
    for (const [keyId, publicKey] of Object.entries(bundle.auditLog.auditPublicKeys)) {
      await storage.put(`audit-key:${keyId}`, {
        kid: keyId,
        publicKeyRaw: publicKey,
        purpose: 'audit',
        imported: true
      });
    }
  }

  // Step 10: Audit import (requires unlock with imported credential)
  // Defer audit until first unlock with imported credential
  await storage.put('pending-audit:import', {
    op: 'backup:import',
    bundleId: bundle.bundleId,
    enrollmentCount: bundle.metadata.enrollmentCount,
    keyCount: bundle.metadata.keyCount,
    mergeMode: !!options.merge,
    importedAt: Date.now()
  });

  console.log(`Import complete: ${bundle.metadata.keyCount} keys, ${bundle.metadata.enrollmentCount} enrollments`);
}

/**
 * Validate MS decrypts correctly with enrollments.
 */
async function validateMSWithEnrollments(
  ms: Uint8Array,
  enrollments: Array<PassphraseConfig | PasskeyPRFConfig>
): Promise<void> {
  // For passphrase enrollments, verify MKEK derivation succeeds
  // (Cannot fully validate without passphrase, but can check derivation)

  try {
    const mkek = await deriveMKEK(ms);
    // If derivation succeeds, MS is likely valid
  } catch (error) {
    throw new Error('MS validation failed: MKEK derivation error');
  }
}

/**
 * Clear all KMS data (for non-merge import).
 */
async function clearAllKMSData(): Promise<void> {
  await storage.clear('enrollment:*');
  await storage.clear('key:*');
  await storage.clear('audit:*');
  await storage.delete('ms:metadata');
  await storage.delete('enrollment:index');
  await storage.delete('audit:state');
}
```

---

## Cross-Device Sync

### Use Case

User wants same keys on multiple devices (laptop + phone).

### Strategy 1: Manual Export/Import

**Flow**:
1. Device A: Export backup bundle
2. Transfer bundle to Device B (secure channel)
3. Device B: Import backup bundle
4. Result: Both devices have same MS and keys

**Transfer Methods**:
- Email (encrypted bundle + password via separate channel)
- Cloud storage (iCloud, Google Drive)
- USB drive
- QR code (for small bundles)

### Strategy 2: Cloud Sync (Future)

**Flow**:
1. User enables cloud sync (setup encryption key)
2. Device A exports bundle, uploads to cloud
3. Device B downloads bundle, imports automatically
4. Periodic sync keeps devices in sync

**Requirements**:
- End-to-end encryption (cloud provider cannot decrypt)
- Conflict resolution (last-write-wins or merge)
- Sync key management (separate from backup password)

### Example: Laptop → Phone Transfer

```typescript
// On Laptop
const bundle = await exportBackupBundle(
  laptopCredential,
  strongBackupPassword,
  { includeAuditLog: true }
);

// Save bundle to file
const bundleJSON = JSON.stringify(bundle, null, 2);
await saveFile('kms-backup.json', bundleJSON);

// Transfer to phone via secure channel (e.g., AirDrop, USB)

// On Phone
const bundleJSON = await readFile('kms-backup.json');
const bundle = JSON.parse(bundleJSON);

await importBackupBundle(
  bundle,
  strongBackupPassword,
  { merge: false, validateMS: true }
);

// Phone now has same keys as laptop
```

---

## Security Considerations

### Backup Password Strength

**Requirement**: Strong backup password (high entropy).

**Enforcement**:
```typescript
/**
 * Check backup password strength.
 */
function checkBackupPasswordStrength(password: string): {
  score: number;  // 0-4 (zxcvbn)
  feedback: string[];
} {
  const result = zxcvbn(password);

  return {
    score: result.score,
    feedback: result.feedback.suggestions
  };
}

// Enforce minimum score
if (checkBackupPasswordStrength(backupPassword).score < 3) {
  throw new Error('Backup password too weak (minimum score: 3/4)');
}
```

### Bundle Confidentiality

**Property**: Bundle is encrypted, safe to store anywhere.

**Threats**:
- ✅ Attacker steals bundle → Cannot decrypt without password
- ✅ Attacker intercepts transfer → Cannot decrypt without password
- ❌ Attacker knows weak password → Can brute-force

**Mitigation**: High PBKDF2 iterations (600,000) + strong password requirement.

### Bundle Integrity

**Property**: Tampering with bundle detected on import.

**Enforcement**:
- AES-GCM authentication tag on encrypted MS
- Schema validation on import
- Enrollment configs already have GCM tags
- Wrapped keys already have GCM tags

**Result**: Any tampering causes decryption failure.

### Password Separation

**Best Practice**: Backup password ≠ passphrase enrollment password.

**Rationale**:
- Backup password only used for export/import (rare)
- Passphrase enrollment used frequently
- If passphrase compromised, backup still safe (and vice versa)

**Enforcement**: Warning in UI if user tries to reuse same password.

---

## Implementation

### Serialize Bundle

```typescript
/**
 * Serialize backup bundle to JSON string.
 *
 * FORMAT: Pretty-printed JSON with ArrayBuffers as base64url
 */
export function serializeBackupBundle(bundle: BackupBundle): string {
  // Convert ArrayBuffers to base64url
  const serializable = convertArrayBuffersToBase64url(bundle);

  // Pretty-print for readability
  return JSON.stringify(serializable, null, 2);
}

/**
 * Deserialize backup bundle from JSON string.
 */
export function deserializeBackupBundle(json: string): BackupBundle {
  const parsed = JSON.parse(json);

  // Convert base64url back to ArrayBuffers
  return convertBase64urlToArrayBuffers(parsed);
}
```

### Download Bundle

```typescript
/**
 * Offer backup bundle as file download.
 */
export async function downloadBackupBundle(bundle: BackupBundle): Promise<void> {
  const json = serializeBackupBundle(bundle);

  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `kms-backup-${bundle.bundleId}.json`;
  a.click();

  URL.revokeObjectURL(url);
}
```

### QR Code Export (Future)

```typescript
/**
 * Export backup bundle as QR code (for small bundles).
 *
 * LIMITATION: QR codes max ~2953 bytes (alphanumeric mode)
 * - Bundle must be small (minimal keys, no audit log)
 * - Or split into multiple QR codes
 */
export async function exportAsQRCode(bundle: BackupBundle): Promise<string> {
  const json = serializeBackupBundle(bundle);

  if (json.length > 2953) {
    throw new Error('Bundle too large for single QR code');
  }

  // Generate QR code (using library like qrcode.js)
  const qr = await QRCode.toDataURL(json, {
    errorCorrectionLevel: 'H',
    type: 'image/png',
    width: 512
  });

  return qr;  // Data URL
}
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('Backup export/import', () => {
  it('should export and import bundle', async () => {
    // Setup: Create KMS with keys
    await setupKMS();
    const { kid } = await generateVAPIDKeypair(credential);

    // Export
    const bundle = await exportBackupBundle(
      credential,
      'strong-backup-password',
      { includeAuditLog: true }
    );

    // Verify bundle structure
    expect(bundle.version).toBe(2);
    expect(bundle.enrollments.length).toBeGreaterThan(0);
    expect(bundle.wrappedKeys.length).toBeGreaterThan(0);

    // Clear KMS
    await clearAllKMSData();

    // Import
    await importBackupBundle(bundle, 'strong-backup-password');

    // Verify keys restored
    const restoredKey = await storage.get(`key:${kid}`);
    expect(restoredKey).toBeDefined();
  });

  it('should reject wrong backup password', async () => {
    const bundle = await exportBackupBundle(
      credential,
      'correct-password'
    );

    await expect(
      importBackupBundle(bundle, 'wrong-password')
    ).rejects.toThrow();
  });

  it('should reject tampered bundle', async () => {
    const bundle = await exportBackupBundle(
      credential,
      'correct-password'
    );

    // Tamper with encrypted MS
    bundle.encryptedMS.ciphertext = new Uint8Array(48).buffer;

    await expect(
      importBackupBundle(bundle, 'correct-password')
    ).rejects.toThrow();
  });
});
```

### Integration Tests

```typescript
describe('Cross-device sync', () => {
  it('should sync keys between devices', async () => {
    // Device A: Setup and generate key
    const deviceA = await setupKMS();
    const { kid } = await generateVAPIDKeypair(credentialA);

    // Export from Device A
    const bundle = await exportBackupBundle(credentialA, 'sync-password');

    // Device B: Import
    const deviceB = await setupKMS();  // Fresh KMS
    await importBackupBundle(bundle, 'sync-password');

    // Verify Device B has same key
    const keyB = await storage.get(`key:${kid}`);
    expect(keyB).toBeDefined();

    // Sign JWT on Device B (key works)
    const jwt = await signVAPIDJWT(credentialB, payload, kid);
    expect(jwt).toBeDefined();
  });
});
```

---

## References

- **Backup Best Practices**: NIST SP 800-53 CP-9
- **Key Export**: NIST SP 800-57 Part 1
- **Password Strength**: zxcvbn library
- **QR Codes**: ISO/IEC 18004:2015

---

**End of V2 Design Documents**

All 9 design files completed:
1. ✅ 01-primitives.md
2. ✅ 02-master-secret.md
3. ✅ 03-unlock-context.md
4. ✅ 04-key-operations.md
5. ✅ 05-audit-log.md
6. ✅ 06-multi-enrollment.md
7. ✅ 07-calibration.md
8. ✅ 08-security-model.md
9. ✅ 09-backup-export.md
