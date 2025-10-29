# Multi-Enrollment (V2)

**Status**: Design Phase
**Version**: 2.0
**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Benefits](#benefits)
4. [Enrollment Management](#enrollment-management)
5. [Migration Scenarios](#migration-scenarios)
6. [Storage Strategy](#storage-strategy)
7. [Security Considerations](#security-considerations)
8. [Implementation](#implementation)
9. [Testing Strategy](#testing-strategy)

---

## Overview

Multi-enrollment is a **V2 feature** that allows a single Master Secret (MS) to be encrypted by multiple credentials. This enables users to authenticate with any of their enrolled methods.

### Single MS, Multiple Wrappers

```
             Master Secret (32 bytes)
                     |
      ┌──────────────┼──────────────┬──────────────┐
      │              │              │              │
   KEK₁ (passphrase) KEK₂ (passkey #1) KEK₃ (passkey #2) KEK₄ (passkey gate)
      │              │              │              │
  Config₁        Config₂        Config₃        Config₄
```

**Key Insight**: All configs encrypt the **same MS**, but with different KEKs.

### Use Cases

1. **Redundancy**: Backup authentication method
2. **Migration**: Add new method before removing old
3. **Device-Specific**: Different methods on different devices
4. **Recovery**: Recover access if primary method lost

---

## Architecture

### Enrollment Types

```typescript
type EnrollmentType =
  | 'passphrase'      // Password-based (PBKDF2)
  | 'passkey-prf'     // WebAuthn PRF extension
  | 'passkey-gate'    // WebAuthn + PBKDF2 (future)
  ;
```

### Enrollment Configuration

Each enrollment has its own configuration:

```typescript
// Enrollment index
interface EnrollmentIndex {
  enrollments: {
    id: string;               // UUID for this enrollment
    method: EnrollmentType;
    label: string;            // User-friendly name ("My Password", "YubiKey 5", etc.)
    createdAt: number;
    lastUsedAt?: number;
    deviceHint?: string;      // Coarse device fingerprint (for sorting)
  }[];
}

// Example
{
  enrollments: [
    {
      id: "enroll-001",
      method: "passphrase",
      label: "My Password",
      createdAt: 1704067200000,
      lastUsedAt: 1704067200000
    },
    {
      id: "enroll-002",
      method: "passkey-prf",
      label: "YubiKey 5 NFC",
      createdAt: 1704067210000,
      lastUsedAt: 1704067210000,
      deviceHint: "linux-chrome"
    },
    {
      id: "enroll-003",
      method: "passkey-prf",
      label: "TouchID (MacBook)",
      createdAt: 1704067220000,
      deviceHint: "macos-safari"
    }
  ]
}
```

### Storage Layout

```
IndexedDB: kms-v2

Objects:
  enrollment:index              → EnrollmentIndex
  enrollment:enroll-001:config  → PassphraseConfig
  enrollment:enroll-002:config  → PasskeyPRFConfig
  enrollment:enroll-003:config  → PasskeyPRFConfig
  ms:metadata                   → { createdAt, version }
```

---

## Benefits

### 1. Redundancy

**Problem**: Lose passkey device → locked out permanently.
**Solution**: Enroll multiple passkeys + backup passphrase.

```typescript
// Setup: Primary + backup
const primary = await enrollPasskey({ label: "YubiKey 5" });
const backup = await enrollPassphrase({
  label: "Recovery Password",
  strength: "strong"
});

// If primary lost, use backup
await unlockWithPassphrase(backupPassword);
```

### 2. Migration

**Problem**: Want to move from passphrase → passkey without disruption.
**Solution**: Add passkey while keeping passphrase, test, then remove passphrase.

```typescript
// Step 1: Add passkey (passphrase still works)
await addEnrollment({ method: 'passkey-prf', label: "YubiKey" });

// Step 2: Test passkey
await testUnlock({ enrollmentId: 'enroll-002' });

// Step 3: Remove passphrase (once confident)
await removeEnrollment({ enrollmentId: 'enroll-001' });
```

### 3. Device-Specific

**Problem**: TouchID on MacBook, fingerprint on Android, YubiKey on desktop.
**Solution**: Enroll device-specific passkeys, UI suggests correct one per device.

```typescript
// Enrollment hints
const enrollments = await getEnrollments();

// Filter by current device
const suggested = enrollments.filter(e =>
  e.deviceHint === getCurrentPlatformHint()
);

// Show suggested first in UI
```

### 4. Recovery

**Problem**: Primary passkey lost (device stolen, broken).
**Solution**: Recovery passphrase or backup passkey.

```typescript
// Recovery flow
if (primaryPasskeyUnavailable) {
  // Offer alternatives
  const alternatives = enrollments.filter(e => e.id !== primaryId);

  // User selects recovery method
  const method = await promptRecoveryMethod(alternatives);

  // Unlock with alternative
  await unlockWith(method);
}
```

---

## Enrollment Management

### Add Enrollment

```typescript
/**
 * Add new enrollment (wrap MS with new credential).
 *
 * REQUIREMENTS:
 * - User must be authenticated (unlock with existing credential)
 * - MS must be available during unlock window
 * - New credential must be distinct (no duplicate passkeys)
 *
 * FLOW:
 * 1. Unlock with existing credential
 * 2. Setup new credential (derive KEK)
 * 3. Wrap MS with new KEK
 * 4. Store new config
 * 5. Update enrollment index
 *
 * @param existingCredential Current credential (for unlock)
 * @param newEnrollment New enrollment details
 * @returns Enrollment ID
 */
export async function addEnrollment(
  existingCredential: Credential,
  newEnrollment: {
    method: EnrollmentType;
    label: string;
    // Method-specific params
    passphrase?: string;
    credentialId?: ArrayBuffer;
  }
): Promise<string> {
  return withUnlock(
    existingCredential,
    async (ctx) => {
      // Generate enrollment ID
      const enrollmentId = `enroll-${crypto.randomUUID()}`;

      // Derive KEK for new method
      let kek: CryptoKey;
      let config: PassphraseConfig | PasskeyPRFConfig;

      switch (newEnrollment.method) {
        case 'passphrase':
          // Calibrate iterations
          const { iterations } = await calibratePBKDF2Iterations();

          // Generate salt
          const salt = crypto.getRandomValues(new Uint8Array(16));

          // Derive KEK
          kek = await deriveKEKFromPassphrase(
            newEnrollment.passphrase!,
            salt,
            iterations
          );

          // Generate KCV
          const kcv = await generateKCV(kek);

          config = {
            kmsVersion: 2,
            algVersion: 1,
            method: 'passphrase',
            kdf: {
              algorithm: 'PBKDF2-HMAC-SHA256',
              iterations,
              salt: salt.buffer,
              lastCalibratedAt: Date.now(),
              platformHash: await getCoarsePlatformHash()
            },
            kcv,
            encryptedMS: new ArrayBuffer(0),  // Filled below
            msIV: new ArrayBuffer(0),
            msAAD: new ArrayBuffer(0),
            msVersion: 1,
            createdAt: Date.now(),
            updatedAt: Date.now()
          };
          break;

        case 'passkey-prf':
          // Generate salts
          const appSalt = crypto.getRandomValues(new Uint8Array(32));
          const hkdfSalt = crypto.getRandomValues(new Uint8Array(32));

          // Derive KEK via WebAuthn PRF
          kek = await deriveKEKFromPasskeyPRF(
            newEnrollment.credentialId!,
            'kms.ats.run',
            appSalt,
            hkdfSalt
          );

          config = {
            kmsVersion: 2,
            algVersion: 1,
            method: 'passkey-prf',
            credentialId: newEnrollment.credentialId!,
            rpId: 'kms.ats.run',
            kdf: {
              algorithm: 'HKDF-SHA256',
              appSalt: appSalt.buffer,
              hkdfSalt: hkdfSalt.buffer,
              info: 'ATS/KMS/KEK-wrap/v2'
            },
            encryptedMS: new ArrayBuffer(0),
            msIV: new ArrayBuffer(0),
            msAAD: new ArrayBuffer(0),
            msVersion: 1,
            createdAt: Date.now(),
            updatedAt: Date.now()
          };
          break;
      }

      // Build AAD
      const aad = buildMSEncryptionAAD({
        kmsVersion: 2,
        method: newEnrollment.method,
        algVersion: 1,
        purpose: 'master-secret',
        credentialId: newEnrollment.credentialId
      });

      // Encrypt MS with new KEK
      const { ciphertext, iv } = await encryptMasterSecret(
        ctx.ms,
        kek,
        new Uint8Array(aad)
      );

      // Update config with encrypted MS
      config.encryptedMS = ciphertext;
      config.msIV = iv;
      config.msAAD = aad;

      // Store config
      await storage.put(`enrollment:${enrollmentId}:config`, config);

      // Update enrollment index
      const index = await storage.get('enrollment:index') || { enrollments: [] };
      index.enrollments.push({
        id: enrollmentId,
        method: newEnrollment.method,
        label: newEnrollment.label,
        createdAt: Date.now(),
        deviceHint: await getCoarsePlatformHint()
      });
      await storage.put('enrollment:index', index);

      // Audit
      await audit.log({
        op: 'enrollment:add',
        kid: enrollmentId,
        requestId: crypto.randomUUID(),
        details: {
          method: newEnrollment.method,
          label: newEnrollment.label,
          totalEnrollments: index.enrollments.length
        }
      }, ctx.mkek);

      return enrollmentId;
    },
    {
      timeout: 30_000,  // WebAuthn may be slow
      purpose: 'enrollment:add'
    }
  );
}
```

### Remove Enrollment

```typescript
/**
 * Remove enrollment.
 *
 * SAFETY:
 * - Require at least 1 enrollment remains
 * - Require authentication with existing credential
 * - Confirm removal (prevent accidental lockout)
 *
 * @param credential Current credential (for authentication)
 * @param enrollmentId Enrollment to remove
 */
export async function removeEnrollment(
  credential: Credential,
  enrollmentId: string
): Promise<void> {
  return withUnlock(
    credential,
    async (ctx) => {
      // Load enrollment index
      const index = await storage.get('enrollment:index');
      if (!index) {
        throw new Error('No enrollments found');
      }

      // Check at least 2 enrollments (can't remove last one)
      if (index.enrollments.length <= 1) {
        throw new Error('Cannot remove last enrollment');
      }

      // Find enrollment
      const enrollment = index.enrollments.find(e => e.id === enrollmentId);
      if (!enrollment) {
        throw new Error(`Enrollment not found: ${enrollmentId}`);
      }

      // Delete configuration
      await storage.delete(`enrollment:${enrollmentId}:config`);

      // Update index
      index.enrollments = index.enrollments.filter(e => e.id !== enrollmentId);
      await storage.put('enrollment:index', index);

      // Audit
      await audit.log({
        op: 'enrollment:remove',
        kid: enrollmentId,
        requestId: crypto.randomUUID(),
        details: {
          method: enrollment.method,
          label: enrollment.label,
          remainingEnrollments: index.enrollments.length
        }
      }, ctx.mkek);
    },
    {
      timeout: 10_000,
      purpose: 'enrollment:remove'
    }
  );
}
```

### List Enrollments

```typescript
/**
 * List all enrollments (no authentication required).
 *
 * @returns Array of enrollment metadata
 */
export async function listEnrollments(): Promise<{
  id: string;
  method: EnrollmentType;
  label: string;
  createdAt: number;
  lastUsedAt?: number;
  deviceHint?: string;
}[]> {
  const index = await storage.get('enrollment:index');
  if (!index) {
    return [];
  }

  return index.enrollments;
}
```

---

## Migration Scenarios

### Scenario 1: Passphrase → Passkey

**Goal**: Move from password-based to WebAuthn.

```typescript
// Step 1: User has passphrase
const enrollments = await listEnrollments();
// [{ method: 'passphrase', label: "My Password" }]

// Step 2: Add passkey
await addEnrollment(
  { method: 'passphrase', passphrase: currentPassword },
  { method: 'passkey-prf', label: "YubiKey 5" }
);

// Step 3: Test passkey works
const testUnlock = await unlockWithPasskey(newCredentialId);
// Success!

// Step 4: Remove passphrase
await removeEnrollment(
  { method: 'passkey-prf', credentialId: newCredentialId },
  passphraseEnrollmentId
);

// Final state: [{ method: 'passkey-prf', label: "YubiKey 5" }]
```

### Scenario 2: Single Passkey → Multiple Passkeys

**Goal**: Add backup passkey for redundancy.

```typescript
// Current: YubiKey 5
const enrollments = await listEnrollments();
// [{ method: 'passkey-prf', label: "YubiKey 5" }]

// Add backup
await addEnrollment(
  { method: 'passkey-prf', credentialId: yubikey5Id },
  { method: 'passkey-prf', label: "Backup YubiKey" }
);

// Final: Both work
// [
//   { method: 'passkey-prf', label: "YubiKey 5" },
//   { method: 'passkey-prf', label: "Backup YubiKey" }
// ]
```

### Scenario 3: Device Migration

**Goal**: Transfer to new device without losing access.

```typescript
// On old device: Export backup
const backupBundle = await exportBackupBundle(
  oldCredential,
  backupPassword
);

// Transfer backup to new device (secure channel)

// On new device: Import backup
await importBackupBundle(backupBundle, backupPassword);

// Add new device's passkey
await addEnrollment(
  { method: 'passphrase', passphrase: backupPassword },
  { method: 'passkey-prf', label: "New Device TouchID" }
);

// Now both devices work
```

---

## Storage Strategy

### IndexedDB Schema

```typescript
// Database: kms-v2
// Version: 2

const schema = {
  stores: {
    // Enrollment index (no sensitive data)
    'enrollment:index': {
      keyPath: null,
      value: {
        enrollments: Array<{
          id: string;
          method: string;
          label: string;
          createdAt: number;
          lastUsedAt?: number;
          deviceHint?: string;
        }>
      }
    },

    // Enrollment configurations (encrypted MS per enrollment)
    'enrollment:{id}:config': {
      keyPath: null,
      value: PassphraseConfig | PasskeyPRFConfig | PasskeyGateConfig
    },

    // MS metadata (non-sensitive)
    'ms:metadata': {
      keyPath: null,
      value: {
        version: number;
        createdAt: number;
        algorithm: 'CSPRNG';
        size: 32;
      }
    }
  }
};
```

### Consistency Guarantees

```typescript
/**
 * Verify all enrollments decrypt to same MS.
 *
 * INTEGRITY CHECK:
 * - Load all enrollment configs
 * - Decrypt MS with each (requires credentials)
 * - Verify all MS values identical
 *
 * @param credentials Map of enrollment ID → credential
 * @returns { consistent, mismatches }
 */
export async function verifyMSConsistency(
  credentials: Map<string, Credential>
): Promise<{
  consistent: boolean;
  mismatches: string[];
}> {
  const enrollments = await listEnrollments();
  const decryptedMS: Map<string, Uint8Array> = new Map();

  // Decrypt MS with each credential
  for (const enrollment of enrollments) {
    const credential = credentials.get(enrollment.id);
    if (!credential) {
      continue;  // Skip if credential not provided
    }

    const ms = await withUnlock(
      credential,
      async (ctx) => {
        return new Uint8Array(ctx.ms);  // Copy MS
      }
    );

    decryptedMS.set(enrollment.id, ms);
  }

  // Compare all MS values
  const msArray = Array.from(decryptedMS.values());
  const reference = msArray[0];
  const mismatches: string[] = [];

  for (const [enrollmentId, ms] of decryptedMS.entries()) {
    if (!arrayEquals(ms, reference)) {
      mismatches.push(enrollmentId);
    }
  }

  return {
    consistent: mismatches.length === 0,
    mismatches
  };
}
```

---

## Security Considerations

### MS Uniqueness

**Critical**: All enrollments must encrypt the **same MS**.

**Enforcement**:
- MS generated once during initial setup
- `addEnrollment` uses existing MS (from unlock context)
- Never generate new MS during enrollment

**Verification**:
- `verifyMSConsistency()` checks all enrollments decrypt to same MS
- Run periodically or on-demand

### Enrollment Isolation

**Property**: Compromising one enrollment doesn't compromise others.

**Why**: Each KEK is independent:
- Passphrase: PBKDF2 with unique salt
- Passkey PRF: Unique appSalt per enrollment
- No shared secrets between enrollments

**Benefit**: Can remove compromised enrollment without re-encrypting MS.

### Minimum Enrollment Count

**Rule**: At least 1 enrollment must exist.

**Enforcement**:
- `removeEnrollment()` checks `enrollments.length > 1`
- Cannot remove last enrollment
- Prevents accidental lockout

### Passkey Uniqueness

**Problem**: Same passkey enrolled twice creates confusion.

**Detection**:
```typescript
function isDuplicatePasskey(
  credentialId: ArrayBuffer,
  existingEnrollments: Enrollment[]
): boolean {
  return existingEnrollments.some(e =>
    e.method === 'passkey-prf' &&
    arrayEquals(e.config.credentialId, credentialId)
  );
}
```

**Prevention**: Check before adding enrollment.

---

## Implementation

### Initial Setup

```typescript
/**
 * Initial setup with first enrollment.
 *
 * @param method Enrollment method
 * @param credential Credential data
 * @returns Enrollment ID
 */
export async function setupInitialEnrollment(
  method: EnrollmentType,
  credential: { passphrase?: string; credentialId?: ArrayBuffer },
  label: string
): Promise<string> {
  // Generate Master Secret
  const ms = generateMasterSecret();

  // Store MS metadata
  await storage.put('ms:metadata', {
    version: 2,
    createdAt: Date.now(),
    algorithm: 'CSPRNG',
    size: 32
  });

  // Create first enrollment
  const enrollmentId = `enroll-${crypto.randomUUID()}`;

  // Setup credential (method-specific)
  const kek = await setupCredentialKEK(method, credential);

  // Build AAD
  const aad = buildMSEncryptionAAD({
    kmsVersion: 2,
    method,
    algVersion: 1,
    purpose: 'master-secret',
    credentialId: credential.credentialId
  });

  // Encrypt MS
  const { ciphertext, iv } = await encryptMasterSecret(
    ms,
    kek,
    new Uint8Array(aad)
  );

  // Build config (method-specific)
  const config = buildEnrollmentConfig(
    method,
    credential,
    ciphertext,
    iv,
    aad
  );

  // Store config
  await storage.put(`enrollment:${enrollmentId}:config`, config);

  // Initialize enrollment index
  await storage.put('enrollment:index', {
    enrollments: [{
      id: enrollmentId,
      method,
      label,
      createdAt: Date.now(),
      deviceHint: await getCoarsePlatformHash()
    }]
  });

  // Generate initial audit key
  // (Requires unlock, so defer or do minimal setup)

  return enrollmentId;
}
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('Multi-enrollment', () => {
  it('should add second enrollment', async () => {
    // Setup: Initial passphrase
    const enroll1 = await setupInitialEnrollment(
      'passphrase',
      { passphrase: 'password123' },
      'My Password'
    );

    // Add passkey
    const enroll2 = await addEnrollment(
      { method: 'passphrase', passphrase: 'password123' },
      { method: 'passkey-prf', label: 'YubiKey' }
    );

    // Verify both work
    const enrollments = await listEnrollments();
    expect(enrollments).toHaveLength(2);
  });

  it('should unlock with either enrollment', async () => {
    // Setup: Two enrollments
    await setupTwoEnrollments();

    // Unlock with first
    const ms1 = await unlockWith(credential1);

    // Unlock with second
    const ms2 = await unlockWith(credential2);

    // Same MS
    expect(arrayEquals(ms1, ms2)).toBe(true);
  });

  it('should prevent removing last enrollment', async () => {
    // Setup: Single enrollment
    const enroll1 = await setupInitialEnrollment(...);

    // Attempt to remove
    await expect(
      removeEnrollment(credential1, enroll1)
    ).rejects.toThrow('Cannot remove last enrollment');
  });

  it('should detect duplicate passkeys', async () => {
    // Setup: Passkey enrollment
    const enroll1 = await setupInitialEnrollment(
      'passkey-prf',
      { credentialId: yubikey5Id },
      'YubiKey'
    );

    // Attempt to add same passkey again
    await expect(
      addEnrollment(
        { method: 'passkey-prf', credentialId: yubikey5Id },
        { method: 'passkey-prf', credentialId: yubikey5Id, label: 'Duplicate' }
      )
    ).rejects.toThrow('Duplicate passkey');
  });
});
```

### Integration Tests

```typescript
describe('Multi-enrollment integration', () => {
  it('should complete migration flow', async () => {
    // Start: Passphrase only
    const enroll1 = await setupInitialEnrollment(
      'passphrase',
      { passphrase: 'old-password' },
      'Old Password'
    );

    // Add passkey
    const enroll2 = await addEnrollment(
      { method: 'passphrase', passphrase: 'old-password' },
      { method: 'passkey-prf', label: 'YubiKey' }
    );

    // Remove passphrase
    await removeEnrollment(
      { method: 'passkey-prf', credentialId: yubikey5Id },
      enroll1
    );

    // Verify only passkey remains
    const enrollments = await listEnrollments();
    expect(enrollments).toHaveLength(1);
    expect(enrollments[0].method).toBe('passkey-prf');
  });
});
```

---

## References

- **Multi-Factor Authentication**: NIST SP 800-63B
- **WebAuthn**: W3C WebAuthn Level 2
- **Key Wrapping**: NIST SP 800-38F

---

**Next**: [07-calibration.md](./07-calibration.md) - PBKDF2 calibration algorithm
