# Phase 1 Full Demo: Complete KMS Lifecycle

This demo provides a comprehensive, interactive demonstration of the entire KMS V2 lifecycle, including enrollment, authentication, key operations, lease management, and audit logging.

## Overview

Unlike the iframe-isolation demo (which focuses on cross-origin communication), this demo provides a **user-facing interface** that demonstrates:

1. **Initial Setup**: Passphrase and WebAuthn enrollment
2. **Persistent Storage**: Refresh the page and continue where you left off
3. **User Authentication**: Unlock with passphrase or WebAuthn
4. **Cryptographic Operations**: Sign data, issue JWTs, generate keys
5. **Lease Management**: Issue leases for background JWT generation
6. **Background Operations**: PWA requests JWTs using leases (no user auth required)
7. **Persistent Audit Trail**: Complete audit log from first KIAK initialization, survives page refreshes
8. **Full Lifecycle**: KIAK Init → Setup → Unlock → Operate → Lock → Reset Demo

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Parent PWA (UI)                        │
│  ┌───────────────────────┐  ┌──────────────────────────┐   │
│  │  LEFT PANE            │  │  RIGHT PANE              │   │
│  │  - Operations         │  │  - Full Audit Log        │   │
│  │  - Setup buttons      │  │  - All entries (KIAK→)   │   │
│  │  - Unlock controls    │  │  - Persists on refresh   │   │
│  │  - Crypto operations  │  │  - Chain verification    │   │
│  │  - Lease management   │  │  - Expandable entries    │   │
│  │  - Reset Demo button  │  │  - Export capability     │   │
│  └───────────────────────┘  └──────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ postMessage (cross-origin)
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              KMS Enclave (cross-origin iframe)              │
│  Origin: http://localhost:5175 (separate Vite server)      │
│  - Handles all cryptographic operations                     │
│  - Manages non-extractable keys                            │
│  - Issues and validates leases                             │
│  - Maintains tamper-evident audit log in IndexedDB         │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### Split-Pane Layout

**LEFT PANE (Operations)**:
- All user interactions (setup, unlock, operations, leases)
- Status indicators and control buttons
- Latest operation results
- Reset Demo button (bottom)

**RIGHT PANE (Audit Log)**:
- **Complete audit history** starting from KIAK initialization
- **Persists across page refreshes** (loaded from IndexedDB on startup)
- Real-time updates as operations occur
- Expandable entries showing full cryptographic artifacts
- Chain verification status
- Export functionality (JSON/CSV)

### KIAK Initialization as First Entry

**CRITICAL**: The very first audit log entry is **KIAK initialization** (seqNum: 1):

```json
{
  "seqNum": 1,
  "op": "init",
  "kid": "audit-instance",
  "requestId": "system-init",
  "timestamp": 1729894200000,
  "previousHash": "",
  "chainHash": "iR8mN2...kL9p",
  "signerId": "audit-instance-keyid",
  "sig": "base64url-signature",
  "details": {
    "kmsVersion": "v2.0.0",
    "note": "KMS worker initialized, KIAK generated"
  }
}
```

This entry is created **automatically** when the KMS worker first runs `ensureKIAK()` and finds no existing audit log. It establishes the audit chain foundation.

### Reset Demo Button

**Location**: Bottom of left pane, styled prominently (red)

**Label**: `[Reset Demo]`

**Behavior**:
1. **Click** → Shows confirmation modal
2. **Confirmation** → Resets ALL demo data:
   - Calls `resetKMS()` on KMS enclave (clears all IndexedDB stores)
   - Reloads the page
   - Fresh state: No config, empty audit log
   - Next setup will create new KIAK (new seqNum #1)

**Confirmation Modal**:
```
⚠️  RESET DEMO

This will DELETE all demo data:
- All enrollment methods (passphrase, WebAuthn)
- All application keys (VAPID, etc.)
- All active leases and stashed JWTs
- Complete audit log (starting fresh with new KIAK)

This allows you to re-demonstrate the full lifecycle from scratch.

[Cancel]  [Reset Demo]
```

**Key Difference from Production "Reset KMS"**:
- Reset Demo is **demo-friendly** (quick confirmation, expected action)
- Production Reset KMS requires typing "RESET" (destructive safeguard)

### Audit Log Persistence

**On Page Load**:
1. Parent PWA requests full audit log: `getAuditLog()`
2. KMS returns all entries from IndexedDB (seqNum 1 → N)
3. Right pane populates with complete history
4. Chain verification runs automatically

**On Each Operation**:
1. Operation completes in KMS
2. KMS returns operation result + new audit entry
3. Right pane **appends** new entry to bottom
4. Entry scrolls into view (smooth animation)
5. Chain verification updates

**After Reset Demo**:
1. All data cleared
2. Page reloads
3. Fresh state: Audit log empty
4. First operation (setup) triggers KIAK init → seqNum #1

## Demo Features

### 1. Initial Load (First Time or After Reset)

**Scenario**: User visits for the first time or after clicking Reset Demo.

**LEFT PANE**:
- **Status Badge**: "Not Configured" (gray/red)
- **Available Actions**:
  - `[Setup with Passphrase]` button
  - `[Setup with WebAuthn (PRF)]` button (if browser supports)
  - `[Setup with WebAuthn (Gate)]` button (if browser supports)

**RIGHT PANE**:
- **Audit Log**: Empty
- Message: "No audit entries yet. Set up KMS to begin."

**User Flow**:
1. Click "Setup with Passphrase"
2. Modal prompts for passphrase (min 12 characters)
3. KMS runs setup:
   - First call to `ensureKIAK()` → generates KIAK → creates audit entry #1 (init)
   - Then processes setup → creates audit entry #2 (setup)
4. Success message: "KMS configured successfully"
5. Status changes to "Locked" (yellow)

**RIGHT PANE After Setup**:
```
Audit Log (2 entries)  [Export JSON]

#1 ✓ init           audit-instance   -      KIAK initialized
#2 ✓ setup          -                250ms  Passphrase enrolled
```

Clicking on entry #1 expands to show full JSON:
```json
{
  "seqNum": 1,
  "op": "init",
  "kid": "audit-instance",
  "requestId": "system-init",
  "timestamp": 1729894200000,
  "previousHash": "",
  "chainHash": "iR8mN2kL9p_sT4vB8cX1zY5wA6q...",
  "signerId": "7J3mP9qR2sT8vX4bC1zY5wA6nE...",
  "sig": "MEUCIQCxyz...signature",
  "details": {
    "kmsVersion": "v2.0.0",
    "timestamp": "2025-10-25T21:30:00.000Z",
    "note": "KMS worker initialized, KIAK generated"
  }
}
```

### 2. Persistence (Refresh Page)

**Scenario**: User refreshes the page after setup and operations.

**Expected Behavior**:
- LEFT PANE:
  - Status Badge: "Locked" (yellow) ← detected from IndexedDB
  - Enrollment methods displayed: "Passphrase ✓"
  - Unlock button enabled

- RIGHT PANE:
  - **Audit log auto-populates with ALL entries from IndexedDB**
  - Example: 15 entries if user performed 14 operations + initial KIAK
  - Chain verification runs automatically: "✓ Chain valid (15 entries)"

**Under the Hood**:
1. Parent PWA loads
2. Sends `getAuditLog()` request to KMS
3. KMS queries IndexedDB: `getAllAuditEntries()`
4. Returns array: `[entry1, entry2, ..., entry15]`
5. Right pane renders all entries
6. `verifyAuditChain()` checks integrity

### 3. Unlock (Authentication)

**Scenario**: User unlocks KMS to perform operations.

**LEFT PANE**:
- `[Unlock with Passphrase]` button → prompts for passphrase
- `[Unlock with WebAuthn]` button → triggers WebAuthn ceremony

**User Flow (Passphrase)**:
1. Click "Unlock with Passphrase"
2. Modal prompts for passphrase
3. KMS derives MKEK from passphrase
4. Success: Status → "Unlocked" (green)
5. Operation buttons become enabled

**RIGHT PANE After Unlock**:
```
Audit Log (3 entries)

#1 ✓ init           audit-instance   -      KIAK initialized
#2 ✓ setup          -                250ms  Passphrase enrolled
#3 ✓ unlock         -                180ms  Passphrase unlock
```

Entry #3 expanded:
```json
{
  "seqNum": 3,
  "op": "unlock",
  "kid": "",
  "requestId": "req-abc123",
  "timestamp": 1729894500000,
  "unlockTime": 180,
  "previousHash": "previous-entry-2-hash",
  "chainHash": "new-hash-for-entry-3",
  "signerId": "audit-instance-keyid",
  "sig": "signature",
  "details": {
    "method": "passphrase"
  }
}
```

### 4. Cryptographic Operations

**Scenario**: User performs various crypto operations while unlocked.

#### 4.1 Sign Data

**LEFT PANE**: `[Sign Message]` button

**User Flow**:
1. Click "Sign Message"
2. Modal prompts for message to sign
3. KMS generates ECDSA P-256 signature
4. Result displayed below button:
   ```
   ✓ Signed successfully
   Message: "Hello, World!"
   Signature: MEUCIQCxyz...
   Kid: key-abc123
   Duration: 15ms
   ```

**RIGHT PANE**: New entry appended:
```
#4 ✓ sign           key-abc123       15ms   ECDSA P-256
```

#### 4.2 Issue VAPID JWT

**LEFT PANE**: `[Issue VAPID JWT]` button

**User Flow**:
1. Click "Issue VAPID JWT"
2. KMS generates/retrieves VAPID keypair
3. Issues JWT
4. Result displayed:
   ```
   ✓ VAPID JWT issued
   JWT: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
   Expires: 2025-10-25T22:37:00Z (1 hour)
   Kid: vapid-key-123
   ```

**RIGHT PANE**:
```
#5 ✓ sign           vapid-key-123    20ms   VAPID JWT
```

#### 4.3 Generate Application Key

**LEFT PANE**: `[Generate App Key]` button

**User Flow**:
1. Click "Generate App Key"
2. Modal prompts for key type (VAPID, Signal, Custom)
3. KMS generates keypair and wraps private key
4. Result displayed:
   ```
   ✓ Key generated
   Kid: vapid-new-456
   Public Key: BG8x7y...
   Algorithm: ECDSA P-256
   Purpose: vapid
   ```

**RIGHT PANE**:
```
#6 ✓ generateKey    vapid-new-456    45ms   VAPID key
```

### 5. Lease Management

**Scenario**: Parent PWA needs to issue JWTs in the background without user authentication.

#### 5.1 Issue Lease

**LEFT PANE**: `[Issue Lease]` button (in Lease section)

**User Flow**:
1. Click "Issue Lease"
2. Modal prompts for:
   - Purpose: VAPID (default)
   - Duration: 24 hours
   - Max JWTs: 100
3. KMS issues lease with 5 stashed JWTs
4. Result displayed:
   ```
   ✓ Lease issued
   Lease ID: lease-abc123
   Expires: 2025-10-26T21:40:00Z (24h)
   Stashed JWTs: 5
   LAK Public Key: 7J3mP9qR...

   [Use Lease] [Revoke Lease]
   ```

**RIGHT PANE**:
```
#7 ✓ issueLease     vapid-key-123    150ms  24h, 5 JWTs stashed
```

Entry expanded shows LAK public key and lease details.

#### 5.2 Use Lease (Background JWT Request)

**LEFT PANE**: Click `[Use Lease]` button next to lease

**Key Point**: KMS is **LOCKED** (user locked it after issuing lease)

**User Flow**:
1. Click "Lock KMS" (status → "Locked")
2. Click "Use Lease" on lease-abc123
3. KMS validates lease, pops stashed JWT
4. Result displayed:
   ```
   ✓ JWT issued (using lease)
   JWT: eyJ...
   Stashed remaining: 4/5
   Signed by: LAK (no unlock required)
   ```

**RIGHT PANE**:
```
#8 ✓ lock           -                2ms    KMS locked
#9 ✓ sign           vapid-key-123    8ms    Background JWT (lease-abc123)
```

**Key Observation**:
- Entry #9 `signerId` shows `lease-abc123-lak` (LAK keyid), not KIAK
- This proves JWT was signed by LAK, not user auth

#### 5.3 Revoke Lease

**LEFT PANE**: Click `[Revoke Lease]` button

**User Flow**:
1. Click "Revoke Lease"
2. Confirmation: "Revoke lease? 4 stashed JWTs will be deleted."
3. Confirm
4. Result: Lease removed from list

**RIGHT PANE**:
```
#10 ✓ revokeLease   -                5ms    lease-abc123 deleted
```

### 6. Reset Demo

**LEFT PANE**: Click `[Reset Demo]` button (bottom, red)

**User Flow**:
1. Click "Reset Demo"
2. Confirmation modal appears
3. Click "Reset Demo" to confirm
4. KMS calls `resetKMS()` → clears all IndexedDB stores
5. **Page reloads automatically**
6. Fresh state:
   - Status: "Not Configured"
   - LEFT PANE: Setup buttons enabled
   - RIGHT PANE: Audit log empty

**After Reset - Next Setup**:
1. User clicks "Setup with Passphrase"
2. **NEW KIAK is generated** (different keys than before)
3. Audit log starts fresh:
   ```
   #1 ✓ init         audit-instance   -      KIAK initialized (NEW)
   #2 ✓ setup        -                250ms  Passphrase enrolled
   ```

## UI Layout (Split Pane)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  KMS V2 Full Demo                                      Status: 🟢 Unlocked  │
├────────────────────────────────────┬───────────────────────────────────────┤
│  LEFT PANE (Operations)            │  RIGHT PANE (Audit Log)              │
├────────────────────────────────────┼───────────────────────────────────────┤
│                                    │                                       │
│  ┌──────────────────────────────┐ │  Audit Log (9 entries)  [Export ▼]   │
│  │  Setup / Enrollment          │ │  ┌─────────────────────────────────┐ │
│  ├──────────────────────────────┤ │  │ #1 ✓ init    audit-inst   -     │ │
│  │ Enrolled: ✓ Passphrase       │ │  │ #2 ✓ setup   -            250ms │ │
│  │                              │ │  │ #3 ✓ unlock  -            180ms │ │
│  │ [Add WebAuthn]               │ │  │ #4 ✓ sign    key-abc123   15ms  │ │
│  └──────────────────────────────┘ │  │ #5 ✓ sign    vapid-key    20ms  │ │
│                                    │  │ #6 ✓ genKey  vapid-new    45ms  │ │
│  ┌──────────────────────────────┐ │  │ #7 ✓ issueLe vapid-key    150ms │ │
│  │  Authentication              │ │  │ #8 ✓ lock    -            2ms   │ │
│  ├──────────────────────────────┤ │  │ #9 ✓ sign    vapid-key    8ms   │ │
│  │ [Unlock Passphrase] [Lock]   │ │  │     (LAK: lease-abc123)         │ │
│  └──────────────────────────────┘ │  └─────────────────────────────────┘ │
│                                    │                                       │
│  ┌──────────────────────────────┐ │  Chain Status: ✓ Valid (9 entries)   │
│  │  Operations                  │ │                                       │
│  ├──────────────────────────────┤ │  Clicking entry #4 expands it:        │
│  │ [Sign] [Issue JWT] [Gen Key] │ │  ┌─────────────────────────────────┐ │
│  └──────────────────────────────┘ │  │ #4 ✓ sign    key-abc123   15ms  │ │
│                                    │  │ ▼ Details:                      │ │
│  ┌──────────────────────────────┐ │  │   {                             │ │
│  │  Leases                      │ │  │     "seqNum": 4,                │ │
│  ├──────────────────────────────┤ │  │     "op": "sign",               │ │
│  │ Active: 1                    │ │  │     "kid": "key-abc123",        │ │
│  │                              │ │  │     "requestId": "req-ghi789",  │ │
│  │ 📋 lease-abc123 (23h 45m)    │ │  │     "duration": 15,             │ │
│  │    Stashed: 4/5              │ │  │     "timestamp": 1729894680000, │ │
│  │    [Use] [Revoke]            │ │  │     "previousHash": "...",      │ │
│  │                              │ │  │     "chainHash": "...",         │ │
│  │ [Issue New Lease]            │ │  │     "signerId": "...",          │ │
│  └──────────────────────────────┘ │  │     "sig": "MEUCIQCxyz...",     │ │
│                                    │  │     "details": {                │ │
│  ┌──────────────────────────────┐ │  │       "algorithm": "ECDSA"      │ │
│  │  Latest Result               │ │  │     }                           │ │
│  ├──────────────────────────────┤ │  │   }                             │ │
│  │ ✓ JWT issued (lease)         │ │  │ [Copy JSON] [Verify Sig]        │ │
│  │ JWT: eyJ...                  │ │  └─────────────────────────────────┘ │
│  │ Stashed: 4/5                 │ │                                       │
│  │ Signed by: LAK               │ │                                       │
│  └──────────────────────────────┘ │                                       │
│                                    │                                       │
│  [Reset Demo] (red)                │                                       │
│                                    │                                       │
└────────────────────────────────────┴───────────────────────────────────────┘
```

## Technical Implementation

### File Structure

```
example/phase-1/full/
├── README.md                 # This file
├── package.json              # Dependencies and scripts
├── vite.config.ts           # Vite config for parent app
├── index.html               # Parent PWA entry point
├── parent.ts                # Parent PWA logic
├── parent.css               # Styling (split-pane layout)
├── components/              # UI components
│   ├── LeftPane.ts         # Operations container
│   ├── RightPane.ts        # Audit log viewer
│   ├── SetupPanel.ts       # Setup/enrollment UI
│   ├── AuthPanel.ts        # Unlock UI
│   ├── OperationsPanel.ts  # Crypto operations UI
│   ├── LeasePanel.ts       # Lease management UI
│   ├── AuditLogEntry.ts    # Single log entry (expandable)
│   └── ResetDemoButton.ts  # Reset demo confirmation
└── types.ts                 # TypeScript types
```

### State Management

The parent app maintains:
```typescript
interface AppState {
  kmsStatus: 'not-configured' | 'locked' | 'unlocked';
  enrollmentMethods: EnrollmentMethod[];
  activeLeases: LeaseInfo[];
  latestOperation: OperationResult | null;
  auditLog: AuditEntryV2[];        // Full history from seqNum 1
  auditChainValid: boolean;
  auditChainErrors: string[];
}
```

### Audit Log Loading (on page load)

```typescript
async function loadAuditLog(): Promise<void> {
  // Request full audit log from KMS
  const response = await kmsClient.sendRequest('getAuditLog', {});

  // Response: { entries: AuditEntryV2[] }
  const entries = response.entries;

  // Populate right pane
  renderAuditLog(entries);

  // Verify chain
  const verification = await kmsClient.sendRequest('verifyAuditChain', {});
  updateChainStatus(verification);
}
```

### Reset Demo Flow

```typescript
async function resetDemo(): Promise<void> {
  // Show confirmation
  const confirmed = await showResetConfirmation();
  if (!confirmed) return;

  // Call KMS reset (clears IndexedDB)
  await kmsClient.sendRequest('resetKMS', {});

  // Reload page (fresh state)
  window.location.reload();
}
```

### KIAK Initialization Detection

In KMS worker (`src/v2/worker.ts`), on module load:

```typescript
// Auto-initialize KIAK on first load
(async () => {
  try {
    await initDB();

    // Check if this is first run (no audit entries)
    const existingEntries = await getAllAuditEntries();

    if (existingEntries.length === 0) {
      // First run - initialize KIAK and log it
      await ensureKIAK();

      // Log KIAK initialization as first audit entry
      await logOperation({
        op: 'init',
        kid: 'audit-instance',
        requestId: 'system-init',
        details: {
          kmsVersion: 'v2.0.0',
          timestamp: new Date().toISOString(),
          note: 'KMS worker initialized, KIAK generated',
        },
      });
    } else {
      // Subsequent loads - just ensure KIAK exists
      await ensureKIAK();
    }
  } catch (err) {
    console.error('[KMS Worker] Initialization failed:', err);
  }
})();
```

## User Testing Scenarios

### Scenario 1: Fresh Demo Start
1. Open demo (clean slate or after reset)
2. **RIGHT PANE**: Empty audit log
3. Click "Setup with Passphrase"
4. Enter passphrase: `my-super-secure-passphrase-123`
5. **RIGHT PANE**: Shows 2 entries:
   - #1 init (KIAK)
   - #2 setup (passphrase)
6. Verify chain status: "✓ Valid (2 entries)"

### Scenario 2: Persistence
1. Refresh page
2. **RIGHT PANE**: Auto-populates with 2 entries from IndexedDB
3. Status shows "Locked"
4. Chain verification runs: "✓ Valid (2 entries)"

### Scenario 3: Full Workflow
1. (Starting from 2 entries: init, setup)
2. Unlock → RIGHT PANE: #3 unlock
3. Sign message → RIGHT PANE: #4 sign
4. Issue VAPID JWT → RIGHT PANE: #5 sign
5. Issue lease → RIGHT PANE: #6 issueLease
6. Lock → RIGHT PANE: #7 lock
7. Use lease → RIGHT PANE: #8 sign (LAK)
8. Refresh page → RIGHT PANE: Shows all 8 entries
9. Expand entry #8 → Verify signerId shows LAK

### Scenario 4: Reset Demo
1. Click "Reset Demo"
2. Confirm
3. Page reloads
4. **RIGHT PANE**: Empty
5. Setup again
6. **RIGHT PANE**: NEW #1 init (different KIAK)

## Security Considerations

1. **Cross-Origin Isolation**: KMS runs on separate origin (`localhost:5175`)
2. **Non-Extractable Keys**: All private keys stored with `extractable: false`
3. **Lease Validation**: LAK signatures verified before issuing JWTs
4. **Audit Integrity**: Chain hashes verified on every operation and page load
5. **Persistent Audit Trail**: Complete history survives resets, proves operations occurred
6. **User Confirmation**: Destructive actions (reset demo) require confirmation

## Development Commands

```bash
# Install dependencies
pnpm install

# Start parent PWA (localhost:5173)
pnpm dev:full:parent

# Start KMS enclave (localhost:5175)
pnpm dev:full:kms

# Run both in parallel
pnpm dev:full

# Build for production
pnpm build:full
```

## Success Criteria

This demo successfully demonstrates the KMS V2 lifecycle when:

1. ✅ KIAK initialization appears as first audit entry (seqNum #1)
2. ✅ Audit log persists across page refreshes (loads from IndexedDB)
3. ✅ Split-pane layout: operations left, full audit log right
4. ✅ User can set up KMS with passphrase
5. ✅ User can set up KMS with WebAuthn (PRF or Gate)
6. ✅ User can unlock with correct credentials
7. ✅ User can perform cryptographic operations while unlocked
8. ✅ User can issue leases for background operations
9. ✅ PWA can use leases to get JWTs without user auth (while locked)
10. ✅ All operations appear in audit log with correct signatures
11. ✅ Audit chain verification succeeds for all entries
12. ✅ User can expand log entries to see full JSON
13. ✅ User can reset demo and start fresh (new KIAK)

## Comparison with iframe-isolation Demo

| Feature | iframe-isolation Demo | full Demo |
|---------|----------------------|-----------|
| **Purpose** | Test cross-origin postMessage | Demonstrate full KMS lifecycle |
| **UI** | Minimal (console output) | Rich split-pane with full audit log |
| **User Input** | Hardcoded test data | User enters passphrases, selects options |
| **Persistence** | No (ephemeral) | Yes (survives refresh) |
| **Audit Log** | Console only | Persistent right pane from KIAK init |
| **Lease Demo** | No | Yes (full workflow) |
| **Reset** | No | Yes (Reset Demo button) |
| **Target Audience** | Developers | End users, stakeholders, demos |

## Questions?

For implementation details, see:
- KMS V2 Architecture: `/docs/architecture/crypto/V2/`
- API Reference: `/src/v2/worker.ts` (handleMessage)
- iframe-isolation Demo: `/example/phase-1/iframe-isolation/`
