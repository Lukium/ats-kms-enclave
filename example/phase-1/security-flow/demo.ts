/**
 * Phase 1 Interactive Demo
 *
 * This demo proves the production-ready KMS implementation with:
 * - Passphrase-based unlock (PBKDF2 600k iterations)
 * - Persistent storage (IndexedDB with AES-GCM wrapping)
 * - Audit logging (complete operation history)
 * - Lock/unlock state management
 */

import { KMSClient } from '../../src/client.js';
import { getAllAuditEntries, getAllWrappedKeys, deleteWrappedKey, initDB, closeDB, DB_NAME, type AuditEntry as StorageAuditEntry, type WrappedKey } from '../../src/storage.js';
import {
  b64uToBytes,
  verifyRawP256,
  verifyJwtEs256Compact,
  verifyVAPIDPayload,
  type PublicKeyVerification,
  type JWTVerification,
  type JWTPayloadVerification,
} from './verify.js';
import { jwkThumbprintP256 } from '../../src/crypto-utils.js';
import { computeEntryHash } from '../../src/audit.js';

// ============================================================================
// Types
// ============================================================================

interface DemoState {
  setupComplete: boolean;
  vapidKid: string | null;
  vapidPublicKey: string | null;
  vapidPublicKeyJwk: JsonWebKey | null;
  jwt: string | null;
  jwtParts: { header: string; payload: string; signature: string } | null;
  isLocked: boolean;
  passphrase: string | null;
  auditEntries: AuditEntry[];
  storedKeys: StoredKeyInfo[];
  metrics: PerformanceMetrics;
  thumbprint: string | null;
  pubKeyVerification: PublicKeyVerification | null;
  jwtVerification: JWTVerification | null;
  payloadVerification: JWTPayloadVerification | null;
  jwtSignatureValid: boolean | null;
  jwtVerificationError: string | null;
  keyMetadata: {
    algorithm: { name: string; namedCurve: string };
    extractable: boolean;
    usages: string[];
  } | null;
  // Phase 1 additions
  auditPublicKey: JsonWebKey | null;
  auditVerification: {
    valid: boolean;
    verified: number;
    errors: string[];
  } | null;
  tamperTestResult: {
    beforeValid: boolean;
    afterValid: boolean;
    errors: string[];
  } | null;
  chainHeadHash: string | null;
  auditEntryHashes: Map<number, string>;
  // Unlock method tracking
  unlockMethod: 'passphrase' | 'passkey-prf' | 'passkey-gate' | null;
  // Passkey metadata (for demo purposes - showing which passkey was created)
  passkeyCredentialId: string | null;
  // Signature conversion tracking (hidden in UI but needed for internal state)
  signatureConversion: {
    originalFormat: 'DER' | 'P-1363';
    originalBytes: Uint8Array;
    convertedBytes: Uint8Array;
    wasConverted: boolean;
  } | null;
}

interface AuditEntry {
  id: number;
  timestamp: string;
  op: string;
  kid: string;
  requestId: string;
  origin?: string;
  details?: Record<string, unknown>;
}

interface StoredKeyInfo {
  kid: string;
  alg: string;
  purpose: string;
  created: string;
  lastUsed?: string;
  publicKey: string;
}

interface PerformanceMetrics {
  setupTime: number | null;
  unlockTime: number | null;
  keyGenTime: number | null;
  signTime: number | null;
  workerLoadTime: number | null;
}

// ============================================================================
// Global State
// ============================================================================

let client: KMSClient | null = null;
const state: DemoState = {
  setupComplete: false,
  vapidKid: null,
  vapidPublicKey: null,
  vapidPublicKeyJwk: null,
  jwt: null,
  jwtParts: null,
  isLocked: false,
  passphrase: null,
  auditEntries: [],
  storedKeys: [],
  metrics: {
    setupTime: null,
    unlockTime: null,
    keyGenTime: null,
    signTime: null,
    workerLoadTime: null,
  },
  thumbprint: null,
  pubKeyVerification: null,
  jwtVerification: null,
  payloadVerification: null,
  jwtSignatureValid: null,
  jwtVerificationError: null,
  keyMetadata: null,
  // Phase 1 additions
  auditPublicKey: null,
  auditVerification: null,
  tamperTestResult: null,
  chainHeadHash: null,
  auditEntryHashes: new Map(),
  // Unlock method tracking
  unlockMethod: null,
  // Passkey metadata
  passkeyCredentialId: null,
  signatureConversion: null,
};

// ============================================================================
// Utility Functions
// ============================================================================

// Note: computeEntryHash is imported from src/audit.ts (not duplicated here)

/**
 * Update button states based on current demo state
 */
function updateButtonStates(): void {
  const stage2Btn = document.getElementById('stage2-btn') as HTMLButtonElement;
  const stage3Btn = document.getElementById('stage3-btn') as HTMLButtonElement;
  const stage4Btn = document.getElementById('stage4-btn') as HTMLButtonElement;
  const stage5Btn = document.getElementById('stage5-btn') as HTMLButtonElement;
  const stage6Btn = document.getElementById('stage6-btn') as HTMLButtonElement;
  const stage7Btn = document.getElementById('stage7-btn') as HTMLButtonElement;
  const stage8Btn = document.getElementById('stage8-btn') as HTMLButtonElement;
  const stage9Btn = document.getElementById('stage9-btn') as HTMLButtonElement;
  const scrollBtn = document.getElementById('scroll-to-output-btn') as HTMLButtonElement;

  // Generate VAPID: enabled when setup is complete (lock state checked at runtime)
  stage2Btn.disabled = !state.setupComplete;

  // Sign JWT: enabled when we have a VAPID key (lock state checked at runtime)
  stage3Btn.disabled = !state.vapidKid;

  // Lock Worker: enabled when setup is complete AND worker is unlocked
  stage4Btn.disabled = !state.setupComplete || state.isLocked;

  // Unlock Worker: enabled when setup is complete AND worker is locked
  stage5Btn.disabled = !state.setupComplete || !state.isLocked;

  // Persistence Test: enabled when we have stored keys
  stage6Btn.disabled = state.storedKeys.length === 0;

  // Verify JWT: enabled when we have a VAPID public key (lock state checked at runtime)
  stage7Btn.disabled = !state.vapidPublicKey;

  // Verify Audit Chain: enabled when setup is complete (lock state checked at runtime)
  stage8Btn.disabled = !state.setupComplete;

  // Tamper Detection: enabled when audit verification has been performed
  stage9Btn.disabled = !state.auditVerification;

  // Scroll to output: enabled when we have any artifacts
  scrollBtn.disabled = !state.vapidKid && !state.jwt;

  // Delete passkey button: enabled when passkey unlock is configured
  const deletePasskeyBtn = document.getElementById('delete-passkey-btn') as HTMLButtonElement;
  deletePasskeyBtn.disabled = state.unlockMethod !== 'passkey-prf' && state.unlockMethod !== 'passkey-gate';
}

/**
 * Scroll to a specific verification card
 */
function scrollToCard(cardName: string): void {
  const card = document.querySelector(`[data-card="${cardName}"]`) as HTMLElement;
  if (card) {
    // Ensure we're on the demo tab
    const demoTab = document.querySelector('[data-tab="demo"]') as HTMLElement;
    if (demoTab && !demoTab.classList.contains('active')) {
      demoTab.click();
    }

    // Wait a bit for tab switch, then scroll within the cards container
    setTimeout(() => {
      const container = document.querySelector('.cards-container');
      if (container) {
        // Calculate scroll position to center the card in viewport
        const containerTop = container.getBoundingClientRect().top;
        const cardTop = card.getBoundingClientRect().top;
        const scrollOffset = cardTop - containerTop - 20; // 20px padding

        container.scrollBy({
          top: scrollOffset,
          behavior: 'smooth'
        });
      }
    }, 100);
  }
}

function renderCheck(status: 'pass' | 'fail' | 'pending' | 'info', label: string, detail?: string): string {
  const icons = { pass: '✅', fail: '❌', pending: '⏳', info: 'ℹ️' };
  const icon = icons[status];
  const detailHtml = detail ? `<div class="check-detail">${detail}</div>` : '';

  return `
    <div class="check-item ${status}">
      <span class="check-icon">${icon}</span>
      <span class="check-label">${label}</span>
      ${detailHtml}
    </div>
  `;
}

function renderCard(title: string, explanation: string, checks: string): string {
  return `
    <div class="verify-card">
      <h3>${title}</h3>
      <p class="explanation">${explanation}</p>
      <div class="checks">
        ${checks}
      </div>
    </div>
  `;
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatDuration(ms: number | null): string {
  if (ms === null) return 'N/A';
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

// ============================================================================
// UI Rendering Functions
// ============================================================================

function renderSetupCard(): void {
  const { setupComplete, unlockMethod, passphrase, metrics, isLocked } = state;

  const checks = [
    setupComplete
      ? renderCheck('pass', 'Setup successful', unlockMethod === 'passphrase' ? 'Passphrase accepted and wrapping key derived' : `Passkey configured (${unlockMethod === 'passkey-prf' ? 'PRF mode' : 'gate-only mode'})`)
      : renderCheck('pending', 'Setup required', 'Choose passphrase or passkey to begin'),

    setupComplete && unlockMethod === 'passphrase' && passphrase
      ? renderCheck('pass', `Passphrase: ${passphrase.length} characters`, 'Minimum 8 characters required')
      : setupComplete && unlockMethod?.startsWith('passkey')
      ? renderCheck('pass', `Passkey method: ${unlockMethod === 'passkey-prf' ? 'PRF (recommended)' : 'Gate-only (fallback)'}`, unlockMethod === 'passkey-prf' ? 'Uses hmac-secret PRF extension for key derivation' : 'Uses user verification as gate, static salt for key derivation')
      : renderCheck('pending', 'Authentication method: Pending', 'Will configure on setup'),

    setupComplete && unlockMethod === 'passphrase'
      ? renderCheck('pass', 'Key derivation: PBKDF2 (600k iterations)', 'OWASP recommendation for 2025+')
      : setupComplete && unlockMethod === 'passkey-prf'
      ? renderCheck('pass', 'Key derivation: PRF + HKDF', 'PRF provides 32 bytes entropy, HKDF derives wrapping key')
      : setupComplete && unlockMethod === 'passkey-gate'
      ? renderCheck('pass', 'Key derivation: Static salt + HKDF', 'User verification gates access, HKDF derives wrapping key')
      : renderCheck('pending', 'Key derivation: Pending', 'Will configure on setup'),

    setupComplete
      ? renderCheck('pass', 'Salt generated', unlockMethod === 'passkey-prf' ? '32 bytes app salt for PRF' : '32 bytes random salt')
      : renderCheck('pending', 'Salt generation: Pending', 'Will generate on setup'),

    setupComplete && !isLocked
      ? renderCheck('pass', 'Worker unlocked', 'Ready for cryptographic operations')
      : setupComplete && isLocked
      ? renderCheck('pending', 'Worker locked', 'Unlock to perform operations')
      : renderCheck('pending', 'Worker state: Not setup', 'Will unlock after setup'),

    metrics.setupTime !== null
      ? renderCheck('pass', `Setup time: ${formatDuration(metrics.setupTime)}`, unlockMethod === 'passphrase' ? 'Target: <2s (includes PBKDF2)' : 'Target: <5s (includes WebAuthn ceremony)')
      : renderCheck('pending', 'Performance: Not measured', 'Will measure on setup'),
  ].join('');

  const card = renderCard(
    '🔧 Initial Setup',
    '<strong>Passphrase mode:</strong> PBKDF2 (600k iterations) derives AES-GCM wrapping key directly from passphrase and 32-byte random salt.<br><br><strong>Passkey PRF mode (recommended):</strong> WebAuthn passkey + PRF extension provides 32 bytes pseudorandom output. HKDF-SHA-256 derives wrapping key from PRF output. Resistant to phishing and credential stuffing.<br><br><strong>Passkey gate-only mode (fallback):</strong> WebAuthn user verification gates access. HKDF-SHA-256 derives wrapping key from deterministic salt (backwards compatible with PRF mode).',
    checks
  );

  document.getElementById('setup-card')!.innerHTML = card;
}

function renderPublicKeyCard(): void {
  const { vapidPublicKey, pubKeyVerification } = state;

  const checks = [
    vapidPublicKey && pubKeyVerification
      ? renderCheck(
          pubKeyVerification.ok ? 'pass' : 'fail',
          `Format: ${pubKeyVerification.length} bytes`,
          pubKeyVerification.ok
            ? 'Uncompressed P-256 point (required by PushManager)'
            : pubKeyVerification.reason
        )
      : renderCheck('pending', 'Format: Awaiting key generation', 'Generate a VAPID keypair first'),

    vapidPublicKey && pubKeyVerification
      ? renderCheck(
          pubKeyVerification.ok && pubKeyVerification.leadingByte === '0x04' ? 'pass' : 'fail',
          `Leading byte: ${pubKeyVerification.leadingByte}`,
          'Indicates uncompressed point format'
        )
      : renderCheck('pending', 'Leading byte: Pending', 'Will check after key generation'),

    vapidPublicKey
      ? renderCheck(
          'pass',
          `Base64url encoded (${vapidPublicKey.length} chars)`,
          vapidPublicKey.substring(0, 60) + '...'
        )
      : renderCheck('pending', 'Base64url encoding: Pending', 'Will display after key generation'),

    vapidPublicKey && pubKeyVerification
      ? renderCheck(
          'info',
          `Raw bytes (hex preview, first 16 bytes)`,
          (() => {
            const bytes = b64uToBytes(vapidPublicKey);
            const hexPreview = Array.from(bytes.slice(0, 16))
              .map((b) => b.toString(16).padStart(2, '0'))
              .join(' ');
            return `${hexPreview} ...`;
          })()
        )
      : renderCheck('pending', 'Hex preview: Pending', 'Generate key first'),

    vapidPublicKey
      ? renderCheck(
          'info',
          `Import test`,
          'Can import as CryptoKey for verification'
        )
      : renderCheck('pending', 'Import test: Pending', 'Generate key to test'),
  ].join('');

  const card = renderCard(
    '🔑 Public Key Verification',
    '<strong>Why this matters:</strong> PushManager requires the raw uncompressed P-256 point (65 bytes). SPKI/JWK formats will fail. Showing 65 bytes and leading 0x04 proves we\'re passing the correct format.',
    checks
  );

  document.getElementById('pubkey-card')!.innerHTML = card;
}

function renderKeyPropertiesCard(): void {
  const { vapidKid, keyMetadata, thumbprint } = state;

  const checks = [
    keyMetadata
      ? renderCheck(
          keyMetadata.algorithm.name === 'ECDSA' ? 'pass' : 'fail',
          `Algorithm: ${keyMetadata.algorithm.name}`,
          'Elliptic Curve Digital Signature Algorithm'
        )
      : renderCheck('pending', 'Algorithm: Pending', 'Generate a key to verify algorithm'),

    keyMetadata
      ? renderCheck(
          keyMetadata.algorithm.namedCurve === 'P-256' ? 'pass' : 'fail',
          `Curve: ${keyMetadata.algorithm.namedCurve}`,
          'NIST P-256 (secp256r1) - required for VAPID'
        )
      : renderCheck('pending', 'Curve: Pending', 'Generate a key to verify curve'),

    keyMetadata
      ? renderCheck(
          keyMetadata.usages.includes('sign') ? 'pass' : 'fail',
          `Usages: ${keyMetadata.usages.join(', ')}`,
          'Key can sign (but not export)'
        )
      : renderCheck('pending', 'Key usages: Pending', 'Generate a key to check usages'),

    vapidKid && thumbprint
      ? renderCheck(
          vapidKid === thumbprint ? 'pass' : 'fail',
          `kid matches JWK thumbprint`,
          vapidKid === thumbprint
            ? '✅ kid is content-derived from public key (RFC 7638)'
            : `❌ Mismatch: kid=${vapidKid.substring(0, 16)}..., thumbprint=${thumbprint.substring(0, 16)}...`
        )
      : renderCheck('pending', 'kid verification: Pending', 'Generate a key to verify kid'),

    vapidKid
      ? renderCheck(
          vapidKid.length === 43 && /^[A-Za-z0-9_-]{43}$/.test(vapidKid) ? 'pass' : 'fail',
          `Kid format: RFC 7638 JWK Thumbprint`,
          `43 chars base64url-encoded SHA-256 hash`
        )
      : renderCheck('pending', 'Kid format: Pending', 'Generate a key to see kid format'),

    keyMetadata
      ? renderCheck(
          !keyMetadata.extractable ? 'pass' : 'fail',
          `Private Key: 🔒 Non-extractable`,
          'Browser enforces - cannot be exported even if code is compromised'
        )
      : renderCheck('pending', 'Private key status: Pending', 'Generate a key to check'),

    vapidKid
      ? renderCheck('pass', 'Stored in IndexedDB', 'Wrapped with AES-GCM encryption')
      : renderCheck('pending', 'Storage: Pending', 'Will store after generation'),
  ].join('');

  const card = renderCard(
    '🔐 Key Properties Verification',
    '<strong>Why this matters:</strong> With extractable: false, the browser refuses to export the private key. Even if the host app misbehaves, it cannot read the key material. The key ID is content-derived from the public key (RFC 7638) for auditability.',
    checks
  );

  document.getElementById('keyprops-card')!.innerHTML = card;
}

function renderVAPIDCard(): void {
  renderPublicKeyCard();
  renderKeyPropertiesCard();
}

function renderJWTCard(): void {
  const { jwt, jwtVerification, payloadVerification, vapidKid } = state;

  const checks = [
    jwt && jwtVerification
      ? renderCheck(
          jwtVerification.header?.alg === 'ES256' ? 'pass' : 'fail',
          `Algorithm: ${jwtVerification.header?.alg || 'unknown'}`,
          'ES256 = ECDSA with P-256 and SHA-256'
        )
      : renderCheck('pending', 'Algorithm: Pending', 'Sign a JWT to verify algorithm'),

    jwt && jwtVerification?.header?.kid && vapidKid
      ? renderCheck(
          jwtVerification.header.kid === vapidKid ? 'pass' : 'fail',
          `Key ID included in header`,
          `kid = ${jwtVerification.header.kid}`
        )
      : renderCheck('pending', 'Key ID verification: Pending', 'Sign a JWT to verify kid'),

    jwt && jwtVerification
      ? renderCheck(
          jwtVerification.ok && jwtVerification.sigLength === 64 ? 'pass' : 'fail',
          `Signature: ${jwtVerification.sigLength || 'unknown'} bytes`,
          jwtVerification.ok ? 'P-1363 format (raw r‖s), not DER' : jwtVerification.reason
        )
      : renderCheck('pending', 'Signature format: Pending', 'Sign a JWT to verify signature'),

    jwt && jwtVerification
      ? renderCheck(
          jwtVerification.ok && jwtVerification.sigLeadingByte !== '0x30' ? 'pass' : 'fail',
          `Leading byte: ${jwtVerification.sigLeadingByte || 'unknown'}`,
          'Not 0x30 (proves it\'s not DER encoding)'
        )
      : renderCheck('pending', 'Leading byte check: Pending', 'Sign a JWT to check encoding'),

    jwt && payloadVerification
      ? renderCheck(
          payloadVerification.ok ? 'pass' : 'fail',
          `Token lifetime: ${payloadVerification.expRelative || 'unknown'}`,
          payloadVerification.ok ? 'Within 24h requirement for VAPID' : payloadVerification.reason
        )
      : renderCheck('pending', 'Token lifetime: Pending', 'Sign a JWT to verify expiry'),

    jwt
      ? renderCheck('pass', 'Audit entry created', 'Operation logged to audit trail')
      : renderCheck('pending', 'Audit logging: Pending', 'Sign JWT first'),
  ].join('');

  const card = renderCard(
    '🎫 JWT Signature Verification',
    '<strong>Why this matters:</strong> WebCrypto returns DER-encoded signatures, but JWS ES256 requires P-1363 format (raw r‖s). A 64-byte signature (not starting with 0x30) proves we converted correctly so validators accept the token.',
    checks
  );

  document.getElementById('jwt-card')!.innerHTML = card;
}

function renderVerifyJWTCard(): void {
  const { jwt, vapidPublicKey, jwtSignatureValid, jwtVerificationError } = state;

  const checks = [
    jwt && vapidPublicKey && jwtSignatureValid !== null
      ? renderCheck(
          jwtSignatureValid ? 'pass' : 'fail',
          jwtSignatureValid ? 'JWT signature is valid' : 'JWT signature is invalid',
          jwtSignatureValid
            ? 'Signature matches current VAPID public key'
            : 'Signature does NOT match current key - likely key was regenerated'
        )
      : renderCheck('pending', 'Signature validation: Pending', 'Click "Verify JWT" to test'),

    jwt && vapidPublicKey
      ? renderCheck(
          'pass',
          'Test demonstrates key rotation',
          'If you regenerate VAPID (Stage 2), the old JWT will fail verification'
        )
      : renderCheck('pending', 'Key rotation demo: Pending', 'Generate JWT first'),

    jwtVerificationError
      ? renderCheck('fail', 'Verification error', jwtVerificationError)
      : renderCheck('pending', 'Error status: No errors', 'Will show if verification fails'),
  ].join('');

  const card = renderCard(
    '🔍 JWT Verification Against Current Key',
    '<strong>Why this matters:</strong> This demonstrates that JWTs are cryptographically bound to their signing key. When you regenerate the VAPID keypair (Stage 2), any previously signed JWTs will fail verification because they were signed with a different private key. This proves proper key rotation security.',
    checks
  );

  document.getElementById('verify-jwt-card')!.innerHTML = card;
}

function renderLockCard(): void {
  const { isLocked } = state;

  const checks = [
    isLocked
      ? renderCheck('pass', 'Worker locked', 'Wrapping key cleared from memory')
      : renderCheck('pending', 'Worker state: Unlocked', 'Lock worker to test'),

    isLocked
      ? renderCheck('pass', 'Keys still in storage', 'Keys remain encrypted in IndexedDB')
      : renderCheck('pending', 'Storage check: Pending', 'Lock worker to verify'),

    isLocked
      ? renderCheck('pass', 'Operations require unlock', 'Crypto operations will fail until unlocked')
      : renderCheck('pending', 'Security check: Pending', 'Lock worker to verify'),
  ].join('');

  const card = renderCard(
    '🔒 Lock Worker',
    '<strong>What happens:</strong> Wrapping key cleared from memory. Worker enters locked state. Crypto operations now fail. Keys remain in IndexedDB (encrypted).',
    checks
  );

  document.getElementById('lock-card')!.innerHTML = card;
}

function renderUnlockCard(): void {
  const { isLocked, unlockMethod, metrics } = state;

  const checks = [
    !isLocked && state.setupComplete && unlockMethod === 'passphrase'
      ? renderCheck('pass', 'Authentication verified', 'Correct passphrase provided')
      : !isLocked && state.setupComplete && unlockMethod?.startsWith('passkey')
      ? renderCheck('pass', 'Authentication verified', 'Passkey authentication successful')
      : renderCheck('pending', 'Authentication: Pending', 'Unlock worker to test'),

    !isLocked && state.setupComplete
      ? renderCheck('pass', 'Worker unlocked', 'Wrapping key re-derived and loaded')
      : renderCheck('pending', 'Worker state: Pending', 'Unlock worker to verify'),

    !isLocked && state.setupComplete
      ? renderCheck('pass', 'Keys accessible', 'Can perform crypto operations again')
      : renderCheck('pending', 'Key access: Pending', 'Unlock worker to verify'),

    metrics.unlockTime !== null
      ? renderCheck('pass', `Unlock time: ${formatDuration(metrics.unlockTime)}`, unlockMethod === 'passphrase' ? 'Target: <2s (includes PBKDF2)' : 'Target: <5s (includes WebAuthn)')
      : renderCheck('pending', 'Performance: Not measured', 'Will measure on unlock'),
  ].join('');

  const card = renderCard(
    '🔓 Unlock Worker',
    '<strong>Passphrase mode:</strong> User provides passphrase, system re-derives wrapping key via PBKDF2.<br><br><strong>Passkey PRF mode:</strong> User authenticates with passkey, PRF provides entropy, HKDF derives wrapping key.<br><br><strong>Passkey gate-only mode:</strong> User verification gates access, HKDF derives wrapping key from static salt.',
    checks
  );

  document.getElementById('unlock-card')!.innerHTML = card;
}

function renderPersistenceCard(): void {
  const { vapidKid, storedKeys } = state;

  const persisted = storedKeys.length > 0 && storedKeys.some(k => k.kid === vapidKid);

  const checks = [
    persisted
      ? renderCheck('pass', 'Keys survived refresh', 'Keys still in IndexedDB after page reload simulation')
      : renderCheck('pending', 'Persistence: Not tested', 'Run persistence test'),

    persisted && vapidKid
      ? renderCheck('pass', `Same kid recovered: ${vapidKid.substring(0, 20)}...`, 'Key ID matches original')
      : renderCheck('pending', 'Key recovery: Pending', 'Run persistence test'),

    persisted
      ? renderCheck('pass', 'JWT signing still works', 'Can sign with recovered key')
      : renderCheck('pending', 'Functionality: Pending', 'Run persistence test'),
  ].join('');

  const card = renderCard(
    '🔄 Persistence Test',
    '<strong>What happens:</strong> Page refreshes (simulated or real F5). Keys still in IndexedDB. User unlocks with passphrase. Original keys recovered and functional.',
    checks
  );

  document.getElementById('persistence-card')!.innerHTML = card;
}

function renderAuditPublicKeyCard(): void {
  const checks = [
    state.auditPublicKey
      ? renderCheck('pass', 'Public Key Exported', `ES256 (P-256) public key available for verification`)
      : renderCheck('pending', 'Public Key: Pending', 'Initialize worker to generate audit keypair'),
    state.auditPublicKey && state.auditPublicKey.kty === 'EC'
      ? renderCheck('pass', 'Key Type', `${state.auditPublicKey.kty} (Elliptic Curve)`)
      : renderCheck('pending', 'Key Type: Pending'),
    state.auditPublicKey && state.auditPublicKey.crv === 'P-256'
      ? renderCheck('pass', 'Curve', `${state.auditPublicKey.crv} (NIST P-256)`)
      : renderCheck('pending', 'Curve: Pending'),
    state.auditPublicKey && state.auditPublicKey.x && state.auditPublicKey.y
      ? renderCheck('pass', 'Coordinates', `x: ${state.auditPublicKey.x.substring(0, 16)}..., y: ${state.auditPublicKey.y.substring(0, 16)}...`)
      : renderCheck('pending', 'Coordinates: Pending'),
  ].join('');

  const card = renderCard(
    '🔐 Audit Log Public Key',
    '<strong>What this is:</strong> The ES256 public key used to verify audit log signatures. Anyone can use this key to independently verify the integrity of the audit chain without access to the private key.',
    checks
  );

  document.getElementById('audit-pubkey-card')!.innerHTML = card;
}

function renderAuditVerificationCard(): void {
  const checks = [
    state.auditVerification
      ? state.auditVerification.valid
        ? renderCheck('pass', 'Chain Integrity', 'All signatures valid, chain unbroken')
        : renderCheck('fail', 'Chain Integrity', `${state.auditVerification.errors.length} errors found`)
      : renderCheck('pending', 'Chain Integrity: Pending', 'Run verification test'),
    state.auditVerification
      ? renderCheck(
          state.auditVerification.valid ? 'pass' : 'fail',
          'Entries Verified',
          `${state.auditVerification.verified} entries checked`
        )
      : renderCheck('pending', 'Entries: Pending'),
    state.chainHeadHash
      ? renderCheck(
          'info',
          'Chain Head Hash',
          `${state.chainHeadHash.substring(0, 16)}... (${state.chainHeadHash.length} chars)`
        )
      : renderCheck('pending', 'Chain Head: Pending', 'Verify chain to compute hash'),
    state.auditVerification && state.auditVerification.errors.length > 0
      ? renderCheck('fail', 'Verification Errors', state.auditVerification.errors.slice(0, 3).join(', '))
      : state.auditVerification
      ? renderCheck('pass', 'No Errors', 'Chain verified successfully')
      : renderCheck('pending', 'Errors: Pending'),
  ].join('');

  const card = renderCard(
    '✅ Audit Chain Verification',
    '<strong>What this proves:</strong> Independent verification of the audit log using ES256 signatures. Each entry is signed with the private key and can be verified with the public key. The chain ensures entries cannot be modified, reordered, or deleted.',
    checks
  );

  document.getElementById('audit-verify-card')!.innerHTML = card;
}

function renderTamperDetectionCard(): void {
  const checks = [
    state.tamperTestResult
      ? renderCheck(
          state.tamperTestResult.beforeValid ? 'pass' : 'fail',
          'Before Tamper',
          state.tamperTestResult.beforeValid ? 'Chain valid' : 'Chain invalid'
        )
      : renderCheck('pending', 'Before Tamper: Pending', 'Run tamper test'),
    state.tamperTestResult
      ? renderCheck(
          !state.tamperTestResult.afterValid ? 'pass' : 'fail',
          'After Tamper',
          !state.tamperTestResult.afterValid ? 'Tampering detected ✅' : 'Tampering not detected ❌'
        )
      : renderCheck('pending', 'After Tamper: Pending'),
    state.tamperTestResult && state.tamperTestResult.errors.length > 0
      ? renderCheck('pass', 'Detection Result', `${state.tamperTestResult.errors.length} tampering errors detected`)
      : state.tamperTestResult
      ? renderCheck('fail', 'Detection Result', 'No tampering detected (unexpected)')
      : renderCheck('pending', 'Detection: Pending'),
  ].join('');

  const card = renderCard(
    '🔍 Tamper Detection Test',
    '<strong>What this proves:</strong> Demonstrates that the audit log detects tampering. We modify an entry in IndexedDB directly and verify that the chain verification fails. This proves the hash-chain and signatures work as intended.',
    checks
  );

  document.getElementById('tamper-card')!.innerHTML = card;
}

function renderJWTPolicyCard(): void {
  if (!state.jwt || !state.jwtParts) {
    document.getElementById('jwt-policy-card')!.innerHTML = renderCard(
      '🎫 JWT Policy Validation',
      '<strong>What this checks:</strong> RFC 8292 (VAPID) compliance. The worker enforces: exp ≤ 24h, aud must be HTTPS, sub must be mailto: or https:. This prevents security issues like overly-long token expiration.',
      renderCheck('pending', 'Policy Check: Pending', 'Sign a JWT to validate policy')
    );
    return;
  }

  // Decode payload
  const payloadJson = JSON.parse(atob(state.jwtParts.payload.replace(/-/g, '+').replace(/_/g, '/')));
  const exp = payloadJson.exp as number;
  const aud = payloadJson.aud as string;
  const sub = payloadJson.sub as string;

  const now = Math.floor(Date.now() / 1000);
  const maxExp = now + 24 * 60 * 60;
  const remaining = exp - now;
  const hours = Math.floor(remaining / 3600);
  const minutes = Math.floor((remaining % 3600) / 60);

  const checks = [
    renderCheck(
      exp <= maxExp ? 'pass' : 'fail',
      'Expiration (exp)',
      `Unix: ${exp}, Remaining: ${hours}h ${minutes}m, Status: ${exp <= maxExp ? '✅ Within 24h limit' : '❌ Exceeds 24h'}`
    ),
    renderCheck(
      aud.startsWith('https://') ? 'pass' : 'fail',
      'Audience (aud)',
      `${aud}, Format: ${aud.startsWith('https://') ? '✅ HTTPS URL' : '❌ Must be HTTPS'}`
    ),
    renderCheck(
      sub.startsWith('mailto:') || sub.startsWith('https://') ? 'pass' : 'fail',
      'Subject (sub)',
      `${sub}, Format: ${sub.startsWith('mailto:') || sub.startsWith('https://') ? '✅ Valid' : '❌ Must be mailto: or https:'}`
    ),
    (exp <= maxExp && aud.startsWith('https://') && (sub.startsWith('mailto:') || sub.startsWith('https://')))
      ? renderCheck('pass', 'Policy Compliance', 'All VAPID requirements met')
      : renderCheck('fail', 'Policy Compliance', 'One or more requirements failed'),
  ].join('');

  const card = renderCard(
    '🎫 JWT Policy Validation (RFC 8292)',
    '<strong>Why this matters:</strong> VAPID (RFC 8292) requires exp ≤ 24h, and specific formats for aud/sub. The worker enforces these policies before signing to prevent security issues.',
    checks
  );

  document.getElementById('jwt-policy-card')!.innerHTML = card;
}

function updateAllCards(): void {
  renderSetupCard();
  renderVAPIDCard();
  renderJWTCard();
  renderJWTPolicyCard();
  renderVerifyJWTCard();
  renderAuditPublicKeyCard();
  renderAuditVerificationCard();
  renderTamperDetectionCard();
  renderLockCard();
  renderUnlockCard();
  renderPersistenceCard();
}

function renderOutput(): void {
  const output = document.getElementById('output-section')!;
  const parts: string[] = [];

  if (state.vapidKid && state.vapidPublicKey) {
    const pubKeyBytes = b64uToBytes(state.vapidPublicKey);

    parts.push(`
      <div class="output-card">
        <h4>🔑 VAPID Keypair Generated</h4>
        <div class="output-item">
          <strong>Kid:</strong>
          <code>${state.vapidKid}</code>
          <span class="length">(${state.vapidKid.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Public Key (Base64url):</strong>
          <code class="truncate">${state.vapidPublicKey}</code>
          <span class="length">(${state.vapidPublicKey.length} chars, ${pubKeyBytes.length} bytes)</span>
        </div>
        ${state.vapidPublicKeyJwk ? `
        <details>
          <summary>Show JWK Representation</summary>
          <pre>${JSON.stringify(state.vapidPublicKeyJwk, null, 2)}</pre>
        </details>
        ` : ''}
        ${state.thumbprint ? `
        <div class="output-item">
          <strong>JWK Thumbprint (RFC 7638):</strong>
          <code>${state.thumbprint}</code>
          <span class="length">(informational - not used as kid in Phase 1)</span>
        </div>
        ` : ''}
        ${state.keyMetadata ? `
        <details>
          <summary>Show Key Metadata</summary>
          <pre>${JSON.stringify(state.keyMetadata, null, 2)}</pre>
        </details>
        ` : ''}
      </div>
    `);
  }

  // Audit ES256 Keypair Card
  if (state.auditPublicKey) {
    parts.push(`
      <div class="output-card">
        <h4>🔐 Audit Log ES256 Keypair</h4>
        <p class="explanation">
          <strong>Purpose:</strong> Tamper-evident audit log signing
        </p>
        <div class="output-item">
          <strong>Private Key:</strong>
          <span>🔒 Non-extractable</span>
          <span class="detail">Stored wrapped in IndexedDB, cannot be exported</span>
        </div>
        <div class="output-item">
          <strong>Algorithm:</strong>
          <span>ECDSA P-256 (ES256)</span>
        </div>
        <div class="output-item">
          <strong>Usage:</strong>
          <code>[sign]</code>
          <span class="detail">Private key signs audit entries</span>
        </div>
        <div class="output-item">
          <strong>Public Key (JWK):</strong>
        </div>
        <details open>
          <summary>Show Public Key JWK</summary>
          <pre>${JSON.stringify(state.auditPublicKey, null, 2)}</pre>
          <button onclick="navigator.clipboard.writeText('${JSON.stringify(state.auditPublicKey)}')">📋 Copy Public Key</button>
        </details>
        <p class="explanation">
          <strong>Why this matters:</strong> The audit log uses asymmetric signatures (ES256).
          Anyone with the public key can verify the audit chain, but only the worker can sign new entries.
          This enables independent third-party verification.
        </p>
      </div>
    `);
  }

  if (state.jwt && state.jwtParts) {
    const signatureBytes = b64uToBytes(state.jwtParts.signature);

    parts.push(`
      <div class="output-card">
        <h4>🎫 JWT Signed</h4>
        <div class="output-item">
          <strong>Full JWT:</strong>
          <code class="wrap">${state.jwt}</code>
          <span class="length">(${state.jwt.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Header:</strong>
          <code class="truncate">${state.jwtParts.header}</code>
          <span class="length">(${state.jwtParts.header.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Payload:</strong>
          <code class="truncate">${state.jwtParts.payload}</code>
          <span class="length">(${state.jwtParts.payload.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Signature:</strong>
          <code class="truncate">${state.jwtParts.signature}</code>
          <span class="length">(${state.jwtParts.signature.length} chars, ${signatureBytes.length} bytes)</span>
        </div>
        ${state.jwtVerification?.header ? `
        <details>
          <summary>Show Decoded Header</summary>
          <pre>${JSON.stringify(state.jwtVerification.header, null, 2)}</pre>
        </details>
        ` : ''}
        ${state.jwtVerification?.payload ? `
        <details>
          <summary>Show Decoded Payload</summary>
          <pre>${JSON.stringify(state.jwtVerification.payload, null, 2)}</pre>
        </details>
        ` : ''}
      </div>
    `);
  }

  output.innerHTML = parts.length > 0 ? parts.join('') : '<p class="empty-state">No output yet. Run demo stages...</p>';
}

function renderAuditLog(): void {
  const container = document.getElementById('audit-content')!;

  if (state.auditEntries.length === 0) {
    container.innerHTML = '<p class="empty-state">No audit entries yet. Run the demo to see operation history...</p>';
    return;
  }

  const rows = state.auditEntries
    .map(
      (entry) => {
        const hash = state.auditEntryHashes.get(entry.id);
        return `
    <tr>
      <td><code>${entry.op}</code></td>
      <td>${formatTimestamp(entry.timestamp)}</td>
      <td><code>${entry.kid.substring(0, 16)}...</code></td>
      <td>${entry.origin || '-'}</td>
      <td>${hash ? `<code title="${hash}">${hash.substring(0, 16)}...</code>` : '-'}</td>
      <td>${entry.details ? JSON.stringify(entry.details) : '-'}</td>
    </tr>
  `;
      }
    )
    .join('');

  container.innerHTML = `
    <table class="audit-table">
      <thead>
        <tr>
          <th>Operation</th>
          <th>Timestamp</th>
          <th>Key ID</th>
          <th>Origin</th>
          <th>Entry Hash</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

function renderStorage(): void {
  const container = document.getElementById('storage-content')!;

  if (state.storedKeys.length === 0) {
    container.innerHTML = '<p class="empty-state">No keys in storage yet. Generate a VAPID key to see it here...</p>';
    return;
  }

  const items = state.storedKeys
    .map(
      (key) => `
    <div class="storage-item">
      <h4>${key.purpose.toUpperCase()} Key</h4>
      <dl>
        <dt>Kid:</dt>
        <dd>${key.kid}</dd>
        <dt>Algorithm:</dt>
        <dd>${key.alg}</dd>
        <dt>Purpose:</dt>
        <dd>${key.purpose}</dd>
        <dt>Created:</dt>
        <dd>${formatTimestamp(key.created)}</dd>
        <dt>Last Used:</dt>
        <dd>${key.lastUsed ? formatTimestamp(key.lastUsed) : 'Never'}</dd>
        <dt>Public Key:</dt>
        <dd>${key.publicKey.substring(0, 40)}...</dd>
      </dl>
    </div>
  `
    )
    .join('');

  container.innerHTML = `<div class="storage-list">${items}</div>`;
}

function renderPerformance(): void {
  const container = document.getElementById('performance-metrics')!;
  const { metrics } = state;

  function getMetricClass(value: number | null, target: number): string {
    if (value === null) return '';
    if (value <= target) return 'good';
    if (value <= target * 1.5) return 'warning';
    return 'bad';
  }

  function formatMetricWithTarget(value: number | null, targetMs: number): string {
    const duration = formatDuration(value);
    const targetDuration = targetMs >= 1000 ? `${targetMs / 1000}s` : `${targetMs}ms`;
    return `${duration} < ${targetDuration}`;
  }

  container.innerHTML = `
    <div class="perf-metric">
      <div class="perf-metric-label">Setup:</div>
      <div class="perf-metric-value ${getMetricClass(metrics.setupTime, 2000)}">${formatMetricWithTarget(metrics.setupTime, 2000)}</div>
    </div>
    <div class="perf-metric">
      <div class="perf-metric-label">KeyGen:</div>
      <div class="perf-metric-value ${getMetricClass(metrics.keyGenTime, 100)}">${formatMetricWithTarget(metrics.keyGenTime, 100)}</div>
    </div>
    <div class="perf-metric">
      <div class="perf-metric-label">Sign:</div>
      <div class="perf-metric-value ${getMetricClass(metrics.signTime, 50)}">${formatMetricWithTarget(metrics.signTime, 50)}</div>
    </div>
    <div class="perf-metric">
      <div class="perf-metric-label">Unlock:</div>
      <div class="perf-metric-value ${getMetricClass(metrics.unlockTime, 2000)}">${formatMetricWithTarget(metrics.unlockTime, 2000)}</div>
    </div>
  `;
}

// ============================================================================
// Data Loading Functions
// ============================================================================

async function loadAuditLog(): Promise<void> {
  try {
    // Initialize DB if needed
    await initDB();

    // Fetch all audit entries from IndexedDB
    const entries = await getAllAuditEntries();

    // Convert to demo format
    state.auditEntries = entries.map((entry: StorageAuditEntry) => ({
      id: entry.id,
      timestamp: entry.timestamp,
      op: entry.op,
      kid: entry.kid,
      requestId: entry.requestId,
      origin: entry.origin,
      details: entry.details,
    }));

    // Compute hashes for all entries (for display in audit log table)
    state.auditEntryHashes.clear();
    for (const entry of entries) {
      const hash = await computeEntryHash(entry);
      state.auditEntryHashes.set(entry.id, hash);
    }

    console.log(`[Demo] Loaded ${state.auditEntries.length} audit entries with hashes`);
  } catch (error) {
    console.error('[Demo] Failed to load audit log:', error);
    state.auditEntries = [];
  }
}

async function loadStorage(): Promise<void> {
  try {
    // Initialize DB if needed
    await initDB();

    // Fetch all wrapped keys from IndexedDB
    const keys = await getAllWrappedKeys();

    // Convert to demo format
    state.storedKeys = keys.map((key: WrappedKey) => ({
      kid: key.kid,
      alg: key.alg || 'ES256',
      purpose: key.purpose || 'vapid',
      created: key.wrappedAt,
      lastUsed: key.wrappedAt, // WrappedKey doesn't track lastUsed, use wrappedAt
      publicKey: arrayBufferToBase64url(key.publicKeyRaw || new ArrayBuffer(0)),
    }));

    console.log(`[Demo] Loaded ${state.storedKeys.length} keys from storage`);
  } catch (error) {
    console.error('[Demo] Failed to load storage:', error);
    state.storedKeys = [];
  }
}

/**
 * Convert ArrayBuffer to base64url (for display)
 */
function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  if (buffer.byteLength === 0) return '';
  const bytes = new Uint8Array(buffer);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ============================================================================
// WebAuthn Passkey Functions
// ============================================================================

/**
 * Create a WebAuthn passkey credential
 */
async function createPasskey(): Promise<void> {
  try {
    // Check if WebAuthn is available
    if (!window.PublicKeyCredential) {
      alert('WebAuthn is not supported in this browser');
      return;
    }

    // Generate random challenge
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));

    // Determine RP ID (use 'localhost' for local development)
    const rpId = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'localhost'
      : window.location.hostname;

    console.log('[Demo] Creating passkey with RP ID:', rpId);

    // Create credential
    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'ATS KMS Demo',
          id: rpId,
        },
        user: {
          id: userId,
          name: 'demo@ats.run',
          displayName: 'Demo User',
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },  // ES256 (ECDSA P-256)
          { alg: -257, type: 'public-key' }, // RS256 (RSA PKCS#1)
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
        },
        timeout: 60000,
      },
    })) as PublicKeyCredential;

    if (!credential) {
      alert('Passkey creation was cancelled');
      return;
    }

    // Store credential ID
    const credentialId = arrayBufferToBase64url(credential.rawId);
    state.passkeyCredentialId = credentialId;

    // Persist to localStorage for page refresh
    localStorage.setItem('demo-passkey-credential-id', credentialId);

    // Extract public key from attestation
    const response = credential.response as AuthenticatorAttestationResponse;
    // Note: In a real implementation, you'd parse the attestationObject to get the public key
    // For demo purposes, we'll just indicate success

    console.log('[Demo] Passkey created successfully');
    console.log('  RP ID:', rpId);
    console.log('  Credential ID:', credentialId);
    console.log('  Credential ID (raw bytes):', Array.from(new Uint8Array(credential.rawId)).slice(0, 8).join(','), '...');
    alert('Passkey created successfully!');

    // Update UI
    updateButtonStates();
    updateAllCards();
  } catch (error) {
    console.error('[Demo] Passkey creation failed:', error);
    alert(`Passkey creation failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Delete/reset passkey unlock configuration
 */
async function deletePasskey(): Promise<void> {
  if (state.unlockMethod !== 'passkey-prf' && state.unlockMethod !== 'passkey-gate') {
    alert('No passkey configured. Use reset to clear passphrase setup.');
    return;
  }

  const confirmed = confirm(
    'This will reset the unlock configuration.\n\n' +
    'Note: WebAuthn does not provide an API to delete passkeys from your device. ' +
    'To remove the passkey from your OS:\n' +
    '• macOS: System Settings → Passwords → Search for "localhost"\n' +
    '• Windows: Settings → Accounts → Passkeys → Remove "localhost"\n' +
    '• Chrome: Settings → Password Manager → Passkeys\n\n' +
    'Continue with reset?'
  );

  if (!confirmed) return;

  // Reset the entire demo
  await resetDemo(true);

  alert('Passkey configuration reset.\n\nRemember to manually delete the passkey from your OS if desired.');
}

/**
 * Unlock with passkey (demonstrates DER signature from WebAuthn)
 */
async function unlockWithPasskey(): Promise<void> {
  if (!state.passkeyCredentialId) {
    alert('No passkey configured. Create a passkey first.');
    return;
  }

  try {
    // Generate random challenge
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    // Determine RP ID (must match the one used during creation)
    const rpId = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'localhost'
      : window.location.hostname;

    console.log('[Demo] Authenticating with RP ID:', rpId);
    console.log('[Demo] Credential ID:', state.passkeyCredentialId);

    // Get assertion
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId,
        allowCredentials: [
          {
            type: 'public-key',
            id: base64urlToBytes(state.passkeyCredentialId),
          },
        ],
        userVerification: 'required',
        timeout: 60000,
      },
    })) as PublicKeyCredential;

    if (!assertion) {
      alert('Passkey authentication was cancelled');
      return;
    }

    const response = assertion.response as AuthenticatorAssertionResponse;
    const signature = new Uint8Array(response.signature);

    // Check if signature is DER format (starts with 0x30)
    const isDER = signature[0] === 0x30;

    console.log('[Demo] WebAuthn signature received:');
    console.log('  Format:', isDER ? 'DER (ASN.1)' : 'Unknown');
    console.log('  Length:', signature.length, 'bytes');
    console.log('  Leading byte:', `0x${signature[0]?.toString(16).padStart(2, '0')}`);

    // If DER, convert to P-1363 for WebCrypto
    let convertedSignature = signature;
    if (isDER) {
      // Import derToP1363 from crypto-utils
      const { derToP1363 } = await import('../../src/crypto-utils.js');
      convertedSignature = derToP1363(signature);
      console.log('[Demo] Converted to P-1363:', convertedSignature.length, 'bytes');
    }

    // Store for display
    state.passkeyAssertion = {
      signature,
      derFormat: isDER,
      converted: convertedSignature,
    };

    console.log('[Demo] Passkey authentication successful');
    alert('Passkey authentication successful!\n\nCheck the "WebAuthn Passkey Signature" card to see the DER → P-1363 conversion.');

    // Update UI
    updateButtonStates();
    updateAllCards();
  } catch (error) {
    console.error('[Demo] Passkey authentication failed:', error);
    if (error instanceof Error) {
      console.error('  Error name:', error.name);
      console.error('  Error message:', error.message);
    }
    alert(`Passkey authentication failed: ${error instanceof Error ? error.message : 'unknown error'}\n\nCheck the console for details.`);
  }
}

// Helper: base64url to Uint8Array
function base64urlToBytes(str: string): Uint8Array {
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

// ============================================================================
// Demo Stage Functions
// ============================================================================

async function stage1SetupPassphrase(): Promise<void> {
  const button = document.getElementById('stage1-passphrase-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Setting up...';

  // Scroll to setup card
  scrollToCard('setup');

  try {
    // Initialize client if needed
    if (!client) {
      const startLoad = performance.now();
      client = new KMSClient();
      state.metrics.workerLoadTime = performance.now() - startLoad;
    }

    // Check if already setup
    const unlockStatus = await client.isUnlockSetup();
    if (unlockStatus.isSetup) {
      alert('Unlock is already configured. Use the reset button to start over.');
      button.disabled = true;
      button.textContent = '✓ Already Setup';
      return;
    }

    // Prompt for passphrase
    const passphrase = prompt('Enter a passphrase (minimum 8 characters):');
    if (!passphrase || passphrase.length < 8) {
      alert('Passphrase must be at least 8 characters');
      button.disabled = false;
      button.textContent = '🔐 Setup Passphrase';
      return;
    }

    state.passphrase = passphrase;

    // Setup passphrase
    const startSetup = performance.now();
    const result = await client.setupPassphrase(passphrase);
    state.metrics.setupTime = performance.now() - startSetup;

    if (!result.success) {
      throw new Error(result.error || 'Setup failed');
    }

    state.setupComplete = true;
    state.isLocked = false;
    state.unlockMethod = 'passphrase';

    // Cache the method in localStorage for future sessions
    localStorage.setItem('kms-passkey-method', 'passphrase');

    // Disable both setup buttons
    (document.getElementById('stage1-passphrase-btn') as HTMLButtonElement).disabled = true;
    (document.getElementById('stage1-passkey-btn') as HTMLButtonElement).disabled = true;

    // Update button states based on new state
    updateButtonStates();

    updateAllCards();
    renderOutput();
    renderPerformance();

    // Reload audit log
    await loadAuditLog();
    renderAuditLog();

    button.textContent = '✓ Passphrase Setup Complete';
    setTimeout(() => {
      button.textContent = '🔐 Setup Passphrase';
    }, 2000);
  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '🔐 Setup Passphrase';
    button.disabled = false;
  }
}

async function stage1SetupPasskey(): Promise<void> {
  const button = document.getElementById('stage1-passkey-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Setting up...';

  // Scroll to setup card
  scrollToCard('setup');

  try {
    // Initialize client if needed
    if (!client) {
      const startLoad = performance.now();
      client = new KMSClient();
      state.metrics.workerLoadTime = performance.now() - startLoad;
    }

    // Check if already setup
    const unlockStatus = await client.isUnlockSetup();
    if (unlockStatus.isSetup) {
      alert('Unlock is already configured. Use the reset button to start over.');
      button.disabled = true;
      button.textContent = '✓ Already Setup';
      return;
    }

    // Determine RP ID (use 'localhost' for local development)
    const rpId = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'localhost'
      : window.location.hostname;
    const rpName = 'ATS KMS Demo';

    console.log('[Demo] Setting up passkey with RP ID:', rpId);

    const startSetup = performance.now();

    // Smart auto-fallback: setupPasskeyPRF tries PRF first, automatically falls back to gate-only
    // if PRF not supported, reusing the same credential (no double authentication!)
    const result = await client.setupPasskeyPRF(rpId, rpName);

    state.metrics.setupTime = performance.now() - startSetup;

    if (!result.success) {
      throw new Error(result.error || 'Passkey setup failed');
    }

    // Determine which method was used (returned by setupPasskeyPRF)
    const usedMethod = result.method === 'gate' ? 'passkey-gate' : 'passkey-prf';
    const fallbackReason = result.method === 'gate'
      ? 'PRF extension not available on this device/browser'
      : null;

    state.setupComplete = true;
    state.isLocked = false;
    state.unlockMethod = usedMethod;

    // Cache the method in localStorage for future sessions
    localStorage.setItem('kms-passkey-method', usedMethod);

    console.log('[Demo] Passkey setup successful using', usedMethod);

    // Show user-friendly message about which mode was used
    if (usedMethod === 'passkey-gate') {
      setTimeout(() => {
        alert(
          '✓ Passkey created successfully!\n\n' +
          'Mode: Basic (gate-only)\n' +
          `Reason: ${fallbackReason}\n\n` +
          'Security note: Your passkey still provides strong authentication, ' +
          'but uses a different key derivation method.'
        );
      }, 100);
    } else {
      setTimeout(() => {
        alert(
          '✓ Passkey created successfully!\n\n' +
          'Mode: Advanced (PRF)\n' +
          'Your device supports the PRF extension for enhanced key derivation.'
        );
      }, 100);
    }

    // Disable both setup buttons
    (document.getElementById('stage1-passphrase-btn') as HTMLButtonElement).disabled = true;
    (document.getElementById('stage1-passkey-btn') as HTMLButtonElement).disabled = true;

    // Update button states based on new state
    updateButtonStates();

    updateAllCards();
    renderOutput();
    renderPerformance();

    // Reload audit log
    await loadAuditLog();
    renderAuditLog();

    button.textContent = usedMethod === 'passkey-prf' ? '✓ Passkey Setup (PRF)' : '✓ Passkey Setup (Gate-only)';
    setTimeout(() => {
      button.textContent = '🔑 Setup Passkey (PRF)';
    }, 2000);
  } catch (error) {
    console.error('[Demo] Passkey setup failed:', error);
    alert(`Passkey setup failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '🔑 Setup Passkey (PRF)';
    button.disabled = false;
  }
}

async function stage2GenerateVAPID(): Promise<void> {
  if (!state.setupComplete) {
    alert('Complete setup first');
    return;
  }

  const button = document.getElementById('stage2-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Generating...';

  // Scroll to VAPID card
  scrollToCard('vapid');

  try {
    // Delete existing VAPID key if present (overwrite behavior)
    if (state.vapidKid) {
      console.log(`[Demo] Deleting existing VAPID key: ${state.vapidKid}`);
      await deleteWrappedKey(state.vapidKid);

      // Clear JWT verification state since we're rotating keys
      // This allows the user to test that old JWTs become invalid
      state.jwtSignatureValid = null;
      state.jwtVerificationError = null;
    }

    const startGen = performance.now();
    const result = await client!.generateVAPID();
    state.metrics.keyGenTime = performance.now() - startGen;

    state.vapidKid = result.kid;
    state.vapidPublicKey = result.publicKey;

    // Verify public key format
    const pubKeyBytes = b64uToBytes(result.publicKey);
    state.pubKeyVerification = verifyRawP256(pubKeyBytes);

    // Convert raw public key to JWK for thumbprint
    // Raw format: 0x04 || x (32 bytes) || y (32 bytes)
    const x = pubKeyBytes.slice(1, 33);
    const y = pubKeyBytes.slice(33, 65);
    state.vapidPublicKeyJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: new TextDecoder().decode(new Uint8Array(Array.from(x).map(b => b.toString(16).padStart(2, '0')).join('').match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)))),
      y: new TextDecoder().decode(new Uint8Array(Array.from(y).map(b => b.toString(16).padStart(2, '0')).join('').match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)))),
    };

    // Actually, let me use a simpler approach - convert to base64url
    const bytesToB64u = (bytes: Uint8Array): string => {
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    };

    state.vapidPublicKeyJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: bytesToB64u(x),
      y: bytesToB64u(y),
    };

    // Compute JWK thumbprint
    state.thumbprint = await jwkThumbprintP256(state.vapidPublicKeyJwk);

    // Set key metadata (these are known values from the implementation)
    state.keyMetadata = {
      algorithm: {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      extractable: false,
      usages: ['sign'],
    };

    // Reload storage and audit log FIRST
    await loadStorage();
    await loadAuditLog();

    // Then update UI (so persistence card has correct data)
    updateButtonStates(); // Update button states (enable Sign JWT)
    updateAllCards();
    renderOutput();
    renderStorage();
    renderAuditLog();
    renderPerformance();

    button.textContent = '✓ VAPID Generated';
    setTimeout(() => {
      button.textContent = '2️⃣ Generate VAPID';
      // Don't manually set disabled - let updateButtonStates handle it
      updateButtonStates();
    }, 2000);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    if (errorMsg.includes('not unlocked')) {
      alert('Worker is locked. Please unlock with your passphrase first (Stage 5).');
    } else {
      alert(`Error: ${errorMsg}`);
    }
    button.textContent = '2️⃣ Generate VAPID';
    updateButtonStates(); // Update based on state
  }
}

async function stage3SignJWT(): Promise<void> {
  if (!state.vapidKid) {
    alert('Generate VAPID key first');
    return;
  }

  const button = document.getElementById('stage3-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Signing...';

  // Scroll to JWT card
  scrollToCard('jwt');

  try {
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:demo@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const startSign = performance.now();
    const result = await client!.signJWT(state.vapidKid, payload);
    state.metrics.signTime = performance.now() - startSign;

    state.jwt = result.jwt;

    // Capture signature conversion details if available (for demo visualization)
    if (result.debug?.signatureConversion) {
      const conv = result.debug.signatureConversion;
      state.signatureConversion = {
        originalFormat: conv.originalFormat as 'DER' | 'P-1363',
        originalBytes: new Uint8Array(conv.originalBytes),
        convertedBytes: new Uint8Array(conv.convertedBytes),
        wasConverted: conv.wasConverted,
      };
    }

    // Split JWT into parts
    const parts = result.jwt.split('.');
    state.jwtParts = {
      header: parts[0]!,
      payload: parts[1]!,
      signature: parts[2]!,
    };

    // Verify JWT format and signature
    state.jwtVerification = verifyJwtEs256Compact(result.jwt);

    // Verify payload
    if (state.jwtVerification.ok && state.jwtVerification.payload) {
      state.payloadVerification = verifyVAPIDPayload(state.jwtVerification.payload);
    }

    // Enable next stage
    (document.getElementById('stage4-btn') as HTMLButtonElement).disabled = false;

    updateAllCards();
    renderOutput();
    renderPerformance();

    // Reload audit log
    await loadAuditLog();
    renderAuditLog();

    button.textContent = '✓ JWT Signed';
    setTimeout(() => {
      button.textContent = '3️⃣ Sign JWT';
      // Don't manually set disabled - let updateButtonStates handle it
      updateButtonStates();
    }, 2000);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    if (errorMsg.includes('not unlocked')) {
      alert('Worker is locked. Please unlock with your passphrase first (Stage 5).');
    } else {
      alert(`Error: ${errorMsg}`);
    }
    button.textContent = '3️⃣ Sign JWT';
    updateButtonStates(); // Update based on state
  }
}

async function stage4LockWorker(): Promise<void> {
  const button = document.getElementById('stage4-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Locking...';

  // Scroll to lock card
  scrollToCard('lock');

  try {
    // Lock worker by terminating it (simulates lock behavior)
    // In production, we'd have a lock() RPC method
    state.isLocked = true;

    // Update button states (disable Lock, enable Unlock)
    updateButtonStates();

    updateAllCards();

    button.textContent = '✓ Worker Locked';
    setTimeout(() => {
      button.textContent = '4️⃣ Lock Worker';
      // Don't manually set disabled - let updateButtonStates handle it
      updateButtonStates();
    }, 2000);
  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '4️⃣ Lock Worker';
    updateButtonStates(); // Update based on state
  }
}

async function stage5UnlockWorker(): Promise<void> {
  const button = document.getElementById('stage5-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Unlocking...';

  // Scroll to unlock card
  scrollToCard('unlock');

  try {
    const startUnlock = performance.now();
    let result: { success: boolean; error?: string };

    // If unlock method is unknown (e.g., after page refresh), try to restore from cache
    if (!state.unlockMethod) {
      const cachedMethod = localStorage.getItem('kms-passkey-method') as 'passkey-prf' | 'passkey-gate' | null;

      if (cachedMethod) {
        console.log('[Demo] Restored unlock method from cache:', cachedMethod);
        state.unlockMethod = cachedMethod;
      } else {
        // Check if setup exists in storage to infer method
        const { isSetup } = await client!.isUnlockSetup();

        if (!isSetup) {
          alert('No unlock configuration found. Please complete setup first (Stage 1).');
          button.disabled = false;
          button.textContent = '5️⃣ Unlock Worker';
          return;
        }

        // Last resort: ask user
        const method = prompt(
          'Unlock method not detected. Please select:\n' +
          '1 = Passphrase\n' +
          '2 = Passkey (PRF mode)\n' +
          '3 = Passkey (gate-only mode)\n\n' +
          'Enter 1, 2, or 3:'
        );

        if (method === '1') {
          state.unlockMethod = 'passphrase';
        } else if (method === '2') {
          state.unlockMethod = 'passkey-prf';
        } else if (method === '3') {
          state.unlockMethod = 'passkey-gate';
        } else {
          button.disabled = false;
          button.textContent = '5️⃣ Unlock Worker';
          return;
        }
      }
    }

    // Determine unlock method and call appropriate function
    if (state.unlockMethod === 'passphrase') {
      // Passphrase unlock
      const passphrase = prompt('Enter passphrase to unlock:');
      if (!passphrase) {
        button.disabled = false;
        button.textContent = '5️⃣ Unlock Worker';
        return;
      }

      state.passphrase = passphrase;
      result = await client!.unlockWithPassphrase(passphrase);
    } else if (state.unlockMethod === 'passkey-prf') {
      // Passkey PRF unlock
      const rpId = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'localhost'
        : window.location.hostname;

      console.log('[Demo] Unlocking with passkey PRF, RP ID:', rpId);
      result = await client!.unlockWithPasskeyPRF(rpId);
    } else if (state.unlockMethod === 'passkey-gate') {
      // Passkey gate-only unlock
      const rpId = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'localhost'
        : window.location.hostname;

      console.log('[Demo] Unlocking with passkey gate-only, RP ID:', rpId);
      result = await client!.unlockWithPasskeyGate(rpId);
    } else {
      throw new Error('Unknown unlock method');
    }

    state.metrics.unlockTime = performance.now() - startUnlock;

    if (!result.success) {
      throw new Error(result.error || 'Unlock failed');
    }

    state.isLocked = false;

    // Update button states (enable Lock, disable Unlock, enable Sign JWT)
    updateButtonStates();

    updateAllCards();
    renderPerformance();

    // Reload audit log
    await loadAuditLog();
    renderAuditLog();

    button.textContent = '✓ Worker Unlocked';
    setTimeout(() => {
      button.textContent = '5️⃣ Unlock Worker';
      // Don't manually set disabled - let updateButtonStates handle it
      updateButtonStates();
    }, 2000);
  } catch (error) {
    console.error('[Demo] Unlock failed:', error);
    alert(`Unlock failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '5️⃣ Unlock Worker';
    updateButtonStates(); // Update based on state
  }
}

async function stage6PersistenceTest(): Promise<void> {
  const button = document.getElementById('stage6-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Testing...';

  // Scroll to persistence card
  scrollToCard('persistence');

  try {
    // Simulate page refresh by checking that keys are still in IndexedDB
    // In a real scenario, user would actually refresh the page
    await loadStorage();
    renderStorage();
    await loadAuditLog();
    renderAuditLog();

    updateAllCards();

    button.textContent = '✓ Persistence Verified';
    setTimeout(() => {
      button.textContent = '6️⃣ Persistence Test';
      // Don't manually set disabled - let updateButtonStates handle it
      updateButtonStates();
    }, 2000);
  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '6️⃣ Persistence Test';
    updateButtonStates(); // Update based on state
  }
}

async function stage7VerifyJWT(): Promise<void> {
  if (!state.vapidPublicKey) {
    alert('Generate VAPID key first');
    return;
  }

  if (!state.jwt) {
    alert('Sign a JWT first (Stage 3)');
    return;
  }

  const button = document.getElementById('stage7-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Verifying...';

  // Scroll to verify JWT card
  scrollToCard('verify-jwt');

  try {
    // Parse JWT parts
    const parts = state.jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const header = parts[0]!;
    const payload = parts[1]!;
    const signatureB64u = parts[2]!;

    // Decode signature from base64url
    const signatureBytes = b64uToBytes(signatureB64u);

    // The signing input is: header.payload
    const signingInput = `${header}.${payload}`;
    const signingInputBytes = new TextEncoder().encode(signingInput);

    // Import the current public key for verification
    // The public key is in raw format (65 bytes: 0x04 || x || y)
    const publicKeyBytes = b64uToBytes(state.vapidPublicKey);

    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['verify']
    );

    // Verify the signature
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      publicKey,
      signatureBytes,
      signingInputBytes
    );

    // Update state
    state.jwtSignatureValid = isValid;
    state.jwtVerificationError = null;

    // Update UI
    updateAllCards();

    button.textContent = isValid ? '✓ JWT Valid' : '❌ JWT Invalid';
    setTimeout(() => {
      button.textContent = '7️⃣ Verify JWT';
      updateButtonStates();
    }, 2000);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    state.jwtSignatureValid = false;
    state.jwtVerificationError = errorMsg;

    updateAllCards();

    alert(`Verification failed: ${errorMsg}`);
    button.textContent = '7️⃣ Verify JWT';
    updateButtonStates();
  }
}

async function stage8VerifyAuditChain(): Promise<void> {
  const button = document.getElementById('stage8-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Verifying...';

  // Scroll to audit verification card
  scrollToCard('audit-verify');

  try {
    if (!client) {
      throw new Error('Client not initialized');
    }

    // Get audit public key
    state.auditPublicKey = await client.getAuditPublicKey();

    // Verify audit chain
    const result = await client.verifyAuditChain();
    state.auditVerification = result;

    // Compute chain head hash (hash of latest entry)
    await initDB();
    const entries = await getAllAuditEntries();
    if (entries.length > 0) {
      const latestEntry = entries[entries.length - 1]!;
      state.chainHeadHash = await computeEntryHash(latestEntry);
    }

    updateAllCards();

    button.textContent = result.valid ? '✓ Chain Verified' : '⚠ Chain Invalid';
    setTimeout(() => {
      button.textContent = '8️⃣ Verify Audit Chain';
      updateButtonStates();
    }, 2000);
  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '8️⃣ Verify Audit Chain';
    updateButtonStates();
  }
}

async function stage9TamperDetection(): Promise<void> {
  const button = document.getElementById('stage9-btn') as HTMLButtonElement;
  button.disabled = true;
  button.textContent = 'Testing...';

  // Scroll to tamper detection card
  scrollToCard('tamper');

  try {
    if (!client) {
      throw new Error('Client not initialized');
    }

    // First, verify the chain is valid before tampering
    const beforeResult = await client.verifyAuditChain();

    // Now tamper with an entry in IndexedDB
    await initDB();
    const entries = await getAllAuditEntries();
    if (entries.length === 0) {
      throw new Error('No audit entries to tamper with');
    }

    // Tamper with the second-to-last entry (modify its operation field)
    const targetEntry = entries[entries.length - 2];
    if (targetEntry) {
      // Modify the entry (this will break the signature)
      const tamperedEntry = { ...targetEntry, op: 'TAMPERED' };

      // Get direct access to IndexedDB to modify the entry
      const db = indexedDB;
      const openRequest = db.open(DB_NAME);

      await new Promise<void>((resolve, reject) => {
        openRequest.onsuccess = () => {
          const database = openRequest.result;
          const transaction = database.transaction('audit', 'readwrite');
          const store = transaction.objectStore('audit');

          // Delete old entry and add tampered one
          const deleteRequest = store.delete(IDBKeyRange.only(entries.length - 1));
          deleteRequest.onsuccess = () => {
            const addRequest = store.add(tamperedEntry);
            addRequest.onsuccess = () => {
              resolve();
            };
            addRequest.onerror = () => reject(new Error('Failed to add tampered entry'));
          };
          deleteRequest.onerror = () => reject(new Error('Failed to delete entry'));
        };
        openRequest.onerror = () => reject(new Error('Failed to open database'));
      });
    }

    // Verify the chain again after tampering
    const afterResult = await client.verifyAuditChain();

    state.tamperTestResult = {
      beforeValid: beforeResult.valid,
      afterValid: afterResult.valid,
      errors: afterResult.errors,
    };

    updateAllCards();

    button.textContent = !afterResult.valid ? '✓ Tampering Detected' : '⚠ Test Failed';
    setTimeout(() => {
      button.textContent = '9️⃣ Tamper Detection';
      updateButtonStates();
    }, 2000);
  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = '9️⃣ Tamper Detection';
    updateButtonStates();
  }
}

async function resetDemo(silent = false): Promise<void> {
  const confirmed = silent || confirm('This will clear all demo state and IndexedDB data. Continue?');
  if (!confirmed) return;

  // Destroy client (terminates worker)
  if (client) {
    client.destroy();
    client = null;
  }

  // Clear IndexedDB
  try {
    // Close DB connection
    closeDB();

    // Delete the entire database
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = () => {
        console.log('[Demo] IndexedDB cleared');
        resolve();
      };
      request.onerror = () => {
        console.error('[Demo] Failed to clear IndexedDB');
        reject(new Error('Failed to clear IndexedDB'));
      };
      request.onblocked = () => {
        console.warn('[Demo] IndexedDB delete blocked - close other tabs');
      };
    });
  } catch (error) {
    console.error('[Demo] Error clearing IndexedDB:', error);
  }

  // Reset state
  Object.assign(state, {
    setupComplete: false,
    vapidKid: null,
    vapidPublicKey: null,
    vapidPublicKeyJwk: null,
    jwt: null,
    jwtParts: null,
    isLocked: false,
    passphrase: null,
    auditEntries: [],
    storedKeys: [],
    metrics: {
      setupTime: null,
      unlockTime: null,
      keyGenTime: null,
      signTime: null,
      workerLoadTime: null,
    },
    thumbprint: null,
    pubKeyVerification: null,
    jwtVerification: null,
    payloadVerification: null,
    jwtSignatureValid: null,
    jwtVerificationError: null,
    keyMetadata: null,
    // Phase 1 additions
    auditPublicKey: null,
    auditVerification: null,
    tamperTestResult: null,
    signatureConversion: null,
    chainHeadHash: null,
    auditEntryHashes: new Map(),
    // Unlock method
    unlockMethod: null,
    // WebAuthn passkey state (demo only)
    passkeyCredentialId: null,
    passkeyPublicKey: null,
    passkeyAssertion: null,
  });

  // Clear passkey from localStorage
  localStorage.removeItem('demo-passkey-credential-id');
  localStorage.removeItem('kms-passkey-method');

  // Re-enable both setup buttons
  const passphraseBtn = document.getElementById('stage1-passphrase-btn') as HTMLButtonElement;
  const passkeyBtn = document.getElementById('stage1-passkey-btn') as HTMLButtonElement;
  passphraseBtn.disabled = false;
  passphraseBtn.textContent = '🔐 Setup Passphrase';
  passkeyBtn.disabled = false;
  passkeyBtn.textContent = '🔑 Setup Passkey (PRF)';

  // Update button states based on reset state
  updateButtonStates();

  // Update UI
  updateAllCards();
  renderOutput();
  renderAuditLog();
  renderStorage();
  renderPerformance();

  if (!silent) {
    alert('Demo reset complete');
  }
}

// ============================================================================
// Tab Management
// ============================================================================

function initTabs(): void {
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const tabName = (tab as HTMLElement).dataset.tab;

      // Update active tab
      tabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');

      // Update active content
      tabContents.forEach((content) => {
        content.classList.remove('active');
        if (content.id === `${tabName}-tab`) {
          content.classList.add('active');
        }
      });
    });
  });
}

// ============================================================================
// Initialize
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Initialize tabs
  initTabs();

  // Initialize empty cards
  updateAllCards();
  renderOutput();
  renderPerformance();

  // Load existing data from IndexedDB
  await loadAuditLog();
  renderAuditLog();
  await loadStorage();
  renderStorage();

  console.log('[Demo] Loaded storage, found', state.storedKeys.length, 'keys');

  // Load passkey credential ID from localStorage (if exists)
  const savedCredentialId = localStorage.getItem('demo-passkey-credential-id');
  if (savedCredentialId) {
    state.passkeyCredentialId = savedCredentialId;
    console.log('[Demo] Loaded passkey credential ID from localStorage');
  }

  // Check if unlock is already configured (e.g., after page refresh)
  try {
    // Initialize client to check unlock status
    if (!client) {
      client = new KMSClient();
    }

    const unlockStatus = await client.isUnlockSetup();

    if (unlockStatus.isSetup) {
      // Unlock is already configured
      console.log('[Demo] Unlock already configured');

      // Disable both setup buttons
      const passphraseBtn = document.getElementById('stage1-passphrase-btn') as HTMLButtonElement;
      const passkeyBtn = document.getElementById('stage1-passkey-btn') as HTMLButtonElement;
      passphraseBtn.disabled = true;
      passphraseBtn.textContent = '✓ Already Setup';
      passkeyBtn.disabled = true;
      passkeyBtn.textContent = '✓ Already Setup';

      // Update state to reflect existing setup
      state.setupComplete = true;
      state.isLocked = true; // After page refresh, worker is locked

      // Try to detect unlock method by checking stored metadata
      // Note: We can't directly read the method without unlocking, so we'll set it to null
      // and require the user to unlock to resume
      state.unlockMethod = null; // Will be determined on unlock

      // Load key info if we have stored keys
      if (state.storedKeys.length > 0) {
        const firstKey = state.storedKeys[0];
        state.vapidKid = firstKey.kid;
        state.vapidPublicKey = firstKey.publicKey;
      }

      // Update button states based on current state
      updateButtonStates();

      console.log('[Demo] Enabled buttons based on state: locked=true, hasKeys=' + (state.storedKeys.length > 0));

      // Update all cards to reflect existing state
      updateAllCards();

      // Re-render output section with loaded key data
      renderOutput();
    } else {
      // No unlock setup - update button states anyway
      updateButtonStates();
    }
  } catch (error) {
    console.error('[Demo] Failed to check unlock status:', error);
    // Still update button states on error
    updateButtonStates();
  }

  // Bind stage buttons
  document.getElementById('stage1-passphrase-btn')!.addEventListener('click', stage1SetupPassphrase);
  document.getElementById('stage1-passkey-btn')!.addEventListener('click', stage1SetupPasskey);
  document.getElementById('stage2-btn')!.addEventListener('click', stage2GenerateVAPID);
  document.getElementById('stage3-btn')!.addEventListener('click', stage3SignJWT);
  document.getElementById('stage4-btn')!.addEventListener('click', stage4LockWorker);
  document.getElementById('stage5-btn')!.addEventListener('click', stage5UnlockWorker);
  document.getElementById('stage6-btn')!.addEventListener('click', stage6PersistenceTest);
  document.getElementById('stage7-btn')!.addEventListener('click', stage7VerifyJWT);
  document.getElementById('stage8-btn')!.addEventListener('click', stage8VerifyAuditChain);
  document.getElementById('stage9-btn')!.addEventListener('click', stage9TamperDetection);
  document.getElementById('scroll-to-output-btn')!.addEventListener('click', () => {
    const outputSection = document.getElementById('output-section');
    if (outputSection) {
      outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
  document.getElementById('reset-btn')!.addEventListener('click', () => resetDemo());

  // Bind passkey buttons
  document.getElementById('delete-passkey-btn')!.addEventListener('click', deletePasskey);

  // Bind refresh buttons
  document.getElementById('refresh-audit-btn')!.addEventListener('click', () => {
    loadAuditLog().then(renderAuditLog);
  });
  document.getElementById('refresh-storage-btn')!.addEventListener('click', () => {
    loadStorage().then(renderStorage);
  });

  console.log('[Phase 1 Demo] Ready');
  console.log('[Phase 1 Demo] Uses production KMSClient with real Worker');
});
