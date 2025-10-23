/**
 * Progressive KMS Demo with Stage-by-Stage Verification
 *
 * Users can either run each stage individually and watch the verification
 * cards populate progressively, or run all stages at once.
 */

import {
  b64uToBytes,
  verifyRawP256,
  verifyJwtEs256Compact,
  verifyVAPIDPayload,
  jwkThumbprintP256,
  type PublicKeyVerification,
  type JWTVerification,
  type JWTPayloadVerification,
} from './verify';

// ============================================================================
// Types
// ============================================================================

interface EnhancedVAPIDKeyPair {
  kid: string;
  publicKey: string;
  publicKeyJwk: JsonWebKey;
  keyMetadata: {
    algorithm: { name: string; namedCurve: string };
    extractable: boolean;
    usages: string[];
  };
}

interface EnhancedJWTResult {
  jwt: string;
  jwtParts: { header: string; payload: string; signature: string };
  decodedHeader: Record<string, unknown>;
  decodedPayload: Record<string, unknown>;
  signatureBytes: number;
}

interface DemoState {
  vapid: EnhancedVAPIDKeyPair | null;
  jwt: EnhancedJWTResult | null;
  thumbprint: string | null;
  pubKeyVerification: PublicKeyVerification | null;
  jwtVerification: JWTVerification | null;
  payloadVerification: JWTPayloadVerification | null;
}

// ============================================================================
// Demo Client
// ============================================================================

class EnhancedKMSClient {
  private worker: Worker | null = null;
  private requestId = 0;
  private pendingRequests = new Map<string, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();

  constructor() {
    this.worker = new Worker(new URL('./demo-worker.ts', import.meta.url), { type: 'module' });

    this.worker.onmessage = (event): void => {
      const response = event.data as { id: string; result?: unknown; error?: { code: string; message: string } };
      const pending = this.pendingRequests.get(response.id);

      if (!pending) return;

      if (response.error) {
        pending.reject(new Error(response.error.message));
      } else {
        pending.resolve(response.result);
      }

      this.pendingRequests.delete(response.id);
    };
  }

  private request<T>(method: string, params?: unknown): Promise<T> {
    const id = `req-${++this.requestId}`;
    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.worker!.postMessage({ id, method, params });
    });
  }

  generateVAPIDEnhanced(): Promise<EnhancedVAPIDKeyPair> {
    return this.request<EnhancedVAPIDKeyPair>('generateVAPIDEnhanced');
  }

  signJWTEnhanced(kid: string, payload: Record<string, unknown>): Promise<EnhancedJWTResult> {
    return this.request<EnhancedJWTResult>('signJWTEnhanced', { kid, payload });
  }
}

// ============================================================================
// Global State
// ============================================================================

let client: EnhancedKMSClient | null = null;
const state: DemoState = {
  vapid: null,
  jwt: null,
  thumbprint: null,
  pubKeyVerification: null,
  jwtVerification: null,
  payloadVerification: null,
};

// ============================================================================
// UI Rendering Functions
// ============================================================================

function renderCheck(status: 'pass' | 'fail' | 'pending', label: string, detail?: string): string {
  const icons = { pass: '✅', fail: '❌', pending: '⏳' };
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

function renderPublicKeyCard(): void {
  const { vapid, pubKeyVerification, thumbprint } = state;

  const checks = [
    vapid && pubKeyVerification
      ? renderCheck(
          pubKeyVerification.ok ? 'pass' : 'fail',
          `Format: ${pubKeyVerification.length} bytes`,
          pubKeyVerification.ok
            ? 'Uncompressed P-256 point (required by PushManager)'
            : pubKeyVerification.reason
        )
      : renderCheck('pending', 'Format: Awaiting key generation', 'Generate a VAPID keypair first'),

    vapid && pubKeyVerification
      ? renderCheck(
          pubKeyVerification.ok && pubKeyVerification.leadingByte === '0x04' ? 'pass' : 'fail',
          `Leading byte: ${pubKeyVerification.leadingByte}`,
          'Indicates uncompressed point format'
        )
      : renderCheck('pending', 'Leading byte: Pending', 'Will check after key generation'),

    vapid
      ? renderCheck(
          'pass',
          `Base64url encoded (${vapid.publicKey.length} chars)`,
          vapid.publicKey
        )
      : renderCheck('pending', 'Base64url encoding: Pending', 'Will display after key generation'),
  ].join('');

  const card = renderCard(
    '🔑 Public Key Verification',
    '<strong>Why this matters:</strong> PushManager requires the raw uncompressed P-256 point (65 bytes). SPKI/JWK formats will fail. Showing 65 bytes and leading 0x04 proves we\'re passing the correct format.',
    checks
  );

  document.getElementById('pubkey-card')!.innerHTML = card;
}

function renderJWTCard(): void {
  const { jwt, jwtVerification, payloadVerification, thumbprint } = state;

  const kidMatch = jwt && thumbprint && jwtVerification?.header?.kid === thumbprint;

  const checks = [
    jwt && jwtVerification
      ? renderCheck(
          jwtVerification.header?.alg === 'ES256' ? 'pass' : 'fail',
          `Algorithm: ${jwtVerification.header?.alg || 'unknown'}`,
          'ES256 = ECDSA with P-256 and SHA-256'
        )
      : renderCheck('pending', 'Algorithm: Pending', 'Sign a JWT to verify algorithm'),

    jwt && thumbprint
      ? renderCheck(
          kidMatch ? 'pass' : 'fail',
          `Key ID matches JWK thumbprint`,
          kidMatch ? `kid = ${thumbprint}` : 'Thumbprints do not match'
        )
      : renderCheck('pending', 'Key ID verification: Pending', 'Sign a JWT to verify kid'),

    jwt && jwtVerification
      ? renderCheck(
          jwtVerification.ok && jwtVerification.sigLength === 64 ? 'pass' : 'fail',
          `Signature: ${jwtVerification.sigLength || jwt.signatureBytes} bytes`,
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
  ].join('');

  const card = renderCard(
    '🎫 JWT Signature Verification',
    '<strong>Why this matters:</strong> WebCrypto returns DER-encoded signatures, but JWS ES256 requires P-1363 format (raw r‖s). A 64-byte signature (not starting with 0x30) proves we converted correctly so validators accept the token.',
    checks
  );

  document.getElementById('jwt-card')!.innerHTML = card;
}

function renderKeyPropertiesCard(): void {
  const { vapid, thumbprint } = state;

  const checks = [
    vapid
      ? renderCheck(
          vapid.keyMetadata.algorithm.name === 'ECDSA' ? 'pass' : 'fail',
          `Algorithm: ${vapid.keyMetadata.algorithm.name}`,
          'Elliptic Curve Digital Signature Algorithm'
        )
      : renderCheck('pending', 'Algorithm: Pending', 'Generate a key to verify algorithm'),

    vapid
      ? renderCheck(
          vapid.keyMetadata.algorithm.namedCurve === 'P-256' ? 'pass' : 'fail',
          `Curve: ${vapid.keyMetadata.algorithm.namedCurve}`,
          'NIST P-256 (secp256r1) - required for VAPID'
        )
      : renderCheck('pending', 'Curve: Pending', 'Generate a key to verify curve'),

    vapid
      ? renderCheck(
          !vapid.keyMetadata.extractable ? 'pass' : 'fail',
          `Extractable: ${vapid.keyMetadata.extractable}`,
          'Private key cannot be exported from browser'
        )
      : renderCheck('pending', 'Extractable flag: Pending', 'Generate a key to check extractable flag'),

    vapid
      ? renderCheck(
          vapid.keyMetadata.usages.includes('sign') ? 'pass' : 'fail',
          `Usages: ${vapid.keyMetadata.usages.join(', ')}`,
          'Key can sign and verify (but not export)'
        )
      : renderCheck('pending', 'Key usages: Pending', 'Generate a key to check usages'),

    thumbprint
      ? renderCheck(
          'pass',
          `JWK Thumbprint (RFC 7638) - ${thumbprint.length} chars`,
          thumbprint
        )
      : renderCheck('pending', 'JWK Thumbprint: Pending', 'Generate a key to compute thumbprint'),
  ].join('');

  const card = renderCard(
    '🔐 Key Properties Verification',
    '<strong>Why this matters:</strong> With extractable: false, the browser refuses to export the private key. Even if the host app misbehaves, it cannot read the key material. The key ID is content-derived from the public key (RFC 7638) for auditability.',
    checks
  );

  document.getElementById('keyprops-card')!.innerHTML = card;
}

function renderOutputSection(): void {
  const output = document.getElementById('output-section')!;
  const parts: string[] = [];

  if (state.vapid) {
    parts.push(`
      <div class="output-card">
        <h4>🔑 VAPID Keypair Generated</h4>
        <div class="output-item">
          <strong>Kid:</strong>
          <code>${state.vapid.kid}</code>
          <span class="length">(${state.vapid.kid.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Public Key (Base64url):</strong>
          <code class="truncate">${state.vapid.publicKey}</code>
          <span class="length">(${state.vapid.publicKey.length} chars, ${b64uToBytes(state.vapid.publicKey).length} bytes)</span>
        </div>
        <details>
          <summary>Show JWK Representation</summary>
          <pre>${JSON.stringify(state.vapid.publicKeyJwk, null, 2)}</pre>
        </details>
      </div>
    `);
  }

  if (state.jwt) {
    parts.push(`
      <div class="output-card">
        <h4>🎫 JWT Signed</h4>
        <div class="output-item">
          <strong>Full JWT:</strong>
          <code class="wrap">${state.jwt.jwt}</code>
          <span class="length">(${state.jwt.jwt.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Header:</strong>
          <code class="truncate">${state.jwt.jwtParts.header}</code>
          <span class="length">(${state.jwt.jwtParts.header.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Payload:</strong>
          <code class="truncate">${state.jwt.jwtParts.payload}</code>
          <span class="length">(${state.jwt.jwtParts.payload.length} chars)</span>
        </div>
        <div class="output-item">
          <strong>Signature:</strong>
          <code class="truncate">${state.jwt.jwtParts.signature}</code>
          <span class="length">(${state.jwt.jwtParts.signature.length} chars, ${state.jwt.signatureBytes} bytes)</span>
        </div>
        <details>
          <summary>Show Decoded Header</summary>
          <pre>${JSON.stringify(state.jwt.decodedHeader, null, 2)}</pre>
        </details>
        <details>
          <summary>Show Decoded Payload</summary>
          <pre>${JSON.stringify(state.jwt.decodedPayload, null, 2)}</pre>
        </details>
      </div>
    `);
  }

  output.innerHTML = parts.length > 0 ? parts.join('') : '<p class="empty-state">Run a demo step to see detailed output...</p>';
}

function updateUI(): void {
  renderPublicKeyCard();
  renderJWTCard();
  renderKeyPropertiesCard();
  renderOutputSection();
}

// ============================================================================
// Demo Actions
// ============================================================================

async function generateVAPIDKey(): Promise<void> {
  const button = document.getElementById('gen-btn') as HTMLButtonElement;
  const signBtn = document.getElementById('sign-btn') as HTMLButtonElement;

  try {
    button.disabled = true;
    button.textContent = 'Generating...';

    if (!client) client = new EnhancedKMSClient();

    // Generate keypair
    state.vapid = await client.generateVAPIDEnhanced();

    // Compute thumbprint
    state.thumbprint = await jwkThumbprintP256(state.vapid.publicKeyJwk);

    // Verify public key
    const pubKeyBytes = b64uToBytes(state.vapid.publicKey);
    state.pubKeyVerification = verifyRawP256(pubKeyBytes);

    // Enable next step
    signBtn.disabled = false;

    updateUI();
    button.textContent = '✓ Key Generated';
    setTimeout(() => { button.textContent = 'Generate VAPID Keypair'; button.disabled = false; }, 2000);

  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = 'Generate VAPID Keypair';
    button.disabled = false;
  }
}

async function signJWT(): Promise<void> {
  if (!state.vapid) {
    alert('Generate a VAPID keypair first');
    return;
  }

  const button = document.getElementById('sign-btn') as HTMLButtonElement;

  try {
    button.disabled = true;
    button.textContent = 'Signing...';

    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:demo@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    };

    state.jwt = await client!.signJWTEnhanced(state.vapid.kid, payload);
    state.jwtVerification = verifyJwtEs256Compact(state.jwt.jwt);
    state.payloadVerification = verifyVAPIDPayload(state.jwt.decodedPayload);

    updateUI();
    button.textContent = '✓ JWT Signed';
    setTimeout(() => { button.textContent = 'Sign JWT Token'; button.disabled = false; }, 2000);

  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = 'Sign JWT Token';
    button.disabled = false;
  }
}

async function runFullDemo(): Promise<void> {
  const button = document.getElementById('full-btn') as HTMLButtonElement;

  try {
    button.disabled = true;
    button.textContent = 'Running Full Demo...';

    // Reset state
    Object.assign(state, {
      vapid: null,
      jwt: null,
      thumbprint: null,
      pubKeyVerification: null,
      jwtVerification: null,
      payloadVerification: null,
    });
    updateUI();

    // Stage 1: Generate key
    await generateVAPIDKey();
    await new Promise(resolve => setTimeout(resolve, 500)); // Brief pause for visual effect

    // Stage 2: Sign JWT
    await signJWT();

    button.textContent = '✓ Demo Complete';
    setTimeout(() => { button.textContent = 'Run Full Demo'; button.disabled = false; }, 2000);

  } catch (error) {
    alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    button.textContent = 'Run Full Demo';
    button.disabled = false;
  }
}

// ============================================================================
// Initialize
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Initialize empty cards
  updateUI();

  // Bind buttons
  document.getElementById('gen-btn')!.addEventListener('click', generateVAPIDKey);
  document.getElementById('sign-btn')!.addEventListener('click', signJWT);
  document.getElementById('full-btn')!.addEventListener('click', runFullDemo);

  console.log('[Progressive Demo] Ready');
});
