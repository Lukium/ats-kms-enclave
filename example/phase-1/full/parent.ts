/**
 * Full Demo - Parent PWA
 *
 * Runs on http://localhost:5173
 * Embeds KMS iframe from http://localhost:5174 (cross-origin isolated)
 */

import { KMSUser, type StatusResult } from '@/kms-user';
import type { AuditEntryV2 } from '@/types';

console.log('[Full Demo] Parent PWA initializing...');

// KMS Configuration
const KMS_ORIGIN = 'http://localhost:5174';

// Initialize KMS User
const kmsUser = new KMSUser({
  kmsOrigin: KMS_ORIGIN,
});

// DOM Elements
const auditLogEl = document.getElementById('audit-log')!;
const resetDemoBtn = document.getElementById('reset-demo-btn')!;
const setupOperationEl = document.getElementById('setup-operation')!;

/**
 * Display audit log entries
 */
function displayAuditLog(entries: AuditEntryV2[]): void {
  if (entries.length === 0) {
    auditLogEl.innerHTML = '<p class="empty">No audit entries yet</p>';
    return;
  }

  // Display entries in reverse chronological order (newest first)
  const html = entries
    .slice()
    .reverse()
    .map((entry) => {
      // Determine color based on signer type
      let signerColor = '#4299e1'; // blue for UAK
      if (entry.signer === 'LAK') {
        signerColor = '#48bb78'; // green for LAK
      } else if (entry.signer === 'KIAK') {
        signerColor = '#ed8936'; // orange for KIAK
      }

      return `
        <div class="audit-entry" style="border-left-color: ${signerColor};">
          <div class="audit-header">
            <span class="audit-seq">#${entry.seqNum}</span>
            <span class="audit-signer" style="color: ${signerColor};">${entry.signer}</span>
            <span class="audit-timestamp">${new Date(entry.timestamp).toLocaleTimeString()}</span>
          </div>
          <div class="audit-details">
            <div><strong>Operation:</strong> ${entry.op}</div>
            <div><strong>Request ID:</strong> <code>${entry.requestId}</code></div>
            ${entry.leaseId ? `<div><strong>Lease ID:</strong> <code>${entry.leaseId}</code></div>` : ''}
            ${entry.kid ? `<div><strong>Key ID:</strong> <code>${entry.kid}</code></div>` : ''}
            <div><strong>Chain Hash:</strong> <code>${entry.chainHash}</code></div>
            <div><strong>Signature:</strong> <code>${entry.sig}</code></div>
            ${entry.cert ? `<div><strong>Delegation:</strong> ${entry.cert.signerKind} (scope: ${entry.cert.scope.join(', ')})</div>` : ''}
          </div>
        </div>
      `;
    })
    .join('');

  auditLogEl.innerHTML = html;
}

/**
 * Load and display audit log
 */
async function loadAuditLog(): Promise<void> {
  try {
    console.log('[Full Demo] Fetching audit log...');
    const result = await kmsUser.getAuditLog();
    console.log('[Full Demo] Audit log fetched:', result.entries.length, 'entries');
    displayAuditLog(result.entries);
  } catch (error) {
    console.error('[Full Demo] Failed to load audit log:', error);
    auditLogEl.innerHTML = `<p class="error">Failed to load audit log: ${error instanceof Error ? error.message : String(error)}</p>`;
  }
}

/**
 * Initialize KMS and load initial audit log
 */
async function initKMS(): Promise<StatusResult> {
  try {
    console.log('[Full Demo] Initializing KMS User...');
    await kmsUser.init();
    console.log('[Full Demo] KMS User initialized successfully');
    console.log('[Full Demo] Cross-origin isolation verified - KMS IndexedDB should NOT be visible in parent context');

    // Wait a moment for KIAK initialization to complete
    await new Promise((resolve) => setTimeout(resolve, 500));

    // Check setup status
    const status = await kmsUser.isSetup();
    console.log('[Full Demo] Setup status:', status);

    // Load initial audit log (should show KIAK initialization)
    await loadAuditLog();

    return status;
  } catch (error) {
    console.error('[Full Demo] KMS initialization failed:', error);
    auditLogEl.innerHTML = `<p class="error">KMS initialization failed: ${error instanceof Error ? error.message : String(error)}</p>`;
    throw error;
  }
}

/**
 * Reset demo - clears KMS database and reloads page
 */
async function resetDemo(): Promise<void> {
  if (!confirm('Reset demo? This will delete all KMS data.\n\nAfter clicking OK, please hard refresh (Ctrl+Shift+R or Cmd+Shift+R) to complete the reset.')) {
    return;
  }

  try {
    console.log('[Full Demo] Resetting KMS...');
    resetDemoBtn.disabled = true;
    resetDemoBtn.textContent = '🔄 Resetting...';

    // Call resetKMS to delete and reinitialize the database
    await kmsUser.resetKMS();

    console.log('[Full Demo] Reset complete!');
    console.log('[Full Demo] Please hard refresh (Ctrl+Shift+R or Cmd+Shift+R) to see the clean state');

    resetDemoBtn.disabled = false;
    resetDemoBtn.textContent = '✅ Reset! Please hard refresh';
    resetDemoBtn.style.background = '#48bb78'; // Green to indicate success

    // Show a persistent message
    auditLogEl.innerHTML = `
      <div style="background: #c6f6d5; border: 2px solid #48bb78; border-radius: 8px; padding: 2rem; text-align: center;">
        <h3 style="color: #22543d; margin: 0 0 1rem 0;">✅ Reset Complete!</h3>
        <p style="color: #22543d; margin: 0; font-size: 1.1rem;">
          Please <strong>hard refresh</strong> the page to see the clean state:
        </p>
        <p style="color: #22543d; margin: 0.5rem 0 0 0; font-family: monospace; font-size: 1.2rem; font-weight: bold;">
          Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)
        </p>
      </div>
    `;
  } catch (error) {
    console.error('[Full Demo] Reset failed:', error);
    resetDemoBtn.disabled = false;
    resetDemoBtn.textContent = '🔄 Reset Demo';
    resetDemoBtn.style.background = '#e53e3e'; // Reset to red
    alert(`Reset failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Render setup operation UI
 */
function renderSetupUI(status: { isSetup: boolean; methods: string[] }): void {
  const hasPassphrase = status.methods.includes('passphrase');
  const hasPasskey = status.methods.includes('passkey');
  const hasAnyMethod = status.isSetup && status.methods.length > 0;

  let html = '';

  // Show enrolled methods
  if (hasAnyMethod) {
    html += '<div class="enrolled-methods">';
    html += '<h4>Enrolled Methods:</h4>';
    html += '<ul>';
    if (hasPassphrase) html += '<li>🔐 Passphrase</li>';
    if (hasPasskey) html += '<li>🔑 WebAuthn</li>';
    html += '</ul>';
    html += '</div>';
  }

  // Determine available options
  const canAddPassphrase = !hasPassphrase;
  const canAddWebAuthn = !hasPasskey;

  if (canAddPassphrase || canAddWebAuthn) {
    const buttonLabel = hasAnyMethod ? 'Add' : 'Setup';
    html += '<div class="setup-choice">';

    if (canAddPassphrase) {
      const btnId = hasAnyMethod ? 'add-passphrase-btn' : 'setup-passphrase-btn';
      html += `<button id="${btnId}" class="operation-btn">🔐 ${buttonLabel} Passphrase</button>`;
    }

    if (canAddWebAuthn) {
      const btnId = hasAnyMethod ? 'add-webauthn-btn' : 'setup-webauthn-btn';
      html += `<button id="${btnId}" class="operation-btn">🔑 ${buttonLabel} WebAuthn</button>`;
    }

    html += '</div>';
  } else {
    html += '<div class="info-message">All authentication methods are enrolled!</div>';
  }

  setupOperationEl.innerHTML = html;

  // Add event listeners
  if (hasAnyMethod) {
    // Add enrollment mode
    if (canAddPassphrase) {
      document.getElementById('add-passphrase-btn')?.addEventListener('click', () => addEnrollmentPassphrase(status));
    }
    if (canAddWebAuthn) {
      document.getElementById('add-webauthn-btn')?.addEventListener('click', () => addEnrollmentWebAuthn(status));
    }
  } else {
    // Initial setup mode
    if (canAddPassphrase) {
      document.getElementById('setup-passphrase-btn')?.addEventListener('click', setupPassphrase);
    }
    if (canAddWebAuthn) {
      document.getElementById('setup-webauthn-btn')?.addEventListener('click', setupWebAuthn);
    }
  }
}

/**
 * Setup passphrase authentication
 */
async function setupPassphrase(): Promise<void> {
  const passphrase = prompt('Enter a passphrase (min 8 characters):');
  if (!passphrase) return;

  if (passphrase.length < 8) {
    alert('Passphrase must be at least 8 characters');
    return;
  }

  try {
    console.log('[Full Demo] Setting up passphrase...');
    const result = await kmsUser.setupPassphrase(passphrase);
    console.log('[Full Demo] Passphrase setup complete:', result);

    // Show success and reload audit log
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ Passphrase Setup Complete!</h4>
        <div class="artifact-card">
          <div class="artifact-title">Enrollment ID</div>
          <div class="artifact-data"><code>${result.enrollmentId}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">VAPID Key ID</div>
          <div class="artifact-data"><code>${result.vapidKid}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">VAPID Public Key</div>
          <div class="artifact-data"><code>${result.vapidPublicKey}</code></div>
        </div>
      </div>
    `;

    await loadAuditLog();

    // Reload setup UI to reflect new enrollment
    const status = await kmsUser.isSetup();
    renderSetupUI(status);
  } catch (error) {
    console.error('[Full Demo] Passphrase setup failed:', error);
    alert(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Setup WebAuthn authentication with PRF/Gate auto-detection
 */
async function setupWebAuthn(): Promise<void> {
  // Fixed demo credentials
  const name = 'Demo User';
  const userId = 'demouser@ats.run';
  const rpId = 'localhost';

  try {
    console.log('[Full Demo] Setting up WebAuthn with PRF auto-detection...');

    // Generate app salt for PRF
    const appSalt = crypto.getRandomValues(new Uint8Array(32));

    // Run WebAuthn ceremony with PRF extension
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: rpId, name: 'ATS KMS V2' },
        user: {
          id: new TextEncoder().encode(userId),
          name,
          displayName: name,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'required',
        },
        extensions: {
          prf: {
            eval: {
              first: appSalt,
            },
          },
        },
      },
    }) as PublicKeyCredential;

    // Check if PRF extension succeeded
    const prfExt = (credential as any).getClientExtensionResults().prf;
    const prfOutput = prfExt?.results?.first;

    let result;
    let method;

    if (prfOutput) {
      // PRF available - use setupPasskeyPRF with the credential from first ceremony
      console.log('[Full Demo] PRF available, using setupPasskeyPRF');
      method = 'Passkey PRF';
      result = await kmsUser.setupPasskeyPRF({
        name,
        rpId,
        userId,
      });

      // Store appSalt for future unlock operations
      localStorage.setItem('kms:appSalt', Array.from(appSalt).toString());
    } else {
      // PRF not available - use Gate with credential from first ceremony (no second ceremony!)
      console.log('[Full Demo] PRF not available, using setupPasskeyGate with existing credential');
      method = 'Passkey Gate';

      // Pass the credential data from the FIRST ceremony to avoid double ceremony
      // kmsUser.setupPasskeyGate will use this credential instead of running a new ceremony
      result = await kmsUser.sendRequest<any>('setupPasskeyGate', {
        credentialId: credential.rawId,
        rpId,
      });
    }

    console.log(`[Full Demo] WebAuthn setup complete (${method}):`, result);

    // Show success and reload audit log
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ WebAuthn Setup Complete! (${method})</h4>
        <div class="artifact-card">
          <div class="artifact-title">Enrollment ID</div>
          <div class="artifact-data"><code>${result.enrollmentId}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">VAPID Key ID</div>
          <div class="artifact-data"><code>${result.vapidKid}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">VAPID Public Key</div>
          <div class="artifact-data"><code>${result.vapidPublicKey}</code></div>
        </div>
      </div>
    `;

    await loadAuditLog();

    // Reload setup UI to reflect new enrollment
    const status = await kmsUser.isSetup();
    renderSetupUI(status);
  } catch (error) {
    console.error('[Full Demo] WebAuthn setup failed:', error);
    alert(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Add passphrase enrollment to existing setup
 */
async function addEnrollmentPassphrase(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  const passphrase = prompt('Enter a passphrase (min 8 characters):');
  if (!passphrase) return;

  if (passphrase.length < 8) {
    alert('Passphrase must be at least 8 characters');
    return;
  }

  // Get existing credentials to unlock
  const existingMethod = status.methods[0]; // Use first enrolled method
  let credentials: any;

  if (existingMethod === 'passphrase') {
    const existingPassphrase = prompt('Enter your CURRENT passphrase to authenticate:');
    if (!existingPassphrase) return;
    credentials = { method: 'passphrase', passphrase: existingPassphrase };
  } else if (existingMethod === 'passkey') {
    alert('Please authenticate with your passkey...');
    // For passkey, we need to run WebAuthn get ceremony
    const appSalt = localStorage.getItem('kms:appSalt');

    try {
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: 'localhost',
          userVerification: 'required',
          extensions: appSalt ? {
            prf: {
              eval: {
                first: new Uint8Array(appSalt.split(',').map(n => parseInt(n, 10))),
              },
            },
          } : undefined,
        },
      }) as PublicKeyCredential;

      // Check if PRF was used and succeeded
      const prfExt = (assertion as any).getClientExtensionResults().prf;
      const prfOutput = prfExt?.results?.first;

      if (prfOutput) {
        credentials = { method: 'passkey-prf', prfOutput };
      } else {
        credentials = { method: 'passkey-gate' };
      }
    } catch (error) {
      console.error('[Full Demo] WebAuthn get failed:', error);
      alert(`Authentication failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
  }

  try {
    console.log('[Full Demo] Adding passphrase enrollment...');
    const result = await kmsUser.addEnrollment(
      'passphrase',
      credentials,
      { passphrase }
    );
    console.log('[Full Demo] Passphrase enrollment added:', result);

    // Show success
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ Passphrase Enrollment Added!</h4>
        <div class="artifact-card">
          <div class="artifact-title">Enrollment ID</div>
          <div class="artifact-data"><code>${result.enrollmentId}</code></div>
        </div>
      </div>
    `;

    await loadAuditLog();

    // Reload setup UI
    const newStatus = await kmsUser.isSetup();
    renderSetupUI(newStatus);
  } catch (error) {
    console.error('[Full Demo] Add enrollment failed:', error);
    alert(`Add enrollment failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Add WebAuthn enrollment to existing setup with PRF/Gate auto-detection
 */
async function addEnrollmentWebAuthn(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  // Fixed demo credentials
  const name = 'Demo User';
  const userId = 'demouser@ats.run';
  const rpId = 'localhost';

  // Get existing credentials to unlock
  const existingMethod = status.methods[0];
  let credentials: any;

  if (existingMethod === 'passphrase') {
    const existingPassphrase = prompt('Enter your CURRENT passphrase to authenticate:');
    if (!existingPassphrase) return;
    credentials = { method: 'passphrase', passphrase: existingPassphrase };
  } else if (existingMethod === 'passkey') {
    alert('Please authenticate with your existing passkey...');
    const appSalt = localStorage.getItem('kms:appSalt');

    try {
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId,
          userVerification: 'required',
          extensions: appSalt ? {
            prf: {
              eval: {
                first: new Uint8Array(appSalt.split(',').map(n => parseInt(n, 10))),
              },
            },
          } : undefined,
        },
      }) as PublicKeyCredential;

      // Check if PRF was used and succeeded
      const prfExt = (assertion as any).getClientExtensionResults().prf;
      const prfOutput = prfExt?.results?.first;

      if (prfOutput) {
        credentials = { method: 'passkey-prf', prfOutput };
      } else {
        credentials = { method: 'passkey-gate' };
      }
    } catch (error) {
      console.error('[Full Demo] Authentication failed:', error);
      alert(`Authentication failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
  }

  try {
    console.log('[Full Demo] Adding WebAuthn enrollment with PRF auto-detection...');

    // Generate app salt for PRF
    const appSalt = crypto.getRandomValues(new Uint8Array(32));

    // Run WebAuthn create ceremony with PRF extension
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: rpId, name: 'ATS KMS V2' },
        user: {
          id: new TextEncoder().encode(userId + '-2'), // Different user ID for second passkey
          name,
          displayName: name,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'required',
        },
        extensions: {
          prf: {
            eval: {
              first: appSalt,
            },
          },
        },
      },
    }) as PublicKeyCredential;

    // Check if PRF succeeded
    const prfExt = (credential as any).getClientExtensionResults().prf;
    const prfOutput = prfExt?.results?.first;

    let result;
    let method;
    let newCredentials: any;

    if (prfOutput) {
      console.log('[Full Demo] PRF available, using passkey-prf');
      method = 'passkey-prf';
      newCredentials = {
        credentialId: credential.rawId,
        prfOutput,
        rpId,
      };
    } else {
      console.log('[Full Demo] PRF not available, using passkey-gate');
      method = 'passkey-gate';
      newCredentials = {
        credentialId: credential.rawId,
        rpId,
      };
    }

    console.log('[Full Demo] About to call addEnrollment with:', { method, credentials, newCredentials });
    result = await kmsUser.addEnrollment(method, credentials, newCredentials);
    console.log('[Full Demo] addEnrollment returned successfully');
    console.log(`[Full Demo] WebAuthn enrollment added (${method}):`, result);
    console.log('[Full Demo] Result type:', typeof result, 'Result value:', result);

    // Store appSalt if PRF was used
    if (prfOutput) {
      localStorage.setItem('kms:appSalt', Array.from(appSalt).toString());
    }

    // Show success
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ WebAuthn Enrollment Added! (${method === 'passkey-prf' ? 'Passkey PRF' : 'Passkey Gate'})</h4>
        <div class="artifact-card">
          <div class="artifact-title">Enrollment ID</div>
          <div class="artifact-data"><code>${result.enrollmentId}</code></div>
        </div>
      </div>
    `;

    await loadAuditLog();

    // Reload setup UI
    const newStatus = await kmsUser.isSetup();
    renderSetupUI(newStatus);
  } catch (error) {
    console.error('[Full Demo] Add enrollment failed:', error);
    alert(`Add enrollment failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Event listeners
resetDemoBtn.addEventListener('click', resetDemo);

// Start
initKMS().then((status) => {
  renderSetupUI(status);
}).catch((error) => {
  console.error('[Full Demo] Failed to initialize:', error);
});
