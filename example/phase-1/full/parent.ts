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
  const hasPasskeyPRF = status.methods.includes('passkey-prf');
  const hasPasskeyGate = status.methods.includes('passkey-gate');

  let html = '';

  // Show enrolled methods
  if (status.isSetup && status.methods.length > 0) {
    html += '<div class="enrolled-methods">';
    html += '<h4>Enrolled Methods:</h4>';
    html += '<ul>';
    if (hasPassphrase) html += '<li>🔐 Passphrase</li>';
    if (hasPasskeyPRF) html += '<li>🔑 WebAuthn (Passkey PRF)</li>';
    if (hasPasskeyGate) html += '<li>🔑 WebAuthn (Passkey Gate)</li>';
    html += '</ul>';
    html += '</div>';
  }

  // Show available setup options
  const availableOptions: string[] = [];
  if (!hasPassphrase) availableOptions.push('passphrase');
  if (!hasPasskeyPRF && !hasPasskeyGate) availableOptions.push('webauthn');

  if (availableOptions.length > 0) {
    html += '<div class="setup-choice">';
    if (!hasPassphrase) {
      html += '<button id="setup-passphrase-btn" class="operation-btn">🔐 Setup Passphrase</button>';
    }
    if (!hasPasskeyPRF && !hasPasskeyGate) {
      html += '<button id="setup-webauthn-btn" class="operation-btn">🔑 Setup WebAuthn</button>';
    }
    html += '</div>';
  } else {
    html += '<div class="info-message">All authentication methods are enrolled!</div>';
  }

  setupOperationEl.innerHTML = html;

  // Add event listeners for available buttons
  if (!hasPassphrase) {
    document.getElementById('setup-passphrase-btn')?.addEventListener('click', setupPassphrase);
  }
  if (!hasPasskeyPRF && !hasPasskeyGate) {
    document.getElementById('setup-webauthn-btn')?.addEventListener('click', setupWebAuthn);
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
 * Setup WebAuthn authentication (Passkey PRF)
 */
async function setupWebAuthn(): Promise<void> {
  const name = prompt('Enter your name for WebAuthn:');
  if (!name) return;

  const userId = prompt('Enter a user ID (e.g., your email):');
  if (!userId) return;

  try {
    console.log('[Full Demo] Setting up WebAuthn (Passkey PRF)...');
    const result = await kmsUser.setupPasskeyPRF({
      name,
      rpId: window.location.hostname,
      userId,
    });
    console.log('[Full Demo] WebAuthn setup complete:', result);

    // Show success and reload audit log
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ WebAuthn Setup Complete!</h4>
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

// Event listeners
resetDemoBtn.addEventListener('click', resetDemo);

// Start
initKMS().then((status) => {
  renderSetupUI(status);
}).catch((error) => {
  console.error('[Full Demo] Failed to initialize:', error);
});
