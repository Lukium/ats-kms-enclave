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
const leaseOperationEl = document.getElementById('lease-operation')!;

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
            <div><strong>User ID:</strong> <code>${entry.userId}</code></div>
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

    // Check setup status (with userId to also fetch leases)
    const status = await kmsUser.isSetup('demouser@ats.run');
    console.log('[Full Demo] Setup status:', status);
    if (status.leases) {
      console.log('[Full Demo] Found', status.leases.length, 'existing leases');
    }

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
 * Display VAPID key information and active leases
 */
async function displayVAPIDKeyInfo(): Promise<void> {
  try {
    console.log('[Full Demo] Fetching VAPID public key...');
    const vapidInfo = await kmsUser.getVAPIDPublicKey('demouser@ats.run');
    console.log('[Full Demo] VAPID public key fetched:', vapidInfo);

    // Fetch active leases
    console.log('[Full Demo] Fetching user leases...');
    const { leases } = await kmsUser.getUserLeases('demouser@ats.run');
    console.log('[Full Demo] User leases fetched:', leases);

    // Filter for active (non-expired) leases
    const now = Date.now();
    const activeLeases = leases.filter((lease) => lease.exp > now);
    const expiredLeases = leases.filter((lease) => lease.exp <= now);

    // Create a container for VAPID key info if it doesn't exist
    let vapidInfoEl = document.getElementById('vapid-key-info');
    if (!vapidInfoEl) {
      vapidInfoEl = document.createElement('div');
      vapidInfoEl.id = 'vapid-key-info';
      vapidInfoEl.style.marginTop = '2rem';
      // Insert before lease operation section
      leaseOperationEl.parentElement?.insertBefore(vapidInfoEl, leaseOperationEl);
    }

    // Build leases HTML
    let leasesHTML = '';
    if (activeLeases.length > 0) {
      leasesHTML = activeLeases
        .map(
          (lease) => `
        <div class="artifact-card">
          <div class="artifact-title">Lease ID</div>
          <div class="artifact-data"><code>${lease.leaseId}</code></div>
          <div class="artifact-title">Expires</div>
          <div class="artifact-data">${new Date(lease.exp).toLocaleString()}</div>
          <div class="artifact-title">Subscriptions</div>
          <div class="artifact-data">${lease.subs.length} endpoint(s)</div>
        </div>
      `
        )
        .join('');
    } else {
      leasesHTML = '<div class="info-message">No active leases. Create a lease below to enable JWT signing.</div>';
    }

    if (expiredLeases.length > 0) {
      leasesHTML += `<div class="info-message" style="color: #888; font-size: 0.8rem;">${expiredLeases.length} expired lease(s) not shown</div>`;
    }

    vapidInfoEl.innerHTML = `
      <div class="vapid-key-card">
        <h4>🔑 VAPID Public Key</h4>
        <div class="artifact-card">
          <div class="artifact-title">Key ID (kid)</div>
          <div class="artifact-data"><code>${vapidInfo.kid}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Public Key</div>
          <div class="artifact-data"><code>${vapidInfo.publicKey}</code></div>
        </div>
        <div class="info-message">
          This is your VAPID public key for Web Push notifications. Share this key with push services to subscribe to notifications.
        </div>
      </div>
      <div class="vapid-key-card" style="margin-top: 1rem;">
        <h4>📋 Active Leases (${activeLeases.length})</h4>
        ${leasesHTML}
      </div>
    `;
  } catch (error) {
    console.error('[Full Demo] Failed to fetch VAPID key or leases:', error);
    // Don't show error UI - it's okay if this fails (e.g., no VAPID key yet)
  }
}

/**
 * Render setup operation UI
 */
async function renderSetupUI(status: { isSetup: boolean; methods: string[] }): Promise<void> {
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

  // Display VAPID key info if setup is complete
  if (hasAnyMethod) {
    await displayVAPIDKeyInfo();
  }

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
    const result = await kmsUser.setupPassphrase('demouser@ats.run', passphrase);
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
    const status = await kmsUser.isSetup('demouser@ats.run');
    renderSetupUI(status);
    renderLeaseUI(status);
  } catch (error) {
    console.error('[Full Demo] Passphrase setup failed:', error);
    alert(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Setup WebAuthn authentication with PRF/Gate auto-detection
 * Checks for existing passkey first to avoid creating duplicates
 */
async function setupWebAuthn(): Promise<void> {
  // Fixed demo credentials
  const name = 'demouser@ats.run';
  const userId = 'demouser@ats.run';
  const rpId = 'localhost';

  try {
    console.log('[Full Demo] Checking for existing passkey...');

    // First, try to authenticate with an existing passkey
    // This will show the user their existing passkeys for this RP
    let credential: PublicKeyCredential | null = null;
    let appSalt: Uint8Array;
    let isExistingPasskey = false;

    try {
      // Try to get existing passkey with conditional UI
      const existingAppSalt = localStorage.getItem('kms:appSalt');
      if (existingAppSalt) {
        appSalt = new Uint8Array(existingAppSalt.split(',').map(n => parseInt(n, 10)));
        console.log('[Full Demo] Found existing appSalt, attempting to authenticate...');

        credential = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: rpId,
            userVerification: 'required',
            extensions: {
              prf: {
                eval: {
                  first: appSalt,
                },
              },
            },
          },
        }) as PublicKeyCredential;

        if (credential) {
          console.log('[Full Demo] Authenticated with existing passkey!');
          isExistingPasskey = true;
        }
      } else {
        // No stored appSalt, will create new passkey
        throw new Error('No existing passkey configuration found');
      }
    } catch (authError) {
      console.log('[Full Demo] No existing passkey found or auth failed, creating new passkey...');
      isExistingPasskey = false;
    }

    // If no existing passkey, create a new one
    if (!isExistingPasskey) {
      // Generate app salt for PRF
      appSalt = crypto.getRandomValues(new Uint8Array(32));

      // Run WebAuthn ceremony with PRF extension
      credential = await navigator.credentials.create({
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

      // Store appSalt for future unlock operations (only for new passkeys)
      localStorage.setItem('kms:appSalt', Array.from(appSalt).toString());
    }

    // Check if PRF extension succeeded
    const prfExt = (credential as any).getClientExtensionResults().prf;
    const prfOutput = prfExt?.results?.first;

    let result;
    let method;

    if (prfOutput) {
      // PRF available - use setupPasskeyPRF
      console.log(`[Full Demo] PRF available, using setupPasskeyPRF (${isExistingPasskey ? 'existing' : 'new'} passkey)`);
      method = `Passkey PRF${isExistingPasskey ? ' (Existing)' : ''}`;
      result = await kmsUser.sendRequest<any>('setupPasskeyPRF', {
        userId: 'demouser@ats.run',
        credentialId: credential.rawId,
        prfOutput: prfOutput,
        rpId,
      });
    } else {
      // PRF not available - use Gate
      console.log(`[Full Demo] PRF not available, using setupPasskeyGate (${isExistingPasskey ? 'existing' : 'new'} passkey)`);
      method = `Passkey Gate${isExistingPasskey ? ' (Existing)' : ''}`;
      result = await kmsUser.sendRequest<any>('setupPasskeyGate', {
        userId: 'demouser@ats.run',
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
    const status = await kmsUser.isSetup('demouser@ats.run');
    renderSetupUI(status);
    renderLeaseUI(status);
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
      'demouser@ats.run',
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
    const newStatus = await kmsUser.isSetup('demouser@ats.run');
    renderSetupUI(newStatus);
  } catch (error) {
    console.error('[Full Demo] Add enrollment failed:', error);
    alert(`Add enrollment failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Get preferred credentials for operations (prefer passkey over passphrase)
 */
async function getPreferredCredentials(status: { methods: string[] }): Promise<any> {
  const hasPasskey = status.methods.includes('passkey');
  const hasPassphrase = status.methods.includes('passphrase');
  const userId = 'demouser@ats.run';

  // Prefer passkey if available
  if (hasPasskey) {
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
        return { method: 'passkey-prf', prfOutput, userId };
      } else {
        return { method: 'passkey-gate', userId };
      }
    } catch (error) {
      console.error('[Full Demo] Passkey authentication failed:', error);
      throw error;
    }
  } else if (hasPassphrase) {
    const passphrase = prompt('Enter your passphrase:');
    if (!passphrase) {
      throw new Error('Passphrase required');
    }
    return { method: 'passphrase', passphrase, userId };
  } else {
    throw new Error('No enrolled authentication methods available');
  }
}

/**
 * Render lease operation UI
 */
function renderLeaseUI(status: { isSetup: boolean; methods: string[] }): void {
  if (!status.isSetup) {
    leaseOperationEl.innerHTML = '<div class="info-message">Please setup authentication first</div>';
    return;
  }

  const html = `
    <div class="lease-section">
      <h3>VAPID Lease Generation</h3>
      <p>Generate a time-limited VAPID authorization lease for push subscriptions.</p>
      <button id="create-lease-btn" class="operation-btn">🎫 Create Lease</button>
    </div>
  `;

  leaseOperationEl.innerHTML = html;

  // Add event listener
  document.getElementById('create-lease-btn')?.addEventListener('click', () => createLease(status));
}

/**
 * Create a VAPID lease
 */
async function createLease(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  try {
    console.log('[Full Demo] Creating VAPID lease...');

    // Get credentials (prefer passkey)
    const credentials = await getPreferredCredentials(status);

    // For demo, use simple subscription parameters
    const userId = 'demouser@ats.run';
    const subs = [
      {
        url: 'https://demo-push-endpoint.example.com/subscription-1',
        aud: 'https://demo-push-endpoint.example.com',
        eid: 'sub-001',
      },
    ];
    const ttlHours = 24; // 24 hour lease

    console.log('[Full Demo] Calling createLease with:', { userId, subs, ttlHours });
    const result = await kmsUser.createLease({
      userId,
      subs,
      ttlHours,
      credentials,
    });
    console.log('[Full Demo] Lease created:', result);

    // Show success with lease details
    const exp = new Date(result.exp);
    leaseOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ VAPID Lease Created!</h4>
        <div class="artifact-card">
          <div class="artifact-title">Lease ID</div>
          <div class="artifact-data"><code>${result.leaseId}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Expiration</div>
          <div class="artifact-data">${exp.toLocaleString()}</div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Quotas</div>
          <div class="artifact-data">
            <div>Signs Remaining: ${result.quotas.signsRemaining}</div>
            <div>Signs Used: ${result.quotas.signsUsed}</div>
          </div>
        </div>
        <button id="create-another-lease-btn" class="operation-btn">🎫 Create Another Lease</button>
      </div>
    `;

    // Add event listener for creating another lease
    document.getElementById('create-another-lease-btn')?.addEventListener('click', () => createLease(status));

    // Refresh VAPID key info to show the new lease
    await displayVAPIDKeyInfo();
    await loadAuditLog();
  } catch (error) {
    console.error('[Full Demo] Lease creation failed:', error);
    alert(`Lease creation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Add WebAuthn enrollment to existing setup with PRF/Gate auto-detection
 */
async function addEnrollmentWebAuthn(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  // Fixed demo credentials
  const name = 'demouser@ats.run';
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
    result = await kmsUser.addEnrollment('demouser@ats.run', method, credentials, newCredentials);
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
    const newStatus = await kmsUser.isSetup('demouser@ats.run');
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
  renderLeaseUI(status);
}).catch((error) => {
  console.error('[Full Demo] Failed to initialize:', error);
});
