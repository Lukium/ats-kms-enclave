/**
 * Full Demo - Parent PWA
 *
 * Runs on http://localhost:5173
 * Embeds KMS iframe from https://kms.ats.run (cross-origin isolated)
 */

import { KMSUser, type StatusResult } from '../../src/v2/kms-user';
import type { AuditEntryV2 } from '../../src/v2/types';
import {
  registerServiceWorker,
  subscribeToPush,
  unsubscribeFromPush,
  convertPushSubscriptionToStored,
  isPushSupported,
  base64UrlToUint8Array,
} from './push-utils.js';

console.log('[Full Demo] Parent PWA initializing...');

// KMS Configuration
const KMS_ORIGIN = 'https://kms.ats.run';

// Initialize KMS User
const kmsUser = new KMSUser({
  kmsOrigin: KMS_ORIGIN,
});

// DOM Elements
const auditLogEl = document.getElementById('audit-log')!;
const resetDemoBtn = document.getElementById('reset-demo-btn')! as HTMLButtonElement;
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

    // Expose kmsUser globally for Playwright tests
    (window as any).kmsUser = kmsUser;

    // Setup postMessage listener for setup completion callbacks
    window.addEventListener('message', handleSetupComplete);

    // Register service worker for push notifications (Phase B)
    if (isPushSupported()) {
      try {
        await registerServiceWorker();
        console.log('[Full Demo] Service worker registered for push notifications');
      } catch (error) {
        console.warn('[Full Demo] Service worker registration failed (push notifications will not work):', error);
      }
    } else {
      console.warn('[Full Demo] Push notifications not supported in this browser');
    }

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
 * Handle setup completion message from KMS setup window
 */
async function handleSetupComplete(event: MessageEvent): Promise<void> {
  // Validate origin (should be from KMS)
  if (event.origin !== KMS_ORIGIN) {
    console.warn('[Full Demo] Ignored message from invalid origin:', event.origin);
    return;
  }

  // Check message type
  if (event.data?.type === 'kms:setup-complete') {
    console.log('[Full Demo] Setup complete notification received:', event.data);

    // Show success message
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ WebAuthn Setup Complete! (${event.data.method})</h4>
        <div class="artifact-card">
          <div class="artifact-title">Enrollment ID</div>
          <div class="artifact-data"><code>${event.data.result.enrollmentId}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">VAPID Key ID</div>
          <div class="artifact-data"><code>${event.data.result.vapidKid}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">VAPID Public Key</div>
          <div class="artifact-data"><code>${event.data.result.vapidPublicKey}</code></div>
        </div>
      </div>
    `;

    // Reload audit log
    await loadAuditLog();

    // Reload setup UI to reflect new enrollment
    const status = await kmsUser.isSetup('demouser@ats.run');
    renderSetupUI(status);
    renderLeaseUI(status);

    console.log('[Full Demo] UI updated after setup completion');
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

    // Check all leases (both active and expired) for display
    const now = Date.now();
    const allLeases = leases.map((lease) => {
      const isExpired = lease.exp <= now;
      const kidMatches = lease.kid === vapidInfo.kid;
      const isValid = !isExpired && kidMatches;
      return { ...lease, isExpired, kidMatches, isValid };
    });

    // Separate active and expired
    const activeLeases = allLeases.filter((lease) => !lease.isExpired);
    const expiredCount = allLeases.filter((lease) => lease.isExpired).length;

    // Use the dedicated vapid-info-section container
    const vapidInfoEl = document.getElementById('vapid-info-section');
    if (!vapidInfoEl) {
      console.error('[Full Demo] vapid-info-section element not found');
      return;
    }

    // Build leases HTML with validation fields
    let leasesHTML = '';
    if (activeLeases.length > 0) {
      leasesHTML = activeLeases
        .map((lease) => {
          // Style based on validity
          const validStyle = lease.isValid
            ? 'color: #28a745; font-weight: bold;'
            : 'color: #dc3545; font-weight: bold;';
          const kidMatchStyle = lease.kidMatches
            ? 'color: #28a745;'
            : 'color: #dc3545;';

          return `
        <div class="artifact-card" style="${lease.isValid ? '' : 'border-left: 3px solid #dc3545;'}">
          <div class="artifact-title">Lease ID</div>
          <div class="artifact-data"><code>${lease.leaseId}</code></div>
          <div class="artifact-title">Valid</div>
          <div class="artifact-data" style="${validStyle}">${lease.isValid ? '✅ Yes' : '❌ No'}</div>
          <div class="artifact-title">Key ID Matches</div>
          <div class="artifact-data" style="${kidMatchStyle}">${lease.kidMatches ? '✅ Yes' : '❌ No (stale)'}</div>
          <div class="artifact-title">VAPID Key ID</div>
          <div class="artifact-data"><code style="font-size: 0.75rem;">${lease.kid}</code></div>
          <div class="artifact-title">Expires</div>
          <div class="artifact-data">${new Date(lease.exp).toLocaleString()}</div>
          <div class="artifact-title">User ID</div>
          <div class="artifact-data">${lease.userId}</div>
        </div>
      `;
        })
        .join('');
    } else {
      leasesHTML = '<div class="info-message">No active leases. Create a lease below to enable JWT signing.</div>';
    }

    if (expiredCount > 0) {
      leasesHTML += `<div class="info-message" style="color: #888; font-size: 0.8rem;">${expiredCount} expired lease(s) not shown</div>`;
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

    // Add event listener for regenerate button
    document.getElementById('regenerate-vapid-btn')?.addEventListener('click', regenerateVAPIDKey);
  } catch (error) {
    console.error('[Full Demo] Failed to fetch VAPID key or leases:', error);

    // Show a placeholder message in the artifacts section
    const vapidInfoEl = document.getElementById('vapid-info-section');
    if (vapidInfoEl) {
      vapidInfoEl.innerHTML = `
        <div class="info-message" style="color: #888;">
          No VAPID key found. Set up authentication and the VAPID key will be generated automatically.
        </div>
      `;
    }
  }
}

/**
 * Regenerate VAPID keypair (invalidates all active leases)
 * Uses iframe authentication - credentials collected in KMS iframe
 */
async function regenerateVAPIDKey(): Promise<void> {
  const confirmed = confirm(
    '⚠️ Warning: Regenerating the VAPID key will:\n\n' +
      '• Delete the current VAPID key\n' +
      '• Invalidate ALL active leases\n' +
      '• Generate a new VAPID keypair\n\n' +
      'Are you sure you want to continue?'
  );

  if (!confirmed) return;

  try {
    console.log('[Full Demo] Regenerating VAPID key...');

    // Call regenerateVAPID - iframe will automatically show modal to collect credentials
    const userId = 'demouser@ats.run';
    const result = await kmsUser.regenerateVAPID({ userId });

    console.log('[Full Demo] VAPID key regenerated:', result);

    // Show success message and refresh VAPID info
    alert(
      '✅ VAPID key regenerated successfully!\n\n' +
        `New Key ID: ${result.kid.substring(0, 16)}...\n\n` +
        'All previous leases are now invalid.'
    );

    // Refresh VAPID info display
    await displayVAPIDKeyInfo();

    // Reload audit log to show the regenerate-vapid operation
    await loadAuditLog();
  } catch (error: any) {
    console.error('[Full Demo] Failed to regenerate VAPID key:', error);
    alert(`❌ Failed to regenerate VAPID key:\n\n${error.message || error}`);
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
  // Both initial setup and add enrollment use the same flow now
  // The KMS client.ts handles multi-enrollment detection automatically
  if (canAddPassphrase) {
    const btnId = hasAnyMethod ? 'add-passphrase-btn' : 'setup-passphrase-btn';
    document.getElementById(btnId)?.addEventListener('click', setupPassphrase);
  }
  if (canAddWebAuthn) {
    const btnId = hasAnyMethod ? 'add-webauthn-btn' : 'setup-webauthn-btn';
    document.getElementById(btnId)?.addEventListener('click', setupWebAuthn);
  }
}

/**
 * Setup passphrase authentication using stateless popup.
 *
 * This function uses the new stateless popup flow:
 * 1. Generate ephemeral transport keys in iframe
 * 2. Open popup with transport parameters in URL
 * 3. Popup collects credentials and encrypts with transport key
 * 4. Parent receives encrypted credentials (blind proxy)
 * 5. Parent forwards encrypted credentials to iframe for decryption and storage
 */
async function setupPassphrase(): Promise<void> {
  console.log('[Full Demo] Starting passphrase setup with stateless popup...');

  try {
    // Step 1: Get transport parameters from iframe KMS
    const transportParams = await kmsUser.generateSetupTransportKey();
    console.log('[Full Demo] Got transport parameters:', {
      keyId: transportParams.keyId,
      publicKey: transportParams.publicKey.slice(0, 20) + '...'
    });

    // Step 2: Open popup with transport parameters
    const setupURL = new URL(KMS_ORIGIN + '/');
    setupURL.searchParams.set('mode', 'setup');
    setupURL.searchParams.set('transportKey', transportParams.publicKey);
    setupURL.searchParams.set('keyId', transportParams.keyId);
    setupURL.searchParams.set('appSalt', transportParams.appSalt);
    setupURL.searchParams.set('hkdfSalt', transportParams.hkdfSalt);
    setupURL.searchParams.set('parentOrigin', window.location.origin);

    console.log('[Full Demo] Opening popup with URL:', setupURL.toString());
    console.log('[Full Demo] URL length:', setupURL.toString().length);

    const setupWindow = window.open(
      setupURL.toString(),
      'kms-setup',
      'width=600,height=700,menubar=no,toolbar=no,location=no,status=no,opener'
    );

    if (!setupWindow) {
      alert('Failed to open setup window. Please allow popups for this site.');
      return;
    }

    console.log('[Full Demo] Popup opened, waiting for credentials...');

    // Step 3: Wait for encrypted credentials from popup
    const credentials = await new Promise<{
      method: string;
      transportKeyId: string;
      ephemeralPublicKey: string;
      iv: string;
      encryptedCredentials: string;
      userId: string;
    }>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Setup timeout (no credentials received)'));
      }, 5 * 60 * 1000); // 5 minute timeout

      const handler = (event: MessageEvent): void => {
        if (event.origin !== KMS_ORIGIN) return;
        if (event.data?.type === 'kms:setup-credentials') {
          clearTimeout(timeout);
          window.removeEventListener('message', handler);
          resolve(event.data);
        }
      };

      window.addEventListener('message', handler);
    });

    console.log('[Full Demo] Received encrypted credentials, importing to iframe...');

    // Step 4: Forward encrypted credentials to iframe KMS
    const result = await kmsUser.setupWithEncryptedCredentials({
      method: credentials.method as 'passphrase' | 'passkey-prf' | 'passkey-gate',
      transportKeyId: credentials.transportKeyId,
      ephemeralPublicKey: credentials.ephemeralPublicKey,
      iv: credentials.iv,
      encryptedCredentials: credentials.encryptedCredentials,
      userId: credentials.userId
    });

    console.log('[Full Demo] Setup completed successfully:', result);

    // Step 5: Show success message
    setupOperationEl.innerHTML = `
      <div class="success-message">
        <h4>✅ Setup Complete! (${credentials.method})</h4>
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

    // Step 6: Reload audit log
    await loadAuditLog();

    // Step 7: Reload setup UI to reflect new enrollment
    const status = await kmsUser.isSetup('demouser@ats.run');
    renderSetupUI(status);
    renderLeaseUI(status);

    console.log('[Full Demo] UI updated after setup completion');

  } catch (error) {
    console.error('[Full Demo] Setup failed:', error);
    alert(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Setup WebAuthn authentication using stateless popup.
 *
 * This function uses the same stateless popup flow as setupPassphrase().
 * The popup will detect WebAuthn and handle PRF detection automatically.
 */
async function setupWebAuthn(): Promise<void> {
  // Same implementation as setupPassphrase - popup handles method detection
  await setupPassphrase();
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
    <div class="operation-section">
      <h3>📬 Push Notification Operations</h3>
      <p>Manage push subscriptions and test notifications.</p>

      <h4 style="margin-top: 1.5rem; font-size: 1rem; color: #888;">Step 1: Subscribe to Push</h4>
      <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
        <button id="subscribe-push-btn" class="operation-btn" style="background-color: #007bff;">
          🔔 Subscribe to Push
        </button>
        <button id="unsubscribe-push-btn" class="operation-btn" style="background-color: #6c757d;">
          🔕 Unsubscribe from Push
        </button>
      </div>
      <div id="push-subscription-status" class="info-message" style="margin-top: 0.5rem;"></div>
    </div>

    <hr style="margin: 1.5rem 0; border: none; border-top: 2px solid #e2e8f0;">

    <div class="operation-section">
      <h3>🎫 VAPID Lease Operations</h3>
      <p>Generate time-limited VAPID authorization leases.</p>

      <h4 style="margin-top: 1.5rem; font-size: 1rem; color: #888;">Step 2: Create Lease & Issue JWTs</h4>

      <div id="lease-verification-results"></div>

      <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap;">
        <button id="create-lease-extendable-btn" class="operation-btn" style="background-color: #28a745;">🎫 Create Extendable Lease</button>
        <button id="create-lease-non-extendable-btn" class="operation-btn" style="background-color: #6c757d;">🎫 Create Non-Extendable Lease</button>
        <button id="extend-all-leases-btn" class="operation-btn" style="background-color: #007bff;">🔄 Extend All Leases</button>
        <button id="extend-all-leases-with-auth-btn" class="operation-btn" style="background-color: #17a2b8;">🔐 Extend Leases with Auth</button>
        <button id="verify-leases-btn" class="operation-btn">🔍 Verify All Leases</button>
        <button id="clear-invalid-leases-btn" class="operation-btn" style="background-color: #dc3545;">🗑️ Clear Invalid Leases</button>
      </div>

      <div style="margin-top: 1rem; display: flex; gap: 0.5rem; align-items: center;">
        <label for="jwt-count-input" style="font-size: 0.9rem;">JWTs to issue:</label>
        <input
          type="number"
          id="jwt-count-input"
          min="1"
          max="10"
          value="1"
          style="width: 80px; padding: 0.5rem; border: 1px solid #333; background: #1a1a1a; color: #fff; border-radius: 4px;"
        />
        <button id="issue-jwts-btn" class="operation-btn">🎟️ Issue JWTs from Lease</button>
      </div>
    </div>

    <hr style="margin: 1.5rem 0; border: none; border-top: 2px solid #e2e8f0;">

    <div class="operation-section">
      <h3>📬 Test Push Notification</h3>
      <p>Send a test notification using the issued JWT.</p>

      <h4 style="margin-top: 1.5rem; font-size: 1rem; color: #888;">Step 3: Send Test Notification</h4>
      <button id="send-test-push-btn" class="operation-btn" style="background-color: #28a745; margin-top: 0.5rem;">
        📬 Send Test Push Notification
      </button>
      <div class="info-message" style="color: #28a745; margin-top: 0.5rem;">
        💡 Validates JWT and sends a test notification to your browser
      </div>
    </div>

    <hr style="margin: 1.5rem 0; border: none; border-top: 2px solid #e2e8f0;">

    <div class="operation-section">
      <h3>⚙️ VAPID Key Management</h3>
      <button id="regenerate-vapid-btn" class="operation-btn" style="background-color: #dc3545; margin-top: 0.5rem;">
        🔄 Regenerate VAPID Key
      </button>
      <div class="info-message" style="color: #dc3545; margin-top: 0.5rem;">
        ⚠️ Warning: Regenerating will invalidate all active leases!
      </div>
    </div>
  `;

  leaseOperationEl.innerHTML = html;

  // Update push subscription status
  updatePushSubscriptionStatus();

  // Add event listeners
  document.getElementById('subscribe-push-btn')?.addEventListener('click', subscribeToPushNotifications);
  document.getElementById('unsubscribe-push-btn')?.addEventListener('click', unsubscribeFromPushNotifications);
  document.getElementById('create-lease-extendable-btn')?.addEventListener('click', () => createLease(status, true));
  document.getElementById('create-lease-non-extendable-btn')?.addEventListener('click', () => createLease(status, false));
  document.getElementById('extend-all-leases-btn')?.addEventListener('click', () => extendAllLeases());
  document.getElementById('extend-all-leases-with-auth-btn')?.addEventListener('click', () => extendAllLeasesWithAuth());
  document.getElementById('verify-leases-btn')?.addEventListener('click', () => verifyAllLeases());
  document.getElementById('clear-invalid-leases-btn')?.addEventListener('click', () => clearInvalidLeases());
  document.getElementById('issue-jwts-btn')?.addEventListener('click', () => issueJWTsFromLease());
  document.getElementById('send-test-push-btn')?.addEventListener('click', sendTestPush);
  document.getElementById('regenerate-vapid-btn')?.addEventListener('click', regenerateVAPIDKey);
}

/**
 * Update the push subscription status display
 */
async function updatePushSubscriptionStatus(): Promise<void> {
  const statusEl = document.getElementById('push-subscription-status');
  if (!statusEl) return;

  try {
    const { subscription } = await kmsUser.getPushSubscription();
    if (subscription) {
      statusEl.innerHTML = `
        <div style="color: #28a745;">
          ✅ Subscribed to push notifications
          <br><strong>Endpoint ID:</strong> ${subscription.eid}
          <br><strong>Created:</strong> ${new Date(subscription.createdAt).toLocaleString()}
        </div>
      `;
    } else {
      statusEl.innerHTML = '<div style="color: #888;">Not subscribed to push notifications</div>';
    }
  } catch (error) {
    console.error('[Full Demo] Failed to get push subscription status:', error);
    statusEl.innerHTML = '<div style="color: #888;">Unable to check subscription status</div>';
  }
}

/**
 * Subscribe to push notifications (Phase B)
 */
async function subscribeToPushNotifications(): Promise<void> {
  try {
    console.log('[Full Demo] Subscribing to push notifications...');

    // Get VAPID public key
    const vapidInfo = await kmsUser.getVAPIDPublicKey('demouser@ats.run');
    if (!vapidInfo) {
      throw new Error('No VAPID key exists. Please set up passphrase first.');
    }

    // Check if service worker is ready
    if (!('serviceWorker' in navigator)) {
      throw new Error('Service workers are not supported in this browser');
    }

    // Get service worker registration
    const registration = await navigator.serviceWorker.ready;

    // Create real push subscription via browser API
    console.log('[Full Demo] Creating push subscription...');
    const rawSub = await subscribeToPush(
      registration,
      base64UrlToUint8Array(vapidInfo.publicKey)
    );
    console.log('[Full Demo] Push subscription created:', rawSub.endpoint);

    // Convert to stored format
    const eid = 'demo-device'; // Could prompt user for device name
    const storedSub = convertPushSubscriptionToStored(rawSub, eid);

    // Store subscription in KMS (stored with VAPID key)
    console.log('[Full Demo] Storing push subscription in KMS...');
    console.log('[Full Demo] Subscription data:', storedSub);
    const result = await kmsUser.setPushSubscription(storedSub);
    console.log('[Full Demo] setPushSubscription result:', result);
    console.log('[Full Demo] ✅ Push subscription stored with VAPID key');

    // Update status display
    await updatePushSubscriptionStatus();
    await loadAuditLog();

    alert('✅ Push subscription created successfully!\n\nYou can now create a lease and send test push notifications.');
  } catch (error) {
    console.error('[Full Demo] Push subscription failed:', error);
    alert(`❌ Push subscription failed:\n\n${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Unsubscribe from push notifications (Phase B)
 */
async function unsubscribeFromPushNotifications(): Promise<void> {
  try {
    console.log('[Full Demo] Unsubscribing from push notifications...');

    // Get service worker registration
    const registration = await navigator.serviceWorker.ready;

    // Unsubscribe from browser push
    await unsubscribeFromPush(registration);

    // Remove subscription from KMS
    console.log('[Full Demo] Removing push subscription from KMS...');
    await kmsUser.removePushSubscription();
    console.log('[Full Demo] ✅ Push subscription removed from KMS');

    // Update status display
    await updatePushSubscriptionStatus();
    await loadAuditLog();

    alert('✅ Push subscription removed successfully!');
  } catch (error) {
    console.error('[Full Demo] Push unsubscribe failed:', error);
    alert(`❌ Push unsubscribe failed:\n\n${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Create a VAPID lease (Phase B: requires existing push subscription)
 */
async function createLease(_status: { isSetup: boolean; methods: string[] }, autoExtend: boolean): Promise<void> {
  try {
    console.log(`[Full Demo] Creating VAPID lease (autoExtend: ${autoExtend})...`);

    // Check if push subscription exists (required for lease creation in Phase 1)
    const { subscription } = await kmsUser.getPushSubscription();
    if (!subscription) {
      alert('No push subscription found. Please subscribe to push notifications first.');
      return;
    }

    // Create lease with subscription info
    const userId = 'demouser@ats.run';
    const ttlHours = 720; // 30 days (720 hours) lease

    // Build subs array from push subscription
    const pushServiceUrl = new URL(subscription.endpoint);
    const subs = [{
      url: subscription.endpoint,
      aud: pushServiceUrl.origin,
      eid: subscription.eid,
    }];

    console.log('[Full Demo] Calling createLease with:', { userId, ttlHours, subs });
    const result = await kmsUser.createLease({
      userId,
      subs,
      ttlHours,
    });
    console.log('[Full Demo] Lease created:', result);

    // Show success with lease details (above the operation section)
    const exp = new Date(result.exp);
    const leaseResultEl = document.getElementById('lease-result');
    if (leaseResultEl) {
      leaseResultEl.innerHTML = `
        <div class="success-message" style="margin-bottom: 1.5rem;">
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
              <div>Tokens/Hour: ${result.quotas.tokensPerHour}</div>
              <div>Sends/Minute: ${result.quotas.sendsPerMinute}</div>
              <div>Burst Sends: ${result.quotas.burstSends}</div>
              <div>Sends/Min/Endpoint: ${result.quotas.sendsPerMinutePerEid}</div>
            </div>
          </div>
          <button id="dismiss-lease-result-btn" class="operation-btn">✖ Dismiss</button>
        </div>
      `;

      // Add dismiss button listener
      document.getElementById('dismiss-lease-result-btn')?.addEventListener('click', () => {
        leaseResultEl.innerHTML = '';
      });
    }

    // Refresh VAPID key info to show the new lease
    await displayVAPIDKeyInfo();
    await loadAuditLog();
  } catch (error) {
    console.error('[Full Demo] Lease creation failed:', error);
    alert(`Lease creation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Extend all extendable leases
 */
async function extendAllLeases(): Promise<void> {
  try {
    console.log('[Full Demo] Extending all leases...');

    // Get all leases for the user
    const userId = 'demouser@ats.run';
    const { leases } = await kmsUser.getUserLeases(userId);

    const resultsContainer = document.getElementById('lease-result');
    if (!resultsContainer) return;

    if (leases.length === 0) {
      resultsContainer.innerHTML = `
        <div class="info-message" style="margin-bottom: 1.5rem;">
          <h4>No Leases Found</h4>
          <p>Create a lease first to test extension.</p>
          <button id="dismiss-results-btn" class="operation-btn">✖ Dismiss</button>
        </div>
      `;
      document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
        resultsContainer.innerHTML = '';
      });
      return;
    }

    console.log(`[Full Demo] Found ${leases.length} lease(s), attempting to extend...`);

    // Get current VAPID key to filter leases
    const vapidInfo = await kmsUser.getVAPIDPublicKey(userId);
    if (!vapidInfo) {
      alert('No VAPID key found. Please set up passphrase first.');
      return;
    }

    // Filter for non-expired leases with matching kid
    const now = Date.now();
    const activeLeases = leases.filter(
      (lease) => lease.exp > now && lease.kid === vapidInfo.kid
    );

    if (activeLeases.length === 0) {
      resultsContainer.innerHTML = `
        <div class="info-message" style="margin-bottom: 1.5rem;">
          <h4>No Active Leases Found</h4>
          <p>All leases are either expired or for a different VAPID key.</p>
          <button id="dismiss-results-btn" class="operation-btn">✖ Dismiss</button>
        </div>
      `;
      document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
        resultsContainer.innerHTML = '';
      });
      return;
    }

    // Extend all active leases in batch (worker will skip non-extendable leases)
    const leaseIds = activeLeases.map((l) => l.leaseId);
    const batchResult = await kmsUser.extendLeases(leaseIds, userId);

    console.log(`[Full Demo] Batch result: ${batchResult.extended} extended, ${batchResult.skipped} skipped`);

    // Map results back to leases for display
    const results = batchResult.results.map((itemResult) => {
      const lease = activeLeases.find((l) => l.leaseId === itemResult.leaseId);
      return {
        lease: lease!,
        result: itemResult.result,
        success: itemResult.status === 'extended',
        error: itemResult.reason || null,
      };
    });

    // Display results
    const resultsHtml = results
      .map(
        ({ lease, result, success, error }) => `
      <div class="artifact-card ${success ? 'valid' : 'invalid'}">
        <div class="artifact-title">
          ${success ? '✅' : '❌'} Lease Extension
        </div>
        <div class="artifact-data">
          <div><strong>Lease ID:</strong> <code style="word-break: break-all;">${lease.leaseId}</code></div>
          <div><strong>Status:</strong> ${success ? 'Extended' : 'Failed'}</div>
          ${success && result ? `
            <div><strong>New Expiration:</strong> ${new Date(result.exp).toLocaleString()}</div>
            <div><strong>Auto-Extend:</strong> ${result.autoExtend ? '✅ Enabled' : '❌ Disabled'}</div>
          ` : ''}
          ${error ? `<div style="color: #dc3545;"><strong>Error:</strong> ${error}</div>` : ''}
        </div>
      </div>
    `
      )
      .join('');

    const successCount = results.filter((r) => r.success).length;
    const failCount = results.length - successCount;

    resultsContainer.innerHTML = `
      <div class="${successCount === results.length ? 'success' : 'warning'}-message" style="margin-bottom: 1.5rem;">
        <h4>Extend All Leases Results</h4>
        <p>Processed ${results.length} lease(s): ${successCount} extended, ${failCount} failed</p>
        ${resultsHtml}
        <button id="dismiss-results-btn" class="operation-btn">✖ Dismiss</button>
      </div>
    `;

    // Add event listener
    document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
      resultsContainer.innerHTML = '';
    });

    // Refresh displays
    await displayVAPIDKeyInfo();
    await loadAuditLog();
  } catch (error) {
    console.error('[Full Demo] Extend all leases failed:', error);
    alert(`Extend all leases failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Extend all leases with authentication (requests auth for non-extendable leases)
 */
async function extendAllLeasesWithAuth(): Promise<void> {
  try {
    console.log('[Full Demo] Extending all leases with auth...');

    // Get all leases for the user
    const userId = 'demouser@ats.run';
    const { leases } = await kmsUser.getUserLeases(userId);

    const resultsContainer = document.getElementById('lease-result');
    if (!resultsContainer) return;

    if (leases.length === 0) {
      resultsContainer.innerHTML = `
        <div class="info-message" style="margin-bottom: 1.5rem;">
          <h4>No Leases Found</h4>
          <p>Create a lease first to test extension.</p>
          <button id="dismiss-results-btn" class="operation-btn">✖ Dismiss</button>
        </div>
      `;
      document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
        resultsContainer.innerHTML = '';
      });
      return;
    }

    console.log(`[Full Demo] Found ${leases.length} lease(s), attempting to extend with auth...`);

    // Get current VAPID key to filter leases
    const vapidInfo = await kmsUser.getVAPIDPublicKey(userId);
    if (!vapidInfo) {
      alert('No VAPID key found. Please set up passphrase first.');
      return;
    }

    // Filter for non-expired leases with matching kid
    const now = Date.now();
    const activeLeases = leases.filter(
      (lease) => lease.exp > now && lease.kid === vapidInfo.kid
    );

    if (activeLeases.length === 0) {
      resultsContainer.innerHTML = `
        <div class="info-message" style="margin-bottom: 1.5rem;">
          <h4>No Active Leases Found</h4>
          <p>All leases are either expired or for a different VAPID key.</p>
          <button id="dismiss-results-btn" class="operation-btn">✖ Dismiss</button>
        </div>
      `;
      document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
        resultsContainer.innerHTML = '';
      });
      return;
    }

    // Extend all active leases in batch with authentication (single auth for all non-extendable leases)
    const leaseIds = activeLeases.map((l) => l.leaseId);
    const batchResult = await kmsUser.extendLeases(leaseIds, userId, { requestAuth: true });

    console.log(`[Full Demo] Batch result with auth: ${batchResult.extended} extended, ${batchResult.skipped} skipped`);

    // Map results back to leases for display
    const results = batchResult.results.map((itemResult) => {
      const lease = activeLeases.find((l) => l.leaseId === itemResult.leaseId);
      return {
        lease: lease!,
        result: itemResult.result,
        success: itemResult.status === 'extended',
        error: itemResult.reason || null,
      };
    });

    // Display results
    const resultsHtml = results
      .map(
        ({ lease, result, success, error }) => `
      <div class="artifact-card ${success ? 'valid' : 'invalid'}">
        <div class="artifact-title">
          ${success ? '✅' : '❌'} Lease ${lease.leaseId.substring(0, 8)}...
          ${lease.autoExtend === false ? '(Non-Extendable)' : '(Auto-Extendable)'}
        </div>
        <div class="artifact-content">
          ${
            success && result
              ? `
            <div><strong>New Expiration:</strong> ${new Date(result.exp).toLocaleString()}</div>
            <div><strong>Issued At:</strong> ${new Date(result.iat).toLocaleString()}</div>
            <div><strong>Auto-Extend:</strong> ${result.autoExtend ? 'Yes' : 'No'}</div>
          `
              : `<div><strong>Error:</strong> ${error}</div>`
          }
        </div>
      </div>
    `
      )
      .join('');

    resultsContainer.innerHTML = `
      <div class="info-message" style="margin-bottom: 1.5rem;">
        <h4>Extend All Leases Results (With Auth)</h4>
        <p>Extended ${results.filter((r) => r.success).length} of ${results.length} lease(s)</p>
        <p style="font-size: 0.85rem; color: #666;">Non-extendable leases required authentication</p>
        <button id="dismiss-results-btn" class="operation-btn">✖ Dismiss</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 0.5rem;">
        ${resultsHtml}
      </div>
    `;

    document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
      resultsContainer.innerHTML = '';
    });
  } catch (error) {
    console.error('[Full Demo] Extend all leases with auth failed:', error);
    alert(`Extend all leases with auth failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Issue JWTs from an existing lease
 */
async function issueJWTsFromLease(): Promise<void> {
  try {
    console.log('[Full Demo] Issuing JWTs from lease...');

    // Get JWT count from input field
    const countInput = document.getElementById('jwt-count-input') as HTMLInputElement;
    if (!countInput) {
      console.error('[Full Demo] JWT count input not found');
      return;
    }

    const count = parseInt(countInput.value, 10);

    // Validate count (1-10)
    if (isNaN(count) || count < 1 || count > 10) {
      alert('Please enter a valid number between 1 and 10');
      return;
    }

    // Get all leases for the user
    const userId = 'demouser@ats.run';
    const { leases } = await kmsUser.getUserLeases(userId);

    // Get current VAPID key to filter leases by matching kid
    const vapidInfo = await kmsUser.getVAPIDPublicKey(userId);
    if (!vapidInfo) {
      alert('No VAPID key found. Please set up passphrase first.');
      return;
    }

    // Filter for active (non-expired) leases with matching kid
    const now = Date.now();
    const activeLeases = leases.filter(
      (lease) => lease.exp > now && lease.kid === vapidInfo.kid
    );

    if (activeLeases.length === 0) {
      alert('No active leases found for current VAPID key. Please create a new lease.');
      return;
    }

    // Use the first active lease (in production, we'd let user select)
    const lease = activeLeases[0]!;
    console.log(`[Full Demo] Using lease: ${lease.leaseId} (kid: ${lease.kid})`);

    // Get push subscription for endpoint info display
    const { subscription } = await kmsUser.getPushSubscription();
    if (!subscription) {
      alert('No push subscription found. Please subscribe to push notifications first.');
      return;
    }

    // Issue JWTs with endpoint info from subscription
    const pushServiceUrl = new URL(subscription.endpoint);
    console.log(`[Full Demo] Issuing ${count} JWT(s)...`);
    const startTime = performance.now();
    const jwts = await kmsUser.issueVAPIDJWTs({
      leaseId: lease.leaseId,
      endpoint: {
        url: subscription.endpoint,
        aud: pushServiceUrl.origin,
        eid: subscription.eid,
      },
      count,
    });
    const duration = performance.now() - startTime;
    console.log(`[Full Demo] ${count} JWT(s) issued successfully in ${duration.toFixed(2)}ms`);

    // Display results in the lease-result area (same as lease creation)
    const resultsContainer = document.getElementById('lease-result');
    if (!resultsContainer) return;

    const jwtListHTML = jwts
      .map(
        (jwt, idx) => `
      <div class="artifact-card">
        <div class="artifact-title">JWT ${idx + 1}</div>
        <div class="artifact-data"><code style="font-size: 0.8rem; word-break: break-all;">${jwt.jwt}</code></div>
        <div class="artifact-title">Expires</div>
        <div class="artifact-data">${new Date(jwt.exp! * 1000).toLocaleString()}</div>
        <div class="artifact-title">JTI</div>
        <div class="artifact-data"><code>${jwt.jti}</code></div>
      </div>
    `
      )
      .join('');

    resultsContainer.innerHTML = `
      <div class="success-message" style="margin-bottom: 1.5rem;">
        <h4>✅ ${count} JWT(s) Issued Successfully!</h4>
        <div class="artifact-card">
          <div class="artifact-title">Lease ID</div>
          <div class="artifact-data"><code>${lease.leaseId}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Endpoint ID</div>
          <div class="artifact-data"><code>${subscription.eid}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Push Endpoint</div>
          <div class="artifact-data" style="word-break: break-all;"><code style="font-size: 0.75rem;">${subscription.endpoint}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Generation Time</div>
          <div class="artifact-data">${duration.toFixed(2)}ms</div>
        </div>
        ${jwtListHTML}
        <button id="dismiss-jwt-results-btn" class="operation-btn">✖ Dismiss</button>
      </div>
    `;

    // Add dismiss button listener
    document.getElementById('dismiss-jwt-results-btn')?.addEventListener('click', () => {
      resultsContainer.innerHTML = '';
    });

    // Refresh audit log to show JWT issuance entries
    await loadAuditLog();
  } catch (error) {
    console.error('[Full Demo] JWT issuance failed:', error);
    alert(`JWT issuance failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Validate a VAPID JWT (Phase C: simulates relay server validation)
 *
 * Validates:
 * - JWT format (3 parts: header.payload.signature)
 * - Algorithm (must be ES256)
 * - Claims (exp, aud, sub)
 * - Signature (ECDSA-P256 verification against VAPID public key)
 */
async function validateVAPIDJWT(
  jwt: string,
  expectedAudience: string
): Promise<{
  valid: boolean;
  reason?: string;
  claims?: Record<string, unknown>;
}> {
  try {
    // Split JWT into parts
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'Invalid JWT format (expected 3 parts)' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode and validate header
    const header = JSON.parse(atob(headerB64!.replace(/-/g, '+').replace(/_/g, '/')));
    if (header.alg !== 'ES256') {
      return { valid: false, reason: `Unsupported algorithm: ${header.alg}` };
    }

    // Decode and validate payload
    const payload = JSON.parse(atob(payloadB64!.replace(/-/g, '+').replace(/_/g, '/')));
    const now = Math.floor(Date.now() / 1000);

    // Check expiration
    if (!payload.exp || typeof payload.exp !== 'number') {
      return { valid: false, reason: 'Missing exp claim' };
    }
    if (payload.exp < now) {
      return { valid: false, reason: 'JWT expired' };
    }

    // Check audience
    if (!payload.aud || payload.aud !== expectedAudience) {
      return {
        valid: false,
        reason: `Invalid audience (expected ${expectedAudience}, got ${payload.aud})`,
      };
    }

    // Check subject
    if (!payload.sub || typeof payload.sub !== 'string') {
      return { valid: false, reason: 'Missing sub claim' };
    }

    // Get VAPID public key for signature verification
    const vapidInfo = await kmsUser.getVAPIDPublicKey('demouser@ats.run');
    if (!vapidInfo) {
      return { valid: false, reason: 'No VAPID key available' };
    }

    // Import public key
    const publicKeyBytes = base64UrlToUint8Array(vapidInfo.publicKey);
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );

    // Verify signature (DER-encoded from KMS)
    const signatureBytes = base64UrlToUint8Array(signatureB64!);
    const dataToVerify = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signatureBytes as BufferSource,
      dataToVerify
    );

    if (!valid) {
      return { valid: false, reason: 'Signature verification failed' };
    }

    return { valid: true, claims: payload };
  } catch (error) {
    return {
      valid: false,
      reason: `Validation error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Send a test push notification (Phase C: mock push delivery)
 */
async function sendTestPush(): Promise<void> {
  try {
    console.log('[Full Demo] Sending test push...');

    // Get subscription to retrieve endpoint for validation
    const subResult = await kmsUser.getPushSubscription();
    if (!subResult.subscription) {
      alert('No push subscription available. Please create a lease first.');
      return;
    }

    const sub = subResult.subscription;
    const pushServiceUrl = new URL(sub.endpoint);

    // Get active lease with matching kid
    const userId = 'demouser@ats.run';
    const { leases } = await kmsUser.getUserLeases(userId);

    // Get current VAPID key to filter leases by matching kid
    const vapidInfo = await kmsUser.getVAPIDPublicKey(userId);
    if (!vapidInfo) {
      alert('No VAPID key found. Please set up passphrase first.');
      return;
    }

    const now = Date.now();
    const activeLeases = leases.filter(
      (lease) => lease.exp > now && lease.kid === vapidInfo.kid
    );

    if (activeLeases.length === 0) {
      alert('No active leases found for current VAPID key. Please create a new lease.');
      return;
    }

    const lease = activeLeases[0]!;
    console.log(`[Full Demo] Using lease: ${lease.leaseId} (kid: ${lease.kid})`);

    // Issue JWT with endpoint info (reuse subscription from above)
    console.log('[Full Demo] Issuing JWT for push notification...');
    const jwtResult = await kmsUser.issueVAPIDJWT({
      leaseId: lease.leaseId,
      endpoint: {
        url: sub.endpoint,
        aud: pushServiceUrl.origin,
        eid: sub.eid,
      },
    });

    console.log('[Full Demo] JWT issued:', jwtResult.jwt.substring(0, 50) + '...');

    // **VALIDATE JWT (simulates relay server validation)**
    console.log('[Full Demo] Validating JWT...');
    const validation = await validateVAPIDJWT(jwtResult.jwt, pushServiceUrl.origin);

    if (!validation.valid) {
      throw new Error(`JWT validation failed: ${validation.reason}`);
    }

    console.log('[Full Demo] ✅ JWT validated successfully', validation.claims);

    // Send mock push to service worker
    const registration = await navigator.serviceWorker.ready;
    if (!registration.active) {
      throw new Error('No active service worker');
    }

    const messageChannel = new MessageChannel();
    await new Promise<void>((resolve, reject) => {
      messageChannel.port1.onmessage = (event) => {
        if (event.data.success) {
          resolve();
        } else {
          reject(new Error(event.data.error));
        }
      };

      registration.active!.postMessage(
        {
          type: 'mock-push',
          endpoint: sub.endpoint,
          jwt: jwtResult.jwt,
          payload: {
            title: 'ATS KMS Demo',
            body: 'Test notification - JWT validated successfully!',
            tag: 'test-push',
            data: { timestamp: Date.now() },
          },
        },
        [messageChannel.port2]
      );
    });

    console.log('[Full Demo] ✅ Push notification sent successfully');
    alert('Push notification sent! Check your notifications.\n\nJWT was validated before delivery.');
  } catch (error) {
    console.error('[Full Demo] Failed to send push:', error);
    alert(`Push send failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Verify all leases against the current VAPID key
 */
async function verifyAllLeases(): Promise<void> {
  try {
    console.log('[Full Demo] Verifying all leases...');

    // Get all leases for the user
    const userId = 'demouser@ats.run';
    const { leases } = await kmsUser.getUserLeases(userId);

    const resultsContainer = document.getElementById('lease-result');
    if (!resultsContainer) return;

    if (leases.length === 0) {
      resultsContainer.innerHTML = `
        <div class="info-message" style="margin-bottom: 1.5rem;">
          <h4>No Leases Found</h4>
          <p>Create a lease first to test verification.</p>
          <button id="dismiss-results-btn" class="operation-btn">✖  Dismiss</button>
        </div>
      `;
      document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
        resultsContainer.innerHTML = '';
      });
      return;
    }

    console.log(`[Full Demo] Found ${leases.length} lease(s), verifying...`);

    // Verify each lease
    const results = [];
    for (const lease of leases) {
      const result = await kmsUser.verifyLease(lease.leaseId);
      results.push({ lease, result });
    }

    // Display results
    const resultsHtml = results
      .map(
        ({ lease, result }) => `
      <div class="artifact-card ${result.valid ? 'valid' : 'invalid'}">
        <div class="artifact-title">
          ${result.valid ? '✅' : '❌'} Lease Verification
        </div>
        <div class="artifact-data">
          <div><strong>Lease ID:</strong> <code style="word-break: break-all;">${lease.leaseId}</code></div>
          <div><strong>Status:</strong> ${result.valid ? 'Valid' : 'Invalid'}</div>
          ${result.reason ? `<div><strong>Reason:</strong> ${result.reason}</div>` : ''}
          <div><strong>Key ID:</strong> <code>${result.kid}</code></div>
          <div><strong>Expires:</strong> ${new Date(lease.exp).toLocaleString()}</div>
        </div>
      </div>
    `
      )
      .join('');

    const validCount = results.filter((r) => r.result.valid).length;
    const invalidCount = results.length - validCount;

    resultsContainer.innerHTML = `
      <div class="${validCount === results.length ? 'success' : 'warning'}-message" style="margin-bottom: 1.5rem;">
        <h4>Lease Verification Results</h4>
        <p>Verified ${results.length} lease(s): ${validCount} valid, ${invalidCount} invalid</p>
        ${resultsHtml}
        <button id="verify-again-btn" class="operation-btn">🔍 Verify Again</button>
        <button id="dismiss-results-btn" class="operation-btn">✖  Dismiss</button>
      </div>
    `;

    // Add event listeners
    document.getElementById('verify-again-btn')?.addEventListener('click', () => verifyAllLeases());
    document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
      resultsContainer.innerHTML = '';
    });
  } catch (error) {
    console.error('[Full Demo] Lease verification failed:', error);
    alert(`Lease verification failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Clear all invalid leases (expired or wrong kid)
 */
async function clearInvalidLeases(): Promise<void> {
  try {
    console.log('[Full Demo] Clearing invalid leases...');

    // Get all leases for the user
    const userId = 'demouser@ats.run';
    const { leases } = await kmsUser.getUserLeases(userId);

    const resultsContainer = document.getElementById('lease-result');
    if (!resultsContainer) return;

    if (leases.length === 0) {
      resultsContainer.innerHTML = `
        <div class="info-message" style="margin-bottom: 1.5rem;">
          <h4>No Leases Found</h4>
          <p>Create a lease first to test clearing.</p>
          <button id="dismiss-results-btn" class="operation-btn">✖  Dismiss</button>
        </div>
      `;
      document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
        resultsContainer.innerHTML = '';
      });
      return;
    }

    console.log(`[Full Demo] Found ${leases.length} lease(s), clearing invalid ones...`);

    // Verify each lease with deleteIfInvalid=true
    let deletedCount = 0;
    const results = [];
    for (const lease of leases) {
      const result = await kmsUser.verifyLease(lease.leaseId, true);
      if (!result.valid) {
        deletedCount++;
      }
      results.push({ lease, result, deleted: !result.valid });
    }

    // Display results
    const resultsHtml = results
      .map(
        ({ lease, result, deleted }) => `
      <div class="artifact-card ${deleted ? 'invalid' : 'valid'}">
        <div class="artifact-title">
          ${deleted ? '🗑️' : '✅'} ${deleted ? 'Deleted Invalid Lease' : 'Valid Lease (Kept)'}
        </div>
        <div class="artifact-data">
          <div><strong>Lease ID:</strong> <code style="word-break: break-all;">${lease.leaseId}</code></div>
          <div><strong>Status:</strong> ${deleted ? 'Deleted' : 'Valid (Kept)'}</div>
          ${result.reason ? `<div><strong>Reason:</strong> ${result.reason}</div>` : ''}
          <div><strong>Key ID:</strong> <code>${result.kid}</code></div>
          <div><strong>Expires:</strong> ${new Date(lease.exp).toLocaleString()}</div>
        </div>
      </div>
    `
      )
      .join('');

    const keptCount = results.length - deletedCount;

    resultsContainer.innerHTML = `
      <div class="${deletedCount > 0 ? 'warning' : 'success'}-message" style="margin-bottom: 1.5rem;">
        <h4>Clear Invalid Leases Results</h4>
        <p>Processed ${results.length} lease(s): ${deletedCount} deleted, ${keptCount} kept</p>
        ${resultsHtml}
        <button id="dismiss-results-btn" class="operation-btn">✖  Dismiss</button>
      </div>
    `;

    // Add event listener
    document.getElementById('dismiss-results-btn')?.addEventListener('click', () => {
      resultsContainer.innerHTML = '';
    });

    // Refresh displays
    await displayVAPIDKeyInfo();
    await loadAuditLog();
  } catch (error) {
    console.error('[Full Demo] Clear invalid leases failed:', error);
    alert(`Clear invalid leases failed: ${error instanceof Error ? error.message : String(error)}`);
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
