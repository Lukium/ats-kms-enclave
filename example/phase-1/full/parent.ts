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

    // Expose kmsUser globally for Playwright tests
    (window as any).kmsUser = kmsUser;

    // Setup postMessage listener for setup completion callbacks
    window.addEventListener('message', handleSetupComplete);

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

    // Filter for active (non-expired) leases
    const now = Date.now();
    const activeLeases = leases.filter((lease) => lease.exp > now);
    const expiredLeases = leases.filter((lease) => lease.exp <= now);

    // Use the dedicated vapid-info-section container
    const vapidInfoEl = document.getElementById('vapid-info-section');
    if (!vapidInfoEl) {
      console.error('[Full Demo] vapid-info-section element not found');
      return;
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
          <div class="artifact-title">VAPID Key ID</div>
          <div class="artifact-data"><code>${lease.kid}</code></div>
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

    // Add event listener for regenerate button
    document.getElementById('regenerate-vapid-btn')?.addEventListener('click', regenerateVAPIDKey);
  } catch (error) {
    console.error('[Full Demo] Failed to fetch VAPID key or leases:', error);
    // Don't show error UI - it's okay if this fails (e.g., no VAPID key yet)
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
 * Setup passphrase authentication
 */
/**
 * Setup Passphrase authentication - opens KMS in new window (first-party context)
 */
async function setupPassphrase(): Promise<void> {
  console.log('[Full Demo] Opening KMS setup window...');

  // Open KMS in new window for passphrase setup
  const setupWindow = window.open(
    KMS_ORIGIN + '/kms.html?parentOrigin=' + encodeURIComponent(window.location.origin),
    'kms-setup',
    'width=600,height=700,menubar=no,toolbar=no,location=no,status=no'
  );

  if (!setupWindow) {
    alert('Failed to open setup window. Please allow popups for this site.');
    return;
  }

  console.log('[Full Demo] Setup window opened, waiting for completion message...');
}

/**
 * Setup WebAuthn authentication - opens KMS in new window (first-party context)
 */
async function setupWebAuthn(): Promise<void> {
  console.log('[Full Demo] Opening KMS setup window...');

  // Open KMS in new window for first-party WebAuthn registration
  const setupWindow = window.open(
    KMS_ORIGIN + '/kms.html?parentOrigin=' + encodeURIComponent(window.location.origin),
    'kms-setup',
    'width=600,height=700,menubar=no,toolbar=no,location=no,status=no'
  );

  if (!setupWindow) {
    alert('Failed to open setup window. Please allow popups for this site.');
    return;
  }

  console.log('[Full Demo] Setup window opened, waiting for completion...');
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
    <div id="lease-verification-results"></div>
    <p>Generate a time-limited VAPID authorization lease for push subscriptions.</p>
    <button id="create-lease-btn" class="operation-btn">🎫 Create Lease</button>
    <button id="verify-leases-btn" class="operation-btn">🔍 Verify All Leases</button>
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
    <hr style="margin: 1.5rem 0; border: none; border-top: 2px solid #e2e8f0;">
    <button id="regenerate-vapid-btn" class="operation-btn" style="background-color: #dc3545;">
      🔄 Regenerate VAPID Key
    </button>
    <div class="info-message" style="color: #dc3545; margin-top: 0.5rem;">
      ⚠️ Warning: Regenerating will invalidate all active leases!
    </div>
  `;

  leaseOperationEl.innerHTML = html;

  // Add event listeners
  document.getElementById('create-lease-btn')?.addEventListener('click', () => createLease(status));
  document.getElementById('verify-leases-btn')?.addEventListener('click', () => verifyAllLeases());
  document.getElementById('issue-jwts-btn')?.addEventListener('click', () => issueJWTsFromLease());
  document.getElementById('regenerate-vapid-btn')?.addEventListener('click', regenerateVAPIDKey);
}

/**
 * Create a VAPID lease
 */
async function createLease(status: { isSetup: boolean; methods: string[] }): Promise<void> {
  try {
    console.log('[Full Demo] Creating VAPID lease...');

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

    // Call createLease - iframe will automatically show modal to collect credentials
    console.log('[Full Demo] Calling createLease with:', { userId, subs, ttlHours });
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

    // Filter for active (non-expired) leases
    const now = Date.now();
    const activeLeases = leases.filter((lease) => lease.exp > now);

    if (activeLeases.length === 0) {
      alert('No active leases found. Please create a lease first.');
      return;
    }

    // Use the first active lease (in production, we'd let user select)
    const lease = activeLeases[0];
    console.log(`[Full Demo] Using lease: ${lease.leaseId}`);

    // Get the first subscription endpoint from the lease
    if (lease.subs.length === 0) {
      alert('Selected lease has no subscriptions');
      return;
    }
    const endpoint = lease.subs[0];

    // Issue JWTs
    console.log(`[Full Demo] Issuing ${count} JWT(s) for endpoint ${endpoint.eid}...`);
    const startTime = performance.now();
    const jwts = await kmsUser.issueVAPIDJWTs({
      leaseId: lease.leaseId,
      endpoint,
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
        <div class="artifact-data">${new Date(jwt.exp * 1000).toLocaleString()}</div>
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
          <div class="artifact-data"><code>${endpoint.eid}</code></div>
        </div>
        <div class="artifact-card">
          <div class="artifact-title">Audience</div>
          <div class="artifact-data"><code>${endpoint.aud}</code></div>
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

// Event listeners
resetDemoBtn.addEventListener('click', resetDemo);

// Start
initKMS().then((status) => {
  renderSetupUI(status);
  renderLeaseUI(status);
}).catch((error) => {
  console.error('[Full Demo] Failed to initialize:', error);
});
