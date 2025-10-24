/**
 * KMS Iframe Bridge
 *
 * Receives postMessage from parent PWA, forwards to Worker via KMSClient,
 * returns responses. Provides thin bridge layer on top of production KMSClient.
 */

import { KMSClient } from '@/client';
import { getAllAuditEntries } from '@/storage';

// Origin validation
const ALLOWED_PARENT_ORIGIN = 'http://localhost:5176';

// Create KMSClient instance (handles all Worker communication)
const kmsClient = new KMSClient();

// Display current origin
document.getElementById('kms-origin')!.textContent = window.location.origin;

// Listen for messages from parent
window.addEventListener('message', async (event) => {
  // Validate origin
  if (event.origin !== ALLOWED_PARENT_ORIGIN) {
    console.warn('[KMS] Rejected message from unauthorized origin:', event.origin);
    return;
  }

  const { id, method, params } = event.data;

  try {
    let result;

    // Forward request to Worker via KMSClient (production code)
    // Unpack params based on method signature
    switch (method) {
      case 'setupPassphrase':
        result = await kmsClient.setupPassphrase(params.passphrase);
        break;
      case 'unlockWithPassphrase':
        result = await kmsClient.unlockWithPassphrase(params.passphrase);
        break;
      case 'setupPasskeyPRF':
        result = await kmsClient.setupPasskeyPRF(
          params.rpId,
          params.rpName,
          params.credentialId,
          params.prfOutput
        );
        break;
      case 'setupPasskeyGate':
        result = await kmsClient.setupPasskeyGate(params.rpId, params.rpName, params.credentialId);
        break;
      case 'unlockWithPasskeyPRF':
        result = await kmsClient.unlockWithPasskeyPRF(params.rpId);
        break;
      case 'unlockWithPasskeyGate':
        result = await kmsClient.unlockWithPasskeyGate();
        break;
      case 'generateVAPID':
        result = await kmsClient.generateVAPID();
        break;
      case 'signJWT':
        result = await kmsClient.signJWT(params.kid, params.payload);
        break;
      case 'getPublicKey':
        result = await kmsClient.getPublicKey(params.kid);
        break;
      case 'isUnlockSetup':
        result = await kmsClient.isUnlockSetup();
        break;
      case 'verifyAuditChain':
        result = await kmsClient.verifyAuditChain();
        break;
      case 'getPasskeyConfig':
        result = await kmsClient.getPasskeyConfig();
        break;
      case 'resetKMS':
        // Forward to KMSClient to reset all data
        result = await kmsClient.resetKMS();
        break;
      default:
        throw new Error(`Unknown method: ${method}`);
    }

    // Send successful response back to parent
    window.parent.postMessage(
      { id, result },
      ALLOWED_PARENT_ORIGIN
    );

    // Update UI after operation
    await updateUI();

  } catch (error) {
    // Send error response back to parent
    window.parent.postMessage(
      {
        id,
        error: {
          code: 'OPERATION_FAILED',
          message: error instanceof Error ? error.message : 'Unknown error'
        }
      },
      ALLOWED_PARENT_ORIGIN
    );
  }
});

// Update UI based on KMS state
async function updateUI(): Promise<void> {
  try {
    // Check if setup is complete
    const setupStatus = await kmsClient.isUnlockSetup();

    // Update lock status (simple heuristic - if setup, assume unlocked after operation)
    const lockStatusEl = document.getElementById('lock-status')!;
    if (setupStatus.isSetup) {
      lockStatusEl.textContent = '🔓 Unlocked';
      lockStatusEl.className = 'status-unlocked';
    } else {
      lockStatusEl.textContent = '🔒 Not Setup';
      lockStatusEl.className = 'status-locked';
    }

    // Refresh audit log
    await refreshAuditLog();
  } catch (error) {
    console.error('[KMS] Failed to update UI:', error);
  }
}

// Display audit log with chain verification
async function refreshAuditLog(): Promise<void> {
  try {
    // Get audit entries directly from storage (same origin = can access IndexedDB)
    const entries = await getAllAuditEntries();

    // Verify chain integrity
    const verification = await kmsClient.verifyAuditChain();

    // Display chain verification status
    const chainStatusEl = document.getElementById('chain-status')!;
    if (verification.valid) {
      chainStatusEl.textContent = `✅ Chain verified (${verification.verified} entries)`;
      chainStatusEl.className = 'chain-valid';
    } else {
      chainStatusEl.textContent = `❌ Chain broken: ${verification.errors.join(', ')}`;
      chainStatusEl.className = 'chain-invalid';
    }

    // Display audit entries
    displayAuditEntries(entries);
  } catch (error) {
    console.error('[KMS] Failed to refresh audit log:', error);
  }
}

// Display audit entries
function displayAuditEntries(entries: any[]): void {
  const entriesEl = document.getElementById('audit-entries')!;

  if (entries.length === 0) {
    entriesEl.innerHTML = '<p class="no-entries">No operations logged yet</p>';
    return;
  }

  const html = entries
    .slice()
    .reverse() // Show newest first
    .map(entry => {
      const timestamp = new Date(entry.timestamp).toLocaleString();
      return `
        <div class="audit-entry">
          <div class="entry-header">
            <span class="entry-op">${entry.op}</span>
            <span class="entry-time">${timestamp}</span>
          </div>
          <div class="entry-details">
            <span>kid: ${entry.kid}</span>
            ${entry.origin ? `<span>origin: ${entry.origin}</span>` : ''}
          </div>
        </div>
      `;
    })
    .join('');

  entriesEl.innerHTML = html;
}

// Initialize UI
updateUI();

console.log('[KMS] Iframe bridge initialized, listening for parent messages');
