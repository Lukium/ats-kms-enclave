/**
 * KMS Iframe Bridge
 *
 * Receives postMessage from parent PWA, forwards to Worker via KMSClient,
 * returns responses. Provides thin bridge layer on top of production KMSClient.
 */

import { KMSClient } from '@/client';
import type { ChainVerificationResult } from '@/client';

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
    // Forward request to Worker via KMSClient (production code)
    const result = await (kmsClient as any)[method](params);

    // Send successful response back to parent
    window.parent.postMessage(
      { id, result },
      ALLOWED_PARENT_ORIGIN
    );

    // Update UI
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
    // Get current status from KMS
    const status = await kmsClient.getStatus();

    // Update lock status indicator
    const lockStatusEl = document.getElementById('lock-status')!;
    if (status.locked) {
      lockStatusEl.textContent = '🔒 Locked';
      lockStatusEl.className = 'status-locked';
    } else {
      lockStatusEl.textContent = '🔓 Unlocked';
      lockStatusEl.className = 'status-unlocked';
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
    // Get audit log via KMSClient (production code)
    const result = await kmsClient.getAuditLog();

    // Display chain verification status
    const chainStatusEl = document.getElementById('chain-status')!;
    if (result.verification.valid) {
      chainStatusEl.textContent = `✅ Chain verified (${result.verification.verified} entries)`;
      chainStatusEl.className = 'chain-valid';
    } else {
      chainStatusEl.textContent = `❌ Chain broken: ${result.verification.errors.join(', ')}`;
      chainStatusEl.className = 'chain-invalid';
    }

    // Display audit entries
    displayAuditEntries(result.entries);
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
