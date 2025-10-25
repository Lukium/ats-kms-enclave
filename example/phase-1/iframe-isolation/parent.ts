/**
 * Parent PWA - Uses KMSUser for iframe communication
 *
 * Demonstrates using KMSUser client to communicate with KMS iframe.
 * KMSUser handles WebAuthn ceremonies in parent context, forwards to iframe.
 */

import { KMSUser } from '@/kms-user';

const iframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
const KMS_ORIGIN = 'http://localhost:5177';

let vapidKid: string | null = null; // Store VAPID kid for reuse
let vapidPublicKey: string | null = null; // Store VAPID public key
let setupMethod: 'passphrase' | 'passkey' | null = null; // Track setup method for unlock
let isLocked = true; // Track lock state
let currentLeaseId: string | null = null; // Store current lease ID

// Display current origin
document.getElementById('parent-origin')!.textContent = window.location.origin;

// Wait for iframe to load, then create KMSUser
iframe.addEventListener('load', () => {
  console.log('[Parent] KMS iframe loaded, creating KMSUser client');
  initKMSUser();
});

let kmsUser: KMSUser;

async function initKMSUser(): Promise<void> {
  // Create KMSUser client (handles parent-side operations and iframe communication)
  kmsUser = new KMSUser({
    kmsOrigin: KMS_ORIGIN,
    iframe,
  });

  console.log('[Parent] KMSUser client ready');

  // Auto-detect if setup already exists
  try {
    const status = await kmsUser.isUnlockSetup();
    if (status.isSetup) {
      // Check setup method
      const config = await kmsUser.getPasskeyConfig();
      if (config && (config.method === 'passkey-prf' || config.method === 'passkey-gate')) {
        setupMethod = 'passkey';
        displayOutput('ℹ️ Existing Passkey Setup Detected', {
          method: config.method,
          note: 'Use Unlock button to unlock with passkey',
        });
      } else {
        setupMethod = 'passphrase';
        displayOutput('ℹ️ Existing Passphrase Setup Detected', {
          note: 'Use Unlock button to unlock with passphrase',
        });
      }
      isLocked = true; // Existing setup starts locked
      enableOperationControls();
    } else {
      enableInitialControls();
    }
  } catch (error) {
    console.error('[Parent] Failed to check setup status:', error);
    enableInitialControls();
  }
}

// Enable initial controls
function enableInitialControls(): void {
  document.getElementById('setup-passphrase')!.removeAttribute('disabled');
  document.getElementById('setup-passkey')!.removeAttribute('disabled');
}

// Enable operation controls (after setup)
function enableOperationControls(): void {
  updateLockButton();
  document.getElementById('create-lease')!.removeAttribute('disabled');
  document.getElementById('sign-jwt')!.removeAttribute('disabled');
}

// Update lock/unlock button based on current state
function updateLockButton(): void {
  const unlockBtn = document.getElementById('unlock-kms') as HTMLButtonElement;

  if (isLocked) {
    unlockBtn.textContent = 'Unlock KMS';
    unlockBtn.removeAttribute('disabled');
    unlockBtn.classList.remove('btn-success');
    unlockBtn.classList.add('btn-secondary');
  } else {
    unlockBtn.textContent = '🔓 Unlocked';
    unlockBtn.setAttribute('disabled', 'true');
    unlockBtn.classList.remove('btn-secondary');
    unlockBtn.classList.add('btn-success');
  }
}

// Display output
function displayOutput(title: string, data: any): void {
  const outputEl = document.getElementById('output-display')!;
  const timestamp = new Date().toLocaleTimeString();

  const html = `
    <div class="output-entry output-success">
      <div class="output-header">
        <strong>${title}</strong>
        <span class="output-time">${timestamp}</span>
      </div>
      <pre class="output-data">${JSON.stringify(data, null, 2)}</pre>
    </div>
  `;

  outputEl.innerHTML = html + outputEl.innerHTML;
}

// Display error
function displayError(error: Error): void {
  const outputEl = document.getElementById('output-display')!;
  const timestamp = new Date().toLocaleTimeString();

  const html = `
    <div class="output-entry output-error">
      <div class="output-header">
        <strong>❌ Error</strong>
        <span class="output-time">${timestamp}</span>
      </div>
      <pre class="output-data">${error.message}</pre>
    </div>
  `;

  outputEl.innerHTML = html + outputEl.innerHTML;
}

// Button handlers
document.getElementById('setup-passphrase')!.addEventListener('click', async () => {
  const passphrase = prompt('Enter passphrase (min 8 characters):');
  if (!passphrase) return;

  try {
    const result = await kmsUser.setupPassphrase(passphrase);

    // Check if setup was successful
    if (result.success) {
      setupMethod = 'passphrase'; // Track setup method
      isLocked = false; // Setup auto-unlocks

      // Capture VAPID keys generated during setup
      vapidKid = result.vapidKid;
      vapidPublicKey = result.vapidPublicKey;

      displayOutput('✅ Passphrase Setup Complete', {
        enrollmentId: result.enrollmentId,
        vapidPublicKey: result.vapidPublicKey,
        vapidKid: result.vapidKid,
        note: 'VAPID keypair generated automatically during setup'
      });
      enableOperationControls();
    } else {
      displayError(new Error(result.error || 'Passphrase setup failed'));
    }
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('setup-passkey')!.addEventListener('click', async () => {
  try {
    const result = await kmsUser.setupPasskey({
      rpId: window.location.hostname,
      rpName: 'ATS KMS Demo',
    });

    // Check if setup was successful
    if (result.success) {
      setupMethod = 'passkey'; // Track setup method
      isLocked = false; // Setup auto-unlocks

      // Capture VAPID keys generated during setup
      vapidKid = result.vapidKid;
      vapidPublicKey = result.vapidPublicKey;

      displayOutput('✅ Passkey Setup Complete', {
        enrollmentId: result.enrollmentId,
        vapidPublicKey: result.vapidPublicKey,
        vapidKid: result.vapidKid,
        note: 'VAPID keypair generated automatically during setup'
      });
      enableOperationControls();
    } else {
      displayError(new Error(result.error || 'Passkey setup failed'));
    }
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('unlock-kms')!.addEventListener('click', async () => {
  if (!setupMethod) {
    displayError(new Error('Please setup passphrase or passkey first'));
    return;
  }

  try {
    // Prompt for optional passphrase (for passphrase-only or fallback)
    let passphrase: string | null = null;
    if (setupMethod === 'passphrase') {
      // Passphrase-only: required
      passphrase = prompt('Enter passphrase to unlock:');
      if (!passphrase) return;
    } else {
      // Passkey or both: optional (for fallback)
      passphrase = prompt('Enter passphrase (optional, for fallback if passkey fails):') || undefined;
    }

    // Use unified unlock() method with automatic passkey-first fallback
    const result = await kmsUser.unlock(
      window.location.hostname,
      passphrase || undefined
    );

    // Check if unlock was successful
    if (result.success) {
      isLocked = false; // Mark as unlocked

      // Extract VAPID kid from unlock result
      if (result.keys && result.keys.length > 0) {
        const vapidKey = result.keys.find(k => k.purpose === 'vapid');
        if (vapidKey) {
          vapidKid = vapidKey.kid;
          console.log('[Parent] Restored VAPID kid from unlock:', vapidKid);
        }
      }

      displayOutput('✅ KMS Unlocked', result);
      updateLockButton(); // Update button state
    } else {
      displayError(new Error(result.error || 'Unlock failed'));
    }
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('create-lease')!.addEventListener('click', async () => {
  if (!vapidKid) {
    displayError(new Error('No VAPID keypair found. Setup should have generated one automatically.'));
    return;
  }

  // Prompt for passphrase to authorize lease creation
  const passphrase = prompt('Enter passphrase to authorize lease creation:');
  if (!passphrase) return;

  try {
    // Create a lease for push subscriptions
    const result = await kmsUser.createLease({
      userId: 'demo-user',
      subs: [
        { url: 'https://fcm.googleapis.com/fcm/send/example1', aud: 'https://fcm.googleapis.com', eid: 'endpoint-1' },
        { url: 'https://fcm.googleapis.com/fcm/send/example2', aud: 'https://fcm.googleapis.com', eid: 'endpoint-2' },
      ],
      ttlHours: 12,
      credentials: { method: 'passphrase', passphrase },
    });

    currentLeaseId = result.leaseId;

    displayOutput('✅ Lease Created', {
      leaseId: result.leaseId,
      expiresAt: new Date(result.exp).toLocaleString(),
      quotas: result.quotas,
      note: 'JWTs can now be issued without user interaction until lease expires'
    });
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('sign-jwt')!.addEventListener('click', async () => {
  if (!currentLeaseId) {
    displayError(new Error('Please create a lease first'));
    return;
  }

  // Use default FCM endpoint for demo
  const endpoint = {
    url: 'https://fcm.googleapis.com/fcm/send/example1',
    aud: 'https://fcm.googleapis.com',
    eid: 'endpoint-1'
  };

  try {
    // Issue JWT using the lease (no credentials needed!)
    const result = await kmsUser.issueVAPIDJWT({
      leaseId: currentLeaseId,
      endpoint,
    });

    displayOutput('✅ JWT Issued (No User Interaction!)', {
      jwt: result.jwt,
      jti: result.jti,
      expiresAt: new Date(result.exp * 1000).toLocaleString(),
      endpoint: endpoint.url,
      note: 'JWT signed using SessionKEK - no user authentication required!'
    });
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('reset-demo')!.addEventListener('click', async () => {
  const confirmed = confirm(
    '⚠️ This will delete all keys and configuration.\n\n' +
    'The demo will reload after reset.\n\n' +
    'Continue?'
  );

  if (!confirmed) return;

  try {
    // Reset KMS (deletes all data in iframe's IndexedDB)
    const result = await kmsUser.resetKMS();
    if (result.success) {
      // Reload page to reset all state
      window.location.reload();
    } else {
      displayError(new Error(result.error || 'Reset failed'));
    }
  } catch (error) {
    displayError(error as Error);
  }
});

console.log('[Parent] PWA initialized, waiting for iframe to load');
