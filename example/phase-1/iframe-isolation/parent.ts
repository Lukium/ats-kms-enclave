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
let setupMethod: 'passphrase' | 'passkey' | null = null; // Track setup method for unlock
let isLocked = true; // Track lock state

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
      if (config) {
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
  document.getElementById('generate-vapid')!.removeAttribute('disabled');
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
      displayOutput('✅ Passphrase Setup Complete', result);
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
      displayOutput('✅ Passkey Setup Complete', result);
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
    if (setupMethod === 'passphrase') {
      const passphrase = prompt('Enter passphrase to unlock:');
      if (!passphrase) return;
      const result = await kmsUser.unlockWithPassphrase(passphrase);

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

        displayOutput('✅ KMS Unlocked (Passphrase)', result);
        updateLockButton(); // Update button state
      } else {
        displayError(new Error(result.error || 'Unlock failed'));
      }
    } else {
      const result = await kmsUser.unlockWithPasskey(window.location.hostname);

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

        displayOutput('✅ KMS Unlocked (Passkey)', result);
        updateLockButton(); // Update button state
      } else {
        displayError(new Error(result.error || 'Unlock failed'));
      }
    }
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('generate-vapid')!.addEventListener('click', async () => {
  try {
    const result = await kmsUser.generateVAPID();
    vapidKid = result.kid; // Store kid for later use
    displayOutput('✅ VAPID Keypair Generated', {
      publicKey: result.publicKey,
      kid: result.kid,
      note: 'Private key is non-extractable and isolated in KMS',
    });
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('sign-jwt')!.addEventListener('click', async () => {
  if (!vapidKid) {
    displayError(new Error('Please generate VAPID keypair first'));
    return;
  }

  // Use default FCM endpoint for demo
  const endpoint = 'https://fcm.googleapis.com/fcm/send/example';

  try {
    const payload = {
      aud: new URL(endpoint).origin,
      sub: 'mailto:admin@allthe.services',
      exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60, // 12 hours
    };
    const result = await kmsUser.signJWT(vapidKid, payload);
    displayOutput('✅ JWT Signed', {
      jwt: result.jwt,
      kid: vapidKid,
      endpoint: endpoint,
      note: 'Signed with non-extractable private key in KMS',
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
