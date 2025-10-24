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
  document.getElementById('unlock-kms')!.removeAttribute('disabled');
  document.getElementById('generate-vapid')!.removeAttribute('disabled');
  document.getElementById('sign-jwt')!.removeAttribute('disabled');
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
    setupMethod = 'passphrase'; // Track setup method
    displayOutput('✅ Passphrase Setup Complete', result);
    enableOperationControls();
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
    setupMethod = 'passkey'; // Track setup method
    displayOutput('✅ Passkey Setup Complete', result);
    enableOperationControls();
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
      displayOutput('✅ KMS Unlocked (Passphrase)', result);
    } else {
      const result = await kmsUser.unlockWithPasskey(window.location.hostname);
      displayOutput('✅ KMS Unlocked (Passkey)', result);
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

  const endpoint = prompt('Enter push endpoint URL:', 'https://fcm.googleapis.com/fcm/send/example');
  if (!endpoint) return;

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
      note: 'Signed with non-extractable private key in KMS',
    });
  } catch (error) {
    displayError(error as Error);
  }
});

console.log('[Parent] PWA initialized, waiting for iframe to load');
