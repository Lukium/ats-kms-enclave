/**
 * Parent PWA - Iframe Communication Client
 *
 * Sends requests to KMS iframe via postMessage, receives responses.
 * Mirrors KMSClient pattern for consistency.
 */

const iframe = document.getElementById('kms-iframe') as HTMLIFrameElement;
const KMS_ORIGIN = 'http://localhost:5177';

let requestIdCounter = 0;
let iframeReady = false;

// Display current origin
document.getElementById('parent-origin')!.textContent = window.location.origin;

// Wait for iframe to load
iframe.addEventListener('load', () => {
  console.log('[Parent] KMS iframe loaded');
  iframeReady = true;
  enableInitialControls();
});

// Send request to KMS iframe (mirrors KMSClient pattern)
async function sendToKMS(method: string, params?: any): Promise<any> {
  if (!iframeReady) {
    throw new Error('KMS iframe not ready');
  }

  return new Promise((resolve, reject) => {
    const id = `req-${++requestIdCounter}`;

    // Set up response listener
    const responseHandler = (event: MessageEvent) => {
      // Validate origin
      if (event.origin !== KMS_ORIGIN) {
        return;
      }

      const response = event.data;
      if (response.id === id) {
        window.removeEventListener('message', responseHandler);
        clearTimeout(timeout);

        if (response.error) {
          reject(new Error(response.error.message));
        } else {
          resolve(response.result);
        }
      }
    };

    window.addEventListener('message', responseHandler);

    // Timeout after 10s
    const timeout = setTimeout(() => {
      window.removeEventListener('message', responseHandler);
      reject(new Error('Request timeout (10s)'));
    }, 10000);

    // Send request to iframe
    iframe.contentWindow!.postMessage(
      { id, method, params },
      KMS_ORIGIN
    );
  });
}

// Enable initial controls
function enableInitialControls(): void {
  document.getElementById('setup-passphrase')!.removeAttribute('disabled');
  document.getElementById('setup-passkey')!.removeAttribute('disabled');
  document.getElementById('get-status')!.removeAttribute('disabled');
  document.getElementById('view-audit')!.removeAttribute('disabled');
}

// Enable operation controls (after setup)
function enableOperationControls(): void {
  document.getElementById('unlock-kms')!.removeAttribute('disabled');
  document.getElementById('generate-vapid')!.removeAttribute('disabled');
  document.getElementById('sign-jwt')!.removeAttribute('disabled');
  document.getElementById('lock-kms')!.removeAttribute('disabled');
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
    const result = await sendToKMS('setupPassphrase', { passphrase });
    displayOutput('✅ Passphrase Setup Complete', result);
    enableOperationControls();
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('setup-passkey')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('setupPasskey', {});
    displayOutput('✅ Passkey Setup Complete', result);
    enableOperationControls();
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('unlock-kms')!.addEventListener('click', async () => {
  try {
    // Get current status first to determine unlock method
    const status = await sendToKMS('getStatus', {});

    if (status.setupMethod === 'passphrase') {
      const passphrase = prompt('Enter passphrase to unlock:');
      if (!passphrase) return;
      const result = await sendToKMS('unlockWithPassphrase', { passphrase });
      displayOutput('✅ KMS Unlocked (Passphrase)', result);
    } else if (status.setupMethod === 'passkey') {
      const result = await sendToKMS('unlockWithPasskey', {});
      displayOutput('✅ KMS Unlocked (Passkey)', result);
    } else {
      throw new Error('No setup method configured');
    }
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('generate-vapid')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('generateVAPIDKeypair', {});
    displayOutput('✅ VAPID Keypair Generated', {
      publicKey: result.publicKey,
      keyId: result.keyId,
      note: 'Private key is non-extractable and isolated in KMS'
    });
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('sign-jwt')!.addEventListener('click', async () => {
  const endpoint = prompt('Enter push endpoint URL:', 'https://fcm.googleapis.com/fcm/send/example');
  if (!endpoint) return;

  try {
    const result = await sendToKMS('signVAPIDJWT', {
      audience: new URL(endpoint).origin,
      subject: 'mailto:admin@allthe.services'
    });
    displayOutput('✅ JWT Signed', {
      jwt: result.jwt,
      note: 'Signed with non-extractable private key in KMS'
    });
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('lock-kms')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('lock', {});
    displayOutput('✅ KMS Locked', result);
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('get-status')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('getStatus', {});
    displayOutput('📊 KMS Status', result);
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('view-audit')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('getAuditLog', {});
    displayOutput('📋 Audit Log', {
      entries: result.entries.length,
      chainValid: result.verification.valid,
      verification: result.verification
    });
  } catch (error) {
    displayError(error as Error);
  }
});

console.log('[Parent] PWA initialized, waiting for iframe to load');
