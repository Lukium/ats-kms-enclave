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
let vapidKid: string | null = null; // Store VAPID kid for reuse

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
}

// Enable operation controls (after setup)
function enableOperationControls(): void {
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
    const result = await sendToKMS('setupPassphrase', { passphrase });
    displayOutput('✅ Passphrase Setup Complete', result);
    enableOperationControls();
  } catch (error) {
    displayError(error as Error);
  }
});

document.getElementById('generate-vapid')!.addEventListener('click', async () => {
  try {
    const result = await sendToKMS('generateVAPID', {});
    vapidKid = result.kid; // Store kid for later use
    displayOutput('✅ VAPID Keypair Generated', {
      publicKey: result.publicKey,
      kid: result.kid,
      note: 'Private key is non-extractable and isolated in KMS'
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
      exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60 // 12 hours
    };
    const result = await sendToKMS('signJWT', {
      kid: vapidKid, // Use stored kid
      payload
    });
    displayOutput('✅ JWT Signed', {
      jwt: result.jwt,
      kid: vapidKid,
      note: 'Signed with non-extractable private key in KMS'
    });
  } catch (error) {
    displayError(error as Error);
  }
});

console.log('[Parent] PWA initialized, waiting for iframe to load');
