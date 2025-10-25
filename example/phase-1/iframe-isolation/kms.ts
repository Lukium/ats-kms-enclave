/**
 * KMS Iframe Entry Point (V2)
 *
 * Minimal bootstrap that creates KMSClient and initializes it.
 * KMSClient automatically handles all message forwarding between parent and Worker.
 *
 * V2 uses per-operation authentication - credentials passed with each request.
 */

import { KMSClient } from '@/client';

// Get parent origin from URL params (passed by KMSUser)
const params = new URLSearchParams(window.location.search);
const parentOrigin = params.get('parentOrigin');

if (!parentOrigin) {
  console.error('[KMS] No parentOrigin provided in URL params');
  throw new Error('Missing required parentOrigin parameter');
}

// Display current origin
const originElement = document.getElementById('kms-origin');
if (originElement) {
  originElement.textContent = window.location.origin;
}

// Create and initialize KMSClient
// KMSClient automatically:
// - Creates the Worker
// - Forwards parent messages to Worker
// - Forwards Worker responses to parent
// - Sends ready signal to parent
const kmsClient = new KMSClient({ parentOrigin });

(async () => {
  try {
    await kmsClient.init();
    console.log('[KMS] KMSClient initialized and ready');
  } catch (error) {
    console.error('[KMS] Initialization failed:', error);
  }
})();
