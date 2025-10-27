/**
 * KMS Enclave Entry Point (Cross-Origin Isolated)
 *
 * This file runs in a sandboxed iframe on http://localhost:5174
 * The parent PWA runs on http://localhost:5173 (different origin = isolated)
 */

import { KMSClient } from '@/client';

console.log('[KMS Enclave] Initializing...');
console.log('[KMS Enclave] 🔍 CRITICAL: Running on origin:', window.location.origin);
console.log('[KMS Enclave] 🔍 CRITICAL: Should be http://localhost:5174');

// Get parent origin from URL params (passed by KMSUser)
const params = new URLSearchParams(window.location.search);
const parentOrigin = params.get('parentOrigin');

if (!parentOrigin) {
  console.error('[KMS] No parentOrigin provided in URL params');
  throw new Error('Missing required parentOrigin parameter');
}

console.log('[KMS] Parent origin:', parentOrigin);
console.log('[KMS] KMS origin:', window.location.origin);

// Verify cross-origin isolation
if (window.location.origin === parentOrigin) {
  console.error('[KMS] ❌ ISOLATION BROKEN: KMS is running on SAME origin as parent!');
  console.error('[KMS] ❌ Expected KMS on http://localhost:5174, parent on http://localhost:5173');
} else {
  console.log('[KMS] ✅ Cross-origin isolation verified: KMS and parent are on different origins');
}

// Create and initialize KMSClient
const kmsClient = new KMSClient({ parentOrigin });

(async () => {
  try {
    await kmsClient.init();
    console.log('[KMS Enclave] Ready');
  } catch (error) {
    console.error('[KMS] Initialization failed:', error);
  }
})();
