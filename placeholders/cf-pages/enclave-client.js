// Bootstrap: Load the KMS worker and establish parent communication
const worker = new Worker('./kms-worker.885ea08b.js', {
  type: 'module',
  name: 'kms-enclave-worker'
});

// Track worker readiness
let workerReady = false;

// Forward messages from parent to worker
window.addEventListener('message', (event) => {
  // TODO: Add origin validation in production
  // if (event.origin !== 'https://ats.run') return;

  if (!workerReady) {
    console.warn('[KMS Enclave] Worker not ready, queueing message');
    // Could implement message queue here if needed
    return;
  }

  console.log('[KMS Enclave] → Worker:', event.data.method || event.data.type);
  worker.postMessage(event.data);
});

// Forward messages from worker to parent
worker.addEventListener('message', (event) => {
  console.log('[KMS Enclave] ← Worker:', event.data);
  window.parent.postMessage(event.data, '*'); // TODO: Specify target origin in production
});

// Handle worker errors
worker.addEventListener('error', (event) => {
  console.error('[KMS Enclave] Worker error:', event);
  window.parent.postMessage({
    type: 'error',
    error: 'Worker crashed: ' + event.message
  }, '*');
});

// Mark worker as ready
worker.addEventListener('message', function readyHandler(event) {
  if (event.data.type === 'ready') {
    workerReady = true;
    worker.removeEventListener('message', readyHandler);
    console.log('[KMS Enclave] Worker ready');
  }
}, { once: false });

// Signal to parent that iframe is loaded
window.parent.postMessage({ type: 'iframe-ready' }, '*');
