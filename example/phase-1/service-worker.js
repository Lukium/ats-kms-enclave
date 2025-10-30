/**
 * Service Worker for Phase 1 Full Demo
 *
 * Handles:
 * - Push notifications (real and mock)
 * - Notification click events
 */

// Service worker installation
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');
  self.skipWaiting(); // Activate immediately
});

// Service worker activation
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');
  event.waitUntil(self.clients.claim()); // Take control immediately
});

// Handle push events (real push notifications from push service)
self.addEventListener('push', (event) => {
  console.log('[Service Worker] Push event received');

  const data = event.data ? event.data.json() : {};
  const title = data.title || 'ATS KMS Demo Push';
  const options = {
    body: data.body || 'Test notification from KMS demo',
    icon: data.icon || '/icon.png',
    badge: data.badge || '/badge.png',
    tag: data.tag || 'ats-kms-demo',
    data: data.data || {},
    requireInteraction: false,
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
      .then(() => {
        console.log('[Service Worker] Notification displayed:', title);
      })
      .catch((error) => {
        console.error('[Service Worker] Failed to show notification:', error);
      })
  );
});

// Handle notification click events
self.addEventListener('notificationclick', (event) => {
  console.log('[Service Worker] Notification clicked:', event.notification.tag);

  event.notification.close();

  // Open/focus the demo page
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        // If demo is already open, focus it
        for (const client of clientList) {
          if (client.url.includes('/example/phase-1/full') && 'focus' in client) {
            return client.focus();
          }
        }
        // Otherwise open a new window
        if (self.clients.openWindow) {
          return self.clients.openWindow('/example/phase-1/full/');
        }
      })
      .catch((error) => {
        console.error('[Service Worker] Failed to handle notification click:', error);
      })
  );
});

// Handle messages from parent (for mock push delivery in Phase C)
self.addEventListener('message', (event) => {
  console.log('[Service Worker] Message received:', event.data.type);

  if (event.data.type === 'mock-push') {
    const { payload } = event.data;
    const title = payload.title || 'ATS KMS Demo Push';
    const options = {
      body: payload.body || 'Test notification',
      icon: payload.icon,
      badge: payload.badge,
      tag: payload.tag || 'ats-kms-demo',
      data: payload.data || {},
      requireInteraction: false,
    };

    event.waitUntil(
      self.registration.showNotification(title, options)
        .then(() => {
          console.log('[Service Worker] Mock push notification displayed');
          if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({ success: true });
          }
        })
        .catch((error) => {
          console.error('[Service Worker] Failed to show mock push notification:', error);
          if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({ success: false, error: error.message });
          }
        })
    );
  }
});

console.log('[Service Worker] Loaded and ready');
