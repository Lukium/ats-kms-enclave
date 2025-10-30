/**
 * Push Notification Utilities for Phase 1 Full Demo
 *
 * Provides helper functions for:
 * - Service worker registration
 * - Push subscription management
 * - Data conversion utilities
 */

import type { StoredPushSubscription } from './src/types.js';

/**
 * Register the service worker for push notifications
 */
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration> {
  if (!('serviceWorker' in navigator)) {
    throw new Error('Service workers are not supported in this browser');
  }

  try {
    const registration = await navigator.serviceWorker.register('./service-worker.js', {
      scope: './',
    });

    console.log('[Push Utils] Service worker registered:', registration.scope);

    // Wait for service worker to be ready
    await navigator.serviceWorker.ready;
    console.log('[Push Utils] Service worker is active and ready');

    return registration;
  } catch (error) {
    console.error('[Push Utils] Service worker registration failed:', error);
    throw new Error(`Service worker registration failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Subscribe to push notifications using the VAPID public key
 *
 * @param registration - Service worker registration
 * @param vapidPublicKey - VAPID public key (Uint8Array, 65 bytes uncompressed P-256)
 * @returns PushSubscription object from browser
 */
export async function subscribeToPush(
  registration: ServiceWorkerRegistration,
  vapidPublicKey: Uint8Array
): Promise<PushSubscription> {
  if (!('PushManager' in window)) {
    throw new Error('Push API is not supported in this browser');
  }

  // Check current permission status
  console.log('[Push Utils] Current notification permission:', Notification.permission);

  // Request notification permission if not granted
  if (Notification.permission === 'default') {
    console.log('[Push Utils] Requesting notification permission...');

    // Some browsers may silently suppress the prompt - detect this with a timeout
    const permissionBefore = Notification.permission;

    // Add timeout to detect if the prompt is hung
    const timeoutPromise = new Promise<NotificationPermission>((_, reject) => {
      setTimeout(() => {
        reject(new Error('TIMEOUT'));
      }, 5000); // 5 second timeout
    });

    let permission: NotificationPermission;
    try {
      permission = await Promise.race([
        Notification.requestPermission(),
        timeoutPromise
      ]);
      console.log('[Push Utils] Permission result:', permission);
    } catch (error) {
      if (error instanceof Error && error.message === 'TIMEOUT') {
        throw new Error(
          `Browser blocked the notification permission prompt.\n\n` +
          `The permission request timed out after 5 seconds.\n\n` +
          `To fix:\n` +
          `1. Click the site info icon (🔒) in the address bar\n` +
          `2. Find "Notifications" and set it to "Allow"\n` +
          `3. Refresh the page and try again\n\n` +
          `Current URL: ${window.location.href}\n` +
          `Browser: ${navigator.userAgent.split(' ').pop()}`
        );
      }
      throw error;
    }

    // If permission is still 'default', the prompt was likely suppressed
    if (permission === 'default' && permissionBefore === 'default') {
      throw new Error(
        `Browser suppressed the notification permission prompt.\n\n` +
        `This can happen if:\n` +
        `• You previously denied notifications on this site\n` +
        `• Browser security settings are blocking prompts\n\n` +
        `To fix:\n` +
        `1. Check your browser console for security errors\n` +
        `2. Click the site info icon (🔒) in the address bar\n` +
        `3. Manually set Notifications to "Allow"\n` +
        `4. Refresh the page and try again\n\n` +
        `Note: Some browsers require HTTPS or specific contexts for push notifications.`
      );
    }

    if (permission !== 'granted') {
      throw new Error(
        `Notification permission ${permission}. Cannot subscribe to push.\n\n` +
        `To enable notifications:\n` +
        `1. Click the site settings icon in your browser's address bar\n` +
        `2. Change Notifications from "Block" to "Allow"\n` +
        `3. Refresh the page and try again`
      );
    }
  }

  if (Notification.permission !== 'granted') {
    throw new Error(
      'Notification permission denied. Cannot subscribe to push.\n\n' +
      `Current permission status: ${Notification.permission}\n\n` +
      `To enable notifications:\n` +
      `1. Click the site settings icon (🔒 or ⓘ) in your browser's address bar\n` +
      `2. Find "Notifications" and change it to "Allow"\n` +
      `3. Refresh the page and try again`
    );
  }

  try {
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: vapidPublicKey,
    });

    console.log('[Push Utils] Push subscription created:', subscription.endpoint);
    return subscription;
  } catch (error) {
    console.error('[Push Utils] Push subscription failed:', error);
    throw new Error(`Push subscription failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Unsubscribe from push notifications
 *
 * @param registration - Service worker registration
 */
export async function unsubscribeFromPush(registration: ServiceWorkerRegistration): Promise<void> {
  try {
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      await subscription.unsubscribe();
      console.log('[Push Utils] Unsubscribed from push notifications');
    } else {
      console.log('[Push Utils] No active push subscription found');
    }
  } catch (error) {
    console.error('[Push Utils] Unsubscribe failed:', error);
    throw new Error(`Unsubscribe failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Convert a PushSubscription object to StoredPushSubscription format
 *
 * @param rawSub - PushSubscription from browser
 * @param eid - Endpoint ID (user-defined device label)
 * @returns StoredPushSubscription for KMS storage
 */
export function convertPushSubscriptionToStored(
  rawSub: PushSubscription,
  eid: string
): StoredPushSubscription {
  // Get keys from subscription
  const p256dhKey = rawSub.getKey('p256dh');
  const authKey = rawSub.getKey('auth');

  if (!p256dhKey || !authKey) {
    throw new Error('Push subscription is missing required keys (p256dh or auth)');
  }

  return {
    endpoint: rawSub.endpoint,
    expirationTime: rawSub.expirationTime,
    keys: {
      p256dh: arrayBufferToBase64Url(p256dhKey),
      auth: arrayBufferToBase64Url(authKey),
    },
    eid,
    createdAt: Date.now(),
  };
}

/**
 * Convert ArrayBuffer to base64url string
 */
export function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  // Convert base64 to base64url
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Convert base64url string to Uint8Array
 */
export function base64UrlToUint8Array(base64Url: string): Uint8Array {
  // Convert base64url to base64
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const base64Padded = base64 + padding;
  // Decode base64 to binary string
  const binary = atob(base64Padded);
  // Convert binary string to Uint8Array
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Check if push notifications are supported
 */
export function isPushSupported(): boolean {
  return (
    'serviceWorker' in navigator &&
    'PushManager' in window &&
    'Notification' in window
  );
}

/**
 * Get current notification permission status
 */
export function getNotificationPermission(): NotificationPermission {
  return Notification.permission;
}

/**
 * Request notification permission
 */
export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!('Notification' in window)) {
    throw new Error('Notifications are not supported in this browser');
  }

  const permission = await Notification.requestPermission();
  console.log('[Push Utils] Notification permission:', permission);
  return permission;
}
