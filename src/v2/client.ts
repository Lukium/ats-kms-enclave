/**
 * KMS V2 Client Bridge
 *
 * This module runs in the KMS iframe (kms.ats.run) and acts as a minimal
 * bridge between the parent PWA (allthe.services) and the KMS Worker.
 *
 * Security:
 * - Origin validation: Only accepts messages from configured parent origin
 * - Minimal logic: Simple message forwarding, no crypto operations
 * - Worker isolation: All crypto operations delegated to Worker
 *
 * Architecture:
 *   PWA (allthe.services)
 *       ↓ postMessage (cross-origin)
 *   client.ts (iframe @ kms.ats.run)
 *       ↓ postMessage (Worker)
 *   worker.ts (Dedicated Worker)
 */

import type { RPCRequest, RPCResponse, AuthCredentials, StoredPushSubscription } from './types.js';
import { formatError, getErrorMessage } from './error-utils.js';
import { getPRFResults } from './webauthn-types.js';
import { arrayBufferToBase64url, base64urlToArrayBuffer } from './crypto-utils.js';
import { decodeInvite } from './invite.js';
import { identityFingerprint } from './master-identity.js';
import { qrSvg, decodeQr } from './qr.js';

// Global constant injected at build time by esbuild
declare const __WORKER_FILENAME__: string;

/**
 * localStorage flag (first-party kms.ats.run) shared by the setup and unlock
 * popups: whether their success panel auto-closes the window. Default on when
 * unset; a "Close automatically" checkbox writes '1'/'0'.
 */
const POPUP_AUTOCLOSE_KEY = 'kms:autoclose';

/** Seconds the popup success panel counts down before auto-closing. */
const POPUP_CLOSE_COUNTDOWN_SECONDS = 2;

/** How many words the user must re-enter to confirm a recovery-phrase backup (BUG-007). */
const MNEMONIC_CONFIRM_REQUIRED = 3;

/** Normalize a mnemonic word for comparison (BIP39 is lowercase, whitespace-trimmed). */
function normalizeMnemonicWord(word: string): string {
  return word.trim().toLowerCase();
}

/**
 * Configuration for KMSClient
 */
export interface KMSClientConfig {
  /**
   * Origin of the parent PWA (e.g., 'https://allthe.services')
   * Only messages from this origin will be accepted
   */
  parentOrigin: string;

  /**
   * Optional worker URL override (for testing)
   * Defaults to './worker.js' relative to this module
   */
  workerUrl?: string;
}

/**
 * KMS Client Bridge
 *
 * Minimal bridge that forwards messages between parent PWA and KMS Worker.
 * Runs in the KMS iframe main thread.
 */
export class KMSClient {
  private worker: Worker | null = null;
  private parentOrigin: string;
  private workerUrl: string;
  private isInitialized = false;
  private pendingUnlockRequest: RPCRequest | null = null;
  private pendingUnlockRequestId: string | null = null; // For addEnrollmentWithPopup unlock flow

  // Stateless popup mode properties
  private isStatelessPopup: boolean = false;
  private transportPublicKey: string | null = null;
  private transportKeyId: string | null = null;
  private appSalt: string | null = null;
  private userId: string | null = null; // User ID (email) from fullSetup/setupWithPopup params
  private popupState: string | null = null; // Anti-CSRF state token
  private messagePort: MessagePort | null = null; // For direct parent communication
  // Note: hkdfSalt from URL is not used directly in popup (sent to iframe via encrypted message)

  // Popup-side unlock ceremony state (BUG-008: passkey unlock runs in a top-level
  // popup, not the iframe, so password managers key on the top-level domain and the
  // PRF appSalt is not storage-partitioned away).
  private credentialPort: MessagePort | null = null; // MessagePort back to the iframe
  private unlockMethod: 'passkey-prf' | 'passkey-gate' | null = null;
  private unlockCredentialId: string | null = null;

  // IFRAME-side handle to the live messaging-unlock popup's port, so the worker's
  // BUG-007 recovery-phrase ceremony (worker:show-mnemonic) can be relayed to the
  // popup UI. Set while handleMessagingUnlockViaPopup is in flight; else null.
  private messagingPopupPort: MessagePort | null = null;

  // IFRAME-side id of the in-flight Connect ceremony RPC (mint/accept). The
  // ceremony renders in the iframe modal (NOT a popup — no credential is
  // collected), so its outcomes (worker:invite-shown / worker:invite-blob) post
  // straight back to the worker, matched by this id. Set while
  // handleConnectViaIframe is in flight; else null.
  private pendingConnectRequestId: string | null = null;
  // Connect accept-view QR scanner: the live camera stream + a run flag for the
  // decode loop. Both torn down on success, cancel, view change, and modal close.
  private connectScanStream: MediaStream | null = null;
  private connectScanning = false;

  /**
   * Create a new KMS client bridge
   *
   * @param config - Client configuration
   */
  constructor(config: KMSClientConfig) {
    this.parentOrigin = config.parentOrigin;
    // Use injected worker filename from build (for production) or fallback to relative path (for dev)
    this.workerUrl = config.workerUrl ?? (typeof __WORKER_FILENAME__ !== 'undefined' ? __WORKER_FILENAME__ : new URL('./worker.js', import.meta.url).href);
  }

  /**
   * Initialize the KMS client
   *
   * Creates the Worker, sets up message handlers, and signals ready to parent.
   *
   * @throws {Error} If already initialized or Worker creation fails
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async init(): Promise<void> {
    if (this.isInitialized) {
      throw new Error('KMSClient already initialized');
    }

    try {
      // Detect stateless popup mode from URL parameters
      const urlParams = new URLSearchParams(window.location.search);
      this.transportPublicKey = urlParams.get('transportKey');
      this.transportKeyId = urlParams.get('keyId');
      this.appSalt = urlParams.get('appSalt');
      this.popupState = urlParams.get('state');
      const parentOriginParam = urlParams.get('parentOrigin');

      // hkdfSalt is available in URL but not used directly in popup (sent to iframe)
      this.isStatelessPopup = !!(this.transportPublicKey && this.transportKeyId);

      /* eslint-disable no-console */
      console.log('[KMS Client] Popup detection:', {
        url: window.location.href,
        transportKey: this.transportPublicKey?.slice(0, 20) + '...',
        keyId: this.transportKeyId,
        state: this.popupState,
        parentOrigin: parentOriginParam,
        isStatelessPopup: this.isStatelessPopup
      });

      if (this.isStatelessPopup) {
        console.log('[KMS Client] Running in stateless popup mode');
      }
      /* eslint-enable no-console */

      // Setup parent window message handler FIRST (before Worker creation)
      // This ensures popup can receive kms:hello even if Worker init fails
      window.addEventListener('message', this.handleParentMessage.bind(this));

      // Create Dedicated Worker
      this.worker = new Worker(this.workerUrl, {
        type: 'module',
        name: 'kms-worker-v2',
      });

      // Setup Worker message handler
      this.worker.addEventListener('message', this.handleWorkerMessage.bind(this));

      // Setup Worker error handler
      this.worker.addEventListener('error', this.handleWorkerError.bind(this));

      this.isInitialized = true;

      // Signal ready to parent
      if (!this.isStatelessPopup) {
        // Normal iframe mode - use existing mechanism
        this.sendToParent({ type: 'kms:ready' });
      } else {
        /* c8 ignore start - stateless popup mode requires browser integration testing */
        /* eslint-disable no-console */
        // Stateless popup mode - two-phase handshake
        // Parent will send kms:hello (no port), we reply kms:ready
        // Then parent sends kms:connect with MessagePort (transferred once)
        console.log('[KMS Client] Stateless popup: Ready for two-phase handshake (hello → ready → connect)');
        /* eslint-enable no-console */
        /* c8 ignore stop */
      }
    } catch (err: unknown) {
      console.error('[KMS Client] Initialization failed:', err);
      throw new Error(formatError('Failed to initialize KMS client', err));
    }
  }

  /**
   * Handle messages from parent window
   *
   * Validates origin and forwards valid messages to Worker.
   *
   * @param event - Message event from parent
   */
  private handleParentMessage(event: MessageEvent): void {
    // Validate origin
    if (event.origin !== this.parentOrigin) {
      console.warn('[KMS Client] Rejected message from invalid origin:', {
        expected: this.parentOrigin,
        received: event.origin,
      });
      return;
    }

    /* c8 ignore start - stateless popup mode requires browser integration testing */
    /* eslint-disable no-console, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment */
    // Two-phase handshake for stateless popup mode
    // Phase 1: Reply to portless "hello" with "ready"
    if (event.data?.type === 'kms:hello' && this.isStatelessPopup) {
      console.log('[KMS Client] Received kms:hello message');

      // Verify state token matches (anti-CSRF)
      if (event.data.state !== this.popupState) {
        console.error('[KMS Client] State mismatch in kms:hello:', {
          expected: this.popupState,
          received: event.data.state
        });
        return;
      }

      // Reply "ready" on window channel (no port yet)
      console.log('[KMS Client] Replying kms:ready to parent');
      if (event.source) {
        (event.source as WindowProxy).postMessage(
          { type: 'kms:ready', state: this.popupState },
          event.origin
        );
      }

      return;
    }

    // Phase 2: Accept one-time MessagePort transfer
    if (event.data?.type === 'kms:connect' && this.isStatelessPopup) {
      console.log('[KMS Client] Received kms:connect message with port');

      // Verify state token matches (anti-CSRF)
      if (event.data.state !== this.popupState) {
        console.error('[KMS Client] State mismatch in kms:connect:', {
          expected: this.popupState,
          received: event.data.state
        });
        return;
      }

      // Extract transferred MessagePort (should only happen once)
      if (!event.ports || event.ports.length === 0) {
        console.error('[KMS Client] No MessagePort transferred in kms:connect');
        return;
      }

      this.messagePort = event.ports[0] || null;
      console.log('[KMS Client] MessagePort established successfully');

      // Signal to parent that connection is established
      if (this.messagePort) {
        this.messagePort.postMessage({ type: 'kms:connected' });
        console.log('[KMS Client] Sent kms:connected confirmation to parent');
      }

      return;
    }
    /* eslint-enable no-console, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment */
    /* c8 ignore stop */

    // Handle popup responses from parent
    const eventData = event.data as { type?: string; requestId?: string; reason?: string };
    /* c8 ignore start - fullSetup flow handlers: work in manual testing, tested against phase2-demo.allthe.services but cannot be reliably automated due to Playwright notification permission restrictions */
    if (eventData?.type === 'kms:popup-opened') {
      // Parent successfully opened popup - forward to worker
      const requestId = eventData.requestId;
      this.worker?.postMessage({
        type: 'worker:popup-opened',
        requestId,
      });
      return;
    }

    if (eventData?.type === 'kms:popup-blocked') {
      // Parent was unable to open popup - forward to worker
      const requestId = eventData.requestId;
      const reason = eventData.reason || 'Popup was blocked';
      this.worker?.postMessage({
        type: 'worker:popup-blocked',
        requestId,
        reason,
      });
      return;
    }

    if (eventData?.type === 'kms:popup-ready') {
      // Popup is ready - parent sends this with MessagePort
      // This is handled in handleSetupWithPopup's promise listener
      // Don't forward to worker, just let the promise handler receive it
      return;
    }

    // Handle push subscription result from parent (fullSetup flow)
    if (eventData?.type === 'kms:push-subscription-result') {
      const data = eventData as { type: string; requestId?: string; subscription?: StoredPushSubscription; error?: string };
      this.worker?.postMessage({
        type: 'worker:push-subscription-result',
        requestId: data.requestId,
        subscription: data.subscription,
        error: data.error,
      });
      return;
    }

    // Handle test notification result from parent (fullSetup flow)
    if (eventData?.type === 'kms:test-notification-result') {
      const data = eventData as { type: string; requestId?: string; success?: boolean; error?: string };
      this.worker?.postMessage({
        type: 'worker:test-notification-result',
        requestId: data.requestId,
        success: data.success,
        error: data.error,
      });
      return;
    }
    /* c8 ignore stop */

    // Validate client is initialized
    if (!this.isInitialized || !this.worker) {
      console.error('[KMS Client] Received message before initialization');
      return;
    }

    const request = event.data as RPCRequest;

    // Intercept operations that require authentication
    // These will show modal, collect credentials, then execute.
    //
    // Messaging unlock (setupMessaging / setupAccountRoot / openMessaging) rides
    // this SAME path: the enclave collects credentials in its own modal so the
    // PWA never constructs them. This is the only place a passkey-prf unlock can
    // happen — the appSalt lives in this (kms.ats.run) origin's localStorage and
    // is unreadable from the parent PWA. The PWA sends only { userId, ... }; the
    // client injects the collected credentials before forwarding to the worker.
    const authRequiredMethods = [
      'createLease',
      'generateVAPID',
      'signJWT',
      'regenerateVAPID',
      'addEnrollment',
      'setupMessaging',
      'provisionMessaging',
      'provisionMessagingFromMnemonic',
      'setupAccountRoot',
      'openMessaging',
    ];
    // Messaging unlock (setupMessaging / setupAccountRoot / openMessaging) now
    // collects ALL credentials — passphrase AND passkey — in the top-level
    // kms.ats.run popup. The iframe modal is NOT shown for these; the popup owns
    // the UI so the password manager and PRF appSalt work at the top level. Every
    // OTHER authRequired method keeps using the iframe modal (showUnlockModal).
    const messagingUnlockMethods = [
      'setupMessaging',
      'provisionMessaging',
      'provisionMessagingFromMnemonic',
      'setupAccountRoot',
      'openMessaging',
    ];
    if (request?.method && authRequiredMethods.includes(request.method)) {
      if (messagingUnlockMethods.includes(request.method)) {
        void this.handleMessagingUnlockViaPopup(request).catch((err: unknown) => {
          console.error('[KMS Client] Messaging unlock via popup failed:', err);
          if (request.id) {
            this.sendToParent({
              id: request.id,
              error: formatError('Messaging unlock failed', err),
            });
          }
        });
      } else {
        this.showUnlockModal(request);
      }
      return; // Don't forward to worker yet
    }

    // Connect ceremony (rooms-and-trust §3.2/§3.4): mint/accept are session-scoped
    // (sid/token) with NO credential collection, so — unlike unlock — they do NOT
    // need a top-level popup. They render in the IFRAME modal (the enclave surface
    // that already holds the vault); the room secret is only ever displayed (mint)
    // or entered (accept) inside the iframe, never in the PWA. The popup exists
    // solely for first-party WebAuthn/passkey unlock, which this ceremony skips.
    const connectCeremonyMethods = ['mintInvite', 'acceptInvite'];
    if (request?.method && connectCeremonyMethods.includes(request.method)) {
      try {
        this.handleConnectViaIframe(request);
      } catch (err: unknown) {
        console.error('[KMS Client] Connect ceremony via iframe failed:', err);
        if (request.id) {
          this.sendToParent({ id: request.id, error: formatError('Connect ceremony failed', err) });
        }
      }
      return; // Don't forward to worker yet — handleConnectViaIframe forwards it.
    }

    // Special case: extendLeases only requires auth if requestAuth flag is set
    if (
      request?.method === 'extendLeases' &&
      request.params &&
      typeof request.params === 'object' &&
      'requestAuth' in request.params &&
      request.params.requestAuth === true
    ) {
      this.showUnlockModal(request);
      return; // Don't forward to worker yet
    }

    // Forward to Worker
    try {
      this.worker.postMessage(event.data);
    } catch (err: unknown) {
      console.error('[KMS Client] Failed to forward message to Worker:', err);

      // Send error response to parent
      if (request?.id) {
        this.sendToParent({
          id: request.id,
          error: formatError('Failed to forward message', err),
        });
      }
    }
  }

  /**
   * Handle messages from Worker
   *
   * Forwards Worker responses to parent window.
   * Intercepts special internal messages (like popup requests) and handles them
   * in the client before forwarding to parent.
   *
   * @param event - Message event from Worker
   */
  private handleWorkerMessage(event: MessageEvent): void {
    try {
      const data = event.data as RPCResponse | { type: string; [key: string]: unknown };

      // Intercept setup-with-popup request from worker
      if ('type' in data && data.type === 'worker:setup-with-popup') {
        void this.handleSetupWithPopup({
          requestId: data.requestId as string,
          userId: data.userId as string,
          popupURL: data.popupURL as string,
          transportKey: data.transportKey as string,
          transportKeyId: data.transportKeyId as string,
          appSalt: data.appSalt as string,
          hkdfSalt: data.hkdfSalt as string,
        });
        return;
      }

      // Intercept unlock request from worker (for addEnrollmentWithPopup)
      if ('type' in data && data.type === 'worker:request-unlock') {
        void this.handleUnlockRequest({
          requestId: data.requestId as string,
          userId: data.userId as string,
        });
        return;
      }

      // BUG-007: worker minted a fresh account root and wants the user to back up
      // the recovery phrase. Relay it to the top-level popup (where the messaging
      // UI lives) over the private port — it must NOT reach the parent PWA.
      if ('type' in data && data.type === 'worker:show-mnemonic') {
        if (this.messagingPopupPort) {
          this.messagingPopupPort.postMessage({
            type: 'popup:show-mnemonic',
            mnemonic: data.mnemonic as string,
          });
        } else {
          // No popup channel to show it in → cancel so the worker persists nothing.
          this.worker?.postMessage({
            type: 'worker:mnemonic-cancelled',
            requestId: data.requestId as string,
            reason: 'No popup available to confirm the recovery phrase',
          });
        }
        return;
      }

      // Restore: worker wants the user to ENTER their recovery phrase. Relay to the
      // top-level popup (where messaging UI lives) over the private port — the
      // entered phrase must NOT reach the parent PWA.
      if ('type' in data && data.type === 'worker:collect-mnemonic') {
        if (this.messagingPopupPort) {
          this.messagingPopupPort.postMessage({ type: 'popup:collect-mnemonic' });
        } else {
          this.worker?.postMessage({
            type: 'worker:mnemonic-cancelled',
            requestId: data.requestId as string,
            reason: 'No popup available to enter the recovery phrase',
          });
        }
        return;
      }

      // Connect ceremony (rooms §3.2/§3.4): render the invite in the IFRAME modal.
      // mint → display the (secret-bearing) link to share; accept → collect + confirm
      // a pasted link. The blob is shown/entered inside the iframe (same origin as
      // the vault) and its outcomes post straight back to the worker — it never
      // reaches the parent PWA. worker:show-invite/collect-invite only arrive while a
      // handleConnectViaIframe ceremony is in flight (pendingConnectRequestId set).
      if ('type' in data && data.type === 'worker:show-invite') {
        this.renderConnectShare(data.blob as string);
        return;
      }
      if ('type' in data && data.type === 'worker:collect-invite') {
        this.renderConnectAccept();
        return;
      }

      // Intercept push subscription request from worker (for fullSetup)
      if ('type' in data && data.type === 'worker:request-push-subscription') {
        void this.handlePushSubscriptionRequest({
          requestId: data.requestId as string,
          vapidPublicKey: data.vapidPublicKey as string,
          userId: data.userId as string,
        });
        return;
      }

      // Intercept test notification request from worker (for fullSetup)
      if ('type' in data && data.type === 'worker:send-test-notification') {
        void this.handleTestNotification({
          requestId: data.requestId as string,
          jwt: data.jwt as string,
          subscription: data.subscription as StoredPushSubscription,
          vapidPublicKey: data.vapidPublicKey as string,
        });
        return;
      }

      // Intercept popup request from worker
      if ('type' in data && data.type === 'worker:request-popup-from-parent') {
        this.handleWorkerPopupRequest(
          data.url as string,
          data.requestId as string
        );
        return;
      }

      // Forward all other messages to parent
      this.sendToParent(data);
    } catch (err: unknown) {
      console.error('[KMS Client] Failed to forward message to parent:', err);
    }
  }

  /**
   * Handle worker request to ask parent to open popup.
   *
   * Worker cannot directly communicate with parent (cross-origin in iframe mode),
   * so we forward the request from worker → client → parent.
   *
   * @param url - Popup URL
   * @param requestId - Request ID for correlation
   */
  private handleWorkerPopupRequest(url: string, requestId: string): void {
    if (!this.parentOrigin) {
      // Notify worker that request failed
      this.worker?.postMessage({
        type: 'worker:popup-blocked',
        requestId,
        reason: 'Parent origin not configured',
      });
      return;
    }

    // Forward request to parent
    const targetWindow = window.parent && window.parent !== window ? window.parent : null;
    if (!targetWindow) {
      this.worker?.postMessage({
        type: 'worker:popup-blocked',
        requestId,
        reason: 'No parent window available',
      });
      return;
    }

    try {
      targetWindow.postMessage(
        {
          type: 'kms:request-popup',
          url,
          requestId,
        },
        this.parentOrigin
      );

      // Parent will respond with kms:popup-opened or kms:popup-blocked
      // which handleParentMessage will receive and forward to worker
    } catch (err: unknown) {
      console.error('[KMS Client] Failed to send popup request to parent:', err);
      this.worker?.postMessage({
        type: 'worker:popup-blocked',
        requestId,
        reason: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  }

  /**
   * Ask the parent PWA to open a top-level popup and wait for the private
   * MessagePort the parent transfers back once the popup signals ready.
   *
   * The parent is the only party that can open a popup (the iframe is sandboxed
   * without `allow-popups`); it brokers a MessageChannel — one port to the iframe
   * (returned here), one to the popup — so the iframe and popup talk directly and
   * privately without the parent seeing the traffic. Shared by the setup-popup
   * flow ({@link handleSetupWithPopup}) and the unlock-popup flow
   * ({@link handleWebAuthnUnlockViaPopup}).
   *
   * @param popupURL - Fully-built popup URL (parentOrigin already appended)
   * @param requestId - Correlation id echoed by the parent in `kms:popup-ready`
   * @returns The iframe-side MessagePort to the popup
   */
  private async openPopupChannel(popupURL: string, requestId: string): Promise<MessagePort> {
    if (!this.parentOrigin) {
      throw new Error('Parent origin not configured');
    }

    const targetWindow = window.parent && window.parent !== window ? window.parent : null;
    if (!targetWindow) {
      throw new Error('No parent window available');
    }

    // Ask parent to open popup
    targetWindow.postMessage(
      {
        type: 'kms:request-popup',
        url: popupURL,
        requestId,
      },
      this.parentOrigin
    );

    // Wait for popup ready signal and MessagePort from parent.
    // Parent creates MessageChannel and sends one port to iframe, one to popup.
    return new Promise<MessagePort>((resolve, reject) => {
      const timeout = setTimeout(() => {
        window.removeEventListener('message', handlePopupReady);
        reject(new Error('Popup ready timeout'));
      }, 30000); // 30 second timeout

      const handlePopupReady = (event: MessageEvent): void => {
        // Parent forwards popup-ready and transfers MessagePort
        const data = event.data as { type?: string; requestId?: string };
        if (data?.type === 'kms:popup-ready' && data.requestId === requestId) {
          clearTimeout(timeout);
          window.removeEventListener('message', handlePopupReady);
          // MessagePort is in event.ports[0]
          if (event.ports && event.ports.length > 0 && event.ports[0]) {
            resolve(event.ports[0]);
          } else {
            reject(new Error('No MessagePort received with popup-ready'));
          }
        }
      };

      window.addEventListener('message', handlePopupReady);
    });
  }

  /**
   * Orchestrate complete popup setup flow.
   *
   * This method handles the entire popup flow for KMS-only credential collection:
   * 1. Request parent to open popup window
   * 2. Wait for popup ready signal (kms:popup-ready)
   * 3. Establish MessageChannel with popup
   * 4. Send transport parameters to popup via MessagePort
   * 5. Receive encrypted credentials from popup
   * 6. Send credentials back to worker for processing
   *
   * @param params - Setup parameters from worker
   */
  private async handleSetupWithPopup(params: {
    requestId: string;
    userId: string;
    popupURL: string;
    transportKey: string;
    transportKeyId: string;
    appSalt: string;
    hkdfSalt: string;
  }): Promise<void> {
    try {
      // Step 1: Request parent to open popup.
      // These preconditions are validated synchronously (before any await) so the
      // worker:popup-error is posted in the same tick — openPopupChannel repeats the
      // same checks defensively, but that path runs a microtask later.
      if (!this.parentOrigin) {
        throw new Error('Parent origin not configured');
      }
      if (!(window.parent && window.parent !== window)) {
        throw new Error('No parent window available');
      }

      // Add parentOrigin to popup URL so popup knows where to send ready signal
      const popupURL = new URL(params.popupURL);
      popupURL.searchParams.set('parentOrigin', this.parentOrigin);

      // Steps 2/3: Ask parent to open popup and wait for the transferred MessagePort.
      const port1 = await this.openPopupChannel(popupURL.toString(), params.requestId);

      // Step 4: Send transport parameters to popup via MessagePort
      // Wait for popup to receive the channel and respond
      const credentialsPromise = new Promise<{
        method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
        transportKeyId: string;
        userId: string;
        ephemeralPublicKey: string;
        iv: string;
        encryptedCredentials: string;
      }>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Credentials timeout'));
        }, 300000); // 5 minute timeout for user to enter credentials

        port1.onmessage = (event: MessageEvent): void => {
          const data = event.data as {
            type?: string;
            method?: 'passphrase' | 'passkey-prf' | 'passkey-gate';
            transportKeyId?: string;
            userId?: string;
            ephemeralPublicKey?: string;
            iv?: string;
            encryptedCredentials?: string;
            reason?: string;
          };

          if (data?.type === 'popup:credentials') {
            clearTimeout(timeout);
            port1.close();
            resolve({
              method: data.method as 'passphrase' | 'passkey-prf' | 'passkey-gate',
              transportKeyId: data.transportKeyId as string,
              userId: data.userId as string,
              ephemeralPublicKey: data.ephemeralPublicKey as string,
              iv: data.iv as string,
              encryptedCredentials: data.encryptedCredentials as string,
            });
          } else if (data?.type === 'popup:error') {
            clearTimeout(timeout);
            port1.close();
            reject(new Error(data.reason || 'Popup error'));
          } else if (data?.type === 'popup:connected') {
            // Popup acknowledged connection, waiting for credentials
            /* eslint-disable-next-line no-console */
            console.log('[KMS Client] Popup connected, waiting for credentials...');
          }
        };
      });

      // Step 3: Send transport params to popup via MessagePort
      // Parent already transferred port2 to popup, so we communicate via port1
      port1.postMessage({
        type: 'kms:connect',
        transportKey: params.transportKey,
        transportKeyId: params.transportKeyId,
        appSalt: params.appSalt,
        hkdfSalt: params.hkdfSalt,
        userId: params.userId,
      });

      // Step 5: Wait for encrypted credentials from popup
      const credentials = await credentialsPromise;

      // Step 6: Send credentials back to worker
      this.worker?.postMessage({
        type: 'worker:popup-credentials',
        requestId: params.requestId,
        credentials,
      });
    } catch (err: unknown) {
      console.error('[KMS Client] Setup with popup failed:', err);
      this.worker?.postMessage({
        type: 'worker:popup-error',
        requestId: params.requestId,
        reason: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  }

  /**
   * Handle unlock request from worker (for addEnrollmentWithPopup)
   *
   * Worker requests unlock modal to get existing credentials AFTER popup completes.
   * This ensures sequential flow: popup first, then unlock.
   *
   * @param params - Parameters from worker unlock request
   */
  private handleUnlockRequest(params: {
    requestId: string;
    userId: string;
  }): void {
    try {
      // Unlock request from worker for addEnrollment flow

      // Store requestId for when credentials are collected
      this.pendingUnlockRequestId = params.requestId;

      // Tell parent to show iframe (so unlock modal is visible)
      this.sendToParent({
        type: 'kms:show-iframe',
      });

      // Create a dummy RPC request to trigger unlock modal
      // The unlock modal expects pendingUnlockRequest to have userId in params
      // Using 'getEnrollments' as a placeholder method (doesn't matter for this flow)
      this.pendingUnlockRequest = {
        id: params.requestId,
        method: 'getEnrollments',
        params: { userId: params.userId },
      };

      // Show unlock modal - this will collect credentials via WebAuthn or passphrase
      this.showUnlockModal(this.pendingUnlockRequest);
    } catch (err: unknown) {
      console.error('[KMS Client] Unlock request failed:', err);
      this.worker?.postMessage({
        type: 'worker:unlock-error',
        requestId: params.requestId,
        reason: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  }

  /**
   * Handle push subscription request from worker (for fullSetup).
   * Asks parent PWA to subscribe to push notifications with the VAPID public key.
   *
   * @param params - Parameters from worker push subscription request
   */
  /* c8 ignore start - fullSetup flow: works in manual testing, tested against phase2-demo.allthe.services but cannot be reliably automated due to Playwright notification permission restrictions */
  private handlePushSubscriptionRequest(params: {
    requestId: string;
    vapidPublicKey: string;
    userId: string;
  }): void {
    try {
      // Ask parent to subscribe to push
      const targetWindow = window.parent && window.parent !== window ? window.parent : null;
      if (!targetWindow) {
        throw new Error('No parent window available');
      }

      targetWindow.postMessage(
        {
          type: 'kms:request-push-subscription',
          requestId: params.requestId,
          vapidPublicKey: params.vapidPublicKey,
          userId: params.userId,
        },
        this.parentOrigin
      );

      // Parent will respond with kms:push-subscription-result
      // which handleParentMessage will receive and forward to worker
    } catch (err: unknown) {
      console.error('[KMS Client] Push subscription request failed:', err);
      this.worker?.postMessage({
        type: 'worker:push-subscription-result',
        requestId: params.requestId,
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  }
  /* c8 ignore stop */

  /**
   * Handle test notification request from worker (for fullSetup).
   * Asks parent PWA to send a test push notification.
   *
   * @param params - Parameters from worker test notification request
   */
  /* c8 ignore start - fullSetup flow: works in manual testing, tested against phase2-demo.allthe.services but cannot be reliably automated due to Playwright notification permission restrictions */
  private handleTestNotification(params: {
    requestId: string;
    jwt: string;
    subscription: StoredPushSubscription;
    vapidPublicKey: string;
  }): void {
    try {
      // Ask parent to send test notification
      const targetWindow = window.parent && window.parent !== window ? window.parent : null;
      if (!targetWindow) {
        throw new Error('No parent window available');
      }

      targetWindow.postMessage(
        {
          type: 'kms:send-test-notification',
          requestId: params.requestId,
          jwt: params.jwt,
          subscription: params.subscription,
          vapidPublicKey: params.vapidPublicKey,
        },
        this.parentOrigin
      );

      // Parent will respond with kms:test-notification-result
      // which handleParentMessage will receive and forward to worker
    } catch (err: unknown) {
      console.error('[KMS Client] Test notification request failed:', err);
      this.worker?.postMessage({
        type: 'worker:test-notification-result',
        requestId: params.requestId,
        success: false,
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  }
  /* c8 ignore stop */

  /**
   * Handle Worker errors
   *
   * Logs errors and sends error response to parent if possible.
   *
   * @param event - Error event from Worker
   */
  private handleWorkerError(event: ErrorEvent): void {
    console.error('[KMS Client] Worker error:', {
      message: event.message,
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno,
    });

    // Worker errors are often fatal - consider reinitializing
    // For now, just log the error
  }

  /**
   * Send message to parent window
   *
   * @param data - Data to send
   */
  private sendToParent(data: RPCResponse | { type: string; [key: string]: unknown }): void {
    // Determine target window based on context
    // Popup mode: use window.opener (popup was opened by parent)
    // Iframe mode: use window.parent (iframe is embedded in parent)

    /* eslint-disable @typescript-eslint/no-unsafe-assignment */
    // More robust popup detection: window.opener must exist, not be null, and not be self
    const hasValidOpener = window.opener && window.opener !== null && window.opener !== window;
    const hasValidParent = window.parent && window.parent !== window;

    // Prefer opener if available (popup mode), otherwise use parent (iframe mode)
    const targetWindow = hasValidOpener ? window.opener : (hasValidParent ? window.parent : null);

    if (!targetWindow) {
      console.error('[KMS Client] No parent/opener window available', {
        hasValidOpener,
        hasValidParent
      });
      /* eslint-enable @typescript-eslint/no-unsafe-assignment */
      return;
    }
     

    try {
      (targetWindow as Window).postMessage(data, this.parentOrigin);
    } catch (err: unknown) {
      console.error('[KMS Client] Failed to send message to parent/opener:', err);
    }
  }

  /**
   * Get enrollments for a user
   *
   * @param userId - User ID to check
   * @returns Array of enrollment IDs
   */
  private async getEnrollments(userId: string): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const requestId = `get-enrollments-${Date.now()}`;
      const request: RPCRequest = {
        id: requestId,
        method: 'getEnrollments',
        params: { userId },
      };

      const handler = (event: MessageEvent): void => {
        const response = event.data as RPCResponse;
        if (response.id === requestId) {
          this.worker?.removeEventListener('message', handler);
          if (response.error) {
            const errorMsg = typeof response.error === 'string' ? response.error : response.error.message;
          reject(new Error(errorMsg));
          } else {
            resolve((response.result as { enrollments: string[] } | undefined)?.enrollments || []);
          }
        }
      };

      this.worker?.addEventListener('message', handler);
      this.worker?.postMessage(request);

      // Timeout after 5s
      setTimeout(() => {
        this.worker?.removeEventListener('message', handler);
        reject(new Error('getEnrollments timeout'));
      }, 5000);
    });
  }

  /**
   * Show unlock modal in iframe
   *
   * Displays authentication modal and sets up event handlers.
   * The modal UI is bound to the iframe origin (kms.ats.run), ensuring
   * WebAuthn credentials are bound to the correct Relying Party.
   *
   * @param request - Original triggerUnlockUI request (null if triggered by parent)
   */
  /* c8 ignore start - DOM manipulation and UI event handlers tested via Playwright */
  private showUnlockModal(request: RPCRequest | null): void {
    this.pendingUnlockRequest = request;

    const modal = document.getElementById('unlock-modal');
    const webauthnBtn = document.getElementById('kms-webauthn-btn');
    const passphraseInput = document.getElementById('kms-passphrase-input') as HTMLInputElement;
    const passphraseBtn = document.getElementById('kms-passphrase-btn');

    if (!modal || !webauthnBtn || !passphraseInput || !passphraseBtn) {
      console.error('[KMS Client] Modal elements not found');

      if (request) {
        this.sendToParent({
          id: request.id,
          error: 'Modal UI not found',
        });
      } else {
        // Notify parent of error
        this.sendToParent({
          type: 'kms:unlock-error',
          error: 'Modal UI not found',
        });
      }
      return;
    }

    // Show modal
    modal.classList.remove('hidden');

    // Setup WebAuthn button handler
    webauthnBtn.onclick = (): Promise<void> => this.handleWebAuthnUnlock();

    // Setup passphrase button handler
    passphraseBtn.onclick = (): Promise<void> => this.handlePassphraseUnlock(passphraseInput.value);

    // Setup Enter key for passphrase
    passphraseInput.onkeydown = (e): void => {
      if (e.key === 'Enter') {
        void this.handlePassphraseUnlock(passphraseInput.value).catch((err: unknown) => {
          console.error('[KMS Client] Passphrase unlock failed:', err);
          this.showError(err instanceof Error ? err.message : 'Unknown error');
        });
      }
    };

    // Clear any previous errors
    this.hideError();
  }

  /**
   * Handle WebAuthn unlock attempt
   *
   * Calls navigator.credentials.get() in iframe context, ensuring
   * credentials are bound to kms.ats.run (correct RP).
   * Automatically detects PRF support and uses appropriate method.
   */
  private async handleWebAuthnUnlock(): Promise<void> {
    this.showLoading();
    this.hideError();

    try {
      // BUG-008: passkey unlock cannot run reliably in this iframe — password
      // managers key passkeys on the TOP-LEVEL domain and the PRF appSalt is
      // storage-partitioned away. So we route the WebAuthn ceremony to a top-level
      // kms.ats.run popup instead. Passphrase unlock stays in the iframe.
      if (!this.pendingUnlockRequest) {
        throw new Error('No pending operation');
      }

      // Resolve userId from the pending request params
      const userId = (this.pendingUnlockRequest.params as { userId?: string } | undefined)?.userId;
      if (!userId) {
        throw new Error('userId not found in request params');
      }

      // Ask the worker for the authoritative unlock params. The appSalt MUST come
      // from the stored PasskeyPRFConfigV2 (worker IndexedDB) — never localStorage,
      // never fabricated. Throws 'No passkey enrollment found for this user' when
      // the user has no passkey enrollment (same error as before).
      const unlockParams = await this.getPasskeyUnlockParams(userId);

      await this.handleWebAuthnUnlockViaPopup({ ...unlockParams, userId });
    } catch (err: unknown) {
      this.hideLoading();
      this.showError(`WebAuthn failed: ${getErrorMessage(err)}`);
      console.error('[KMS Client] WebAuthn unlock failed:', err);
    }
  }

  /**
   * Fetch the authoritative passkey unlock parameters from the worker.
   *
   * Mirrors {@link getEnrollments}' request/response round-trip. Returns the
   * enrollment `method`, the PRF `appSalt` (base64url, from the stored config's
   * `kdf.appSalt`), the stored `credentialId` (base64url, if any), and the `rpId`.
   */
  private async getPasskeyUnlockParams(userId: string): Promise<{
    method: 'passkey-prf' | 'passkey-gate';
    appSalt?: string;
    credentialId?: string;
    rpId?: string;
  }> {
    return new Promise((resolve, reject) => {
      const requestId = `get-passkey-unlock-params-${Date.now()}`;
      const request: RPCRequest = {
        id: requestId,
        method: 'getPasskeyUnlockParams',
        params: { userId },
      };

      const handler = (event: MessageEvent): void => {
        const response = event.data as RPCResponse;
        if (response.id === requestId) {
          this.worker?.removeEventListener('message', handler);
          if (response.error) {
            const errorMsg = typeof response.error === 'string' ? response.error : response.error.message;
            reject(new Error(errorMsg));
          } else {
            resolve(response.result as {
              method: 'passkey-prf' | 'passkey-gate';
              appSalt?: string;
              credentialId?: string;
              rpId?: string;
            });
          }
        }
      };

      this.worker?.addEventListener('message', handler);
      this.worker?.postMessage(request);

      // Timeout after 5s
      setTimeout(() => {
        this.worker?.removeEventListener('message', handler);
        reject(new Error('getPasskeyUnlockParams timeout'));
      }, 5000);
    });
  }

  /**
   * Fetch the messaging unlock options from the worker (BUG-008 follow-up).
   *
   * Mirrors {@link getPasskeyUnlockParams}' round-trip but returns the boolean
   * method flags (`hasPassphrase` / `hasPasskeyPrf` / `hasPasskeyGate`) the
   * top-level popup needs to render its unlock modal, plus the PRF `appSalt`,
   * stored `credentialId`, and `rpId` (all sourced from the worker config).
   */
  private async getMessagingUnlockOptions(userId: string): Promise<{
    hasPassphrase: boolean;
    hasPasskeyPrf: boolean;
    hasPasskeyGate: boolean;
    appSalt?: string;
    credentialId?: string;
    rpId?: string;
  }> {
    return new Promise((resolve, reject) => {
      const requestId = `get-messaging-unlock-options-${Date.now()}`;
      const request: RPCRequest = {
        id: requestId,
        method: 'getMessagingUnlockOptions',
        params: { userId },
      };

      const handler = (event: MessageEvent): void => {
        const response = event.data as RPCResponse;
        if (response.id === requestId) {
          this.worker?.removeEventListener('message', handler);
          if (response.error) {
            const errorMsg = typeof response.error === 'string' ? response.error : response.error.message;
            reject(new Error(errorMsg));
          } else {
            resolve(response.result as {
              hasPassphrase: boolean;
              hasPasskeyPrf: boolean;
              hasPasskeyGate: boolean;
              appSalt?: string;
              credentialId?: string;
              rpId?: string;
            });
          }
        }
      };

      this.worker?.addEventListener('message', handler);
      this.worker?.postMessage(request);

      // Timeout after 5s
      setTimeout(() => {
        this.worker?.removeEventListener('message', handler);
        reject(new Error('getMessagingUnlockOptions timeout'));
      }, 5000);
    });
  }

  /**
   * Run the passkey unlock via a top-level kms.ats.run popup (BUG-008, approach B).
   *
   * Opens a `mode=unlock` popup through the parent broker, hands it the unlock
   * params over the private MessagePort, and awaits the popup's WebAuthn result.
   * The PRF output travels back as PLAINTEXT over the port (both ends are enclave
   * code) — there is no encrypted-credential/transport-key round trip. The
   * reconstructed `credentials` object is injected downstream IDENTICALLY to the
   * previous iframe unlock path.
   */
  private async handleWebAuthnUnlockViaPopup(unlockParams: {
    method: 'passkey-prf' | 'passkey-gate';
    appSalt?: string;
    credentialId?: string;
    userId: string;
  }): Promise<void> {
    const { method, appSalt, credentialId, userId } = unlockParams;
    const requestId = `unlock-popup-${Date.now()}`;

    // Distinct mode=unlock popup on the top-level enclave origin.
    const popupURL = `${location.origin}/?mode=unlock&parentOrigin=${this.parentOrigin}`;

    const port = await this.openPopupChannel(popupURL, requestId);

    // Await the popup's WebAuthn result over the private MessagePort.
    const credentialsPromise = new Promise<{
      method: 'passkey-prf' | 'passkey-gate';
      prfOutput?: number[];
    }>((resolve, reject) => {
      const timeout = setTimeout(() => {
        port.close();
        reject(new Error('Popup unlock timeout'));
      }, 120000); // ~2 minutes for the user to complete the ceremony

      port.onmessage = (event: MessageEvent): void => {
        const data = event.data as {
          type?: string;
          method?: 'passkey-prf' | 'passkey-gate';
          prfOutput?: number[];
          error?: string;
        };

        if (data?.type === 'popup:credentials') {
          clearTimeout(timeout);
          port.close();
          const resolvedMethod = data.method ?? 'passkey-prf';
          resolve(
            data.prfOutput
              ? { method: resolvedMethod, prfOutput: data.prfOutput }
              : { method: resolvedMethod }
          );
        } else if (data?.type === 'popup:error') {
          clearTimeout(timeout);
          port.close();
          reject(new Error(data.error || 'Popup unlock error'));
        } else if (data?.type === 'popup:connected') {
          /* eslint-disable-next-line no-console */
          console.log('[KMS Client] Unlock popup connected, awaiting ceremony...');
        }
      };
    });

    // Tell the popup which ceremony to run (plaintext params — enclave-to-enclave).
    port.postMessage({
      type: 'kms:connect',
      operation: 'unlock',
      method,
      appSalt,
      credentialId,
      userId,
    });

    const popupResult = await credentialsPromise;

    // Reconstruct AuthCredentials in exactly the shape the worker expects today.
    let credentials: AuthCredentials;
    if (method === 'passkey-prf') {
      if (!popupResult.prfOutput) {
        throw new Error('No PRF output returned from popup');
      }
      // Port carries a plain number[]; reconstruct the ArrayBuffer the worker wants.
      const prfOutput = new Uint8Array(popupResult.prfOutput).buffer;
      credentials = { method: 'passkey-prf', prfOutput, userId };
    } else {
      credentials = { method: 'passkey-gate', userId };
    }

    if (!this.pendingUnlockRequest) {
      throw new Error('No pending operation');
    }

    // IDENTICAL downstream injection to the previous handleWebAuthnUnlock.
    if (this.pendingUnlockRequestId) {
      // addEnrollmentWithPopup unlock flow → send credentials straight to worker.
      this.worker?.postMessage({
        type: 'worker:unlock-credentials',
        requestId: this.pendingUnlockRequestId,
        credentials,
      });

      this.pendingUnlockRequestId = null;
      this.pendingUnlockRequest = null;

      this.hideModal();
      this.hideLoading();
    } else {
      // Normal unlock flow for RPC methods.
      const requestWithCredentials: RPCRequest = {
        ...this.pendingUnlockRequest,
        params: {
          ...(this.pendingUnlockRequest.params as Record<string, unknown>),
          credentials,
        },
      };

      this.setupUnlockResponseListener(requestWithCredentials);
      this.worker?.postMessage(requestWithCredentials);
    }
  }

  /**
   * Run messaging unlock via a top-level kms.ats.run popup (BUG-008 follow-up).
   *
   * ALL messaging auth (passphrase AND passkey) happens in the popup: the iframe
   * modal is never shown. We fetch the unlock options from the worker, open the
   * `mode=unlock` popup, hand it the options over the private MessagePort, and
   * await whichever credential the user produces. Credentials travel back as
   * PLAINTEXT over the port (both ends are enclave code); the reconstructed
   * `AuthCredentials` is injected downstream IDENTICALLY to
   * {@link handleWebAuthnUnlockViaPopup} / {@link handlePassphraseUnlock}.
   */
  private async handleMessagingUnlockViaPopup(request: RPCRequest): Promise<void> {
    this.pendingUnlockRequest = request;

    const userId = (request.params as { userId?: string } | undefined)?.userId;
    if (!userId) {
      throw new Error('userId not found in request params');
    }

    // Authoritative flags + PRF appSalt from the worker config (never localStorage).
    const options = await this.getMessagingUnlockOptions(userId);

    const requestId = `unlock-popup-${Date.now()}`;
    const popupURL = `${location.origin}/?mode=unlock&parentOrigin=${this.parentOrigin}`;
    const port = await this.openPopupChannel(popupURL, requestId);
    // Expose the port so the worker's BUG-007 recovery-phrase ceremony
    // (worker:show-mnemonic) can be relayed to this popup. Cleared when done.
    this.messagingPopupPort = port;
    const rpcId = request.id;

    // Await whichever credential the user picks in the popup modal.
    const credentialsPromise = new Promise<{
      method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
      passphrase?: string;
      prfOutput?: number[];
    }>((resolve, reject) => {
      const timeout = setTimeout(() => {
        port.close();
        reject(new Error('Popup unlock timeout'));
      }, 120000); // ~2 minutes for the user to complete the ceremony

      port.onmessage = (event: MessageEvent): void => {
        const data = event.data as {
          type?: string;
          method?: 'passphrase' | 'passkey-prf' | 'passkey-gate';
          passphrase?: string;
          prfOutput?: number[];
          error?: string;
          mnemonic?: string;
        };

        if (data?.type === 'popup:credentials') {
          clearTimeout(timeout);
          // Keep the port OPEN so we can relay the unlock outcome back to the
          // popup (popup:unlock-result) once the worker responds — the popup
          // uses it to show the green confirmation + auto-close.
          resolve({
            method: data.method ?? 'passphrase',
            ...(data.passphrase !== undefined ? { passphrase: data.passphrase } : {}),
            ...(data.prfOutput ? { prfOutput: data.prfOutput } : {}),
          });
        } else if (data?.type === 'popup:mnemonic-confirmed') {
          // BUG-007: user confirmed the recovery-phrase backup in the popup →
          // let the worker persist the account root (keyed by the RPC id).
          if (rpcId) {
            this.worker?.postMessage({ type: 'worker:mnemonic-confirmed', requestId: rpcId });
          }
        } else if (data?.type === 'popup:mnemonic-entered') {
          // Restore: user entered a recovery phrase in the popup → hand it to the
          // worker (keyed by the RPC id) to import the account root. The phrase
          // stays inside kms.ats.run; it never reaches the parent PWA.
          if (rpcId) {
            this.worker?.postMessage({
              type: 'worker:mnemonic-entered',
              requestId: rpcId,
              mnemonic: typeof data.mnemonic === 'string' ? data.mnemonic : '',
            });
          }
        } else if (data?.type === 'popup:mnemonic-cancelled') {
          // BUG-007: user cancelled the backup → worker persists nothing.
          if (rpcId) {
            this.worker?.postMessage({
              type: 'worker:mnemonic-cancelled',
              requestId: rpcId,
              reason: 'Recovery-phrase backup was cancelled',
            });
          }
        } else if (data?.type === 'popup:error') {
          clearTimeout(timeout);
          port.close();
          reject(new Error(data.error || 'Popup unlock error'));
        } else if (data?.type === 'popup:connected') {
          /* eslint-disable-next-line no-console */
          console.log('[KMS Client] Messaging unlock popup connected, awaiting credentials...');
        }
      };
    });

    // Tell the popup to render the unlock modal (plaintext — enclave-to-enclave).
    port.postMessage({
      type: 'kms:connect',
      operation: 'unlock',
      options,
      appSalt: options.appSalt,
      credentialId: options.credentialId,
      userId,
    });

    const popupResult = await credentialsPromise;

    // Reconstruct AuthCredentials in exactly the shape the worker expects.
    let credentials: AuthCredentials;
    if (popupResult.method === 'passphrase') {
      if (!popupResult.passphrase) {
        throw new Error('No passphrase returned from popup');
      }
      credentials = { method: 'passphrase', passphrase: popupResult.passphrase, userId };
    } else if (popupResult.method === 'passkey-prf') {
      if (!popupResult.prfOutput) {
        throw new Error('No PRF output returned from popup');
      }
      // Port carries a plain number[]; reconstruct the ArrayBuffer the worker wants.
      const prfOutput = new Uint8Array(popupResult.prfOutput).buffer;
      credentials = { method: 'passkey-prf', prfOutput, userId };
    } else {
      credentials = { method: 'passkey-gate', userId };
    }

    if (!this.pendingUnlockRequest) {
      throw new Error('No pending operation');
    }

    // IDENTICAL downstream injection to handleWebAuthnUnlockViaPopup.
    if (this.pendingUnlockRequestId) {
      this.worker?.postMessage({
        type: 'worker:unlock-credentials',
        requestId: this.pendingUnlockRequestId,
        credentials,
      });

      this.pendingUnlockRequestId = null;
      this.pendingUnlockRequest = null;

      this.hideModal();
      this.hideLoading();
    } else {
      const requestWithCredentials: RPCRequest = {
        ...this.pendingUnlockRequest,
        params: {
          ...(this.pendingUnlockRequest.params as Record<string, unknown>),
          credentials,
        },
      };

      // Relay the unlock outcome to the popup so it can confirm + auto-close (or
      // show the error). This is IN ADDITION to setupUnlockResponseListener,
      // which forwards the RPC response to the parent — we only post to the
      // popup port here, so there is no double-forward to the parent.
      const relayToPopup = (event: MessageEvent): void => {
        const resp = event.data as RPCResponse;
        if (resp.id !== requestWithCredentials.id) return;
        this.worker?.removeEventListener('message', relayToPopup);
        // The messaging RPC is done (incl. any BUG-007 mnemonic ceremony) — drop
        // the port handle so a later worker:show-mnemonic can't target a stale popup.
        this.messagingPopupPort = null;
        const errMsg =
          resp.error === undefined
            ? undefined
            : typeof resp.error === 'string'
              ? resp.error
              : resp.error.message;
        try {
          port.postMessage({
            type: 'popup:unlock-result',
            success: resp.error === undefined,
            ...(errMsg !== undefined ? { error: errMsg } : {}),
          });
        } catch {
          /* popup may already be gone */
        }
        // On success the popup confirms + closes itself; drop our port end after
        // a grace period. On error keep it open (the popup shows the error).
        if (resp.error === undefined) {
          setTimeout(() => {
            try {
              port.close();
            } catch {
              /* ignore */
            }
          }, 8000);
        }
      };
      this.worker?.addEventListener('message', relayToPopup);

      this.setupUnlockResponseListener(requestWithCredentials);
      this.worker?.postMessage(requestWithCredentials);
    }
  }

  /**
   * Connect ceremony rendered in the IFRAME modal (rooms-and-trust §3.2/§3.4).
   * `mintInvite`/`acceptInvite` are session-scoped (sid/token) with NO credential
   * collection, so — unlike unlock — they do NOT need a top-level popup. They run
   * in the iframe (the enclave surface that already holds the vault): the room
   * secret is only ever displayed (mint) or entered (accept) here, never in the
   * PWA. The worker drives the ceremony via worker:show-invite / worker:collect-
   * invite (transport-agnostic); this client renders the modal and posts the
   * outcomes (worker:invite-shown / worker:invite-blob) straight back to the
   * worker — no cross-window MessagePort. The RPC result forwards to the PWA via
   * the DEFAULT worker-message path (public data only).
   */
  /* c8 ignore start - iframe connect-ceremony UI is exercised in the browser, not the unit env */
  private handleConnectViaIframe(request: RPCRequest): void {
    // Serialize ceremonies: the connect modal + pendingConnectRequestId are
    // singletons, so refuse a second mint/accept while one is in flight rather
    // than clobbering the live ceremony's state.
    if (this.pendingConnectRequestId) {
      if (request.id) {
        this.sendToParent({
          id: request.id,
          error: formatError('Connect ceremony already in progress', new Error('busy')),
        });
      }
      return;
    }
    const mode = request.method === 'mintInvite' ? 'share' : 'accept';
    this.pendingConnectRequestId = request.id ?? null;

    // Reveal the iframe so its modal is visible. The PWA's kms-user wrapper also
    // toggles iframe visibility around the request; this covers the worker-driven
    // reveal path (mirrors handleUnlockRequest's kms:show-iframe).
    this.sendToParent({ type: 'kms:show-iframe' });
    this.showConnectCeremony(mode);

    // On the worker's final RPC response: tear down the modal. The response itself
    // forwards to the parent via the DEFAULT handleWorkerMessage path — do NOT
    // sendToParent here (that would double-forward).
    const onFinalResponse = (event: MessageEvent): void => {
      const resp = event.data as RPCResponse;
      if (resp.id !== request.id) return;
      this.worker?.removeEventListener('message', onFinalResponse);
      this.pendingConnectRequestId = null;
      this.hideConnectModal();
    };
    this.worker?.addEventListener('message', onFinalResponse);

    // Forward the RPC to the worker, which drives the show-invite / collect-invite
    // handshake back to this client.
    this.worker?.postMessage(request);
  }

  /** Hide the connect modal (the PWA's kms-user wrapper hides the iframe itself). */
  private hideConnectModal(): void {
    this.stopConnectScan();
    document.getElementById('connect-modal')?.classList.add('hidden');
  }

  /**
   * Post a Connect ceremony outcome back to the worker, matched to the in-flight
   * mint/accept RPC. No-ops if no ceremony is active (defensive).
   */
  private emitInviteOutcome(type: string, blob?: string): void {
    const requestId = this.pendingConnectRequestId;
    if (!requestId) return;
    this.worker?.postMessage({ type, requestId, ...(blob !== undefined ? { blob } : {}) });
  }
  /* c8 ignore stop */

  /**
   * Popup-side WebAuthn unlock ceremony (BUG-008). Runs in the top-level
   * kms.ats.run popup after it receives `kms:connect` with `operation: 'unlock'`.
   *
   * Mirrors {@link handleWebAuthnSetup}'s stateless branch but calls
   * `credentials.get()` (assertion) instead of `credentials.create()`. Posts the
   * PRF output back to the iframe as PLAINTEXT (`number[]`) over the MessagePort.
   */
  async runPopupUnlockCeremony(): Promise<void> {
    const port = this.credentialPort;
    if (!port) {
      console.error('[KMS Client] No credential port for unlock ceremony');
      return;
    }

    try {
      await this.performPopupUnlockAssertion(port);
    } catch (err: unknown) {
      // Legacy passkey-only path (non-messaging iframe modal → popup): any failure
      // is fatal for this popup, so surface it to the iframe.
      port.postMessage({ type: 'popup:error', error: getErrorMessage(err) });
    }
  }

  /**
   * Run the WebAuthn assertion (PRF or gate) and post the credential back over
   * the private port. THROWS on failure (does not post `popup:error`) so callers
   * can decide whether the failure is fatal ({@link runPopupUnlockCeremony}) or
   * recoverable ({@link setupPopupUnlockModal}'s passkey button → retry).
   *
   * Reads `this.unlockMethod` / `this.appSalt` / `this.unlockCredentialId`.
   */
  private async performPopupUnlockAssertion(port: MessagePort): Promise<void> {
    const method = this.unlockMethod ?? 'passkey-prf';
    // Pass allowCredentials only when a credentialId is stored; otherwise omit it
    // entirely so the browser runs a discoverable-credential get().
    const allowCredentials: PublicKeyCredentialDescriptor[] | undefined = this.unlockCredentialId
      ? [{ type: 'public-key', id: base64urlToArrayBuffer(this.unlockCredentialId) }]
      : undefined;

    if (method === 'passkey-prf') {
      if (!this.appSalt) {
        throw new Error('Missing appSalt for PRF unlock');
      }
      const appSalt = base64urlToArrayBuffer(this.appSalt);

      // NOTE: this entire method lives inside the class-level `c8 ignore` region
      // (DOM/WebAuthn ceremony cannot be unit-tested without a real authenticator).
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          timeout: 60000,
          userVerification: 'required',
          ...(allowCredentials ? { allowCredentials } : {}),
          extensions: {
            prf: {
              eval: {
                first: appSalt,
              },
            },
          },
        },
      }) as PublicKeyCredential;

      const prfOutput = getPRFResults(assertion)?.results?.first;
      if (!prfOutput) {
        throw new Error('PRF output not available from assertion');
      }

      port.postMessage({
        type: 'popup:credentials',
        method: 'passkey-prf',
        prfOutput: Array.from(new Uint8Array(prfOutput)),
      });
    } else {
      await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          timeout: 60000,
          userVerification: 'required',
          ...(allowCredentials ? { allowCredentials } : {}),
        },
      });

      port.postMessage({ type: 'popup:credentials', method: 'passkey-gate' });
    }
  }

  /**
   * Popup-side messaging unlock modal (BUG-008 follow-up). Runs in the top-level
   * kms.ats.run popup after it receives `kms:connect` with `operation: 'unlock'`
   * AND an `options` payload (messaging flow). Reuses the enclave HTML's existing
   * `#unlock-modal`.
   *
   * Reveals the modal, shows/hides the passphrase field and the passkey button
   * per the option flags, and wires both credential paths. The passphrase is
   * posted straight over the port as plaintext (`popup:credentials`,
   * `method: 'passphrase'`); the passkey button runs
   * {@link performPopupUnlockAssertion}. Recoverable errors are shown in the
   * popup (`#kms-modal-error`) so the user can retry — only a missing modal/port
   * posts `popup:error`.
   */
  setupPopupUnlockModal(options: {
    hasPassphrase: boolean;
    hasPasskeyPrf: boolean;
    hasPasskeyGate: boolean;
  }): void {
    const port = this.credentialPort;
    const modal = document.getElementById('unlock-modal');
    const webauthnBtn = document.getElementById('kms-webauthn-btn');
    const passphraseInput = document.getElementById('kms-passphrase-input') as HTMLInputElement | null;
    const passphraseBtn = document.getElementById('kms-passphrase-btn');

    if (!port) {
      console.error('[KMS Client] No credential port for unlock modal');
      return;
    }
    if (!modal) {
      console.error('[KMS Client] Unlock modal element not found');
      port.postMessage({ type: 'popup:error', error: 'Unlock modal UI not found' });
      return;
    }

    // Reveal the modal.
    modal.classList.remove('hidden');
    this.hideError();
    this.hideLoading();

    // Show only the methods the user actually has, hiding the WHOLE block for a
    // missing method — not just its input/button — so we never leave an orphaned
    // "Passphrase" label or a dangling "── or ──" divider. The divider is shown
    // only when BOTH methods are offered.
    const hasPasskey = options.hasPasskeyPrf || options.hasPasskeyGate;
    const passkeyOption = document.getElementById('kms-unlock-passkey-option');
    const passphraseOption = document.getElementById('kms-unlock-passphrase-option');
    const divider = document.getElementById('kms-unlock-divider');
    if (passkeyOption) passkeyOption.style.display = hasPasskey ? '' : 'none';
    if (passphraseOption) passphraseOption.style.display = options.hasPassphrase ? '' : 'none';
    if (divider) divider.style.display = hasPasskey && options.hasPassphrase ? '' : 'none';

    // Passphrase path: post the value straight over the private port (plaintext).
    // Keep the spinner up until the iframe relays popup:unlock-result.
    const submitPassphrase = (): void => {
      const value = passphraseInput?.value ?? '';
      if (!value || value.trim().length === 0) {
        this.showError('Please enter a passphrase');
        return;
      }
      this.hideError();
      this.showLoading();
      port.postMessage({ type: 'popup:credentials', method: 'passphrase', passphrase: value });
    };
    if (passphraseBtn) {
      passphraseBtn.onclick = submitPassphrase;
    }
    if (passphraseInput) {
      passphraseInput.onkeydown = (e): void => {
        if (e.key === 'Enter') submitPassphrase();
      };
    }

    // Passkey path: run the assertion; keep the modal open for retry on error.
    // On a successful assertion the spinner stays up until the iframe relays
    // popup:unlock-result (the actual key unlock happens there).
    if (webauthnBtn) {
      webauthnBtn.onclick = (): void => {
        this.hideError();
        this.showLoading();
        void this.performPopupUnlockAssertion(port).catch((err: unknown) => {
          this.showError(`Passkey failed: ${getErrorMessage(err)}`);
          this.hideLoading();
        });
      };
    }
  }

  /**
   * Handle passphrase unlock attempt
   *
   * @param passphrase - User-entered passphrase
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  private async handlePassphraseUnlock(passphrase: string): Promise<void> {
    if (!passphrase || passphrase.trim().length === 0) {
      this.showError('Please enter a passphrase');
      return;
    }

    this.showLoading();
    this.hideError();

    try {
      // Passphrase collected - now execute the pending operation with credentials
      if (!this.pendingUnlockRequest) {
        throw new Error('No pending operation');
      }

      // Extract userId from the pending request params
      const userId = (this.pendingUnlockRequest.params as { userId?: string } | undefined)?.userId;
      if (!userId) {
        throw new Error('userId not found in request params');
      }

      // Check if this is for addEnrollmentWithPopup unlock flow
      if (this.pendingUnlockRequestId) {
        // Send credentials directly to worker for addEnrollmentWithPopup
        this.worker?.postMessage({
          type: 'worker:unlock-credentials',
          requestId: this.pendingUnlockRequestId,
          credentials: { method: 'passphrase', passphrase, userId },
        });

        // Clear state
        this.pendingUnlockRequestId = null;
        this.pendingUnlockRequest = null;

        // Hide modal
        this.hideModal();
        this.hideLoading();
      } else {
        // Normal unlock flow for RPC methods
        // Add credentials to the request params (include userId)
        const requestWithCredentials: RPCRequest = {
          ...this.pendingUnlockRequest,
          params: {
            ...(this.pendingUnlockRequest.params as Record<string, unknown>),
            credentials: { method: 'passphrase', passphrase, userId },
          },
        };

        // Send to worker and setup response listener
        this.setupUnlockResponseListener(requestWithCredentials);
        this.worker?.postMessage(requestWithCredentials);
      }
    } catch (err: unknown) {
      console.error('[KMS Client] Passphrase unlock failed:', err);
      this.hideLoading();
      this.showError(`Unlock failed: ${getErrorMessage(err)}`);
    }
  }

  /**
   * Setup listener for operation response from worker
   *
   * Waits for worker response and forwards to parent, then hides modal.
   *
   * @param operationRequest - The operation request sent to worker
   */
  private setupUnlockResponseListener(operationRequest: RPCRequest): void {
    const handleOperationResponse = (event: MessageEvent): void => {
      const response = event.data as RPCResponse;

      // Check if this is the response to our operation request
      if (response.id === operationRequest.id) {
        // Remove listener
        this.worker?.removeEventListener('message', handleOperationResponse);

        // Hide modal
        this.hideModal();

        // Forward RPC response to parent
        this.sendToParent(response);

        // Clear pending request
        this.pendingUnlockRequest = null;
      }
    };

    // Add temporary listener for this specific response
    this.worker?.addEventListener('message', handleOperationResponse);
  }

  /**
   * Show error message in modal
   *
   * @param message - Error message to display
   */
  private showError(message: string): void {
    const errorDiv = document.getElementById('kms-modal-error');
    if (errorDiv) {
      errorDiv.textContent = message;
      errorDiv.classList.remove('hidden');
    }
  }

  /**
   * Hide error message
   */
  private hideError(): void {
    const errorDiv = document.getElementById('kms-modal-error');
    if (errorDiv) {
      errorDiv.classList.add('hidden');
    }
  }

  /**
   * Show loading indicator
   */
  private showLoading(): void {
    const loadingDiv = document.getElementById('kms-modal-loading');
    if (loadingDiv) {
      loadingDiv.classList.remove('hidden');
    }
  }

  /**
   * Hide loading indicator
   */
  private hideLoading(): void {
    const loadingDiv = document.getElementById('kms-modal-loading');
    if (loadingDiv) {
      loadingDiv.classList.add('hidden');
    }
  }

  /**
   * Hide unlock modal
   */
  private hideModal(): void {
    const modal = document.getElementById('unlock-modal');
    if (modal) {
      modal.classList.add('hidden');
    }

    // Clear passphrase input
    const passphraseInput = document.getElementById('kms-passphrase-input') as HTMLInputElement;
    if (passphraseInput) {
      passphraseInput.value = '';
    }

    this.hideLoading();
    this.hideError();
  }
  /* c8 ignore stop */

  /**
   * Prompt user to unlock with existing method for multi-enrollment.
   * Shows the unlock modal to collect credentials before adding new enrollment.
   *
   * @param enrollments - List of existing enrollment IDs
   * @param userId - User ID
   * @returns Collected credentials
   */
  /* c8 ignore start - Multi-enrollment unlock UI tested via Playwright (client-ui-coverage.spec.ts) */
  private async promptUnlockForEnrollment(enrollments: string[], userId: string): Promise<AuthCredentials> {

    // Hide success message from previous setup (if visible)
    this.hideSetupSuccess();

    // Show the setup modal body temporarily with instructions
    const setupModalBody = document.querySelector('#setup-modal .kms-modal-body') as HTMLElement;
    if (setupModalBody) {
      // Hide setup options, show unlock instructions
      const setupOptions = setupModalBody.querySelectorAll('.kms-auth-option, .kms-divider');
      setupOptions.forEach(el => ((el as HTMLElement).classList.add('hidden')));

      // Create unlock instructions
      const unlockInstructions = document.createElement('div');
      unlockInstructions.id = 'multi-enrollment-unlock';
      unlockInstructions.className = 'multi-enrollment-instructions';
      unlockInstructions.innerHTML = `
        <p class="multi-enrollment-title">
          🔒 Multi-Enrollment Authentication Required
        </p>
        <p class="multi-enrollment-description">
          You already have an authentication method set up. Please authenticate with your existing method to add a new one.
        </p>
      `;
      setupModalBody.insertBefore(unlockInstructions, setupModalBody.firstChild);

      // Show appropriate unlock option based on existing enrollments
      const hasPassphrase = enrollments.some(e => e.includes('passphrase'));
      const hasPasskey = enrollments.some(e => e.includes('passkey'));

      if (hasPassphrase) {
        // Show passphrase input
        const passphraseOption = document.createElement('div');
        passphraseOption.className = 'kms-auth-option';
        passphraseOption.id = 'temp-passphrase-unlock';
        passphraseOption.innerHTML = `
          <label for="temp-passphrase-input" class="kms-input-label">Passphrase</label>
          <input
            type="password"
            id="temp-passphrase-input"
            class="kms-input"
            placeholder="Enter your passphrase"
            autocomplete="off"
          />
          <button id="temp-passphrase-btn" class="kms-auth-btn kms-secondary">
            <span class="kms-auth-icon">🔐</span>
            <span class="kms-auth-label">Unlock with Passphrase</span>
          </button>
        `;
        setupModalBody.appendChild(passphraseOption);
      }

      if (hasPasskey) {
        // Show passkey button
        const passkeyOption = document.createElement('div');
        passkeyOption.className = 'kms-auth-option';
        passkeyOption.id = 'temp-passkey-unlock';
        passkeyOption.innerHTML = `
          <button id="temp-passkey-btn" class="kms-auth-btn kms-primary">
            <span class="kms-auth-icon">🔑</span>
            <span class="kms-auth-label">Unlock with Passkey</span>
          </button>
        `;
        setupModalBody.appendChild(passkeyOption);
      }
    }

    // Return promise that resolves when user successfully unlocks
    return new Promise<AuthCredentials>((resolve) => {
      const cleanup = (): void => {
        // Remove temporary elements
        document.getElementById('multi-enrollment-unlock')?.remove();
        document.getElementById('temp-passphrase-unlock')?.remove();
        document.getElementById('temp-passkey-unlock')?.remove();

        // Restore setup options
        const setupOptions = setupModalBody?.querySelectorAll('.kms-auth-option, .kms-divider');
        setupOptions?.forEach(el => ((el as HTMLElement).classList.remove('hidden')));
      };

      // Handle passphrase unlock
      const passphraseBtn = document.getElementById('temp-passphrase-btn');
      const passphraseInput = document.getElementById('temp-passphrase-input') as HTMLInputElement;

      if (passphraseBtn && passphraseInput) {
        const handlePassphraseUnlock = (): void => {
          const passphrase = passphraseInput.value;
          if (!passphrase) {
            this.showSetupError('Please enter your passphrase');
            return;
          }

          cleanup();
          resolve({ method: 'passphrase', passphrase, userId });
        };

        passphraseBtn.onclick = handlePassphraseUnlock;
        passphraseInput.onkeydown = (e): void => {
          if (e.key === 'Enter') handlePassphraseUnlock();
        };
      }

      // Handle passkey unlock
      const passkeyBtn = document.getElementById('temp-passkey-btn');
      if (passkeyBtn) {
        passkeyBtn.onclick = async (): Promise<void> => {
          try {
            // Load appSalt for PRF
            const appSaltStr = localStorage.getItem('kms:appSalt');
            let appSalt: Uint8Array;

            if (appSaltStr) {
              appSalt = new Uint8Array(appSaltStr.split(',').map(n => parseInt(n, 10)));
            } else {
              appSalt = crypto.getRandomValues(new Uint8Array(32));
            }

            // Call WebAuthn
            const credential = await navigator.credentials.get({
              publicKey: {
                challenge: new Uint8Array(32),
                timeout: 60000,
                userVerification: 'required',
                extensions: {
                  prf: {
                    eval: {
                      first: appSalt as BufferSource,
                    },
                  },
                },
              },
            }) as PublicKeyCredential;

            if (!credential) {
              throw new Error('No credential returned');
            }

            // Check if PRF succeeded
            const prfExt = getPRFResults(credential);
            const prfOutput = prfExt?.results?.first;

            // Determine method based on enrollment type
            const hasPRF = enrollments.some(e => e.includes('prf'));
            const hasGate = enrollments.some(e => e.includes('gate'));

            let credentials: AuthCredentials;
            if (hasPRF && prfOutput) {
              credentials = { method: 'passkey-prf', prfOutput, userId };
            } else if (hasGate) {
              credentials = { method: 'passkey-gate', userId };
            } else {
              throw new Error('Unable to determine passkey method');
            }

            cleanup();
            resolve(credentials);
          } catch (err: unknown) {
            this.showSetupError(`Passkey unlock failed: ${getErrorMessage(err)}`);
          }
        };
      }
    });
  }
  /* c8 ignore stop */

  /**
   * Setup modal handling (for standalone setup window)
   * This runs in first-party context, enabling credentials.create()
   */
  setupSetupModalHandlers(): void {
    const webauthnBtn = document.getElementById('kms-setup-webauthn-btn');
    const passphraseInput = document.getElementById('kms-setup-passphrase-input') as HTMLInputElement;
    const passphraseConfirmInput = document.getElementById('kms-setup-passphrase-confirm-input') as HTMLInputElement;
    const passphraseBtn = document.getElementById('kms-setup-passphrase-btn');
    const charCount = document.getElementById('kms-passphrase-char-count');

    if (!webauthnBtn || !passphraseInput || !passphraseConfirmInput || !passphraseBtn) {
      console.error('[KMS Client] Setup modal elements not found');
      return;
    }

    // Setup WebAuthn button handler
    webauthnBtn.onclick = (): Promise<void> => this.handleWebAuthnSetup();

    // Setup character count for passphrase
    const matchFeedback = document.getElementById('kms-passphrase-match-feedback');

    const updateMatchFeedback = (): void => {
      const passphrase = passphraseInput.value;
      const confirm = passphraseConfirmInput.value;

      if (!matchFeedback) return;

      // Only show feedback if user has typed in confirmation field
      if (confirm.length === 0) {
        matchFeedback.classList.add('hidden');
        return;
      }

      matchFeedback.classList.remove('hidden');

      if (passphrase === confirm) {
        matchFeedback.textContent = '✓ Passphrases match';
        matchFeedback.classList.remove('error');
        matchFeedback.classList.add('success');
      } else {
        matchFeedback.textContent = '✗ Passphrases do not match';
        matchFeedback.classList.remove('success');
        matchFeedback.classList.add('error');
      }
    };

    passphraseInput.oninput = (): void => {
      const length = passphraseInput.value.length;
      const minLength = 12;
      if (charCount) {
        charCount.textContent = `${length} / ${minLength} characters`;
        if (length < minLength) {
          charCount.classList.remove('success');
          charCount.classList.add('error');
        } else {
          charCount.classList.remove('error');
          charCount.classList.add('success');
        }
      }
      updateMatchFeedback();
    };

    // Update match feedback as user types in confirmation field
    passphraseConfirmInput.oninput = updateMatchFeedback;

    // Setup passphrase button handler
    passphraseBtn.onclick = (): Promise<void> => this.handlePassphraseSetup(passphraseInput.value, passphraseConfirmInput.value);

    // Setup Enter key for passphrase (in both fields)
    const handleEnter = (): void => {
      void this.handlePassphraseSetup(passphraseInput.value, passphraseConfirmInput.value).catch((err: unknown) => {
        console.error('[KMS Client] Passphrase setup failed:', err);
        this.showSetupError(err instanceof Error ? err.message : 'Unknown error');
      });
    };

    passphraseInput.onkeydown = (e): void => {
      if (e.key === 'Enter') handleEnter();
    };

    passphraseConfirmInput.onkeydown = (e): void => {
      if (e.key === 'Enter') handleEnter();
    };
  }

  /**
   * Encrypt credentials with transport public key (popup mode).
   *
   * SECURITY:
   * - Ephemeral ECDH keypair per encryption (one-time use)
   * - Shared secret derived via ECDH
   * - AES-GCM encryption with HKDF-derived key
   * - Parent cannot decrypt (doesn't have iframe's private key)
   *
   * This method is used by stateless popup mode to encrypt credentials
   * before sending them to the parent (which acts as a blind proxy).
   *
   * @param credentials - Raw credentials object (passphrase or PRF output)
   * @param transportPublicKey - Iframe's ephemeral public key (base64url, 65 bytes)
   * @returns Encrypted payload for parent to forward
   */
  private async encryptCredentials(
    credentials: Record<string, unknown>,
    transportPublicKey: string
  ): Promise<{
    ephemeralPublicKey: string;
    iv: string;
    encryptedCredentials: string;
  }> {
    // Step 1: Generate ephemeral keypair for this encryption
    const ephemeralKeypair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    // Step 2: Import iframe's transport public key
    const iframePublicKeyBytes = base64urlToArrayBuffer(transportPublicKey);
    const iframePublicKey = await crypto.subtle.importKey(
      'raw',
      iframePublicKeyBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Step 3: Derive shared secret (ECDH)
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: iframePublicKey,
      },
      ephemeralKeypair.privateKey,
      256
    );

    // Step 4: Derive AES-GCM key from shared secret (HKDF)
    const sharedSecretKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits']
    );

    const aesKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        salt: new Uint8Array(32), // Zero salt (shared secret already random)
        info: new TextEncoder().encode('ATS/KMS/setup-transport/v2'),
        hash: 'SHA-256',
      },
      sharedSecretKey,
      256
    );

    const aesKey = await crypto.subtle.importKey(
      'raw',
      aesKeyBits,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    // Step 5: Encrypt credentials
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(credentials));

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      aesKey,
      plaintext
    );

    // Step 6: Export ephemeral public key
    const ephemeralPublicKeyRaw = await crypto.subtle.exportKey('raw', ephemeralKeypair.publicKey);

    return {
      ephemeralPublicKey: arrayBufferToBase64url(ephemeralPublicKeyRaw),
      iv: arrayBufferToBase64url(iv.buffer),
      encryptedCredentials: arrayBufferToBase64url(ciphertext),
    };
  }

  /**
   * Handle WebAuthn setup (credentials.create in first-party context)
   * Supports both initial setup and multi-enrollment (adding second+ method)
   */
  private async handleWebAuthnSetup(): Promise<void> {
    this.showSetupLoading();
    this.hideSetupError();

    try {
      // Use userId from parent (passed via fullSetup/setupWithPopup)
      const userId = this.userId || 'demouser@ats.run'; // Fallback for backward compatibility
      const rpId = window.location.hostname; // kms.ats.run or localhost

      // Check if stateless popup mode
      if (this.isStatelessPopup) {
        /* eslint-disable no-console */
        // Use appSalt from URL parameters
        const appSalt = base64urlToArrayBuffer(this.appSalt!);

        // Step 1: WebAuthn create ceremony with PRF extension
        const credential = await navigator.credentials.create({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { id: rpId, name: 'ATS KMS V2' },
            user: {
              id: new TextEncoder().encode(userId),
              name: userId,
              displayName: userId,
            },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 }, // ES256
              { type: 'public-key', alg: -257 }, // RS256
            ],
            authenticatorSelection: {
              authenticatorAttachment: 'platform',
              userVerification: 'required',
              residentKey: 'required',
            },
            extensions: {
              prf: {
                eval: {
                  first: appSalt,
                },
              },
            },
          },
        }) as PublicKeyCredential;

        if (!credential) {
          throw new Error('No credential returned');
        }

        // Step 2: Check if PRF extension succeeded and if output is available
        // NOTE: Modern platforms return { enabled: true, results: { first: ArrayBuffer } }
        //       Legacy platforms return { enabled: true } (no results yet)
        //       No PRF support returns { enabled: false } or undefined
        const prfExt = getPRFResults(credential);
        const prfEnabled = prfExt?.enabled === true;
        let prfOutput = prfExt?.results?.first; // May be available immediately!

        // Step 3: Determine if we need to call credentials.get() for PRF output
        let detectedMethod: 'passkey-prf' | 'passkey-gate';

        if (prfEnabled) {
          // PRF is supported by authenticator

          if (prfOutput) {
            // Case A: Modern platform - PRF output available immediately! ✅
            detectedMethod = 'passkey-prf';
            console.log('[KMS Client] PRF output available from create() (modern platform)');
          } else {
            // Case B: Legacy platform - need to call get() for PRF output ⚠️
            console.log('[KMS Client] PRF enabled but no output yet, calling get() (legacy platform)');

            const assertion = await navigator.credentials.get({
              publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                timeout: 60000,
                userVerification: 'required',
                extensions: {
                  prf: {
                    eval: {
                      first: appSalt,
                    },
                  },
                },
              },
            }) as PublicKeyCredential;

            const assertionPrfExt = getPRFResults(assertion);
            prfOutput = assertionPrfExt?.results?.first;

            if (prfOutput) {
              detectedMethod = 'passkey-prf';
              console.log('[KMS Client] PRF output obtained from get()');
            } else {
              // PRF enabled but still no output (shouldn't happen, but handle gracefully)
              detectedMethod = 'passkey-gate';
              console.warn('[KMS Client] PRF enabled but no output from get(), falling back to gate mode');
            }
          }
        } else {
          // Case C: PRF not supported - use gate mode
          detectedMethod = 'passkey-gate';
          console.log('[KMS Client] PRF not supported by authenticator, using gate mode');
        }

        // Step 4: Build credentials object based on detected method
        const credentials: Record<string, unknown> = {
          credentialId: arrayBufferToBase64url(credential.rawId),
          rpId,
        };

        // Include prfOutput only if PRF mode
        if (detectedMethod === 'passkey-prf' && prfOutput) {
          credentials.prfOutput = arrayBufferToBase64url(prfOutput);
        }

        // NOTE: appSalt and hkdfSalt NOT included (iframe already has them)

        // Step 5: Encrypt credentials
        const encrypted = await this.encryptCredentials(credentials, this.transportPublicKey!);

        // Step 6: Send credentials via MessagePort (KMS-only flow) or window.opener (legacy)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
        const credentialPort = (this as any).credentialPort as MessagePort | undefined;

        if (credentialPort) {
          // KMS-only popup flow: send via MessagePort to iframe
          console.log('[KMS Client] Sending credentials via MessagePort to iframe');
          credentialPort.postMessage({
            type: 'popup:credentials',
            method: detectedMethod,
            transportKeyId: this.transportKeyId,
            userId,
            ...encrypted,
          });

          // Show success (keep window open for testing)
          this.hideSetupLoading();
          this.showSetupSuccess();
          // setTimeout(() => window.close(), 2000); // Disabled for testing
        } else if (window.opener) {
          // Legacy stateless popup flow: send via window.opener to parent
          console.log('[KMS Client] Sending credentials via window.opener to parent');
          (window.opener as Window).postMessage(
            {
              type: 'kms:setup-credentials',
              method: detectedMethod, // Critical: tells iframe which setup to use
              transportKeyId: this.transportKeyId,
              userId,
              ...encrypted,
            },
            this.parentOrigin
          );

          // Show success (keep window open for testing)
          this.hideSetupLoading();
          this.showSetupSuccess();
          // setTimeout(() => window.close(), 2000); // Disabled for testing
        }
        return;
      }

      // Check if user already has enrollments (multi-enrollment scenario)
      const enrollments = await this.getEnrollments(userId);

      // If enrollments exist, we need to collect existing credentials first
      let existingCredentials: AuthCredentials | null = null;
      if (enrollments.length > 0) {
        this.hideSetupLoading();

        // Prompt user to unlock with existing method
        existingCredentials = await this.promptUnlockForEnrollment(enrollments, userId);

        this.showSetupLoading();
      }

      // Generate app salt for PRF
      const appSalt = crypto.getRandomValues(new Uint8Array(32));

      // Call credentials.create() in first-party context (correct RP)
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: rpId, name: 'ATS KMS V2' },
          user: {
            id: new TextEncoder().encode(userId),
            name: userId,
            displayName: userId,
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 }, // ES256
            { type: 'public-key', alg: -257 }, // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required',
          },
          extensions: {
            prf: {
              eval: {
                first: appSalt,
              },
            },
          },
        },
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('No credential returned');
      }

      // Check if PRF extension succeeded
      // NOTE: credentials.create() returns { enabled: true/false }
      //       credentials.get() returns { results: { first: ArrayBuffer } }
      const prfExt = getPRFResults(credential);
      const prfEnabled = prfExt?.enabled === true;

      // If PRF is enabled, we need to call credentials.get() to obtain the actual PRF output
      let prfOutput: ArrayBuffer | undefined;
      if (prfEnabled) {
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            timeout: 60000,
            userVerification: 'required',
            extensions: {
              prf: {
                eval: {
                  first: appSalt,
                },
              },
            },
          },
        }) as PublicKeyCredential;

        const getPrfExt = getPRFResults(assertion);
        prfOutput = getPrfExt?.results?.first;
      }

      // Determine method and params based on whether this is initial or multi-enrollment
      let setupRequest: RPCRequest;

      if (existingCredentials) {
        // Multi-enrollment: Add new enrollment to existing MS
        setupRequest = {
          id: `add-enrollment-${Date.now()}`,
          method: 'addEnrollment',
          params: {
            userId,
            method: (prfEnabled && prfOutput) ? 'passkey-prf' : 'passkey-gate',
            credentials: existingCredentials,
            newCredentials: {
              credentialId: credential.rawId,
              ...(prfOutput && { prfOutput }),
              rpId,
            },
          },
        };
      } else {
        // Initial setup: Create new MS
        setupRequest = {
          id: `setup-${Date.now()}`,
          method: (prfEnabled && prfOutput) ? 'setupPasskeyPRF' : 'setupPasskeyGate',
          params: {
            userId,
            credentialId: credential.rawId,
            ...(prfOutput && { prfOutput }),
            rpId,
          },
        };
      }

      this.worker?.postMessage(setupRequest);

      // Wait for response
      const response: unknown = await new Promise((resolve, reject) => {
        const handler = (event: MessageEvent): void => {
          const data = event.data as RPCResponse;
          if (data.id === setupRequest.id) {
            this.worker?.removeEventListener('message', handler);
            if (data.error) {
              const errorMsg = typeof data.error === 'string' ? data.error : data.error.message;
              reject(new Error(errorMsg));
            } else {
              resolve(data.result);
            }
          }
        };
        this.worker?.addEventListener('message', handler);

        // Timeout after 30s
        setTimeout(() => {
          this.worker?.removeEventListener('message', handler);
          reject(new Error('Setup timeout'));
        }, 30000);
      });

      this.hideSetupLoading();
      this.showSetupSuccess();

      // Store appSalt for future unlock operations
      localStorage.setItem('kms:appSalt', Array.from(appSalt).toString());

      // Notify parent window via postMessage
      this.notifySetupComplete({
        method: prfOutput ? 'passkey-prf' : 'passkey-gate',
        result: response,
      });

    } catch (err: unknown) {
      this.hideSetupLoading();
      this.showSetupError(`WebAuthn setup failed: ${getErrorMessage(err)}`);
      console.error('[KMS Client] WebAuthn setup failed:', err);
    }
  }

  /**
   * Handle passphrase setup
   * Supports both initial setup and multi-enrollment (adding second+ method)
   */
  private async handlePassphraseSetup(passphrase: string, confirmPassphrase: string): Promise<void> {
    if (!passphrase || passphrase.trim().length === 0) {
      this.showSetupError('Please enter a passphrase');
      return;
    }

    if (passphrase.length < 12) {
      this.showSetupError('Passphrase must be at least 12 characters');
      return;
    }

    if (!confirmPassphrase || confirmPassphrase.trim().length === 0) {
      this.showSetupError('Please confirm your passphrase');
      return;
    }

    if (passphrase !== confirmPassphrase) {
      this.showSetupError('Passphrases do not match');
      return;
    }

    this.showSetupLoading();
    this.hideSetupError();

    try {
      // Use userId from parent (passed via fullSetup/setupWithPopup)
      const userId = this.userId || 'demouser@ats.run'; // Fallback for backward compatibility

      console.log('[KMS Client] handlePassphraseSetup - isStatelessPopup:', this.isStatelessPopup, {
        transportKey: this.transportPublicKey?.slice(0, 20) + '...',
        keyId: this.transportKeyId,
        userId
      });

      // Check if stateless popup mode
      if (this.isStatelessPopup) {
        console.log('[KMS Client] Entering stateless popup flow for passphrase setup');

        console.log('[KMS Client] window.opener check:', {
          hasOpener: !!window.opener,
          openerIsWindow: window.opener === window,
          parentOrigin: this.parentOrigin
        });

        // Encrypt credentials
        const encrypted = await this.encryptCredentials(
          {
            passphrase,
          },
          this.transportPublicKey!
        );

        /* c8 ignore start - stateless popup mode requires browser integration testing */
        /* eslint-disable no-console */
        console.log('[KMS Client] Credentials encrypted, preparing to send');

        // Check for MessagePort (KMS-only flow) or window.opener (legacy flow)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
        const credentialPort = (this as any).credentialPort as MessagePort | undefined;

        if (credentialPort) {
          // KMS-only popup flow: send via MessagePort to iframe
          console.log('[KMS Client] Sending credentials via MessagePort to iframe');
          credentialPort.postMessage({
            type: 'popup:credentials',
            method: 'passphrase',
            transportKeyId: this.transportKeyId,
            userId,
            ...encrypted,
          });

          // Show success (keep window open for testing)
          this.hideSetupLoading();
          this.showSetupSuccess();
          // setTimeout(() => window.close(), 2000); // Disabled for testing
        } else if (window.opener) {
          // Legacy stateless popup flow: send via window.opener to parent
          console.log('[KMS Client] Sending credentials via window.opener to parent');
          (window.opener as Window).postMessage(
            {
              type: 'kms:setup-credentials',
              method: 'passphrase',
              transportKeyId: this.transportKeyId,
              userId,
              ...encrypted,
            },
            this.parentOrigin
          );

          // Show success (keep window open for testing)
          this.hideSetupLoading();
          this.showSetupSuccess();
          // setTimeout(() => window.close(), 2000); // Disabled for testing
        } else {
          console.error('[KMS Client] No communication channel available');
          this.hideSetupLoading();
          this.showSetupError('Communication channel not ready. Please try again.');
        }
        /* eslint-enable no-console */
        return;
        /* c8 ignore stop */
      }

      // Check if user already has enrollments (multi-enrollment scenario)
      const enrollments = await this.getEnrollments(userId);

      // If enrollments exist, we need to collect existing credentials first
      let existingCredentials: AuthCredentials | null = null;
      if (enrollments.length > 0) {
        this.hideSetupLoading();

        // Prompt user to unlock with existing method
        existingCredentials = await this.promptUnlockForEnrollment(enrollments, userId);

        this.showSetupLoading();
      }

      // Determine method and params based on whether this is initial or multi-enrollment
      let setupRequest: RPCRequest;

      if (existingCredentials) {
        // Multi-enrollment: Add new enrollment to existing MS
        setupRequest = {
          id: `add-enrollment-${Date.now()}`,
          method: 'addEnrollment',
          params: {
            userId,
            method: 'passphrase',
            credentials: existingCredentials,
            newCredentials: {
              passphrase,
            },
          },
        };
      } else {
        // Initial setup: Create new MS
        setupRequest = {
          id: `setup-${Date.now()}`,
          method: 'setupPassphrase',
          params: {
            userId,
            passphrase,
          },
        };
      }

      this.worker?.postMessage(setupRequest);

      // Wait for response
      const response: unknown = await new Promise((resolve, reject) => {
        const handler = (event: MessageEvent): void => {
          const data = event.data as RPCResponse;
          if (data.id === setupRequest.id) {
            this.worker?.removeEventListener('message', handler);
            if (data.error) {
              const errorMsg = typeof data.error === 'string' ? data.error : data.error.message;
              reject(new Error(errorMsg));
            } else {
              resolve(data.result);
            }
          }
        };
        this.worker?.addEventListener('message', handler);

        // Timeout after 30s
        setTimeout(() => {
          this.worker?.removeEventListener('message', handler);
          reject(new Error('Setup timeout'));
        }, 30000);
      });

      this.hideSetupLoading();
      this.showSetupSuccess();

      // Notify parent window via postMessage
      this.notifySetupComplete({
        method: 'passphrase',
        result: response,
      });

    } catch (err: unknown) {
      this.hideSetupLoading();
      this.showSetupError(`Setup failed: ${getErrorMessage(err)}`);
      console.error('[KMS Client] Passphrase setup failed:', err);
    }
  }

  /**
   * Show setup error message
   */
  private showSetupError(message: string): void {
    const errorDiv = document.getElementById('kms-setup-error');
    if (errorDiv) {
      errorDiv.textContent = message;
      errorDiv.classList.remove('hidden');
    }
  }

  /**
   * Hide setup error message
   */
  private hideSetupError(): void {
    const errorDiv = document.getElementById('kms-setup-error');
    if (errorDiv) {
      errorDiv.classList.add('hidden');
    }
  }

  /**
   * Show setup loading indicator
   */
  private showSetupLoading(): void {
    const loadingDiv = document.getElementById('kms-setup-loading');
    if (loadingDiv) {
      loadingDiv.classList.remove('hidden');
    }
  }

  /**
   * Hide setup loading indicator
   */
  private hideSetupLoading(): void {
    const loadingDiv = document.getElementById('kms-setup-loading');
    if (loadingDiv) {
      loadingDiv.classList.add('hidden');
    }
  }

  /**
   * Show setup success message + the shared auto-close footer (countdown +
   * "Close automatically" checkbox + "Close now"). Called from the popup setup
   * ceremony once credentials have been produced.
   */
  private showSetupSuccess(): void {
    const successDiv = document.getElementById('kms-setup-success');
    if (successDiv) {
      successDiv.classList.remove('hidden');
      this.renderPopupClose(successDiv, { countdown: true });
    }
  }

  /**
   * Show the messaging-unlock success panel + auto-close footer. Hides the auth
   * options + spinner (the unlock is done) and reveals the green confirmation.
   * Called on a confirmed `popup:unlock-result { success: true }` from the iframe.
   */
  showUnlockSuccess(): void {
    // The BUG-007 ceremony may have hidden the unlock modal; restore it so the
    // success panel is visible, and drop the mnemonic modal.
    document.getElementById('unlock-modal')?.classList.remove('hidden');
    document.getElementById('mnemonic-modal')?.classList.add('hidden');
    this.hideLoading();
    this.hideError();
    for (const id of ['kms-unlock-passkey-option', 'kms-unlock-divider', 'kms-unlock-passphrase-option']) {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    }
    const successDiv = document.getElementById('kms-unlock-success');
    if (successDiv) {
      successDiv.classList.remove('hidden');
      this.renderPopupClose(successDiv, { countdown: true });
    }
  }

  /**
   * Handle the iframe's relayed unlock outcome in the popup (BUG-011 follow-up).
   * Success → green confirmation + auto-close. Failure → surface the error and
   * stop the spinner (the parent RPC also rejects; the user retries from the app).
   */
  handlePopupUnlockResult(success: boolean, error?: string): void {
    if (success) {
      this.showUnlockSuccess();
    } else {
      // Restore the unlock modal (the BUG-007 ceremony may have covered it) so the
      // error is visible, and drop the mnemonic modal.
      document.getElementById('unlock-modal')?.classList.remove('hidden');
      document.getElementById('mnemonic-modal')?.classList.add('hidden');
      this.hideLoading();
      this.showError(error || 'Unlock failed');
    }
  }

  /**
   * Open the connect-modal shell (in the iframe) for the given ceremony `mode`.
   * `share` waits on the worker's minted blob (worker:show-invite → renderConnect-
   * Share); `accept` immediately renders the paste field (worker:collect-invite is
   * satisfied by the blob the user enters). Runs in the iframe — same origin as the
   * vault — so the room secret never reaches the PWA.
   */
  /* c8 ignore start - iframe connect-ceremony UI is exercised in the browser, not the unit env */
  private showConnectCeremony(mode: 'share' | 'accept'): void {
    document.getElementById('unlock-modal')?.classList.add('hidden');
    document.getElementById('connect-modal')?.classList.remove('hidden');
    if (mode === 'accept') {
      this.renderConnectAccept();
    } else {
      const subtitle = document.getElementById('kms-connect-subtitle');
      if (subtitle) subtitle.textContent = 'Generating your invite…';
      this.showConnectView('finishing');
    }
  }

  /** Render the share view: the invite link (with copy) to send out-of-band. */
  private renderConnectShare(blob: string): void {
    const link = document.getElementById('kms-connect-link') as HTMLTextAreaElement | null;
    if (!link) {
      this.emitInviteOutcome('worker:invite-show-cancelled');
      return;
    }
    const url = `https://kms.ats.run/connect#c=${blob}`;
    link.value = url;
    // Render an in-person-scannable QR of the link. Encoded here in the iframe
    // (never the PWA) because the link's fragment carries the room secret. The SVG
    // is derived purely from the module grid — no untrusted text in markup.
    const qrBox = document.getElementById('kms-connect-qr');
    if (qrBox) {
      try {
        qrBox.innerHTML = qrSvg(url);
        // Tap to enlarge the QR to fill the viewport (easier to scan from a
        // distance), tap again to shrink. Reset on each (re)render.
        qrBox.classList.remove('kms-qr-enlarged');
        qrBox.onclick = (): void => {
          qrBox.classList.toggle('kms-qr-enlarged');
        };
      } catch {
        qrBox.innerHTML = ''; // link + copy remain the fallback
      }
    }
    const subtitle = document.getElementById('kms-connect-subtitle');
    if (subtitle) subtitle.textContent = 'Share this link to connect';
    this.showConnectView('share');

    const copyBtn = document.getElementById('kms-connect-copy');
    if (copyBtn) {
      const markCopied = (): void => {
        copyBtn.textContent = 'Copied ✓';
      };
      // Fallback for when the async clipboard API is unavailable/blocked: select the
      // link and use the legacy execCommand (works in this iframe on a user gesture).
      const execCopy = (): boolean => {
        try {
          link.focus();
          link.select();
          if (document.execCommand('copy')) {
            markCopied();
            return true;
          }
        } catch {
          /* fall through */
        }
        return false;
      };
      copyBtn.onclick = (): void => {
        // Select first so the user can always Ctrl+C manually even if both fail.
        link.focus();
        link.select();
        if (navigator.clipboard?.writeText) {
          void navigator.clipboard
            .writeText(url)
            .then(markCopied)
            .catch(() => {
              execCopy();
            });
        } else {
          execCopy();
        }
      };
    }
    const doneBtn = document.getElementById('kms-connect-done');
    if (doneBtn) {
      doneBtn.onclick = (): void => {
        this.showConnectView('finishing');
        this.emitInviteOutcome('worker:invite-shown');
      };
    }
  }

  /** Render the accept view: paste a link, then confirm the sender's fingerprint. */
  private renderConnectAccept(): void {
    const paste = document.getElementById('kms-connect-paste') as HTMLTextAreaElement | null;
    if (!paste) {
      this.emitInviteOutcome('worker:invite-collect-cancelled');
      return;
    }
    const subtitle = document.getElementById('kms-connect-subtitle');
    if (subtitle) subtitle.textContent = 'Scan or paste an invite';
    document.getElementById('kms-connect-paste-error')?.classList.add('hidden');
    const scanStatus = document.getElementById('kms-connect-scan-status');
    if (scanStatus) scanStatus.textContent = '';
    this.showConnectView('accept');

    const cancelBtn = document.getElementById('kms-connect-cancel');
    if (cancelBtn) {
      cancelBtn.onclick = (): void => {
        this.emitInviteOutcome('worker:invite-collect-cancelled');
      };
    }
    const scanBtn = document.getElementById('kms-connect-scan-btn');
    if (scanBtn) {
      scanBtn.onclick = (): void => {
        if (this.connectScanning) {
          this.stopConnectScan();
        } else {
          void this.startConnectScan();
        }
      };
    }
    const checkBtn = document.getElementById('kms-connect-check');
    if (checkBtn) {
      checkBtn.onclick = (): void => {
        void this.confirmConnectPaste(paste.value);
      };
    }
  }

  /** Decode a pasted link + show the sender's name/fingerprint for mutual confirmation. */
  private async confirmConnectPaste(input: string): Promise<void> {
    const errEl = document.getElementById('kms-connect-paste-error');
    let card: { uid: string; name?: string; msk: string; mek: string };
    try {
      card = decodeInvite(input).card;
    } catch {
      if (errEl) {
        errEl.textContent = "That doesn't look like a valid invite link.";
        errEl.classList.remove('hidden');
      }
      return;
    }
    const fp = await identityFingerprint(
      new Uint8Array(base64urlToArrayBuffer(card.msk)),
      new Uint8Array(base64urlToArrayBuffer(card.mek))
    );
    const nameEl = document.getElementById('kms-connect-peer-name');
    if (nameEl) nameEl.textContent = card.name || card.uid;
    const fpEl = document.getElementById('kms-connect-peer-fp');
    if (fpEl) fpEl.textContent = this.formatConnectFingerprint(fp);
    this.showConnectView('confirm');

    const backBtn = document.getElementById('kms-connect-confirm-back');
    if (backBtn) {
      backBtn.onclick = (): void => {
        this.showConnectView('accept');
      };
    }
    const connectBtn = document.getElementById('kms-connect-confirm-connect');
    if (connectBtn) {
      connectBtn.onclick = (): void => {
        this.showConnectView('finishing');
        this.emitInviteOutcome('worker:invite-blob', input);
      };
    }
  }
  /* c8 ignore stop */

  /** Show exactly one connect-modal sub-view; hide the rest. */
  private showConnectView(view: 'share' | 'accept' | 'confirm' | 'finishing'): void {
    // Any view change stops a running scan (leaving accept, or re-entering it).
    this.stopConnectScan();
    document.getElementById('connect-modal')?.classList.remove('hidden');
    for (const v of ['share', 'accept', 'confirm', 'finishing']) {
      document.getElementById(`kms-connect-${v}`)?.classList.toggle('hidden', v !== view);
    }
  }

  /**
   * Start the accept-view QR scanner: open the camera in the iframe and decode
   * frames until an invite QR is found, then hand its text to the same paste path
   * (confirmConnectPaste). Best-effort — if the camera is denied/unavailable
   * (notably iOS Safari in a cross-origin iframe), we surface a hint and the user
   * pastes the link instead. Runs entirely in the iframe; camera pixels are decoded
   * locally and never leave the enclave origin.
   */
  /* c8 ignore start - camera UI is exercised in the browser, not the unit env */
  private async startConnectScan(): Promise<void> {
    const scanBox = document.getElementById('kms-connect-scan');
    const video = document.getElementById('kms-connect-video') as HTMLVideoElement | null;
    const status = document.getElementById('kms-connect-scan-status');
    const btn = document.getElementById('kms-connect-scan-btn');
    if (!scanBox || !video) return;
    if (status) status.textContent = 'Requesting camera…';
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
        audio: false,
      });
      this.connectScanStream = stream;
      this.connectScanning = true;
      video.srcObject = stream;
      await video.play();
      scanBox.classList.remove('hidden');
      if (btn) btn.textContent = 'Stop scanning';
      if (status) status.textContent = 'Point the camera at the invite QR…';
      this.connectScanLoop(video);
    } catch {
      this.stopConnectScan();
      if (status) status.textContent = 'Camera unavailable — paste the invite link below instead.';
    }
  }

  /** Grab video frames onto a canvas and decode each until an invite QR appears. */
  private connectScanLoop(video: HTMLVideoElement): void {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const tick = (): void => {
      if (!this.connectScanning || !ctx) return;
      if (video.readyState >= 2 && video.videoWidth > 0) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        try {
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const text = decodeQr(img.data, img.width, img.height);
          // Only accept a Connect invite QR (has the secret fragment); ignore any
          // other QR the camera happens to see. confirmConnectPaste re-validates.
          if (text && text.includes('#c=')) {
            this.stopConnectScan();
            void this.confirmConnectPaste(text);
            return;
          }
        } catch {
          /* transient frame read error — keep scanning */
        }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  /** Stop the scanner: end the camera stream, halt the loop, reset the UI. */
  private stopConnectScan(): void {
    this.connectScanning = false;
    if (this.connectScanStream) {
      for (const track of this.connectScanStream.getTracks()) track.stop();
      this.connectScanStream = null;
    }
    const video = document.getElementById('kms-connect-video') as HTMLVideoElement | null;
    if (video) video.srcObject = null;
    document.getElementById('kms-connect-scan')?.classList.add('hidden');
    const btn = document.getElementById('kms-connect-scan-btn');
    if (btn) btn.textContent = '📷 Scan QR code';
  }
  /* c8 ignore stop */

  /** Group a base64url fingerprint into uppercase blocks for out-of-band compare. */
  private formatConnectFingerprint(fp: string): string {
    const clean = fp.replace(/[_-]/g, '').toUpperCase();
    const out: string[] = [];
    for (let i = 0; i < clean.length; i += 5) out.push(clean.slice(i, i + 5));
    return out.join(' ');
  }

  showMnemonicCeremony(mnemonic: string): void {
    const port = this.credentialPort;
    const modal = document.getElementById('mnemonic-modal');
    const words = mnemonic.trim().split(/\s+/).filter(Boolean);
    const reveal = document.getElementById('kms-mnemonic-reveal');
    const confirm = document.getElementById('kms-mnemonic-confirm');
    const wordsEl = document.getElementById('kms-mnemonic-words');
    if (!port || !modal || !reveal || !confirm || !wordsEl || words.length === 0) {
      // Can't render → cancel so the worker persists nothing.
      port?.postMessage({ type: 'popup:mnemonic-cancelled' });
      return;
    }

    // Cover the unlock modal with the ceremony.
    document.getElementById('unlock-modal')?.classList.add('hidden');
    document.getElementById('kms-mnemonic-finishing')?.classList.add('hidden');
    modal.classList.remove('hidden');

    // --- Step 1: reveal the words ---
    wordsEl.innerHTML = '';
    for (let i = 0; i < words.length; i++) {
      const li = document.createElement('li');
      li.className = 'kms-mnemonic-word';
      const num = document.createElement('span');
      num.className = 'kms-mnemonic-num';
      num.textContent = String(i + 1);
      const text = document.createElement('span');
      text.className = 'kms-mnemonic-text';
      text.textContent = words[i]!;
      li.appendChild(num);
      li.appendChild(text);
      wordsEl.appendChild(li);
    }
    reveal.classList.remove('hidden');
    confirm.classList.add('hidden');

    const copyBtn = document.getElementById('kms-mnemonic-copy');
    if (copyBtn) {
      copyBtn.onclick = (): void => {
        if (!navigator.clipboard) return; // no clipboard API — the user can read the words
        void navigator.clipboard
          .writeText(words.join(' '))
          .then(() => {
            copyBtn.textContent = 'Copied ✓';
          })
          .catch(() => {
            /* clipboard blocked — the user can still read the words */
          });
      };
    }

    const cancel = (): void => {
      modal.classList.add('hidden');
      port.postMessage({ type: 'popup:mnemonic-cancelled' });
    };
    const cancelBtn = document.getElementById('kms-mnemonic-cancel');
    if (cancelBtn) cancelBtn.onclick = cancel;

    // Required-subset positions the user must re-enter on the confirm screen.
    const required = this.pickRequiredMnemonicIndices(words.length, MNEMONIC_CONFIRM_REQUIRED);

    const continueBtn = document.getElementById('kms-mnemonic-continue');
    if (continueBtn) {
      continueBtn.onclick = (): void => {
        reveal.classList.add('hidden');
        confirm.classList.remove('hidden');
        this.renderMnemonicConfirmGrid(words, required, port, modal);
      };
    }
  }

  /**
   * Restore ceremony (the other half of BUG-007): collect a 12-word recovery
   * phrase in the enclave popup and post it back over the private port. The phrase
   * stays inside kms.ats.run — only the result (entered/cancelled) leaves this
   * window; it never reaches the parent PWA. The worker validates the BIP39
   * checksum, so light 12-word checking here is enough.
   */
  /* c8 ignore start - in-popup recovery-phrase entry UI runs in the browser */
  showMnemonicInputCeremony(): void {
    const port = this.credentialPort;
    const modal = document.getElementById('mnemonic-modal');
    const input = document.getElementById('kms-mnemonic-input');
    const field = document.getElementById('kms-mnemonic-input-field') as HTMLTextAreaElement | null;
    const errEl = document.getElementById('kms-mnemonic-input-error');
    if (!port || !modal || !input || !field) {
      port?.postMessage({ type: 'popup:mnemonic-cancelled' });
      return;
    }

    // Reframe the shared mnemonic modal for restore.
    const header = modal.querySelector('.kms-modal-header h3');
    if (header) header.textContent = '🔑 Restore from your recovery phrase';
    const sub = modal.querySelector('.kms-modal-header .kms-modal-subtitle');
    if (sub) sub.textContent = 'Enter the 12 words you saved when you first set up messaging.';

    // Show only the input view.
    document.getElementById('unlock-modal')?.classList.add('hidden');
    for (const v of ['reveal', 'confirm', 'finishing']) {
      document.getElementById(`kms-mnemonic-${v}`)?.classList.add('hidden');
    }
    input.classList.remove('hidden');
    modal.classList.remove('hidden');
    field.value = '';
    errEl?.classList.add('hidden');
    field.focus();

    const cancelBtn = document.getElementById('kms-mnemonic-input-cancel');
    if (cancelBtn) {
      cancelBtn.onclick = (): void => {
        modal.classList.add('hidden');
        port.postMessage({ type: 'popup:mnemonic-cancelled' });
      };
    }
    const submitBtn = document.getElementById('kms-mnemonic-input-submit');
    if (submitBtn) {
      submitBtn.onclick = (): void => {
        const words = field.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
        if (words.length !== 12) {
          if (errEl) {
            errEl.textContent = `Enter all 12 words (you entered ${words.length}).`;
            errEl.classList.remove('hidden');
          }
          return;
        }
        // Hand off to the worker (it validates the checksum) and show a working
        // state; on a bad phrase the RPC rejects and the PWA surfaces the error.
        input.classList.add('hidden');
        document.getElementById('kms-mnemonic-finishing')?.classList.remove('hidden');
        port.postMessage({ type: 'popup:mnemonic-entered', mnemonic: words.join(' ') });
      };
    }
  }
  /* c8 ignore stop */

  /** Pick `count` distinct random positions in `[0,total)` for the confirm screen. */
  private pickRequiredMnemonicIndices(total: number, count: number): Set<number> {
    const picks = new Set<number>();
    const n = Math.min(count, total);
    while (picks.size < n) {
      picks.add(crypto.getRandomValues(new Uint32Array(1))[0]! % total);
    }
    return picks;
  }

  /**
   * Render the confirm-screen input grid (words hidden). Required positions are
   * highlighted; pasting the whole phrase into any field distributes it across
   * all inputs. On verify: every required field must be filled + correct, and
   * every OTHER filled field must also match — then post `popup:mnemonic-confirmed`.
   */
  private renderMnemonicConfirmGrid(
    words: string[],
    required: Set<number>,
    port: MessagePort,
    modal: HTMLElement
  ): void {
    const grid = document.getElementById('kms-mnemonic-confirm-grid');
    const errEl = document.getElementById('kms-mnemonic-confirm-error');
    if (!grid) return;
    grid.innerHTML = '';
    errEl?.classList.add('hidden');

    const inputs: HTMLInputElement[] = [];
    for (let i = 0; i < words.length; i++) {
      const cell = document.createElement('div');
      cell.className = 'kms-mnemonic-cell' + (required.has(i) ? ' kms-required' : '');
      const num = document.createElement('span');
      num.className = 'kms-mnemonic-num';
      num.textContent = String(i + 1);
      const input = document.createElement('input');
      input.type = 'text';
      input.autocomplete = 'off';
      input.spellcheck = false;
      input.className = 'kms-mnemonic-input';
      input.onpaste = (e: ClipboardEvent): void => {
        const text = e.clipboardData?.getData('text') ?? '';
        const parts = text.trim().split(/\s+/).filter(Boolean);
        if (parts.length > 1) {
          e.preventDefault();
          for (let j = 0; j < inputs.length; j++) {
            if (parts[j] !== undefined) inputs[j]!.value = normalizeMnemonicWord(parts[j]!);
          }
        }
      };
      inputs.push(input);
      cell.appendChild(num);
      cell.appendChild(input);
      grid.appendChild(cell);
    }

    const backBtn = document.getElementById('kms-mnemonic-back');
    if (backBtn) {
      backBtn.onclick = (): void => {
        document.getElementById('kms-mnemonic-confirm')?.classList.add('hidden');
        document.getElementById('kms-mnemonic-reveal')?.classList.remove('hidden');
      };
    }

    const verifyBtn = document.getElementById('kms-mnemonic-verify');
    if (verifyBtn) {
      verifyBtn.onclick = (): void => {
        let ok = true;
        for (let i = 0; i < inputs.length; i++) {
          const val = normalizeMnemonicWord(inputs[i]!.value);
          const missingRequired = required.has(i) && val === '';
          const wrong = val !== '' && val !== words[i];
          const bad = missingRequired || wrong;
          if (bad) ok = false;
          inputs[i]!.classList.toggle('kms-invalid', bad);
        }
        if (!ok) {
          if (errEl) {
            errEl.textContent = "Some words don't match. Check the highlighted fields.";
            errEl.classList.remove('hidden');
          }
          return;
        }
        // Confirmed → let the worker persist; show a finishing state until the
        // relayed unlock result swaps in the success panel (or an error).
        errEl?.classList.add('hidden');
        document.getElementById('kms-mnemonic-reveal')?.classList.add('hidden');
        document.getElementById('kms-mnemonic-confirm')?.classList.add('hidden');
        document.getElementById('kms-mnemonic-finishing')?.classList.remove('hidden');
        void modal; // kept visible; handlePopupUnlockResult/showUnlockSuccess hides it
        port.postMessage({ type: 'popup:mnemonic-confirmed' });
      };
    }
  }

  /** Close the popup window, tolerating environments where close() is blocked. */
  private closePopupWindow(): void {
    try {
      window.close();
    } catch {
      /* jsdom / blocked — ignore */
    }
  }

  /**
   * Render the shared popup auto-close footer into `container` (a success panel).
   * With `countdown`, reads the `kms:autoclose` localStorage flag (default on):
   * when on, counts down {@link POPUP_CLOSE_COUNTDOWN_SECONDS}s then closes; the
   * checkbox persists the choice and starts/stops the countdown live. A "Close
   * now" button always closes immediately. Idempotent (replaces any prior footer).
   */
  private renderPopupClose(container: HTMLElement, opts: { countdown: boolean }): void {
    container.querySelector('.kms-popup-close')?.remove();

    const footer = document.createElement('div');
    footer.className = 'kms-popup-close';

    let timer: ReturnType<typeof setInterval> | null = null;
    const clearTimer = (): void => {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
    };

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'kms-auth-btn kms-secondary kms-popup-close-btn';
    closeBtn.textContent = 'Close now';
    closeBtn.onclick = (): void => {
      clearTimer();
      this.closePopupWindow();
    };
    footer.appendChild(closeBtn);

    if (opts.countdown) {
      let autoClose = true;
      try {
        autoClose = localStorage.getItem(POPUP_AUTOCLOSE_KEY) !== '0';
      } catch {
        /* ignore */
      }

      const countdownEl = document.createElement('div');
      countdownEl.className = 'kms-countdown';

      const label = document.createElement('label');
      label.className = 'kms-autoclose-label';
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'kms-autoclose-checkbox';
      checkbox.checked = autoClose;
      label.appendChild(checkbox);
      label.appendChild(document.createTextNode('Close automatically'));

      footer.appendChild(countdownEl);
      footer.appendChild(label);

      const startCountdown = (): void => {
        let remaining = POPUP_CLOSE_COUNTDOWN_SECONDS;
        countdownEl.textContent = `Closing in ${remaining}s…`;
        timer = setInterval(() => {
          remaining -= 1;
          if (remaining <= 0) {
            clearTimer();
            this.closePopupWindow();
            return;
          }
          countdownEl.textContent = `Closing in ${remaining}s…`;
        }, 1000);
      };

      checkbox.onchange = (): void => {
        try {
          localStorage.setItem(POPUP_AUTOCLOSE_KEY, checkbox.checked ? '1' : '0');
        } catch {
          /* ignore */
        }
        if (checkbox.checked) {
          startCountdown();
        } else {
          clearTimer();
          countdownEl.textContent = '';
        }
      };

      if (autoClose) startCountdown();
    }

    container.appendChild(footer);
  }

  /**
   * Hide setup success message
   */
  private hideSetupSuccess(): void {
    const successDiv = document.getElementById('kms-setup-success');
    if (successDiv) {
      successDiv.classList.add('hidden');
    }
  }

  /**
   * Notify parent window that setup is complete
   *
   * Uses multiple strategies for cross-origin communication:
   * 1. Direct postMessage to window.opener (if available)
   * 2. LocalStorage flag for same-origin iframe coordination
   * 3. BroadcastChannel for modern browser support
   */
  private notifySetupComplete(data: { method: string; result: unknown }): void {
    const message = {
      type: 'kms:setup-complete',
      method: data.method,
      result: data.result,
    };

    // Strategy 1: Direct postMessage if window.opener is available
    if (window.opener) {
      (window.opener as Window).postMessage(message, this.parentOrigin);
    }

    // Strategy 2: LocalStorage flag for same-origin iframe coordination
    // This allows the iframe (on same origin) to detect setup completion
    try {
      localStorage.setItem('kms:setup-complete', JSON.stringify({
        timestamp: Date.now(),
        ...message,
      }));
    } catch (err) {
      console.warn('[KMS Client] Failed to set localStorage flag:', err);
    }

    // Strategy 3: BroadcastChannel for modern browsers (same-origin only)
    try {
      const channel = new BroadcastChannel('kms-setup');
      channel.postMessage(message);
      channel.close();
    } catch (err) {
      console.warn('[KMS Client] BroadcastChannel not available:', err);
    }
  }

  /**
   * Terminate the Worker and cleanup
   *
   * Useful for testing or manual cleanup.
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async terminate(): Promise<void> {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }

    this.isInitialized = false;
  }

  /**
   * Legacy API compatibility: Send RPC request directly (for testing)
   *
   * This method exists for backward compatibility with tests that expect
   * a synchronous send() method. In production, messages flow through
   * postMessage handlers.
   *
   * @deprecated Use postMessage-based communication instead
   * @param request - RPC request
   * @returns RPC response
   */
  async send(request: RPCRequest): Promise<RPCResponse> {
    // For testing environments, import worker directly
    // This provides backward compatibility with tests
    const { handleMessage } = await import('./worker.js');
    return await handleMessage(request);
  }
}

/**
 * Auto-initialize in browser environment
 *
 * When loaded in iframe, automatically creates and initializes KMSClient.
 * Parent origin is extracted from URL search params or defaults to localhost.
 */
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  // Extract parent origin from URL search params
  const params = new URLSearchParams(window.location.search);
  const parentOrigin = params.get('parentOrigin') ?? 'https://allthe.services';

  // Detect if we're in an iframe or standalone window
  const isIframe = window.self !== window.top;
  // Check for setup mode via URL param OR window.opener
  const isSetupMode = params.get('mode') === 'setup' || params.has('setup');
  const isStandaloneSetup = !isIframe && (window.opener !== null || isSetupMode);

  // Create and initialize client
  const client = new KMSClient({ parentOrigin });

  // Initialize when DOM is ready
  const initFn = (): void => {
    client.init().catch((err) => {
      console.error('[KMS Client] Auto-initialization failed:', err);
    });

    // If standalone setup window, handle two flows:
    // 1. Stateless popup (legacy): transport params in URL
    // 2. KMS-only popup (new): receives transport params via MessageChannel
    if (isStandaloneSetup) {
      const hasTransportParams = params.has('transportKey') && params.has('keyId');

      if (!hasTransportParams) {
        // KMS-only popup flow: no transport params in URL
        // Signal ready to parent (which will forward to iframe)
        /* eslint-disable-next-line no-console */
        console.log('[KMS Client] Popup in KMS-only mode, signaling ready to parent...');

        // Send ready signal to parent (who will forward to iframe)
        // Parent origin is in URL params
        const popupParentOrigin = params.get('parentOrigin') ?? 'http://localhost:5173';
        if (window.opener) {
          /* eslint-disable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
          window.opener.postMessage(
            { type: 'kms:popup-ready' },
            popupParentOrigin
          );
          /* eslint-enable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
        }

        // Step 1: Listen for kms:connect-port from parent (cross-origin)
        // Parent creates MessageChannel and transfers one port to popup
        window.addEventListener('message', (event: MessageEvent) => {
          const data = event.data as {
            type?: string;
            requestId?: string;
          };

          // Accept kms:connect-port from parent (parentOrigin)
          if (data?.type === 'kms:connect-port' && event.origin === popupParentOrigin) {
            /* eslint-disable no-console */
            console.log('[KMS Client] Popup received kms:connect-port from parent');
            /* eslint-enable no-console */

            if (!event.ports || !event.ports[0]) {
              console.error('[KMS Client] No MessagePort received with kms:connect-port');
              return;
            }

            const port = event.ports[0];

            // Step 2: Listen for kms:connect message on MessagePort (from iframe)
            port.onmessage = (portEvent: MessageEvent): void => {
              const portData = portEvent.data as {
                type?: string;
                operation?: 'setup' | 'unlock' | 'connect';
                mode?: 'share' | 'accept';
                blob?: string;
                method?: 'passkey-prf' | 'passkey-gate';
                options?: {
                  hasPassphrase: boolean;
                  hasPasskeyPrf: boolean;
                  hasPasskeyGate: boolean;
                  appSalt?: string;
                  credentialId?: string;
                  rpId?: string;
                };
                transportKey?: string;
                transportKeyId?: string;
                appSalt?: string;
                credentialId?: string;
                hkdfSalt?: string;
                userId?: string;
                success?: boolean;
                error?: string;
                mnemonic?: string;
              };

              // Iframe relayed the unlock outcome (BUG-011 follow-up): confirm +
              // auto-close on success, or surface the error in the popup.
              if (portData?.type === 'popup:unlock-result') {
                client.handlePopupUnlockResult(portData.success === true, portData.error);
                return;
              }

              // BUG-007: worker minted a fresh account root — run the in-popup
              // recovery-phrase backup ceremony (reveal → confirm). The phrase
              // stays in this enclave popup; only confirmed/cancelled goes back.
              if (portData?.type === 'popup:show-mnemonic') {
                client.showMnemonicCeremony(portData.mnemonic ?? '');
                return;
              }

              // Restore: worker wants the recovery phrase — run the in-popup 12-word
              // entry ceremony. The entered phrase stays in this enclave popup; only
              // the result (entered/cancelled) goes back over the port.
              if (portData?.type === 'popup:collect-mnemonic') {
                client.showMnemonicInputCeremony();
                return;
              }

              // Connect ceremony (rooms §3.2/§3.4) now renders in the IFRAME modal,
              // not a popup (no credential is collected), so there are no
              // popup:show-invite / collect-invite / connect-result relays here.

              if (portData?.type === 'kms:connect') {
                /* eslint-disable no-console */
                console.log('[KMS Client] Popup received kms:connect via MessagePort', portData.operation ?? 'setup');
                /* eslint-enable no-console */

                /* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access */
                if (portData.operation === 'unlock') {
                  // BUG-008: top-level unlock in the popup (approach B).
                  (client as any).appSalt = portData.appSalt ?? null;
                  (client as any).unlockCredentialId = portData.credentialId ?? null;
                  (client as any).userId = portData.userId!;
                  (client as any).credentialPort = port;

                  if (portData.options) {
                    // Messaging unlock: the user picks passphrase OR passkey in the
                    // popup modal. Default the passkey method to PRF when available.
                    const opts = portData.options;
                    (client as any).unlockMethod = opts.hasPasskeyPrf ? 'passkey-prf' : 'passkey-gate';
                    port.postMessage({ type: 'popup:connected' });
                    client.setupPopupUnlockModal(opts);
                  } else {
                    // Legacy passkey-only unlock (non-messaging iframe modal → popup):
                    // the user already chose passkey in the iframe, so auto-run the
                    // ceremony (top-level, so the password manager and PRF salt work).
                    (client as any).unlockMethod = portData.method ?? 'passkey-prf';
                    port.postMessage({ type: 'popup:connected' });
                    void client.runPopupUnlockCeremony();
                  }
                } else {
                  // Setup flow (unchanged): store transport params, show setup modal.
                  (client as any).transportPublicKey = portData.transportKey!;
                  (client as any).transportKeyId = portData.transportKeyId!;
                  (client as any).appSalt = portData.appSalt!;
                  (client as any).hkdfSalt = portData.hkdfSalt!;
                  (client as any).userId = portData.userId!; // Store userId from parent
                  (client as any).isStatelessPopup = true;

                  // Store the MessagePort for sending credentials later
                  (client as any).credentialPort = port;

                  // Confirm connection
                  port.postMessage({ type: 'popup:connected' });

                  // Show setup modal
                  setTimeout(() => {
                    client.setupSetupModalHandlers();
                    const setupModal = document.getElementById('setup-modal');
                    if (setupModal) {
                      setupModal.classList.remove('hidden');
                    }
                  }, 100);
                }
                /* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access */
              }
            };
          }
        });
      } else {
        // Legacy stateless popup flow: transport params in URL
        setTimeout(() => {
          client.setupSetupModalHandlers();
          const setupModal = document.getElementById('setup-modal');
          if (setupModal) {
            setupModal.classList.remove('hidden');
          }
        }, 100);
      }
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFn);
  } else {
    initFn();
  }

  // Prevent form submission on password forms (CSP-compliant)
  // This replaces inline onsubmit handlers which violate CSP
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      const unlockForm = document.getElementById('kms-unlock-form');
      const setupForm = document.getElementById('kms-setup-form');

      if (unlockForm) {
        unlockForm.addEventListener('submit', (e) => {
          e.preventDefault();
          return false;
        });
      }

      if (setupForm) {
        setupForm.addEventListener('submit', (e) => {
          e.preventDefault();
          return false;
        });
      }
    });
  } else {
    const unlockForm = document.getElementById('kms-unlock-form');
    const setupForm = document.getElementById('kms-setup-form');

    if (unlockForm) {
      unlockForm.addEventListener('submit', (e) => {
        e.preventDefault();
        return false;
      });
    }

    if (setupForm) {
      setupForm.addEventListener('submit', (e) => {
        e.preventDefault();
        return false;
      });
    }
  }

  // If running in iframe, listen for setup completion signals from popup window
  if (isIframe) {
    // Define the setup message type for type safety
    interface SetupCompleteMessage {
      type: string;
      method: string;
      result: unknown;
      timestamp?: number;
    }

    // Listen for BroadcastChannel messages from setup popup
    try {
      // Listen for stateless popup credentials (Phase 2)
      const credentialsChannel = new BroadcastChannel('kms-setup-credentials');
      credentialsChannel.addEventListener('message', (event) => {
        /* eslint-disable no-console, @typescript-eslint/no-unsafe-member-access */
        console.log('[KMS Client] Iframe received credentials from popup via BroadcastChannel');
        if (event.data?.type === 'kms:setup-credentials') {
          // Forward to parent PWA
          if (window.parent) {
            window.parent.postMessage(event.data, parentOrigin);
            console.log('[KMS Client] Iframe forwarded credentials to parent');
          }
        }
        /* eslint-enable no-console, @typescript-eslint/no-unsafe-member-access */
      });

      // Listen for legacy setup complete messages
      const setupChannel = new BroadcastChannel('kms-setup');
      setupChannel.addEventListener('message', (event) => {
        const data = event.data as SetupCompleteMessage;
        if (data?.type === 'kms:setup-complete') {
          // Forward to parent PWA
          if (window.parent) {
            window.parent.postMessage(data, parentOrigin);
          }
        }
      });
    } catch (err) {
      console.warn('[KMS Client] BroadcastChannel not available for iframe:', err);
    }

    // Listen for localStorage changes from setup popup
    window.addEventListener('storage', (event) => {
      // Handle stateless popup credentials
      if (event.key === 'kms:setup-credentials' && event.newValue) {
        try {
          /* eslint-disable no-console, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access */
          console.log('[KMS Client] Iframe received credentials from popup via localStorage');
          const data = JSON.parse(event.newValue);
          if (data?.type === 'kms:setup-credentials') {
            // Forward to parent PWA
            if (window.parent) {
              window.parent.postMessage(data, parentOrigin);
              console.log('[KMS Client] Iframe forwarded credentials to parent');
            }
          /* eslint-enable no-console, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access */
            // Clear the flag
            localStorage.removeItem('kms:setup-credentials');
          }
        } catch (err) {
          console.warn('[KMS Client] Failed to parse setup-credentials from localStorage:', err);
        }
      }

      // Handle legacy setup complete messages
      if (event.key === 'kms:setup-complete' && event.newValue) {
        try {
          const message = JSON.parse(event.newValue) as SetupCompleteMessage;
          // Forward to parent PWA
          if (window.parent) {
            window.parent.postMessage({
              type: message.type,
              method: message.method,
              result: message.result,
            }, parentOrigin);
          }
          // Clear the flag
          localStorage.removeItem('kms:setup-complete');
        } catch (err) {
          console.warn('[KMS Client] Failed to parse setup-complete from localStorage:', err);
        }
      }
    });

    // Also check localStorage on load in case we missed the event
    try {
      const stored = localStorage.getItem('kms:setup-complete');
      if (stored) {
        const message = JSON.parse(stored) as SetupCompleteMessage;
        // Only forward if recent (within last 5 seconds)
        if (message.timestamp && Date.now() - message.timestamp < 5000) {
          if (window.parent) {
            window.parent.postMessage({
              type: message.type,
              method: message.method,
              result: message.result,
            }, parentOrigin);
          }
        }
        // Clear the flag
        localStorage.removeItem('kms:setup-complete');
      }
    } catch (err) {
      console.warn('[KMS Client] Failed to check localStorage for setup-complete:', err);
    }
  }

  // Note: Removed localStorage polling - credentials are sent via MessageChannel
  // from popup directly to parent (see handlePassphraseSetup in stateless mode)

  // Export for debugging
  (window as Window & { __kmsClient?: unknown }).__kmsClient = client;
  (window as Window & { __kmsContext?: unknown }).__kmsContext = { isIframe, isStandaloneSetup };
}
