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

import type { RPCRequest, RPCResponse, AuthCredentials } from './types.js';
import { formatError, getErrorMessage } from './error-utils.js';
import { getPRFResults } from './webauthn-types.js';
import { arrayBufferToBase64url, base64urlToArrayBuffer } from './crypto-utils.js';

// Global constant injected at build time by esbuild
declare const __WORKER_FILENAME__: string;

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

  // Stateless popup mode properties
  private isStatelessPopup: boolean = false;
  private transportPublicKey: string | null = null;
  private transportKeyId: string | null = null;
  private appSalt: string | null = null;
  // Note: hkdfSalt from URL is not used directly in popup (sent to iframe via encrypted message)

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
      // hkdfSalt is available in URL but not used directly in popup (sent to iframe)
      this.isStatelessPopup = !!(this.transportPublicKey && this.transportKeyId);

      console.log('[KMS Client] Popup detection:', {
        url: window.location.href,
        transportKey: this.transportPublicKey?.slice(0, 20) + '...',
        keyId: this.transportKeyId,
        isStatelessPopup: this.isStatelessPopup
      });

      if (this.isStatelessPopup) {
        console.log('[KMS Client] Running in stateless popup mode');
      }

      // Create Dedicated Worker
      this.worker = new Worker(this.workerUrl, {
        type: 'module',
        name: 'kms-worker-v2',
      });

      // Setup Worker message handler
      this.worker.addEventListener('message', this.handleWorkerMessage.bind(this));

      // Setup Worker error handler
      this.worker.addEventListener('error', this.handleWorkerError.bind(this));

      // Setup parent window message handler
      window.addEventListener('message', this.handleParentMessage.bind(this));

      this.isInitialized = true;

      // Signal ready to parent (skip in stateless popup mode - popup doesn't need persistent connection)
      if (!this.isStatelessPopup) {
        this.sendToParent({ type: 'kms:ready' });
      } else {
        console.log('[KMS Client] Skipping kms:ready in stateless popup mode');
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

    // Validate client is initialized
    if (!this.isInitialized || !this.worker) {
      console.error('[KMS Client] Received message before initialization');
      return;
    }

    const request = event.data as RPCRequest;

    // Intercept operations that require authentication
    // These will show modal, collect credentials, then execute
    const authRequiredMethods = ['createLease', 'generateVAPID', 'signJWT', 'regenerateVAPID', 'addEnrollment'];
    if (request?.method && authRequiredMethods.includes(request.method)) {
      this.showUnlockModal(request);
      return; // Don't forward to worker yet
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
   *
   * @param event - Message event from Worker
   */
  private handleWorkerMessage(event: MessageEvent): void {
    try {
      const data = event.data as RPCResponse | { type: string; [key: string]: unknown };
      this.sendToParent(data);
    } catch (err: unknown) {
      console.error('[KMS Client] Failed to forward message to parent:', err);
    }
  }

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
    const isPopup = window.opener !== null && window.opener !== window;
    const targetWindow = isPopup ? window.opener : window.parent;

    if (!targetWindow || targetWindow === window) {
      console.error('[KMS Client] No parent/opener window available', {
        isPopup,
        hasOpener: window.opener !== null,
        hasParent: window.parent !== window
      });
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
      // Load appSalt for PRF (or generate new one for first unlock attempt)
      const appSaltStr = localStorage.getItem('kms:appSalt');
      let appSalt: Uint8Array;

      if (appSaltStr) {
        // Parse stored appSalt
        appSalt = new Uint8Array(appSaltStr.split(',').map(n => parseInt(n, 10)));
      } else {
        // Generate new appSalt for first unlock attempt
        appSalt = crypto.getRandomValues(new Uint8Array(32));
      }

      // Call WebAuthn in iframe context - ALWAYS try PRF extension
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: new Uint8Array(32), // Dummy challenge for demo
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

      // WebAuthn succeeded - now execute the pending operation with credentials
      if (!this.pendingUnlockRequest) {
        throw new Error('No pending operation');
      }

      // Extract userId from the pending request params
      const userId = (this.pendingUnlockRequest.params as { userId?: string } | undefined)?.userId;
      if (!userId) {
        throw new Error('userId not found in request params');
      }

      // Check what enrollment methods exist for this user
      // We need to match the unlock method to the setup method
      const enrollments = await this.getEnrollments(userId);


      // Build credentials object based on enrollment type (include userId)
      // Use PRF only if user has PRF enrollment, otherwise use Gate
      const hasPRFEnrollment = enrollments.includes('enrollment:passkey-prf:v2');
      const hasGateEnrollment = enrollments.includes('enrollment:passkey-gate:v2');

      let credentials: AuthCredentials;
      if (hasPRFEnrollment && prfOutput) {
        credentials = { method: 'passkey-prf', prfOutput, userId };
      } else if (hasGateEnrollment) {
        credentials = { method: 'passkey-gate', userId };
      } else {
        throw new Error('No passkey enrollment found for this user');
      }


      // Add credentials to the request params
      const requestWithCredentials: RPCRequest = {
        ...this.pendingUnlockRequest,
        params: {
          ...(this.pendingUnlockRequest.params as Record<string, unknown>),
          credentials,
        },
      };

      // Send to worker and setup response listener
      this.setupUnlockResponseListener(requestWithCredentials);
      this.worker?.postMessage(requestWithCredentials);
    } catch (err: unknown) {
      this.hideLoading();
      this.showError(`WebAuthn failed: ${getErrorMessage(err)}`);
      console.error('[KMS Client] WebAuthn unlock failed:', err);
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
      const userId = 'demouser@ats.run';
      const rpId = window.location.hostname; // kms.ats.run or localhost

      // Check if stateless popup mode
      if (this.isStatelessPopup) {
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
                  first: appSalt as BufferSource,
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
                      first: appSalt as BufferSource,
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

        // Step 6: Send to parent with detected method
        if (window.opener) {
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

          // Show success and close
          this.hideSetupLoading();
          this.showSetupSuccess();
          setTimeout(() => window.close(), 2000);
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
                first: appSalt as BufferSource,
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
                  first: appSalt as BufferSource,
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
      const userId = 'demouser@ats.run';

      console.log('[KMS Client] handlePassphraseSetup - isStatelessPopup:', this.isStatelessPopup, {
        transportKey: this.transportPublicKey?.slice(0, 20) + '...',
        keyId: this.transportKeyId
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

        console.log('[KMS Client] Credentials encrypted, preparing to send to parent');

        // Prepare message
        const message = {
          type: 'kms:setup-credentials',
          method: 'passphrase',
          transportKeyId: this.transportKeyId,
          userId,
          ...encrypted,
        };

        // Send to parent - try ALL strategies (not just one) for maximum reliability
        let sent = false;

        // Strategy 1: Try window.opener if available
        if (window.opener) {
          try {
            console.log('[KMS Client] Sending encrypted credentials via window.opener');
            (window.opener as Window).postMessage(message, this.parentOrigin);
            sent = true;
          } catch (err) {
            console.warn('[KMS Client] Failed to send via window.opener:', err);
          }
        }

        // Strategy 2: Use localStorage (most reliable for popup→iframe same-origin)
        try {
          console.log('[KMS Client] Sending encrypted credentials via localStorage');
          localStorage.setItem('kms:setup-credentials', JSON.stringify({
            ...message,
            timestamp: Date.now()
          }));
          sent = true;
        } catch (err) {
          console.warn('[KMS Client] Failed to send via localStorage:', err);
        }

        // Strategy 3: Use BroadcastChannel (may not work popup→iframe)
        try {
          console.log('[KMS Client] Sending encrypted credentials via BroadcastChannel');
          const channel = new BroadcastChannel('kms-setup-credentials');
          channel.postMessage(message);
          channel.close();
          sent = true;
        } catch (err) {
          console.warn('[KMS Client] Failed to send via BroadcastChannel:', err);
        }

        if (sent) {
          // Show success and close
          this.hideSetupLoading();
          this.showSetupSuccess();
          setTimeout(() => window.close(), 2000);
        } else {
          console.error('[KMS Client] All communication strategies failed!');
          this.hideSetupLoading();
          this.showSetupError('Cannot communicate with parent window. Please try again.');
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
   * Show setup success message
   */
  private showSetupSuccess(): void {
    const successDiv = document.getElementById('kms-setup-success');
    if (successDiv) {
      successDiv.classList.remove('hidden');
    }
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

    // If standalone setup window, show setup modal immediately
    if (isStandaloneSetup) {
      // Wait a bit for client to fully initialize
      setTimeout(() => {
        client.setupSetupModalHandlers();
        const setupModal = document.getElementById('setup-modal');
        if (setupModal) {
          setupModal.classList.remove('hidden');
        }
      }, 100);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFn);
  } else {
    initFn();
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
        console.log('[KMS Client] Iframe received credentials from popup via BroadcastChannel');
        if (event.data?.type === 'kms:setup-credentials') {
          // Forward to parent PWA
          if (window.parent) {
            window.parent.postMessage(event.data, parentOrigin);
            console.log('[KMS Client] Iframe forwarded credentials to parent');
          }
        }
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
          console.log('[KMS Client] Iframe received credentials from popup via localStorage');
          const data = JSON.parse(event.newValue);
          if (data?.type === 'kms:setup-credentials') {
            // Forward to parent PWA
            if (window.parent) {
              window.parent.postMessage(data, parentOrigin);
              console.log('[KMS Client] Iframe forwarded credentials to parent');
            }
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

  // If iframe, poll localStorage for credentials from popup (in case storage event doesn't fire)
  if (isIframe) {
    console.log('[KMS Client] Iframe: Starting localStorage polling for popup credentials...');
    const pollInterval = setInterval(() => {
      try {
        const stored = localStorage.getItem('kms:setup-credentials');
        if (stored) {
          const data = JSON.parse(stored);
          if (data?.type === 'kms:setup-credentials' && data.timestamp && Date.now() - data.timestamp < 30000) {
            console.log('[KMS Client] Iframe found credentials in localStorage (polling)!', {
              hasType: !!data.type,
              type: data.type,
              hasCredentials: !!data.encryptedCredentials,
              keys: Object.keys(data)
            });
            clearInterval(pollInterval);
            // Forward to parent PWA
            if (window.parent) {
              console.log('[KMS Client] Iframe forwarding to parent:', parentOrigin);
              window.parent.postMessage(data, parentOrigin);
              console.log('[KMS Client] Iframe forwarded credentials to parent');
            }
            // Clear the flag
            localStorage.removeItem('kms:setup-credentials');
          }
        }
      } catch (err) {
        // Ignore polling errors
      }
    }, 200); // Poll every 200ms

    // Stop polling after 5 minutes
    setTimeout(() => clearInterval(pollInterval), 5 * 60 * 1000);
  }

  // Export for debugging
  (window as Window & { __kmsClient?: unknown }).__kmsClient = client;
  (window as Window & { __kmsContext?: unknown }).__kmsContext = { isIframe, isStandaloneSetup };
}
