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

import type { RPCRequest, RPCResponse } from './types.js';

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

  /**
   * Create a new KMS client bridge
   *
   * @param config - Client configuration
   */
  constructor(config: KMSClientConfig) {
    this.parentOrigin = config.parentOrigin;
    this.workerUrl = config.workerUrl ?? new URL('./worker.js', import.meta.url).href;
  }

  /**
   * Initialize the KMS client
   *
   * Creates the Worker, sets up message handlers, and signals ready to parent.
   *
   * @throws {Error} If already initialized or Worker creation fails
   */
  async init(): Promise<void> {
    if (this.isInitialized) {
      throw new Error('KMSClient already initialized');
    }

    try {
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

      // Signal ready to parent
      this.sendToParent({ type: 'kms:ready' });
    } catch (err: any) {
      console.error('[KMS Client] Initialization failed:', err);
      throw new Error(`Failed to initialize KMS client: ${err.message}`);
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
      console.log('[KMS Client] Operation requires authentication:', request.method);
      this.showUnlockModal(request);
      return; // Don't forward to worker yet
    }

    // Forward to Worker
    try {
      this.worker.postMessage(event.data);
    } catch (err: any) {
      console.error('[KMS Client] Failed to forward message to Worker:', err);

      // Send error response to parent
      if (request?.id) {
        this.sendToParent({
          id: request.id,
          error: `Failed to forward message: ${err.message}`,
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
      this.sendToParent(event.data);
    } catch (err: any) {
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
  private sendToParent(data: any): void {
    if (!window.parent) {
      console.error('[KMS Client] No parent window available');
      return;
    }

    try {
      window.parent.postMessage(data, this.parentOrigin);
    } catch (err: any) {
      console.error('[KMS Client] Failed to send message to parent:', err);
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

      const handler = (event: MessageEvent) => {
        const response = event.data as RPCResponse;
        if (response.id === requestId) {
          this.worker?.removeEventListener('message', handler);
          if (response.error) {
            reject(new Error(response.error));
          } else {
            resolve(response.result?.enrollments || []);
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
    modal.style.display = 'flex';

    // Setup WebAuthn button handler
    webauthnBtn.onclick = () => this.handleWebAuthnUnlock();

    // Setup passphrase button handler
    passphraseBtn.onclick = () => this.handlePassphraseUnlock(passphraseInput.value);

    // Setup Enter key for passphrase
    passphraseInput.onkeydown = (e) => {
      if (e.key === 'Enter') {
        this.handlePassphraseUnlock(passphraseInput.value);
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
                first: appSalt,
              },
            },
          },
        },
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('No credential returned');
      }

      // Check if PRF succeeded
      const prfExt = (credential as any).getClientExtensionResults().prf;
      const prfOutput = prfExt?.results?.first;

      console.log('[KMS Client] PRF extension result:', {
        prfExt,
        hasResults: !!prfExt?.results,
        hasFirst: !!prfExt?.results?.first,
        prfOutputType: prfOutput ? prfOutput.constructor.name : 'undefined'
      });

      // WebAuthn succeeded - now execute the pending operation with credentials
      if (!this.pendingUnlockRequest) {
        throw new Error('No pending operation');
      }

      // Extract userId from the pending request params
      const userId = this.pendingUnlockRequest.params?.userId;
      if (!userId) {
        throw new Error('userId not found in request params');
      }

      // Check what enrollment methods exist for this user
      // We need to match the unlock method to the setup method
      const enrollments = await this.getEnrollments(userId);

      console.log('[KMS Client] User enrollments:', enrollments);

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

      console.log('[KMS Client] Built credentials:', { method: credentials.method, userId, hasPrfOutput: !!prfOutput });

      // Add credentials to the request params
      const requestWithCredentials: RPCRequest = {
        ...this.pendingUnlockRequest,
        params: {
          ...this.pendingUnlockRequest.params,
          credentials,
        },
      };

      // Send to worker and setup response listener
      this.setupUnlockResponseListener(requestWithCredentials);
      this.worker?.postMessage(requestWithCredentials);
    } catch (err: any) {
      this.hideLoading();
      this.showError(`WebAuthn failed: ${err.message}`);
      console.error('[KMS Client] WebAuthn unlock failed:', err);
    }
  }

  /**
   * Handle passphrase unlock attempt
   *
   * @param passphrase - User-entered passphrase
   */
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
      const userId = this.pendingUnlockRequest.params?.userId;
      if (!userId) {
        throw new Error('userId not found in request params');
      }

      // Add credentials to the request params (include userId)
      const requestWithCredentials: RPCRequest = {
        ...this.pendingUnlockRequest,
        params: {
          ...this.pendingUnlockRequest.params,
          credentials: { method: 'passphrase', passphrase, userId },
        },
      };

      // Send to worker and setup response listener
      this.setupUnlockResponseListener(requestWithCredentials);
      this.worker?.postMessage(requestWithCredentials);
    } catch (err: any) {
      this.hideLoading();
      this.showError(`Unlock failed: ${err.message}`);
      console.error('[KMS Client] Passphrase unlock failed:', err);
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
    const handleOperationResponse = (event: MessageEvent) => {
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
      errorDiv.style.display = 'block';
    }
  }

  /**
   * Hide error message
   */
  private hideError(): void {
    const errorDiv = document.getElementById('kms-modal-error');
    if (errorDiv) {
      errorDiv.style.display = 'none';
    }
  }

  /**
   * Show loading indicator
   */
  private showLoading(): void {
    const loadingDiv = document.getElementById('kms-modal-loading');
    if (loadingDiv) {
      loadingDiv.style.display = 'flex';
    }
  }

  /**
   * Hide loading indicator
   */
  private hideLoading(): void {
    const loadingDiv = document.getElementById('kms-modal-loading');
    if (loadingDiv) {
      loadingDiv.style.display = 'none';
    }
  }

  /**
   * Hide unlock modal
   */
  private hideModal(): void {
    const modal = document.getElementById('unlock-modal');
    if (modal) {
      modal.style.display = 'none';
    }

    // Clear passphrase input
    const passphraseInput = document.getElementById('kms-passphrase-input') as HTMLInputElement;
    if (passphraseInput) {
      passphraseInput.value = '';
    }

    this.hideLoading();
    this.hideError();
  }

  /**
   * Setup modal handling (for standalone setup window)
   * This runs in first-party context, enabling credentials.create()
   */
  setupSetupModalHandlers(): void {
    const webauthnBtn = document.getElementById('kms-setup-webauthn-btn');
    const passphraseInput = document.getElementById('kms-setup-passphrase-input') as HTMLInputElement;
    const passphraseBtn = document.getElementById('kms-setup-passphrase-btn');

    if (!webauthnBtn || !passphraseInput || !passphraseBtn) {
      console.error('[KMS Client] Setup modal elements not found');
      return;
    }

    // Setup WebAuthn button handler
    webauthnBtn.onclick = () => this.handleWebAuthnSetup();

    // Setup passphrase button handler
    passphraseBtn.onclick = () => this.handlePassphraseSetup(passphraseInput.value);

    // Setup Enter key for passphrase
    passphraseInput.onkeydown = (e) => {
      if (e.key === 'Enter') {
        this.handlePassphraseSetup(passphraseInput.value);
      }
    };
  }

  /**
   * Handle WebAuthn setup (credentials.create in first-party context)
   */
  private async handleWebAuthnSetup(): Promise<void> {
    this.showSetupLoading();
    this.hideSetupError();

    try {
      const userId = 'demouser@ats.run';
      const rpId = window.location.hostname; // kms.ats.run or localhost

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
      const prfExt = (credential as any).getClientExtensionResults().prf;
      const prfEnabled = prfExt?.enabled === true;

      console.log('[KMS Client] Setup PRF extension result:', {
        prfExt,
        prfEnabled,
        willUsePRF: prfEnabled
      });

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

        const getPrfExt = (assertion as any).getClientExtensionResults().prf;
        prfOutput = getPrfExt?.results?.first;

        console.log('[KMS Client] PRF output from get():', {
          hasPrfOutput: !!prfOutput,
          prfOutputSize: prfOutput?.byteLength
        });
      }

      // Send setup request to worker
      const setupRequest: RPCRequest = {
        id: `setup-${Date.now()}`,
        method: (prfEnabled && prfOutput) ? 'setupPasskeyPRF' : 'setupPasskeyGate',
        params: {
          userId,
          credentialId: credential.rawId,
          ...(prfOutput && { prfOutput }),
          rpId,
        },
      };

      this.worker?.postMessage(setupRequest);

      // Wait for response
      const response: any = await new Promise((resolve, reject) => {
        const handler = (event: MessageEvent) => {
          const resp = event.data;
          if (resp.id === setupRequest.id) {
            this.worker?.removeEventListener('message', handler);
            if (resp.error) {
              reject(new Error(resp.error));
            } else {
              resolve(resp.result);
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
      if (window.opener) {
        window.opener.postMessage({
          type: 'kms:setup-complete',
          method: prfOutput ? 'passkey-prf' : 'passkey-gate',
          result: response,
        }, '*'); // Parent will validate origin
      }

      console.log('[KMS Client] WebAuthn setup complete, notified parent');
    } catch (err: any) {
      this.hideSetupLoading();
      this.showSetupError(`WebAuthn setup failed: ${err.message}`);
      console.error('[KMS Client] WebAuthn setup failed:', err);
    }
  }

  /**
   * Handle passphrase setup
   */
  private async handlePassphraseSetup(passphrase: string): Promise<void> {
    if (!passphrase || passphrase.trim().length === 0) {
      this.showSetupError('Please enter a passphrase');
      return;
    }

    if (passphrase.length < 8) {
      this.showSetupError('Passphrase must be at least 8 characters');
      return;
    }

    this.showSetupLoading();
    this.hideSetupError();

    try {
      const userId = 'demouser@ats.run';

      // Send setup request to worker
      const setupRequest: RPCRequest = {
        id: `setup-${Date.now()}`,
        method: 'setupPassphrase',
        params: {
          userId,
          passphrase,
        },
      };

      this.worker?.postMessage(setupRequest);

      // Wait for response
      const response: any = await new Promise((resolve, reject) => {
        const handler = (event: MessageEvent) => {
          const resp = event.data;
          if (resp.id === setupRequest.id) {
            this.worker?.removeEventListener('message', handler);
            if (resp.error) {
              reject(new Error(resp.error));
            } else {
              resolve(resp.result);
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
      if (window.opener) {
        window.opener.postMessage({
          type: 'kms:setup-complete',
          method: 'passphrase',
          result: response,
        }, '*'); // Parent will validate origin
      }

      console.log('[KMS Client] Passphrase setup complete, notified parent');
    } catch (err: any) {
      this.hideSetupLoading();
      this.showSetupError(`Setup failed: ${err.message}`);
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
      errorDiv.style.display = 'block';
    }
  }

  /**
   * Hide setup error message
   */
  private hideSetupError(): void {
    const errorDiv = document.getElementById('kms-setup-error');
    if (errorDiv) {
      errorDiv.style.display = 'none';
    }
  }

  /**
   * Show setup loading indicator
   */
  private showSetupLoading(): void {
    const loadingDiv = document.getElementById('kms-setup-loading');
    if (loadingDiv) {
      loadingDiv.style.display = 'flex';
    }
  }

  /**
   * Hide setup loading indicator
   */
  private hideSetupLoading(): void {
    const loadingDiv = document.getElementById('kms-setup-loading');
    if (loadingDiv) {
      loadingDiv.style.display = 'none';
    }
  }

  /**
   * Show setup success message
   */
  private showSetupSuccess(): void {
    const successDiv = document.getElementById('kms-setup-success');
    if (successDiv) {
      successDiv.style.display = 'block';
    }
  }

  /**
   * Terminate the Worker and cleanup
   *
   * Useful for testing or manual cleanup.
   */
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
  const isStandaloneSetup = !isIframe && window.opener !== null;

  console.log('[KMS Client] Context detection:', {
    isIframe,
    isStandaloneSetup,
    hasOpener: window.opener !== null,
  });

  // Create and initialize client
  const client = new KMSClient({ parentOrigin });

  // Initialize when DOM is ready
  const initFn = () => {
    client.init().catch((err) => {
      console.error('[KMS Client] Auto-initialization failed:', err);
    });

    // If standalone setup window, show setup modal immediately
    if (isStandaloneSetup) {
      console.log('[KMS Client] Standalone setup window detected, showing setup modal');
      // Wait a bit for client to fully initialize
      setTimeout(() => {
        client.setupSetupModalHandlers();
        const setupModal = document.getElementById('setup-modal');
        if (setupModal) {
          setupModal.style.display = 'flex';
        }
      }, 100);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFn);
  } else {
    initFn();
  }

  // Export for debugging
  (window as any).__kmsClient = client;
  (window as any).__kmsContext = { isIframe, isStandaloneSetup };
}
