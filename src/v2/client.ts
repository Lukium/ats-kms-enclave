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
      this.sendToParent(event.data);
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
  private sendToParent(data: any): void {
    if (!window.parent) {
      console.error('[KMS Client] No parent window available');
      return;
    }

    try {
      window.parent.postMessage(data, this.parentOrigin);
    } catch (err: unknown) {
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

      const handler = (event: MessageEvent): void => {
        const response = event.data as RPCResponse;
        if (response.id === requestId) {
          this.worker?.removeEventListener('message', handler);
          if (response.error) {
            const errorMsg = typeof response.error === 'string' ? response.error : response.error.message;
          reject(new Error(errorMsg));
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
    modal.style.display = 'flex';

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
      const userId = this.pendingUnlockRequest.params?.userId;
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
          ...this.pendingUnlockRequest.params,
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
    } catch (err: unknown) {
      this.hideLoading();
      this.showError(`Unlock failed: ${getErrorMessage(err)}`);
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
      setupOptions.forEach(el => ((el as HTMLElement).style.display = 'none'));

      // Create unlock instructions
      const unlockInstructions = document.createElement('div');
      unlockInstructions.id = 'multi-enrollment-unlock';
      unlockInstructions.style.cssText = 'margin-bottom: 1.5rem; padding: 1rem; background: rgba(102, 126, 234, 0.1); border: 1px solid rgba(102, 126, 234, 0.3); border-radius: 6px;';
      unlockInstructions.innerHTML = `
        <p style="margin: 0 0 0.5rem 0; color: #a5b4fc; font-size: 0.875rem; font-weight: 600;">
          🔒 Multi-Enrollment Authentication Required
        </p>
        <p style="margin: 0; color: #888; font-size: 0.8rem;">
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
        setupOptions?.forEach(el => ((el as HTMLElement).style.display = ''));
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
        matchFeedback.style.display = 'none';
        return;
      }

      matchFeedback.style.display = 'block';

      if (passphrase === confirm) {
        matchFeedback.textContent = '✓ Passphrases match';
        matchFeedback.style.color = '#48d391'; // green
      } else {
        matchFeedback.textContent = '✗ Passphrases do not match';
        matchFeedback.style.color = '#ef4444'; // red
      }
    };

    passphraseInput.oninput = (): void => {
      const length = passphraseInput.value.length;
      const minLength = 12;
      if (charCount) {
        charCount.textContent = `${length} / ${minLength} characters`;
        if (length < minLength) {
          charCount.style.color = '#ef4444'; // red
        } else {
          charCount.style.color = '#48d391'; // green
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
   * Handle WebAuthn setup (credentials.create in first-party context)
   * Supports both initial setup and multi-enrollment (adding second+ method)
   */
  private async handleWebAuthnSetup(): Promise<void> {
    this.showSetupLoading();
    this.hideSetupError();

    try {
      const userId = 'demouser@ats.run';
      const rpId = window.location.hostname; // kms.ats.run or localhost

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
      const response: any = await new Promise((resolve, reject) => {
        const handler = (event: MessageEvent): void => {
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
      const response: any = await new Promise((resolve, reject) => {
        const handler = (event: MessageEvent): void => {
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
   * Hide setup success message
   */
  private hideSetupSuccess(): void {
    const successDiv = document.getElementById('kms-setup-success');
    if (successDiv) {
      successDiv.style.display = 'none';
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
