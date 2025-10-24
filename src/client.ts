/**
 * KMS Client - RPC Bridge (Phase 0)
 *
 * Client-side RPC bridge that communicates with the Worker via postMessage.
 * Provides a Promise-based API for cryptographic operations.
 */

interface RPCRequest {
  id: string;
  method: string;
  params?: unknown;
}

interface RPCResponse {
  id: string;
  result?: unknown;
  error?: {
    code: string;
    message: string;
  };
}

/**
 * Chain verification result from audit log
 */
export interface ChainVerificationResult {
  valid: boolean;
  verified: number;
  errors: string[];
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

export class KMSClient {
  private worker: Worker | null = null;
  private requestId = 0;
  private pendingRequests = new Map<string, PendingRequest>();
  private destroyed = false;

  constructor() {
    // Create Worker instance
    // Vite will handle this specially when bundling
    this.worker = new Worker(new URL('./worker.ts', import.meta.url), {
      type: 'module',
    });

    // Set up message handler
    this.worker.onmessage = (event: MessageEvent<RPCResponse>): void => {
      this.handleResponse(event.data);
    };

    // Set up error handler
    this.worker.onerror = (error: ErrorEvent): void => {
      console.error('[KMS Client] Worker error:', error);
      // Reject all pending requests
      for (const [id, pending] of this.pendingRequests.entries()) {
        pending.reject(new Error(`Worker error: ${error.message}`));
        this.pendingRequests.delete(id);
      }
    };
  }

  private handleResponse(response: RPCResponse): void {
    const pending = this.pendingRequests.get(response.id);
    if (!pending) {
      console.warn('[KMS Client] Received response for unknown request:', response.id);
      return;
    }

    if (response.error) {
      pending.reject(new Error(response.error.message));
    } else {
      pending.resolve(response.result);
    }

    this.pendingRequests.delete(response.id);
  }

  private request<T>(method: string, params?: unknown): Promise<T> {
    if (this.destroyed) {
      return Promise.reject(new Error('Client has been destroyed'));
    }

    /* c8 ignore next 3 - defensive: worker is always initialized in constructor */
    if (!this.worker) {
      return Promise.reject(new Error('Worker not initialized'));
    }

    const id = `req-${++this.requestId}`;

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });

      const request: RPCRequest = {
        id,
        method,
        params,
      };

      this.worker!.postMessage(request);
    });
  }

  destroy(): void {
    if (this.destroyed) {
      return;
    }

    this.destroyed = true;

    // Reject all pending requests
    for (const [id, pending] of this.pendingRequests.entries()) {
      pending.reject(new Error('Client destroyed'));
      this.pendingRequests.delete(id);
    }

    // Terminate worker
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
  }

  // ============================================================================
  // Unlock Methods
  // ============================================================================

  /**
   * Setup passphrase for first-time unlock
   */
  setupPassphrase(
    passphrase: string
  ): Promise<{ success: boolean; error?: string }> {
    return this.request<{ success: boolean; error?: string }>('setupPassphrase', {
      passphrase,
    });
  }

  /**
   * Unlock with passphrase
   */
  unlockWithPassphrase(
    passphrase: string
  ): Promise<{ success: boolean; error?: string }> {
    return this.request<{ success: boolean; error?: string }>(
      'unlockWithPassphrase',
      { passphrase }
    );
  }

  /**
   * Check if unlock is configured
   */
  isUnlockSetup(): Promise<{ isSetup: boolean }> {
    return this.request<{ isSetup: boolean }>('isUnlockSetup');
  }

  /**
   * Get passkey configuration from worker storage
   * (needed because client can't access worker's IndexedDB)
   */
  getPasskeyConfig(): Promise<{
    method: string;
    credentialId?: ArrayBuffer;
    appSalt?: ArrayBuffer;
  } | null> {
    return this.request<{
      method: string;
      credentialId?: ArrayBuffer;
      appSalt?: ArrayBuffer;
    } | null>('getPasskeyConfig');
  }

  /**
   * Setup passkey with PRF extension (recommended)
   *
   * Performs WebAuthn ceremony in the client (main window), then sends
   * credential data to the worker for key derivation and storage.
   *
   * Automatically falls back to gate-only mode if PRF is not supported,
   * reusing the same credential to avoid double authentication.
   */
  async setupPasskeyPRF(
    rpId: string,
    rpName: string
  ): Promise<{ success: boolean; error?: string; method?: 'prf' | 'gate' }> {
    console.log('[KMS Client] setupPasskeyPRF called with:', { rpId, rpName });

    // Check WebAuthn availability
    if (
      typeof navigator === 'undefined' ||
      typeof window === 'undefined' ||
      !navigator.credentials ||
      !window.PublicKeyCredential
    ) {
      console.log('[KMS Client] WebAuthn not available');
      return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
    }

    console.log('[KMS Client] WebAuthn available, creating credential...');

    try {
      // Generate random app salt for PRF
      const appSalt = crypto.getRandomValues(new Uint8Array(32));
      console.log('[KMS Client] App salt generated:', appSalt.length, 'bytes');

      // Create passkey with PRF extension
      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: rpId, name: rpName },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: 'kms-user',
            displayName: 'KMS User',
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256 (preferred)
            { type: 'public-key', alg: -257 }, // RS256 (fallback)
          ],
          authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
          },
          extensions: {
            prf: {},
          },
        },
      })) as PublicKeyCredential | null;

      console.log('[KMS Client] Credential created:', {
        hasCredential: !!credential,
        credentialId: credential ? credential.id : null,
        rawIdLength: credential ? credential.rawId.byteLength : 0,
      });

      if (!credential) {
        console.log('[KMS Client] Credential creation returned null');
        return { success: false, error: 'PASSKEY_CREATION_FAILED' };
      }

      const clientExtensionResults = credential.getClientExtensionResults();
      console.log('[KMS Client] Extension results:', {
        hasPrf: !!clientExtensionResults.prf,
        prfEnabled: clientExtensionResults.prf?.enabled,
      });

      // Check if PRF extension is supported
      if (!clientExtensionResults.prf?.enabled) {
        // PRF not supported - use gate-only mode with the same credential
        console.log('[KMS Client] PRF not supported, using gate-only mode with same credential');
        console.log('[KMS Client] Credential for gate-only:', {
          rawIdType: Object.prototype.toString.call(credential.rawId),
          rawIdLength: credential.rawId.byteLength,
          rawIdIsArrayBuffer: credential.rawId instanceof ArrayBuffer,
        });

        const gateResult = await this.request<{ success: boolean; error?: string }>('setupPasskeyGate', {
          credentialId: credential.rawId,
        });

        return {
          success: gateResult.success,
          method: 'gate' as const,
          ...(gateResult.error && { error: gateResult.error })
        };
      }

      // PRF is supported - proceed with PRF flow
      // Derive PRF output (first auth with same passkey)
      const assertionCredential = (await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: rpId,
          allowCredentials: [
            {
              type: 'public-key',
              id: credential.rawId,
            },
          ],
          userVerification: 'required',
          extensions: {
            prf: {
              eval: {
                first: appSalt,
              },
            },
          },
        },
      })) as PublicKeyCredential | null;

      if (!assertionCredential) {
        return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
      }

      const assertionExtensions = assertionCredential.getClientExtensionResults();

      // Extract PRF output
      const prfResults = assertionExtensions.prf;
      if (!prfResults?.results?.first) {
        // PRF failed during assertion - fall back to gate-only with same credential
        console.log('[KMS Client] PRF failed during assertion, using gate-only mode');

        const gateResult = await this.request<{ success: boolean; error?: string }>('setupPasskeyGate', {
          credentialId: credential.rawId,
        });

        return {
          success: gateResult.success,
          method: 'gate' as const,
          ...(gateResult.error && { error: gateResult.error })
        };
      }

      // Send credential data to worker for PRF mode
      console.log('[KMS Client] Sending setupPasskeyPRF to worker:', {
        credentialIdType: Object.prototype.toString.call(credential.rawId),
        credentialIdLength: credential.rawId.byteLength,
        prfOutputType: Object.prototype.toString.call(prfResults.results.first),
        prfOutputLength: prfResults.results.first.byteLength,
        credentialIdIsArrayBuffer: credential.rawId instanceof ArrayBuffer,
        prfOutputIsArrayBuffer: prfResults.results.first instanceof ArrayBuffer,
      });

      const prfResult = await this.request<{ success: boolean; error?: string }>('setupPasskeyPRF', {
        credentialId: credential.rawId,
        prfOutput: prfResults.results.first,
      });

      return {
        success: prfResult.success,
        method: 'prf' as const,
        ...(prfResult.error && { error: prfResult.error })
      };
    } catch (error) {
      console.error('[KMS Client] Passkey setup failed:', error);

      // Check if error is user cancellation (NotAllowedError)
      if (error instanceof Error && error.name === 'NotAllowedError') {
        return { success: false, error: 'PASSKEY_CREATION_FAILED' };
      }

      // For other errors, this is likely a fatal issue
      return { success: false, error: 'PASSKEY_CREATION_FAILED' };
    }
  }

  /**
   * Unlock with passkey using PRF extension
   */
  async unlockWithPasskeyPRF(
    rpId: string
  ): Promise<{ success: boolean; error?: string }> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
    }

    try {
      // Retrieve stored credential ID from worker storage via RPC
      const config = await this.getPasskeyConfig();
      console.log('[KMS Client] Retrieved passkey config:', {
        hasConfig: !!config,
        method: config?.method,
        hasCredentialId: !!(config?.credentialId),
        hasAppSalt: !!(config?.appSalt),
      });

      if (!config || config.method !== 'passkey-prf' || !config.credentialId || !config.appSalt) {
        console.log('[KMS Client] Config validation failed');
        return { success: false, error: 'NOT_SETUP' };
      }

      const appSalt = new Uint8Array(config.appSalt);

      // Get assertion with PRF
      const credential = (await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: rpId,
          allowCredentials: [
            {
              type: 'public-key',
              id: config.credentialId,
            },
          ],
          userVerification: 'required',
          extensions: {
            prf: {
              eval: {
                first: appSalt,
              },
            },
          },
        },
      })) as PublicKeyCredential | null;

      if (!credential) {
        return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
      }

      const extensions = credential.getClientExtensionResults();
      const prfResults = extensions.prf;
      if (!prfResults?.results?.first) {
        return { success: false, error: 'PASSKEY_PRF_NOT_SUPPORTED' };
      }

      // Send PRF output to worker
      return this.request<{ success: boolean; error?: string }>('unlockWithPasskeyPRF', {
        prfOutput: prfResults.results.first,
      });
    } catch (error) {
      console.error('[KMS Client] Passkey unlock failed:', error);
      return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
    }
  }

  /**
   * Setup passkey in gate-only mode (fallback)
   */
  async setupPasskeyGate(
    rpId: string,
    rpName: string
  ): Promise<{ success: boolean; error?: string }> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
    }

    try {
      // Create passkey without PRF extension
      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: rpId, name: rpName },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: 'kms-user',
            displayName: 'KMS User',
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256 (preferred)
            { type: 'public-key', alg: -257 }, // RS256 (fallback)
          ],
          authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
          },
        },
      })) as PublicKeyCredential | null;

      if (!credential) {
        return { success: false, error: 'PASSKEY_CREATION_FAILED' };
      }

      // Send credential ID to worker
      return this.request<{ success: boolean; error?: string }>('setupPasskeyGate', {
        credentialId: credential.rawId,
      });
    } catch (error) {
      console.error('[KMS Client] Passkey gate setup failed:', error);
      return { success: false, error: 'PASSKEY_CREATION_FAILED' };
    }
  }

  /**
   * Unlock with passkey in gate-only mode (fallback)
   */
  async unlockWithPasskeyGate(
    rpId: string
  ): Promise<{ success: boolean; error?: string }> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      return { success: false, error: 'PASSKEY_NOT_AVAILABLE' };
    }

    try {
      // Retrieve stored credential ID from worker storage via RPC
      const config = await this.getPasskeyConfig();
      console.log('[KMS Client] Retrieved passkey config for gate-only:', {
        hasConfig: !!config,
        method: config?.method,
        hasCredentialId: !!(config?.credentialId),
      });

      if (!config || config.method !== 'passkey-gate' || !config.credentialId) {
        console.log('[KMS Client] Gate-only config validation failed');
        return { success: false, error: 'NOT_SETUP' };
      }

      // Get assertion (user verification is the gate)
      const credential = (await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: rpId,
          allowCredentials: [
            {
              type: 'public-key',
              id: config.credentialId,
            },
          ],
          userVerification: 'required',
        },
      })) as PublicKeyCredential | null;

      if (!credential) {
        return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
      }

      // Send unlock request to worker (no PRF output needed)
      return this.request<{ success: boolean; error?: string }>('unlockWithPasskeyGate', {});
    } catch (error) {
      console.error('[KMS Client] Passkey gate unlock failed:', error);
      return { success: false, error: 'PASSKEY_AUTHENTICATION_FAILED' };
    }
  }

  // ============================================================================
  // Crypto Operations (require unlock)
  // ============================================================================

  generateVAPID(): Promise<{ kid: string; publicKey: string }> {
    return this.request<{ kid: string; publicKey: string }>('generateVAPID');
  }

  signJWT(kid: string, payload: unknown): Promise<{ jwt: string }> {
    return this.request<{ jwt: string }>('signJWT', { kid, payload });
  }

  getPublicKey(kid: string): Promise<{ publicKey: string | null }> {
    return this.request<{ publicKey: string | null }>('getPublicKey', { kid });
  }

  // ============================================================================
  // Audit Operations
  // ============================================================================

  /**
   * Get the audit log public key for external verification
   *
   * This public key can be used by anyone to independently verify the audit chain.
   * The key is exported in JWK format for easy use with standard crypto libraries.
   *
   * @returns Public key in JWK format, or null if audit logger not initialized
   */
  getAuditPublicKey(): Promise<JsonWebKey | null> {
    return this.request<JsonWebKey | null>('getAuditPublicKey');
  }

  /**
   * Verify the integrity of the entire audit chain
   *
   * Checks:
   * - Each entry has a valid ES256 signature
   * - Each entry's prevHash correctly references the previous entry
   * - Chain is unbroken from genesis to latest entry
   *
   * @returns Verification result with error details
   */
  verifyAuditChain(): Promise<ChainVerificationResult> {
    return this.request<ChainVerificationResult>('verifyAuditChain');
  }
}
