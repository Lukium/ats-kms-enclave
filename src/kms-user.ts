/**
 * KMS User Client - Parent Window Client
 *
 * Client-side class that runs in the parent window (not iframe) to handle
 * operations that require parent context (WebAuthn ceremonies, user gestures).
 * Communicates with KMS iframe via postMessage.
 *
 * Separation of concerns:
 * - KMSUser (parent): WebAuthn, user-facing operations, postMessage sender
 * - KMSClient (iframe): Worker communication, crypto operations, storage
 */

interface KMSUserConfig {
  /** Origin of the KMS iframe (e.g., "http://localhost:5177") */
  kmsOrigin: string;
  /** Reference to the KMS iframe element */
  iframe: HTMLIFrameElement;
  /** Timeout for iframe responses in milliseconds (default: 10000) */
  timeout?: number;
}

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

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}

/**
 * Parent-side client for KMS iframe communication
 *
 * Handles operations that must run in parent window context:
 * - WebAuthn ceremonies (passkey setup/unlock)
 * - User gestures
 * - iframe communication
 *
 * Example usage:
 * ```typescript
 * const kmsUser = new KMSUser({
 *   kmsOrigin: 'http://localhost:5177',
 *   iframe: document.getElementById('kms-iframe') as HTMLIFrameElement
 * });
 *
 * // Setup with passphrase
 * await kmsUser.setupPassphrase('my-secure-passphrase');
 *
 * // Setup with passkey (handles WebAuthn in parent)
 * await kmsUser.setupPasskey({
 *   rpId: 'example.com',
 *   rpName: 'Example App'
 * });
 *
 * // Generate VAPID keypair
 * const { kid, publicKey } = await kmsUser.generateVAPID();
 *
 * // Sign JWT
 * const { jwt } = await kmsUser.signJWT(kid, payload);
 * ```
 */
export class KMSUser {
  private kmsOrigin: string;
  private iframe: HTMLIFrameElement;
  private timeout: number;
  private requestId = 0;
  private pendingRequests = new Map<string, PendingRequest>();
  private ready = false;

  constructor(config: KMSUserConfig) {
    this.kmsOrigin = config.kmsOrigin;
    this.iframe = config.iframe;
    this.timeout = config.timeout ?? 10000;

    // Set up response listener
    window.addEventListener('message', this.handleMessage.bind(this));

    // Wait for iframe to load
    if (this.iframe.contentWindow) {
      this.ready = true;
    } else {
      this.iframe.addEventListener('load', () => {
        this.ready = true;
      });
    }
  }

  private handleMessage(event: MessageEvent): void {
    // Validate origin
    if (event.origin !== this.kmsOrigin) {
      return;
    }

    const response: RPCResponse = event.data;
    const pending = this.pendingRequests.get(response.id);

    if (!pending) {
      return;
    }

    clearTimeout(pending.timeout);
    this.pendingRequests.delete(response.id);

    if (response.error) {
      pending.reject(new Error(response.error.message));
    } else {
      pending.resolve(response.result);
    }
  }

  private request<T>(method: string, params?: unknown): Promise<T> {
    if (!this.ready) {
      return Promise.reject(new Error('KMS iframe not ready'));
    }

    const id = `req-${++this.requestId}`;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request timeout (${this.timeout}ms)`));
      }, this.timeout);

      this.pendingRequests.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timeout,
      });

      const request: RPCRequest = {
        id,
        method,
        params,
      };

      this.iframe.contentWindow!.postMessage(request, this.kmsOrigin);
    });
  }

  // ============================================================================
  // Setup Methods (run in parent context)
  // ============================================================================

  /**
   * Setup passphrase-based unlock
   *
   * Sends passphrase to KMS iframe for key derivation and storage.
   */
  setupPassphrase(passphrase: string): Promise<{ success: boolean; error?: string }> {
    return this.request<{ success: boolean; error?: string }>('setupPassphrase', {
      passphrase,
    });
  }

  /**
   * Setup passkey with PRF extension
   *
   * Performs WebAuthn ceremony in parent window (required for user gesture),
   * then sends PRF output to KMS iframe for key derivation.
   */
  async setupPasskey(config: {
    rpId: string;
    rpName: string;
  }): Promise<{ success: boolean; error?: string; method?: 'prf' | 'gate' }> {
    // Perform WebAuthn ceremony in parent context
    // This is where WebAuthn MUST run (not in iframe)

    /* c8 ignore start - browser WebAuthn API */
    if (!window.PublicKeyCredential) {
      return {
        success: false,
        error: 'WEBAUTHN_NOT_SUPPORTED',
      };
    }

    try {
      // Check PRF extension support
      const prfSupported = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();

      // Create credential with PRF extension
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: {
            id: config.rpId,
            name: config.rpName,
          },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: 'user@example.com',
            displayName: 'User',
          },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'preferred',
          },
          extensions: {
            prf: {
              eval: {
                first: crypto.getRandomValues(new Uint8Array(32)),
              },
            },
          },
        },
      }) as PublicKeyCredential;

      // Get PRF output
      const prfResults = (credential as any).getClientExtensionResults().prf;

      if (prfResults?.results?.first) {
        // Send PRF output to iframe
        return this.request<{ success: boolean; error?: string; method?: 'prf' | 'gate' }>(
          'setupPasskeyPRF',
          {
            rpId: config.rpId,
            rpName: config.rpName,
            credentialId: credential.id,
            prfOutput: prfResults.results.first,
          }
        );
      } else {
        // Fallback to gate-only mode
        return this.request<{ success: boolean; error?: string; method?: 'prf' | 'gate' }>(
          'setupPasskeyGate',
          {
            credentialId: credential.id,
          }
        );
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'PASSKEY_CREATION_FAILED',
      };
    }
    /* c8 ignore end */
  }

  /**
   * Unlock with passphrase
   */
  unlockWithPassphrase(passphrase: string): Promise<{ success: boolean; error?: string }> {
    return this.request<{ success: boolean; error?: string }>('unlockWithPassphrase', {
      passphrase,
    });
  }

  /**
   * Unlock with passkey
   *
   * Performs WebAuthn ceremony in parent window, sends PRF output to iframe.
   */
  async unlockWithPasskey(rpId: string): Promise<{ success: boolean; error?: string }> {
    /* c8 ignore start - browser WebAuthn API */
    if (!window.PublicKeyCredential) {
      return {
        success: false,
        error: 'WEBAUTHN_NOT_SUPPORTED',
      };
    }

    try {
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId,
          userVerification: 'required',
          extensions: {
            prf: {
              eval: {
                first: crypto.getRandomValues(new Uint8Array(32)),
              },
            },
          },
        },
      }) as PublicKeyCredential;

      const prfResults = (assertion as any).getClientExtensionResults().prf;

      if (prfResults?.results?.first) {
        return this.request<{ success: boolean; error?: string }>('unlockWithPasskeyPRF', {
          rpId,
          prfOutput: prfResults.results.first,
        });
      } else {
        return this.request<{ success: boolean; error?: string }>('unlockWithPasskeyGate', {});
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'PASSKEY_UNLOCK_FAILED',
      };
    }
    /* c8 ignore end */
  }

  // ============================================================================
  // Crypto Operations (forwarded to iframe)
  // ============================================================================

  /**
   * Generate VAPID keypair for Web Push
   */
  generateVAPID(): Promise<{ kid: string; publicKey: string }> {
    return this.request<{ kid: string; publicKey: string }>('generateVAPID');
  }

  /**
   * Sign JWT with VAPID private key
   */
  signJWT(kid: string, payload: unknown): Promise<{ jwt: string }> {
    return this.request<{ jwt: string }>('signJWT', { kid, payload });
  }

  /**
   * Get public key for a given kid
   */
  getPublicKey(kid: string): Promise<{ publicKey: string | null }> {
    return this.request<{ publicKey: string | null }>('getPublicKey', { kid });
  }

  // ============================================================================
  // Status Methods
  // ============================================================================

  /**
   * Check if unlock is configured
   */
  isUnlockSetup(): Promise<{ isSetup: boolean }> {
    return this.request<{ isSetup: boolean }>('isUnlockSetup');
  }

  /**
   * Verify audit chain integrity
   */
  verifyAuditChain(): Promise<{
    valid: boolean;
    verified: number;
    errors: string[];
  }> {
    return this.request<{
      valid: boolean;
      verified: number;
      errors: string[];
    }>('verifyAuditChain');
  }

  /**
   * Get passkey configuration (to determine unlock method)
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
   * Destroy client and clean up resources
   */
  destroy(): void {
    // Reject all pending requests
    for (const [id, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Client destroyed'));
      this.pendingRequests.delete(id);
    }

    window.removeEventListener('message', this.handleMessage);
  }
}
