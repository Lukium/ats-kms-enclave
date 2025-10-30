/**
 * KMS V2 User API
 *
 * This class provides the PWA-facing API for the KMS. It runs in the PWA
 * context (allthe.services) and communicates with the KMS iframe via postMessage.
 *
 * Features:
 * - Iframe initialization and lifecycle management
 * - Request/response correlation with timeouts
 * - WebAuthn ceremony orchestration
 * - Setup and unlock operations
 * - VAPID key management and JWT signing
 * - Lease-based authorization
 *
 * Architecture:
 *   kms-user.ts (PWA @ allthe.services)
 *       ↓ postMessage (cross-origin)
 *   client.ts (iframe @ kms.ats.run)
 *       ↓ postMessage (Worker)
 *   worker.ts (Dedicated Worker)
 */

import type {
  RPCRequest,
  RPCResponse,
  RPCMethod,
  AuthCredentials,
  AuditEntryV2,
  LeaseRecord,
  LeaseVerificationResult,
} from './types.js';
import { formatError } from './error-utils.js';
import { getPRFResults } from './webauthn-types.js';

/**
 * Configuration for KMSUser
 */
export interface KMSUserConfig {
  /**
   * Origin of the KMS iframe (e.g., 'https://kms.ats.run')
   */
  kmsOrigin: string;

  /**
   * Default timeout for RPC requests in milliseconds
   * @default 10000 (10 seconds)
   */
  defaultTimeout?: number;

  /**
   * Whether to auto-initialize on construction
   * @default false
   */
  autoInit?: boolean;
}

/**
 * Pending RPC request
 */
interface PendingRequest {
  resolve: (result: unknown) => void;
  reject: (error: Error) => void;
  timeoutId: NodeJS.Timeout | number;
  method: string;
}

/**
 * Setup result
 */
export interface SetupResult {
  success: boolean;
  enrollmentId: string;
}

/**
 * Unlock result
 */
export interface UnlockResult {
  success: boolean;
}

/**
 * VAPID key pair result
 */
export interface VAPIDKeyResult {
  kid: string;
  publicKey: string;
}

/**
 * Lease result
 */
export interface LeaseResult {
  leaseId: string;
  exp: number;
  quotas: {
    tokensPerHour: number;
    sendsPerMinute: number;
    burstSends: number;
    sendsPerMinutePerEid: number;
  };
}

/**
 * JWT result
 */
export interface JWTResult {
  jwt: string;
  jti?: string;
  exp?: number;
}

/**
 * Status result
 */
export interface StatusResult {
  isSetup: boolean;
  methods: string[];
  leases?: LeaseRecord[];
}

/**
 * Audit verification result
 */
export interface AuditVerificationResult {
  valid: boolean;
  entries: number;
}

/**
 * KMS User API
 *
 * Main entry point for PWA to interact with KMS.
 */
export class KMSUser {
  private iframe: HTMLIFrameElement | null = null;
  private pendingRequests: Map<string, PendingRequest> = new Map();
  private kmsOrigin: string;
  private defaultTimeout: number;
  private isInitialized = false;
  private isReady = false;
  private boundMessageHandler: ((event: MessageEvent) => void) | null = null;

  /**
   * Create a new KMS user API instance
   *
   * @param config - Configuration
   */
  constructor(config: KMSUserConfig) {
    this.kmsOrigin = config.kmsOrigin;
    this.defaultTimeout = config.defaultTimeout ?? 10000;

    if (config.autoInit && typeof window !== 'undefined') {
      this.init().catch((err) => {
        console.error('[KMS User] Auto-initialization failed:', err);
      });
    }
  }

  // ========================================================================
  // Initialization and Lifecycle
  // ========================================================================

  /**
   * Initialize the KMS by creating and loading the iframe
   *
   * @throws {Error} If already initialized or iframe creation fails
   */
  async init(): Promise<void> {
    if (this.isInitialized) {
      throw new Error('KMSUser already initialized');
    }

    if (typeof window === 'undefined' || typeof document === 'undefined') {
      throw new Error('KMSUser requires browser environment');
    }

    try {
      // Create iframe
      this.iframe = document.createElement('iframe');
      this.iframe.src = `${this.kmsOrigin}/kms.html?parentOrigin=${encodeURIComponent(window.location.origin)}`;

      // Style as full-page overlay (hidden by default)
      this.iframe.style.position = 'fixed';
      this.iframe.style.top = '0';
      this.iframe.style.left = '0';
      this.iframe.style.width = '100%';
      this.iframe.style.height = '100%';
      this.iframe.style.border = 'none';
      this.iframe.style.zIndex = '99999';
      this.iframe.style.display = 'none'; // Hidden by default

      this.iframe.sandbox.add('allow-scripts', 'allow-same-origin');
      this.iframe.allow = 'publickey-credentials-get; publickey-credentials-create';

      // Setup message handler (store bound reference for later removal)
      this.boundMessageHandler = this.handleMessage.bind(this);
      window.addEventListener('message', this.boundMessageHandler);

      // Append to DOM
      document.body.appendChild(this.iframe);

      this.isInitialized = true;

      // Wait for ready signal from iframe
      await this.waitForReady();
    } catch (err: unknown) {
      console.error('[KMS User] Initialization failed:', err);
      this.cleanup();
      throw new Error(formatError('Failed to initialize KMS', err));
    }
  }

  /**
   * Wait for ready signal from KMS iframe
   *
   * @param timeout - Timeout in milliseconds
   * @returns Promise that resolves when ready
   */
  private waitForReady(timeout: number = 5000): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error('Timeout waiting for KMS ready signal'));
      }, timeout);

      const checkReady = (event: MessageEvent): void => {
        const data = event.data as { type?: string };
        if (event.origin === this.kmsOrigin && data?.type === 'kms:ready') {
          clearTimeout(timeoutId);
          window.removeEventListener('message', checkReady);
          this.isReady = true;
          resolve();
        }
      };

      window.addEventListener('message', checkReady);
    });
  }

  /**
   * Cleanup iframe and resources (without rejecting pending requests)
   */
  private cleanup(): void {
    // Remove message event listener
    if (this.boundMessageHandler) {
      window.removeEventListener('message', this.boundMessageHandler);
      this.boundMessageHandler = null;
    }

    // Remove iframe
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
    }
    this.iframe = null;

    this.isInitialized = false;
    this.isReady = false;
  }

  /**
   * Terminate the KMS iframe
   * Clears all pending requests without rejecting them to avoid unhandled rejection errors
   */
  terminate(): void {
    // Clear all pending request timeouts
    for (const pending of this.pendingRequests.values()) {
      clearTimeout(pending.timeoutId as number);
    }
    this.pendingRequests.clear();

    // Cleanup iframe and state
    this.cleanup();
  }

  // ========================================================================
  // RPC Communication
  // ========================================================================

  /**
   * Handle messages from KMS iframe
   *
   * @param event - Message event
   */
  private handleMessage(event: MessageEvent): void {
    // Validate origin
    if (event.origin !== this.kmsOrigin) {
      return;
    }

    // Handle ready signal (already handled in waitForReady)
    const data = event.data as { type?: string };
    if (data?.type === 'kms:ready') {
      return;
    }

    // Handle RPC response
    const response = event.data as RPCResponse;
    if (!response.id) {
      console.warn('[KMS User] Received message without ID:', response);
      return;
    }

    const pending = this.pendingRequests.get(response.id);
    if (!pending) {
      console.warn('[KMS User] No pending request for ID:', response.id);
      return;
    }

    // Clear timeout
    clearTimeout(pending.timeoutId as number);
    this.pendingRequests.delete(response.id);

    // Resolve or reject
    if ('error' in response && response.error) {
      // Handle both string and object error formats
      const errorMsg = typeof response.error === 'string'
        ? response.error
        : response.error.message || JSON.stringify(response.error);
      pending.reject(new Error(errorMsg));
    } else {
      pending.resolve(response.result);
    }
  }

  /**
   * Send RPC request to KMS iframe
   *
   * @param method - RPC method
   * @param params - RPC parameters
   * @param timeout - Optional timeout override
   * @returns Promise that resolves with result
   */
  private async sendRequest<T>(
    method: RPCMethod,
    params: unknown,
    timeout?: number
  ): Promise<T> {
    if (!this.isInitialized || !this.isReady) {
      throw new Error('KMS not initialized. Call init() first.');
    }

    if (!this.iframe?.contentWindow) {
      throw new Error('KMS iframe not available');
    }

    const requestId = crypto.randomUUID();
    const requestTimeout = timeout ?? this.defaultTimeout;

    return new Promise<T>((resolve, reject) => {
      // Setup timeout
      const timeoutId = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error(`Request timeout: ${method} (${requestTimeout}ms)`));
      }, requestTimeout);

      // Store pending request
      this.pendingRequests.set(requestId, {
        resolve: resolve as (result: unknown) => void,
        reject,
        timeoutId,
        method,
      });

      // Send request
      const request: RPCRequest = {
        id: requestId,
        method,
        params,
      };

      this.iframe!.contentWindow!.postMessage(request, this.kmsOrigin);
    });
  }

  // ========================================================================
  // Setup Operations
  // ========================================================================

  /**
   * Setup KMS with passphrase authentication
   *
   * @param userId - User ID
   * @param passphrase - User passphrase (min 8 characters)
   * @returns Setup result
   */
  async setupPassphrase(userId: string, passphrase: string): Promise<SetupResult> {
    return this.sendRequest<SetupResult>('setupPassphrase', { userId, passphrase });
  }

  /**
   * Setup KMS with passkey PRF authentication
   *
   * This method orchestrates the WebAuthn credential creation ceremony
   * in the parent PWA context, then sends the PRF output to the KMS.
   *
   * @param config - Passkey configuration
   * @returns Setup result
   */
  async setupPasskeyPRF(config: {
    userId: string;
    name: string;
    rpId: string;
  }): Promise<SetupResult> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('WebAuthn not supported');
    }

    // Generate app salt for PRF
    const appSalt = crypto.getRandomValues(new Uint8Array(32));

    try {
      // WebAuthn create ceremony (runs in parent PWA context)
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: config.rpId, name: 'ATS KMS V2' },
          user: {
            id: new TextEncoder().encode(config.userId),
            name: config.name,
            displayName: config.name,
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

      // Extract PRF output
      const prfExt = getPRFResults(credential);
      const prfOutput = prfExt?.results?.first;

      if (!prfOutput) {
        throw new Error('PRF extension not supported or failed');
      }

      // Send to KMS
      const result = await this.sendRequest<SetupResult>('setupPasskeyPRF', {
        userId: config.userId,
        credentialId: credential.rawId,
        prfOutput: prfOutput,
        rpId: config.rpId,
      });

      // Store appSalt for future unlock operations
      // In production, store this securely (e.g., in localStorage or IndexedDB)
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('kms:appSalt', Array.from(appSalt).toString());
      }

      return result;
    } catch (err: unknown) {
      throw new Error(formatError('Passkey setup failed', err));
    }
  }

  /**
   * Setup KMS with passkey gate authentication
   *
   * @param config - Passkey configuration
   * @returns Setup result
   */
  async setupPasskeyGate(config: {
    userId: string;
    name: string;
    rpId: string;
  }): Promise<SetupResult> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('WebAuthn not supported');
    }

    try {
      // WebAuthn create ceremony
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { id: config.rpId, name: 'ATS KMS V2' },
          user: {
            id: new TextEncoder().encode(config.userId),
            name: config.name,
            displayName: config.name,
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
        },
      }) as PublicKeyCredential;

      // Send to KMS
      return await this.sendRequest<SetupResult>('setupPasskeyGate', {
        userId: config.userId,
        credentialId: credential.rawId,
        rpId: config.rpId,
      });
    } catch (err: unknown) {
      throw new Error(formatError('Passkey gate setup failed', err));
    }
  }

  /**
   * Add additional enrollment method (multi-enrollment)
   *
   * @param userId - User ID
   * @param method - Method to add
   * @param credentials - Current credentials to unlock
   * @param newCredentials - New credentials to add
   * @returns Setup result
   */
  async addEnrollment(
    userId: string,
    method: 'passphrase' | 'passkey-prf' | 'passkey-gate',
    credentials: AuthCredentials,
    newCredentials: unknown
  ): Promise<SetupResult> {
    return this.sendRequest<SetupResult>('addEnrollment', {
      userId,
      method,
      credentials,
      newCredentials,
    });
  }

  // ========================================================================
  // Unlock Operations
  // ========================================================================

  /**
   * Unlock KMS with passphrase
   *
   * Note: This only validates the passphrase. Actual operations require

  /**
   * Regenerate VAPID keypair, invalidating all existing leases
   *
   * This operation:
   * - Deletes all existing VAPID keys for the authenticated user
   * - Generates a new VAPID keypair with a new kid
   * - All existing leases become invalid (they reference the old kid)
   *
   * SECURITY: Credentials are ALWAYS collected in KMS iframe. The parent
   * MUST NOT pass credentials - doing so would bypass iframe isolation.
   *
   * @param params - Parameters (userId only)
   * @returns VAPID key result with new kid and public key
   */
  async regenerateVAPID(params: {
    userId: string;
  }): Promise<VAPIDKeyResult> {
    // ALWAYS show iframe for authentication
    // Credentials are collected in iframe, never passed from parent
    if (this.iframe) {
      this.iframe.style.display = 'block';
    }

    try {
      const result = await this.sendRequest<VAPIDKeyResult>('regenerateVAPID', params);
      // Hide iframe on success
      if (this.iframe) {
        this.iframe.style.display = 'none';
      }
      return result;
    } catch (error) {
      // Hide iframe on error
      if (this.iframe) {
        this.iframe.style.display = 'none';
      }
      throw error;
    }
  }

  /**
   * Get public key for VAPID key
   *
   * @param kid - Key ID
   * @returns Public key (base64url-encoded)
   */
  async getPublicKey(kid: string): Promise<{ publicKey: string }> {
    return this.sendRequest<{ publicKey: string }>('getPublicKey', { kid });
  }

  /**
   * Get VAPID public key for user (convenience method)
   *
   * This is a convenience wrapper that retrieves the user's VAPID public key
   * without requiring the key ID. It internally calls getVAPIDKid() to get the
   * key ID, then calls getPublicKey() with that kid.
   *
   * @param _userId - User ID (currently unused, but kept for API consistency)
   * @returns VAPID public key (base64url-encoded) and key ID
   * @throws Error if no VAPID key exists or multiple keys found
   */
  async getVAPIDPublicKey(_userId: string): Promise<{ publicKey: string; kid: string }> {
    // Get the VAPID kid (will throw if not found or multiple found)
    const { kid } = await this.sendRequest<{ kid: string }>('getVAPIDKid', {});
    // Get the public key for that kid
    const result = await this.getPublicKey(kid);
    return {
      publicKey: result.publicKey,
      kid,
    };
  }

  // ========================================================================
  // VAPID Lease Operations
  // ========================================================================

  /**
   * Create VAPID lease for relay authorization
   *
   * SECURITY: Credentials are ALWAYS collected in KMS iframe. The parent
   * MUST NOT pass credentials - doing so would bypass iframe isolation.
   *
   * @param params - Lease parameters (userId, subs, ttlHours only)
   * @returns Lease result
   */
  async createLease(params: {
    userId: string;
    subs: Array<{ url: string; aud: string; eid: string }>;
    ttlHours: number;
  }): Promise<LeaseResult> {
    // ALWAYS show iframe for authentication
    // Credentials are collected in iframe, never passed from parent
    if (this.iframe) {
      this.iframe.style.display = 'block';
    }

    try {
      const result = await this.sendRequest<LeaseResult>('createLease', params);
      // Hide iframe on success
      if (this.iframe) {
        this.iframe.style.display = 'none';
      }
      return result;
    } catch (error) {
      // Hide iframe on error
      if (this.iframe) {
        this.iframe.style.display = 'none';
      }
      throw error;
    }
  }

  /**
   * Issue VAPID JWT for endpoint using lease authorization.
   * No credentials required - the lease IS the authorization.
   *
   * @param params - Issuance parameters
   * @returns JWT result
   */
  async issueVAPIDJWT(params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    kid?: string; // Optional - auto-detected if not provided (per V2 spec)
  }): Promise<JWTResult> {
    return this.sendRequest<JWTResult>('issueVAPIDJWT', params);
  }

  /**
   * Issue multiple VAPID JWTs with staggered expirations (batch issuance for JWT stashing)
   *
   * This method generates N JWTs for the same endpoint with intelligent expiration staggering:
   * - JWT[0]: expires at T+15min (900s)
   * - JWT[1]: expires at T+24min (900s + 540s stagger)
   * - JWT[2]: expires at T+33min (900s + 1080s stagger)
   *
   * The stagger interval is 60% of the JWT TTL (540s for 900s TTL), ensuring seamless
   * rotation: when JWT[0] reaches 60% TTL, JWT[1] is already valid.
   *
   * @param params.leaseId - Lease ID
   * @param params.endpoint - Push endpoint details
   * @param params.count - Number of JWTs to issue (1-10, hard limit)
   * @param params.kid - Optional VAPID key ID (auto-detected if not provided)
   * @returns Array of JWT results with staggered expirations
   */
  async issueVAPIDJWTs(params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    count: number;
    kid?: string;
  }): Promise<JWTResult[]> {
    return this.sendRequest<JWTResult[]>('issueVAPIDJWTs', params);
  }

  // ========================================================================
  // Status and Management
  // ========================================================================

  /**
   * Check if KMS is setup
   *
   * @param userId - Optional user ID to fetch leases for
   * @returns Setup status (includes leases if userId provided and setup is true)
   */
  async isSetup(userId?: string): Promise<StatusResult> {
    return this.sendRequest<StatusResult>('isSetup', { userId });
  }

  /**
   * Get list of enrolled authentication methods
   *
   * @returns List of enrollment IDs
   */
  async getEnrollments(): Promise<{ enrollments: string[] }> {
    return this.sendRequest<{ enrollments: string[] }>('getEnrollments', {});
  }

  /**
   * Verify audit chain integrity
   *
   * @returns Verification result
   */
  async verifyAuditChain(): Promise<AuditVerificationResult> {
    return this.sendRequest<AuditVerificationResult>('verifyAuditChain', {});
  }

  /**
   * Get audit log entries
   *
   * @returns All audit log entries
   */
  async getAuditLog(): Promise<{ entries: AuditEntryV2[] }> {
    return this.sendRequest<{ entries: AuditEntryV2[] }>('getAuditLog', {});
  }

  /**
   * Get audit log public key
   *
   * @returns Public key (base64url-encoded)
   */
  async getAuditPublicKey(): Promise<{ publicKey: string }> {
    return this.sendRequest<{ publicKey: string }>('getAuditPublicKey', {});
  }

  /**
   * Get all leases for a user
   *
   * @param userId - User ID to query leases for
   * @returns Array of lease records with expiration timestamps
   */
  async getUserLeases(userId: string): Promise<{ leases: LeaseRecord[] }> {
    return this.sendRequest<{ leases: LeaseRecord[] }>('getUserLeases', { userId });
  }

  /**
   * Verify a single lease against the current VAPID key
   *
   * Checks if the lease is valid (exists, not expired, matches current VAPID key).
   * This is a read-only operation that does not create audit entries.
   *
   * @param leaseId - Lease ID to verify
   * @returns Verification result with validity status and reason if invalid
   */
  async verifyLease(leaseId: string): Promise<LeaseVerificationResult> {
    return this.sendRequest<LeaseVerificationResult>('verifyLease', { leaseId });
  }

  /**
   * Reset KMS (delete all data)
   *
   * @returns Success result
   */
  async resetKMS(): Promise<{ success: boolean }> {
    return this.sendRequest<{ success: boolean }>('resetKMS', {});
  }

  /**
   * Remove specific enrollment method
   *
   * @param enrollmentId - Enrollment ID to remove
   * @param credentials - Authentication credentials
   * @returns Success result
   */
  async removeEnrollment(
    enrollmentId: string,
    credentials: AuthCredentials
  ): Promise<{ success: boolean }> {
    return this.sendRequest<{ success: boolean }>('removeEnrollment', {
      enrollmentId,
      credentials,
    });
  }
}
