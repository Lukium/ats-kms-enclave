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
  StoredPushSubscription,
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
  autoExtend?: boolean;
}

/**
 * Extend lease result (single lease)
 */
export interface ExtendLeaseResult {
  leaseId: string;
  exp: number;
  iat: number;
  kid: string;
  autoExtend: boolean;
}

/**
 * Individual lease result in batch operation
 */
export interface ExtendLeasesItemResult {
  leaseId: string;
  status: 'extended' | 'skipped';
  reason?: string;
  result?: ExtendLeaseResult;
}

/**
 * Batch extend leases result
 */
export interface ExtendLeasesResult {
  results: ExtendLeasesItemResult[];
  extended: number;
  skipped: number;
  failed: number;
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
    this.defaultTimeout = config.defaultTimeout ?? 300000; // 5 minutes for testing

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
      this.iframe.src = `${this.kmsOrigin}/?parentOrigin=${encodeURIComponent(window.location.origin)}`;

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
   * Setup KMS with passphrase authentication.
   *
   * Creates the Master Secret (if first enrollment) and generates initial VAPID keypair.
   * The passphrase is hashed using PBKDF2 with calibrated iterations (150-300ms target).
   *
   * **Security Notes:**
   * - Passphrase must be at least 8 characters (recommended: 12+ characters)
   * - PBKDF2 iterations are calibrated on first call for device performance
   * - Master Secret is randomly generated (32 bytes) and encrypted with passphrase-derived KEK
   *
   * @category Setup Operations
   *
   * @param userId - User identifier for enrollment
   * @param passphrase - User passphrase (minimum 8 characters, recommended 12+)
   *
   * @returns Promise resolving to setup result
   *
   * @throws {Error} Passphrase must be at least 8 characters
   * @throws {Error} KMS not initialized (call init() first)
   * @throws {Error} Request timeout (>10s)
   * @throws {Error} IndexedDB access denied
   *
   * @example
   * ```typescript
   * const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
   * await kmsUser.init();
   *
   * const result = await kmsUser.setupPassphrase(
   *   'user@example.com',
   *   'my-secure-passphrase-123'
   * );
   *
   * console.log('Enrollment ID:', result.enrollmentId);
   * ```
   *
   * @see {@link setupPasskeyPRF} for WebAuthn PRF setup
   * @see {@link setupPasskeyGate} for WebAuthn gate setup
   * @see {@link addEnrollment} to add additional auth methods
   */
  async setupPassphrase(userId: string, passphrase: string): Promise<SetupResult> {
    return this.sendRequest<SetupResult>('setupPassphrase', { userId, passphrase });
  }

  /**
   * Setup KMS with WebAuthn PRF (Pseudo-Random Function) authentication.
   *
   * Creates a WebAuthn credential with PRF extension support, deriving a cryptographic
   * key from the authenticator's PRF output. The PRF output is deterministic based on
   * the credential and salt, providing a secure key derivation mechanism.
   *
   * **How it works:**
   * 1. WebAuthn credential creation ceremony runs in parent PWA context
   * 2. PRF extension extracts deterministic output from authenticator
   * 3. PRF output sent to KMS and used to derive KEK
   * 4. Master Secret encrypted with PRF-derived KEK
   * 5. App salt stored in localStorage for future authentication
   *
   * **Requirements:**
   * - Authenticator must support PRF extension (most platform authenticators do)
   * - Requires user presence verification
   * - Platform authenticator recommended (biometrics)
   *
   * @category Setup Operations
   *
   * @param config - Passkey PRF configuration
   * @param config.userId - User identifier for enrollment
   * @param config.name - Display name for credential
   * @param config.rpId - Relying Party ID (domain, e.g., "ats.run")
   *
   * @returns Promise resolving to setup result
   * @returns {SetupResult} result
   * @returns {boolean} result.success - Always true if no error
   * @returns {string} result.enrollmentId - Enrollment identifier (format: "enrollment:passkey-prf:{credId}")
   *
   * @throws {Error} WebAuthn not supported
   * @throws {Error} PRF extension not supported or failed
   * @throws {Error} User cancelled WebAuthn ceremony
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
   * await kmsUser.init();
   *
   * try {
   *   const result = await kmsUser.setupPasskeyPRF({
   *     userId: 'user@example.com',
   *     name: 'My Device',
   *     rpId: 'ats.run',
   *   });
   *
   *   console.log('Passkey PRF setup complete');
   *   console.log('Enrollment ID:', result.enrollmentId);
   * } catch (err) {
   *   if (err.message.includes('PRF extension not supported')) {
   *     console.error('Your authenticator does not support PRF');
   *   }
   * }
   * ```
   *
   * @see {@link setupPassphrase} for passphrase-based setup
   * @see {@link setupPasskeyGate} for WebAuthn gate mode
   * @see {@link addEnrollment} to add additional auth methods
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
   * Setup KMS with WebAuthn gate authentication.
   *
   * Creates a WebAuthn credential that acts as a "gate" for accessing the KMS. Unlike
   * PRF mode, gate mode does not derive keys from the authenticator - it simply verifies
   * user presence before allowing KMS access. The Master Secret is randomly generated
   * and stored encrypted.
   *
   * **How it works:**
   * 1. WebAuthn credential creation ceremony runs in parent PWA context
   * 2. Credential ID stored as enrollment method
   * 3. Future operations require WebAuthn assertion to prove possession
   * 4. Master Secret is randomly generated (not derived from authenticator)
   *
   * **Use Cases:**
   * - Simpler WebAuthn integration (no PRF extension required)
   * - Works with more authenticators
   * - Good for additional auth factor (after passphrase)
   *
   * @category Setup Operations
   *
   * @param config - Passkey gate configuration
   * @param config.userId - User identifier for enrollment
   * @param config.name - Display name for credential
   * @param config.rpId - Relying Party ID (domain, e.g., "ats.run")
   *
   * @returns Promise resolving to setup result
   * @returns {SetupResult} result
   * @returns {boolean} result.success - Always true if no error
   * @returns {string} result.enrollmentId - Enrollment identifier (format: "enrollment:passkey-gate:{credId}")
   *
   * @throws {Error} WebAuthn not supported
   * @throws {Error} User cancelled WebAuthn ceremony
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * const kmsUser = new KMSUser({ kmsOrigin: 'https://kms.ats.run' });
   * await kmsUser.init();
   *
   * const result = await kmsUser.setupPasskeyGate({
   *   userId: 'user@example.com',
   *   name: 'My Security Key',
   *   rpId: 'ats.run',
   * });
   *
   * console.log('Passkey Gate setup complete');
   * console.log('Enrollment ID:', result.enrollmentId);
   * ```
   *
   * @see {@link setupPassphrase} for passphrase-based setup
   * @see {@link setupPasskeyPRF} for WebAuthn PRF mode
   * @see {@link addEnrollment} to add additional auth methods
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
   * Add an additional authentication method (multi-enrollment).
   *
   * Allows users to enroll multiple authentication methods (e.g., passphrase + passkey).
   * This provides flexibility and redundancy - if one method is unavailable, another
   * can be used. Requires authentication with an existing method to add a new one.
   *
   * **Use Cases:**
   * - Add passkey after initial passphrase setup
   * - Add backup authentication method
   * - Support multiple devices with different auth capabilities
   *
   * @category Setup Operations
   *
   * @param userId - User ID for the enrollment
   * @param method - Type of method to add ('passphrase', 'passkey-prf', or 'passkey-gate')
   * @param credentials - Current credentials to authenticate (proves ownership)
   * @param newCredentials - New credentials for the method being added
   *
   * @returns Promise resolving to setup result
   * @returns {SetupResult} result
   * @returns {boolean} result.success - Always true if no error
   * @returns {string} result.enrollmentId - New enrollment identifier
   *
   * @throws {Error} Authentication failed with current credentials
   * @throws {Error} Method already enrolled
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * // Add passkey PRF after initial passphrase setup
   * const result = await kmsUser.addEnrollment(
   *   'user@example.com',
   *   'passkey-prf',
   *   { passphrase: 'my-current-passphrase' },  // Existing auth
   *   {  // New WebAuthn credentials
   *     credentialId: rawId,
   *     prfOutput: prfData,
   *     rpId: 'ats.run',
   *   }
   * );
   *
   * console.log('Added passkey PRF:', result.enrollmentId);
   * ```
   *
   * @see {@link getEnrollments} to list all enrolled methods
   * @see {@link removeEnrollment} to remove a method
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

  // Legacy methods generateSetupTransportKey() and setupWithEncryptedCredentials() removed.
  // Use setupWithPopup() instead for secure KMS-only popup flow.

  /**
   * Setup user authentication via popup (iframe-managed flow).
   *
   * This method allows the iframe KMS to directly manage popup communication.
   * Parent only assists with window.open() - all cryptographic operations
   * and credential exchange bypass the parent entirely.
   *
   * **Security Benefits:**
   * - Parent never sees transport parameters
   * - Parent never receives encrypted credentials
   * - Direct same-origin communication between iframe and popup
   * - Reduced attack surface (parent out of credential path)
   *
   * **Flow:**
   * 1. Parent calls this method (RPC to iframe)
   * 2. Iframe requests parent to open popup (kms:request-popup)
   * 3. Parent opens popup with minimal URL and notifies iframe (kms:popup-opened)
   * 4. Popup signals ready to iframe (kms:popup-ready, same-origin)
   * 5. Iframe establishes MessageChannel with popup (kms:connect + transport params)
   * 6. Popup collects and encrypts credentials
   * 7. Popup sends credentials to iframe directly (via MessagePort)
   * 8. Iframe processes setup and returns result to parent
   *
   * **Parent Visibility:**
   * - Parent only sees minimal popup URL: `https://kms.ats.run/?mode=setup`
   * - Parent does NOT see: transport keys, salts, credentials, setup method
   *
   * **Comparison with setupWithEncryptedCredentials:**
   * - Old: Parent mediates all communication (parent ↔ popup ↔ iframe)
   * - New: Direct communication (popup ↔ iframe), parent only opens window
   *
   * @category Setup Operations
   *
   * @param params.userId - User ID to setup authentication for
   * @returns Setup result with enrollment ID and VAPID key info
   *
   * @throws {Error} If popup is blocked by browser
   * @throws {Error} If popup never responds (timeout)
   * @throws {Error} If credential collection fails in popup
   * @throws {Error} If setup processing fails in iframe
   *
   * @example
   * ```typescript
   * // In parent PWA:
   * const result = await kmsUser.setupWithPopup({
   *   userId: 'user@example.com'
   * });
   * console.log('Setup complete:', result.enrollmentId);
   * ```
   */
  async setupWithPopup(params: {
    userId: string;
  }): Promise<SetupResult> {
    return this.sendRequest<SetupResult>('setupWithPopup', params);
  }

  // ========================================================================
  // Unlock Operations
  // ========================================================================

  /**
   * Unlock KMS with passphrase
   *
   * Note: This only validates the passphrase. Actual operations require

  /**
   * Regenerate VAPID keypair, invalidating all existing leases.
   *
   * Deletes the current VAPID key and generates a new one with a new key ID (kid).
   * This is a destructive operation that invalidates:
   * - All existing leases (they reference the old kid)
   * - All JWT stashes (signed with old key)
   * - Push subscription (stored on the old key)
   *
   * **When to use:**
   * - VAPID key suspected to be compromised
   * - Rotating keys as security best practice
   * - Resetting authorization state
   *
   * **What happens:**
   * 1. User authenticates via iframe modal
   * 2. Old VAPID key(s) deleted from storage
   * 3. New P-256 ECDSA keypair generated
   * 4. New kid computed (JWK thumbprint)
   * 5. All leases invalidated (wrong-key)
   * 6. Push subscription lost (must call setPushSubscription again)
   *
   * **Security:** Credentials are ALWAYS collected in KMS iframe. The parent
   * MUST NOT pass credentials - doing so would bypass iframe isolation.
   *
   * @category VAPID Key Management
   *
   * @param params - Regeneration parameters
   * @param params.userId - User ID for authentication (REQUIRED for iframe modal)
   *
   * @returns Promise resolving to new VAPID key information
   * @returns {VAPIDKeyResult} result
   * @returns {string} result.kid - New key ID (JWK thumbprint)
   * @returns {string} result.publicKey - New public key (base64url-encoded, 65 bytes)
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} User not setup (no enrollments)
   * @throws {Error} Authentication cancelled by user
   * @throws {Error} IndexedDB access denied
   *
   * @example
   * ```typescript
   * // Regenerate VAPID key (triggers auth modal)
   * const newKey = await kmsUser.regenerateVAPID({
   *   userId: 'user@example.com',
   * });
   *
   * console.log('New VAPID Key ID:', newKey.kid);
   * console.log('New Public Key:', newKey.publicKey);
   *
   * // All leases are now invalid - verify and clean up
   * const { leases } = await kmsUser.getUserLeases('user@example.com');
   * for (const lease of leases) {
   *   const result = await kmsUser.verifyLease(lease.leaseId, true);
   *   console.log(`Lease ${lease.leaseId}:`, result.valid ? 'VALID' : 'INVALID');
   * }
   *
   * // Push subscription lost - must re-register
   * const { subscription } = await kmsUser.getPushSubscription();
   * console.log('Subscription:', subscription);  // null
   *
   * // Re-subscribe to push
   * await kmsUser.setPushSubscription(newSubscription);
   *
   * // Create new lease with new key
   * await kmsUser.createLease({ userId: 'user@example.com', subs: [...], ttlHours: 12 });
   * ```
   *
   * @see {@link verifyLease} to check which leases are now invalid
   * @see {@link getUserLeases} to get all leases for cleanup
   * @see {@link setPushSubscription} to re-register push subscription
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
   * Get public key for a specific VAPID key by key ID.
   *
   * Retrieves the public key portion of a VAPID keypair given its key ID (kid).
   * The public key is returned in raw format (65 bytes, uncompressed P-256 point)
   * encoded as base64url, suitable for use with PushManager.subscribe().
   *
   * **Note:** Most applications should use `getVAPIDPublicKey()` instead, which
   * automatically retrieves the current VAPID key without needing to know the kid.
   *
   * @category VAPID Key Management
   *
   * @param kid - Key ID (JWK thumbprint) of the VAPID key
   *
   * @returns Promise resolving to public key
   * @returns {object} result
   * @returns {string} result.publicKey - Public key (base64url-encoded, 65 bytes decoded)
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} Key not found
   *
   * @example
   * ```typescript
   * // Get public key by kid (if you know the kid)
   * const { publicKey } = await kmsUser.getPublicKey('kid-abc-123');
   * console.log('Public Key:', publicKey);
   *
   * // Use with PushManager (convert to Uint8Array)
   * const pubKeyBytes = base64urlToUint8Array(publicKey);
   * const subscription = await registration.pushManager.subscribe({
   *   userVisibleOnly: true,
   *   applicationServerKey: pubKeyBytes,
   * });
   * ```
   *
   * @see {@link getVAPIDPublicKey} to get current VAPID key without knowing kid
   */
  async getPublicKey(kid: string): Promise<{ publicKey: string }> {
    return this.sendRequest<{ publicKey: string }>('getPublicKey', { kid });
  }

  /**
   * Get VAPID public key for the current user (convenience method).
   *
   * Retrieves the user's VAPID public key without requiring the key ID. This is the
   * recommended method for most applications, as it automatically finds the current
   * VAPID key and returns both the public key and its kid.
   *
   * **Implementation:** Internally calls getVAPIDKid() to get the key ID, then
   * calls getPublicKey() with that kid.
   *
   * **Use Cases:**
   * - Subscribe to Web Push notifications
   * - Display VAPID key info to user
   * - Verify key exists before creating leases
   *
   * @category VAPID Key Management
   *
   * @param _userId - User ID (currently unused, kept for API consistency)
   *
   * @returns Promise resolving to VAPID key information
   * @returns {object} result
   * @returns {string} result.publicKey - Public key (base64url-encoded, 65 bytes decoded)
   * @returns {string} result.kid - Key ID (JWK thumbprint)
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} No VAPID key found (user needs to setup or regenerate)
   * @throws {Error} Multiple VAPID keys found (data corruption - should not happen)
   *
   * @example
   * ```typescript
   * // Get current VAPID public key
   * const { publicKey, kid } = await kmsUser.getVAPIDPublicKey('user@example.com');
   *
   * console.log('VAPID Key ID:', kid);
   * console.log('Public Key:', publicKey);
   *
   * // Use with PushManager.subscribe()
   * const pubKeyBytes = base64urlToUint8Array(publicKey);
   * const registration = await navigator.serviceWorker.ready;
   * const subscription = await registration.pushManager.subscribe({
   *   userVisibleOnly: true,
   *   applicationServerKey: pubKeyBytes,
   * });
   *
   * // Store subscription in KMS
   * await kmsUser.setPushSubscription({
   *   endpoint: subscription.endpoint,
   *   expirationTime: subscription.expirationTime,
   *   keys: {
   *     p256dh: arrayBufferToBase64url(subscription.getKey('p256dh')),
   *     auth: arrayBufferToBase64url(subscription.getKey('auth')),
   *   },
   *   eid: 'my-device',
   *   createdAt: Date.now(),
   * });
   * ```
   *
   * @see {@link getPublicKey} to get public key by kid (if you know the kid)
   * @see {@link regenerateVAPID} to generate a new VAPID key
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
   * Create VAPID lease for long-lived JWT issuance authorization.
   *
   * Leases allow issuing JWTs without re-authentication by deriving a session-specific KEK
   * from the Master Secret. The VAPID private key is re-wrapped with this SessionKEK and
   * stored in memory, enabling credential-free JWT signing until lease expiration.
   *
   * **Authentication:** This operation triggers iframe modal for user authentication.
   * Credentials are collected inside the KMS iframe and NEVER exposed to parent PWA.
   *
   * **Push Subscription:** The lease automatically uses the push subscription stored on
   * the VAPID key. Call `setPushSubscription()` before creating leases if you need
   * push notification support.
   *
   * **Quotas:** Each lease has rate limits enforced by the worker:
   * - 100 tokens per hour
   * - 10 sends per minute (burst: 20)
   * - 5 sends per minute per endpoint ID
   *
   * @category VAPID Lease Operations
   *
   * @param params - Lease creation parameters
   * @param params.userId - User ID for authentication (REQUIRED for iframe modal)
   * @param params.subs - Array of push subscription endpoints to authorize
   * @param params.ttlHours - Lease time-to-live in hours (max 720 hours / 30 days)
   *
   * @returns Promise resolving to lease information
   * @returns {LeaseResult} result
   * @returns {string} result.leaseId - Unique lease identifier (format: "lease-{uuid}")
   * @returns {number} result.exp - Expiration timestamp in milliseconds
   * @returns {object} result.quotas - Rate limit quotas for this lease
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} User not setup (no enrollments)
   * @throws {Error} No VAPID key found
   * @throws {Error} No push subscription found (call setPushSubscription first)
   * @throws {Error} Invalid subs format
   * @throws {Error} ttlHours exceeds maximum (720 hours)
   * @throws {Error} Authentication cancelled by user
   *
   * @example
   * ```typescript
   * // Ensure push subscription is set
   * await kmsUser.setPushSubscription(subscription);
   *
   * // Create lease (triggers auth modal)
   * const lease = await kmsUser.createLease({
   *   userId: 'user@example.com',
   *   subs: [
   *     {
   *       url: 'https://fcm.googleapis.com/fcm/send/abc123',
   *       aud: 'https://fcm.googleapis.com',
   *       eid: 'endpoint-1',
   *     },
   *   ],
   *   ttlHours: 12,
   * });
   *
   * console.log('Lease ID:', lease.leaseId);
   * console.log('Expires:', new Date(lease.exp));
   *
   * // Now can issue JWTs without re-authentication
   * const jwt = await kmsUser.issueVAPIDJWT({
   *   leaseId: lease.leaseId,
   *   endpoint: { url: '...', aud: '...', eid: 'endpoint-1' },
   * });
   * ```
   *
   * @see {@link issueVAPIDJWT} to issue single JWT from lease
   * @see {@link issueVAPIDJWTs} to batch issue JWTs from lease
   * @see {@link verifyLease} to check lease validity
   * @see {@link getUserLeases} to list all user leases
   * @see {@link setPushSubscription} to configure push subscription
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
   * Extend one or more existing leases.
   *
   * Updates lease expirations to 30 days from now. This method accepts an array of lease IDs
   * and processes them in batch, returning detailed results for each lease.
   *
   * **Auto-Extend Behavior:**
   * - `autoExtend=true` (default): Extension works without authentication
   * - `autoExtend=false`: Requires authentication OR will be skipped if `requestAuth` not set
   *
   * **Smart Skipping:** If `requestAuth` is not set, the worker will automatically skip
   * non-extendable leases (autoExtend=false) and return them with status='skipped'. This
   * allows "Extend All Leases" to gracefully handle mixed lease types.
   *
   * **Single Authentication:** When `requestAuth=true`, the user authenticates once and
   * all leases (both extendable and non-extendable) are processed with credentials.
   *
   * **Security Note:** Leases must be for the current VAPID key. If the VAPID key has
   * been regenerated, extensions will fail and new leases must be created.
   *
   * @category VAPID Lease Operations
   *
   * @param leaseIds - Array of lease IDs to extend
   * @param userId - The user ID who owns the leases
   * @param options - Extension options
   * @param options.requestAuth - Set to true to request user authentication for all leases
   *
   * @returns Promise resolving to batch result with per-lease details
   *
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * // Extend multiple auto-extendable leases (skips non-extendable)
   * const result = await kmsUser.extendLeases(
   *   ['lease-abc-123', 'lease-def-456', 'lease-ghi-789'],
   *   'user@example.com'
   * );
   * console.log(`Extended: ${result.extended}, Skipped: ${result.skipped}`);
   *
   * // Extend with authentication (processes all leases)
   * const result = await kmsUser.extendLeases(
   *   ['lease-abc-123', 'lease-def-456'],
   *   'user@example.com',
   *   { requestAuth: true }
   * );
   * ```
   *
   * @see {@link createLease} to create a new lease
   * @see {@link verifyLease} to verify lease validity
   */
  async extendLeases(
    leaseIds: string[],
    userId: string,
    options?: { requestAuth?: boolean }
  ): Promise<ExtendLeasesResult> {
    // Show iframe if authentication is requested (needed for modal to be visible)
    if (options?.requestAuth && this.iframe) {
      this.iframe.style.display = 'block';
    }

    try {
      const result = await this.sendRequest<ExtendLeasesResult>('extendLeases', {
        leaseIds,
        userId,
        requestAuth: options?.requestAuth ?? false,
      });
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
   * Issue a single VAPID JWT for an endpoint using lease authorization.
   *
   * Uses an existing lease to sign a JWT without requiring re-authentication. The JWT
   * is signed with the VAPID private key and includes RFC 8292 VAPID headers for push
   * service authorization.
   *
   * **No Credentials Required:** The lease IS the authorization. Once a lease exists,
   * JWTs can be issued freely until the lease expires.
   *
   * **Automatic Verification:** Automatically verifies the lease is valid before issuing
   * the JWT. This prevents JWT issuance against expired or invalidated leases.
   *
   * **JWT Format:** RFC 8292 compliant with:
   * - Header: `{ typ: 'JWT', alg: 'ES256' }`
   * - Payload: `{ aud, exp, sub }`
   * - Signature: ECDSA P-256 (P-1363 format, 64 bytes)
   * - Default TTL: 15 minutes (900 seconds)
   *
   * @category VAPID Lease Operations
   *
   * @param params - JWT issuance parameters
   * @param params.leaseId - Lease ID for authorization
   * @param params.endpoint - Push endpoint details
   * @param params.endpoint.url - Push service URL (e.g., FCM endpoint)
   * @param params.endpoint.aud - Audience (push service origin, e.g., "https://fcm.googleapis.com")
   * @param params.endpoint.eid - Endpoint identifier for quota tracking
   * @param params.kid - Optional VAPID key ID (auto-detected if not provided)
   *
   * @returns Promise resolving to JWT result
   * @returns {JWTResult} result
   * @returns {string} result.jwt - Signed JWT token (base64url-encoded)
   * @returns {string} [result.jti] - JWT ID (unique identifier)
   * @returns {number} [result.exp] - Expiration timestamp in milliseconds
   *
   * @throws {Error} Cannot issue JWT: lease expired
   * @throws {Error} Cannot issue JWT: lease wrong-key
   * @throws {Error} Cannot issue JWT: lease not-found
   * @throws {Error} KMS not initialized
   * @throws {Error} Lease not found in worker memory
   * @throws {Error} Quota exceeded (rate limits)
   *
   * @example
   * ```typescript
   * // Issue a single JWT using a lease
   * const jwt = await kmsUser.issueVAPIDJWT({
   *   leaseId: 'lease-abc-123',
   *   endpoint: {
   *     url: 'https://fcm.googleapis.com/fcm/send/abc123',
   *     aud: 'https://fcm.googleapis.com',
   *     eid: 'device-1',
   *   },
   * });
   *
   * console.log('JWT:', jwt.jwt);
   * console.log('Expires:', new Date(jwt.exp));
   *
   * // Use JWT in push notification Authorization header
   * const vapidHeader = `vapid t=${jwt.jwt}, k=${vapidPublicKey}`;
   * ```
   *
   * @see {@link issueVAPIDJWTs} to batch issue multiple JWTs
   * @see {@link createLease} to create a lease first
   * @see {@link verifyLease} to check lease validity
   */
  async issueVAPIDJWT(params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    kid?: string; // Optional - auto-detected if not provided (per V2 spec)
  }): Promise<JWTResult> {
    // Auto-verify lease before issuing JWT (fail-fast)
    const verification = await this.verifyLease(params.leaseId);

    if (!verification.valid) {
      throw new Error(`Cannot issue JWT: lease ${verification.reason || 'invalid'}`);
    }

    return this.sendRequest<JWTResult>('issueVAPIDJWT', params);
  }

  /**
   * Issue multiple VAPID JWTs with staggered expirations for JWT rotation.
   *
   * Generates N JWTs for the same endpoint with intelligent expiration staggering to enable
   * seamless JWT rotation without gaps. This is useful for "JWT stashing" where the client
   * pre-fetches multiple JWTs to avoid needing to call the KMS for every push notification.
   *
   * **Staggered Expirations:**
   * - JWT[0]: expires at T+15min (900s)
   * - JWT[1]: expires at T+24min (900s + 540s stagger)
   * - JWT[2]: expires at T+33min (900s + 1080s stagger)
   *
   * The stagger interval is 60% of the JWT TTL (540s for 900s TTL), ensuring seamless
   * rotation: when JWT[0] reaches 60% TTL, JWT[1] is already valid.
   *
   * **Automatic Verification:** Automatically verifies the lease is valid before issuing JWTs.
   * This prevents JWT issuance against expired or invalidated leases.
   *
   * @category VAPID Lease Operations
   *
   * @param params - Batch issuance parameters
   * @param params.leaseId - Lease ID for authorization
   * @param params.endpoint - Push endpoint details
   * @param params.endpoint.url - Push service URL
   * @param params.endpoint.aud - Audience (push service origin)
   * @param params.endpoint.eid - Endpoint identifier for quota tracking
   * @param params.count - Number of JWTs to issue (1-10, hard limit enforced by worker)
   * @param params.kid - Optional VAPID key ID (auto-detected if not provided)
   *
   * @returns Promise resolving to array of JWT results with staggered expirations
   * @returns {JWTResult[]} results - Array of JWT objects
   *
   * @throws {Error} Cannot issue JWTs: lease expired
   * @throws {Error} Cannot issue JWTs: lease wrong-key
   * @throws {Error} Cannot issue JWTs: lease not-found
   * @throws {Error} KMS not initialized
   * @throws {Error} count must be between 1 and 10
   * @throws {Error} Quota exceeded (rate limits)
   *
   * @example
   * ```typescript
   * // Issue 5 staggered JWTs for JWT rotation
   * const jwts = await kmsUser.issueVAPIDJWTs({
   *   leaseId: 'lease-abc-123',
   *   endpoint: {
   *     url: 'https://fcm.googleapis.com/fcm/send/abc123',
   *     aud: 'https://fcm.googleapis.com',
   *     eid: 'device-1',
   *   },
   *   count: 5,
   * });
   *
   * console.log('Generated', jwts.length, 'JWTs');
   * jwts.forEach((jwt, i) => {
   *   console.log(`JWT[${i}] expires:`, new Date(jwt.exp));
   * });
   *
   * // Store JWTs for rotation
   * localStorage.setItem('jwt-stash', JSON.stringify(jwts));
   * ```
   *
   * @see {@link issueVAPIDJWT} to issue a single JWT
   * @see {@link createLease} to create a lease first
   * @see {@link verifyLease} to check lease validity
   */
  async issueVAPIDJWTs(params: {
    leaseId: string;
    endpoint: { url: string; aud: string; eid: string };
    count: number;
    kid?: string;
  }): Promise<JWTResult[]> {
    // Auto-verify lease before issuing JWTs (fail-fast for entire batch)
    const verification = await this.verifyLease(params.leaseId);

    if (!verification.valid) {
      throw new Error(`Cannot issue JWTs: lease ${verification.reason || 'invalid'}`);
    }

    return this.sendRequest<JWTResult[]>('issueVAPIDJWTs', params);
  }

  // ========================================================================
  // Status and Management
  // ========================================================================

  /**
   * Check if KMS is setup for the current user.
   *
   * Returns whether the KMS has been initialized with at least one enrollment method.
   * If setup is complete, also returns the list of enrolled authentication methods.
   * Optionally includes lease information if a userId is provided.
   *
   * **Use Cases:**
   * - Check if user needs to complete setup before using KMS
   * - Display enrolled authentication methods to user
   * - Monitor lease status
   *
   * @category Status and Query Operations
   *
   * @param userId - Optional user ID to fetch leases for
   *
   * @returns Promise resolving to setup status
   * @returns {StatusResult} result
   * @returns {boolean} result.isSetup - Whether KMS has at least one enrollment
   * @returns {string[]} result.methods - Array of enrollment IDs (e.g., ["enrollment:passphrase:v2"])
   * @returns {LeaseRecord[]} [result.leases] - Array of lease records (only if userId provided and isSetup true)
   *
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * // Check if setup (without leases)
   * const status = await kmsUser.isSetup();
   *
   * if (status.isSetup) {
   *   console.log('KMS is setup');
   *   console.log('Enrolled methods:', status.methods);
   * } else {
   *   console.log('KMS not setup - need to call setupPassphrase() or setupPasskeyPRF()');
   * }
   *
   * // Check with leases
   * const statusWithLeases = await kmsUser.isSetup('user@example.com');
   * if (statusWithLeases.leases) {
   *   console.log(`User has ${statusWithLeases.leases.length} active leases`);
   * }
   * ```
   *
   * @see {@link setupPassphrase} to setup with passphrase
   * @see {@link setupPasskeyPRF} to setup with WebAuthn PRF
   * @see {@link getEnrollments} to get full enrollment list
   */
  async isSetup(userId?: string): Promise<StatusResult> {
    return this.sendRequest<StatusResult>('isSetup', { userId });
  }

  /**
   * Get list of all enrolled authentication methods.
   *
   * Returns the enrollment IDs for all authentication methods that have been registered
   * with the KMS. This includes passphrase, passkey-PRF, and passkey-gate enrollments.
   *
   * @category Status and Query Operations
   *
   * @returns Promise resolving to array of enrollment IDs
   * @returns {object} result
   * @returns {string[]} result.enrollments - Array of enrollment IDs (e.g., ["enrollment:passphrase:v2", "enrollment:passkey-prf:abc123"])
   *
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * const { enrollments } = await kmsUser.getEnrollments();
   *
   * console.log('Enrolled methods:', enrollments);
   * enrollments.forEach(eid => {
   *   if (eid.startsWith('enrollment:passphrase:')) {
   *     console.log('  - Passphrase');
   *   } else if (eid.startsWith('enrollment:passkey-prf:')) {
   *     console.log('  - WebAuthn PRF');
   *   } else if (eid.startsWith('enrollment:passkey-gate:')) {
   *     console.log('  - WebAuthn Gate');
   *   }
   * });
   * ```
   *
   * @see {@link isSetup} to check if any enrollments exist
   * @see {@link addEnrollment} to add additional methods
   * @see {@link removeEnrollment} to remove a method
   */
  async getEnrollments(): Promise<{ enrollments: string[] }> {
    return this.sendRequest<{ enrollments: string[] }>('getEnrollments', {});
  }

  /**
   * Verify the integrity of the audit log chain.
   *
   * Verifies cryptographic signatures and hash chains to ensure the audit log has not
   * been tampered with. Each audit entry is signed with an Ed25519 key and includes
   * a hash of the previous entry, forming an immutable chain.
   *
   * @category Status and Query Operations
   *
   * @returns Promise resolving to verification result
   * @returns {AuditVerificationResult} result
   * @returns {boolean} result.valid - Whether the audit chain is valid
   * @returns {number} result.entries - Number of entries verified
   *
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * const result = await kmsUser.verifyAuditChain();
   *
   * if (result.valid) {
   *   console.log(`✓ Audit chain valid (${result.entries} entries)`);
   * } else {
   *   console.error('⚠️ Audit chain integrity compromised!');
   * }
   * ```
   *
   * @see {@link getAuditLog} to retrieve all audit entries
   * @see {@link getAuditPublicKey} to get the verification key
   */
  async verifyAuditChain(): Promise<AuditVerificationResult> {
    return this.sendRequest<AuditVerificationResult>('verifyAuditChain', {});
  }

  /**
   * Get all audit log entries.
   *
   * Returns the complete audit log showing all cryptographic operations performed
   * by the KMS. Each entry includes operation type, timestamp, parameters, and
   * cryptographic signature.
   *
   * @category Status and Query Operations
   *
   * @returns Promise resolving to audit log entries
   * @returns {object} result
   * @returns {AuditEntryV2[]} result.entries - Array of audit entries
   *
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * const { entries } = await kmsUser.getAuditLog();
   *
   * console.log(`Audit log: ${entries.length} entries`);
   * entries.forEach(entry => {
   *   console.log(`[${new Date(entry.timestamp)}] ${entry.operation}`);
   *   if (entry.params) {
   *     console.log('  Params:', JSON.stringify(entry.params, null, 2));
   *   }
   * });
   * ```
   *
   * @see {@link verifyAuditChain} to verify integrity
   */
  async getAuditLog(): Promise<{ entries: AuditEntryV2[] }> {
    return this.sendRequest<{ entries: AuditEntryV2[] }>('getAuditLog', {});
  }

  /**
   * Get the audit log's Ed25519 public key.
   *
   * Returns the public key used to verify audit log signatures. This key is
   * generated once during first KMS operation and used for all subsequent
   * audit entries.
   *
   * @category Status and Query Operations
   *
   * @returns Promise resolving to public key
   * @returns {object} result
   * @returns {string} result.publicKey - Ed25519 public key (base64url-encoded, 32 bytes)
   *
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * const { publicKey } = await kmsUser.getAuditPublicKey();
   * console.log('Audit Public Key:', publicKey);
   *
   * // Can be used to independently verify audit signatures
   * ```
   *
   * @see {@link verifyAuditChain} to verify audit integrity
   */
  async getAuditPublicKey(): Promise<{ publicKey: string }> {
    return this.sendRequest<{ publicKey: string }>('getAuditPublicKey', {});
  }

  /**
   * Get all leases for a user.
   *
   * Returns all lease records associated with the user, including lease IDs, expiration
   * timestamps, VAPID key IDs, and authorized endpoints. This is useful for:
   * - Displaying active leases in UI
   * - Bulk lease verification/cleanup
   * - Monitoring lease expiration
   * - Debugging authorization issues
   *
   * **Note:** This method returns all leases regardless of validity. Use `verifyLease()`
   * to check if individual leases are still valid (not expired, correct VAPID key).
   *
   * @category VAPID Lease Operations
   *
   * @param userId - User ID to query leases for
   *
   * @returns Promise resolving to array of lease records
   * @returns {object} result
   * @returns {LeaseRecord[]} result.leases - Array of lease records
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} Request timeout
   *
   * @example
   * ```typescript
   * // Get all leases for a user
   * const { leases } = await kmsUser.getUserLeases('user@example.com');
   *
   * console.log(`Found ${leases.length} leases`);
   * leases.forEach(lease => {
   *   console.log('Lease ID:', lease.leaseId);
   *   console.log('Expires:', new Date(lease.exp));
   *   console.log('VAPID Key:', lease.kid);
   *   console.log('Endpoints:', lease.subs.map(s => s.eid).join(', '));
   *
   *   // Check if expired
   *   if (lease.exp < Date.now()) {
   *     console.log('  ⚠️ EXPIRED');
   *   }
   * });
   *
   * // Verify and clean up invalid leases
   * for (const lease of leases) {
   *   await kmsUser.verifyLease(lease.leaseId, true); // Delete if invalid
   * }
   * ```
   *
   * @see {@link verifyLease} to check individual lease validity
   * @see {@link createLease} to create new leases
   */
  async getUserLeases(userId: string): Promise<{ leases: LeaseRecord[] }> {
    return this.sendRequest<{ leases: LeaseRecord[] }>('getUserLeases', { userId });
  }

  /**
   * Verify lease validity against current VAPID key.
   *
   * Checks if a lease is valid by verifying:
   * 1. Lease exists in storage
   * 2. Lease has not expired (exp > Date.now())
   * 3. Lease kid matches current VAPID key kid
   *
   * This is a **read-only** operation that does not modify lease state or produce audit entries.
   *
   * **Optional Deletion:** If `deleteIfInvalid` is true, invalid leases (expired or wrong kid)
   * are automatically deleted from storage. This is useful for cleanup after VAPID key regeneration.
   *
   * @category VAPID Lease Operations
   *
   * @param leaseId - Lease identifier to verify
   * @param deleteIfInvalid - If true, delete lease if invalid (default: false)
   *
   * @returns Promise resolving to verification result
   * @returns {LeaseVerificationResult} result
   * @returns {string} result.leaseId - Lease identifier (echoed from input)
   * @returns {boolean} result.valid - Whether lease is valid
   * @returns {string} result.kid - Key ID from lease
   * @returns {string} [result.reason] - Reason if invalid ("expired", "wrong-key", "not-found")
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} Request timeout
   *
   * @example
   * ```typescript
   * // Basic verification
   * const result = await kmsUser.verifyLease('lease-abc-123');
   *
   * if (result.valid) {
   *   console.log('Lease is valid');
   * } else {
   *   console.log('Lease is invalid:', result.reason);
   *   // reason can be: "expired", "wrong-key", or "not-found"
   * }
   *
   * // Verify and clean up invalid leases
   * const resultWithCleanup = await kmsUser.verifyLease('lease-abc-123', true);
   * if (!resultWithCleanup.valid) {
   *   console.log('Invalid lease was automatically deleted');
   * }
   *
   * // Bulk cleanup after VAPID regeneration
   * const { leases } = await kmsUser.getUserLeases('user@example.com');
   * for (const lease of leases) {
   *   await kmsUser.verifyLease(lease.leaseId, true); // Delete if invalid
   * }
   * ```
   *
   * @see {@link getUserLeases} to get all user leases
   * @see {@link createLease} to create new leases
   * @see {@link regenerateVAPID} invalidates all leases
   */
  async verifyLease(
    leaseId: string,
    deleteIfInvalid?: boolean
  ): Promise<LeaseVerificationResult> {
    return this.sendRequest<LeaseVerificationResult>('verifyLease', {
      leaseId,
      ...(deleteIfInvalid !== undefined && { deleteIfInvalid }),
    });
  }

  /**
   * Reset KMS and delete all data.
   *
   * **DESTRUCTIVE OPERATION** - Permanently deletes all KMS data including:
   * - All enrollment methods (passphrase, passkeys)
   * - Master Secret and derived keys
   * - VAPID keypairs
   * - All leases
   * - Push subscriptions
   * - Audit log
   *
   * This operation cannot be undone. Use for testing, debugging, or complete account reset.
   *
   * **Security:** No authentication required - this is a nuclear option for complete reset.
   *
   * @category Management Operations
   *
   * @returns Promise resolving to success status
   * @returns {object} result
   * @returns {boolean} result.success - Always true if no error
   *
   * @throws {Error} KMS not initialized
   * @throws {Error} IndexedDB access denied
   *
   * @example
   * ```typescript
   * // ⚠️ WARNING: This deletes everything!
   * const result = await kmsUser.resetKMS();
   * console.log('KMS reset complete - all data deleted');
   *
   * // After reset, user must setup again
   * await kmsUser.setupPassphrase('user@example.com', 'new-passphrase');
   * ```
   *
   * @see {@link setupPassphrase} to setup after reset
   */
  async resetKMS(): Promise<{ success: boolean }> {
    return this.sendRequest<{ success: boolean }>('resetKMS', {});
  }

  /**
   * Remove a specific enrollment method.
   *
   * Deletes an authentication method from the KMS. Requires authentication with
   * current credentials to prove ownership before removal. Cannot remove the last
   * enrollment method (at least one must remain).
   *
   * **Use Cases:**
   * - Remove compromised passphrase
   * - Remove lost/stolen hardware key
   * - Clean up unused authentication methods
   *
   * @category Management Operations
   *
   * @param enrollmentId - Enrollment ID to remove (e.g., "enrollment:passphrase:v2")
   * @param credentials - Current authentication credentials (proves ownership)
   *
   * @returns Promise resolving to success status
   * @returns {object} result
   * @returns {boolean} result.success - Always true if no error
   *
   * @throws {Error} Authentication failed
   * @throws {Error} Cannot remove last enrollment method
   * @throws {Error} Enrollment not found
   * @throws {Error} KMS not initialized
   *
   * @example
   * ```typescript
   * // Remove a passphrase enrollment
   * await kmsUser.removeEnrollment(
   *   'enrollment:passphrase:v2',
   *   { passphrase: 'current-passphrase' }
   * );
   *
   * console.log('Passphrase enrollment removed');
   *
   * // Verify removal
   * const { enrollments } = await kmsUser.getEnrollments();
   * console.log('Remaining methods:', enrollments);
   * ```
   *
   * @see {@link getEnrollments} to list all enrollment methods
   * @see {@link addEnrollment} to add a new method
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

  // ============================================================================
  // Push Subscription Methods
  // ============================================================================

  /**
   * Store or update Web Push subscription on VAPID key.
   *
   * The subscription is stored on the `WrappedKey` record in IndexedDB, establishing a 1:1
   * relationship between VAPID key and push subscription. This allows leases and JWTs to
   * automatically use the subscription data without passing it on every call.
   *
   * **Storage Location:** The subscription is stored on the VAPID key's `subscription` field,
   * NOT in lease records. All leases for a VAPID key use the same subscription (single source of truth).
   *
   * **Security:** Endpoints are validated against a whitelist of known push services:
   * - Firebase Cloud Messaging (FCM)
   * - Apple Push Notification service (APNs)
   * - Mozilla Push Service
   * - Windows Push Notification Services (WNS)
   *
   * @category Push Notifications
   *
   * @param subscription - Push subscription object from PushManager.subscribe()
   * @param subscription.endpoint - Push service URL (must be HTTPS and whitelisted)
   * @param subscription.expirationTime - Subscription expiry timestamp (ms) or null
   * @param subscription.keys - Client encryption keys
   * @param subscription.keys.p256dh - Client public key (base64url, 65 bytes decoded)
   * @param subscription.keys.auth - Auth secret (base64url, 16 bytes decoded)
   * @param subscription.eid - User-defined endpoint label (e.g., "laptop-chrome")
   * @param subscription.createdAt - Creation timestamp in milliseconds
   *
   * @returns Promise resolving to success status
   *
   * @throws {Error} No VAPID key found (call generateVAPID first)
   * @throws {Error} Multiple VAPID keys found (ambiguous which to update)
   * @throws {Error} Endpoint must use HTTPS
   * @throws {Error} Endpoint must be from a known push service (whitelist check failed)
   * @throws {Error} keys.p256dh must be base64url string of exactly 65 decoded bytes
   * @throws {Error} keys.auth must be base64url string of exactly 16 decoded bytes
   *
   * @example
   * ```typescript
   * // Generate VAPID key first
   * const vapid = await kmsUser.generateVAPID(credentials);
   *
   * // Subscribe to push in browser
   * const registration = await navigator.serviceWorker.ready;
   * const pushSub = await registration.pushManager.subscribe({
   *   userVisibleOnly: true,
   *   applicationServerKey: vapid.publicKey,
   * });
   *
   * // Convert and store in KMS
   * await kmsUser.setPushSubscription({
   *   endpoint: pushSub.endpoint,
   *   expirationTime: pushSub.expirationTime,
   *   keys: {
   *     p256dh: arrayBufferToBase64url(pushSub.getKey('p256dh')),
   *     auth: arrayBufferToBase64url(pushSub.getKey('auth')),
   *   },
   *   eid: 'my-laptop-chrome',
   *   createdAt: Date.now(),
   * });
   * ```
   *
   * @see {@link getPushSubscription} to retrieve subscription
   * @see {@link removePushSubscription} to delete subscription
   * @see {@link issueVAPIDJWT} uses subscription for JWT generation
   */
  async setPushSubscription(subscription: StoredPushSubscription): Promise<{ success: boolean }> {
    return this.sendRequest<{ success: boolean }>('setPushSubscription', {
      subscription,
    });
  }

  /**
   * Remove the Web Push subscription from the VAPID key.
   *
   * Removes the subscription field from the VAPID key record. The VAPID key itself is **not**
   * deleted - only the subscription field is removed. This operation is idempotent (calling
   * when no subscription exists does not throw an error).
   *
   * **Behavior:**
   * - Subscription field deleted from VAPID key
   * - VAPID key remains (can still sign JWTs if subscription not needed)
   * - Existing leases remain valid but cannot issue JWTs until subscription is re-added
   * - Idempotent: safe to call multiple times
   *
   * @category Push Notifications
   *
   * @returns Promise resolving to success status
   * @returns {object} result
   * @returns {boolean} result.success - Always true if no error thrown
   *
   * @throws {Error} KMS not initialized (call init() first)
   * @throws {Error} No VAPID key found
   * @throws {Error} Multiple VAPID keys found (ambiguous which to update)
   *
   * @example
   * ```typescript
   * // Unsubscribe from push in browser first
   * const registration = await navigator.serviceWorker.ready;
   * const subscription = await registration.pushManager.getSubscription();
   * if (subscription) {
   *   await subscription.unsubscribe();
   * }
   *
   * // Remove subscription from KMS storage
   * await kmsUser.removePushSubscription();
   *
   * // Verify removal
   * const { subscription: stored } = await kmsUser.getPushSubscription();
   * console.log('Subscription is now:', stored);  // null
   * ```
   *
   * @see {@link setPushSubscription} to store a new subscription
   * @see {@link getPushSubscription} to check if subscription exists
   * @see {@link regenerateVAPID} regenerates key (also loses subscription)
   */
  async removePushSubscription(): Promise<{ success: boolean }> {
    return this.sendRequest<{ success: boolean }>('removePushSubscription', {});
  }

  /**
   * Get the push subscription stored on the VAPID key.
   *
   * Returns the Web Push subscription currently associated with the VAPID key, or null if
   * no subscription has been set. The subscription is stored on the VAPID key's `subscription`
   * field (1:1 relationship).
   *
   * **Use Cases:**
   * - Check if push notifications are configured before creating leases
   * - Verify subscription hasn't expired
   * - Display current subscription endpoint to user
   * - Check subscription exists before issuing JWTs
   *
   * @category Push Notifications
   *
   * @returns Promise resolving to object containing subscription or null
   * @returns {object} result
   * @returns {StoredPushSubscription | null} result.subscription - The stored subscription or null
   *
   * @throws {Error} KMS not initialized (call init() first)
   * @throws {Error} No VAPID key found
   * @throws {Error} Multiple VAPID keys found (ambiguous which to read from)
   *
   * @example
   * ```typescript
   * // Check if subscription exists
   * const { subscription } = await kmsUser.getPushSubscription();
   *
   * if (subscription) {
   *   console.log('Push endpoint:', subscription.endpoint);
   *   console.log('Endpoint ID:', subscription.eid);
   *
   *   // Check if expired
   *   if (subscription.expirationTime && subscription.expirationTime < Date.now()) {
   *     console.warn('Subscription expired, need to renew');
   *   }
   * } else {
   *   console.log('No subscription configured');
   *   // Need to call setPushSubscription()
   * }
   * ```
   *
   * @see {@link setPushSubscription} to store a subscription
   * @see {@link removePushSubscription} to delete the subscription
   * @see {@link createLease} requires subscription to be set first
   */
  async getPushSubscription(): Promise<{ subscription: StoredPushSubscription | null }> {
    return this.sendRequest<{ subscription: StoredPushSubscription | null }>('getPushSubscription', {});
  }
}
