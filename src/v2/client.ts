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

    // Forward to Worker
    try {
      this.worker.postMessage(event.data);
    } catch (err: any) {
      console.error('[KMS Client] Failed to forward message to Worker:', err);

      // Send error response to parent
      const request = event.data as RPCRequest;
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

  // Create and initialize client
  const client = new KMSClient({ parentOrigin });

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      client.init().catch((err) => {
        console.error('[KMS Client] Auto-initialization failed:', err);
      });
    });
  } else {
    // DOM already ready
    client.init().catch((err) => {
      console.error('[KMS Client] Auto-initialization failed:', err);
    });
  }

  // Export for debugging
  (window as any).__kmsClient = client;
}
