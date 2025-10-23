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

  generateVAPID(): Promise<{ kid: string; publicKey: string }> {
    return this.request<{ kid: string; publicKey: string }>('generateVAPID');
  }

  signJWT(kid: string, payload: unknown): Promise<{ jwt: string }> {
    return this.request<{ jwt: string }>('signJWT', { kid, payload });
  }

  getPublicKey(kid: string): Promise<{ publicKey: string | null }> {
    return this.request<{ publicKey: string | null }>('getPublicKey', { kid });
  }
}
