/**
 * Vitest Setup File
 *
 * Provides polyfills and mocks for test environment
 */

import { handleMessage } from '@/worker';

// Mock Worker for testing in happy-dom environment
if (typeof Worker === 'undefined') {
  class WorkerMock extends EventTarget {
    public onmessage: ((event: MessageEvent) => void) | null = null;
    public onerror: ((event: ErrorEvent) => void) | null = null;
    private isTerminated = false;

    constructor(_url: URL | string, _options?: WorkerOptions) {
      super();
    }

    postMessage(data: unknown): void {
      if (this.isTerminated) {
        throw new Error('Worker has been terminated');
      }

      // Process message asynchronously to simulate real Worker behavior
      setTimeout(() => {
        if (this.isTerminated) {
          return;
        }

        // Call handleMessage directly (unit test approach)
        handleMessage(data as never)
          .then((response) => {
            if (this.isTerminated) {
              return;
            }

            const messageEvent = new MessageEvent('message', { data: response });

            if (this.onmessage) {
              this.onmessage(messageEvent);
            }
            this.dispatchEvent(messageEvent);
          })
          .catch((error: Error) => {
            if (this.isTerminated) {
              return;
            }

            const errorEvent = new ErrorEvent('error', {
              error,
              message: error.message,
            });

            if (this.onerror) {
              this.onerror(errorEvent);
            }
            this.dispatchEvent(errorEvent);
          });
      }, 0);
    }

    terminate(): void {
      this.isTerminated = true;
      this.onmessage = null;
      this.onerror = null;
    }
  }

  // Install mock
  globalThis.Worker = WorkerMock as unknown as typeof Worker;
}
