/**
 * Iframe client for the KMS V2
 *
 * In the browser the client would live inside a sandboxed iframe and
 * forward messages between the parent window and a dedicated worker.
 * For this simplified Node implementation the client calls the
 * worker directly via imported functions. The public API consists
 * solely of the `send` method which accepts an RPC request and
 * resolves with an RPC response.
 */

import type { RPCRequest, RPCResponse } from './types';
import { handleMessage } from './worker';

export class KMSClient {
  /**
   * Send an RPC request to the worker and return its response. In a
   * browser environment this would post a message to the worker;
   * here we call the handler directly.
   */
  async send(request: RPCRequest): Promise<RPCResponse> {
    return await handleMessage(request);
  }
}
