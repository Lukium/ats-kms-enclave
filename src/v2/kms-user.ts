/**
 * PWA facing API for the KMS V2
 *
 * This class exposes a friendly interface for the front‑end to
 * interact with the KMS. Methods return plain JavaScript objects and
 * wrap the underlying RPC mechanism. Each request is assigned a
 * random identifier which is echoed in the response. Errors from
 * the worker are surfaced as thrown exceptions.
 */

import type {
  AuthCredentials,
  UnlockOperationResult,
  RPCRequest,
  RPCResponse,
} from './types';
import { KMSClient } from './client';

function randomId(): string {
  return Math.random().toString(36).slice(2);
}

export class KMSUser {
  private client: KMSClient;
  constructor() {
    this.client = new KMSClient();
  }
  private async rpc(method: string, params: any): Promise<any> {
    const request: RPCRequest = { id: randomId(), method, params };
    const response: RPCResponse = await this.client.send(request);
    if (response.error) throw new Error(response.error);
    return response.result;
  }
  async setupPassphrase(passphrase: string): Promise<any> {
    return this.rpc('setupPassphrase', { passphrase });
  }
  async unlockWithPassphrase(passphrase: string): Promise<any> {
    return this.rpc('unlockWithPassphrase', { passphrase });
  }
  async generateVAPID(credentials: AuthCredentials): Promise<any> {
    return this.rpc('generateVAPID', { credentials });
  }
  async signJWT(kid: string, payload: any, credentials: AuthCredentials): Promise<{ jwt: string }> {
    return this.rpc('signJWT', { kid, payload, credentials });
  }
  async verifyAudit(): Promise<any> {
    return this.rpc('verifyAudit', {});
  }
  async getAuditPublicKey(): Promise<{ publicKey: string }> {
    return this.rpc('getAuditPublicKey', {});
  }
}
