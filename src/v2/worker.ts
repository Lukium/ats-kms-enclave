/**
 * KMS worker orchestrator
 *
 * The worker sits at the heart of the KMS and exposes an RPC
 * interface used by the iframe client. It routes incoming requests
 * to the appropriate module (unlock, audit, storage, crypto) and
 * ensures that sensitive operations are executed within a properly
 * unlocked context. For brevity this implementation supports only a
 * subset of methods and stubs out VAPID functionality.
 */

import type { RPCRequest, RPCResponse, AuthCredentials } from './types';
import {
  setupPassphrase,
  unlockWithPassphrase,
  withUnlock,
} from './unlock';
import { logOperation, verifyAuditChain, getAuditPublicKey } from './audit';
import { wrapKey, unwrapKey, getWrappedKey } from './storage';

// In-memory counter for generating simplistic key identifiers
let vapidCounter = 0;

/**
 * Handle a single RPC request. Dispatches to the corresponding
 * internal method based on the `method` property. All handlers are
 * asynchronous and return a promise resolving to a response object.
 */
export async function handleMessage(request: RPCRequest): Promise<RPCResponse> {
  const { id, method, params } = request;
  try {
    let result: any;
    switch (method) {
      case 'setupPassphrase': {
        const { passphrase } = params;
        result = await setupPassphrase(passphrase);
        await logOperation({ op: 'setupPassphrase', kid: '', requestId: id });
        break;
      }
      case 'unlockWithPassphrase': {
        const { passphrase } = params;
        result = await unlockWithPassphrase(passphrase);
        await logOperation({ op: 'unlockWithPassphrase', kid: '', requestId: id });
        break;
      }
      case 'generateVAPID': {
        const { credentials } = params;
        // Stub implementation: create new dummy key pair if none exists
        result = await withUnlock(credentials as AuthCredentials, async () => {
          const kid = `vapid-${++vapidCounter}`;
          const existing = await getWrappedKey(kid);
          if (!existing) {
            // Generate ECDSA P-256 key pair
            const keyPair = await crypto.subtle.generateKey(
              { name: 'ECDSA', namedCurve: 'P-256' },
              true,
              ['sign', 'verify']
            );
            // Store wrapped private key (for demonstration we wrap the private key under itself)
            await wrapKey(keyPair.privateKey, keyPair.privateKey, kid, 'ECDSA', ['sign'], { alg: 'ECDSA', purpose: 'vapid' });
            const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
            return { kid, publicKey: Buffer.from(publicKey).toString('base64') };
          } else {
            return { kid, publicKey: existing.publicKeyRaw ? Buffer.from(existing.publicKeyRaw).toString('base64') : '' };
          }
        });
        await logOperation({ op: 'generateVAPID', kid: result.result.kid, requestId: id });
        break;
      }
      case 'signJWT': {
        // Stub: return dummy JWT
        const { kid, payload, credentials } = params;
        const jwt = await withUnlock(credentials as AuthCredentials, async () => {
          // In a real implementation we would unwrap the private key and sign
          return 'eyJhbGciOiJFUzI1NiJ9.' + Buffer.from(JSON.stringify(payload)).toString('base64') + '.signature';
        });
        await logOperation({ op: 'signJWT', kid, requestId: id });
        result = { jwt: jwt.result };
        break;
      }
      case 'verifyAudit': {
        result = await verifyAuditChain();
        break;
      }
      case 'getAuditPublicKey': {
        result = await getAuditPublicKey();
        break;
      }
      default:
        throw new Error(`Unknown method: ${method}`);
    }
    return { id, result };
  } catch (err: any) {
    return { id, error: err.message ?? String(err) };
  }
}
