/**
 * KMS Client - RPC Bridge (Phase 0 - Stub)
 *
 * This is a minimal stub to allow tests to compile.
 * Implementation will be written after tests are complete (TDD GREEN phase).
 */

export class KMSClient {
  // Stub implementation - tests will fail until we implement

  destroy(): void {
    throw new Error('Not implemented');
  }

  generateVAPID(): Promise<{ kid: string; publicKey: string }> {
    return Promise.reject(new Error('Not implemented'));
  }

  signJWT(_kid: string, _payload: unknown): Promise<{ jwt: string }> {
    return Promise.reject(new Error('Not implemented'));
  }

  getPublicKey(_kid: string): Promise<{ publicKey: string | null }> {
    return Promise.reject(new Error('Not implemented'));
  }
}
