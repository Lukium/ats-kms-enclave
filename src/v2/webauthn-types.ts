/**
 * @file webauthn-types.ts
 * @description Type-safe interfaces and type guards for WebAuthn API results.
 *
 * The WebAuthn API returns `any` for extension results from
 * `credential.getClientExtensionResults()`, which bypasses TypeScript safety.
 * These utilities provide proper typing and runtime validation.
 */

/**
 * WebAuthn PRF extension result structure
 * See: https://w3c.github.io/webauthn/#prf-extension
 */
export interface PRFExtensionResults {
  enabled?: boolean;
  results?: {
    first: ArrayBuffer;
    second?: ArrayBuffer;
  };
}

/**
 * All extension results returned by getClientExtensionResults()
 */
export interface ClientExtensionResults {
  prf?: PRFExtensionResults;
  // Add other extensions as needed (e.g., credProps, largeBlob)
}

/**
 * Type guard for PRF extension results.
 * Validates structure at runtime to ensure safe access.
 *
 * @param value - Unknown value to validate
 * @returns true if value matches PRFExtensionResults structure
 *
 * @example
 * ```typescript
 * const extensions = credential.getClientExtensionResults();
 * if (isPRFResult(extensions.prf)) {
 *   const firstKey = extensions.prf.results?.first;
 * }
 * ```
 */
export function isPRFResult(value: unknown): value is PRFExtensionResults {
  if (typeof value !== 'object' || value === null) return false;
  const prf = value as Partial<PRFExtensionResults>;

  // enabled is optional boolean
  if ('enabled' in prf && typeof prf.enabled !== 'boolean') return false;

  // results is optional object with ArrayBuffer properties
  if ('results' in prf) {
    if (typeof prf.results !== 'object' || prf.results === null) return false;
    const results = prf.results as Record<string, unknown>;
    // Accept both ArrayBuffer and Uint8Array (Uint8Array is a view over ArrayBuffer)
    if ('first' in results && !(results.first instanceof ArrayBuffer) && !(results.first instanceof Uint8Array)) return false;
    if ('second' in results && !(results.second instanceof ArrayBuffer) && !(results.second instanceof Uint8Array)) return false;
  }

  return true;
}

/**
 * Safely extract PRF results from WebAuthn credential.
 * Returns undefined if PRF extension not present or invalid.
 *
 * @param credential - WebAuthn credential from navigator.credentials.create/get
 * @returns PRF extension results or undefined
 *
 * @example
 * ```typescript
 * const credential = await navigator.credentials.get(...);
 * const prfExt = getPRFResults(credential);
 * if (prfExt?.results) {
 *   const symmetricKey = prfExt.results.first;
 * }
 * ```
 */
export function getPRFResults(credential: PublicKeyCredential): PRFExtensionResults | undefined {
  const extensions = credential.getClientExtensionResults() as ClientExtensionResults;
  const prf = extensions.prf;

  if (!prf) return undefined;
  if (!isPRFResult(prf)) {
    console.warn('[WebAuthn] Invalid PRF extension result structure:', prf);
    return undefined;
  }

  return prf;
}

/**
 * Check if credential response has authenticator data.
 * Type guard for AuthenticatorAssertionResponse vs AuthenticatorAttestationResponse.
 *
 * @param response - Credential response
 * @returns true if response is AuthenticatorAssertionResponse with authenticatorData
 */
export function hasAuthenticatorData(
  response: AuthenticatorResponse
): response is AuthenticatorAssertionResponse {
  return 'authenticatorData' in response && response.authenticatorData instanceof ArrayBuffer;
}
