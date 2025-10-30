/**
 * @file rpc-validation.ts
 * @description Runtime validation for RPC method parameters.
 *
 * The Worker receives parameters via postMessage with `any` typing.
 * These validators provide type-safe parameter extraction with runtime
 * validation at the RPC boundary, ensuring type safety before passing
 * to typed handler functions.
 */

import type { AuthCredentials, VAPIDPayload } from './types.js';

/**
 * Custom error for RPC parameter validation failures.
 * Provides detailed context about what validation failed.
 */
export class RPCValidationError extends Error {
  constructor(
    public readonly method: string,
    public readonly param: string,
    public readonly expected: string,
    public readonly received: unknown
  ) {
    super(`RPC ${method}: Invalid ${param} - expected ${expected}, got ${typeof received}`);
    this.name = 'RPCValidationError';
  }
}

/**
 * Validate base params structure
 */
function validateParamsObject(method: string, params: unknown): Record<string, unknown> {
  if (typeof params !== 'object' || params === null) {
    throw new RPCValidationError(method, 'params', 'object', params);
  }
  return params as Record<string, unknown>;
}

/**
 * Validate string parameter
 */
function validateString(method: string, paramName: string, value: unknown): string {
  if (typeof value !== 'string') {
    throw new RPCValidationError(method, paramName, 'string', value);
  }
  return value;
}

/**
 * Validate optional string parameter
 */
function validateOptionalString(method: string, paramName: string, value: unknown): string | undefined {
  if (value === undefined) return undefined;
  return validateString(method, paramName, value);
}

/**
 * Validate number parameter
 */
function validateNumber(method: string, paramName: string, value: unknown): number {
  if (typeof value !== 'number') {
    throw new RPCValidationError(method, paramName, 'number', value);
  }
  return value;
}

/**
 * Validate ArrayBuffer parameter (convert Uint8Array to ArrayBuffer if needed)
 */
function validateBuffer(method: string, paramName: string, value: unknown): ArrayBuffer {
  if (value instanceof ArrayBuffer) {
    return value;
  }
  if (value instanceof Uint8Array) {
    // Ensure we return an ArrayBuffer, not SharedArrayBuffer
    const buffer = new ArrayBuffer(value.byteLength);
    new Uint8Array(buffer).set(value);
    return buffer;
  }
  throw new RPCValidationError(method, paramName, 'ArrayBuffer or Uint8Array', value);
}

/**
 * Validate optional buffer parameter (convert Uint8Array to ArrayBuffer if needed)
 */
function validateOptionalBuffer(
  method: string,
  paramName: string,
  value: unknown
): Uint8Array | undefined {
  if (value === undefined) return undefined;
  // For existingMS, handlers expect Uint8Array specifically
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  throw new RPCValidationError(method, paramName, 'ArrayBuffer or Uint8Array', value);
}

/**
 * Validate AuthCredentials discriminated union
 */
function validateAuthCredentials(method: string, credentials: unknown): AuthCredentials {
  if (typeof credentials !== 'object' || credentials === null) {
    throw new RPCValidationError(method, 'credentials', 'AuthCredentials object', credentials);
  }

  const creds = credentials as Record<string, unknown>;

  // Validate method discriminator
  if (typeof creds.method !== 'string') {
    throw new RPCValidationError(method, 'credentials.method', 'string', creds.method);
  }

  // Validate userId (present in all variants)
  if (typeof creds.userId !== 'string') {
    throw new RPCValidationError(method, 'credentials.userId', 'string', creds.userId);
  }

  // Validate variant-specific fields
  switch (creds.method) {
    case 'passphrase':
      if (typeof creds.passphrase !== 'string') {
        throw new RPCValidationError(method, 'credentials.passphrase', 'string', creds.passphrase);
      }
      return {
        method: 'passphrase',
        passphrase: creds.passphrase,
        userId: creds.userId,
      };

    case 'passkey-prf':
      if (!(creds.prfOutput instanceof ArrayBuffer)) {
        throw new RPCValidationError(method, 'credentials.prfOutput', 'ArrayBuffer', creds.prfOutput);
      }
      return {
        method: 'passkey-prf',
        prfOutput: creds.prfOutput,
        userId: creds.userId,
      };

    case 'passkey-gate':
      return {
        method: 'passkey-gate',
        userId: creds.userId,
      };

    default:
      throw new RPCValidationError(
        method,
        'credentials.method',
        'passphrase | passkey-prf | passkey-gate',
        creds.method
      );
  }
}

/**
 * Validate VAPID JWT payload
 */
function validateVAPIDPayload(method: string, payload: unknown): VAPIDPayload {
  if (typeof payload !== 'object' || payload === null) {
    throw new RPCValidationError(method, 'payload', 'VAPIDPayload object', payload);
  }

  const p = payload as Record<string, unknown>;

  return {
    aud: validateString(method, 'payload.aud', p.aud),
    sub: validateString(method, 'payload.sub', p.sub),
    exp: validateNumber(method, 'payload.exp', p.exp),
    jti: validateString(method, 'payload.jti', p.jti),
  };
}

/**
 * Validate array of subscription objects
 */
function validateSubscriptions(
  method: string,
  subs: unknown
): Array<{ url: string; aud: string; eid: string }> {
  if (!Array.isArray(subs)) {
    throw new RPCValidationError(method, 'subs', 'Array', subs);
  }

  return subs.map((sub, index) => {
    if (typeof sub !== 'object' || sub === null) {
      throw new RPCValidationError(method, `subs[${index}]`, 'object', sub);
    }

    const s = sub as Record<string, unknown>;
    return {
      url: validateString(method, `subs[${index}].url`, s.url),
      aud: validateString(method, `subs[${index}].aud`, s.aud),
      eid: validateString(method, `subs[${index}].eid`, s.eid),
    };
  });
}

// ============================================================================
// RPC Method Validators
// ============================================================================

export function validateSetupPassphrase(params: unknown): {
  userId: string;
  passphrase: string;
  existingMS?: Uint8Array;
} {
  const p = validateParamsObject('setupPassphrase', params);
  const existingMS = validateOptionalBuffer('setupPassphrase', 'existingMS', p.existingMS);
  return {
    userId: validateString('setupPassphrase', 'userId', p.userId),
    passphrase: validateString('setupPassphrase', 'passphrase', p.passphrase),
    ...(existingMS !== undefined && { existingMS }),
  };
}

export function validateSetupPasskeyPRF(params: unknown): {
  userId: string;
  credentialId: ArrayBuffer;
  prfOutput: ArrayBuffer;
  rpId?: string;
  existingMS?: Uint8Array;
} {
  const p = validateParamsObject('setupPasskeyPRF', params);

  // Check for credentialId presence first (match handler error message)
  if (!p.credentialId) {
    throw new Error('credentialId required');
  }

  const rpId = validateOptionalString('setupPasskeyPRF', 'rpId', p.rpId);
  const existingMS = validateOptionalBuffer('setupPasskeyPRF', 'existingMS', p.existingMS);

  return {
    userId: validateString('setupPasskeyPRF', 'userId', p.userId),
    credentialId: validateBuffer('setupPasskeyPRF', 'credentialId', p.credentialId),
    prfOutput: validateBuffer('setupPasskeyPRF', 'prfOutput', p.prfOutput),
    ...(rpId !== undefined && { rpId }),
    ...(existingMS !== undefined && { existingMS }),
  };
}

export function validateSetupPasskeyGate(params: unknown): {
  userId: string;
  credentialId: ArrayBuffer;
  rpId?: string;
  existingMS?: Uint8Array;
} {
  const p = validateParamsObject('setupPasskeyGate', params);
  const rpId = validateOptionalString('setupPasskeyGate', 'rpId', p.rpId);
  const existingMS = validateOptionalBuffer('setupPasskeyGate', 'existingMS', p.existingMS);
  return {
    userId: validateString('setupPasskeyGate', 'userId', p.userId),
    credentialId: validateBuffer('setupPasskeyGate', 'credentialId', p.credentialId),
    ...(rpId !== undefined && { rpId }),
    ...(existingMS !== undefined && { existingMS }),
  };
}

export function validateAddEnrollment(params: unknown): {
  userId: string;
  method: 'passphrase' | 'passkey-prf' | 'passkey-gate';
  credentials: AuthCredentials;
  newCredentials: unknown;
} {
  const p = validateParamsObject('addEnrollment', params);
  const method = validateString('addEnrollment', 'method', p.method);

  // Validate method is one of the allowed values
  if (method !== 'passphrase' && method !== 'passkey-prf' && method !== 'passkey-gate') {
    throw new RPCValidationError('addEnrollment', 'method', 'passphrase | passkey-prf | passkey-gate', method);
  }

  return {
    userId: validateString('addEnrollment', 'userId', p.userId),
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- Runtime validation above ensures this is safe
    method: method as 'passphrase' | 'passkey-prf' | 'passkey-gate',
    credentials: validateAuthCredentials('addEnrollment', p.credentials),
    newCredentials: p.newCredentials, // Pass through - discriminated union based on method
  };
}

export function validateGenerateVAPID(params: unknown): {
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('generateVAPID', params);
  return {
    credentials: validateAuthCredentials('generateVAPID', p.credentials),
  };
}

export function validateRegenerateVAPID(params: unknown): {
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('regenerateVAPID', params);
  return {
    credentials: validateAuthCredentials('regenerateVAPID', p.credentials),
  };
}

export function validateSignJWT(params: unknown): {
  kid: string;
  payload: VAPIDPayload;
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('signJWT', params);
  return {
    kid: validateString('signJWT', 'kid', p.kid),
    payload: validateVAPIDPayload('signJWT', p.payload),
    credentials: validateAuthCredentials('signJWT', p.credentials),
  };
}

export function validateCreateLease(params: unknown): {
  userId: string;
  subs: Array<{ url: string; aud: string; eid: string }>;
  ttlHours: number;
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('createLease', params);
  return {
    userId: validateString('createLease', 'userId', p.userId),
    subs: validateSubscriptions('createLease', p.subs),
    ttlHours: validateNumber('createLease', 'ttlHours', p.ttlHours),
    credentials: validateAuthCredentials('createLease', p.credentials),
  };
}

export function validateIssueVAPIDJWT(params: unknown): {
  leaseId: string;
  endpoint: { url: string; aud: string; eid: string };
  kid?: string;
  jti?: string;
  exp?: number;
} {
  const p = validateParamsObject('issueVAPIDJWT', params);

  // Validate endpoint object
  if (typeof p.endpoint !== 'object' || p.endpoint === null) {
    throw new RPCValidationError('issueVAPIDJWT', 'endpoint', 'object', p.endpoint);
  }
  const endpoint = p.endpoint as Record<string, unknown>;

  const kid = validateOptionalString('issueVAPIDJWT', 'kid', p.kid);
  const jti = validateOptionalString('issueVAPIDJWT', 'jti', p.jti);
  const exp = p.exp !== undefined ? validateNumber('issueVAPIDJWT', 'exp', p.exp) : undefined;

  return {
    leaseId: validateString('issueVAPIDJWT', 'leaseId', p.leaseId),
    endpoint: {
      url: validateString('issueVAPIDJWT', 'endpoint.url', endpoint.url),
      aud: validateString('issueVAPIDJWT', 'endpoint.aud', endpoint.aud),
      eid: validateString('issueVAPIDJWT', 'endpoint.eid', endpoint.eid),
    },
    ...(kid !== undefined && { kid }),
    ...(jti !== undefined && { jti }),
    ...(exp !== undefined && { exp }),
  };
}

export function validateIssueVAPIDJWTs(params: unknown): {
  leaseId: string;
  endpoint: { url: string; aud: string; eid: string };
  count: number;
  kid?: string;
} {
  const p = validateParamsObject('issueVAPIDJWTs', params);

  // Validate endpoint object
  if (typeof p.endpoint !== 'object' || p.endpoint === null) {
    throw new RPCValidationError('issueVAPIDJWTs', 'endpoint', 'object', p.endpoint);
  }
  const endpoint = p.endpoint as Record<string, unknown>;

  const kid = validateOptionalString('issueVAPIDJWTs', 'kid', p.kid);

  return {
    leaseId: validateString('issueVAPIDJWTs', 'leaseId', p.leaseId),
    endpoint: {
      url: validateString('issueVAPIDJWTs', 'endpoint.url', endpoint.url),
      aud: validateString('issueVAPIDJWTs', 'endpoint.aud', endpoint.aud),
      eid: validateString('issueVAPIDJWTs', 'endpoint.eid', endpoint.eid),
    },
    count: validateNumber('issueVAPIDJWTs', 'count', p.count),
    ...(kid !== undefined && { kid }),
  };
}

export function validateIsSetup(params: unknown): { userId?: string } {
  // isSetup takes optional params
  if (params === undefined || params === null) {
    return {};
  }
  const p = validateParamsObject('isSetup', params);
  const userId = validateOptionalString('isSetup', 'userId', p.userId);
  return userId !== undefined ? { userId } : {};
}

export function validateGetEnrollments(params: unknown): { userId?: string } {
  // getEnrollments takes optional params
  if (params === undefined || params === null) {
    return {};
  }
  const p = validateParamsObject('getEnrollments', params);
  const userId = validateOptionalString('getEnrollments', 'userId', p.userId);
  return userId !== undefined ? { userId } : {};
}

export function validateVerifyAuditChain(_params: unknown): Record<string, never> {
  // No params required
  return {};
}

export function validateGetAuditLog(_params: unknown): Record<string, never> {
  // No params required
  return {};
}

export function validateGetPublicKey(params: unknown): { kid: string } {
  const p = validateParamsObject('getPublicKey', params);
  return {
    kid: validateString('getPublicKey', 'kid', p.kid),
  };
}

export function validateGetAuditPublicKey(_params: unknown): Record<string, never> {
  // No params required
  return {};
}

export function validateGetUserLeases(params: unknown): { userId: string } {
  const p = validateParamsObject('getUserLeases', params);
  return {
    userId: validateString('getUserLeases', 'userId', p.userId),
  };
}

export function validateVerifyLease(params: unknown): { leaseId: string } {
  const p = validateParamsObject('verifyLease', params);
  return {
    leaseId: validateString('verifyLease', 'leaseId', p.leaseId),
  };
}

export function validateGetVAPIDKid(_params: unknown): Record<string, never> {
  // No params required
  return {};
}

export function validateResetKMS(_params: unknown): Record<string, never> {
  // No params required
  return {};
}

export function validateRemoveEnrollment(params: unknown): {
  enrollmentId: string;
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('removeEnrollment', params);
  return {
    enrollmentId: validateString('removeEnrollment', 'enrollmentId', p.enrollmentId),
    credentials: validateAuthCredentials('removeEnrollment', p.credentials),
  };
}
