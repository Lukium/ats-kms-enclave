/**
 * @file rpc-validation.ts
 * @description Runtime validation for RPC method parameters.
 *
 * The Worker receives parameters via postMessage with `any` typing.
 * These validators provide type-safe parameter extraction with runtime
 * validation at the RPC boundary, ensuring type safety before passing
 * to typed handler functions.
 */

import type { AuthCredentials, VAPIDPayload, StoredPushSubscription } from './types.js';

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
  ttlHours: number;
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('createLease', params);
  return {
    userId: validateString('createLease', 'userId', p.userId),
    ttlHours: validateNumber('createLease', 'ttlHours', p.ttlHours),
    credentials: validateAuthCredentials('createLease', p.credentials),
  };
}

export function validateIssueVAPIDJWT(params: unknown): {
  leaseId: string;
  kid?: string;
  jti?: string;
  exp?: number;
} {
  const p = validateParamsObject('issueVAPIDJWT', params);

  const kid = validateOptionalString('issueVAPIDJWT', 'kid', p.kid);
  const jti = validateOptionalString('issueVAPIDJWT', 'jti', p.jti);
  const exp = p.exp !== undefined ? validateNumber('issueVAPIDJWT', 'exp', p.exp) : undefined;

  return {
    leaseId: validateString('issueVAPIDJWT', 'leaseId', p.leaseId),
    ...(kid !== undefined && { kid }),
    ...(jti !== undefined && { jti }),
    ...(exp !== undefined && { exp }),
  };
}

export function validateIssueVAPIDJWTs(params: unknown): {
  leaseId: string;
  count: number;
  kid?: string;
} {
  const p = validateParamsObject('issueVAPIDJWTs', params);

  const kid = validateOptionalString('issueVAPIDJWTs', 'kid', p.kid);

  return {
    leaseId: validateString('issueVAPIDJWTs', 'leaseId', p.leaseId),
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

export function validateVerifyLease(params: unknown): {
  leaseId: string;
  deleteIfInvalid?: boolean;
} {
  const p = validateParamsObject('verifyLease', params);
  const result: { leaseId: string; deleteIfInvalid?: boolean } = {
    leaseId: validateString('verifyLease', 'leaseId', p.leaseId),
  };

  // Optional parameter
  if ('deleteIfInvalid' in p) {
    if (typeof p.deleteIfInvalid !== 'boolean') {
      throw new Error('verifyLease: deleteIfInvalid must be a boolean');
    }
    result.deleteIfInvalid = p.deleteIfInvalid;
  }

  return result;
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

// ============================================================================
// Push Notification Subscription Validation
// ============================================================================

/**
 * Known push service domains (whitelist)
 */
const KNOWN_PUSH_SERVICES = [
  'fcm.googleapis.com', // Google Firebase Cloud Messaging
  'web.push.apple.com', // Apple Push Notification Service
  'updates.push.services.mozilla.com', // Mozilla Push Service
  'notify.windows.com', // Windows Push Notification Service
];

/**
 * Validate push subscription object with security whitelist.
 *
 * Validates:
 * - endpoint is HTTPS
 * - endpoint is from a known push service (FCM, APNs, Mozilla, WNS)
 * - keys.p256dh and keys.auth are present and non-empty strings
 * - eid is a non-empty string
 * - createdAt is a valid timestamp
 * - expirationTime is number or null
 */
function validatePushSubscription(method: string, value: unknown): StoredPushSubscription {
  if (typeof value !== 'object' || value === null) {
    throw new RPCValidationError(method, 'subscription', 'object', value);
  }

  const sub = value as Record<string, unknown>;

  // Validate endpoint
  const endpoint = validateString(method, 'subscription.endpoint', sub.endpoint);

  // Require HTTPS
  if (!endpoint.startsWith('https://')) {
    throw new Error(`${method}: subscription.endpoint must use HTTPS`);
  }

  // Whitelist known push services
  let endpointUrl: URL;
  try {
    endpointUrl = new URL(endpoint);
  } catch {
    throw new Error(`${method}: subscription.endpoint is not a valid URL`);
  }

  const isKnownService = KNOWN_PUSH_SERVICES.some(
    (service) => endpointUrl.hostname === service || endpointUrl.hostname.endsWith(`.${service}`)
  );

  if (!isKnownService) {
    throw new Error(
      `${method}: subscription.endpoint must be from a known push service (FCM, APNs, Mozilla Push, WNS). Got: ${endpointUrl.hostname}`
    );
  }

  // Validate expirationTime (number or null)
  const expirationTime = sub.expirationTime;
  if (expirationTime !== null && typeof expirationTime !== 'number') {
    throw new RPCValidationError(method, 'subscription.expirationTime', 'number or null', expirationTime);
  }

  // Validate keys object
  if (typeof sub.keys !== 'object' || sub.keys === null) {
    throw new RPCValidationError(method, 'subscription.keys', 'object', sub.keys);
  }

  const keys = sub.keys as Record<string, unknown>;
  const p256dh = validateString(method, 'subscription.keys.p256dh', keys.p256dh);
  const auth = validateString(method, 'subscription.keys.auth', keys.auth);

  if (p256dh.length === 0) {
    throw new Error(`${method}: subscription.keys.p256dh must be non-empty`);
  }
  if (auth.length === 0) {
    throw new Error(`${method}: subscription.keys.auth must be non-empty`);
  }

  // Validate eid
  const eid = validateString(method, 'subscription.eid', sub.eid);
  if (eid.length === 0) {
    throw new Error(`${method}: subscription.eid must be non-empty`);
  }

  // Validate createdAt
  const createdAt = sub.createdAt;
  if (typeof createdAt !== 'number') {
    throw new RPCValidationError(method, 'subscription.createdAt', 'number', createdAt);
  }

  return {
    endpoint,
    expirationTime,
    keys: { p256dh, auth },
    eid,
    createdAt,
  };
}

export function validateSetPushSubscription(params: unknown): {
  subscription: StoredPushSubscription;
} {
  const p = validateParamsObject('setPushSubscription', params);
  return {
    subscription: validatePushSubscription('setPushSubscription', p.subscription),
  };
}

export function validateRemovePushSubscription(_params: unknown): Record<string, never> {
  // No params required
  return {};
}

export function validateGetPushSubscription(_params: unknown): Record<string, never> {
  // No params required
  return {};
}
