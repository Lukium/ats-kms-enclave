/**
 * @file rpc-validation.ts
 * @description Runtime validation for RPC method parameters.
 *
 * The Worker receives parameters via postMessage with `any` typing.
 * These validators provide type-safe parameter extraction with runtime
 * validation at the RPC boundary, ensuring type safety before passing
 * to typed handler functions.
 */

import type {
  AuthCredentials,
  VAPIDPayload,
  StoredPushSubscription,
  WrappedAccountRoot,
} from './types.js';

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
 * Validate boolean parameter
 */
function validateBoolean(method: string, paramName: string, value: unknown): boolean {
  if (typeof value !== 'boolean') {
    throw new RPCValidationError(method, paramName, 'boolean', value);
  }
  return value;
}

/**
 * Validate optional boolean parameter
 */
function validateOptionalBoolean(method: string, paramName: string, value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  return validateBoolean(method, paramName, value);
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

// Legacy validator removed: validateSetupWithEncryptedCredentials
// This is now an internal function used only by setupWithPopup

export function validateSetupWithPopup(params: unknown): {
  userId: string;
} {
  const p = validateParamsObject('setupWithPopup', params);

  return {
    userId: validateString('setupWithPopup', 'userId', p.userId),
  };
}

/**
 * Validate fullSetup parameters
 */
export function validateFullSetup(params: unknown): {
  userId: string;
  autoExtend?: boolean;
  ttlHours?: number;
} {
  const p = validateParamsObject('fullSetup', params);

  const userId = validateString('fullSetup', 'userId', p.userId);

  // Build result object, only including optional fields if they were provided
  const result: { userId: string; autoExtend?: boolean; ttlHours?: number } = { userId };

  // autoExtend is optional, defaults to true
  if (p.autoExtend !== undefined) {
    if (typeof p.autoExtend !== 'boolean') {
      throw new RPCValidationError('fullSetup', 'autoExtend', 'boolean', typeof p.autoExtend);
    }
    result.autoExtend = p.autoExtend;
  }

  // ttlHours is optional, defaults to 12
  if (p.ttlHours !== undefined) {
    const ttlHours = validateNumber('fullSetup', 'ttlHours', p.ttlHours);
    if (ttlHours <= 0 || ttlHours > 720) {
      throw new RPCValidationError('fullSetup', 'ttlHours', '0 < ttlHours <= 720', ttlHours);
    }
    result.ttlHours = ttlHours;
  }

  return result;
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
  credentials: AuthCredentials;
} {
  const p = validateParamsObject('addEnrollment', params);

  return {
    userId: validateString('addEnrollment', 'userId', p.userId),
    credentials: validateAuthCredentials('addEnrollment', p.credentials),
  };
}

export function validateAddEnrollmentWithPopup(params: unknown): {
  userId: string;
} {
  const p = validateParamsObject('addEnrollmentWithPopup', params);

  return {
    userId: validateString('addEnrollmentWithPopup', 'userId', p.userId),
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
  autoExtend?: boolean;
} {
  const p = validateParamsObject('createLease', params);
  const result: {
    userId: string;
    ttlHours: number;
    credentials: AuthCredentials;
    autoExtend?: boolean;
  } = {
    userId: validateString('createLease', 'userId', p.userId),
    ttlHours: validateNumber('createLease', 'ttlHours', p.ttlHours),
    credentials: validateAuthCredentials('createLease', p.credentials),
  };

  const autoExtend = validateOptionalBoolean('createLease', 'autoExtend', p.autoExtend);
  if (autoExtend !== undefined) {
    result.autoExtend = autoExtend;
  }

  return result;
}

export function validateExtendLeases(params: unknown): {
  leaseIds: string[];
  userId: string;
  requestAuth?: boolean;
  credentials?: AuthCredentials;
} {
  const p = validateParamsObject('extendLeases', params);

  // Validate leaseIds array
  if (!Array.isArray(p.leaseIds)) {
    throw new Error(`RPC extendLeases: Invalid leaseIds - expected array, got ${typeof p.leaseIds}`);
  }
  if (p.leaseIds.length === 0) {
    throw new Error(`RPC extendLeases: leaseIds array cannot be empty`);
  }
  const leaseIds = p.leaseIds.map((id: unknown, index: number) => {
    if (typeof id !== 'string' || id.length === 0) {
      throw new Error(`RPC extendLeases: Invalid leaseId at index ${index} - expected non-empty string`);
    }
    return id;
  });

  const result: {
    leaseIds: string[];
    userId: string;
    requestAuth?: boolean;
    credentials?: AuthCredentials;
  } = {
    leaseIds,
    userId: validateString('extendLeases', 'userId', p.userId),
  };

  // requestAuth is optional boolean
  const requestAuth = validateOptionalBoolean('extendLeases', 'requestAuth', p.requestAuth);
  if (requestAuth !== undefined) {
    result.requestAuth = requestAuth;
  }

  // credentials are optional (provided by client after auth modal)
  if (p.credentials !== undefined) {
    result.credentials = validateAuthCredentials('extendLeases', p.credentials);
  }

  return result;
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

export function validateGetPasskeyUnlockParams(params: unknown): { userId?: string } {
  // getPasskeyUnlockParams takes an optional userId (defaults to 'default')
  if (params === undefined || params === null) {
    return {};
  }
  const p = validateParamsObject('getPasskeyUnlockParams', params);
  const userId = validateOptionalString('getPasskeyUnlockParams', 'userId', p.userId);
  return userId !== undefined ? { userId } : {};
}

export function validateGetMessagingUnlockOptions(params: unknown): { userId?: string } {
  // getMessagingUnlockOptions takes an optional userId (defaults to 'default')
  if (params === undefined || params === null) {
    return {};
  }
  const p = validateParamsObject('getMessagingUnlockOptions', params);
  const userId = validateOptionalString('getMessagingUnlockOptions', 'userId', p.userId);
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

// ============================================================================
// Signal Messaging Validation (Phase 2)
// ============================================================================

/** Upper bounds for messaging inputs (reject oversized payloads at the boundary). */
const MAX_PLAINTEXT_BYTES = 64 * 1024; // 64 KiB cleartext per message
const MAX_PEER_NAME_CHARS = 256;
const MAX_ONETIME_PREKEY_COUNT = 100;
/** Signal key ids live in the 24-bit medium-id space (1..0xFFFFFF). */
const MAX_KEY_ID = 0xffffff;

/** Validate a Signal key id: an integer in [1, 0xFFFFFF]. */
function validateKeyId(method: string, paramName: string, value: unknown): number {
  const n = validateNumber(method, paramName, value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_KEY_ID) {
    throw new RPCValidationError(method, paramName, `integer in [1, ${MAX_KEY_ID}]`, value);
  }
  return n;
}

/** Validate a bounded-length string. */
function validateBoundedString(
  method: string,
  paramName: string,
  value: unknown,
  maxChars: number
): string {
  const s = validateString(method, paramName, value);
  if (s.length === 0 || s.length > maxChars) {
    throw new RPCValidationError(method, paramName, `non-empty string ≤ ${maxChars} chars`, value);
  }
  return s;
}

/** Validate an ArrayBuffer of an exact byte length. */
function validateBufferOfLength(
  method: string,
  paramName: string,
  value: unknown,
  expectedBytes: number
): ArrayBuffer {
  const buf = validateBuffer(method, paramName, value);
  if (buf.byteLength !== expectedBytes) {
    throw new RPCValidationError(method, paramName, `ArrayBuffer of ${expectedBytes} bytes`, value);
  }
  return buf;
}

/**
 * A peer's public prekey bundle, shaped to the fork's `DeviceType`. The `preKey`
 * (one-time prekey) is optional: X3DH proceeds with the signed prekey alone when
 * the directory has no unconsumed one-time prekey left.
 */
export interface MessagingDeviceBundle {
  registrationId: number;
  identityKey: ArrayBuffer;
  identitySigningKey: ArrayBuffer;
  signedPreKey: { keyId: number; publicKey: ArrayBuffer; signature: ArrayBuffer };
  preKey?: { keyId: number; publicKey: ArrayBuffer };
}

/** Validate a peer device bundle (public bytes only) used to start a session. */
function validateDeviceBundle(method: string, value: unknown): MessagingDeviceBundle {
  if (typeof value !== 'object' || value === null) {
    throw new RPCValidationError(method, 'deviceBundle', 'object', value);
  }
  const d = value as Record<string, unknown>;

  const signed = d.signedPreKey;
  if (typeof signed !== 'object' || signed === null) {
    throw new RPCValidationError(method, 'deviceBundle.signedPreKey', 'object', signed);
  }
  const sp = signed as Record<string, unknown>;

  const bundle: MessagingDeviceBundle = {
    registrationId: validateNumber(method, 'deviceBundle.registrationId', d.registrationId),
    identityKey: validateBufferOfLength(method, 'deviceBundle.identityKey', d.identityKey, 33),
    identitySigningKey: validateBufferOfLength(
      method,
      'deviceBundle.identitySigningKey',
      d.identitySigningKey,
      32
    ),
    signedPreKey: {
      keyId: validateKeyId(method, 'deviceBundle.signedPreKey.keyId', sp.keyId),
      publicKey: validateBufferOfLength(method, 'deviceBundle.signedPreKey.publicKey', sp.publicKey, 33),
      signature: validateBufferOfLength(method, 'deviceBundle.signedPreKey.signature', sp.signature, 64),
    },
  };

  if (d.preKey !== undefined) {
    if (typeof d.preKey !== 'object' || d.preKey === null) {
      throw new RPCValidationError(method, 'deviceBundle.preKey', 'object', d.preKey);
    }
    const pk = d.preKey as Record<string, unknown>;
    bundle.preKey = {
      keyId: validateKeyId(method, 'deviceBundle.preKey.keyId', pk.keyId),
      publicKey: validateBufferOfLength(method, 'deviceBundle.preKey.publicKey', pk.publicKey, 33),
    };
  }

  return bundle;
}

export function validateSetupMessaging(params: unknown): {
  credentials: AuthCredentials;
  signedPreKeyId: number;
  oneTimePrekeyCount: number;
} {
  const p = validateParamsObject('setupMessaging', params);
  const credentials = validateAuthCredentials('setupMessaging', p.credentials);
  const signedPreKeyId =
    p.signedPreKeyId === undefined ? 1 : validateKeyId('setupMessaging', 'signedPreKeyId', p.signedPreKeyId);
  let oneTimePrekeyCount = 20;
  if (p.oneTimePrekeyCount !== undefined) {
    oneTimePrekeyCount = validateNumber('setupMessaging', 'oneTimePrekeyCount', p.oneTimePrekeyCount);
    if (
      !Number.isInteger(oneTimePrekeyCount) ||
      oneTimePrekeyCount < 1 ||
      oneTimePrekeyCount > MAX_ONETIME_PREKEY_COUNT
    ) {
      throw new RPCValidationError(
        'setupMessaging',
        'oneTimePrekeyCount',
        `integer in [1, ${MAX_ONETIME_PREKEY_COUNT}]`,
        p.oneTimePrekeyCount
      );
    }
  }
  return { credentials, signedPreKeyId, oneTimePrekeyCount };
}

export function validateProvisionMessaging(params: unknown): {
  credentials: AuthCredentials;
  signedPreKeyId: number;
  oneTimePrekeyCount: number;
} {
  const p = validateParamsObject('provisionMessaging', params);
  const credentials = validateAuthCredentials('provisionMessaging', p.credentials);
  const signedPreKeyId =
    p.signedPreKeyId === undefined
      ? 1
      : validateKeyId('provisionMessaging', 'signedPreKeyId', p.signedPreKeyId);
  let oneTimePrekeyCount = 20;
  if (p.oneTimePrekeyCount !== undefined) {
    oneTimePrekeyCount = validateNumber('provisionMessaging', 'oneTimePrekeyCount', p.oneTimePrekeyCount);
    if (
      !Number.isInteger(oneTimePrekeyCount) ||
      oneTimePrekeyCount < 1 ||
      oneTimePrekeyCount > MAX_ONETIME_PREKEY_COUNT
    ) {
      throw new RPCValidationError(
        'provisionMessaging',
        'oneTimePrekeyCount',
        `integer in [1, ${MAX_ONETIME_PREKEY_COUNT}]`,
        p.oneTimePrekeyCount
      );
    }
  }
  return { credentials, signedPreKeyId, oneTimePrekeyCount };
}

export function validateGetMessagingBundle(params: unknown): { userId: string } {
  const p = validateParamsObject('getMessagingBundle', params);
  return { userId: validateString('getMessagingBundle', 'userId', p.userId) };
}

export function validateGetPrekeyCount(params: unknown): { userId: string } {
  const p = validateParamsObject('getPrekeyCount', params);
  return { userId: validateString('getPrekeyCount', 'userId', p.userId) };
}

export function validateOpenMessaging(params: unknown): { credentials: AuthCredentials } {
  const p = validateParamsObject('openMessaging', params);
  return { credentials: validateAuthCredentials('openMessaging', p.credentials) };
}

export function validateCloseMessaging(params: unknown): { sid: string; token: string } {
  const p = validateParamsObject('closeMessaging', params);
  return {
    sid: validateString('closeMessaging', 'sid', p.sid),
    token: validateString('closeMessaging', 'token', p.token),
  };
}

export function validateRotatePrekeys(params: unknown): {
  sid: string;
  token: string;
  signedPreKeyId: number;
  startKeyId: number;
  count: number;
} {
  const p = validateParamsObject('rotatePrekeys', params);
  const count = validateNumber('rotatePrekeys', 'count', p.count);
  if (!Number.isInteger(count) || count < 1 || count > MAX_ONETIME_PREKEY_COUNT) {
    throw new RPCValidationError(
      'rotatePrekeys',
      'count',
      `integer in [1, ${MAX_ONETIME_PREKEY_COUNT}]`,
      p.count
    );
  }
  return {
    sid: validateString('rotatePrekeys', 'sid', p.sid),
    token: validateString('rotatePrekeys', 'token', p.token),
    signedPreKeyId: validateKeyId('rotatePrekeys', 'signedPreKeyId', p.signedPreKeyId),
    startKeyId: validateKeyId('rotatePrekeys', 'startKeyId', p.startKeyId),
    count,
  };
}

// === Fan-out Bundle Operations (secure-messaging §8/§12) ===

/** Max devices in one logical message's fan-out (a contact's devices + own devices). */
const MAX_FANOUT_RECIPIENTS = 64;
/** Max serialized bundle size (guards openBundle's parse against hostile input). */
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;

function validateRecipientAddress(
  method: string,
  value: unknown
): { peerName: string; peerDeviceId: number } {
  const r = validateParamsObject(method, value);
  return {
    peerName: validateBoundedString(method, 'peerName', r.peerName, MAX_PEER_NAME_CHARS),
    peerDeviceId: r.peerDeviceId === undefined ? 1 : validateNumber(method, 'peerDeviceId', r.peerDeviceId),
  };
}

export function validateBuildBundle(params: unknown): {
  sid: string;
  token: string;
  recipients: Array<{ peerName: string; peerDeviceId: number; deviceBundle?: MessagingDeviceBundle }>;
  plaintext: ArrayBuffer;
} {
  const p = validateParamsObject('buildBundle', params);
  const plaintext = validateBuffer('buildBundle', 'plaintext', p.plaintext);
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new RPCValidationError(
      'buildBundle',
      'plaintext',
      `non-empty ArrayBuffer ≤ ${MAX_PLAINTEXT_BYTES} bytes`,
      p.plaintext
    );
  }
  if (!Array.isArray(p.recipients) || p.recipients.length < 1 || p.recipients.length > MAX_FANOUT_RECIPIENTS) {
    throw new RPCValidationError(
      'buildBundle',
      'recipients',
      `array of 1..${MAX_FANOUT_RECIPIENTS}`,
      p.recipients
    );
  }
  const recipients = p.recipients.map((raw) => {
    const addr = validateRecipientAddress('buildBundle', raw);
    const obj = validateParamsObject('buildBundle', raw);
    if (obj.deviceBundle === undefined) {
      return addr;
    }
    return { ...addr, deviceBundle: validateDeviceBundle('buildBundle', obj.deviceBundle) };
  });
  return {
    sid: validateString('buildBundle', 'sid', p.sid),
    token: validateString('buildBundle', 'token', p.token),
    recipients,
    plaintext,
  };
}

export function validateOpenBundle(params: unknown): {
  sid: string;
  token: string;
  senders: Array<{ peerName: string; peerDeviceId: number }>;
  bundle: ArrayBuffer;
} {
  const p = validateParamsObject('openBundle', params);
  const bundle = validateBuffer('openBundle', 'bundle', p.bundle);
  if (bundle.byteLength === 0 || bundle.byteLength > MAX_BUNDLE_BYTES) {
    throw new RPCValidationError(
      'openBundle',
      'bundle',
      `non-empty ArrayBuffer ≤ ${MAX_BUNDLE_BYTES} bytes`,
      p.bundle
    );
  }
  if (!Array.isArray(p.senders) || p.senders.length < 1 || p.senders.length > MAX_FANOUT_RECIPIENTS) {
    throw new RPCValidationError(
      'openBundle',
      'senders',
      `array of 1..${MAX_FANOUT_RECIPIENTS}`,
      p.senders
    );
  }
  const senders = p.senders.map((raw) => validateRecipientAddress('openBundle', raw));
  return {
    sid: validateString('openBundle', 'sid', p.sid),
    token: validateString('openBundle', 'token', p.token),
    senders,
    bundle,
  };
}

// === Account Root Operations (secure-messaging §18) ===

/** Max recovery-phrase length in chars (24 words × ~9 chars + spaces, padded). */
const MAX_MNEMONIC_CHARS = 512;

export function validateSetupAccountRoot(params: unknown): { credentials: AuthCredentials } {
  const p = validateParamsObject('setupAccountRoot', params);
  return { credentials: validateAuthCredentials('setupAccountRoot', p.credentials) };
}

export function validateImportAccountRootFromMnemonic(params: unknown): {
  credentials: AuthCredentials;
  mnemonic: string;
} {
  const p = validateParamsObject('importAccountRootFromMnemonic', params);
  return {
    credentials: validateAuthCredentials('importAccountRootFromMnemonic', p.credentials),
    mnemonic: validateBoundedString(
      'importAccountRootFromMnemonic',
      'mnemonic',
      p.mnemonic,
      MAX_MNEMONIC_CHARS
    ),
  };
}

export function validateImportWrappedAccountRoot(params: unknown): {
  credentials: AuthCredentials;
  wrapped: WrappedAccountRoot;
} {
  const p = validateParamsObject('importWrappedAccountRoot', params);
  const w = validateParamsObject('importWrappedAccountRoot', p.wrapped);
  return {
    credentials: validateAuthCredentials('importWrappedAccountRoot', p.credentials),
    wrapped: {
      ephemeralPubKey: validateBufferOfLength(
        'importWrappedAccountRoot',
        'wrapped.ephemeralPubKey',
        w.ephemeralPubKey,
        32
      ),
      iv: validateBufferOfLength('importWrappedAccountRoot', 'wrapped.iv', w.iv, 12),
      ciphertext: validateBufferOfLength(
        'importWrappedAccountRoot',
        'wrapped.ciphertext',
        w.ciphertext,
        32
      ),
    },
  };
}

export function validateWrapAccountRootForDevice(params: unknown): {
  credentials: AuthCredentials;
  recipientIdentityPubKey: ArrayBuffer;
} {
  const p = validateParamsObject('wrapAccountRootForDevice', params);
  const pub = validateBuffer('wrapAccountRootForDevice', 'recipientIdentityPubKey', p.recipientIdentityPubKey);
  if (pub.byteLength !== 32 && pub.byteLength !== 33) {
    throw new RPCValidationError(
      'wrapAccountRootForDevice',
      'recipientIdentityPubKey',
      'ArrayBuffer of 32 or 33 bytes',
      p.recipientIdentityPubKey
    );
  }
  return {
    credentials: validateAuthCredentials('wrapAccountRootForDevice', p.credentials),
    recipientIdentityPubKey: pub,
  };
}

export function validateHasAccountRoot(params: unknown): { userId: string } {
  const p = validateParamsObject('hasAccountRoot', params);
  return { userId: validateString('hasAccountRoot', 'userId', p.userId) };
}

// === Self-channel Operations (secure-messaging §18.2) ===

/** Max self-channel plaintext (announcements are tiny; snapshots are a contact list). */
const MAX_SELF_PAYLOAD_BYTES = 256 * 1024;
/** Self-channel ciphertext bound (payload + 12-byte IV + 16-byte GCM tag, padded). */
const MAX_SELF_CIPHERTEXT_BYTES = MAX_SELF_PAYLOAD_BYTES + 64;
/** Max self-channel context-label length. */
const MAX_SELF_CONTEXT_CHARS = 64;

function validateSelfContext(method: string, value: unknown): string {
  if (value === undefined) {
    return 'announcement';
  }
  return validateBoundedString(method, 'context', value, MAX_SELF_CONTEXT_CHARS);
}

export function validateGetSelfScope(params: unknown): { sid: string; token: string } {
  const p = validateParamsObject('getSelfScope', params);
  return {
    sid: validateString('getSelfScope', 'sid', p.sid),
    token: validateString('getSelfScope', 'token', p.token),
  };
}

export function validateSealSelfMessage(params: unknown): {
  sid: string;
  token: string;
  payload: ArrayBuffer;
  context: string;
} {
  const p = validateParamsObject('sealSelfMessage', params);
  const payload = validateBuffer('sealSelfMessage', 'payload', p.payload);
  if (payload.byteLength === 0 || payload.byteLength > MAX_SELF_PAYLOAD_BYTES) {
    throw new RPCValidationError(
      'sealSelfMessage',
      'payload',
      `non-empty ArrayBuffer ≤ ${MAX_SELF_PAYLOAD_BYTES} bytes`,
      p.payload
    );
  }
  return {
    sid: validateString('sealSelfMessage', 'sid', p.sid),
    token: validateString('sealSelfMessage', 'token', p.token),
    payload,
    context: validateSelfContext('sealSelfMessage', p.context),
  };
}

export function validateOpenSelfMessage(params: unknown): {
  sid: string;
  token: string;
  ciphertext: ArrayBuffer;
  context: string;
} {
  const p = validateParamsObject('openSelfMessage', params);
  const ciphertext = validateBuffer('openSelfMessage', 'ciphertext', p.ciphertext);
  if (ciphertext.byteLength === 0 || ciphertext.byteLength > MAX_SELF_CIPHERTEXT_BYTES) {
    throw new RPCValidationError(
      'openSelfMessage',
      'ciphertext',
      `non-empty ArrayBuffer ≤ ${MAX_SELF_CIPHERTEXT_BYTES} bytes`,
      p.ciphertext
    );
  }
  return {
    sid: validateString('openSelfMessage', 'sid', p.sid),
    token: validateString('openSelfMessage', 'token', p.token),
    ciphertext,
    context: validateSelfContext('openSelfMessage', p.context),
  };
}

// === Pairing / Contact Operations (secure-messaging §5/§6) ===

/** Max pairing-secret bytes (QR high-entropy ~32; word-pair bytes; padded). */
const MAX_CONTACT_SECRET_BYTES = 1024;
/** Max device-exchange payload (a device bundle: identity + prekeys + OTK pool). */
const MAX_DEVICE_EXCHANGE_BYTES = 256 * 1024;

function validatePeerUserId(method: string, value: unknown): string {
  return validateBoundedString(method, 'peerUserId', value, MAX_PEER_NAME_CHARS);
}

export function validateSetContactSecret(params: unknown): {
  sid: string;
  token: string;
  peerUserId: string;
  secret: ArrayBuffer;
} {
  const p = validateParamsObject('setContactSecret', params);
  const secret = validateBuffer('setContactSecret', 'secret', p.secret);
  if (secret.byteLength === 0 || secret.byteLength > MAX_CONTACT_SECRET_BYTES) {
    throw new RPCValidationError(
      'setContactSecret',
      'secret',
      `non-empty ArrayBuffer ≤ ${MAX_CONTACT_SECRET_BYTES} bytes`,
      p.secret
    );
  }
  return {
    sid: validateString('setContactSecret', 'sid', p.sid),
    token: validateString('setContactSecret', 'token', p.token),
    peerUserId: validatePeerUserId('setContactSecret', p.peerUserId),
    secret,
  };
}

export function validateGetContactPairID(params: unknown): {
  sid: string;
  token: string;
  peerUserId: string;
} {
  const p = validateParamsObject('getContactPairID', params);
  return {
    sid: validateString('getContactPairID', 'sid', p.sid),
    token: validateString('getContactPairID', 'token', p.token),
    peerUserId: validatePeerUserId('getContactPairID', p.peerUserId),
  };
}

export function validateListContacts(params: unknown): { sid: string; token: string } {
  const p = validateParamsObject('listContacts', params);
  return {
    sid: validateString('listContacts', 'sid', p.sid),
    token: validateString('listContacts', 'token', p.token),
  };
}

export function validateSealDeviceExchange(params: unknown): {
  sid: string;
  token: string;
  peerUserId: string;
  payload: ArrayBuffer;
} {
  const p = validateParamsObject('sealDeviceExchange', params);
  const payload = validateBuffer('sealDeviceExchange', 'payload', p.payload);
  if (payload.byteLength === 0 || payload.byteLength > MAX_DEVICE_EXCHANGE_BYTES) {
    throw new RPCValidationError(
      'sealDeviceExchange',
      'payload',
      `non-empty ArrayBuffer ≤ ${MAX_DEVICE_EXCHANGE_BYTES} bytes`,
      p.payload
    );
  }
  return {
    sid: validateString('sealDeviceExchange', 'sid', p.sid),
    token: validateString('sealDeviceExchange', 'token', p.token),
    peerUserId: validatePeerUserId('sealDeviceExchange', p.peerUserId),
    payload,
  };
}

export function validateOpenDeviceExchange(params: unknown): {
  sid: string;
  token: string;
  peerUserId: string;
  ciphertext: ArrayBuffer;
} {
  const p = validateParamsObject('openDeviceExchange', params);
  const ciphertext = validateBuffer('openDeviceExchange', 'ciphertext', p.ciphertext);
  if (ciphertext.byteLength === 0 || ciphertext.byteLength > MAX_DEVICE_EXCHANGE_BYTES + 64) {
    throw new RPCValidationError(
      'openDeviceExchange',
      'ciphertext',
      `non-empty ArrayBuffer ≤ ${MAX_DEVICE_EXCHANGE_BYTES + 64} bytes`,
      p.ciphertext
    );
  }
  return {
    sid: validateString('openDeviceExchange', 'sid', p.sid),
    token: validateString('openDeviceExchange', 'token', p.token),
    peerUserId: validatePeerUserId('openDeviceExchange', p.peerUserId),
    ciphertext,
  };
}

export function validateSealContactAnnouncement(params: unknown): {
  sid: string;
  token: string;
  peerUserId: string;
} {
  const p = validateParamsObject('sealContactAnnouncement', params);
  return {
    sid: validateString('sealContactAnnouncement', 'sid', p.sid),
    token: validateString('sealContactAnnouncement', 'token', p.token),
    peerUserId: validatePeerUserId('sealContactAnnouncement', p.peerUserId),
  };
}

export function validateApplyContactAnnouncement(params: unknown): {
  sid: string;
  token: string;
  ciphertext: ArrayBuffer;
} {
  const p = validateParamsObject('applyContactAnnouncement', params);
  const ciphertext = validateBuffer('applyContactAnnouncement', 'ciphertext', p.ciphertext);
  if (ciphertext.byteLength === 0 || ciphertext.byteLength > MAX_CONTACT_SECRET_BYTES + 512) {
    throw new RPCValidationError(
      'applyContactAnnouncement',
      'ciphertext',
      `non-empty ArrayBuffer ≤ ${MAX_CONTACT_SECRET_BYTES + 512} bytes`,
      p.ciphertext
    );
  }
  return {
    sid: validateString('applyContactAnnouncement', 'sid', p.sid),
    token: validateString('applyContactAnnouncement', 'token', p.token),
    ciphertext,
  };
}
