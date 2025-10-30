/**
 * @file rpc-validation.test.ts
 * @description Comprehensive tests for rpc-validation.ts
 * Tests all validation functions with valid inputs, invalid inputs, and edge cases.
 */

import { describe, it, expect } from 'vitest';
import {
  RPCValidationError,
  validateSetupPassphrase,
  validateSetupPasskeyPRF,
  validateSetupPasskeyGate,
  validateAddEnrollment,
  validateGenerateVAPID,
  validateRegenerateVAPID,
  validateSignJWT,
  validateCreateLease,
  validateIssueVAPIDJWT,
  validateIssueVAPIDJWTs,
  validateIsSetup,
  validateGetEnrollments,
  validateVerifyAuditChain,
  validateGetAuditLog,
  validateGetPublicKey,
  validateGetAuditPublicKey,
  validateGetUserLeases,
  validateVerifyLease,
  validateGetVAPIDKid,
  validateResetKMS,
  validateRemoveEnrollment,
} from '@/v2/rpc-validation';

describe('RPCValidationError', () => {
  it('should create error with all details', () => {
    const error = new RPCValidationError('testMethod', 'testParam', 'string', 123);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('RPCValidationError');
    expect(error.method).toBe('testMethod');
    expect(error.param).toBe('testParam');
    expect(error.expected).toBe('string');
    expect(error.received).toBe(123);
    expect(error.message).toBe('RPC testMethod: Invalid testParam - expected string, got number');
  });

  it('should handle null received value', () => {
    const error = new RPCValidationError('method', 'param', 'string', null);
    expect(error.message).toContain('got object');
  });
});

describe('validateSetupPassphrase', () => {
  describe('valid inputs', () => {
    it('should validate minimal valid params', () => {
      const result = validateSetupPassphrase({
        userId: 'user123',
        passphrase: 'secret',
      });
      expect(result).toEqual({
        userId: 'user123',
        passphrase: 'secret',
      });
    });

    it('should validate with optional existingMS as Uint8Array', () => {
      const existingMS = new Uint8Array([1, 2, 3]);
      const result = validateSetupPassphrase({
        userId: 'user123',
        passphrase: 'secret',
        existingMS,
      });
      expect(result).toEqual({
        userId: 'user123',
        passphrase: 'secret',
        existingMS,
      });
    });

    it('should validate with optional existingMS as ArrayBuffer', () => {
      const existingMS = new ArrayBuffer(8);
      const result = validateSetupPassphrase({
        userId: 'user123',
        passphrase: 'secret',
        existingMS,
      });
      expect(result.existingMS).toBeInstanceOf(Uint8Array);
      expect(result.existingMS?.byteLength).toBe(8);
    });
  });

  describe('invalid inputs', () => {
    it('should reject null params', () => {
      expect(() => validateSetupPassphrase(null)).toThrow(RPCValidationError);
    });

    it('should reject non-object params', () => {
      expect(() => validateSetupPassphrase('not an object')).toThrow(RPCValidationError);
    });

    it('should reject missing userId', () => {
      expect(() =>
        validateSetupPassphrase({
          passphrase: 'secret',
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-string userId', () => {
      expect(() =>
        validateSetupPassphrase({
          userId: 123,
          passphrase: 'secret',
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject missing passphrase', () => {
      expect(() =>
        validateSetupPassphrase({
          userId: 'user123',
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-string passphrase', () => {
      expect(() =>
        validateSetupPassphrase({
          userId: 'user123',
          passphrase: 123,
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject invalid existingMS type', () => {
      expect(() =>
        validateSetupPassphrase({
          userId: 'user123',
          passphrase: 'secret',
          existingMS: 'not a buffer',
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateSetupPasskeyPRF', () => {
  describe('valid inputs', () => {
    it('should validate minimal valid params', () => {
      const result = validateSetupPasskeyPRF({
        userId: 'user123',
        credentialId: new ArrayBuffer(16),
        prfOutput: new ArrayBuffer(32),
      });
      expect(result.userId).toBe('user123');
      expect(result.credentialId).toBeInstanceOf(ArrayBuffer);
      expect(result.prfOutput).toBeInstanceOf(ArrayBuffer);
    });

    it('should validate with optional rpId', () => {
      const result = validateSetupPasskeyPRF({
        userId: 'user123',
        credentialId: new ArrayBuffer(16),
        prfOutput: new ArrayBuffer(32),
        rpId: 'example.com',
      });
      expect(result.rpId).toBe('example.com');
    });

    it('should validate with optional existingMS', () => {
      const existingMS = new Uint8Array([1, 2, 3]);
      const result = validateSetupPasskeyPRF({
        userId: 'user123',
        credentialId: new ArrayBuffer(16),
        prfOutput: new ArrayBuffer(32),
        existingMS,
      });
      expect(result.existingMS).toBe(existingMS);
    });

    it('should convert Uint8Array credentialId to ArrayBuffer', () => {
      const credId = new Uint8Array([1, 2, 3, 4]);
      const result = validateSetupPasskeyPRF({
        userId: 'user123',
        credentialId: credId,
        prfOutput: new ArrayBuffer(32),
      });
      expect(result.credentialId).toBeInstanceOf(ArrayBuffer);
      expect(result.credentialId.byteLength).toBe(4);
    });
  });

  describe('invalid inputs', () => {
    it('should reject missing credentialId', () => {
      expect(() =>
        validateSetupPasskeyPRF({
          userId: 'user123',
          prfOutput: new ArrayBuffer(32),
        })
      ).toThrow('credentialId required');
    });

    it('should reject null credentialId', () => {
      expect(() =>
        validateSetupPasskeyPRF({
          userId: 'user123',
          credentialId: null,
          prfOutput: new ArrayBuffer(32),
        })
      ).toThrow('credentialId required');
    });

    it('should reject invalid credentialId type', () => {
      expect(() =>
        validateSetupPasskeyPRF({
          userId: 'user123',
          credentialId: 'not a buffer',
          prfOutput: new ArrayBuffer(32),
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject invalid prfOutput type', () => {
      expect(() =>
        validateSetupPasskeyPRF({
          userId: 'user123',
          credentialId: new ArrayBuffer(16),
          prfOutput: 'not a buffer',
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-string rpId', () => {
      expect(() =>
        validateSetupPasskeyPRF({
          userId: 'user123',
          credentialId: new ArrayBuffer(16),
          prfOutput: new ArrayBuffer(32),
          rpId: 123,
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateSetupPasskeyGate', () => {
  describe('valid inputs', () => {
    it('should validate minimal valid params', () => {
      const result = validateSetupPasskeyGate({
        userId: 'user123',
        credentialId: new ArrayBuffer(16),
      });
      expect(result.userId).toBe('user123');
      expect(result.credentialId).toBeInstanceOf(ArrayBuffer);
    });

    it('should validate with optional rpId', () => {
      const result = validateSetupPasskeyGate({
        userId: 'user123',
        credentialId: new ArrayBuffer(16),
        rpId: 'example.com',
      });
      expect(result.rpId).toBe('example.com');
    });

    it('should validate with optional existingMS', () => {
      const existingMS = new Uint8Array([1, 2, 3]);
      const result = validateSetupPasskeyGate({
        userId: 'user123',
        credentialId: new ArrayBuffer(16),
        existingMS,
      });
      expect(result.existingMS).toBe(existingMS);
    });
  });

  describe('invalid inputs', () => {
    it('should reject invalid credentialId type', () => {
      expect(() =>
        validateSetupPasskeyGate({
          userId: 'user123',
          credentialId: 'not a buffer',
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateAddEnrollment', () => {
  describe('valid inputs', () => {
    it('should validate passphrase enrollment', () => {
      const result = validateAddEnrollment({
        userId: 'user123',
        method: 'passphrase',
        credentials: {
          method: 'passphrase',
          userId: 'user123',
          passphrase: 'current-pass',
        },
        newCredentials: {
          passphrase: 'new-pass',
        },
      });
      expect(result.method).toBe('passphrase');
      expect(result.credentials.method).toBe('passphrase');
    });

    it('should validate passkey-prf enrollment', () => {
      const result = validateAddEnrollment({
        userId: 'user123',
        method: 'passkey-prf',
        credentials: {
          method: 'passkey-prf',
          userId: 'user123',
          prfOutput: new ArrayBuffer(32),
        },
        newCredentials: {
          credentialId: new ArrayBuffer(16),
          prfOutput: new ArrayBuffer(32),
        },
      });
      expect(result.method).toBe('passkey-prf');
    });

    it('should validate passkey-gate enrollment', () => {
      const result = validateAddEnrollment({
        userId: 'user123',
        method: 'passkey-gate',
        credentials: {
          method: 'passkey-gate',
          userId: 'user123',
        },
        newCredentials: {
          credentialId: new ArrayBuffer(16),
        },
      });
      expect(result.method).toBe('passkey-gate');
    });
  });

  describe('invalid inputs', () => {
    it('should reject invalid method value', () => {
      expect(() =>
        validateAddEnrollment({
          userId: 'user123',
          method: 'invalid-method',
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'pass',
          },
          newCredentials: {},
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-string method', () => {
      expect(() =>
        validateAddEnrollment({
          userId: 'user123',
          method: 123,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'pass',
          },
          newCredentials: {},
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject invalid credentials', () => {
      expect(() =>
        validateAddEnrollment({
          userId: 'user123',
          method: 'passphrase',
          credentials: 'not an object',
          newCredentials: {},
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateAuthCredentials', () => {
  describe('passphrase credentials', () => {
    it('should validate via validateGenerateVAPID', () => {
      const result = validateGenerateVAPID({
        credentials: {
          method: 'passphrase',
          userId: 'user123',
          passphrase: 'secret',
        },
      });
      expect(result.credentials.method).toBe('passphrase');
      if (result.credentials.method === 'passphrase') {
        expect(result.credentials.passphrase).toBe('secret');
      }
    });

    it('should reject passphrase credentials with missing passphrase', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 'passphrase',
            userId: 'user123',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject passphrase credentials with non-string passphrase', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 123,
          },
        })
      ).toThrow(RPCValidationError);
    });
  });

  describe('passkey-prf credentials', () => {
    it('should validate via validateGenerateVAPID', () => {
      const result = validateGenerateVAPID({
        credentials: {
          method: 'passkey-prf',
          userId: 'user123',
          prfOutput: new ArrayBuffer(32),
        },
      });
      expect(result.credentials.method).toBe('passkey-prf');
    });

    it('should reject passkey-prf credentials with invalid prfOutput', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 'passkey-prf',
            userId: 'user123',
            prfOutput: 'not a buffer',
          },
        })
      ).toThrow(RPCValidationError);
    });
  });

  describe('passkey-gate credentials', () => {
    it('should validate via validateGenerateVAPID', () => {
      const result = validateGenerateVAPID({
        credentials: {
          method: 'passkey-gate',
          userId: 'user123',
        },
      });
      expect(result.credentials.method).toBe('passkey-gate');
    });
  });

  describe('invalid credentials', () => {
    it('should reject null credentials', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: null,
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-object credentials', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: 'not an object',
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject credentials without method', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            userId: 'user123',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject credentials with non-string method', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 123,
            userId: 'user123',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject credentials without userId', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 'passphrase',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject credentials with non-string userId', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 'passphrase',
            userId: 123,
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject credentials with invalid method value', () => {
      expect(() =>
        validateGenerateVAPID({
          credentials: {
            method: 'invalid',
            userId: 'user123',
          },
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateRegenerateVAPID', () => {
  it('should validate valid params', () => {
    const result = validateRegenerateVAPID({
      credentials: {
        method: 'passphrase',
        userId: 'user123',
        passphrase: 'secret',
      },
    });
    expect(result.credentials.method).toBe('passphrase');
  });

  it('should reject invalid credentials', () => {
    expect(() =>
      validateRegenerateVAPID({
        credentials: null,
      })
    ).toThrow(RPCValidationError);
  });
});

describe('validateSignJWT', () => {
  describe('valid inputs', () => {
    it('should validate complete params', () => {
      const result = validateSignJWT({
        kid: 'key-id-123',
        payload: {
          aud: 'https://example.com',
          sub: 'mailto:test@example.com',
          exp: 1234567890,
          jti: 'unique-id',
        },
        credentials: {
          method: 'passphrase',
          userId: 'user123',
          passphrase: 'secret',
        },
      });
      expect(result.kid).toBe('key-id-123');
      expect(result.payload.aud).toBe('https://example.com');
      expect(result.payload.exp).toBe(1234567890);
    });
  });

  describe('invalid inputs', () => {
    it('should reject missing kid', () => {
      expect(() =>
        validateSignJWT({
          payload: {
            aud: 'https://example.com',
            sub: 'mailto:test@example.com',
            exp: 1234567890,
            jti: 'unique-id',
          },
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-string kid', () => {
      expect(() =>
        validateSignJWT({
          kid: 123,
          payload: {
            aud: 'https://example.com',
            sub: 'mailto:test@example.com',
            exp: 1234567890,
            jti: 'unique-id',
          },
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject null payload', () => {
      expect(() =>
        validateSignJWT({
          kid: 'key-id',
          payload: null,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject payload with missing aud', () => {
      expect(() =>
        validateSignJWT({
          kid: 'key-id',
          payload: {
            sub: 'mailto:test@example.com',
            exp: 1234567890,
            jti: 'unique-id',
          },
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject payload with non-number exp', () => {
      expect(() =>
        validateSignJWT({
          kid: 'key-id',
          payload: {
            aud: 'https://example.com',
            sub: 'mailto:test@example.com',
            exp: 'not a number',
            jti: 'unique-id',
          },
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateCreateLease', () => {
  describe('valid inputs', () => {
    it('should validate complete params', () => {
      const result = validateCreateLease({
        userId: 'user123',
        subs: [
          { url: 'https://push1.com', aud: 'https://push1.com', eid: 'endpoint1' },
          { url: 'https://push2.com', aud: 'https://push2.com', eid: 'endpoint2' },
        ],
        ttlHours: 24,
        credentials: {
          method: 'passphrase',
          userId: 'user123',
          passphrase: 'secret',
        },
      });
      expect(result.subs).toHaveLength(2);
      expect(result.ttlHours).toBe(24);
    });

    it('should validate with empty subs array', () => {
      const result = validateCreateLease({
        userId: 'user123',
        subs: [],
        ttlHours: 24,
        credentials: {
          method: 'passphrase',
          userId: 'user123',
          passphrase: 'secret',
        },
      });
      expect(result.subs).toHaveLength(0);
    });
  });

  describe('invalid inputs', () => {
    it('should reject non-array subs', () => {
      expect(() =>
        validateCreateLease({
          userId: 'user123',
          subs: 'not an array',
          ttlHours: 24,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject subs with non-object element', () => {
      expect(() =>
        validateCreateLease({
          userId: 'user123',
          subs: ['not an object'],
          ttlHours: 24,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject subs with null element', () => {
      expect(() =>
        validateCreateLease({
          userId: 'user123',
          subs: [null],
          ttlHours: 24,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject subs element missing url', () => {
      expect(() =>
        validateCreateLease({
          userId: 'user123',
          subs: [{ aud: 'https://push.com', eid: 'endpoint1' }],
          ttlHours: 24,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject subs element with non-string url', () => {
      expect(() =>
        validateCreateLease({
          userId: 'user123',
          subs: [{ url: 123, aud: 'https://push.com', eid: 'endpoint1' }],
          ttlHours: 24,
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-number ttlHours', () => {
      expect(() =>
        validateCreateLease({
          userId: 'user123',
          subs: [],
          ttlHours: 'not a number',
          credentials: {
            method: 'passphrase',
            userId: 'user123',
            passphrase: 'secret',
          },
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateIssueVAPIDJWT', () => {
  describe('valid inputs', () => {
    it('should validate minimal params', () => {
      const result = validateIssueVAPIDJWT({
        leaseId: 'lease123',
        endpoint: {
          url: 'https://push.com',
          aud: 'https://push.com',
          eid: 'endpoint1',
        },
      });
      expect(result.leaseId).toBe('lease123');
      expect(result.endpoint.url).toBe('https://push.com');
    });

    it('should validate with optional kid', () => {
      const result = validateIssueVAPIDJWT({
        leaseId: 'lease123',
        endpoint: {
          url: 'https://push.com',
          aud: 'https://push.com',
          eid: 'endpoint1',
        },
        kid: 'key-id',
      });
      expect(result.kid).toBe('key-id');
    });

    it('should validate with optional jti', () => {
      const result = validateIssueVAPIDJWT({
        leaseId: 'lease123',
        endpoint: {
          url: 'https://push.com',
          aud: 'https://push.com',
          eid: 'endpoint1',
        },
        jti: 'jwt-id',
      });
      expect(result.jti).toBe('jwt-id');
    });

    it('should validate with optional exp', () => {
      const result = validateIssueVAPIDJWT({
        leaseId: 'lease123',
        endpoint: {
          url: 'https://push.com',
          aud: 'https://push.com',
          eid: 'endpoint1',
        },
        exp: 1234567890,
      });
      expect(result.exp).toBe(1234567890);
    });
  });

  describe('invalid inputs', () => {
    it('should reject null endpoint', () => {
      expect(() =>
        validateIssueVAPIDJWT({
          leaseId: 'lease123',
          endpoint: null,
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-object endpoint', () => {
      expect(() =>
        validateIssueVAPIDJWT({
          leaseId: 'lease123',
          endpoint: 'not an object',
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject endpoint missing url', () => {
      expect(() =>
        validateIssueVAPIDJWT({
          leaseId: 'lease123',
          endpoint: {
            aud: 'https://push.com',
            eid: 'endpoint1',
          },
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-string kid', () => {
      expect(() =>
        validateIssueVAPIDJWT({
          leaseId: 'lease123',
          endpoint: {
            url: 'https://push.com',
            aud: 'https://push.com',
            eid: 'endpoint1',
          },
          kid: 123,
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-number exp', () => {
      expect(() =>
        validateIssueVAPIDJWT({
          leaseId: 'lease123',
          endpoint: {
            url: 'https://push.com',
            aud: 'https://push.com',
            eid: 'endpoint1',
          },
          exp: 'not a number',
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateIssueVAPIDJWTs', () => {
  describe('valid inputs', () => {
    it('should validate minimal params', () => {
      const result = validateIssueVAPIDJWTs({
        leaseId: 'lease123',
        endpoint: {
          url: 'https://push.com',
          aud: 'https://push.com',
          eid: 'endpoint1',
        },
        count: 5,
      });
      expect(result.count).toBe(5);
    });

    it('should validate with optional kid', () => {
      const result = validateIssueVAPIDJWTs({
        leaseId: 'lease123',
        endpoint: {
          url: 'https://push.com',
          aud: 'https://push.com',
          eid: 'endpoint1',
        },
        count: 5,
        kid: 'key-id',
      });
      expect(result.kid).toBe('key-id');
    });
  });

  describe('invalid inputs', () => {
    it('should reject null endpoint', () => {
      expect(() =>
        validateIssueVAPIDJWTs({
          leaseId: 'lease123',
          endpoint: null,
          count: 5,
        })
      ).toThrow(RPCValidationError);
    });

    it('should reject non-number count', () => {
      expect(() =>
        validateIssueVAPIDJWTs({
          leaseId: 'lease123',
          endpoint: {
            url: 'https://push.com',
            aud: 'https://push.com',
            eid: 'endpoint1',
          },
          count: 'not a number',
        })
      ).toThrow(RPCValidationError);
    });
  });
});

describe('validateIsSetup', () => {
  it('should accept undefined params', () => {
    const result = validateIsSetup(undefined);
    expect(result).toEqual({});
  });

  it('should accept null params', () => {
    const result = validateIsSetup(null);
    expect(result).toEqual({});
  });

  it('should accept empty object', () => {
    const result = validateIsSetup({});
    expect(result).toEqual({});
  });

  it('should accept optional userId', () => {
    const result = validateIsSetup({ userId: 'user123' });
    expect(result).toEqual({ userId: 'user123' });
  });

  it('should reject non-string userId', () => {
    expect(() => validateIsSetup({ userId: 123 })).toThrow(RPCValidationError);
  });
});

describe('validateGetEnrollments', () => {
  it('should accept undefined params', () => {
    const result = validateGetEnrollments(undefined);
    expect(result).toEqual({});
  });

  it('should accept null params', () => {
    const result = validateGetEnrollments(null);
    expect(result).toEqual({});
  });

  it('should accept optional userId', () => {
    const result = validateGetEnrollments({ userId: 'user123' });
    expect(result).toEqual({ userId: 'user123' });
  });

  it('should reject non-string userId', () => {
    expect(() => validateGetEnrollments({ userId: 123 })).toThrow(RPCValidationError);
  });
});

describe('validateVerifyAuditChain', () => {
  it('should accept any params', () => {
    const result = validateVerifyAuditChain(undefined);
    expect(result).toEqual({});
  });

  it('should accept null params', () => {
    const result = validateVerifyAuditChain(null);
    expect(result).toEqual({});
  });

  it('should accept object params', () => {
    const result = validateVerifyAuditChain({ ignored: 'value' });
    expect(result).toEqual({});
  });
});

describe('validateGetAuditLog', () => {
  it('should accept any params', () => {
    const result = validateGetAuditLog(undefined);
    expect(result).toEqual({});
  });

  it('should accept null params', () => {
    const result = validateGetAuditLog(null);
    expect(result).toEqual({});
  });
});

describe('validateGetPublicKey', () => {
  it('should validate valid params', () => {
    const result = validateGetPublicKey({ kid: 'key-id-123' });
    expect(result).toEqual({ kid: 'key-id-123' });
  });

  it('should reject missing kid', () => {
    expect(() => validateGetPublicKey({})).toThrow(RPCValidationError);
  });

  it('should reject non-string kid', () => {
    expect(() => validateGetPublicKey({ kid: 123 })).toThrow(RPCValidationError);
  });
});

describe('validateGetAuditPublicKey', () => {
  it('should accept any params', () => {
    const result = validateGetAuditPublicKey(undefined);
    expect(result).toEqual({});
  });
});

describe('validateGetUserLeases', () => {
  it('should validate valid params', () => {
    const result = validateGetUserLeases({ userId: 'user123' });
    expect(result).toEqual({ userId: 'user123' });
  });

  it('should reject missing userId', () => {
    expect(() => validateGetUserLeases({})).toThrow(RPCValidationError);
  });

  it('should reject non-string userId', () => {
    expect(() => validateGetUserLeases({ userId: 123 })).toThrow(RPCValidationError);
  });
});

describe('validateVerifyLease', () => {
  it('should validate valid params', () => {
    const result = validateVerifyLease({ leaseId: 'lease123' });
    expect(result).toEqual({ leaseId: 'lease123' });
  });

  it('should reject missing leaseId', () => {
    expect(() => validateVerifyLease({})).toThrow(RPCValidationError);
  });

  it('should reject non-string leaseId', () => {
    expect(() => validateVerifyLease({ leaseId: 123 })).toThrow(RPCValidationError);
  });
});

describe('validateGetVAPIDKid', () => {
  it('should accept any params', () => {
    const result = validateGetVAPIDKid(undefined);
    expect(result).toEqual({});
  });
});

describe('validateResetKMS', () => {
  it('should accept any params', () => {
    const result = validateResetKMS(undefined);
    expect(result).toEqual({});
  });
});

describe('validateRemoveEnrollment', () => {
  it('should validate valid params', () => {
    const result = validateRemoveEnrollment({
      enrollmentId: 'enroll123',
      credentials: {
        method: 'passphrase',
        userId: 'user123',
        passphrase: 'secret',
      },
    });
    expect(result.enrollmentId).toBe('enroll123');
    expect(result.credentials.method).toBe('passphrase');
  });

  it('should reject missing enrollmentId', () => {
    expect(() =>
      validateRemoveEnrollment({
        credentials: {
          method: 'passphrase',
          userId: 'user123',
          passphrase: 'secret',
        },
      })
    ).toThrow(RPCValidationError);
  });

  it('should reject invalid credentials', () => {
    expect(() =>
      validateRemoveEnrollment({
        enrollmentId: 'enroll123',
        credentials: null,
      })
    ).toThrow(RPCValidationError);
  });
});
