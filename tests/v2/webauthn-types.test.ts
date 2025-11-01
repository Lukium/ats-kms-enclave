/**
 * Tests for WebAuthn type guards and helpers
 */

import { describe, it, expect, vi } from 'vitest';
import { getPRFResults, hasAuthenticatorData } from '../../src/v2/webauthn-types.js';

describe('getPRFResults', () => {
  it('should return undefined when prf is undefined', () => {
    const response: any = {
      getClientExtensionResults: () => ({}),
    };
    expect(getPRFResults(response)).toBeUndefined();
  });

  it('should return undefined and warn when PRF structure is invalid', () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const response: any = {
      getClientExtensionResults: () => ({
        prf: { results: { first: 'not-an-arraybuffer' } }, // Invalid: first must be ArrayBuffer
      }),
    };

    const result = getPRFResults(response);

    expect(result).toBeUndefined();
    expect(consoleSpy).toHaveBeenCalledWith(
      '[WebAuthn] Invalid PRF extension result structure:',
      { results: { first: 'not-an-arraybuffer' } }
    );

    consoleSpy.mockRestore();
  });

  it('should return PRF result when valid', () => {
    const prfResult = {
      results: {
        first: new ArrayBuffer(32),
      },
    };

    const response: any = {
      getClientExtensionResults: () => ({
        prf: prfResult,
      }),
    };

    expect(getPRFResults(response)).toEqual(prfResult);
  });
});

describe('hasAuthenticatorData', () => {
  it('should return true for AuthenticatorAssertionResponse with authenticatorData', () => {
    const response: any = {
      authenticatorData: new ArrayBuffer(37),
    };

    expect(hasAuthenticatorData(response)).toBe(true);
  });

  it('should return false when authenticatorData is missing', () => {
    const response: any = {
      clientDataJSON: new ArrayBuffer(100),
    };

    expect(hasAuthenticatorData(response)).toBe(false);
  });

  it('should return false when authenticatorData is not an ArrayBuffer', () => {
    const response: any = {
      authenticatorData: 'not an arraybuffer',
    };

    expect(hasAuthenticatorData(response)).toBe(false);
  });
});
