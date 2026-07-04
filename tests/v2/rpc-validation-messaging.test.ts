/**
 * RPC validation tests for the Signal messaging methods (Phase 2).
 *
 * Focused on the boundary guarantees: oversized payloads are rejected, key ids
 * and counts are bounded, and peer device bundles are shape/length-checked
 * before any crypto runs.
 */

import { describe, it, expect } from 'vitest';
import {
  validateSetupMessaging,
  validateGetMessagingBundle,
  validateGetPrekeyCount,
  validateOpenMessaging,
  validateCloseMessaging,
  validateBuildBundle,
  validateOpenBundle,
  validateRotatePrekeys,
  type MessagingDeviceBundle,
} from '@/v2/rpc-validation';

const creds = { method: 'passphrase' as const, userId: 'alice', passphrase: 'correct-horse-battery' };

function validBundle(): MessagingDeviceBundle {
  return {
    registrationId: 42,
    identityKey: new ArrayBuffer(33),
    identitySigningKey: new ArrayBuffer(32),
    signedPreKey: { keyId: 1, publicKey: new ArrayBuffer(33), signature: new ArrayBuffer(64) },
    preKey: { keyId: 7, publicKey: new ArrayBuffer(33) },
  };
}

describe('validateSetupMessaging', () => {
  it('applies defaults for optional fields', () => {
    const r = validateSetupMessaging({ credentials: creds });
    expect(r.signedPreKeyId).toBe(1);
    expect(r.oneTimePrekeyCount).toBe(20);
    expect(r.credentials.userId).toBe('alice');
  });

  it('accepts explicit in-range values', () => {
    const r = validateSetupMessaging({ credentials: creds, signedPreKeyId: 5, oneTimePrekeyCount: 50 });
    expect(r.signedPreKeyId).toBe(5);
    expect(r.oneTimePrekeyCount).toBe(50);
  });

  it('rejects an out-of-range one-time prekey count', () => {
    expect(() => validateSetupMessaging({ credentials: creds, oneTimePrekeyCount: 101 })).toThrow();
    expect(() => validateSetupMessaging({ credentials: creds, oneTimePrekeyCount: 0 })).toThrow();
    expect(() => validateSetupMessaging({ credentials: creds, oneTimePrekeyCount: 1.5 })).toThrow();
  });

  it('rejects an out-of-range signed prekey id', () => {
    expect(() => validateSetupMessaging({ credentials: creds, signedPreKeyId: 0 })).toThrow();
    expect(() => validateSetupMessaging({ credentials: creds, signedPreKeyId: 0x1000000 })).toThrow();
  });

  it('rejects missing credentials', () => {
    expect(() => validateSetupMessaging({})).toThrow();
  });
});

describe('validateGetMessagingBundle / validateGetPrekeyCount', () => {
  it('requires a userId', () => {
    expect(validateGetMessagingBundle({ userId: 'bob' })).toEqual({ userId: 'bob' });
    expect(validateGetPrekeyCount({ userId: 'bob' })).toEqual({ userId: 'bob' });
    expect(() => validateGetMessagingBundle({})).toThrow();
    expect(() => validateGetPrekeyCount({ userId: 5 })).toThrow();
  });
});

describe('validateOpenMessaging / validateCloseMessaging', () => {
  it('open requires credentials', () => {
    expect(validateOpenMessaging({ credentials: creds }).credentials.userId).toBe('alice');
    expect(() => validateOpenMessaging({})).toThrow();
  });

  it('close requires sid and token', () => {
    expect(validateCloseMessaging({ sid: 's', token: 't' })).toEqual({ sid: 's', token: 't' });
    expect(() => validateCloseMessaging({ sid: 's' })).toThrow();
    expect(() => validateCloseMessaging({ token: 't' })).toThrow();
  });
});

describe('validateBuildBundle', () => {
  const base = {
    sid: 's',
    token: 't',
    recipients: [{ peerName: 'bob' }],
    plaintext: new TextEncoder().encode('hi').buffer,
  };

  it('defaults peerDeviceId to 1 and passes through a valid device bundle', () => {
    const r = validateBuildBundle({
      ...base,
      recipients: [{ peerName: 'bob', deviceBundle: validBundle() }],
    });
    expect(r.recipients[0]!.peerDeviceId).toBe(1);
    expect(r.recipients[0]!.deviceBundle?.registrationId).toBe(42);
  });

  it('allows a recipient without a device bundle (existing session)', () => {
    const r = validateBuildBundle(base);
    expect(r.recipients[0]!.deviceBundle).toBeUndefined();
  });

  it('rejects empty or oversized plaintext', () => {
    expect(() => validateBuildBundle({ ...base, plaintext: new ArrayBuffer(0) })).toThrow();
    expect(() => validateBuildBundle({ ...base, plaintext: new ArrayBuffer(64 * 1024 + 1) })).toThrow();
  });

  it('rejects an empty or oversized recipients array', () => {
    expect(() => validateBuildBundle({ ...base, recipients: [] })).toThrow();
    const many = Array.from({ length: 65 }, () => ({ peerName: 'b' }));
    expect(() => validateBuildBundle({ ...base, recipients: many })).toThrow();
  });

  it('rejects an oversized peer name', () => {
    expect(() => validateBuildBundle({ ...base, recipients: [{ peerName: 'x'.repeat(257) }] })).toThrow();
  });

  it('rejects a device bundle with wrong-length keys', () => {
    const bad = validBundle();
    bad.identityKey = new ArrayBuffer(32); // must be 33
    expect(() => validateBuildBundle({ ...base, recipients: [{ peerName: 'bob', deviceBundle: bad }] })).toThrow();
  });

  it('rejects a device bundle with a bad signature length', () => {
    const bad = validBundle();
    bad.signedPreKey.signature = new ArrayBuffer(63);
    expect(() => validateBuildBundle({ ...base, recipients: [{ peerName: 'bob', deviceBundle: bad }] })).toThrow();
  });

  it('accepts a device bundle without a one-time prekey', () => {
    const b = validBundle();
    delete b.preKey;
    const r = validateBuildBundle({ ...base, recipients: [{ peerName: 'bob', deviceBundle: b }] });
    expect(r.recipients[0]!.deviceBundle?.preKey).toBeUndefined();
  });
});

describe('validateOpenBundle', () => {
  const base = {
    sid: 's',
    token: 't',
    senders: [{ peerName: 'bob' }],
    bundle: new Uint8Array([1, 0, 0]).buffer,
  };

  it('defaults peerDeviceId to 1', () => {
    expect(validateOpenBundle(base).senders[0]!.peerDeviceId).toBe(1);
  });

  it('rejects an empty or oversized bundle', () => {
    expect(() => validateOpenBundle({ ...base, bundle: new ArrayBuffer(0) })).toThrow();
    expect(() => validateOpenBundle({ ...base, bundle: new ArrayBuffer(4 * 1024 * 1024 + 1) })).toThrow();
  });

  it('rejects an empty or oversized senders array', () => {
    expect(() => validateOpenBundle({ ...base, senders: [] })).toThrow();
    const many = Array.from({ length: 65 }, () => ({ peerName: 'b' }));
    expect(() => validateOpenBundle({ ...base, senders: many })).toThrow();
  });
});

describe('validateRotatePrekeys', () => {
  it('accepts valid params', () => {
    const r = validateRotatePrekeys({ sid: 's', token: 't', signedPreKeyId: 2, startKeyId: 100, count: 10 });
    expect(r).toEqual({ sid: 's', token: 't', signedPreKeyId: 2, startKeyId: 100, count: 10 });
  });

  it('bounds the count and key ids', () => {
    const ok = { sid: 's', token: 't', signedPreKeyId: 2, startKeyId: 100 };
    expect(() => validateRotatePrekeys({ ...ok, count: 0 })).toThrow();
    expect(() => validateRotatePrekeys({ ...ok, count: 101 })).toThrow();
    expect(() => validateRotatePrekeys({ ...ok, startKeyId: 0, count: 5 })).toThrow();
  });
});
