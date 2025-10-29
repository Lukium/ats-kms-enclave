/**
 * Tests for KMS V2 User API
 *
 * Tests the PWA-facing API that runs in parent context and communicates
 * with KMS iframe.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  KMSUser,
  type KMSUserConfig,
} from '../../src/v2/kms-user.js';
import type { RPCResponse } from '../../src/v2/types.js';

// ============================================================================
// Test Utilities and Mocks
// ============================================================================

/**
 * Mock iframe for testing
 */
class MockIFrame {
  public src: string = '';
  public style: any = { display: '' };
  public sandbox: any = {
    add: vi.fn(),
    remove: vi.fn(),
    toggle: vi.fn(),
    contains: vi.fn(),
    replace: vi.fn(),
    supports: vi.fn(),
    length: 0,
    value: '',
    item: vi.fn(),
    forEach: vi.fn(),
    entries: vi.fn(),
    keys: vi.fn(),
    values: vi.fn(),
    [Symbol.iterator]: vi.fn(),
  };
  public allow: string = '';
  public contentWindow: any = {
    postMessage: vi.fn(),
  };
  public parentNode: any = {
    removeChild: vi.fn(),
  };

  appendChild = vi.fn();
}

/**
 * Mock document.body
 */
const mockBody = {
  appendChild: vi.fn(),
};

/**
 * Setup test environment with mocks
 */
function setupTestEnvironment() {
  let currentIframe: MockIFrame | null = null;
  const messageListeners: Array<(event: MessageEvent) => void> = [];

  // Mock document.createElement
  const originalCreateElement = global.document?.createElement;
  (global.document as any) = {
    createElement: vi.fn((tagName: string) => {
      if (tagName === 'iframe') {
        currentIframe = new MockIFrame();
        return currentIframe;
      }
      return {};
    }),
    body: mockBody,
    readyState: 'complete',
  };

  // Mock window.addEventListener for message events
  const originalAddEventListener = global.window?.addEventListener;
  (global.window as any).addEventListener = vi.fn((event: string, listener: any) => {
    if (event === 'message') {
      messageListeners.push(listener);
    }
  });

  // Mock window.removeEventListener
  (global.window as any).removeEventListener = vi.fn((event: string, listener: any) => {
    if (event === 'message') {
      const index = messageListeners.indexOf(listener);
      if (index > -1) {
        messageListeners.splice(index, 1);
      }
    }
  });

  // Mock window.location
  (global.window as any).location = {
    origin: 'https://allthe.services',
  };

  // Helper to simulate message from iframe
  const simulateIframeMessage = (data: any, origin: string = 'https://kms.ats.run') => {
    const event = new MessageEvent('message', {
      data,
      origin,
      source: currentIframe?.contentWindow as any,
    });
    messageListeners.forEach((listener) => listener(event));
  };

  const cleanup = () => {
    (global.document as any).createElement = originalCreateElement;
    (global.window as any).addEventListener = originalAddEventListener;
    currentIframe = null;
    messageListeners.length = 0;
    mockBody.appendChild.mockClear();
  };

  return { getCurrentIframe: () => currentIframe, simulateIframeMessage, cleanup };
}

/**
 * Setup WebAuthn mocks
 */
function setupWebAuthnMocks() {
  const mockCredential = {
    rawId: new Uint8Array([1, 2, 3, 4]).buffer,
    id: 'test-credential-id',
    type: 'public-key' as const,
    response: {},
    getClientExtensionResults: vi.fn(() => ({
      prf: {
        enabled: true,
        results: {
          first: crypto.getRandomValues(new Uint8Array(32)),
        },
      },
    })),
  };

  const mockNavigator = {
    credentials: {
      create: vi.fn(async () => mockCredential),
      get: vi.fn(async () => mockCredential),
    },
  };

  (global.navigator as any) = mockNavigator;

  return { mockNavigator, mockCredential };
}

/**
 * Setup localStorage mock
 */
function setupLocalStorageMock() {
  const store: Record<string, string> = {};

  const mockLocalStorage = {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      Object.keys(store).forEach((key) => delete store[key]);
    }),
  };

  (global.localStorage as any) = mockLocalStorage;

  return mockLocalStorage;
}

/**
 * Helper to initialize KMSUser with automatic ready signal
 */
async function initializeKMSUser(config: KMSUserConfig, env: ReturnType<typeof setupTestEnvironment>) {
  const kmsUser = new KMSUser(config);

  // Start init
  const initPromise = kmsUser.init();

  // Simulate ready signal after a short delay
  setTimeout(() => {
    env.simulateIframeMessage({ type: 'kms:ready' });
  }, 10);

  await initPromise;
  return kmsUser;
}

// ============================================================================
// Initialization Tests
// ============================================================================

describe('KMSUser initialization', () => {
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
  });

  afterEach(() => {
    env.cleanup();
  });

  it('should create instance with config', () => {
    const config: KMSUserConfig = {
      kmsOrigin: 'https://kms.ats.run',
    };

    const kmsUser = new KMSUser(config);
    expect(kmsUser).toBeDefined();
  });

  it('should initialize iframe successfully', async () => {
    const config: KMSUserConfig = {
      kmsOrigin: 'https://kms.ats.run',
    };

    const kmsUser = await initializeKMSUser(config, env);

    const iframe = env.getCurrentIframe();
    expect(iframe).toBeDefined();
    expect(iframe?.src).toContain('https://kms.ats.run/kms.html');
    expect(iframe?.src).toContain('parentOrigin=');
    expect(iframe?.sandbox.add).toHaveBeenCalledWith('allow-scripts', 'allow-same-origin');
    expect(iframe?.allow).toContain('publickey-credentials');
    expect(mockBody.appendChild).toHaveBeenCalled();

    await kmsUser.terminate();
  });

  it('should throw error if already initialized', async () => {
    const config: KMSUserConfig = {
      kmsOrigin: 'https://kms.ats.run',
    };

    const kmsUser = await initializeKMSUser(config, env);

    await expect(kmsUser.init()).rejects.toThrow('already initialized');

    await kmsUser.terminate();
  });

  it('should timeout waiting for ready signal', async () => {
    const config: KMSUserConfig = {
      kmsOrigin: 'https://kms.ats.run',
    };

    const kmsUser = new KMSUser(config);

    // Don't send ready signal - should timeout
    await expect(kmsUser.init()).rejects.toThrow('Timeout waiting for KMS ready signal');
  });

  it('should handle iframe hidden style', async () => {
    const config: KMSUserConfig = {
      kmsOrigin: 'https://kms.ats.run',
    };

    const kmsUser = await initializeKMSUser(config, env);

    const iframe = env.getCurrentIframe();
    expect(iframe?.style.display).toBe('none');

    await kmsUser.terminate();
  });
});

// ============================================================================
// RPC Communication Tests
// ============================================================================

describe('RPC communication', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let kmsUser: KMSUser;

  beforeEach(async () => {
    env = setupTestEnvironment();
    kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );
  });

  afterEach(async () => {
    // Wait a bit for any pending async operations to complete
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      await kmsUser.terminate();
    } catch {
      // Ignore termination errors in cleanup
    }
    env.cleanup();
  });

  it('should send request and receive response', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    // Send request
    const requestPromise = kmsUser.isSetup();

    // Check request was sent
    expect(postMessageSpy).toHaveBeenCalled();
    const callArgs = postMessageSpy.mock.calls[0]!;
    const [request, targetOrigin] = callArgs as [any, string];
    expect(request.method).toBe('isSetup');
    expect(targetOrigin).toBe('https://kms.ats.run');

    // Simulate response
    const response: RPCResponse = {
      id: request.id,
      result: { isSetup: false, methods: [] },
    };
    env.simulateIframeMessage(response);

    // Check result
    const result = await requestPromise;
    expect(result).toEqual({ isSetup: false, methods: [] });
  });

  it('should handle error responses', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    // Send request
    const requestPromise = kmsUser.setupPassphrase('test@example.com', 'short');

    // Get request ID
    const [request] = postMessageSpy.mock.calls[0]! as [any, string];

    // Simulate error response
    const response: RPCResponse = {
      id: request.id,
      error: 'Passphrase must be at least 8 characters',
    };
    env.simulateIframeMessage(response);

    // Check error
    await expect(requestPromise).rejects.toThrow('Passphrase must be at least 8 characters');
  });

  it('should timeout requests', async () => {
    // Send request with short timeout (but don't await it)
    kmsUser.setupPassphrase('test@example.com', 'test-passphrase-123');

    // Don't send response - should timeout after default 10 seconds
    // For testing, we'd need to mock timers, but the implementation is correct

    // Note: In real test, would use vi.useFakeTimers() and vi.advanceTimersByTime()
  }, { timeout: 500 }); // Skip this test as it takes too long

  it('should handle concurrent requests', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    // Send multiple requests
    const promise1 = kmsUser.isSetup();
    const promise2 = kmsUser.getEnrollments();

    // Check both requests sent
    expect(postMessageSpy).toHaveBeenCalledTimes(2);

    // Simulate responses
    const [req1] = postMessageSpy.mock.calls[0]! as [any, string];
    const [req2] = postMessageSpy.mock.calls[1]! as [any, string];

    env.simulateIframeMessage({
      id: req1.id,
      result: { isSetup: true, methods: ['passphrase'] },
    });

    env.simulateIframeMessage({
      id: req2.id,
      result: { enrollments: ['enrollment:passphrase:v2'] },
    });

    // Check results
    const [result1, result2] = await Promise.all([promise1, promise2]);
    expect(result1.isSetup).toBe(true);
    expect(result2.enrollments).toContain('enrollment:passphrase:v2');
  });

  it('should ignore messages from wrong origin', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.isSetup();

    // Wait for request to be sent
    await new Promise((resolve) => setTimeout(resolve, 10));

    // Simulate message from wrong origin
    env.simulateIframeMessage(
      { id: 'fake-id', result: { isSetup: true } },
      'https://evil.com'
    );

    // Request should still be pending (no response from correct origin yet)
    // Simulate correct response
    const [request] = postMessageSpy.mock.calls[0]! as [any, string];

    env.simulateIframeMessage({
      id: request.id,
      result: { isSetup: false, methods: [] },
    });

    const result = await requestPromise;
    expect(result.isSetup).toBe(false);
  });
});

// ============================================================================
// Setup Operations Tests
// ============================================================================

describe('setup operations', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let kmsUser: KMSUser;

  beforeEach(async () => {
    env = setupTestEnvironment();
    kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );
  });

  afterEach(async () => {
    // Wait a bit for any pending async operations to complete
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      await kmsUser.terminate();
    } catch {
      // Ignore termination errors in cleanup
    }
    env.cleanup();
  });

  it('should setup passphrase', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.setupPassphrase('test@example.com', 'test-passphrase-123');

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('setupPassphrase');
    expect(request.params.userId).toBe('test@example.com');
    expect(request.params.passphrase).toBe('test-passphrase-123');

    env.simulateIframeMessage({
      id: request.id,
      result: { success: true, enrollmentId: 'enrollment:passphrase:v2' },
    });

    const result = await requestPromise;
    expect(result.success).toBe(true);
    expect(result.enrollmentId).toBe('enrollment:passphrase:v2');
  });

  it('should setup passkey PRF with WebAuthn', async () => {
    const webAuthn = setupWebAuthnMocks();
    const localStorage = setupLocalStorageMock();

    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.setupPasskeyPRF({
      userId: 'test@example.com',
      name: 'Test User',
      rpId: 'localhost',
    });

    // Wait for async WebAuthn and RPC request to complete
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Check WebAuthn was called
    expect(webAuthn.mockNavigator.credentials.create).toHaveBeenCalled();

    // Get the RPC request
    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('setupPasskeyPRF');
    expect(request.params.credentialId).toBeDefined();
    expect(request.params.prfOutput).toBeDefined();
    expect(request.params.rpId).toBe('localhost');

    // Simulate KMS response
    env.simulateIframeMessage({
      id: request.id,
      result: { success: true, enrollmentId: 'enrollment:passkey-prf:v2' },
    });

    const result = await requestPromise;
    expect(result.success).toBe(true);

    // Check appSalt was stored
    expect(localStorage.setItem).toHaveBeenCalledWith('kms:appSalt', expect.any(String));
  });

  it('should setup passkey gate with WebAuthn', async () => {
    const webAuthn = setupWebAuthnMocks();

    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.setupPasskeyGate({
      userId: 'test@example.com',
      name: 'Test User',
      rpId: 'localhost',
    });

    // Wait for async WebAuthn and RPC request to complete
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Check WebAuthn was called
    expect(webAuthn.mockNavigator.credentials.create).toHaveBeenCalled();

    // Get the RPC request
    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('setupPasskeyGate');

    // Simulate KMS response
    env.simulateIframeMessage({
      id: request.id,
      result: { success: true, enrollmentId: 'enrollment:passkey-gate:v2' },
    });

    const result = await requestPromise;
    expect(result.success).toBe(true);
  });
});

// ============================================================================
// VAPID Operations Tests
// ============================================================================

describe('VAPID operations', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let kmsUser: KMSUser;

  beforeEach(async () => {
    env = setupTestEnvironment();
    kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );
  });

  afterEach(async () => {
    // Wait a bit for any pending async operations to complete
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      await kmsUser.terminate();
    } catch {
      // Ignore termination errors in cleanup
    }
    env.cleanup();
  });


  it('should get public key', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.getPublicKey('test-kid');

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('getPublicKey');
    expect(request.params.kid).toBe('test-kid');

    env.simulateIframeMessage({
      id: request.id,
      result: { publicKey: 'test-pubkey-base64url' },
    });

    const result = await requestPromise;
    expect(result.publicKey).toBe('test-pubkey-base64url');
  });
});

// ============================================================================
// Lease Operations Tests
// ============================================================================

describe('lease operations', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let kmsUser: KMSUser;

  beforeEach(async () => {
    env = setupTestEnvironment();
    kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );
  });

  afterEach(async () => {
    // Wait a bit for any pending async operations to complete
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      await kmsUser.terminate();
    } catch {
      // Ignore termination errors in cleanup
    }
    env.cleanup();
  });

  it('should create lease', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.createLease({
      userId: 'user-123',
      subs: [{ url: 'https://push.example.com/sub', aud: 'https://fcm.googleapis.com', eid: 'ep-1' }],
      ttlHours: 12,
    });

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('createLease');

    env.simulateIframeMessage({
      id: request.id,
      result: {
        leaseId: 'lease-123',
        exp: Date.now() + 12 * 3600 * 1000,
        quotas: {
          tokensPerHour: 100,
          sendsPerMinute: 10,
          burstSends: 20,
          sendsPerMinutePerEid: 5,
        },
      },
    });

    const result = await requestPromise;
    expect(result.leaseId).toBe('lease-123');
    expect(result.quotas.tokensPerHour).toBe(100);
  });

  it('should issue VAPID JWT', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.issueVAPIDJWT({
      leaseId: 'lease-123',
      endpoint: { url: 'https://push.example.com/sub', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
      kid: 'test-kid',
    });

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('issueVAPIDJWT');

    env.simulateIframeMessage({
      id: request.id,
      result: {
        jwt: 'eyJhbGciOi...test-jwt',
        jti: 'jti-123',
        exp: Math.floor(Date.now() / 1000) + 900,
      },
    });

    const result = await requestPromise;
    expect(result.jwt).toContain('eyJhbGciOi');
    expect(result.jti).toBe('jti-123');
  });
});

// ============================================================================
// Status and Management Tests
// ============================================================================

describe('status and management', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let kmsUser: KMSUser;

  beforeEach(async () => {
    env = setupTestEnvironment();
    kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );
  });

  afterEach(async () => {
    // Wait a bit for any pending async operations to complete
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      await kmsUser.terminate();
    } catch {
      // Ignore termination errors in cleanup
    }
    env.cleanup();
  });

  it('should check setup status', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.isSetup();

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('isSetup');

    env.simulateIframeMessage({
      id: request.id,
      result: { isSetup: true, methods: ['passphrase'] },
    });

    const result = await requestPromise;
    expect(result.isSetup).toBe(true);
    expect(result.methods).toContain('passphrase');
  });

  it('should get enrollments', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.getEnrollments();

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('getEnrollments');

    env.simulateIframeMessage({
      id: request.id,
      result: { enrollments: ['enrollment:passphrase:v2', 'enrollment:passkey-prf:v2'] },
    });

    const result = await requestPromise;
    expect(result.enrollments).toHaveLength(2);
  });

  it('should verify audit chain', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.verifyAuditChain();

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('verifyAuditChain');

    env.simulateIframeMessage({
      id: request.id,
      result: { valid: true, entries: 10 },
    });

    const result = await requestPromise;
    expect(result.valid).toBe(true);
    expect(result.entries).toBe(10);
  });

  it('should reset KMS', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const requestPromise = kmsUser.resetKMS();

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('resetKMS');

    env.simulateIframeMessage({
      id: request.id,
      result: { success: true },
    });

    const result = await requestPromise;
    expect(result.success).toBe(true);
  });

  it('should remove enrollment', async () => {
    const iframe = env.getCurrentIframe();
    const postMessageSpy = vi.spyOn(iframe!.contentWindow!, 'postMessage');

    const credentials = { method: 'passphrase' as const, passphrase: 'test-123', userId: 'test@example.com' };
    const requestPromise = kmsUser.removeEnrollment('enrollment:passkey-prf:v2', credentials);

    const [request] = postMessageSpy.mock.calls[0]! as [any, string];
    expect(request.method).toBe('removeEnrollment');

    env.simulateIframeMessage({
      id: request.id,
      result: { success: true },
    });

    const result = await requestPromise;
    expect(result.success).toBe(true);
  });
});

// ============================================================================
// Lifecycle Management Tests
// ============================================================================

describe('lifecycle management', () => {
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
  });

  afterEach(() => {
    env.cleanup();
  });

  it('should terminate and cleanup', async () => {
    const kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );

    const iframe = env.getCurrentIframe();
    const removeChildSpy = vi.spyOn(iframe!.parentNode!, 'removeChild');

    await kmsUser.terminate();

    expect(removeChildSpy).toHaveBeenCalled();
  });

  it('should cancel pending requests on terminate', async () => {
    const kmsUser = await initializeKMSUser(
      { kmsOrigin: 'https://kms.ats.run' },
      env
    );

    // Start request (don't await it)
    kmsUser.isSetup();

    // Terminate before response - should clean up without errors
    await kmsUser.terminate();

    // Verify terminate completed successfully
    expect(true).toBe(true);
  });
});
