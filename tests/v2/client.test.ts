/**
 * Tests for KMS V2 Client Bridge
 *
 * Tests the iframe client that forwards messages between parent PWA and Worker.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { KMSClient, type KMSClientConfig } from '../../src/v2/client.js';
import type { RPCRequest, RPCResponse } from '../../src/v2/types.js';

// ============================================================================
// Test Utilities
// ============================================================================

/**
 * Mock Worker for testing
 *
 * Simulates a Dedicated Worker with message passing capabilities.
 */
class MockWorker implements Partial<Worker> {
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public onerror: ((event: ErrorEvent) => void) | null = null;
  public listeners: Map<string, Set<EventListener>> = new Map();

  constructor(
    public scriptURL: string | URL,
    public options?: WorkerOptions
  ) {}

  postMessage(_data: any): void {
    // Simulate async message processing
    setTimeout(() => {
      // In real Worker, this would process the message
      // For testing, we'll manually trigger responses in tests
    }, 0);
  }

  addEventListener(type: string, listener: EventListener): void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, new Set());
    }
    this.listeners.get(type)!.add(listener);

    // Also set on* property for compatibility
    if (type === 'message') {
      this.onmessage = listener as any;
    } else if (type === 'error') {
      this.onerror = listener as any;
    }
  }

  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  terminate(): void {
    this.listeners.clear();
  }

  // Test helper: Simulate Worker sending a message
  simulateMessage(data: any): void {
    const listeners = this.listeners.get('message');
    if (listeners) {
      const event = new MessageEvent('message', { data });
      listeners.forEach((listener) => listener(event as any));
    }
  }

  // Test helper: Simulate Worker error
  simulateError(message: string): void {
    const listeners = this.listeners.get('error');
    if (listeners) {
      const event = new ErrorEvent('error', { message });
      listeners.forEach((listener) => listener(event as any));
    }
  }
}

/**
 * Mock window.parent for testing
 */
class MockParentWindow {
  public receivedMessages: any[] = [];

  postMessage(data: any, targetOrigin: string): void {
    this.receivedMessages.push({ data, targetOrigin });
  }

  getLastMessage(): any {
    return this.receivedMessages[this.receivedMessages.length - 1];
  }

  clearMessages(): void {
    this.receivedMessages = [];
  }
}

/**
 * Setup test environment with mocks
 */
function setupTestEnvironment() {
  const mockParent = new MockParentWindow();
  let mockWorker: MockWorker | null = null;

  // Mock global Worker constructor
  const OriginalWorker = global.Worker;
  (global as any).Worker = vi.fn((scriptURL: string | URL, options?: WorkerOptions) => {
    mockWorker = new MockWorker(scriptURL, options);
    return mockWorker;
  });

  // Mock window.parent
  if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'parent', {
      writable: true,
      value: mockParent,
    });
  }

  const cleanup = () => {
    (global as any).Worker = OriginalWorker;
    mockWorker = null;
  };

  return { mockParent, getMockWorker: () => mockWorker, cleanup };
}

/**
 * Create test RPC request
 */
function createRequest(method: string, params?: any): RPCRequest {
  return {
    id: `test-${Date.now()}-${Math.random()}`,
    method: method as any,
    params: params ?? {},
  };
}

/**
 * Simulate parent sending message to iframe
 */
function simulateParentMessage(_client: any, data: any, origin: string = 'https://allthe.services') {
  const event = new MessageEvent('message', {
    data,
    origin,
    source: window.parent as any,
  });

  // Trigger the handleParentMessage method
  window.dispatchEvent(event);
}

// ============================================================================
// Client Initialization Tests
// ============================================================================

describe('KMSClient initialization', () => {
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
  });

  afterEach(() => {
    env.cleanup();
  });

  it('should create client with config', () => {
    const config: KMSClientConfig = {
      parentOrigin: 'https://allthe.services',
    };

    const client = new KMSClient(config);
    expect(client).toBeDefined();
  });

  it('should initialize worker successfully', async () => {
    const config: KMSClientConfig = {
      parentOrigin: 'https://allthe.services',
      workerUrl: '/test-worker.js',
    };

    const client = new KMSClient(config);
    await client.init();

    const worker = env.getMockWorker();
    expect(worker).toBeDefined();
    expect(worker?.scriptURL).toBe('/test-worker.js');
    expect(worker?.options?.type).toBe('module');
    expect(worker?.options?.name).toBe('kms-worker-v2');
  });

  it('should send ready signal to parent after init', async () => {
    const config: KMSClientConfig = {
      parentOrigin: 'https://allthe.services',
    };

    const client = new KMSClient(config);
    await client.init();

    const lastMessage = env.mockParent.getLastMessage();
    expect(lastMessage).toBeDefined();
    expect(lastMessage.data).toEqual({ type: 'kms:ready' });
    expect(lastMessage.targetOrigin).toBe('https://allthe.services');
  });

  it('should throw error if already initialized', async () => {
    const config: KMSClientConfig = {
      parentOrigin: 'https://allthe.services',
    };

    const client = new KMSClient(config);
    await client.init();

    await expect(client.init()).rejects.toThrow('already initialized');
  });

  it('should setup message event listeners', async () => {
    const config: KMSClientConfig = {
      parentOrigin: 'https://allthe.services',
    };

    const client = new KMSClient(config);
    await client.init();

    const worker = env.getMockWorker();
    expect(worker?.listeners.get('message')?.size).toBeGreaterThan(0);
    expect(worker?.listeners.get('error')?.size).toBeGreaterThan(0);
  });
});

// ============================================================================
// Message Forwarding Tests
// ============================================================================

describe('message forwarding', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let client: KMSClient;

  beforeEach(async () => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
    env.mockParent.clearMessages();
  });

  afterEach(async () => {
    await client.terminate();
    env.cleanup();
  });

  it('should forward message from parent to worker', () => {
    const request = createRequest('isSetup');
    const worker = env.getMockWorker();

    // Spy on worker.postMessage
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    // Simulate parent sending message
    simulateParentMessage(client, request);

    expect(postMessageSpy).toHaveBeenCalledWith(request);
  });

  it('should forward response from worker to parent', () => {
    const response: RPCResponse = {
      id: 'test-123',
      result: { isSetup: true, methods: ['passphrase'] },
    };

    const worker = env.getMockWorker();

    // Simulate worker sending response
    worker!.simulateMessage(response);

    // Check parent received the response
    const lastMessage = env.mockParent.getLastMessage();
    expect(lastMessage.data).toEqual(response);
    expect(lastMessage.targetOrigin).toBe('https://allthe.services');
  });

  it('should handle bidirectional message flow', () => {
    const request = createRequest('setupPassphrase', { passphrase: 'test-123' });
    const response: RPCResponse = {
      id: request.id,
      result: { success: true, enrollmentId: 'enrollment:passphrase:v2' },
    };

    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    // Parent sends request
    simulateParentMessage(client, request);
    expect(postMessageSpy).toHaveBeenCalledWith(request);

    // Worker sends response
    env.mockParent.clearMessages();
    worker!.simulateMessage(response);

    // Check parent received response
    const lastMessage = env.mockParent.getLastMessage();
    expect(lastMessage.data).toEqual(response);
  });
});

// ============================================================================
// Origin Validation Tests
// ============================================================================

describe('origin validation', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let client: KMSClient;

  beforeEach(async () => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
  });

  afterEach(async () => {
    await client.terminate();
    env.cleanup();
  });

  it('should accept messages from configured parent origin', () => {
    const request = createRequest('isSetup');
    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    simulateParentMessage(client, request, 'https://allthe.services');

    expect(postMessageSpy).toHaveBeenCalledWith(request);
  });

  it('should reject messages from invalid origin', () => {
    const request = createRequest('isSetup');
    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    // Try to send from malicious origin
    simulateParentMessage(client, request, 'https://evil.com');

    // Worker should NOT receive the message
    expect(postMessageSpy).not.toHaveBeenCalled();
  });

  it('should reject messages from localhost when expecting production origin', () => {
    const request = createRequest('isSetup');
    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    simulateParentMessage(client, request, 'http://localhost:3000');

    expect(postMessageSpy).not.toHaveBeenCalled();
  });

  it('should accept messages from localhost when configured', async () => {
    await client.terminate();

    // Create new client with localhost origin
    const localhostClient = new KMSClient({
      parentOrigin: 'http://localhost:3000',
    });
    await localhostClient.init();

    const request = createRequest('isSetup');
    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    simulateParentMessage(localhostClient, request, 'http://localhost:3000');

    expect(postMessageSpy).toHaveBeenCalledWith(request);

    await localhostClient.terminate();
  });
});

// ============================================================================
// Error Handling Tests
// ============================================================================

describe('error handling', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let client: KMSClient;

  beforeEach(async () => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
    env.mockParent.clearMessages();
  });

  afterEach(async () => {
    await client.terminate();
    env.cleanup();
  });

  it('should handle worker errors gracefully', () => {
    const worker = env.getMockWorker();
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Simulate worker error
    worker!.simulateError('Test error');

    expect(consoleErrorSpy).toHaveBeenCalled();
    consoleErrorSpy.mockRestore();
  });

  it('should not forward messages before initialization', async () => {
    const uninitializedClient = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });

    const request = createRequest('isSetup');
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Try to send message before init
    simulateParentMessage(uninitializedClient, request);

    expect(consoleErrorSpy).toHaveBeenCalled();
    consoleErrorSpy.mockRestore();
  });

  it('should log warning for invalid origin', () => {
    const request = createRequest('isSetup');
    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    simulateParentMessage(client, request, 'https://evil.com');

    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining('invalid origin'),
      expect.objectContaining({
        expected: 'https://allthe.services',
        received: 'https://evil.com',
      })
    );

    consoleWarnSpy.mockRestore();
  });

  it('should handle worker postMessage failure gracefully', () => {
    const request = createRequest('isSetup');
    const worker = env.getMockWorker();
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Make worker.postMessage throw an error
    vi.spyOn(worker!, 'postMessage').mockImplementation(() => {
      throw new Error('postMessage failed');
    });

    // Should not throw, should log error and send error response to parent
    simulateParentMessage(client, request);

    expect(consoleErrorSpy).toHaveBeenCalled();

    // Should send error response to parent
    const lastMessage = env.mockParent.getLastMessage();
    expect(lastMessage.data.id).toBe(request.id);
    expect(lastMessage.data.error).toContain('Failed to forward message');

    consoleErrorSpy.mockRestore();
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

  it('should terminate worker successfully', async () => {
    const client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();

    const worker = env.getMockWorker();
    const terminateSpy = vi.spyOn(worker!, 'terminate');

    await client.terminate();

    expect(terminateSpy).toHaveBeenCalled();
  });

  it('should handle terminate when not initialized', async () => {
    const client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });

    // Should not throw
    await expect(client.terminate()).resolves.toBeUndefined();
  });

  it('should allow re-initialization after terminate', async () => {
    const client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
    await client.terminate();

    // Should be able to init again
    await expect(client.init()).resolves.toBeUndefined();

    await client.terminate();
  });
});

// ============================================================================
// Legacy API Compatibility Tests
// ============================================================================

describe('legacy send() API', () => {
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
  });

  afterEach(() => {
    env.cleanup();
  });

  it('should work in Node.js environment (for testing)', async () => {
    const client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });

    const request = createRequest('isSetup');
    const response = await client.send(request);

    expect(response.id).toBe(request.id);
    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
  });
});

// ============================================================================
// Authentication Interception Tests
// ============================================================================

describe('authentication interception', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let client: KMSClient;

  beforeEach(async () => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
    env.mockParent.clearMessages();
  });

  afterEach(async () => {
    await client.terminate();
    env.cleanup();
  });

  const authRequiredMethods = ['createLease', 'generateVAPID', 'signJWT', 'regenerateVAPID', 'addEnrollment'];

  authRequiredMethods.forEach((method) => {
    it(`should intercept ${method} and not forward to worker immediately`, () => {
      const request = createRequest(method, { userId: 'test-user' });
      const worker = env.getMockWorker();
      const postMessageSpy = vi.spyOn(worker!, 'postMessage');

      // Simulate parent sending auth-required request
      simulateParentMessage(client, request);

      // Should NOT be forwarded to worker immediately (modal shown instead)
      expect(postMessageSpy).not.toHaveBeenCalled();
    });
  });

  it('should forward non-auth-required methods immediately', () => {
    const nonAuthMethods = ['isSetup', 'getEnrollments', 'verifyAuditChain', 'getAuditLog'];

    nonAuthMethods.forEach((method) => {
      const request = createRequest(method);
      const worker = env.getMockWorker();
      const postMessageSpy = vi.spyOn(worker!, 'postMessage');

      simulateParentMessage(client, request);

      expect(postMessageSpy).toHaveBeenCalledWith(request);
    });
  });
});

// ============================================================================
// Setup With Popup Flow Tests
// ============================================================================

describe('setupWithPopup flow', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let client: KMSClient;

  beforeEach(async () => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
    env.mockParent.clearMessages();
  });

  afterEach(async () => {
    await client.terminate();
    env.cleanup();
  });

  it('should handle worker:setup-with-popup message and request parent to open popup', () => {
    const setupMessage = {
      type: 'worker:setup-with-popup',
      requestId: 'test-request-123',
      userId: 'test@example.com',
      popupURL: 'https://kms.ats.run/?mode=setup',
      transportKey: 'test-transport-key',
      transportKeyId: 'test-key-id',
      appSalt: 'test-app-salt',
      hkdfSalt: 'test-hkdf-salt',
    };

    const worker = env.getMockWorker();
    worker!.simulateMessage(setupMessage);

    // Should send kms:request-popup to parent
    const lastMessage = env.mockParent.getLastMessage();
    expect(lastMessage).toBeDefined();
    expect(lastMessage.data).toMatchObject({
      type: 'kms:request-popup',
      requestId: 'test-request-123',
    });
    expect(lastMessage.data.url).toContain('https://kms.ats.run/?mode=setup');
    expect(lastMessage.data.url).toContain('parentOrigin=');
  });

  it('should add parentOrigin to popup URL', () => {
    const setupMessage = {
      type: 'worker:setup-with-popup',
      requestId: 'test-request-123',
      userId: 'test@example.com',
      popupURL: 'https://kms.ats.run/?mode=setup',
      transportKey: 'test-transport-key',
      transportKeyId: 'test-key-id',
      appSalt: 'test-app-salt',
      hkdfSalt: 'test-hkdf-salt',
    };

    const worker = env.getMockWorker();
    worker!.simulateMessage(setupMessage);

    const lastMessage = env.mockParent.getLastMessage();
    const popupURL = new URL(lastMessage.data.url);
    expect(popupURL.searchParams.get('parentOrigin')).toBe('https://allthe.services');
  });

  it('should send worker:popup-error if parent window not available', () => {
    // Mock window.parent to be same as window (not in iframe)
    Object.defineProperty(window, 'parent', {
      writable: true,
      configurable: true,
      value: window,
    });

    const setupMessage = {
      type: 'worker:setup-with-popup',
      requestId: 'test-request-123',
      userId: 'test@example.com',
      popupURL: 'https://kms.ats.run/?mode=setup',
      transportKey: 'test-transport-key',
      transportKeyId: 'test-key-id',
      appSalt: 'test-app-salt',
      hkdfSalt: 'test-hkdf-salt',
    };

    const worker = env.getMockWorker();
    const workerPostSpy = vi.spyOn(worker!, 'postMessage');
    worker!.simulateMessage(setupMessage);

    // Should send error back to worker
    const errorMessage = workerPostSpy.mock.calls.find(
      call => call[0]?.type === 'worker:popup-error'
    );
    expect(errorMessage).toBeDefined();
    expect(errorMessage![0]).toMatchObject({
      type: 'worker:popup-error',
      requestId: 'test-request-123',
      reason: expect.stringContaining('parent window'),
    });

    workerPostSpy.mockRestore();
  });

  it('should send worker:popup-error if parentOrigin not configured', async () => {
    // Create client without parentOrigin
    await client.terminate();
    const clientWithoutOrigin = new KMSClient({
      parentOrigin: '',
    });
    await clientWithoutOrigin.init();

    const setupMessage = {
      type: 'worker:setup-with-popup',
      requestId: 'test-request-123',
      userId: 'test@example.com',
      popupURL: 'https://kms.ats.run/?mode=setup',
      transportKey: 'test-transport-key',
      transportKeyId: 'test-key-id',
      appSalt: 'test-app-salt',
      hkdfSalt: 'test-hkdf-salt',
    };

    const worker = env.getMockWorker();
    const workerPostSpy = vi.spyOn(worker!, 'postMessage');
    worker!.simulateMessage(setupMessage);

    // Should send error back to worker
    const errorMessage = workerPostSpy.mock.calls.find(
      call => call[0]?.type === 'worker:popup-error'
    );
    expect(errorMessage).toBeDefined();
    expect(errorMessage![0]).toMatchObject({
      type: 'worker:popup-error',
      requestId: 'test-request-123',
      reason: expect.stringContaining('origin'),
    });

    workerPostSpy.mockRestore();
    await clientWithoutOrigin.terminate();
  });

  it('should not send transport params in popup URL', () => {
    const setupMessage = {
      type: 'worker:setup-with-popup',
      requestId: 'test-request-123',
      userId: 'test@example.com',
      popupURL: 'https://kms.ats.run/?mode=setup',
      transportKey: 'test-transport-key',
      transportKeyId: 'test-key-id',
      appSalt: 'test-app-salt',
      hkdfSalt: 'test-hkdf-salt',
    };

    const worker = env.getMockWorker();
    worker!.simulateMessage(setupMessage);

    // Check popup URL doesn't contain sensitive params
    const lastMessage = env.mockParent.getLastMessage();
    const popupURL = new URL(lastMessage.data.url);

    expect(popupURL.searchParams.has('transportKey')).toBe(false);
    expect(popupURL.searchParams.has('transportKeyId')).toBe(false);
    expect(popupURL.searchParams.has('appSalt')).toBe(false);
    expect(popupURL.searchParams.has('hkdfSalt')).toBe(false);
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('client integration', () => {
  let env: ReturnType<typeof setupTestEnvironment>;
  let client: KMSClient;

  beforeEach(async () => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
    await client.init();
    env.mockParent.clearMessages();
  });

  afterEach(async () => {
    await client.terminate();
    env.cleanup();
  });

  it('should handle complete request/response cycle', () => {
    const request = createRequest('setupPassphrase', { passphrase: 'test-passphrase-123' });
    const worker = env.getMockWorker();

    // Parent sends request
    simulateParentMessage(client, request);

    // Worker processes and sends response (simulated)
    const response: RPCResponse = {
      id: request.id,
      result: { success: true, enrollmentId: 'enrollment:passphrase:v2' },
    };
    worker!.simulateMessage(response);

    // Check parent received response
    const lastMessage = env.mockParent.getLastMessage();
    expect(lastMessage.data).toEqual(response);
  });

  it('should handle multiple concurrent requests', () => {
    const request1 = createRequest('isSetup');
    const request2 = createRequest('getEnrollments');
    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    // Send multiple requests
    simulateParentMessage(client, request1);
    simulateParentMessage(client, request2);

    expect(postMessageSpy).toHaveBeenCalledTimes(2);
    expect(postMessageSpy).toHaveBeenNthCalledWith(1, request1);
    expect(postMessageSpy).toHaveBeenNthCalledWith(2, request2);
  });

  it('should maintain origin validation across multiple messages', () => {
    const request1 = createRequest('isSetup');
    const request2 = createRequest('getEnrollments');
    const worker = env.getMockWorker();
    const postMessageSpy = vi.spyOn(worker!, 'postMessage');

    // Valid message
    simulateParentMessage(client, request1, 'https://allthe.services');

    // Invalid message
    simulateParentMessage(client, request2, 'https://evil.com');

    // Only valid message should be forwarded
    expect(postMessageSpy).toHaveBeenCalledTimes(1);
    expect(postMessageSpy).toHaveBeenCalledWith(request1);
  });
});
