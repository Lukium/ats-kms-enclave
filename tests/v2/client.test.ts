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

  const authRequiredMethods = [
    'createLease',
    'generateVAPID',
    'signJWT',
    'regenerateVAPID',
    'addEnrollment',
    'setupMessaging',
    'provisionMessaging',
    'setupAccountRoot',
    'openMessaging',
  ];

  // Messaging methods route to the top-level popup, which first makes a
  // getMessagingUnlockOptions worker round-trip; the ORIGINAL request must still
  // not be forwarded to the worker until credentials are collected.
  const messagingUnlockMethods = [
    'setupMessaging',
    'provisionMessaging',
    'setupAccountRoot',
    'openMessaging',
  ];

  authRequiredMethods.forEach((method) => {
    it(`should intercept ${method} and not forward the request to worker immediately`, () => {
      const request = createRequest(method, { userId: 'test-user' });
      const worker = env.getMockWorker();
      const postMessageSpy = vi.spyOn(worker!, 'postMessage');

      // Simulate parent sending auth-required request
      simulateParentMessage(client, request);

      if (messagingUnlockMethods.includes(method)) {
        // Popup flow: a getMessagingUnlockOptions RPC may be sent, but never the
        // original auth-required request.
        expect(postMessageSpy).not.toHaveBeenCalledWith(request);
      } else {
        // Iframe modal flow: nothing forwarded to the worker at all.
        expect(postMessageSpy).not.toHaveBeenCalled();
      }
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

// ============================================================================
// Setup UI Helper Functions
// ============================================================================

describe('setup UI helpers', () => {
  let client: KMSClient;
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('showSetupError', () => {
    it('should display error message and remove hidden class', () => {
      const errorDiv = document.createElement('div');
      errorDiv.id = 'kms-setup-error';
      errorDiv.classList.add('hidden');
      document.body.appendChild(errorDiv);

      // Access private method via any cast
      (client as any).showSetupError('Test error message');

      expect(errorDiv.textContent).toBe('Test error message');
      expect(errorDiv.classList.contains('hidden')).toBe(false);

      document.body.removeChild(errorDiv);
    });

    it('should handle missing error div gracefully', () => {
      // Should not throw when element doesn't exist
      expect(() => {
        (client as any).showSetupError('Test error');
      }).not.toThrow();
    });
  });

  describe('hideSetupError', () => {
    it('should add hidden class to error div', () => {
      const errorDiv = document.createElement('div');
      errorDiv.id = 'kms-setup-error';
      errorDiv.textContent = 'Some error';
      document.body.appendChild(errorDiv);

      (client as any).hideSetupError();

      expect(errorDiv.classList.contains('hidden')).toBe(true);

      document.body.removeChild(errorDiv);
    });

    it('should handle missing error div gracefully', () => {
      expect(() => {
        (client as any).hideSetupError();
      }).not.toThrow();
    });
  });

  describe('showSetupLoading', () => {
    it('should remove hidden class from loading div', () => {
      const loadingDiv = document.createElement('div');
      loadingDiv.id = 'kms-setup-loading';
      loadingDiv.classList.add('hidden');
      document.body.appendChild(loadingDiv);

      (client as any).showSetupLoading();

      expect(loadingDiv.classList.contains('hidden')).toBe(false);

      document.body.removeChild(loadingDiv);
    });

    it('should handle missing loading div gracefully', () => {
      expect(() => {
        (client as any).showSetupLoading();
      }).not.toThrow();
    });
  });

  describe('hideSetupLoading', () => {
    it('should add hidden class to loading div', () => {
      const loadingDiv = document.createElement('div');
      loadingDiv.id = 'kms-setup-loading';
      document.body.appendChild(loadingDiv);

      (client as any).hideSetupLoading();

      expect(loadingDiv.classList.contains('hidden')).toBe(true);

      document.body.removeChild(loadingDiv);
    });

    it('should handle missing loading div gracefully', () => {
      expect(() => {
        (client as any).hideSetupLoading();
      }).not.toThrow();
    });
  });

  describe('showSetupSuccess', () => {
    it('should remove hidden class from success div and append the auto-close footer', () => {
      // Disable auto-close so no countdown timer leaks from this sync test.
      localStorage.setItem('kms:autoclose', '0');
      const successDiv = document.createElement('div');
      successDiv.id = 'kms-setup-success';
      successDiv.classList.add('hidden');
      document.body.appendChild(successDiv);

      (client as any).showSetupSuccess();

      expect(successDiv.classList.contains('hidden')).toBe(false);
      expect(successDiv.querySelector('.kms-popup-close')).not.toBeNull();

      document.body.removeChild(successDiv);
      localStorage.removeItem('kms:autoclose');
    });

    it('should handle missing success div gracefully', () => {
      expect(() => {
        (client as any).showSetupSuccess();
      }).not.toThrow();
    });
  });

  describe('hideSetupSuccess', () => {
    it('should add hidden class to success div', () => {
      const successDiv = document.createElement('div');
      successDiv.id = 'kms-setup-success';
      document.body.appendChild(successDiv);

      (client as any).hideSetupSuccess();

      expect(successDiv.classList.contains('hidden')).toBe(true);

      document.body.removeChild(successDiv);
    });

    it('should handle missing success div gracefully', () => {
      expect(() => {
        (client as any).hideSetupSuccess();
      }).not.toThrow();
    });
  });
});

// ============================================================================
// Popup auto-close footer + unlock success + method visibility (BUG-011 UX)
// ============================================================================

describe('popup unlock UX (BUG-011)', () => {
  let client: KMSClient;
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
    client = new KMSClient({ parentOrigin: 'https://allthe.services' });
    localStorage.removeItem('kms:autoclose');
    document.body.innerHTML = ''; // isolate DOM (avoid duplicate-id bleed between tests)
  });

  afterEach(() => {
    document.body.innerHTML = '';
    localStorage.removeItem('kms:autoclose');
    vi.useRealTimers();
    env.cleanup();
  });

  /** Build the unlock modal DOM (blocks + success panel) the client expects. */
  function buildUnlockModal(): HTMLElement {
    const modal = document.createElement('div');
    modal.id = 'unlock-modal';
    modal.innerHTML = `
      <div class="kms-modal-body">
        <div class="kms-auth-option" id="kms-unlock-passkey-option">
          <button id="kms-webauthn-btn"></button>
        </div>
        <div class="kms-divider" id="kms-unlock-divider"><span>or</span></div>
        <div class="kms-auth-option" id="kms-unlock-passphrase-option">
          <form id="kms-unlock-form">
            <input id="kms-passphrase-input" />
            <button id="kms-passphrase-btn"></button>
          </form>
        </div>
        <div id="kms-modal-error" class="hidden"></div>
        <div id="kms-modal-loading" class="hidden"></div>
        <div id="kms-unlock-success" class="hidden">
          <div class="kms-success-content"></div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    return modal;
  }

  describe('renderPopupClose', () => {
    it('auto-closes after the countdown when the flag is on (default)', () => {
      vi.useFakeTimers();
      const closeSpy = vi.spyOn(window, 'close').mockImplementation(() => {});
      const container = document.createElement('div');

      (client as any).renderPopupClose(container, { countdown: true });

      // Footer + checkbox rendered, checkbox reflects the default-on state.
      const checkbox = container.querySelector('.kms-autoclose-checkbox') as HTMLInputElement;
      expect(checkbox).not.toBeNull();
      expect(checkbox.checked).toBe(true);

      // Not closed before the countdown elapses; closed after 2s.
      vi.advanceTimersByTime(1000);
      expect(closeSpy).not.toHaveBeenCalled();
      vi.advanceTimersByTime(1000);
      expect(closeSpy).toHaveBeenCalledTimes(1);
    });

    it('does not start a countdown when the flag is off', () => {
      vi.useFakeTimers();
      const closeSpy = vi.spyOn(window, 'close').mockImplementation(() => {});
      localStorage.setItem('kms:autoclose', '0');
      const container = document.createElement('div');

      (client as any).renderPopupClose(container, { countdown: true });

      const checkbox = container.querySelector('.kms-autoclose-checkbox') as HTMLInputElement;
      expect(checkbox.checked).toBe(false);
      vi.advanceTimersByTime(5000);
      expect(closeSpy).not.toHaveBeenCalled();
    });

    it('"Close now" closes immediately', () => {
      const closeSpy = vi.spyOn(window, 'close').mockImplementation(() => {});
      localStorage.setItem('kms:autoclose', '0'); // avoid a background timer
      const container = document.createElement('div');

      (client as any).renderPopupClose(container, { countdown: true });
      (container.querySelector('.kms-popup-close-btn') as HTMLButtonElement).click();

      expect(closeSpy).toHaveBeenCalledTimes(1);
    });

    it('toggling the checkbox persists to localStorage and starts/stops the countdown', () => {
      vi.useFakeTimers();
      const closeSpy = vi.spyOn(window, 'close').mockImplementation(() => {});
      localStorage.setItem('kms:autoclose', '0');
      const container = document.createElement('div');
      (client as any).renderPopupClose(container, { countdown: true });

      const checkbox = container.querySelector('.kms-autoclose-checkbox') as HTMLInputElement;
      // Enable → persists '1' and starts a countdown that closes.
      checkbox.checked = true;
      checkbox.dispatchEvent(new Event('change'));
      expect(localStorage.getItem('kms:autoclose')).toBe('1');
      // Disable mid-countdown → persists '0' and cancels the close.
      checkbox.checked = false;
      checkbox.dispatchEvent(new Event('change'));
      expect(localStorage.getItem('kms:autoclose')).toBe('0');
      vi.advanceTimersByTime(5000);
      expect(closeSpy).not.toHaveBeenCalled();
    });
  });

  describe('showUnlockSuccess / handlePopupUnlockResult', () => {
    it('reveals the success panel and hides the auth options + divider', () => {
      localStorage.setItem('kms:autoclose', '0');
      buildUnlockModal();

      client.showUnlockSuccess();

      expect((document.getElementById('kms-unlock-success') as HTMLElement).classList.contains('hidden')).toBe(false);
      expect((document.getElementById('kms-unlock-passkey-option') as HTMLElement).style.display).toBe('none');
      expect((document.getElementById('kms-unlock-divider') as HTMLElement).style.display).toBe('none');
      expect((document.getElementById('kms-unlock-passphrase-option') as HTMLElement).style.display).toBe('none');
    });

    it('on failure shows the error and does not reveal success', () => {
      buildUnlockModal();

      client.handlePopupUnlockResult(false, 'decryption failed');

      const err = document.getElementById('kms-modal-error') as HTMLElement;
      expect(err.textContent).toContain('decryption failed');
      expect(err.classList.contains('hidden')).toBe(false);
      expect((document.getElementById('kms-unlock-success') as HTMLElement).classList.contains('hidden')).toBe(true);
    });
  });

  describe('setupPopupUnlockModal method visibility', () => {
    beforeEach(() => {
      buildUnlockModal();
      (client as any).credentialPort = { postMessage: vi.fn() };
    });

    it('hides the passphrase block AND the divider when there is no passphrase', () => {
      client.setupPopupUnlockModal({ hasPassphrase: false, hasPasskeyPrf: true, hasPasskeyGate: false });
      expect((document.getElementById('kms-unlock-passphrase-option') as HTMLElement).style.display).toBe('none');
      expect((document.getElementById('kms-unlock-divider') as HTMLElement).style.display).toBe('none');
      expect((document.getElementById('kms-unlock-passkey-option') as HTMLElement).style.display).not.toBe('none');
    });

    it('hides the passkey block AND the divider when there is no passkey', () => {
      client.setupPopupUnlockModal({ hasPassphrase: true, hasPasskeyPrf: false, hasPasskeyGate: false });
      expect((document.getElementById('kms-unlock-passkey-option') as HTMLElement).style.display).toBe('none');
      expect((document.getElementById('kms-unlock-divider') as HTMLElement).style.display).toBe('none');
      expect((document.getElementById('kms-unlock-passphrase-option') as HTMLElement).style.display).not.toBe('none');
    });

    it('shows the divider only when BOTH methods are offered', () => {
      client.setupPopupUnlockModal({ hasPassphrase: true, hasPasskeyPrf: true, hasPasskeyGate: false });
      expect((document.getElementById('kms-unlock-divider') as HTMLElement).style.display).not.toBe('none');
    });
  });

  describe('recovery-phrase ceremony (BUG-007)', () => {
    const MNEMONIC = 'aa bb cc dd ee ff gg hh ii jj kk ll';
    const WORDS = MNEMONIC.split(' ');

    function buildMnemonicModal(): void {
      const unlock = document.createElement('div');
      unlock.id = 'unlock-modal';
      unlock.innerHTML = '<div class="kms-modal-body"><div id="kms-unlock-success" class="hidden"></div></div>';
      document.body.appendChild(unlock);

      const modal = document.createElement('div');
      modal.id = 'mnemonic-modal';
      modal.className = 'kms-modal hidden';
      modal.innerHTML = `
        <div id="kms-mnemonic-reveal">
          <ol id="kms-mnemonic-words"></ol>
          <button id="kms-mnemonic-copy"></button>
          <button id="kms-mnemonic-continue"></button>
          <button id="kms-mnemonic-cancel"></button>
        </div>
        <div id="kms-mnemonic-confirm" class="hidden">
          <div id="kms-mnemonic-confirm-grid"></div>
          <div id="kms-mnemonic-confirm-error" class="hidden"></div>
          <button id="kms-mnemonic-back"></button>
          <button id="kms-mnemonic-verify"></button>
        </div>
        <div id="kms-mnemonic-finishing" class="hidden"></div>`;
      document.body.appendChild(modal);
    }

    /** Read the required-word positions the ceremony highlighted (post-continue). */
    function requiredInputs(): { input: HTMLInputElement; pos: number }[] {
      const cells = Array.from(document.querySelectorAll('#kms-mnemonic-confirm-grid .kms-mnemonic-cell'));
      return cells
        .map((c, i) => ({ req: c.classList.contains('kms-required'), input: c.querySelector('input') as HTMLInputElement, pos: i }))
        .filter((x) => x.req)
        .map((x) => ({ input: x.input, pos: x.pos }));
    }

    let port: { postMessage: ReturnType<typeof vi.fn> };
    beforeEach(() => {
      buildMnemonicModal();
      port = { postMessage: vi.fn() };
      (client as any).credentialPort = port;
    });

    it('renders the 12 words on the reveal step and hides the confirm step', () => {
      client.showMnemonicCeremony(MNEMONIC);
      expect(document.getElementById('mnemonic-modal')!.classList.contains('hidden')).toBe(false);
      expect(document.querySelectorAll('#kms-mnemonic-words .kms-mnemonic-word')).toHaveLength(12);
      expect(document.getElementById('kms-mnemonic-confirm')!.classList.contains('hidden')).toBe(true);
    });

    it('cancels (persists nothing) when the user clicks Cancel', () => {
      client.showMnemonicCeremony(MNEMONIC);
      (document.getElementById('kms-mnemonic-cancel') as HTMLButtonElement).click();
      expect(port.postMessage).toHaveBeenCalledWith({ type: 'popup:mnemonic-cancelled' });
    });

    it('reveals a highlighted required subset on Continue', () => {
      client.showMnemonicCeremony(MNEMONIC);
      (document.getElementById('kms-mnemonic-continue') as HTMLButtonElement).click();
      expect(document.getElementById('kms-mnemonic-confirm')!.classList.contains('hidden')).toBe(false);
      expect(document.querySelectorAll('#kms-mnemonic-confirm-grid input')).toHaveLength(12);
      expect(requiredInputs().length).toBe(3);
    });

    it('confirms when the required words are entered correctly', () => {
      client.showMnemonicCeremony(MNEMONIC);
      (document.getElementById('kms-mnemonic-continue') as HTMLButtonElement).click();
      for (const { input, pos } of requiredInputs()) input.value = WORDS[pos]!;
      (document.getElementById('kms-mnemonic-verify') as HTMLButtonElement).click();
      expect(port.postMessage).toHaveBeenCalledWith({ type: 'popup:mnemonic-confirmed' });
      expect(document.getElementById('kms-mnemonic-finishing')!.classList.contains('hidden')).toBe(false);
    });

    it('rejects a wrong required word (no confirm posted)', () => {
      client.showMnemonicCeremony(MNEMONIC);
      (document.getElementById('kms-mnemonic-continue') as HTMLButtonElement).click();
      const reqs = requiredInputs();
      reqs.forEach(({ input, pos }, k) => (input.value = k === 0 ? 'WRONGWORD' : WORDS[pos]!));
      (document.getElementById('kms-mnemonic-verify') as HTMLButtonElement).click();
      expect(port.postMessage).not.toHaveBeenCalledWith({ type: 'popup:mnemonic-confirmed' });
      expect(document.getElementById('kms-mnemonic-confirm-error')!.classList.contains('hidden')).toBe(false);
      expect(reqs[0]!.input.classList.contains('kms-invalid')).toBe(true);
    });

    it('smart-paste distributes the whole phrase across all inputs', () => {
      client.showMnemonicCeremony(MNEMONIC);
      (document.getElementById('kms-mnemonic-continue') as HTMLButtonElement).click();
      const first = document.querySelector('#kms-mnemonic-confirm-grid input') as HTMLInputElement;
      const evt = new Event('paste') as unknown as ClipboardEvent;
      Object.defineProperty(evt, 'clipboardData', { value: { getData: () => MNEMONIC } });
      first.onpaste!(evt);
      const values = Array.from(document.querySelectorAll('#kms-mnemonic-confirm-grid input')).map(
        (i) => (i as HTMLInputElement).value
      );
      expect(values).toEqual(WORDS);
    });

    it('cancels when there is no port (worker persists nothing)', () => {
      (client as any).credentialPort = null;
      // Should not throw; nothing to post to.
      expect(() => client.showMnemonicCeremony(MNEMONIC)).not.toThrow();
    });
  });
});

// ============================================================================
// notifySetupComplete
// ============================================================================

describe('notifySetupComplete', () => {
  let client: KMSClient;
  let env: ReturnType<typeof setupTestEnvironment>;

  beforeEach(() => {
    env = setupTestEnvironment();
    client = new KMSClient({
      parentOrigin: 'https://allthe.services',
    });
  });

  afterEach(() => {
    env.cleanup();
    localStorage.clear();
  });

  it('should send message via window.opener if available', () => {
    const mockOpener = {
      postMessage: vi.fn(),
    };
    Object.defineProperty(window, 'opener', {
      value: mockOpener,
      writable: true,
      configurable: true,
    });

    const data = { method: 'setup', result: { success: true } };
    (client as any).notifySetupComplete(data);

    expect(mockOpener.postMessage).toHaveBeenCalledWith(
      {
        type: 'kms:setup-complete',
        method: 'setup',
        result: { success: true },
      },
      'https://allthe.services'
    );

    // Cleanup
    Object.defineProperty(window, 'opener', {
      value: null,
      writable: true,
      configurable: true,
    });
  });

  it('should set localStorage flag with timestamp', () => {
    const data = { method: 'setup', result: { enrollmentId: 'test-123' } };
    const beforeTime = Date.now();

    (client as any).notifySetupComplete(data);

    const stored = localStorage.getItem('kms:setup-complete');
    expect(stored).toBeTruthy();

    const parsed = JSON.parse(stored!);
    expect(parsed.type).toBe('kms:setup-complete');
    expect(parsed.method).toBe('setup');
    expect(parsed.result).toEqual({ enrollmentId: 'test-123' });
    expect(parsed.timestamp).toBeGreaterThanOrEqual(beforeTime);
    expect(parsed.timestamp).toBeLessThanOrEqual(Date.now());
  });

  it('should use BroadcastChannel if available', () => {
    const mockChannel = {
      postMessage: vi.fn(),
      close: vi.fn(),
    };

    // Mock BroadcastChannel constructor
    const OriginalBroadcastChannel = global.BroadcastChannel;
    global.BroadcastChannel = vi.fn().mockImplementation(() => mockChannel) as any;

    const data = { method: 'setup', result: { success: true } };
    (client as any).notifySetupComplete(data);

    expect(global.BroadcastChannel).toHaveBeenCalledWith('kms-setup');
    expect(mockChannel.postMessage).toHaveBeenCalledWith({
      type: 'kms:setup-complete',
      method: 'setup',
      result: { success: true },
    });
    expect(mockChannel.close).toHaveBeenCalled();

    // Restore
    global.BroadcastChannel = OriginalBroadcastChannel;
  });

  it('should handle localStorage errors gracefully', () => {
    // Mock localStorage.setItem to throw
    const originalSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = vi.fn().mockImplementation(() => {
      throw new Error('Storage quota exceeded');
    });

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const data = { method: 'setup', result: { success: true } };

    // Should not throw
    expect(() => {
      (client as any).notifySetupComplete(data);
    }).not.toThrow();

    expect(consoleWarnSpy).toHaveBeenCalledWith(
      '[KMS Client] Failed to set localStorage flag:',
      expect.any(Error)
    );

    // Restore
    Storage.prototype.setItem = originalSetItem;
    consoleWarnSpy.mockRestore();
  });

  it('should handle missing BroadcastChannel gracefully', () => {
    // Remove BroadcastChannel
    const OriginalBroadcastChannel = global.BroadcastChannel;
    (global as any).BroadcastChannel = undefined;

    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const data = { method: 'setup', result: { success: true } };

    // Should not throw
    expect(() => {
      (client as any).notifySetupComplete(data);
    }).not.toThrow();

    // Restore
    global.BroadcastChannel = OriginalBroadcastChannel;
    consoleWarnSpy.mockRestore();
  });
});
