/**
 * Vitest Setup File
 *
 * Provides polyfills and mocks for test environment (V2 only)
 */

import { IDBFactory } from 'fake-indexeddb';
import { IDBKeyRange } from 'fake-indexeddb';

// Mock IndexedDB for testing
globalThis.indexedDB = new IDBFactory();
globalThis.IDBKeyRange = IDBKeyRange;

// Mock self for Worker context (needed for module imports with Worker code)
// Worker modules reference 'self' at module level, so we must provide it before imports
// Use a Proxy to ensure 'self' remains defined even after test teardown
(globalThis as any).self = new Proxy(globalThis, {
  get(target, prop) {
    // Always return globalThis for self, even if tests try to unset it
    if (prop === 'self') {
      return target;
    }
    return Reflect.get(target, prop);
  },
});
