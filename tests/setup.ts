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

// Mock self for Worker context (needed for coverage collection)
// @ts-expect-error - self is a Worker global, not available in Node test environment
if (typeof self === 'undefined') {
  // @ts-expect-error - Adding self to globalThis for Worker compatibility
  globalThis.self = globalThis;
}
