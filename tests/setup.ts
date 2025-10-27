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
if (!globalThis.self) {
  (globalThis as any).self = globalThis;
}
