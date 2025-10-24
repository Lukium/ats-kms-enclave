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
