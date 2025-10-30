/**
 * @file error-utils.test.ts
 * @description Comprehensive tests for error-utils.ts
 * Tests all code paths including error handling, type conversion, and edge cases.
 */

import { describe, it, expect } from 'vitest';
import { getErrorMessage, toError, formatError } from '@/v2/error-utils';

describe('getErrorMessage', () => {
  describe('Error objects', () => {
    it('should extract message from Error object', () => {
      const error = new Error('Test error message');
      expect(getErrorMessage(error)).toBe('Test error message');
    });

    it('should extract message from TypeError', () => {
      const error = new TypeError('Type error message');
      expect(getErrorMessage(error)).toBe('Type error message');
    });

    it('should extract message from custom Error subclass', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }
      const error = new CustomError('Custom error message');
      expect(getErrorMessage(error)).toBe('Custom error message');
    });

    it('should handle Error with empty message', () => {
      const error = new Error('');
      expect(getErrorMessage(error)).toBe('');
    });
  });

  describe('String errors', () => {
    it('should return string error as-is', () => {
      expect(getErrorMessage('String error message')).toBe('String error message');
    });

    it('should handle empty string', () => {
      expect(getErrorMessage('')).toBe('');
    });

    it('should handle multi-line string', () => {
      const multiLine = 'Line 1\nLine 2\nLine 3';
      expect(getErrorMessage(multiLine)).toBe(multiLine);
    });

    it('should handle string with special characters', () => {
      const special = 'Error: 💥 Something went wrong!';
      expect(getErrorMessage(special)).toBe(special);
    });
  });

  describe('Object with message property', () => {
    it('should extract message from object with message property', () => {
      const errorLike = { message: 'Object error message', code: 500 };
      expect(getErrorMessage(errorLike)).toBe('Object error message');
    });

    it('should extract message from Error-like object with stack', () => {
      const errorLike = {
        message: 'Error with stack',
        stack: 'Error: Error with stack\n    at <anonymous>',
        name: 'CustomError',
      };
      expect(getErrorMessage(errorLike)).toBe('Error with stack');
    });

    it('should handle object with non-string message property', () => {
      const obj = { message: 123 };
      // Should fall through to String(obj) fallback
      expect(getErrorMessage(obj)).toContain('object');
    });

    it('should handle object with null message', () => {
      const obj = { message: null };
      expect(getErrorMessage(obj)).toContain('object');
    });
  });

  describe('Fallback for other types', () => {
    it('should convert number to string', () => {
      expect(getErrorMessage(404)).toBe('404');
    });

    it('should convert zero to string', () => {
      expect(getErrorMessage(0)).toBe('0');
    });

    it('should convert boolean to string', () => {
      expect(getErrorMessage(true)).toBe('true');
      expect(getErrorMessage(false)).toBe('false');
    });

    it('should handle null', () => {
      expect(getErrorMessage(null)).toBe('null');
    });

    it('should handle undefined', () => {
      expect(getErrorMessage(undefined)).toBe('undefined');
    });

    it('should convert array to string', () => {
      expect(getErrorMessage([1, 2, 3])).toBe('1,2,3');
    });

    it('should convert empty array to empty string', () => {
      expect(getErrorMessage([])).toBe('');
    });

    it('should convert plain object to string', () => {
      const obj = { foo: 'bar', baz: 42 };
      const result = getErrorMessage(obj);
      expect(result).toContain('object');
    });

    it('should handle object without toString', () => {
      const obj = Object.create(null);
      obj.foo = 'bar';
      const result = getErrorMessage(obj);
      // Should not throw, should return some string representation
      expect(typeof result).toBe('string');
    });

    it('should handle Symbol', () => {
      const sym = Symbol('test-symbol');
      const result = getErrorMessage(sym);
      expect(result).toContain('Symbol');
    });

    it('should handle BigInt', () => {
      const big = BigInt(9007199254740991);
      expect(getErrorMessage(big)).toBe('9007199254740991');
    });

    it('should handle function', () => {
      const fn = function testFunc() {
        return 42;
      };
      const result = getErrorMessage(fn);
      expect(result).toContain('function');
    });

    it('should handle circular reference with fallback', () => {
      const circular: { self?: unknown } = {};
      circular.self = circular;
      // String(circular) might throw on circular refs, should catch and return 'Unknown error'
      const result = getErrorMessage(circular);
      expect(typeof result).toBe('string');
      // Either successfully stringified or fell back to 'Unknown error'
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('Edge cases', () => {
    it('should handle Date object', () => {
      const date = new Date('2025-01-01T00:00:00Z');
      const result = getErrorMessage(date);
      // Date toString() includes date/time, just verify it's a string representation
      expect(result).toContain('202'); // Should contain year prefix regardless of timezone
    });

    it('should handle RegExp', () => {
      const regex = /test-pattern/gi;
      expect(getErrorMessage(regex)).toBe('/test-pattern/gi');
    });

    it('should handle NaN', () => {
      expect(getErrorMessage(NaN)).toBe('NaN');
    });

    it('should handle Infinity', () => {
      expect(getErrorMessage(Infinity)).toBe('Infinity');
      expect(getErrorMessage(-Infinity)).toBe('-Infinity');
    });
  });
});

describe('toError', () => {
  describe('Error objects', () => {
    it('should return Error object as-is', () => {
      const error = new Error('Original error');
      const result = toError(error);
      expect(result).toBe(error);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('Original error');
    });

    it('should return TypeError as-is', () => {
      const error = new TypeError('Type error');
      const result = toError(error);
      expect(result).toBe(error);
      expect(result).toBeInstanceOf(TypeError);
    });

    it('should preserve Error subclass', () => {
      class CustomError extends Error {
        code: number;
        constructor(message: string, code: number) {
          super(message);
          this.code = code;
          this.name = 'CustomError';
        }
      }
      const error = new CustomError('Custom error', 500);
      const result = toError(error) as CustomError;
      expect(result).toBe(error);
      expect(result.code).toBe(500);
    });
  });

  describe('Non-Error values', () => {
    it('should wrap string in Error', () => {
      const result = toError('String error');
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('String error');
    });

    it('should wrap number in Error', () => {
      const result = toError(404);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('404');
    });

    it('should wrap boolean in Error', () => {
      const result = toError(false);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('false');
    });

    it('should wrap null in Error', () => {
      const result = toError(null);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('null');
    });

    it('should wrap undefined in Error', () => {
      const result = toError(undefined);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('undefined');
    });

    it('should wrap object with message in Error', () => {
      const errorLike = { message: 'Error-like object', code: 500 };
      const result = toError(errorLike);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('Error-like object');
    });

    it('should wrap plain object in Error', () => {
      const obj = { foo: 'bar' };
      const result = toError(obj);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toContain('object');
    });

    it('should wrap array in Error', () => {
      const result = toError([1, 2, 3]);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('1,2,3');
    });
  });
});

describe('formatError', () => {
  describe('Basic formatting', () => {
    it('should format Error object with prefix', () => {
      const error = new Error('Connection failed');
      const result = formatError('Database operation failed', error);
      expect(result).toBe('Database operation failed: Connection failed');
    });

    it('should format string error with prefix', () => {
      const result = formatError('VAPID generation failed', 'Invalid key size');
      expect(result).toBe('VAPID generation failed: Invalid key size');
    });

    it('should format number error with prefix', () => {
      const result = formatError('HTTP error', 404);
      expect(result).toBe('HTTP error: 404');
    });

    it('should format null with prefix', () => {
      const result = formatError('Unexpected null', null);
      expect(result).toBe('Unexpected null: null');
    });

    it('should format undefined with prefix', () => {
      const result = formatError('Missing value', undefined);
      expect(result).toBe('Missing value: undefined');
    });
  });

  describe('Complex errors', () => {
    it('should format object with message property', () => {
      const errorLike = { message: 'Quota exceeded', code: 'QUOTA_EXCEEDED' };
      const result = formatError('Lease creation failed', errorLike);
      expect(result).toBe('Lease creation failed: Quota exceeded');
    });

    it('should format TypeError with prefix', () => {
      const error = new TypeError('Expected string, got number');
      const result = formatError('Validation failed', error);
      expect(result).toBe('Validation failed: Expected string, got number');
    });

    it('should format RangeError with prefix', () => {
      const error = new RangeError('Index out of bounds');
      const result = formatError('Array access failed', error);
      expect(result).toBe('Array access failed: Index out of bounds');
    });
  });

  describe('Edge cases', () => {
    it('should handle empty prefix', () => {
      const error = new Error('Test error');
      const result = formatError('', error);
      expect(result).toBe(': Test error');
    });

    it('should handle empty error message', () => {
      const error = new Error('');
      const result = formatError('Operation failed', error);
      expect(result).toBe('Operation failed: ');
    });

    it('should handle prefix with colon', () => {
      const result = formatError('Failed:', 'reason');
      expect(result).toBe('Failed:: reason');
    });

    it('should handle multi-line error message', () => {
      const error = new Error('Line 1\nLine 2\nLine 3');
      const result = formatError('Multi-line error', error);
      expect(result).toBe('Multi-line error: Line 1\nLine 2\nLine 3');
    });

    it('should handle special characters in prefix', () => {
      const result = formatError('Error 💥', 'Something went wrong');
      expect(result).toBe('Error 💥: Something went wrong');
    });

    it('should handle boolean error', () => {
      const result = formatError('Assertion failed', false);
      expect(result).toBe('Assertion failed: false');
    });
  });
});
