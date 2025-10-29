/**
 * @file error-utils.ts
 * @description Type-safe error handling utilities for converting unknown errors
 * to typed Error objects and extracting error messages safely.
 *
 * These utilities replace unsafe `catch (err: any)` patterns with type-safe
 * `catch (err: unknown)` patterns throughout the codebase.
 */

/**
 * Extract error message from unknown error value.
 * Handles Error objects, strings, and other types safely.
 *
 * @param err - Unknown error value (from catch block)
 * @returns Human-readable error message
 *
 * @example
 * ```typescript
 * catch (err: unknown) {
 *   console.error('Operation failed:', getErrorMessage(err));
 * }
 * ```
 */
export function getErrorMessage(err: unknown): string {
  // Standard Error object
  if (err instanceof Error) {
    return err.message;
  }

  // String error (throw "string" or Promise.reject("string"))
  if (typeof err === 'string') {
    return err;
  }

  // Object with message property (duck-typing for Error-like objects)
  if (
    typeof err === 'object' &&
    err !== null &&
    'message' in err &&
    typeof (err as { message: unknown }).message === 'string'
  ) {
    return (err as { message: string }).message;
  }

  // Fallback for other types
  try {
    return String(err);
  } catch {
    return 'Unknown error';
  }
}

/**
 * Wrap unknown error in Error object if needed.
 * Preserves Error objects, wraps others with message extraction.
 *
 * @param err - Unknown error value (from catch block)
 * @returns Proper Error object
 *
 * @example
 * ```typescript
 * catch (err: unknown) {
 *   throw toError(err);  // Guaranteed to be Error object
 * }
 * ```
 */
export function toError(err: unknown): Error {
  // Already an Error, return as-is
  if (err instanceof Error) {
    return err;
  }

  // Wrap non-Error values
  return new Error(getErrorMessage(err));
}

/**
 * Create a prefixed error message for context.
 * Useful for adding operation context to error messages.
 *
 * @param prefix - Context prefix (e.g., "Failed to unlock")
 * @param err - Unknown error value
 * @returns Formatted error message with prefix
 *
 * @example
 * ```typescript
 * catch (err: unknown) {
 *   throw new Error(formatError('VAPID key generation failed', err));
 * }
 * ```
 */
export function formatError(prefix: string, err: unknown): string {
  return `${prefix}: ${getErrorMessage(err)}`;
}
