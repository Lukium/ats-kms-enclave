/**
 * @file storage-types.ts
 * @description Type guards and validation for data stored in IndexedDB.
 *
 * IndexedDB returns `unknown` types that need runtime validation before use.
 * These utilities provide type-safe access to stored data structures.
 */

/**
 * Rate limit state structure stored in IndexedDB
 */
export interface RateLimitState {
  tokensIssued: number;
  lastResetAt: number; // Unix timestamp
}

/**
 * Type guard for rate limit state
 * Validates structure at runtime to ensure safe access.
 *
 * @param value - Unknown value from storage to validate
 * @returns true if value matches RateLimitState structure
 */
export function isRateLimitState(value: unknown): value is RateLimitState {
  if (typeof value !== 'object' || value === null) return false;
  const state = value as Partial<RateLimitState>;
  return (
    typeof state.tokensIssued === 'number' &&
    typeof state.lastResetAt === 'number'
  );
}

/**
 * Safely load rate limit state with default fallback.
 * Returns valid state or default if stored data is invalid/missing.
 *
 * @param rawState - Unknown value from storage
 * @returns Validated rate limit state or default
 */
export function loadRateLimitState(rawState: unknown): RateLimitState {
  if (isRateLimitState(rawState)) {
    return rawState;
  }
  // Return default state if invalid or missing
  return {
    tokensIssued: 0,
    lastResetAt: Date.now(),
  };
}
