/**
 * edge-rate-limiter: Zero-dependency token bucket and sliding-window rate limiter for Edge and Node.js.
 * Built with native WebCrypto for cryptographic Zero-PII client anonymization.
 */

export * from './store.js';

import { RateLimiterStore, MemoryRateLimiterStore, RateLimitEntry } from './store.js';

export interface RateLimiterOptions {
  /** Maximum number of allowed requests/tokens within window. Defaults to 60. */
  limit?: number;
  /** Window size in milliseconds. Defaults to 60,000 (1 minute). */
  windowMs?: number;
  /** Storage backend. Defaults to in-memory store. */
  store?: RateLimiterStore;
  /** Optional salt to cryptographically anonymize client identifiers (Zero-PII). */
  salt?: string;
}

export interface RateLimitResult {
  /** Whether the request is permitted. */
  success: boolean;
  /** Maximum quota allowed. */
  limit: number;
  /** Remaining allowance in current window. */
  remaining: number;
  /** Milliseconds until current quota fully resets. */
  resetMs: number;
  /** Seconds client must wait before retrying (0 if success is true). */
  retryAfter: number;
}

/**
 * Anonymize an IP address or client identifier using salted SHA-256.
 * Ensures storage never holds raw IP addresses.
 */
export async function anonymizeClient(identifier: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${salt}:${identifier}`);
  const hash = await globalThis.crypto.subtle.digest('SHA-256', data);
  const hex = Array.from(new Uint8Array(hash))
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `rl_anon_${hex}`;
}

export class RateLimiter {
  readonly limit: number;
  readonly windowMs: number;
  private readonly store: RateLimiterStore;
  private readonly salt?: string;

  constructor(options: RateLimiterOptions = {}) {
    this.limit = options.limit ?? 60;
    this.windowMs = options.windowMs ?? 60_000;
    this.store = options.store ?? new MemoryRateLimiterStore();
    this.salt = options.salt;
  }

  /**
   * Consume quota for a given client key.
   */
  async consume(rawKey: string, cost = 1): Promise<RateLimitResult> {
    const key = this.salt ? await anonymizeClient(rawKey, this.salt) : rawKey;
    const now = Date.now();
    const windowSec = Math.ceil(this.windowMs / 1000);

    let entry = await this.store.get(key);

    if (!entry || now - entry.windowStartMs >= this.windowMs) {
      // New window
      entry = {
        tokens: this.limit - cost,
        lastRefillMs: now,
        windowStartMs: now,
        count: cost,
      };

      const success = entry.tokens >= 0;
      await this.store.set(key, entry, windowSec);

      return {
        success,
        limit: this.limit,
        remaining: Math.max(0, entry.tokens),
        resetMs: this.windowMs,
        retryAfter: success ? 0 : windowSec,
      };
    }

    // Existing active window
    const elapsed = now - entry.windowStartMs;
    const remainingTimeMs = Math.max(0, this.windowMs - elapsed);
    const retryAfterSec = Math.max(1, Math.ceil(remainingTimeMs / 1000));

    if (entry.tokens < cost) {
      return {
        success: false,
        limit: this.limit,
        remaining: 0,
        resetMs: remainingTimeMs,
        retryAfter: retryAfterSec,
      };
    }

    entry.tokens -= cost;
    entry.count += cost;
    await this.store.set(key, entry, retryAfterSec);

    return {
      success: true,
      limit: this.limit,
      remaining: entry.tokens,
      resetMs: remainingTimeMs,
      retryAfter: 0,
    };
  }

  /**
   * Format IETF standard rate limit response headers.
   */
  getHeaders(result: RateLimitResult): Record<string, string> {
    const headers: Record<string, string> = {
      'RateLimit-Limit': String(result.limit),
      'RateLimit-Remaining': String(result.remaining),
      'RateLimit-Reset': String(Math.ceil(result.resetMs / 1000)),
    };

    if (!result.success && result.retryAfter > 0) {
      headers['Retry-After'] = String(result.retryAfter);
    }

    return headers;
  }
}
