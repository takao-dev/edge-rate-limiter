/**
 * edge-rate-limiter: Zero-dependency fixed-window rate limiter for Edge and Node.js.
 * Built with native WebCrypto for optional keyed client pseudonyms.
 * Features: Auto penalty blocks, variable cost, private IP bypass, concurrency lock, IETF RateLimit headers.
 */

export * from './store.js';
export * from './ip.js';

import { RateLimiterStore, MemoryRateLimiterStore } from './store.js';
import { isPrivateOrLoopbackIp } from './ip.js';

export interface RateLimiterOptions {
  /** Maximum number of allowed requests/tokens within window. Defaults to 60. */
  limit?: number;
  /** Window size in milliseconds. Defaults to 60,000 (1 minute). */
  windowMs?: number;
  /** Storage backend. Defaults to in-memory store. */
  store?: RateLimiterStore;
  /** Optional secret of at least 32 UTF-8 bytes; when omitted, the raw client key is stored. */
  salt?: string;
  /** Automatically bypass rate limiting for private/loopback IP addresses. Defaults to false. */
  skipPrivateIps?: boolean;
}

export interface ConsumeOptions {
  /** Quota cost for this operation (e.g. 5 for heavy queries). Defaults to 1. */
  cost?: number;
  /** Override base limit for this specific tier or call. */
  customLimit?: number;
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
  /** Whether the client is currently under a penalty block / ban. */
  isBlocked?: boolean;
}

export function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error('WebCrypto SubtleCrypto is not available in this environment');
}

/**
 * Derive a keyed pseudonym for an IP address or client identifier.
 */
export async function anonymizeClient(identifier: string, salt: string): Promise<string> {
  if (typeof identifier !== 'string' || typeof salt !== 'string' || new TextEncoder().encode(salt).byteLength < 32) {
    throw new Error('Anonymization requires a client identifier and a secret of at least 32 UTF-8 bytes');
  }
  const encoder = new TextEncoder();
  const crypto = getWebCrypto();
  const key = await crypto.subtle.importKey('raw', encoder.encode(salt), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hash = await crypto.subtle.sign('HMAC', key, encoder.encode(`edge-rate-limiter:client:v2\0${identifier}`));
  const hex = Array.from(new Uint8Array(hash))
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `rl_anon_v2_${hex}`;
}

export class RateLimiter {
  readonly limit: number;
  readonly windowMs: number;
  private readonly store: RateLimiterStore;
  private readonly salt?: string;
  private readonly skipPrivateIps: boolean;
  private readonly locks: Map<string, Promise<void>>;

  constructor(options: RateLimiterOptions = {}) {
    this.limit = options.limit ?? 60;
    this.windowMs = options.windowMs ?? 60_000;
    if (!Number.isFinite(this.limit) || this.limit <= 0) throw new Error('limit must be positive and finite');
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) throw new Error('windowMs must be positive and finite');
    this.store = options.store ?? new MemoryRateLimiterStore();
    this.locks = getStoreLocks(this.store);
    if (options.salt !== undefined && (typeof options.salt !== 'string' || new TextEncoder().encode(options.salt).byteLength < 32)) {
      throw new Error('salt must be a secret of at least 32 UTF-8 bytes');
    }
    this.salt = options.salt;
    this.skipPrivateIps = Boolean(options.skipPrivateIps);
  }

  private async acquireLock(key: string): Promise<() => void> {
    while (this.locks.has(key)) {
      await this.locks.get(key);
    }
    let release!: () => void;
    const promise = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.locks.set(key, promise);
    return () => {
      this.locks.delete(key);
      release();
    };
  }

  /**
   * Check if a client key is currently under a penalty block.
   */
  async checkBlocked(rawKey: string): Promise<{ blocked: boolean; remainingMs: number }> {
    if (typeof rawKey !== 'string' || rawKey.length === 0) throw new Error('Client key must be a non-empty string');
    const key = this.salt ? await anonymizeClient(rawKey, this.salt) : rawKey;
    const release = await this.acquireLock(key);
    try {
      const entry = await this.store.get(key);
      if (!entry || !entry.blockedUntilMs) {
        return { blocked: false, remainingMs: 0 };
      }

      const now = Date.now();
      if (now < entry.blockedUntilMs) {
        return { blocked: true, remainingMs: entry.blockedUntilMs - now };
      }

      return { blocked: false, remainingMs: 0 };
    } finally {
      release();
    }
  }

  /**
   * Apply a penalty block (ban) to a client for a specified duration in milliseconds.
   */
  async block(rawKey: string, durationMs: number): Promise<void> {
    if (typeof rawKey !== 'string' || rawKey.length === 0) throw new Error('Client key must be a non-empty string');
    if (!Number.isFinite(durationMs) || durationMs <= 0) throw new Error('Block duration must be positive and finite');
    const key = this.salt ? await anonymizeClient(rawKey, this.salt) : rawKey;
    const release = await this.acquireLock(key);
    try {
      const now = Date.now();
      const blockedUntilMs = now + durationMs;
      const ttlSeconds = Math.max(1, Math.ceil(durationMs / 1000));

      let entry = await this.store.get(key);
      if (!entry) {
        entry = {
          tokens: 0,
          lastRefillMs: now,
          windowStartMs: now,
          count: 0,
          blockedUntilMs,
        };
      } else {
        entry.tokens = 0;
        entry.blockedUntilMs = blockedUntilMs;
      }

      await this.store.set(key, entry, ttlSeconds);
    } finally {
      release();
    }
  }

  /**
   * Consume quota for a given client key.
   */
  async consume(rawKey: string, optionsOrCost: number | ConsumeOptions = 1): Promise<RateLimitResult> {
    if (typeof rawKey !== 'string' || rawKey.length === 0) throw new Error('Client key must be a non-empty string');
    if (optionsOrCost === null || (typeof optionsOrCost !== 'number' && typeof optionsOrCost !== 'object')) {
      throw new Error('Consume options must be a positive cost or options object');
    }
    // Check private IP bypass if enabled
    if (this.skipPrivateIps && isPrivateOrLoopbackIp(rawKey)) {
      return {
        success: true,
        limit: this.limit,
        remaining: this.limit,
        resetMs: 0,
        retryAfter: 0,
      };
    }

    const cost = typeof optionsOrCost === 'number' ? optionsOrCost : (optionsOrCost.cost ?? 1);
    const activeLimit = typeof optionsOrCost === 'object' && typeof optionsOrCost.customLimit === 'number'
      ? optionsOrCost.customLimit
      : this.limit;
    if (!Number.isFinite(cost) || cost <= 0 || !Number.isFinite(activeLimit) || activeLimit <= 0) {
      throw new Error('Rate limit and cost must be positive finite numbers');
    }

    const key = this.salt ? await anonymizeClient(rawKey, this.salt) : rawKey;
    const release = await this.acquireLock(key);

    try {
      const now = Date.now();
      const windowSec = Math.ceil(this.windowMs / 1000);

      let entry = await this.store.get(key);

      // Check penalty block
      if (entry && entry.blockedUntilMs) {
        if (now < entry.blockedUntilMs) {
          const remainingMs = entry.blockedUntilMs - now;
          return {
            success: false,
            limit: activeLimit,
            remaining: 0,
            resetMs: remainingMs,
            retryAfter: Math.max(1, Math.ceil(remainingMs / 1000)),
            isBlocked: true,
          };
        } else {
          // Block expired; recover tokens and start fresh window
          delete entry.blockedUntilMs;
          entry.tokens = activeLimit;
          entry.count = 0;
          entry.windowStartMs = now;
        }
      }

      if (!entry || now - entry.windowStartMs >= this.windowMs) {
        // New window initialization
        const initialTokens = activeLimit - cost;
        entry = {
          tokens: initialTokens,
          lastRefillMs: now,
          windowStartMs: now,
          count: cost,
        };

        const success = initialTokens >= 0;
        await this.store.set(key, entry, windowSec);

        return {
          success,
          limit: activeLimit,
          remaining: Math.max(0, initialTokens),
          resetMs: this.windowMs,
          retryAfter: success ? 0 : windowSec,
        };
      }

      // Existing active window
      const elapsed = now - entry.windowStartMs;
      const remainingTimeMs = Math.max(0, this.windowMs - elapsed);
      const retryAfterSec = Math.max(1, Math.ceil(remainingTimeMs / 1000));
      const remainingAllowance = Math.max(0, Math.min(entry.tokens, activeLimit - entry.count));

      if (remainingAllowance < cost) {
        return {
          success: false,
          limit: activeLimit,
          remaining: 0,
          resetMs: remainingTimeMs,
          retryAfter: retryAfterSec,
        };
      }

      entry.tokens = remainingAllowance - cost;
      entry.count += cost;
      await this.store.set(key, entry, retryAfterSec);

      return {
        success: true,
        limit: activeLimit,
        remaining: entry.tokens,
        resetMs: remainingTimeMs,
        retryAfter: 0,
      };
    } finally {
      release();
    }
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

const storeLocks = new WeakMap<RateLimiterStore, Map<string, Promise<void>>>();
function getStoreLocks(store: RateLimiterStore): Map<string, Promise<void>> {
  let locks = storeLocks.get(store);
  if (!locks) { locks = new Map(); storeLocks.set(store, locks); }
  return locks;
}
