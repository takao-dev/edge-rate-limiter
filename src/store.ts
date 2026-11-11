/**
 * Store abstraction for edge-rate-limiter.
 * Zero Runtime Dependencies.
 */

export interface RateLimitEntry {
  tokens: number;
  lastRefillMs: number;
  windowStartMs: number;
  count: number;
  blockedUntilMs?: number;
}

export interface RateLimiterStore {
  get(key: string): Promise<RateLimitEntry | null> | RateLimitEntry | null;
  set(key: string, entry: RateLimitEntry, ttlSeconds: number): Promise<void> | void;
  delete(key: string): Promise<void> | void;
}

/**
 * Ultra-fast In-Memory sliding store with automatic garbage collection and penalty blocks.
 */
export class MemoryRateLimiterStore implements RateLimiterStore {
  private readonly map = new Map<string, { entry: RateLimitEntry; expiresAt: number }>();
  private readonly maxEntries: number;

  constructor(maxEntries = 10_000) {
    this.maxEntries = maxEntries;
  }

  get(key: string): RateLimitEntry | null {
    const item = this.map.get(key);
    if (!item) return null;
    if (Date.now() > item.expiresAt) {
      this.map.delete(key);
      return null;
    }
    return item.entry;
  }

  set(key: string, entry: RateLimitEntry, ttlSeconds: number): void {
    if (this.map.size >= this.maxEntries) {
      // Simple FIFO eviction when max capacity reached
      const firstKey = this.map.keys().next().value;
      if (firstKey) this.map.delete(firstKey);
    }
    const expiresAt = Date.now() + Math.max(1, ttlSeconds) * 1000;
    this.map.set(key, { entry, expiresAt });
  }

  delete(key: string): void {
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}
