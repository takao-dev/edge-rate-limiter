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
 * In-memory fixed-window store with expiration cleanup and penalty blocks.
 */
export class MemoryRateLimiterStore implements RateLimiterStore {
  private readonly map = new Map<string, { entry: RateLimitEntry; expiresAt: number }>();
  private readonly maxEntries: number;

  constructor(maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new Error('maxEntries must be a positive integer');
    this.maxEntries = maxEntries;
  }

  get(key: string): RateLimitEntry | null {
    const item = this.map.get(key);
    if (!item) return null;
    if (Date.now() >= item.expiresAt) {
      this.map.delete(key);
      return null;
    }
    return item.entry;
  }

  set(key: string, entry: RateLimitEntry, ttlSeconds: number): void {
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) throw new Error('ttlSeconds must be positive and finite');
    const now = Date.now();
    for (const [storedKey, item] of this.map) {
      if (now >= item.expiresAt) this.map.delete(storedKey);
    }
    if (!this.map.has(key) && this.map.size >= this.maxEntries) {
      throw new Error('Rate limiter store capacity reached; refusing to evict active quota state');
    }
    const expiresAt = now + ttlSeconds * 1000;
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
