import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RateLimiter,
  MemoryRateLimiterStore,
  anonymizeClient,
} from '../dist/index.js';

test('RateLimiter consumes tokens and tracks remaining allowance', async () => {
  const limiter = new RateLimiter({ limit: 5, windowMs: 10_000 });

  const r1 = await limiter.consume('client-1');
  assert.equal(r1.success, true);
  assert.equal(r1.remaining, 4);
  assert.equal(r1.limit, 5);

  const r2 = await limiter.consume('client-1', 2);
  assert.equal(r2.success, true);
  assert.equal(r2.remaining, 2);

  const r3 = await limiter.consume('client-1', 2);
  assert.equal(r3.success, true);
  assert.equal(r3.remaining, 0);

  // Exceeded
  const r4 = await limiter.consume('client-1', 1);
  assert.equal(r4.success, false);
  assert.equal(r4.remaining, 0);
  assert.ok(r4.retryAfter > 0);
});

test('RateLimiter generates IETF compliant RateLimit headers', async () => {
  const limiter = new RateLimiter({ limit: 10, windowMs: 60_000 });
  const result = await limiter.consume('user-100');

  const headers = limiter.getHeaders(result);
  assert.equal(headers['RateLimit-Limit'], '10');
  assert.equal(headers['RateLimit-Remaining'], '9');
  assert.ok(Number(headers['RateLimit-Reset']) > 0);
  assert.equal(headers['Retry-After'], undefined);

  // Exhaust quota
  await limiter.consume('user-100', 9);
  const blocked = await limiter.consume('user-100', 1);
  const blockedHeaders = limiter.getHeaders(blocked);
  assert.equal(blockedHeaders['RateLimit-Remaining'], '0');
  assert.ok(Number(blockedHeaders['Retry-After']) > 0);
});

test('RateLimiter resets allowance after window expires', async () => {
  const limiter = new RateLimiter({ limit: 2, windowMs: 100 });

  await limiter.consume('short-client', 2);
  const blocked = await limiter.consume('short-client');
  assert.equal(blocked.success, false);

  // Wait 120ms
  await new Promise((resolve) => setTimeout(resolve, 120));

  const renewed = await limiter.consume('short-client');
  assert.equal(renewed.success, true);
  assert.equal(renewed.remaining, 1);
});

test('anonymizeClient hashes raw identifiers into Zero-PII keys', async () => {
  const salt = 'daily-rotation-salt-20261111';
  const ip = '203.0.113.195';

  const anonKey = await anonymizeClient(ip, salt);
  assert.ok(anonKey.startsWith('rl_anon_'));
  assert.ok(!anonKey.includes(ip));

  const sameKey = await anonymizeClient(ip, salt);
  assert.equal(anonKey, sameKey);

  const otherKey = await anonymizeClient('198.51.100.22', salt);
  assert.notEqual(anonKey, otherKey);
});

test('RateLimiter isolates different clients', async () => {
  const limiter = new RateLimiter({ limit: 2, windowMs: 5000 });

  await limiter.consume('alice', 2);
  const aliceBlocked = await limiter.consume('alice');
  assert.equal(aliceBlocked.success, false);

  const bobAllowed = await limiter.consume('bob');
  assert.equal(bobAllowed.success, true);
  assert.equal(bobAllowed.remaining, 1);
});
