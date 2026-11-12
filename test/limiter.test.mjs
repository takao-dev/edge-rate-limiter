import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = webcrypto;
}

import {
  RateLimiter,
  MemoryRateLimiterStore,
  anonymizeClient,
  isPrivateOrLoopbackIp,
} from '../dist/index.js';

test('isPrivateOrLoopbackIp correctly identifies private, link-local and loopback ranges', () => {
  // Loopback
  assert.equal(isPrivateOrLoopbackIp('127.0.0.1'), true);
  assert.equal(isPrivateOrLoopbackIp('127.0.1.5'), true);
  assert.equal(isPrivateOrLoopbackIp('::1'), true);

  // Private RFC 1918
  assert.equal(isPrivateOrLoopbackIp('10.0.0.1'), true);
  assert.equal(isPrivateOrLoopbackIp('172.16.0.1'), true);
  assert.equal(isPrivateOrLoopbackIp('172.31.255.254'), true);
  assert.equal(isPrivateOrLoopbackIp('192.168.1.100'), true);
  assert.equal(isPrivateOrLoopbackIp('169.254.1.1'), true); // link-local

  // Public IPs
  assert.equal(isPrivateOrLoopbackIp('8.8.8.8'), false);
  assert.equal(isPrivateOrLoopbackIp('1.1.1.1'), false);
  assert.equal(isPrivateOrLoopbackIp('203.0.113.50'), false);
  assert.equal(isPrivateOrLoopbackIp('172.32.0.1'), false); // beyond 172.16-31
});

test('skipPrivateIps bypasses rate limiting for internal traffic while limiting public IPs', async () => {
  const limiter = new RateLimiter({ limit: 2, skipPrivateIps: true });

  // Private IP can make unlimited requests
  for (let i = 0; i < 10; i++) {
    const res = await limiter.consume('127.0.0.1');
    assert.equal(res.success, true);
    assert.equal(res.remaining, 2);
  }

  // Public IP is properly throttled
  await limiter.consume('203.0.113.1');
  await limiter.consume('203.0.113.1');
  const blocked = await limiter.consume('203.0.113.1');
  assert.equal(blocked.success, false);
});

test('Penalty block (Ban/Jail) enforces total lockout and recovers after duration', async () => {
  const limiter = new RateLimiter({ limit: 10, windowMs: 60_000 });
  const attackerIp = '198.51.100.200';

  // Apply a 150ms penalty block
  await limiter.block(attackerIp, 150);

  // Check status
  const check = await limiter.checkBlocked(attackerIp);
  assert.equal(check.blocked, true);
  assert.ok(check.remainingMs > 0);

  // Even small cost 0 requests must be rejected during block
  const res = await limiter.consume(attackerIp, 0);
  assert.equal(res.success, false);
  assert.equal(res.isBlocked, true);
  assert.ok(res.retryAfter > 0);

  // Wait for block to expire
  await new Promise((resolve) => setTimeout(resolve, 180));

  const recoveredCheck = await limiter.checkBlocked(attackerIp);
  assert.equal(recoveredCheck.blocked, false);

  const allowed = await limiter.consume(attackerIp);
  assert.equal(allowed.success, true);
});

test('Concurrency stress test: 50 parallel requests never exceed limit (race-condition free)', async () => {
  const limiter = new RateLimiter({ limit: 20, windowMs: 5000 });
  const clientKey = 'concurrent-tester-1';

  // Fire 50 simultaneous requests
  const results = await Promise.all(
    Array.from({ length: 50 }, () => limiter.consume(clientKey, 1))
  );

  const passed = results.filter((r) => r.success).length;
  const blocked = results.filter((r) => !r.success).length;

  assert.equal(passed, 20);
  assert.equal(blocked, 30);
});

test('Variable cost consumption deducts arbitrary token amounts', async () => {
  const limiter = new RateLimiter({ limit: 10, windowMs: 10_000 });

  // Heavy operation costs 6 tokens
  const r1 = await limiter.consume('user-var', { cost: 6 });
  assert.equal(r1.success, true);
  assert.equal(r1.remaining, 4);

  // Operation requiring 5 tokens fails because only 4 remain
  const r2 = await limiter.consume('user-var', { cost: 5 });
  assert.equal(r2.success, false);
  assert.equal(r2.remaining, 0);

  // Operation requiring 4 tokens succeeds exactly
  const r3 = await limiter.consume('user-var', { cost: 4 });
  assert.equal(r3.success, true);
  assert.equal(r3.remaining, 0);
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

test('MemoryRateLimiterStore lifecycle, eviction, size and TTL expiration', async () => {
  const store = new MemoryRateLimiterStore(2); // capacity 2
  assert.equal(store.size, 0);

  const entry1 = { tokens: 5, lastRefillMs: Date.now(), windowStartMs: Date.now(), count: 1 };
  store.set('k1', entry1, 1);
  assert.equal(store.size, 1);
  assert.equal(store.get('k1')?.tokens, 5);

  // Expiration check
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(store.get('k1'), null);
  assert.equal(store.size, 0);

  // Eviction check when maxEntries reached
  store.set('a', entry1, 60);
  store.set('b', entry1, 60);
  assert.equal(store.size, 2);
  store.set('c', entry1, 60); // triggers FIFO eviction of 'a'
  assert.equal(store.get('a'), null);
  assert.ok(store.get('b'));
  assert.ok(store.get('c'));

  // delete and clear
  store.delete('b');
  assert.equal(store.get('b'), null);
  store.clear();
  assert.equal(store.size, 0);
});

test('IP validator comprehensive boundary cases', () => {
  // Empty and non-string inputs
  assert.equal(isPrivateOrLoopbackIp(null), false);
  assert.equal(isPrivateOrLoopbackIp(undefined), false);
  assert.equal(isPrivateOrLoopbackIp(''), false);

  // Malformed IPv4
  assert.equal(isPrivateOrLoopbackIp('192.168.1'), false); // 3 parts
  assert.equal(isPrivateOrLoopbackIp('192.168.1.1.1'), false); // 5 parts
  assert.equal(isPrivateOrLoopbackIp('192.168.1.abc'), false); // NaN
  assert.equal(isPrivateOrLoopbackIp('192.168.1.999'), false); // Out of range
  assert.equal(isPrivateOrLoopbackIp('0.0.0.0'), true); // 0.0.0.0/8

  // IPv6 boundary cases
  assert.equal(isPrivateOrLoopbackIp('::'), true); // Unspecified
  assert.equal(isPrivateOrLoopbackIp('fe80::1ff:fe23:4567:890a'), true); // Link-local
  assert.equal(isPrivateOrLoopbackIp('fc00::1'), true); // Unique local
  assert.equal(isPrivateOrLoopbackIp('fd12:3456:789a::1'), true); // Unique local
  assert.equal(isPrivateOrLoopbackIp('2001:4860:4860::8888'), false); // Google DNS Public IPv6
});

test('RateLimiter penalty checkBlocked and initial overload rejection', async () => {
  const limiter = new RateLimiter({ limit: 10, windowMs: 10_000, salt: 'test-salt' });

  // Initial checkBlocked should be false
  const unblocked = await limiter.checkBlocked('client_test');
  assert.equal(unblocked.blocked, false);

  // Block existing entry
  await limiter.consume('client_test', 1);
  await limiter.block('client_test', 5000);

  const blocked = await limiter.checkBlocked('client_test');
  assert.equal(blocked.blocked, true);
  assert.ok(blocked.remainingMs > 0);

  // Overload: request costing more than total limit fails immediately
  const overload = await limiter.consume('overloaded_client', 100);
  assert.equal(overload.success, false);
  assert.equal(overload.remaining, 0);
  assert.ok(overload.retryAfter > 0);
});
