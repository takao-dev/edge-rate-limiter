# edge-rate-limiter

Zero-dependency, high-performance sliding-window and token bucket rate limiter for Edge, Cloudflare Workers, and Node.js with native Zero-PII client anonymization.

[![npm version](https://img.shields.io/npm/v/edge-rate-limiter.svg)](https://www.npmjs.com/package/edge-rate-limiter)
[![CI](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/edge-rate-limiter/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/edge-rate-limiter)
[![CodeQL](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

---

## Features

- **Zero Runtime Dependencies**: Pure TypeScript/JavaScript with zero third-party dependencies.
- **Zero-PII Client Anonymization**: Hashes raw IP addresses with rotating cryptographic salt to ensure privacy compliance.
- **IETF RateLimit Header Generation**: Automatically produces `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After` headers.
- **Pluggable Storage**: Includes in-memory sliding store and flexible store interfaces for Cloudflare KV / Cache API / Durable Objects.

---

## Usage

```typescript
import { RateLimiter } from 'edge-rate-limiter';

const limiter = new RateLimiter({
  limit: 100, // 100 requests
  windowMs: 60_000, // per minute
  salt: process.env.RATE_LIMIT_SALT, // Optional Zero-PII salt
});

export async function handleRequest(request: Request) {
  const ip = request.headers.get('cf-connecting-ip') || '127.0.0.1';
  const result = await limiter.consume(ip);
  const headers = limiter.getHeaders(result);

  if (!result.success) {
    return new Response('Too Many Requests', { status: 429, headers });
  }

  return new Response('OK', { headers });
}
```

---

## License

SPDX-License-Identifier: MIT
Copyright (c) 2026 takao-dev
