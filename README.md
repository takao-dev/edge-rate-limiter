# edge-rate-limiter

Zero-dependency fixed-window rate limiter for Edge, Cloudflare Workers, and Node.js with optional keyed client pseudonyms.

## Storage-key compatibility and migration

Salted client keys now use HMAC-SHA-256 with a versioned domain. Existing salted buckets use different storage keys and will not be read; after upgrading, affected clients start with a full quota window. Plan this quota reset during rollout, and keep the same secret salt across instances and deployments.

[![npm version](https://img.shields.io/npm/v/edge-rate-limiter.svg)](https://www.npmjs.com/package/edge-rate-limiter)
[![npm downloads](https://img.shields.io/npm/dw/edge-rate-limiter.svg)](https://www.npmjs.com/package/edge-rate-limiter)
[![CI](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/edge-rate-limiter/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/edge-rate-limiter)
[![CodeQL](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/edge-rate-limiter/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

---

## Features

- **Zero Runtime Dependencies**: Pure TypeScript/JavaScript with zero third-party dependencies.
- **Optional Keyed Client Pseudonyms**: Stores keyed identifiers when a secret salt is configured.
- **IETF RateLimit Header Generation**: Automatically produces `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After` headers.
- **Pluggable Storage**: Includes an in-memory fixed-window store. A custom store can persist quota state across requests.

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

The built-in store and per-store lock protect concurrent requests only inside one JavaScript isolate. A custom `get`/`set` store does not provide an atomic update across isolates or machines; use a single-owner service such as a Durable Object when a quota must hold globally. Cloudflare KV and Cache API do not provide that guarantee.

Provide a secret `salt` containing at least 32 UTF-8 bytes to avoid storing raw client keys. If `salt` is omitted, the store key is the raw identifier; `anonymizeClient` always requires the secret.

---

## Related Edge Security Packages

Complementary zero-dependency, high-performance security modules for Edge runtimes, Cloudflare Workers, and modern Node.js:

- [wasm-crypto-hash](https://github.com/takao-dev/wasm-crypto-hash): Ultra-fast WebAssembly & WebCrypto cryptographic suite (SHA-2/3, BLAKE3, PQC, Argon2, TOTP, BIP-39).
- [edge-secure-token](https://github.com/takao-dev/edge-secure-token): Zero-dependency, timing-safe WebCrypto JWT suite with field-level claims encryption.
- [edge-session-crypto](https://github.com/takao-dev/edge-session-crypto): Stateless encrypted cookie session manager with AES-GCM and key rotation.
- [zero-pii-redactor](https://github.com/takao-dev/zero-pii-redactor): High-speed, ReDoS-free PII redactor, tokenizer, and pseudonymizer for logs and AI prompts.
- [webcrypto-secure-storage](https://github.com/takao-dev/webcrypto-secure-storage): Tamper-evident authenticated key-value storage with AES-GCM & HMAC.
- [edge-audit-crypto](https://github.com/takao-dev/edge-audit-crypto): Tamper-evident cryptographic append-only audit trail logging.

---

## License

SPDX-License-Identifier: MIT
Copyright (c) 2026 takao-dev
