# `@phinehas/core`

> The foundational threat detection engine, RFC 8615 lookahead matcher, anti-bypass path normalizer, and zero-allocation LRU state driver for Phinehas.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../../../LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../../../compliance/)

---

## 1. Overview & Philosophy

`@phinehas/core` implements the deterministic threat evaluation mechanics for the Phinehas active defense architecture ("The Spear"). It is designed to evaluate incoming HTTP request paths in $O(1)$ constant time ($< 15\mu s$), evading all known WAF bypass techniques, and deterministically isolating reconnaissance bots before request payloads reach application controllers.

This package has **zero external runtime dependencies** in its core engine and forms the underlying evaluation substrate for:
* [`@phinehas/node`](../node/README.md) (Express, Fastify, Connect, raw HTTP)
* [`@phinehas/next`](../next/README.md) (Next.js Edge & Server Middleware)
* [`@phinehas/nestjs`](../nestjs/README.md) (Enterprise NestJS Modules)

---

## 2. Installation

Install using **Yarn**:
```bash
yarn add @phinehas/core
```

---

## 3. Core Engine Architecture

```
+-------------------------------------------------------------------------------+
|                            RAW REQUEST PATH STRING                            |
|                     (e.g., "//%2e%2e/app/\.env.local?foo=bar")                 |
+-------------------------------------------------------------------------------+
                                       |
                                       v
+-------------------------------------------------------------------------------+
| 1. DETERMINISTIC 6-STAGE NORMALIZATION (normalizePath)                        |
|    - Strips query string and fragment hash                                    |
|    - Hex percent-decoding (%2e -> ., %2f -> /, %5c -> \)                      |
|    - Backslash conversion (\ -> /)                                            |
|    - Consecutive duplicate slash collapsing (/// -> /)                        |
|    - Safe directory traversal resolution (/a/b/../../ -> /)                   |
|    - Lowercasing & trailing slash removal                                     |
+-------------------------------------------------------------------------------+
                                       |
                                       v
+-------------------------------------------------------------------------------+
| 2. RFC 8615 SAFE HARBOR EVALUATION                                            |
|    - Path starts with "/.well-known"?                                         |
|      -> YES: SAFE HARBOR. Automatically exempt from all dotfile rules.        |
|      -> NO:  Proceed to Dotfile Wildcard Regex.                               |
+-------------------------------------------------------------------------------+
                                       |
                         +-------------+-------------+
                         |                           |
                 [Safe / Pass]               [Dotfile Detected]
                         |                           |
                         v                           v
+-----------------------------------+   +---------------------------------------+
| 3. EXPLICIT TRAP MATCHING         |   | THREAT VERDICT: BLOCKED               |
|    - Checks DEFAULT_TRAPS list    |   | Rule: "rfc8615_wildcard"              |
|    - Checks customTraps regex     |   | Action: Strike counter & ban evaluate |
+-----------------------------------+   +---------------------------------------+
```

---

## 4. API Reference

### `normalizePath(rawPath: string): string`

Sanitizes any URI path string, preventing WAF bypasses and path traversal evasions before rule matching:

```typescript
import { normalizePath } from '@phinehas/core';

// Evasion payload: hex-encoded traversal + backslashes
const clean = normalizePath('//%2e%2e/app\\production\\..\\..\\.env');
console.log(clean); // Output: "/.env"
```

#### Normalization Guarantees:
1. **Hex URL Decoding:** Decodes `%2e` (`.`), `%2f` (`/`), `%5c` (`\`), and multi-byte hex representations iteratively.
2. **Backslash Conversion:** Converts Windows-style `\` to standard `/`.
3. **Sequential Slash Collapsing:** Merges `////` down to `/`.
4. **Path Traversal Resolution:** Safely folds `/api/v1/../../.env` to `/.env` without escaping root.
5. **Lowercasing:** Normalizes characters to lowercase (`/.EnV` $\rightarrow$ `/.env`).
6. **Trailing Slash Removal:** Enforces consistent endpoint matching (`/wp-admin/` $\rightarrow$ `/wp-admin`).

---

### `ThreatEvaluator`

The core rule-matching engine:

```typescript
import { ThreatEvaluator } from '@phinehas/core';

// [REQUIRED] Initialize with default rules
const evaluator = new ThreatEvaluator();

// [OPTIONAL] Initialize with advanced custom rules
const customEvaluator = new ThreatEvaluator({
  // [OPTIONAL - DEFAULT: []]
  // Additional regex patterns or literal paths to trap
  custom: [
    /^\/internal-backdoor(\/.*)?$/,
    '/api/v1/debug-dump',
  ],

  // [OPTIONAL - DEFAULT: false]
  // Set to true to disable default database/CMS/debugger signatures
  // and evaluate ONLY custom rules + RFC 8615 dotfiles
  excludeDefaults: false,
});

// Evaluate a path:
const verdict = customEvaluator.evaluate('/%2eenv');
console.log(verdict);
// {
//   isBlocked: true,
//   ruleMatched: 'rfc8615_wildcard',
//   normalizedPath: '/.env',
//   reason: 'Matched RFC 8615 hidden path wildcard: /.env'
// }
```

---

### `MemoryStore` (High-Performance $O(1)$ LRU Cache)

Tracks client IP strikes and ban durations in process memory using a doubly linked list + hash map:

```typescript
import { MemoryStore } from '@phinehas/core';

const store = new MemoryStore({
  // [OPTIONAL - DEFAULT: 25000]
  // Maximum IP addresses tracked concurrently (~5MB memory footprint)
  maxCapacity: 25000,

  // [OPTIONAL - DEFAULT: 86400 (24 hours)]
  // Default TTL for bans in seconds
  defaultTtlSeconds: 86400,
});

// Strike recording:
const currentStrikes = store.recordStrike('203.0.113.5', 60); // 60s window
console.log(`IP has ${currentStrikes} strikes`);

// Banning:
store.ban('203.0.113.5', 3600); // Ban for 1 hour
console.log(store.isBanned('203.0.113.5')); // true

// Permanent ban:
store.ban('203.0.113.5', 0); // 0 = permanent
```

---

### `RedisStore` (Distributed Cluster Ban Synchronizer)

For multi-instance clusters running behind load balancers:

```typescript
import { RedisStore } from '@phinehas/core';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

const store = new RedisStore({
  // [REQUIRED] Underlying Redis client instance
  client: redis,

  // [OPTIONAL - DEFAULT: "phinehas:ban:"]
  prefix: 'phinehas:ban:',

  // [PRODUCTION RECOMMENDED - DEFAULT: 5000]
  // In-memory L1 cache TTL in milliseconds. Protects Redis from being
  // overwhelmed during distributed volumetric crawling attacks.
  l1CacheTtlMs: 5000,
});

// Asynchronously check ban status (served from local L1 cache when hot):
const isBlocked = await store.isBanned('198.51.100.99');
```

---

### Custom Storage Adapter (`BanStoreInterface`)

You can implement your own storage backend (e.g., Memcached, DynamoDB, MongoDB, SQLite) by fulfilling `BanStoreInterface`:

```typescript
import { BanStoreInterface } from '@phinehas/core';

export class CustomDynamoDbStore implements BanStoreInterface {
  async isBanned(ip: string): Promise<boolean> {
    // Custom database lookup
    return false;
  }

  async recordStrike(ip: string, windowSeconds: number): Promise<number> {
    // Atomic increment in DynamoDB
    return 1;
  }

  async ban(ip: string, durationSeconds: number): Promise<void> {
    // Put item with DynamoDB TTL
  }

  async unban(ip: string): Promise<void> {
    // Delete item
  }

  async clear(): Promise<void> {
    // Flush table
  }
}
```

---

## 5. Direct Non-Framework Engine Usage

If you are running inside AWS Lambda, Cloudflare Workers, or a custom HTTP gateway without Express, you can invoke `@phinehas/core` directly:

```typescript
import { normalizePath, ThreatEvaluator, MemoryStore } from '@phinehas/core';

const evaluator = new ThreatEvaluator();
const store = new MemoryStore({ maxCapacity: 10000 });

export async function handleRequest(clientIp: string, rawUrl: string) {
  // 1. Check if IP is already banned
  if (store.isBanned(clientIp)) {
    return { status: 403, body: 'Forbidden', severSocket: true };
  }

  // 2. Evaluate incoming path
  const normalized = normalizePath(rawUrl);
  const verdict = evaluator.evaluate(normalized);

  if (verdict.isBlocked) {
    // Record strike
    const strikes = store.recordStrike(clientIp, 60);
    if (strikes >= 3) {
      store.ban(clientIp, 86400); // 24-hour ban
    }
    return { status: 403, body: '', severSocket: true, reason: verdict.reason };
  }

  return { status: 200, body: 'OK', severSocket: false };
}
```

---

## 6. Navigation

* [Root SDK Documentation](../../../../README.md)
* [Node.js & Express Middleware (`@phinehas/node`)](../node/README.md)
* [Next.js Edge Guard (`@phinehas/next`)](../next/README.md)
* [NestJS Module (`@phinehas/nestjs`)](../nestjs/README.md)

---

## 7. License

Licensed under the [Apache-2.0 License](../../../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
