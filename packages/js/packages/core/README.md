# `@phinehas/core`

> The foundational threat detection engine, RFC 8615 lookahead matcher, anti-bypass path normalizer, and zero-allocation LRU state driver for Phinehas.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue)](https://www.typescriptlang.org/)

---

## Overview

`@phinehas/core` implements the deterministic threat evaluation mechanics for the Phinehas active defense architecture ("The Spear"). It is designed to evaluate raw incoming HTTP request paths in $O(1)$ constant time, evading bypass techniques, and deterministically isolating reconnaissance bots before request payloads reach application controllers.

---

## Installation

```bash
yarn add @phinehas/core
```

---

## Core Capabilities

### 1. RFC 8615-Compliant Wildcard Trapping
Evaluates paths beginning with a dot using a strict negative lookahead regular expression:

```regex
^\/\.(?!well-known(\/|$))[a-zA-Z0-9_\-\.]+
```

* **Trapped (Instant Strike):** `/.env`, `/.git/HEAD`, `/.aws/credentials`, `/.kube/config`, `/.DS_Store`, `/.vscode/settings.json`, `/.ssh/id_rsa`.
* **Safely Allowed:** `/.well-known/acme-challenge/*`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json`, `/.well-known/security.txt`.

### 2. 6-Stage Anti-Bypass Normalization Pipeline
Before rule matching, paths pass through `normalizePath()`:
1. **Hex URL Decoding:** Decodes `%2e` (`.`), `%2f` (`/`), `%5c` (`\`), and multi-byte hex representations iteratively.
2. **Backslash Conversion:** Converts Windows-style `\` to standard `/`.
3. **Sequential Slash Collapsing:** Merges `////` down to `/`.
4. **Path Traversal Resolution:** Safely folds `/api/v1/../../.env` to `/.env` without escaping root.
5. **Lowercasing:** Normalizes characters to lowercase (`/.EnV` $\rightarrow$ `/.env`).
6. **Trailing Slash Removal:** Enforces consistent endpoint matching (`/wp-admin/` $\rightarrow$ `/wp-admin`).

### 3. High-Performance Zero-Allocation Storage (`BanStore`)
* **`MemoryStore`:** Doubly-linked list + hash map LRU cache capped at **25,000 IP entries** ($<5\text{MB}$ memory footprint) with automatic $O(1)$ idle and expiry eviction.
* **`RedisStore`:** Distributed cluster ban storage (`SET phinehas:ban:<ip> "1" EX <ttl>`) shielded by an in-memory 5-second L1 cache to protect Redis connections during massive scans.
* **Fail-Open Policy:** Storage exceptions are caught defensively, ensuring security checks never take down host applications.

---

## API Reference

### `ThreatEvaluator`

```typescript
import { ThreatEvaluator } from '@phinehas/core';

const evaluator = new ThreatEvaluator({
  custom: ['/api/internal/debug'],
  excludeDefaults: false
});

const result = evaluator.evaluate('/%2eenv');
console.log(result);
// {
//   isBlocked: true,
//   ruleMatched: 'rfc8615_wildcard',
//   normalizedPath: '/.env',
//   reason: 'Matched RFC 8615 hidden path wildcard: /.env'
// }
```

### `MemoryStore`

```typescript
import { MemoryStore } from '@phinehas/core';

const store = new MemoryStore({
  maxCapacity: 25000,
  defaultTtlSeconds: 3600 // 1 hour
});

store.ban('192.0.2.1', 86400);
console.log(store.isBanned('192.0.2.1')); // true
```

### `PhinehasLogger`

```typescript
import { PhinehasLogger } from '@phinehas/core';

const logger = new PhinehasLogger({
  format: 'structured', // Outputs JSON formatted for Loki/Datadog/Vector
  onStrike: (strike) => {
    // Custom Slack / PagerDuty webhook hook
  }
});
```

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
