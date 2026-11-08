# `@phinehas/node`

> Active-defense security middleware for Express, Connect, and raw Node.js HTTP servers with immediate TCP socket severance.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Yarn](https://img.shields.io/badge/yarn-pkg-2C8EBB.svg)](https://yarnpkg.com/)

---

## Overview

Traditional firewalls and web frameworks log attacks and return HTTP `403` or `404` error pages. This consumes server CPU, database connections, and memory bandwidth, giving attackers clear confirmation that an endpoint exists.

`@phinehas/node` terminates the underlying TCP socket immediately (`req.socket.destroy()`). Attackers receive zero bytes and zero diagnostic feedback, triggering abrupt connection resets and timeouts on automated crawling tools.

---

## Installation

```bash
yarn add @phinehas/node @phinehas/core
```

---

## Quick Start (Express)

```typescript
import express from 'express';
import { phinehas } from '@phinehas/node';

const app = express();

// Register Phinehas as the very first middleware
app.use(phinehas({
  action: 'terminate', // Drops the raw TCP socket immediately (Default)
  storage: {
    driver: 'memory',
    ttl: 3600 // Ban attacking IP for 1 hour
  },
  logging: {
    format: 'structured',
    onStrike: (strike) => {
      console.warn(`[STRIKE] Dropped ${strike.ip} probing ${strike.path}`);
    }
  }
}));

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok' }));

app.listen(3000);
```

---

## Distributed Redis Deployment

For multi-pod clusters (Kubernetes / Docker Swarm), sync bans across all nodes via Redis:

```typescript
import express from 'express';
import { phinehas } from '@phinehas/node';
import Redis from 'ioredis';

const app = express();
const redis = new Redis(process.env.REDIS_URL!);

app.set('trust proxy', true);

app.use(phinehas({
  storage: {
    driver: 'redis',
    client: redis,
    ttl: 86400, // 24-hour ban across entire cluster
    keyPrefix: 'phinehas:ban:'
  },
  proxy: {
    trust: true,
    header: 'cf-connecting-ip' // Cloudflare / ALB trusted proxy header
  }
}));
```

---

## Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `action` | `'terminate' \| 'reject' \| 'tarpit'` | `'terminate'` | Defense action executed on attack. |
| `storage.driver` | `'memory' \| 'redis'` | `'memory'` | Storage engine for banned IPs. |
| `storage.ttl` | `number \| null` | `3600` | Ban duration in seconds (`0` or `null` for permanent). |
| `storage.client` | `any` | `undefined` | Active Redis client instance (`ioredis` or `node-redis`). |
| `allowList` | `string[]` | `['127.0.0.1', '::1']` | Whitelisted IP addresses exempt from bans. |
| `proxy.trust` | `boolean` | `false` | Whether to trust reverse proxy headers. |
| `proxy.header` | `string` | `undefined` | Custom IP header (e.g. `'cf-connecting-ip'`). |
| `proxy.depth` | `number` | `undefined` | Number of proxy hops to traverse in `X-Forwarded-For`. |
| `honeypots.custom` | `string[]` | `[]` | Extra paths to trap (e.g. `['/secret.json']`). |
| `logging.format` | `'structured' \| 'compact'` | `'structured'` | Structured JSON vs compact stdout text. |

---

## Action Modes Explained

* **`'terminate'` (Default):** Calls `req.socket.destroy()`. Drops the connection abruptly with no HTTP status code, leaking zero bytes. Defensively handles `ECONNRESET` so your Node.js process never crashes.
* **`'reject'`:** Returns an immediate HTTP `403 Forbidden` with a zero-length body and `Connection: close`.
* **`'tarpit'`:** Holds the socket open, dripping 1 byte every 10 seconds to exhaust the attacker's concurrency pool.

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
