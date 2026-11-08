# `@phinehas/node`

> Active-defense security middleware for Express, Connect, Fastify, and raw Node.js HTTP servers with immediate TCP socket severance.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../../../LICENSE)
[![Yarn](https://img.shields.io/badge/yarn-pkg-2C8EBB.svg)](https://yarnpkg.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../../../compliance/)

---

## 1. Overview & Transport Severance

Traditional firewalls and web frameworks log attacks and return HTTP `403 Forbidden` or `404 Not Found` error pages. This consumes server CPU, database connections, and memory bandwidth, while leaking headers (e.g. `Server`, `X-Powered-By`) that confirm endpoint presence to automated crawlers.

`@phinehas/node` terminates the underlying TCP socket immediately via `req.socket.destroy()`. Attackers receive an abrupt transport reset (`ECONNRESET`) with **zero HTTP response bytes and zero diagnostic headers**, starving automated reconnaissance tools of feedback and crashing vulnerable scanner worker threads.

---

## 2. Installation

Install using **Yarn**:
```bash
yarn add @phinehas/node @phinehas/core
# Optional for multi-node Redis deployments:
yarn add ioredis
```

---

## 3. Production Express.js Integration

```typescript
import express from 'express';
import { phinehas } from '@phinehas/node';
import Redis from 'ioredis';

const app = express();

// =========================================================================
// PHINEHAS MIDDLEWARE (Explicit Required vs Optional Showcase)
// =========================================================================
app.use(
  phinehas({
    // [OPTIONAL - DEFAULT: 'terminate']
    // Enforcement action executed on malicious scan:
    // - 'terminate': Calls req.socket.destroy() immediately (ECONNRESET)
    // - 'reject':    Returns HTTP 403 Forbidden with zero-byte body
    // - 'tarpit':    Holds socket open to exhaust crawler concurrency
    action: 'terminate',

    // [OPTIONAL - DEFAULT: in-memory LRU store with 3600s TTL]
    storage: {
      // [OPTIONAL - DEFAULT: 'memory']
      // 'memory' for single-instance, 'redis' for multi-pod Kubernetes clusters
      driver: 'redis',

      // [REQUIRED IF driver === 'redis']
      client: new Redis(process.env.REDIS_URL || 'redis://localhost:6379'),

      // [OPTIONAL - DEFAULT: 3600 (1 hour)]
      // Duration in seconds for which an attacking IP is banned. Set to 0 for permanent.
      ttl: 86400,

      // [OPTIONAL - DEFAULT: 'phinehas:ban:']
      keyPrefix: 'phinehas:ban:',
    },

    // [PRODUCTION RECOMMENDED - DEFAULT: false]
    // Set to true when running behind Cloudflare, AWS ALB, Nginx, or Google Cloud Armor.
    proxy: {
      // [REQUIRED IF BEHIND PROXY]
      trust: true,

      // [OPTIONAL - DEFAULT: 'x-forwarded-for']
      // Specific trusted client IP header to inspect:
      // 'cf-connecting-ip' (Cloudflare), 'true-client-ip' (Akamai), or 'x-forwarded-for'
      header: 'cf-connecting-ip',

      // [OPTIONAL - DEFAULT: 1]
      // Number of reverse proxy hops to traverse in X-Forwarded-For chain
      depth: 1,
    },

    // [OPTIONAL - DEFAULT: ['127.0.0.1', '::1']]
    // Trusted IP addresses or loopbacks exempt from all threat evaluation
    allowList: ['127.0.0.1', '::1', '10.0.0.1'],

    // [OPTIONAL - DEFAULT: built-in signatures + RFC 8615]
    honeypots: {
      // Additional regex patterns or paths to classify as malicious probes
      custom: [
        /^\/internal-admin(\/.*)?$/,
        /^\/debug\/vars$/,
        '/api/v1/dump-credentials',
      ],

      // [OPTIONAL - DEFAULT: false]
      // Set to true to disable default CMS/DB/debugger traps
      excludeDefaults: false,
    },

    // [OPTIONAL - DEFAULT: { format: 'structured' }]
    logging: {
      // 'structured' (JSON formatted for Datadog/Loki) or 'compact' (terminal)
      format: 'structured',

      // Custom event callback for real-time alerting (Slack, PagerDuty, Prometheus)
      onStrike: (strike) => {
        console.warn(`[SECURITY ALERT] Dropped ${strike.ip} probing ${strike.path}`, {
          ruleMatched: strike.ruleMatched,
          timestamp: strike.timestamp,
        });
      },
    },
  })
);

// [REQUIRED] Application routes mounted AFTER Phinehas
app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
```

---

## 4. Fastify Framework Integration

In Fastify, register Phinehas via the `onRequest` hook to evaluate incoming connections before route parsing:

```typescript
import Fastify from 'fastify';
import { phinehas } from '@phinehas/node';

const fastify = Fastify({ logger: true });

const guard = phinehas({
  action: 'terminate',
  proxy: { trust: true },
});

// [REQUIRED] Register hook at the earliest entry point
fastify.addHook('onRequest', async (request, reply) => {
  await new Promise<void>((resolve, reject) => {
    guard(request.raw, reply.raw, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
});

fastify.get('/api/health', async () => ({ status: 'ok' }));

fastify.listen({ port: 3000 });
```

---

## 5. Raw Node.js `http.createServer`

You can use Phinehas directly in vanilla Node.js without any framework:

```typescript
import http from 'node:http';
import { phinehas } from '@phinehas/node';

const guard = phinehas({ action: 'terminate' });

const server = http.createServer((req, res) => {
  guard(req, res, () => {
    // Normal request handling
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  });
});

server.listen(8080);
```

---

## 6. Testing Your Application with Phinehas

When writing unit and integration tests with `supertest`, automated test runners expect HTTP responses and may report `ECONNRESET` as a test error when Phinehas destroys attacker sockets.

To test both clean pass-through and strike behavior cleanly:

```typescript
import request from 'supertest';
import express from 'express';
import { phinehas } from '@phinehas/node';

describe('Phinehas Express Security Middleware', () => {
  const app = express();

  // Use action: 'reject' in integration test suites to assert on HTTP 403
  app.use(phinehas({ action: 'reject' }));
  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

  it('allows legitimate application traffic', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  it('safely allows RFC 8615 .well-known discovery endpoints', async () => {
    const res = await request(app).get('/.well-known/security.txt');
    // Passes through Phinehas to 404 (route not found in app, but not blocked by security guard)
    expect(res.status).toBe(404);
  });

  it('intercepts and blocks dotfile reconnaissance', async () => {
    const res = await request(app).get('/.env');
    expect(res.status).toBe(403);
  });

  it('intercepts obfuscated directory traversal attempts', async () => {
    const res = await request(app).get('//%2e%2e/wp-config.php');
    expect(res.status).toBe(403);
  });
});
```

---

## 7. Action Modes Explained

* **`'terminate'` (Default):** Calls `req.socket.destroy()`. Drops the connection abruptly at the TCP layer with no HTTP status code, leaking zero bytes. Defensively handles `ECONNRESET` so your Node.js process never crashes.
* **`'reject'`:** Returns an immediate HTTP `403 Forbidden` with a zero-length body and `Connection: close`.
* **`'tarpit'`:** Holds the socket open, dripping 1 byte every 10 seconds to exhaust the attacker's concurrency pool.

---

## 8. Navigation

* [Root SDK Documentation](../../../../README.md)
* [Core Engine Guide (`@phinehas/core`)](../core/README.md)
* [Next.js Edge Guard (`@phinehas/next`)](../next/README.md)
* [NestJS Module (`@phinehas/nestjs`)](../nestjs/README.md)

---

## 9. License

Licensed under the [Apache-2.0 License](../../../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
