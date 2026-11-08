# Phinehas SDKs

> *"Then stood up Phinehas, and executed judgment: and so the plague was stayed."* — Psalms 106:30  
> **The Spear: Zero-Tolerance Active Defense & Perimeter Interception Middleware.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GitHub Org](https://img.shields.io/badge/org-phinehas--hq-181717.svg?logo=github)](https://github.com/phinehas-hq)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25%20passing-brightgreen.svg)](compliance/)
[![Node.js](https://img.shields.io/badge/node-18%2B-339933.svg?logo=node.js&logoColor=white)](packages/js/packages/node/README.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](packages/python/README.md)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg?logo=go&logoColor=white)](packages/go/README.md)
[![PHP](https://img.shields.io/badge/php-8.2%2B-777BB4.svg?logo=php&logoColor=white)](packages/php/README.md)

---

## 1. What to Expect: The Active Defense Paradigm

Traditional web application firewalls (WAFs), reverse proxies, and web framework rate-limiters are **passive**. When an automated botnet or malicious crawler scans for sensitive configuration files (`/.env`, `/.git/config`), database dumps (`/dump.sql`), or administration consoles (`/phpmyadmin/`), standard applications:
1. Process the request through full routing, controller dispatch, and template pipelines.
2. Consume server CPU, worker threads, and precious database pool connections.
3. Return verbose HTTP `404 Not Found` or `403 Forbidden` error pages with headers that confirm the backend technology stack (e.g. `Server`, `X-Powered-By`).

**Phinehas operates on a fundamentally different philosophy: Strike & Sever.**

```
+---------------------------------------------------------------------------------------+
|                               INCOMING HTTP REQUEST                                   |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
    +-------------------------------------------------------------------------------+
    | 1. DETERMINISTIC PATH NORMALIZATION (< 5 microseconds)                        |
    |    - Hex percent-decoding (%2e -> .)                                          |
    |    - Backslash conversion (\ -> /)                                            |
    |    - Directory traversal flattening (/a/../ -> /)                             |
    |    - Multi-slash collapsing (/// -> /)                                        |
    |    - Case normalization & trailing slash removal                              |
    +-------------------------------------------------------------------------------+
                                           |
                                           v
    +-------------------------------------------------------------------------------+
    | 2. RFC 8615 SAFE HARBOR INSPECTION (< 2 microseconds)                         |
    |    - Matches `/.well-known/*`? --> SAFE: Bypasses dotfile rules               |
    |    - Matches `/\.(?!well-known)[a-zA-Z0-9_\-\.]+`? --> MALICIOUS RECONNAISSANCE|
    +-------------------------------------------------------------------------------+
                                           |
                         +-----------------+-----------------+
                         |                                   |
                   [Clean Path]                       [Threat Vector]
                         |                                   |
                         v                                   v
    +-----------------------------------------+   +------------------------------------+
    | 3. PASS TO APPLICATION LOGIC            |   | 4. ATOMIC STRIKE & SEVER           |
    |    - Controllers, routers, ORM          |   |    - Increment strike counter (LRU)|
    |    - Sub-15 microsecond overhead        |   |    - Sever TCP socket immediately  |
    +-----------------------------------------+   |      (`req.socket.destroy()`,      |
                                                  |       ASGI disconnect, Go hijack)  |
                                                  |    - Zero HTTP headers returned    |
                                                  |    - Attacker receives ECONNRESET  |
                                                  +------------------------------------+
```

### Core Architectural Guarantees

* **Physical TCP Socket Termination:** Drops malicious connections at the transport layer (`req.socket.destroy()` in Node, ASGI socket disconnect in Python, `http.Hijacker` in Go). Attackers receive an abrupt connection reset (`ECONNRESET`) with **zero HTTP response bytes and zero diagnostic headers**.
* **Zero False Positives for RFC 8615:** Built-in negative lookaheads guarantee that legitimate automated services (ACME Let's Encrypt certificates, OpenID discovery, Apple Pay associations, and `security.txt` disclosures) are never blocked.
* **Deterministic Anti-Bypass Normalization:** Request paths pass through a 6-stage sanitization pipeline to defeat hex-encoding evasions (`%2e%2e`), Windows path separators (`\`), directory traversal obfuscations, and duplicate slash delimiters before matching.
* **Zero-Allocation In-Memory Shield:** In-memory $O(1)$ LRU cache (capped to 25,000 entries by default) blocks repeat offenders instantaneously. Optional Redis storage adapter provides distributed ban synchronization across multi-instance clusters with local L1 shielding.
* **Fail-Open Resilience:** If Redis is unreachable or a memory boundary fails, Phinehas yields control downstream to application logic. Security logic will never cause operational downtime.

---

## 2. Multi-Language & Framework Navigation Matrix

Every SDK package in this monorepo is tested against the shared compliance suite and follows the native idioms and tooling of its language ecosystem. Click any framework link below for detailed integration documentation:

| Ecosystem | Framework / Environment | Package Name | Package Manager | Documentation Guide |
| :--- | :--- | :--- | :--- | :--- |
| **Node.js / TS** | Core Engine | [`@phinehas/core`](packages/js/packages/core/) | `yarn add @phinehas/core` | [Core Engine Guide](packages/js/packages/core/README.md) |
| **Node.js / TS** | Express & Raw HTTP | [`@phinehas/node`](packages/js/packages/node/) | `yarn add @phinehas/node @phinehas/core` | [Node / Express Guide](packages/js/packages/node/README.md) |
| **Node.js / TS** | Next.js (Edge & Server) | [`@phinehas/next`](packages/js/packages/next/) | `yarn add @phinehas/next @phinehas/core` | [Next.js Guard Guide](packages/js/packages/next/README.md) |
| **Node.js / TS** | NestJS Module | [`@phinehas/nestjs`](packages/js/packages/nestjs/) | `yarn add @phinehas/nestjs @phinehas/node @phinehas/core` | [NestJS Module Guide](packages/js/packages/nestjs/README.md) |
| **Python** | FastAPI & Starlette (ASGI) | [`phinehas`](packages/python/) | `uv add "phinehas[fastapi]"` | [FastAPI Guide](packages/python/README.md#1-fastapi--starlette-asgi) |
| **Python** | Django (WSGI & ASGI) | [`phinehas`](packages/python/) | `uv add "phinehas[django]"` | [Django Guide](packages/python/README.md#2-django-wsgi--asgi) |
| **Python** | Flask Extension | [`phinehas`](packages/python/) | `uv add "phinehas[flask]"` | [Flask Guide](packages/python/README.md#3-flask-extension) |
| **Python** | Universal WSGI (Gunicorn / uWSGI) | [`phinehas`](packages/python/) | `uv add phinehas` | [WSGI Guide](packages/python/README.md#4-universal-wsgi-middleware-gunicorn-uwsgi-falcon-bottle) |
| **Golang** | Standard Library `net/http` | [`sdks/packages/go`](packages/go/) | `go get github.com/phinehas-hq/sdks/packages/go` | [net/http Guide](packages/go/README.md#quick-start-nethttp) |
| **Golang** | Gin Framework | [`sdks/packages/go`](packages/go/) | `go get github.com/phinehas-hq/sdks/packages/go` | [Gin Guide](packages/go/README.md#gin-framework) |
| **Golang** | Chi Router | [`sdks/packages/go`](packages/go/) | `go get github.com/phinehas-hq/sdks/packages/go` | [Chi Guide](packages/go/README.md#chi-router) |
| **Golang** | Echo Framework | [`sdks/packages/go`](packages/go/) | `go get github.com/phinehas-hq/sdks/packages/go` | [Echo Guide](packages/go/README.md#echo-framework) |
| **PHP** | Laravel 11+ | [`phinehas/phinehas-php`](packages/php/) | `composer require phinehas/phinehas-php` | [Laravel 11 Guide](packages/php/README.md#quick-start-laravel-11) |
| **PHP** | Symfony | [`phinehas/phinehas-php`](packages/php/) | `composer require phinehas/phinehas-php` | [Symfony Guide](packages/php/README.md#symfony-integration) |
| **PHP** | Standalone / PSR-15 | [`phinehas/phinehas-php`](packages/php/) | `composer require phinehas/phinehas-php` | [Standalone Guide](packages/php/README.md#standalone-php-usage) |

---

## 3. Comprehensive Framework Examples & Option Guides

Below are full, production-ready examples for every supported framework. Each code example explicitly distinguishes **`[REQUIRED]`** setup from **`[OPTIONAL]`** tuning parameters and **`[PRODUCTION RECOMMENDED]`** cluster settings.

---

### A. Node.js & TypeScript

#### 1. Express / Connect / Fastify (`@phinehas/node`)

Install using **Yarn**:
```bash
yarn add @phinehas/node @phinehas/core
# Optional Redis cluster support:
yarn add ioredis
```

```typescript
import express from 'express';
import { phinehas, RedisStore, MemoryStore } from '@phinehas/node';
import Redis from 'ioredis';

const app = express();

// =========================================================================
// PRODUCTION CONFIGURATION (Explicit Required vs Optional Showcase)
// =========================================================================
app.use(
  phinehas({
    // [OPTIONAL - DEFAULT: "terminate"]
    // Enforcement action on detection:
    // - "terminate": Destroys underlying TCP socket immediately (ECONNRESET)
    // - "reject":    Returns HTTP 403 Forbidden with zero response body bytes
    // - "tarpit": Holds attacker socket open for `tarpitDelayMs` to starve crawler
    action: 'terminate',

    // [OPTIONAL - DEFAULT: 3]
    // Number of malicious reconnaissance attempts before an IP is banned
    banThreshold: 3,

    // [OPTIONAL - DEFAULT: 86400 (24 hours)]
    // Ban duration in seconds. Set to 0 for a permanent ban.
    banDurationSeconds: 86400,

    // [OPTIONAL - DEFAULT: 60]
    // Rolling time window in seconds during which strikes accumulate
    strikeWindowSeconds: 60,

    // [PRODUCTION RECOMMENDED - DEFAULT: false]
    // Set to true when running behind Cloudflare, AWS ALB, Nginx, or Fastly.
    // Inspects CF-Connecting-IP, True-Client-IP, and X-Forwarded-For securely.
    trustProxy: true,

    // [OPTIONAL - DEFAULT: 1]
    // Number of reverse proxy hops to traverse in X-Forwarded-For header
    proxyDepth: 1,

    // [OPTIONAL - DEFAULT: []]
    // Additional application-specific honeypot routes or proprietary traps
    customTraps: [
      /^\/internal-admin(\/.*)?$/,
      /^\/api\/v\d+\/debug-console$/,
      '/super-secret-backdoor',
    ],

    // [OPTIONAL - DEFAULT: false]
    // If true, disables the built-in trap list (e.g. CMS, DB dumps, debuggers)
    // and evaluates ONLY customTraps + RFC 8615 dotfiles
    excludeDefaultTraps: false,

    // [OPTIONAL - DEFAULT: []]
    // Subnets (CIDR) or specific paths that are unconditionally allowed
    whitelist: [
      '127.0.0.1',
      '10.0.0.0/8',
      '/.well-known/custom-enterprise-verification',
    ],

    // [PRODUCTION RECOMMENDED FOR MULTI-SERVER CLUSTERS - DEFAULT: MemoryStore]
    // Synchronize bans across horizontal instances via Redis, backed by an
    // in-process L1 shield cache to preserve sub-15 microsecond latency:
    store: new RedisStore({
      client: new Redis(process.env.REDIS_URL || 'redis://localhost:6379'),
      prefix: 'phinehas:ban:',
      l1CacheTtlMs: 5000, // 5-second in-memory L1 shield preventing Redis query flood
    }),

    // [OPTIONAL - DEFAULT: 5000]
    // Milliseconds to hold the socket open when `action: "tarpit"` is active
    tarpitDelayMs: 5000,

    // [OPTIONAL - DEFAULT: built-in structured JSON logger]
    // Custom event callback for metrics pipelines (Datadog, OpenTelemetry, Prometheus)
    onStrike: (strikeEvent) => {
      console.warn(`[SECURITY ALERT] Strike recorded for IP ${strikeEvent.actor.ip}:`, {
        rule: strikeEvent.verdict.ruleMatched,
        path: strikeEvent.target.path,
        action: strikeEvent.verdict.actionTaken,
      });
    },
  })
);

// [REQUIRED] Normal application business routes continue below
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
```

---

#### 2. Next.js Edge & Server Guard (`@phinehas/next`)

In Next.js Edge Middleware (V8 Isolates), raw OS TCP sockets cannot be forcefully severed. `@phinehas/next` provides `createPhinehasEdgeGuard()`, returning zero-byte `403 Forbidden` responses before React Server Components or Edge API routes render.

Install using **Yarn**:
```bash
yarn add @phinehas/next @phinehas/core
```

```typescript
// middleware.ts (in your Next.js project root or src/)
import { NextRequest } from 'next/server';
import { createPhinehasEdgeGuard } from '@phinehas/next';

// =========================================================================
// INITIALIZE EDGE GUARD (Required vs Optional)
// =========================================================================
const phinehasGuard = createPhinehasEdgeGuard({
  // [OPTIONAL - DEFAULT: "drop"]
  // In V8 edge isolates, "drop" immediately returns a zero-byte 403 Forbidden
  action: 'reject',

  // [OPTIONAL - DEFAULT: 3]
  banThreshold: 3,

  // [OPTIONAL - DEFAULT: 86400]
  banDurationSeconds: 86400,

  // [PRODUCTION RECOMMENDED - DEFAULT: true on Next.js]
  // Automatically inspects Vercel/Cloudflare headers: req.ip, x-real-ip
  trustProxy: true,

  // [OPTIONAL - DEFAULT: []]
  // Protect your Next.js internal routes from probing
  customTraps: ['/_next/data/staging-secrets.json', '/api/debug/dump'],

  // [OPTIONAL - DEFAULT: []]
  whitelist: ['/.well-known/apple-developer-merchantid-domain-association'],
});

// [REQUIRED] Export Next.js middleware handler
export async function middleware(request: NextRequest) {
  return await phinehasGuard(request);
}

// [PRODUCTION RECOMMENDED] Match all paths except static assets & images
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

#### 3. NestJS Enterprise Module (`@phinehas/nestjs`)

Install using **Yarn**:
```bash
yarn add @phinehas/nestjs @phinehas/node @phinehas/core
```

```typescript
// app.module.ts
import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PhinehasModule, PhinehasMiddleware } from '@phinehas/nestjs';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),

    // =========================================================================
    // OPTION 1: STATIC REGISTRATION (PhinehasModule.forRoot)
    // =========================================================================
    PhinehasModule.forRoot({
      action: 'terminate',         // [OPTIONAL] 'terminate' | 'reject' | 'tarpit'
      banThreshold: 3,             // [OPTIONAL] Strikes before IP ban
      banDurationSeconds: 86400,   // [OPTIONAL] 24-hour ban
      trustProxy: true,            // [PRODUCTION RECOMMENDED]
    }),

    // =========================================================================
    // OPTION 2: ASYNC REGISTRATION (PhinehasModule.forRootAsync with ConfigService)
    // =========================================================================
    /*
    PhinehasModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        action: config.get('PHINEHAS_ACTION', 'terminate'),
        banThreshold: config.get<number>('PHINEHAS_BAN_THRESHOLD', 3),
        trustProxy: config.get<boolean>('TRUST_PROXY', true),
      }),
    }),
    */
  ],
})
export class AppModule implements NestModule {
  // [REQUIRED] Apply the Phinehas middleware globally across all routes
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(PhinehasMiddleware).forRoutes('*');
  }
}
```

---

### B. Python

Install using **`uv`**:
```bash
uv add phinehas
# Or install with framework-specific extras:
uv add "phinehas[fastapi]"
uv add "phinehas[django]"
uv add "phinehas[flask]"
uv add "phinehas[redis]"
```

---

#### 1. FastAPI / Starlette (ASGI)

```python
import os
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware
from phinehas.store import RedisStore, MemoryStore
import redis

app = FastAPI(title="Production Service")

# =========================================================================
# PRODUCTION ASGI MIDDLEWARE REGISTRATION
# =========================================================================
app.add_middleware(
    PhinehasMiddleware,
    # [OPTIONAL - DEFAULT: "terminate"]
    # "terminate": Immediately terminates the ASGI transport socket
    # "reject":    Returns HTTP 403 Forbidden with empty response body
    # "tarpit": Delays the response before dropping to exhaust crawlers
    action="terminate",

    # [OPTIONAL - DEFAULT: 3]
    # Number of strike events before the client IP is banned
    ban_threshold=3,

    # [OPTIONAL - DEFAULT: 86400]
    # Ban duration in seconds (86400 = 24 hours, 0 = permanent)
    ban_duration_seconds=86400,

    # [OPTIONAL - DEFAULT: 60]
    # Rolling window in seconds for strike accumulation
    strike_window_seconds=60,

    # [PRODUCTION RECOMMENDED - DEFAULT: False]
    # Set to True when deployed behind Cloudflare, Nginx, or AWS ALB
    trust_proxy=True,

    # [OPTIONAL - DEFAULT: 1]
    # Proxy hops in X-Forwarded-For
    proxy_depth=1,

    # [OPTIONAL - DEFAULT: []]
    # Custom application-specific threat regex patterns or exact paths
    custom_traps=[
        r"^/api/internal/.*",
        r"^/debug/metrics-dump$",
        "/phpmyadmin",
    ],

    # [OPTIONAL - DEFAULT: []]
    # Unconditionally allowed IP addresses, CIDR blocks, or URIs
    whitelist=[
        "127.0.0.1",
        "10.0.0.0/8",
        "/.well-known/security.txt",
    ],

    # [PRODUCTION RECOMMENDED FOR MULTI-WORKER DEPLOYMENTS - DEFAULT: MemoryStore()]
    # Distributed Redis store with local 5-second L1 cache:
    store=RedisStore(
        redis_client=redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0")),
        prefix="phinehas:ban:",
        l1_cache_ttl_seconds=5,
    ),

    # [OPTIONAL - DEFAULT: 5000]
    # Delay in milliseconds when action="tarpit"
    tarpit_delay_ms=5000,
)

# [REQUIRED] Application business routes
@app.get("/api/health")
async def health():
    return {"status": "ok"}
```

---

#### 2. Django (WSGI & ASGI)

```python
# settings.py
import os

# [REQUIRED] Prepend PhinehasMiddleware at the VERY TOP of your middleware pipeline
MIDDLEWARE = [
    'phinehas.django.PhinehasMiddleware',  # MUST execute before all other middlewares
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # ...
]

# =========================================================================
# PHINEHAS CONFIGURATION DICTIONARY (Required vs Optional)
# =========================================================================
PHINEHAS = {
    # [OPTIONAL - DEFAULT: 'terminate']
    'ACTION': 'terminate',

    # [OPTIONAL - DEFAULT: 3]
    'BAN_THRESHOLD': 3,

    # [OPTIONAL - DEFAULT: 86400]
    'BAN_DURATION_SECONDS': 86400,

    # [OPTIONAL - DEFAULT: 60]
    'STRIKE_WINDOW_SECONDS': 60,

    # [PRODUCTION RECOMMENDED - DEFAULT: False]
    # Set to True when behind Nginx or AWS Load Balancer
    'TRUST_PROXY': True,
    'PROXY_DEPTH': 1,

    # [OPTIONAL - DEFAULT: []]
    'CUSTOM_TRAPS': [
        r'^/private-admin/',
        r'^/debug/vars',
    ],

    # [OPTIONAL - DEFAULT: []]
    'WHITELIST': [
        '127.0.0.1',
        '/.well-known/acme-challenge/',
    ],

    # [PRODUCTION RECOMMENDED - DEFAULT: None (uses in-memory OrderedDict LRU)]
    # Connect to your Redis cluster for global ban synchronization
    'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379/1'),
    'REDIS_PREFIX': 'phinehas:django:ban:',

    # [OPTIONAL - DEFAULT: 5000]
    'TARPIT_DELAY_MS': 5000,
}
```

---

#### 3. Flask Extension

```python
import os
from flask import Flask, jsonify
from phinehas.flask import Phinehas

app = Flask(__name__)

# =========================================================================
# FLASK CONFIGURATION (Can be loaded from config object or environment)
# =========================================================================
app.config.update(
    PHINEHAS_ACTION="terminate",         # [OPTIONAL] 'terminate' | 'reject' | 'tarpit'
    PHINEHAS_BAN_THRESHOLD=3,            # [OPTIONAL] Strikes before IP ban
    PHINEHAS_BAN_DURATION_SECONDS=86400, # [OPTIONAL] 24-hour ban
    PHINEHAS_TRUST_PROXY=True,           # [PRODUCTION RECOMMENDED]
    PHINEHAS_CUSTOM_TRAPS=[              # [OPTIONAL]
        r"^/flask-admin/.*",
        "/internal/status",
    ],
    PHINEHAS_REDIS_URL=os.getenv("REDIS_URL"), # [PRODUCTION RECOMMENDED]
)

# [REQUIRED] Initialize the Phinehas extension
phinehas_guard = Phinehas(app)
# Or use application factory pattern:
# phinehas_guard = Phinehas()
# phinehas_guard.init_app(app)

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})
```

---

#### 4. Universal WSGI Middleware (Gunicorn / uWSGI)

```python
# wsgi.py (Universal WSGI wrapper for Gunicorn, uWSGI, Falcon, Bottle)
from my_application import app  # Any standard WSGI callable
from phinehas.wsgi import PhinehasWSGIMiddleware

# [REQUIRED] Wrap your application
application = PhinehasWSGIMiddleware(
    app,
    action="terminate",              # [OPTIONAL - DEFAULT: 'terminate']
    ban_threshold=3,             # [OPTIONAL - DEFAULT: 3]
    ban_duration_seconds=86400,  # [OPTIONAL - DEFAULT: 86400]
    trust_proxy=True,            # [PRODUCTION RECOMMENDED]
    custom_traps=[r"^/wp-login\.php$"], # [OPTIONAL]
)
```

Run with Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:8000 wsgi:application
```

---

### C. Golang

Install using **`go get`**:
```bash
go get github.com/phinehas-hq/sdks/packages/go
```

---

#### 1. Standard Library `net/http`

```go
package main

import (
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/phinehas-hq/sdks/packages/go"
)

func main() {
	// =====================================================================
	// PHINEHAS CONFIGURATION (Required vs Optional)
	// =====================================================================
	cfg := phinehas.Config{
		// [OPTIONAL - DEFAULT: ActionTerminate]
		// ActionTerminate: Hijacks connection via http.Hijacker and closes TCP socket
		// ActionReject:    Returns HTTP 403 Forbidden with empty body
		// ActionTarpit: Sleeps for TarpitDelayMs before severing socket
		Action: phinehas.ActionTerminate,

		// [OPTIONAL - DEFAULT: 3]
		// Strikes before client IP is banned
		BanThreshold: 3,

		// [OPTIONAL - DEFAULT: 86400]
		// Ban duration in seconds (86400 = 24h, 0 = permanent)
		BanDurationSeconds: 86400,

		// [OPTIONAL - DEFAULT: 60]
		// Rolling time window in seconds for strike accumulation
		StrikeWindowSeconds: 60,

		// [PRODUCTION RECOMMENDED - DEFAULT: false]
		// Enables CF-Connecting-IP, True-Client-IP, and X-Forwarded-For parsing
		TrustProxy: true,

		// [OPTIONAL - DEFAULT: 1]
		// Number of proxy hops to parse in X-Forwarded-For
		ProxyDepth: 1,

		// [OPTIONAL - DEFAULT: empty]
		// Additional compiled regex patterns or exact path traps
		CustomTraps: []*regexp.Regexp{
			regexp.MustCompile(`^/internal/system-info$`),
			regexp.MustCompile(`^/debug/pprof/.*`),
		},

		// [OPTIONAL - DEFAULT: empty]
		// Paths or CIDR blocks unconditionally allowed
		Whitelist: []string{
			"127.0.0.1",
			"/.well-known/matrix/server",
		},

		// [OPTIONAL - DEFAULT: 5000]
		// Milliseconds to delay connection when Action == ActionTarpit
		TarpitDelayMs: 5000,
	}

	// [REQUIRED] Initialize Guard
	guard := phinehas.New(cfg)

	// [REQUIRED] Standard HTTP multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	server := &http.Server{
		Addr:         ":8080",
		Handler:      guard.Wrap(mux), // [REQUIRED] Wrap router with Guard
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Listening on :8080 with Phinehas active defense...")
	log.Fatal(server.ListenAndServe())
}
```

---

#### 2. Gin, Chi, and Echo Frameworks

```go
// -------------------------------------------------------------------------
// GIN FRAMEWORK
// -------------------------------------------------------------------------
r := gin.Default()
guard := phinehas.New(phinehas.Config{Action: phinehas.ActionTerminate, TrustProxy: true})

r.Use(func(c *gin.Context) {
    guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        c.Next()
    })).ServeHTTP(c.Writer, c.Request)
})

// -------------------------------------------------------------------------
// CHI ROUTER
// -------------------------------------------------------------------------
r := chi.NewRouter()
guard := phinehas.New(phinehas.Config{Action: phinehas.ActionTerminate, TrustProxy: true})

r.Use(guard.Wrap)

// -------------------------------------------------------------------------
// ECHO FRAMEWORK
// -------------------------------------------------------------------------
e := echo.New()
guard := phinehas.New(phinehas.Config{Action: phinehas.ActionTerminate, TrustProxy: true})

e.Use(echo.WrapMiddleware(guard.Wrap))
```

---

### D. PHP

Install using **Composer**:
```bash
composer require phinehas/phinehas-php
```

---

#### 1. Laravel 11+ Integration

Publish the configuration file:
```bash
php artisan vendor:publish --tag=phinehas-config
```

```php
// config/phinehas.php (Comprehensive Configuration Schema)
return [
    /*
    |--------------------------------------------------------------------------
    | Enforcement Action
    |--------------------------------------------------------------------------
    | 'terminate': Forcefully exits script execution immediately
    | 'reject':    HTTP 403 Forbidden without diagnostic headers
    | 'tarpit': Sleeps for tarpit_delay_ms before terminating
    */
    'action' => env('PHINEHAS_ACTION', 'terminate'),

    // [OPTIONAL - DEFAULT: 3] Strike threshold before temporary or permanent ban
    'ban_threshold' => (int) env('PHINEHAS_BAN_THRESHOLD', 3),

    // [OPTIONAL - DEFAULT: 86400 (24h)] Ban duration in seconds (0 = permanent)
    'ban_duration_seconds' => (int) env('PHINEHAS_BAN_DURATION', 86400),

    // [OPTIONAL - DEFAULT: 60] Rolling window in seconds
    'strike_window_seconds' => (int) env('PHINEHAS_STRIKE_WINDOW', 60),

    // [PRODUCTION RECOMMENDED - DEFAULT: false]
    // Set to true when running behind Cloudflare or AWS ALB
    'trust_proxy' => (bool) env('PHINEHAS_TRUST_PROXY', true),

    // [OPTIONAL - DEFAULT: []] Additional regex traps
    'custom_traps' => [
        '/^\\/artisan-terminal/',
        '/^\\/telescope\\/api/',
    ],

    // [OPTIONAL - DEFAULT: []] Whitelisted paths or IP addresses
    'whitelist' => [
        '127.0.0.1',
        '/.well-known/apple-developer-merchantid-domain-association',
    ],

    // [PRODUCTION RECOMMENDED FOR MULTI-SERVER CLUSTERS]
    // 'memory' (default in-process LRU) or 'redis'
    'store' => env('PHINEHAS_STORE', 'redis'),
    'redis' => [
        'url' => env('REDIS_URL', 'redis://127.0.0.1:6379'),
        'prefix' => 'phinehas:ban:',
        'l1_ttl_seconds' => 5, // Local in-memory shield cache
    ],

    // [OPTIONAL - DEFAULT: 5000] Delay for tarpit mode
    'tarpit_delay_ms' => 5000,
];
```

Register the middleware in `bootstrap/app.php`:
```php
// bootstrap/app.php
use Illuminate\Foundation\Application;
use Phinehas\Laravel\PhinehasMiddleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        // [REQUIRED] Prepend Phinehas to execute before authentication & session state
        $middleware->prepend(PhinehasMiddleware::class);
    })
    ->create();
```

---

#### 2. Symfony Integration

Register `PhinehasListener` as a kernel event listener:
```yaml
# config/services.yaml
services:
    Phinehas\Symfony\PhinehasListener:
        arguments:
            $config:
                action: 'terminate'         # [OPTIONAL] 'terminate' | 'reject' | 'tarpit'
                ban_threshold: 3            # [OPTIONAL]
                ban_duration_seconds: 86400 # [OPTIONAL]
                trust_proxy: true           # [PRODUCTION RECOMMENDED]
                custom_traps:               # [OPTIONAL]
                    - '/^\\/app_dev\\.php/'
        tags:
            - { name: kernel.event_listener, event: kernel.request, priority: 4096 }
```

---

## 4. Master Configuration Dictionary

The following table provides the cross-ecosystem translation of every Phinehas configuration option:

| Option (JS / Go) | Option (Python / PHP) | Type | Default | Status | Detailed Purpose & Production Guidance |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `action` | `action` | `string` | `"terminate"` | Optional | Enforcement mode: `"terminate"` (kill TCP socket), `"reject"` (HTTP 403), or `"tarpit"` (crawler delay). |
| `banThreshold` | `ban_threshold` | `int` | `3` | Optional | Number of malicious reconnaissance attempts before IP is banned across the cluster. |
| `banDurationSeconds` | `ban_duration_seconds` | `int` | `86400` | Optional | IP ban duration in seconds (`86400` = 24 hours). Set to `0` for permanent bans. |
| `strikeWindowSeconds` | `strike_window_seconds` | `int` | `60` | Optional | Rolling window in seconds during which strikes accumulate toward `banThreshold`. |
| `trustProxy` | `trust_proxy` | `bool` | `false` | **Production** | Inspects `CF-Connecting-IP`, `True-Client-IP`, `X-Forwarded-For`. Must be `true` behind CDNs. |
| `proxyDepth` | `proxy_depth` | `int` | `1` | Optional | Number of trusted reverse proxy hops in `X-Forwarded-For` chain. |
| `customTraps` | `custom_traps` | `list` | `[]` | Optional | Custom regex patterns or literal paths classified as malicious (e.g. proprietary admin APIs). |
| `excludeDefaultTraps` | `exclude_default_traps` | `bool` | `false` | Optional | Disables built-in database/CMS/debugger trap list, evaluating only custom traps and dotfiles. |
| `whitelist` | `whitelist` | `list` | `[]` | Optional | CIDR blocks (`10.0.0.0/8`) or exact paths unconditionally exempted from threat evaluation. |
| `store` | `store` | `Store` | `Memory` | **Production** | In-memory $O(1)$ LRU (default) or distributed multi-node Redis with L1 read shielding. |
| `tarpitDelayMs` | `tarpit_delay_ms` | `int` | `5000` | Optional | Sleep delay in milliseconds before connection termination when `action: "tarpit"`. |
| `onStrike` / `logger` | `on_strike` / `logger` | `func` | `Stdout` | Optional | Custom structured logger / telemetry dispatcher for Datadog, Prometheus, or ELK. |

---

## 5. Threat Interception Lifecycle

Phinehas executes in $O(1)$ constant time on every incoming HTTP request:

```
+----------------------------------------------------------------------------------------+
| STAGE 1: Anti-Bypass Normalization                                                     |
| Raw Request: "GET //%2e%2e/app/\.env HTTP/1.1"                                         |
| Sanitized:   "/.env"                                                                   |
+----------------------------------------------------------------------------------------+
                                           |
                                           v
+----------------------------------------------------------------------------------------+
| STAGE 2: RFC 8615 & Dotfile Traps                                                      |
| Path: "/.well-known/security.txt" -> PASS (RFC 8615 Discovery Exemption)               |
| Path: "/.env"                     -> MATCH: Wildcard Dotfile Trap                      |
+----------------------------------------------------------------------------------------+
                                           |
                                           v
+----------------------------------------------------------------------------------------+
| STAGE 3: Explicit Threat Signatures                                                    |
| Path: "/wp-config.php", "/phpmyadmin", "/actuator/env", "/.git/HEAD"                   |
| Result: Malicious probe detected                                                       |
+----------------------------------------------------------------------------------------+
                                           |
                                           v
+----------------------------------------------------------------------------------------+
| STAGE 4: Enforcement & Action Dispatch                                                 |
| - Action "terminate": Abrupt TCP RST (zero bytes, zero headers)                        |
| - Action "reject":  HTTP 403 Forbidden without headers or body bytes                     |
| - Action "tarpit": Holds attacker socket open for 5 seconds, exhausting bot worker     |
| - Strike Count >= banThreshold -> IP banned across cluster                             |
+----------------------------------------------------------------------------------------+
```

---

## 6. Shared Compliance Test Suite (`compliance/`)

All SDK implementations are strictly verified against canonical, language-agnostic JSON test vectors located in [`compliance/`](compliance/):

* **[`compliance/rfc8615_vectors.json`](compliance/rfc8615_vectors.json):** Validates RFC 8615 safe harbor paths (`/.well-known/*`) against active dotfile traps (`/.env`, `/.git`, `/.aws`).
* **[`compliance/normalization_vectors.json`](compliance/normalization_vectors.json):** Validates hex encoding (`%2e`), backslash normalization (`\`), directory traversal stripping (`..`), and slash collapsing.
* **[`compliance/explicit_traps.json`](compliance/explicit_traps.json):** Validates default non-dotfile threat signatures (CMS configs, database dumps, debug endpoints).

### Running Compliance Tests Across All Languages

```bash
# 1. Node.js / TypeScript Test Suite (21 tests)
node --test packages/js/packages/*/tests/*.test.ts

# 2. Python Test Suite (15 tests)
python3 -m unittest discover -s packages/python/tests -p "test_*.py"

# 3. Golang Test Suite (9 tests)
cd packages/go && go test -v ./... && cd ../..

# 4. PHP Test Suite (7 tests)
php packages/php/tests/run.php
```

---

## 7. Monorepo Directory Layout

```
sdks/
├── [LICENSE](LICENSE)                                # Apache-2.0 Open Source License
├── [README.md](README.md)                            # Root Documentation & Navigation Hub
├── [compliance/](compliance/)                        # Canonical Compliance Test Vectors (SSOT)
│   ├── [rfc8615_vectors.json](compliance/rfc8615_vectors.json)
│   ├── [normalization_vectors.json](compliance/normalization_vectors.json)
│   └── [explicit_traps.json](compliance/explicit_traps.json)
│
└── packages/
    ├── [js/](packages/js/)                           # Node.js & TypeScript Monorepo (Yarn)
    │   ├── package.json                              # Workspace definition
    │   └── packages/
    │       ├── [core/](packages/js/packages/core/)   # Core detection engine & LRU store (@phinehas/core)
    │       ├── [node/](packages/js/packages/node/)   # Express & Node HTTP middleware (@phinehas/node)
    │       ├── [next/](packages/js/packages/next/)   # Next.js Edge & Server guard (@phinehas/next)
    │       └── [nestjs/](packages/js/packages/nestjs/) # NestJS Module & Middleware (@phinehas/nestjs)
    │
    ├── [python/](packages/python/)                   # Python SDK via uv (FastAPI, Django, Flask, WSGI)
    │   ├── [pyproject.toml](packages/python/pyproject.toml)
    │   └── [README.md](packages/python/README.md)
    │
    ├── [go/](packages/go/)                           # Golang SDK (net/http, Gin, Chi, Echo)
    │   ├── [go.mod](packages/go/go.mod)
    │   └── [README.md](packages/go/README.md)
    │
    └── [php/](packages/php/)                         # PHP SDK via Composer (Laravel 11, Symfony, PSR-15)
        ├── [composer.json](packages/php/composer.json)
        └── [README.md](packages/php/README.md)
```

---

## 8. Contributing & Security Reporting

* **Found a Vulnerability?** If you discover a bypass or security defect, please report it privately to [security@phinehas.dev](mailto:security@phinehas.dev) rather than opening a public issue.
* **Adding New Signatures:** Propose additions to [`compliance/explicit_traps.json`](compliance/explicit_traps.json) via Pull Request. Changes to the compliance vectors must pass across all 4 ecosystems before merging.
* **License:** Licensed under the [Apache-2.0 License](LICENSE).  
* **Organization:** Maintained with pride by [Phinehas HQ](https://github.com/phinehas-hq).
