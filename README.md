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

## 3. Quickstart Examples

### Node.js (Express)
```typescript
import express from 'express';
import { phinehas } from '@phinehas/node';

const app = express();

// Register Phinehas before all route handlers
app.use(phinehas({
  action: 'sever',             // Immediately destroy attacker TCP sockets
  banThreshold: 3,             // Ban after 3 malicious reconnaissance attempts
  banDurationSeconds: 86400,   // 24-hour ban duration
}));

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.listen(3000);
```

### Python (FastAPI / Starlette)
```python
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware

app = FastAPI()

app.add_middleware(
    PhinehasMiddleware,
    action="sever",              # Drops ASGI socket instantly
    ban_threshold=3,
    ban_duration_seconds=86400,
)

@app.get("/api/health")
async def health():
    return {"status": "ok"}
```

### Golang (`net/http`)
```go
package main

import (
	"net/http"
	"github.com/phinehas-hq/sdks/packages/go"
)

func main() {
	guard := phinehas.New(phinehas.Config{
		Action:             phinehas.ActionSever, // Hijacks and severs TCP connection
		BanThreshold:       3,
		BanDurationSeconds: 86400,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.ListenAndServe(":8080", guard.Wrap(mux))
}
```

### PHP (Laravel 11)
```php
// bootstrap/app.php
use Illuminate\Foundation\Application;
use Phinehas\Laravel\PhinehasMiddleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->prepend(PhinehasMiddleware::class);
    })
    ->create();
```

---

## 4. Threat Interception Lifecycle

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
| - Action "sever": Abrupt TCP RST (zero bytes, zero headers)                            |
| - Action "drop":  HTTP 403 Forbidden without headers or body bytes                     |
| - Action "tarpit": Holds attacker socket open for 5 seconds, exhausting bot worker     |
| - Strike Count >= banThreshold -> IP banned across cluster                             |
+----------------------------------------------------------------------------------------+
```

---

## 5. Shared Compliance Test Suite (`compliance/`)

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

## 6. Action Modes & Configuration

Every SDK supports identical configuration parameters:

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `action` | `string` | `"sever"` | Enforcement mode: `"sever"` (kill TCP socket), `"drop"` (HTTP 403), or `"tarpit"` (artificial delay). |
| `banThreshold` | `number` | `3` | Number of malicious strikes within window before IP is banned. |
| `banDurationSeconds`| `number` | `86400` | Duration of the IP ban in seconds (default: 24 hours). `0` = permanent. |
| `strikeWindowSeconds`| `number`| `60` | Time window in seconds during which strikes accumulate. |
| `customTraps` | `string[]`| `[]` | Additional regex patterns or literal paths to classify as malicious. |
| `whitelist` | `string[]`| `[]` | Exact paths or CIDR blocks exempt from threat evaluation. |
| `trustProxy` | `boolean` | `false` | When behind a reverse proxy/CDN, trusts `CF-Connecting-IP`, `X-Forwarded-For`, etc. |
| `tarpitDelayMs` | `number` | `5000` | Delay in milliseconds applied when `action: "tarpit"`. |

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
