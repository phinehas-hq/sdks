# `phinehas` (Python)

> Active-defense in-process security middleware for Python web frameworks (FastAPI, Starlette, Django) with immediate ASGI connection severance, zero-allocation LRU, and RFC 8615-compliant wildcard detection.

[![PyPI version](https://img.shields.io/pypi/v/phinehas.svg)](https://pypi.org/project/phinehas/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

---

## Overview

Traditional web application firewalls and Python middlewares log scans and return HTTP 403 or 404 responses. This consumes server CPU, database connections, and worker threads, while confirming endpoint existence to attackers.

`phinehas` terminates the underlying ASGI connection immediately, starving automated reconnaissance crawlers of diagnostic feedback and triggering instant connection timeouts.

---

## Installation

Using modern Python package managers (**uv** recommended):

```bash
uv add phinehas
# Or with FastAPI and Redis dependencies
uv add "phinehas[fastapi,redis]"
```

Or via Poetry:
```bash
poetry add phinehas
```

---

## Quick Start (FastAPI / Starlette)

```python
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware

app = FastAPI()

# Register Phinehas before all application routes
app.add_middleware(
    PhinehasMiddleware,
    ttl=86400,             # Ban attacking IPs for 24 hours
    action="terminate",    # Sever ASGI connection immediately (Default)
    custom_traps=["/backup.dump", "/admin_test.php"],
    on_strike=lambda strike: print(f"[STRIKE] Severed {strike['ip']} accessing {strike['path']}")
)

@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}
```

---

## Multi-Instance Redis Cluster Deployment

For container fleets (Kubernetes, AWS ECS, Docker Swarm), sync bans cluster-wide using `redis.asyncio`:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware
import redis.asyncio as aioredis

redis_client = aioredis.from_url("redis://localhost:6379", decode_responses=True)

app = FastAPI()

app.add_middleware(
    PhinehasMiddleware,
    redis_client=redis_client,
    ttl=86400,
    action="terminate",
    proxy_trust=True,
    proxy_header="cf-connecting-ip"  # Cloudflare / AWS ALB header
)
```

---

## Configuration Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `action` | `"terminate" \| "reject" \| "tarpit"` | `"terminate"` | Defense action executed upon detecting an attack or banned IP. |
| `ttl` | `Optional[int]` | `3600` | Ban duration in seconds (`None` or `0` for permanent). |
| `storage` | `Optional[BanStore]` | `None` | Custom storage driver implementing `BanStore`. |
| `redis_client` | `Optional[Any]` | `None` | Active `redis.asyncio.Redis` instance. |
| `allow_list` | `Optional[List[str]]` | `["127.0.0.1", "::1"]` | Exempt IP addresses (never banned or trapped). |
| `proxy_trust` | `bool` | `False` | Whether to parse reverse proxy headers. |
| `proxy_header` | `Optional[str]` | `None` | Custom header (e.g. `"cf-connecting-ip"`). |
| `proxy_depth` | `Optional[int]` | `None` | Number of proxy hops to inspect in `X-Forwarded-For`. |
| `custom_traps` | `Optional[List[str]]` | `None` | Extra application routes to trap. |
| `exclude_defaults` | `bool` | `False` | Disable standard non-dot threat signatures. |
| `logging_format` | `"structured" \| "compact"` | `"structured"` | Structured JSON vs compact stderr text. |
| `on_strike` | `Optional[Callable]` | `None` | Callback hook for Slack, Discord, or Datadog alerts. |

---

## Action Modes Explained

* **`"terminate"` (Default):** Closes the ASGI connection immediately without emitting HTTP headers or status codes. Attacker tools encounter raw connection resets.
* **`"reject"`:** Emits an immediate HTTP `403 Forbidden` with a zero-length body and `X-Phinehas-Verdict: blocked`.
* **`"tarpit"`:** Holds the connection open, dripping 1 byte every 10 seconds to exhaust crawler connection pools.

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
