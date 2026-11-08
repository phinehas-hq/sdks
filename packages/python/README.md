# `phinehas` (Python)

> Active-defense in-process security middleware for Python web frameworks (FastAPI, Starlette, Django, Flask, and WSGI) with immediate connection severance, zero-allocation LRU, and RFC 8615-compliant wildcard detection.

[![PyPI version](https://img.shields.io/pypi/v/phinehas.svg)](https://pypi.org/project/phinehas/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

---

## Overview

Traditional web application firewalls and Python middlewares log scans and return HTTP 403 or 404 responses. This consumes server CPU, database connections, and worker threads, while confirming endpoint existence to attackers.

`phinehas` terminates the underlying connection immediately, starving automated reconnaissance crawlers of diagnostic feedback and triggering instant connection timeouts.

---

## Installation

Using modern Python package managers (**uv** recommended per best practices):

```bash
uv add phinehas
# Or install with framework extras:
uv add "phinehas[fastapi,redis]"
uv add "phinehas[django]"
uv add "phinehas[flask]"
```

Or via Poetry:
```bash
poetry add phinehas
```

---

## 1. FastAPI / Starlette (ASGI)

```python
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware

app = FastAPI()

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

## 2. Django (WSGI & ASGI)

In your Django `settings.py`:

```python
MIDDLEWARE = [
    "phinehas.django.PhinehasMiddleware",
    # ... other middlewares
]

PHINEHAS = {
    "ACTION": "terminate",   # 'terminate' or 'reject'
    "TTL": 86400,            # 24-hour ban
    "ALLOW_LIST": ["127.0.0.1", "::1"],
    "PROXY": {
        "TRUST": True,
        "HEADER": "HTTP_CF_CONNECTING_IP",  # Cloudflare / ALB trusted proxy header
    },
    "CUSTOM_TRAPS": ["/internal/secret.json"],
}
```

---

## 3. Flask Extension

```python
from flask import Flask
from phinehas.flask import Phinehas

app = Flask(__name__)

# Register Phinehas with Flask
phinehas = Phinehas(
    app,
    action="terminate",
    ttl=86400,
    allow_list=["127.0.0.1"],
    proxy_trust=True,
    proxy_header="CF-Connecting-IP"
)

@app.route("/api/v1/health")
def health():
    return {"status": "ok"}
```

---

## 4. Universal WSGI Middleware (Gunicorn, uWSGI, Falcon, Bottle)

```python
from phinehas.wsgi import PhinehasWSGIMiddleware

def raw_wsgi_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "application/json")])
    return [b'{"status": "ok"}']

# Wrap any WSGI callable
app = PhinehasWSGIMiddleware(
    raw_wsgi_app,
    action="terminate",
    ttl=3600
)
```

---

## Multi-Instance Redis Cluster Deployment

For container fleets (Kubernetes, AWS ECS, Docker Swarm), sync bans cluster-wide using `redis.asyncio`:

```python
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
    proxy_header="cf-connecting-ip"
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

* **`"terminate"` (Default):** Closes the connection immediately without emitting HTTP headers or status codes. Attacker tools encounter raw connection resets.
* **`"reject"`:** Emits an immediate HTTP `403 Forbidden` with a zero-length body and `X-Phinehas-Verdict: blocked`.
* **`"tarpit"`:** Holds the connection open, dripping bytes to exhaust crawler connection pools.

---

## License

Apache-2.0. Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
