# `phinehas` (Python)

> Active-defense in-process security middleware for Python web frameworks (FastAPI, Starlette, Django, Flask, and WSGI) with immediate connection severance, zero-allocation LRU, and RFC 8615-compliant wildcard detection.

[![PyPI version](https://img.shields.io/pypi/v/phinehas.svg)](https://pypi.org/project/phinehas/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Compliance Parity](https://img.shields.io/badge/compliance-100%25-brightgreen.svg)](../../compliance/)

---

## 1. Overview & Transport Severance

Traditional web application firewalls and Python middlewares log scans and return HTTP 403 or 404 responses. This consumes server CPU, database connections, and worker threads, while confirming endpoint existence to attackers through verbose response headers.

`phinehas` terminates the underlying connection immediately:
* **ASGI (FastAPI / Starlette):** Drops the ASGI transport socket, starving automated scanners of diagnostic feedback and triggering instant connection timeouts.
* **WSGI (Django / Flask / Gunicorn):** Emits zero-byte headers and closes the WSGI response generator immediately, starving crawler thread capacity.

---

## 2. Installation

Install using modern Python package managers (**`uv`** recommended per project standards):

```bash
uv add phinehas
# Or install with framework-specific extras:
uv add "phinehas[fastapi]"
uv add "phinehas[django]"
uv add "phinehas[flask]"
uv add "phinehas[redis]"
```

Or via Poetry:
```bash
poetry add phinehas
```

---

## 3. Framework Integrations

### 1. FastAPI / Starlette (ASGI)

```python
import os
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware
from phinehas.store import RedisStore, MemoryStore
import redis

app = FastAPI(title="Enterprise API")

# =========================================================================
# PRODUCTION ASGI MIDDLEWARE REGISTRATION (Required vs Optional Showcase)
# =========================================================================
app.add_middleware(
    PhinehasMiddleware,
    # [OPTIONAL - DEFAULT: "terminate"]
    # Action taken upon detection:
    # - "terminate": Drops raw ASGI transport socket immediately (ECONNRESET)
    # - "reject":    Returns HTTP 403 Forbidden with empty body
    # - "tarpit":    Sleeps for tarpit_delay_ms before terminating socket
    action="terminate",

    # [OPTIONAL - DEFAULT: 3600 (1 hour)]
    # Ban duration in seconds. Set to 0 for a permanent ban.
    ttl=86400,

    # [PRODUCTION RECOMMENDED - DEFAULT: False]
    # Set to True when deployed behind Cloudflare, AWS ALB, Nginx, or Fastly.
    proxy_trust=True,

    # [OPTIONAL - DEFAULT: None]
    # Header containing client IP ('cf-connecting-ip', 'x-real-ip', or 'x-forwarded-for')
    proxy_header="cf-connecting-ip",

    # [OPTIONAL - DEFAULT: 1]
    # Hop depth in X-Forwarded-For
    proxy_depth=1,

    # [OPTIONAL - DEFAULT: ["127.0.0.1", "::1"]]
    # Whitelisted IPs exempt from all evaluation
    allow_list=["127.0.0.1", "::1", "10.0.0.1"],

    # [OPTIONAL - DEFAULT: None]
    # Additional application-specific paths or regex patterns to classify as traps
    custom_traps=[
        "/api/internal/debug-console",
        "/admin_test.php",
        r"^/wp-login\.php$",
    ],

    # [OPTIONAL - DEFAULT: False]
    # Set to True to disable default CMS/DB/debugger traps
    exclude_defaults=False,

    # [PRODUCTION RECOMMENDED FOR MULTI-WORKER CLUSTERS - DEFAULT: MemoryStore]
    # Synchronize bans across horizontal workers via Redis with local L1 shielding:
    storage=RedisStore(
        redis_client=redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0")),
        key_prefix="phinehas:ban:",
        default_ttl_seconds=86400,
    ),

    # [OPTIONAL - DEFAULT: "structured"]
    # "structured" (JSON formatted for Datadog/ELK) or "compact"
    logging_format="structured",

    # [OPTIONAL] Real-time callback hook for metrics/alerting
    on_strike=lambda strike: print(
        f"[PHINEHAS STRIKE] IP {strike['ip']} probed {strike['path']} (Rule: {strike['rule_matched']})"
    ),
)

# [REQUIRED] Normal application business routes continue below
@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}
```

---

### 2. Django (WSGI & ASGI)

In your Django `settings.py`:

```python
# settings.py
import os

# [REQUIRED] Prepend PhinehasMiddleware at index 0 of your MIDDLEWARE list
MIDDLEWARE = [
    "phinehas.django.PhinehasMiddleware",  # MUST execute before all other middlewares
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

# =========================================================================
# DJANGO PHINEHAS CONFIGURATION DICTIONARY (Required vs Optional)
# =========================================================================
PHINEHAS = {
    # [OPTIONAL - DEFAULT: 'terminate']
    "ACTION": "terminate",

    # [OPTIONAL - DEFAULT: 3600]
    "TTL": 86400,  # 24-hour ban

    # [PRODUCTION RECOMMENDED - DEFAULT: False]
    "PROXY": {
        "TRUST": True,
        "HEADER": "HTTP_CF_CONNECTING_IP",  # Django converts headers to HTTP_*
        "DEPTH": 1,
    },

    # [OPTIONAL - DEFAULT: ['127.0.0.1', '::1']]
    "ALLOW_LIST": ["127.0.0.1", "::1"],

    # [OPTIONAL - DEFAULT: []]
    "CUSTOM_TRAPS": [
        r"^/private-django-admin/",
        "/debug/system-metrics",
    ],

    # [PRODUCTION RECOMMENDED FOR GUNICORN / CELERY - DEFAULT: None (MemoryStore)]
    "REDIS_URL": os.getenv("REDIS_URL", "redis://localhost:6379/1"),
    "REDIS_PREFIX": "phinehas:django:ban:",

    # [OPTIONAL - DEFAULT: 'structured']
    "LOGGING_FORMAT": "structured",
}
```

---

### 3. Flask Extension

```python
import os
from flask import Flask, jsonify
from phinehas.flask import Phinehas

app = Flask(__name__)

# =========================================================================
# FLASK CONFIGURATION
# =========================================================================
app.config.update(
    PHINEHAS_ACTION="terminate",         # [OPTIONAL] 'terminate' | 'reject' | 'tarpit'
    PHINEHAS_TTL=86400,                  # [OPTIONAL] 24-hour ban
    PHINEHAS_PROXY_TRUST=True,           # [PRODUCTION RECOMMENDED]
    PHINEHAS_PROXY_HEADER="CF-Connecting-IP",
    PHINEHAS_CUSTOM_TRAPS=[              # [OPTIONAL]
        r"^/flask-admin/.*",
        "/internal/debug-dump",
    ],
    PHINEHAS_REDIS_URL=os.getenv("REDIS_URL"), # [PRODUCTION RECOMMENDED]
)

# [REQUIRED] Initialize with Flask app
phinehas_guard = Phinehas(app)

# Or using the application factory pattern:
# phinehas_guard = Phinehas()
# phinehas_guard.init_app(app)

@app.route("/api/v1/health")
def health():
    return jsonify({"status": "ok"})
```

---

### 4. Universal WSGI Middleware (Gunicorn, uWSGI, Falcon, Bottle)

Wrap any standard WSGI callable directly in your `wsgi.py` entrypoint:

```python
# wsgi.py
from my_application import app  # Any standard WSGI callable
from phinehas.wsgi import PhinehasWSGIMiddleware

# [REQUIRED] Wrap application
application = PhinehasWSGIMiddleware(
    app,
    action="terminate",         # [OPTIONAL - DEFAULT: 'terminate']
    ttl=86400,                  # [OPTIONAL - DEFAULT: 3600]
    proxy_trust=True,           # [PRODUCTION RECOMMENDED]
    proxy_header="X-Forwarded-For",
    custom_traps=[r"^/wp-config\.php$"], # [OPTIONAL]
)
```

Run with Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:8000 wsgi:application
```

---

## 4. Multi-Worker Redis Cluster State Sharing

In production deployments with multiple Gunicorn or Uvicorn workers, in-memory storage maintains separate local ban tables per process. Use `RedisStore` backed by a shared connection pool to synchronize bans across all worker processes instantaneously:

```python
import redis
from phinehas.store import RedisStore

# Create shared connection pool
pool = redis.ConnectionPool.from_url(
    "redis://localhost:6379/0",
    max_connections=20,
    socket_timeout=1.0,
    socket_connect_timeout=1.0,
)
redis_client = redis.Redis(connection_pool=pool)

# Initialize store with 5-second local L1 shield cache
store = RedisStore(
    redis_client=redis_client,
    key_prefix="phinehas:ban:",
    default_ttl_seconds=86400,
)
```

---

## 5. Testing Your Python Application with Phinehas

When testing with `pytest`, use `action="reject"` in test environments to assert on HTTP 403 status codes rather than handling raw transport drops:

```python
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from phinehas.fastapi import PhinehasMiddleware

@pytest.fixture
def client():
    app = FastAPI()
    app.add_middleware(PhinehasMiddleware, action="reject")

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    return TestClient(app)

def test_legitimate_traffic_passes(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_well_known_safe_pass(client):
    response = client.get("/.well-known/security.txt")
    # Passes through Phinehas to 404 (route not defined, but not blocked by security guard)
    assert response.status_code == 404

def test_dotfile_trapping(client):
    response = client.get("/.env")
    assert response.status_code == 403

def test_traversal_evasion_blocked(client):
    response = client.get("//%2e%2e/wp-config.php")
    assert response.status_code == 403
```

---

## 6. Navigation

* [Root SDK Documentation](../../README.md)
* [Shared Compliance Vectors (`compliance/`)](../../compliance/)

---

## 7. License

Licensed under the [Apache-2.0 License](../../LICENSE). Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
