# Phinehas Python SDK

Active-defense, in-process security middleware for Python web frameworks (FastAPI, Starlette, Django) with immediate ASGI connection severance, zero-allocation LRU, and RFC 8615-compliant wildcard detection.

## Installation

```bash
uv add phinehas
# or with FastAPI extras
uv add "phinehas[fastapi,redis]"
```

## Quick Start (FastAPI)

```python
from fastapi import FastAPI
from phinehas.fastapi import PhinehasMiddleware

app = FastAPI()

app.add_middleware(
    PhinehasMiddleware,
    ttl=86400,
    action="terminate"
)
```
