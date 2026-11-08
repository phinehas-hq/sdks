"""
Phinehas FastAPI & Starlette ASGI Middleware
Specification: Section 5.4
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from .evaluator import ThreatEvaluator
from .logger import PhinehasLogger
from .store import BanStore, MemoryStore, RedisStore
from .types import BanAction, LogFormat, StrikeCallback, StrikeEvent


def normalize_ip(ip: str) -> str:
    if not ip:
        return "127.0.0.1"
    cleaned = ip.strip()
    if cleaned.startswith("::ffff:"):
        cleaned = cleaned[7:]
    return cleaned


def is_ip_allowed(ip: str, allow_list: List[str]) -> bool:
    normalized = normalize_ip(ip)
    for allowed in allow_list:
        norm_allowed = normalize_ip(allowed)
        if normalized == norm_allowed:
            return True
        if (
            normalized in ("127.0.0.1", "::1")
            and norm_allowed in ("127.0.0.1", "::1", "localhost")
        ):
            return True
    return False


def extract_asgi_headers(scope: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for raw_name, raw_val in scope.get("headers", []):
        try:
            name = raw_name.decode("latin-1").lower()
            val = raw_val.decode("latin-1")
            headers[name] = val
        except Exception:
            continue
    return headers


def extract_client_ip(
    scope: Dict[str, Any],
    headers: Dict[str, str],
    proxy_trust: bool = False,
    proxy_header: Optional[str] = None,
    proxy_depth: Optional[int] = None,
) -> str:
    client = scope.get("client")
    socket_ip = normalize_ip(client[0]) if client and client[0] else "127.0.0.1"

    if not proxy_trust:
        return socket_ip

    # 1. Custom proxy header
    if proxy_header:
        custom_val = headers.get(proxy_header.lower())
        if custom_val:
            return normalize_ip(custom_val.split(",")[0].strip())

    # 2. Cloudflare header
    cf_ip = headers.get("cf-connecting-ip")
    if cf_ip:
        return normalize_ip(cf_ip.split(",")[0].strip())

    # 3. X-Real-IP
    real_ip = headers.get("x-real-ip")
    if real_ip:
        return normalize_ip(real_ip.strip())

    # 4. X-Forwarded-For with depth
    xff = headers.get("x-forwarded-for")
    if xff:
        ips = [normalize_ip(item.strip()) for item in xff.split(",")]
        if proxy_depth and proxy_depth > 0:
            target_idx = len(ips) - proxy_depth
            if 0 <= target_idx < len(ips):
                return ips[target_idx]
        return ips[0]

    return socket_ip


class PhinehasMiddleware:
    """
    Phinehas Active Defense ASGI Middleware for FastAPI and Starlette.
    """

    def __init__(
        self,
        app: Any,
        storage: Optional[BanStore] = None,
        redis_client: Optional[Any] = None,
        ttl: Optional[int] = 3600,
        action: BanAction = "terminate",
        custom_traps: Optional[List[str]] = None,
        exclude_defaults: bool = False,
        allow_list: Optional[List[str]] = None,
        proxy_trust: bool = False,
        proxy_header: Optional[str] = None,
        proxy_depth: Optional[int] = None,
        logging_enabled: bool = True,
        logging_format: LogFormat = "structured",
        on_strike: Optional[StrikeCallback] = None,
    ) -> None:
        self.app = app
        self.ttl = ttl
        self.action = action
        self.allow_list = allow_list if allow_list is not None else ["127.0.0.1", "::1"]
        self.proxy_trust = proxy_trust
        self.proxy_header = proxy_header
        self.proxy_depth = proxy_depth

        self.evaluator = ThreatEvaluator(
            custom_traps=custom_traps,
            exclude_defaults=exclude_defaults,
        )

        self.logger = PhinehasLogger(
            enabled=logging_enabled,
            log_format=logging_format,
            on_strike=on_strike,
        )

        # Storage initialization
        if storage is not None:
            self.store = storage
            self.store_name = storage.__class__.__name__.lower()
        elif redis_client is not None:
            self.store = RedisStore(client=redis_client, default_ttl_seconds=ttl)
            self.store_name = "redis"
        else:
            self.store = MemoryStore(default_ttl_seconds=ttl)
            self.store_name = "memory"

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: Callable[[], Any],
        send: Callable[[Dict[str, Any]], Any],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            headers = extract_asgi_headers(scope)
            client_ip = extract_client_ip(
                scope=scope,
                headers=headers,
                proxy_trust=self.proxy_trust,
                proxy_header=self.proxy_header,
                proxy_depth=self.proxy_depth,
            )

            # 1. Allowlist exemption check
            if is_ip_allowed(client_ip, self.allow_list):
                await self.app(scope, receive, send)
                return

            raw_path = scope.get("path", "/")

            # 2. Check if IP is already banned
            if await self.store.is_banned(client_ip):
                strike: StrikeEvent = {
                    "ip": client_ip,
                    "path": raw_path,
                    "method": scope.get("method", "GET"),
                    "headers": headers,
                    "ruleMatched": "explicit_trap",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.logger.log_strike(
                    strike=strike,
                    action_taken=self.action,
                    ban_store_name=self.store_name,
                    ban_ttl_seconds=self.ttl,
                    user_agent=headers.get("user-agent"),
                    host=headers.get("host"),
                )
                await self._enforce_action(send)
                return

            # 3. Evaluate Request Path
            result = self.evaluator.evaluate(raw_path)
            if result.is_blocked and result.rule_matched:
                await self.store.ban(client_ip, self.ttl)

                strike = {
                    "ip": client_ip,
                    "path": raw_path,
                    "method": scope.get("method", "GET"),
                    "headers": headers,
                    "ruleMatched": result.rule_matched,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.logger.log_strike(
                    strike=strike,
                    action_taken=self.action,
                    ban_store_name=self.store_name,
                    ban_ttl_seconds=self.ttl,
                    user_agent=headers.get("user-agent"),
                    host=headers.get("host"),
                )
                await self._enforce_action(send)
                return

            # Clean request: hand off to application
            await self.app(scope, receive, send)

        except Exception:
            # Graceful Fail-Open: security checks must never bring down host app
            await self.app(scope, receive, send)

    async def _enforce_action(self, send: Callable[[Dict[str, Any]], Any]) -> None:
        if self.action == "terminate":
            # Immediately close the ASGI connection without emitting an HTTP response
            # In ASGI servers (Uvicorn/Hypercorn), returning without response.start severs connection
            return

        if self.action == "reject":
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-length", b"0"),
                        (b"connection", b"close"),
                        (b"x-phinehas-verdict", b"blocked"),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"",
                    "more_body": False,
                }
            )
            return

        if self.action == "tarpit":
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/octet-stream"),
                        (b"transfer-encoding", b"chunked"),
                        (b"connection", b"keep-alive"),
                    ],
                }
            )
            # Drip 1 byte every 10 seconds to exhaust crawler connection pools
            for _ in range(6):  # Drip for up to 60 seconds
                await asyncio.sleep(10)
                await send(
                    {
                        "type": "http.response.body",
                        "body": b" ",
                        "more_body": True,
                    }
                )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"",
                    "more_body": False,
                }
            )
