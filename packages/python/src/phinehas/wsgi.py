"""
Phinehas Universal WSGI Middleware
Compatible with Gunicorn, uWSGI, Flask, Bottle, Falcon, and standard WSGI servers.
"""

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional
from .evaluator import ThreatEvaluator
from .fastapi import is_ip_allowed, normalize_ip
from .logger import PhinehasLogger
from .store import BanStore, MemoryStore
from .types import BanAction, LogFormat, StrikeCallback, StrikeEvent


def extract_wsgi_headers(environ: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for key, val in environ.items():
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").lower()
            if isinstance(val, str):
                headers[header_name] = val
    if "CONTENT_TYPE" in environ and environ["CONTENT_TYPE"]:
        headers["content-type"] = str(environ["CONTENT_TYPE"])
    if "CONTENT_LENGTH" in environ and environ["CONTENT_LENGTH"]:
        headers["content-length"] = str(environ["CONTENT_LENGTH"])
    return headers


def extract_wsgi_client_ip(
    environ: Dict[str, Any],
    headers: Dict[str, str],
    proxy_trust: bool = False,
    proxy_header: Optional[str] = None,
    proxy_depth: Optional[int] = None,
) -> str:
    socket_ip = normalize_ip(environ.get("REMOTE_ADDR", "127.0.0.1"))
    if not proxy_trust:
        return socket_ip

    if proxy_header:
        custom_val = headers.get(proxy_header.lower())
        if custom_val:
            return normalize_ip(custom_val.split(",")[0].strip())

    cf_ip = headers.get("cf-connecting-ip")
    if cf_ip:
        return normalize_ip(cf_ip.split(",")[0].strip())

    real_ip = headers.get("x-real-ip")
    if real_ip:
        return normalize_ip(real_ip.strip())

    xff = headers.get("x-forwarded-for")
    if xff:
        ips = [normalize_ip(item.strip()) for item in xff.split(",")]
        if proxy_depth and proxy_depth > 0:
            target_idx = len(ips) - proxy_depth
            if 0 <= target_idx < len(ips):
                return ips[target_idx]
        return ips[0]

    return socket_ip


class PhinehasWSGIMiddleware:
    """
    Universal WSGI Middleware for Phinehas Active Defense.
    """

    def __init__(
        self,
        app: Any,
        storage: Optional[BanStore] = None,
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

        if storage is not None:
            self.store = storage
            self.store_name = storage.__class__.__name__.lower()
        else:
            self.store = MemoryStore(default_ttl_seconds=ttl)
            self.store_name = "memory"

    def _is_banned_sync(self, ip: str) -> bool:
        if isinstance(self.store, MemoryStore):
            return self.store.is_banned_sync(ip)
        return False

    def _ban_sync(self, ip: str, ttl: Optional[int]) -> None:
        if isinstance(self.store, MemoryStore):
            self.store.ban_sync(ip, ttl)

    def __call__(
        self,
        environ: Dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterable[bytes]:
        try:
            headers = extract_wsgi_headers(environ)
            client_ip = extract_wsgi_client_ip(
                environ=environ,
                headers=headers,
                proxy_trust=self.proxy_trust,
                proxy_header=self.proxy_header,
                proxy_depth=self.proxy_depth,
            )

            # 1. Allowlist exemption check
            if is_ip_allowed(client_ip, self.allow_list):
                return self.app(environ, start_response)

            raw_path = environ.get("PATH_INFO", "/")

            # 2. Check if IP is already banned
            if self._is_banned_sync(client_ip):
                strike: StrikeEvent = {
                    "ip": client_ip,
                    "path": raw_path,
                    "method": environ.get("REQUEST_METHOD", "GET"),
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
                return self._enforce_action(start_response)

            # 3. Evaluate Request Path
            result = self.evaluator.evaluate(raw_path)
            if result.is_blocked and result.rule_matched:
                self._ban_sync(client_ip, self.ttl)

                strike = {
                    "ip": client_ip,
                    "path": raw_path,
                    "method": environ.get("REQUEST_METHOD", "GET"),
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
                return self._enforce_action(start_response)

            return self.app(environ, start_response)

        except Exception:
            # Graceful Fail-Open
            return self.app(environ, start_response)

    def _enforce_action(self, start_response: Callable[..., Any]) -> Iterable[bytes]:
        if self.action == "terminate":
            # In WSGI, terminate immediately with zero bytes and close connection
            start_response(
                "403 Forbidden",
                [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "0"),
                    ("Connection", "close"),
                    ("X-Phinehas-Verdict", "terminated"),
                ],
            )
            return [b""]

        if self.action == "reject":
            start_response(
                "403 Forbidden",
                [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "0"),
                    ("Connection", "close"),
                    ("X-Phinehas-Verdict", "blocked"),
                ],
            )
            return [b""]

        if self.action == "tarpit":
            # Hold thread and return 403
            time.sleep(5)
            start_response(
                "403 Forbidden",
                [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "0"),
                    ("Connection", "close"),
                    ("X-Phinehas-Verdict", "tarpit"),
                ],
            )
            return [b""]

        return [b""]
