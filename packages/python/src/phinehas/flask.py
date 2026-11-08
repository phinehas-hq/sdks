"""
Phinehas Flask Extension
Specification: Section 5.4 & Flask Integration
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from .evaluator import ThreatEvaluator
from .fastapi import is_ip_allowed, normalize_ip
from .logger import PhinehasLogger
from .store import BanStore, MemoryStore
from .types import BanAction, LogFormat, StrikeCallback, StrikeEvent

try:
    from flask import request, abort, make_response, Response
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    request = None  # type: ignore

    def abort(status: int):  # type: ignore
        raise Exception(f"HTTP {status}")

    def make_response(content: bytes, status: int):  # type: ignore
        return (content, status)


def extract_flask_ip(
    req: Any,
    proxy_trust: bool = False,
    proxy_header: Optional[str] = None,
    proxy_depth: Optional[int] = None,
) -> str:
    socket_ip = normalize_ip(getattr(req, "remote_addr", "127.0.0.1"))
    if not proxy_trust:
        return socket_ip

    headers = getattr(req, "headers", {})

    if proxy_header:
        custom_val = headers.get(proxy_header)
        if custom_val:
            return normalize_ip(custom_val.split(",")[0].strip())

    cf_ip = headers.get("CF-Connecting-IP")
    if cf_ip:
        return normalize_ip(cf_ip.split(",")[0].strip())

    real_ip = headers.get("X-Real-IP")
    if real_ip:
        return normalize_ip(real_ip.strip())

    xff = headers.get("X-Forwarded-For")
    if xff:
        ips = [normalize_ip(item.strip()) for item in xff.split(",")]
        if proxy_depth and proxy_depth > 0:
            target_idx = len(ips) - proxy_depth
            if 0 <= target_idx < len(ips):
                return ips[target_idx]
        return ips[0]

    return socket_ip


class Phinehas:
    """
    Phinehas extension for Flask applications.
    """

    def __init__(
        self,
        app: Optional[Any] = None,
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

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        """Register the before_request hook on the Flask application."""
        app.before_request(self.intercept_request)

    def _is_banned(self, ip: str) -> bool:
        if isinstance(self.store, MemoryStore):
            return self.store.is_banned_sync(ip)
        return False

    def _ban(self, ip: str, ttl: Optional[int]) -> None:
        if isinstance(self.store, MemoryStore):
            self.store.ban_sync(ip, ttl)

    def intercept_request(self, req: Optional[Any] = None) -> Optional[Any]:
        current_req = req or request
        if current_req is None:
            return None

        try:
            client_ip = extract_flask_ip(
                req=current_req,
                proxy_trust=self.proxy_trust,
                proxy_header=self.proxy_header,
                proxy_depth=self.proxy_depth,
            )

            # 1. Allowlist exemption check
            if is_ip_allowed(client_ip, self.allow_list):
                return None

            raw_path = getattr(current_req, "path", "/")
            method = getattr(current_req, "method", "GET")
            headers = dict(getattr(current_req, "headers", {}))

            # 2. Check if IP is already banned
            if self._is_banned(client_ip):
                strike: StrikeEvent = {
                    "ip": client_ip,
                    "path": raw_path,
                    "method": method,
                    "headers": headers,
                    "ruleMatched": "explicit_trap",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.logger.log_strike(
                    strike=strike,
                    action_taken=self.action,
                    ban_store_name=self.store_name,
                    ban_ttl_seconds=self.ttl,
                    user_agent=headers.get("User-Agent"),
                    host=headers.get("Host"),
                )
                return self._create_blocked_response()

            # 3. Evaluate Request Path
            result = self.evaluator.evaluate(raw_path)
            if result.is_blocked and result.rule_matched:
                self._ban(client_ip, self.ttl)

                strike = {
                    "ip": client_ip,
                    "path": raw_path,
                    "method": method,
                    "headers": headers,
                    "ruleMatched": result.rule_matched,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.logger.log_strike(
                    strike=strike,
                    action_taken=self.action,
                    ban_store_name=self.store_name,
                    ban_ttl_seconds=self.ttl,
                    user_agent=headers.get("User-Agent"),
                    host=headers.get("Host"),
                )
                return self._create_blocked_response()

            return None

        except Exception:
            # Graceful Fail-Open
            return None

    def _create_blocked_response(self) -> Any:
        if FLASK_AVAILABLE:
            resp = make_response(b"", 403)
            resp.headers["Content-Length"] = "0"
            resp.headers["Connection"] = "close"
            resp.headers["X-Phinehas-Verdict"] = "blocked"
            return resp
        return (b"", 403, {"Content-Length": "0", "Connection": "close", "X-Phinehas-Verdict": "blocked"})
