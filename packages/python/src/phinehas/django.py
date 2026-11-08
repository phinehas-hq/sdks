"""
Phinehas Django Middleware
Specification: Section 5.4 & Django Integration
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from .evaluator import ThreatEvaluator
from .fastapi import is_ip_allowed, normalize_ip
from .logger import PhinehasLogger
from .store import BanStore, MemoryStore
from .types import BanAction, LogFormat, StrikeCallback, StrikeEvent

# Gracefully import Django HttpResponse or provide lightweight fallback
try:
    from django.http import HttpResponseForbidden, HttpResponse
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False

    class HttpResponse:
        def __init__(self, content: bytes = b"", status: int = 200, **kwargs):
            self.content = content
            self.status_code = status
            self.headers: Dict[str, str] = kwargs.get("headers", {})

        def __setitem__(self, key: str, value: str) -> None:
            self.headers[key] = str(value)

        def __getitem__(self, key: str) -> str:
            return self.headers.get(key, "")

    class HttpResponseForbidden(HttpResponse):
        def __init__(self, content: bytes = b"", **kwargs):
            super().__init__(content, status=403, **kwargs)


def get_django_settings() -> Dict[str, Any]:
    try:
        from django.conf import settings
        return getattr(settings, "PHINEHAS", {})
    except Exception:
        return {}


def extract_django_ip(
    request: Any,
    proxy_trust: bool = False,
    proxy_header: Optional[str] = None,
    proxy_depth: Optional[int] = None,
) -> str:
    meta = getattr(request, "META", {})
    socket_ip = normalize_ip(meta.get("REMOTE_ADDR", "127.0.0.1"))

    if not proxy_trust:
        return socket_ip

    if proxy_header:
        meta_key = proxy_header.upper().replace("-", "_")
        if not meta_key.startswith("HTTP_"):
            meta_key = f"HTTP_{meta_key}"
        custom_val = meta.get(meta_key)
        if custom_val:
            return normalize_ip(custom_val.split(",")[0].strip())

    cf_ip = meta.get("HTTP_CF_CONNECTING_IP")
    if cf_ip:
        return normalize_ip(cf_ip.split(",")[0].strip())

    real_ip = meta.get("HTTP_X_REAL_IP")
    if real_ip:
        return normalize_ip(real_ip.strip())

    xff = meta.get("HTTP_X_FORWARDED_FOR")
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
    Django middleware for Phinehas active-defense threat interception.
    """

    def __init__(
        self,
        get_response: Callable[[Any], Any],
        **kwargs: Any,
    ) -> None:
        self.get_response = get_response
        django_opts = get_django_settings()

        # Merge Django settings with optional kwargs overrides
        self.action: BanAction = kwargs.get(
            "action", django_opts.get("ACTION", "terminate")
        )
        self.ttl: Optional[int] = kwargs.get(
            "ttl", django_opts.get("TTL", 3600)
        )
        self.allow_list: List[str] = kwargs.get(
            "allow_list", django_opts.get("ALLOW_LIST", ["127.0.0.1", "::1"])
        )

        proxy_opts = django_opts.get("PROXY", {})
        self.proxy_trust: bool = kwargs.get(
            "proxy_trust", proxy_opts.get("TRUST", False)
        )
        self.proxy_header: Optional[str] = kwargs.get(
            "proxy_header", proxy_opts.get("HEADER", None)
        )
        self.proxy_depth: Optional[int] = kwargs.get(
            "proxy_depth", proxy_opts.get("DEPTH", None)
        )

        custom_traps = kwargs.get(
            "custom_traps", django_opts.get("CUSTOM_TRAPS", None)
        )
        exclude_defaults = kwargs.get(
            "exclude_defaults", django_opts.get("EXCLUDE_DEFAULTS", False)
        )

        self.evaluator = ThreatEvaluator(
            custom_traps=custom_traps,
            exclude_defaults=exclude_defaults,
        )

        logging_opts = django_opts.get("LOGGING", {})
        self.logger = PhinehasLogger(
            enabled=kwargs.get("logging_enabled", logging_opts.get("ENABLED", True)),
            log_format=kwargs.get("logging_format", logging_opts.get("FORMAT", "structured")),
            on_strike=kwargs.get("on_strike", logging_opts.get("ON_STRIKE", None)),
        )

        storage = kwargs.get("storage")
        if storage is not None:
            self.store: BanStore = storage
            self.store_name = storage.__class__.__name__.lower()
        else:
            self.store = MemoryStore(default_ttl_seconds=self.ttl)
            self.store_name = "memory"

    def _is_banned(self, ip: str) -> bool:
        if isinstance(self.store, MemoryStore):
            return self.store.is_banned_sync(ip)
        return False

    def _ban(self, ip: str, ttl: Optional[int]) -> None:
        if isinstance(self.store, MemoryStore):
            self.store.ban_sync(ip, ttl)

    def __call__(self, request: Any) -> Any:
        try:
            client_ip = extract_django_ip(
                request=request,
                proxy_trust=self.proxy_trust,
                proxy_header=self.proxy_header,
                proxy_depth=self.proxy_depth,
            )

            # 1. Allowlist exemption
            if is_ip_allowed(client_ip, self.allow_list):
                return self.get_response(request)

            raw_path = getattr(request, "path_info", getattr(request, "path", "/"))
            method = getattr(request, "method", "GET")
            headers = {
                k[5:].replace("_", "-").lower(): str(v)
                for k, v in getattr(request, "META", {}).items()
                if k.startswith("HTTP_")
            }

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
                    user_agent=headers.get("user-agent"),
                    host=headers.get("host"),
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
                    user_agent=headers.get("user-agent"),
                    host=headers.get("host"),
                )
                return self._create_blocked_response()

            return self.get_response(request)

        except Exception:
            # Graceful Fail-Open
            return self.get_response(request)

    def _create_blocked_response(self) -> Any:
        response = HttpResponseForbidden(b"", content_type="text/plain")
        response["Content-Length"] = "0"
        response["Connection"] = "close"
        response["X-Phinehas-Verdict"] = "blocked"
        return response
