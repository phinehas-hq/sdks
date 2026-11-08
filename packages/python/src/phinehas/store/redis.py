"""
Distributed Redis BanStore Driver with L1 Shielding Cache for Python
Specification: Section 3.2
"""

import time
from typing import Any, Dict, Optional, Tuple
from .base import BanStore


class RedisStore(BanStore):
    def __init__(
        self,
        client: Any,
        key_prefix: str = "phinehas:ban:",
        default_ttl_seconds: Optional[int] = 3600,
        l1_ttl_seconds: float = 5.0,
    ) -> None:
        if client is None:
            raise ValueError("[Phinehas] RedisStore requires an active redis client instance.")
        self.client = client
        self.key_prefix = key_prefix
        self.default_ttl = default_ttl_seconds
        self.l1_ttl_seconds = l1_ttl_seconds
        # L1 cache: ip -> (is_banned: bool, expires_at: float)
        self.l1_cache: Dict[str, Tuple[bool, float]] = {}

    def _get_key(self, ip: str) -> str:
        return f"{self.key_prefix}{ip}"

    async def is_banned(self, ip: str) -> bool:
        now = time.time()
        l1_entry = self.l1_cache.get(ip)

        if l1_entry and now < l1_entry[1]:
            return l1_entry[0]

        try:
            key = self._get_key(ip)
            res = await self.client.get(key)
            is_banned = res is not None

            # Update L1 shielding cache
            self.l1_cache[ip] = (is_banned, now + self.l1_ttl_seconds)
            return is_banned
        except Exception:
            # Graceful fail-open: never crash host app if Redis is partitioned
            return False

    async def ban(self, ip: str, ttl_seconds: Optional[int] = 3600) -> None:
        effective_ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        key = self._get_key(ip)

        try:
            if effective_ttl and effective_ttl > 0:
                await self.client.set(key, "1", ex=effective_ttl)
            else:
                await self.client.set(key, "1")

            self.l1_cache[ip] = (True, time.time() + self.l1_ttl_seconds)
        except Exception:
            # Graceful fail-open
            pass

    async def unban(self, ip: str) -> None:
        key = self._get_key(ip)
        self.l1_cache.pop(ip, None)

        try:
            await self.client.delete(key)
        except Exception:
            pass

    async def close(self) -> None:
        self.l1_cache.clear()
