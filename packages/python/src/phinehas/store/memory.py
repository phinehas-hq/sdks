"""
In-Memory LRU BanStore Driver for Python
Specification: Section 3.1
Hard allocation cap of 25,000 IP entries with O(1) LRU eviction.
"""

import time
from collections import OrderedDict
from typing import Optional
from .base import BanStore


class MemoryStore(BanStore):
    def __init__(
        self,
        max_capacity: int = 25000,
        default_ttl_seconds: Optional[int] = 3600,
    ) -> None:
        self.max_capacity = max_capacity
        self.default_ttl = default_ttl_seconds
        # OrderedDict mapping ip -> Optional[float] (expiration timestamp in epoch seconds)
        self.cache: OrderedDict[str, Optional[float]] = OrderedDict()

    @property
    def size(self) -> int:
        return len(self.cache)

    async def is_banned(self, ip: str) -> bool:
        if ip not in self.cache:
            return False

        expires_at = self.cache[ip]
        now = time.time()

        if expires_at is not None and now > expires_at:
            # Key has expired: purge immediately
            del self.cache[ip]
            return False

        # Refresh LRU position to most recently used
        self.cache.move_to_end(ip, last=True)
        return True

    def is_banned_sync(self, ip: str) -> bool:
        """Synchronous version for non-async execution paths."""
        if ip not in self.cache:
            return False

        expires_at = self.cache[ip]
        now = time.time()

        if expires_at is not None and now > expires_at:
            del self.cache[ip]
            return False

        self.cache.move_to_end(ip, last=True)
        return True

    async def ban(self, ip: str, ttl_seconds: Optional[int] = 3600) -> None:
        effective_ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = (
            time.time() + effective_ttl
            if effective_ttl and effective_ttl > 0
            else None
        )

        if ip in self.cache:
            self.cache[ip] = expires_at
            self.cache.move_to_end(ip, last=True)
            return

        # Enforce capacity cap (evict least recently used entry)
        if len(self.cache) >= self.max_capacity:
            self.cache.popitem(last=False)

        self.cache[ip] = expires_at

    def ban_sync(self, ip: str, ttl_seconds: Optional[int] = 3600) -> None:
        """Synchronous version for non-async execution paths."""
        effective_ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = (
            time.time() + effective_ttl
            if effective_ttl and effective_ttl > 0
            else None
        )

        if ip in self.cache:
            self.cache[ip] = expires_at
            self.cache.move_to_end(ip, last=True)
            return

        if len(self.cache) >= self.max_capacity:
            self.cache.popitem(last=False)

        self.cache[ip] = expires_at

    async def unban(self, ip: str) -> None:
        self.cache.pop(ip, None)

    def unban_sync(self, ip: str) -> None:
        self.cache.pop(ip, None)

    async def close(self) -> None:
        self.cache.clear()
