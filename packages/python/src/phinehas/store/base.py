"""
Abstract BanStore Contract
Specification: Section 3
"""

from abc import ABC, abstractmethod
from typing import Optional


class BanStore(ABC):
    @abstractmethod
    async def is_banned(self, ip: str) -> bool:
        """Check if an IP address is actively banned."""
        ...

    @abstractmethod
    async def ban(self, ip: str, ttl_seconds: Optional[int] = 3600) -> None:
        """Ban an IP address with optional TTL in seconds. None or 0 denotes permanent ban."""
        ...

    @abstractmethod
    async def unban(self, ip: str) -> None:
        """Remove an IP address from the ban registry."""
        ...

    async def close(self) -> None:
        """Optional cleanup hook."""
        pass
