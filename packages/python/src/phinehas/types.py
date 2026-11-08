"""
Phinehas Core Type Definitions
Specification Version: 1.2.0
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Literal, Optional, TypedDict

BanAction = Literal["terminate", "reject", "tarpit"]
LogFormat = Literal["compact", "structured"]
RuleMatched = Literal["rfc8615_wildcard", "explicit_trap", "custom_trap"]


class StrikeEvent(TypedDict):
    ip: str
    path: str
    method: str
    headers: Dict[str, str]
    ruleMatched: RuleMatched
    timestamp: str  # ISO 8601


@dataclass(frozen=True)
class EvaluationResult:
    is_blocked: bool
    normalized_path: str
    rule_matched: Optional[RuleMatched] = None
    reason: Optional[str] = None


StrikeCallback = Callable[[StrikeEvent], None]
