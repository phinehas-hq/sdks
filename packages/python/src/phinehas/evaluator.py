"""
Phinehas Threat Detection Evaluator
Specification: Section 2
"""

from typing import List, Optional, Set
from .normalizer import normalize_path
from .traps import DEFAULT_EXPLICIT_TRAPS, RFC8615_PATTERN
from .types import EvaluationResult


class ThreatEvaluator:
    def __init__(
        self,
        custom_traps: Optional[List[str]] = None,
        exclude_defaults: bool = False,
    ) -> None:
        default_traps = () if exclude_defaults else DEFAULT_EXPLICIT_TRAPS
        self.explicit_traps: Set[str] = set(default_traps)
        self.custom_traps: Set[str] = {
            normalize_path(p) for p in (custom_traps or [])
        }

        # Prefix traps without dot extension (e.g. /wp-admin, /actuator, /phpmyadmin)
        self.prefix_traps: List[str] = [
            trap for trap in self.explicit_traps if "." not in trap
        ]

    def evaluate(self, raw_path: str) -> EvaluationResult:
        """
        Evaluates a request path against the threat detection pipeline:
        1. Path Normalization (anti-bypass)
        2. RFC 8615 Wildcard Rule
        3. Custom Honeypot Traps
        4. Explicit Non-Dot Traps Registry
        """
        normalized = normalize_path(raw_path)

        # 1. Check RFC 8615 Wildcard Rule
        if RFC8615_PATTERN.match(normalized):
            return EvaluationResult(
                is_blocked=True,
                rule_matched="rfc8615_wildcard",
                normalized_path=normalized,
                reason=f"Matched RFC 8615 hidden path wildcard: {normalized}",
            )

        # 2. Check Custom Honeypots
        for custom in self.custom_traps:
            if normalized == custom or normalized.startswith(custom + "/"):
                return EvaluationResult(
                    is_blocked=True,
                    rule_matched="custom_trap",
                    normalized_path=normalized,
                    reason=f"Matched custom honeypot trap: {custom}",
                )

        # 3. Check Explicit Non-Dot Traps (Exact match)
        if normalized in self.explicit_traps:
            return EvaluationResult(
                is_blocked=True,
                rule_matched="explicit_trap",
                normalized_path=normalized,
                reason=f"Matched explicit threat signature: {normalized}",
            )

        # 4. Check Explicit Prefix Traps (e.g. /wp-admin/foo, /actuator/bar)
        for prefix in self.prefix_traps:
            if normalized.startswith(prefix + "/"):
                return EvaluationResult(
                    is_blocked=True,
                    rule_matched="explicit_trap",
                    normalized_path=normalized,
                    reason=f"Matched explicit prefix threat signature: {prefix}",
                )

        return EvaluationResult(is_blocked=False, normalized_path=normalized)
