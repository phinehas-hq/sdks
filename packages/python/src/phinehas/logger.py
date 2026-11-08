"""
Phinehas Structured & Compact Logger for Python
Specification: Section 7
"""

import json
import sys
from typing import Optional
from .types import BanAction, LogFormat, StrikeCallback, StrikeEvent


class PhinehasLogger:
    def __init__(
        self,
        enabled: bool = True,
        log_format: LogFormat = "structured",
        on_strike: Optional[StrikeCallback] = None,
    ) -> None:
        self.enabled = enabled
        self.format = log_format
        self.on_strike = on_strike

    def log_strike(
        self,
        strike: StrikeEvent,
        action_taken: BanAction,
        ban_store_name: str,
        ban_ttl_seconds: Optional[int],
        user_agent: Optional[str] = None,
        host: Optional[str] = None,
    ) -> None:
        # Trigger custom strike hook if supplied
        if self.on_strike:
            try:
                self.on_strike(strike)
            except Exception:
                # Suppress callback errors to preserve fail-open safety
                pass

        if not self.enabled:
            return

        if self.format == "compact":
            action_label = "Severed" if action_taken == "terminate" else "Blocked"
            print(
                f"[PHINEHAS STRIKE] {action_label} {strike['ip']} accessing {strike['path']}",
                file=sys.stderr,
            )
            return

        action_desc = (
            "TCP_SOCKET_TERMINATED"
            if action_taken == "terminate"
            else "HTTP_403_REJECTED"
            if action_taken == "reject"
            else "TARPIT_ENFORCED"
        )

        structured_log = {
            "timestamp": strike["timestamp"],
            "level": "WARN",
            "event": "PHINEHAS_SPEAR_STRIKE",
            "actor": {
                "ip": strike["ip"],
                "user_agent": user_agent or strike["headers"].get("user-agent", "unknown"),
            },
            "target": {
                "path": strike["path"],
                "method": strike["method"],
                "host": host or strike["headers"].get("host", "unknown"),
            },
            "verdict": {
                "rule_matched": strike["ruleMatched"],
                "action_taken": action_desc,
                "ban_store": ban_store_name,
                "ban_ttl_seconds": ban_ttl_seconds,
            },
        }

        print(json.dumps(structured_log), file=sys.stderr)
