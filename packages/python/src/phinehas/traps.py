"""
Default Explicit Non-Dot Traps Registry & RFC 8615 Pattern
Specification: Section 2
"""

import re
from typing import Tuple

DEFAULT_EXPLICIT_TRAPS: Tuple[str, ...] = (
    # CMS & Common Admin Consoles
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/wp-config.php",
    "/administrator",
    "/user/login",
    # Database Management Consoles
    "/phpmyadmin",
    "/pma",
    "/adminer.php",
    "/mysql",
    "/dbadmin",
    # Framework Debuggers & Sensitive Endpoints
    "/_ignition/execute-solution",
    "/__debug__",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/telescope",
    "/elmah.axd",
    # Sensitive File Dumps & Archives
    "/dump.sql",
    "/backup.sql",
    "/database.sql",
    "/db.sqlite3",
    "/backup.tar.gz",
    "/backup.zip",
)

# RFC 8615-Compliant Wildcard Detection Pattern
RFC8615_PATTERN = re.compile(r"^\/\.(?!well-known(\/|$))[a-zA-Z0-9_\-\.]+")
