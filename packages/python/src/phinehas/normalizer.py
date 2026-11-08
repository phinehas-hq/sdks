"""
Anti-Bypass Path Normalization Pipeline
Specification: Section 6
"""

import re
import urllib.parse
from typing import List


def safe_url_decode(raw_path: str) -> str:
    """
    Iteratively decodes percent-encoded characters up to 3 passes.
    Handles single, double, and nested hex-encodings.
    """
    decoded = raw_path
    for _ in range(3):
        try:
            next_decoded = urllib.parse.unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        except Exception:
            # Fallback manual replacement for critical bypass hex codes
            decoded = (
                decoded.replace("%2e", ".")
                .replace("%2E", ".")
                .replace("%2f", "/")
                .replace("%2F", "/")
                .replace("%5c", "\\")
                .replace("%5C", "\\")
            )
            break
    return decoded


def resolve_path_traversal(path_str: str) -> str:
    """
    Resolves relative directory traversal segments (. and ..) without escaping root.
    """
    parts = path_str.split("/")
    resolved: List[str] = []

    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if resolved:
                resolved.pop()
        else:
            resolved.append(part)

    return "/" + "/".join(resolved)


def normalize_path(raw_path: str) -> str:
    """
    Executes the 6-stage anti-bypass normalization pipeline:
    1. Hex URL decoding (%2e, %2f, %5c)
    2. Backslash conversion (\\ -> /)
    3. Slash collapsing (//+ -> /)
    4. Path traversal resolution (/api/v1/../../.env -> /.env)
    5. Lowercasing
    6. Trailing slash removal
    """
    if not raw_path or not isinstance(raw_path, str):
        return "/"

    # 1. URL Decoding
    normalized = safe_url_decode(raw_path)

    # 2. Windows Backslash Conversion
    normalized = re.sub(r"\\+", "/", normalized)

    # Ensure leading slash
    if not normalized.startswith("/"):
        normalized = "/" + normalized

    # 3. Slash Collapsing
    normalized = re.sub(r"/+", "/", normalized)

    # 4. Path Traversal Resolution
    normalized = resolve_path_traversal(normalized)

    # 5. Lowercasing
    normalized = normalized.lower()

    # 6. Trailing Slash Removal (preserve single root '/')
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]

    return normalized
