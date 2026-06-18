"""Audit redaction patterns.

Regex-based redaction for known secret shapes (AWS keys + bearer tokens).
Production would need full secret-scanning (Gitleaks-style + envelope
encryption + per-tenant key management). The redaction logic ships behind
the `forensic_30d` retention class — raw payloads are only stored under
that policy, and redaction runs on store, not on read.
"""

from __future__ import annotations

import re
from typing import Pattern

REDACTION_LABEL = "[REDACTED]"

_AWS_ACCESS_KEY: Pattern[str] = re.compile(r"AKIA[0-9A-Z]{16}")
_AWS_SECRET: Pattern[str] = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])")
_BEARER_TOKEN: Pattern[str] = re.compile(r"[Bb]earer\s+[A-Za-z0-9._\-]+")
_GENERIC_API_KEY: Pattern[str] = re.compile(
    r"(?i)(api[_\-]?key|x[_\-]?api[_\-]?key|authorization)[\s:=]+[\"']?[A-Za-z0-9._\-]{8,}"
)
_EMAIL: Pattern[str] = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)

_PATTERNS: tuple[tuple[str, Pattern[str]], ...] = (
    ("aws_access_key", _AWS_ACCESS_KEY),
    ("bearer_token", _BEARER_TOKEN),
    ("generic_api_key", _GENERIC_API_KEY),
    ("email", _EMAIL),
    ("aws_secret", _AWS_SECRET),
)


def redact_text(text: str) -> tuple[str, list[str]]:
    """Return (redacted_text, hit_pattern_names)."""
    hits: list[str] = []
    out = text
    for name, pattern in _PATTERNS:
        new_out, n = pattern.subn(REDACTION_LABEL, out)
        if n:
            hits.append(name)
            out = new_out
    return out, hits


def redact_dict(payload: dict) -> tuple[dict, list[str]]:
    """Recursively walk a dict; redact strings; return (redacted, hits)."""
    all_hits: list[str] = []

    def _walk(node):
        if isinstance(node, str):
            redacted, hits = redact_text(node)
            all_hits.extend(hits)
            return redacted
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v) for v in node]
        return node

    return _walk(payload), list(dict.fromkeys(all_hits))
