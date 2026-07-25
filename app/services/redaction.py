from __future__ import annotations

import re
from typing import Any


PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd|passphrase)\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(snmp(?:get|walk|bulkwalk).*?\s-c\s+)(\S+)"), r"\1[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[PRIVATE KEY REDACTED]"),
    (re.compile(r"(?i)(postgresql(?:\+\w+)?://[^:/\s]+:)[^@\s]+(@)"), r"\1[REDACTED]\2"),
    (re.compile(r"(?i)(mysql://[^:/\s]+:)[^@\s]+(@)"), r"\1[REDACTED]\2"),
)


def redact_text(value: str) -> str:
    result = value or ""
    for pattern, replacement in PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_object(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if str(key).casefold() in {"password", "passwd", "passphrase", "secret", "token", "api_key", "authorization"}:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_object(item)
        return redacted
    if isinstance(value, list):
        return [redact_object(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_object(item) for item in value)
    return value
