"""Known-pattern redaction for text crossing the AI service boundary.

This module masks documented secret and private-path patterns before evidence
summaries enter a provider request payload, and again on model-supplied text
before validation. It is a defense for the listed known patterns only: it
cannot recognize every arbitrary secret, and must never be described as a
universal-secret guarantee. Texts that match nothing pass through unchanged.

Documented patterns:
- private absolute filesystem paths (/Users/, /home/, /private/, /tmp/,
  Windows drive paths),
- AWS-style access key material and GitHub token shapes,
- ``name=value`` credential assignments (password, secret, api key, token),
- ``CANARY_`` markers, a deterministic test hook (not a security boundary).
"""

from __future__ import annotations

import re

MAX_REDACTED_CHARS = 2000

_PRIVATE_PATH = re.compile(
    r"(?<![A-Za-z0-9_])(?:/(?:Users|home|private|tmp)/|[A-Za-z]:\\)[^\s,;]*"
)
_TOKEN = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+)"
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s,;]+"
)
_CANARY = re.compile(r"\bCANARY_[A-Za-z0-9_\-]{1,64}\b")


def redact_text(value: str, *, max_chars: int = MAX_REDACTED_CHARS) -> str:
    """Mask documented secret patterns in one text field.

    Returns the redacted string, bounded to ``max_chars`` characters. Never
    raises for string input; non-string input raises TypeError.
    """
    if not isinstance(value, str):
        raise TypeError("redact_text requires a string")
    redacted = _PRIVATE_PATH.sub("[private path]", value)
    redacted = _TOKEN.sub("[redacted]", redacted)
    redacted = _ASSIGNMENT.sub(
        lambda match: match.group(1) + "=[redacted]", redacted
    )
    redacted = _CANARY.sub("[redacted]", redacted)
    if len(redacted) > max_chars:
        redacted = redacted[:max_chars] + "..."
    return redacted
