"""Validate bounded advisory prose and exact references to deterministic findings.

Schema, citations, and specific identifier checks do not prove every sentence
of generated prose true. Advice is explicitly labeled for human review. The
model cannot add findings, change evidence strength, or set risk/exit fields.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any
from valid import templates
from valid.models import Explanation, Finding

PERMITTED_KEYS = frozenset({"finding_id", "evidence_ids", "title", "why_it_matters",
                            "recommended_action", "evidence_strength"})
_PERMITTED_FIELDS = ("title", "why_it_matters", "recommended_action")
FIELD_LIMITS = {"title": 140, "why_it_matters": 1200, "recommended_action": 1600}
_RESOURCE = re.compile(r"\b(?:aws|azurerm|google)_[a-zA-Z0-9_]+\.[a-zA-Z0-9_-]+")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_PORT = re.compile(r"\bport\s+(\d+)\b", re.IGNORECASE)
_UNSAFE = re.compile(
    r"PWNED|ignore.{0,30}instructions|system\s+prompt|https?://|"
    r"terraform\s+(?:apply|destroy|import)|git\s+(?:push|merge)|gh\s+pr\s+merge|"
    r"(?:is|are|now)\s+(?:compliant|completely secure|production.ready)|"
    r"(?:verdict|exit.code|score)\s*[:=]", re.IGNORECASE)


class ValidationError(ValueError):
    """A model response violates the advisory contract."""


def permitted_options(finding: Finding) -> dict[str, str]:
    """Basic guidance supplied as context, rather than mandatory copy text."""
    template = templates.explain([finding])[0]
    return {field: getattr(template, field) for field in _PERMITTED_FIELDS}


def _check_text(text: Any, field: str, finding: Finding) -> None:
    if not isinstance(text, str) or not text.strip() or len(text) > FIELD_LIMITS[field]:
        raise ValidationError("advice text is empty, invalid, or oversized")
    if any(unicodedata.category(c).startswith("C") and c not in "\n\t\r" for c in text):
        raise ValidationError("advice contains hidden control characters")
    if _UNSAFE.search(text):
        raise ValidationError("advice includes disallowed instructions or assurances")
    evidence = " ".join(e.summary for e in finding.evidence)
    resource = finding.resource.address if finding.resource else None
    if any(address != resource for address in _RESOURCE.findall(text)):
        raise ValidationError("advice references an unprovided resource")
    if any(address not in evidence for address in _IP.findall(text)):
        raise ValidationError("advice invents a network address")
    if any(not re.search(r"\b" + re.escape(port) + r"\b", evidence)
           for port in _PORT.findall(text)):
        raise ValidationError("advice invents a port")


def validate(items: Any, findings: list[Finding]) -> list[Explanation]:
    """Accept useful generated advice without changing detector-owned facts."""
    selected = list(findings)
    if not isinstance(items, list) or len(items) != len(selected):
        raise ValidationError("model output must cover exactly the requested findings")
    by_id: dict[str, Finding] = {}
    for finding in selected:
        if not isinstance(finding, Finding) or finding.finding_id in by_id:
            raise ValidationError("validation input has invalid or duplicate findings")
        by_id[finding.finding_id] = finding
    checked: dict[str, Explanation] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != PERMITTED_KEYS:
            raise ValidationError("model output has invalid or unexpected fields")
        finding_id = item["finding_id"]
        if not isinstance(finding_id, str) or finding_id not in by_id or finding_id in checked:
            raise ValidationError("model output cites an unknown or repeated finding ID")
        finding = by_id[finding_id]
        expected_ids = sorted(e.evidence_id for e in finding.evidence)
        evidence_ids = item["evidence_ids"]
        if not isinstance(evidence_ids, list) or evidence_ids != expected_ids:
            raise ValidationError("model output must cite exactly the finding evidence IDs")
        if item["evidence_strength"] != finding.evidence_strength:
            raise ValidationError("model output changed evidence strength")
        for field in _PERMITTED_FIELDS:
            _check_text(item[field], field, finding)
        prose = " ".join(item[field] for field in _PERMITTED_FIELDS).lower()
        if (finding.evidence_strength != "deterministic" or finding.priority == "unknown") and not any(
                word in prose for word in ("review", "verify", "confirm", "unknown", "not evaluated")):
            raise ValidationError("uncertain evidence must retain a verification caveat")
        options = permitted_options(finding)
        origin = "template" if all(item[field] == options[field] for field in _PERMITTED_FIELDS) else "ai"
        checked[finding_id] = Explanation(**item, origin=origin)
    return [checked[finding.finding_id] for finding in selected]
