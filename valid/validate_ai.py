"""Strict validation of model-supplied explanations against supplied findings.

A model response is accepted only when it covers exactly the requested
findings with no duplicates, no extra or missing finding IDs, evidence IDs
identical to each finding's evidence set, unchanged evidence strength, and
title/why/recommended-action text copied exactly from the permitted
deterministic template options for that finding.

ID and schema checks alone cannot prove that arbitrary free-form prose is
grounded in the evidence. This module therefore enforces a constrained
explanation contract: the only permitted wording for each field is the
pre-approved template text, and anything else is rejected so the caller can
use the deterministic template fallback. A regular expression (or another
model) is never presented as a guarantee of free-form truth.
"""

from __future__ import annotations

from typing import Any

from valid import templates
from valid.models import Explanation, Finding

PERMITTED_KEYS = frozenset(
    {
        "finding_id",
        "evidence_ids",
        "title",
        "why_it_matters",
        "recommended_action",
        "evidence_strength",
    }
)
_PERMITTED_FIELDS = ("title", "why_it_matters", "recommended_action")


class ValidationError(ValueError):
    """A model-supplied explanation violates the constrained contract."""


def permitted_options(finding: Finding) -> dict[str, str]:
    """Return the exact permitted title/why/action wording for one finding."""
    template = templates.explain([finding])[0]
    return {
        "title": template.title,
        "why_it_matters": template.why_it_matters,
        "recommended_action": template.recommended_action,
    }


def validate(items: Any, findings: list[Finding]) -> list[Explanation]:
    """Validate parsed model output and return Explanations in findings order.

    Raises ValidationError on any coverage, identity, strength, wording, or
    type violation. Never returns a partial list.
    """
    selected = list(findings)
    if not isinstance(items, list):
        raise ValidationError("model output must be a JSON array")
    if len(items) != len(selected):
        raise ValidationError(
            "model output covers %d findings, %d were requested"
            % (len(items), len(selected))
        )
    by_id: dict[str, Finding] = {}
    for finding in selected:
        if not isinstance(finding, Finding):
            raise ValidationError("validation input must be Finding objects")
        if finding.finding_id in by_id:
            raise ValidationError("duplicate finding ID in validation input")
        by_id[finding.finding_id] = finding
    checked: dict[str, Explanation] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValidationError("model output entries must be objects")
        if set(item) != PERMITTED_KEYS:
            raise ValidationError("model output entry has unexpected fields")
        finding_id = item["finding_id"]
        if not isinstance(finding_id, str) or finding_id not in by_id:
            raise ValidationError("model output cites an unknown finding ID")
        if finding_id in checked:
            raise ValidationError("model output repeats a finding ID")
        finding = by_id[finding_id]
        expected_ids = sorted(item.evidence_id for item in finding.evidence)
        evidence_ids = item["evidence_ids"]
        if (
            not isinstance(evidence_ids, list)
            or any(not isinstance(value, str) for value in evidence_ids)
            or list(evidence_ids) != expected_ids
        ):
            raise ValidationError(
                "model output must cite exactly the finding evidence IDs"
            )
        if item["evidence_strength"] != finding.evidence_strength:
            raise ValidationError("model output changed evidence strength")
        options = permitted_options(finding)
        for field in _PERMITTED_FIELDS:
            if not isinstance(item[field], str) or item[field] != options[field]:
                raise ValidationError(
                    "model output uses wording outside the permitted options"
                )
        checked[finding_id] = Explanation(
            finding_id=finding_id,
            evidence_ids=list(evidence_ids),
            title=item["title"],
            why_it_matters=item["why_it_matters"],
            recommended_action=item["recommended_action"],
            evidence_strength=item["evidence_strength"],
        )
    if set(checked) != set(by_id):
        raise ValidationError("model output misses requested findings")
    return [checked[finding.finding_id] for finding in selected]
