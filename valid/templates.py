"""Deterministic explanations for normalized infrastructure findings."""

from __future__ import annotations

from valid.models import Explanation, Finding

_GUIDANCE = {
    "open_ssh": (
        "SSH ingress is open to the internet",
        "Public SSH ingress permits connection attempts from untrusted networks.",
        "Restrict SSH ingress to an approved administration CIDR and rerun the scan.",
    ),
    "missing_tags": (
        "Required resource tags are missing or empty",
        "Missing ownership or environment tags make resource accountability harder.",
        "Set nonempty owner and environment tags through resource tags or resolvable provider defaults.",
    ),
    "rds_deletion_protection": (
        "RDS deletion protection is disabled",
        "Disabled deletion protection removes this safeguard against deleting the database.",
        "Set deletion_protection to true and rerun the scan.",
    ),
}
_GAP = (
    "A required check could not be evaluated",
    "The available static evidence cannot establish the result of this check.",
    "Resolve the reported coverage gap and rerun the scan before relying on the verdict.",
)
_GENERIC = (
    "Scanner finding needs review",
    "The scanner reported a policy failure. Its evidence and severity provenance require review.",
    "Review the supplied scanner evidence and its rule before choosing a change.",
)


def explain(findings: list[Finding]) -> list[Explanation]:
    """Explain supplied findings without changing their identity or strength."""
    result = []
    seen = set()
    for finding in findings:
        if finding.finding_id in seen:
            raise ValueError("Duplicate finding ID in explanation input")
        seen.add(finding.finding_id)
        if finding.evidence_strength == "not_evaluated":
            guidance = _GAP
        elif finding.evidence_strength != "deterministic":
            guidance = (
                "Heuristic finding needs review",
                "This heuristic is a review signal rather than a confirmed violation.",
                "Review the supplied evidence and verify the result before choosing a change.",
            )
        elif finding.priority == "unknown":
            guidance = _GENERIC
        else:
            guidance = _GUIDANCE.get(finding.recommendation.template_id, _GENERIC)
        title, why, action = guidance
        result.append(
            Explanation(
                finding_id=finding.finding_id,
                evidence_ids=sorted({item.evidence_id for item in finding.evidence}),
                title=title,
                why_it_matters=why,
                recommended_action=action,
                evidence_strength=finding.evidence_strength,
            )
        )
    return result
