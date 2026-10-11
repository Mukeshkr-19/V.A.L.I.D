"""Deterministic risk policy for V.A.L.I.D.

Implements summarize(findings, coverage, config) -> RiskSummary.
"""

from __future__ import annotations

from valid.models import (
    Category,
    Coverage,
    Finding,
    PolicyMode,
    RiskSummary,
    Severity,
    Status,
    ValidConfig,
)

ALL_SEVERITIES: tuple[Severity, ...] = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
    "unknown",
)

ALL_CATEGORIES: tuple[Category, ...] = (
    "security",
    "reliability",
    "governance",
    "cost_risk",
)

SEVERITY_HIERARCHY: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

SEVERITY_WEIGHTS: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 10,
}


def canonical_finding_key(finding: Finding) -> tuple[str, str, str, str, str]:
    """Return the canonical sorting key.

    Stable ordering: path, resource.address or "", tool, rule_id, finding_id.
    """
    path = finding.location.path if finding.location and finding.location.path else ""
    address = (
        finding.resource.address
        if (finding.resource and finding.resource.address)
        else ""
    )
    tool = finding.source.tool if finding.source and finding.source.tool else ""
    rule_id = finding.source.rule_id if finding.source and finding.source.rule_id else ""
    finding_id = finding.finding_id or ""
    return (path, address, tool, rule_id, finding_id)


def is_blocking_finding(finding: Finding, config: ValidConfig) -> bool:
    """Return True if the finding is an evaluated deterministic high/critical block finding.

    Evaluated means evidence_strength != 'not_evaluated'.
    Deterministic means evidence_strength == 'deterministic'.
    PolicyMode must be 'block'.
    Priority must be in config.blocking_priorities (defaults to ['high', 'critical']).
    An explicit empty blocking_priorities list disables blocking.
    """
    if finding.evidence_strength != "deterministic":
        return False
    if finding.policy_mode != "block":
        return False
    blocking_priorities = getattr(config, "blocking_priorities", None)
    if blocking_priorities is None:
        blocking_priorities = ("high", "critical")
    return finding.priority in blocking_priorities


def _location_str(finding: Finding) -> str:
    path = finding.location.path if finding.location else ""
    if finding.location and finding.location.start_line is not None:
        return f"{path}:{finding.location.start_line}"
    return path


def summarize(
    findings: list[Finding],
    coverage: Coverage,
    config: ValidConfig,
) -> RiskSummary:
    """Summarize detector findings and scan coverage into a deterministic RiskSummary.

    Precedence:
    1. Required stage or coverage failure (or not_evaluated finding) -> INCOMPLETE.
    2. Evaluated deterministic high/critical finding with block policy -> HIGH RISK.
    3. Unknown severity, optional gaps, evaluated heuristic, low/medium finding,
       or warning policy -> REVIEW.
    4. Otherwise -> PASS (known info-only inform findings do not force review).

    Score:
    info=0, low=1, medium=3, high=7, critical=10.
    Evaluated known priority only; unknown and not_evaluated are excluded from score.
    """
    # Canonical stable ordering of findings
    sorted_findings = sorted(findings, key=canonical_finding_key)

    # 1. Counts: exactly all 6 severities initialized to 0
    counts: dict[str, int] = {s: 0 for s in ALL_SEVERITIES}
    for f in sorted_findings:
        if f.priority in counts:
            counts[f.priority] += 1

    # 2. Category counts: exactly all 4 categories initialized to 0
    category_counts: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    for f in sorted_findings:
        if f.category in category_counts:
            category_counts[f.category] += 1

    # 3. Score: sum evaluated known-priority detector findings only
    score = sum(
        SEVERITY_WEIGHTS[f.priority]
        for f in sorted_findings
        if f.evidence_strength != "not_evaluated" and f.priority in SEVERITY_WEIGHTS
    )

    # 4. Top priority: highest evaluated known severity; unknown-only => unknown; no findings => None
    if not sorted_findings:
        top_priority: Severity | None = None
    else:
        evaluated_known = {
            f.priority
            for f in sorted_findings
            if f.evidence_strength != "not_evaluated" and f.priority in SEVERITY_WEIGHTS
        }
        top_priority = next(
            (sev for sev in SEVERITY_HIERARCHY if sev in evaluated_known),
            None,
        )
        if top_priority is None:
            top_priority = "unknown"

    # 5. Evaluate precedence predicates
    # Tier 1: INCOMPLETE
    has_required_failed_stages = bool(coverage.required_failed_stages)
    has_required_gaps = bool(coverage.required_gaps)
    has_not_evaluated = any(
        f.evidence_strength == "not_evaluated" for f in sorted_findings
    )
    is_incomplete = (
        has_required_failed_stages
        or has_required_gaps
        or has_not_evaluated
    )

    # Tier 2: HIGH RISK
    blocking_findings = [f for f in sorted_findings if is_blocking_finding(f, config)]
    has_high_risk = bool(blocking_findings)

    # Tier 3: REVIEW
    has_optional_gaps = bool(coverage.optional_gaps)
    has_unknown = any(f.priority == "unknown" for f in sorted_findings)
    has_heuristic = any(
        f.evidence_strength in ("strong_heuristic", "weak_heuristic")
        for f in sorted_findings
    )
    has_warn_policy = any(f.policy_mode == "warn" for f in sorted_findings)
    has_low_or_medium = any(
        f.priority in ("low", "medium") for f in sorted_findings
    )
    has_non_blocking_high = any(
        f.priority in ("high", "critical") and not is_blocking_finding(f, config)
        for f in sorted_findings
    )

    is_review = (
        has_optional_gaps
        or has_unknown
        or has_heuristic
        or has_warn_policy
        or has_low_or_medium
        or has_non_blocking_high
    )

    # Determine status
    if is_incomplete:
        status: Status = "INCOMPLETE"
    elif has_high_risk:
        status = "HIGH RISK"
    elif is_review:
        status = "REVIEW"
    else:
        status = "PASS"

    # 6. Populate reasons in stable canonical order
    reasons: list[str] = []

    # Required stage failures (sorted unique)
    for stage in sorted(set(coverage.required_failed_stages)):
        reasons.append(f"Required stage failed: {stage}")

    # Required gaps (sorted unique)
    for gap in sorted(set(coverage.required_gaps)):
        reasons.append(f"Required coverage gap: {gap}")

    # Not-evaluated checks (findings with not_evaluated evidence strength)
    for f in sorted_findings:
        if f.evidence_strength == "not_evaluated":
            loc = _location_str(f)
            reasons.append(f"Required check not evaluated: {f.source.rule_id} at {loc}")

    # Blocking findings (visible in INCOMPLETE and HIGH RISK)
    for f in blocking_findings:
        loc = _location_str(f)
        reasons.append(f"Blocking {f.priority} finding: {f.source.rule_id} at {loc}")

    # Review findings (unknown, heuristic, warn policy, low/medium, non-blocking high/critical)
    for f in sorted_findings:
        if f.evidence_strength == "not_evaluated" or is_blocking_finding(f, config):
            continue
        loc = _location_str(f)
        if f.priority == "unknown":
            reasons.append(f"Finding with unknown severity: {f.source.rule_id} at {loc}")
        elif f.evidence_strength in ("strong_heuristic", "weak_heuristic"):
            reasons.append(
                f"Heuristic finding ({f.evidence_strength}): {f.source.rule_id} ({f.priority}) at {loc}"
            )
        elif f.policy_mode == "warn":
            reasons.append(
                f"Warning policy finding: {f.source.rule_id} ({f.priority}) at {loc}"
            )
        elif f.priority in ("low", "medium", "high", "critical"):
            reasons.append(f"Evaluated {f.priority} finding: {f.source.rule_id} at {loc}")

    # Optional gaps (sorted unique)
    for gap in sorted(set(coverage.optional_gaps)):
        reasons.append(f"Optional coverage gap: {gap}")

    # For PASS: reasons is empty list
    if status == "PASS":
        reasons.clear()

    coverage_out = coverage.model_copy(deep=True)

    return RiskSummary(
        schema_version="1.0.0",
        status=status,
        score=score,
        counts=counts,
        category_counts=category_counts,
        top_priority=top_priority,
        coverage=coverage_out,
        reasons=reasons,
    )


def exit_code(status: Status) -> int:
    """Map status to CLI exit code: PASS/REVIEW -> 0, HIGH RISK/INCOMPLETE -> 1."""
    if status in ("PASS", "REVIEW"):
        return 0
    if status in ("HIGH RISK", "INCOMPLETE"):
        return 1
    raise ValueError(f"Unknown status: {status!r}")
