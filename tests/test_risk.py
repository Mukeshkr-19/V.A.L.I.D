"""Tests for valid.risk: deterministic risk policy."""

from __future__ import annotations

import random
from typing import Literal

import pytest

from valid.models import (
    Category,
    Coverage,
    EvidenceItem,
    EvidenceStrength,
    Finding,
    FindingSource,
    Location,
    PolicyMode,
    Recommendation,
    ResourceRef,
    RiskSummary,
    Severity,
    ValidConfig,
)
from valid.risk import exit_code, is_blocking_finding, summarize


def make_test_finding(
    finding_id: str = "f_1234567890abcdef",
    fingerprint: str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    tool: str = "valid",
    rule_id: str = "DG-AWS-NET-001",
    priority: Severity = "high",
    scanner_severity: Severity = "high",
    severity_origin: Literal["scanner", "rule_map", "custom_rule", "defaulted"] = "custom_rule",
    path: str = "main.tf",
    start_line: int | None = 10,
    end_line: int | None = 20,
    category: Category = "security",
    evidence_strength: EvidenceStrength = "deterministic",
    policy_mode: PolicyMode = "block",
    resource_type: str | None = "aws_security_group",
    resource_address: str | None = "aws_security_group.web",
    summary_text: str = "open ssh",
) -> Finding:
    """Helper to create valid Finding instances conforming to StrictModel."""
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        source=FindingSource(
            tool=tool,
            version="0.1.0",
            rule_id=rule_id,
            scanner_severity=scanner_severity,
            severity_origin=severity_origin,
        ),
        location=Location(path=path, start_line=start_line, end_line=end_line),
        resource=ResourceRef(type=resource_type, address=resource_address),
        category=category,
        priority=priority,
        evidence_strength=evidence_strength,
        change_action="unknown",
        evidence=[
            EvidenceItem(
                evidence_id="e_" + finding_id[-8:],
                kind="scanner" if tool == "checkov" else "literal_hcl",
                summary=summary_text,
            )
        ],
        recommendation=Recommendation(template_id="open_ssh"),
        policy_mode=policy_mode,
    )


# =========================================================================== #
# Status Tests: PASS
# =========================================================================== #
def test_empty_complete_pass() -> None:
    """Empty findings with complete evaluated coverage evaluates to PASS."""
    coverage = Coverage(evaluated_files=["main.tf"])
    config = ValidConfig()

    summary = summarize([], coverage, config)

    assert summary.status == "PASS"
    assert summary.score == 0
    assert summary.top_priority is None
    assert summary.reasons == []
    assert summary.counts == {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
        "unknown": 0,
    }
    assert summary.category_counts == {
        "security": 0,
        "reliability": 0,
        "governance": 0,
        "cost_risk": 0,
    }
    assert summary.coverage.evaluated_files == ["main.tf"]


def test_info_inform_deterministic_pass() -> None:
    """Known info-only findings with inform policy do not force review -> PASS."""
    finding = make_test_finding(
        finding_id="f_info1",
        rule_id="CKV_AWS_INFO",
        priority="info",
        policy_mode="inform",
        evidence_strength="deterministic",
        category="governance",
    )
    coverage = Coverage(evaluated_files=["main.tf"])
    config = ValidConfig()

    summary = summarize([finding], coverage, config)

    assert summary.status == "PASS"
    assert summary.score == 0
    assert summary.top_priority == "info"
    assert summary.counts["info"] == 1
    assert summary.category_counts["governance"] == 1
    assert summary.reasons == []


# =========================================================================== #
# Status Tests: HIGH RISK
# =========================================================================== #
def test_high_deterministic_block_high_risk() -> None:
    """Evaluated deterministic high finding with block policy -> HIGH RISK."""
    finding = make_test_finding(
        finding_id="f_high1",
        rule_id="DG-AWS-NET-001",
        priority="high",
        policy_mode="block",
        evidence_strength="deterministic",
        category="security",
    )
    coverage = Coverage(evaluated_files=["main.tf"])
    config = ValidConfig()

    summary = summarize([finding], coverage, config)

    assert summary.status == "HIGH RISK"
    assert summary.score == 7
    assert summary.top_priority == "high"
    assert summary.counts["high"] == 1
    assert summary.category_counts["security"] == 1
    assert len(summary.reasons) == 1
    assert "Blocking high finding" in summary.reasons[0]


def test_critical_deterministic_block_high_risk() -> None:
    """Evaluated deterministic critical finding with block policy -> HIGH RISK."""
    finding = make_test_finding(
        finding_id="f_crit1",
        rule_id="DG-AWS-CRIT-001",
        priority="critical",
        policy_mode="block",
        evidence_strength="deterministic",
        category="security",
    )
    coverage = Coverage(evaluated_files=["main.tf"])
    config = ValidConfig()

    summary = summarize([finding], coverage, config)

    assert summary.status == "HIGH RISK"
    assert summary.score == 10
    assert summary.top_priority == "critical"
    assert summary.counts["critical"] == 1
    assert len(summary.reasons) == 1
    assert "Blocking critical finding" in summary.reasons[0]


# =========================================================================== #
# Status Tests: REVIEW
# =========================================================================== #
def test_optional_gaps_review() -> None:
    """Empty findings but with optional gaps -> REVIEW."""
    coverage = Coverage(
        evaluated_files=["main.tf"],
        optional_gaps=["unsupported_construct"],
    )
    config = ValidConfig()

    summary = summarize([], coverage, config)

    assert summary.status == "REVIEW"
    assert summary.score == 0
    assert summary.top_priority is None
    assert len(summary.reasons) == 1
    assert "Optional coverage gap: unsupported_construct" in summary.reasons[0]


def test_unknown_severity_review() -> None:
    """Finding with unknown priority -> REVIEW, score=0, top_priority='unknown'."""
    finding = make_test_finding(
        finding_id="f_unk1",
        rule_id="CKV_CUSTOM_UNK",
        priority="unknown",
        policy_mode="warn",
        evidence_strength="deterministic",
        category="governance",
    )
    coverage = Coverage(evaluated_files=["main.tf"])
    config = ValidConfig()

    summary = summarize([finding], coverage, config)

    assert summary.status == "REVIEW"
    assert summary.score == 0
    assert summary.top_priority == "unknown"
    assert summary.counts["unknown"] == 1
    assert any("Finding with unknown severity" in r for r in summary.reasons)


def test_heuristic_high_review() -> None:
    """Heuristic high finding with block policy -> REVIEW (not deterministic)."""
    finding = make_test_finding(
        finding_id="f_heur1",
        rule_id="DG-AWS-NET-001",
        priority="high",
        policy_mode="block",
        evidence_strength="strong_heuristic",
        category="security",
    )
    coverage = Coverage(evaluated_files=["main.tf"])
    config = ValidConfig()

    summary = summarize([finding], coverage, config)

    assert summary.status == "REVIEW"
    assert summary.score == 7
    assert summary.top_priority == "high"
    assert any("Heuristic finding" in r for r in summary.reasons)


def test_weak_heuristic_high_review() -> None:
    """Weak heuristic finding -> REVIEW."""
    finding = make_test_finding(
        finding_id="f_wheur1",
        rule_id="DG-AWS-NET-001",
        priority="high",
        policy_mode="block",
        evidence_strength="weak_heuristic",
        category="security",
    )
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), ValidConfig())

    assert summary.status == "REVIEW"
    assert any("weak_heuristic" in r for r in summary.reasons)


def test_high_warn_policy_review() -> None:
    """Deterministic high finding with warn policy -> REVIEW."""
    finding = make_test_finding(
        finding_id="f_warn_hi",
        rule_id="CKV_AWS_24",
        priority="high",
        policy_mode="warn",
        evidence_strength="deterministic",
        category="security",
    )
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), ValidConfig())

    assert summary.status == "REVIEW"
    assert summary.score == 7
    assert any("Warning policy finding" in r for r in summary.reasons)


def test_high_inform_policy_review() -> None:
    """Deterministic high finding with inform policy -> REVIEW (not info-only)."""
    finding = make_test_finding(
        finding_id="f_inf_hi",
        rule_id="CKV_AWS_24",
        priority="high",
        policy_mode="inform",
        evidence_strength="deterministic",
        category="security",
    )
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), ValidConfig())

    assert summary.status == "REVIEW"
    assert summary.score == 7


def test_medium_finding_review() -> None:
    """Medium finding -> REVIEW."""
    finding = make_test_finding(
        finding_id="f_med1",
        rule_id="DG-AWS-TAG-001",
        priority="medium",
        policy_mode="warn",
        evidence_strength="deterministic",
        category="governance",
    )
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), ValidConfig())

    assert summary.status == "REVIEW"
    assert summary.score == 3
    assert summary.top_priority == "medium"
    assert summary.counts["medium"] == 1


def test_low_finding_review() -> None:
    """Low finding -> REVIEW."""
    finding = make_test_finding(
        finding_id="f_low1",
        rule_id="CKV_AWS_LOW",
        priority="low",
        policy_mode="inform",
        evidence_strength="deterministic",
        category="governance",
    )
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), ValidConfig())

    assert summary.status == "REVIEW"
    assert summary.score == 1
    assert summary.top_priority == "low"
    assert summary.counts["low"] == 1


def test_info_warn_policy_review() -> None:
    """Info finding with warn policy -> REVIEW."""
    finding = make_test_finding(
        finding_id="f_info_warn",
        rule_id="CKV_INFO",
        priority="info",
        policy_mode="warn",
        evidence_strength="deterministic",
        category="governance",
    )
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), ValidConfig())

    assert summary.status == "REVIEW"


# =========================================================================== #
# Status Tests: INCOMPLETE
# =========================================================================== #
def test_required_failed_stages_incomplete() -> None:
    """Required stage failure -> INCOMPLETE."""
    coverage = Coverage(
        evaluated_files=["main.tf"],
        required_failed_stages=["checkov_execution"],
    )
    summary = summarize([], coverage, ValidConfig())

    assert summary.status == "INCOMPLETE"
    assert summary.score == 0
    assert any("Required stage failed: checkov_execution" in r for r in summary.reasons)


def test_required_gaps_incomplete() -> None:
    """Required coverage gap -> INCOMPLETE."""
    coverage = Coverage(
        evaluated_files=["main.tf"],
        required_gaps=["rds_deletion_protection"],
    )
    summary = summarize([], coverage, ValidConfig())

    assert summary.status == "INCOMPLETE"
    assert any("Required coverage gap: rds_deletion_protection" in r for r in summary.reasons)


def test_not_evaluated_finding_incomplete() -> None:
    """Finding with evidence_strength='not_evaluated' -> INCOMPLETE, excluded from score."""
    finding = make_test_finding(
        finding_id="f_not_eval",
        rule_id="DG-AWS-RDS-001",
        priority="unknown",
        policy_mode="warn",
        evidence_strength="not_evaluated",
        category="reliability",
    )
    coverage = Coverage(evaluated_files=["main.tf"])
    summary = summarize([finding], coverage, ValidConfig())

    assert summary.status == "INCOMPLETE"
    assert summary.score == 0  # not_evaluated is coverage, not scored risk
    assert summary.top_priority == "unknown"
    assert any("Required check not evaluated" in r for r in summary.reasons)


def test_required_failure_plus_confirmed_high_remains_incomplete_with_evidence_visible() -> None:
    """Required failure plus confirmed high finding remains INCOMPLETE with evidence visible."""
    high_finding = make_test_finding(
        finding_id="f_high_block",
        rule_id="DG-AWS-NET-001",
        priority="high",
        policy_mode="block",
        evidence_strength="deterministic",
        category="security",
        path="main.tf",
        start_line=15,
    )
    coverage = Coverage(
        evaluated_files=["main.tf"],
        required_failed_stages=["checkov_execution"],
    )
    summary = summarize([high_finding], coverage, ValidConfig())

    # 1. Precedence: INCOMPLETE takes precedence over HIGH RISK
    assert summary.status == "INCOMPLETE"

    # 2. Score reflects evaluated known priority finding
    assert summary.score == 7
    assert summary.counts["high"] == 1
    assert summary.top_priority == "high"

    # 3. Evidence visible: both required stage failure AND blocking high finding are in reasons
    reasons_text = "\n".join(summary.reasons)
    assert "Required stage failed: checkov_execution" in reasons_text
    assert "Blocking high finding: DG-AWS-NET-001 at main.tf:15" in reasons_text


# =========================================================================== #
# Scoring and Priority Hierarchy
# =========================================================================== #
def test_scoring_weights_sum() -> None:
    """Verify exact weights: info0, low1, medium3, high7, critical10; unknown and not_eval excluded."""
    findings = [
        make_test_finding(finding_id="f_info", priority="info", policy_mode="inform"),
        make_test_finding(finding_id="f_low", priority="low", policy_mode="warn"),
        make_test_finding(finding_id="f_med", priority="medium", policy_mode="warn"),
        make_test_finding(finding_id="f_hi", priority="high", policy_mode="block"),
        make_test_finding(finding_id="f_crit", priority="critical", policy_mode="block"),
        make_test_finding(finding_id="f_unk", priority="unknown", policy_mode="warn"),
        make_test_finding(
            finding_id="f_noteval",
            priority="high",
            evidence_strength="not_evaluated",
            policy_mode="warn",
        ),
    ]
    # score: 0 + 1 + 3 + 7 + 10 + 0 (unk) + 0 (not_evaluated) = 21
    summary = summarize(findings, Coverage(evaluated_files=["main.tf"]), ValidConfig())
    assert summary.score == 21
    assert summary.counts["info"] == 1
    assert summary.counts["low"] == 1
    assert summary.counts["medium"] == 1
    assert summary.counts["high"] == 2  # both high findings counted
    assert summary.counts["critical"] == 1
    assert summary.counts["unknown"] == 1


def test_top_priority_hierarchy() -> None:
    """Highest evaluated known severity is selected, ignoring unknown and not_evaluated."""
    f1 = make_test_finding(finding_id="f1", priority="unknown", evidence_strength="deterministic")
    f2 = make_test_finding(finding_id="f2", priority="low", evidence_strength="deterministic")
    f3 = make_test_finding(finding_id="f3", priority="medium", evidence_strength="deterministic")
    f4 = make_test_finding(finding_id="f4", priority="critical", evidence_strength="not_evaluated")

    summary = summarize([f1, f2, f3, f4], Coverage(evaluated_files=["main.tf"]), ValidConfig())
    # f4 is not_evaluated so not an evaluated known severity.
    # Evaluated known severities are 'low' and 'medium'. Highest is 'medium'.
    assert summary.top_priority == "medium"


# =========================================================================== #
# Invariance and Determinism Tests
# =========================================================================== #
def test_input_order_invariance() -> None:
    """Input-order invariance: shuffling findings produces identical summary."""
    f1 = make_test_finding(
        finding_id="f_001",
        path="a.tf",
        rule_id="RULE-1",
        priority="high",
        policy_mode="block",
    )
    f2 = make_test_finding(
        finding_id="f_002",
        path="b.tf",
        rule_id="RULE-2",
        priority="medium",
        policy_mode="warn",
    )
    f3 = make_test_finding(
        finding_id="f_003",
        path="c.tf",
        rule_id="RULE-3",
        priority="low",
        policy_mode="inform",
    )
    f4 = make_test_finding(
        finding_id="f_004",
        path="d.tf",
        rule_id="RULE-4",
        priority="info",
        policy_mode="inform",
    )

    base_list = [f1, f2, f3, f4]
    base_summary = summarize(base_list, Coverage(evaluated_files=["a.tf", "b.tf"]), ValidConfig())
    base_json = base_summary.model_dump_json()

    for seed in range(10):
        shuffled = list(base_list)
        random.Random(seed).shuffle(shuffled)
        shuffled_summary = summarize(
            shuffled, Coverage(evaluated_files=["a.tf", "b.tf"]), ValidConfig()
        )
        assert shuffled_summary.model_dump_json() == base_json
        assert shuffled_summary.reasons == base_summary.reasons


def test_repeat_serialized_output() -> None:
    """Repeated serialization yields byte-for-byte identical output."""
    finding = make_test_finding(
        finding_id="f_rep",
        path="main.tf",
        rule_id="DG-AWS-NET-001",
        priority="high",
        policy_mode="block",
    )
    coverage = Coverage(
        evaluated_files=["main.tf"],
        optional_gaps=["gap_b", "gap_a"],
    )
    config = ValidConfig()

    s1 = summarize([finding], coverage, config)
    s2 = summarize([finding], coverage, config)

    dump1 = s1.model_dump_json()
    dump2 = s2.model_dump_json()

    assert dump1 == dump2
    # Verify optional gaps are stably ordered in reasons
    reasons = s1.reasons
    assert reasons[0].startswith("Blocking high finding")
    assert reasons[1] == "Optional coverage gap: gap_a"
    assert reasons[2] == "Optional coverage gap: gap_b"


# =========================================================================== #
# Config Overrides and Exit Codes
# =========================================================================== #
def test_config_blocking_priorities_override() -> None:
    """Config blocking_priorities override changes block evaluation."""
    finding = make_test_finding(
        finding_id="f_hi",
        priority="high",
        policy_mode="block",
        evidence_strength="deterministic",
    )
    # If config blocking_priorities only includes 'critical', high finding drops to REVIEW
    config = ValidConfig(blocking_priorities=["critical"])
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), config)

    assert summary.status == "REVIEW"


def test_config_empty_blocking_priorities_disables_blocking() -> None:
    """Explicit empty blocking_priorities list disables blocking; finding remains REVIEW."""
    finding = make_test_finding(
        finding_id="f_hi_empty",
        priority="high",
        policy_mode="block",
        evidence_strength="deterministic",
    )
    config = ValidConfig(blocking_priorities=[])
    summary = summarize([finding], Coverage(evaluated_files=["main.tf"]), config)

    assert summary.status == "REVIEW"
    assert summary.score == 7
    assert summary.top_priority == "high"
    assert summary.counts["high"] == 1
    assert any("Evaluated high finding" in r for r in summary.reasons)


def test_coverage_copy_isolation() -> None:
    """Coverage in RiskSummary is an isolated copy; mutating input does not mutate summary."""
    coverage = Coverage(evaluated_files=["main.tf"], optional_gaps=["gap1"])
    summary = summarize([], coverage, ValidConfig())

    coverage.optional_gaps.append("gap2")
    assert summary.coverage.optional_gaps == ["gap1"]


def test_exit_code_mapping() -> None:
    """Verify exit code mapping: PASS/REVIEW -> 0, HIGH RISK/INCOMPLETE -> 1."""
    assert exit_code("PASS") == 0
    assert exit_code("REVIEW") == 0
    assert exit_code("HIGH RISK") == 1
    assert exit_code("INCOMPLETE") == 1

    with pytest.raises(ValueError):
        exit_code("UNKNOWN_STATUS")  # type: ignore[arg-type]
