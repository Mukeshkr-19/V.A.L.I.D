from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from valid.models import (
    CATEGORIES,
    SEVERITIES,
    Coverage,
    CustomScanResult,
    EvidenceItem,
    Explanation,
    Finding,
    FindingSource,
    Location,
    RawScanResult,
    Recommendation,
    ResourceRef,
    RiskSummary,
    RulePolicy,
    ValidConfig,
)
from valid.terraform_types import ParsedScan, ResourceBlock

ROOT = Path(__file__).resolve().parents[1]


def make_finding(**overrides):
    data = {
        "finding_id": "f_0123456789abcdef",
        "fingerprint": "0" * 64,
        "source": {
            "tool": "valid",
            "version": "0.1.0",
            "rule_id": "DG-AWS-NET-001",
            "scanner_severity": "high",
            "severity_origin": "custom_rule",
        },
        "location": {"path": "main.tf", "start_line": 1, "end_line": 9},
        "resource": {"type": "aws_security_group", "address": "aws_security_group.web"},
        "category": "security",
        "priority": "high",
        "evidence_strength": "deterministic",
        "evidence": [{"evidence_id": "e_0123456789abcdef", "kind": "literal_hcl", "summary": "port 22"}],
        "recommendation": {"template_id": "open_ssh"},
        "policy_mode": "block",
    }
    data.update(overrides)
    return Finding.model_validate(data)


def make_summary(**overrides):
    data = {
        "status": "PASS",
        "score": 0,
        "counts": {s: 0 for s in SEVERITIES},
        "category_counts": {c: 0 for c in CATEGORIES},
        "top_priority": None,
        "coverage": Coverage(),
        "reasons": [],
    }
    data.update(overrides)
    return RiskSummary(**data)


def test_enumerations_match_contract():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical", "unknown")
    assert CATEGORIES == ("security", "reliability", "governance", "cost_risk")


def test_finding_valid_and_defaults():
    finding = make_finding()
    assert finding.change_action == "unknown"
    assert finding.source.severity_origin == "custom_rule"


def test_finding_round_trips_through_json():
    finding = make_finding()
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


@pytest.mark.parametrize(
    "model, data",
    [
        (Location, {"path": "main.tf", "extra": 1}),
        (ResourceRef, {"kind": "x"}),
        (Recommendation, {"template_id": "open_ssh", "text": "x"}),
        (Coverage, {"gaps": []}),
        (ValidConfig, {"requiredTags": ["owner"]}),
        (RawScanResult, {"status": "complete", "absolute_file_path": "/tmp/x"}),
    ],
)
def test_unknown_and_aliased_fields_rejected(model, data):
    with pytest.raises(ValidationError):
        model.model_validate(data)


def test_finding_extra_field_rejected():
    with pytest.raises(ValidationError):
        make_finding(score=7)


@pytest.mark.parametrize(
    "field, value",
    [
        ("category", "cost"),
        ("priority", "HIGH"),
        ("evidence_strength", "certain"),
        ("change_action", "modify"),
        ("policy_mode", "fail"),
    ],
)
def test_finding_enum_values_validated(field, value):
    with pytest.raises(ValidationError):
        make_finding(**{field: value})


def test_finding_required_fields():
    with pytest.raises(ValidationError):
        Finding.model_validate({"finding_id": "f_1"})
    data = make_finding().model_dump()
    del data["resource"]
    with pytest.raises(ValidationError):
        Finding.model_validate(data)
    data = make_finding().model_dump()
    del data["evidence"]
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_finding_resource_may_be_null():
    assert make_finding(resource=None).resource is None


def test_resource_ref_rejects_blank_fields_and_treats_none_as_absent():
    assert ResourceRef() == ResourceRef(type=None, address=None)
    assert ResourceRef(type="aws_instance").address is None
    for field in ("type", "address"):
        for value in ("", "  "):
            with pytest.raises(ValidationError):
                ResourceRef(**{field: value})


def test_severity_origin_and_evidence_kind_validated():
    with pytest.raises(ValidationError):
        FindingSource(tool="checkov", version="3.3.8", rule_id="CKV_AWS_24",
                      scanner_severity="unknown", severity_origin="guessed")
    with pytest.raises(ValidationError):
        EvidenceItem(evidence_id="e_1", kind="ai", summary="x")


@pytest.mark.parametrize("value", ["", "   "])
def test_ids_must_be_nonempty(value):
    with pytest.raises(ValidationError):
        make_finding(finding_id=value)
    with pytest.raises(ValidationError):
        make_finding(fingerprint=value)
    with pytest.raises(ValidationError):
        EvidenceItem(evidence_id=value, kind="scanner", summary="x")
    with pytest.raises(ValidationError):
        Recommendation(template_id=value)
    with pytest.raises(ValidationError):
        FindingSource(tool="valid", version="0.1.0", rule_id=value,
                      scanner_severity="high", severity_origin="custom_rule")
    with pytest.raises(ValidationError):
        Explanation(finding_id="f_1", evidence_ids=[value], title="t", why_it_matters="w",
                    recommended_action="a", evidence_strength="deterministic")


@pytest.mark.parametrize("path", ["main.tf", "modules/net/main.tf", "."])
def test_relative_paths_accepted(path):
    assert Location(path=path).path == path


@pytest.mark.parametrize(
    "path",
    ["", "/main.tf", "../main.tf", "a/../main.tf", "a/..", "./main.tf", "a//b.tf",
     "a\\b.tf", "C:/x/main.tf", "main.tf/", "a\x00b"],
)
def test_unsafe_or_noncanonical_paths_rejected(path):
    with pytest.raises(ValidationError):
        Location(path=path)
    with pytest.raises(ValidationError):
        Coverage(evaluated_files=[path])
    with pytest.raises(ValidationError):
        ResourceBlock(block_type="resource", resource_type="aws_instance", name="a",
                      address="aws_instance.a", path=path)


def test_lines_nullable_positive_and_ordered():
    assert Location(path="main.tf").start_line is None
    assert Location(path="main.tf", start_line=3, end_line=3).end_line == 3
    assert Location(path="main.tf", start_line=3).end_line is None
    for start, end in [(0, 1), (-1, None), (5, 4)]:
        with pytest.raises(ValidationError):
            Location(path="main.tf", start_line=start, end_line=end)
    with pytest.raises(ValidationError):
        ResourceBlock(block_type="resource", resource_type="aws_instance", name="a",
                      address="aws_instance.a", path="main.tf", start_line=9, end_line=2)


def test_strict_types_reject_coercion():
    with pytest.raises(ValidationError):
        Location(path="main.tf", start_line="3")
    with pytest.raises(ValidationError):
        Location(path=Path("main.tf"))
    with pytest.raises(ValidationError):
        RawScanResult(status="complete", return_code=True)


def test_validate_assignment_enforced():
    location = Location(path="main.tf")
    with pytest.raises(ValidationError):
        location.path = "../x.tf"


def test_mutable_defaults_are_not_shared():
    a, b = Coverage(), Coverage()
    a.required_gaps.append("x")
    assert b.required_gaps == []
    r1, r2 = RawScanResult(status="complete"), RawScanResult(status="complete")
    r1.coverage.diagnostics.append("x")
    r1.failed_checks.append({"check_id": "x"})
    assert r2.coverage.diagnostics == [] and r2.failed_checks == []
    c1, c2 = CustomScanResult(), CustomScanResult()
    c1.findings.append(make_finding())
    assert c2.findings == [] and c1.coverage is not c2.coverage
    v1, v2 = ValidConfig(), ValidConfig()
    v1.required_tags.append("team")
    v1.checkov_severity_map["X"] = RulePolicy(priority="low", category="governance",
                                              policy_mode="warn", template_id="scanner_review")
    assert v2.required_tags == ["owner", "environment"] and v2.checkov_severity_map == {}
    p1, p2 = ParsedScan(), ParsedScan()
    p1.parsed["main.tf"] = []
    assert p2.parsed == {} and p1.coverage is not p2.coverage
    b1 = ResourceBlock(block_type="resource", resource_type="aws_instance", name="a",
                       address="aws_instance.a", path="main.tf")
    b2 = b1.model_copy(deep=True)
    b1.literal_attributes["tags"] = {}
    assert b2.literal_attributes == {}


def test_valid_config_defaults():
    config = ValidConfig()
    assert config.required_tags == ["owner", "environment"]
    assert config.taggable_resource_types == ["aws_security_group", "aws_instance", "aws_db_instance"]
    assert config.blocking_priorities == ["high", "critical"]
    assert config.checkov_severity_map == {}
    assert config.max_visible_findings == 10
    assert config.scanner_timeout_seconds == 120
    assert config.checkov_command == ["checkov"]
    assert config.schema_version == "1.0.0"


def test_valid_config_bounds():
    for bad in ({"max_visible_findings": -1}, {"scanner_timeout_seconds": 0},
                {"checkov_command": []}, {"blocking_priorities": ["severe"]},
                {"schema_version": "2.0.0"}):
        with pytest.raises(ValidationError):
            ValidConfig.model_validate(bad)


def test_raw_scan_result_defaults():
    raw = RawScanResult(status="error")
    assert (raw.tool, raw.version, raw.return_code) == ("checkov", "3.3.8", None)
    assert raw.coverage == Coverage()
    with pytest.raises(ValidationError):
        RawScanResult(status="timeout")


def test_risk_summary_counts_complete_and_nonnegative():
    summary = make_summary()
    assert summary.schema_version == "1.0.0"
    assert RiskSummary.model_validate_json(summary.model_dump_json()) == summary
    partial = {"high": 1}
    with pytest.raises(ValidationError):
        make_summary(counts=partial)
    with pytest.raises(ValidationError):
        make_summary(category_counts={"security": 0})
    with pytest.raises(ValidationError):
        make_summary(counts={**{s: 0 for s in SEVERITIES}, "high": -1})
    with pytest.raises(ValidationError):
        make_summary(counts={**{s: 0 for s in SEVERITIES}, "severe": 0})
    with pytest.raises(ValidationError):
        make_summary(score=-1)
    with pytest.raises(ValidationError):
        make_summary(status="FAIL")
    assert make_summary(top_priority="unknown").top_priority == "unknown"


def test_resource_block_provider_shape():
    block = ResourceBlock(
        block_type="provider", resource_type="aws", name="west", address="provider.aws.west",
        path="providers.tf", literal_attributes={"alias": "west", "default_tags": {"owner": "a"}},
    )
    assert block.unresolved_attributes == []
    with pytest.raises(ValidationError):
        ResourceBlock(block_type="module", resource_type="x", name="x", address="module.x", path="main.tf")
    with pytest.raises(ValidationError):
        ParsedScan(parsed={"../main.tf": []})


def test_checkov_severity_config_loads_into_valid_config():
    data = yaml.safe_load((ROOT / "config" / "checkov_severity.yaml").read_text(encoding="utf-8"))
    config = ValidConfig.model_validate(data)
    policy = config.checkov_severity_map
    assert set(policy) == {"CKV_AWS_24", "CKV_AWS_293"}
    assert policy["CKV_AWS_24"] == RulePolicy(priority="high", category="security",
                                              policy_mode="block", template_id="open_ssh")
    assert policy["CKV_AWS_293"] == RulePolicy(priority="high", category="reliability",
                                               policy_mode="block", template_id="rds_deletion_protection")
