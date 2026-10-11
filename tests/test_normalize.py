"""Normalization tests for valid.normalize.

Covers the contract list: shuffled/repeated input, changed evidence IDs,
same resource names in different paths, unknown severity, null locations,
invalid records, repeated same-source findings, and retained cross-source
provenance. Plain asserts only, so the suite runs under pytest or a stdlib
runner.
"""

from valid.models import (
    FindingSource,
    Location,
    RawScanResult,
    Recommendation,
    ResourceRef,
    RulePolicy,
    ValidConfig,
)
from valid.normalize import make_finding, normalize


def _config():
    return ValidConfig(
        checkov_severity_map={
            "CKV_AWS_24": RulePolicy(
                priority="high",
                category="security",
                policy_mode="block",
                template_id="open_ssh",
            ),
            "CKV_AWS_293": RulePolicy(
                priority="high",
                category="reliability",
                policy_mode="block",
                template_id="rds_deletion_protection",
            ),
        }
    )


def _record(**overrides):
    base = {
        "check_id": "CKV_AWS_24",
        "check_name": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "file_path": "/main.tf",
        "resource": "aws_security_group.open",
        "file_line_range": [10, 20],
        "severity": "HIGH",
    }
    base.update(overrides)
    return base


def _raw(checks):
    return RawScanResult(
        status="complete", tool="checkov", version="3.3.8", failed_checks=checks
    )


def _custom(rule="DG-AWS-NET-001", path="main.tf", priority="high",
            summary="literal ingress 0.0.0.0/0 to 22"):
    return make_finding(
        source=FindingSource(
            tool="valid",
            version="0.1.0",
            rule_id=rule,
            scanner_severity=priority,
            severity_origin="custom_rule",
        ),
        location=Location(path=path, start_line=10, end_line=20),
        resource=ResourceRef(
            type="aws_security_group", address="aws_security_group.open"
        ),
        category="security",
        priority=priority,
        evidence_strength="deterministic",
        evidence_summaries=[("literal_hcl", summary)],
        recommendation=Recommendation(template_id="open_ssh"),
        policy_mode="block",
    )


def _raises_valueerror(fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("expected ValueError, nothing was raised")


def test_mapped_check_uses_configured_policy():
    (finding,) = normalize(_raw([_record()]), [], _config())
    assert finding.source.rule_id == "CKV_AWS_24"
    assert finding.source.severity_origin == "rule_map"
    assert finding.source.scanner_severity == "high"
    assert finding.priority == "high"
    assert finding.category == "security"
    assert finding.policy_mode == "block"
    assert finding.recommendation.template_id == "open_ssh"
    assert finding.location.path == "main.tf"
    assert (finding.location.start_line, finding.location.end_line) == (10, 20)
    assert finding.resource.type == "aws_security_group"
    assert finding.resource.address == "aws_security_group.open"
    assert finding.finding_id.startswith("f_")
    assert len(finding.evidence) == 1
    assert finding.evidence[0].kind == "scanner"


def test_mapped_check_absent_severity_stays_unknown():
    (finding,) = normalize(_raw([_record(severity=None)]), [], _config())
    assert finding.source.scanner_severity == "unknown"
    assert finding.source.severity_origin == "rule_map"
    assert finding.priority == "high"


def test_unmapped_check_is_unknown_warn_triage():
    (finding,) = normalize(
        _raw([_record(check_id="CKV_AWS_999", severity=None)]), [], _config()
    )
    assert finding.priority == "unknown"
    assert finding.policy_mode == "warn"
    assert finding.source.severity_origin == "defaulted"
    assert finding.source.scanner_severity == "unknown"
    assert finding.category == "governance"
    assert finding.recommendation.template_id == "scanner_review"


def test_unmapped_check_preserves_usable_scanner_severity():
    (finding,) = normalize(
        _raw([_record(check_id="CKV_AWS_999", severity="MEDIUM")]), [], _config()
    )
    assert finding.source.scanner_severity == "medium"
    assert finding.source.severity_origin == "scanner"
    # Priority is never inferred from scary prose: still unknown.
    assert finding.priority == "unknown"
    assert finding.policy_mode == "warn"


def test_garbage_severity_token_becomes_unknown():
    (finding,) = normalize(
        _raw([_record(check_id="CKV_AWS_999", severity="SUPERBAD")]), [], _config()
    )
    assert finding.source.scanner_severity == "unknown"
    assert finding.source.severity_origin == "defaulted"


def test_private_absolute_path_is_stripped():
    record = _record()
    record["absolute_file_path"] = "/private/var cland/x/main.tf"
    (finding,) = normalize(_raw([record]), [], _config())
    assert finding.location.path == "main.tf"


def test_null_locations_survive():
    (no_lines,) = normalize(_raw([_record(file_line_range=None)]), [], _config())
    assert no_lines.location.start_line is None
    assert no_lines.location.end_line is None
    (bad_lines,) = normalize(
        _raw([_record(file_line_range=[20, 10])]), [], _config()
    )
    assert bad_lines.location.start_line is None
    assert bad_lines.location.end_line is None


def test_invalid_records_raise():
    config = _config()
    _raises_valueerror(lambda: normalize(_raw([{"file_path": "/a.tf"}]), [], config))
    _raises_valueerror(
        lambda: normalize(_raw([_record(file_path="../../etc/x.tf")]), [], config)
    )
    _raises_valueerror(
        lambda: normalize(_raw([_record(file_path="")]), [], config)
    )
    _raises_valueerror(lambda: normalize(_raw(["not-a-dict"]), [], config))
    _raises_valueerror(lambda: normalize(_raw([_record(check_id="")]), [], config))


def test_malformed_resource_string_is_rejected():
    # A dotted resource with an empty type part (".foo") is invalid scanner
    # data, not a valid empty resource type: it must surface for INCOMPLETE
    # handling rather than produce a finding with a blank type.
    config = _config()
    _raises_valueerror(
        lambda: normalize(_raw([_record(resource=".foo")]), [], config)
    )
    _raises_valueerror(
        lambda: normalize(_raw([_record(resource=".")]), [], config)
    )


def test_failed_scan_surfaces_incomplete():
    config = _config()
    errored = RawScanResult(status="error", failed_checks=[_record()])
    _raises_valueerror(lambda: normalize(errored, [], config))
    parse_failed = RawScanResult(
        status="complete",
        failed_checks=[_record()],
        parsing_errors=["broken.tf: unexpected token"],
    )
    _raises_valueerror(lambda: normalize(parse_failed, [], config))


def test_shuffled_repeated_input_is_stable():
    first = _record()
    second = _record(check_id="CKV_AWS_293", resource="aws_db_instance.main")
    custom = _custom()
    expected = normalize(_raw([first, second]), [custom], _config())
    # Reversed order with every scanner record duplicated.
    actual = normalize(_raw([second, first, first, second]), [custom], _config())
    assert [f.finding_id for f in actual] == [f.finding_id for f in expected]
    assert len(actual) == 3
    keys = [
        (
            f.location.path,
            f.resource.address if f.resource and f.resource.address else "",
            f.source.tool,
            f.source.rule_id,
            f.finding_id,
        )
        for f in actual
    ]
    assert keys == sorted(keys)


def test_changed_evidence_merges_under_one_finding():
    first = _record(check_name="name one")
    second = _record(check_name="name two")
    (finding,) = normalize(_raw([first, second]), [], _config())
    assert len(finding.evidence) == 2
    ids = [item.evidence_id for item in finding.evidence]
    assert ids == sorted(ids)


def test_repeated_custom_findings_merge():
    merged = normalize(_raw([]), [_custom(), _custom()], _config())
    assert len(merged) == 1
    assert len(merged[0].evidence) == 1
    first, second = _custom(), _custom(summary="a different literal excerpt")
    merged = normalize(_raw([]), [first, second], _config())
    assert len(merged) == 1
    assert len(merged[0].evidence) == 2


def test_contradictory_duplicates_raise():
    config = _config()
    low = _custom(priority="low")
    high = _custom(priority="high")
    assert low.fingerprint == high.fingerprint
    _raises_valueerror(lambda: normalize([], [low, high], config))


def test_cross_source_provenance_retained():
    findings = normalize(_raw([_record()]), [_custom()], _config())
    assert len(findings) == 2
    assert sorted(f.source.tool for f in findings) == ["checkov", "valid"]
    # Same logical detector/path/resource, separate detector findings.
    assert findings[0].fingerprint != findings[1].fingerprint


def test_same_resource_names_in_different_paths_stay_separate():
    findings = normalize(
        _raw(
            [
                _record(file_path="/a/main.tf"),
                _record(file_path="/b/main.tf"),
            ]
        ),
        [],
        _config(),
    )
    assert len(findings) == 2
    assert findings[0].location.path == "a/main.tf"
    assert findings[1].location.path == "b/main.tf"


def test_custom_finding_fields_pass_through():
    custom = make_finding(
        source=FindingSource(
            tool="valid",
            version="0.1.0",
            rule_id="DG-AWS-TAG-001",
            scanner_severity="medium",
            severity_origin="custom_rule",
        ),
        location=Location(path="tags.tf"),
        resource=None,
        category="governance",
        priority="medium",
        evidence_strength="strong_heuristic",
        evidence_summaries=[("literal_hcl", "missing owner tag")],
        recommendation=Recommendation(template_id="missing_tags"),
        policy_mode="warn",
        change_action="update",
    )
    (finding,) = normalize(_raw([]), [custom], _config())
    assert finding.priority == "medium"
    assert finding.evidence_strength == "strong_heuristic"
    assert finding.change_action == "update"
    assert finding.resource is None
    assert finding.source.severity_origin == "custom_rule"
