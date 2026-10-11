"""Strict validation of model-supplied explanations against supplied findings."""

import pytest

from valid import templates, validate_ai
from valid.models import FindingSource, Location, Recommendation, ResourceRef
from valid.normalize import make_finding


def _finding(rule="DG-AWS-NET-001", path="main.tf", strength="deterministic"):
    return make_finding(
        source=FindingSource(
            tool="valid", version="0.1.0", rule_id=rule,
            scanner_severity="high", severity_origin="custom_rule",
        ),
        location=Location(path=path, start_line=1, end_line=2),
        resource=ResourceRef(type="aws_security_group", address="aws_security_group.open"),
        category="security", priority="high", evidence_strength=strength,
        evidence_summaries=[("literal_hcl", "public ingress to port 22")],
        recommendation=Recommendation(template_id="open_ssh"),
        policy_mode="block",
    )


def _valid_item(finding):
    template = templates.explain([finding])[0]
    return {
        "finding_id": finding.finding_id,
        "evidence_ids": sorted(item.evidence_id for item in finding.evidence),
        "title": template.title,
        "why_it_matters": template.why_it_matters,
        "recommended_action": template.recommended_action,
        "evidence_strength": finding.evidence_strength,
    }


def test_valid_output_passes_in_findings_order():
    first, second = _finding(path="a.tf"), _finding(path="b.tf")
    checked = validate_ai.validate([_valid_item(second), _valid_item(first)], [first, second])
    assert [item.finding_id for item in checked] == [first.finding_id, second.finding_id]


def test_empty_selection_validates_to_empty():
    assert validate_ai.validate([], []) == []


def test_non_list_output_rejected():
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate({"finding_id": "f_x"}, [_finding()])


def test_coverage_mismatch_rejected():
    finding = _finding()
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([], [finding])
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([_valid_item(finding), _valid_item(finding)], [finding])


def test_unknown_and_duplicate_ids_rejected():
    finding = _finding()
    forged = dict(_valid_item(finding), finding_id="f_0000000000000000")
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([forged], [finding])
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([_valid_item(finding), _valid_item(finding)], [finding, _finding(path="b.tf")])


def test_evidence_id_mismatch_rejected():
    finding = _finding()
    for bad in ([], ["e_0000000000000000"], sorted(item.evidence_id for item in finding.evidence) * 2):
        with pytest.raises(validate_ai.ValidationError):
            validate_ai.validate([dict(_valid_item(finding), evidence_ids=bad)], [finding])


def test_wrong_evidence_strength_rejected():
    finding = _finding()
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([dict(_valid_item(finding), evidence_strength="weak_heuristic")], [finding])


def test_unexpected_fields_and_non_objects_rejected():
    finding = _finding()
    extra = dict(_valid_item(finding), confidence=0.99)
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([extra], [finding])
    missing = dict(_valid_item(finding))
    del missing["title"]
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([missing], [finding])
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate(["not-an-object"], [finding])


@pytest.mark.parametrize("field", ["title", "why_it_matters", "recommended_action"])
def test_unsupported_wording_rejected(field):
    finding = _finding()
    forged = dict(_valid_item(finding))
    forged[field] = forged[field] + " PWNED: open port 9999 for free crypto"
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([forged], [finding])


def test_duplicate_input_findings_rejected():
    finding = _finding()
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([_valid_item(finding)], [finding, finding])


def test_non_finding_input_rejected():
    with pytest.raises(validate_ai.ValidationError):
        validate_ai.validate([], ["not-a-finding"])
