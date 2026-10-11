"""Deterministic identity tests for valid.normalize.

Each vector recomputes the contract hash formulas inline with hashlib so the
tests pin make_finding to the spec instead of to itself.
"""

import hashlib
import json

from valid.models import FindingSource, Location, ResourceRef
from valid.normalize import (
    canonical_json,
    evidence_id_of,
    finding_id_of,
    fingerprint_of,
    make_finding,
)


def _source(tool="checkov", rule="CKV_AWS_24"):
    return FindingSource(
        tool=tool,
        version="3.3.8",
        rule_id=rule,
        scanner_severity="high",
        severity_origin="scanner",
    )


def _location(path="main.tf"):
    return Location(path=path, start_line=10, end_line=20)


def _resource():
    return ResourceRef(type="aws_security_group", address="aws_security_group.open")


def test_canonical_identity_json_shape():
    text = canonical_json(
        {
            "tool": "checkov",
            "rule_id": "CKV_AWS_24",
            "path": "main.tf",
            "resource_type": "aws_security_group",
            "resource_address": "aws_security_group.open",
        }
    )
    assert text == (
        '{"path":"main.tf","resource_address":"aws_security_group.open",'
        '"resource_type":"aws_security_group","rule_id":"CKV_AWS_24",'
        '"tool":"checkov"}'
    )


def test_finding_id_matches_spec_vector():
    source, location, resource = _source(), _location(), _resource()
    identity = (
        '{"path":"main.tf","resource_address":"aws_security_group.open",'
        '"resource_type":"aws_security_group","rule_id":"CKV_AWS_24",'
        '"tool":"checkov"}'
    )
    expected_fp = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    assert fingerprint_of(source, location, resource) == expected_fp
    assert finding_id_of(source, location, resource) == "f_" + expected_fp[:16]

    finding = make_finding(
        source=source,
        location=location,
        resource=resource,
        category="security",
        priority="high",
        evidence_strength="deterministic",
        evidence_summaries=[("scanner", "Checkov CKV_AWS_24 failed")],
        recommendation=__import__(
            "valid.models", fromlist=["Recommendation"]
        ).Recommendation(template_id="open_ssh"),
        policy_mode="block",
    )
    assert finding.finding_id == "f_" + expected_fp[:16]
    assert finding.fingerprint == expected_fp


def test_evidence_id_matches_spec_formula():
    fid = "f_0123456789abcdef"
    kind, summary = "scanner", "Checkov CKV_AWS_24 failed for sg in main.tf"
    payload = fid + "|" + kind + "|" + json.dumps(
        summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert evidence_id_of(fid, kind, summary) == "e_" + hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:16]


def test_crlf_summaries_share_evidence_id():
    fid = "f_abcdef0123456789"
    assert evidence_id_of(fid, "scanner", "line one\r\nline two") == evidence_id_of(
        fid, "scanner", "line one\nline two"
    )
    assert evidence_id_of(fid, "scanner", "line one\rline two") == evidence_id_of(
        fid, "scanner", "line one\nline two"
    )


def test_evidence_change_keeps_finding_identity():
    kwargs = dict(
        source=_source(),
        location=_location(),
        resource=_resource(),
        category="security",
        priority="high",
        evidence_strength="deterministic",
        policy_mode="block",
    )
    from valid.models import Recommendation

    first = make_finding(
        evidence_summaries=[("scanner", "summary one")],
        recommendation=Recommendation(template_id="open_ssh"),
        **kwargs,
    )
    second = make_finding(
        evidence_summaries=[("scanner", "summary two")],
        recommendation=Recommendation(template_id="open_ssh"),
        **kwargs,
    )
    assert first.finding_id == second.finding_id
    assert first.fingerprint == second.fingerprint
    assert [e.evidence_id for e in first.evidence] != [
        e.evidence_id for e in second.evidence
    ]


def test_same_resource_name_different_paths_differ():
    from valid.models import Recommendation

    def build(path):
        return make_finding(
            source=_source(),
            location=Location(path=path),
            resource=_resource(),
            category="security",
            priority="high",
            evidence_strength="deterministic",
            evidence_summaries=[("scanner", "same summary")],
            recommendation=Recommendation(template_id="open_ssh"),
            policy_mode="block",
        )

    assert build("a/main.tf").finding_id != build("b/main.tf").finding_id


def test_none_and_absent_resource_share_identity():
    assert finding_id_of(_source(), _location(), None) == finding_id_of(
        _source(), _location(), ResourceRef(type=None, address=None)
    )


def test_blank_resource_fields_fail_validation():
    cases = [
        {"type": "", "address": "aws_security_group.open"},
        {"type": "aws_security_group", "address": ""},
        {"type": "", "address": ""},
    ]
    for kwargs in cases:
        try:
            ResourceRef(**kwargs)
        except ValueError:
            continue
        raise AssertionError(
            "blank ResourceRef fields must fail validation: %r" % (kwargs,)
        )


def test_repeated_construction_is_identical():
    from valid.models import Recommendation

    def build():
        return make_finding(
            source=_source(),
            location=_location(),
            resource=_resource(),
            category="security",
            priority="high",
            evidence_strength="deterministic",
            evidence_summaries=[("scanner", "stable")],
            recommendation=Recommendation(template_id="open_ssh"),
            policy_mode="block",
        )

    first, second = build(), build()
    assert first.finding_id == second.finding_id
    assert [e.evidence_id for e in first.evidence] == [
        e.evidence_id for e in second.evidence
    ]


def test_rejects_unknown_evidence_kind():
    from valid.models import Recommendation

    try:
        make_finding(
            source=_source(),
            location=_location(),
            resource=_resource(),
            category="security",
            priority="high",
            evidence_strength="deterministic",
            evidence_summaries=[("scanner_output", "nope")],
            recommendation=Recommendation(template_id="open_ssh"),
            policy_mode="block",
        )
    except ValueError:
        return
    raise AssertionError("unknown evidence kind must raise ValueError")


def test_rejects_empty_evidence_summaries():
    from valid.models import Recommendation

    try:
        make_finding(
            source=_source(),
            location=_location(),
            resource=_resource(),
            category="security",
            priority="high",
            evidence_strength="deterministic",
            evidence_summaries=[],
            recommendation=Recommendation(template_id="open_ssh"),
            policy_mode="block",
        )
    except ValueError:
        return
    raise AssertionError("empty evidence_summaries must raise ValueError")
