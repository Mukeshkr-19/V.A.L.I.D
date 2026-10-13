"""Bounded Markdown and evidence association tests."""
import html
import pytest

from valid.models import Coverage, EvidenceItem, ResourceRef
from valid.report import render
from valid.templates import explain
from report_support import finding, summary


@pytest.mark.parametrize("status", ["PASS","REVIEW","HIGH RISK","INCOMPLETE"])
def test_verdict_marker_and_scope(status):
    document = render(summary(status), [], [])
    assert document.startswith("<!-- valid-report -->\n")
    assert "Review - " + status in document
    assert "Terraform source tree; static analysis only" in document
    if status == "INCOMPLETE":
        assert "Required analysis is incomplete" in document
        assert "No findings were supplied; analysis is incomplete" in document


def test_exact_evidence_and_locations():
    item = finding()
    document = html.unescape(render(summary(), [item], explain([item])))
    assert "main.tf:1" in document
    assert "aws_security_group.web1" in document
    assert item.evidence[0].evidence_id in document
    assert item.evidence[0].summary in document


def test_more_than_ten_findings_collapsed():
    items = [finding(index) for index in range(1,14)]
    document = render(summary(), items, explain(items))
    assert sum(line.startswith(tuple("### " + str(i) + "." for i in range(1, 11)))
               for line in document.splitlines()) == 10
    assert "<summary>3 additional detector findings</summary>" in document
    assert "findings.json" in document


def test_findings_order_is_stable():
    items = [finding(3), finding(1), finding(2)]
    assert render(summary(), items, explain(items)) == render(summary(), list(reversed(items)), explain(list(reversed(items))))


def test_untrusted_text_cannot_inject_markdown_or_mentions():
    hostile = "\n## forged\n</details><script>alert(1)</script>\n\x60\x60\x60\n[click](javascript:alert(1)) @someone"
    item = finding(text=hostile)
    item.resource = ResourceRef(address="x @someone")
    document = render(summary(), [item], explain([item]))
    assert "<script>" not in document
    assert "</details>" not in document
    assert "\n## forged" not in document
    assert "javascript:" not in document
    assert "@someone" not in document
    assert document.count("\x60\x60\x60") == 2  # Only the reviewed, static edit example is fenced.


def test_common_secrets_and_private_paths_redacted():
    item = finding(text="password=dummy-value /Users/example/private/file.tf AKIA" + "A"*16)
    document = html.unescape(render(summary(), [item], explain([item])))
    assert "dummy-value" not in document
    assert "/Users/example" not in document
    assert "AKIA" + "A"*16 not in document
    assert "[redacted]" in document


@pytest.mark.parametrize("mutation", ["unknown","duplicate","missing","foreign_evidence","changed_strength"])
def test_invalid_explanations_rejected(mutation):
    item = finding()
    explanations = explain([item])
    if mutation == "unknown":
        explanations[0].finding_id = "foreign-id"
    elif mutation == "duplicate":
        explanations.append(explanations[0])
    elif mutation == "missing":
        explanations = []
    elif mutation == "foreign_evidence":
        explanations[0].evidence_ids = ["foreign-evidence"]
    else:
        explanations[0].evidence_strength = "strong_heuristic"
    with pytest.raises(ValueError):
        render(summary(), [item], explanations)


def test_not_evaluated_and_unknown_remain_explicit():
    item = finding(strength="not_evaluated", priority="unknown")
    document = html.unescape(render(summary("INCOMPLETE"), [item], explain([item])))
    assert "not evaluated; this is not a confirmed violation" in document
    assert "**Severity mapping:** unknown" in document


def test_large_hostile_fields_fit_comment_budget():
    items = [finding(index, text="<"*5000) for index in range(1,14)]
    for item in items:
        item.evidence = [EvidenceItem(evidence_id="e_" + str(index), kind="literal_hcl", summary="<"*5000) for index in range(1,20)]
    coverage = Coverage(required_gaps=["#"*5000 + str(index) for index in range(20)])
    document = render(summary("INCOMPLETE", coverage=coverage), items, explain(items))
    assert len(document.encode("utf-8")) <= 60000
    assert document.startswith("<!-- valid-report -->\n")
    assert "INCOMPLETE" in document


def test_null_location_and_resource_are_honest():
    item = finding()
    item.location.start_line = None
    item.location.end_line = None
    item.resource = None
    document = html.unescape(render(summary(), [item], explain([item])))
    assert "**Location:** main.tf" in document
    assert "None" not in document


def test_comment_truncation_preserves_header_and_limit():
    items = [finding(index, text="#" * 5000) for index in range(1, 14)]
    for item in items:
        item.source.tool = "#" * 5000
        item.source.rule_id = "#" * 5000
        item.resource.address = "#" * 5000
        item.evidence = [
            EvidenceItem(evidence_id="#" * 5000 + str(index), kind="literal_hcl", summary="#" * 5000)
            for index in range(5)
        ]
    explanations = explain(items)
    for explanation in explanations:
        explanation.title = "#" * 5000
        explanation.why_it_matters = "#" * 5000
        explanation.recommended_action = "#" * 5000
    document = render(summary(), items, explanations)
    assert len(document.encode("utf-8")) <= 60000
    assert document.startswith("<!-- valid-report -->\n## V.A.L.I.D. Review - HIGH RISK\n")
    assert "Report preview truncated" in document
