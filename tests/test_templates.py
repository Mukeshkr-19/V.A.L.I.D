"""Deterministic template contract tests."""
import pytest

from valid.templates import explain
from report_support import finding


@pytest.mark.parametrize("template,title", [
    ("open_ssh", "SSH ingress is open to the internet"),
    ("missing_tags", "Required resource tags are missing or empty"),
    ("rds_deletion_protection", "RDS deletion protection is disabled"),
])
def test_supported_guidance(template, title):
    item = finding(template=template)
    original = item.model_dump_json()
    result = explain([item])
    assert len(result) == 1
    assert result[0].title == title
    assert result[0].finding_id == item.finding_id
    assert result[0].evidence_ids == [item.evidence[0].evidence_id]
    assert result[0].evidence_strength == item.evidence_strength
    assert item.model_dump_json() == original


def test_no_key_or_network_needed(monkeypatch):
    import socket
    monkeypatch.delenv("VALID_API_KEY", raising=False)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("Network call"))
    assert explain([finding()]) == explain([finding()])


@pytest.mark.parametrize("strength", ["not_evaluated", "strong_heuristic", "weak_heuristic"])
def test_weaker_evidence_is_not_confirmed_violation(strength):
    item = finding(strength=strength)
    text = explain([item])[0]
    assert text.evidence_strength == strength
    assert "SSH ingress is open" not in text.title


def test_unknown_or_foreign_template_is_generic():
    assert explain([finding(template="not-a-supported-rule")])[0].title == "Scanner finding needs review"
    assert explain([finding(priority="unknown")])[0].title == "Scanner finding needs review"


def test_duplicate_finding_ids_rejected():
    item = finding()
    with pytest.raises(ValueError):
        explain([item, item])


def test_empty_input():
    assert explain([]) == []


def test_all_evidence_ids_are_retained_unique():
    item = finding()
    item.evidence.append(item.evidence[0])
    assert explain([item])[0].evidence_ids == [item.evidence[0].evidence_id]
