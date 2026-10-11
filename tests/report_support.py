"""Focused fixtures for explanation and Markdown tests."""

from valid.models import Coverage, EvidenceItem, Finding, FindingSource, Location, Recommendation, ResourceRef, RiskSummary


def finding(index=1, *, template="open_ssh", strength="deterministic", priority="high", text="Public IPv4 SSH ingress"):
    return Finding(
        finding_id=f"f_{index:016x}",
        fingerprint=f"{index:064x}",
        source=FindingSource(tool="valid", version="0.1.0", rule_id="DG-AWS-NET-001", scanner_severity=priority, severity_origin="custom_rule"),
        location=Location(path="main.tf", start_line=1, end_line=5),
        resource=ResourceRef(type="aws_security_group", address=f"aws_security_group.web{index}"),
        category="security", priority=priority, evidence_strength=strength, change_action="unknown",
        evidence=[EvidenceItem(evidence_id=f"e_{index:016x}", kind="coverage_gap" if strength=="not_evaluated" else "literal_hcl", summary=text)],
        recommendation=Recommendation(template_id=template), policy_mode="warn" if priority=="unknown" else "block",
    )


def summary(status="HIGH RISK", *, coverage=None):
    return RiskSummary(
        status=status, score=7,
        counts={"info":0,"low":0,"medium":0,"high":1,"critical":0,"unknown":0},
        category_counts={"security":1,"reliability":0,"governance":0,"cost_risk":0},
        top_priority="high", coverage=coverage or Coverage(evaluated_files=["main.tf"]), reasons=[],
    )
