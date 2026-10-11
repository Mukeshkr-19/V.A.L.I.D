"""Contract tests for the risky/fixed Terraform fixtures against the real scanners."""

import hashlib
import re
import sys
from pathlib import Path

import pytest
import yaml

import valid
from valid import normalize, risk
from valid.models import Coverage, ValidConfig
from valid.scanners import checkov, literal_hcl

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
RISKY = FIXTURES / "risky"
FIXED = FIXTURES / "fixed"

NET, TAG, RDS = "DG-AWS-NET-001", "DG-AWS-TAG-001", "DG-AWS-RDS-001"
CUSTOM_RULES = {NET, TAG, RDS}
SG, EC2, DB = "aws_security_group.web", "aws_instance.web", "aws_db_instance.main"
TAGGABLE = {SG, EC2, DB}


def load_config() -> ValidConfig:
    data = yaml.safe_load((ROOT / "config" / "checkov_severity.yaml").read_text(encoding="utf-8"))
    return ValidConfig.model_validate(data)


def checkov_config() -> ValidConfig:
    executable = Path(sys.executable).parent / "checkov"
    if not executable.is_file():
        pytest.fail(f"Checkov executable not found next to the interpreter: {executable.name}")
    return load_config().model_copy(update={"checkov_command": [str(executable)]})


def custom_scan(root: Path):
    config = load_config()
    parsed = literal_hcl.parse(root, config)
    return parsed, literal_hcl.scan(parsed.parsed, config)


def merged_coverage(*coverages: Coverage) -> Coverage:
    def union(field: str) -> list[str]:
        out: list[str] = []
        for coverage in coverages:
            for item in getattr(coverage, field):
                if item not in out:
                    out.append(item)
        return out

    return Coverage(**{field: union(field) for field in Coverage.model_fields})


def assert_no_required_gaps(coverage: Coverage) -> None:
    assert coverage.required_failed_stages == []
    assert coverage.required_gaps == []


def rule_hits(findings) -> set[tuple[str, str]]:
    return {(f.source.rule_id, f.resource.address) for f in findings if f.source.rule_id in CUSTOM_RULES}


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


@pytest.fixture(scope="module")
def pipeline():
    """Real parser, custom rules, Checkov, normalizer, and risk for each fixture."""
    config = checkov_config()
    results = {}
    for name, root in (("risky", RISKY), ("fixed", FIXED)):
        before = tree_digest(root)
        parsed = literal_hcl.parse(root, config)
        custom = literal_hcl.scan(parsed.parsed, config)
        raw = checkov.run(root, config)
        findings = normalize.normalize(raw, custom.findings, config)
        coverage = merged_coverage(parsed.coverage, custom.coverage, raw.coverage)
        summary = risk.summarize(findings, coverage, config)
        results[name] = {
            "raw": raw,
            "findings": findings,
            "coverage": coverage,
            "summary": summary,
            "unchanged": tree_digest(root) == before,
        }
    return results


def test_modules_under_test_come_from_this_tree():
    for module in (valid, literal_hcl, checkov, normalize, risk, sys.modules["valid.models"]):
        assert Path(module.__file__).resolve().is_relative_to(ROOT), module.__name__


@pytest.mark.parametrize("root", [RISKY, FIXED], ids=["risky", "fixed"])
def test_fixture_is_static_and_contains_no_real_values(root):
    files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    assert files == ["main.tf"]
    text = (root / "main.tf").read_text(encoding="utf-8")
    assert "checkov:skip" not in text.lower()
    assert not re.search(r"^\s*(module|backend|data)\b", text, re.MULTILINE)
    assert not re.search(r"\bami-[0-9a-f]{8,}\b", text)
    assert not re.search(r"(AKIA|ASIA)[0-9A-Z]{16}", text)
    assert not re.search(r"\b\d{12}\b", text)
    assert not re.search(r"https?://", text)
    assert re.search(r'^\s*password\s*=\s*var\.db_password\s*$', text, re.MULTILINE)
    assert re.search(r"^\s*ami\s*=\s*var\.ami_id\s*$", text, re.MULTILINE)
    for name in ("ami_id", "db_password"):
        block = re.search(r'variable "%s" \{(.*?)\n\}' % name, text, re.DOTALL).group(1)
        assert re.search(r"^\s*type\s*=\s*string\s*$", block, re.MULTILINE)
        assert "default" not in block


def test_fixtures_share_resource_identities():
    ids = {}
    for name, root in (("risky", RISKY), ("fixed", FIXED)):
        parsed, _ = custom_scan(root)
        ids[name] = sorted(b.address for b in parsed.parsed["main.tf"] if b.block_type == "resource")
    assert ids["risky"] == ids["fixed"] == sorted(TAGGABLE)


def test_risky_custom_rules_find_all_three_controls():
    parsed, custom = custom_scan(RISKY)
    assert_no_required_gaps(parsed.coverage)
    assert_no_required_gaps(custom.coverage)
    assert parsed.coverage.evaluated_files == ["main.tf"]
    assert rule_hits(custom.findings) == {(NET, SG), (RDS, DB)} | {(TAG, address) for address in TAGGABLE}
    for finding in custom.findings:
        assert finding.location.path == "main.tf"
        assert finding.evidence_strength == "deterministic"
        assert finding.source.tool == "valid"
    by_rule = {f.source.rule_id: f for f in custom.findings}
    assert (by_rule[NET].priority, by_rule[NET].policy_mode) == ("high", "block")
    assert (by_rule[RDS].priority, by_rule[RDS].policy_mode) == ("high", "block")
    assert (by_rule[TAG].priority, by_rule[TAG].policy_mode) == ("medium", "warn")


def test_fixed_custom_rules_find_nothing():
    parsed, custom = custom_scan(FIXED)
    assert_no_required_gaps(parsed.coverage)
    assert_no_required_gaps(custom.coverage)
    assert parsed.coverage.evaluated_files == ["main.tf"]
    assert custom.findings == []


def _replace_in_resource(text: str, resource: str, old: str, new: str) -> str:
    start = text.index(f'resource "{resource.split(".")[0]}" "{resource.split(".")[1]}"')
    end = text.find("\nresource ", start + 1)
    end = len(text) if end == -1 else end
    block = text[start:end]
    assert block.count(old) == 1, (resource, old)
    return text[:start] + block.replace(old, new) + text[end:]


@pytest.mark.parametrize(
    "source, resource, old, new, expected",
    [
        (FIXED, SG, '["10.0.0.0/8"]', '["0.0.0.0/0"]', {(NET, SG)}),
        (FIXED, EC2, 'owner       = "platform-team"', 'owner       = ""', {(TAG, EC2)}),
        (FIXED, DB, "deletion_protection = true", "deletion_protection = false", {(RDS, DB)}),
        (RISKY, SG, '["0.0.0.0/0"]', '["10.0.0.0/8"]', {(TAG, SG), (TAG, EC2), (TAG, DB), (RDS, DB)}),
        (RISKY, DB, "deletion_protection = false", "deletion_protection = true",
         {(NET, SG), (TAG, SG), (TAG, EC2), (TAG, DB)}),
    ],
    ids=["fixed-open-ssh", "fixed-blank-owner", "fixed-rds-unprotected",
         "risky-private-ssh", "risky-rds-protected"],
)
def test_changing_one_control_changes_only_its_finding(tmp_path, source, resource, old, new, expected):
    text = (source / "main.tf").read_text(encoding="utf-8")
    (tmp_path / "main.tf").write_text(_replace_in_resource(text, resource, old, new), encoding="utf-8")
    parsed, custom = custom_scan(tmp_path)
    assert_no_required_gaps(parsed.coverage)
    assert_no_required_gaps(custom.coverage)
    assert rule_hits(custom.findings) == expected


def test_pipeline_does_not_modify_fixtures(pipeline):
    assert pipeline["risky"]["unchanged"] and pipeline["fixed"]["unchanged"]


@pytest.mark.parametrize("name", ["risky", "fixed"])
def test_checkov_completes_with_full_coverage(pipeline, name):
    raw = pipeline[name]["raw"]
    assert raw.status == "complete"
    assert raw.version == "3.3.8"
    assert raw.return_code in (0, 1)
    assert raw.parsing_errors == []
    assert raw.coverage.evaluated_files == ["main.tf"]
    assert_no_required_gaps(raw.coverage)
    assert raw.coverage.optional_gaps == []
    for check in raw.failed_checks:
        assert check["file_path"] == "main.tf"


def test_checkov_mapped_checks_follow_the_fixture_controls(pipeline):
    risky_ids = {c["check_id"] for c in pipeline["risky"]["raw"].failed_checks}
    fixed_ids = {c["check_id"] for c in pipeline["fixed"]["raw"].failed_checks}
    assert {"CKV_AWS_24", "CKV_AWS_293"} <= risky_ids
    assert not {"CKV_AWS_24", "CKV_AWS_293"} & fixed_ids
    mapped = {f.source.rule_id: f for f in pipeline["risky"]["findings"] if f.source.tool == "checkov"}
    for rule_id, category, template in (("CKV_AWS_24", "security", "open_ssh"),
                                        ("CKV_AWS_293", "reliability", "rds_deletion_protection")):
        finding = mapped[rule_id]
        assert finding.source.scanner_severity == "unknown"
        assert finding.source.severity_origin == "rule_map"
        assert (finding.priority, finding.category, finding.policy_mode) == ("high", category, "block")
        assert finding.recommendation.template_id == template


def test_risky_pipeline_is_high_risk(pipeline):
    result = pipeline["risky"]
    assert_no_required_gaps(result["coverage"])
    summary = result["summary"]
    assert summary.status == "HIGH RISK"
    assert risk.exit_code(summary.status) == 1
    assert summary.top_priority == "high"
    assert rule_hits(result["findings"]) == {(NET, SG), (RDS, DB)} | {(TAG, a) for a in TAGGABLE}
    assert {f.location.path for f in result["findings"]} == {"main.tf"}


def test_fixed_pipeline_is_pass_or_review_without_blocking_findings(pipeline):
    result = pipeline["fixed"]
    assert_no_required_gaps(result["coverage"])
    summary = result["summary"]
    assert summary.status in ("PASS", "REVIEW")
    assert risk.exit_code(summary.status) == 0
    assert rule_hits(result["findings"]) == set()
    assert not [f for f in result["findings"] if f.policy_mode == "block"]
    assert summary.counts["high"] == summary.counts["critical"] == 0
    assert {f.location.path for f in result["findings"]} <= {"main.tf"}
