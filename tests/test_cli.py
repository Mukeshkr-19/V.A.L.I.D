"""End-to-end tests that run the real CLI in a subprocess."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from valid.models import CustomScanResult, Explanation, Finding, RawScanResult, RiskSummary, ValidConfig
from valid.scanners import literal_hcl
from valid import templates

ROOT = Path(__file__).resolve().parents[1]
RISKY = ROOT / "fixtures" / "risky"
FIXED = ROOT / "fixtures" / "fixed"
MARKER = "<!-- valid-report -->"
ARTIFACTS = {"raw_checkov.json", "raw_custom.json", "findings.json", "summary.json", "comment.md", "ai.json"}
CUSTOM_RULES = {"DG-AWS-NET-001", "DG-AWS-TAG-001", "DG-AWS-RDS-001"}
VENV_PATH = os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"])
SYSTEM_PATH = os.pathsep.join(["/usr/bin", "/bin"])
FINDINGS = TypeAdapter(list[Finding])
AI_EXPLANATIONS = TypeAdapter(list[Explanation])
AI_ENV_KEYS = ("VALID_AI_PROVIDER", "VALID_AI_BASE_URL", "VALID_AI_MODEL",
               "VALID_AI_API_KEY", "NEBIUS_API_KEY", "OPENAI_API_KEY")


def scrub_ai_env(monkeypatch) -> None:
    for key in AI_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def environment(path: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
    env.update(PATH=path, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    return env


def run_cli(*args, path: str = VENV_PATH, inject: str | None = None, timeout: int = 180):
    """Run ``python -m valid``; ``inject`` patches one module attribute first to simulate a failure."""
    if inject is None:
        command = [sys.executable, "-P", "-m", "valid", *map(str, args)]
    else:
        script = inject + "\nfrom valid.cli import main\nraise SystemExit(main(sys.argv[1:]))\n"
        command = [sys.executable, "-P", "-c", "import sys\n" + script, *map(str, args)]
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=environment(path), timeout=timeout)


def scan(source: Path, output: Path, **kwargs):
    return run_cli("scan", "--path", source, "--output", output, **kwargs)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(root.rglob("*")):
        digest.update(item.relative_to(root).as_posix().encode())
        if item.is_file():
            digest.update(item.read_bytes())
    return digest.hexdigest()


def load_artifacts(output: Path) -> dict:
    assert {p.name for p in output.iterdir()} == ARTIFACTS
    comment = (output / "comment.md").read_text(encoding="utf-8")
    assert comment.splitlines()[0] == MARKER
    result = {
        "raw_checkov": RawScanResult.model_validate_json((output / "raw_checkov.json").read_text(encoding="utf-8")),
        "raw_custom": CustomScanResult.model_validate_json((output / "raw_custom.json").read_text(encoding="utf-8")),
        "findings": FINDINGS.validate_json((output / "findings.json").read_text(encoding="utf-8")),
        "ai": AI_EXPLANATIONS.validate_json((output / "ai.json").read_text(encoding="utf-8")),
        "summary": RiskSummary.model_validate_json((output / "summary.json").read_text(encoding="utf-8")),
        "comment": comment,
    }
    by_id = {finding.finding_id: finding for finding in result["findings"]}
    assert len(by_id) == len(result["findings"])
    seen = set()
    for explanation in result["ai"]:
        assert explanation.finding_id in by_id and explanation.finding_id not in seen
        seen.add(explanation.finding_id)
        finding = by_id[explanation.finding_id]
        assert sorted(explanation.evidence_ids) == sorted(item.evidence_id for item in finding.evidence)
        assert explanation.evidence_strength == finding.evidence_strength
    assert seen == set(by_id) or (not seen and result["summary"].status == "INCOMPLETE")
    return result


def assert_incomplete(result, output: Path) -> dict:
    assert result.returncode == 1, result.stderr
    artifacts = load_artifacts(output)
    summary = artifacts["summary"]
    assert summary.status == "INCOMPLETE"
    assert summary.coverage.required_failed_stages or summary.coverage.required_gaps
    assert artifacts["comment"].splitlines()[1] == "## V.A.L.I.D. Review - INCOMPLETE"
    return artifacts


def fake_checkov(directory: Path, body: str) -> str:
    directory.mkdir()
    script = directory / "checkov"
    script.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    script.chmod(0o755)
    return os.pathsep.join([str(directory), SYSTEM_PATH])


def rule_ids(findings) -> set[str]:
    return {finding.source.rule_id for finding in findings}


# --------------------------------------------------------------------------- live fixtures


def test_risky_fixture_is_high_risk_with_valid_artifacts(tmp_path):
    before = tree_digest(RISKY)
    result = scan(RISKY, tmp_path / "out")
    assert result.returncode == 1, result.stderr
    artifacts = load_artifacts(tmp_path / "out")
    summary, findings = artifacts["summary"], artifacts["findings"]
    assert summary.status == "HIGH RISK"
    assert summary.coverage.required_failed_stages == [] and summary.coverage.required_gaps == []
    assert CUSTOM_RULES | {"CKV_AWS_24", "CKV_AWS_293"} <= rule_ids(findings)
    assert artifacts["raw_checkov"].status == "complete"
    assert artifacts["raw_custom"].coverage.evaluated_files == ["main.tf"]
    assert CUSTOM_RULES == rule_ids(artifacts["raw_custom"].findings)
    for finding in findings:
        assert finding.change_action == "unknown"
        assert finding.location.path == "main.tf"
    mapped = {f.source.rule_id: f for f in findings if f.source.tool == "checkov"}
    for rule_id in ("CKV_AWS_24", "CKV_AWS_293"):
        assert mapped[rule_id].source.scanner_severity == "unknown"
        assert mapped[rule_id].source.severity_origin == "rule_map"
        assert (mapped[rule_id].priority, mapped[rule_id].policy_mode) == ("high", "block")
    assert "## V.A.L.I.D. Review - HIGH RISK" in artifacts["comment"]
    assert "DG&#45;AWS&#45;NET&#45;001" in artifacts["comment"]
    assert tree_digest(RISKY) == before


def test_fixed_fixture_passes_or_reviews_without_required_gaps(tmp_path):
    before = tree_digest(FIXED)
    result = scan(FIXED, tmp_path / "out")
    assert result.returncode == 0, result.stderr
    artifacts = load_artifacts(tmp_path / "out")
    summary = artifacts["summary"]
    assert summary.status in ("PASS", "REVIEW")
    assert summary.coverage.required_failed_stages == [] and summary.coverage.required_gaps == []
    assert not CUSTOM_RULES & rule_ids(artifacts["findings"])
    assert not [f for f in artifacts["findings"] if f.policy_mode == "block"]
    assert tree_digest(FIXED) == before


def test_repeat_scans_are_stable(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    assert scan(RISKY, first).returncode == 1
    assert scan(RISKY, second).returncode == 1
    for name in sorted(ARTIFACTS):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name
    findings = FINDINGS.validate_json((first / "findings.json").read_text(encoding="utf-8"))
    assert all(f.finding_id.startswith("f_") and all(e.evidence_id.startswith("e_") for e in f.evidence) for f in findings)


def test_no_key_ai_matches_deterministic_templates(tmp_path, monkeypatch):
    scrub_ai_env(monkeypatch)
    result = scan(RISKY, tmp_path / "out")
    assert result.returncode == 1, result.stderr
    artifacts = load_artifacts(tmp_path / "out")
    expected = [item.model_dump(mode="json") for item in templates.explain(artifacts["findings"])]
    assert [item.model_dump(mode="json") for item in artifacts["ai"]] == expected


def _echo_ai(calls: Path) -> str:
    return (
        "import json as _json, os as _os\n"
        "import valid.explain as _ai\n"
        "_original_bounded_request = _ai._bounded_request\n"
        "_selected_for_echo = []\n"
        "def _capture_selection(model, candidates):\n"
        "    selected, body = _original_bounded_request(model, candidates)\n"
        "    _selected_for_echo[:] = selected\n"
        "    return selected, body\n"
        "_ai._bounded_request = _capture_selection\n"
        "for _k, _v in {'VALID_AI_PROVIDER': 'openai_compatible', 'VALID_AI_BASE_URL': 'https://ai.example.test', 'VALID_AI_MODEL': 'test-model', 'VALID_AI_API_KEY': 'TEST-KEY-CANARY-1'}.items():\n"
        "    _os.environ[_k] = _v\n"
        "def _echo(url, headers, body, timeout):\n"
        f"    with open({str(calls)!r}, 'a') as _h:\n"
        "        _h.write('x')\n"
        "    assert url == 'https://ai.example.test/chat/completions'\n"
        "    assert headers['Authorization'] == 'Bearer TEST-KEY-CANARY-1'\n"
        "    payload = _json.loads(body.decode('utf-8'))\n"
        "    entries = _json.loads(payload['messages'][1]['content'])['findings']\n"
        "    assert all('options' not in e for e in entries)\n"
        "    items = [e.model_dump(exclude={'origin'}) for e in _ai.templates.explain(_selected_for_echo)]\n"
        "    return 200, _json.dumps({'choices': [{'message': {'content': _json.dumps(items)}}]}).encode('utf-8')\n"
        "_ai._default_transport = _echo\n"
    )


def _failing_ai(calls: Path) -> str:
    return (
        "import os as _os\n"
        "import valid.explain as _ai\n"
        "for _k, _v in {'VALID_AI_PROVIDER': 'openai_compatible', 'VALID_AI_BASE_URL': 'https://ai.example.test', 'VALID_AI_MODEL': 'test-model', 'VALID_AI_API_KEY': 'TEST-KEY-CANARY-2'}.items():\n"
        "    _os.environ[_k] = _v\n"
        "def _boom(url, headers, body, timeout):\n"
        f"    with open({str(calls)!r}, 'a') as _h:\n"
        "        _h.write('x')\n"
        "    raise _ai.TransportError('simulated transport failure')\n"
        "_ai._default_transport = _boom\n"
    )


def _tracing(trace: Path) -> str:
    """Record risk/explanation/report call order and the explanations each step saw."""
    return (
        "import json as _tjson\n"
        "import valid.explain as _tai, valid.report as _treport, valid.risk as _trisk\n"
        "def _tlog(event, items=None):\n"
        f"    with open({str(trace)!r}, 'a', encoding='utf-8') as _h:\n"
        "        _h.write(_tjson.dumps({'event': event, 'items': items}) + '\\n')\n"
        "_t_summarize, _t_explain, _t_render = _trisk.summarize, _tai.explain, _treport.render\n"
        "def _tsummarize(*a, **k):\n"
        "    _tlog('risk')\n"
        "    return _t_summarize(*a, **k)\n"
        "def _texplain(*a, **k):\n"
        "    result = _t_explain(*a, **k)\n"
        "    _tlog('explain', [i.model_dump(mode='json') for i in result])\n"
        "    return result\n"
        "def _trender(summary, findings, explanations):\n"
        "    _tlog('render', [i.model_dump(mode='json') for i in explanations])\n"
        "    return _t_render(summary, findings, explanations)\n"
        "_trisk.summarize, _tai.explain, _treport.render = _tsummarize, _texplain, _trender\n"
    )


def _read_trace(trace: Path) -> list[dict]:
    return [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("mode", ["no_key", "valid_ai", "failing_ai"])
def test_explanation_service_runs_after_risk_and_feeds_the_reporter(tmp_path, monkeypatch, mode):
    scrub_ai_env(monkeypatch)
    trace, calls = tmp_path / "trace", tmp_path / "calls"
    inject = _tracing(trace) + {"no_key": "", "valid_ai": _echo_ai(calls), "failing_ai": _failing_ai(calls)}[mode]
    output = tmp_path / "out"
    assert scan(RISKY, output, inject=inject).returncode == 1
    events = _read_trace(trace)
    assert [event["event"] for event in events] == ["risk", "explain", "render"]
    published = json.loads((output / "ai.json").read_text(encoding="utf-8"))
    assert events[1]["items"] == events[2]["items"] == published
    load_artifacts(output)
    assert (calls.read_text() if calls.exists() else "") == {"no_key": "", "valid_ai": "x", "failing_ai": "xx"}[mode]


_SENTINEL_SERVICE = (
    "import valid.explain as _sai\n"
    "from valid import templates as _stemplates\n"
    "def _sentinel(findings, **k):\n"
    "    return [item.model_copy(update={'title': 'Sentinel explanation service title'}) for item in _stemplates.explain(findings)]\n"
    "_sai.explain = _sentinel\n"
)


def test_reporter_and_ai_json_publish_the_service_result(tmp_path, monkeypatch):
    scrub_ai_env(monkeypatch)
    output = tmp_path / "out"
    assert scan(RISKY, output, inject=_SENTINEL_SERVICE).returncode == 1
    artifacts = load_artifacts(output)
    assert artifacts["ai"] and all(item.title == "Sentinel explanation service title" for item in artifacts["ai"])
    assert "Sentinel explanation service title" in artifacts["comment"]
    assert artifacts["summary"].status == "HIGH RISK"


def test_explanation_service_crash_uses_templates_without_changing_the_verdict(tmp_path, monkeypatch):
    scrub_ai_env(monkeypatch)
    plain, crashed = tmp_path / "plain", tmp_path / "crashed"
    assert scan(RISKY, plain).returncode == 1
    assert scan(RISKY, crashed, inject=_boom("valid.explain.explain")).returncode == 1
    for name in sorted(ARTIFACTS):
        assert (plain / name).read_bytes() == (crashed / name).read_bytes(), name


@pytest.mark.parametrize("fixture, expected_exit", [(RISKY, 1), (FIXED, 0)], ids=["risky", "fixed"])
def test_ai_modes_preserve_deterministic_outcomes(tmp_path, monkeypatch, fixture, expected_exit):
    scrub_ai_env(monkeypatch)
    plain = tmp_path / "plain"
    assert scan(fixture, plain).returncode == expected_exit
    echoed = tmp_path / "echoed"
    assert scan(fixture, echoed, inject=_echo_ai(tmp_path / "echo-calls")).returncode == expected_exit
    failed = tmp_path / "failed"
    assert scan(fixture, failed, inject=_failing_ai(tmp_path / "fail-calls")).returncode == expected_exit
    for name in ("findings.json", "summary.json", "ai.json", "comment.md"):
        assert (plain / name).read_bytes() == (echoed / name).read_bytes() == (failed / name).read_bytes(), name
    if json.loads((plain / "findings.json").read_text(encoding="utf-8")):
        assert (tmp_path / "echo-calls").read_text() == "x"
        assert (tmp_path / "fail-calls").read_text() == "xx"
    published = b"".join((echoed / name).read_bytes() for name in sorted(ARTIFACTS))
    published += b"".join((failed / name).read_bytes() for name in sorted(ARTIFACTS))
    assert b"TEST-KEY-CANARY-1" not in published and b"TEST-KEY-CANARY-2" not in published


# --------------------------------------------------------------------------- input failures


def test_empty_source_is_incomplete(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    artifacts = assert_incomplete(scan(source, tmp_path / "out"), tmp_path / "out")
    assert any("no Terraform files" in gap for gap in artifacts["summary"].coverage.required_gaps)


def test_missing_source_is_incomplete(tmp_path):
    artifacts = assert_incomplete(scan(tmp_path / "absent", tmp_path / "out"), tmp_path / "out")
    stages = artifacts["summary"].coverage.required_failed_stages
    assert {"input_validation", "literal_hcl_parse", "checkov_execution"} <= set(stages)


def test_malformed_terraform_is_incomplete(tmp_path):
    source = tmp_path / "bad"
    source.mkdir()
    (source / "main.tf").write_text('resource "aws_instance" "x" {\n  ami = \n', encoding="utf-8")
    assert_incomplete(scan(source, tmp_path / "out"), tmp_path / "out")


def test_parser_only_required_gap_survives_combined_coverage(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(FIXED, source)
    (source / "modules.tf").write_text('module "network" {\n  source = "./modules/network"\n}\n', encoding="utf-8")
    config = ValidConfig()
    parsed = literal_hcl.parse(source, config)
    parser_gaps = [gap for gap in parsed.coverage.required_gaps if "module.network" in gap]
    assert parser_gaps
    assert literal_hcl.scan(parsed.parsed, config).coverage.required_gaps == []
    artifacts = assert_incomplete(scan(source, tmp_path / "out"), tmp_path / "out")
    assert set(parser_gaps) <= set(artifacts["summary"].coverage.required_gaps)
    assert set(parser_gaps) <= set(artifacts["raw_custom"].coverage.required_gaps)


# --------------------------------------------------------------------------- scanner failures


def test_missing_checkov_is_incomplete_not_custom_only(tmp_path):
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", path=SYSTEM_PATH), tmp_path / "out")
    assert artifacts["raw_checkov"].status == "error"
    assert "checkov_execution" in artifacts["summary"].coverage.required_failed_stages


def test_checkov_timeout_is_incomplete(tmp_path):
    path = fake_checkov(tmp_path / "bin", "exec sleep 30")
    inject = "import valid.scanners.checkov as c\nc.scan_timeout_seconds = lambda config: 1"
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", path=path, inject=inject), tmp_path / "out")
    assert artifacts["raw_checkov"].status == "error"
    assert any("timed out" in note for note in artifacts["raw_checkov"].diagnostics)


@pytest.mark.parametrize("body", ["echo 'not json'; exit 1", "echo '{\"results\": \"bad\"}'; exit 0", "echo '[]'; exit 2"])
def test_malformed_checkov_output_is_incomplete(tmp_path, body):
    path = fake_checkov(tmp_path / "bin", body)
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", path=path), tmp_path / "out")
    assert artifacts["summary"].status != "PASS"


def test_untrusted_scanner_config_in_input_is_incomplete(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(RISKY, source)
    (source / ".checkov.yaml").write_text("skip-check:\n  - CKV_AWS_24\n", encoding="utf-8")
    artifacts = assert_incomplete(scan(source, tmp_path / "out"), tmp_path / "out")
    assert "checkov_local_config" in artifacts["summary"].coverage.required_gaps


# --------------------------------------------------------------------------- stage failures


def _boom(target: str) -> str:
    module, attribute = target.rsplit(".", 1)
    return (
        f"import {module} as target_module\n"
        "def failing(*args, **kwargs):\n    raise RuntimeError('simulated failure')\n"
        f"target_module.{attribute} = failing"
    )


def test_normalization_failure_is_incomplete_and_keeps_validated_findings(tmp_path):
    artifacts = assert_incomplete(scan(RISKY, tmp_path / "out", inject=_boom("valid.normalize.normalize")), tmp_path / "out")
    assert "normalization" in artifacts["summary"].coverage.required_failed_stages
    assert rule_ids(artifacts["findings"]) == CUSTOM_RULES
    assert "simulated failure" not in (tmp_path / "out" / "summary.json").read_text(encoding="utf-8")


def test_parser_exception_is_incomplete(tmp_path):
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", inject=_boom("valid.scanners.literal_hcl.parse")), tmp_path / "out")
    assert "literal_hcl_parse" in artifacts["summary"].coverage.required_failed_stages
    assert "literal_hcl_parse" in artifacts["raw_custom"].coverage.required_failed_stages


def test_custom_rule_exception_is_incomplete(tmp_path):
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", inject=_boom("valid.scanners.literal_hcl.scan")), tmp_path / "out")
    assert "custom_rules" in artifacts["summary"].coverage.required_failed_stages


@pytest.mark.parametrize("target", ["valid.templates.explain", "valid.report.render"])
def test_reporting_failure_produces_consistent_incomplete_fallback(tmp_path, target):
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", inject=_boom(target)), tmp_path / "out")
    assert "report_generation" in artifacts["summary"].coverage.required_failed_stages
    assert "Deterministic scan verdict before the reporting failure: REVIEW." in artifacts["comment"]


def _counting_risk(counter: Path, succeed_first: int) -> str:
    """Patch risk.summarize to succeed ``succeed_first`` times, then raise on every later call."""
    return (
        "import valid.risk as risk_module\n"
        "real_summarize = risk_module.summarize\n"
        "def counting(*args, **kwargs):\n"
        f"    with open({str(counter)!r}, 'a') as handle:\n"
        "        handle.write('x')\n"
        f"    with open({str(counter)!r}) as handle:\n"
        "        calls = len(handle.read())\n"
        f"    if calls <= {succeed_first}:\n"
        "        return real_summarize(*args, **kwargs)\n"
        "    raise RuntimeError('simulated failure')\n"
        "risk_module.summarize = counting\n"
    )


def assert_emergency_summary(artifacts: dict) -> None:
    summary, findings = artifacts["summary"], artifacts["findings"]
    assert "risk_summary" in summary.coverage.required_failed_stages
    assert "Required stage failed: risk_summary" in summary.reasons
    assert any(reason.startswith("Risk score unavailable") for reason in summary.reasons)
    assert summary.score == 0 and summary.top_priority is None
    for severity, count in summary.counts.items():
        assert count == sum(1 for f in findings if f.priority == severity)
    for category, count in summary.category_counts.items():
        assert count == sum(1 for f in findings if f.category == category)
    assert "Risk score unavailable" in artifacts["comment"]
    assert "simulated failure" not in artifacts["comment"] + json.dumps(summary.model_dump(mode="json"))


def test_persistent_risk_failure_publishes_emergency_incomplete_summary(tmp_path):
    counter = tmp_path / "calls"
    result = scan(RISKY, tmp_path / "out", inject=_counting_risk(counter, succeed_first=0))
    artifacts = assert_incomplete(result, tmp_path / "out")
    assert counter.read_text() == "x"
    assert CUSTOM_RULES | {"CKV_AWS_24", "CKV_AWS_293"} <= rule_ids(artifacts["findings"])
    assert_emergency_summary(artifacts)
    assert artifacts["summary"].counts["high"] >= 1


def test_report_recovery_survives_persistent_risk_failure(tmp_path):
    counter = tmp_path / "calls"
    inject = _counting_risk(counter, succeed_first=1) + _boom("valid.report.render")
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", inject=inject), tmp_path / "out")
    assert counter.read_text() == "xx"
    assert {"report_generation", "risk_summary"} <= set(artifacts["summary"].coverage.required_failed_stages)
    assert "Deterministic scan verdict before the reporting failure: REVIEW." in artifacts["comment"]
    assert_emergency_summary(artifacts)


def _failing_link(fail_on: str, foreign: bool = False) -> str:
    """Patch os.link to fail persistently for one artifact, optionally after a foreign file claims its name."""
    return (
        "import os\n"
        "real_link = os.link\n"
        "def link(source, target, *args, **kwargs):\n"
        f"    if os.path.basename(target) == {fail_on!r}:\n"
        + (
            "        with open(target, 'x') as handle:\n            handle.write('foreign')\n"
            if foreign
            else "        raise OSError(28, 'No space left on device')\n"
        )
        + "    return real_link(source, target, *args, **kwargs)\n"
        "os.link = link\n"
    )


def test_late_artifact_write_failure_rolls_back_the_publication_set(tmp_path):
    output = tmp_path / "out"
    result = scan(FIXED, output, inject=_failing_link("summary.json"))
    assert result.returncode == 1
    assert result.stderr.startswith(MARKER) and "INCOMPLETE" in result.stderr
    assert "could not be published" in result.stderr
    assert list(output.iterdir()) == []


def test_publication_rollback_never_removes_a_file_it_did_not_create(tmp_path):
    output = tmp_path / "out"
    before = tree_digest(FIXED)
    result = scan(FIXED, output, inject=_failing_link("comment.md", foreign=True))
    assert result.returncode == 1
    assert result.stderr.startswith(MARKER) and "could not be published" in result.stderr
    assert [p.name for p in output.iterdir()] == ["comment.md"]
    assert (output / "comment.md").read_text(encoding="utf-8") == "foreign"
    assert tree_digest(FIXED) == before


def test_missing_policy_file_is_incomplete(tmp_path):
    inject = f"import valid.cli\nvalid.cli.POLICY_FILE = valid.cli.Path({str(tmp_path / 'missing.yaml')!r})"
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", inject=inject), tmp_path / "out")
    assert "policy_load" in artifacts["summary"].coverage.required_failed_stages


def test_policy_without_required_mappings_is_incomplete(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "checkov_severity_map:\n  CKV_AWS_24:\n    priority: high\n    category: security\n"
        "    policy_mode: block\n    template_id: open_ssh\n",
        encoding="utf-8",
    )
    inject = f"import valid.cli\nvalid.cli.POLICY_FILE = valid.cli.Path({str(policy)!r})"
    artifacts = assert_incomplete(scan(FIXED, tmp_path / "out", inject=inject), tmp_path / "out")
    assert "policy_load" in artifacts["summary"].coverage.required_failed_stages


def test_missing_python_dependency_reports_on_stderr(tmp_path):
    output = tmp_path / "out"
    result = scan(FIXED, output, inject="sys.modules['yaml'] = None")
    assert result.returncode == 1
    assert result.stderr.startswith(MARKER) and "INCOMPLETE" in result.stderr
    assert list(output.iterdir()) == []


def test_unwritable_output_reports_on_stderr(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    output.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        result = scan(FIXED, output)
    finally:
        output.chmod(stat.S_IRWXU)
    assert result.returncode == 1
    assert result.stderr.startswith(MARKER) and "INCOMPLETE" in result.stderr
    assert "could not be published" in result.stderr
    assert list(output.iterdir()) == []


def test_uncreatable_output_reports_on_stderr(tmp_path):
    parent = tmp_path / "locked"
    parent.mkdir()
    parent.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        result = scan(FIXED, parent / "out")
    finally:
        parent.chmod(stat.S_IRWXU)
    assert result.returncode == 1
    assert result.stderr.startswith(MARKER) and "INCOMPLETE" in result.stderr
    assert not (parent / "out").exists()


# --------------------------------------------------------------------------- output safety and invocation


def test_nonempty_output_is_refused_without_overwrite(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "summary.json").write_text("keep", encoding="utf-8")
    result = scan(FIXED, output)
    assert result.returncode == 1 and "not empty" in result.stderr
    assert [p.name for p in output.iterdir()] == ["summary.json"]
    assert (output / "summary.json").read_text(encoding="utf-8") == "keep"


def test_output_file_and_symlink_are_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    result = scan(FIXED, link)
    assert result.returncode == 1 and "symbolic link" in result.stderr
    assert list(target.iterdir()) == []
    regular = tmp_path / "file"
    regular.write_text("keep", encoding="utf-8")
    result = scan(FIXED, regular)
    assert result.returncode == 1 and regular.read_text(encoding="utf-8") == "keep"


def test_output_inside_scanned_input_is_refused(tmp_path):
    source = tmp_path / "src"
    shutil.copytree(FIXED, source)
    before = tree_digest(source)
    result = scan(source, source / "out")
    assert result.returncode == 1 and "inside the scanned input" in result.stderr
    assert tree_digest(source) == before


def test_existing_empty_output_directory_is_used(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    assert scan(FIXED, output).returncode == 0
    load_artifacts(output)


@pytest.mark.parametrize("args", [["--help"], ["scan", "--help"]])
def test_help_exits_zero(args):
    result = run_cli(*args)
    assert result.returncode == 0
    assert "usage:" in result.stdout


@pytest.mark.parametrize(
    "args",
    [[], ["scan"], ["scan", "--path", "fixtures/fixed"], ["deploy"], ["scan", "--path", "a", "--output", "b", "--demo"]],
)
def test_malformed_invocation_exits_one(tmp_path, args):
    result = run_cli(*args)
    assert result.returncode == 1
    assert "usage:" in result.stderr
    assert not (ROOT / "b").exists()
