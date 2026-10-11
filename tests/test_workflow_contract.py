"""Workflow contracts: static structure plus execution of the actual wrapper, gate, CI and comment code."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import TypeAdapter

from scripts import ci_scan
from valid import models
from valid.models import CustomScanResult, Finding, RawScanResult, RiskSummary

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "ci_scan.py"
VALID_YML = ROOT / ".github" / "workflows" / "valid.yml"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
FIXED = ROOT / "fixtures" / "fixed"
RISKY = ROOT / "fixtures" / "risky"
MARKER = "<!-- valid-report -->"
SHA = "a" * 40
OTHER_SHA = "b" * 40
FINDINGS = TypeAdapter(list[Finding])
BASH = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c"]

# Official release tags resolved to commits through the GitHub tag API; each runs on node24.
EXPECTED_PINS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2"),
    "actions/download-artifact": ("9000827ccba6bdab643e8b6fd33ac0654aef8333", "v8.0.2"),
    "actions/github-script": ("3a2844b7e9c422d3c10d287c895573f7108da1b3", "v9.0.0"),
}


# --------------------------------------------------------------------------- helpers


def load_workflow(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def job_steps(path: Path, job: str) -> list[dict[str, Any]]:
    return load_workflow(path)["jobs"][job]["steps"]


def step(path: Path, job: str, name_prefix: str) -> dict[str, Any]:
    matches = [s for s in job_steps(path, job) if s.get("name", "").startswith(name_prefix)]
    assert len(matches) == 1, name_prefix
    return matches[0]


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(root.rglob("*")):
        digest.update(item.relative_to(root).as_posix().encode())
        if item.is_file() and not item.is_symlink():
            digest.update(item.read_bytes())
    return digest.hexdigest()


def executable(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def run_wrapper(*args: Any, isolated: bool = False, extra_env: dict[str, str] | None = None, timeout: int = 300):
    """Run the wrapper as CI does; ``isolated`` hides the analyzer package from the wrapper itself."""
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1", **(extra_env or {}))
    command = [sys.executable, "-I" if isolated else "-P", str(WRAPPER), *map(str, args)]
    return subprocess.run(command, capture_output=True, text=True, env=env, timeout=timeout)


def scan(output: Path, python_bin: Path | str, source: Path = FIXED, **kwargs: Any):
    return run_wrapper("scan", "--scan-path", source, "--output", output, "--head-sha", SHA,
                       "--python-bin", python_bin, **kwargs)


def meta(output: Path) -> dict[str, Any]:
    return json.loads((output / "scan_meta.json").read_text(encoding="utf-8"))


def load_artifacts(output: Path) -> dict[str, Any]:
    artifacts = output / "artifacts"
    assert sorted(p.name for p in artifacts.iterdir()) == sorted(ci_scan.ARTIFACTS)
    result = {
        "raw_checkov": RawScanResult.model_validate_json((artifacts / "raw_checkov.json").read_text(encoding="utf-8")),
        "raw_custom": CustomScanResult.model_validate_json((artifacts / "raw_custom.json").read_text(encoding="utf-8")),
        "findings": FINDINGS.validate_json((artifacts / "findings.json").read_text(encoding="utf-8")),
        "ai": TypeAdapter(list[models.Explanation]).validate_json((artifacts / "ai.json").read_text(encoding="utf-8")),
        "summary": RiskSummary.model_validate_json((artifacts / "summary.json").read_text(encoding="utf-8")),
        "comment": (artifacts / "comment.md").read_text(encoding="utf-8"),
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
    assert seen == set(by_id)
    return result


def assert_recovery(output: Path, stage: str) -> dict[str, Any]:
    record = meta(output)
    assert record["completed"] is True and record["wrapper_exit"] == 1
    assert record["validated"] is False and record["status"] == "INCOMPLETE" and record["stage"] == stage
    artifacts = load_artifacts(output)
    summary = artifacts["summary"]
    assert summary.status == "INCOMPLETE" and summary.score == 0 and summary.top_priority is None
    assert stage in summary.coverage.required_failed_stages
    assert f"Required stage failed: {stage}" in summary.reasons and ci_scan.SCORE_UNAVAILABLE in summary.reasons
    assert summary.counts == {s: sum(f.priority == s for f in artifacts["findings"]) for s in models.SEVERITIES}
    lines = artifacts["comment"].split("\n")
    assert lines[0] == MARKER and lines[1] == "## V.A.L.I.D. Review - INCOMPLETE"
    return artifacts


def fake_python(directory: Path, body: str) -> Path:
    """An interpreter double: receives the wrapper's ``-I -m valid scan ...`` arguments and runs ``body``."""
    return executable(
        directory / "fake-bin" / "python",
        f"#!{sys.executable}\nimport json, os, shutil, subprocess, sys, time\nfrom pathlib import Path\n"
        "args = sys.argv[1:]\nout = Path(args[args.index('--output') + 1])\n" + body,
    )


def from_template(directory: Path, template: Path, mutate: str = "", exit_code: int = 0) -> Path:
    return fake_python(directory, f"shutil.copytree({str(template)!r}, out)\n{mutate}\nsys.exit({exit_code})\n")


# --------------------------------------------------------------------------- real analyzer runs


@pytest.fixture(scope="session")
def source_python(tmp_path_factory) -> Path:
    """Interpreter shim that runs the real analyzer from this source tree (the wrapper always passes -I)."""
    directory = tmp_path_factory.mktemp("source-python")
    return executable(
        directory / "python",
        '#!/bin/sh\n[ "$1" = "-I" ] && shift\n'
        f"PYTHONPATH={shlex.quote(str(ROOT))} PYTHONDONTWRITEBYTECODE=1 exec {shlex.quote(sys.executable)} -P \"$@\"\n",
    )


@pytest.fixture(scope="session")
def real_runs(tmp_path_factory, source_python) -> dict[str, Any]:
    base = tmp_path_factory.mktemp("real-runs")
    runs = {}
    for name, source in (("fixed", FIXED), ("risky", RISKY)):
        before = tree_digest(source)
        result = scan(base / name, source_python, source=source)
        assert tree_digest(source) == before
        runs[name] = (base / name, result)
    return runs


def test_real_fixed_scan_completes_validated(real_runs):
    output, result = real_runs["fixed"]
    assert result.returncode == 0, result.stderr
    record = meta(output)
    assert record["completed"] is True and record["validated"] is True and record["wrapper_exit"] == 0
    assert record["analyzer_exit"] == 0 and record["timeout"] is False and record["stage"] is None
    assert record["status"] in ("PASS", "REVIEW") and record["head_sha"] == SHA
    artifacts = load_artifacts(output)
    assert artifacts["summary"].status == record["status"]
    assert artifacts["comment"].split("\n")[:2] == [MARKER, "## V.A.L.I.D. Review - " + record["status"]]


def test_real_risky_scan_completes_high_risk(real_runs):
    output, result = real_runs["risky"]
    assert result.returncode == 1, result.stderr
    record = meta(output)
    assert record["completed"] is True and record["validated"] is True and record["wrapper_exit"] == 1
    assert record["analyzer_exit"] == 1 and record["status"] == "HIGH RISK"
    artifacts = load_artifacts(output)
    assert artifacts["summary"].status == "HIGH RISK"
    assert {"DG-AWS-NET-001", "CKV_AWS_24"} <= {f.source.rule_id for f in artifacts["findings"]}


# --------------------------------------------------------------------------- output safety


def test_nonempty_output_is_refused_and_preserved(tmp_path, source_python):
    output = tmp_path / "out"
    output.mkdir()
    (output / "keep.txt").write_text("owned by caller", encoding="utf-8")
    (output / "artifacts").mkdir()
    before = tree_digest(output)
    result = scan(output, source_python)
    assert result.returncode == 2 and result.stderr.startswith(MARKER)
    assert tree_digest(output) == before and not (output / "scan_meta.json").exists()


def test_symlink_output_is_refused(tmp_path, source_python):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    result = scan(link, source_python)
    assert result.returncode == 2 and "symbolic link" in result.stderr
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("relation", ["equal", "inside"])
def test_output_overlapping_input_is_refused(tmp_path, source_python, relation):
    source = tmp_path / "src"
    shutil.copytree(FIXED, source)
    before = tree_digest(source)
    output = source if relation == "equal" else source / "out"
    result = scan(output, source_python, source=source)
    assert result.returncode == 2
    assert tree_digest(source) == before


def test_invalid_head_sha_is_an_invocation_error(tmp_path, source_python):
    result = run_wrapper("scan", "--scan-path", FIXED, "--output", tmp_path / "out", "--head-sha", "main",
                         "--python-bin", source_python)
    assert result.returncode == 2 and not (tmp_path / "out").exists()


# --------------------------------------------------------------------------- launch, execution and timeout recovery


def test_launch_failure_publishes_strict_recovery(tmp_path):
    output = tmp_path / "out"
    result = scan(output, tmp_path / "absent-python")
    assert result.returncode == 1
    artifacts = assert_recovery(output, "analyzer_launch")
    assert meta(output)["analyzer_exit"] is None
    assert artifacts["raw_checkov"].status == "error" and artifacts["raw_checkov"].tool == "checkov"
    assert artifacts["raw_checkov"].version == "3.3.8"
    assert artifacts["findings"] == [] and artifacts["raw_custom"].findings == []
    assert "analyzer_launch" in artifacts["raw_custom"].coverage.required_failed_stages
    assert "not a clean result" in artifacts["comment"]


def test_pre_launch_sentinel_is_persisted_outside_the_artifact_directory(tmp_path):
    seen = tmp_path / "seen-meta.json"
    python = fake_python(tmp_path, f"shutil.copy(out.parent / 'scan_meta.json', {str(seen)!r})\n"
                                   "assert not out.exists()\nsys.exit(0)\n")
    output = tmp_path / "out"
    assert scan(output, python).returncode == 1
    pending = json.loads(seen.read_text(encoding="utf-8"))
    assert pending["wrapper_exit"] == 2 and pending["completed"] is False and pending["analyzer_exit"] is None
    assert pending["head_sha"] == SHA
    assert_recovery(output, "artifact_validation")


def test_analyzer_crash_does_not_disclose_output_or_environment(tmp_path):
    canary = "SYNTHETIC-DIAGNOSTIC-CANARY"
    seen_env = tmp_path / "seen-env.json"
    python = fake_python(tmp_path, f"print({canary!r}); print({canary!r}, file=sys.stderr)\n"
                                   f"Path({str(seen_env)!r}).write_text(json.dumps(sorted(os.environ)))\n"
                                   "raise SystemExit(134)\n")
    output = tmp_path / "out"
    result = scan(output, python, extra_env={"VALID_CANARY_TOKEN": canary, "PYTHONSTARTUP": canary})
    assert result.returncode == 1
    assert_recovery(output, "analyzer_execution")
    assert meta(output)["analyzer_exit"] == 134
    published = "".join(p.read_text(encoding="utf-8") for p in output.rglob("*") if p.is_file())
    assert canary not in published + result.stdout + result.stderr
    assert str(tmp_path) not in published
    names = json.loads(seen_env.read_text(encoding="utf-8"))
    assert "VALID_CANARY_TOKEN" not in names and "PYTHONSTARTUP" not in names


def _wait_until_gone(pid: int, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def test_timeout_kills_and_reaps_the_process_group(tmp_path):
    child_pid = tmp_path / "child.pid"
    python = fake_python(tmp_path, "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                                   f"Path({str(child_pid)!r}).write_text(str(child.pid))\ntime.sleep(120)\n")
    output = tmp_path / "out"
    started = time.monotonic()
    result = run_wrapper("scan", "--scan-path", FIXED, "--output", output, "--head-sha", SHA,
                         "--python-bin", python, "--timeout", 2)
    assert result.returncode == 1 and time.monotonic() - started < 60
    assert_recovery(output, "analyzer_timeout")
    record = meta(output)
    assert record["timeout"] is True and record["analyzer_exit"] is None
    assert _wait_until_gone(int(child_pid.read_text(encoding="utf-8")))


def test_background_descendants_are_terminated_after_normal_exit(tmp_path, real_runs):
    child_pid = tmp_path / "child.pid"
    template = real_runs["fixed"][0] / "artifacts"
    python = from_template(tmp_path, template, "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                                               f"Path({str(child_pid)!r}).write_text(str(child.pid))")
    output = tmp_path / "out"
    assert scan(output, python).returncode == 0
    record = meta(output)
    assert record["validated"] is True
    assert any("background processes" in note for note in record["diagnostics"])
    assert _wait_until_gone(int(child_pid.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- artifact validation


MUTATIONS = {
    "missing_artifact": ("(out / 'findings.json').unlink()", 0),
    "malformed_summary_json": ("(out / 'summary.json').write_text('{')", 0),
    "raw_custom_schema": ("(out / 'raw_custom.json').write_text('[]\\n')", 0),
    "unknown_status": ("p = out / 'summary.json'; s = json.loads(p.read_text()); s['status'] = 'UNKNOWN_STATUS'; "
                       "p.write_text(json.dumps(s))", 0),
    "missing_marker": ("p = out / 'comment.md'; p.write_text('# report\\n' + p.read_text().split('\\n', 1)[1])", 0),
    "heading_mismatch": ("p = out / 'comment.md'; p.write_text(p.read_text().replace('Review - ', 'Review - PASS ', 1))", 0),
    "counts_mismatch": ("p = out / 'summary.json'; s = json.loads(p.read_text()); s['counts']['critical'] += 1; "
                        "p.write_text(json.dumps(s))", 0),
    "contradictory_exit": ("", 1),
    "extra_entry": ("(out / 'notes.txt').write_text('x')", 0),
    "missing_ai": ("(out / 'ai.json').unlink()", 0),
    "malformed_ai_json": ("(out / 'ai.json').write_text('{')", 0),
    "ai_coverage": ("(out / 'ai.json').write_text('[]\\n')", 0),
    "ai_extra_id": ("p = out / 'ai.json'; a = json.loads(p.read_text()); "
                    "a.append({'finding_id': 'f_ffffffffffffffff', 'evidence_ids': [], 'title': 'x', "
                    "'why_it_matters': 'x', 'recommended_action': 'x', 'evidence_strength': 'deterministic'}); "
                    "p.write_text(json.dumps(a))", 0),
}


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_invalid_analyzer_output_becomes_incomplete(tmp_path, real_runs, case):
    mutate, exit_code = MUTATIONS[case]
    template = real_runs["fixed"][0] / "artifacts"
    output = tmp_path / "out"
    result = scan(output, from_template(tmp_path, template, mutate, exit_code))
    assert result.returncode == 1
    assert_recovery(output, "artifact_validation")
    assert meta(output)["analyzer_exit"] == exit_code
    assert (output / "discarded-1").is_dir()


def test_high_risk_artifacts_with_exit_zero_are_rejected(tmp_path, real_runs):
    output = tmp_path / "out"
    assert scan(output, from_template(tmp_path, real_runs["risky"][0] / "artifacts", "", 0)).returncode == 1
    assert_recovery(output, "artifact_validation")


def test_two_file_pass_output_never_completes_cleanly(tmp_path):
    python = fake_python(tmp_path, "out.mkdir()\n(out / 'summary.json').write_text(json.dumps({'status': 'PASS'}))\n"
                                   "(out / 'comment.md').write_text('not a marker report')\nsys.exit(0)\n")
    output = tmp_path / "out"
    result = scan(output, python)
    assert result.returncode == 1
    assert_recovery(output, "artifact_validation")


def test_recovery_preserves_individually_validated_evidence(tmp_path, real_runs):
    template = real_runs["risky"][0] / "artifacts"
    output = tmp_path / "out"
    assert scan(output, from_template(tmp_path, template, "(out / 'summary.json').write_text('{')", 1)).returncode == 1
    artifacts = assert_recovery(output, "artifact_validation")
    original = FINDINGS.validate_json((template / "findings.json").read_text(encoding="utf-8"))
    assert artifacts["findings"] == original and original
    assert (output / "artifacts" / "raw_checkov.json").read_bytes() == (template / "raw_checkov.json").read_bytes()
    assert artifacts["summary"].counts["high"] == sum(f.priority == "high" for f in original)


def test_recovery_publishes_template_ai_for_preserved_findings(tmp_path, real_runs):
    template = real_runs["risky"][0] / "artifacts"
    output = tmp_path / "out"
    assert scan(output, from_template(tmp_path, template, "(out / 'summary.json').write_text('{')", 1)).returncode == 1
    artifacts = assert_recovery(output, "artifact_validation")
    assert artifacts["findings"]
    by_id = {finding.finding_id: finding for finding in artifacts["findings"]}
    assert {item.finding_id for item in artifacts["ai"]} == set(by_id)
    for item in artifacts["ai"]:
        finding = by_id[item.finding_id]
        assert sorted(item.evidence_ids) == sorted(evidence.evidence_id for evidence in finding.evidence)
        assert item.evidence_strength == finding.evidence_strength


def test_recovery_publishes_empty_ai_without_findings(tmp_path):
    output = tmp_path / "out"
    result = scan(output, tmp_path / "absent-python")
    assert result.returncode == 1
    artifacts = assert_recovery(output, "analyzer_launch")
    assert artifacts["findings"] == [] and artifacts["ai"] == []
    assert json.loads((output / "artifacts" / "ai.json").read_text(encoding="utf-8")) == []


def test_validation_fails_closed_when_contracts_cannot_import(tmp_path, real_runs):
    output = tmp_path / "out"
    python = from_template(tmp_path, real_runs["fixed"][0] / "artifacts")
    result = run_wrapper("scan", "--scan-path", FIXED, "--output", output, "--head-sha", SHA,
                         "--python-bin", python, isolated=True)
    assert result.returncode == 1
    assert_recovery(output, "artifact_validation")
    assert any("artifact_validation unavailable" in note for note in meta(output)["diagnostics"])


# --------------------------------------------------------------------------- recover command


def test_recover_writes_strict_layout_without_analyzer_dependencies(tmp_path):
    output = tmp_path / "out"
    result = run_wrapper("recover", "--stage", "dependency_install", "--output", output, "--head-sha", SHA, isolated=True)
    assert result.returncode == 0, result.stderr
    assert_recovery(output, "dependency_install")
    assert meta(output)["head_sha"] == SHA


def test_recover_keeps_a_completed_record(tmp_path, real_runs):
    output = tmp_path / "out"
    shutil.copytree(real_runs["fixed"][0], output)
    before = tree_digest(output)
    result = run_wrapper("recover", "--stage", "scan_wrapper", "--output", output, "--head-sha", SHA)
    assert result.returncode == 0 and tree_digest(output) == before


def test_recover_adopts_an_unfinished_wrapper_layout(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    ci_scan.write_meta(output, ci_scan.new_record(SHA))
    (output / "artifacts").mkdir()
    (output / "artifacts" / "summary.json").write_text('{"status": "PASS"}', encoding="utf-8")
    result = run_wrapper("recover", "--stage", "scan_wrapper", "--output", output, "--head-sha", SHA)
    assert result.returncode == 0
    assert_recovery(output, "scan_wrapper")
    assert (output / "discarded-1" / "summary.json").read_text(encoding="utf-8") == '{"status": "PASS"}'


@pytest.mark.parametrize("case", ["foreign", "other_commit"])
def test_recover_refuses_layouts_it_does_not_own(tmp_path, case):
    output = tmp_path / "out"
    output.mkdir()
    if case == "foreign":
        (output / "keep.txt").write_text("owned by caller", encoding="utf-8")
    else:
        ci_scan.write_meta(output, ci_scan.new_record(OTHER_SHA))
    before = tree_digest(output)
    result = run_wrapper("recover", "--stage", "scan_wrapper", "--output", output, "--head-sha", SHA)
    assert result.returncode == 2 and tree_digest(output) == before


# --------------------------------------------------------------------------- final gate (actual workflow code)


def run_step(script: str, cwd: Path, env: dict[str, str], path_prefix: Path | None = None):
    full = dict(os.environ, **env)
    if path_prefix is not None:
        full["PATH"] = str(path_prefix) + os.pathsep + full["PATH"]
    return subprocess.run([*BASH, script], cwd=cwd, env=full, capture_output=True, text=True, timeout=300)


def run_gate(workdir: Path, expected: str = SHA, scan_result: str = "success"):
    script = step(VALID_YML, "report", "Final review gate")["run"]
    return run_step(script, workdir, {"EXPECTED_HEAD_SHA": expected, "SCAN_RESULT": scan_result})


def gate_dir(tmp_path: Path, source: Path) -> Path:
    workdir = tmp_path / "gate"
    shutil.copytree(source, workdir / "scan-output")
    return workdir


def _edit_json(path: Path, **changes: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(changes)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_gate_passes_only_a_validated_matching_pass_or_review(tmp_path, real_runs):
    result = run_gate(gate_dir(tmp_path, real_runs["fixed"][0]))
    assert result.returncode == 0, result.stdout
    assert "gate: passed with verdict" in result.stdout


GATE_FAILURES = {
    "unknown_status": lambda d: _edit_json(d / "scan_meta.json", status="UNKNOWN_STATUS"),
    "summary_mismatch": lambda d: _edit_json(d / "artifacts" / "summary.json", status="PASS")
    if json.loads((d / "scan_meta.json").read_text())["status"] == "REVIEW"
    else _edit_json(d / "artifacts" / "summary.json", status="REVIEW"),
    "not_completed": lambda d: _edit_json(d / "scan_meta.json", completed=False, wrapper_exit=2),
    "not_validated": lambda d: _edit_json(d / "scan_meta.json", validated=False),
    "string_exit": lambda d: _edit_json(d / "scan_meta.json", analyzer_exit="0"),
    "head_in_record": lambda d: _edit_json(d / "scan_meta.json", head_sha=OTHER_SHA),
    "unknown_schema": lambda d: _edit_json(d / "scan_meta.json", schema="other"),
    "missing_meta": lambda d: (d / "scan_meta.json").unlink(),
    "malformed_meta": lambda d: (d / "scan_meta.json").write_text("{"),
    "missing_artifacts": lambda d: shutil.rmtree(d / "artifacts"),
    "missing_findings": lambda d: (d / "artifacts" / "findings.json").unlink(),
    "missing_ai": lambda d: (d / "artifacts" / "ai.json").unlink(),
    "unmarked_comment": lambda d: (d / "artifacts" / "comment.md").write_text("## V.A.L.I.D. Review - REVIEW\n"),
    "missing_everything": lambda d: shutil.rmtree(d),
}


@pytest.mark.parametrize("case", sorted(GATE_FAILURES))
def test_gate_rejects_unknown_mismatched_or_missing_data(tmp_path, real_runs, case):
    workdir = gate_dir(tmp_path, real_runs["fixed"][0])
    GATE_FAILURES[case](workdir / "scan-output")
    result = run_gate(workdir)
    assert result.returncode == 1 and "gate: FAILED" in result.stdout and "passed" not in result.stdout


@pytest.mark.parametrize("expected, scan_result", [(OTHER_SHA, "success"), (SHA, "failure"), ("", "success")])
def test_gate_rejects_event_mismatch_or_failed_scan_job(tmp_path, real_runs, expected, scan_result):
    result = run_gate(gate_dir(tmp_path, real_runs["fixed"][0]), expected, scan_result)
    assert result.returncode == 1 and "gate: FAILED" in result.stdout


@pytest.mark.parametrize("run", ["risky", "recovery"])
def test_gate_fails_high_risk_and_incomplete(tmp_path, real_runs, run):
    if run == "risky":
        source = real_runs["risky"][0]
    else:
        source = tmp_path / "recovery"
        assert run_wrapper("recover", "--stage", "dependency_install", "--output", source, "--head-sha", SHA).returncode == 0
    result = run_gate(gate_dir(tmp_path, source))
    assert result.returncode == 1 and "verdict is" in result.stdout


def test_job_summary_uses_marked_report_or_honest_fallback(tmp_path, real_runs):
    script = step(VALID_YML, "report", "Write job summary")["run"]
    present = gate_dir(tmp_path, real_runs["fixed"][0])
    summary_file = tmp_path / "summary.md"
    assert run_step(script, present, {"GITHUB_STEP_SUMMARY": str(summary_file)}).returncode == 0
    assert summary_file.read_text(encoding="utf-8") == (present / "scan-output" / "artifacts" / "comment.md").read_text(encoding="utf-8")
    missing = tmp_path / "missing"
    missing.mkdir()
    fallback_file = tmp_path / "fallback.md"
    assert run_step(script, missing, {"GITHUB_STEP_SUMMARY": str(fallback_file)}).returncode == 0
    lines = fallback_file.read_text(encoding="utf-8").split("\n")
    assert lines[:2] == [MARKER, "## V.A.L.I.D. Review - INCOMPLETE"]


# --------------------------------------------------------------------------- Linux CI steps (actual bash)


@pytest.fixture()
def controlled_python(tmp_path, real_runs) -> Path:
    """`python` double for CI steps: `-m valid scan` copies a template and exits as told; other calls run Python."""
    template = real_runs["risky"][0] / "artifacts"
    executable(
        tmp_path / "ci-bin" / "python",
        f"#!{sys.executable}\nimport json, os, shutil, sys\nfrom pathlib import Path\nargs = sys.argv[1:]\n"
        f"if '-m' not in args:\n    os.execv({sys.executable!r}, [{sys.executable!r}, *args])\n"
        f"out = Path(args[args.index('--output') + 1])\nshutil.copytree({str(template)!r}, out)\n"
        "if os.environ.get('FAKE_STATUS'):\n"
        "    p = out / 'summary.json'; s = json.loads(p.read_text()); s['status'] = os.environ['FAKE_STATUS']\n"
        "    p.write_text(json.dumps(s))\n"
        "if os.environ.get('FAKE_DIFFER') and out.name == 'seed1':\n"
        "    (out / 'comment.md').write_text((out / 'comment.md').read_text() + 'x')\n"
        "sys.exit(int(os.environ['FAKE_EXIT']))\n",
    )
    return tmp_path / "ci-bin"


def ci_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    temp = tmp_path / "runner-temp"
    temp.mkdir(exist_ok=True)
    return {"GITHUB_WORKSPACE": str(ROOT), "RUNNER_TEMP": str(temp), **extra}


REPEAT_STEP = "Verify repeat risky scans are byte-identical"


def test_ci_repeat_step_with_real_analyzer_reaches_byte_comparison(tmp_path, source_python):
    result = run_step(step(CI_YML, "linux-validation", REPEAT_STEP)["run"], tmp_path, ci_env(tmp_path),
                      source_python.parent)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Repeat risky scans are byte-identical" in result.stdout


def test_ci_repeat_step_accepts_expected_exit_one(tmp_path, controlled_python):
    result = run_step(step(CI_YML, "linux-validation", REPEAT_STEP)["run"], tmp_path,
                      ci_env(tmp_path, FAKE_EXIT="1"), controlled_python)
    assert result.returncode == 0 and "byte-identical" in result.stdout


@pytest.mark.parametrize("extra, message", [
    ({"FAKE_EXIT": "0"}, "expected exit 1 twice"),
    ({"FAKE_EXIT": "2"}, "expected exit 1 twice"),
    ({"FAKE_EXIT": "1", "FAKE_STATUS": "REVIEW"}, "expected HIGH RISK"),
    ({"FAKE_EXIT": "1", "FAKE_DIFFER": "1"}, "comment.md"),
])
def test_ci_repeat_step_fails_on_wrong_exit_status_or_drift(tmp_path, controlled_python, extra, message):
    result = run_step(step(CI_YML, "linux-validation", REPEAT_STEP)["run"], tmp_path,
                      ci_env(tmp_path, **extra), controlled_python)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr and "are byte-identical" not in result.stdout


def test_ci_installed_wheel_step_rejects_source_tree_imports(tmp_path, source_python):
    script = step(CI_YML, "linux-validation", "Verify installed wheel")["run"]
    result = run_step(script, tmp_path, ci_env(tmp_path), source_python.parent)
    assert result.returncode != 0
    assert "Installed-wheel fixture contracts verified" not in result.stdout


# --------------------------------------------------------------------------- sticky comment (actual workflow JS)

NODE_DRIVER = r"""
const fs = require('fs');
const [scriptPath, scenarioPath] = process.argv.slice(2);
const script = fs.readFileSync(scriptPath, 'utf8');
const scenario = JSON.parse(fs.readFileSync(scenarioPath, 'utf8'));
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction('require', 'github', 'context', 'core', script);
const writes = [];
const warnings = [];
const pages = [];
const fakeFs = {
  readFileSync(path) {
    if (!Object.prototype.hasOwnProperty.call(scenario.files, path)) {
      const error = new Error('ENOENT');
      error.code = 'ENOENT';
      throw error;
    }
    return scenario.files[path];
  },
};
const maybeFail = (name) => {
  if (scenario.fail === name) {
    const error = new Error('simulated');
    error.name = 'HttpError';
    error.status = 502;
    throw error;
  }
};
const github = { rest: {
  pulls: { get: async () => { maybeFail('pulls.get'); return { data: { head: { sha: scenario.current_head } } }; } },
  issues: {
    listComments: async (p) => {
      maybeFail('listComments');
      pages.push(p.page);
      const start = (p.page - 1) * p.per_page;
      return { data: scenario.comments.slice(start, start + p.per_page) };
    },
    updateComment: async (p) => { maybeFail('updateComment'); writes.push({ op: 'update', id: p.comment_id, body: p.body }); return { data: { id: p.comment_id } }; },
    createComment: async (p) => { maybeFail('createComment'); writes.push({ op: 'create', body: p.body }); return { data: { id: 999 } }; },
  },
} };
const core = {
  warning: (message) => warnings.push(String(message)),
  info: () => {},
  setFailed: (message) => { throw new Error('setFailed called: ' + message); },
};
process.env.HEAD_SHA = scenario.event_head;
process.env.PR_NUMBER = String(scenario.pr_number);
execute((name) => (name === 'fs' ? fakeFs : require(name)), github, { repo: { owner: 'example-owner', repo: 'example-repo' } }, core)
  .then(() => {
    const out = writes.map((w) => ({ ...w, bytes: Buffer.byteLength(w.body, 'utf8') }));
    process.stdout.write(JSON.stringify({ ok: true, writes: out, warnings, pages }));
  })
  .catch((error) => process.stdout.write(JSON.stringify({ ok: false, error: String(error && error.name) })));
"""

HUMAN = {"id": 11, "body": MARKER + "\nhuman-authored", "user": {"login": "example-user", "type": "User"}}
BOT = {"id": 22, "body": MARKER + "\nprevious report", "user": {"login": "github-actions[bot]", "type": "Bot"}}
FILLER = {"id": 1, "body": "looks good", "user": {"login": "example-user", "type": "User"}}
REPORT = MARKER + "\n## V.A.L.I.D. Review - REVIEW\n\nreport body\n"


META_TEXT = json.dumps({"schema": "valid-scan-meta/1", "head_sha": SHA})


def sticky(tmp_path: Path, *, comments: list[dict[str, Any]] | None = None, report: str | None = REPORT,
           meta_text: str | None = META_TEXT, current_head: str = SHA, event_head: str = SHA, fail: str | None = None):
    node = shutil.which("node")
    assert node, "node is required on PATH to execute the workflow comment script"
    files = {}
    if meta_text is not None:
        files["scan-output/scan_meta.json"] = meta_text
    if report is not None:
        files["scan-output/artifacts/comment.md"] = report
    scenario = {"files": files, "comments": comments or [], "current_head": current_head,
                "event_head": event_head, "pr_number": 7, "fail": fail}
    script = tmp_path / "script.js"
    script.write_text(step(VALID_YML, "report", "Update sticky PR comment")["with"]["script"], encoding="utf-8")
    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(json.dumps(scenario), encoding="utf-8")
    driver = tmp_path / "driver.js"
    driver.write_text(NODE_DRIVER, encoding="utf-8")
    result = subprocess.run([node, str(driver), str(script), str(scenario_file)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["ok"] is True, outcome
    return outcome


def test_sticky_updates_only_the_bots_own_marker_comment_across_pages(tmp_path):
    comments = [HUMAN] + [FILLER] * 99 + [BOT]
    outcome = sticky(tmp_path, comments=comments)
    assert outcome["pages"] == [1, 2]
    assert [(w["op"], w.get("id")) for w in outcome["writes"]] == [("update", 22)]
    assert outcome["writes"][0]["body"] == REPORT


@pytest.mark.parametrize("decoy", [
    HUMAN,
    {"id": 33, "body": "intro\n" + MARKER, "user": BOT["user"]},
    {"id": 34, "body": MARKER + " trailing\nreport", "user": BOT["user"]},
    {"id": 35, "body": MARKER + "\nreport", "user": {"login": "github-actions[bot]", "type": "User"}},
    {"id": 36, "body": MARKER + "\nreport", "user": {"login": "other-app[bot]", "type": "Bot"}},
])
def test_sticky_never_overwrites_foreign_or_inexact_marker_comments(tmp_path, decoy):
    outcome = sticky(tmp_path, comments=[decoy])
    assert [w["op"] for w in outcome["writes"]] == ["create"]


@pytest.mark.parametrize("unit", ["é", "\U0001F600", "界"])
def test_sticky_bounds_utf8_bytes_on_character_boundaries(tmp_path, unit):
    report = MARKER + "\n## V.A.L.I.D. Review - REVIEW\n\n" + unit * 40000
    outcome = sticky(tmp_path, report=report)
    (write,) = outcome["writes"]
    assert write["bytes"] <= 60000
    assert write["body"].startswith(MARKER + "\n") and "\ufffd" not in write["body"]
    assert "Report truncated" in write["body"]


@pytest.mark.parametrize("kwargs", [{"current_head": OTHER_SHA}, {"event_head": OTHER_SHA}, {"event_head": "main"}])
def test_sticky_skips_stale_or_mismatched_heads(tmp_path, kwargs):
    outcome = sticky(tmp_path, comments=[BOT], **kwargs)
    assert outcome["writes"] == [] and outcome["warnings"]


@pytest.mark.parametrize("files", [
    {"report": None, "meta_text": "{"},
    {"report": None, "meta_text": "[]"},
    {"report": "unmarked report\n"},
    {"report": None},
    {"meta_text": None},
])
def test_sticky_posts_honest_fallback_for_missing_or_malformed_artifacts(tmp_path, files):
    outcome = sticky(tmp_path, comments=[BOT], **files)
    (write,) = outcome["writes"]
    assert write["op"] == "update" and write["id"] == 22
    assert write["body"].split("\n")[:2] == [MARKER, "## V.A.L.I.D. Review - INCOMPLETE"]


@pytest.mark.parametrize("fail", ["pulls.get", "listComments", "updateComment"])
def test_sticky_api_errors_are_nonfatal(tmp_path, fail):
    outcome = sticky(tmp_path, comments=[BOT], fail=fail)
    assert any("nonfatal" in warning for warning in outcome["warnings"])


def test_sticky_does_not_create_duplicates_when_pages_are_exhausted(tmp_path):
    outcome = sticky(tmp_path, comments=[FILLER] * 5000)
    assert outcome["writes"] == [] and outcome["pages"] == list(range(1, 51))


# --------------------------------------------------------------------------- static workflow contract


def test_triggers_concurrency_and_budgets():
    data = load_workflow(VALID_YML)
    triggers = data.get("on", data.get(True))
    assert set(triggers) == {"pull_request"}
    assert set(triggers["pull_request"]["types"]) == {"opened", "synchronize", "reopened"}
    assert data["concurrency"]["cancel-in-progress"] is True
    assert "github.event.pull_request.number" in data["concurrency"]["group"]
    assert data["jobs"]["scan"]["timeout-minutes"] == 12
    assert "--timeout 600" in step(VALID_YML, "scan", "Run trusted scan wrapper")["run"]
    assert ci_scan.DEFAULT_TIMEOUT_SECONDS == 600


def test_privilege_separation_and_no_secrets():
    data = load_workflow(VALID_YML)
    assert data["permissions"] == {}
    assert data["jobs"]["scan"]["permissions"] == {"contents": "read"}
    assert data["jobs"]["report"]["permissions"] == {"contents": "read", "pull-requests": "write"}
    for path in (VALID_YML, CI_YML):
        raw = path.read_text(encoding="utf-8")
        for forbidden in ("pull_request_target", "workflow_run", "secrets.", "always()"):
            assert forbidden not in raw, (path.name, forbidden)
        for job in load_workflow(path)["jobs"].values():
            for item in job["steps"]:
                assert "${{ github.event" not in item.get("run", ""), "event data must reach scripts via env"
                assert "${{" not in item.get("with", {}).get("script", "")


def test_checkouts_use_exact_commits_without_persisted_credentials():
    base = step(VALID_YML, "scan", "Checkout trusted reviewer")["with"]
    head = step(VALID_YML, "scan", "Checkout PR head")["with"]
    assert base["ref"] == "${{ github.event.pull_request.base.sha }}" and base["path"] == "trusted-base"
    assert head["ref"] == "${{ github.event.pull_request.head.sha }}" and head["path"] == "pr-head"
    for path in (VALID_YML, CI_YML):
        for job in load_workflow(path)["jobs"].values():
            for item in job["steps"]:
                if item.get("uses", "").startswith("actions/checkout@"):
                    assert item["with"]["persist-credentials"] is False


def test_pr_head_is_data_only_and_reviewer_build_is_bootstrapped():
    install = step(VALID_YML, "scan", "Install reviewer")["run"]
    assert "pr-head" not in install
    assert install.index("setuptools==80.9.0") < install.index("--no-build-isolation")
    assert "--upgrade pip" not in install and "--no-index" in install
    wrapper_run = step(VALID_YML, "scan", "Run trusted scan wrapper")["run"]
    runs = [item.get("run", "") for item in job_steps(VALID_YML, "scan")]
    assert [r for r in runs if "pr-head" in r] == [wrapper_run]
    assert wrapper_run.startswith("python -I trusted-base/scripts/ci_scan.py scan --scan-path pr-head/infra ")
    ci_runs = [item.get("run", "") for item in job_steps(CI_YML, "linux-validation")]
    bootstrap = next(i for i, r in enumerate(ci_runs) if "setuptools==80.9.0" in r)
    build = next(i for i, r in enumerate(ci_runs) if "pip wheel" in r)
    assert bootstrap < build and "--no-index" in ci_runs[build] and "--no-build-isolation" in ci_runs[build]


def test_reporting_and_upload_precede_the_final_gate():
    scan_names = [s["name"] for s in job_steps(VALID_YML, "scan")]
    assert scan_names.index("Run trusted scan wrapper on PR data") < scan_names.index(
        "Record INCOMPLETE recovery if no scan result was recorded") < scan_names.index("Upload scan record and artifacts")
    for name in ("Record INCOMPLETE recovery", "Upload scan record"):
        assert step(VALID_YML, "scan", name)["if"].startswith("${{ !cancelled()")
    assert step(VALID_YML, "scan", "Run trusted scan wrapper")["continue-on-error"] is True
    report = load_workflow(VALID_YML)["jobs"]["report"]
    assert report["if"] == "${{ !cancelled() }}" and report["needs"] == "scan"
    names = [s["name"] for s in report["steps"]]
    assert names == ["Download scan record and artifacts", "Write job summary",
                     "Update sticky PR comment (nonfatal)", "Final review gate"]
    for item in report["steps"][1:]:
        assert item["if"] == "${{ !cancelled() }}"
    assert report["steps"][0]["continue-on-error"] is True and report["steps"][2]["continue-on-error"] is True
    assert "continue-on-error" not in report["steps"][3]
    assert report["steps"][3]["env"]["SCAN_RESULT"] == "${{ needs.scan.result }}"


def test_all_actions_use_verified_release_commits():
    for path in (VALID_YML, CI_YML):
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if "uses:" in line]
        assert lines
        for line in lines:
            match = re.fullmatch(r"\s*(?:- )?uses: ([\w./-]+)@([0-9a-f]{40}) # (v[\d.]+)", line)
            assert match, line
            assert EXPECTED_PINS[match.group(1)] == (match.group(2), match.group(3)), line


def test_actionlint_when_available():
    actionlint = shutil.which("actionlint")
    if actionlint is None:
        pytest.skip("actionlint is not installed on PATH")
    result = subprocess.run([actionlint, "-no-color", str(VALID_YML), str(CI_YML)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
