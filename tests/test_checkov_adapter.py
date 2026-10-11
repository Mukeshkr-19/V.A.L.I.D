"""Tests for the real Checkov subprocess adapter (valid.scanners.checkov).

The subprocess contract is exercised with generated stub executables so the
suite runs without Checkov installed. One additional test runs the real pinned
release against the repository fixtures when a ``checkov`` executable and
``fixtures/risky`` are present.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

import pytest

from valid.models import ValidConfig
from valid.scanners import checkov as adapter

REPO_ROOT = Path(__file__).resolve().parents[1]
FROZEN_SAMPLE = REPO_ROOT / "fixtures" / "raw" / "checkov-3.3.8.json"
RISKY_FIXTURE = REPO_ROOT / "fixtures" / "risky" / "main.tf"


def _real_checkov() -> str | None:
    """Path to a real Checkov executable, looking at the project venv too."""
    found = shutil.which("checkov")
    if found:
        return found
    candidate = REPO_ROOT / ".venv" / "bin" / "checkov"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


REAL_CHECKOV = _real_checkov()

TERRAFORM = 'resource "aws_security_group" "probe" {\n  name = "probe"\n}\n'


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def scan_dir(tmp_path: Path, content: str = TERRAFORM) -> Path:
    root = tmp_path / "scan"
    root.mkdir(parents=True, exist_ok=True)
    (root / "main.tf").write_text(content, encoding="utf-8")
    return root


def check(
    check_id: str = "CKV_AWS_24", file_path: str = "/main.tf", **extra: Any
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "check_id": check_id,
        "check_name": f"probe {check_id}",
        "check_result": {"result": "FAILED", "evaluated_keys": []},
        "file_line_range": [1, 2],
        "resource": "aws_security_group.probe",
        "severity": None,
        "file_path": file_path,
    }
    record.update(extra)
    return record


def envelope(
    failed: Sequence[dict[str, Any]] = (),
    passed: Sequence[dict[str, Any]] = (),
    skipped: Sequence[dict[str, Any]] = (),
    parsing_errors: Sequence[str] = (),
) -> str:
    report = {
        "check_type": "terraform",
        "results": {
            "failed_checks": list(failed),
            "passed_checks": list(passed),
            "skipped_checks": list(skipped),
            "parsing_errors": list(parsing_errors),
        },
        "summary": {
            "passed": len(passed),
            "failed": len(failed),
            "skipped": len(skipped),
            "parsing_errors": len(parsing_errors),
            "resource_count": len(failed) + len(passed),
            "checkov_version": adapter.CHECKOV_VERSION,
        },
    }
    return json.dumps(report)


def flat_envelope(resource_count: int = 0) -> str:
    return json.dumps(
        {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": resource_count,
            "checkov_version": adapter.CHECKOV_VERSION,
        }
    )


def stub_command(
    tmp_path: Path,
    stdout: str,
    *,
    exit_code: int = 0,
    sleep: float = 0.0,
    record_path: Path | None = None,
) -> list[str]:
    """Write a stub executable that prints ``stdout`` and returns ``exit_code``."""
    lines = [
        "import json, os, sys, time",
        f"sys.stdout.write({stdout!r})",
        "sys.stderr.write('stub checkov log line\\n')",
    ]
    if sleep:
        lines.append(f"time.sleep({sleep!r})")
    if record_path is not None:
        lines.append(
            "open(" + repr(str(record_path)) + ", 'w').write("
            "json.dumps({'argv': sys.argv, 'env': dict(os.environ), 'cwd': os.getcwd()}))"
        )
    lines.append(f"raise SystemExit({exit_code})")
    script = tmp_path / "stub_checkov.py"
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [sys.executable, str(script)]


def config_for(command: Sequence[str], **overrides: Any) -> ValidConfig:
    return ValidConfig(checkov_command=list(command), **overrides)


def unvalidated_config(**overrides: Any) -> ValidConfig:
    """A config carrying values the strict model would normally reject."""
    return ValidConfig().model_copy(update=overrides)


def as_json(result: Any) -> str:
    return json.dumps(result.model_dump())


def risk_status(result: Any, config: ValidConfig) -> str:
    """V.A.L.I.D. status for a raw scan result; required failures are decisive."""
    from valid.risk import summarize

    return summarize([], result.coverage, config).status


# --------------------------------------------------------------------------- #
# completed scans
# --------------------------------------------------------------------------- #
def test_clean_scan_is_complete(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, envelope(passed=[check(check_id="CKV_AWS_24")]))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.return_code == 0
    assert result.failed_checks == []
    assert result.parsing_errors == []
    assert result.coverage.required_failed_stages == []
    assert result.coverage.required_gaps == []
    assert result.coverage.optional_gaps == []
    assert result.coverage.evaluated_files == ["main.tf"]
    assert result.tool == "checkov"
    assert result.version == adapter.CHECKOV_VERSION


def test_failing_scan_with_nonzero_exit_code_is_complete(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, envelope(failed=[check()]), exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.return_code == 1
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_24"]
    assert result.failed_checks[0]["file_path"] == "main.tf"
    assert result.coverage.required_failed_stages == []
    assert result.diagnostics == []


def test_list_envelope_is_supported(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    payload = json.dumps(
        [
            json.loads(envelope(failed=[check(check_id="CKV_AWS_293")])),
            {"check_type": "secrets", "results": {"failed_checks": []}, "summary": {}},
        ]
    )
    command = stub_command(tmp_path, payload, exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_293"]


def test_malformed_required_buckets_are_a_required_gap(tmp_path: Path) -> None:
    # Updated expectation: this payload previously returned a clean-ish result
    # with the malformed bucket silently discarded (the confirmed fail-open
    # path).  Malformed required data is now a required gap, never green.
    root = scan_dir(tmp_path)
    payload = json.dumps(
        {
            "check_type": "terraform",
            "results": {"failed_checks": "not-a-list", "passed_checks": [1, 2]},
            "summary": {"failed": 0, "passed": 0},
        }
    )
    command = stub_command(tmp_path, payload)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.failed_checks == []
    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    assert adapter.NO_EVALUATED_FILES_GAP in result.coverage.required_gaps
    assert any(
        "malformed required result structure" in note for note in result.diagnostics
    )
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_malformed_failed_check_record_is_a_required_gap(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    payload = json.dumps(
        {
            "check_type": "terraform",
            "results": {"failed_checks": [check(), "not-a-record"], "parsing_errors": []},
            "summary": {"failed": 2},
        }
    )
    command = stub_command(tmp_path, payload, exit_code=1)

    result = adapter.run(root, config_for(command))

    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    # The well-formed record is still reported; only the bad one is rejected.
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_24"]
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_skipped_checks_are_a_coverage_limitation(tmp_path: Path) -> None:
    # A suppressed check is evidence the scan does not have, so a valid JSON
    # envelope with skipped checks must not read as complete policy coverage.
    root = scan_dir(tmp_path)
    skipped = [check(check_id="CKV_AWS_24", check_result={"result": "SKIPPED"})]
    command = stub_command(tmp_path, envelope(passed=[check()], skipped=skipped))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert adapter.SKIPPED_CHECKS_GAP in result.coverage.required_gaps
    assert any("CKV_AWS_24" in note for note in result.diagnostics)
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_absent_buckets_are_tolerated(tmp_path: Path) -> None:
    # The pinned release omits buckets that do not apply to a report, so an
    # absent bucket is legitimate data, not a malformed structure.
    root = scan_dir(tmp_path)
    payload = json.dumps(
        [
            json.loads(envelope(passed=[check()])),
            {"check_type": "secrets", "summary": {"passed": 0}},
        ]
    )
    command = stub_command(tmp_path, payload, exit_code=0)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.coverage.required_gaps == []
    assert result.coverage.required_failed_stages == []


def test_flat_resource_less_envelope_is_not_a_clean_scan(tmp_path: Path) -> None:
    root = scan_dir(tmp_path, content="# no terraform resources here\n")
    command = stub_command(tmp_path, flat_envelope(resource_count=0))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.return_code == 0
    assert result.failed_checks == []
    assert result.coverage.evaluated_files == []
    assert adapter.NO_EVALUATED_FILES_GAP in result.coverage.required_gaps
    assert any("no Terraform resources" in note for note in result.diagnostics)


def test_private_absolute_paths_are_stripped(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    private = str(root / "main.tf")
    record = check(
        file_abs_path=private,
        repo_file_path=private,
        definition_context_file_path=private,
        caller_file_path=private,
    )
    command = stub_command(tmp_path, envelope(failed=[record]), exit_code=1)

    result = adapter.run(root, config_for(command))

    dumped = as_json(result)
    assert private not in dumped
    assert str(root) not in dumped
    assert "file_abs_path" not in dumped
    assert "repo_file_path" not in dumped
    assert "definition_context_file_path" not in dumped
    assert "caller_file_path" not in dumped
    assert result.failed_checks[0]["file_path"] == "main.tf"


def test_parsing_errors_are_a_required_stage_failure(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    private = str(root / "main.tf")
    command = stub_command(
        tmp_path, envelope(parsing_errors=[private, "second problem"]), exit_code=0
    )

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.parsing_errors == ["main.tf", "second problem"]
    assert result.coverage.required_failed_stages == [adapter.PARSING_STAGE]
    assert private not in as_json(result)


def test_out_of_root_and_traversal_locations_are_rejected(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    outside = check(check_id="CKV_AWS_24", file_path="/etc/passwd")
    traversal = check(check_id="CKV_AWS_999", file_path="../../secrets.tf")
    command = stub_command(
        tmp_path, envelope(failed=[outside, traversal], passed=[check()]), exit_code=1
    )

    result = adapter.run(root, config_for(command))

    assert result.failed_checks == []
    assert result.coverage.required_gaps == [adapter.UNUSABLE_LOCATION_GAP]
    assert result.coverage.evaluated_files == ["main.tf"]
    assert "2 failed check(s) omitted" in " ".join(result.diagnostics)
    dumped = as_json(result)
    assert "/etc/passwd" not in dumped
    assert "secrets.tf" not in dumped


def test_frozen_scanner_sample_round_trips(tmp_path: Path) -> None:
    if not FROZEN_SAMPLE.is_file():
        pytest.skip("frozen Checkov sample fixture not present")
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, FROZEN_SAMPLE.read_text(encoding="utf-8"), exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.return_code == 1
    assert result.failed_checks
    ids = {c["check_id"] for c in result.failed_checks}
    assert "CKV_AWS_24" in ids
    for record in result.failed_checks:
        assert not record["file_path"].startswith("/")
        assert ".." not in record["file_path"]
    dumped = as_json(result)
    assert str(REPO_ROOT) not in dumped
    # The capture keeps an absolute location in the raw records; the adapter
    # must strip those keys rather than pass an absolute path through.
    assert "/scan/main.tf" not in dumped
    assert "file_abs_path" not in dumped


def test_frozen_scanner_sample_contains_no_private_paths() -> None:
    text = FROZEN_SAMPLE.read_text(encoding="utf-8")
    for marker in ("/Users", "/private/", "/var/folders", "visualizations"):
        assert marker not in text
    assert str(REPO_ROOT) not in text
    assert str(Path.home()) not in text



def test_caching_is_not_used_across_runs(tmp_path: Path) -> None:
    """Every call re-executes the scanner; a second call sees the new payload."""
    root = scan_dir(tmp_path)
    first = stub_command(tmp_path, envelope(failed=[check()]), exit_code=1)
    result_one = adapter.run(root, config_for(first))
    second = stub_command(tmp_path, envelope(passed=[check()]), exit_code=0)
    result_two = adapter.run(root, config_for(second))

    assert result_one.failed_checks and result_one.return_code == 1
    assert result_two.failed_checks == [] and result_two.return_code == 0


# --------------------------------------------------------------------------- #
# execution failures
# --------------------------------------------------------------------------- #
def test_timeout_is_an_execution_error(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, envelope(), sleep=30)

    started = time.monotonic()
    result = adapter.run(root, config_for(command, scanner_timeout_seconds=1))
    elapsed = time.monotonic() - started

    assert result.status == "error"
    assert result.return_code is None
    assert result.failed_checks == []
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert any("timed out" in note for note in result.diagnostics)
    assert elapsed < 20


def test_missing_executable_is_an_execution_error(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)

    result = adapter.run(root, config_for(["checkov-not-installed-3.3.8"]))

    assert result.status == "error"
    assert result.return_code is None
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert "checkov-not-installed-3.3.8" in " ".join(result.diagnostics)
    assert str(root) not in as_json(result)
    assert str(tmp_path) not in as_json(result)


def test_missing_scan_path_is_an_execution_error(tmp_path: Path) -> None:
    command = stub_command(tmp_path, envelope())

    result = adapter.run(tmp_path / "does-not-exist", config_for(command))

    assert result.status == "error"
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert str(tmp_path) not in as_json(result)


def test_empty_command_is_an_execution_error(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)

    result = adapter.run(root, unvalidated_config(checkov_command=[]))

    assert result.status == "error"
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert any("checkov_command" in note for note in result.diagnostics)


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "   \n",
        "not json at all",
        '{"results": {"failed_checks": [',
        '{"hello": "world"}',
        "[]",
        '{"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "unexpected": 1}',
        envelope() + "\n" + envelope(),
        '[1, 2, 3]',
        'null',
    ],
)
def test_unusable_output_is_an_execution_error(tmp_path: Path, stdout: str) -> None:
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, stdout, exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "error"
    assert result.failed_checks == []
    assert result.parsing_errors == []
    assert result.return_code == 1
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert result.diagnostics


def test_embedded_json_with_wrapper_noise_is_recovered(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    noisy = "Checkov 3.3.8 scan starting\n" + envelope(failed=[check()]) + "\ntrailing noise"
    command = stub_command(tmp_path, noisy, exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_24"]


def test_flat_envelope_tolerates_the_extra_url_key(tmp_path: Path) -> None:
    root = scan_dir(tmp_path, content="# empty\n")
    payload = json.dumps(
        {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 0,
            "checkov_version": adapter.CHECKOV_VERSION,
            "url": "https://bridgecrew.cloud",
        }
    )
    command = stub_command(tmp_path, payload)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.coverage.required_gaps == [adapter.NO_EVALUATED_FILES_GAP]


# --------------------------------------------------------------------------- #
# argument, environment and isolation contract
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("exit_code", [0, 1])
def test_normal_completed_exit_codes_stay_complete(
    tmp_path: Path, exit_code: int
) -> None:
    root = scan_dir(tmp_path)
    failed = [check()] if exit_code == 1 else []
    command = stub_command(
        tmp_path, envelope(failed=failed, passed=[check()]), exit_code=exit_code
    )

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.return_code == exit_code
    assert result.coverage.required_failed_stages == []
    assert result.coverage.required_gaps == []
    assert result.coverage.evaluated_files == ["main.tf"]


@pytest.mark.parametrize("exit_code", [2, 3])
def test_unexpected_exit_code_is_an_execution_error(
    tmp_path: Path, exit_code: int
) -> None:
    # Previously an unexpected code with recognised JSON stayed status=complete
    # with a diagnostic only; it is now an execution failure that keeps the
    # actual return code.
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, envelope(failed=[check()]), exit_code=exit_code)

    result = adapter.run(root, config_for(command))

    assert result.status == "error"
    assert result.return_code == exit_code
    assert result.failed_checks == []
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert any(
        f"unexpected status {exit_code}" in note for note in result.diagnostics
    )
    assert risk_status(result, config_for(command)) == "INCOMPLETE"
    assert str(root) not in as_json(result)


def test_scope_flags_keep_the_scan_restricted(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)

    argv = adapter.build_command(root, config_for(["checkov"]))

    assert argv[0] == "checkov"
    assert argv[1 : len(adapter.SCOPE_FLAGS) + 1] == list(adapter.SCOPE_FLAGS)
    assert argv[argv.index("--framework") + 1] == "terraform"
    assert argv[argv.index("--download-external-modules") + 1] == "False"
    assert "json" in argv
    assert argv[argv.index("-d") + 1] == str(root)
    assert not adapter.FORBIDDEN_FLAGS.intersection(argv)


def test_file_target_uses_file_selector(tmp_path: Path) -> None:
    target = scan_dir(tmp_path) / "main.tf"
    argv = adapter.build_command(target, config_for(["checkov"]))

    assert argv[argv.index("-f") + 1] == str(target)
    assert "-d" not in argv


def test_subprocess_runs_without_shell_and_with_finite_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = scan_dir(tmp_path)
    captured: dict[str, Any] = {}

    def fake_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, stdout=envelope(passed=[check()]), stderr="")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    adapter.run(root, config_for(["checkov"], scanner_timeout_seconds=7))

    assert isinstance(captured["argv"], list)
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 7
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
    assert Path(captured["kwargs"]["cwd"]) != root
    assert str(root) not in str(captured["kwargs"]["cwd"])


def test_credentials_are_not_forwarded_to_the_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = scan_dir(tmp_path)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "probe-secret")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("CHECKOV_CONFIG_FILE", "/tmp/probe.yaml")
    monkeypatch.setenv("CKV_VAR_FILE", "/tmp/probe.tfvars")
    monkeypatch.setenv("BC_API_KEY", "probe-key")
    captured: dict[str, Any] = {}

    def fake_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(argv, 0, stdout=envelope(passed=[check()]), stderr="")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    result = adapter.run(root, config_for(["checkov"]))

    assert result.status == "complete"
    assert "AWS_SECRET_ACCESS_KEY" not in captured["env"]
    assert "CHECKOV_CONFIG_FILE" not in captured["env"]
    assert "CKV_VAR_FILE" not in captured["env"]
    assert "BC_API_KEY" not in captured["env"]
    assert captured["env"]["AWS_DEFAULT_REGION"] == "eu-west-1"
    assert "probe-secret" not in as_json(result)


def test_scan_target_is_never_interpolated_into_a_shell(tmp_path: Path) -> None:
    hostile = tmp_path / "scan; touch pwned $(touch pwned) `touch pwned`"
    hostile.mkdir()
    (hostile / "main.tf").write_text(TERRAFORM, encoding="utf-8")
    record = tmp_path / "record.json"
    command = stub_command(
        tmp_path, envelope(passed=[check()]), record_path=record
    )

    previous = Path.cwd()
    result = adapter.run(hostile, config_for(command))

    assert result.status == "complete"
    assert not (tmp_path / "pwned").exists()
    assert not (previous / "pwned").exists()
    recorded = json.loads(record.read_text(encoding="utf-8"))
    assert recorded["argv"][-1] == str(hostile)
    assert recorded["argv"].count(str(hostile)) == 1
    assert not (hostile / "pwned").exists()


def test_scanner_runs_in_an_isolated_working_directory(tmp_path: Path) -> None:
    host_config = tmp_path / ".checkov.yaml"
    host_config.write_text("soft-fail: true\n", encoding="utf-8")
    root = scan_dir(tmp_path)
    record = tmp_path / "record.json"
    command = stub_command(tmp_path, envelope(passed=[check()]), record_path=record)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    recorded = json.loads(record.read_text(encoding="utf-8"))
    assert Path(recorded["cwd"]) != tmp_path
    assert str(REPO_ROOT) not in recorded["cwd"]


@pytest.mark.parametrize("name", [".checkov.yaml", ".checkov.yml"])
def test_scan_root_config_file_is_refused_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    # Updated expectation: this was previously only an optional gap while the
    # scanner still ran, so a supplied ``skip-check`` could suppress a required
    # check.  The scan is now refused before the subprocess is started.
    root = scan_dir(tmp_path)
    (root / name).write_text("skip-check:\n  - CKV_AWS_24\n", encoding="utf-8")
    command = stub_command(tmp_path, envelope(passed=[check()]))

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("checkov must not execute with untrusted configuration")

    monkeypatch.setattr(adapter.subprocess, "run", forbidden)
    result = adapter.run(root, config_for(command))

    assert result.status == "error"
    assert result.return_code is None
    assert result.coverage.required_failed_stages == [adapter.EXECUTION_STAGE]
    assert result.coverage.required_gaps == [adapter.LOCAL_CONFIG_GAP]
    assert result.coverage.optional_gaps == []
    assert result.coverage.evaluated_files == []
    assert any(name in note for note in result.diagnostics)
    assert risk_status(result, config_for(command)) == "INCOMPLETE"
    assert str(root) not in as_json(result)


def test_no_config_file_means_no_gap(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, envelope(passed=[check()]))

    result = adapter.run(root, config_for(command))

    assert result.coverage.optional_gaps == []
    assert not any(".checkov" in note for note in result.coverage.diagnostics)


def test_configured_command_prefix_is_preserved(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    command = stub_command(tmp_path, envelope(passed=[check()]))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    argv = adapter.build_command(root, config_for(command))
    assert argv[: len(command)] == command


def test_timeout_helper_is_finite() -> None:
    assert adapter.scan_timeout_seconds(config_for(["checkov"])) == 120
    assert adapter.scan_timeout_seconds(config_for(["checkov"], scanner_timeout_seconds=45)) == 45
    assert adapter.scan_timeout_seconds(unvalidated_config(scanner_timeout_seconds=0)) == 1
    assert adapter.scan_timeout_seconds(unvalidated_config(scanner_timeout_seconds=-5)) == 1


def test_result_is_deterministic_for_the_same_payload(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    payload = envelope(failed=[check(check_id="CKV_AWS_293")], passed=[check()])
    first = adapter.run(root, config_for(stub_command(tmp_path, payload, exit_code=1)))
    second = adapter.run(root, config_for(stub_command(tmp_path, payload, exit_code=1)))

    assert as_json(first) == as_json(second)


# --------------------------------------------------------------------------- #
# real scanner integration (skipped when Checkov or fixtures are unavailable)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    REAL_CHECKOV is None or not RISKY_FIXTURE.is_file(),
    reason="real checkov executable and fixtures/risky are both required",
)
def test_real_checkov_reports_terraform_findings() -> None:
    result = adapter.run(RISKY_FIXTURE.parent, config_for([REAL_CHECKOV]))

    assert result.status == "complete"
    assert result.return_code in (0, 1)
    ids = {c["check_id"] for c in result.failed_checks}
    assert "CKV_AWS_24" in ids, ids
    assert all(not c["file_path"].startswith("/") for c in result.failed_checks)
    assert result.coverage.evaluated_files
    assert str(REPO_ROOT) not in as_json(result)
    assert os.sep + "Users" not in as_json(result)


# --------------------------------------------------------------------------- #
# malformed transport regressions (follow-up)
# --------------------------------------------------------------------------- #
def test_declared_failure_with_missing_bucket_is_a_required_gap(tmp_path: Path) -> None:
    # A summary that declares a failed check while the failed_checks bucket is
    # absent means required records were lost.  Previously this returned PASS
    # because an absent bucket was tolerated unconditionally.
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    del report["results"]["failed_checks"]
    report["summary"]["failed"] = 1
    command = stub_command(tmp_path, json.dumps(report), exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.failed_checks == []
    assert adapter.MISSING_RECORDS_GAP in result.coverage.required_gaps
    assert result.coverage.evaluated_files == ["main.tf"]
    assert any("declares 1 failed check" in note for note in result.diagnostics)
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_truncated_failed_list_is_a_required_gap(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    report = json.loads(envelope(failed=[check()]))
    report["summary"]["failed"] = 3
    command = stub_command(tmp_path, json.dumps(report), exit_code=1)

    result = adapter.run(root, config_for(command))

    # The readable record is still reported; only the missing ones raise the gap.
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_24"]
    assert adapter.MISSING_RECORDS_GAP in result.coverage.required_gaps
    assert any("2 required record(s) are missing" in note for note in result.diagnostics)
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_declared_skipped_count_without_evidence_is_a_required_gap(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    del report["results"]["skipped_checks"]
    report["summary"]["skipped"] = 1
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert adapter.MISSING_RECORDS_GAP in result.coverage.required_gaps
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_declared_parsing_errors_without_evidence_is_a_required_gap(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    del report["results"]["parsing_errors"]
    report["summary"]["parsing_errors"] = 2
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    # No parse failure evidence can be named, so the stage stays clean and the
    # lost-record gap carries the incompleteness instead.
    assert result.coverage.required_failed_stages == []
    assert result.parsing_errors == []
    assert adapter.MISSING_RECORDS_GAP in result.coverage.required_gaps
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_malformed_summary_counter_is_a_required_gap(tmp_path: Path) -> None:
    # A counter supplied with a value of the wrong shape is malformed data, not
    # missing metadata, so it must fail closed rather than be ignored.
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    del report["results"]["failed_checks"]
    report["summary"]["failed"] = "1"
    command = stub_command(tmp_path, json.dumps(report), exit_code=1)

    result = adapter.run(root, config_for(command))

    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    assert any("malformed required result structure" in note for note in result.diagnostics)
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_non_object_summary_is_a_required_gap(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    report["summary"] = "not-a-summary"
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_null_counters_are_unavailable_not_malformed(tmp_path: Path) -> None:
    # Counterexample: an explicitly null counter carries no metadata, so no gap
    # is invented for it.
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    report["summary"]["failed"] = None
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert adapter.MALFORMED_RESULTS_GAP not in result.coverage.required_gaps
    assert adapter.MISSING_RECORDS_GAP not in result.coverage.required_gaps
    assert result.coverage.required_gaps == []


def _silent_report() -> dict[str, Any]:
    """A report with no summary and no records: counters are unavailable."""
    return {"check_type": "other", "results": {}}


def _null_counter_report() -> dict[str, Any]:
    """A report whose three counters are explicitly null: also unavailable."""
    return {
        "check_type": "other",
        "results": {},
        "summary": {"failed": None, "skipped": None, "parsing_errors": None},
    }


@pytest.mark.parametrize(
    "counter,bucket",
    [
        ("failed", "failed_checks"),
        ("skipped", "skipped_checks"),
        ("parsing_errors", "parsing_errors"),
    ],
)
@pytest.mark.parametrize("peer", ["absent", "null"])
@pytest.mark.parametrize("reverse", [False, True])
def test_lost_records_are_not_suppressed_by_an_unavailable_peer(
    tmp_path: Path, counter: str, bucket: str, peer: str, reverse: bool
) -> None:
    # An unrelated report's missing/null counters or empty records must not
    # silence a report that explicitly declares lost records.  Both report
    # orders are covered.
    root = scan_dir(tmp_path)
    owner = json.loads(envelope(passed=[check()]))
    owner["summary"][counter] = 1
    del owner["results"][bucket]
    other = _silent_report() if peer == "absent" else _null_counter_report()
    payload = [other, owner] if reverse else [owner, other]
    command = stub_command(tmp_path, json.dumps(payload), exit_code=1)

    result = adapter.run(root, config_for(command))

    assert adapter.MISSING_RECORDS_GAP in result.coverage.required_gaps
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_peer_records_do_not_offset_this_reports_declared_loss(tmp_path: Path) -> None:
    # The peer's extra record must not make the owner's missing declaration look
    # whole; counters are compared per report, never as one pool.
    root = scan_dir(tmp_path)
    owner = json.loads(envelope(passed=[check()]))
    del owner["results"]["failed_checks"]
    owner["summary"]["failed"] = 1
    peer = {
        "check_type": "other",
        "results": {"failed_checks": [check(check_id="CKV_OTHER")]},
        "summary": {"failed": 0, "skipped": 0, "parsing_errors": 0},
    }
    command = stub_command(tmp_path, json.dumps([owner, peer]), exit_code=1)

    result = adapter.run(root, config_for(command))

    assert adapter.MISSING_RECORDS_GAP in result.coverage.required_gaps
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_OTHER"]
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


@pytest.mark.parametrize("value", ["bad", True, -1])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("peer", ["absent", "null"])
def test_malformed_counter_is_not_hidden_by_an_unavailable_report(
    tmp_path: Path, value: Any, reverse: bool, peer: str
) -> None:
    # A supplied malformed counter stays malformed even when an earlier report
    # has no summary at all, in either order and beside an absent or null peer.
    root = scan_dir(tmp_path)
    bad = json.loads(envelope(passed=[check()]))
    bad["summary"]["failed"] = value
    other = _silent_report() if peer == "absent" else _null_counter_report()
    payload = [bad, other] if reverse else [other, bad]
    command = stub_command(tmp_path, json.dumps(payload))

    result = adapter.run(root, config_for(command))

    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_unavailable_peer_reports_with_no_lost_records_stay_complete(
    tmp_path: Path,
) -> None:
    # Counterexample: legitimate all-empty reports with absent/null counters
    # invent no gap when nothing is actually missing.
    root = scan_dir(tmp_path)
    payload = [json.loads(envelope(passed=[check()])), _silent_report(), _null_counter_report()]
    command = stub_command(tmp_path, json.dumps(payload))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.coverage.required_gaps == []
    assert result.coverage.required_failed_stages == []
    assert result.coverage.evaluated_files == ["main.tf"]
    assert risk_status(result, config_for(command)) == "PASS"


def test_zero_counts_with_absent_buckets_stay_complete(tmp_path: Path) -> None:
    # Counterexample: omitted empty buckets with honest zero counters are
    # legitimate pinned-release output and must not be greeted as loss.
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    for bucket in ("failed_checks", "skipped_checks", "parsing_errors"):
        del report["results"][bucket]
    report["summary"].update({"failed": 0, "skipped": 0, "parsing_errors": 0})
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.coverage.required_gaps == []
    assert result.coverage.required_failed_stages == []
    assert risk_status(result, config_for(command)) == "PASS"


def test_absent_summary_counters_do_not_invent_gaps(tmp_path: Path) -> None:
    # Counterexample: with no readable counters there is nothing to compare, so
    # no gap is fabricated from missing metadata alone.
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    report["summary"] = {"passed": 1}
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.coverage.required_gaps == []
    assert risk_status(result, config_for(command)) == "PASS"


def test_skipped_record_without_check_id_is_still_a_coverage_gap(tmp_path: Path) -> None:
    # Skipped coverage is detected from record presence, so a record whose
    # check_id is missing can no longer cancel the required gap.
    root = scan_dir(tmp_path)
    report = json.loads(envelope(passed=[check()]))
    report["results"]["skipped_checks"] = [{"file_path": "/main.tf"}]
    report["summary"]["skipped"] = 1
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert adapter.SKIPPED_CHECKS_GAP in result.coverage.required_gaps
    assert any(
        "not evaluated" in note and "no diagnostic check ids" in note
        for note in result.diagnostics
    )
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_skipped_only_row_is_not_evaluated_evidence(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    report = json.loads(envelope())
    report["results"]["skipped_checks"] = [check(check_id="CKV_AWS_24")]
    report["summary"]["skipped"] = 1
    command = stub_command(tmp_path, json.dumps(report))

    result = adapter.run(root, config_for(command))

    assert result.coverage.evaluated_files == []
    assert result.coverage.required_gaps == [
        adapter.SKIPPED_CHECKS_GAP,
        adapter.NO_EVALUATED_FILES_GAP,
    ]
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


@pytest.mark.parametrize(
    "member",
    ["not-a-report", 7, {"foo": "bar"}, {"results": "wrong-type"}],
    ids=["string", "number", "object", "object-wrong-results"],
)
def test_malformed_report_list_member_is_a_required_gap(
    tmp_path: Path, member: Any
) -> None:
    # A list carrying a valid report next to an unreadable member previously
    # dropped the member and returned PASS.  The valid report is still readable,
    # but it cannot be presented as covering the whole scan.
    root = scan_dir(tmp_path)
    payload = json.dumps(
        [json.loads(envelope(failed=[check(check_id="CKV_AWS_293")])), member]
    )
    command = stub_command(tmp_path, payload, exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_293"]
    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    assert any("report list member" in note for note in result.diagnostics)
    assert risk_status(result, config_for(command)) == "INCOMPLETE"


def test_well_formed_multi_framework_list_has_no_member_gap(tmp_path: Path) -> None:
    # Counterexample: a measured two-framework payload stays complete.
    root = scan_dir(tmp_path)
    payload = json.dumps(
        [
            json.loads(envelope(failed=[check(check_id="CKV_AWS_293")])),
            {
                "check_type": "secrets",
                "results": {"failed_checks": []},
                "summary": {
                    "passed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "parsing_errors": 0,
                },
            },
        ]
    )
    command = stub_command(tmp_path, payload, exit_code=1)

    result = adapter.run(root, config_for(command))

    assert result.status == "complete"
    assert result.coverage.required_gaps == []
    assert [c["check_id"] for c in result.failed_checks] == ["CKV_AWS_293"]
