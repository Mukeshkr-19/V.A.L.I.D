"""Trusted CI wrapper: run the analyzer on pull-request data and publish one validated scan record.

The wrapper owns a fresh output directory with this layout:

    scan_meta.json   wrapper record, persisted before launch with wrapper_exit=2 (not completed)
    artifacts/       the analyzer's six report artifacts, or a conservative INCOMPLETE recovery set

Recovery uses only the standard library, so it still works when analyzer dependencies are missing.
Public outputs carry controlled stage, error-type and exit diagnostics only: never analyzer
stdout/stderr, tracebacks, environment values or absolute scan paths.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MARKER = "<!-- valid-report -->"
META_NAME = "scan_meta.json"
META_SCHEMA = "valid-scan-meta/1"
ARTIFACT_DIR = "artifacts"
DISCARDED_PREFIX = "discarded-"
ARTIFACTS = ("raw_checkov.json", "raw_custom.json", "findings.json", "comment.md", "ai.json", "summary.json")
STATUS_EXIT = {"PASS": 0, "REVIEW": 0, "HIGH RISK": 1, "INCOMPLETE": 1}
SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
CATEGORIES = ("security", "reliability", "governance", "cost_risk")
CHECKOV_VERSION = "3.3.8"
NOT_COMPLETED = 2
DEFAULT_TIMEOUT_SECONDS = 600
KILL_GRACE_SECONDS = 5.0
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
RECOVERY_STAGES = ("checkout_head", "python_setup", "dependency_install", "scan_wrapper")
SCORE_UNAVAILABLE = "Risk score unavailable: analysis did not complete, so no score or top priority was computed."
SHA_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SENSITIVE_ENV = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL", re.IGNORECASE)


class OutputRefused(Exception):
    """The requested output location cannot be used without risking caller or input files."""


# --------------------------------------------------------------------------- output layout


def _same_or_nested(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def prepare_output(output: Path, scan_path: Path | None) -> None:
    """Create or adopt an empty, non-symlink output directory that does not overlap the scan input."""
    if output.is_symlink():
        raise OutputRefused("output path is a symbolic link")
    if output.exists():
        if not output.is_dir():
            raise OutputRefused("output path exists and is not a directory")
        if any(output.iterdir()):
            raise OutputRefused("output directory is not empty")
    if scan_path is not None and _same_or_nested(output.resolve(), scan_path.resolve()):
        raise OutputRefused("output directory overlaps the scan input")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(exist_ok=True)


def new_record(head_sha: str) -> dict[str, Any]:
    return {
        "schema": META_SCHEMA,
        "head_sha": head_sha,
        "completed": False,
        "wrapper_exit": NOT_COMPLETED,
        "analyzer_exit": None,
        "validated": False,
        "status": "INCOMPLETE",
        "stage": None,
        "timeout": False,
        "diagnostics": ["scan started; no result has been recorded"],
    }


def write_meta(output: Path, record: dict[str, Any]) -> None:
    temp = output / f".{META_NAME}.tmp"
    with open(temp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, output / META_NAME)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


# --------------------------------------------------------------------------- analyzer execution


def analyzer_env(python_bin: str) -> dict[str, str]:
    """Inherit a scrubbed environment: no credential-like or interpreter-steering variables."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not SENSITIVE_ENV.search(key) and not key.startswith("PYTHON")
    }
    located = shutil.which(python_bin) or python_bin
    bin_dir = os.path.dirname(os.path.abspath(located))
    path = env.get("PATH", "")
    if bin_dir not in path.split(os.pathsep):
        env["PATH"] = bin_dir + (os.pathsep + path if path else "")
    return env


def terminate_group(proc: subprocess.Popen[bytes]) -> bool:
    """Terminate and reap every process left in the analyzer's process group; report whether any were found."""
    found = False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            break
        found = True
        deadline = time.monotonic() + KILL_GRACE_SECONDS
        while time.monotonic() < deadline:
            proc.poll()
            try:
                os.killpg(proc.pid, 0)
            except (ProcessLookupError, PermissionError):
                break
            time.sleep(0.05)
        else:
            continue
        break
    try:
        proc.wait(timeout=KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    return found


def launch(python_bin: str, scan_path: Path, artifacts: Path, timeout: int) -> dict[str, Any]:
    command = [python_bin, "-I", "-m", "valid", "scan", "--path", str(scan_path), "--output", str(artifacts)]
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=analyzer_env(python_bin),
            start_new_session=True,
            close_fds=True,
        )
    except (OSError, ValueError) as error:
        return {"exit": None, "timeout": False, "stage": "analyzer_launch",
                "diagnostics": [f"analyzer_launch failed ({type(error).__name__})"]}
    timed_out = False
    try:
        returncode: int | None = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = None
    leftovers = terminate_group(proc)
    diagnostics: list[str] = []
    if timed_out:
        diagnostics.append(f"analyzer_timeout: exceeded {timeout}s; process group terminated")
        return {"exit": None, "timeout": True, "stage": "analyzer_timeout", "diagnostics": diagnostics}
    if leftovers:
        diagnostics.append("analyzer left background processes; they were terminated")
    if returncode not in (0, 1):
        diagnostics.append(f"analyzer_execution: unexpected exit status {returncode}")
        return {"exit": returncode, "timeout": False, "stage": "analyzer_execution", "diagnostics": diagnostics}
    return {"exit": returncode, "timeout": False, "stage": None, "diagnostics": diagnostics}


# --------------------------------------------------------------------------- artifact validation


def _read_regular(path: Path) -> bytes:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("not a regular file")
    if info.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact too large")
    return path.read_bytes()


def _tally(findings: list[dict[str, Any]]) -> tuple[dict[str, int], dict[str, int]]:
    counts = {severity: 0 for severity in SEVERITIES}
    categories = {category: 0 for category in CATEGORIES}
    for finding in findings:
        counts[finding["priority"]] += 1
        categories[finding["category"]] += 1
    return counts, categories


def validate_artifacts(artifacts: Path, analyzer_exit: int | None) -> tuple[str | None, list[str], dict[str, Any]]:
    """Validate the full artifact set against the canonical contracts.

    Returns (status, problems, evidence). ``status`` is set only when every check passes;
    ``evidence`` holds individually validated JSON artifacts that recovery may preserve.
    """
    problems: list[str] = []
    evidence: dict[str, Any] = {}
    if artifacts.is_symlink() or not artifacts.is_dir():
        return None, ["artifact_validation: artifact directory is missing"], evidence
    present = {entry.name for entry in artifacts.iterdir()}
    missing = [name for name in ARTIFACTS if name not in present]
    if missing:
        problems.append("artifact_validation: missing " + ", ".join(missing))
    if present - set(ARTIFACTS):
        problems.append(f"artifact_validation: {len(present - set(ARTIFACTS))} unexpected entries")
    try:
        from pydantic import TypeAdapter
        from valid import models
    except Exception as error:
        problems.append(f"artifact_validation unavailable ({type(error).__name__})")
        return None, problems, evidence

    contracts = {
        "raw_checkov.json": models.RawScanResult,
        "raw_custom.json": models.CustomScanResult,
        "findings.json": TypeAdapter(list[models.Finding]),
        "ai.json": TypeAdapter(list[models.Explanation]),
        "summary.json": models.RiskSummary,
    }
    parsed: dict[str, Any] = {}
    for name, contract in contracts.items():
        if name in missing:
            continue
        try:
            text = _read_regular(artifacts / name).decode("utf-8")
            if isinstance(contract, TypeAdapter):
                value = contract.validate_json(text)
                evidence[name] = [item.model_dump(mode="json") for item in value]
            else:
                value = contract.model_validate_json(text)
                evidence[name] = value.model_dump(mode="json")
            parsed[name] = value
        except Exception as error:
            problems.append(f"artifact_validation: {name} rejected ({type(error).__name__})")

    summary = parsed.get("summary.json")
    if summary is not None:
        expected_exit = STATUS_EXIT.get(summary.status)
        if expected_exit is None or analyzer_exit != expected_exit:
            problems.append(f"artifact_validation: status {summary.status} disagrees with analyzer exit {analyzer_exit}")
        if "findings.json" in evidence:
            counts, categories = _tally(evidence["findings.json"])
            if summary.counts != counts or summary.category_counts != categories:
                problems.append("artifact_validation: summary counts disagree with findings.json")
    explanations = parsed.get("ai.json")
    if explanations is not None and "findings.json" in evidence:
        by_id = {finding["finding_id"]: finding for finding in evidence["findings.json"]}
        seen: set[str] = set()
        for explanation in explanations:
            finding_id = explanation.finding_id
            finding = by_id.get(finding_id)
            if finding is None or finding_id in seen:
                problems.append("artifact_validation: ai.json has a duplicate or unknown finding ID")
                break
            seen.add(finding_id)
            expected_ids = sorted(item["evidence_id"] for item in finding["evidence"])
            if list(explanation.evidence_ids) != expected_ids:
                problems.append("artifact_validation: ai.json evidence IDs disagree with findings.json")
                break
            if explanation.evidence_strength != finding["evidence_strength"]:
                problems.append("artifact_validation: ai.json evidence strength disagrees with findings.json")
                break
        if not problems and set(by_id) - seen:
            problems.append("artifact_validation: ai.json misses validated findings")
    if "comment.md" not in missing:
        try:
            lines = _read_regular(artifacts / "comment.md").decode("utf-8").split("\n")
            if lines[0] != MARKER:
                problems.append("artifact_validation: comment.md does not start with the report marker")
            elif summary is not None and (len(lines) < 2 or lines[1] != "## V.A.L.I.D. Review - " + summary.status):
                problems.append("artifact_validation: comment.md heading disagrees with summary status")
        except Exception as error:
            problems.append(f"artifact_validation: comment.md rejected ({type(error).__name__})")

    if problems or summary is None:
        return None, problems, evidence
    return summary.status, [], evidence


# --------------------------------------------------------------------------- recovery


def recovery_ai(findings: list[dict[str, Any]]) -> str:
    """Template explanations for preserved validated findings, else an empty list.

    Uses the analyzer's deterministic templates when its dependencies import;
    with missing dependencies it stays usable and publishes ``[]`` rather than
    fabricating explanations. Findings are never invented here.
    """
    if not findings:
        return _json([])
    try:
        from valid import models as valid_models
        from valid import templates as valid_templates
        rebuilt = [valid_models.Finding.model_validate(item) for item in findings]
        return _json([item.model_dump(mode="json") for item in valid_templates.explain(rebuilt)])
    except Exception:
        return _json([])


def recovery_artifacts(stage: str, diagnostics: list[str], evidence: dict[str, Any]) -> dict[str, str]:
    """Conservative INCOMPLETE artifacts matching the canonical schemas; validated evidence is preserved."""
    coverage = {
        "required_failed_stages": [stage],
        "required_gaps": [],
        "optional_gaps": [],
        "evaluated_files": [],
        "diagnostics": list(diagnostics),
    }
    raw_checkov = evidence.get("raw_checkov.json") or {
        "status": "error",
        "tool": "checkov",
        "version": CHECKOV_VERSION,
        "failed_checks": [],
        "parsing_errors": [],
        "coverage": coverage,
        "return_code": None,
        "diagnostics": list(diagnostics),
    }
    raw_custom = evidence.get("raw_custom.json") or {"findings": [], "coverage": coverage}
    findings = evidence.get("findings.json", [])
    counts, categories = _tally(findings)
    summary = {
        "schema_version": "1.0.0",
        "status": "INCOMPLETE",
        "score": 0,
        "counts": counts,
        "category_counts": categories,
        "top_priority": None,
        "coverage": coverage,
        "reasons": [f"Required stage failed: {stage}", SCORE_UNAVAILABLE],
    }
    if findings:
        evidence_line = (
            f"{len(findings)} validated analyzer finding(s) are preserved in findings.json; "
            "they are not a complete review."
        )
    else:
        evidence_line = "No detector findings are reported because analysis did not complete. This is not a clean result."
    comment = "\n".join([
        MARKER,
        "## V.A.L.I.D. Review - INCOMPLETE",
        "",
        f"**Required analysis is incomplete: the {stage} stage failed in the CI scan wrapper.**",
        "",
        *[f"- {note}" for note in diagnostics],
        "",
        SCORE_UNAVAILABLE,
        evidence_line,
        "",
        "_Static evidence only. No deployment, merge, or change validation was performed by this report._",
    ]) + "\n"
    return {
        "raw_checkov.json": _json(raw_checkov),
        "raw_custom.json": _json(raw_custom),
        "findings.json": _json(findings),
        "ai.json": recovery_ai(findings),
        "comment.md": comment,
        "summary.json": _json(summary),
    }


def _set_aside(output: Path, artifacts: Path) -> None:
    """Move an unusable artifact directory out of the published path without deleting anything."""
    if not (artifacts.exists() or artifacts.is_symlink()):
        return
    index = 1
    while (output / f"{DISCARDED_PREFIX}{index}").exists():
        index += 1
    os.rename(artifacts, output / f"{DISCARDED_PREFIX}{index}")


def publish_recovery(output: Path, contents: dict[str, str]) -> None:
    artifacts = output / ARTIFACT_DIR
    _set_aside(output, artifacts)
    artifacts.mkdir()
    for name in ARTIFACTS:
        fd = os.open(artifacts / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents[name])
            handle.flush()
            os.fsync(handle.fileno())


def finalize(output: Path, record: dict[str, Any], *, stage: str | None, status: str | None,
             analyzer_exit: int | None, timed_out: bool, diagnostics: list[str], evidence: dict[str, Any]) -> int:
    record.update(analyzer_exit=analyzer_exit, timeout=timed_out, stage=stage)
    if stage is None and status is not None:
        wrapper_exit = STATUS_EXIT[status]
        record.update(validated=True, status=status, diagnostics=list(diagnostics))
    else:
        stage = stage or "artifact_validation"
        wrapper_exit = 1
        record.update(validated=False, status="INCOMPLETE", stage=stage, diagnostics=list(diagnostics))
        try:
            publish_recovery(output, recovery_artifacts(stage, diagnostics, evidence))
        except OSError as error:
            record["diagnostics"].append(f"recovery_publication failed ({type(error).__name__})")
    record.update(completed=True, wrapper_exit=wrapper_exit)
    try:
        write_meta(output, record)
    except OSError as error:
        _notice(f"The scan record could not be written ({type(error).__name__}).")
        return NOT_COMPLETED
    print(f"valid-scan: status={record['status']} validated={str(record['validated']).lower()} "
          f"wrapper_exit={wrapper_exit} stage={record['stage'] or 'none'}")
    return wrapper_exit


def _notice(reason: str) -> None:
    print(f"{MARKER}\n## V.A.L.I.D. Review - INCOMPLETE\n\n{reason}\n", file=sys.stderr)


# --------------------------------------------------------------------------- commands


def command_scan(args: argparse.Namespace) -> int:
    output, scan_path = Path(args.output), Path(args.scan_path)
    try:
        prepare_output(output, scan_path)
    except (OutputRefused, OSError) as error:
        reason = str(error) if isinstance(error, OutputRefused) else f"output directory unusable ({type(error).__name__})"
        _notice(f"No scan was run: {reason}. Existing files were left untouched.")
        return NOT_COMPLETED
    record = new_record(args.head_sha)
    try:
        write_meta(output, record)
    except OSError as error:
        _notice(f"No scan was run: the scan record could not be written ({type(error).__name__}).")
        return NOT_COMPLETED

    outcome = launch(args.python_bin, scan_path, output / ARTIFACT_DIR, max(1, args.timeout))
    status, problems, evidence = validate_artifacts(output / ARTIFACT_DIR, outcome["exit"])
    stage = outcome["stage"]
    diagnostics = list(outcome["diagnostics"])
    if stage is None and status is None:
        stage = "artifact_validation"
        diagnostics.extend(problems)
    return finalize(output, record, stage=stage, status=None if stage else status,
                    analyzer_exit=outcome["exit"], timed_out=outcome["timeout"],
                    diagnostics=diagnostics, evidence=evidence)


def _pending_layout(output: Path) -> dict[str, Any] | None:
    """Return this wrapper's unfinished record if ``output`` holds only its own layout, else None."""
    allowed = {META_NAME, ARTIFACT_DIR, f".{META_NAME}.tmp"}
    names = {entry.name for entry in output.iterdir()}
    if META_NAME not in names or any(n not in allowed and not n.startswith(DISCARDED_PREFIX) for n in names):
        return None
    try:
        record = json.loads(_read_regular(output / META_NAME).decode("utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(record, dict) and record.get("schema") == META_SCHEMA:
        return record
    return None


def command_recover(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        _notice("No recovery was recorded: the output path is not a usable directory.")
        return NOT_COMPLETED
    if output.exists() and any(output.iterdir()):
        record = _pending_layout(output)
        if record is None:
            _notice("No recovery was recorded: the output directory holds files this wrapper does not own.")
            return NOT_COMPLETED
        if record.get("completed") is True and record.get("wrapper_exit") in (0, 1):
            print("valid-scan: a completed scan record already exists; no recovery needed")
            return 0
        if record.get("head_sha") != args.head_sha:
            _notice("No recovery was recorded: the unfinished scan record belongs to another commit.")
            return NOT_COMPLETED
    else:
        try:
            prepare_output(output, None)
        except (OutputRefused, OSError) as error:
            _notice(f"No recovery was recorded ({type(error).__name__}).")
            return NOT_COMPLETED
    record = new_record(args.head_sha)
    diagnostics = [f"{args.stage} did not complete; the analyzer did not produce a validated result"]
    finalize(output, record, stage=args.stage, status=None, analyzer_exit=None, timed_out=False,
             diagnostics=diagnostics, evidence={})
    return 0 if record["completed"] else NOT_COMPLETED


def _head_sha(value: str) -> str:
    if not SHA_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("must be a full lowercase hexadecimal commit SHA")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ci_scan.py", description="Trusted CI wrapper for V.A.L.I.D. scans.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="run the analyzer and publish a validated scan record")
    scan.add_argument("--scan-path", required=True, help="Terraform directory from the pull-request head")
    scan.add_argument("--output", required=True, help="new or empty directory owned by this wrapper")
    scan.add_argument("--head-sha", required=True, type=_head_sha, help="exact pull-request head commit")
    scan.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="analyzer budget in seconds")
    scan.add_argument("--python-bin", default=sys.executable, help="interpreter with the reviewer installed")
    recover = commands.add_parser("recover", help="record an INCOMPLETE result when the scan could not run")
    recover.add_argument("--stage", required=True, choices=RECOVERY_STAGES, help="workflow stage that failed")
    recover.add_argument("--output", required=True, help="scan output directory")
    recover.add_argument("--head-sha", required=True, type=_head_sha, help="exact pull-request head commit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return command_scan(args)
    return command_recover(args)


if __name__ == "__main__":
    sys.exit(main())
