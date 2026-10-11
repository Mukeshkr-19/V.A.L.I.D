"""Command-line entry point: scan a Terraform directory and write review artifacts."""

from __future__ import annotations

import argparse
import json
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Any

MARKER = "<!-- valid-report -->"
POLICY_FILE: Any = resources.files("valid").joinpath("data", "checkov_severity.yaml")
REQUIRED_POLICY_IDS = ("CKV_AWS_24", "CKV_AWS_293")
# summary.json is published last so an interrupted publication never leaves a verdict without its report.
ARTIFACTS = ("raw_checkov.json", "raw_custom.json", "findings.json", "comment.md", "ai.json", "summary.json")
SCORE_UNAVAILABLE = "Risk score unavailable: the risk engine failed, so no score or top priority was computed."
COVERAGE_FIELDS = ("required_failed_stages", "required_gaps", "optional_gaps", "evaluated_files", "diagnostics")


class UsageError(Exception):
    """Malformed command-line invocation."""


class OutputError(Exception):
    """The selected output directory cannot be used safely."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(f"{self.format_usage().strip()}\n{self.prog}: error: {message}")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m valid", description="Deterministic Terraform pull-request risk review.")
    commands = parser.add_subparsers(dest="command", required=True, metavar="scan", parser_class=_Parser)
    scan = commands.add_parser("scan", help="scan a Terraform source directory")
    scan.add_argument("--path", required=True, help="Terraform source directory to scan")
    scan.add_argument("--output", required=True, help="new or empty directory for report artifacts")
    return parser


def _incomplete_notice(reason: str) -> str:
    return f"{MARKER}\n## V.A.L.I.D. Review - INCOMPLETE\n\n{reason}\n"


def _failure(stage: str, error: BaseException) -> tuple[str, str]:
    return stage, f"cli: {stage} failed ({type(error).__name__})"


def prepare_output(output: Path, scan_root: Path) -> Path:
    """Create or adopt an empty, non-symlink output directory outside the scan input."""
    if output.is_symlink():
        raise OutputError("output path is a symbolic link")
    if output.exists():
        if not output.is_dir():
            raise OutputError("output path exists and is not a directory")
        if any(output.iterdir()):
            raise OutputError("output directory is not empty; refusing to overwrite existing files")
    resolved = output.resolve()
    if scan_root.exists() and (resolved == scan_root or scan_root in resolved.parents):
        raise OutputError("output directory must not be inside the scanned input")
    if not output.exists():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir()
    return output


def _remove_if_same(path: Path, identity: tuple[int, int]) -> None:
    try:
        info = os.lstat(path)
        if (info.st_dev, info.st_ino) == identity:
            os.unlink(path)
    except OSError:
        pass


def publish_artifacts(directory: Path, contents: dict[str, str]) -> None:
    """Publish all artifacts as one set of new files, or roll back every file this call created.

    Files are staged under exclusive temporary names, then hard-linked to names that must not
    already exist. Rollback removes only links and temporaries whose inode this call created, so
    pre-existing or concurrently created files are never deleted or overwritten.
    """
    staged: list[tuple[str, Path, tuple[int, int]]] = []
    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        for name in ARTIFACTS:
            temp = directory / f".{name}.{os.getpid()}.tmp"
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            info = os.fstat(fd)
            staged.append((name, temp, (info.st_dev, info.st_ino)))
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(contents[name])
                handle.flush()
                os.fsync(handle.fileno())
        for name, temp, identity in staged:
            os.link(temp, directory / name)
            published.append((directory / name, identity))
    except BaseException:
        for final, identity in reversed(published):
            _remove_if_same(final, identity)
        raise
    finally:
        for _, temp, identity in staged:
            _remove_if_same(temp, identity)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def merge_coverage(coverage_cls: Any, *coverages: Any) -> Any:
    merged: dict[str, list[str]] = {field: [] for field in COVERAGE_FIELDS}
    for coverage in coverages:
        for field in COVERAGE_FIELDS:
            for item in getattr(coverage, field):
                if item not in merged[field]:
                    merged[field].append(item)
    return coverage_cls(**merged)


def load_policy(models: Any, yaml: Any) -> Any:
    data = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    config = models.ValidConfig.model_validate(data)
    missing = [rule for rule in REQUIRED_POLICY_IDS if rule not in config.checkov_severity_map]
    if missing:
        raise ValueError("required Checkov policy mappings are missing")
    return config


def emergency_summary(models: Any, findings: list[Any], coverage: Any) -> Any:
    """Conservative INCOMPLETE summary built without the risk engine: tallies only, no assessment."""
    counts = {severity: 0 for severity in models.SEVERITIES}
    category_counts = {category: 0 for category in models.CATEGORIES}
    for finding in findings:
        counts[finding.priority] += 1
        category_counts[finding.category] += 1
    stages = sorted(set(coverage.required_failed_stages))
    return models.RiskSummary(
        status="INCOMPLETE",
        score=0,
        counts=counts,
        category_counts=category_counts,
        top_priority=None,
        coverage=coverage,
        reasons=[f"Required stage failed: {stage}" for stage in stages] + [SCORE_UNAVAILABLE],
    )


def fallback_comment(summary: Any, prior_status: str | None, stage: str, score_available: bool = True) -> str:
    lines = [
        MARKER,
        "## V.A.L.I.D. Review - " + summary.status,
        "",
        "**Required analysis is incomplete: the " + stage + " stage failed, so the full report could not be rendered.**",
    ]
    if prior_status is not None:
        lines.append("Deterministic scan verdict before the reporting failure: " + prior_status + ".")
    if not score_available:
        lines.append(SCORE_UNAVAILABLE)
    lines.extend([
        "",
        "**Severity counts:** " + " · ".join(f"{key}: {summary.counts[key]}" for key in sorted(summary.counts)),
        "",
        "Findings and coverage details are available in findings.json and summary.json.",
        "",
        "_Static evidence only. No deployment, merge, or change validation was performed by this report._",
    ])
    return "\n".join(lines) + "\n"


def run_scan(scan_root: Path, output: Path) -> int:
    try:
        import yaml

        from valid import explain, models, normalize, report, risk, templates
        from valid.scanners import checkov, literal_hcl
    except ImportError as error:
        print(_incomplete_notice(f"A required component could not be imported ({type(error).__name__})."), file=sys.stderr)
        return 1

    Coverage = models.Coverage
    failures: list[tuple[str, str]] = []

    def orchestration() -> Any:
        return Coverage(
            required_failed_stages=[stage for stage, _ in failures],
            diagnostics=[note for _, note in failures],
        )

    try:
        config = load_policy(models, yaml)
    except Exception as error:
        failures.append(_failure("policy_load", error))
        config = models.ValidConfig()

    if not scan_root.is_dir():
        failures.append(("input_validation", "cli: input_validation failed (scan path is not a readable directory)"))

    try:
        raw_checkov = checkov.run(scan_root, config)
    except Exception as error:
        stage, note = _failure("checkov_scan", error)
        raw_checkov = models.RawScanResult(
            status="error",
            coverage=Coverage(required_failed_stages=[stage]),
            diagnostics=[note],
        )

    custom_failures: list[tuple[str, str]] = []
    parse_coverage = Coverage()
    custom = models.CustomScanResult()
    try:
        parsed = literal_hcl.parse(scan_root, config)
        parse_coverage = parsed.coverage
        try:
            custom = literal_hcl.scan(parsed.parsed, config)
        except Exception as error:
            custom_failures.append(_failure("custom_rules", error))
    except Exception as error:
        custom_failures.append(_failure("literal_hcl_parse", error))
    custom_stage_coverage = Coverage(
        required_failed_stages=[stage for stage, _ in custom_failures],
        diagnostics=[note for _, note in custom_failures],
    )
    raw_custom = models.CustomScanResult(
        findings=custom.findings,
        coverage=merge_coverage(Coverage, parse_coverage, custom.coverage, custom_stage_coverage),
    )

    checkov_usable = raw_checkov.status == "complete" and not raw_checkov.parsing_errors
    if not checkov_usable and not raw_checkov.coverage.required_failed_stages:
        failures.append(("checkov_scan", "cli: checkov_scan failed (scanner result is not a completed scan)"))
    findings = list(custom.findings)
    if checkov_usable:
        try:
            findings = normalize.normalize(raw_checkov, list(custom.findings), config)
        except Exception as error:
            failures.append(_failure("normalization", error))

    def combined() -> Any:
        return merge_coverage(Coverage, parse_coverage, custom.coverage, custom_stage_coverage, raw_checkov.coverage, orchestration())

    risk_failed = False

    def summarize() -> Any:
        nonlocal risk_failed
        if not risk_failed:
            try:
                return risk.summarize(findings, combined(), config)
            except Exception as error:
                risk_failed = True
                failures.append(_failure("risk_summary", error))
        return emergency_summary(models, findings, combined())

    summary = summarize()

    # Advisory explanations run after the deterministic verdict and before the
    # report, which renders exactly the list published as ai.json. A provider
    # failure only selects the deterministic templates; a template failure is a
    # genuine report_generation failure. Neither changes findings or score.
    def explanation_service() -> list[Any]:
        try:
            return explain.explain(findings)
        except Exception:
            return templates.explain(findings)

    explanations: list[Any] = []
    if risk_failed:
        try:
            explanations = explanation_service()
        except Exception:
            explanations = []
        comment = fallback_comment(summary, None, "risk_summary", score_available=False)
    else:
        try:
            explanations = explanation_service()
            comment = report.render(summary, findings, explanations)
            if not comment.startswith(MARKER + "\n"):
                raise ValueError("rendered report is missing the report marker")
        except Exception as error:
            prior_status = summary.status
            failures.append(_failure("report_generation", error))
            summary = summarize()
            comment = fallback_comment(summary, prior_status, "report_generation", score_available=not risk_failed)

    contents = {
        "raw_checkov.json": _json(raw_checkov.model_dump(mode="json")),
        "raw_custom.json": _json(raw_custom.model_dump(mode="json")),
        "findings.json": _json([finding.model_dump(mode="json") for finding in findings]),
        "ai.json": _json([explanation.model_dump(mode="json") for explanation in explanations]),
        "summary.json": _json(summary.model_dump(mode="json")),
        "comment.md": comment,
    }
    try:
        publish_artifacts(output, contents)
    except OSError as error:
        print(
            _incomplete_notice(
                f"Report artifacts could not be published ({type(error).__name__}). "
                "Files created by this run were rolled back; treat this run as having no verdict."
            ),
            file=sys.stderr,
        )
        return 1
    return risk.exit_code(summary.status)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as error:
        print(str(error), file=sys.stderr)
        return 1
    except SystemExit as exit_request:
        return 0 if exit_request.code in (0, None) else 1

    scan_root = Path(args.path)
    try:
        output = prepare_output(Path(args.output), scan_root.resolve())
    except (OutputError, OSError) as error:
        reason = str(error) if isinstance(error, OutputError) else f"output directory could not be created ({type(error).__name__})"
        print(_incomplete_notice(f"No scan was run: {reason}."), file=sys.stderr)
        return 1
    try:
        return run_scan(scan_root, output)
    except Exception as error:
        print(_incomplete_notice(f"The scan stopped unexpectedly ({type(error).__name__})."), file=sys.stderr)
        return 1
