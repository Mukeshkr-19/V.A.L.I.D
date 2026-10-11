"""Runtime raw-artifact privacy and repeatability tests.

These tests pin the minimal retained-record contract of the Checkov adapter and
prove it on the real release:

* a canary placed in any field the adapter does not retain (source excerpts,
  definitions/context, evaluated values, unknown nested source data) never
  reaches a raw artifact, while detector identity and coverage are kept,
* retained free-text fields are sanitised (private paths and recognisable
  credential patterns removed) and required coverage failures survive,
* a real Checkov scan of a copied Terraform fixture carrying a synthetic
  literal secret canary publishes no artifact containing the canary while
  keeping every detector ID,
* real risky scans under different subprocess hash seeds are byte-identical for
  all six artifacts, with identical finding and evidence IDs, and ai.json
  validates against the real Explanation model with exactly one explanation
  per finding carrying that finding's evidence IDs and strength, and
* the frozen raw sample stays genuine and unchanged, and its runtime-sanitised
  result still validates against the real models.

No real secret is used anywhere: the canary is a deliberately synthetic,
non-credential marker. Secret material is never printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

import pytest
from pydantic import TypeAdapter

from valid.models import Explanation, Finding, RawScanResult, RiskSummary, ValidConfig
from valid.risk import summarize
from valid.scanners import checkov as adapter

ROOT = Path(__file__).resolve().parents[1]
FROZEN_SAMPLE = ROOT / "fixtures" / "raw" / "checkov-3.3.8.json"
RISKY = ROOT / "fixtures" / "risky"
FROZEN_SAMPLE_SHA256 = "a64fd76668f44179cbc11544266f5d2f9b002996ddc72aff9969fb12da3b35f2"
ARTIFACTS = (
    "raw_checkov.json",
    "raw_custom.json",
    "findings.json",
    "summary.json",
    "comment.md",
    "ai.json",
)
FINDINGS = TypeAdapter(list[Finding])
EXPLANATIONS = TypeAdapter(list[Explanation])

# Synthetic, non-credential canary. It is not a password, token or key: it only
# has to be a distinctive string that must never appear in a public artifact.
CANARY = "VALID-SYNTHETIC-CANARY-NOT-A-SECRET-4f2a"
# Split so this file never contains a literal key-shaped string.
FAKE_KEY_ID = "AKIA" + "ABCDEFGHIJKLMNOP"

TERRAFORM = 'resource "aws_security_group" "probe" {\n  name = "probe"\n}\n'

VENV_PATH = os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"])


def environment(path: str = VENV_PATH, hash_seed: str | None = None) -> dict[str, str]:
    """Subprocess environment for the CLI, optionally pinning the hash seed."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
    env.update(PATH=path, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    if hash_seed is None:
        env.pop("PYTHONHASHSEED", None)
    else:
        env["PYTHONHASHSEED"] = hash_seed
    return env


def _real_checkov() -> str | None:
    found = shutil.which("checkov")
    if found:
        return found
    candidate = ROOT / ".venv" / "bin" / "checkov"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


REAL_CHECKOV = _real_checkov()


def run_cli(*args: Any, env: dict[str, str] | None = None, timeout: int = 180):
    command = [sys.executable, "-P", "-m", "valid", *map(str, args)]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env if env is not None else environment(),
        timeout=timeout,
    )


def scan(source: Path, output: Path, **kwargs: Any):
    return run_cli("scan", "--path", source, "--output", output, **kwargs)


def scan_dir(tmp_path: Path, content: str = TERRAFORM) -> Path:
    root = tmp_path / "scan"
    root.mkdir(parents=True, exist_ok=True)
    (root / "main.tf").write_text(content, encoding="utf-8")
    return root


def stub_checkov(tmp_path: Path, stdout: str, exit_code: int = 0) -> list[str]:
    """A stub scanner executable that prints ``stdout`` and exits ``exit_code``."""
    script = tmp_path / "stub_raw_artifact_checkov.py"
    script.write_text(
        "import sys\n"
        f"sys.stdout.write({stdout!r})\n"
        f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)]


def envelope(
    failed: Sequence[dict[str, Any]] = (),
    passed: Sequence[dict[str, Any]] = (),
    skipped: Sequence[dict[str, Any]] = (),
) -> str:
    report = {
        "check_type": "terraform",
        "results": {
            "failed_checks": list(failed),
            "passed_checks": list(passed),
            "skipped_checks": list(skipped),
            "parsing_errors": [],
        },
        "summary": {
            "passed": len(passed),
            "failed": len(failed),
            "skipped": len(skipped),
            "parsing_errors": 0,
            "resource_count": len(failed) + len(passed),
        },
    }
    return json.dumps(report)


def dumped(result: RawScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), sort_keys=True)


def risk_status(result: RawScanResult, config: ValidConfig) -> str:
    return summarize([], result.coverage, config).status


def canary_check_record() -> dict[str, Any]:
    """One failed check whose unretained fields are full of canaries."""
    return {
        "check_id": "CKV_AWS_24",
        "bc_check_id": None,
        "check_name": "probe rule for canary retention",
        "check_result": {
            "result": "FAILED",
            "evaluated_keys": [
                "ingress/[0]/cidr_blocks",
                "engine",
                f"evaluated/{CANARY}",
                "resource_type",
            ],
            "evaluated_values": {f"value-{CANARY}": CANARY},
        },
        "code_block": [[1, f'  password = "{CANARY}"\n'], [2, f"  note = \"{CANARY}\"\n"]],
        "definition": {"context": [{"source": CANARY}], "raw": CANARY},
        "fixed_definition": [[1, CANARY]],
        "definition_context_file_path": "/scan/main.tf",
        "file_abs_path": "/scan/main.tf",
        "repo_file_path": "/scan/main.tf",
        "caller_file_path": "/scan/main.tf",
        "file_path": "/main.tf",
        "file_line_range": [1, 2],
        "resource": {
            "type": "aws_db_instance",
            "address": "aws_db_instance.main",
            "unknown_nested": {"canary": CANARY},
        },
        "resource_address": CANARY,
        "severity": "HIGH",
        "description": CANARY,
        "short_description": CANARY,
        "guideline": CANARY,
        "vulnerability_details": {"secret": [CANARY]},
        "details": [{"raw": CANARY}],
        "unknown_field": {"nested": {"deeper": [CANARY, {"key": CANARY}]}},
    }


# --------------------------------------------------------------------------- #
# minimal retained-record contract (stub scanner)
# --------------------------------------------------------------------------- #
def test_unretained_source_data_never_reaches_the_raw_result(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    payload = envelope(failed=[canary_check_record()], passed=[canary_check_record()])
    command = stub_checkov(tmp_path, payload, exit_code=1)

    result = adapter.run(root, ValidConfig(checkov_command=command))

    text = dumped(result)
    assert CANARY not in text
    for marker in (
        "code_block",
        "evaluated_keys",
        "evaluated_values",
        "definition",
        "fixed_definition",
        "vulnerability_details",
        "unknown_field",
        "resource_address",
        "description",
        "guideline",
        "file_abs_path",
        "repo_file_path",
        "caller_file_path",
        "definition_context_file_path",
    ):
        assert marker not in text, marker
    assert "/scan/main.tf" not in text


def test_retained_record_is_the_explicit_minimal_contract(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    payload = envelope(failed=[canary_check_record()])
    command = stub_checkov(tmp_path, payload, exit_code=1)

    result = adapter.run(root, ValidConfig(checkov_command=command))

    assert result.status == "complete"
    assert result.return_code == 1
    assert len(result.failed_checks) == 1
    record = result.failed_checks[0]
    assert set(record) == set(adapter.RETAINED_FAILED_CHECK_KEYS)
    assert record["check_id"] == "CKV_AWS_24"
    assert record["check_name"] == "probe rule for canary retention"
    assert record["severity"] == "HIGH"
    assert record["file_path"] == "main.tf"
    assert record["file_line_range"] == [1, 2]
    assert record["resource"] == {"type": "aws_db_instance", "address": "aws_db_instance.main"}
    # The unordered scanner result metadata is not retained at all, so no hash
    # seed can reorder it.
    assert "check_result" not in record
    # Detector evidence and coverage are kept.
    assert result.coverage.evaluated_files == ["main.tf"]
    assert result.coverage.required_gaps == []
    assert result.coverage.required_failed_stages == []
    assert result.diagnostics == []
    RawScanResult.model_validate(result.model_dump(mode="json"))


def test_bc_check_id_is_retained_as_the_rule_identity(tmp_path: Path) -> None:
    # Only the fallback id is supplied: identity must still be preserved, since
    # a lost rule id would drop a real finding.
    root = scan_dir(tmp_path)
    record = canary_check_record()
    record["check_id"] = None
    record["bc_check_id"] = "BC_AWS_SG_1"
    command = stub_checkov(tmp_path, envelope(failed=[record]), exit_code=1)

    result = adapter.run(root, ValidConfig(checkov_command=command))

    assert [c["check_id"] for c in result.failed_checks] == ["BC_AWS_SG_1"]


def test_failed_check_without_a_rule_id_fails_closed(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    anonymous = canary_check_record()
    anonymous["check_id"] = None
    anonymous["bc_check_id"] = None
    command = stub_checkov(tmp_path, envelope(failed=[anonymous]), exit_code=1)

    result = adapter.run(root, ValidConfig(checkov_command=command))

    assert result.status == "complete"
    assert result.failed_checks == []
    assert adapter.MALFORMED_RESULTS_GAP in result.coverage.required_gaps
    # The counter still matches the raw payload, so this is malformed data
    # rather than an invented missing-records gap.
    assert adapter.MISSING_RECORDS_GAP not in result.coverage.required_gaps
    assert any("no usable rule id" in note for note in result.diagnostics)
    assert risk_status(result, ValidConfig(checkov_command=command)) == "INCOMPLETE"


def test_retained_free_text_is_sanitized_and_gaps_survive(tmp_path: Path) -> None:
    root = scan_dir(tmp_path)
    private = str(root / "main.tf")
    record = canary_check_record()
    record["check_name"] = f"probe near {private} {FAKE_KEY_ID}"
    skipped = [{"check_id": f"CKV_PROBE {private} {FAKE_KEY_ID}", "file_path": "/main.tf"}]
    command = stub_checkov(
        tmp_path, envelope(failed=[record], skipped=skipped, passed=[canary_check_record()])
    )

    result = adapter.run(root, ValidConfig(checkov_command=command))

    text = dumped(result)
    assert private not in text
    assert str(root) not in text
    assert FAKE_KEY_ID not in text
    assert "<scan-root>" in text and "<redacted>" in text
    # The suppression is a required coverage failure and must be kept.
    assert adapter.SKIPPED_CHECKS_GAP in result.coverage.required_gaps
    assert any("not evaluated" in note for note in result.diagnostics)
    assert risk_status(result, ValidConfig(checkov_command=command)) == "INCOMPLETE"


# --------------------------------------------------------------------------- #
# frozen sample
# --------------------------------------------------------------------------- #
def test_frozen_sample_is_genuine_unchanged_and_sanitized_at_runtime(tmp_path: Path) -> None:
    assert FROZEN_SAMPLE.is_file()
    raw_bytes = FROZEN_SAMPLE.read_bytes()
    assert hashlib.sha256(raw_bytes).hexdigest() == FROZEN_SAMPLE_SHA256
    text = raw_bytes.decode("utf-8")
    # The capture is genuine: it still carries the source excerpts and the
    # unordered evaluated keys that the runtime artifact must not.
    assert '"code_block"' in text and '"evaluated_keys"' in text

    root = scan_dir(tmp_path)
    command = stub_checkov(tmp_path, text, exit_code=1)

    result = adapter.run(root, ValidConfig(checkov_command=command))

    assert result.status == "complete"
    assert result.return_code == 1
    ids = {record["check_id"] for record in result.failed_checks}
    assert "CKV_AWS_24" in ids
    assert len(result.failed_checks) == 16
    assert result.coverage.required_gaps == []
    assert result.coverage.required_failed_stages == []
    assert result.coverage.evaluated_files == ["main.tf"]
    for record in result.failed_checks:
        assert set(record) <= set(adapter.RETAINED_FAILED_CHECK_KEYS)
        assert not record["file_path"].startswith("/")
        assert ".." not in record["file_path"]
    artifact = dumped(result)
    assert "code_block" not in artifact
    assert "evaluated_keys" not in artifact
    assert "file_abs_path" not in artifact
    assert "definition_context_file_path" not in artifact
    assert "/scan/main.tf" not in artifact
    assert str(ROOT) not in artifact
    assert str(Path.home()) not in artifact
    RawScanResult.model_validate(result.model_dump(mode="json"))


@pytest.mark.parametrize("ordering", ["reverse", "rotate", "swap_graph_checks"])
def test_scanner_emission_order_does_not_change_raw_artifact(tmp_path: Path, ordering: str) -> None:
    original = json.loads(FROZEN_SAMPLE.read_text(encoding="utf-8"))
    variant = json.loads(json.dumps(original))
    reports = variant if isinstance(variant, list) else [variant]
    changed = False
    for report in reports:
        records = report["results"].get("failed_checks", [])
        if ordering == "reverse":
            records.reverse()
        elif ordering == "rotate" and records:
            records[:] = records[1:] + records[:1]
        elif ordering == "swap_graph_checks":
            positions = {record["check_id"]: index for index, record in enumerate(records)}
            if {"CKV2_AWS_30", "CKV2_AWS_41"} <= positions.keys():
                first, second = positions["CKV2_AWS_30"], positions["CKV2_AWS_41"]
                records[first], records[second] = records[second], records[first]
                changed = True
    if ordering == "swap_graph_checks":
        assert changed, "the genuine capture must contain the observed graph-check pair"
    assert variant != original
    root = scan_dir(tmp_path)
    baseline = adapter.run(root, ValidConfig(checkov_command=stub_checkov(tmp_path, json.dumps(original), 1)))
    reordered = adapter.run(root, ValidConfig(checkov_command=stub_checkov(tmp_path, json.dumps(variant), 1)))
    assert baseline.status == reordered.status == "complete"
    assert len(baseline.failed_checks) == len(reordered.failed_checks) == 16
    assert dumped(baseline) == dumped(reordered)


def test_record_order_preserves_duplicates_and_all_retained_fields(tmp_path: Path) -> None:
    base = canary_check_record()
    records = [
        {**base, "check_name": "same rule, variant A", "severity": None, "resource": "aws_security_group.open"},
        {**base, "check_name": "same rule, variant B", "severity": "HIGH", "resource": {"type": "aws_security_group", "address": "aws_security_group.open"}},
        {**base, "check_name": None, "severity": "LOW", "file_line_range": None, "resource": None},
    ]
    records.append(dict(records[0]))
    root = scan_dir(tmp_path)
    baseline = adapter.run(root, ValidConfig(checkov_command=stub_checkov(tmp_path, envelope(failed=records), 1)))
    reordered = adapter.run(root, ValidConfig(checkov_command=stub_checkov(tmp_path, envelope(failed=list(reversed(records))), 1)))
    assert baseline.status == reordered.status == "complete"
    assert len(baseline.failed_checks) == 4
    assert dumped(baseline) == dumped(reordered)
    assert sum(record["check_name"] == "same rule, variant A" for record in baseline.failed_checks) == 2
    assert {record["severity"] for record in baseline.failed_checks} == {None, "HIGH", "LOW"}


# --------------------------------------------------------------------------- #
# real Checkov and the real CLI
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(REAL_CHECKOV is None, reason="real checkov executable is required")
def test_real_scan_publishes_no_literal_secret_canary(tmp_path: Path) -> None:
    source = tmp_path / "src"
    shutil.copytree(RISKY, source)
    fixture = source / "main.tf"
    text = fixture.read_text(encoding="utf-8")
    assert text.count("= var.db_password") == 1
    fixture.write_text(
        text.replace("= var.db_password", f'= "{CANARY}"', 1), encoding="utf-8"
    )
    assert CANARY in fixture.read_text(encoding="utf-8")
    output = tmp_path / "out"

    result = scan(source, output)

    assert result.returncode == 1, result.stderr
    assert {path.name for path in output.iterdir()} == set(ARTIFACTS)
    for name in ARTIFACTS:
        assert CANARY.encode("utf-8") not in (output / name).read_bytes(), name

    raw = RawScanResult.model_validate_json((output / "raw_checkov.json").read_text(encoding="utf-8"))
    summary = RiskSummary.model_validate_json((output / "summary.json").read_text(encoding="utf-8"))
    assert raw.status == "complete"
    assert raw.coverage.evaluated_files == ["main.tf"]
    assert {"CKV_AWS_24", "CKV_AWS_293"} <= {record["check_id"] for record in raw.failed_checks}
    assert summary.status == "HIGH RISK"
    assert summary.coverage.required_gaps == []
    assert summary.coverage.required_failed_stages == []
    findings = FINDINGS.validate_json((output / "findings.json").read_text(encoding="utf-8"))
    assert {"CKV_AWS_24", "CKV_AWS_293"} <= {f.source.rule_id for f in findings}
    assert_ai_covers_findings(output, findings)


def assert_ai_covers_findings(output: Path, findings: Sequence[Finding]) -> None:
    """ai.json is schema-valid and explains each finding once, in order, with its own evidence."""
    explanations = EXPLANATIONS.validate_json((output / "ai.json").read_text(encoding="utf-8"))
    assert [item.finding_id for item in explanations] == [f.finding_id for f in findings]
    for explanation, finding in zip(explanations, findings):
        assert sorted(explanation.evidence_ids) == sorted(item.evidence_id for item in finding.evidence)
        assert explanation.evidence_strength == finding.evidence_strength


@pytest.mark.skipif(REAL_CHECKOV is None, reason="real checkov executable is required")
def test_real_risky_scans_are_byte_identical_across_hash_seeds(tmp_path: Path) -> None:
    outputs: list[Path] = []
    for index, seed in enumerate(("0", "1", "987654")):
        output = tmp_path / f"out{index}"
        result = scan(RISKY, output, env=environment(hash_seed=seed))
        assert result.returncode == 1, result.stderr
        outputs.append(output)

    baseline = {name: (outputs[0] / name).read_bytes() for name in ARTIFACTS}
    for output in outputs[1:]:
        for name in ARTIFACTS:
            assert (output / name).read_bytes() == baseline[name], (name, output.name)

    raw_text = (outputs[0] / "raw_checkov.json").read_text(encoding="utf-8")
    assert "code_block" not in raw_text
    assert "evaluated_keys" not in raw_text

    documents = [
        FINDINGS.validate_json((output / "findings.json").read_text(encoding="utf-8"))
        for output in outputs
    ]

    def identity(finding: Finding) -> tuple[Any, ...]:
        return (
            finding.finding_id,
            finding.fingerprint,
            tuple((item.kind, item.evidence_id) for item in finding.evidence),
        )

    first = [identity(finding) for finding in documents[0]]
    assert first
    assert first == [identity(finding) for finding in documents[1]]
    assert first == [identity(finding) for finding in documents[2]]
    for output, findings in zip(outputs, documents):
        assert_ai_covers_findings(output, findings)
