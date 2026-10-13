"""Enrich a verified scan record using trusted installed reviewer code only.

No PR source is read or executed. Original scan artifacts and the gate record
are immutable; generated advisory outputs are published separately.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

ARTIFACTS = ("raw_checkov.json", "raw_custom.json", "findings.json", "comment.md", "ai.json", "summary.json")
MAX_INPUT_BYTES = 8 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def read_regular(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
        raise ValueError("scan input is not a bounded regular file")
    return path.read_bytes()


def enrich(record: Path, output: Path, head_sha: str) -> str:
    from pydantic import TypeAdapter
    from valid import explain, models, report

    if not SHA.fullmatch(head_sha) or record.is_symlink() or not record.is_dir():
        raise ValueError("scan identity is invalid")
    if output.exists() or output.is_symlink() or record.resolve() == output.resolve() or record.resolve() in output.resolve().parents:
        raise ValueError("output must be new and separate from the scan record")
    artifacts = record / "artifacts"
    if artifacts.is_symlink() or not artifacts.is_dir() or {p.name for p in artifacts.iterdir()} != set(ARTIFACTS):
        raise ValueError("scan artifact set is invalid")
    snapshots = {name: read_regular(artifacts / name) for name in ARTIFACTS}
    meta_bytes = read_regular(record / "scan_meta.json")
    meta = json.loads(meta_bytes)
    if not isinstance(meta, dict) or meta.get("schema") != "valid-scan-meta/1" or meta.get("head_sha") != head_sha:
        raise ValueError("scan record belongs to a different commit")
    if meta.get("completed") is not True or meta.get("validated") is not True:
        raise ValueError("scan did not complete validation")
    summary = models.RiskSummary.model_validate_json(snapshots["summary.json"])
    expected_exit = {"PASS": 0, "REVIEW": 0, "HIGH RISK": 1}.get(summary.status)
    if expected_exit is None or meta.get("status") != summary.status or any(
            type(meta.get(key)) is not int or meta[key] != expected_exit for key in ("wrapper_exit", "analyzer_exit")):
        raise ValueError("scan verdict or exit record is inconsistent")
    findings = TypeAdapter(list[models.Finding]).validate_json(snapshots["findings.json"])
    counts = {key: sum(f.priority == key for f in findings) for key in models.SEVERITIES}
    categories = {key: sum(f.category == key for f in findings) for key in models.CATEGORIES}
    if counts != summary.counts or categories != summary.category_counts:
        raise ValueError("scan counts disagree with findings")
    if summary.coverage.required_failed_stages or summary.coverage.required_gaps:
        raise ValueError("required analysis has gaps")
    models.RawScanResult.model_validate_json(snapshots["raw_checkov.json"])
    models.CustomScanResult.model_validate_json(snapshots["raw_custom.json"])
    old_advice = TypeAdapter(list[models.Explanation]).validate_json(snapshots["ai.json"])
    # The reporter verifies exact finding/evidence identity for both old and new advice.
    report.render(summary, findings, old_advice)
    if not snapshots["comment.md"].decode("utf-8").startswith("<!-- valid-report -->\n## V.A.L.I.D. Review - " + summary.status + "\n"):
        raise ValueError("original report does not match the scan verdict")
    advice = explain.explain(findings)
    comment = report.render(summary, findings, advice)
    for name, before in snapshots.items():
        if read_regular(artifacts / name) != before:
            raise ValueError("scan artifacts changed during review")
    if read_regular(record / "scan_meta.json") != meta_bytes:
        raise ValueError("scan record changed during review")
    contents = {"comment.md": comment,
                "ai.json": json.dumps([e.model_dump(mode="json") for e in advice],sort_keys=True,indent=2)+"\n"}
    output.mkdir(parents=True)
    created = []
    try:
        for name, text in contents.items():
            path = output / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            info = os.fstat(fd); created.append((path, info.st_dev, info.st_ino))
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush(); os.fsync(handle.fileno())
    except BaseException:
        for path, device, inode in created:
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == (device, inode): path.unlink()
            except OSError:
                pass
        raise
    return "ai" if any(e.origin == "ai" for e in advice) else "basic"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Add advisory AI review to a verified scan, without changing its gate.")
    parser.add_argument("--record", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--head-sha", required=True)
    args=parser.parse_args(argv)
    try:
        mode=enrich(Path(args.record),Path(args.output),args.head_sha)
    except Exception as error:
        print("valid-ai-review: skipped ("+type(error).__name__+")",file=sys.stderr)
        return 1
    print("valid-ai-review: mode="+mode+"; deterministic scan record preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
