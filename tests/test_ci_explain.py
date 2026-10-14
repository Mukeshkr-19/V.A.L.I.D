"""Advisory enrichment never consumes PR code or rewrites gate evidence."""
import importlib.util
import json
from pathlib import Path
import pytest
from valid import explain, risk, report, templates
from valid.models import Coverage, CustomScanResult, RawScanResult, ValidConfig
from test_useful_ai import finding, prose

SCRIPT=Path(__file__).resolve().parents[1]/"scripts/ci_explain.py"
spec=importlib.util.spec_from_file_location("ci_explain",SCRIPT)
ci_explain=importlib.util.module_from_spec(spec); spec.loader.exec_module(ci_explain)
HEAD="a"*40


def record(root, summary=None):
    f=finding(); findings=[f]
    summary=summary or risk.summarize(findings,Coverage(),ValidConfig())
    root.mkdir(); folder=root/"artifacts"; folder.mkdir()
    models={"raw_checkov.json":RawScanResult(status="complete"),"raw_custom.json":CustomScanResult(findings=findings),"summary.json":summary}
    for name,model in models.items(): (folder/name).write_text(model.model_dump_json())
    (folder/"findings.json").write_text(json.dumps([f.model_dump(mode="json")]))
    (folder/"ai.json").write_text(json.dumps([e.model_dump(mode="json") for e in templates.explain(findings)]))
    (folder/"comment.md").write_text(report.render(summary,findings,templates.explain(findings)))
    exitcode=0 if summary.status in ("PASS","REVIEW") else 1
    (root/"scan_meta.json").write_text(json.dumps({"schema":"valid-scan-meta/1","head_sha":HEAD,"completed":True,"validated":True,"status":summary.status,"wrapper_exit":exitcode,"analyzer_exit":exitcode}))
    return f


def snapshot(root): return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_generated_advice_preserves_every_original_byte(tmp_path,monkeypatch):
    root=tmp_path/"scan"; f=record(root); before=snapshot(root)
    generated=templates.explain([f])[0].model_copy(update={**prose(f),"origin":"ai"})
    monkeypatch.setattr(explain,"explain",lambda findings,**kwargs:[generated])
    out=tmp_path/"review"
    assert ci_explain.enrich(root,out,HEAD)=="ai"
    assert snapshot(root)==before
    assert {p.name for p in out.iterdir()}=={"ai.json","comment.md","review_meta.json"}
    assert "Review - HIGH RISK" in (out/"comment.md").read_text()
    assert "Review mode: AI-assisted" in (out/"comment.md").read_text()


def test_missing_key_is_explicit_basic_review(tmp_path,monkeypatch):
    root=tmp_path/"scan"; record(root); monkeypatch.setenv("VALID_AI_PROVIDER","disabled")
    assert ci_explain.enrich(root,tmp_path/"out",HEAD)=="basic"
    assert "Review mode: basic" in (tmp_path/"out/comment.md").read_text()


@pytest.mark.parametrize("mutation",["wrong_head","not_validated","wrong_exit","extra_file","symlink","wrong_counts"])
def test_invalid_scan_cannot_reach_provider(tmp_path,monkeypatch,mutation):
    root=tmp_path/"scan"; record(root); out=tmp_path/"out"
    monkeypatch.setattr(explain,"explain",lambda *a,**k:pytest.fail("provider was called"))
    meta=json.loads((root/"scan_meta.json").read_text())
    if mutation=="wrong_head": meta["head_sha"]="b"*40
    elif mutation=="not_validated": meta["validated"]=False
    elif mutation=="wrong_exit": meta["analyzer_exit"]=0
    elif mutation=="extra_file": (root/"artifacts/attack.py").write_text("raise SystemExit")
    elif mutation=="symlink":
        original=root/"artifacts/findings.json"; backup=root/"findings-backup.json"
        original.rename(backup); original.symlink_to(backup)
    elif mutation=="wrong_counts":
        path=root/"artifacts/summary.json"; data=json.loads(path.read_text()); data["counts"]["high"]=99; path.write_text(json.dumps(data))
    (root/"scan_meta.json").write_text(json.dumps(meta))
    with pytest.raises((ValueError,OSError)):ci_explain.enrich(root,out,HEAD)
    assert not out.exists()


def test_existing_output_is_preserved(tmp_path):
    root=tmp_path/"scan"; record(root); out=tmp_path/"out"; out.mkdir(); (out/"personal.txt").write_text("preserve")
    with pytest.raises(ValueError):ci_explain.enrich(root,out,HEAD)
    assert (out/"personal.txt").read_text()=="preserve"


def test_incomplete_scan_never_gets_ai_assurances(tmp_path,monkeypatch):
    root=tmp_path/"scan"; f=finding()
    summary=risk.summarize([f],Coverage(required_gaps=["unresolved expression"]),ValidConfig())
    record(root,summary)
    monkeypatch.setattr(explain,"explain",lambda *a,**k:pytest.fail("provider was called"))
    with pytest.raises(ValueError):ci_explain.enrich(root,tmp_path/"out",HEAD)
