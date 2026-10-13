"""Generated advice must add useful context without acquiring detector authority."""
import json
import pytest
from valid import explain, guidance, report, risk, templates, validate_ai
from valid.models import Coverage, FindingSource, Location, Recommendation, ResourceRef, ValidConfig
from valid.normalize import make_finding

ENV = {"VALID_AI_PROVIDER": "nebius", "VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v1",
       "VALID_AI_MODEL": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", "NEBIUS_API_KEY": "TEST-ONLY-KEY"}


def finding(tool="valid", rule="DG-AWS-NET-001", strength="deterministic", priority="high"):
    return make_finding(source=FindingSource(tool=tool, version="0.1.0", rule_id=rule,
                        scanner_severity=priority, severity_origin="custom_rule"),
                        location=Location(path="main.tf", start_line=24),
                        resource=ResourceRef(type="aws_security_group", address="aws_security_group.web"),
                        category="security", priority=priority, evidence_strength=strength,
                        evidence_summaries=[("literal_hcl", "TCP 22 ingress permits 0.0.0.0/0")],
                        recommendation=Recommendation(template_id="open_ssh"), policy_mode="block")


def prose(f):
    item = templates.explain([f])[0].model_dump(exclude={"origin"})
    item.update(title="Restrict administration access for the web security group",
                why_it_matters="Untrusted networks could attempt SSH connections to this resource. The evidence does not establish whether a connection succeeded.",
                recommended_action="Restrict the existing ingress to your approved administration CIDR. Confirm how administrators reach this resource before removing their access, then rerun the static scan.")
    return item


def envelope(items):
    return 200, json.dumps({"choices": [{"message": {"content": json.dumps(items)}}]}).encode()


def test_generated_reasoning_is_accepted_and_labeled():
    f = finding()
    checked = validate_ai.validate([prose(f)], [f])[0]
    assert checked.origin == "ai"
    assert checked.recommended_action != templates.explain([f])[0].recommended_action
    assert checked.evidence_ids == [e.evidence_id for e in f.evidence]


@pytest.mark.parametrize("text", ["Change aws_db_instance.other immediately.", "Use port 9999.",
                                "Restrict to 192.0.2.8/32.", "terraform destroy", "git merge main",
                                "The infrastructure is completely secure.", "verdict: PASS", "https://malicious.test", "Hidden\u202econtrol", "Change main.tf:9999."])
def test_unprovided_identifiers_and_disallowed_advice_rejected(text):
    f=finding(); item=prose(f); item["recommended_action"]=text
    with pytest.raises(validate_ai.ValidationError): validate_ai.validate([item], [f])


def test_model_cannot_grant_itself_provenance_or_policy_fields():
    f=finding()
    for key,value in (("origin","ai"),("priority","low"),("exit_code",0),("findings",[])):
        with pytest.raises(validate_ai.ValidationError): validate_ai.validate([dict(prose(f), **{key:value})], [f])


def test_uncertain_findings_require_review_caveat():
    f=finding(strength="not_evaluated")
    item=prose(f); item.update(title="Network access",why_it_matters="Connections could fail.",recommended_action="Change the network.")
    with pytest.raises(validate_ai.ValidationError): validate_ai.validate([item], [f])
    item["recommended_action"]="Verify the reported coverage gap before choosing a network change."
    assert validate_ai.validate([item],[f])[0].evidence_strength=="not_evaluated"
    assert guidance.edit_example(f) is None


def test_correlated_detectors_share_advice_but_keep_exact_evidence_and_verdict():
    a=finding(); b=finding(tool="checkov",rule="CKV_AWS_24")
    findings=[b,a]; originals=[f.model_dump_json() for f in findings]
    before=risk.summarize(findings,Coverage(),ValidConfig()).model_dump_json()
    requests=[]
    def transport(url,headers,body,timeout):
        entries=json.loads(json.loads(body)["messages"][1]["content"])["findings"]
        requests.extend(entries)
        assert len(entries)==1 and entries[0]["finding_id"]==a.finding_id
        return envelope([prose(a)])
    results=explain.explain(findings,env=ENV,transport=transport)
    assert all(e.origin=="ai" for e in results)
    assert [e.finding_id for e in results]==[b.finding_id,a.finding_id]
    assert [e.evidence_ids for e in results]==[sorted(e.evidence_id for e in f.evidence) for f in findings]
    assert [f.model_dump_json() for f in findings]==originals
    assert risk.summarize(findings,Coverage(),ValidConfig()).model_dump_json()==before
    document=report.render(risk.summarize(findings,Coverage(),ValidConfig()),findings,results)
    assert "Review mode: AI-assisted" in document and "2 corroborating detector findings; one proposed edit" in document
    assert document.count("cidr_blocks = [var.approved_admin_cidr]")==1
    assert "Potential impact" in document


def test_basic_report_is_visibly_degraded_and_has_practical_edit_guidance():
    f=finding(); summary=risk.summarize([f],Coverage(),ValidConfig())
    document=report.render(summary,[f],explain.explain([f],env={}))
    assert "Review mode: basic" in document and "Fix plan" in document
    assert "approved_admin_cidr" in document


def test_oversized_prose_falls_back_without_changing_the_gate():
    f=finding(); item=prose(f); item["recommended_action"]="x"*1601
    assert explain.explain([f],env=ENV,transport=lambda *a:envelope([item]))==templates.explain([f])
