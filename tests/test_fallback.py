"""Provider-failure fallback: every failure mode yields complete template explanations."""

import json
import socket

import pytest

from valid import explain, redact, templates
from valid.models import FindingSource, Location, Recommendation, ResourceRef
from valid.normalize import make_finding

BASE_ENV = {
    "VALID_AI_PROVIDER": "openai_compatible",
    "VALID_AI_BASE_URL": "https://ai.example.test",
    "VALID_AI_MODEL": "test-model",
    "VALID_AI_API_KEY": "TEST-KEY-CANARY-9",
}


def _finding(summary="public ingress to port 22", path="main.tf"):
    return make_finding(
        source=FindingSource(
            tool="valid", version="0.1.0", rule_id="DG-AWS-NET-001",
            scanner_severity="high", severity_origin="custom_rule",
        ),
        location=Location(path=path, start_line=1, end_line=2),
        resource=ResourceRef(type="aws_security_group", address="aws_security_group.open"),
        category="security", priority="high", evidence_strength="deterministic",
        evidence_summaries=[("literal_hcl", summary)],
        recommendation=Recommendation(template_id="open_ssh"),
        policy_mode="block",
    )


def _templates(findings):
    return [item.model_dump(mode="json") for item in templates.explain(findings)]


def _dumped(result):
    return [item.model_dump(mode="json") for item in result]


def _envelope(items):
    return 200, json.dumps({"choices": [{"message": {"content": json.dumps(items)}}]}).encode("utf-8")


def _valid_items(findings):
    return [
        {
            "finding_id": finding.finding_id,
            "evidence_ids": sorted(item.evidence_id for item in finding.evidence),
            "title": templates.explain([finding])[0].title,
            "why_it_matters": templates.explain([finding])[0].why_it_matters,
            "recommended_action": templates.explain([finding])[0].recommended_action,
            "evidence_strength": finding.evidence_strength,
        }
        for finding in findings
    ]


def test_no_key_is_template_only_with_zero_network_calls():
    calls = []

    def _forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("template-only mode must not call any transport")

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env={}, transport=_forbidden)) == _templates(findings)
    assert calls == []


def test_no_key_succeeds_with_sockets_disabled(monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("no-key path must not open sockets")

    monkeypatch.setattr(socket, "socket", _blocked)
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env={})) == _templates(findings)


@pytest.mark.parametrize("env", [
    {},
    {"VALID_AI_PROVIDER": "disabled"},
    {"VALID_AI_PROVIDER": "none"},
    {**BASE_ENV, "VALID_AI_PROVIDER": "mystery-vendor"},
    {**BASE_ENV, "VALID_AI_MODEL": ""},
    {**BASE_ENV, "VALID_AI_BASE_URL": "http://ai.example.test"},
    {**BASE_ENV, "VALID_AI_BASE_URL": "not-a-url"},
    {**BASE_ENV, "VALID_AI_API_KEY": "", "NEBIUS_API_KEY": "", "OPENAI_API_KEY": ""},
])
def test_absent_or_invalid_config_falls_back_without_network(env):
    def _forbidden(*args, **kwargs):
        raise AssertionError("invalid config must not call any transport")

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=env, transport=_forbidden)) == _templates(findings)


def test_valid_simulated_response_is_accepted():
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=dict(BASE_ENV), transport=lambda *a, **k: _envelope(_valid_items(findings)))) == _templates(findings)


def test_transient_failure_retries_once_then_falls_back():
    calls = []

    def _flaky(*args, **kwargs):
        calls.append(args)
        raise explain.TransportError("simulated timeout")

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=dict(BASE_ENV), transport=_flaky)) == _templates(findings)
    assert len(calls) == 2


def test_transient_status_then_success():
    calls = []

    def _then_ok(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            return 500, b"{}"
        findings = [_finding()]
        return _envelope(_valid_items(findings))

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=dict(BASE_ENV), transport=_then_ok)) == _templates(findings)
    assert len(calls) == 2


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404])
def test_non_transient_status_fails_without_retry(status):
    calls = []

    def _fixed(*args, **kwargs):
        calls.append(args)
        return status, b"{}"

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=dict(BASE_ENV), transport=_fixed)) == _templates(findings)
    assert len(calls) == 1


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"{}", b"x" * (65 * 1024)])
def test_unusable_responses_fall_back(raw):
    findings = [_finding()]
    transport = lambda *a, **k: (200, raw)  # noqa: E731
    assert _dumped(explain.explain(findings, env=dict(BASE_ENV), transport=transport)) == _templates(findings)


def test_timeouts_stay_within_shared_budget():
    seen = []

    def _recording(url, headers, body, timeout):
        seen.append(timeout)
        raise TimeoutError("simulated timeout")

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=dict(BASE_ENV), transport=_recording)) == _templates(findings)
    assert 0 < len(seen) <= 2 and all(0 < value <= explain.SHARED_BUDGET_SECONDS for value in seen)


def test_key_never_enters_the_payload():
    bodies = []

    def _capture(url, headers, body, timeout):
        bodies.append(body)
        assert headers["Authorization"] == "Bearer TEST-KEY-CANARY-9"
        findings = [_finding()]
        return _envelope(_valid_items(findings))

    explain.explain([_finding()], env=dict(BASE_ENV), transport=_capture)
    assert bodies and b"TEST-KEY-CANARY-9" not in b"".join(bodies)


def test_secret_canaries_absent_from_payload_and_ai_json():
    canary_summary = "evidence AKIAIOSFODNN7CANARYX with api_key=CANARY-SECRET-2 at /Users/someone/repo"
    bodies = []

    def _capture(url, headers, body, timeout):
        bodies.append(body)
        payload = json.loads(body.decode("utf-8"))
        entries = json.loads(payload["messages"][1]["content"])["findings"]
        items = [
            {
                "finding_id": entry["finding_id"],
                "evidence_ids": entry["evidence_ids"],
                "title": entry["options"]["title"],
                "why_it_matters": entry["options"]["why_it_matters"],
                "recommended_action": entry["options"]["recommended_action"],
                "evidence_strength": entry["evidence_strength"],
            }
            for entry in entries
        ]
        return _envelope(items)

    findings = [_finding(summary=canary_summary)]
    result = explain.explain(findings, env=dict(BASE_ENV), transport=_capture)
    assert _dumped(result) == _templates(findings)
    payload = bodies[0].decode("utf-8")
    assert b"[redacted]" in bodies[0]
    assert b"AKIAIOSFODNN7CANARYX" not in bodies[0]
    assert b"CANARY-SECRET-2" not in bodies[0]
    assert "/Users/someone/repo" not in payload


def test_partial_top10_selection_templates_the_rest():
    findings = [_finding(summary="public ingress excerpt %d" % i, path="file-%d.tf" % i) for i in range(12)]
    seen = {}

    def _capture(url, headers, body, timeout):
        payload = json.loads(body.decode("utf-8"))
        entries = json.loads(payload["messages"][1]["content"])["findings"]
        seen["count"] = len(entries)
        return _envelope(_valid_items(findings[:10]))

    result = explain.explain(findings, env=dict(BASE_ENV), transport=_capture)
    assert seen["count"] == 10
    assert _dumped(result) == _templates(findings)


def test_unknown_provider_is_the_selected_provider_and_is_refused():
    env = {**BASE_ENV, "VALID_AI_PROVIDER": "mystery-vendor"}
    assert env["VALID_AI_PROVIDER"] == "mystery-vendor"
    assert explain._configure(env) is None
    assert explain._configure(BASE_ENV) is not None


NEBIUS_ENV = {
    "VALID_AI_PROVIDER": "nebius",
    "VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v1/",
    "VALID_AI_MODEL": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
    "NEBIUS_API_KEY": "TEST-KEY-CANARY-NEB",
}


@pytest.mark.parametrize("base", [
    "https://api.tokenfactory.us-central1.nebius.com/v1/",
    "https://api.tokenfactory.us-central1.nebius.com/v1",
])
def test_nebius_accepts_only_the_documented_endpoint_and_explicit_model(base):
    config = explain._configure({**NEBIUS_ENV, "VALID_AI_BASE_URL": base})
    assert config == {
        "provider": "nebius",
        "endpoint": "https://api.tokenfactory.us-central1.nebius.com/v1/chat/completions",
        "model": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
        "key": "TEST-KEY-CANARY-NEB",
    }


@pytest.mark.parametrize("override", [
    {"VALID_AI_BASE_URL": "https://not-nebius.example.test/v1"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.nebius.com/v1"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com.attacker.test/v1"},
    {"VALID_AI_BASE_URL": "https://evil.api.tokenfactory.us-central1.nebius.com/v1"},
    {"VALID_AI_BASE_URL": "http://api.tokenfactory.us-central1.nebius.com/v1"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v2"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v1/extra"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com:8443/v1"},
    {"VALID_AI_BASE_URL": "https://user@api.tokenfactory.us-central1.nebius.com/v1"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v1?x=1"},
    {"VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v1//"},
    {"VALID_AI_MODEL": "unrelated-model"},
    {"VALID_AI_MODEL": "meta-llama/Llama-3.3-70B-Instruct"},
    {"VALID_AI_MODEL": "nvidia/"},
    {"VALID_AI_MODEL": "NVIDIA/Nemotron"},
    {"VALID_AI_MODEL": "nvidia/../other"},
    {"VALID_AI_MODEL": "nvidia/model name"},
    {"VALID_AI_MODEL": ""},
    {"NEBIUS_API_KEY": ""},
    {"NEBIUS_API_KEY": "bad\r\nX-Injected: 1"},
])
def test_nebius_rejects_other_hosts_and_models_without_network(override):
    def _forbidden(*args, **kwargs):
        raise AssertionError("rejected Nebius config must not call any transport")

    env = {**NEBIUS_ENV, **override}
    assert explain._configure(env) is None
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=env, transport=_forbidden)) == _templates(findings)


@pytest.mark.parametrize("base", [
    "https://",
    "https:///v1",
    "https://user:pass@ai.example.test",
    "https://ai.example.test:notaport",
    "https://ai.example.test:99999",
    "https://ai.example.test/v1?query=1",
    "https://ai.example.test/v1?",
    "https://ai.example.test/v1#fragment",
    "https://ai.example.test/a/../b",
    "https://ai.example.test//v1",
    "https://ai example.test",
    "https://ai.example.test/\x00",
    "ftp://ai.example.test",
    "//ai.example.test",
])
def test_generic_provider_rejects_malformed_endpoints_without_network(base):
    def _forbidden(*args, **kwargs):
        raise AssertionError("malformed endpoint must not call any transport")

    env = {**BASE_ENV, "VALID_AI_BASE_URL": base}
    assert explain._configure(env) is None
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=env, transport=_forbidden)) == _templates(findings)


def test_generic_provider_remains_supported_on_any_explicit_https_host():
    config = explain._configure({**BASE_ENV, "VALID_AI_BASE_URL": "https://llm.internal.example.test:8443/openai/v1/"})
    assert config is not None
    assert config["endpoint"] == "https://llm.internal.example.test:8443/openai/v1/chat/completions"
    assert config["provider"] == "openai_compatible"


def _many_evidence_finding(count):
    base = _finding()
    dumped = base.model_dump(mode="json")
    template = dumped["evidence"][0]
    dumped["evidence"] = [
        {**template, "evidence_id": "e_%064x" % index, "summary": "public ingress observation %d" % index}
        for index in range(count)
    ]
    return type(base).model_validate(dumped)


def test_finding_with_thousands_of_evidence_ids_is_never_sent():
    huge = _many_evidence_finding(5000)
    assert len({item.evidence_id for item in huge.evidence}) == 5000
    calls = []

    def _forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("an out-of-bounds finding must not be sent")

    assert _dumped(explain.explain([huge], env=dict(BASE_ENV), transport=_forbidden)) == _templates([huge])
    assert calls == []


def test_oversized_finding_keeps_its_template_while_others_are_sent_in_order():
    huge = _many_evidence_finding(5000)
    normal = _finding(summary="public ingress to port 3389", path="other.tf")
    findings = [huge, normal]
    bodies = []

    def _capture(url, headers, body, timeout):
        bodies.append(body)
        entries = json.loads(json.loads(body.decode("utf-8"))["messages"][1]["content"])["findings"]
        assert [entry["finding_id"] for entry in entries] == [normal.finding_id]
        return _envelope(_valid_items([normal]))

    result = explain.explain(findings, env=dict(BASE_ENV), transport=_capture)
    assert _dumped(result) == _templates(findings)
    assert [item.finding_id for item in result] == [huge.finding_id, normal.finding_id]
    assert len(bodies) == 1 and len(bodies[0]) <= explain.MAX_REQUEST_BYTES


def test_request_byte_cap_drops_findings_instead_of_truncating():
    long_summary = "public ingress observation " + "x" * 3000
    findings = []
    for index in range(10):
        finding = _many_evidence_finding(explain.MAX_EVIDENCE_PER_FINDING)
        dumped = finding.model_dump(mode="json")
        dumped["finding_id"] = "f_%064x" % index
        dumped["location"]["path"] = "file-%d.tf" % index
        for item in dumped["evidence"]:
            item["summary"] = long_summary
        findings.append(type(finding).model_validate(dumped))
    bodies = []

    def _capture(url, headers, body, timeout):
        bodies.append(body)
        entries = json.loads(json.loads(body.decode("utf-8"))["messages"][1]["content"])["findings"]
        by_id = {finding.finding_id: finding for finding in findings}
        for entry in entries:
            assert entry["evidence_ids"] == sorted(item.evidence_id for item in by_id[entry["finding_id"]].evidence)
        return _envelope(_valid_items([by_id[entry["finding_id"]] for entry in entries]))

    result = explain.explain(findings, env=dict(BASE_ENV), transport=_capture)
    assert _dumped(result) == _templates(findings)
    assert len(bodies) == 1 and len(bodies[0]) <= explain.MAX_REQUEST_BYTES
    sent = json.loads(json.loads(bodies[0].decode("utf-8"))["messages"][1]["content"])["findings"]
    assert 0 < len(sent) < 10
    assert [entry["finding_id"] for entry in sent] == [finding.finding_id for finding in findings[: len(sent)]]


def test_redaction_happens_before_summary_truncation():
    secret = "AKIA" + "IOSFODNN7CANARYZ"
    summary = "x" * (explain.MAX_SUMMARY_CHARS - 6) + " " + secret
    bodies = []

    def _capture(url, headers, body, timeout):
        bodies.append(body)
        return 500, b"{}"

    explain.explain([_finding(summary=summary)], env=dict(BASE_ENV), transport=_capture)
    assert bodies and b"AKIA" not in bodies[0]


def test_redaction_limits_are_documented_not_universal():
    assert "cannot recognize every arbitrary secret" in redact.__doc__
    assert redact.redact_text("nothing secret here") == "nothing secret here"
    assert "[redacted]" in redact.redact_text("token CANARY_X9 end")
    with pytest.raises(TypeError):
        redact.redact_text(None)
