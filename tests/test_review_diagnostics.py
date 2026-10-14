"""Fallback diagnostics retain only bounded numeric and controlled status fields."""
import json
from valid import explain, templates
from test_useful_ai import ENV, finding, prose


def response(item, **extra):
    return 200, json.dumps({'model':ENV['VALID_AI_MODEL'], 'choices':[{'finish_reason':'stop','message':{'content':json.dumps([item])}}], **extra}).encode()


def test_accepted_reply_records_safe_serving_and_identity_proof():
    f=finding(); metrics={}
    advice=explain.explain([f],env=ENV,transport=lambda *a:response(prose(f),usage={'total_tokens':123,'extra':'TEST-ONLY-KEY'}),diagnostics=metrics)
    assert advice[0].origin=='ai'
    assert metrics['http_status']==200 and metrics['response_model_matches_requested']
    assert metrics['accepted_findings']==1 and metrics['attempts']==1 and metrics['finish_reason']=='stop'
    assert metrics['usage']=={'total_tokens':123} and 'TEST-ONLY-KEY' not in json.dumps(metrics)


def test_truncated_json_is_not_accepted_and_keeps_length_reason():
    f=finding(); metrics={}
    raw=json.dumps({'choices':[{'finish_reason':'length','message':{'content':'[{"finding_id":'}}]}).encode()
    assert explain.explain([f],env=ENV,transport=lambda *a:(200,raw),diagnostics=metrics)==templates.explain([f])
    assert metrics['failure_reason']=='response_format' and metrics['finish_reason']=='length'
    assert metrics['accepted_findings']==0


def test_invalid_advice_logs_only_controlled_failure_code():
    f=finding(); metrics={}; item=prose(f); item['recommended_action']='Change aws_db_instance.unprovided.'
    explain.explain([f],env=ENV,transport=lambda *a:response(item),diagnostics=metrics)
    assert metrics['failure_reason']=='advice_validation' and metrics['validation_reason']=='resource_reference'
    assert 'unprovided' not in json.dumps(metrics)


def test_provider_error_body_never_enters_diagnostics():
    f=finding(); metrics={}
    explain.explain([f],env=ENV,transport=lambda *a:(401,b'CANARY_SECRET_123 provider-error-payload'),diagnostics=metrics)
    assert metrics['http_status']==401 and metrics['failure_reason']=='provider_status'
    assert 'CANARY' not in json.dumps(metrics) and '/Users' not in json.dumps(metrics)


def test_missing_key_has_no_request_and_explicit_reason():
    metrics={}
    explain.explain([finding()],env={},transport=lambda *a:(_ for _ in ()).throw(AssertionError('network')),diagnostics=metrics)
    assert metrics['attempts']==0 and metrics['failure_reason']=='not_configured'
