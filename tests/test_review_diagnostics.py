"""Fallback diagnostics retain only bounded numeric and controlled status fields."""
import json
import pytest
import jsonschema
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


def test_response_sized_batch_accepts_advice_and_preserves_unselected_findings():
    from test_fallback import _finding
    findings=[_finding(path='file-%02d.tf'%i,summary='Public SSH ingress') for i in range(12)]
    before=[f.model_dump_json() for f in findings]
    metrics={}
    def transport(url,headers,body,timeout):
        entries=json.loads(json.loads(body)['messages'][1]['content'])['findings']
        assert len(entries)==3
        assert all('options' not in entry for entry in entries)
        items=[]
        for entry in entries:
            item={key:entry[key] for key in ('finding_id','evidence_ids','evidence_strength')}
            item.update(title='Review this administration boundary',why_it_matters='Untrusted networks could attempt administration access.',recommended_action='Confirm the approved administration path, restrict ingress to it and rerun the scan.')
            items.append(item)
        return 200,json.dumps({'choices':[{'message':{'content':json.dumps(items)}}]}).encode()
    advice=explain.explain(findings,env=ENV,transport=transport,diagnostics=metrics)
    assert metrics['selected_issues']==3 and metrics['accepted_findings']==3
    assert [e.origin for e in advice]==['ai']*3+['template']*9
    assert [f.model_dump_json() for f in findings]==before


@pytest.mark.parametrize('provider,model,expected', [
    ('nebius','nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B',True),
    ('nebius','nvidia/another-model',False),
    ('openai_compatible','nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B',False),
])
def test_nano_thinking_control_is_scoped_to_the_exact_nebius_profile(provider,model,expected):
    f=finding(); seen=[]
    env={**ENV,'VALID_AI_PROVIDER':provider,'VALID_AI_MODEL':model,
         'VALID_AI_API_KEY':'TEST-ONLY-KEY',
         'VALID_AI_BASE_URL':'https://api.tokenfactory.us-central1.nebius.com/v1'}
    def transport(url,headers,body,timeout):
        payload=json.loads(body); seen.append(payload)
        assert payload['max_tokens']==2400
        assert ('chat_template_kwargs' in payload)==expected
        if expected:
            assert payload['chat_template_kwargs']=={'enable_thinking':False}
        return response(prose(f))
    advice=explain.explain([f],env=env,transport=transport)
    assert len(seen)==1 and advice[0].origin=='ai'


@pytest.mark.parametrize('priority,strength,required', [
    ('high','deterministic',False),
    ('unknown','deterministic',True),
    ('high','weak_heuristic',True),
])
def test_request_makes_uncertainty_requirement_explicit(priority,strength,required):
    f=finding(priority=priority,strength=strength); seen=[]
    def transport(url,headers,body,timeout):
        payload=json.loads(body)
        entry=json.loads(payload['messages'][1]['content'])['findings'][0]
        assert entry['requires_verification'] is required
        assert "'Verify whether'" in payload['messages'][0]['content']
        assert ('response_format' in payload) is required
        seen.append(entry)
        item=prose(f)
        if required:
            item.update(title='Does this administration boundary need review?',
                        why_it_matters='Unintended administration access could expose this resource.',
                        recommended_action='Verify whether the reported access matches the approved administration path before choosing a change.')
            schema=payload['response_format']['json_schema']['schema']
            jsonschema.validate([item],schema)
            bad={**item,'recommended_action':'Change the network.'}
            with pytest.raises(jsonschema.ValidationError): jsonschema.validate([bad],schema)
        return response(item)
    result=explain.explain([f],env=ENV,transport=transport)
    assert len(seen)==1 and result[0].origin=='ai'
    assert result[0].evidence_strength==strength


def test_uncertain_generic_provider_does_not_receive_model_specific_schema():
    f=finding(priority='unknown')
    _,body=explain._bounded_request(ENV['VALID_AI_MODEL'],[f],provider='openai_compatible')
    payload=json.loads(body)
    assert 'response_format' not in payload and 'chat_template_kwargs' not in payload
