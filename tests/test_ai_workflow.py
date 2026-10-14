"""Privileged advice must never execute PR code or expose keys to scan steps."""
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/valid-ai.yml'


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def test_exact_privileged_boundary_and_default_checkout():
    data = workflow()
    assert data[True] == {'workflow_run': {'workflows': ['V.A.L.I.D. PR Review'], 'types': ['completed']}}
    assert data['permissions'] == {}
    assert set(data['jobs']) == {'review'}
    job = data['jobs']['review']
    assert job['permissions'] == {'contents': 'read', 'actions': 'read', 'pull-requests': 'write'}
    assert job['timeout-minutes'] == 6
    steps = job['steps']
    checkouts = [s for s in steps if s.get('uses', '').startswith('actions/checkout@')]
    assert len(checkouts) == 1
    assert checkouts[0]['with'] == {'ref': '${{ github.sha }}', 'path': 'trusted-default', 'persist-credentials': False}
    for step in steps:
        if 'uses' in step:
            assert re.fullmatch(r'actions/[a-z-]+@[0-9a-f]{40}', step['uses'])
        assert 'pr-head' not in step.get('run', '')
        assert 'head_branch' not in step.get('run', '')
    guard = next(s for s in steps if s.get('id') == 'guard')
    assert 'trusted-default/scripts/ai_review_guard.js' in guard['with']['script']
    download = next(s for s in steps if s.get('uses', '').startswith('actions/download-artifact@'))
    assert download['if'] == "steps.guard.outputs.approved == 'true'"
    assert download['with']['run-id'] == '${{ github.event.workflow_run.id }}'
    assert download['with']['name'] == 'valid-scan'


def test_secret_is_confined_to_guarded_evidence_enrichment():
    data = workflow()
    assert 'env' not in data and 'env' not in data['jobs']['review']
    steps = data['jobs']['review']['steps']
    secret_steps = [s for s in steps if 'secrets.' in json.dumps(s)]
    assert len(secret_steps) == 1 and secret_steps[0]['id'] == 'enrich'
    enrich = secret_steps[0]
    assert enrich['if'] == "steps.guard.outputs.approved == 'true'"
    assert enrich['continue-on-error'] is True
    assert enrich['env']['VALID_AI_MODEL'] == 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B'
    assert enrich['env']['NEBIUS_API_KEY'] == '${{ secrets.NEBIUS_API_KEY }}'
    assert enrich['env']['VALID_AI_BASE_URL'] == 'https://api.tokenfactory.us-central1.nebius.com/v1'
    assert 'python -I -B trusted-default/scripts/ci_explain.py' in enrich['run']
    assert steps.index(enrich) > next(i for i,s in enumerate(steps) if 'Install only' in s['name'])
    publisher = next(s for s in steps if 'post_ai_comment.js' in s.get('with', {}).get('script', ''))
    assert publisher['if'] == "steps.enrich.outcome == 'success'"
    assert publisher['continue-on-error'] is True
    assert 'NEBIUS_API_KEY' not in publisher.get('env', {})
    upload = next(s for s in steps if s.get('uses', '').startswith('actions/upload-artifact@'))
    assert upload['with']['name'] == 'valid-ai-review'
    assert upload['with']['path'] != '${{ runner.temp }}/valid-ai-input'


JS = r'''
const publish = require(process.argv[1]);
const scenario = process.argv[2], root = process.argv[3];
process.env.HEAD_SHA = 'a'.repeat(40); process.env.PR_NUMBER = '4'; process.env.REVIEW_DIR = root;
delete process.env.GITHUB_STEP_SUMMARY;
const calls=[], warnings=[]; let reads=0;
const pr={state:'open',head:{sha:process.env.HEAD_SHA,repo:{full_name:'owner/repo'}}};
if(scenario==='stale') pr.head.sha='b'.repeat(40);
if(scenario==='closed') pr.state='closed';
if(scenario==='fork') pr.head.repo.full_name='other/repo';
const human={id:1,user:{login:'person',type:'User'},body:'<!-- valid-report -->\nHuman report'};
const bot={id:2,user:{login:'github-actions[bot]',type:'Bot'},body:'<!-- valid-report -->\nOld report'};
const unmarked={id:3,user:{login:'github-actions[bot]',type:'Bot'},body:'Other bot text'};
const github={rest:{pulls:{get:async()=>{reads++;return {data:scenario==='race'&&reads>1?{...pr,head:{...pr.head,sha:'c'.repeat(40)}}:pr};}},issues:{
listComments:async args=>{calls.push(['list',args]);if(scenario==='pagination'&&args.page===1)return {data:Array(100).fill(human)};return {data:scenario==='missing'?[human,unmarked]:[human,unmarked,bot]};},
updateComment:async args=>{if(scenario==='denied')throw new Error('API failure');calls.push(['update',args]);},
createComment:async()=>{throw new Error('AI must never create a competing sticky comment');}
}}};
publish({github,context:{repo:{owner:'owner',repo:'repo'}},core:{info:()=>{},warning:s=>warnings.push(s)}}).then(()=>console.log(JSON.stringify({calls,warnings})));
'''


def publish(tmp_path, scenario, text='<!-- valid-report -->\n## V.A.L.I.D. Review - HIGH RISK\n\n**Review mode: AI-assisted.**\n'):
    root = tmp_path / 'review'
    root.mkdir()
    (root/'comment.md').write_text(text)
    if scenario == 'symlink':
        (root/'comment.md').rename(root/'target')
        (root/'comment.md').symlink_to(root/'target')
    node = shutil.which('node')
    assert node, 'Node is required for workflow tests'
    result = subprocess.run([node, '-e', JS, str(ROOT/'scripts/post_ai_comment.js'), scenario, str(root)],
                            capture_output=True, text=True, timeout=10, check=True)
    return json.loads(result.stdout)


def test_publisher_updates_only_existing_bot_report(tmp_path):
    result = publish(tmp_path, 'valid')
    writes = [args for name,args in result['calls'] if name=='update']
    assert len(writes)==1 and writes[0]['comment_id']==2
    assert 'original scan check remains authoritative' in writes[0]['body']
    assert len(writes[0]['body'].encode()) <= 60000


@pytest.mark.parametrize('scenario',['stale','closed','fork','race','missing','symlink'])
def test_stale_or_untrusted_comments_are_never_written(tmp_path, scenario):
    result = publish(tmp_path, scenario)
    assert not any(name=='update' for name,args in result['calls'])


def test_comment_permission_failure_is_nonfatal(tmp_path):
    assert publish(tmp_path,'denied')['warnings']


def test_publisher_searches_later_pages(tmp_path):
    result=publish(tmp_path,'pagination')
    assert [args['page'] for name,args in result['calls'] if name=='list']==[1,2]
    assert any(name=='update' for name,args in result['calls'])


def test_report_bound_is_valid_utf8_and_retains_commit_footer(tmp_path):
    text='<!-- valid-report -->\n## V.A.L.I.D. Review - HIGH RISK\n'+'é'*29000
    result=publish(tmp_path,'valid',text)
    body=next(args['body'] for name,args in result['calls'] if name=='update')
    assert len(body.encode())<=60000 and '\ufffd' not in body and 'a'*40 in body


def test_all_three_workflows_pass_actionlint():
    binary=shutil.which('actionlint')
    if not binary: pytest.skip('actionlint is not installed on PATH')
    result=subprocess.run([binary,str(WORKFLOW),str(ROOT/'.github/workflows/valid.yml'),str(ROOT/'.github/workflows/ci.yml')],capture_output=True,text=True,timeout=15)
    assert result.returncode==0, result.stdout+result.stderr
