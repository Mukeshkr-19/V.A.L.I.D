"""Real JavaScript guard execution with bounded API doubles, no GitHub writes."""
import json
from pathlib import Path
import shutil
import subprocess
import pytest

SCRIPT=Path(__file__).resolve().parents[1]/"scripts/ai_review_guard.js"
JS=r'''
const guard = require(process.argv[1]);
const scenario = process.argv[2];
const outputs = {}, calls = [];
const head = 'a'.repeat(40), base = 'b'.repeat(40), blob = 'c'.repeat(40);
const repo = { full_name:'owner/repo', name:'repo', owner:{login:'owner'} };
const pr = { number:4,state:'open',user:{login:'owner'},head:{sha:head,repo},base:{sha:base,ref:'main',repo} };
if(scenario==='fork') pr.head.repo={full_name:'outsider/repo',name:'repo',owner:{login:'outsider'}};
const github={rest:{actions:{
 getWorkflowRun:async args=>{calls.push(['run',args]);return {data:{id:1,event:scenario==='wrong_event'?'push':'pull_request',path:'.github/workflows/valid.yml',status:'completed',conclusion:scenario==='cancelled'?'cancelled':'failure',head_sha:head}};},
 listWorkflowRunArtifacts:async args=>{calls.push(['artifacts',args]);return {data:{total_count:1,artifacts:[{name:'valid-scan',expired:scenario==='expired',size_in_bytes:scenario==='oversized'?9000000:10000}]}};}
},repos:{
 listPullRequestsAssociatedWithCommit:async args=>{calls.push(['associated',args]);return {data:[pr]};},
 getContent:async args=>{calls.push(['content',args]);return {data:{sha:scenario==='workflow_changed'&&args.ref===head?'d'.repeat(40):blob}};},
 getCollaboratorPermissionLevel:async args=>{calls.push(['permission',args]);return {data:{permission:scenario==='untrusted_author'?'read':'write'}};}
},pulls:{get:async args=>{calls.push(['pr',args]);return {data:scenario==='stale'?{...pr,head:{...pr.head,sha:'e'.repeat(40)}}:pr};}}}};
const context={repo:{owner:'owner',repo:'repo'},payload:{workflow_run:{id:1,pull_requests:[]},repository:{default_branch:'main'}}};
const core={info:()=>{},warning:()=>{},setOutput:(key,value)=>outputs[key]=value};
guard({github,context,core}).then(()=>console.log(JSON.stringify({outputs,calls}))).catch(e=>{console.error(e.name);process.exit(1);});
'''


def execute(scenario):
    node=shutil.which("node"); assert node,"Node is required for workflow security checks"
    result=subprocess.run([node,"-e",JS,str(SCRIPT),scenario],capture_output=True,text=True,timeout=10,check=True)
    return json.loads(result.stdout)


def test_real_guard_handles_empty_pull_requests_metadata():
    result=execute("valid")
    assert result["outputs"]=={"approved":"true","pr_number":"4","head_sha":"a"*40}
    reads=[args for name,args in result["calls"] if name=="content"]
    assert {args["ref"] for args in reads}=={"a"*40,"b"*40}
    assert all(args["path"]==".github/workflows/valid.yml" for args in reads)


@pytest.mark.parametrize("scenario",["fork","wrong_event","cancelled","expired","oversized","workflow_changed","stale","untrusted_author"])
def test_ineligible_runs_never_get_approval(scenario):
    assert execute(scenario)["outputs"]=={}
