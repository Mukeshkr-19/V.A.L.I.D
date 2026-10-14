'use strict';
// Artifact data never supplies executable code, PR identity or checkout refs.
const SHA = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const WORKFLOW = '.github/workflows/valid.yml';

module.exports = async function guard({ github, context, core }) {
  const { owner, repo } = context.repo;
  const runId = context.payload.workflow_run && context.payload.workflow_run.id;
  if (!Number.isSafeInteger(runId) || runId <= 0) throw new Error('Invalid run identity');
  const { data: run } = await github.rest.actions.getWorkflowRun({ owner, repo, run_id: runId });
  if (run.event !== 'pull_request' || run.path !== WORKFLOW || run.status !== 'completed'
      || !['success', 'failure'].includes(run.conclusion) || !SHA.test(run.head_sha || '')) {
    core.info('AI review skipped: source run is not an eligible completed PR scan.');
    return;
  }
  // pull_requests can be empty on real workflow_run payloads; resolve through the API.
  const { data: associated } = await github.rest.repos.listPullRequestsAssociatedWithCommit({
    owner, repo, commit_sha: run.head_sha, per_page: 100,
  });
  const defaultBranch = context.payload.repository.default_branch;
  if (!Array.isArray(associated) || associated.length >= 100) return;
  const matching = associated.filter(pr => pr.state === 'open' && pr.head && pr.head.sha === run.head_sha
    && pr.base && pr.base.repo && pr.base.repo.full_name === `${owner}/${repo}` && pr.base.ref === defaultBranch);
  if (matching.length !== 1) { core.info('AI review skipped: no unique current PR for this commit.'); return; }
  const number = matching[0].number;
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error('Invalid PR identity');
  const { data: pr } = await github.rest.pulls.get({ owner, repo, pull_number: number });
  if (pr.state !== 'open' || !pr.head || pr.head.sha !== run.head_sha || !pr.base
      || !SHA.test(pr.base.sha || '') || pr.base.ref !== defaultBranch
      || !pr.base.repo || pr.base.repo.full_name !== `${owner}/${repo}`) return;
  const headRepo = pr.head.repo;
  if (!headRepo || headRepo.full_name !== `${owner}/${repo}` || !pr.user || !pr.user.login) {
    core.info('AI review skipped: only repository-owned PR branches are enabled.'); return;
  }
  const { data: access } = await github.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username: pr.user.login });
  if (!['admin', 'maintain', 'write'].includes(access.permission)) {
    core.info('AI review skipped: PR author does not have repository write permission.'); return;
  }
  if (!headRepo || !headRepo.owner || !/^[A-Za-z0-9_.-]+$/.test(headRepo.owner.login)
      || !/^[A-Za-z0-9_.-]+$/.test(headRepo.name)) return;
  // A PR-modified scan workflow could forge artifacts; do not give it privileged review.
  const [base, head] = await Promise.all([
    github.rest.repos.getContent({ owner, repo, path: WORKFLOW, ref: pr.base.sha }),
    github.rest.repos.getContent({ owner: headRepo.owner.login, repo: headRepo.name, path: WORKFLOW, ref: pr.head.sha }),
  ]);
  if (!base.data || !head.data || !SHA.test(base.data.sha || '') || base.data.sha !== head.data.sha) {
    core.warning('AI review skipped: the PR changes the scan workflow. Review that change separately.'); return;
  }
  const { data: result } = await github.rest.actions.listWorkflowRunArtifacts({ owner, repo, run_id: runId, per_page: 100 });
  if (!Array.isArray(result.artifacts) || !Number.isSafeInteger(result.total_count)
      || result.total_count < 0 || result.total_count >= 100
      || result.artifacts.length !== result.total_count) return;
  const artifacts = result.artifacts.filter(a => a.name === 'valid-scan' && !a.expired);
  if (artifacts.length !== 1 || !Number.isSafeInteger(artifacts[0].size_in_bytes)
      || artifacts[0].size_in_bytes < 0
      || artifacts[0].size_in_bytes > 8 * 1024 * 1024) {
    core.warning('AI review skipped: scan artifact is missing, ambiguous or oversized.'); return;
  }
  core.setOutput('approved', 'true');
  core.setOutput('pr_number', String(number));
  core.setOutput('head_sha', pr.head.sha);
};
