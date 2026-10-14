'use strict';
const fs = require('fs');
const path = require('path');
const MARKER = '<!-- valid-report -->';
const SHA = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const MAX_BYTES = 60000;

module.exports = async function publish({github, context, core}) {
  try {
    const head = process.env.HEAD_SHA || '';
    const number = Number(process.env.PR_NUMBER);
    if (!SHA.test(head) || !Number.isSafeInteger(number) || number <= 0) return;
    const root = process.env.REVIEW_DIR;
    if (!root || !fs.lstatSync(root).isDirectory() || fs.lstatSync(root).isSymbolicLink()) return;
    const file = path.join(root, 'comment.md');
    const info = fs.lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BYTES) return;
    let body = fs.readFileSync(file, 'utf8');
    if (!body.startsWith(MARKER + '\n## V.A.L.I.D. Review - ')) return;
    const footer = `\n\n_Advisory review for commit ${head}. The original scan check remains authoritative._\n`;
    const notice = '\n\n_Report preview shortened; complete advice is in the valid-ai-review artifact._\n';
    const limit = MAX_BYTES - Buffer.byteLength(footer + notice, 'utf8');
    const bytes = Buffer.from(body, 'utf8');
    if (bytes.length > limit) {
      let cut = limit;
      while (cut > 0 && (bytes[cut] & 0xc0) === 0x80) cut -= 1;
      body = bytes.subarray(0, cut).toString('utf8') + notice;
    }
    body += footer;
    const {owner, repo} = context.repo;
    const {data: pr} = await github.rest.pulls.get({owner, repo, pull_number:number});
    if (pr.state !== 'open' || !pr.head || pr.head.sha !== head || !pr.head.repo
        || pr.head.repo.full_name !== `${owner}/${repo}`) {
      core.info('AI comment skipped: PR closed or head changed.'); return;
    }
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, body);
    for (let page = 1; page <= 50; page += 1) {
      const {data: comments} = await github.rest.issues.listComments({owner, repo, issue_number:number, per_page:100, page});
      if (!Array.isArray(comments)) return;
      const existing = comments.find(c => c.user && c.user.login === 'github-actions[bot]'
        && c.user.type === 'Bot' && typeof c.body === 'string' && c.body.split('\n',1)[0] === MARKER);
      if (existing) {
        // Repeat the live-head check immediately before the comment write.
        const {data: current} = await github.rest.pulls.get({owner, repo, pull_number:number});
        if (current.state !== 'open' || !current.head || current.head.sha !== head) return;
        await github.rest.issues.updateComment({owner, repo, comment_id:existing.id, body});
        core.info('Updated the existing V.A.L.I.D. advisory report.'); return;
      }
      if (comments.length < 100) {
        core.info('AI comment skipped: original scan comment is unavailable. See advisory artifacts.'); return;
      }
    }
    core.warning('AI comment skipped: comment search exceeded its bound.');
  } catch (error) {
    core.warning('AI comment not updated (nonfatal): ' + (error && error.name ? error.name : 'Error'));
  }
};
