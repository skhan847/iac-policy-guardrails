// Posts (or updates) a single policy report comment on the pull request.
// Called from .github/workflows/pr-checks.yml via actions/github-script.
const fs = require('fs');
const path = require('path');

const MARKER = '<!-- iac-policy-report -->';
const MAX_BODY = 60000;

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function planSummary(file) {
  try {
    const text = fs.readFileSync(file, 'utf8');
    const line = text.split('\n').find((l) => /^(Plan:|No changes\.)/.test(l.trim()));
    return line ? line.trim() : 'Plan summary not found.';
  } catch {
    return 'Plan output not available.';
  }
}

module.exports = async ({ github, context, workdir, outcome }) => {
  const results = readJson(path.join(workdir, 'policy.json')) || [];
  const failures = results.flatMap((r) => r.failures || []).map((f) => f.msg);
  const warnings = results.flatMap((r) => r.warnings || []).map((w) => w.msg);
  const passed = outcome === 'success' && failures.length === 0;

  const lines = [
    MARKER,
    `## ${passed ? '✅' : '❌'} Terraform policy check`,
    '',
    `**Plan:** ${planSummary(path.join(workdir, 'plan.txt'))}`,
    '',
    `| Result | Count |`,
    `|---|---|`,
    `| Denied (blocks merge) | ${failures.length} |`,
    `| Warnings | ${warnings.length} |`,
    '',
  ];

  if (failures.length) {
    lines.push('### Denied', '', ...failures.map((m) => `- ${m}`), '');
  }
  if (warnings.length) {
    lines.push('### Warnings', '', ...warnings.map((m) => `- ${m}`), '');
  }
  if (!passed) {
    lines.push(
      `> Fix the findings above, or follow [docs/exceptions.md](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/blob/main/docs/exceptions.md) ` +
        'to request a time-boxed exception.',
      '',
    );
  }
  lines.push(`<sub>Commit ${(context.payload.pull_request?.head?.sha || context.sha).slice(0, 7)} · run [#${context.runNumber}](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})</sub>`);

  let body = lines.join('\n');
  if (body.length > MAX_BODY) {
    body = body.slice(0, MAX_BODY) + '\n\n…truncated; see the workflow log for the full report.';
  }

  const { owner, repo } = context.repo;
  const issue_number = context.issue.number;
  const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number });
  const existing = comments.find((c) => c.user?.type === 'Bot' && c.body?.includes(MARKER));

  if (existing) {
    await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
  } else {
    await github.rest.issues.createComment({ owner, repo, issue_number, body });
  }
};
