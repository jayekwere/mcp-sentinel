import { spawnSync, execFileSync } from 'node:child_process';
import {
  openSync,
  closeSync,
  writeFileSync,
  readFileSync,
  copyFileSync,
  existsSync,
  readdirSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
const results = [];
function run(name, command, args, file, allowed = [0]) {
  console.log(`Running ${name}`);
  const fd = openSync('evidence/' + file, 'w');
  const result = spawnSync(command, args, { stdio: ['ignore', fd, fd], env: process.env });
  closeSync(fd);
  if (file.endsWith('.txt'))
    writeFileSync(
      'evidence/' + file,
      readFileSync('evidence/' + file, 'utf8').replace(/[ \t]+$/gm, ''),
    );
  results.push({ name, exit: result.status });
  if (!allowed.includes(result.status))
    throw new Error(`${name} failed (${result.status}); see evidence/${file}`);
}
run('verify', 'npm', ['run', 'verify'], 'verify.txt');
run('coverage', 'npm', ['run', 'test:coverage'], 'coverage.txt');
run('demo', 'npm', ['run', 'demo', '--', '--write'], 'demo.txt');
run('browser', 'npm', ['run', 'test:browser'], 'browser.txt');
copyFileSync('test-results/dashboard-desktop.png', 'docs/dashboard.png');
copyFileSync('test-results/dashboard-mobile.png', 'docs/dashboard-mobile.png');
run('container build', 'docker', ['build', '-t', 'mcp-sentinel:local', '.'], 'container-build.txt');
run(
  'container smoke',
  process.execPath,
  ['scripts/container-smoke.mjs', 'mcp-sentinel:local'],
  'container-smoke.txt',
);
run('dependency audit', 'npm', ['audit', '--json'], 'dependencies.json');
const actionlint = process.env.ACTIONLINT_PATH ?? 'actionlint';
const gitleaks = process.env.GITLEAKS_PATH ?? 'gitleaks';
run('actionlint version', actionlint, ['-version'], 'actionlint-version.txt');
run('workflow lint', actionlint, [], 'workflows.txt');
run('gitleaks version', gitleaks, ['version'], 'gitleaks-version.txt');
run(
  'secret scan',
  gitleaks,
  ['git', '--no-banner', '--redact', '--log-opts=--all'],
  'gitleaks.txt',
);
run('content policy', process.execPath, ['scripts/check-content.mjs'], 'content-policy.txt');
const paths = [];
const walk = (dir) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path);
    else paths.push(path);
  }
};
for (const dir of ['src', 'test', 'scripts', 'web', '.github']) walk(dir);
paths.push(
  '.gitleaks.toml',
  'Dockerfile',
  '.dockerignore',
  'compose.yaml',
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'tsconfig.web.json',
  'playwright.config.ts',
);
const manifest = Object.fromEntries(
  paths.sort().map((p) => [p, createHash('sha256').update(readFileSync(p)).digest('hex')]),
);
writeFileSync('evidence/source-manifest.json', JSON.stringify(manifest, null, 2) + '\n');
const coverage = readFileSync('evidence/coverage.txt', 'utf8');
const counts = Object.fromEntries(
  ['tests', 'pass', 'fail', 'skipped'].map((k) => [
    k,
    coverage.match(new RegExp('(?:ℹ|#) ' + k + ' (\\d+)'))?.[1] ?? 'unknown',
  ]),
);
const coverageRow =
  coverage
    .split('\n')
    .find((l) => /all files/.test(l))
    ?.trimEnd() ?? 'See coverage.txt for the exercised-file coverage table.';
const browser =
  readFileSync('evidence/browser.txt', 'utf8').match(/(\d+) passed/)?.[1] ?? 'unknown';
const deps = JSON.parse(readFileSync('evidence/dependencies.json', 'utf8')).metadata.vulnerabilities
  .total;
const date = new Intl.DateTimeFormat('en-CA', {
  timeZone: 'America/Vancouver',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
}).format(new Date());
writeFileSync(
  'evidence/VALIDATION.md',
  `# Release validation\n\nGenerated on ${date} by \`npm run evidence\`. All results below come from executed commands against the source hashes in [source-manifest.json](source-manifest.json). Host Node ${process.versions.node}; the container build independently runs tests on Node 24.\n\n| Check | Observed result | Evidence |\n| --- | --- | --- |\n| Format, strict types, automated tests, build and demo | Passed | [verify.txt](verify.txt) |\n| Automated coverage run | ${counts.pass} passed, ${counts.fail} failed, ${counts.skipped} skipped (${counts.tests} tests) | [coverage.txt](coverage.txt) |\n| Browser | ${browser} passed, desktop and mobile, no page errors | [browser.txt](browser.txt), [desktop](../docs/dashboard.png), [mobile](../docs/dashboard-mobile.png) |\n| Container build | Passed, includes independent Node 24 type and test checks | [container-build.txt](container-build.txt) |\n| Container smoke | Passed, non-root distroless Node 24, read-only root, dropped capabilities, limits, authentication, approvals and replay checks | [container-smoke.txt](container-smoke.txt) |\n| Locked dependency advisory query | ${deps} reported advisories at execution time | [dependencies.json](dependencies.json) |\n| Tracked text policy | Passed | [content-policy.txt](content-policy.txt) |\n| Workflow syntax | Passed locally with actionlint | [workflows.txt](workflows.txt), [version](actionlint-version.txt) |\n| Secret scan | Passed locally with gitleaks over all reachable history | [gitleaks.txt](gitleaks.txt), [version](gitleaks-version.txt) |\n\nCoverage totals reported by V8:\n\n\`\`\`text\n${coverageRow}\n\`\`\`\n\nCoverage totals describe only the files listed in the V8 table, including captured startup and maintenance subprocesses. Browser source isn't part of this report. Logs retain command output with trailing display whitespace removed. Browser tests use ${process.env.CHROME_PATH ? 'the locally configured compatible browser via CHROME_PATH' : 'Playwright Chromium'}. Coverage is execution evidence, not proof of all security properties. Dependency results change over time and aren't a container vulnerability scan.\n\nThe attack suite tests 1,000 bad tokens, audit tampering, blind and changed approvals, legacy migration, revocations, real SIGHUP reload, full descriptor changes, forbidden upstream content, structured-output mismatch, each secret pattern and safe audit counts, file modes, second writers in separate processes, transaction rollback, checkpoint rollback/signature forgery, maintenance commands, detection deduplication/failure isolation, encoded routes, and containment expiry/release/rearming. See [the threat-to-test map](../docs/THREAT-MODEL.md).\n\nThe gitleaks configuration excludes only the generated SHA256 source manifest, which caused a generic-key false positive. Synthetic JWT fixtures are assembled from segments so their literal value isn't mistaken for a live credential in source history. CI workflow assertions check pinned action references, scoped permissions and required release steps. These local checks don't execute hosted CodeQL, Scorecard, gitleaks, keyless signing or provenance publication. No release tag, public deployment, live external issuer, cloud account or external MCP service was exercised. Real MCP SDK clients and fixture servers run over local HTTP; a child service exercises production-format configuration and SIGHUP. The demo uses synthetic exports. No credentials are printed in committed evidence. UUIDs, timestamps, hashes and durations vary by run.\n`,
);
writeFileSync('evidence/checks.json', JSON.stringify(results, null, 2) + '\n');
// Generated JSON and Markdown follow the repository formatter without manual transcription.
execFileSync(
  'node_modules/.bin/prettier',
  [
    '--write',
    'evidence/source-manifest.json',
    'evidence/dependencies.json',
    'evidence/demo.json',
    'evidence/sentinel-events.json',
    'evidence/VALIDATION.md',
    'evidence/checks.json',
  ],
  { stdio: 'ignore' },
);
console.log('PASS: all evidence regenerated from executed checks');
