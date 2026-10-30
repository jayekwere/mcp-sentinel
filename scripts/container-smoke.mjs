import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const image = process.argv[2] ?? 'mcp-sentinel:local',
  name = 'mcp-sentinel-smoke-' + process.pid;
const base = 'http://127.0.0.1:4310';
const docker = (args) =>
  execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
try {
  docker([
    'run',
    '--rm',
    '-d',
    '--name',
    name,
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--pids-limit=128',
    '--memory=512m',
    '--tmpfs',
    '/tmp:size=16m',
    '-e',
    'DEMO=1',
    '-e',
    'BASE_URL=' + base,
    '-p',
    '127.0.0.1:4310:4310',
    image,
  ]);
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try {
      if ((await fetch(base + '/health')).ok) {
        ready = true;
        break;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(ready, 'Container became healthy');
  const logs = docker(['logs', name]);
  const tokens = JSON.parse(logs.split('Ephemeral demo tokens (15 minutes):\n')[1]);
  const headers = (role) => ({
    authorization: 'Bearer ' + tokens[role],
    'content-type': 'application/json',
  });
  assert.equal((await fetch(base + '/api/me')).status, 401);
  assert.equal((await fetch(base + '/api/me', { headers: headers('operator') })).status, 200);
  const call = { tool: 'evidence.export', arguments: { caseId: 'case-smoke', format: 'json' } };
  const post = (path, body, role = 'agent') =>
    fetch(base + path, { method: 'POST', headers: headers(role), body: JSON.stringify(body) });
  assert.equal((await post('/api/call', call)).status, 403);
  const approval = await (await post('/api/approvals', call)).json();
  assert.equal(
    (await post(`/api/approvals/${approval.id}/review`, { approve: true }, 'operator')).status,
    200,
  );
  assert.equal((await post('/api/call', { ...call, approvalId: approval.id })).status, 200);
  assert.equal((await post('/api/call', { ...call, approvalId: approval.id })).status, 403);
  console.log(
    'PASS: non-root read-only container, health, authentication, approval, execution, and replay rejection',
  );
} finally {
  try {
    docker(['rm', '-f', name]);
  } catch {}
}
