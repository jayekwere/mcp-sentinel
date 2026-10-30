import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const { auth, tokens } = await demoAuth('mcp-sentinel'),
  store = new Store(':memory:', 'k'.repeat(32));
const { app } = createApp({ auth, store, baseUrl: 'http://127.0.0.1:4310' });
const h = (role: string) => ({ host: '127.0.0.1:4310', authorization: 'Bearer ' + tokens[role] });
const call = { tool: 'evidence.export', arguments: { caseId: 'case-demo', format: 'json' } };
try {
  const denied = await app.inject({
    method: 'POST',
    url: '/api/call',
    headers: h('agent'),
    payload: call,
  });
  assert.equal(denied.statusCode, 403);
  const approval = (
    await app.inject({ method: 'POST', url: '/api/approvals', headers: h('agent'), payload: call })
  ).json();
  assert.equal(approval.status, 'pending');
  assert.equal(
    (
      await app.inject({
        method: 'POST',
        url: `/api/approvals/${approval.id}/review`,
        headers: h('operator'),
        payload: { approve: true },
      })
    ).statusCode,
    200,
  );
  const allowed = await app.inject({
    method: 'POST',
    url: '/api/call',
    headers: h('agent'),
    payload: { ...call, approvalId: approval.id },
  });
  assert.equal(allowed.statusCode, 200);
  const replay = await app.inject({
    method: 'POST',
    url: '/api/call',
    headers: h('agent'),
    payload: { ...call, approvalId: approval.id },
  });
  assert.equal(replay.statusCode, 403);
  for (let i = 0; i < 5; i++)
    await app.inject({
      method: 'POST',
      url: '/api/call',
      headers: h('agent'),
      payload: { tool: 'admin.delete', arguments: {} },
    });
  const events = store.audits('sandbox').reverse();
  const output = {
    unapproved: { status: denied.statusCode, error: denied.json().error },
    review: 'approved by independent operator',
    approved: { status: allowed.statusCode, result: allowed.json().result },
    replayed: { status: replay.statusCode, error: replay.json().error },
    audit: { integrity: store.verify(), entries: events.length },
    detections: (await app.inject({ url: '/api/overview', headers: h('operator') }))
      .json()
      .detections.map((d: { rule: string }) => d.rule),
  };
  if (process.argv.includes('--write')) {
    writeFileSync('evidence/demo.json', JSON.stringify(output, null, 2) + '\n');
    writeFileSync(
      'evidence/sentinel-events.json',
      JSON.stringify(
        events.map((record) => ({ provider: 'sentinel', record })),
        null,
        2,
      ) + '\n',
    );
  }
  console.log(JSON.stringify(output, null, 2));
} finally {
  await app.close();
  store.close();
}
