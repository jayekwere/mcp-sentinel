import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const key = 'k'.repeat(32);
test('bounds unauthenticated audit flooding from 1000 bad tokens', async () => {
  const demo = await demoAuth('mcp-sentinel');
  const store = new Store(':memory:', key);
  const { app } = createApp({
    auth: demo.auth,
    store,
    baseUrl: 'http://127.0.0.1:4310',
    limit: 2000,
  });
  try {
    for (let i = 0; i < 1000; i++) {
      const r = await app.inject({
        url: '/api/me',
        headers: { host: '127.0.0.1:4310', authorization: 'Bearer bad' },
      });
      assert.equal(r.statusCode, 401);
    }
    await app.close();
    const rows = store.audits('system', 2000);
    assert.ok(rows.length <= 2);
    assert.equal(rows[0]?.action, 'authentication.denied');
    assert.equal(
      rows.reduce((n, r) => n + Number(r.detail.count), 0),
      1000,
    );
  } finally {
    await app.close();
    store.close();
  }
});
test('incremental verification rejects a tampered newer audit row', () => {
  const store = new Store(':memory:', key);
  try {
    store.audit('sandbox', 'a', 'first', 'allowed');
    assert.equal(store.verify(), true);
    store.audit('sandbox', 'a', 'second', 'allowed');
    store.db.exec("UPDATE audit SET body=json_set(body,'$.outcome','denied') WHERE seq=2");
    assert.equal(store.verify(), false);
  } finally {
    store.close();
  }
});

test('rejects blind review of legacy approvals during migration', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { randomUUID } = await import('node:crypto');
  const { Gateway } = await import('../src/gateway.js');
  const demo = await demoAuth('mcp-sentinel');
  const dir = mkdtempSync(join(tmpdir(), 'legacy-approval-')),
    file = join(dir, 'db');
  const id = randomUUID();
  const raw = new DatabaseSync(file);
  raw.exec(
    'CREATE TABLE approvals(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,subject TEXT NOT NULL,binding TEXT NOT NULL,expires INTEGER NOT NULL,status TEXT NOT NULL,reviewer TEXT)',
  );
  raw
    .prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,NULL)')
    .run(id, 'sandbox', 'demo-agent', 'legacy-binding', Date.now() + 300000, 'pending');
  raw.close();
  const store = new Store(file, key);
  try {
    assert.throws(() => new Gateway(store).review(demo.auth.config.identities[2]!, id, true), {
      code: 'approval_unavailable',
    });
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('prevents blind approval of custom cloud summary policy and binds every argument', async () => {
  const { Gateway } = await import('../src/gateway.js');
  const { PolicyEngine, defaultPolicy } = await import('../src/policy.js');
  const store = new Store(':memory:', key);
  const demo = await demoAuth('mcp-sentinel');
  const agent = demo.auth.config.identities[0]!;
  const operator = demo.auth.config.identities[2]!;
  const g = new Gateway(
    store,
    new PolicyEngine({
      version: 'review',
      rules: [{ ...defaultPolicy.rules[0], effect: 'approve' }],
    }),
  );
  const call = {
    tool: 'cloud.audit.summary',
    arguments: { provider: 'aws', records: [{ eventID: 'review-this', extra: 'x'.repeat(5000) }] },
  };
  try {
    const a = g.request(agent, call);
    const full = store.db
      .prepare("SELECT body FROM audit WHERE json_extract(body,'$.action')='approval.requested'")
      .get() as { body: string };
    assert.deepEqual(JSON.parse(full.body).detail.args, call.arguments);
    const view = g.approvals(operator)[0]!;
    assert.equal(view.request.argsTruncated, true);
    assert.ok(Buffer.byteLength(String(view.request.args)) <= 4096);
    for (let i = 0; i < 1001; i++) store.audit('sandbox', 'a', 'filler', 'allowed');
    assert.equal(g.approvals(operator)[0]!.request.tool, 'cloud.audit.summary');
    g.review(operator, a.id, true);
    await assert.rejects(
      g.call(agent, {
        ...call,
        approvalId: a.id,
        arguments: { ...call.arguments, records: [{ eventID: 'changed' }] },
      }),
      { code: 'approval_required' },
    );
    const small = { ...call, arguments: { provider: 'aws', records: [{ eventID: 'visible' }] } };
    g.request(agent, small);
    assert.ok(
      g
        .approvals(operator)
        .some((v) => JSON.stringify(v.request.args) === JSON.stringify(small.arguments)),
    );
  } finally {
    store.close();
  }
});
