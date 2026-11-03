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

test('rejects revoked token jti and revoked subject without making tokens one time use', async () => {
  const { decodeJwt } = await import('jose');
  const demo = await demoAuth('mcp-sentinel');
  const store = new Store(':memory:', key);
  const { app } = createApp({ auth: demo.auth, store, baseUrl: 'http://127.0.0.1:4310' });
  const h = (role: string) => ({
    host: '127.0.0.1:4310',
    authorization: 'Bearer ' + demo.tokens[role],
  });
  try {
    for (let i = 0; i < 2; i++)
      assert.equal((await app.inject({ url: '/api/me', headers: h('agent') })).statusCode, 200);
    const revoke = async (body: unknown, role = 'operator') =>
      app.inject({
        method: 'POST',
        url: '/api/revocations',
        headers: h(role),
        payload: body as object,
      });
    assert.equal(
      (
        await revoke({
          kind: 'jti',
          value: decodeJwt(demo.tokens.agent!).jti,
          subject: 'demo-agent',
          expiresAt: new Date(Date.now() + 60000).toISOString(),
        })
      ).statusCode,
      201,
    );
    assert.equal(
      (await app.inject({ url: '/api/me', headers: h('agent') })).json().error,
      'invalid_token',
    );
    assert.equal(
      (
        await revoke({
          kind: 'subject',
          value: 'demo-analyst',
          subject: 'demo-analyst',
          expiresAt: new Date(Date.now() + 60000).toISOString(),
        })
      ).statusCode,
      201,
    );
    assert.equal((await app.inject({ url: '/api/me', headers: h('analyst') })).statusCode, 401);
    assert.equal(
      (
        await revoke({
          kind: 'subject',
          value: 'other-tenant',
          subject: 'other-tenant',
          expiresAt: new Date(Date.now() + 60000).toISOString(),
        })
      ).statusCode,
      403,
    );
    assert.equal(
      (
        await revoke({
          kind: 'subject',
          value: 'demo-operator',
          subject: 'demo-operator',
          expiresAt: new Date(Date.now() + 60000).toISOString(),
          extra: true,
        })
      ).statusCode,
      400,
    );
    assert.equal(store.audits('sandbox').filter((e) => e.action === 'identity.revoked').length, 2);
  } finally {
    await app.close();
    store.close();
  }
});
test('revokes every accepted token ID including IDs longer than 200 characters', async () => {
  const { SignJWT } = await import('jose');
  const demo = await demoAuth('mcp-sentinel');
  const jti = 'synthetic-' + 'x'.repeat(201);
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: 'ephemeral-demo' })
    .setIssuer(demo.auth.config.issuer)
    .setAudience('mcp-sentinel')
    .setSubject('demo-agent')
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(demo.privateKey);
  const store = new Store(':memory:', key);
  const { app } = createApp({ auth: demo.auth, store, baseUrl: 'http://127.0.0.1:4310' });
  const headers = { host: '127.0.0.1:4310', authorization: 'Bearer ' + token };
  try {
    assert.equal((await app.inject({ url: '/api/me', headers })).statusCode, 200);
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: '/api/revocations',
          headers: { ...headers, authorization: 'Bearer ' + demo.tokens.operator },
          payload: {
            kind: 'jti',
            value: jti,
            subject: 'demo-agent',
            expiresAt: new Date(Date.now() + 60000).toISOString(),
          },
        })
      ).statusCode,
      201,
    );
    assert.equal((await app.inject({ url: '/api/me', headers })).json().error, 'invalid_token');
  } finally {
    await app.close();
    store.close();
  }
});

test('rejects unusable verification keys on auth reload', async () => {
  const { reloadAuth } = await import('../src/config.js');
  const demo = await demoAuth('mcp-sentinel');
  const original = structuredClone(demo.auth.config);
  const store = new Store(':memory:', key);
  try {
    for (const change of [{ use: 'enc' }, { key_ops: ['sign'] }, { key_ops: [] }, { alg: '' }]) {
      const input = { ...original, jwks: { keys: [{ ...original.jwks.keys[0]!, ...change }] } };
      assert.equal(reloadAuth(demo.auth, store, input, 'mcp-sentinel'), false);
      assert.equal((await demo.auth.verify('Bearer ' + demo.tokens.agent)).subject, 'demo-agent');
    }
    assert.equal(store.audits('system').filter((e) => e.outcome === 'denied').length, 4);
  } finally {
    store.close();
  }
});

test('invalid auth reload keeps the old configuration and audits both outcomes', async () => {
  const { reloadAuth } = await import('../src/config.js');
  const demo = await demoAuth('mcp-sentinel');
  const store = new Store(':memory:', key);
  try {
    assert.equal(
      reloadAuth(
        demo.auth,
        store,
        { ...demo.auth.config, jwks: { keys: [{ kty: 'EC' }] } },
        'mcp-sentinel',
      ),
      false,
    );
    assert.equal((await demo.auth.verify('Bearer ' + demo.tokens.agent)).subject, 'demo-agent');
    assert.equal(
      reloadAuth(
        demo.auth,
        store,
        {
          ...demo.auth.config,
          identities: demo.auth.config.identities.filter((i) => i.subject !== 'demo-agent'),
        },
        'mcp-sentinel',
      ),
      true,
    );
    await assert.rejects(demo.auth.verify('Bearer ' + demo.tokens.agent), {
      code: 'invalid_token',
    });
    assert.deepEqual(
      store.audits('system').map((e) => e.outcome),
      ['allowed', 'denied'],
    );
  } finally {
    store.close();
  }
});
