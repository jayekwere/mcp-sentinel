import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
async function setup(limit?: number) {
  const demo = await demoAuth('mcp-sentinel'),
    store = new Store(':memory:', 'k'.repeat(32));
  const { app } = createApp({
    auth: demo.auth,
    store,
    baseUrl: 'http://127.0.0.1:4310',
    ...(limit ? { limit } : {}),
  });
  return { ...demo, store, app };
}
test('HTTP boundary rejects missing tokens, untrusted hosts, cross origins, large bodies, and analyst calls', async () => {
  const { app, tokens, store } = await setup();
  try {
    for (const [headers, status] of [
      [{}, 401],
      [{ authorization: 'Bearer bad' }, 401],
      [{ host: 'evil.invalid' }, 403],
      [{ origin: 'https://evil.invalid' }, 403],
    ] as const) {
      const r = await app.inject({
        method: 'GET',
        url: '/api/tools',
        headers: { host: '127.0.0.1:4310', ...headers },
      });
      assert.equal(r.statusCode, status);
    }
    const headers = { host: '127.0.0.1:4310', authorization: 'Bearer ' + tokens.agent };
    assert.equal(
      (await app.inject({ method: 'GET', url: '/api/overview', headers })).statusCode,
      403,
    );
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: '/api/call',
          headers,
          payload: { tool: 'knowledge.search', arguments: { query: 'x'.repeat(300000) } },
        })
      ).statusCode,
      413,
    );
    const malformed = await app.inject({
      method: 'POST',
      url: '/api/call',
      headers: { ...headers, 'content-type': 'application/json' },
      payload: '{',
    });
    assert.equal(malformed.statusCode, 400);
    const response = await app.inject({ url: '/health', headers: { host: '127.0.0.1:4310' } });
    assert.match(response.headers['content-security-policy'] as string, /frame-ancestors 'none'/);
    assert.equal(response.headers['access-control-allow-origin'], undefined);
  } finally {
    await app.close();
    store.close();
  }
});
test('subject rate limits apply to authenticated API requests', async () => {
  const { app, tokens, store } = await setup(2);
  try {
    const h = { host: '127.0.0.1:4310', authorization: 'Bearer ' + tokens.agent };
    assert.equal((await app.inject({ url: '/api/me', headers: h })).statusCode, 200);
    assert.equal((await app.inject({ url: '/api/me', headers: h })).statusCode, 200);
    assert.equal((await app.inject({ url: '/api/me', headers: h })).statusCode, 429);
  } finally {
    await app.close();
    store.close();
  }
});
test('official SDK client initializes, lists scoped tools, executes, and receives denial over HTTP', async () => {
  const { tokens, auth } = await demoAuth('mcp-sentinel'),
    store = new Store(':memory:', 'k'.repeat(32));
  const { app, gateway } = createApp({ auth, store, baseUrl: 'http://127.0.0.1:14310' });
  const client = new Client({ name: 'security-test', version: '1.0.0' });
  try {
    await app.listen({ port: 14310, host: '127.0.0.1' });
    await client.connect(
      new StreamableHTTPClientTransport(new URL('http://127.0.0.1:14310/mcp'), {
        requestInit: { headers: { authorization: 'Bearer ' + tokens.agent } },
      }),
    );
    const catalog = await client.listTools();
    assert.equal(catalog.tools.length, 3);
    const allowed = await client.callTool({
      name: 'knowledge.search',
      arguments: { query: 'approval' },
    });
    assert.notEqual(allowed.isError, true);
    const blocked = await client.callTool({
      name: 'evidence.export',
      arguments: { caseId: 'case-test', format: 'json' },
    });
    assert.equal(blocked.isError, true);
    assert.match(JSON.stringify(blocked), /approval_required/);
    const agent = auth.config.identities.find((i) => i.role === 'agent')!,
      operator = auth.config.identities.find(
        (i) => i.role === 'operator' && i.tenant === 'sandbox',
      )!;
    const request = { tool: 'evidence.export', arguments: { caseId: 'case-test', format: 'json' } };
    const approval = gateway.request(agent, request);
    gateway.review(operator, approval.id, true);
    const approved = await client.callTool({
      name: request.tool,
      arguments: request.arguments,
      _meta: { 'sentinel/approval': approval.id },
    });
    assert.notEqual(approved.isError, true);
    const replayed = await client.callTool({
      name: request.tool,
      arguments: request.arguments,
      _meta: { 'sentinel/approval': approval.id },
    });
    assert.equal(replayed.isError, true);
    const unknown = await client.callTool({ name: 'admin.delete', arguments: {} });
    assert.equal(unknown.isError, true);
  } finally {
    await client.close();
    await app.close();
    store.close();
  }
});
test('REST review and audit endpoints restrict roles and tenant records', async () => {
  const { app, tokens, store } = await setup();
  const h = (r: string) => ({ host: '127.0.0.1:4310', authorization: 'Bearer ' + tokens[r] });
  try {
    const body = { tool: 'evidence.export', arguments: { caseId: 'case-rest', format: 'json' } };
    const pending = (
      await app.inject({
        method: 'POST',
        url: '/api/approvals',
        headers: h('agent'),
        payload: body,
      })
    ).json();
    assert.equal(
      (await app.inject({ url: '/api/approvals', headers: h('agent') })).statusCode,
      403,
    );
    assert.equal(
      (await app.inject({ url: '/api/approvals', headers: h('operator') })).json().approvals.length,
      1,
    );
    assert.equal(
      (await app.inject({ url: '/api/approvals', headers: h('outsider') })).json().approvals.length,
      0,
    );
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: `/api/approvals/${pending.id}/review`,
          headers: h('outsider'),
          payload: { approve: true },
        })
      ).statusCode,
      404,
    );
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: `/api/approvals/${pending.id}/review`,
          headers: h('operator'),
          payload: { approve: true },
        })
      ).statusCode,
      200,
    );
    assert.equal(
      (await app.inject({ url: '/api/audit', headers: h('analyst') })).json().integrity,
      true,
    );
    assert.equal((await app.inject({ url: '/api/audit', headers: h('agent') })).statusCode, 403);
    assert.equal(
      (await app.inject({ url: '/api/audit', headers: h('outsider') })).json().events.length,
      0,
    );
  } finally {
    await app.close();
    store.close();
  }
});
