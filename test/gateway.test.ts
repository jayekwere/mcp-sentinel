import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Gateway } from '../src/gateway.js';
import { PolicyEngine, defaultPolicy } from '../src/policy.js';
import { Store } from '../src/store.js';
import { cloudSummary } from '../src/tools.js';
import type { Identity } from '../src/security.js';
const agent: Identity = { subject: 'a', tenant: 'sandbox', agent: 'researcher', role: 'agent' },
  operator: Identity = { subject: 'o', tenant: 'sandbox', agent: 'reviewer', role: 'operator' };
const call = { tool: 'evidence.export', arguments: { caseId: 'case-demo', format: 'json' } };
function setup() {
  let now = 1000000;
  const store = new Store(':memory:', 'k'.repeat(32), () => now);
  const g = new Gateway(store, new PolicyEngine(), () => now);
  return {
    store,
    g,
    advance: (n: number) => {
      now += n;
    },
  };
}
test('deny by default, role and agent boundaries, tool catalog filtering', async () => {
  const { g, store } = setup();
  try {
    await assert.rejects(g.call(agent, { tool: 'admin.delete', arguments: {} }), {
      code: 'unknown_tool',
    });
    for (const who of [
      { ...agent, agent: 'unregistered' },
      { ...agent, role: 'operator' as const },
      { ...agent, tenant: 'isolated' },
    ])
      await assert.rejects(
        g.call(who, { tool: 'knowledge.search', arguments: { query: 'approval' } }),
        { code: 'policy_denied' },
      );
    assert.equal(g.catalog(operator).length, 0);
    assert.equal(g.catalog(agent).length, 3);
    const result = await g.call(agent, {
      tool: 'knowledge.search',
      arguments: { query: 'approval' },
    });
    assert.equal(result.decision, 'allowed');
    assert.equal(store.verify(), true);
  } finally {
    store.close();
  }
});
test('explicit deny dominates allow and approval, exact matches avoid wildcard grants', () => {
  const rule = defaultPolicy.rules[0]!;
  const p = new PolicyEngine({
    version: 'test',
    rules: [
      rule,
      { ...rule, id: 'deny', effect: 'deny' },
      { ...rule, id: 'approve', effect: 'approve' },
    ],
  });
  assert.equal(p.evaluate(agent, 'knowledge.search').effect, 'deny');
  assert.equal(p.evaluate(agent, 'knowledge.search.extra').effect, 'deny');
});
test('unexpected and malformed tool arguments never reach execution', async () => {
  const { g, store } = setup();
  try {
    for (const args of [{ query: 'x', url: 'http://169.254.169.254' }, { query: '' }, { query: 5 }])
      await assert.rejects(g.call(agent, { tool: 'knowledge.search', arguments: args }));
    assert.equal(store.audits('sandbox').filter((e) => e.action === 'tool.intent').length, 0);
  } finally {
    store.close();
  }
});
test('approval lifecycle requires independent review and consumes exactly once', async () => {
  const { g, store } = setup();
  try {
    await assert.rejects(g.call(agent, call), { code: 'approval_required' });
    const a = g.request(agent, call);
    await assert.rejects(g.call(agent, { ...call, approvalId: a.id }), {
      code: 'approval_required',
    });
    assert.throws(() => g.review(agent, a.id, true), { code: 'forbidden' });
    assert.throws(() => g.review({ ...operator, subject: agent.subject }, a.id, true), {
      code: 'self_approval',
    });
    assert.throws(() => g.review({ ...operator, tenant: 'isolated' }, a.id, true), {
      code: 'approval_not_found',
    });
    g.review(operator, a.id, true);
    const r = await g.call(agent, { ...call, approvalId: a.id });
    assert.equal(r.decision, 'allowed');
    await assert.rejects(g.call(agent, { ...call, approvalId: a.id }), {
      code: 'approval_required',
    });
    assert.equal(store.audits('sandbox').filter((e) => e.action === 'tool.completed').length, 1);
  } finally {
    store.close();
  }
});
for (const mutation of ['arguments', 'actor', 'agent', 'policy'])
  test('approval binding rejects changed ' + mutation, async () => {
    const { g, store } = setup();
    try {
      const approval = g.request(agent, call);
      g.review(operator, approval.id, true);
      const who =
        mutation === 'actor'
          ? { ...agent, subject: 'other' }
          : mutation === 'agent'
            ? { ...agent, agent: 'investigator' }
            : agent;
      const target =
        mutation === 'policy'
          ? new Gateway(
              store,
              new PolicyEngine({ ...defaultPolicy, version: 'new' }),
              () => 1000000,
            )
          : g;
      const changed = {
        ...call,
        approvalId: approval.id,
        ...(mutation === 'arguments'
          ? { arguments: { caseId: 'case-other', format: 'json' } }
          : {}),
      };
      await assert.rejects(target.call(who, changed));
      assert.equal(store.audits('sandbox').filter((e) => e.action === 'tool.completed').length, 0);
    } finally {
      store.close();
    }
  });
test('expiry, rejection, and repeat review are enforced', async () => {
  const { g, store, advance } = setup();
  try {
    const a = g.request(agent, call);
    g.review(operator, a.id, false);
    assert.throws(() => g.review(operator, a.id, true), { code: 'approval_unavailable' });
    await assert.rejects(g.call(agent, { ...call, approvalId: a.id }));
    const b = g.request(agent, call);
    g.review(operator, b.id, true);
    advance(300001);
    await assert.rejects(g.call(agent, { ...call, approvalId: b.id }));
    const c = g.request(agent, call);
    advance(300001);
    assert.throws(() => g.review(operator, c.id, true), { code: 'approval_unavailable' });
  } finally {
    store.close();
  }
});
test('concurrent approval reuse results in one execution', async () => {
  const { g, store } = setup();
  try {
    const a = g.request(agent, call);
    g.review(operator, a.id, true);
    const results = await Promise.allSettled(
      Array.from({ length: 12 }, () => g.call(agent, { ...call, approvalId: a.id })),
    );
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal(store.audits('sandbox').filter((e) => e.action === 'tool.intent').length, 1);
  } finally {
    store.close();
  }
});
test('approval consumption survives process restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gateway-')),
    file = join(dir, 'db'),
    key = 'k'.repeat(32);
  let store = new Store(file, key);
  try {
    let g = new Gateway(store);
    const a = g.request(agent, call);
    g.review(operator, a.id, true);
    await g.call(agent, { ...call, approvalId: a.id });
    store.close();
    store = new Store(file, key);
    g = new Gateway(store);
    await assert.rejects(g.call(agent, { ...call, approvalId: a.id }), {
      code: 'approval_required',
    });
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test('executor failure consumes approval and records failure without its exception message', async () => {
  const { store } = setup();
  const g = new Gateway(
    store,
    new PolicyEngine(),
    () => 1000000,
    async () => {
      throw new Error('sensitive-upstream-token');
    },
  );
  try {
    const a = g.request(agent, call);
    g.review(operator, a.id, true);
    await assert.rejects(g.call(agent, { ...call, approvalId: a.id }), { code: 'tool_failed' });
    await assert.rejects(g.call(agent, { ...call, approvalId: a.id }), {
      code: 'approval_required',
    });
    assert.equal(
      JSON.stringify(store.audits('sandbox')).includes('sensitive-upstream-token'),
      false,
    );
  } finally {
    store.close();
  }
});
test('pending approval queue is bounded and denial burst detection expires', async () => {
  const { g, store, advance } = setup();
  try {
    for (let i = 0; i < 20; i++) g.request(agent, call);
    assert.throws(() => g.request(agent, call), { code: 'approval_queue_full' });
    for (let i = 0; i < 5; i++)
      await assert.rejects(g.call(agent, { tool: 'unknown', arguments: {} }));
    assert.ok(g.detections(agent).some((d) => d.rule === 'agent-denial-burst'));
    advance(60001);
    assert.equal(g.detections(agent).length, 0);
  } finally {
    store.close();
  }
});
for (const provider of ['aws', 'azure', 'gcp'])
  test(provider + ' export adapter validates its documented fields', () => {
    const record =
      provider === 'aws'
        ? {
            eventID: '1',
            eventTime: '2026-01-01T00:00:00Z',
            eventName: 'ListUsers',
            userIdentity: { principalId: 'synthetic' },
          }
        : provider === 'azure'
          ? {
              eventDataId: '1',
              eventTimestamp: '2026-01-01T00:00:00Z',
              caller: 'synthetic',
              operationName: { value: 'read' },
            }
          : {
              insertId: '1',
              timestamp: '2026-01-01T00:00:00Z',
              protoPayload: {
                methodName: 'read',
                authenticationInfo: { principalEmail: 'synthetic@invalid.example' },
              },
            };
    assert.equal(cloudSummary({ provider, records: [record] }).count, 1);
    assert.throws(() => cloudSummary({ provider, records: [{}] }));
  });
