import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { demoAuth } from '../src/security.js';
import { PolicyEngine, defaultPolicy } from '../src/policy.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const { auth, tokens } = await demoAuth('mcp-sentinel'),
  store = new Store(':memory:', 'k'.repeat(32));
const policy = new PolicyEngine({
  ...defaultPolicy,
  rules: [
    ...defaultPolicy.rules,
    {
      ...defaultPolicy.rules[0]!,
      id: 'browser-cloud-review',
      effect: 'approve',
      tools: ['cloud.audit.summary'],
    },
  ],
});
const { app, gateway } = createApp({
  auth,
  store,
  policy,
  suspendSeconds: 300,
  baseUrl: 'http://127.0.0.1:4310',
});
const agent = auth.config.identities.find((i) => i.role === 'agent')!;
await gateway.call(agent, { tool: 'knowledge.search', arguments: { query: 'approval' } });
gateway.request(agent, {
  tool: 'evidence.export',
  arguments: { caseId: 'case-investigation', format: 'json' },
});
for (let i = 0; i < 5; i++)
  await gateway.call(agent, { tool: 'admin.delete', arguments: {} }).catch(() => {});
mkdirSync('test-results', { recursive: true });
writeFileSync('test-results/tokens.json', JSON.stringify(tokens), { mode: 0o600 });
await app.listen({ port: 4310, host: '127.0.0.1' });
