import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const { auth, tokens } = await demoAuth('mcp-sentinel'),
  store = new Store(':memory:', 'k'.repeat(32));
const { app, gateway } = createApp({ auth, store, baseUrl: 'http://127.0.0.1:4310' });
const agent = auth.config.identities.find((i) => i.role === 'agent')!;
await gateway.call(agent, { tool: 'knowledge.search', arguments: { query: 'approval' } });
for (let i = 0; i < 5; i++)
  await gateway.call(agent, { tool: 'admin.delete', arguments: {} }).catch(() => {});
gateway.request(agent, {
  tool: 'evidence.export',
  arguments: { caseId: 'case-investigation', format: 'json' },
});
mkdirSync('test-results', { recursive: true });
writeFileSync('test-results/tokens.json', JSON.stringify(tokens), { mode: 0o600 });
await app.listen({ port: 4310, host: '127.0.0.1' });
