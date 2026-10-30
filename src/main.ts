import { readFileSync } from 'node:fs';
import { config } from './config.js';
import { Store } from './store.js';
import { createApp } from './app.js';
import { upstreamExecutor } from './upstream.js';
import { PolicyEngine } from './policy.js';
const c = await config('mcp-sentinel', 4310);
const store = new Store(c.db, c.key);
const policy = new PolicyEngine(
  process.env.POLICY_FILE ? JSON.parse(readFileSync(process.env.POLICY_FILE, 'utf8')) : undefined,
);
const upstream = process.env.UPSTREAM_CONFIG
  ? upstreamExecutor(
      JSON.parse(readFileSync(process.env.UPSTREAM_CONFIG, 'utf8')),
      process.env.UPSTREAM_TOKEN,
      c.demo,
    )
  : undefined;
const { app } = createApp({
  auth: c.auth,
  store,
  baseUrl: c.baseUrl,
  policy,
  ...(upstream ? { executor: upstream.execute, executionVersion: upstream.version } : {}),
});
await app.listen({ port: Number(process.env.PORT ?? 4310), host: c.host });
console.log(`MCP Sentinel listening at ${c.baseUrl}`);
if (c.demo)
  console.log('Ephemeral demo tokens (15 minutes):\n' + JSON.stringify(c.tokens, null, 2));
for (const signal of ['SIGINT', 'SIGTERM'] as const)
  process.on(signal, () => {
    void app.close().then(() => {
      store.close();
      process.exit(0);
    });
  });
