import { z } from 'zod';
import { Auth } from './security.js';
import { Store } from './store.js';
import { secureApp, requireRole } from './http.js';
import { Gateway } from './gateway.js';
import { mcpRoutes } from './mcp.js';
import { PolicyEngine } from './policy.js';
export function createApp(options: {
  auth: Auth;
  store: Store;
  baseUrl: string;
  webRoot?: string;
  policy?: PolicyEngine;
  limit?: number;
  executor?: typeof import('./tools.js').execute;
  executionVersion?: string;
}) {
  const app = secureApp(
    options.auth,
    options.store,
    options.baseUrl,
    options.webRoot,
    options.limit,
  );
  const gateway = new Gateway(
    options.store,
    options.policy,
    undefined,
    options.executor,
    options.executionVersion,
  );
  app.get('/api/tools', async (req) => ({ tools: gateway.catalog(req.identity) }));
  app.post('/api/call', async (req) => gateway.call(req.identity, req.body));
  app.post('/api/approvals', async (req, reply) =>
    reply.status(201).send(gateway.request(req.identity, req.body)),
  );
  app.get('/api/approvals', async (req) => ({ approvals: gateway.approvals(req.identity) }));
  app.post('/api/approvals/:id/review', async (req) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const { approve } = z.object({ approve: z.boolean() }).strict().parse(req.body);
    return gateway.review(req.identity, id, approve);
  });
  app.get('/api/overview', async (req) => {
    requireRole(req, ['operator', 'analyst']);
    const events = options.store.audits(req.identity.tenant);
    return {
      policy: {
        version: gateway.policy.policy.version,
        hash: gateway.policy.hash,
        rules: gateway.policy.policy.rules.length,
      },
      events,
      detections: gateway.detections(req.identity),
      integrity: options.store.verify(),
      totals: {
        allowed: events.filter((e) => e.action === 'tool.completed').length,
        denied: events.filter((e) => e.outcome === 'denied').length,
        pending: gateway.store.db
          .prepare(
            "SELECT count(*) AS n FROM approvals WHERE tenant=? AND status='pending' AND expires>?",
          )
          .get(req.identity.tenant, Date.now()),
      },
    };
  });
  mcpRoutes(app, gateway, options.baseUrl);
  return { app, gateway };
}
