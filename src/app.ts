import { z } from 'zod';
import { Auth, Fault } from './security.js';
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
  app.post('/api/revocations', async (req, reply) => {
    requireRole(req, ['operator']);
    const body = z
      .object({
        kind: z.enum(['jti', 'subject']),
        value: z.string().min(1).max(8192),
        subject: z.string().min(1).max(200),
        expiresAt: z.iso.datetime(),
      })
      .strict()
      .parse(req.body);
    const identity = options.auth.identity(body.subject);
    if (
      !identity ||
      identity.tenant !== req.identity.tenant ||
      (body.kind === 'subject' && body.value !== body.subject)
    )
      throw new Fault(403, 'forbidden');
    const expires = Date.parse(body.expiresAt);
    if (expires <= Date.now() || expires > Date.now() + 31536000000)
      throw new Fault(400, 'invalid_request');
    options.store.transaction(() => {
      options.store.db.prepare('DELETE FROM revocations WHERE expires<=?').run(Date.now());
      options.store.db
        .prepare(
          'INSERT INTO revocations VALUES(?,?,?,?,?) ON CONFLICT(tenant,kind,value,subject) DO UPDATE SET expires=max(expires,excluded.expires)',
        )
        .run(req.identity.tenant, body.kind, body.value, body.subject, expires);
      options.store.audit(
        req.identity.tenant,
        req.identity.subject,
        'identity.revoked',
        'allowed',
        body,
      );
    });
    return reply.status(201).send({ status: 'revoked' });
  });
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
        pending: (
          gateway.store.db
            .prepare(
              "SELECT count(*) AS n FROM approvals WHERE tenant=? AND status='pending' AND expires>?",
            )
            .get(req.identity.tenant, Date.now()) as { n: number }
        ).n,
      },
    };
  });
  mcpRoutes(app, gateway, options.baseUrl);
  return { app, gateway };
}
