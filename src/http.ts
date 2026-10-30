import Fastify, { type FastifyRequest } from 'fastify';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ZodError } from 'zod';
import { Auth, Fault, Limiter, type Identity } from './security.js';
import { Store } from './store.js';

declare module 'fastify' {
  interface FastifyRequest {
    identity: Identity;
  }
}
export function secureApp(
  auth: Auth,
  store: Store,
  baseUrl: string,
  webRoot = resolve('dist/web'),
  limit = 120,
) {
  const base = new URL(baseUrl);
  const app = Fastify({
    logger: false,
    bodyLimit: 262144,
    requestTimeout: 15000,
    connectionTimeout: 10000,
    trustProxy: false,
    routerOptions: { maxParamLength: 100 },
  });
  const ips = new Limiter(limit * 3),
    subjects = new Limiter(limit);
  app.decorateRequest('identity');
  app.addHook('onRequest', async (req, reply) => {
    reply.header(
      'content-security-policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
    reply
      .header('x-content-type-options', 'nosniff')
      .header('referrer-policy', 'no-referrer')
      .header('cache-control', 'no-store')
      .header('permissions-policy', 'camera=(), microphone=(), geolocation=()');
    if (base.protocol === 'https:') reply.header('strict-transport-security', 'max-age=31536000');
    ips.take(req.ip);
    if (
      req.headers.host !== base.host ||
      (req.headers.origin && req.headers.origin !== base.origin)
    )
      throw new Fault(403, 'untrusted_origin');
    if (req.url.startsWith('/api/') || req.url.split('?')[0] === '/mcp') {
      try {
        req.identity = await auth.verify(req.headers.authorization);
        subjects.take(req.identity.subject);
      } catch (e) {
        if (e instanceof Fault && e.status === 401) {
          reply.header(
            'www-authenticate',
            `Bearer resource_metadata="${base.origin}/.well-known/oauth-protected-resource"`,
          );
          store.audit('system', 'unknown', 'authentication', 'denied');
        }
        throw e;
      }
    }
  });
  app.setErrorHandler((error, _req, reply) => {
    if (error instanceof Fault) return reply.status(error.status).send({ error: error.code });
    const statusCode =
      typeof error === 'object' && error !== null && 'statusCode' in error ? error.statusCode : 0;
    if (error instanceof ZodError || statusCode === 400)
      return reply.status(400).send({ error: 'invalid_request' });
    if (statusCode === 413) return reply.status(413).send({ error: 'payload_too_large' });
    if (statusCode === 415) return reply.status(415).send({ error: 'unsupported_media_type' });
    return reply.status(500).send({ error: 'internal_error' });
  });
  app.get('/health', async () => ({ status: 'ok' }));
  app.get('/.well-known/oauth-protected-resource', async () => ({
    resource: base.origin,
    authorization_servers: [auth.config.issuer],
    bearer_methods_supported: ['header'],
  }));
  for (const [url, file, type] of [
    ['/', 'index.html', 'text/html'],
    ['/app.js', 'app.js', 'application/javascript'],
    ['/style.css', 'style.css', 'text/css'],
  ]) {
    app.get(url!, async (_req, reply) =>
      reply.type(type!).send(readFileSync(resolve(webRoot, file!))),
    );
  }
  app.get('/api/me', async (req) => req.identity);
  app.get('/api/audit', async (req) => {
    requireRole(req, ['analyst', 'operator']);
    return { integrity: store.verify(), events: store.audits(req.identity.tenant) };
  });
  return app;
}
export function requireRole(req: FastifyRequest, roles: Identity['role'][]) {
  if (!roles.includes(req.identity.role)) throw new Fault(403, 'forbidden');
}
