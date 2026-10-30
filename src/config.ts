import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { Auth, demoAuth, type AuthConfig } from './security.js';
export async function config(name: string, port: number) {
  const demo = process.env.DEMO === '1';
  const baseUrl = process.env.BASE_URL ?? `http://127.0.0.1:${port}`;
  const url = new URL(baseUrl);
  if (!demo && url.protocol !== 'https:')
    throw new Error('Set an HTTPS BASE_URL and terminate TLS at a trusted proxy');
  let auth: Auth,
    tokens: Record<string, string> = {};
  if (demo) {
    const generated = await demoAuth(name);
    auth = generated.auth;
    tokens = generated.tokens;
  } else {
    if (!process.env.AUTH_CONFIG) throw new Error('AUTH_CONFIG is required');
    const raw = JSON.parse(readFileSync(process.env.AUTH_CONFIG, 'utf8')) as AuthConfig;
    if (new URL(raw.issuer).protocol !== 'https:' || raw.audience !== url.origin)
      throw new Error('Invalid issuer or audience');
    auth = new Auth(raw);
  }
  const key = process.env.AUDIT_KEY ?? (demo ? randomBytes(32).toString('hex') : '');
  if (Buffer.byteLength(key) < 32) throw new Error('AUDIT_KEY requires at least 32 bytes');
  const db = process.env.DB_PATH ?? (demo ? ':memory:' : '.data/state.sqlite');
  if (demo && db !== ':memory:' && !process.env.AUDIT_KEY)
    throw new Error('Persistent demo storage requires a stable AUDIT_KEY');
  return {
    auth,
    tokens,
    key,
    db,
    baseUrl,
    port: Number(url.port || port),
    host: process.env.HOST ?? '127.0.0.1',
    demo,
  };
}
