import { createHash, randomUUID } from 'node:crypto';
import {
  createLocalJWKSet,
  jwtVerify,
  generateKeyPair,
  exportJWK,
  SignJWT,
  type JSONWebKeySet,
} from 'jose';
import { z } from 'zod';

export class Fault extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(code);
  }
}
export const IdentitySchema = z
  .object({
    subject: z.string().min(1).max(200),
    tenant: z.string().regex(/^[a-z0-9-]{1,64}$/),
    agent: z.string().regex(/^[a-z0-9-]{1,64}$/),
    role: z.enum(['agent', 'analyst', 'operator']),
  })
  .strict();
export type Identity = z.infer<typeof IdentitySchema>;
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object')
    return (
      '{' +
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => JSON.stringify(k) + ':' + canonical(v))
        .join(',') +
      '}'
    );
  return JSON.stringify(value) ?? 'null';
}
export const digest = (v: unknown) => createHash('sha256').update(canonical(v)).digest('hex');
export interface AuthConfig {
  issuer: string;
  audience: string;
  jwks: JSONWebKeySet;
  identities: Identity[];
}
export class Auth {
  private keys;
  private identities: Map<string, Identity>;
  constructor(public config: AuthConfig) {
    if (!config.jwks.keys.length || config.jwks.keys.some((k) => 'd' in k || k.kty === 'oct'))
      throw new Error('Public asymmetric verification keys required');
    this.keys = createLocalJWKSet(config.jwks);
    const ids = z.array(IdentitySchema).min(1).max(1000).parse(config.identities);
    this.identities = new Map(ids.map((i) => [i.subject, Object.freeze(i)]));
    if (this.identities.size !== ids.length) throw new Error('Duplicate subject');
  }
  async verify(header: string | undefined): Promise<Identity> {
    if (!header?.startsWith('Bearer ') || header.length > 8192)
      throw new Fault(401, 'invalid_token');
    try {
      const { payload, protectedHeader } = await jwtVerify(header.slice(7), this.keys, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        algorithms: ['ES256', 'RS256'],
        requiredClaims: ['exp', 'iat', 'sub', 'jti'],
        maxTokenAge: '15m',
        clockTolerance: 2,
      });
      if (
        protectedHeader.typ !== 'at+jwt' ||
        typeof payload.jti !== 'string' ||
        !payload.jti ||
        payload.exp! - payload.iat! > 900
      )
        throw new Error('Token contract');
      const identity = this.identities.get(payload.sub!);
      if (!identity) throw new Error('Unregistered subject');
      return identity;
    } catch {
      throw new Fault(401, 'invalid_token');
    }
  }
}
export async function demoAuth(audience: string) {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const key = { ...(await exportJWK(publicKey)), kid: 'ephemeral-demo', alg: 'ES256', use: 'sig' };
  const identities: Identity[] = [
    { subject: 'demo-agent', tenant: 'sandbox', agent: 'researcher', role: 'agent' },
    { subject: 'demo-analyst', tenant: 'sandbox', agent: 'investigator', role: 'analyst' },
    { subject: 'demo-operator', tenant: 'sandbox', agent: 'reviewer', role: 'operator' },
    { subject: 'other-tenant', tenant: 'isolated', agent: 'outsider', role: 'operator' },
  ];
  const issuer = 'https://issuer.invalid/demo';
  const tokens = Object.fromEntries(
    await Promise.all(
      identities.map(async (i) => [
        i.role === 'operator' && i.tenant === 'isolated' ? 'outsider' : i.role,
        await new SignJWT({})
          .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: key.kid })
          .setIssuer(issuer)
          .setAudience(audience)
          .setSubject(i.subject)
          .setJti(randomUUID())
          .setIssuedAt()
          .setExpirationTime('15m')
          .sign(privateKey),
      ]),
    ),
  );
  return {
    auth: new Auth({ issuer, audience, jwks: { keys: [key] }, identities }),
    tokens,
    privateKey,
  };
}
/** Bounded fixed windows. Overflow fails closed until the oldest window expires. */
export class Limiter {
  private buckets = new Map<string, { n: number; until: number }>();
  constructor(
    private limit = 120,
    private window = 60000,
    private maxKeys = 10000,
  ) {}
  take(key: string, now = Date.now()) {
    for (const [k, v] of this.buckets) if (v.until <= now) this.buckets.delete(k);
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maxKeys) throw new Fault(429, 'rate_limited');
      bucket = { n: 0, until: now + this.window };
      this.buckets.set(key, bucket);
    }
    if (++bucket.n > this.limit) throw new Fault(429, 'rate_limited');
  }
}
