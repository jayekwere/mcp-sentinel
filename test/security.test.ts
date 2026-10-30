import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Auth, demoAuth, Fault, Limiter, canonical, digest } from '../src/security.js';
import { Store } from '../src/store.js';
let demo: Awaited<ReturnType<typeof demoAuth>>;
before(async () => {
  demo = await demoAuth('test');
});
test('valid asymmetric access token maps to the server registry', async () => {
  const who = await demo.auth.verify('Bearer ' + demo.tokens.agent);
  assert.equal(who.agent, 'researcher');
  assert.equal(who.role, 'agent');
});
for (const kind of [
  'issuer',
  'audience',
  'expired',
  'future',
  'lifetime',
  'subject',
  'type',
  'jti',
  'forged-role',
])
  test('token contract: ' + kind, async () => {
    const now = Math.floor(Date.now() / 1000);
    let jwt = new SignJWT({ role: 'operator', tenant: 'isolated' })
      .setProtectedHeader({
        alg: 'ES256',
        kid: 'ephemeral-demo',
        typ: kind === 'type' ? 'JWT' : 'at+jwt',
      })
      .setIssuer(kind === 'issuer' ? 'https://evil.invalid' : 'https://issuer.invalid/demo')
      .setAudience(kind === 'audience' ? 'other' : 'test')
      .setSubject(kind === 'subject' ? 'unregistered' : 'demo-agent')
      .setIssuedAt(now)
      .setExpirationTime(
        kind === 'expired' ? now - 30 : kind === 'lifetime' ? now + 1000 : now + 60,
      );
    if (kind !== 'jti') jwt = jwt.setJti('test-jti');
    if (kind === 'future') jwt = jwt.setNotBefore(now + 60);
    const header = 'Bearer ' + (await jwt.sign(demo.privateKey));
    if (kind === 'forged-role') {
      const who = await demo.auth.verify(header);
      assert.equal(who.role, 'agent');
      assert.equal(who.tenant, 'sandbox');
    } else await assert.rejects(demo.auth.verify(header), { code: 'invalid_token' });
  });
test('invalid headers, unsigned payloads, and foreign signing keys fail closed', async () => {
  for (const h of [undefined, '', 'Basic value', 'Bearer a.b.c', 'Bearer ' + 'x'.repeat(9000)])
    await assert.rejects(demo.auth.verify(h), { code: 'invalid_token' });
  const pair = await generateKeyPair('ES256');
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: 'ephemeral-demo' })
    .setIssuer('https://issuer.invalid/demo')
    .setAudience('test')
    .setSubject('demo-agent')
    .setJti('x')
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(pair.privateKey);
  await assert.rejects(demo.auth.verify('Bearer ' + token));
});
test('private keys and ambiguous identities are rejected at configuration', async () => {
  const pair = await generateKeyPair('ES256', { extractable: true });
  assert.throws(() => new Auth({ ...demo.auth.config, jwks: { keys: [awaitKey()] } }));
  function awaitKey() {
    return { kty: 'oct', k: 'bad' };
  }
  const privateJwk = await exportJWK(pair.privateKey);
  assert.throws(() => new Auth({ ...demo.auth.config, jwks: { keys: [privateJwk] } }));
  assert.throws(
    () =>
      new Auth({
        ...demo.auth.config,
        identities: [demo.auth.config.identities[0]!, demo.auth.config.identities[0]!],
      }),
  );
});
test('canonical request digest ignores object key order and preserves array order', () => {
  assert.equal(digest({ a: 1, b: [2, 3] }), digest({ b: [2, 3], a: 1 }));
  assert.notEqual(digest([1, 2]), digest([2, 1]));
  assert.equal(canonical(null), 'null');
});
test('rate limits include bounded key capacity and window expiry', () => {
  const limiter = new Limiter(2, 100, 1);
  limiter.take('a', 0);
  limiter.take('a', 1);
  assert.throws(() => limiter.take('a', 2), { code: 'rate_limited' });
  assert.throws(() => limiter.take('b', 2), { code: 'rate_limited' });
  limiter.take('b', 101);
});
test('audit detects edited content, removed middle records, and wrong keys on reopen', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-test-')),
    file = join(dir, 'state.sqlite'),
    key = 'k'.repeat(32);
  let store = new Store(file, key);
  try {
    store.audit('a', 'actor', 'one', 'allowed');
    store.audit('b', 'actor', 'two', 'denied');
    store.audit('a', 'actor', 'three', 'allowed');
    assert.equal(store.verify(), true);
    assert.equal(store.audits('a').length, 2);
    store.close();
    store = new Store(file, key);
    assert.equal(store.verify(), true);
    assert.throws(() => {
      const other = new Store(file, 'x'.repeat(32));
      other.close();
    }, /integrity/);
    store.db.prepare('DELETE FROM audit WHERE seq=2').run();
    assert.equal(store.verify(), false);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test('database transaction rolls back intent and state together', () => {
  const store = new Store(':memory:', 'k'.repeat(32));
  try {
    assert.throws(() =>
      store.transaction(() => {
        store.audit('a', 'b', 'c', 'allowed');
        throw new Fault(409, 'conflict');
      }),
    );
    assert.equal(store.audits('a').length, 0);
  } finally {
    store.close();
  }
});

test('RS256 public verification and audit content-edit detection', async () => {
  const pair = await generateKeyPair('RS256');
  const key = { ...(await exportJWK(pair.publicKey)), kid: 'rsa', alg: 'RS256' };
  const auth = new Auth({ ...demo.auth.config, jwks: { keys: [key] } });
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'rsa' })
    .setIssuer('https://issuer.invalid/demo')
    .setAudience('test')
    .setSubject('demo-agent')
    .setJti('rsa-test')
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(pair.privateKey);
  assert.equal((await auth.verify('Bearer ' + token)).role, 'agent');
  const store = new Store(':memory:', 'k'.repeat(32));
  try {
    store.audit('a', 'b', 'c', 'denied');
    store.db
      .prepare("UPDATE audit SET body=json_set(body,'$.outcome','allowed') WHERE seq=1")
      .run();
    assert.equal(store.verify(), false);
  } finally {
    store.close();
  }
});
