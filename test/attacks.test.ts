import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const key = 'k'.repeat(32);
test('bounds unauthenticated audit flooding from 1000 bad tokens', async () => {
  const demo = await demoAuth('mcp-sentinel');
  const store = new Store(':memory:', key);
  const { app } = createApp({
    auth: demo.auth,
    store,
    baseUrl: 'http://127.0.0.1:4310',
    limit: 2000,
  });
  try {
    for (let i = 0; i < 1000; i++) {
      const r = await app.inject({
        url: '/api/me',
        headers: { host: '127.0.0.1:4310', authorization: 'Bearer bad' },
      });
      assert.equal(r.statusCode, 401);
    }
    await app.close();
    const rows = store.audits('system', 2000);
    assert.ok(rows.length <= 2);
    assert.equal(rows[0]?.action, 'authentication.denied');
    assert.equal(
      rows.reduce((n, r) => n + Number(r.detail.count), 0),
      1000,
    );
  } finally {
    await app.close();
    store.close();
  }
});
test('incremental verification rejects a tampered newer audit row', () => {
  const store = new Store(':memory:', key);
  try {
    store.audit('sandbox', 'a', 'first', 'allowed');
    assert.equal(store.verify(), true);
    store.audit('sandbox', 'a', 'second', 'allowed');
    store.db.exec("UPDATE audit SET body=json_set(body,'$.outcome','denied') WHERE seq=2");
    assert.equal(store.verify(), false);
  } finally {
    store.close();
  }
});
