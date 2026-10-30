import { DatabaseSync } from 'node:sqlite';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical } from './security.js';

export interface Audit {
  seq: number;
  at: string;
  tenant: string;
  actor: string;
  action: string;
  outcome: string;
  detail: Record<string, unknown>;
  prev: string;
  hash: string;
}
export class Store {
  readonly db: DatabaseSync;
  constructor(
    path: string,
    private key: string,
    private now = () => Date.now(),
  ) {
    if (Buffer.byteLength(key) < 32) throw new Error('Audit key must be at least 32 bytes');
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL, binding TEXT NOT NULL, expires INTEGER NOT NULL, status TEXT NOT NULL, reviewer TEXT);
      CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, body TEXT NOT NULL);
    `);
    if (!this.verify()) {
      this.db.close();
      throw new Error('Audit integrity check failed');
    }
  }
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const value = fn();
      this.db.exec('COMMIT');
      return value;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }
  audit(
    tenant: string,
    actor: string,
    action: string,
    outcome: string,
    detail: Record<string, unknown> = {},
  ): Audit {
    const last = this.db.prepare('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1').get() as
      { seq: number; hash: string } | undefined;
    const body = {
      seq: (last?.seq ?? 0) + 1,
      at: new Date(this.now()).toISOString(),
      tenant,
      actor,
      action,
      outcome,
      detail,
      prev: last?.hash ?? 'genesis',
    };
    const hash = createHmac('sha256', this.key).update(canonical(body)).digest('hex');
    this.db
      .prepare('INSERT INTO audit(seq,body,hash) VALUES(?,?,?)')
      .run(body.seq, canonical(body), hash);
    return { ...body, hash };
  }
  verify(): boolean {
    let prev = 'genesis',
      seq = 1;
    for (const row of this.db.prepare('SELECT body,hash FROM audit ORDER BY seq').all() as {
      body: string;
      hash: string;
    }[]) {
      try {
        const body = JSON.parse(row.body) as Audit;
        const hash = createHmac('sha256', this.key).update(canonical(body)).digest('hex');
        if (
          body.prev !== prev ||
          body.seq !== seq++ ||
          hash.length !== row.hash.length ||
          !timingSafeEqual(Buffer.from(hash), Buffer.from(row.hash))
        )
          return false;
        prev = row.hash;
      } catch {
        return false;
      }
    }
    return true;
  }
  audits(tenant: string, limit = 200): Audit[] {
    return (
      this.db
        .prepare(
          "SELECT body,hash FROM audit WHERE json_extract(body,'$.tenant')=? ORDER BY seq DESC LIMIT ?",
        )
        .all(tenant, limit) as { body: string; hash: string }[]
    ).map((r) => ({ ...JSON.parse(r.body), hash: r.hash }));
  }
  close() {
    this.db.close();
  }
}
