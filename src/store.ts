import { verifyCheckpoint } from './checkpoint.js';
import { DatabaseSync } from 'node:sqlite';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical, argumentPreview } from './security.js';

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
  private verified = { seq: 0, hash: 'genesis' };
  private integrityFailed = false;
  private pendingAudits: Audit[] = [];
  private observers = new Set<(event: Audit) => void>();
  onAudit(fn: (event: Audit) => void) {
    this.observers.add(fn);
    return () => {
      this.observers.delete(fn);
    };
  }
  constructor(
    path: string,
    private key: string,
    private now = () => Date.now(),
    checkpoint: { file?: string | undefined; key?: string | undefined } = {
      file: process.env.CHECKPOINT_FILE,
      key: process.env.CHECKPOINT_PUBLIC_KEY ?? process.env.CHECKPOINT_KEY,
    },
  ) {
    if (Buffer.byteLength(key) < 32) throw new Error('Audit key must be at least 32 bytes');
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    process.umask(0o077);
    this.db = new DatabaseSync(path);
    try {
      if (path !== ':memory:') chmodSync(path, 0o600);
      this.db.exec(
        'PRAGMA busy_timeout=0; PRAGMA journal_mode=WAL; BEGIN IMMEDIATE; COMMIT; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;',
      );
      this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL, binding TEXT NOT NULL, expires INTEGER NOT NULL, status TEXT NOT NULL, reviewer TEXT);
      CREATE TABLE IF NOT EXISTS revocations(tenant TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, subject TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(tenant,kind,value,subject));
      CREATE TABLE IF NOT EXISTS detections(tenant TEXT NOT NULL, rule TEXT NOT NULL, evidence INTEGER NOT NULL, at INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(tenant,rule,evidence));
      CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, body TEXT NOT NULL);
    `);
      const columns = this.db.prepare('PRAGMA table_info(approvals)').all() as { name: string }[];
      if (!columns.some((c) => c.name === 'request'))
        this.transaction(() => {
          this.db.exec(
            "ALTER TABLE approvals ADD COLUMN request TEXT NOT NULL DEFAULT '{}'; UPDATE approvals SET status='invalidated' WHERE status IN ('pending','approved');",
          );
        });
      if (!this.verify(true)) throw new Error('Audit integrity check failed');
      if (checkpoint.file) {
        if (!checkpoint.key) throw new Error('Checkpoint verification key is required');
        verifyCheckpoint(this.db, checkpoint.file, checkpoint.key);
      }
    } catch (e) {
      this.db.close();
      if (e instanceof Error && /database is locked/.test(e.message))
        throw new Error('Database is held by another process: single-writer service');
      throw e;
    }
  }
  transaction<T>(fn: () => T): T {
    if (this.db.isTransaction) return fn();
    this.db.exec('BEGIN IMMEDIATE');
    let value: T;
    try {
      value = fn();
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      this.pendingAudits = [];
      throw e;
    }
    const events = this.pendingAudits;
    this.pendingAudits = [];
    for (const event of events) for (const observe of this.observers) observe(event);
    return value;
  }

  audit(
    tenant: string,
    actor: string,
    action: string,
    outcome: string,
    detail: Record<string, unknown> = {},
  ): Audit {
    return this.transaction(() => {
      const last = this.db
        .prepare('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1')
        .get() as { seq: number; hash: string } | undefined;
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
      const event = { ...body, hash };
      this.pendingAudits.push(event);
      return event;
    });
  }
  verify(full = false): boolean {
    if (this.integrityFailed && !full) return false;
    const head = full ? { seq: 0, hash: 'genesis' } : this.verified;
    const anchor = head.seq
      ? (this.db.prepare('SELECT hash FROM audit WHERE seq=?').get(head.seq) as
          { hash: string } | undefined)
      : undefined;
    if (head.seq && anchor?.hash !== head.hash) return ((this.integrityFailed = true), false);
    let prev = head.hash,
      seq = head.seq + 1;
    for (const row of this.db
      .prepare('SELECT seq,body,hash FROM audit WHERE seq>? ORDER BY seq')
      .all(head.seq) as {
      seq: number;
      body: string;
      hash: string;
    }[]) {
      try {
        const body = JSON.parse(row.body) as Audit;
        const hash = createHmac('sha256', this.key).update(canonical(body)).digest('hex');
        if (
          body.prev !== prev ||
          body.seq !== seq++ ||
          row.seq !== body.seq ||
          hash.length !== row.hash.length ||
          !timingSafeEqual(Buffer.from(hash), Buffer.from(row.hash))
        )
          return ((this.integrityFailed = true), false);
        prev = row.hash;
      } catch {
        return ((this.integrityFailed = true), false);
      }
    }
    this.verified = { seq: seq - 1, hash: prev };
    this.integrityFailed = false;
    return true;
  }
  audits(tenant: string, limit = 200): Audit[] {
    return (
      this.db
        .prepare(
          "SELECT body,hash FROM audit WHERE json_extract(body,'$.tenant')=? ORDER BY seq DESC LIMIT ?",
        )
        .all(tenant, limit) as { body: string; hash: string }[]
    ).map((r) => ({
      ...JSON.parse(r.body),
      hash: r.hash,
      detail: argumentPreview(JSON.parse(r.body).detail),
    }));
  }
  revoked(tenant: string, subject: string, jti: string): boolean {
    return !!this.db
      .prepare(
        "SELECT 1 FROM revocations WHERE tenant=? AND subject=? AND expires>? AND ((kind='jti' AND value=?) OR kind='subject') LIMIT 1",
      )
      .get(tenant, subject, this.now(), jti);
  }
  close() {
    this.observers.clear();
    this.db.close();
  }
}
