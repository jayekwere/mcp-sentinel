import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Store } from './store.js';
import { digest, canonical, argumentPreview, Fault, type Identity } from './security.js';
import { PolicyEngine } from './policy.js';
import { execute, schemaHash, tools, validate } from './tools.js';
export const CallSchema = z
  .object({
    tool: z.string().min(1).max(100),
    arguments: z.record(z.string(), z.unknown()),
    approvalId: z.string().uuid().optional(),
  })
  .strict();
export type Call = z.infer<typeof CallSchema>;
interface Approval {
  id: string;
  tenant: string;
  subject: string;
  binding: string;
  expires: number;
  status: string;
  reviewer: string | null;
  request: string;
}
export class Gateway {
  constructor(
    readonly store: Store,
    readonly policy = new PolicyEngine(),
    private now = () => Date.now(),
    private executor = execute,
    private executionVersion = 'builtin-v1',
  ) {}
  private binding(who: Identity, call: Call) {
    return digest({
      subject: who.subject,
      tenant: who.tenant,
      agent: who.agent,
      tool: call.tool,
      args: call.arguments,
      policy: this.policy.hash,
      schema: schemaHash(call.tool),
      execution: this.executionVersion,
    });
  }
  private check(who: Identity, call: Call) {
    try {
      validate(call.tool, call.arguments);
      const decision = this.policy.evaluate(who, call.tool);
      if (decision.effect === 'deny') throw new Fault(403, 'policy_denied');
      return decision;
    } catch (e) {
      this.store.audit(who.tenant, who.subject, 'tool.denied', 'denied', {
        tool: call.tool,
        policy: this.policy.hash,
        reason: e instanceof Fault ? e.code : 'invalid_arguments',
      });
      throw e;
    }
  }
  catalog(who: Identity) {
    return tools
      .filter((t) => this.policy.evaluate(who, t.name).effect !== 'deny')
      .map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: z.toJSONSchema(t.schema),
        schemaHash: schemaHash(t.name),
        approval: this.policy.evaluate(who, t.name).effect === 'approve',
      }));
  }
  request(who: Identity, input: unknown) {
    const call = CallSchema.omit({ approvalId: true }).parse(input),
      decision = this.check(who, call);
    if (decision.effect !== 'approve') throw new Fault(400, 'approval_not_required');
    const id = randomUUID(),
      expires = this.now() + 300000;
    this.store.transaction(() => {
      this.store.db.prepare('DELETE FROM approvals WHERE expires < ?').run(this.now() - 86400000);
      const count = this.store.db
        .prepare(
          "SELECT count(*) AS n FROM approvals WHERE subject=? AND status='pending' AND expires>?",
        )
        .get(who.subject, this.now()) as { n: number };
      if (count.n >= 20) throw new Fault(429, 'approval_queue_full');
      this.store.db
        .prepare(
          'INSERT INTO approvals(id,tenant,subject,binding,expires,status,reviewer,request) VALUES(?,?,?,?,?,?,NULL,?)',
        )
        .run(
          id,
          who.tenant,
          who.subject,
          this.binding(who, call),
          expires,
          'pending',
          canonical({ tool: call.tool, args: call.arguments }),
        );
      this.store.audit(who.tenant, who.subject, 'approval.requested', 'pending', {
        id,
        tool: call.tool,
        args: call.arguments,
        policy: this.policy.hash,
      });
    });
    return {
      id,
      expiresAt: new Date(expires).toISOString(),
      binding: this.binding(who, call),
      status: 'pending',
    };
  }
  review(who: Identity, id: string, approve: boolean) {
    if (who.role !== 'operator') throw new Fault(403, 'forbidden');
    return this.store.transaction(() => {
      const row = this.store.db
        .prepare('SELECT * FROM approvals WHERE id=? AND tenant=?')
        .get(id, who.tenant) as Approval | undefined;
      if (!row) throw new Fault(404, 'approval_not_found');
      if (row.subject === who.subject) throw new Fault(403, 'self_approval');
      if (row.status !== 'pending' || row.expires <= this.now())
        throw new Fault(409, 'approval_unavailable');
      const status = approve ? 'approved' : 'rejected';
      this.store.db
        .prepare('UPDATE approvals SET status=?,reviewer=? WHERE id=?')
        .run(status, who.subject, id);
      this.store.audit(who.tenant, who.subject, 'approval.reviewed', status, { id });
      return { id, status };
    });
  }
  approvals(who: Identity) {
    if (who.role !== 'operator') throw new Fault(403, 'forbidden');
    const rows = this.store.db
      .prepare('SELECT * FROM approvals WHERE tenant=? ORDER BY expires DESC LIMIT 100')
      .all(who.tenant) as unknown as Approval[];
    return rows.map((r) => ({
      ...r,
      request: argumentPreview(JSON.parse(r.request) as Record<string, unknown>),
    }));
  }

  async call(who: Identity, input: unknown) {
    const call = CallSchema.parse(input),
      decision = this.check(who, call),
      requestId = randomUUID();
    if (decision.effect === 'approve') {
      try {
        this.store.transaction(() => {
          const row = this.store.db
            .prepare('SELECT * FROM approvals WHERE id=? AND tenant=?')
            .get(call.approvalId ?? '', who.tenant) as Approval | undefined;
          if (
            !row ||
            row.status !== 'approved' ||
            row.expires <= this.now() ||
            row.subject !== who.subject ||
            row.binding !== this.binding(who, call)
          )
            throw new Fault(403, 'approval_required');
          this.store.db.prepare("UPDATE approvals SET status='consumed' WHERE id=?").run(row.id);
          this.store.audit(who.tenant, who.subject, 'approval.consumed', 'allowed', {
            id: row.id,
            requestId,
          });
        });
      } catch (e) {
        this.store.audit(who.tenant, who.subject, 'approval.invalid', 'denied', {
          tool: call.tool,
        });
        throw e;
      }
    }
    // Write intent before side effects. A consumed approval is never restored on failure.
    this.store.audit(who.tenant, who.subject, 'tool.intent', 'allowed', {
      tool: call.tool,
      argsDigest: digest(call.arguments),
      requestId,
      rule: decision.rule,
      policy: this.policy.hash,
    });
    try {
      const result = await this.executor(call.tool, call.arguments, {
        onRedaction: (counts) => {
          this.store.audit(who.tenant, who.subject, 'upstream.output.redacted', 'redacted', {
            tool: call.tool,
            requestId,
            counts,
          });
        },
      });
      this.store.audit(who.tenant, who.subject, 'tool.completed', 'allowed', {
        tool: call.tool,
        requestId,
      });
      return { requestId, decision: 'allowed', rule: decision.rule, result };
    } catch (error) {
      const safeCodes = [
        'upstream_content_rejected',
        'upstream_output_schema_invalid',
        'upstream_descriptor_changed',
        'upstream_result_too_large',
        'upstream_tool_error',
        'upstream_catalog_requires_pagination',
      ];
      const reason =
        error instanceof Fault && safeCodes.includes(error.code) ? error.code : 'tool_failed';
      this.store.audit(who.tenant, who.subject, 'tool.failed', 'error', {
        tool: call.tool,
        requestId,
        reason,
      });
      throw new Fault(502, reason);
    }
  }
  detections(who: Identity) {
    const events = this.store.audits(who.tenant, 1000),
      recent = events.filter((e) => Date.parse(e.at) > this.now() - 60000);
    const counts = new Map<string, number>();
    for (const e of recent.filter((e) => e.action === 'tool.denied'))
      counts.set(e.actor, (counts.get(e.actor) ?? 0) + 1);
    return [
      ...[...counts]
        .filter(([, n]) => n >= 5)
        .map(([actor, n]) => ({
          rule: 'agent-denial-burst',
          severity: 'high',
          actor,
          count: n,
          windowSeconds: 60,
        })),
      ...recent
        .filter((e) => e.action === 'approval.invalid')
        .map((e) => ({
          rule: 'invalid-approval-use',
          severity: 'high',
          actor: e.actor,
          evidence: e.seq,
        })),
      ...recent
        .filter((e) => e.action === 'upstream.output.redacted')
        .map((e) => ({
          rule: 'upstream-secret-redacted',
          severity: 'high',
          actor: e.actor,
          evidence: e.seq,
        })),
      ...recent
        .filter((e) => e.action === 'tool.failed')
        .map((e) => ({
          rule: 'tool-execution-failure',
          severity: 'medium',
          actor: e.actor,
          evidence: e.seq,
        })),
    ];
  }
}
