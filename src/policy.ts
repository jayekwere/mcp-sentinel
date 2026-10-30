import { z } from 'zod';
import { digest, type Identity } from './security.js';
const Rule = z
  .object({
    id: z.string().regex(/^[a-z0-9-]+$/),
    effect: z.enum(['allow', 'deny', 'approve']),
    tenants: z.array(z.string()).min(1),
    agents: z.array(z.string()).min(1),
    tools: z.array(z.string()).min(1),
    roles: z.array(z.enum(['agent', 'analyst', 'operator'])).min(1),
  })
  .strict();
export const PolicySchema = z
  .object({ version: z.string().min(1), rules: z.array(Rule).max(100) })
  .strict();
export type Policy = z.infer<typeof PolicySchema>;
export const defaultPolicy: Policy = {
  version: '2026-10-30.1',
  rules: [
    {
      id: 'read-evidence',
      effect: 'allow',
      tenants: ['sandbox'],
      agents: ['researcher'],
      roles: ['agent'],
      tools: ['knowledge.search', 'cloud.audit.summary'],
    },
    {
      id: 'export-review',
      effect: 'approve',
      tenants: ['sandbox'],
      agents: ['researcher'],
      roles: ['agent'],
      tools: ['evidence.export'],
    },
  ],
};
export class PolicyEngine {
  readonly policy: Policy;
  readonly hash: string;
  constructor(input: unknown = defaultPolicy) {
    this.policy = PolicySchema.parse(input);
    this.hash = digest(this.policy);
  }
  evaluate(who: Identity, tool: string): { effect: 'allow' | 'deny' | 'approve'; rule: string } {
    const rules = this.policy.rules.filter(
      (r) =>
        r.tenants.includes(who.tenant) &&
        r.agents.includes(who.agent) &&
        r.roles.includes(who.role) &&
        r.tools.includes(tool),
    );
    const match =
      rules.find((r) => r.effect === 'deny') ??
      rules.find((r) => r.effect === 'approve') ??
      rules.find((r) => r.effect === 'allow');
    return match
      ? { effect: match.effect, rule: match.id }
      : { effect: 'deny', rule: 'default-deny' };
  }
}
