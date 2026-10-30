import { z } from 'zod';
import { digest, Fault } from './security.js';
const text = z.string().min(1).max(200);
const CloudRecord = z.record(z.string(), z.unknown());
const Knowledge = z.object({ query: text }).strict();
const Summary = z
  .object({
    provider: z.enum(['aws', 'azure', 'gcp']),
    records: z.array(CloudRecord).min(1).max(100),
  })
  .strict();
const Export = z
  .object({ caseId: z.string().regex(/^case-[a-z0-9-]{1,40}$/), format: z.literal('json') })
  .strict();
export const tools = [
  {
    name: 'knowledge.search',
    description: 'Search the local security reference catalog.',
    schema: Knowledge,
  },
  {
    name: 'cloud.audit.summary',
    description:
      'Validate and summarize supplied cloud audit exports. Performs no cloud API calls.',
    schema: Summary,
  },
  {
    name: 'evidence.export',
    description: 'Create a synthetic case evidence manifest. Requires independent approval.',
    schema: Export,
  },
];
const entry = (name: string) => {
  const t = tools.find((t) => t.name === name);
  if (!t) throw new Fault(403, 'unknown_tool');
  return t;
};
export const schemaHash = (name: string) => digest(z.toJSONSchema(entry(name).schema));
export const validate = (name: string, args: unknown) => entry(name).schema.parse(args);
export function cloudSummary(input: unknown) {
  const { provider, records } = Summary.parse(input);
  const actions = records.map((record) => {
    if (provider === 'aws')
      return z
        .object({
          eventID: text,
          eventTime: z.iso.datetime(),
          eventName: text,
          userIdentity: z.object({ principalId: text }),
        })
        .parse(record).eventName;
    if (provider === 'azure')
      return z
        .object({
          eventDataId: text,
          eventTimestamp: z.iso.datetime(),
          caller: text,
          operationName: z.object({ value: text }),
        })
        .parse(record).operationName.value;
    return z
      .object({
        insertId: text,
        timestamp: z.iso.datetime(),
        protoPayload: z.object({
          methodName: text,
          authenticationInfo: z.object({ principalEmail: text }),
        }),
      })
      .parse(record).protoPayload.methodName;
  });
  return {
    provider,
    count: records.length,
    actions: [...new Set(actions)].sort(),
    inputDigest: digest(records),
    source: 'supplied-export',
  };
}
export async function execute(name: string, args: unknown): Promise<unknown> {
  const parsed = validate(name, args);
  if (name === 'cloud.audit.summary') return cloudSummary(parsed);
  if (name === 'evidence.export') {
    const data = {
      caseId: Export.parse(parsed).caseId,
      classification: 'synthetic',
      timeline: [{ time: '2026-01-01T00:00:00Z', action: 'access-reviewed', outcome: 'allowed' }],
    };
    return { format: 'json', data, contentDigest: digest(data) };
  }
  const query = Knowledge.parse(parsed).query.toLowerCase();
  const docs = [
    {
      id: 'least-privilege',
      title: 'Least privilege',
      body: 'Grant exact tools to registered agents. Deny unmatched requests.',
    },
    {
      id: 'approval',
      title: 'Independent approval',
      body: 'Bind a short-lived approval to the actor, arguments, schema, and policy.',
    },
    {
      id: 'audit',
      title: 'Audit integrity',
      body: 'Authenticate each audit entry and retain an external checkpoint.',
    },
  ];
  return {
    matches: docs.filter((d) => (d.title + ' ' + d.body).toLowerCase().includes(query)),
    source: 'local-catalog',
  };
}
