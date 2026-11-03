import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
import { Fault } from './security.js';
const patterns: [string, RegExp][] = [
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  [
    'pem-private-key',
    /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
  ],
  ['jwt', /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g],
];
export function controlOutput(
  descriptor: Record<string, unknown>,
  result: Record<string, unknown>,
  onRedaction?: (counts: Record<string, number>) => void,
) {
  const content = result.content;
  if (
    !Array.isArray(content) ||
    content.some((c) => !c || c.type !== 'text' || typeof c.text !== 'string')
  )
    throw new Fault(502, 'upstream_content_rejected');
  const counts: Record<string, number> = {};
  const scan = (text: string) => {
    for (const [type, pattern] of patterns)
      text = text.replace(pattern, () => {
        counts[type] = (counts[type] ?? 0) + 1;
        return `[REDACTED:${type}]`;
      });
    return text;
  };
  const sanitize = (value: unknown): unknown => {
    if (typeof value === 'string') return scan(value);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === 'object')
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [scan(k), sanitize(v)]));
    return value;
  };
  let validator;
  if (descriptor.outputSchema !== undefined) {
    try {
      validator = new AjvJsonSchemaValidator().getValidator(
        descriptor.outputSchema as Record<string, unknown>,
      );
    } catch {
      throw new Fault(502, 'upstream_output_schema_invalid');
    }
    if (!result.structuredContent || !validator(result.structuredContent).valid)
      throw new Fault(502, 'upstream_output_schema_invalid');
  }
  const cleanContent = content.map((c) => ({ type: 'text', text: scan(c.text) }));
  const structuredContent = sanitize(result.structuredContent);
  if (Object.keys(counts).length) onRedaction?.(counts);
  if (validator && !validator(structuredContent).valid)
    throw new Fault(502, 'upstream_output_schema_invalid');
  return {
    source: 'pinned-upstream',
    content: cleanContent,
    ...(structuredContent === undefined ? {} : { structuredContent }),
  };
}
