import { z } from 'zod';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { digest, Fault } from './security.js';
import { execute } from './tools.js';
const Config = z
  .object({
    url: z.url(),
    tools: z
      .array(
        z
          .object({
            local: z.enum(['knowledge.search', 'cloud.audit.summary', 'evidence.export']),
            remote: z.string().min(1).max(100),
            descriptorHash: z.string().regex(/^[0-9a-f]{64}$/),
          })
          .strict(),
      )
      .min(1)
      .max(3),
  })
  .strict();
export type UpstreamConfig = z.infer<typeof Config>;
export function upstreamExecutor(input: unknown, token: string | undefined, allowLocal = false) {
  const config = Config.parse(input),
    url = new URL(config.url);
  if (
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    !(
      url.protocol === 'https:' ||
      (allowLocal && url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname))
    )
  )
    throw new Error('Upstream requires a fixed HTTPS URL without credentials, query, or fragment');
  if (new Set(config.tools.map((t) => t.local)).size !== config.tools.length)
    throw new Error('Duplicate tool mapping');
  return {
    version: digest(config),
    execute: async (name: string, args: unknown): Promise<unknown> => {
      const mapping = config.tools.find((t) => t.local === name);
      if (!mapping) return execute(name, args);
      const client = new Client({ name: 'mcp-sentinel-upstream', version: '1.0.0' });
      // Never forward the caller token. Redirects fail, and every network request has a deadline.
      const limitedFetch: typeof fetch = async (input, init) => {
        const response = await fetch(input, {
          ...init,
          redirect: 'error',
          signal: AbortSignal.any([
            ...(init?.signal ? [init.signal] : []),
            AbortSignal.timeout(5000),
          ]),
        });
        if (!response.body) return response;
        const reader = response.body.getReader();
        let size = 0;
        const stream = new ReadableStream({
          async pull(controller) {
            try {
              const chunk = await reader.read();
              if (chunk.done) {
                controller.close();
                return;
              }
              size += chunk.value.byteLength;
              if (size > 262144) {
                await reader.cancel();
                controller.error(new Error('Upstream response too large'));
                return;
              }
              controller.enqueue(chunk.value);
            } catch (e) {
              controller.error(e);
            }
          },
          cancel: () => reader.cancel(),
        });
        return new Response(stream, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      };
      try {
        await client.connect(
          new StreamableHTTPClientTransport(url, {
            fetch: limitedFetch,
            requestInit: { headers: token ? { authorization: 'Bearer ' + token } : {} },
          }),
          { timeout: 5000 },
        );
        const catalog = await client.listTools({}, { timeout: 5000 });
        if (catalog.nextCursor) throw new Fault(502, 'upstream_catalog_requires_pagination');
        const remote = catalog.tools.find((t) => t.name === mapping.remote);
        if (
          !remote ||
          digest({
            name: remote.name,
            description: remote.description ?? '',
            inputSchema: remote.inputSchema,
          }) !== mapping.descriptorHash
        )
          throw new Fault(502, 'upstream_descriptor_changed');
        const result = await client.callTool(
          { name: mapping.remote, arguments: args as Record<string, unknown> },
          undefined,
          { timeout: 5000 },
        );
        if (Buffer.byteLength(JSON.stringify(result)) > 65536)
          throw new Fault(502, 'upstream_result_too_large');
        if (result.isError) throw new Fault(502, 'upstream_tool_error');
        return { source: 'pinned-upstream', content: result.content };
      } finally {
        await client.close();
      }
    },
  };
}
