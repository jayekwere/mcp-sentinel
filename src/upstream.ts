import { z } from 'zod';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { digest, Fault } from './security.js';
import { execute, type ExecutionContext } from './tools.js';
import { controlOutput } from './output.js';
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
    execute: async (name: string, args: unknown, context?: ExecutionContext): Promise<unknown> => {
      const mapping = config.tools.find((t) => t.local === name);
      if (!mapping) return execute(name, args);
      const client = new Client({ name: 'mcp-sentinel-upstream', version: '1.0.0' });

      try {
        await client.connect(
          new StreamableHTTPClientTransport(url, {
            fetch: limitedFetch,
            requestInit: { headers: token ? { authorization: 'Bearer ' + token } : {} },
          }),
          { timeout: 5000 },
        );
        const catalog = await client.request({ method: 'tools/list', params: {} }, RawCatalog, {
          timeout: 5000,
        });
        if (catalog.nextCursor) throw new Fault(502, 'upstream_catalog_requires_pagination');
        const remote = catalog.tools.find((t) => t.name === mapping.remote);
        if (!remote || descriptorHash(remote) !== mapping.descriptorHash)
          throw new Fault(502, 'upstream_descriptor_changed');
        const result = await client.request(
          {
            method: 'tools/call',
            params: { name: mapping.remote, arguments: args as Record<string, unknown> },
          },
          z.record(z.string(), z.unknown()),
          { timeout: 5000 },
        );
        if (Buffer.byteLength(JSON.stringify(result)) > 65536)
          throw new Fault(502, 'upstream_result_too_large');
        if (result.isError) throw new Fault(502, 'upstream_tool_error');
        return controlOutput(remote, result, context?.onRedaction);
      } finally {
        await client.close();
      }
    },
  };
}

// Never forward the caller token. Redirects fail, and every network request has a deadline.
const limitedFetch: typeof fetch = async (input, init) => {
  const response = await fetch(input, {
    ...init,
    redirect: 'error',
    signal: AbortSignal.any([...(init?.signal ? [init.signal] : []), AbortSignal.timeout(5000)]),
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

// The volatile-field allowlist is empty: every returned descriptor field is pinned.
export const descriptorHash = (tool: Record<string, unknown>) => digest(tool);
const RawCatalog = z.object({
  tools: z.array(z.record(z.string(), z.unknown())).max(1000),
  nextCursor: z.string().optional(),
});
export async function pinUpstream(url: string, token?: string) {
  upstreamExecutor(
    {
      url,
      tools: [{ local: 'knowledge.search', remote: 'inspect', descriptorHash: '0'.repeat(64) }],
    },
    token,
    process.env.DEMO === '1',
  );
  const client = new Client({ name: 'mcp-sentinel-pin', version: '1' });
  try {
    await client.connect(
      new StreamableHTTPClientTransport(new URL(url), {
        fetch: limitedFetch,
        requestInit: { headers: token ? { authorization: 'Bearer ' + token } : {} },
      }),
      { timeout: 5000 },
    );
    const catalog = await client.request({ method: 'tools/list', params: {} }, RawCatalog, {
      timeout: 5000,
    });
    if (catalog.nextCursor) throw new Error('Paginated catalogs are unsupported');
    return catalog.tools.map((t) => ({ name: t.name, descriptorHash: descriptorHash(t) }));
  } finally {
    await client.close();
  }
}
