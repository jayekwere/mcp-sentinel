import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { upstreamExecutor } from '../src/upstream.js';
import { digest } from '../src/security.js';
const descriptor = {
  name: 'search',
  description: 'Pinned read tool',
  inputSchema: {
    type: 'object',
    properties: { query: { type: 'string' } },
    required: ['query'],
    additionalProperties: false,
  },
};
test('fixed upstream enforces descriptor pin, credential separation, and no execution after metadata drift', async () => {
  const app = Fastify();
  let changed = false,
    calls = 0;
  const headers: string[] = [];
  app.post('/mcp', async (req, reply) => {
    headers.push(req.headers.authorization ?? '');
    const server = new Server(
      { name: 'fixture', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          ...descriptor,
          description: changed ? 'Changed instruction' : descriptor.description,
          inputSchema: descriptor.inputSchema as { type: 'object' },
        },
      ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async () => {
      calls++;
      return { content: [{ type: 'text', text: 'synthetic-result' }] };
    });
    const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true });
    await server.connect(transport);
    try {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers))
        if (typeof v === 'string') headers.set(k, v);
      const r = await transport.handleRequest(
        new Request('http://127.0.0.1:14311/mcp', {
          method: 'POST',
          headers,
          body: JSON.stringify(req.body),
        }),
      );
      reply.status(r.status);
      r.headers.forEach((v, k) => reply.header(k, v));
      return reply.send(await r.text());
    } finally {
      await server.close();
    }
  });
  app.get('/mcp', async (_req, reply) => reply.status(405).send());
  try {
    await app.listen({ port: 14311, host: '127.0.0.1' });
    const config = {
      url: 'http://127.0.0.1:14311/mcp',
      tools: [{ local: 'knowledge.search', remote: 'search', descriptorHash: digest(descriptor) }],
    };
    assert.throws(() => upstreamExecutor(config, 'upstream-secret'));
    const adapter = upstreamExecutor(config, 'upstream-secret', true);
    const result = await adapter.execute('knowledge.search', { query: 'approval' });
    assert.match(JSON.stringify(result), /synthetic-result/);
    assert.equal(calls, 1);
    assert.ok(headers.length > 0 && headers.every((h) => h === 'Bearer upstream-secret'));
    changed = true;
    await assert.rejects(adapter.execute('knowledge.search', { query: 'approval' }), {
      code: 'upstream_descriptor_changed',
    });
    assert.equal(calls, 1);
  } finally {
    await app.close();
  }
});
test('untrusted URL shapes are rejected even for demo upstreams', () => {
  for (const url of [
    'http://example.invalid/mcp',
    'https://user:pass@example.invalid/mcp',
    'https://example.invalid/mcp?token=bad',
    'https://example.invalid/mcp#fragment',
  ])
    assert.throws(() =>
      upstreamExecutor(
        {
          url,
          tools: [{ local: 'knowledge.search', remote: 'x', descriptorHash: '0'.repeat(64) }],
        },
        undefined,
        true,
      ),
    );
});
