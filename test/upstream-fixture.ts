import Fastify from 'fastify';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
export const descriptor = {
  name: 'search',
  description: 'Fixture',
  inputSchema: { type: 'object' as const },
};
export async function upstreamFixture() {
  const app = Fastify();
  const state = {
    descriptor: structuredClone(descriptor) as Record<string, unknown>,
    result: {
      content: [{ type: 'text', text: 'safe' }],
      structuredContent: { ok: true },
    } as Record<string, unknown>,
    calls: 0,
  };
  app.post('/mcp', async (req, reply) => {
    const server = new Server({ name: 'fixture', version: '1' }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [state.descriptor as typeof descriptor],
    }));
    server.setRequestHandler(CallToolRequestSchema, async () => {
      state.calls++;
      return state.result;
    });
    const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true });
    await server.connect(transport);
    try {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers))
        if (typeof v === 'string') headers.set(k, v);
      const r = await transport.handleRequest(
        new Request('http://127.0.0.1/mcp', {
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
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  return { app, state, url: address + '/mcp' };
}
