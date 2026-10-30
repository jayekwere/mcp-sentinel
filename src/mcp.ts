import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { FastifyInstance } from 'fastify';
import { Gateway } from './gateway.js';
import { Fault } from './security.js';
export function mcpRoutes(app: FastifyInstance, gateway: Gateway, baseUrl: string) {
  app.post('/mcp', async (req, reply) => {
    const server = new Server(
      { name: 'mcp-sentinel', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: gateway.catalog(req.identity).map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema as { type: 'object' },
      })),
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const approval = request.params._meta?.['sentinel/approval'];
        const result = await gateway.call(req.identity, {
          tool: request.params.name,
          arguments: request.params.arguments ?? {},
          ...(typeof approval === 'string' ? { approvalId: approval } : {}),
        });
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      } catch (e) {
        return {
          isError: true,
          content: [{ type: 'text', text: e instanceof Fault ? e.code : 'invalid_request' }],
        };
      }
    });
    const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true });
    await server.connect(transport);
    try {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers))
        if (typeof v === 'string') headers.set(k, v);
      const response = await transport.handleRequest(
        new Request(new URL('/mcp', baseUrl), {
          method: 'POST',
          headers,
          body: JSON.stringify(req.body),
        }),
      );
      reply.status(response.status);
      response.headers.forEach((v, k) => reply.header(k, v));
      return reply.send(await response.text());
    } finally {
      await server.close();
    }
  });
  app.route({
    method: ['GET', 'DELETE'],
    url: '/mcp',
    handler: async (_req, reply) => reply.status(405).send({ error: 'stateless_transport' }),
  });
}
