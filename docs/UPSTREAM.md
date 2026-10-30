# Pinned upstream MCP adapter

Set `UPSTREAM_CONFIG` to a read-only JSON file and optionally `UPSTREAM_TOKEN` to a dedicated, least-privilege bearer credential. Never place client credentials or a secret in the URL. A configuration has this shape:

```json
{
  "url": "https://tools.invalid/mcp",
  "tools": [
    {
      "local": "knowledge.search",
      "remote": "search",
      "descriptorHash": "<64 lowercase hex characters>"
    }
  ]
}
```

The placeholder hash deliberately fails validation. Each local name must be unique and be one of the three built-in tools. The local strict argument schema and authorization still apply. Remote tools must accept that local argument shape. Unmapped tools run locally. HTTPS is required; demo mode additionally permits explicit loopback HTTP addresses. URL credentials, query strings, and fragments are rejected.

Calculate a pin after manually reviewing a real `tools/list` response. Import `digest` from the compiled `dist/src/security.js` module and hash exactly `{name: tool.name, description: tool.description ?? '', inputSchema: tool.inputSchema}` using the returned descriptor. Do not paste a guessed hash. The unit test hosts a real SDK server and calculates the pin from its actual fixture descriptor.

Each invocation opens an independent SDK connection, initializes, lists tools, validates the selected descriptor, invokes it, and closes the connection. Paginated catalogs fail closed rather than silently skipping checks. A changed name, description, or input schema blocks execution. The binding for outstanding approvals includes the full upstream configuration hash, so a configuration change invalidates prior approvals.

Every outbound request has a five-second deadline; JSON/SSE response bytes are capped at 256 KiB, and the final tool result at 64 KiB. Redirects fail. SDK operations use five-second timeouts. There is no automatic tool retry, token exchange, user-supplied target routing, arbitrary tool discovery proxy, or OAuth login to upstreams. A dedicated server credential is sent, and the caller's token is never forwarded.

The configured server is an operator trust decision. Restrict outbound network access to intended services. Metadata pins detect drift but do not attest code or sanitize arbitrary tool output. Approval consumption happens before network execution; a timeout may leave the remote outcome unknown. Investigate before granting another attempt. Tests validate local SDK behavior, credential isolation and drift prevention, not a live external MCP service.
