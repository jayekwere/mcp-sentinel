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

Run `npm run pin:upstream -- https://tools.invalid/mcp` with the optional dedicated `UPSTREAM_TOKEN` in the environment. Review the descriptors independently before copying the printed name and `descriptorHash` into configuration. The tool uses the same bounded transport as execution. It rejects paginated catalogs. `DEMO=1` additionally permits explicit loopback HTTP for fixtures.

Pins hash the complete canonical descriptor returned by `tools/list`, including `title`, `annotations`, `outputSchema`, `_meta`, icons, execution metadata, and unknown extension fields. The volatile-field exclusion allowlist is empty. No descriptor field is omitted. Missing and explicitly empty fields produce different hashes. Version 1.0 pins must be regenerated.

Each invocation opens an independent SDK connection, initializes, lists tools, validates the selected descriptor, invokes it, and closes the connection. Paginated catalogs fail closed rather than silently skipping checks. A change to any descriptor field blocks execution before calling the tool. The binding for outstanding approvals includes the full upstream configuration hash, so a configuration change invalidates prior approvals.

Every outbound request has a five-second deadline; JSON/SSE response bytes are capped at 256 KiB, and the final tool result at 64 KiB. Redirects fail. SDK operations use five-second timeouts. There is no automatic tool retry, token exchange, user-supplied target routing, arbitrary tool discovery proxy, or OAuth login to upstreams. A dedicated server credential is sent, and the caller's token is never forwarded.

The configured server is an operator trust decision. Restrict outbound network access to intended services. Metadata pins detect drift but do not attest code or sanitize arbitrary tool output. Approval consumption happens before network execution; a timeout may leave the remote outcome unknown. Investigate before granting another attempt. Tests validate local SDK behavior, credential isolation and drift prevention, not a live external MCP service.
