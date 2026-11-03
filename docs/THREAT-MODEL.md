# Threat model

## Assets and trust boundaries

Protect tool execution authority, operator approval authority, upstream credentials, tenant evidence, audit integrity, and service availability. Treat clients, tool arguments, cloud exports, and upstream output as untrusted. Trust the configured token issuer for subject authentication, the local identity registry and policy for authorization, and the service operator for endpoint configuration. The service host, database, and audit key form the trusted computing base.

| Attacker action                                        | Control                                                                          | Evidence and residual risk                                                                  |
| ------------------------------------------------------ | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Forge identity or alter tenant/role claims             | Asymmetric signature and claim verification, server registry                     | Token contract tests; stolen valid bearer tokens remain usable until expiry                 |
| Invoke an ungranted tool or impersonate an agent       | Exact subject mapping and default-deny policy                                    | Role/agent/tenant negative tests, scoped discovery                                          |
| Sneak a URL, command, or extra field through arguments | Strict bounded schemas and fixed executors                                       | Unexpected argument tests; extending the tool registry needs a fresh review                 |
| Self-approve or review another tenant's request        | Independent same-tenant operator check                                           | Self-approval and cross-tenant tests                                                        |
| Reuse or race an approval                              | Bound canonical request and transactionally consumed state                       | Changed actor/args/policy, concurrent callers, expiry, and restart tests                    |
| Change an upstream tool description or schema          | Full descriptor hash pin before each call                                        | Metadata-drift test; unchanged malicious runtime behavior remains possible                  |
| Steal a caller token through upstream forwarding       | Dedicated upstream credential, fixed target, no redirects                        | Real SDK adapter credential test; trusted operators can configure outbound endpoints        |
| Cause unaudited execution                              | Intent persisted before execution, failures reported generically                 | Audit ordering and failure tests; crash creates an unresolved intent                        |
| Tamper with stored history                             | HMAC chain and startup verification                                              | Persistence/tamper tests; host/key compromise and suffix rollback require external controls |
| Read another tenant's evidence                         | Tenant predicates and role checks                                                | API and approval isolation tests; a fully privileged host operator can read all data        |
| Inject script into the dashboard                       | Text-node rendering, local assets, restrictive CSP                               | Browser workflow and mobile tests; no comprehensive external penetration test claimed       |
| Exhaust CPU, memory, approval rows, or disk            | Bounded bodies, token length, rate buckets, queue, upstream output and deadlines | Bounds tests; audit storage has no automatic retention and needs monitoring                 |

## Out of scope

The service does not secure a compromised issuer, host, operator, or malicious upstream whose pinned metadata remains unchanged. It does not make arbitrary LLM output safe, implement a cloud IAM provider, validate cloud export provenance, or supply a full OAuth authorization server. Tool outputs remain untrusted at the client. No broad prompt-injection detection claim is made.

Security invariants: unauthorized tools never execute; approval is independent and exact; one approval permits at most one execution attempt; tenant-visible records are scoped; credentials are never written into audit details; errors do not return upstream secrets. Change these only with explicit design review and failure-inducing tests.

Upstream output controls allow only text content, enforce any pinned output schema against required structured content, and redact deterministic AWS access-key, PEM private-key, JWT-shaped, and GitHub-token patterns from returned text and structured strings. Redactions produce counts and a detection without storing the matched secret. If redaction violates an output schema, the result fails closed. These controls check content types and secret patterns. They don't detect prompt injection or prove that returned text is safe to execute or trust. Pattern variants and unrecognized secret formats can pass through.
