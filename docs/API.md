# API contract

All `/api/*` and `/mcp` requests require a bearer access token. Examples assume the demo is running and that `AGENT_TOKEN` and `OPERATOR_TOKEN` contain the terminal tokens. Do not commit these environment values. JSON request bodies use `Content-Type: application/json`.

```sh
curl -s http://127.0.0.1:4310/api/call   -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json'   -d '{"tool":"knowledge.search","arguments":{"query":"approval"}}'
```

| Route                                       | Role                              | Result                                                                |
| ------------------------------------------- | --------------------------------- | --------------------------------------------------------------------- |
| `GET /health`                               | Public                            | Liveness only, no sensitive state                                     |
| `GET /.well-known/oauth-protected-resource` | Public                            | Resource and configured external authorization server metadata        |
| `GET /api/me`                               | Any registered identity           | Server-owned identity                                                 |
| `GET /api/tools`                            | Any registered identity           | Policy-filtered catalog and schema hashes                             |
| `POST /api/call`                            | Exact policy grant                | `{tool, arguments, approvalId?}`; execution result                    |
| `POST /api/approvals`                       | Approval-gated tool grant         | `{tool, arguments}`; 201 pending approval                             |
| `GET /api/approvals`                        | Operator                          | Up to 100 recent tenant approvals                                     |
| `POST /api/approvals/:id/review`            | Independent operator              | `{approve:true}` or `{approve:false}`                                 |
| `GET /api/overview`                         | Analyst, operator                 | Recent ledger, policy, totals, integrity and signals                  |
| `GET /api/audit`                            | Analyst, operator                 | Up to 200 tenant entries and incremental database verification result |
| `POST /mcp`                                 | Authenticated plus per-tool grant | Stateless Streamable HTTP MCP                                         |

Calls use strict top-level and argument schemas. Knowledge query length is 1 to 200. Evidence export arguments are `{"caseId":"case-demo","format":"json"}`; case IDs match `case-[a-z0-9-]{1,40}`. Summary arguments are `{provider, records}` with provider `aws`, `azure`, or `gcp` and 1 to 100 records.

Cloud summary projections require:

- AWS: `eventID`, ISO UTC `eventTime`, `eventName`, and `userIdentity.principalId`.
- Azure: `eventDataId`, ISO UTC `eventTimestamp`, `caller`, and `operationName.value`.
- GCP: `insertId`, ISO UTC `timestamp`, `protoPayload.methodName`, and `protoPayload.authenticationInfo.principalEmail`.

These are deliberately small export projections. They do not imply support for every provider event type. Required strings are 1 to 200 characters. Unknown provider fields are not echoed; the response includes provider, count, unique sorted actions, input digest, and `source=supplied-export`.

Typical REST errors: 400 invalid request, 401 invalid token, 403 forbidden/policy denied/approval required, 404 approval not found, 409 approval unavailable, 413 body too large, 429 rate or queue limit, 502 tool failed. Executor details are hidden. Approvals cannot be renewed or reused. A rejected execution does not consume an unrelated valid approval.

The dashboard shows bounded recent evidence. Totals count only the fetched recent 200 entries, not all-time service traffic. The pending count is a current tenant database count. Detection signals inspect the latest 1,000 tenant entries within a sixty-second window.

`GET /api/overview` returns integer totals, for example `"totals":{"allowed":2,"denied":1,"pending":0}`. Version 1.1 changes `totals.pending` from `{n:number}` to `number`.
