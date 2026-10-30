# Design decisions

## 001: A small single-node service

Use strict TypeScript, a typed schema boundary, an HTTP server, a small browser application, and SQLite. This keeps authentication, state transitions, and replay behavior inspectable without requiring a distributed stack. The cost is a single-node capacity and availability boundary. Synchronous database operations are deliberately bounded for the reference workloads; this is not a streaming platform.

## 002: Server-owned identity mapping

Validate access-token signatures and claim constraints, then map the subject through an operator-managed registry. Ignore token-supplied application roles and tenant labels. A compromised low-privilege client cannot promote itself by changing those claims. The tradeoff is explicit provisioning and restart-based mapping changes.

## 003: No dynamic credential or endpoint routing

The application does not accept a target URL, cloud credential, shell command, or code expression from a caller. Cloud data arrives as supplied exports. Sentinel's optional upstream endpoint and descriptor pins are operator configuration, and its upstream credential is separate from client credentials. This narrows confused-deputy and outbound-request risks at the expense of a deliberately small integration surface.

## 004: Inspectable evidence

Keep versioned rules, request fingerprints, audit sequence information, and event evidence visible. Do not retain complete raw cloud records or arbitrary tool arguments in the audit trail. No model-generated explanation is used to authorize a request or decide whether a deterministic rule matched. Descriptions communicate what the rule observed and leave intent assessment to an investigator.

## 005: Minimal browser state

Compile local TypeScript into a single script and use semantic HTML, system fonts, and local CSS. Render all untrusted values through text nodes. Use no external fonts, analytics, cookies, or browser credential storage. A strict content security policy blocks inline script execution. The cost is manual token connection for the local demonstration rather than a bundled sign-in service.
