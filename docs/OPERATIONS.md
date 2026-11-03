# Deployment and operations

## Local demonstration

`DEMO=1` generates a new asymmetric signing key and four short-lived access tokens at startup. Tokens expire after fifteen minutes. Restart to obtain new tokens. Signing keys and the default SQLite database remain in memory. The outsider token exists to demonstrate tenant isolation. No authentication bypass is enabled.

Run `npm ci --ignore-scripts`, `npm run build`, and `DEMO=1 npm start`. Open `http://127.0.0.1:4310`. Copy a token from your terminal into the password field. The UI keeps its active credential in memory, does not use cookies or browser storage, and does not fetch external assets. The separate agent field in Sentinel also stays on the page only. Reload to clear credentials.

`docker compose up --build` starts the same demonstration on a loopback port. `docker compose logs` shows the ephemeral demo tokens. Use `docker compose down` to stop it. The container is non-root, read-only, drops capabilities, and has process and memory limits. Demo logs contain disposable credentials, so restrict log access. Do not expose demo mode publicly.

## Production configuration contract

Demo mode is off unless `DEMO=1` is explicitly set. Startup requires a public HTTPS `BASE_URL`, an `AUTH_CONFIG` JSON file, and a stable `AUDIT_KEY` of at least 32 bytes. Generate the audit key from a cryptographic random source and supply it through a secret manager. Never commit it. Set `DB_PATH` to a writable local SQLite path and mount the parent directory for the non-root container user, UID 1000. Keep configuration files read-only.

| Setting       | Purpose                                                                                  |
| ------------- | ---------------------------------------------------------------------------------------- |
| `BASE_URL`    | External origin, for example `https://security.invalid`; exact Host and Origin allowlist |
| `AUTH_CONFIG` | Path to issuer, audience, public JWKS, and identity registry JSON                        |
| `AUDIT_KEY`   | Stable secret for the HMAC audit chain                                                   |
| `DB_PATH`     | Default `.data/state.sqlite`; demo defaults to `:memory:`                                |
| `HOST`        | Default `127.0.0.1`; image sets `0.0.0.0`                                                |
| `PORT`        | Internal listen port, default 4310                                                       |
| `DEMO`        | Set to `1` only for the local synthetic demonstration                                    |

The authentication configuration has this shape. Replace the empty `keys` array with actual public ES256 or RS256 verification keys from your issuer. An empty array deliberately fails startup.

```json
{
  "issuer": "https://issuer.invalid/realm",
  "audience": "https://security.invalid",
  "jwks": { "keys": [] },
  "identities": [
    { "subject": "agent-subject", "tenant": "sandbox", "agent": "researcher", "role": "agent" },
    { "subject": "reviewer-subject", "tenant": "sandbox", "agent": "reviewer", "role": "operator" }
  ]
}
```

The production audience must equal the external origin. Demo audiences are application names. Access tokens require an asymmetric signature, `typ=at+jwt`, expected issuer and audience, `exp`, `iat`, `sub`, and nonempty `jti`. Lifetime and maximum token age are at most fifteen minutes, with two seconds of clock tolerance. `nbf` is enforced when present. Tokens are reusable bearer credentials during their lifetime. A `jti` is required for traceability, not proof of possession or a replay cache. Use TLS and protect tokens at rest.

The server registry assigns tenant, agent, and role by the verified subject. Role and tenant claims inside the token cannot grant privileges. Subjects must be unique within the configured issuer. To rotate keys and mappings, replace `AUTH_CONFIG` and send `SIGHUP`. The service fully validates the replacement before swapping it, retains the old configuration on failure, and audits either outcome. A successful reload invalidates outstanding pending and approved requests so changed identities cannot retain approval authority. There is no automatic JWKS refresh, browser login, authorization server, registration service, token introspection, or automatic token introspection. Integrate an external issuer that produces the documented access-token contract.

## Network boundary

Terminate TLS at a trusted reverse proxy. Preserve the configured external Host header, strip inbound forwarding headers, cap request bodies and connections at the edge, and keep the internal port off public networks. The app intentionally does not trust proxy headers. Its IP limiter therefore sees the proxy address. Configure appropriate limits at the proxy for a deployment with many users.

API requests require bearer credentials. Untrusted Host and browser Origin headers are denied. Credentials are never accepted from query strings. No permissive CORS is enabled. Static UI and health are public, contain no user state, and receive restrictive security headers. Body size is capped at 256 KiB. The default limiter permits 120 requests per subject and 360 per observed IP per minute with 10,000 active key buckets. Limits are local to one process. Do not horizontally scale behind a shared credential boundary without a distributed limiter and shared state design.

## Durable state and recovery

SQLite uses WAL, a five-second busy timeout, and immediate transactions for state transitions. This is a single-writer service using a local disk. SQLite holds an exclusive lock for the process lifetime. A second opener fails with a single-writer error. Stop the service before running offline audit verification, checkpoint creation, backups, or direct database inspection. The OS releases the lock on process exit. Do not use network filesystems. The database file has mode 0600 and newly created parent directories have mode 0700. The process sets umask 0077 before opening SQLite so WAL and SHM files also use mode 0600. Secure an existing parent directory, backups, and the service account yourself. Keep disk capacity and audit growth under observation.

The audit chain authenticates sequence, timestamp, tenant, actor, action, outcome, details, and previous hash. Startup verifies the entire chain. Dashboard verification reports chain validity. Edits and middle deletions are detected. A configured signed checkpoint detects a database restored to before its retained sequence or a different hash at that sequence. Events after the latest checkpoint remain exposed to suffix truncation. A host administrator who obtains the audit key can forge records. Export the last sequence and hash to independent append-only storage for stronger guarantees. Exported per-tenant lists can omit intervening entries from other tenants, so they are not standalone complete chains. Audit endpoints verify new rows since the cached verified head; they check that the cached head still exists with its expected hash. Historical edits behind that head need a full scan. Stop the service and run `DB_PATH=... AUDIT_KEY=... npm run audit:verify` for a full scan. Startup always runs a full scan.

Do not rotate the audit key in place. Archive the closed database and checkpoint, start a new database with a new key, and preserve the old key securely for verification. Back up the database with SQLite's online backup tooling or stop the service and preserve the database plus any WAL state. Test restoration before relying on a backup. No automatic retention, external sink, high availability, database encryption, or backup scheduler is included.

## Release verification

Run `npm run verify`, `npm audit --audit-level=moderate`, and browser tests after installing Chromium with `npx playwright install chromium`. `CHROME_PATH` can select an existing compatible browser locally. CI installs the test runner's Chromium build. Run `docker build -t mcp-sentinel:local .` and `node scripts/container-smoke.mjs mcp-sentinel:local` with the demo port free. The smoke test does not print credentials and removes its temporary container in a final cleanup step.

CI has read-only repository permissions, disables persisted checkout credentials, pins every action to a full commit SHA, and checks types, automated tests, the reproducible demo, dependencies, browser workflows, content policy, container build, and container behavior. It does not publish packages or deploy a public service. Releases are source tags; deployment remains an operator action.

Operators can revoke a subject or a token ID in their own tenant through `POST /api/revocations` with strict JSON `{kind:"subject"|"jti", value, subject, expiresAt}`. Subject revocation requires `value=subject`. Token revocation binds the ID to its registered subject. Expiry must be in the future and within one year. Every accepted revocation is audited; expired rows are pruned on later revocations. Access tokens remain reusable unless revoked. Protect audit details, including full arguments retained for approval review, as sensitive operator data.

## Signed external checkpoints

Generate a separate Ed25519 PKCS8 PEM key with `openssl genpkey -algorithm ED25519 -out checkpoint-key.pem` and export the verification key with `openssl pkey -in checkpoint-key.pem -pubout -out checkpoint-public.pem`. Restrict the signing key to the checkpoint operator. Stop the single-writer service, then run `DB_PATH=... AUDIT_KEY=... CHECKPOINT_KEY=checkpoint-key.pem CHECKPOINT_FILE=/independent/checkpoint.json npm run checkpoint`. The command fully verifies the ledger before atomically writing signed `{seq,hash,at,signature}` JSON.

Set `CHECKPOINT_FILE` and `CHECKPOINT_PUBLIC_KEY` on the runtime. Startup requires a valid Ed25519 signature and matching sequence/hash. The runtime needs only the public key. For an offline operator workflow, `CHECKPOINT_KEY` can also supply the verification key through its public component. Keep the checkpoint and public-key configuration in independent protected storage; rolling back or replacing both defeats this control. A missing configured file fails startup. Checkpoint creation is offline because the database deliberately permits one opener. The initial checkpoint must exist before enabling startup enforcement.
