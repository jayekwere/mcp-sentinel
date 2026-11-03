# Release validation

Generated on 2026-11-03 by `npm run evidence`. All results below come from executed commands against the source hashes in [source-manifest.json](source-manifest.json). Host Node 26.3.0; the container build independently runs tests on Node 24.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Format, strict types, automated tests, build and demo | Passed | [verify.txt](verify.txt) |
| Automated coverage run | 79 passed, 0 failed, 0 skipped (79 tests) | [coverage.txt](coverage.txt) |
| Browser | 2 passed, desktop and mobile, no page errors | [browser.txt](browser.txt), [desktop](../docs/dashboard.png), [mobile](../docs/dashboard-mobile.png) |
| Container build | Passed, includes independent Node 24 type and test checks | [container-build.txt](container-build.txt) |
| Container smoke | Passed, non-root distroless Node 24, read-only root, dropped capabilities, limits, authentication, approvals and replay checks | [container-smoke.txt](container-smoke.txt) |
| Locked dependency advisory query | 0 reported advisories at execution time | [dependencies.json](dependencies.json) |
| Tracked text policy | Passed | [content-policy.txt](content-policy.txt) |
| Workflow syntax | Passed locally with actionlint | [workflows.txt](workflows.txt), [version](actionlint-version.txt) |
| Secret scan | Passed locally with gitleaks over all reachable history | [gitleaks.txt](gitleaks.txt), [version](gitleaks-version.txt) |

Coverage totals reported by V8:

```text
ℹ all files        |  98.19 |    86.12 |   97.58 |
```

Coverage totals describe only the files listed in the V8 table, including captured startup and maintenance subprocesses. Browser source isn't part of this report. Logs retain command output with trailing display whitespace removed. Browser tests use the locally configured compatible browser via CHROME_PATH. Coverage is execution evidence, not proof of all security properties. Dependency results change over time and aren't a container vulnerability scan.

The attack suite tests 1,000 bad tokens, audit tampering, blind and changed approvals, legacy migration, revocations, real SIGHUP reload, full descriptor changes, forbidden upstream content, structured-output mismatch, each secret pattern and safe audit counts, file modes, second writers in separate processes, transaction rollback, checkpoint rollback/signature forgery, maintenance commands, detection deduplication/failure isolation, encoded routes, and containment expiry/release/rearming. See [the threat-to-test map](../docs/THREAT-MODEL.md).

The gitleaks configuration excludes only the generated SHA256 source manifest, which caused a generic-key false positive. Synthetic JWT fixtures are assembled from segments so their literal value isn't mistaken for a live credential in source history. CI workflow assertions check pinned action references, scoped permissions and required release steps. These local checks don't execute hosted CodeQL, Scorecard, gitleaks, keyless signing or provenance publication. No release tag, public deployment, live external issuer, cloud account or external MCP service was exercised. Real MCP SDK clients and fixture servers run over local HTTP; a child service exercises production-format configuration and SIGHUP. The demo uses synthetic exports. No credentials are printed in committed evidence. UUIDs, timestamps, hashes and durations vary by run.
